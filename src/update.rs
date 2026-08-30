use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, PoisonError};
use std::thread;

use anyhow::{Context, Result, anyhow};
use futures_util::StreamExt;
use reqwest::header;
use self_update::update::{Release, ReleaseAsset};
use serde::Deserialize;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::{AppState, State};

/// The user's answer to the "update available" prompt.
///
/// This travels on a channel of its own rather than on the shared
/// [`crate::Message`] stream. The update check used to `recv()` straight from
/// the UI channel, so every unrelated message that happened to arrive while the
/// prompt was up — the one and only startup `StartCapture`, and the startup
/// `VerifyTrackerKey` — was consumed here and thrown away, which meant packet
/// capture silently never started for the whole session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateAnswer {
    Accepted,
    Declined,
}

/// Where a user is pointed when Irminsul can find an update but cannot install
/// it for them.
const RELEASES_URL: &str = "https://github.com/tawan475/irminsul/releases";

/// Serialises replacing the installed binary against process exit.
///
/// `IrminsulApp::drop` cancels the monitor and then joins it with a deadline,
/// after which the thread is detached and `main` returning kills it. That is
/// right for a capture backend and catastrophic for `self_replace`, which on
/// Windows renames the running exe aside, copies the replacement to a temporary
/// and renames *that* into place: a process killed inside that window leaves
/// nothing at the install path at all — the unrecoverable brick the update
/// guards were added to prevent, caused by the guard against a wedged exit.
///
/// So the two agree explicitly. Everything before the point of no return (the
/// download) is cancellable and gives up as soon as the token fires; the
/// replacement itself takes this lock, and shutdown waits on it without a
/// deadline. Only one of the two can win, whichever gets to the mutex first:
///
/// * install first — `shutdown_and_wait` blocks until `self_replace` returns;
/// * shutdown first — `begin_install` refuses and no bytes are written.
#[derive(Debug, Default)]
pub struct InstallLock {
    state: Mutex<InstallLockState>,
    idle: Condvar,
}

#[derive(Debug, Default)]
struct InstallLockState {
    installing: bool,
    shutting_down: bool,
}

impl InstallLock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Claim the right to overwrite the running executable, or `None` when the
    /// process is already shutting down and must not start one.
    fn begin_install(&self) -> Option<InstallInProgress<'_>> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.shutting_down {
            return None;
        }
        state.installing = true;
        Some(InstallInProgress { lock: self })
    }

    /// Refuse any install that has not started yet, and block until one that
    /// has is finished.
    ///
    /// Deliberately unbounded: `self_replace` is a short, fixed sequence of
    /// filesystem calls, and a shutdown that hangs is recoverable where a
    /// half-replaced executable is not.
    pub fn shutdown_and_wait(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.shutting_down = true;
        if state.installing {
            tracing::warn!(
                "an update is being installed; waiting for it to finish before exiting \
                 (killing Irminsul now would leave no executable behind)"
            );
        }
        while state.installing {
            state = self
                .idle
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// Held for exactly as long as the running executable is being replaced.
struct InstallInProgress<'a> {
    lock: &'a InstallLock,
}

impl Drop for InstallInProgress<'_> {
    fn drop(&mut self) {
        let mut state = self
            .lock
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.installing = false;
        self.lock.idle.notify_all();
    }
}

/// Whether a version string carries a semver pre-release identifier.
///
/// Irminsul's own version (`0.2.1-T-1`) is one, which is exactly why this
/// matters: a stable build must never be walked onto a prerelease, while a
/// build that is already off the stable track may take another one.
fn is_prerelease(version: &str) -> bool {
    // Build metadata (`+…`) may itself contain hyphens and is not a
    // pre-release marker, so it has to come off first.
    let core = version.split('+').next().unwrap_or(version);
    core.split_once('-')
        .is_some_and(|(_, pre)| !pre.trim().is_empty())
}

/// Pick the release the running build should be offered, if any.
///
/// The list GitHub returns is neither sorted by version nor filtered, so the
/// old `releases.first().version != current` test offered downgrades (any local
/// or fork build whose version merely *differs*) and prereleases as updates,
/// and accepting one overwrote the binary with it.
fn best_release(releases: &[Release], current_version: &str) -> Option<Release> {
    let allow_prerelease = is_prerelease(current_version);

    let mut best: Option<&Release> = None;
    for release in releases {
        if !allow_prerelease && is_prerelease(&release.version) {
            continue;
        }
        // An unparseable tag is not something to offer as an update.
        if !self_update::version::bump_is_greater(current_version, &release.version)
            .unwrap_or(false)
        {
            continue;
        }
        let is_better = match best {
            None => true,
            Some(best) => self_update::version::bump_is_greater(&best.version, &release.version)
                .unwrap_or(false),
        };
        if is_better {
            best = Some(release);
        }
    }

    best.cloned()
}

pub fn check_for_new_version() -> Result<Option<Release>> {
    // This needs to be outside of an async context otherwise it panics.
    let releases = thread::spawn(move || -> Result<Vec<Release>> {
        let releases = self_update::backends::github::ReleaseList::configure()
            .repo_owner("tawan475")
            .repo_name("irminsul")
            .build()?
            .fetch()?;
        Ok(releases)
    })
    .join();
    let releases = releases
        .map_err(|_| anyhow!("error joining update thread"))?
        .context("error fetching releases")?;

    let current_version = self_update::cargo_crate_version!();
    let Some(release) = best_release(&releases, current_version) else {
        tracing::info!("{current_version} is current, continuing with app startup");
        return Ok(None);
    };

    tracing::info!("Found update {current_version} -> {}", release.version);

    Ok(Some(release))
}

/// The release asset name that matches the binary currently running.
///
/// These must stay in sync with the `out_file` names produced by
/// `.github/workflows/release.yaml`. Renaming these also means updating
/// `docs/src/02-quickstart.md` in the same commit: the quickstart lists all
/// four asset names verbatim, so it is a third copy that will otherwise
/// silently rot.
const CURRENT_ASSET_NAME: Option<&str> = {
    #[cfg(all(target_os = "windows", feature = "pcap"))]
    {
        Some("irminsul-windows-pcap.exe")
    }
    #[cfg(all(target_os = "windows", not(feature = "pcap")))]
    {
        Some("irminsul-windows.exe")
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Some("irminsul-linux-x86_64.tar.gz")
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        Some("Irminsul-macos-arm64.app.tar.gz")
    }
    #[cfg(not(any(
        target_os = "windows",
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
    )))]
    {
        None
    }
};

/// Pick the release asset that matches the platform of the running binary so we
/// don't, for example, download a Linux tarball onto a Windows machine.
fn asset_for_current_platform(release: &Release) -> Result<ReleaseAsset> {
    let name = CURRENT_ASSET_NAME
        .ok_or_else(|| anyhow!("no prebuilt binary is available for this platform"))?;

    release
        .assets
        .iter()
        .find(|asset| asset.name == name)
        .cloned()
        .ok_or_else(|| {
            anyhow!(
                "release {} does not contain asset '{name}'",
                release.version
            )
        })
}

/// The single entry the Linux release tarball holds.
///
/// `.github/workflows/release.yaml` builds it as `tar -czf <out_file> <binary>`
/// from `target/release`, so the archive contains exactly one member, named
/// after the matrix's `binary` field. Renaming that means renaming this.
const TARBALL_EXECUTABLE_ENTRY: &str = "irminsul";

/// How a downloaded release asset becomes the file handed to `self_replace`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InstallPlan {
    /// The asset is the program itself; install it verbatim.
    Direct,
    /// The asset is a gzipped tar holding one bare executable, which has to be
    /// unpacked first. Handing the tarball straight to `self_replace` wrote raw
    /// gzip bytes over the installed binary, and the next launch was "Exec
    /// format error" with no way to repair it from inside the app.
    UnpackTarGz(&'static str),
}

/// Decide how an asset can be installed, or refuse it.
///
/// Only shapes this function knows how to turn into a native executable are
/// accepted. A macOS `.app` is the one release asset that genuinely cannot be
/// installed this way: it is a directory tree, and replacing the Mach-O inside
/// the installed bundle is not what `self_replace` does.
fn install_plan_for(asset: &ReleaseAsset) -> Result<InstallPlan> {
    // Checked before the plain `.tar.gz` arm below, which it also matches.
    if asset.name.ends_with(".app.tar.gz") {
        return Err(anyhow!(
            "the release asset for this platform ({}) is a macOS application bundle, which \
             Irminsul cannot install over itself; download it from {RELEASES_URL} and \
             replace the installed copy by hand",
            asset.name
        ));
    }

    if asset.name.ends_with(".tar.gz") || asset.name.ends_with(".tgz") {
        return Ok(InstallPlan::UnpackTarGz(TARBALL_EXECUTABLE_ENTRY));
    }

    if asset.name.ends_with(".zip") {
        return Err(anyhow!(
            "the release asset for this platform ({}) is a zip archive, which Irminsul cannot \
             install over itself; download it from {RELEASES_URL} and replace the \
             installed copy by hand",
            asset.name
        ));
    }

    Ok(InstallPlan::Direct)
}

/// Unpack one entry of a gzipped tar into `into_dir` and return its path.
///
/// The extracted file still goes through the size and magic-number checks
/// below: an archive is no more trustworthy than a bare download.
fn extract_tar_gz_entry(archive: &Path, into_dir: &Path, entry: &str) -> Result<PathBuf> {
    self_update::Extract::from_source(archive)
        // Named rather than sniffed from the extension: `detect_archive` keys
        // off the *last* extension only, so `irminsul-linux-x86_64.tar.gz`
        // would be read as a bare gzip stream rather than as a tar.
        .archive(self_update::ArchiveKind::Tar(Some(
            self_update::Compression::Gz,
        )))
        .extract_file(into_dir, entry)
        .map_err(|e| anyhow!("{e}"))
        .with_context(|| format!("could not unpack '{entry}' from {archive:?}"))?;

    let path = into_dir.join(entry);
    if !path.is_file() {
        return Err(anyhow!("the downloaded archive did not contain '{entry}'"));
    }
    Ok(path)
}

const PE_MAGIC: &[u8] = b"MZ";
const ELF_MAGIC: &[u8] = b"\x7fELF";

/// No Irminsul build is anywhere near this small; an HTTP error page is.
const MIN_ASSET_LEN: u64 = 64 * 1024;

/// Reject a download that is too small to be a build of this program.
///
/// The download used to be installed with no HTTP status check at all, so a
/// transient GitHub/CDN error page could be `self_replace`d onto the exe. The
/// status check added below is the real fix; this is the backstop for a
/// truncated or empty body served with a 200.
fn check_minimum_size(path: &Path) -> Result<()> {
    let len = std::fs::metadata(path)
        .with_context(|| format!("could not stat the downloaded update at {path:?}"))?
        .len();

    if len < MIN_ASSET_LEN {
        return Err(anyhow!(
            "the downloaded update is only {len} bytes, which is too small to be an Irminsul build"
        ));
    }

    Ok(())
}

/// Reject a download that is not an executable for this platform before it
/// overwrites the running one. Installing the wrong platform's binary leaves an
/// app that cannot run, and so cannot update itself back out of it.
fn check_is_native_executable(path: &Path) -> Result<()> {
    let magic = if cfg!(windows) {
        PE_MAGIC
    } else if cfg!(target_os = "linux") {
        ELF_MAGIC
    } else {
        return Err(anyhow!(
            "Irminsul cannot verify a downloaded update on this platform"
        ));
    };

    let mut header = [0u8; 4];
    let read = std::fs::File::open(path)
        .with_context(|| format!("could not open the downloaded update at {path:?}"))?
        .read(&mut header)?;

    if !header[..read].starts_with(magic) {
        return Err(anyhow!(
            "the downloaded update is not an executable for this platform"
        ));
    }

    Ok(())
}

/// What came of an accepted update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InstallOutcome {
    /// The running executable was replaced; the app should restart.
    Installed,
    /// Shutdown began before anything was written. The staging directory is
    /// cleaned up on the way out and the install is untouched.
    Cancelled,
}

/// Fetch a release asset into `dest`.
///
/// Split out so the whole download can be raced against the cancel token by a
/// single `select!`: dropping this future mid-stream leaves at most a partial
/// file inside the staging directory, which is removed with it.
async fn download_asset(client: &reqwest::Client, asset: &ReleaseAsset, dest: &Path) -> Result<()> {
    #[derive(Deserialize)]
    struct DownloadMetadata {
        browser_download_url: String,
    }

    tracing::info!("fetching artifact info {}", asset.download_url);
    let metadata: DownloadMetadata = client
        .get(&asset.download_url)
        .header(header::USER_AGENT, "rust-reqwest/self-update")
        .send()
        .await
        .with_context(|| format!("could not reach {}", asset.download_url))?
        // Without this an error page is happily parsed, downloaded and
        // installed over the running program.
        .error_for_status()
        .with_context(|| format!("could not fetch asset metadata from {}", asset.download_url))?
        .json()
        .await
        .with_context(|| format!("{} did not return asset metadata", asset.download_url))?;

    tracing::info!("downloading {} to {dest:?}", metadata.browser_download_url);
    let mut stream = client
        .get(&metadata.browser_download_url)
        .header(header::USER_AGENT, "rust-reqwest/self-update")
        .send()
        .await
        .with_context(|| format!("could not reach {}", metadata.browser_download_url))?
        .error_for_status()
        .with_context(|| format!("could not download {}", metadata.browser_download_url))?
        .bytes_stream();

    let mut file =
        std::fs::File::create(dest).with_context(|| format!("could not create {dest:?}"))?;
    while let Some(chunk) = stream.next().await {
        file.write_all(&chunk?)?;
    }
    file.flush()?;

    Ok(())
}

async fn download_new_version_and_replace_current(
    release: Release,
    cancel_token: &CancellationToken,
    install_lock: &InstallLock,
) -> Result<InstallOutcome> {
    let asset = asset_for_current_platform(&release)?;
    let plan = install_plan_for(&asset)?;
    tracing::info!("asset: {asset:#?}");

    // Stage the download next to the executable being replaced. self_replace
    // finishes with a rename, which cannot cross filesystems, and the current
    // directory is neither guaranteed to be writable nor on the same mount as
    // the install.
    let current_exe = std::env::current_exe().context("could not find the current exe")?;
    let exe_dir = current_exe
        .parent()
        .context("current exe has no parent directory")?;
    let tmp_dir = tempfile::Builder::new()
        .prefix("self_update")
        .tempdir_in(exe_dir)?;
    let tmp_asset_path = tmp_dir.path().join(&asset.name);

    let client = reqwest::Client::builder().gzip(true).build()?;

    // The download is the long, network-bound half and nothing has been written
    // over the install yet, so closing the window during it must give up
    // promptly rather than leave `IrminsulApp::drop` waiting out its deadline
    // and then detaching this thread mid-download — which also leaked the
    // staging directory next to the executable, because `TempDir::drop` never
    // ran.
    let cancelled = tokio::select! {
        _ = cancel_token.cancelled() => true,
        result = download_asset(&client, &asset, &tmp_asset_path) => {
            result?;
            false
        }
    };
    if cancelled {
        tracing::info!("update download cancelled during shutdown; nothing was installed");
        return Ok(InstallOutcome::Cancelled);
    }

    let installable = match plan {
        InstallPlan::Direct => tmp_asset_path,
        InstallPlan::UnpackTarGz(entry) => {
            tracing::info!("unpacking '{entry}' from {tmp_asset_path:?}");
            extract_tar_gz_entry(&tmp_asset_path, tmp_dir.path(), entry)?
        }
    };

    check_minimum_size(&installable)?;
    check_is_native_executable(&installable)?;

    // Release assets are written without the executable bit.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&installable, std::fs::Permissions::from_mode(0o755))
            .context("could not make the downloaded binary executable")?;
    }

    // Point of no return. Everything above is safe to abandon; from here the
    // installed executable is being taken apart and put back together, and the
    // process must stay alive until it is whole again.
    let Some(_installing) = install_lock.begin_install() else {
        tracing::info!("shutdown started before the update was installed; leaving it alone");
        return Ok(InstallOutcome::Cancelled);
    };

    tracing::info!("replacing current exe");
    self_update::self_replace::self_replace(installable)?;

    Ok(InstallOutcome::Installed)
}

/// Where the last "install this by hand" notice is remembered.
fn manual_notice_marker() -> Option<PathBuf> {
    eframe::storage_dir(crate::APP_ID).map(|mut path| {
        path.push("last_manual_update_notice");
        path
    })
}

/// Whether to tell the user about a release they have to install themselves.
///
/// Once per release, not once per launch: on a platform whose asset cannot be
/// installed in place the same toast would otherwise greet every single start
/// for as long as that release is the newest one. Answering yes records
/// `version` in the marker, which is what makes the next answer no.
fn should_report_manual_install(marker: Option<&Path>, version: &str) -> bool {
    let Some(marker) = marker else {
        // No storage directory to remember it in; a repeated toast beats a
        // silently skipped update.
        return true;
    };

    if std::fs::read_to_string(marker)
        .ok()
        .as_deref()
        .map(str::trim)
        == Some(version)
    {
        return false;
    }

    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(marker, version);
    true
}

pub async fn check_for_app_update(
    state_tx: &watch::Sender<AppState>,
    update_answer_rx: &mut mpsc::UnboundedReceiver<UpdateAnswer>,
    cancel_token: &CancellationToken,
    toast_tx: &mpsc::UnboundedSender<(String, bool)>,
    install_lock: &InstallLock,
) -> Result<()> {
    let mut app_state = state_tx.borrow().clone();
    app_state.state = State::CheckingForUpdate;
    let _ = state_tx.send(app_state.clone());

    let Some(release) = check_for_new_version()? else {
        // No new version.
        return Ok(());
    };

    // Do not put up a prompt for an update that cannot be installed. This used
    // to be discovered only *after* the user accepted, at which point the
    // download either failed late or — on Linux and macOS — bricked the
    // install.
    if let Err(e) = asset_for_current_platform(&release).and_then(|asset| install_plan_for(&asset))
    {
        tracing::warn!(
            "Irminsul {} is available but cannot be installed in place: {e}",
            release.version
        );
        // Say so rather than silently skipping the update: on the platforms
        // this hits, downloading by hand is the only way to get it -- but say
        // it once per release, not on every launch for the rest of its life.
        if should_report_manual_install(manual_notice_marker().as_deref(), &release.version) {
            let _ = toast_tx.send((
                format!(
                    "Irminsul {} is available, but has to be installed by hand on this \
                     platform: {RELEASES_URL}",
                    release.version
                ),
                true,
            ));
        }
        return Ok(());
    }

    // Notify user of update and ask for acknowledgement.
    app_state.state = State::WaitingForUpdateConfirmation(release.version.clone());
    let _ = state_tx.send(app_state.clone());

    // Wait for acknowledgment. Every arm here has to be able to give up:
    // without the cancel arm, closing the window at the prompt left this task
    // parked forever while `IrminsulApp::drop` joined on it, and the process
    // sat at 0% CPU holding the single-instance mutex.
    let answer = tokio::select! {
        _ = cancel_token.cancelled() => return Ok(()),
        answer = update_answer_rx.recv() => answer,
    };
    match answer {
        Some(UpdateAnswer::Accepted) => (),
        Some(UpdateAnswer::Declined) => return Ok(()),
        // The UI is gone. `recv()` returns `None` forever from here, so the old
        // `_ => ()` arm spun its wait loop at full tilt instead of giving up.
        None => return Ok(()),
    }

    app_state.state = State::Updating;
    let _ = state_tx.send(app_state.clone());

    match download_new_version_and_replace_current(release, cancel_token, install_lock).await {
        Ok(InstallOutcome::Installed) => (),
        // Shutdown won the race and the installed binary was never touched.
        // The window is already closing, so there is nobody to tell.
        Ok(InstallOutcome::Cancelled) => return Ok(()),
        Err(e) => {
            // A failed install used to leave the spinner up and the reason in
            // the log file only; the guards above mean this is now a clean
            // error instead of a bricked binary, so it is worth showing.
            let _ = toast_tx.send((format!("Update failed: {e}"), true));
            return Err(e);
        }
    }

    app_state.state = State::Updated;
    let _ = state_tx.send(app_state.clone());

    // The UI now closes the viewport; `main` relaunches the replacement once
    // `run_native` has returned and the single-instance mutex has been
    // released. Nothing more arrives on this channel, so wait only for the
    // shutdown signal.
    cancel_token.cancelled().await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    fn release(version: &str, assets: &[&str]) -> Release {
        Release {
            version: version.to_owned(),
            assets: assets
                .iter()
                .map(|name| ReleaseAsset {
                    download_url: format!("https://example.invalid/{name}"),
                    name: (*name).to_owned(),
                })
                .collect(),
            ..Default::default()
        }
    }

    /// Every asset published by .github/workflows/release.yaml. Keep the two in
    /// sync (and docs/src/02-quickstart.md with them).
    const PUBLISHED_ASSETS: &[&str] = &[
        "irminsul-windows.exe",
        "irminsul-windows-pcap.exe",
        "irminsul-linux-x86_64.tar.gz",
        "Irminsul-macos-arm64.app.tar.gz",
    ];

    #[test]
    fn picks_the_asset_for_this_platform() {
        let release = release("9.9.9", PUBLISHED_ASSETS);

        match CURRENT_ASSET_NAME {
            Some(expected) => {
                let asset =
                    asset_for_current_platform(&release).expect("an asset for this platform");
                assert_eq!(asset.name, expected);
            }
            None => {
                asset_for_current_platform(&release)
                    .expect_err("no asset is published for this platform");
            }
        }
    }

    #[test]
    fn a_release_without_our_asset_is_an_error() {
        let release = release("9.9.9", &["some-other-project.exe"]);

        asset_for_current_platform(&release)
            .expect_err("an unrelated asset must not be installed over irminsul");
    }

    fn asset(name: &str) -> ReleaseAsset {
        ReleaseAsset {
            download_url: format!("https://example.invalid/{name}"),
            name: name.to_owned(),
        }
    }

    #[test]
    fn a_tarball_is_unpacked_rather_than_installed_verbatim() {
        // Handing the gzip bytes to self_replace is what bricked Linux
        // installs; refusing them outright is what removed in-app updates from
        // Linux entirely. Neither is the answer -- unpacking is.
        for name in ["irminsul-linux-x86_64.tar.gz", "irminsul.tgz"] {
            assert_eq!(
                install_plan_for(&asset(name)).unwrap(),
                InstallPlan::UnpackTarGz(TARBALL_EXECUTABLE_ENTRY),
                "{name} holds a bare executable and must be unpacked"
            );
        }
    }

    #[test]
    fn a_macos_bundle_and_a_zip_are_still_refused() {
        // A .app is a directory tree: there is no single file self_replace can
        // put in place of the running one. Note it also ends with `.tar.gz`, so
        // the order of the checks in `install_plan_for` is load bearing.
        install_plan_for(&asset("Irminsul-macos-arm64.app.tar.gz"))
            .expect_err("a macOS bundle cannot be installed over a single executable");
        install_plan_for(&asset("irminsul.zip")).expect_err("nothing unpacks zips");
    }

    #[test]
    fn a_bare_executable_is_installed_verbatim() {
        for name in ["irminsul-windows.exe", "irminsul-linux-x86_64"] {
            assert_eq!(
                install_plan_for(&asset(name)).unwrap(),
                InstallPlan::Direct,
                "{name} is the program itself"
            );
        }
    }

    /// Build the archive shape release.yaml publishes for Linux:
    /// `cd target/release && tar -czf <out_file> irminsul`, one member named
    /// after the matrix's `binary` field.
    fn write_tarball(path: &Path, entries: &[(&str, &[u8])]) {
        let file = std::fs::File::create(path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);
        for (name, contents) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append_data(&mut header, name, *contents).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
    }

    #[test]
    fn the_linux_tarball_yields_an_installable_executable() {
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("irminsul-linux-x86_64.tar.gz");

        let mut payload = ELF_MAGIC.to_vec();
        payload.resize(MIN_ASSET_LEN as usize + 1, 0);
        write_tarball(&archive_path, &[(TARBALL_EXECUTABLE_ENTRY, &payload)]);

        let extracted =
            extract_tar_gz_entry(&archive_path, dir.path(), TARBALL_EXECUTABLE_ENTRY).unwrap();
        assert_eq!(extracted, dir.path().join(TARBALL_EXECUTABLE_ENTRY));
        assert_eq!(std::fs::read(&extracted).unwrap(), payload);

        // The unpacked file, not the archive, is what the install guards vet.
        check_minimum_size(&extracted).expect("the unpacked binary is a plausible size");
        check_minimum_size(&archive_path)
            .expect_err("the compressed archive is far below the floor");
    }

    #[test]
    fn a_missing_archive_entry_is_an_error_rather_than_a_silent_install() {
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("wrong.tar.gz");
        write_tarball(&archive_path, &[("README", b"not a program")]);

        extract_tar_gz_entry(&archive_path, dir.path(), TARBALL_EXECUTABLE_ENTRY)
            .expect_err("an archive without the executable must not install anything");
    }

    #[test]
    fn the_manual_install_notice_fires_once_per_release() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("nested").join("last_manual_update_notice");

        assert!(should_report_manual_install(Some(&marker), "0.3.0"));
        // Every launch afterwards used to raise the same toast again.
        assert!(!should_report_manual_install(Some(&marker), "0.3.0"));
        assert!(should_report_manual_install(Some(&marker), "0.4.0"));
        assert!(!should_report_manual_install(Some(&marker), "0.4.0"));

        // No storage directory: better a repeated toast than a silent update.
        assert!(should_report_manual_install(None, "0.4.0"));
    }

    #[test]
    fn an_install_already_running_holds_shutdown_until_it_finishes() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let lock = Arc::new(InstallLock::new());
        let finished = Arc::new(AtomicBool::new(false));
        let started = Arc::new((Mutex::new(false), Condvar::new()));

        let installer = {
            let lock = Arc::clone(&lock);
            let finished = Arc::clone(&finished);
            let started = Arc::clone(&started);
            thread::spawn(move || {
                let _guard = lock.begin_install().expect("nothing has shut down yet");
                let (mutex, condvar) = &*started;
                *mutex.lock().unwrap() = true;
                condvar.notify_all();
                // Stands in for `self_replace`: the window in which there is no
                // executable at the install path at all.
                thread::sleep(Duration::from_millis(150));
                finished.store(true, Ordering::SeqCst);
            })
        };

        let (mutex, condvar) = &*started;
        let mut running = mutex.lock().unwrap();
        while !*running {
            running = condvar.wait(running).unwrap();
        }
        drop(running);

        lock.shutdown_and_wait();
        assert!(
            finished.load(Ordering::SeqCst),
            "shutdown must not return while the executable is half replaced"
        );
        installer.join().unwrap();
    }

    #[test]
    fn an_install_cannot_start_once_shutdown_has_begun() {
        let lock = InstallLock::new();
        lock.shutdown_and_wait();
        assert!(
            lock.begin_install().is_none(),
            "a process on its way out must not start replacing its own executable"
        );
    }

    #[test]
    fn a_foreign_binary_is_rejected() {
        let dir = tempfile::tempdir().unwrap();

        let native_magic: &[u8] = if cfg!(windows) { PE_MAGIC } else { ELF_MAGIC };

        let native = dir.path().join("native");
        std::fs::write(&native, native_magic).unwrap();

        let foreign = dir.path().join("foreign");
        std::fs::write(&foreign, b"\x00not an executable").unwrap();
        check_is_native_executable(&foreign).expect_err("a foreign binary must be rejected");

        // An HTML error page served in place of the asset is the case that
        // bricked installs.
        let error_page = dir.path().join("error_page");
        std::fs::write(&error_page, b"<?xml version=\"1.0\"?><Error>").unwrap();
        check_is_native_executable(&error_page).expect_err("an error page must be rejected");

        let empty = dir.path().join("empty");
        std::fs::write(&empty, b"").unwrap();
        check_is_native_executable(&empty).expect_err("a truncated download must be rejected");

        if cfg!(any(windows, target_os = "linux")) {
            check_is_native_executable(&native).expect("this platform's magic must be accepted");
        } else {
            check_is_native_executable(&native)
                .expect_err("this platform publishes nothing we can verify");
        }
    }

    #[test]
    fn a_short_download_is_rejected() {
        let dir = tempfile::tempdir().unwrap();

        let short = dir.path().join("short");
        std::fs::write(&short, b"MZ not really a program").unwrap();
        check_minimum_size(&short).expect_err("an error-page-sized download must be rejected");

        let long = dir.path().join("long");
        std::fs::write(&long, vec![0u8; MIN_ASSET_LEN as usize]).unwrap();
        check_minimum_size(&long).expect("a plausibly sized download must be accepted");
    }

    #[test]
    fn prereleases_are_recognised() {
        assert!(!is_prerelease("0.2.1"));
        assert!(!is_prerelease("1.0.0+build-7"));
        assert!(is_prerelease("0.2.1-T-1"));
        assert!(is_prerelease("1.0.0-rc.1"));
        assert!(is_prerelease("1.0.0-rc.1+build-7"));
    }

    #[test]
    fn a_stable_build_is_never_offered_a_prerelease() {
        let releases = [
            release("0.3.0-rc.1", PUBLISHED_ASSETS),
            release("0.2.0", PUBLISHED_ASSETS),
        ];

        let best = best_release(&releases, "0.2.0");
        assert!(best.is_none(), "0.2.0 is already the newest stable release");
    }

    #[test]
    fn a_prerelease_build_may_take_a_prerelease() {
        let releases = [
            release("0.3.0-rc.1", PUBLISHED_ASSETS),
            release("0.2.0", PUBLISHED_ASSETS),
        ];

        let best = best_release(&releases, "0.2.1-T-1").expect("0.3.0-rc.1 is newer");
        assert_eq!(best.version, "0.3.0-rc.1");
    }

    #[test]
    fn downgrades_are_never_offered() {
        // The old check was `releases.first().version != current`, so a fork or
        // local build one version ahead was told to "update" backwards.
        let releases = [release("0.2.0", PUBLISHED_ASSETS)];

        assert!(best_release(&releases, "0.3.0").is_none());
        assert!(best_release(&releases, "0.2.0").is_none());
    }

    #[test]
    fn the_newest_release_wins_regardless_of_list_order() {
        // GitHub's ordering is not guaranteed to be by version, and `first()`
        // trusted it.
        let releases = [
            release("0.2.2", PUBLISHED_ASSETS),
            release("0.10.0", PUBLISHED_ASSETS),
            release("0.3.0", PUBLISHED_ASSETS),
        ];

        let best = best_release(&releases, "0.2.0").expect("0.10.0 is newer");
        assert_eq!(best.version, "0.10.0");
    }

    #[test]
    fn an_unparseable_tag_is_skipped() {
        let releases = [
            release("nightly", PUBLISHED_ASSETS),
            release("0.3.0", PUBLISHED_ASSETS),
        ];

        let best = best_release(&releases, "0.2.0").expect("0.3.0 is newer");
        assert_eq!(best.version, "0.3.0");

        assert!(best_release(&[release("nightly", PUBLISHED_ASSETS)], "0.2.0").is_none());
    }
}
