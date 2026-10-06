#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, reload};

use crate::game_watch::GameStatus;
use crate::player_data::ExportSettings;

mod admin;
mod app;
mod autostart;
mod capture;
mod crash;
mod game_watch;
mod good;
mod monitor;
mod pcapng;
mod player_data;
mod recording;
mod replay;
mod update;
mod wish;

const APP_ID: &str = "Irminsul";

#[derive(Clone, Copy, Debug)]
pub enum ConfirmationType {
    Initial,
    Update,
}

#[derive(Clone, Debug)]
pub enum State {
    Starting,
    CheckingForUpdate,
    WaitingForUpdateConfirmation(String),
    Updating,
    Updated,
    CheckingForData,
    WaitingForDownloadConfirmation(ConfirmationType),
    Downloading,
    Main,
}

/// A request from the UI to the background monitor.
///
/// The update prompt deliberately does *not* travel on this channel: see
/// [`update::UpdateAnswer`]. Draining this one to wait for an update
/// acknowledgement is what used to swallow the startup `StartCapture`.
#[derive(Debug)]
pub enum Message {
    DownloadAcknowledged,
    StartCapture,
    StopCapture,
    ClearData,
    ExportGenshinOptimizer(ExportSettings, oneshot::Sender<Result<String>>),
    ExportAchievements(oneshot::Sender<Result<Vec<u32>>>),
    /// Only sent by the wish UI, which exists on Windows and on Linux (through
    /// a Proton/Wine prefix) — the platforms where the game writes the
    /// `output_log.txt` the URL is recovered from. `monitor.rs` still handles
    /// it everywhere.
    #[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
    FindWishUrl(oneshot::Sender<Result<String>>),
    VerifyTrackerKey(
        String,
        String,
        oneshot::Sender<Result<monitor::TrackerAccount>>,
    ),
    UploadToTracker(String, String, String, oneshot::Sender<Result<(), String>>),
    /// Terminate the running game, from the "game already running" modal.
    ///
    /// Handled in `monitor.rs` rather than in the UI because the process
    /// scanner lives there, and because the reply has to wait for the process
    /// to actually go away before the status line is re-derived. Carries the
    /// number of processes stopped; zero is a real answer, not a failure.
    KillGame(oneshot::Sender<usize>),
}

#[derive(Clone, Debug)]
pub struct DataUpdated {
    achievements_updated: Option<Instant>,
    achievements_updated_time: Option<chrono::DateTime<chrono::Local>>,
    characters_updated: Option<Instant>,
    items_updated: Option<Instant>,
}

impl DataUpdated {
    pub fn new() -> Self {
        Self {
            achievements_updated: None,
            achievements_updated_time: None,
            characters_updated: None,
            items_updated: None,
        }
    }
}

impl Default for DataUpdated {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct AppState {
    state: State,
    capturing: bool,
    updated: DataUpdated,
    /// Whether the game is running and, more to the point, whether Irminsul
    /// watched this game session start. `capturing` says the backend is up; it
    /// says nothing about whether the traffic it sees can be decrypted at all.
    /// See [`game_watch`].
    game_status: GameStatus,
    /// What the captured data says about the account (`gi_player`), for the
    /// data panel and the tracker's UID check. `None` until something is known.
    player: Option<good::GiPlayer>,
}

impl AppState {
    fn new() -> Self {
        AppState {
            state: State::Starting,
            capturing: false,
            updated: DataUpdated::new(),
            game_status: GameStatus::default(),
            player: None,
        }
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(
        long,
        default_value_t = false,
        long_help = "Skip the packet-capture privilege check.\n\n\
                     No effect on Windows: build.rs embeds an application manifest with \
                     requestedExecutionLevel=requireAdministrator, so Windows decides elevation \
                     before main() runs and the process is already elevated by the time this flag \
                     is parsed."
    )]
    no_admin: bool,

    #[arg(
        long = "capture-backend",
        short = 'b',
        value_enum,
        default_value_t = capture::DEFAULT_CAPTURE_BACKEND_TYPE
    )]
    capture_backend: capture::BackendType,

    #[arg(long, short, default_value_t = false, requires("savefile_path"))]
    read_from_file: bool,

    #[arg(
        long = "replay-export",
        value_name = "OUT_JSON",
        requires = "savefile_path",
        conflicts_with_all = ["read_from_file", "capture_backend"],
        help = "Decode the recording SAVEFILE_PATH without the app and write its export to OUT_JSON",
        long_help = "Decode the recording SAVEFILE_PATH without starting the app, and write the \
                     export it yields to OUT_JSON.\n\n\
                     The recording is the irminsul-data/log/*.pcapng a debug build writes, or a \
                     pcap or pcapng file from `-b pcap <template>` or Wireshark; no pcap support \
                     is needed to read it. It is decoded the way live capture decodes: the \
                     session key is recovered from the login in the recording, and a reconnect or \
                     a second login replaces the earlier data once it delivers its own. The state \
                     at the end is exported with the default export settings (pretty-printed, \
                     gi_* extras included) and stamped with the time its data was captured.\n\n\
                     Nothing is uploaded, no key is verified, no automation file is saved, no \
                     update is checked for, no settings are read or written, nothing under \
                     Irminsul's data directory is touched, and the single-instance lock is not \
                     taken, so it can run beside a running Irminsul. It needs no administrator \
                     rights, but on Windows the executable's manifest still asks for them before \
                     any of this runs: set __COMPAT_LAYER=RunAsInvoker to start it unelevated.\n\n\
                     The log goes to stdout and to OUT_JSON.log (RUST_LOG sets the level). Exits \
                     with 1 when nothing could be decoded, saying why."
    )]
    replay_export: Option<PathBuf>,

    #[arg(
        value_name = "SAVEFILE_PATH",
        help = "Recording to replay (--read-from-file, --replay-export), or a filename template to record to",
        long_help = "Recording to replay with --read-from-file or --replay-export, or a filename \
                     template to record live traffic to.\n\n\
                     With --read-from-file or --replay-export the path is used as given: it is \
                     the recording to replay.\n\n\
                     Without either the path is a template, not an output file. Irminsul captures on \
                     every eligible network interface at once, and each one is recorded to its \
                     own file named after the device, because one pcap dump file cannot be shared \
                     by several capture handles. `irminsul -b pcap session.pcap` therefore writes \
                     `session-<interface>.pcap` once per interface and no plain `session.pcap`; \
                     the log line \"Recording <device> to savefile ...\" names each file as it is \
                     opened.\n\n\
                     Recording is only supported by the pcap capture backend (-b pcap)."
    )]
    savefile_path: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, Default)]
pub enum TracingLevel {
    #[default]
    Default,
    VerboseInfo,
    VerboseDebug,
    VerboseTrace,
}

impl Display for TracingLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TracingLevel::Default => write!(f, "Default"),
            TracingLevel::VerboseInfo => write!(f, "Verbose Info"),
            TracingLevel::VerboseDebug => write!(f, "Verbose Debug"),
            TracingLevel::VerboseTrace => write!(f, "Verbose Trace"),
        }
    }
}

impl TracingLevel {
    fn get_filter(&self) -> &'static str {
        match self {
            TracingLevel::Default => {
                if cfg!(debug_assertions) {
                    "info"
                } else {
                    "warn,irminsul=info,auto_artifactarium=info"
                }
            }
            TracingLevel::VerboseInfo => "info",
            TracingLevel::VerboseDebug => "debug",
            TracingLevel::VerboseTrace => "trace",
        }
    }
}

struct ReloadHandle(reload::Handle<EnvFilter, tracing_subscriber::Registry>);

impl ReloadHandle {
    pub fn set_filter(&mut self, filter: &str) {
        if let Err(e) = self.0.reload(filter) {
            tracing::warn!("Failed to set tracing filter to \"{filter}\": {e}");
        }
        tracing::info!("Set tracing filter to \"{filter}\"");
    }
}

impl Args {
    /// `(recording, export)` when this is a `--replay-export` run.
    fn replay_request(&self) -> Option<(&Path, &Path)> {
        let out = self.replay_export.as_deref()?;
        // clap requires SAVEFILE_PATH with --replay-export.
        Some((self.savefile_path.as_deref()?, out))
    }
}

fn main() -> eframe::Result {
    let args = Args::parse();

    // A replay is a command-line tool, not the app, and it goes before
    // anything the app does at startup: the single-instance lock (so it runs
    // beside a live Irminsul), the log rotation in the data directory (which
    // in a debug build would move the very recording being replayed), and the
    // elevation check. See `replay.rs` for what else it never does.
    if let Some((recording, out)) = args.replay_request() {
        let code = replay::run(recording, out);
        let _ = std::io::Write::flush(&mut std::io::stdout());
        std::process::exit(code);
    }

    let instance = single_instance::SingleInstance::new("irminsul_app_instance").unwrap();
    if !instance.is_single() {
        eprintln!("Another instance of Irminsul is already running.");
        std::process::exit(1);
    }

    let (_guard, reload_handle, previous_run_notice) = tracing_init().unwrap();

    if !args.no_admin && !args.read_from_file {
        #[cfg(any(windows, unix))]
        admin::ensure_admin();
    }

    let capture_source = if args.read_from_file {
        capture::CaptureSource::File(args.savefile_path.unwrap()) // Should be checked by clap
    } else {
        capture::CaptureSource::Device(args.savefile_path)
    };

    let capture_backend = args.capture_backend;

    // The background's 1600x1000 at half size, plus 20 px of height: the
    // panels had grown past 500 px.
    let window_size = [800., 520.];

    // Set by the UI once a self-update has been installed. The relaunch has to
    // happen out here, after `run_native` returns and `instance` is dropped:
    // the replacement process takes the same single-instance mutex on startup,
    // so spawning it from inside the running app made the child exit
    // immediately with "Another instance is already running".
    let restart_requested = Arc::new(AtomicBool::new(false));
    let app_restart_requested = Arc::clone(&restart_requested);

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(window_size)
            .with_resizable(false)
            .with_decorations(false)
            .with_icon(
                // NOTE: Adding an icon is optional
                eframe::icon_data::from_png_bytes(&include_bytes!("../assets/icon-256.png")[..])
                    .expect("Failed to load icon"),
            ),
        persist_window: false,
        ..Default::default()
    };
    let result = eframe::run_native(
        "Irminsul",
        native_options,
        Box::new(move |cc| {
            Ok(Box::new(app::IrminsulApp::new(
                cc,
                reload_handle,
                capture_backend,
                capture_source,
                app_restart_requested,
                previous_run_notice,
            )))
        }),
    );

    // Every orderly way out -- the close button, the tray's Quit, "Close
    // Irminsul" in the missed-launch modal, the update relaunch -- closes the
    // window and comes back here, so this is the one place the clean exit is
    // marked. Before the relaunch: the replacement reads this log at startup.
    let restart = restart_requested.load(Ordering::SeqCst);
    match &result {
        Err(e) => crash::mark_clean_exit(&format!("the window could not run: {e}")),
        Ok(()) if restart => crash::mark_clean_exit("restarting after an update"),
        Ok(()) => crash::mark_clean_exit("window closed"),
    }

    // Release the single-instance mutex before the replacement tries to take
    // it.
    drop(instance);

    if restart {
        // The command line is reproduced as faithfully as it can be. argv[0]
        // is deliberately *not* reused: it is whatever the launcher passed,
        // which can be a bare name or a path relative to a working directory
        // that no longer applies. argv[1..] on the other hand has to be carried
        // across -- without it a user who started
        // `irminsul-windows-pcap.exe -b pcap` came back on the pktmon default
        // after an update, and `--no-admin` and `-r <file>` replay mode were
        // dropped the same way.
        let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
        match std::env::current_exe() {
            Ok(exe) => match std::process::Command::new(&exe).args(&args).spawn() {
                Ok(_) => tracing::info!("relaunched {exe:?} with {args:?} after update"),
                Err(e) => tracing::error!("could not relaunch {exe:?} after update: {e}"),
            },
            Err(e) => tracing::error!("could not find the current executable to relaunch: {e}"),
        }
    }

    result
}

/// The root everything Irminsul writes for itself hangs off.
///
/// Release builds use the platform's per-application data directory, which is
/// where a user's installed copy should keep its state. Debug builds use the
/// working directory instead, so a `cargo run` drops its log, packet log and
/// pcapng trace next to the source being debugged rather than somewhere under
/// `AppData` that has to be hunted for -- and so a developer's traces never mix
/// with an installed copy's.
pub fn data_dir() -> Result<PathBuf> {
    if cfg!(debug_assertions) {
        let mut dir = std::env::current_dir().context("Working directory not found")?;
        dir.push("irminsul-data");
        return Ok(dir);
    }
    eframe::storage_dir(APP_ID).context("Storage dir not found")
}

/// Where every HTTP client Irminsul builds starts, so that all of them use
/// rustls.
///
/// reqwest is compiled with two TLS stacks: its default, native-tls, and
/// rustls, which `self_update` already uses for the release check. On Windows
/// native-tls is SChannel, and the first HTTPS request through it (the wish
/// URL check at startup, or the tracker key check) cost about 30 MB that
/// stayed for the life of the process, plus some 40 MB more for a moment while
/// Windows built the certificate chain. The same request through rustls costs
/// about 4 MB.
///
/// The root store is the operating system's certificates plus the bundled
/// Mozilla roots (both reqwest features are on in Cargo.toml), so a root the
/// user installed, for an antivirus that inspects HTTPS or a company proxy, is
/// trusted just as SChannel trusted it.
pub fn http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().use_rustls_tls()
}

fn log_dir() -> Result<PathBuf> {
    let mut dir = data_dir()?;
    dir.push("log");
    Ok(dir)
}

/// Where `monitor.rs` writes the raw packet log when the power tool is on.
///
/// One file per session, and every one of them is decrypted account data --
/// characters, inventory, achievements -- so an unbounded directory is a
/// privacy problem as much as a disk one. `monitor.rs` prunes it as it opens a
/// new session file; this is the startup sweep that also catches the files an
/// older build left behind (it wrote one *per command*) on a machine where raw
/// packet logging is never turned on again.
fn packet_log_dir() -> Result<PathBuf> {
    let mut dir = data_dir()?;
    dir.push("packet_log");
    Ok(dir)
}

fn open_log_dir() -> Result<()> {
    let dir = log_dir()?;
    open::that(dir)?;
    Ok(())
}

/// How many rotated files to keep, per kind.
const LOG_RETENTION: usize = 6;

/// How many logs of runs that did not exit cleanly (`*-abrupt.log`,
/// `*-crashed.log`) to keep, on a budget of their own: six ordinary restarts
/// must not be enough to delete the one log that shows what went wrong.
const KEPT_LOG_RETENTION: usize = 4;

/// Move `latest.<extension>` aside, renamed after its modification time with
/// `suffix` appended, and return where it went.
fn rotate_latest(log_dir: &Path, extension: &str, suffix: &str) -> Option<PathBuf> {
    let latest_path = log_dir.join(format!("latest.{extension}"));
    let Ok(modified) = std::fs::metadata(&latest_path).and_then(|metadata| metadata.modified())
    else {
        // Missing (first run) or unreadable: nothing to rotate either way.
        return None;
    };

    let dt: chrono::DateTime<chrono::Local> = modified.into();
    let new_path = log_dir.join(format!(
        "{}{suffix}.{extension}",
        dt.format("%Y-%m-%d_%H-%M-%S")
    ));
    std::fs::rename(&latest_path, &new_path).ok()?;
    Some(new_path)
}

/// Whether `name` is a log kept for a run that did not exit cleanly.
fn is_kept_log(name: &str, extension: &str) -> bool {
    [crash::KEPT_ABRUPT_SUFFIX, crash::KEPT_CRASHED_SUFFIX]
        .iter()
        .any(|suffix| name.ends_with(&format!("{suffix}.{extension}")))
}

/// Delete all but the newest [`LOG_RETENTION`] rotated `*.<extension>` files,
/// and all but the newest [`KEPT_LOG_RETENTION`] kept ones.
///
/// Each extension gets its own budget. Sharing one between `.log` and `.pcapng`
/// roughly halved the log history in debug builds — exactly when a developer
/// wants to compare several runs. `latest.*` is live, and `crash.log` is not a
/// rotated log at all.
fn prune_rotated(log_dir: &Path, extension: &str) {
    let latest_name = format!("latest.{extension}");

    let Ok(dir) = std::fs::read_dir(log_dir) else {
        return;
    };

    let mut rotated = Vec::new();
    let mut kept = Vec::new();
    for entry in dir.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some(extension) {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name == latest_name || name == crash::CRASH_LOG {
            continue;
        }
        let Ok(modified) = entry.metadata().and_then(|metadata| metadata.modified()) else {
            continue;
        };
        if is_kept_log(name, extension) {
            kept.push((path, modified));
        } else {
            rotated.push((path, modified));
        }
    }

    for (mut entries, retention) in [(rotated, LOG_RETENTION), (kept, KEPT_LOG_RETENTION)] {
        entries.sort_by_key(|(_, modified)| std::cmp::Reverse(*modified));
        for (path, _) in entries.into_iter().skip(retention) {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Rotate and prune everything under the log directories. `log_suffix` goes on
/// the rotated `latest.log` (see [`crash::RunEnd::kept_suffix`]); returns
/// where that log went.
fn rotate_logs(log_dir: &Path, log_suffix: &str) -> Option<PathBuf> {
    let rotated_log = rotate_latest(log_dir, "log", log_suffix);
    prune_rotated(log_dir, "log");

    // Not under `log_dir`, and nothing else sweeps it at startup. Keep the same
    // budget as monitor.rs's `PACKET_LOG_RETENTION`; the live file for this
    // session has not been created yet, so nothing in flight can be caught.
    if let Ok(packet_log_dir) = packet_log_dir() {
        prune_rotated(&packet_log_dir, "bin");
    }

    // Both the pcapng writer (monitor.rs) and its rotation are debug-only, so a
    // release build must not touch pcapng files at all: it used to quietly
    // delete captures left over from debug runs that a developer was keeping.
    #[cfg(debug_assertions)]
    {
        rotate_latest(log_dir, "pcapng", "");
        prune_rotated(log_dir, "pcapng");
    }

    rotated_log
}

/// Set up logging and crash reporting. Also returns the notice for the UI
/// when the previous run did not exit cleanly (see `crash.rs`).
fn tracing_init() -> Result<(
    tracing_appender::non_blocking::WorkerGuard,
    ReloadHandle,
    Option<String>,
)> {
    let dir = log_dir()?;
    std::fs::create_dir_all(&dir)?;
    // Before rotation moves it: how did the run that wrote latest.log end?
    let previous_run = crash::examine_previous_run(&dir);
    let rotated_log = rotate_logs(&dir, previous_run.kept_suffix());

    let file = crash::create_run_log(&dir)?;
    let (non_blocking_appender, guard) = tracing_appender::non_blocking(file);

    let filter = EnvFilter::new(TracingLevel::default().get_filter());
    let (filter, reload_handle) = reload::Layer::new(filter);
    let writer = tracing_subscriber::fmt::layer()
        .with_writer(non_blocking_appender)
        .with_ansi(false);
    tracing_subscriber::registry()
        .with(filter)
        .with(writer)
        .init();
    crash::install(&dir);
    tracing::info!("Tracing initialized and logging to file.");
    let notice = crash::report_previous_run(&previous_run, rotated_log.as_deref());

    Ok((guard, ReloadHandle(reload_handle), notice))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use clap::CommandFactory;

    use super::*;

    fn parse(args: &[&str]) -> Result<Args, clap::Error> {
        Args::try_parse_from(std::iter::once("irminsul").chain(args.iter().copied()))
    }

    #[test]
    fn the_command_line_definition_is_valid() {
        Args::command().debug_assert();
    }

    /// Every client goes through `http_client_builder`, which selects rustls
    /// with the OS roots added to the bundled ones; building one is where a
    /// missing reqwest feature or an unreadable OS store would show.
    #[test]
    fn the_http_client_builds_with_rustls_and_both_root_stores() {
        http_client_builder().build().unwrap();
    }

    /// No HTTP client may be built around `http_client_builder`: one that is
    /// gets reqwest's default TLS, SChannel on Windows, and its ~30 MB back.
    #[test]
    fn every_http_client_is_built_through_the_shared_builder() {
        for (name, source) in [
            ("monitor.rs", include_str!("monitor.rs")),
            ("wish.rs", include_str!("wish.rs")),
            ("update.rs", include_str!("update.rs")),
            ("app.rs", include_str!("app.rs")),
            ("replay.rs", include_str!("replay.rs")),
        ] {
            for forbidden in ["Client::builder()", "Client::new()", "reqwest::get("] {
                let code_lines = source
                    .lines()
                    .filter(|line| !line.trim_start().starts_with("//"))
                    .filter(|line| line.contains(forbidden))
                    .count();
                assert_eq!(
                    code_lines, 0,
                    "{name} builds an HTTP client with {forbidden}; use crate::http_client_builder()"
                );
            }
        }
    }

    #[test]
    fn replay_export_takes_the_export_path_and_the_recording() {
        let expected = Some((Path::new("latest.pcapng"), Path::new("out.json")));
        let args = parse(&["--replay-export", "out.json", "latest.pcapng"]).unwrap();
        assert_eq!(args.replay_request(), expected);
        let args = parse(&["latest.pcapng", "--replay-export=out.json"]).unwrap();
        assert_eq!(args.replay_request(), expected);
    }

    #[test]
    fn replay_export_needs_a_recording() {
        assert!(parse(&["--replay-export", "out.json"]).is_err());
    }

    #[test]
    fn replay_export_takes_no_capture_options() {
        // It reads the recording itself; a backend or -r would mean the app.
        assert!(parse(&["--replay-export", "o.json", "-r", "rec.pcapng"]).is_err());
        assert!(parse(&["--replay-export", "o.json", "-b", "pcap", "rec.pcapng"]).is_err());
    }

    #[test]
    fn the_app_modes_are_not_replays() {
        // Each of these starts the app, never the headless replay.
        for args in [
            &[][..],
            &["--no-admin"][..],
            &["-r", "rec.pcapng"][..],
            &["-b", "pcap", "template.pcap"][..],
        ] {
            let parsed = parse(args).unwrap();
            assert_eq!(parsed.replay_request(), None, "{args:?}");
        }
    }

    /// A fixed instant to age the fixtures relative to, so mtime ordering does
    /// not depend on how fast the filesystem is.
    const BASE: u64 = 1_700_000_000;

    /// Create `name` with an mtime `age_secs` in the past.
    fn write_aged(dir: &Path, name: &str, age_secs: u64) {
        let file = std::fs::File::create(dir.join(name)).unwrap();
        file.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(BASE - age_secs))
            .unwrap();
    }

    fn names_with_extension(dir: &Path, extension: &str) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(&format!(".{extension}")))
            .collect();
        names.sort();
        names
    }

    #[test]
    fn pruning_keeps_the_newest_files_of_one_kind_only() {
        let dir = tempfile::tempdir().unwrap();

        // Ten rotated logs, `log-0` the newest.
        for i in 0..10u64 {
            write_aged(dir.path(), &format!("log-{i}.log"), i);
        }
        // Ten rotated captures, which must not be touched by the .log budget.
        for i in 0..10u64 {
            write_aged(dir.path(), &format!("cap-{i}.pcapng"), i);
        }

        prune_rotated(dir.path(), "log");

        let logs = names_with_extension(dir.path(), "log");
        assert_eq!(logs.len(), LOG_RETENTION, "kept {logs:?}");
        for i in 0..LOG_RETENTION as u64 {
            assert!(logs.contains(&format!("log-{i}.log")), "kept {logs:?}");
        }

        assert_eq!(
            names_with_extension(dir.path(), "pcapng").len(),
            10,
            "the two kinds must not share a retention budget"
        );
    }

    #[test]
    fn pruning_bounds_the_raw_packet_log_without_touching_the_text_logs() {
        // `rotate_logs` swept only `log_dir()`, so `packet_log` grew forever --
        // one file per session now, one per *command* in builds before that.
        let dir = tempfile::tempdir().unwrap();

        for i in 0..40u64 {
            write_aged(dir.path(), &format!("2024-01-01_00-00-{i:02}.bin"), i);
        }
        write_aged(dir.path(), "latest.log", 100);

        prune_rotated(dir.path(), "bin");

        let kept = names_with_extension(dir.path(), "bin");
        assert_eq!(kept.len(), LOG_RETENTION, "kept {kept:?}");
        assert!(
            kept.contains(&"2024-01-01_00-00-00.bin".to_string()),
            "{kept:?}"
        );
        assert!(
            !kept.contains(&"2024-01-01_00-00-39.bin".to_string()),
            "{kept:?}"
        );
        assert!(dir.path().join("latest.log").exists());
    }

    #[test]
    fn pruning_never_deletes_the_live_file() {
        let dir = tempfile::tempdir().unwrap();

        // `latest.log` is deliberately the oldest, so a budget that counted it
        // would delete it first.
        write_aged(dir.path(), "latest.log", 1_000);
        for i in 0..10u64 {
            write_aged(dir.path(), &format!("log-{i}.log"), i);
        }

        prune_rotated(dir.path(), "log");

        assert!(dir.path().join("latest.log").exists());
    }

    #[test]
    fn rotating_renames_the_live_file_and_is_a_no_op_without_one() {
        let dir = tempfile::tempdir().unwrap();

        // No latest.log yet: the first run must not fail or invent a file.
        assert_eq!(rotate_latest(dir.path(), "log", ""), None);
        assert!(names_with_extension(dir.path(), "log").is_empty());

        write_aged(dir.path(), "latest.log", 0);
        let rotated = rotate_latest(dir.path(), "log", "").unwrap();

        assert!(!dir.path().join("latest.log").exists());
        assert_eq!(names_with_extension(dir.path(), "log").len(), 1);
        assert!(rotated.exists());
    }

    #[test]
    fn the_log_of_a_run_that_ended_abruptly_is_rotated_under_its_own_name() {
        let dir = tempfile::tempdir().unwrap();
        write_aged(dir.path(), "latest.log", 0);

        let rotated = rotate_latest(dir.path(), "log", crash::KEPT_ABRUPT_SUFFIX).unwrap();

        let name = rotated.file_name().unwrap().to_str().unwrap();
        assert!(name.ends_with("-abrupt.log"), "{name}");
        assert!(is_kept_log(name, "log"));
        assert!(!is_kept_log("2026-10-06_14-39-41.log", "log"));
    }

    #[test]
    fn kept_logs_and_crash_log_outlive_ordinary_rotation() {
        let dir = tempfile::tempdir().unwrap();

        // The run that went wrong, then ten ordinary ones after it.
        write_aged(dir.path(), "2026-10-06_14-39-41-abrupt.log", 100);
        write_aged(dir.path(), crash::CRASH_LOG, 200);
        for i in 0..10u64 {
            write_aged(dir.path(), &format!("log-{i}.log"), i);
        }

        prune_rotated(dir.path(), "log");

        assert!(dir.path().join("2026-10-06_14-39-41-abrupt.log").exists());
        assert!(dir.path().join(crash::CRASH_LOG).exists());
        assert_eq!(
            names_with_extension(dir.path(), "log").len(),
            LOG_RETENTION + 2
        );
    }

    #[test]
    fn kept_logs_have_a_budget_of_their_own() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..10u64 {
            let suffix = if i % 2 == 0 {
                crash::KEPT_ABRUPT_SUFFIX
            } else {
                crash::KEPT_CRASHED_SUFFIX
            };
            write_aged(dir.path(), &format!("kept-{i}{suffix}.log"), i);
        }

        prune_rotated(dir.path(), "log");

        let kept = names_with_extension(dir.path(), "log");
        assert_eq!(kept.len(), KEPT_LOG_RETENTION, "{kept:?}");
        assert!(kept.contains(&"kept-0-abrupt.log".to_string()), "{kept:?}");
        assert!(kept.contains(&"kept-3-crashed.log".to_string()), "{kept:?}");
    }
}
