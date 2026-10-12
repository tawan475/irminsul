//! The game's web cache: the second source of wish keys.
//!
//! When the game's wish history page opens, its web view caches the page's
//! requests -- the game's own link, key included -- in
//! `<game>/<…>_Data/webCaches/<version>/Cache/Cache_Data/data_2`. The key
//! lasts about a day, so a link found there works for the rest of it even
//! when Irminsul did not see the key in the traffic (it was not running, or
//! not decrypting). A link is trusted only once ONE request to the game's
//! server says it works; a key from the traffic always wins over it.
//!
//! The game's folder comes from its log (`output_log.txt` or `Player.log`
//! under `AppData/LocalLow/miHoYo/<Genshin Impact|原神>`): the newest log
//! that names it. The game rewrites its log when it starts and names its
//! folder a few seconds later, so the folder found last is kept meanwhile.
//! The game keeps these files open; they are read without locking them
//! (`std::fs` opens with read, write and delete sharing on Windows).
//!
//! The log never gets a URL, a key or a path under the user's profile from
//! here: only which log was read and what came of the cache.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime};

use async_watcher::notify::{RecommendedWatcher, RecursiveMode};
use async_watcher::{AsyncDebouncer, DebouncedEvent};
use regex::bytes::Regex;
use tokio::sync::{mpsc, oneshot};

use super::WishHub;
use super::gacha_log::{KeySource, Probe, WishKey, probe};

/// The game's data folder as its log names it: `X:/…/GenshinImpact_Data`
/// (global) or `…/YuanShen_Data` (Chinese client), with either slash. The
/// tracker's `wish-url.ps1` pattern, plus a word boundary before the drive
/// letter so a URL's `https://` is not taken for a drive. On bytes, so a
/// folder name in any script (UTF-8) is kept whole.
static GAME_DATA_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?-u)\b[A-Za-z]:[\\/][^\r\n:*?"<>|]*?(?:GenshinImpact_Data|YuanShen_Data)"#)
        .expect("the game data pattern is a compile-time constant")
});

/// A wish history link in the web cache: the tracker's
/// `WISH_CACHE_URL_PATTERN`. Printable ASCII only, so the binary around it
/// ends it; it ends at `game_biz`'s value, as the game writes it last.
static WISH_LINK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u)https://[!-~]+?webview_gacha[!-~]*?game_biz=[A-Za-z0-9_]+")
        .expect("the wish link pattern is a compile-time constant")
});

/// The clients' folders under `AppData/LocalLow/miHoYo`: global, Chinese.
const CLIENT_DIRS: [&str; 2] = ["Genshin Impact", "原神"];

/// The logs the game writes there.
const LOG_NAMES: [&str; 2] = ["output_log.txt", "Player.log"];

/// The web view's cache file under a `webCaches/<version>` folder.
const CACHE_FILE: [&str; 3] = ["Cache", "Cache_Data", "data_2"];

/// Whole-request timeout for the one check of a cached link.
const CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// Connect timeout for the same check.
const CHECK_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Why no link came from the cache. Its text is what the UI says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Miss {
    NoLog,
    NoGameFolder,
    NoCache,
    NoLink,
    /// The cache file could not be read (the kind of I/O error).
    Unreadable(String),
}

impl fmt::Display for Miss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoLog => write!(f, "the game's log is not on this PC"),
            Self::NoGameFolder => write!(f, "the game's log does not name its folder"),
            Self::NoCache => write!(f, "the game's web cache is empty"),
            Self::NoLink => write!(f, "the game's web cache holds no wish link"),
            Self::Unreadable(why) => write!(f, "the game's web cache could not be read ({why})"),
        }
    }
}

/// The game's data folder named in a log's contents: the first one.
pub(crate) fn data_dir_in_log(log: &[u8]) -> Option<PathBuf> {
    let found = GAME_DATA_RE.find(log)?;
    let text = String::from_utf8_lossy(found.as_bytes());
    Some(PathBuf::from(text.as_ref()))
}

/// The wish link in a cache file's contents: the last `getGachaLog` link
/// with a key, else the last link of any kind with one (the history page's
/// own, which carries the same key).
pub(crate) fn wish_link_in_cache(cache: &[u8]) -> Option<String> {
    let mut api = None;
    let mut any = None;
    for found in WISH_LINK_RE.find_iter(cache) {
        // Printable ASCII by the pattern.
        let link = String::from_utf8_lossy(found.as_bytes());
        if !link.contains("authkey=") {
            continue;
        }
        if link.contains("/getGachaLog?") {
            api = Some(link.clone().into_owned());
        }
        any = Some(link.into_owned());
    }
    api.or(any)
}

/// The newest `webCaches/<version>` folder's cache file under `data_dir`
/// that exists.
pub(crate) fn newest_cache_file(data_dir: &Path) -> Option<PathBuf> {
    let mut versions: Vec<(SystemTime, PathBuf)> = std::fs::read_dir(data_dir.join("webCaches"))
        .ok()?
        .flatten()
        .filter_map(|entry| {
            let metadata = entry.metadata().ok()?;
            if !metadata.is_dir() {
                return None;
            }
            Some((metadata.modified().ok()?, entry.path()))
        })
        .collect();
    // Newest first; the higher version first on a tie.
    versions.sort_by(|a, b| b.cmp(a));
    versions.into_iter().find_map(|(_, dir)| {
        let file = CACHE_FILE.iter().fold(dir, |path, part| path.join(part));
        file.is_file().then_some(file)
    })
}

/// The log files the game may write, for each user profile root.
fn log_candidates(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut logs = Vec::new();
    for root in roots {
        for client in CLIENT_DIRS {
            let dir = root
                .join("AppData")
                .join("LocalLow")
                .join("miHoYo")
                .join(client);
            for name in LOG_NAMES {
                logs.push(dir.join(name));
            }
        }
    }
    logs
}

/// `<client folder>/<file>`: which log, without the profile path.
fn log_label(log: &Path) -> String {
    let name = log.file_name().unwrap_or_default().to_string_lossy();
    let client = log
        .parent()
        .and_then(Path::file_name)
        .unwrap_or_default()
        .to_string_lossy();
    format!("{client}/{name}")
}

/// `(mtime, len)` of `path`.
fn signature(path: &Path) -> Option<(SystemTime, u64)> {
    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.modified().ok()?, metadata.len()))
}

/// A link found in the cache, and how old the cache file is.
#[derive(Clone, Debug)]
pub(crate) struct FoundLink {
    pub(crate) url: String,
    pub(crate) age: Duration,
}

/// Finds the cache file through the game's logs.
pub(crate) struct CacheReader {
    logs: Vec<PathBuf>,
    /// The game's folder, as the last log that named one named it.
    data_dir: Option<PathBuf>,
    /// The newest log and its length when the folder was read from it.
    log_read: Option<(PathBuf, u64)>,
    /// The cache file found last.
    found: Option<PathBuf>,
}

impl CacheReader {
    pub(crate) fn new(roots: &[PathBuf]) -> Self {
        Self {
            logs: log_candidates(roots),
            data_dir: None,
            log_read: None,
            found: None,
        }
    }

    /// A reader that knows the game's folder already (tests).
    #[cfg(test)]
    pub(crate) fn for_data_dir(data_dir: PathBuf) -> Self {
        Self {
            logs: Vec::new(),
            data_dir: Some(data_dir),
            log_read: None,
            found: None,
        }
    }

    /// The folders the logs live in.
    fn log_dirs(&self) -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = self
            .logs
            .iter()
            .filter_map(|log| log.parent().map(Path::to_path_buf))
            .collect();
        dirs.dedup();
        dirs
    }

    fn is_log(&self, path: &Path) -> bool {
        self.logs.iter().any(|log| log == path)
    }

    /// The logs that exist with their length, newest first.
    fn existing_logs(&self) -> Vec<(PathBuf, u64)> {
        let mut logs: Vec<(SystemTime, PathBuf, u64)> = self
            .logs
            .iter()
            .filter_map(|log| {
                let metadata = std::fs::metadata(log).ok()?;
                if !metadata.is_file() {
                    return None;
                }
                Some((metadata.modified().ok()?, log.clone(), metadata.len()))
            })
            .collect();
        logs.sort_by_key(|(modified, _, _)| std::cmp::Reverse(*modified));
        logs.into_iter().map(|(_, log, len)| (log, len)).collect()
    }

    /// Find the game's folder: read the logs again only when the newest one
    /// is another file or was rewritten (shorter), or no folder is known.
    /// `Err` only when no folder is known at all.
    pub(crate) fn locate(&mut self) -> Result<PathBuf, Miss> {
        let logs = self.existing_logs();
        let newest = logs.first().cloned();
        let reread = self.data_dir.is_none()
            || match (&self.log_read, &newest) {
                (Some((read, read_len)), Some((log, len))) => read != log || len < read_len,
                (None, Some(_)) => true,
                (_, None) => false,
            };
        if reread {
            let found = logs.iter().find_map(|(log, _)| {
                let bytes = std::fs::read(log).ok()?;
                data_dir_in_log(&bytes).map(|dir| (dir, log))
            });
            match found {
                Some((dir, log)) => {
                    if self.data_dir.as_ref() != Some(&dir) {
                        tracing::info!(log = %log_label(log), "wish cache: the game's log names its folder");
                    }
                    self.data_dir = Some(dir);
                    self.log_read = newest;
                }
                None => tracing::debug!(
                    "wish cache: no log names the game's folder (yet); keeping the last one"
                ),
            }
        }
        match &self.data_dir {
            Some(dir) => Ok(dir.clone()),
            None if logs.is_empty() => Err(Miss::NoLog),
            None => Err(Miss::NoGameFolder),
        }
    }

    /// The cache file to read.
    pub(crate) fn cache_file(&mut self) -> Result<PathBuf, Miss> {
        let dir = self.locate()?;
        let file = newest_cache_file(&dir).ok_or(Miss::NoCache)?;
        self.found = Some(file.clone());
        Ok(file)
    }

    /// The link in `file`.
    pub(crate) fn read_link(file: &Path) -> Result<FoundLink, Miss> {
        let bytes =
            std::fs::read(file).map_err(|error| Miss::Unreadable(error.kind().to_string()))?;
        let url = wish_link_in_cache(&bytes).ok_or(Miss::NoLink)?;
        let age = std::fs::metadata(file)
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| SystemTime::now().duration_since(modified).ok())
            .unwrap_or_default();
        Ok(FoundLink { url, age })
    }
}

/// What the cache shows, for the UI's "seen" list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum CacheState {
    /// No link (or not looked yet).
    #[default]
    None,
    /// A link, not checked: a key from the game is in use, or the check got
    /// no answer.
    Found,
    /// The game's server said the link works.
    Valid,
    /// The link's key expired.
    Expired,
    /// The game's server refused the link otherwise.
    Refused,
}

impl CacheState {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Found => "found",
            Self::Valid => "valid",
            Self::Expired => "expired",
            Self::Refused => "refused",
        }
    }
}

/// What a check of one link came to; kept so a link is checked once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Checked {
    Valid,
    Expired,
    Refused(i64),
}

/// A request from the UI: look now; answered with the wish URL or why not.
pub(crate) type CacheReply = oneshot::Sender<Result<String, String>>;

/// The cache source task: looks on start, when the logs or the cache file
/// change, and when the UI asks.
pub(crate) struct CacheSource {
    hub: WishHub,
    reader: CacheReader,
    http: reqwest::Client,
    /// Where checks go instead of the key's own endpoint (tests).
    endpoint: Option<String>,
    requests: mpsc::UnboundedReceiver<CacheReply>,
    /// The last link checked and what came of it. Memory only.
    checked: Option<(String, Checked)>,
    /// The cache file's `(path, mtime, len)` when last read.
    read: Option<(PathBuf, (SystemTime, u64))>,
    /// The last thing logged, so a file that keeps changing does not repeat
    /// it.
    reported: Option<String>,
}

impl CacheSource {
    pub(crate) fn new(hub: WishHub, requests: mpsc::UnboundedReceiver<CacheReply>) -> Self {
        let roots = user_profile_roots().unwrap_or_else(|error| {
            tracing::info!("wish cache unavailable: {error}");
            Vec::new()
        });
        Self::with_reader(hub, requests, CacheReader::new(&roots))
    }

    pub(crate) fn with_reader(
        hub: WishHub,
        requests: mpsc::UnboundedReceiver<CacheReply>,
        reader: CacheReader,
    ) -> Self {
        let http = crate::http_client_builder()
            .timeout(CHECK_TIMEOUT)
            .connect_timeout(CHECK_CONNECT_TIMEOUT)
            .build()
            .expect("the TLS backend must initialise for any HTTP request to work");
        Self {
            hub,
            reader,
            http,
            endpoint: None,
            requests,
            checked: None,
            read: None,
            reported: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(mut self, endpoint: String) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    /// Log `what` (info) unless it was the last thing logged.
    fn report(&mut self, what: String) {
        if self.reported.as_ref() != Some(&what) {
            tracing::info!("wish cache: {what}");
            self.reported = Some(what);
        }
    }

    fn miss(&mut self, miss: Miss) -> String {
        self.hub.see_cache(CacheState::None);
        self.report(miss.to_string());
        miss.to_string()
    }

    /// Look at the cache now: the wish URL in use afterwards, or why there
    /// is none.
    pub(crate) async fn look(&mut self) -> Result<String, String> {
        let file = match self.reader.cache_file() {
            Ok(file) => file,
            Err(miss) => return Err(self.miss(miss)),
        };
        let file_signature = signature(&file);
        let link = match CacheReader::read_link(&file) {
            Ok(link) => link,
            Err(miss) => {
                if !matches!(miss, Miss::Unreadable(_)) {
                    self.read = file_signature.map(|signature| (file.clone(), signature));
                }
                return Err(self.miss(miss));
            }
        };
        self.read = file_signature.map(|signature| (file.clone(), signature));

        let now = Instant::now();
        let Some(key) = WishKey::from_game_link(&link.url, link.age, now) else {
            return Err(self.miss(Miss::NoLink));
        };
        if let Some(held) = self.hub.held_key(now) {
            if held.same_key(&key) {
                self.hub.see_cache(CacheState::Valid);
                self.report("the cached link holds the key in use".to_owned());
                return Ok(held.wish_url());
            }
            if held.source() == KeySource::Game {
                // A key from the traffic always wins: no request for this one.
                self.hub.see_cache(CacheState::Found);
                self.report(
                    "found a wish link; the key from the game's traffic is used instead".to_owned(),
                );
                return Ok(held.wish_url());
            }
        }

        let before = match &self.checked {
            Some((url, checked)) if *url == link.url => Some(*checked),
            _ => None,
        };
        let checked = match before {
            // Taken before and gone since: the sync found it expired.
            Some(Checked::Valid) => Checked::Expired,
            Some(checked) => checked,
            None => {
                self.report("found a wish link; checking it with the game's server".to_owned());
                let endpoint = self
                    .endpoint
                    .clone()
                    .unwrap_or_else(|| key.endpoint().to_owned());
                match probe(&self.http, &endpoint, &key).await {
                    Probe::Valid => Checked::Valid,
                    Probe::Expired => Checked::Expired,
                    Probe::Refused(retcode) => Checked::Refused(retcode),
                    Probe::Failed(why) => {
                        // Not remembered: the next look checks again.
                        self.hub.see_cache(CacheState::Found);
                        self.report(format!("could not check the cached link: {why}"));
                        return Err(format!(
                            "could not check the link in the game's cache ({why})"
                        ));
                    }
                }
            }
        };
        self.checked = Some((link.url, checked));
        match checked {
            Checked::Valid => {
                self.hub.see_cache(CacheState::Valid);
                let taken = self.hub.offer_cached(key, now);
                self.report(format!(
                    "the cached link works{}",
                    if taken { "; using its key" } else { "" }
                ));
                self.hub
                    .held_key(now)
                    .map(|held| held.wish_url())
                    .ok_or_else(|| "the link in the game's cache expired".to_owned())
            }
            Checked::Expired => {
                self.hub.see_cache(CacheState::Expired);
                self.report("the cached link expired".to_owned());
                Err("the link in the game's cache expired".to_owned())
            }
            Checked::Refused(retcode) => {
                self.hub.see_cache(CacheState::Refused);
                self.report(format!(
                    "the game's server refused the cached link ({retcode})"
                ));
                Err("the game's server refused the link in its cache".to_owned())
            }
        }
    }

    /// The logs or the cache changed: look again, unless the cache file is
    /// the one read last, unchanged.
    async fn on_change(&mut self) {
        if let Ok(file) = self.reader.cache_file()
            && let Some(now) = signature(&file)
            && self.read.as_ref() == Some(&(file, now))
        {
            return;
        }
        let _ = self.look().await;
    }

    /// Run until the UI's end of the request channel is gone.
    pub(crate) async fn run(mut self) {
        let (mut debouncer, mut events) =
            match AsyncDebouncer::<RecommendedWatcher>::new_with_channel(
                Duration::from_secs(1),
                Some(Duration::from_secs(1)),
            )
            .await
            {
                Ok((debouncer, events)) => (Some(debouncer), Some(events)),
                Err(error) => {
                    tracing::info!(
                        "wish cache: cannot watch files ({error}); looking on start and on demand only"
                    );
                    (None, None)
                }
            };
        if let Some(debouncer) = &mut debouncer {
            for dir in self.reader.log_dirs() {
                if dir.is_dir() {
                    let _ = debouncer.watcher().watch(&dir, RecursiveMode::NonRecursive);
                }
            }
        }

        let _ = self.look().await;
        let mut watched: Option<PathBuf> = None;
        loop {
            // The cache file is watched by itself: a new game version makes a
            // new `webCaches` folder.
            if let Some(debouncer) = &mut debouncer
                && watched != self.reader.found
            {
                if let Some(old) = watched.take() {
                    let _ = debouncer.watcher().unwatch(&old);
                }
                if let Some(new) = &self.reader.found
                    && debouncer
                        .watcher()
                        .watch(new, RecursiveMode::NonRecursive)
                        .is_ok()
                {
                    watched = Some(new.clone());
                }
            }
            tokio::select! {
                request = self.requests.recv() => match request {
                    Some(reply) => {
                        let answer = self.look().await;
                        let _ = reply.send(answer);
                    }
                    None => break,
                },
                batch = next_events(&mut events) => match batch {
                    Some(Ok(batch)) => {
                        if self.relevant(&batch) {
                            self.on_change().await;
                        }
                    }
                    Some(Err(errors)) => tracing::debug!(?errors, "wish cache: watch errors"),
                    None => events = None,
                },
            }
        }
    }

    fn relevant(&self, batch: &[DebouncedEvent]) -> bool {
        batch.iter().any(|event| {
            self.reader.is_log(&event.path)
                || self.reader.found.as_deref() == Some(event.path.as_path())
        })
    }
}

type Events = mpsc::Receiver<Result<Vec<DebouncedEvent>, Vec<async_watcher::notify::Error>>>;

/// The next batch of file events; never, without a watcher.
async fn next_events(
    events: &mut Option<Events>,
) -> Option<Result<Vec<DebouncedEvent>, Vec<async_watcher::notify::Error>>> {
    match events {
        Some(events) => events.recv().await,
        None => std::future::pending().await,
    }
}

/// Roots holding an `AppData/LocalLow` tree for a Genshin client.
#[cfg(windows)]
fn user_profile_roots() -> anyhow::Result<Vec<PathBuf>> {
    use anyhow::Context as _;
    let user_profile = std::env::var("userprofile").context("could not find userprofile var")?;
    Ok(vec![PathBuf::from(user_profile)])
}

/// Roots holding an `AppData/LocalLow` tree for a Genshin client.
///
/// There is no native Linux client: the game runs under Proton or Wine, so the
/// Windows user profile lives inside a prefix at `<prefix>/drive_c/users/<user>`.
#[cfg(target_os = "linux")]
fn user_profile_roots() -> anyhow::Result<Vec<PathBuf>> {
    use anyhow::Context as _;
    let home = PathBuf::from(std::env::var("HOME").context("could not find HOME var")?);

    let mut prefixes = vec![home.join(".wine")];
    if let Ok(prefix) = std::env::var("WINEPREFIX") {
        prefixes.push(PathBuf::from(prefix));
    }

    // Steam gives every Proton game its own prefix under compatdata/<app id>.
    for steam_root in [
        ".steam/steam",
        ".local/share/Steam",
        ".var/app/com.valvesoftware.Steam/.local/share/Steam",
    ] {
        let compatdata = home.join(steam_root).join("steamapps/compatdata");
        let Ok(entries) = std::fs::read_dir(&compatdata) else {
            continue;
        };
        for entry in entries.flatten() {
            prefixes.push(entry.path().join("pfx"));
        }
    }

    let login_name = std::env::var("USER").ok();
    let mut roots = Vec::new();
    for prefix in prefixes {
        let users = prefix.join("drive_c/users");
        // Proton always names the profile "steamuser"; a hand-rolled Wine
        // prefix uses the login name.
        roots.push(users.join("steamuser"));
        if let Some(login_name) = &login_name {
            roots.push(users.join(login_name));
        }
    }

    Ok(roots)
}

/// The web cache is a Windows-client thing; there is no Genshin client for
/// this platform to read a log from.
#[cfg(not(any(windows, target_os = "linux")))]
fn user_profile_roots() -> anyhow::Result<Vec<PathBuf>> {
    Err(anyhow::anyhow!(
        "the game's web cache is only read on Windows, and on Linux through a Proton/Wine prefix"
    ))
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;
