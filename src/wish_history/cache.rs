//! The game's web cache: the link Copy wish URL falls back on.
//!
//! When the game's wish history page opens, its web view caches the page's
//! requests -- the game's own link, key included -- in
//! `<game>/<…>_Data/webCaches/<version>/Cache/Cache_Data/data_2`. The cache
//! is the PC's, not the login's: with several accounts on one PC the link
//! there may be another account's. So it is never a key for the sync (that
//! only takes a key the traffic shows after a login) and is not even checked
//! with the game's server; it is read only when the user asks for the wish
//! URL (Copy, paimon.moe, StarDB) while no key of this login is held.
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
use std::time::SystemTime;

use regex::bytes::Regex;
use tokio::sync::{mpsc, oneshot};

use super::WishHub;

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

/// Finds the cache file through the game's logs.
pub(crate) struct CacheReader {
    logs: Vec<PathBuf>,
    /// The game's folder, as the last log that named one named it.
    data_dir: Option<PathBuf>,
    /// The newest log and its length when the folder was read from it.
    log_read: Option<(PathBuf, u64)>,
}

impl CacheReader {
    pub(crate) fn new(roots: &[PathBuf]) -> Self {
        Self {
            logs: log_candidates(roots),
            data_dir: None,
            log_read: None,
        }
    }

    /// A reader that knows the game's folder already (tests).
    #[cfg(test)]
    pub(crate) fn for_data_dir(data_dir: PathBuf) -> Self {
        Self {
            logs: Vec::new(),
            data_dir: Some(data_dir),
            log_read: None,
        }
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
        newest_cache_file(&dir).ok_or(Miss::NoCache)
    }

    /// The link in `file`.
    pub(crate) fn read_link(file: &Path) -> Result<String, Miss> {
        let bytes =
            std::fs::read(file).map_err(|error| Miss::Unreadable(error.kind().to_string()))?;
        wish_link_in_cache(&bytes).ok_or(Miss::NoLink)
    }

    /// The link in the cache now.
    pub(crate) fn find(&mut self) -> Result<String, Miss> {
        let file = self.cache_file()?;
        Self::read_link(&file)
    }
}

/// What the cache showed when last read, for the UI's "seen" list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum CacheState {
    /// No link (or not looked yet).
    #[default]
    None,
    /// A link; whose, the cache does not say.
    Found,
}

impl CacheState {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Found => "found (may be another account)",
        }
    }
}

/// A request from the UI: read the cache now; answered with the link or why
/// there is none.
pub(crate) type CacheReply = oneshot::Sender<Result<String, String>>;

/// Answers the UI's requests for the cached link. Sends nothing anywhere.
pub(crate) struct CacheSource {
    hub: WishHub,
    reader: CacheReader,
    requests: mpsc::UnboundedReceiver<CacheReply>,
    /// The last thing logged, so asking again does not repeat it.
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
        Self {
            hub,
            reader,
            requests,
            reported: None,
        }
    }

    /// Log `what` (info) unless it was the last thing logged.
    fn report(&mut self, what: String) {
        if self.reported.as_ref() != Some(&what) {
            tracing::info!("wish cache: {what}");
            self.reported = Some(what);
        }
    }

    /// Read the cache now: the link, or why there is none.
    pub(crate) fn look(&mut self) -> Result<String, String> {
        match self.reader.find() {
            Ok(link) => {
                self.hub.see_cache(CacheState::Found);
                self.report(
                    "found a wish link (for Copy only; it may be another account's)".to_owned(),
                );
                Ok(link)
            }
            Err(miss) => {
                self.hub.see_cache(CacheState::None);
                self.report(miss.to_string());
                Err(miss.to_string())
            }
        }
    }

    /// Answer requests until the UI's end of the channel is gone.
    pub(crate) async fn run(mut self) {
        while let Some(reply) = self.requests.recv().await {
            let answer = self.look();
            let _ = reply.send(answer);
        }
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
