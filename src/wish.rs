// Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex "&{$((New-Object System.Net.WebClient).DownloadString('https://gist.github.com/MadeBaruna/1d75c1d37d19eca71591ec8a31178235/raw/getlink.ps1'))} global"

use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow};
// RecommendedWatcher is ReadDirectoryChangesWatcher on Windows, and INotifyWatcher on Linux
use async_watcher::notify::{RecommendedWatcher, RecursiveMode};
use async_watcher::{AsyncDebouncer, DebouncedEvent};
use regex::Regex;
use reqwest::Url;
use serde::Deserialize;
use tokio::fs;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{mpsc, watch};

/// Matches the gacha-log URL that the in-game web view leaves in its HTTP
/// cache.
///
/// The trailing `[A-Za-z0-9_]+` matters: without it the capture stops right
/// after `game_biz=` and the URL handed to the user carries an empty
/// `game_biz` value.
///
/// Compiled once — this used to be rebuilt on every debounced log event.
static WISH_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(https.+?webview_gacha.+?game_biz=[A-Za-z0-9_]+)")
        .expect("the wish url regex is a compile-time constant")
});

/// Matches the game's data directory as printed by the client into
/// `output_log.txt`.
static GAME_DATA_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m).:[/\\].+(GenshinImpact_Data|YuanShen_Data)")
        .expect("the game data regex is a compile-time constant")
});

/// Whole-request timeout for the gacha-log validation probe.
///
/// `reqwest::get` (and any client built without this) has no timeout at all,
/// so a blackholed or half-open `hk4e-api-os.hoyoverse.com` used to wedge the
/// spawned `force_find_url` task for the life of the process: its oneshot is
/// never answered and the wish button stays disabled for the rest of the
/// session with nothing for the user to act on.
const VALIDATE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Connect timeout for the same probe. Separate from the whole-request timeout
/// so an unreachable host fails in five seconds rather than ten.
const VALIDATE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The client every validation request goes through.
///
/// Built once: clones share its connection pool, and building it here is what
/// puts the timeouts above on the request. `build` only fails if the TLS
/// backend cannot initialise, which is exactly when `reqwest::Client::new`
/// panics too.
static HTTP: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(VALIDATE_REQUEST_TIMEOUT)
        .connect_timeout(VALIDATE_CONNECT_TIMEOUT)
        .build()
        .expect("the TLS backend must initialise for any HTTP request to work")
});

/// Query parameters of the gacha URL that carry the credential, or that only
/// make sense together with it. Blanked out before the URL is logged.
const CREDENTIAL_QUERY_PARAMS: [&str; 3] = ["authkey", "sign_type", "authkey_ver"];

/// Locations of `output_log.txt` relative to a Windows user profile, newest
/// client first. The second entry is the Chinese client, which is also what
/// makes the `YuanShen_Data` branch of [`GAME_DATA_RE`] reachable.
const OUTPUT_LOG_RELATIVE_PATHS: [&str; 2] = [
    "AppData/LocalLow/miHoYo/Genshin Impact/output_log.txt",
    "AppData/LocalLow/miHoYo/原神/output_log.txt",
];

pub struct Wish {
    url_tx: watch::Sender<Option<String>>,
    output_log_path: PathBuf,
    web_cache_path: Option<PathBuf>,
    /// `(mtime, len)` of `web_cache_path` as of the last successful read, used
    /// to skip re-reading a cache file that has not moved.
    cache_signature: Option<(SystemTime, u64)>,
    debouncer: AsyncDebouncer<RecommendedWatcher>,
    file_events: mpsc::Receiver<Result<Vec<DebouncedEvent>, Vec<async_watcher::notify::Error>>>,
    prev_url: String,
}

impl Wish {
    pub async fn new(url_tx: watch::Sender<Option<String>>) -> Result<Self> {
        let output_log_path = output_log_path()?;
        let (debouncer, file_events) =
            AsyncDebouncer::new_with_channel(Duration::from_secs(1), Some(Duration::from_secs(1)))
                .await?;
        Ok(Self {
            url_tx,
            output_log_path,
            web_cache_path: None,
            cache_signature: None,
            debouncer,
            file_events,
            prev_url: String::new(),
        })
    }

    pub async fn monitor(&mut self) -> Result<()> {
        // Resolved once in `new()`; re-deriving it here would re-stat every
        // candidate path on a value that cannot change while we run.
        let output_log_path = self.output_log_path.clone();

        self.debouncer
            .watcher()
            .watch(&output_log_path, RecursiveMode::NonRecursive)?;

        if let Err(e) = self.handle_log_update().await {
            tracing::info!("handle log didn't find web cache dir: {e}");
        }

        while let Some(Ok(events)) = self.file_events.recv().await {
            for event in events {
                if event.path == output_log_path {
                    if let Err(e) = self.handle_log_update().await {
                        tracing::info!("handle log didn't find web cache dir: {e}");
                    }
                } else if self.web_cache_path.as_deref() == Some(event.path.as_path())
                    && let Err(e) = self.handle_web_cache_dir_update().await
                {
                    tracing::info!("no url found in web cache dir: {e}");
                }
            }
        }

        Ok(())
    }

    async fn handle_log_update(&mut self) -> Result<()> {
        tracing::debug!("output log path changed");

        let web_cache_path = self.get_web_cache_path().await?;

        if self.web_cache_path.as_deref() == Some(web_cache_path.as_path()) {
            // Same cache file as last time, which is the overwhelmingly common
            // case. Re-registering the watch would only risk losing events in
            // the gap between unwatch and watch.
            tracing::debug!("cache dir {web_cache_path:?} unchanged, keeping the existing watch");
        } else {
            // Unwatch the old path if we were previously watching to avoid
            // leaking watchers.
            if let Some(old_cache_path) = self.web_cache_path.take() {
                tracing::debug!("unwatching old cache dir {old_cache_path:?}");
                let _ = self.debouncer.watcher().unwatch(&old_cache_path);
            }

            tracing::debug!("watching new cache dir {web_cache_path:?}");
            self.web_cache_path = Some(web_cache_path.clone());
            // A different file: whatever we remembered about the old one no
            // longer says anything about this one.
            self.cache_signature = None;

            let _ = self
                .debouncer
                .watcher()
                .watch(&web_cache_path, RecursiveMode::NonRecursive);
        }

        if let Err(e) = self.handle_web_cache_dir_update().await {
            tracing::info!("no url found in web cache dir: {e}");
        }

        Ok(())
    }

    async fn get_web_cache_path(&self) -> Result<PathBuf> {
        let data_dir = get_data_dir(&self.output_log_path).await?;
        let mut web_cache_path = get_web_cache_dir(data_dir).await?;

        web_cache_path.push("Cache/Cache_Data/data_2");

        Ok(web_cache_path)
    }

    async fn handle_web_cache_dir_update(&mut self) -> Result<()> {
        tracing::debug!("handling web cache dir update");
        let Some(data_path) = self.web_cache_path.clone() else {
            return Ok(());
        };

        // The debounced watcher fires for every write burst, but the gacha URL
        // only changes when the player reopens the wish history. Skip the
        // ~1 MB read plus regex scan while the file has not moved.
        let signature = file_signature(&data_path).await;
        if signature.is_some() && signature == self.cache_signature {
            tracing::debug!("{data_path:?} unchanged since the last read");
            return Ok(());
        }

        let read = read_url_from_cache(&data_path).await;
        if read.is_ok() {
            // Only remember the signature once the file really was readable,
            // so a transient failure (the game holding it open, say) is
            // retried on the next event instead of being cached away.
            self.cache_signature = signature;
        }
        let url = read?.ok_or_else(|| anyhow!("Can't find URL in {data_path:?}"))?;

        // Don't attempt to validate the same URL more than once.
        if url == self.prev_url {
            return Ok(());
        }

        validate_url(&url).await?;

        // Never log the URL as-is: it carries the gacha authkey, and this log
        // is what the in-app bug report dialog asks users to attach to public
        // issues.
        tracing::info!("found {}", redact_url(&url));
        self.prev_url = url.clone();
        let _ = self.url_tx.send(Some(url));

        Ok(())
    }
}

pub async fn force_find_url() -> Result<String> {
    let output_log_path = output_log_path()?;
    let data_dir = get_data_dir(&output_log_path).await?;
    let mut web_cache_path = get_web_cache_dir(data_dir).await?;
    web_cache_path.push("Cache/Cache_Data/data_2");

    let url = extract_url_from_cache(&web_cache_path).await?;
    validate_url(&url).await?;
    Ok(url)
}

/// `(mtime, len)` of `path`, or `None` if it cannot be stat'ed or the platform
/// has no modification time. `None` is never equal to a previous reading, so a
/// missing signature simply means "assume it changed".
async fn file_signature(path: &Path) -> Option<(SystemTime, u64)> {
    let metadata = fs::metadata(path).await.ok()?;
    Some((metadata.modified().ok()?, metadata.len()))
}

/// Read the web view's cache file and pull the gacha URL out of it.
///
/// `Ok(None)` means the file was readable but does not hold a gacha URL yet —
/// distinct from an I/O error, which the caller must not treat as a
/// successfully consumed version of the file.
async fn read_url_from_cache(data_path: &Path) -> Result<Option<String>> {
    let data = fs::read(data_path)
        .await
        .with_context(|| format!("could not open file {data_path:?}"))?;

    Ok(find_wish_url(&String::from_utf8_lossy(&data)))
}

async fn extract_url_from_cache(data_path: &Path) -> Result<String> {
    read_url_from_cache(data_path)
        .await?
        .ok_or_else(|| anyhow!("Can't find URL in {data_path:?}"))
}

/// Pick the gacha URL out of the raw cache contents.
///
/// The cache holds two kinds of matching URL: the `getGachaLog` API endpoint
/// and the web view's own `index.html` page, which carries the same authkey
/// but answers with HTML — [`validate_url`]'s JSON parse fails on that one.
/// Prefer the last API URL, and only fall back to the last match of any kind
/// so that a cache without an API URL behaves as it did before.
fn find_wish_url(haystack: &str) -> Option<String> {
    let mut api_url = None;
    let mut any_url = None;

    for candidate in WISH_URL_RE.find_iter(haystack) {
        if candidate.as_str().contains("getGachaLog") {
            api_url = Some(candidate.as_str());
        }
        any_url = Some(candidate.as_str());
    }

    api_url.or(any_url).map(str::to_owned)
}

/// Rebuild `url` with the credential-bearing parameters blanked out.
///
/// The gacha URL's `authkey` grants read access to the account's entire wish
/// history for roughly a day. `latest.log` is the file users are told to
/// attach to public bug reports, so the raw URL must never be written to it.
fn redact_url(url: &str) -> String {
    let Ok(mut parsed) = Url::parse(url) else {
        return "<unparsable wish url, redacted>".to_owned();
    };

    let pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(key, value)| {
            let key = key.into_owned();
            let value = if CREDENTIAL_QUERY_PARAMS.contains(&key.as_str()) {
                "REDACTED".to_owned()
            } else {
                value.into_owned()
            };
            (key, value)
        })
        .collect();

    if pairs.is_empty() {
        // `query_pairs_mut()` would leave a bare `?` behind.
        parsed.set_query(None);
    } else {
        parsed.query_pairs_mut().clear().extend_pairs(pairs);
    }

    // Some web view URLs carry their parameters in the fragment instead.
    if parsed.fragment().is_some_and(|f| f.contains("authkey")) {
        parsed.set_fragment(Some("REDACTED"));
    }

    parsed.into()
}

async fn get_data_dir(output_log_path: &Path) -> Result<PathBuf> {
    let file = fs::File::open(output_log_path)
        .await
        .with_context(|| format!("could not open {output_log_path:?}"))?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        if let Some(game_data_path) = GAME_DATA_RE.captures_iter(&line).next()
            && let Some(game_data_path) = game_data_path.get(0)
        {
            return Ok(game_data_path.as_str().into());
        }
    }

    Err(anyhow!("Can't find game data path in {output_log_path:?}"))
}

/// Roots holding an `AppData/LocalLow` tree for a Genshin client.
#[cfg(windows)]
fn user_profile_roots() -> Result<Vec<PathBuf>> {
    let user_profile = std::env::var("userprofile").context("could not find userprofile var")?;

    Ok(vec![PathBuf::from(user_profile)])
}

/// Roots holding an `AppData/LocalLow` tree for a Genshin client.
///
/// There is no native Linux client: the game runs under Proton or Wine, so the
/// Windows user profile lives inside a prefix at `<prefix>/drive_c/users/<user>`.
#[cfg(target_os = "linux")]
fn user_profile_roots() -> Result<Vec<PathBuf>> {
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

/// Wish history is a Windows-client feature; there is no Genshin client for
/// this platform to read a log from.
#[cfg(not(any(windows, target_os = "linux")))]
fn user_profile_roots() -> Result<Vec<PathBuf>> {
    Err(anyhow!(
        "wish history is only available on Windows, and on Linux through a Proton/Wine prefix"
    ))
}

fn output_log_path() -> Result<PathBuf> {
    let roots = user_profile_roots()?;
    let mut candidates = Vec::with_capacity(roots.len() * OUTPUT_LOG_RELATIVE_PATHS.len());
    for root in &roots {
        for relative in OUTPUT_LOG_RELATIVE_PATHS {
            candidates.push(root.join(relative));
        }
    }

    // Both the global and the Chinese client may be installed; whichever log
    // was written last is the one the player is using.
    candidates
        .iter()
        .filter_map(|path| {
            let metadata = std::fs::metadata(path).ok()?;
            if !metadata.is_file() {
                return None;
            }
            Some((metadata.modified().ok()?, path))
        })
        .max_by_key(|(modified, _)| *modified)
        .map(|(_, path)| path.clone())
        .ok_or_else(|| {
            anyhow!(
                "could not find Genshin Impact's output_log.txt; looked for {}",
                describe_candidates(&candidates)
            )
        })
}

fn describe_candidates(candidates: &[PathBuf]) -> String {
    const MAX_LISTED: usize = 6;

    let listed = candidates
        .iter()
        .take(MAX_LISTED)
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");

    match candidates.len().checked_sub(MAX_LISTED) {
        Some(0) | None => listed,
        Some(rest) => format!("{listed}, and {rest} more"),
    }
}

async fn get_web_cache_dir(data_dir: PathBuf) -> Result<PathBuf> {
    let mut web_caches = data_dir;
    web_caches.push("webCaches");
    let mut dir = fs::read_dir(&web_caches)
        .await
        .with_context(|| format!("could not open directory {web_caches:?}"))?;
    let mut latest_dir = (SystemTime::UNIX_EPOCH, None);
    while let Some(entry) = dir.next_entry().await? {
        let metadata = entry.metadata().await?;
        if !metadata.is_dir() {
            continue;
        }
        let modified = metadata.modified()?;
        if modified > latest_dir.0 {
            latest_dir = (modified, Some(entry.path()))
        }
    }

    latest_dir
        .1
        .ok_or_else(|| anyhow!("Unable to find directory in {web_caches:?}"))
}

async fn validate_url(url: &str) -> Result<()> {
    let url = Url::parse_with_params(
        url,
        &[
            ("lang", "en"),
            ("gacha_type", "301"),
            ("size", "5"),
            ("lang", "en-us"),
        ],
    )?;

    #[derive(Deserialize)]
    struct Response {
        retcode: i32,
    }

    // `reqwest::Error` renders the request URL in its `Display`, and our
    // callers log these errors, so strip the URL off every one of them and
    // re-attach a redacted copy as context instead.
    let redacted = redact_url(url.as_str());

    let response = HTTP
        .get(url)
        .send()
        .await
        .and_then(|response| response.error_for_status())
        .map_err(reqwest::Error::without_url)
        .with_context(|| format!("request to {redacted} failed"))?;

    let body: Response = response
        .json()
        .await
        .map_err(reqwest::Error::without_url)
        .with_context(|| format!("could not read the response from {redacted}"))?;

    if body.retcode != 0 {
        return Err(anyhow!("error code: {}", body.retcode));
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    /// The gacha-log API endpoint, shaped like the real thing.
    const API_URL: &str = "https://hk4e-api-os.hoyoverse.com/gacha_info/api/getGachaLog?win_mode=fullscreen&authkey_ver=1&sign_type=2&auth_appid=webview_gacha&init_type=301&lang=en&device_type=pc&plat_type=pc&region=os_asia&authkey=Sup3rSecret%2FKey&game_biz=hk4e_global";

    /// The web view page. Carries the same authkey but answers with HTML.
    const WEBVIEW_URL: &str = "https://webstatic-sea.hoyoverse.com/genshin/event/e20190909gacha-v3/index.html?win_mode=fullscreen&authkey_ver=1&sign_type=2&auth_appid=webview_gacha&authkey=Sup3rSecret%2FKey&game_biz=hk4e_global";

    #[test]
    fn game_data_regex_matches_both_clients() {
        assert!(GAME_DATA_RE.is_match(
            r"[Subsystems] Discovering subsystems at path C:/Program Files/Genshin Impact/Genshin Impact Game/GenshinImpact_Data/UnitySubsystems"
        ));
        assert!(GAME_DATA_RE.is_match(
            r"[Subsystems] Discovering subsystems at path D:\Genshin Impact\Genshin Impact Game\YuanShen_Data\UnitySubsystems"
        ));
        assert!(!GAME_DATA_RE.is_match("nothing that looks like a game data path"));
    }

    #[test]
    fn wish_url_keeps_the_game_biz_value() {
        // Surrounded by the binary noise of the cache file.
        let haystack = format!("\u{0}\u{1}garbage{API_URL}\u{0}\u{0}trailing");

        let found = find_wish_url(&haystack).expect("url should be found");
        assert_eq!(found, API_URL);
        assert!(found.ends_with("game_biz=hk4e_global"), "{found}");
    }

    #[test]
    fn wish_url_prefers_the_api_endpoint_over_the_webview_page() {
        let haystack = format!("{API_URL}\u{0}{WEBVIEW_URL}");

        assert_eq!(find_wish_url(&haystack).as_deref(), Some(API_URL));
    }

    #[test]
    fn wish_url_falls_back_to_the_webview_page() {
        assert_eq!(find_wish_url(WEBVIEW_URL).as_deref(), Some(WEBVIEW_URL));
    }

    #[test]
    fn no_wish_url_in_unrelated_data() {
        assert_eq!(find_wish_url("https://example.invalid/game_biz=x"), None);
    }

    #[test]
    fn redact_url_blanks_the_credential_but_keeps_the_rest() {
        let redacted = redact_url(API_URL);

        assert!(!redacted.contains("Sup3rSecret"), "{redacted}");
        assert!(redacted.contains("authkey=REDACTED"), "{redacted}");
        assert!(redacted.contains("authkey_ver=REDACTED"), "{redacted}");
        assert!(redacted.contains("sign_type=REDACTED"), "{redacted}");
        // Everything that is not a credential survives, so the log line is
        // still useful in a bug report.
        assert!(redacted.contains("region=os_asia"), "{redacted}");
        assert!(redacted.contains("game_biz=hk4e_global"), "{redacted}");
        assert!(
            redacted.starts_with("https://hk4e-api-os.hoyoverse.com/gacha_info/api/getGachaLog?"),
            "{redacted}"
        );
    }

    #[test]
    fn redact_url_blanks_a_fragment_carrying_the_credential() {
        let redacted = redact_url("https://example.invalid/index.html#/log?authkey=Sup3rSecret");

        assert!(!redacted.contains("Sup3rSecret"), "{redacted}");
    }

    #[test]
    fn redact_url_leaves_a_url_without_a_query_alone() {
        assert_eq!(
            redact_url("https://example.invalid/index.html"),
            "https://example.invalid/index.html"
        );
    }

    #[test]
    fn redact_url_drops_anything_it_cannot_parse() {
        let redacted = redact_url("not a url at all authkey=Sup3rSecret");

        assert!(!redacted.contains("Sup3rSecret"), "{redacted}");
    }

    /// The gacha-log probe must carry a timeout.
    ///
    /// `reqwest::get` -- what this used to call -- builds a client with no
    /// timeout of any kind, so a host that accepts the connection and never
    /// answers hangs the spawned `force_find_url` task forever and its
    /// oneshot is never resolved.
    ///
    /// `reqwest::Client`'s `Debug` prints the total timeout as a `Duration`
    /// and prints no timeout field at all when there is none, so the rendered
    /// duration is what we can assert on from outside the crate. The connect
    /// timeout lives in the connector and is not rendered, so it is not
    /// covered here. If a reqwest upgrade changes this rendering, repair the
    /// assertion rather than deleting it.
    #[test]
    fn validation_client_is_built_with_a_request_timeout() {
        let rendered = format!("{:?}", *HTTP);

        assert!(
            rendered.contains(&format!("{VALIDATE_REQUEST_TIMEOUT:?}")),
            "the wish validation client lost its request timeout: {rendered}"
        );
    }

    #[test]
    fn describe_candidates_summarizes_long_lists() {
        let one = [PathBuf::from("a")];
        assert_eq!(describe_candidates(&one), "a");

        let many: Vec<PathBuf> = (0..8).map(|n| PathBuf::from(n.to_string())).collect();
        assert_eq!(describe_candidates(&many), "0, 1, 2, 3, 4, 5, and 2 more");

        assert_eq!(describe_candidates(&[]), "");
    }
}
