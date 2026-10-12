//! The game's wish history API (`getGachaLog`): the URL, one page at a time,
//! paced and with back-off.
//!
//! The key in every URL here is a password while it lasts: nothing in this
//! module logs a URL unredacted, and every `reqwest::Error` has its URL
//! stripped before it is turned into text.

use std::fmt;
use std::time::{Duration, Instant};

use reqwest::Url;
use serde::Deserialize;

use super::Banner;

/// The global servers' wish history endpoint.
pub(crate) const GLOBAL_LOG_URL: &str =
    "https://public-operation-hk4e-sg.hoyoverse.com/gacha_info/api/getGachaLog";

/// The Chinese servers' (`hk4e_cn`) endpoint.
pub(crate) const CN_LOG_URL: &str =
    "https://public-operation-hk4e.mihoyo.com/gacha_info/api/getGachaLog";

/// Records per page. The API's maximum.
pub(crate) const PAGE_SIZE: u32 = 20;

/// How long a key is believed to last. The game does not say; keys have been
/// observed to stop working about a day after they were issued, and the API
/// answers "authkey timeout" when one has, which ends it sooner.
pub(crate) const KEY_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// The `message` of the answer to an expired key.
const AUTHKEY_TIMEOUT: &str = "authkey timeout";

/// The retcode of an expired key (with [`AUTHKEY_TIMEOUT`]).
const RETCODE_AUTHKEY_TIMEOUT: i64 = -101;

/// The retcode of "visit too frequently".
const RETCODE_TOO_FREQUENT: i64 = -110;

/// The least time a key from the game's web cache is believed to last once
/// the game's server said it works: its age is only guessed from the cache
/// file's time, which can be older than the key.
pub(crate) const CACHED_MIN_LIFETIME: Duration = Duration::from_secs(60 * 60);

/// The parameters a page request sets itself; dropped from the game's own
/// link before they are added, so none is sent twice.
const PAGING_PARAMS: [&str; 4] = ["gacha_type", "size", "page", "end_id"];

/// Query parameters that carry the credential, or that only make sense
/// together with it. Blanked out before a URL is logged.
const CREDENTIAL_QUERY_PARAMS: [&str; 3] = ["authkey", "sign_type", "authkey_ver"];

/// The start of the link's query when no banner list was seen: the history
/// link's fixed parameters, as the game writes them, without the banner's
/// `gacha_id` and `timestamp` (the API does not need them).
pub(crate) const FALLBACK_RECORD_QUERY: &str = "win_mode=fullscreen&no_joypad_close=1&authkey_ver=1\
     &sign_type=2&auth_appid=webview_gacha&init_type=301";

/// What the game puts in the wish history link besides the key, as captured
/// before the key arrived. Nothing here is secret.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct LinkParts {
    /// The history link query the server gave the banner (`GetGachaInfoRsp`):
    /// `win_mode=…&init_type=301&gacha_id=…&timestamp=…`, verbatim.
    pub(crate) record_query: Option<String>,
    /// The client's version (`game_version`), from its login.
    pub(crate) game_version: Option<String>,
    /// The server region (`region`): `os_asia`, `os_usa`, `os_euro`,
    /// `os_cht`, `cn_gf01`, `cn_qd01`.
    pub(crate) region: Option<String>,
}

/// Percent-encode a query value the way the game does: everything but
/// `A-Z a-z 0-9 - _ . ~`, with lowercase hex (`%2f`, `%2b`, `%3d`).
pub(crate) fn encode_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3 / 2);
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02x}"));
        }
    }
    out
}

/// Where a key came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeySource {
    /// The game's traffic: the server's answer when its history page opened.
    Game,
    /// A link the game left in its web cache, checked with the game's server.
    Cache,
}

/// A wish history key from the game, with when it arrived and what the
/// game's link carries besides it.
///
/// Memory only: never logged (its `Debug` prints no key), never persisted,
/// never sent anywhere but the game's own API.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WishKey {
    authkey: String,
    /// Chooses the endpoint (`hk4e_cn` → the Chinese one). A built link
    /// carries an empty `game_biz=`, as the game's does.
    game_biz: String,
    received_at: Instant,
    /// How long after `received_at` the key is believed to work.
    lifetime: Duration,
    link: LinkParts,
    source: KeySource,
    /// The game's own link from its web cache, verbatim: what Copy wish URL
    /// gives and what page requests are built on. `None` for a key from the
    /// traffic, whose link is built from [`LinkParts`].
    game_link: Option<String>,
}

impl WishKey {
    pub(crate) fn new(authkey: &str, game_biz: &str, received_at: Instant) -> Self {
        Self {
            authkey: authkey.to_owned(),
            game_biz: game_biz.to_owned(),
            received_at,
            lifetime: KEY_LIFETIME,
            link: LinkParts::default(),
            source: KeySource::Game,
            game_link: None,
        }
    }

    /// A key from the game's own link, found in its web cache at `now`; `age`
    /// is how old the cache file is (the key is at least that old). `None`
    /// when the link carries no key.
    pub(crate) fn from_game_link(url: &str, age: Duration, now: Instant) -> Option<Self> {
        let (base, rest) = url.split_once('?')?;
        let query = rest.split('#').next().unwrap_or_default();
        let authkey = percent_decode(query_value(query, "authkey")?)?;
        if authkey.is_empty() {
            return None;
        }
        let mut game_biz = query_value(query, "game_biz")
            .unwrap_or_default()
            .to_owned();
        let host = base
            .split("://")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .unwrap_or_default();
        if game_biz.is_empty() && host.ends_with(".mihoyo.com") {
            game_biz = "hk4e_cn".to_owned();
        }
        Some(Self {
            authkey,
            game_biz,
            received_at: now,
            lifetime: KEY_LIFETIME.saturating_sub(age).max(CACHED_MIN_LIFETIME),
            link: LinkParts::default(),
            source: KeySource::Cache,
            game_link: Some(url.to_owned()),
        })
    }

    pub(crate) fn source(&self) -> KeySource {
        self.source
    }

    /// The same key came from the game's traffic too: it is the game's now.
    pub(crate) fn mark_from_game(&mut self) {
        self.source = KeySource::Game;
    }

    pub(crate) fn with_link(mut self, link: LinkParts) -> Self {
        self.link = link;
        self
    }

    /// Whether this is the same key as `other`, whenever and from wherever
    /// each arrived.
    pub(crate) fn same_key(&self, other: &Self) -> bool {
        self.authkey == other.authkey
    }

    /// How long the key is still believed to work at `now`.
    pub(crate) fn remaining(&self, now: Instant) -> Duration {
        self.lifetime
            .saturating_sub(now.saturating_duration_since(self.received_at))
    }

    pub(crate) fn is_fresh(&self, now: Instant) -> bool {
        !self.remaining(now).is_zero()
    }

    /// The endpoint for this key's servers.
    pub(crate) fn endpoint(&self) -> &'static str {
        if self.game_biz == "hk4e_cn" {
            CN_LOG_URL
        } else {
            GLOBAL_LOG_URL
        }
    }

    /// The wish URL people paste into paimon.moe ("Manual" import) or
    /// stardb: the link the game itself writes when its history opens --
    /// verbatim when it came from the game's cache.
    pub(crate) fn wish_url(&self) -> String {
        match &self.game_link {
            Some(link) => link.clone(),
            None => format!("{}?{}", self.endpoint(), self.link_query()),
        }
    }

    /// The query page requests are built on: the game's own link's as it is
    /// (but for the paging parameters), else the built one.
    fn base_query(&self) -> String {
        let Some(link) = &self.game_link else {
            return self.link_query();
        };
        let query = link
            .split_once('?')
            .map(|(_, rest)| rest.split('#').next().unwrap_or_default())
            .unwrap_or_default();
        query
            .split('&')
            .filter(|part| {
                let name = part.split('=').next().unwrap_or_default();
                !part.is_empty() && !PAGING_PARAMS.contains(&name)
            })
            .collect::<Vec<_>>()
            .join("&")
    }

    /// The game's link query, in the game's order and encoding: the banner's
    /// history link query (or [`FALLBACK_RECORD_QUERY`]), then `lang=en`,
    /// `device_type=pc`, `game_version`, `region` (each left out when it was
    /// not captured), the key and an empty `game_biz`.
    fn link_query(&self) -> String {
        let link = &self.link;
        let mut query = link
            .record_query
            .clone()
            .unwrap_or_else(|| FALLBACK_RECORD_QUERY.to_owned());
        query.push_str("&lang=en&device_type=pc");
        if let Some(version) = &link.game_version {
            query.push_str("&game_version=");
            query.push_str(&encode_value(version));
        }
        if let Some(region) = &link.region {
            query.push_str("&region=");
            query.push_str(&encode_value(region));
        }
        query.push_str("&authkey=");
        query.push_str(&encode_value(&self.authkey));
        query.push_str("&game_biz=");
        query
    }

    /// The game's link on `endpoint`, then `extra` (what paimon.moe sets on
    /// it to page: `gacha_type`, `size`, `page`, `end_id`).
    pub(crate) fn url_at(&self, endpoint: &str, extra: &[(&str, &str)]) -> Url {
        let mut url = format!("{endpoint}?{}", self.base_query());
        for (name, value) in extra {
            url.push('&');
            url.push_str(name);
            url.push('=');
            url.push_str(&encode_value(value));
        }
        Url::parse(&url).expect("the wish history endpoints are valid URLs")
    }
}

impl fmt::Debug for WishKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WishKey")
            .field("authkey", &"<redacted>")
            .field("game_biz", &self.game_biz)
            .field("received_at", &self.received_at)
            .field("lifetime", &self.lifetime)
            .field("link", &self.link)
            .field("source", &self.source)
            .field("game_link", &self.game_link.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// The raw value of `name` in a query string (`a=1&b=2`).
fn query_value<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|part| {
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        (key == name).then_some(value)
    })
}

/// Undo `%XX` escapes; `+` stays `+` (keys are base64). `None` for a broken
/// escape or a result that is not UTF-8.
fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let hex = std::str::from_utf8(bytes.get(at + 1..at + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Rebuild `url` with the credential-bearing parameters blanked out.
///
/// A wish link's `authkey` grants read access to the account's entire wish
/// history for roughly a day. `latest.log` is the file users are told to
/// attach to public bug reports, so the raw URL must never be written to it.
pub(crate) fn redact_url(url: &str) -> String {
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

/// One wish as the API returns it. Every field is a string on the wire.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct ApiRecord {
    pub(crate) uid: String,
    pub(crate) gacha_type: String,
    #[serde(default)]
    pub(crate) item_id: String,
    pub(crate) time: String,
    pub(crate) name: String,
    pub(crate) item_type: String,
    pub(crate) rank_type: String,
    pub(crate) id: String,
}

#[derive(Deserialize)]
struct Answer {
    retcode: i64,
    #[serde(default)]
    message: String,
    data: Option<AnswerData>,
}

#[derive(Deserialize)]
struct AnswerData {
    #[serde(default)]
    region: String,
    #[serde(default)]
    list: Vec<ApiRecord>,
}

/// One page of a banner's history, newest first.
#[derive(Debug)]
pub(crate) struct LogPage {
    pub(crate) region: String,
    pub(crate) records: Vec<ApiRecord>,
}

/// Why a page could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FetchError {
    /// "authkey timeout": the key no longer works.
    KeyExpired,
    /// Still throttled after every back-off.
    Throttled,
    /// Network or HTTP trouble, retried and still failing; or an answer that
    /// is not the API's. The text carries no URL.
    Failed(String),
    /// The API refused the request (a retcode other than the above).
    Refused { retcode: i64, message: String },
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyExpired => write!(f, "the wish key expired"),
            Self::Throttled => write!(f, "the wish history API is busy (too many requests)"),
            Self::Failed(why) => write!(f, "{why}"),
            Self::Refused { retcode, message } => {
                write!(f, "the wish history API refused: {message} ({retcode})")
            }
        }
    }
}

/// What one attempt came to: done, or worth another try after a back-off.
enum Attempt {
    Done(Result<LogPage, FetchError>),
    Retry(FetchError),
}

/// Waits, so tests can see the pacing without spending it.
pub(crate) trait Sleeper {
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send;
}

/// The real clock.
pub(crate) struct TokioSleeper;

impl Sleeper for TokioSleeper {
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send {
        tokio::time::sleep(duration)
    }
}

/// The waits between requests.
#[derive(Clone, Debug)]
pub(crate) struct Pacing {
    /// Between two requests (pages of one banner).
    pub(crate) request: Duration,
    /// Before the first request of the next banner.
    pub(crate) banner: Duration,
    /// Before each retry of a throttled or failed request; its length is the
    /// number of retries.
    pub(crate) backoff: Vec<Duration>,
}

impl Default for Pacing {
    /// What paimon.moe and the other importers do (1 s per page, 2 s per
    /// banner), with a back-off that gives a throttle time to lift.
    fn default() -> Self {
        Self {
            request: Duration::from_secs(1),
            banner: Duration::from_secs(2),
            backoff: vec![
                Duration::from_secs(5),
                Duration::from_secs(15),
                Duration::from_secs(45),
            ],
        }
    }
}

/// Reads pages of the wish history with one key, keeping to [`Pacing`].
pub(crate) struct LogClient<S> {
    http: reqwest::Client,
    endpoint: String,
    key: WishKey,
    sleeper: S,
    pacing: Pacing,
    /// The wait owed before the next request; `None` before the first one.
    owed: Option<Duration>,
    requests: u32,
}

impl<S: Sleeper> LogClient<S> {
    pub(crate) fn new(
        http: reqwest::Client,
        endpoint: String,
        key: WishKey,
        sleeper: S,
        pacing: Pacing,
    ) -> Self {
        Self {
            http,
            endpoint,
            key,
            sleeper,
            pacing,
            owed: None,
            requests: 0,
        }
    }

    /// Requests sent so far, retries included.
    pub(crate) fn requests(&self) -> u32 {
        self.requests
    }

    /// The next request starts a new banner: wait the banner gap before it.
    pub(crate) fn next_banner(&mut self) {
        if self.owed.is_some() {
            self.owed = Some(self.pacing.banner.max(self.pacing.request));
        }
    }

    /// One page of `banner`, the one after the record `end_id` (0 = newest).
    pub(crate) async fn page(
        &mut self,
        banner: Banner,
        page: u32,
        end_id: u64,
    ) -> Result<LogPage, FetchError> {
        let banner = banner.to_string();
        let size = PAGE_SIZE.to_string();
        let page = page.to_string();
        let end_id = end_id.to_string();
        let url = self.key.url_at(
            &self.endpoint,
            &[
                ("gacha_type", &banner),
                ("size", &size),
                ("page", &page),
                ("end_id", &end_id),
            ],
        );

        let mut retries = self.pacing.backoff.clone().into_iter();
        loop {
            if let Some(wait) = self.owed.take() {
                self.sleeper.sleep(wait).await;
            }
            self.requests += 1;
            let attempt = self.attempt(url.clone()).await;
            self.owed = Some(self.pacing.request);
            match attempt {
                Attempt::Done(result) => return result,
                Attempt::Retry(error) => {
                    let Some(backoff) = retries.next() else {
                        return Err(error);
                    };
                    tracing::info!(
                        banner = %banner,
                        page = %page,
                        "wish history request failed ({error}); retrying in {}s",
                        backoff.as_secs()
                    );
                    self.owed = Some(backoff.max(self.pacing.request));
                }
            }
        }
    }

    async fn attempt(&self, url: Url) -> Attempt {
        let response = match self.http.get(url.clone()).send().await {
            Ok(response) => response,
            Err(error) => {
                let error = error.without_url();
                tracing::debug!("request to {} failed: {error}", redact_url(url.as_str()));
                return Attempt::Retry(FetchError::Failed(format!(
                    "could not reach the wish history API: {error}"
                )));
            }
        };
        let status = response.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Attempt::Retry(FetchError::Throttled);
        }
        if status.is_server_error() {
            return Attempt::Retry(FetchError::Failed(format!(
                "the wish history API answered HTTP {status}"
            )));
        }
        if !status.is_success() {
            return Attempt::Done(Err(FetchError::Failed(format!(
                "the wish history API answered HTTP {status}"
            ))));
        }
        let body = match response.bytes().await {
            Ok(body) => body,
            Err(error) => {
                return Attempt::Retry(FetchError::Failed(format!(
                    "the wish history answer was cut off: {}",
                    error.without_url()
                )));
            }
        };
        match read_answer(&body) {
            // "Visit too frequently" is a throttle like HTTP 429.
            Err(FetchError::Throttled) => Attempt::Retry(FetchError::Throttled),
            other => Attempt::Done(other),
        }
    }
}

/// What one check of a key with the game's server came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Probe {
    /// The server answered with a page (retcode 0): the key works.
    Valid,
    /// "authkey timeout" (-101).
    Expired,
    /// Any other refusal, such as -109 "app id error" (a key for another
    /// page). Carries the retcode only.
    Refused(i64),
    /// No answer, or not the API's. The text carries no URL.
    Failed(String),
}

/// Check `key` with ONE request on `endpoint`: the newest record of the
/// character event banner. Never retried; never logs the URL.
pub(crate) async fn probe(http: &reqwest::Client, endpoint: &str, key: &WishKey) -> Probe {
    let url = key.url_at(
        endpoint,
        &[
            ("gacha_type", "301"),
            ("size", "1"),
            ("page", "1"),
            ("end_id", "0"),
        ],
    );
    let response = match http.get(url).send().await {
        Ok(response) => response,
        Err(error) => {
            return Probe::Failed(format!(
                "could not reach the wish history API: {}",
                error.without_url()
            ));
        }
    };
    let status = response.status();
    if !status.is_success() {
        return Probe::Failed(format!("the wish history API answered HTTP {status}"));
    }
    let body = match response.bytes().await {
        Ok(body) => body,
        Err(error) => {
            return Probe::Failed(format!(
                "the wish history answer was cut off: {}",
                error.without_url()
            ));
        }
    };
    match read_answer(&body) {
        Ok(_) => Probe::Valid,
        Err(FetchError::KeyExpired) => Probe::Expired,
        Err(FetchError::Refused { retcode, .. }) => Probe::Refused(retcode),
        Err(error) => Probe::Failed(error.to_string()),
    }
}

/// Read one answer of the API. "Slow down" comes back as
/// [`FetchError::Throttled`], which [`LogClient::page`] retries.
fn read_answer(body: &[u8]) -> Result<LogPage, FetchError> {
    let answer: Answer = serde_json::from_slice(body).map_err(|error| {
        FetchError::Failed(format!(
            "the wish history API sent something unexpected: {error}"
        ))
    })?;
    if answer.retcode != 0 {
        if answer.retcode == RETCODE_AUTHKEY_TIMEOUT || answer.message == AUTHKEY_TIMEOUT {
            return Err(FetchError::KeyExpired);
        }
        if answer.retcode == RETCODE_TOO_FREQUENT {
            return Err(FetchError::Throttled);
        }
        return Err(FetchError::Refused {
            retcode: answer.retcode,
            message: answer.message,
        });
    }
    let data = answer.data.ok_or_else(|| {
        FetchError::Failed("the wish history API answered without data".to_owned())
    })?;
    Ok(LogPage {
        region: data.region,
        records: data.list,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTHKEY: &str = "SyNtHeTiC+tEsT/kEy==";

    fn key(biz: &str) -> WishKey {
        WishKey::new(AUTHKEY, biz, Instant::now())
    }

    /// What the game captured before the key: the banner's history link
    /// query, the client version, the region. Synthetic values.
    fn captured() -> LinkParts {
        LinkParts {
            record_query: Some(
                "win_mode=fullscreen&no_joypad_close=1&authkey_ver=1&sign_type=2\
                 &auth_appid=webview_gacha&init_type=301\
                 &gacha_id=0123456789abcdef0123456789abcdef01234567&timestamp=1790000000"
                    .to_owned(),
            ),
            game_version: Some("OSRELWin7.1.0_R11111111_S22222222_D33333333".to_owned()),
            region: Some("os_asia".to_owned()),
        }
    }

    #[test]
    fn the_url_is_the_games_own_link_in_its_order_and_encoding() {
        assert_eq!(
            key("hk4e_global").with_link(captured()).wish_url(),
            "https://public-operation-hk4e-sg.hoyoverse.com/gacha_info/api/getGachaLog\
             ?win_mode=fullscreen&no_joypad_close=1&authkey_ver=1&sign_type=2\
             &auth_appid=webview_gacha&init_type=301\
             &gacha_id=0123456789abcdef0123456789abcdef01234567&timestamp=1790000000\
             &lang=en&device_type=pc&game_version=OSRELWin7.1.0_R11111111_S22222222_D33333333\
             &region=os_asia&authkey=SyNtHeTiC%2btEsT%2fkEy%3d%3d&game_biz="
        );
    }

    #[test]
    fn what_was_not_captured_is_left_out_of_the_url() {
        assert_eq!(
            key("hk4e_global").wish_url(),
            "https://public-operation-hk4e-sg.hoyoverse.com/gacha_info/api/getGachaLog\
             ?win_mode=fullscreen&no_joypad_close=1&authkey_ver=1&sign_type=2\
             &auth_appid=webview_gacha&init_type=301&lang=en&device_type=pc\
             &authkey=SyNtHeTiC%2btEsT%2fkEy%3d%3d&game_biz="
        );
    }

    #[test]
    fn values_are_encoded_like_the_game_with_lowercase_hex() {
        assert_eq!(encode_value("a+b/c=d"), "a%2bb%2fc%3dd");
        assert_eq!(encode_value("Az09-_.~"), "Az09-_.~");
        assert_eq!(encode_value("a b&c"), "a%20b%26c");
    }

    #[test]
    fn a_chinese_key_uses_the_chinese_endpoint() {
        let url = key("hk4e_cn").wish_url();
        assert!(
            url.starts_with("https://public-operation-hk4e.mihoyo.com/gacha_info/api/getGachaLog?"),
            "{url}"
        );
        // Like the game's own link: the game is named by the host, and the
        // parameter stays empty.
        assert!(url.ends_with("&game_biz="), "{url}");
    }

    #[test]
    fn requests_keep_the_link_byte_for_byte_and_add_the_paging() {
        let key = key("hk4e_global").with_link(captured());
        let url = key.url_at(
            GLOBAL_LOG_URL,
            &[
                ("gacha_type", "301"),
                ("size", "20"),
                ("page", "2"),
                ("end_id", "17"),
            ],
        );
        assert_eq!(
            url.as_str(),
            format!("{}&gacha_type=301&size=20&page=2&end_id=17", key.wish_url())
        );
    }

    #[test]
    fn the_key_round_trips_through_the_url_encoding() {
        let url = Url::parse(&key("hk4e_global").wish_url()).unwrap();
        let authkey = url
            .query_pairs()
            .find(|(name, _)| name == "authkey")
            .map(|(_, value)| value.into_owned());
        assert_eq!(authkey.as_deref(), Some(AUTHKEY));
    }

    #[test]
    fn the_key_never_shows_in_debug_or_in_a_redacted_url() {
        let key = key("hk4e_global");
        let rendered = format!("{key:?} {}", redact_url(&key.wish_url()));
        assert!(!rendered.contains("SyNtHeTiC"), "{rendered}");
    }

    #[test]
    fn a_key_is_believed_for_a_day() {
        let at = Instant::now();
        let key = WishKey::new(AUTHKEY, "hk4e_global", at);
        assert_eq!(key.remaining(at), KEY_LIFETIME);
        assert!(key.is_fresh(at + Duration::from_secs(23 * 3600)));
        assert!(!key.is_fresh(at + KEY_LIFETIME));
    }

    #[test]
    fn answers_are_read() {
        let page = read_answer(
            br#"{"retcode":0,"message":"OK","data":{"page":"1","size":"20","region":"os_asia",
               "list":[{"uid":"811111111","gacha_type":"400","item_id":"","count":"1",
               "time":"2026-10-12 21:04:11","name":"Some Character","lang":"en-us",
               "item_type":"Character","rank_type":"5","id":"1790000000000000002"}]}}"#,
        )
        .unwrap();
        assert_eq!(page.region, "os_asia");
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].gacha_type, "400");

        assert_eq!(
            read_answer(br#"{"retcode":-101,"message":"authkey timeout","data":null}"#)
                .unwrap_err(),
            FetchError::KeyExpired
        );
        assert_eq!(
            read_answer(br#"{"retcode":-110,"message":"visit too frequently","data":null}"#)
                .unwrap_err(),
            FetchError::Throttled
        );
        assert!(matches!(
            read_answer(br#"{"retcode":-100,"message":"authkey error","data":null}"#),
            Err(FetchError::Refused { retcode: -100, .. })
        ));
        assert!(matches!(read_answer(b"<html>"), Err(FetchError::Failed(_))));
    }

    /// The game's own link as its web cache holds it. Synthetic values.
    const CACHED_LINK: &str = "https://public-operation-hk4e-sg.hoyoverse.com/gacha_info/api/getGachaLog\
        ?win_mode=fullscreen&no_joypad_close=1&authkey_ver=1&sign_type=2\
        &auth_appid=webview_gacha&init_type=301\
        &gacha_id=0123456789abcdef0123456789abcdef01234567&timestamp=1790000000\
        &lang=en&device_type=pc&game_version=OSRELWin7.1.0_R11111111_S22222222_D33333333\
        &region=os_asia&authkey=SyNtHeTiC%2btEsT%2fkEy%3d%3d&game_biz=hk4e_global";

    #[test]
    fn a_cached_link_is_used_verbatim_and_carries_its_key() {
        let now = Instant::now();
        let key = WishKey::from_game_link(CACHED_LINK, Duration::ZERO, now).unwrap();
        assert_eq!(key.source(), KeySource::Cache);
        assert_eq!(key.wish_url(), CACHED_LINK);
        assert_eq!(key.endpoint(), GLOBAL_LOG_URL);
        // The same key as the traffic's, whatever the link around it.
        assert!(key.same_key(&WishKey::new(AUTHKEY, "hk4e_global", now)));
        assert!(!key.same_key(&WishKey::new("other", "hk4e_global", now)));

        let url = key.url_at(GLOBAL_LOG_URL, &[("gacha_type", "302"), ("size", "20")]);
        assert_eq!(
            url.as_str(),
            format!("{CACHED_LINK}&gacha_type=302&size=20")
        );
        let rendered = format!("{key:?}");
        assert!(!rendered.contains("SyNtHeTiC"), "{rendered}");
    }

    #[test]
    fn paging_in_a_cached_link_is_replaced_not_repeated() {
        let link = format!("{CACHED_LINK}&gacha_type=200&page=4&size=5&end_id=9#/log");
        let key = WishKey::from_game_link(&link, Duration::ZERO, Instant::now()).unwrap();
        let url = key.url_at(
            GLOBAL_LOG_URL,
            &[("gacha_type", "301"), ("page", "1"), ("end_id", "0")],
        );
        assert_eq!(
            url.as_str(),
            format!("{CACHED_LINK}&gacha_type=301&page=1&end_id=0")
        );
    }

    #[test]
    fn a_cached_key_lasts_what_is_left_of_its_day_but_at_least_an_hour() {
        let now = Instant::now();
        let fresh = WishKey::from_game_link(CACHED_LINK, Duration::from_secs(3600), now).unwrap();
        assert_eq!(
            fresh.remaining(now),
            KEY_LIFETIME - Duration::from_secs(3600)
        );
        let old = WishKey::from_game_link(CACHED_LINK, KEY_LIFETIME * 3, now).unwrap();
        assert_eq!(old.remaining(now), CACHED_MIN_LIFETIME);
    }

    #[test]
    fn a_link_without_a_key_is_no_key_and_a_chinese_one_uses_the_chinese_endpoint() {
        let now = Instant::now();
        assert!(
            WishKey::from_game_link("https://example.invalid/x?a=1", Duration::ZERO, now).is_none()
        );
        assert!(
            WishKey::from_game_link("https://example.invalid/x?authkey=", Duration::ZERO, now)
                .is_none()
        );
        assert!(
            WishKey::from_game_link("https://example.invalid/x?authkey=%zz", Duration::ZERO, now)
                .is_none()
        );
        let cn = WishKey::from_game_link(
            "https://public-operation-hk4e.mihoyo.com/gacha_info/api/getGachaLog?authkey=a%2bb&game_biz=",
            Duration::ZERO,
            now,
        )
        .unwrap();
        assert_eq!(cn.endpoint(), CN_LOG_URL);
        assert!(cn.same_key(&WishKey::new("a+b", "hk4e_cn", now)));
        let cn = WishKey::from_game_link(
            "https://example.invalid/index.html?authkey=k&game_biz=hk4e_cn",
            Duration::ZERO,
            now,
        )
        .unwrap();
        assert_eq!(cn.endpoint(), CN_LOG_URL);
    }

    #[test]
    fn redact_url_blanks_the_credential_but_keeps_the_rest() {
        let redacted = redact_url(CACHED_LINK);

        assert!(!redacted.contains("SyNtHeTiC"), "{redacted}");
        assert!(redacted.contains("authkey=REDACTED"), "{redacted}");
        assert!(redacted.contains("authkey_ver=REDACTED"), "{redacted}");
        assert!(redacted.contains("sign_type=REDACTED"), "{redacted}");
        // Everything that is not a credential survives, so the log line is
        // still useful in a bug report.
        assert!(redacted.contains("region=os_asia"), "{redacted}");
        assert!(redacted.contains("game_biz=hk4e_global"), "{redacted}");
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
}
