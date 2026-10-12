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
use crate::wish::redact_url;

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

/// A wish history key captured from the game, with when it arrived and what
/// the game's link carries besides it.
///
/// Memory only: never logged (its `Debug` prints no key), never persisted,
/// never sent anywhere but the game's own API.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WishKey {
    authkey: String,
    /// Chooses the endpoint (`hk4e_cn` → the Chinese one). The link itself
    /// carries an empty `game_biz=`, as the game's does.
    game_biz: String,
    received_at: Instant,
    link: LinkParts,
}

impl WishKey {
    pub(crate) fn new(authkey: &str, game_biz: &str, received_at: Instant) -> Self {
        Self {
            authkey: authkey.to_owned(),
            game_biz: game_biz.to_owned(),
            received_at,
            link: LinkParts::default(),
        }
    }

    pub(crate) fn with_link(mut self, link: LinkParts) -> Self {
        self.link = link;
        self
    }

    /// Whether this is the same key as `other`, whenever each arrived.
    pub(crate) fn same_key(&self, other: &Self) -> bool {
        self.authkey == other.authkey && self.game_biz == other.game_biz
    }

    /// How long the key is still believed to work at `now`.
    pub(crate) fn remaining(&self, now: Instant) -> Duration {
        KEY_LIFETIME.saturating_sub(now.saturating_duration_since(self.received_at))
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
    /// stardb: the link the game itself writes when its history opens.
    pub(crate) fn wish_url(&self) -> String {
        format!("{}?{}", self.endpoint(), self.link_query())
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
        let mut url = format!("{endpoint}?{}", self.link_query());
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
            .field("link", &self.link)
            .finish()
    }
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
    /// "authkey timeout": open Wish -> History in game again.
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
}
