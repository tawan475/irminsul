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

/// A wish history key captured from the game, with when it arrived.
///
/// Memory only: never logged (its `Debug` prints no key), never persisted,
/// never sent anywhere but the game's own API.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WishKey {
    authkey: String,
    game_biz: String,
    received_at: Instant,
}

impl WishKey {
    pub(crate) fn new(authkey: &str, game_biz: &str, received_at: Instant) -> Self {
        Self {
            authkey: authkey.to_owned(),
            game_biz: game_biz.to_owned(),
            received_at,
        }
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

    /// The wish URL people paste into paimon.moe ("Manual" import) or stardb.
    pub(crate) fn wish_url(&self) -> String {
        self.url_at(self.endpoint(), &[]).into()
    }

    /// The URL with the contract's fixed parameters, then `extra`.
    pub(crate) fn url_at(&self, endpoint: &str, extra: &[(&str, &str)]) -> Url {
        let mut url = Url::parse(endpoint).expect("the wish history endpoints are valid URLs");
        url.query_pairs_mut()
            .append_pair("authkey_ver", "1")
            .append_pair("sign_type", "2")
            .append_pair("auth_appid", "webview_gacha")
            .append_pair("init_type", "301")
            .append_pair("lang", "en-us")
            .append_pair("authkey", &self.authkey)
            .append_pair("game_biz", &self.game_biz)
            .extend_pairs(extra);
        url
    }
}

impl fmt::Debug for WishKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WishKey")
            .field("authkey", &"<redacted>")
            .field("game_biz", &self.game_biz)
            .field("received_at", &self.received_at)
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

    #[test]
    fn the_global_url_carries_the_contracts_parameters_in_order() {
        assert_eq!(
            key("hk4e_global").wish_url(),
            "https://public-operation-hk4e-sg.hoyoverse.com/gacha_info/api/getGachaLog\
             ?authkey_ver=1&sign_type=2&auth_appid=webview_gacha&init_type=301&lang=en-us\
             &authkey=SyNtHeTiC%2BtEsT%2FkEy%3D%3D&game_biz=hk4e_global"
        );
    }

    #[test]
    fn a_chinese_key_uses_the_chinese_endpoint() {
        let url = key("hk4e_cn").wish_url();
        assert!(
            url.starts_with("https://public-operation-hk4e.mihoyo.com/gacha_info/api/getGachaLog?"),
            "{url}"
        );
        assert!(url.ends_with("&game_biz=hk4e_cn"), "{url}");
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
    fn a_page_request_adds_the_paging_parameters() {
        let url = key("hk4e_global").url_at(
            GLOBAL_LOG_URL,
            &[
                ("gacha_type", "301"),
                ("size", "20"),
                ("page", "2"),
                ("end_id", "17"),
            ],
        );
        assert!(
            url.as_str()
                .ends_with("&game_biz=hk4e_global&gacha_type=301&size=20&page=2&end_id=17"),
            "{url}"
        );
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
