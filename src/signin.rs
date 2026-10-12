//! "Sign in with the tracker": OAuth 2.0 authorization code with PKCE over a
//! loopback redirect, the flow RFC 8252 recommends for desktop apps.
//!
//! Irminsul is a public client (nothing secret is baked into the binary), so
//! it proves the code is its own with PKCE (RFC 7636, `S256`) and receives the
//! browser's answer on a one-shot listener on `127.0.0.1`. The wire contract
//! (discovery, authorize, token, revoke, whoami, import) is shared with the
//! tracker and lives in its repository
//! (`docs/plans/irminsul-sign-in-and-destinations.md`, contract v1); the
//! endpoints are all under the API base the user configured
//! (`SavedAppState::tracker_api_url`).
//!
//! What is kept where:
//! - the **refresh token** in the OS credential store ([`KeyringStore`]:
//!   Windows Credential Manager, the macOS Keychain, the Secret Service on
//!   Linux), one entry per tracker *origin*, never in `app.ron`. It rotates on
//!   every use, so every refresh writes the new one back.
//! - the **access token** in memory only, refreshed shortly before it expires
//!   and once more when the tracker answers 401 `token_expired`.
//!
//! A token is only ever sent to the origin it was issued for: discovery must
//! name token and revoke URLs on the API's own origin, and changing the
//! tracker address ([`TrackerAuth::set_address`]) signs out of the old one
//! before anything talks to the new one.
//!
//! Nothing here logs a token, a code, the PKCE verifier or the authorize URL
//! (its `state` is what stops another page completing the sign-in); the log
//! says which step ran and the tracker's error *codes*, nothing more.
//!
//! The import key (`x-import-key`, `monitor.rs`) is a separate, older path
//! and stays exactly as it was: it is a wire contract with released builds.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use base64::prelude::*;
use reqwest::{StatusCode, Url};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc, watch};
use tokio_util::sync::CancellationToken;

/// The OAuth client id the tracker knows Irminsul by.
pub const CLIENT_ID: &str = "irminsul";

/// The credential store's service name; the entry's account is the tracker
/// origin (`https://genshin-tracker.475.dev`).
const KEYRING_SERVICE: &str = "irminsul";

/// How long the loopback listener waits for the browser. Signing in may mean
/// a password, a human check or a Discord round trip, so this is generous;
/// the UI's Cancel ends it sooner.
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// How long one loopback connection may take to send its request head.
/// Browsers open speculative connections that never send anything; those
/// are dropped after this without holding up the real callback.
const CALLBACK_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The most of a request head the listener reads. The callback is one short
/// request line plus a browser's headers.
const MAX_REQUEST_HEAD: usize = 16 * 1024;

/// An access token is refreshed when it has less than this left, so a
/// request is never sent with one about to lapse in flight.
const ACCESS_TOKEN_MARGIN: Duration = Duration::from_secs(60);

/// Revoking is best effort (sign-out deletes the local token either way), so
/// it gets a short budget instead of the client's 60 s.
const REVOKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The contract's limit on the `device` parameter.
const DEVICE_NAME_MAX_CHARS: usize = 64;

/// What the UI says when the tracker ended this sign-in (revoked from its
/// Devices page, a password change, "sign out everywhere", expiry).
pub const SIGNED_OUT_NOTICE: &str = "Signed out, sign in again";

// ---------------------------------------------------------------------------
// PKCE and state
// ---------------------------------------------------------------------------

/// A PKCE pair (RFC 7636): the verifier stays here, the challenge goes in
/// the authorize URL.
pub(crate) struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    /// A fresh pair: 32 random bytes, base64url without padding, which is the
    /// RFC's recommended 43-character verifier.
    pub fn generate() -> Result<Self, String> {
        Ok(Self::from_verifier(random_url_safe(32)?))
    }

    pub fn from_verifier(verifier: String) -> Self {
        let challenge = s256_challenge(&verifier);
        Self {
            verifier,
            challenge,
        }
    }
}

/// `BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`, no padding.
pub(crate) fn s256_challenge(verifier: &str) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// `bytes` random bytes from the OS, base64url without padding.
pub(crate) fn random_url_safe(bytes: usize) -> Result<String, String> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).map_err(|e| format!("no randomness available: {e}"))?;
    Ok(BASE64_URL_SAFE_NO_PAD.encode(buf))
}

/// Compare without stopping at the first differing byte.
fn same_secret(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// The PC's name for the consent screen and the tracker's Devices list
/// ("Irminsul on <device>"). Only the signed-in user sees it.
pub fn device_name() -> String {
    clean_device_name(&gethostname::gethostname().to_string_lossy())
}

fn clean_device_name(raw: &str) -> String {
    let name: String = raw
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(DEVICE_NAME_MAX_CHARS)
        .collect();
    let name = name.trim();
    if name.is_empty() {
        "this PC".to_string()
    } else {
        name.to_string()
    }
}

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

/// The API base as compared and stored: trimmed, without a trailing slash.
pub(crate) fn normalize_base(base: &str) -> String {
    base.trim().trim_end_matches('/').to_string()
}

fn parse_web_url(url: &str) -> Option<Url> {
    Url::parse(url.trim())
        .ok()
        .filter(|url| matches!(url.scheme(), "http" | "https") && url.host_str().is_some())
}

/// The origin a tracker address belongs to (`https://host[:port]`), which is
/// what a stored sign-in is keyed by.
pub(crate) fn origin_of(base: &str) -> Result<String, String> {
    parse_web_url(base)
        .map(|url| url.origin().ascii_serialization())
        .ok_or_else(|| "the tracker address is not an http(s) URL".to_string())
}

/// The host a tracker address points at, for "Uploads will now go to <host>".
pub(crate) fn host_of(base: &str) -> Option<String> {
    let url = parse_web_url(base)?;
    let host = url.host_str()?.to_string();
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn endpoint(base: &str, path: &str) -> String {
    format!("{}/{path}", normalize_base(base))
}

/// Keep a server-supplied link only when it is safe to hand to the browser.
fn web_link(value: Option<&serde_json::Value>) -> Option<String> {
    let link = value?.as_str()?.trim();
    parse_web_url(link).map(|_| link.to_string())
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// `GET <api>/oauth/irminsul`: where the sign-in's pages and endpoints are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Discovery {
    pub authorize_url: String,
    pub token_url: String,
    pub revoke_url: String,
}

/// Read a discovery answer for the API at `base`.
///
/// The token and revoke URLs receive the refresh token, so they must be on
/// the API's own origin: a tracker (or anything answering on its address)
/// cannot point them elsewhere. The authorize URL only ever reaches the
/// browser, carrying nothing secret, and just has to be http(s).
pub(crate) fn parse_discovery(body: &str, base: &str) -> Result<Discovery, String> {
    let json: serde_json::Value = serde_json::from_str(body)
        .map_err(|_| "the tracker's sign-in discovery is not JSON".to_string())?;
    let field = |name: &str| {
        json.get(name)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| format!("the tracker's sign-in discovery has no {name}"))
    };
    let authorize_url = field("authorize_url")?;
    let token_url = field("token_url")?;
    let revoke_url = field("revoke_url")?;

    let origin = origin_of(base)?;
    if parse_web_url(&authorize_url).is_none() {
        return Err("the tracker's sign-in page is not an http(s) URL".to_string());
    }
    for url in [&token_url, &revoke_url] {
        let same_origin =
            parse_web_url(url).is_some_and(|url| url.origin().ascii_serialization() == origin);
        if !same_origin {
            return Err("the tracker's sign-in endpoints are not on its own address".to_string());
        }
    }
    Ok(Discovery {
        authorize_url,
        token_url,
        revoke_url,
    })
}

/// The browser URL that starts a sign-in (contract section 2).
pub(crate) fn authorize_url(
    discovery: &Discovery,
    redirect_uri: &str,
    state: &str,
    challenge: &str,
    device: &str,
) -> Result<String, String> {
    let mut url = Url::parse(&discovery.authorize_url)
        .map_err(|_| "the tracker's sign-in page is not a URL".to_string())?;
    url.query_pairs_mut()
        .append_pair("client_id", CLIENT_ID)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("state", state)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("device", device);
    Ok(url.into())
}

// ---------------------------------------------------------------------------
// The loopback callback
// ---------------------------------------------------------------------------

/// What one request to the loopback listener was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Callback {
    /// The tracker's answer: an authorization code with the right `state`.
    Code(String),
    /// The user pressed Cancel on the consent screen.
    Denied,
    /// The tracker reported another OAuth error (its code, sanitized).
    Failed(String),
    /// A callback whose `state` is missing or not ours: not this sign-in's
    /// answer, and possibly another page trying to complete it.
    StateMismatch,
    /// A callback with neither a code nor an error.
    Malformed,
    /// Not the callback at all (a favicon, a wrong path or method). Answered
    /// 404 and ignored.
    Other,
}

impl Callback {
    /// The sentence the browser tab shows.
    fn page_message(&self) -> &'static str {
        match self {
            Self::Code(_) => "You can close this tab and go back to Irminsul.",
            Self::Denied => "Sign-in was cancelled. You can close this tab.",
            Self::Failed(_) | Self::Malformed => {
                "The tracker did not sign you in. Try again from Irminsul."
            }
            Self::StateMismatch => {
                "This sign-in link does not belong to the sign-in Irminsul started. \
                 Start again from Irminsul."
            }
            Self::Other => "Not found.",
        }
    }
}

/// Classify a request head (request line plus headers) sent to the
/// loopback listener.
pub(crate) fn parse_callback(head: &str, expected_state: &str) -> Callback {
    let Some(request_line) = head.lines().next() else {
        return Callback::Other;
    };
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Callback::Other;
    };
    if method != "GET" || !version.starts_with("HTTP/1.") || !target.starts_with('/') {
        return Callback::Other;
    }
    let Ok(url) = Url::parse(&format!("http://127.0.0.1{target}")) else {
        return Callback::Other;
    };
    if url.path() != "/callback" {
        return Callback::Other;
    }

    let mut query: HashMap<String, String> = HashMap::new();
    for (key, value) in url.query_pairs() {
        // The first value wins; a repeated parameter cannot override it.
        query
            .entry(key.into_owned())
            .or_insert_with(|| value.into_owned());
    }
    let state_matches = query
        .get("state")
        .is_some_and(|state| same_secret(state, expected_state));
    if !state_matches {
        return Callback::StateMismatch;
    }
    if let Some(error) = query.get("error") {
        return if error == "access_denied" {
            Callback::Denied
        } else {
            Callback::Failed(sanitize_code(error))
        };
    }
    match query.get("code") {
        Some(code) if !code.is_empty() => Callback::Code(code.clone()),
        _ => Callback::Malformed,
    }
}

/// An error code fit for a log line or a status message: the OAuth
/// alphabet, bounded.
fn sanitize_code(code: &str) -> String {
    let code: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(64)
        .collect();
    if code.is_empty() {
        "unknown_error".to_string()
    } else {
        code
    }
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The small, self-contained page the browser shows after the callback: no
/// scripts, no external resources, nothing from the request echoed back.
pub(crate) fn callback_page(signed_in: bool, message: &str) -> String {
    let (title, colour) = if signed_in {
        ("Signed in", "#00ab3f")
    } else {
        ("Not signed in", "#e05252")
    };
    let message = html_escape(message);
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>Irminsul: {title}</title><style>\
         body{{margin:0;min-height:100vh;display:grid;place-items:center;\
         background:#111827;color:#e5e7eb;font:16px system-ui,sans-serif}}\
         main{{text-align:center;padding:24px}}\
         h1{{font-size:22px;margin:0 0 8px;color:{colour}}}\
         p{{margin:0;color:#9ca3af}}</style></head>\
         <body><main><h1>{title}</h1><p>{message}</p></main></body></html>"
    )
}

fn http_response(status: &str, content_type: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

async fn write_and_close(mut stream: TcpStream, response: Vec<u8>) {
    let _ = stream.write_all(&response).await;
    let _ = stream.shutdown().await;
}

/// Read one request head, or `None` for a connection that sends nothing
/// usable in time.
async fn read_request_head(stream: &mut TcpStream) -> Option<String> {
    let read = async {
        let mut head = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        loop {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            head.extend_from_slice(&chunk[..n]);
            if head.windows(4).any(|w| w == b"\r\n\r\n") {
                return Some(String::from_utf8_lossy(&head).into_owned());
            }
            if head.len() > MAX_REQUEST_HEAD {
                return None;
            }
        }
    };
    tokio::time::timeout(CALLBACK_READ_TIMEOUT, read)
        .await
        .ok()
        .flatten()
}

/// The one-shot listener the browser is redirected to.
///
/// It binds `127.0.0.1` only (never a routable address) on a port the OS
/// picks, serves exactly one callback and closes: everything else it hears
/// gets a bare 404, and it never answers with anything but the fixed pages
/// in [`callback_page`].
pub(crate) struct Loopback {
    listener: TcpListener,
    port: u16,
}

/// The callback request, held open so the page can say how the code
/// exchange went.
pub(crate) struct CallbackHit {
    pub outcome: Callback,
    stream: TcpStream,
}

impl CallbackHit {
    pub async fn answer(self, signed_in: bool) {
        let page = callback_page(signed_in, self.outcome.page_message());
        write_and_close(
            self.stream,
            http_response("200 OK", "text/html; charset=utf-8", &page),
        )
        .await;
    }

    /// Answer with a failure page whatever the outcome was.
    async fn answer_failed(self, message: &str) {
        let page = callback_page(false, message);
        write_and_close(
            self.stream,
            http_response("200 OK", "text/html; charset=utf-8", &page),
        )
        .await;
    }
}

impl Loopback {
    pub async fn bind() -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();
        Ok(Self { listener, port })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The `redirect_uri` for this listener. `127.0.0.1` rather than
    /// `localhost`, which can resolve to `::1` where nothing listens.
    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}/callback", self.port)
    }

    /// Wait for the callback, up to `timeout`. Consumes the listener: the
    /// port closes when this returns.
    pub async fn wait(
        self,
        expected_state: &str,
        timeout: Duration,
    ) -> Result<CallbackHit, String> {
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        // Each connection reads its head on its own task, so a speculative
        // connection that never sends anything cannot hold up the real one.
        let (head_tx, mut head_rx) = mpsc::unbounded_channel::<(TcpStream, String)>();
        loop {
            tokio::select! {
                _ = &mut deadline => {
                    return Err("the browser did not come back in time".to_string());
                }
                accepted = self.listener.accept() => {
                    let Ok((mut stream, peer)) = accepted else { continue };
                    if !peer.ip().is_loopback() {
                        continue;
                    }
                    let head_tx = head_tx.clone();
                    tokio::spawn(async move {
                        if let Some(head) = read_request_head(&mut stream).await {
                            let _ = head_tx.send((stream, head));
                        }
                    });
                }
                Some((stream, head)) = head_rx.recv() => {
                    match parse_callback(&head, expected_state) {
                        Callback::Other => {
                            tokio::spawn(write_and_close(
                                stream,
                                http_response("404 Not Found", "text/plain; charset=utf-8", "Not found"),
                            ));
                        }
                        outcome => return Ok(CallbackHit { outcome, stream }),
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Token and whoami answers
// ---------------------------------------------------------------------------

/// Who the signed-in user is and where this PC's uploads go
/// (`GET <api>/irminsul/whoami`, also carried in token answers).
///
/// Irminsul never changes the target itself: the tracker's website does
/// (`config_url`), and the UI re-reads this when the user comes back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Whoami {
    pub scope: UploadScope,
    pub user: String,
    pub account_id: Option<i64>,
    pub account_name: Option<String>,
    pub uid: Option<String>,
    pub server: Option<String>,
    pub dashboard_url: Option<String>,
    /// The tracker page where this session's upload target is changed.
    pub config_url: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadScope {
    /// The account is picked by the capture's UID; new UIDs create one.
    Uid,
    /// Always one account.
    Account,
}

impl Whoami {
    /// Where uploads go, in a few words.
    pub fn target_label(&self) -> String {
        match self.scope {
            UploadScope::Uid => "Auto (by UID)".to_string(),
            // The chosen account was deleted on the tracker: nothing uploads
            // (409 `upload_target_missing`) until one is picked again.
            UploadScope::Account if self.account_id.is_none() && self.account_name.is_none() => {
                "Not chosen".to_string()
            }
            // An account the tracker made for a new UID has no name; the
            // website calls it by its UID then, and so does this.
            UploadScope::Account => match (&self.account_name, &self.uid) {
                (Some(name), Some(uid)) => format!("{name} (UID {uid})"),
                (Some(name), None) => name.clone(),
                (None, Some(uid)) => format!("UID {uid}"),
                (None, None) => "an account".to_string(),
            },
        }
    }
}

/// Read a whoami object. Lenient where the verify-key reader is (a numeric
/// UID, missing optional fields); strict on what a link may be.
pub(crate) fn parse_whoami(json: &serde_json::Value) -> Result<Whoami, String> {
    let text = |name: &str| {
        json.get(name)
            .and_then(|v| match v {
                serde_json::Value::String(s) => Some(s.trim().to_string()),
                serde_json::Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .filter(|s| !s.is_empty())
    };
    let scope = match json.get("scope").and_then(|v| v.as_str()) {
        Some("uid") => UploadScope::Uid,
        Some("account") => UploadScope::Account,
        _ => return Err("the tracker's whoami answer has no known scope".to_string()),
    };
    Ok(Whoami {
        scope,
        user: text("user").unwrap_or_else(|| "?".to_string()),
        account_id: json.get("accountId").and_then(|v| v.as_i64()),
        account_name: text("accountName"),
        uid: text("uid"),
        server: text("server"),
        dashboard_url: web_link(json.get("dashboardUrl")),
        config_url: web_link(json.get("configUrl")),
    })
}

/// A successful token answer. Deliberately not `Debug`: it holds both tokens.
pub(crate) struct Tokens {
    pub access_token: String,
    pub expires_in: Duration,
    pub refresh_token: String,
    pub whoami: Option<Whoami>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TokenError {
    /// The code or refresh token is no longer accepted (used, expired,
    /// rotated away, or the session was ended): signed out.
    InvalidGrant,
    /// The tracker account is suspended.
    Suspended,
    /// Any other refusal, with the OAuth error code.
    Rejected {
        status: u16,
        error: String,
    },
    Network(String),
    Malformed(String),
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGrant => f.write_str(SIGNED_OUT_NOTICE),
            Self::Suspended => f.write_str("This tracker account is suspended"),
            Self::Rejected { status, error } => {
                write!(
                    f,
                    "The tracker refused the sign-in (HTTP {status}, {error})"
                )
            }
            Self::Network(e) => write!(f, "Could not reach the tracker: {e}"),
            Self::Malformed(e) => write!(f, "Unexpected answer from the tracker: {e}"),
        }
    }
}

/// The error code in a tracker answer: OAuth's `{"error": "code"}` or the
/// app's `{"error": {"code": "..."}}`.
pub(crate) fn api_error_code(body: &str) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    let error = json.get("error")?;
    let code = error
        .as_str()
        .or_else(|| error.get("code").and_then(|c| c.as_str()))?;
    Some(sanitize_code(code))
}

/// The human sentence in an app error (`{"error": {"message": "..."}}`).
fn api_error_message(body: &str) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    let message = json.get("error")?.get("message")?.as_str()?.trim();
    (!message.is_empty()).then(|| message.to_string())
}

/// A failed signed-in request as the UI says it: `HTTP {status} - ` and the
/// tracker's own sentence when it gave one (a deleted upload target, blocked
/// uploads, a quota), else the raw body -- the key path's shape.
fn http_failure(status: StatusCode, body: &str) -> String {
    let detail = api_error_message(body).unwrap_or_else(|| body.to_string());
    format!("HTTP {status} - {detail}")
}

/// Read the token endpoint's answer (both grants; contract section 3).
pub(crate) fn parse_token_response(status: u16, body: &str) -> Result<Tokens, TokenError> {
    if !(200..300).contains(&status) {
        let error = api_error_code(body).unwrap_or_else(|| "unknown_error".to_string());
        return Err(match (status, error.as_str()) {
            (_, "invalid_grant") => TokenError::InvalidGrant,
            (403, "account_suspended") => TokenError::Suspended,
            _ => TokenError::Rejected { status, error },
        });
    }
    let json: serde_json::Value = serde_json::from_str(body)
        .map_err(|_| TokenError::Malformed("the token answer is not JSON".to_string()))?;
    let token = |name: &str| {
        json.get(name)
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| TokenError::Malformed(format!("the token answer has no {name}")))
    };
    if let Some(kind) = json.get("token_type").and_then(|v| v.as_str())
        && !kind.eq_ignore_ascii_case("bearer")
    {
        return Err(TokenError::Malformed(format!(
            "unsupported token type {}",
            sanitize_code(kind)
        )));
    }
    let access_token = token("access_token")?;
    let refresh_token = token("refresh_token")?;
    let expires_in = json
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(900);
    let whoami = json.get("whoami").and_then(|w| parse_whoami(w).ok());
    Ok(Tokens {
        access_token,
        expires_in: Duration::from_secs(expires_in),
        refresh_token,
        whoami,
    })
}

// ---------------------------------------------------------------------------
// The credential store
// ---------------------------------------------------------------------------

/// Where refresh tokens persist between runs, keyed by tracker origin.
///
/// A trait so the tests never touch the real store ([`MemoryStore`]).
pub trait CredentialStore: Send + Sync {
    fn load(&self, origin: &str) -> Result<Option<String>, String>;
    fn save(&self, origin: &str, token: &str) -> Result<(), String>;
    fn delete(&self, origin: &str) -> Result<(), String>;
}

/// The OS credential store, through the `keyring` crate: service
/// `irminsul`, account = the tracker origin.
pub struct KeyringStore;

impl KeyringStore {
    fn entry(origin: &str) -> Result<keyring::Entry, String> {
        keyring::Entry::new(KEYRING_SERVICE, origin)
            .map_err(|e| format!("the credential store is unavailable: {e}"))
    }
}

impl CredentialStore for KeyringStore {
    fn load(&self, origin: &str) -> Result<Option<String>, String> {
        match Self::entry(origin)?.get_password() {
            Ok(token) => Ok(Some(token)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(format!("could not read the saved sign-in: {e}")),
        }
    }

    fn save(&self, origin: &str, token: &str) -> Result<(), String> {
        Self::entry(origin)?
            .set_password(token)
            .map_err(|e| format!("could not save the sign-in: {e}"))
    }

    fn delete(&self, origin: &str) -> Result<(), String> {
        match Self::entry(origin)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(format!("could not remove the saved sign-in: {e}")),
        }
    }
}

/// An in-memory [`CredentialStore`] for tests.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MemoryStore {
    pub tokens: StdMutex<HashMap<String, String>>,
}

#[cfg(test)]
impl CredentialStore for MemoryStore {
    fn load(&self, origin: &str) -> Result<Option<String>, String> {
        Ok(self.tokens.lock().unwrap().get(origin).cloned())
    }

    fn save(&self, origin: &str, token: &str) -> Result<(), String> {
        self.tokens
            .lock()
            .unwrap()
            .insert(origin.to_string(), token.to_string());
        Ok(())
    }

    fn delete(&self, origin: &str) -> Result<(), String> {
        self.tokens.lock().unwrap().remove(origin);
        Ok(())
    }
}

/// Run a store call off the async workers: the Secret Service is a D-Bus
/// round trip and may wait on an unlock prompt.
async fn with_store<T: Send + 'static>(
    store: &Arc<dyn CredentialStore>,
    call: impl FnOnce(&dyn CredentialStore) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let store = Arc::clone(store);
    tokio::task::spawn_blocking(move || call(store.as_ref()))
        .await
        .map_err(|e| format!("the credential store call failed: {e}"))?
}

// ---------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------

/// What the UI shows about the sign-in.
#[derive(Clone, PartialEq, Eq)]
pub enum AuthStatus {
    /// The stored sign-in has not been read yet.
    Loading,
    /// Not signed in to this address. `notice` says why, when the tracker
    /// ended it or a sign-in failed.
    SignedOut { notice: Option<String> },
    /// The browser is open on the tracker's sign-in page. `link` is that
    /// page, for "Copy link" when the browser that opened is not the one the
    /// user is signed in to (see [`TrackerAuth::sign_in`]).
    Waiting { link: Option<String> },
    /// Signed in. `whoami` is the last answer (`None` until the first
    /// arrives); `error` the last failure to refresh it.
    SignedIn {
        whoami: Option<Whoami>,
        error: Option<String>,
    },
}

impl AuthStatus {
    #[cfg(test)]
    pub fn is_signed_in(&self) -> bool {
        matches!(self, Self::SignedIn { .. })
    }
}

/// By hand, so the sign-in link never reaches a log through `{:?}`.
impl fmt::Debug for AuthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Loading => f.write_str("Loading"),
            Self::SignedOut { notice } => {
                f.debug_struct("SignedOut").field("notice", notice).finish()
            }
            Self::Waiting { link } => f
                .debug_struct("Waiting")
                .field("link", &link.as_ref().map(|_| "<redacted>"))
                .finish(),
            Self::SignedIn { whoami, error } => f
                .debug_struct("SignedIn")
                .field("scope", &whoami.as_ref().map(|w| w.scope))
                .field("error", error)
                .finish(),
        }
    }
}

/// What the UI asks of the sign-in (`Message::Tracker`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrackerRequest {
    /// Read the stored sign-in for the current address (at startup).
    Load,
    SignIn,
    CancelSignIn,
    SignOut,
    /// Re-read whoami (the user came back from the tracker's website).
    Refresh,
    /// The tracker address changed (already confirmed by the user).
    SetAddress(String),
}

/// How an upload authenticates. Chosen by `app::upload_credential`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UploadCredential {
    /// The old path: `x-import-key` to `import-by-key` (a wire contract
    /// with released builds; unchanged).
    ImportKey { url: String, key: String },
    /// Bearer to `<api>/irminsul/import`, with this session's tokens, for
    /// the address the UI meant (`base`). [`TrackerAuth::upload`] refuses it
    /// when the session belongs to another address, so an upload queued
    /// around an address change never goes with the old address's token.
    SignedIn { base: String },
}

pub type Opener = Arc<dyn Fn(String) + Send + Sync>;
pub type Notify = Arc<dyn Fn() + Send + Sync>;

struct Access {
    token: String,
    expires_at: Instant,
}

struct Session {
    /// The API base this session belongs to (normalized).
    base: String,
    /// Bumped whenever the address changes or the sign-in ends, so work that
    /// started before cannot write its result over the new state.
    generation: u64,
    /// The refresh token, read from or written to the store. `None` means
    /// signed out.
    refresh: Option<String>,
    access: Option<Access>,
    discovery: Option<Discovery>,
}

/// A bearer grant for one request: the token and the address it is for.
struct Grant {
    token: String,
    base: String,
    generation: u64,
}

#[derive(Debug)]
pub(crate) enum AuthError {
    /// There is no sign-in (any more).
    SignedOut,
    Network(String),
    Http {
        status: StatusCode,
        body: String,
    },
    Token(TokenError),
    Other(String),
}

impl fmt::Display for AuthError {
    /// `HTTP {status} - {body}` for an HTTP failure, the shape the key path's
    /// upload errors have (`app.rs::tracker_error_status`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignedOut => f.write_str(SIGNED_OUT_NOTICE),
            Self::Network(e) | Self::Other(e) => f.write_str(e),
            Self::Http { status, body } => f.write_str(&http_failure(*status, body)),
            Self::Token(e) => write!(f, "{e}"),
        }
    }
}

fn network_error(e: reqwest::Error) -> String {
    // `without_url`: the URLs here carry nothing secret, but this keeps the
    // message short and the habit safe.
    e.without_url().to_string()
}

struct Inner {
    store: Arc<dyn CredentialStore>,
    opener: Opener,
    notify: Notify,
    device: String,
    status_tx: watch::Sender<AuthStatus>,
    session: Mutex<Session>,
    /// The running sign-in's id and cancel token.
    sign_in: StdMutex<Option<(u64, CancellationToken)>>,
    sign_in_counter: std::sync::atomic::AtomicU64,
}

/// The tracker sign-in: shared by the UI (status) and the monitor (requests,
/// uploads). Cheap to clone.
#[derive(Clone)]
pub struct TrackerAuth {
    inner: Arc<Inner>,
}

impl TrackerAuth {
    /// `opener` shows a URL in the system browser; `notify` asks the UI to
    /// repaint. Starts in [`AuthStatus::Loading`] until
    /// [`TrackerRequest::Load`] runs.
    pub fn new(
        base: &str,
        store: Arc<dyn CredentialStore>,
        device: String,
        opener: Opener,
        notify: Notify,
    ) -> Self {
        let (status_tx, _) = watch::channel(AuthStatus::Loading);
        Self {
            inner: Arc::new(Inner {
                store,
                opener,
                notify,
                device,
                status_tx,
                session: Mutex::new(Session {
                    base: normalize_base(base),
                    generation: 0,
                    refresh: None,
                    access: None,
                    discovery: None,
                }),
                sign_in: StdMutex::new(None),
                sign_in_counter: std::sync::atomic::AtomicU64::new(0),
            }),
        }
    }

    pub fn status(&self) -> watch::Receiver<AuthStatus> {
        self.inner.status_tx.subscribe()
    }

    /// Run a UI request in the background.
    pub fn handle(&self, client: reqwest::Client, request: TrackerRequest) {
        if request == TrackerRequest::CancelSignIn {
            self.cancel_sign_in();
            return;
        }
        let auth = self.clone();
        tokio::spawn(async move {
            match request {
                TrackerRequest::Load => auth.load(&client).await,
                TrackerRequest::SignIn => auth.sign_in(&client).await,
                TrackerRequest::SignOut => auth.sign_out(&client).await,
                TrackerRequest::Refresh => auth.refresh_whoami(&client).await,
                TrackerRequest::SetAddress(base) => auth.set_address(&client, &base).await,
                TrackerRequest::CancelSignIn => {}
            }
        });
    }

    fn publish(&self, status: AuthStatus) {
        tracing::debug!(?status, "tracker sign-in status");
        self.inner.status_tx.send_replace(status);
        (self.inner.notify)();
    }

    fn last_whoami(&self) -> Option<Whoami> {
        match &*self.inner.status_tx.borrow() {
            AuthStatus::SignedIn { whoami, .. } => whoami.clone(),
            _ => None,
        }
    }

    /// Read the stored sign-in for the current address, then whoami.
    pub async fn load(&self, client: &reqwest::Client) {
        let (base, generation) = {
            let session = self.inner.session.lock().await;
            (session.base.clone(), session.generation)
        };
        let origin = match origin_of(&base) {
            Ok(origin) => origin,
            Err(e) => {
                self.publish(AuthStatus::SignedOut { notice: Some(e) });
                return;
            }
        };
        let stored = with_store(&self.inner.store, move |store| store.load(&origin)).await;

        {
            let mut session = self.inner.session.lock().await;
            if session.generation != generation {
                return;
            }
            match stored {
                Ok(Some(token)) => {
                    tracing::info!("tracker sign-in: found a saved sign-in");
                    session.refresh = Some(token);
                    self.publish(AuthStatus::SignedIn {
                        whoami: None,
                        error: None,
                    });
                }
                Ok(None) => {
                    self.publish(AuthStatus::SignedOut { notice: None });
                    return;
                }
                Err(e) => {
                    // Not said in the UI: a Linux desktop without a Secret
                    // Service would hear it at every start. Signing in says
                    // so instead, when it cannot save ("for this session
                    // only").
                    tracing::warn!("tracker sign-in: {e}");
                    self.publish(AuthStatus::SignedOut { notice: None });
                    return;
                }
            }
        }
        self.refresh_whoami(client).await;
    }

    /// The discovery document for the session's address, fetched once.
    async fn discovery_locked(
        &self,
        session: &mut Session,
        client: &reqwest::Client,
    ) -> Result<Discovery, String> {
        if let Some(discovery) = &session.discovery {
            return Ok(discovery.clone());
        }
        let response = client
            .get(endpoint(&session.base, "oauth/irminsul"))
            .send()
            .await
            .map_err(|e| format!("Could not reach the tracker: {}", network_error(e)))?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!(
                "This tracker does not support signing in (HTTP {status})"
            ));
        }
        let discovery = parse_discovery(&body, &session.base)?;
        session.discovery = Some(discovery.clone());
        Ok(discovery)
    }

    /// Sign in through the browser.
    ///
    /// The authorize page is opened the way every other link in the app is
    /// (`egui::Context::open_url`, through `opener`). Irminsul runs elevated
    /// on Windows, and a browser started from an elevated process can come up
    /// as a separate instance that is not signed in to the tracker (or, for
    /// some browsers, as a second profile). The sign-in still works there --
    /// the user signs in once more -- and the UI offers "Copy link" so the
    /// page can be opened in the browser they normally use instead: the
    /// callback goes to `127.0.0.1` either way. The device-code flow
    /// (RFC 8628) would avoid this and is the planned fallback; it is not
    /// part of v1.
    pub async fn sign_in(&self, client: &reqwest::Client) {
        let id = self
            .inner
            .sign_in_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let cancel = CancellationToken::new();
        if let Some((_, previous)) = self
            .inner
            .sign_in
            .lock()
            .unwrap()
            .replace((id, cancel.clone()))
        {
            previous.cancel();
        }

        let generation = self.inner.session.lock().await.generation;
        let result = self.sign_in_inner(client, &cancel).await;

        // Only the newest attempt reports, and only for the address it began
        // on: a cancelled attempt must not overwrite its replacement.
        let ours = {
            let mut slot = self.inner.sign_in.lock().unwrap();
            let ours = slot.as_ref().is_some_and(|(slot_id, _)| *slot_id == id);
            if ours {
                *slot = None;
            }
            ours
        };
        if let Err(e) = result {
            let current = self.inner.session.lock().await.generation == generation;
            if ours && current {
                let notice = (!cancel.is_cancelled()).then_some(e);
                if let Some(notice) = &notice {
                    tracing::warn!("tracker sign-in failed: {notice}");
                } else {
                    tracing::info!("tracker sign-in cancelled");
                }
                self.publish(AuthStatus::SignedOut { notice });
            }
        }
    }

    async fn sign_in_inner(
        &self,
        client: &reqwest::Client,
        cancel: &CancellationToken,
    ) -> Result<(), String> {
        self.publish(AuthStatus::Waiting { link: None });
        let (discovery, generation) = {
            let mut session = self.inner.session.lock().await;
            if session.refresh.is_some() {
                // Already signed in; nothing to do. Re-publish what is true.
                drop(session);
                self.publish(AuthStatus::SignedIn {
                    whoami: self.last_whoami(),
                    error: None,
                });
                return Ok(());
            }
            let discovery = self.discovery_locked(&mut session, client).await?;
            (discovery, session.generation)
        };

        let loopback = Loopback::bind()
            .await
            .map_err(|e| format!("Could not open a local port for the sign-in: {e}"))?;
        let redirect_uri = loopback.redirect_uri();
        let pkce = Pkce::generate()?;
        let state = random_url_safe(32)?;
        let link = authorize_url(
            &discovery,
            &redirect_uri,
            &state,
            &pkce.challenge,
            &self.inner.device,
        )?;

        tracing::info!(
            port = loopback.port(),
            "tracker sign-in: opening the browser"
        );
        self.publish(AuthStatus::Waiting {
            link: Some(link.clone()),
        });
        (self.inner.opener)(link);

        let hit = tokio::select! {
            _ = cancel.cancelled() => return Err("cancelled".to_string()),
            hit = loopback.wait(&state, SIGN_IN_TIMEOUT) => hit?,
        };

        let code = match &hit.outcome {
            Callback::Code(code) => code.clone(),
            other => {
                let error = match other {
                    Callback::Denied => "Sign-in cancelled on the tracker".to_string(),
                    Callback::Failed(code) => format!("The tracker did not sign you in ({code})"),
                    Callback::StateMismatch => {
                        "The browser answered for another sign-in; try again".to_string()
                    }
                    _ => "The tracker's answer was not understood".to_string(),
                };
                hit.answer(false).await;
                return Err(error);
            }
        };
        tracing::info!("tracker sign-in: the browser came back, exchanging the code");

        let body = serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": code,
            "code_verifier": pkce.verifier,
            "redirect_uri": redirect_uri,
        });
        let tokens = match post_token(client, &discovery.token_url, &body).await {
            Ok(tokens) => tokens,
            Err(e) => {
                hit.answer_failed("The tracker did not sign you in. Try again from Irminsul.")
                    .await;
                return Err(e.to_string());
            }
        };

        let mut session = self.inner.session.lock().await;
        if session.generation != generation {
            // The address changed while the browser was open: these tokens
            // belong to the old one. Give them back and keep nothing.
            drop(session);
            revoke(client, &discovery, &tokens.refresh_token).await;
            hit.answer_failed("The tracker address changed in Irminsul. Sign in again there.")
                .await;
            return Err("The tracker address changed during the sign-in".to_string());
        }
        let has_whoami = tokens.whoami.is_some();
        self.adopt_tokens(&mut session, tokens).await;
        drop(session);
        hit.answer(true).await;
        tracing::info!("tracker sign-in: signed in");

        if !has_whoami {
            self.refresh_whoami(client).await;
        }
        Ok(())
    }

    /// Take a token answer: keep the access token in memory, persist the
    /// (rotated) refresh token, publish the new status.
    async fn adopt_tokens(&self, session: &mut Session, tokens: Tokens) {
        let Tokens {
            access_token,
            expires_in,
            refresh_token,
            whoami,
        } = tokens;
        // Rotation: the tracker ends the whole session when a rotated-away
        // refresh token is presented again. So the new one replaces the old
        // in memory at once, is written to the store before this returns
        // (and so before the new access token is used), and every refresh
        // runs under the session lock, one at a time.
        session.access = Some(Access {
            token: access_token,
            expires_at: Instant::now() + expires_in,
        });
        session.refresh = Some(refresh_token.clone());

        let mut error = None;
        match origin_of(&session.base) {
            Ok(origin) => {
                let saved = with_store(&self.inner.store, move |store| {
                    store.save(&origin, &refresh_token)
                })
                .await;
                if let Err(e) = saved {
                    // Still signed in for this run; the next one asks again.
                    tracing::warn!("tracker sign-in: {e}");
                    error = Some(format!("Signed in for this session only: {e}"));
                }
            }
            Err(e) => error = Some(e),
        }

        let whoami = whoami.or_else(|| self.last_whoami());
        self.publish(AuthStatus::SignedIn { whoami, error });
    }

    /// End the sign-in locally: drop the tokens, delete the stored one,
    /// publish signed out with `notice`.
    async fn forget_locked(&self, session: &mut Session, notice: Option<String>) {
        session.refresh = None;
        session.access = None;
        session.generation += 1;
        if let Ok(origin) = origin_of(&session.base)
            && let Err(e) = with_store(&self.inner.store, move |store| store.delete(&origin)).await
        {
            tracing::warn!("tracker sign-in: {e}");
        }
        self.publish(AuthStatus::SignedOut { notice });
    }

    /// Use the refresh token. On `invalid_grant` the sign-in is over.
    async fn refresh_locked(
        &self,
        session: &mut Session,
        client: &reqwest::Client,
    ) -> Result<(), AuthError> {
        let Some(refresh) = session.refresh.clone() else {
            return Err(AuthError::SignedOut);
        };
        let discovery = self
            .discovery_locked(session, client)
            .await
            .map_err(AuthError::Other)?;
        let body = serde_json::json!({
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": refresh,
        });
        match post_token(client, &discovery.token_url, &body).await {
            Ok(tokens) => {
                tracing::info!("tracker sign-in: refreshed the access token");
                self.adopt_tokens(session, tokens).await;
                Ok(())
            }
            Err(TokenError::InvalidGrant) => {
                tracing::info!("tracker sign-in: the tracker ended this sign-in");
                self.forget_locked(session, Some(SIGNED_OUT_NOTICE.to_string()))
                    .await;
                Err(AuthError::SignedOut)
            }
            Err(e) => {
                tracing::warn!("tracker sign-in: refresh failed: {e}");
                Err(AuthError::Token(e))
            }
        }
    }

    /// An access token with some life left, refreshing first if needed.
    async fn grant(&self, client: &reqwest::Client) -> Result<Grant, AuthError> {
        let mut session = self.inner.session.lock().await;
        let fresh = session
            .access
            .as_ref()
            .is_some_and(|access| access.expires_at > Instant::now() + ACCESS_TOKEN_MARGIN);
        if !fresh {
            self.refresh_locked(&mut session, client).await?;
        }
        let token = session
            .access
            .as_ref()
            .map(|access| access.token.clone())
            .ok_or(AuthError::SignedOut)?;
        Ok(Grant {
            token,
            base: session.base.clone(),
            generation: session.generation,
        })
    }

    /// A new grant after the tracker rejected `rejected`, refreshing unless
    /// another request already did.
    async fn regrant(
        &self,
        client: &reqwest::Client,
        rejected: &Grant,
    ) -> Result<Grant, AuthError> {
        let mut session = self.inner.session.lock().await;
        if session.generation != rejected.generation {
            return Err(AuthError::SignedOut);
        }
        let replaced = session
            .access
            .as_ref()
            .is_some_and(|access| access.token != rejected.token);
        if !replaced {
            session.access = None;
            self.refresh_locked(&mut session, client).await?;
        }
        let token = session
            .access
            .as_ref()
            .map(|access| access.token.clone())
            .ok_or(AuthError::SignedOut)?;
        Ok(Grant {
            token,
            base: session.base.clone(),
            generation: session.generation,
        })
    }

    /// The tracker said this session is over (401 `session_revoked`).
    async fn revoked(&self, grant: &Grant) {
        let mut session = self.inner.session.lock().await;
        if session.generation == grant.generation && session.refresh.is_some() {
            tracing::info!("tracker sign-in: the tracker revoked this session");
            self.forget_locked(&mut session, Some(SIGNED_OUT_NOTICE.to_string()))
                .await;
        }
    }

    /// Send a request with a bearer token: refresh and retry once on a 401
    /// (`token_expired`, or anything else that a refresh can answer), sign
    /// out on `session_revoked`.
    async fn authorized<F>(
        &self,
        client: &reqwest::Client,
        build: F,
    ) -> Result<(reqwest::Response, u64), AuthError>
    where
        F: Fn(&Grant) -> Result<reqwest::RequestBuilder, String>,
    {
        let grant = self.grant(client).await?;
        let response = build(&grant)
            .map_err(AuthError::Other)?
            .send()
            .await
            .map_err(|e| AuthError::Network(network_error(e)))?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return Ok((response, grant.generation));
        }
        let body = response.text().await.unwrap_or_default();
        if api_error_code(&body).as_deref() == Some("session_revoked") {
            self.revoked(&grant).await;
            return Err(AuthError::SignedOut);
        }

        let grant = self.regrant(client, &grant).await?;
        let response = build(&grant)
            .map_err(AuthError::Other)?
            .send()
            .await
            .map_err(|e| AuthError::Network(network_error(e)))?;
        if response.status() == StatusCode::UNAUTHORIZED {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            if api_error_code(&body).as_deref() == Some("session_revoked") {
                self.revoked(&grant).await;
                return Err(AuthError::SignedOut);
            }
            return Err(AuthError::Http { status, body });
        }
        Ok((response, grant.generation))
    }

    /// Re-read whoami and publish it. Nothing to do when signed out.
    pub async fn refresh_whoami(&self, client: &reqwest::Client) {
        if self.inner.session.lock().await.refresh.is_none() {
            return;
        }
        let result = self
            .authorized(client, |grant| {
                Ok(client
                    .get(endpoint(&grant.base, "irminsul/whoami"))
                    .bearer_auth(&grant.token))
            })
            .await;
        let (whoami, error, generation) = match result {
            Err(AuthError::SignedOut) => return,
            Err(e) => (self.last_whoami(), Some(e.to_string()), None),
            Ok((response, generation)) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                let parsed = if status.is_success() {
                    serde_json::from_str::<serde_json::Value>(&body)
                        .map_err(|_| "the whoami answer is not JSON".to_string())
                        .and_then(|json| parse_whoami(&json))
                } else {
                    Err(http_failure(status, &body))
                };
                match parsed {
                    Ok(whoami) => {
                        tracing::info!(scope = ?whoami.scope, "tracker sign-in: whoami");
                        (Some(whoami), None, Some(generation))
                    }
                    Err(e) => (self.last_whoami(), Some(e), Some(generation)),
                }
            }
        };
        if let Some(e) = &error {
            tracing::warn!("tracker sign-in: whoami failed: {e}");
        }
        // Not over a sign-out or an address change that happened meanwhile.
        let session = self.inner.session.lock().await;
        if session.refresh.is_some() && generation.is_none_or(|g| g == session.generation) {
            self.publish(AuthStatus::SignedIn { whoami, error });
        }
    }

    /// Upload a GOOD snapshot with this session (contract section 6). The
    /// error has the key path's `HTTP {status} - {body}` shape.
    pub async fn upload(
        &self,
        client: &reqwest::Client,
        expected_base: &str,
        json: String,
        captured_at_ms: Option<i64>,
        timeout: Duration,
    ) -> Result<(), String> {
        let expected_base = normalize_base(expected_base);
        let result = self
            .authorized(client, |grant| {
                if grant.base != expected_base {
                    return Err("The tracker address changed; upload again".to_string());
                }
                let form = crate::monitor::snapshot_form(json.clone(), captured_at_ms)?;
                Ok(client
                    .post(endpoint(&grant.base, "irminsul/import"))
                    .timeout(timeout)
                    .bearer_auth(&grant.token)
                    .multipart(form))
            })
            .await;
        let (response, _) = result.map_err(|e| {
            tracing::error!("Tracker upload failed: {e}");
            e.to_string()
        })?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if status.is_success() {
            tracing::info!("Successfully uploaded data to tracker (signed in)");
            Ok(())
        } else {
            tracing::error!("Tracker upload failed ({}): {}", status, body);
            Err(http_failure(status, &body))
        }
    }

    pub fn cancel_sign_in(&self) {
        if let Some((_, cancel)) = self.inner.sign_in.lock().unwrap().as_ref() {
            cancel.cancel();
        }
    }

    /// Revoke the session on the tracker (best effort) and delete the
    /// stored token.
    pub async fn sign_out(&self, client: &reqwest::Client) {
        self.cancel_sign_in();
        let mut session = self.inner.session.lock().await;
        self.revoke_locked(&mut session, client).await;
        self.forget_locked(&mut session, None).await;
        tracing::info!("tracker sign-in: signed out");
    }

    async fn revoke_locked(&self, session: &mut Session, client: &reqwest::Client) {
        let Some(refresh) = session.refresh.clone() else {
            return;
        };
        match self.discovery_locked(session, client).await {
            Ok(discovery) => revoke(client, &discovery, &refresh).await,
            Err(e) => tracing::warn!("tracker sign-in: could not revoke: {e}"),
        }
    }

    /// Point the sign-in at another tracker address. Signs out of the old
    /// one first (revoke + delete), so its token is never sent anywhere
    /// else, then reads whatever is stored for the new one.
    pub async fn set_address(&self, client: &reqwest::Client, base: &str) {
        let base = normalize_base(base);
        {
            let mut session = self.inner.session.lock().await;
            if session.base == base {
                return;
            }
            tracing::info!("tracker sign-in: the tracker address changed");
            if session.refresh.is_some() {
                self.revoke_locked(&mut session, client).await;
                self.forget_locked(&mut session, None).await;
            }
            session.base = base;
            session.discovery = None;
            session.access = None;
            session.refresh = None;
            session.generation += 1;
        }
        self.cancel_sign_in();
        self.publish(AuthStatus::Loading);
        self.load(client).await;
    }
}

/// POST to the token endpoint.
async fn post_token(
    client: &reqwest::Client,
    url: &str,
    body: &serde_json::Value,
) -> Result<Tokens, TokenError> {
    let response = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| TokenError::Network(network_error(e)))?;
    let status = response.status().as_u16();
    let text = response
        .text()
        .await
        .map_err(|e| TokenError::Network(network_error(e)))?;
    parse_token_response(status, &text)
}

/// Revoke a refresh token (RFC 7009; the tracker answers 200 always).
async fn revoke(client: &reqwest::Client, discovery: &Discovery, refresh_token: &str) {
    let body = serde_json::json!({ "token": refresh_token, "client_id": CLIENT_ID });
    let result = client
        .post(&discovery.revoke_url)
        .timeout(REVOKE_TIMEOUT)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send()
        .await;
    match result {
        Ok(response) => tracing::info!(status = %response.status(), "tracker sign-in: revoked"),
        Err(e) => tracing::warn!("tracker sign-in: revoke failed: {}", network_error(e)),
    }
}

#[cfg(test)]
mod tests;

/// Against a real local tracker; ignored unless asked for (`tests/e2e/`).
#[cfg(test)]
mod e2e;
