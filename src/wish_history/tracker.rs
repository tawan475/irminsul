//! The tracker's wish routes (`/wishes/cursor`, `/wishes/import`) and the
//! credential they are called with.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::Banner;
use super::gacha_log::ApiRecord;
use crate::signin::{AuthError, TrackerAuth};

/// Records per import request: the tracker's limit.
pub(crate) const MAX_RECORDS_PER_IMPORT: usize = 2_000;

/// The language the records are fetched in (the URL's `lang`).
pub(crate) const RECORD_LANG: &str = "en-us";

/// How irminsul proves who it uploads for: the same choice as a snapshot
/// upload (`app::upload_credential`). Both routes accept either kind and
/// resolve it to an owner exactly like a snapshot upload does.
#[derive(Clone)]
pub(crate) enum TrackerCredential {
    /// The import key from Settings (`gdt_import_…` / `gdt_uk_…`), sent as
    /// `x-import-key`. Used only while not signed in.
    ImportKey(String),
    /// The tracker sign-in: a bearer token from [`TrackerAuth`], which
    /// refreshes it (under its own lock) and retries once on a 401, and ends
    /// the sign-in on `session_revoked`. `base` is the address the token must
    /// belong to.
    SignedIn { auth: TrackerAuth, base: String },
}

impl fmt::Debug for TrackerCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ImportKey(_) => f.write_str("ImportKey(<redacted>)"),
            Self::SignedIn { base, .. } => write!(f, "SignedIn({base})"),
        }
    }
}

/// The newest record id the tracker holds per banner.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Cursor {
    pub(crate) newest: BTreeMap<Banner, u64>,
}

impl Cursor {
    pub(crate) fn newest(&self, banner: Banner) -> Option<u64> {
        self.newest.get(&banner).copied()
    }
}

/// What an import did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Imported {
    pub(crate) added: u64,
    pub(crate) known: u64,
}

#[derive(Deserialize)]
struct CursorAnswer {
    #[serde(default)]
    newest: BTreeMap<String, Option<String>>,
}

#[derive(Deserialize)]
struct ImportAnswer {
    #[serde(default)]
    added: u64,
    #[serde(default)]
    known: u64,
}

#[derive(Deserialize)]
struct ErrorAnswer {
    error: ErrorBody,
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(default)]
    code: String,
    #[serde(default)]
    message: String,
}

/// One record as the import takes it.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct ImportRecord {
    pub(crate) id: String,
    pub(crate) gacha_type: String,
    pub(crate) time: String,
    pub(crate) name: String,
    pub(crate) item_type: String,
    pub(crate) rank_type: String,
    pub(crate) item_id: String,
}

impl From<&ApiRecord> for ImportRecord {
    fn from(record: &ApiRecord) -> Self {
        Self {
            id: record.id.clone(),
            gacha_type: record.gacha_type.clone(),
            time: record.time.clone(),
            name: record.name.clone(),
            item_type: record.item_type.clone(),
            rank_type: record.rank_type.clone(),
            item_id: record.item_id.clone(),
        }
    }
}

/// The body of `POST /wishes/import`.
#[derive(Debug, Serialize)]
pub(crate) struct ImportBody<'a> {
    pub(crate) uid: &'a str,
    pub(crate) region: &'a str,
    pub(crate) lang: &'a str,
    /// The UTC offset of the records' times (they are the server's local
    /// time).
    pub(crate) timezone: i32,
    pub(crate) records: Vec<ImportRecord>,
}

/// The UTC offset a region's record times are in: the UIGF table.
pub(crate) fn region_timezone(region: &str) -> i32 {
    match region {
        "os_usa" => -5,
        "os_euro" => 1,
        _ => 8,
    }
}

/// Talks to one tracker with one credential.
pub(crate) struct Tracker {
    pub(crate) http: reqwest::Client,
    /// The API base (`SavedAppState.tracker_api_url`).
    pub(crate) base_url: String,
    pub(crate) credential: TrackerCredential,
}

impl Tracker {
    fn url(&self, path: &str) -> String {
        format!("{}/wishes/{path}", self.base_url.trim_end_matches('/'))
    }

    /// `GET /wishes/cursor?uid=`.
    pub(crate) async fn cursor(&self, uid: &str) -> Result<Cursor, String> {
        let url = self.url("cursor");
        let body = self
            .send(|| self.http.get(&url).query(&[("uid", uid)]))
            .await?;
        let answer: CursorAnswer = serde_json::from_str(&body)
            .map_err(|e| format!("the tracker's wish cursor was unreadable: {e}"))?;
        let mut cursor = Cursor::default();
        for (banner, newest) in answer.newest {
            let (Ok(banner), Some(newest)) = (banner.parse::<Banner>(), newest) else {
                continue;
            };
            let newest = newest
                .parse::<u64>()
                .map_err(|_| format!("the tracker's wish cursor holds a bad id for {banner}"))?;
            cursor.newest.insert(banner, newest);
        }
        Ok(cursor)
    }

    /// `POST /wishes/import`, once per [`MAX_RECORDS_PER_IMPORT`] records,
    /// in the order given.
    pub(crate) async fn import(
        &self,
        uid: &str,
        region: &str,
        records: &[ApiRecord],
    ) -> Result<Imported, String> {
        let mut total = Imported::default();
        for chunk in records.chunks(MAX_RECORDS_PER_IMPORT) {
            let body = ImportBody {
                uid,
                region,
                lang: RECORD_LANG,
                timezone: region_timezone(region),
                records: chunk.iter().map(ImportRecord::from).collect(),
            };
            let url = self.url("import");
            let answer = self.send(|| self.http.post(&url).json(&body)).await?;
            let answer: ImportAnswer = serde_json::from_str(&answer)
                .map_err(|e| format!("the tracker's import answer was unreadable: {e}"))?;
            total.added += answer.added;
            total.known += answer.known;
        }
        Ok(total)
    }

    /// Send the request `build` makes with the credential; the body of a
    /// success, else what to tell the user. `build` may run twice (a
    /// signed-in retry after a refresh).
    async fn send(&self, build: impl Fn() -> reqwest::RequestBuilder) -> Result<String, String> {
        let response =
            match &self.credential {
                TrackerCredential::ImportKey(key) => build()
                    .header("x-import-key", key)
                    .send()
                    .await
                    .map_err(|e| format!("could not reach the tracker: {}", e.without_url()))?,
                TrackerCredential::SignedIn { auth, base } => auth
                    .send_signed_in(&self.http, base, |token| build().bearer_auth(token))
                    .await
                    .map_err(|error| match error {
                        AuthError::SignedOut => describe_failure(401, "session_revoked", ""),
                        AuthError::Http { status, body } => failure(status.as_u16(), &body),
                        other => format!("tracker: {other}"),
                    })?,
            };
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if status.is_success() {
            return Ok(body);
        }
        Err(failure(status.as_u16(), &body))
    }
}

/// What to say about a refused tracker request.
fn failure(status: u16, body: &str) -> String {
    match serde_json::from_str::<ErrorAnswer>(body) {
        Ok(ErrorAnswer { error }) => describe_failure(status, &error.code, &error.message),
        Err(_) => describe_failure(status, "", ""),
    }
}

/// The status line's words for the tracker's error codes (the ones
/// `/irminsul/import` uses, which the wish routes share), else the code and
/// the tracker's own sentence.
fn describe_failure(status: u16, code: &str, message: &str) -> String {
    let known = match code {
        // Only after the refresh and retry did not help.
        "token_expired" => "the sign-in expired; sign in again",
        "session_revoked" => "signed out of the tracker; sign in again",
        "upload_target_missing" => {
            "the upload target no longer exists; choose one with Configure on the tracker"
        }
        "uid_mismatch" => "the tracker account uploads go to has another UID",
        "uploads_blocked" => "uploads are blocked for this tracker account",
        "account_suspended" => "this tracker account is suspended",
        "rate_limited" => "the tracker is busy; the next key or wish tries again",
        "daily_upload_limit" => "today's upload limit on the tracker is reached",
        "storage_quota" => "the tracker storage is full",
        _ => "",
    };
    if !known.is_empty() {
        return format!("tracker: {known}");
    }
    match (code.is_empty(), message.is_empty()) {
        (true, _) if status == 429 => {
            "tracker: busy (HTTP 429); the next key or wish tries again".to_owned()
        }
        (true, _) => format!("tracker: HTTP {status}"),
        (false, true) => format!("tracker: HTTP {status} {code}"),
        (false, false) => format!("tracker: HTTP {status} {code} ({})", truncate(message, 160)),
    }
}

fn truncate(text: &str, max: usize) -> &str {
    match text.char_indices().nth(max) {
        Some((at, _)) => &text[..at],
        None => text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_time_zones_follow_uigf() {
        assert_eq!(region_timezone("os_usa"), -5);
        assert_eq!(region_timezone("os_euro"), 1);
        assert_eq!(region_timezone("os_asia"), 8);
        assert_eq!(region_timezone("os_cht"), 8);
        assert_eq!(region_timezone("cn_gf01"), 8);
    }

    #[test]
    fn the_credential_never_shows_in_debug_output() {
        let rendered = format!("{:?}", TrackerCredential::ImportKey("gdt_uk_secret".into()));
        assert!(!rendered.contains("secret"), "{rendered}");
    }

    #[test]
    fn the_trackers_error_codes_read_as_sentences() {
        let says = |status, code: &str| {
            failure(
                status,
                &serde_json::json!({ "error": { "code": code } }).to_string(),
            )
        };
        assert_eq!(
            says(409, "upload_target_missing"),
            "tracker: the upload target no longer exists; choose one with Configure on the tracker"
        );
        assert_eq!(
            says(409, "uid_mismatch"),
            "tracker: the tracker account uploads go to has another UID"
        );
        assert_eq!(
            says(403, "uploads_blocked"),
            "tracker: uploads are blocked for this tracker account"
        );
        assert_eq!(
            says(403, "account_suspended"),
            "tracker: this tracker account is suspended"
        );
        assert_eq!(
            says(429, "rate_limited"),
            "tracker: the tracker is busy; the next key or wish tries again"
        );
        assert_eq!(
            says(401, "session_revoked"),
            "tracker: signed out of the tracker; sign in again"
        );
        assert_eq!(
            says(401, "token_expired"),
            "tracker: the sign-in expired; sign in again"
        );
        assert_eq!(
            failure(429, "busy"),
            "tracker: busy (HTTP 429); the next key or wish tries again"
        );
        assert_eq!(failure(404, "<html>"), "tracker: HTTP 404");
        assert_eq!(
            failure(
                400,
                r#"{"error":{"code":"bad_records","message":"No records"}}"#
            ),
            "tracker: HTTP 400 bad_records (No records)"
        );
    }

    #[test]
    fn long_error_messages_are_cut_on_a_character_boundary() {
        assert_eq!(truncate("abc", 5), "abc");
        assert_eq!(truncate("aéc", 2), "aé");
    }
}
