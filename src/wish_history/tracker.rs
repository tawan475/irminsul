//! The tracker's wish routes (`/wishes/cursor`, `/wishes/import`) and the
//! credential they are called with.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::Banner;
use super::gacha_log::ApiRecord;

/// Records per import request: the tracker's limit.
pub(crate) const MAX_RECORDS_PER_IMPORT: usize = 2_000;

/// The language the records are fetched in (the URL's `lang`).
pub(crate) const RECORD_LANG: &str = "en-us";

/// How irminsul proves who it uploads for.
///
/// Both routes accept either kind and resolve it to an owner exactly like a
/// snapshot upload does.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum TrackerCredential {
    /// The import key from Settings (`gdt_import_…` / `gdt_uk_…`), sent as
    /// `x-import-key`.
    ImportKey(String),
    // SIGN-IN: when "Sign in with the tracker" lands, add
    //
    //     /// An irminsul access token, sent as `Authorization: Bearer`.
    //     Bearer(String),
    //
    // send it in `apply` below with `request.bearer_auth(token)`, and have
    // `credential_for` (in `mod.rs`) return it in place of the import key
    // while signed in. The access token lasts 15 minutes: hand the sync a
    // fresh one per run, and refresh and retry once on a 401 `token_expired`.
}

impl TrackerCredential {
    fn apply(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self {
            Self::ImportKey(key) => request.header("x-import-key", key),
        }
    }
}

impl fmt::Debug for TrackerCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ImportKey(_) => f.write_str("ImportKey(<redacted>)"),
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
        let request = self.http.get(self.url("cursor")).query(&[("uid", uid)]);
        let body = self.send(request).await?;
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
            let request = self.http.post(self.url("import")).json(&body);
            let answer = self.send(request).await?;
            let answer: ImportAnswer = serde_json::from_str(&answer)
                .map_err(|e| format!("the tracker's import answer was unreadable: {e}"))?;
            total.added += answer.added;
            total.known += answer.known;
        }
        Ok(total)
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> Result<String, String> {
        let response = self
            .credential
            .apply(request)
            .send()
            .await
            .map_err(|e| format!("could not reach the tracker: {}", e.without_url()))?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if status.is_success() {
            return Ok(body);
        }
        Err(match serde_json::from_str::<ErrorAnswer>(&body) {
            Ok(ErrorAnswer { error }) if !error.code.is_empty() => {
                if error.message.is_empty() {
                    format!("tracker: HTTP {} {}", status.as_u16(), error.code)
                } else {
                    format!(
                        "tracker: HTTP {} {} ({})",
                        status.as_u16(),
                        error.code,
                        truncate(&error.message, 160)
                    )
                }
            }
            _ => format!("tracker: HTTP {}", status.as_u16()),
        })
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
    fn long_error_messages_are_cut_on_a_character_boundary() {
        assert_eq!(truncate("abc", 5), "abc");
        assert_eq!(truncate("aéc", 2), "aé");
    }
}
