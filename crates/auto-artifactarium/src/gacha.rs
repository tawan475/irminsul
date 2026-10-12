//! The wish (gacha) messages, recognised by shape.
//!
//! Two server answers matter for wish history:
//!
//! * **`GetAuthkeyRsp`** (command 9681 in 7.1) answers the client's request for
//!   a web view key. Opening Wish -> History in game asks for one with
//!   `auth_appid` `webview_gacha`; that key is what the wish history API takes.
//!   Logging in asks for others (`ugc_login` in 7.1), which are for something
//!   else. The message is three strings -- the key, the app id, the game
//!   (`hk4e_global` / `hk4e_cn`) -- beside two small numbers (`sign_type`,
//!   `authkey_ver`) and the retcode.
//! * **`DoGachaRsp`** (command 21670 in 7.1) answers a wish. It carries one
//!   entry per pull, each wrapping the pulled item, and the banner's
//!   `gacha_type` among a dozen counters.
//!
//! Like every other message this library reads, both command ids and every
//! field number are reshuffled by each game version, so nothing here names one.
//!
//! ## The key is a password
//!
//! The authkey grants read access to the account's wish history for about a
//! day. [`GachaAuthKey`]'s `Debug` never prints it, nothing in this crate logs
//! it, and the only way to read it is [`GachaAuthKey::authkey`].
//!
//! ## Why these do not claim other messages
//!
//! `GetAuthkeyRsp`: exactly three length-delimited fields, each a string, and
//! each a different one of: a game id (`hk4e_` and a lowercase word), an app
//! id (a lowercase identifier), and a long base64 key -- plus at most a few
//! small scalars. The token exchange (`GetPlayerTokenRsp`) also carries
//! `hk4e_global` and base64 strings, but with a dozen other fields beside them;
//! no other message in a recorded 7.1 session has this shape.
//!
//! `DoGachaRsp`: one repeated submessage field of 1 or 10 entries, each of
//! which wraps exactly one item whose id is a character's or a weapon's, with
//! nothing but flags (0/1) beside it; and among the scalars a wish's currency
//! (Intertwined or Acquaint Fate, items 223/224), the pull count itself, and
//! a known banner type. Item hint and reward lists carry their items directly,
//! not wrapped, and the banner list (`GetGachaInfoRsp`) carries strings and
//! timestamps in its entries.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::RangeInclusive;

use protobuf::Message;
use protobuf::UnknownValueRef::{Fixed32, Fixed64, LengthDelimited, Varint};

use crate::r#gen::protos::Unk;

/// The banner types a wish can be made on, as the game and the wish history
/// API both number them: 100 Beginners', 200 Standard, 301 and 400 the two
/// character event banners, 302 the weapon banner, 500 Chronicled.
pub const GACHA_TYPES: [u32; 6] = [100, 200, 301, 302, 400, 500];

/// The two wish currencies: Intertwined Fate (event banners) and Acquaint Fate
/// (Standard and Beginners').
pub const WISH_CURRENCY_IDS: [u64; 2] = [223, 224];

/// Character ids as a pull carries them (`10000002` Kamisato Ayaka ...).
const PULLED_AVATAR_IDS: RangeInclusive<u64> = 10_000_001..=10_000_999;

/// Weapon ids: five-digit, 11xxx swords to 15xxx bows.
const PULLED_WEAPON_IDS: RangeInclusive<u64> = 11_000..=15_999;

/// Pull counts a wish can have.
const PULL_COUNTS: [usize; 2] = [1, 10];

/// The shortest authkey believed. Real ones are well over a thousand
/// characters; this only rules out short base64-looking strings.
const MIN_AUTHKEY_LEN: usize = 64;

/// The longest authkey believed.
const MAX_AUTHKEY_LEN: usize = 16 * 1024;

/// Scalars beside the key's strings: `sign_type`, `authkey_ver`, the retcode,
/// and some room.
const MAX_AUTHKEY_SCALARS: usize = 6;

/// A web view key from `GetAuthkeyRsp`.
///
/// Its `Debug` prints everything but the key.
#[derive(Clone, PartialEq, Eq)]
pub struct GachaAuthKey {
    authkey: String,
    /// What the key is for: `webview_gacha` for wish history.
    pub auth_appid: String,
    /// The game: `hk4e_global` or `hk4e_cn`.
    pub game_biz: String,
}

impl GachaAuthKey {
    /// Build one by hand, e.g. in a test.
    pub fn new(
        authkey: impl Into<String>,
        auth_appid: impl Into<String>,
        game_biz: impl Into<String>,
    ) -> Self {
        Self {
            authkey: authkey.into(),
            auth_appid: auth_appid.into(),
            game_biz: game_biz.into(),
        }
    }

    /// The key itself. A credential: never log or persist it.
    pub fn authkey(&self) -> &str {
        &self.authkey
    }

    /// Whether this key opens the wish history (`auth_appid` `webview_gacha`).
    pub fn is_wish_history_key(&self) -> bool {
        self.auth_appid == "webview_gacha"
    }
}

impl fmt::Debug for GachaAuthKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GachaAuthKey")
            .field(
                "authkey",
                &format_args!("<redacted, {} chars>", self.authkey.len()),
            )
            .field("auth_appid", &self.auth_appid)
            .field("game_biz", &self.game_biz)
            .finish()
    }
}

/// A wish made in game, from `DoGachaRsp`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GachaWish {
    /// The banner, one of [`GACHA_TYPES`]; `None` when more than one scalar
    /// held a banner-type value and they could not be told apart.
    pub gacha_type: Option<u32>,
    /// 1 or 10.
    pub pulls: u32,
}

fn is_game_biz(s: &str) -> bool {
    s.strip_prefix("hk4e_").is_some_and(|rest| {
        (1..=16).contains(&rest.len()) && rest.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
    })
}

fn is_app_id(s: &str) -> bool {
    let bytes = s.as_bytes();
    (2..=32).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && !is_game_biz(s)
}

fn is_authkey(s: &str) -> bool {
    (MIN_AUTHKEY_LEN..=MAX_AUTHKEY_LEN).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

/// Recover the key from a `GetAuthkeyRsp` payload, or `None` if it is not one.
///
/// Any app id is returned (the login's `ugc_login` keys too); a caller that
/// wants the wish history checks [`GachaAuthKey::is_wish_history_key`].
pub fn matches_get_authkey_rsp(data: &[u8]) -> Option<GachaAuthKey> {
    let msg = Unk::parse_from_bytes(data).ok()?;

    let mut strings: BTreeMap<u32, &str> = BTreeMap::new();
    let mut scalars: BTreeMap<u32, u64> = BTreeMap::new();
    for (tag, value) in msg.unknown_fields().iter() {
        match value {
            LengthDelimited(bytes) => {
                let s = std::str::from_utf8(bytes).ok()?;
                if strings.insert(tag, s).is_some() {
                    return None;
                }
            }
            Varint(value) => {
                // A failed answer carries a negative retcode (a ten-byte
                // varint) and no key; a real answer's scalars are small.
                if value > u64::from(u32::MAX) || scalars.insert(tag, value).is_some() {
                    return None;
                }
            }
            Fixed32(_) | Fixed64(_) => return None,
        }
    }
    if strings.len() != 3 || scalars.len() > MAX_AUTHKEY_SCALARS {
        return None;
    }

    let pick = |test: fn(&str) -> bool| {
        let found: Vec<&str> = strings.values().copied().filter(|s| test(s)).collect();
        match found.as_slice() {
            [one] => Some(*one),
            _ => None,
        }
    };
    let game_biz = pick(is_game_biz)?;
    let auth_appid = pick(is_app_id)?;
    let authkey = pick(is_authkey)?;

    Some(GachaAuthKey::new(authkey, auth_appid, game_biz))
}

/// A submessage's varint fields, keyed by tag, or `None` if it holds anything
/// else or repeats a tag.
fn varint_fields(bytes: &[u8]) -> Option<BTreeMap<u32, u64>> {
    let msg = Unk::parse_from_bytes(bytes).ok()?;
    let mut fields = BTreeMap::new();
    for (tag, value) in msg.unknown_fields().iter() {
        let Varint(value) = value else {
            return None;
        };
        if fields.insert(tag, value).is_some() {
            return None;
        }
    }
    Some(fields)
}

/// Read a submessage as the pulled item (`ItemParam {item_id, count}`): a
/// character or weapon id and, if present, a count of 1.
fn read_pulled_item(bytes: &[u8]) -> Option<u64> {
    let fields = varint_fields(bytes)?;
    if fields.is_empty() || fields.len() > 2 {
        return None;
    }
    let (ids, rest): (Vec<u64>, Vec<u64>) = fields
        .values()
        .partition(|id| PULLED_AVATAR_IDS.contains(id) || PULLED_WEAPON_IDS.contains(id));
    match (ids.as_slice(), rest.as_slice()) {
        ([id], []) | ([id], [1]) => Some(*id),
        _ => None,
    }
}

/// Read one entry of the pull list (`GachaItem`): exactly one pulled item,
/// any number of other submessages (the Starglitter/Stardust tokens and the
/// constellation transfer items), and flags.
fn read_gacha_item(bytes: &[u8]) -> Option<u64> {
    let msg = Unk::parse_from_bytes(bytes).ok()?;
    let mut pulled = None;
    for (_, value) in msg.unknown_fields().iter() {
        match value {
            Varint(flag) if flag <= 1 => {}
            Varint(_) | Fixed32(_) | Fixed64(_) => return None,
            LengthDelimited(inner) => {
                if let Some(id) = read_pulled_item(inner) {
                    if pulled.is_some() {
                        return None;
                    }
                    pulled = Some(id);
                } else if Unk::parse_from_bytes(inner).is_err() {
                    return None;
                }
            }
        }
    }
    pulled
}

/// Recover what a `DoGachaRsp` payload says about the wish, or `None` if it is
/// not one. See the module documentation for the shape.
pub fn matches_do_gacha_rsp(data: &[u8]) -> Option<GachaWish> {
    let msg = Unk::parse_from_bytes(data).ok()?;

    let mut lists: BTreeMap<u32, Vec<&[u8]>> = BTreeMap::new();
    let mut scalars: BTreeMap<u32, u64> = BTreeMap::new();
    for (tag, value) in msg.unknown_fields().iter() {
        match value {
            LengthDelimited(bytes) => lists.entry(tag).or_default().push(bytes),
            Varint(value) => {
                if scalars.insert(tag, value).is_some() {
                    return None;
                }
            }
            Fixed32(_) | Fixed64(_) => return None,
        }
    }

    let mut lists = lists.into_values();
    let (Some(entries), None) = (lists.next(), lists.next()) else {
        return None;
    };
    if !PULL_COUNTS.contains(&entries.len()) {
        return None;
    }
    for entry in &entries {
        read_gacha_item(entry)?;
    }

    let values: Vec<u64> = scalars.into_values().collect();
    if !values.iter().any(|value| WISH_CURRENCY_IDS.contains(value)) {
        return None;
    }
    if !values.contains(&(entries.len() as u64)) {
        return None;
    }
    let mut types: Vec<u32> = values
        .iter()
        .filter_map(|&value| u32::try_from(value).ok())
        .filter(|value| GACHA_TYPES.contains(value))
        .collect();
    types.sort_unstable();
    types.dedup();
    let gacha_type = match types.as_slice() {
        [] => return None,
        [one] => Some(*one),
        _ => None,
    };

    Some(GachaWish {
        gacha_type,
        pulls: entries.len() as u32,
    })
}

/// The most banners believed in one banner list.
const MAX_BANNERS: usize = 64;

/// The longest record link query believed.
const MAX_RECORD_QUERY_LEN: usize = 1024;

/// One banner's wish history link, from `GetGachaInfoRsp`.
///
/// The server sends every banner a link to its history page
/// (`https://…/index.html?win_mode=fullscreen&…&init_type=301&gacha_id=…&timestamp=…`).
/// When the player opens the history, the game adds its own parameters and
/// the key to that link's query and calls the wish history API with it; this
/// is the query, verbatim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GachaRecordLink {
    /// The banner, one of [`GACHA_TYPES`]; `None` when it could not be told.
    pub gacha_type: Option<u32>,
    /// The link's query, as the server sent it (no leading `?`).
    pub query: String,
}

/// The query of a history page link, if `s` is one: an http(s) URL whose
/// query names the wish web view and an `init_type` (the history category),
/// made of nothing but plain URL characters. Event banners' links also name
/// a `gacha_id`; the Beginners' banner's does not.
fn record_link_query(s: &str) -> Option<&str> {
    if !(s.starts_with("https://") || s.starts_with("http://")) {
        return None;
    }
    let (_, query) = s.split_once('?')?;
    let plain = query
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'=' | b'&' | b'_' | b'-' | b'.'));
    let has = |name: &str| query.split('&').any(|pair| pair.starts_with(name));
    (plain
        && query.len() <= MAX_RECORD_QUERY_LEN
        && query
            .split('&')
            .any(|pair| pair == "auth_appid=webview_gacha")
        && has("init_type="))
    .then_some(query)
}

/// Read one entry of the banner list (`GachaInfo`): its history link and its
/// banner type.
fn read_gacha_info(bytes: &[u8]) -> Option<GachaRecordLink> {
    let msg = Unk::parse_from_bytes(bytes).ok()?;
    let mut query = None;
    let mut types = Vec::new();
    for (_, value) in msg.unknown_fields().iter() {
        match value {
            Varint(value) => {
                if let Ok(value) = u32::try_from(value)
                    && GACHA_TYPES.contains(&value)
                    && !types.contains(&value)
                {
                    types.push(value);
                }
            }
            LengthDelimited(bytes) => {
                // The link appears more than once (the global and the
                // overseas copy); they are the same.
                if query.is_none()
                    && let Ok(s) = std::str::from_utf8(bytes)
                {
                    query = record_link_query(s).map(str::to_owned);
                }
            }
            Fixed32(_) | Fixed64(_) => {}
        }
    }
    Some(GachaRecordLink {
        gacha_type: match types.as_slice() {
            [one] => Some(*one),
            _ => None,
        },
        query: query?,
    })
}

/// Recover every banner's history link from a `GetGachaInfoRsp` payload, or
/// `None` if it is not one.
///
/// The shape: one repeated submessage field (the banner list, 1 to 64
/// entries) beside scalars, every entry carrying a history
/// page link of the wish web view. No other message carries those links.
pub fn matches_get_gacha_info_rsp(data: &[u8]) -> Option<Vec<GachaRecordLink>> {
    let msg = Unk::parse_from_bytes(data).ok()?;
    let mut lists: BTreeMap<u32, Vec<&[u8]>> = BTreeMap::new();
    for (tag, value) in msg.unknown_fields().iter() {
        match value {
            LengthDelimited(bytes) => lists.entry(tag).or_default().push(bytes),
            Varint(_) => {}
            Fixed32(_) | Fixed64(_) => return None,
        }
    }
    let mut lists = lists.into_values();
    let (Some(entries), None) = (lists.next(), lists.next()) else {
        return None;
    };
    if entries.len() > MAX_BANNERS {
        return None;
    }
    entries.iter().map(|entry| read_gacha_info(entry)).collect()
}

/// Whether `s` is a full client version (`OSRELWin7.1.0_R11111111_S22222222_D33333333`):
/// a release name -- capitals, the platform, a dotted version -- then at least
/// two `_<capital><digits>` build numbers.
fn is_client_version(s: &str) -> bool {
    if s.len() > 96 {
        return false;
    }
    let mut parts = s.split('_');
    let Some(release) = parts.next() else {
        return false;
    };
    let builds: Vec<&str> = parts.collect();
    let capitals = release.bytes().take_while(u8::is_ascii_uppercase).count();
    let rest = &release[capitals..];
    let letters = rest.bytes().take_while(u8::is_ascii_alphabetic).count();
    let version = &rest[letters..];
    let dotted = version.split('.').collect::<Vec<_>>();
    capitals >= 2
        && letters >= 1
        && dotted.len() == 3
        && dotted
            .iter()
            .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        && builds.len() >= 2
        && builds.iter().all(|build| {
            let bytes = build.as_bytes();
            bytes.len() >= 2
                && bytes[0].is_ascii_uppercase()
                && bytes[1..].iter().all(u8::is_ascii_digit)
        })
}

/// Recover the client's full version string from a payload that carries it
/// as a top-level string (the client's `GetPlayerTokenReq` at login), or
/// `None`. The wish history link names it (`game_version`).
pub fn matches_client_version(data: &[u8]) -> Option<String> {
    let msg = Unk::parse_from_bytes(data).ok()?;
    let mut found = None;
    for (_, value) in msg.unknown_fields().iter() {
        if let LengthDelimited(bytes) = value
            && let Ok(s) = std::str::from_utf8(bytes)
            && is_client_version(s)
        {
            if found.as_deref().is_some_and(|other| other != s) {
                return None;
            }
            found = Some(s.to_owned());
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommandMatch, GameCommand, classify_command};

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    fn field_varint(tag: u32, value: u64) -> Vec<u8> {
        let mut out = varint(u64::from(tag) << 3);
        out.extend(varint(value));
        out
    }

    fn field_bytes(tag: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = varint((u64::from(tag) << 3) | 2);
        out.extend(varint(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    fn command(command_id: u16, payload: &[u8]) -> GameCommand {
        let mut out = vec![0x45, 0x67];
        out.extend(command_id.to_be_bytes());
        out.extend(0u16.to_be_bytes());
        out.extend((payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out.extend([0x89, 0xAB]);
        GameCommand::try_new(out).expect("fixture should be a well formed command")
    }

    /// A synthetic key: base64 alphabet, the length of a real one, nothing in
    /// it from any account.
    fn synthetic_authkey() -> String {
        let mut key = String::new();
        while key.len() < 1360 {
            key.push_str("SyNtHeTiC+tEsT/kEy0123456789");
        }
        key.push_str("==");
        key
    }

    /// `GetAuthkeyRsp` with the 7.1 field numbers.
    fn authkey_rsp(appid: &str, biz: &str, key: &str) -> Vec<u8> {
        [
            field_varint(1, 2),
            field_bytes(3, key.as_bytes()),
            field_bytes(5, appid.as_bytes()),
            field_varint(8, 1),
            field_bytes(15, biz.as_bytes()),
        ]
        .concat()
    }

    #[test]
    fn the_7_1_key_answer_is_read() {
        let key = synthetic_authkey();
        let found =
            matches_get_authkey_rsp(&authkey_rsp("webview_gacha", "hk4e_global", &key)).unwrap();
        assert_eq!(found.authkey(), key);
        assert_eq!(found.auth_appid, "webview_gacha");
        assert_eq!(found.game_biz, "hk4e_global");
        assert!(found.is_wish_history_key());
    }

    #[test]
    fn key_field_numbers_are_found_rather_than_assumed() {
        let key = synthetic_authkey();
        let payload = [
            field_bytes(2, b"hk4e_cn"),
            field_varint(7, 1),
            field_bytes(9, key.as_bytes()),
            field_bytes(11, b"webview_gacha"),
            field_varint(13, 2),
        ]
        .concat();
        let found = matches_get_authkey_rsp(&payload).unwrap();
        assert_eq!(found.authkey(), key);
        assert_eq!(found.game_biz, "hk4e_cn");
    }

    #[test]
    fn a_login_key_is_recognised_but_is_not_for_wish_history() {
        let found = matches_get_authkey_rsp(&authkey_rsp(
            "ugc_login",
            "hk4e_global",
            &synthetic_authkey(),
        ))
        .unwrap();
        assert_eq!(found.auth_appid, "ugc_login");
        assert!(!found.is_wish_history_key());
    }

    #[test]
    fn the_key_never_shows_in_debug_output() {
        let key = synthetic_authkey();
        let found =
            matches_get_authkey_rsp(&authkey_rsp("webview_gacha", "hk4e_global", &key)).unwrap();
        let rendered = format!("{found:?} {:?}", CommandMatch::AuthKey(found.clone()));
        assert!(!rendered.contains("SyNtHeTiC"), "{rendered}");
        assert!(rendered.contains("webview_gacha"), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    #[test]
    fn the_key_answer_is_classified_as_a_key_and_nothing_else() {
        let payload = authkey_rsp("webview_gacha", "hk4e_global", &synthetic_authkey());
        match classify_command(&command(9681, &payload)) {
            Some(CommandMatch::AuthKey(key)) => assert!(key.is_wish_history_key()),
            other => panic!("expected a key, got {other:?}"),
        }
    }

    #[test]
    fn the_key_request_is_not_a_key() {
        // GetAuthkeyReq: the app id and two numbers, no key.
        let req = [
            field_varint(3, 1),
            field_bytes(8, b"webview_gacha"),
            field_varint(15, 2),
        ]
        .concat();
        assert_eq!(matches_get_authkey_rsp(&req), None);
    }

    #[test]
    fn a_failed_key_answer_is_not_a_key() {
        // A retcode of -1 is a ten-byte varint, and there is no key.
        let failed = [
            field_varint(6, (-1i64) as u64),
            field_bytes(5, b"webview_gacha"),
            field_bytes(15, b"hk4e_global"),
        ]
        .concat();
        assert_eq!(matches_get_authkey_rsp(&failed), None);
    }

    #[test]
    fn short_or_non_base64_keys_and_extra_strings_are_refused() {
        let short = authkey_rsp("webview_gacha", "hk4e_global", "c2hvcnQ=");
        assert_eq!(matches_get_authkey_rsp(&short), None);

        let not_base64 = "not a key, just a long sentence with spaces in it ".repeat(4);
        let prose = authkey_rsp("webview_gacha", "hk4e_global", &not_base64);
        assert_eq!(matches_get_authkey_rsp(&prose), None);

        // A fourth string: some other message carrying the game id.
        let mut more = authkey_rsp("webview_gacha", "hk4e_global", &synthetic_authkey());
        more.extend(field_bytes(20, b"TH"));
        assert_eq!(matches_get_authkey_rsp(&more), None);

        // Two keys, or no game id: nothing to tell apart.
        let two_keys = [
            field_bytes(3, synthetic_authkey().as_bytes()),
            field_bytes(4, synthetic_authkey().as_bytes()),
            field_bytes(15, b"hk4e_global"),
        ]
        .concat();
        assert_eq!(matches_get_authkey_rsp(&two_keys), None);
        let no_biz = authkey_rsp("webview_gacha", "mihoyo", &synthetic_authkey());
        assert_eq!(matches_get_authkey_rsp(&no_biz), None);
    }

    #[test]
    fn a_token_answer_carrying_the_game_id_is_not_a_key() {
        // GetPlayerTokenRsp-like: the game id and base64 strings among many
        // other fields.
        let payload = [
            field_varint(10, 811_111_111),
            field_bytes(11, b"hk4e_global"),
            field_varint(12, 1),
            field_bytes(342, b"TH"),
            field_bytes(368, synthetic_authkey().as_bytes()),
            field_bytes(790, b"mihoyo"),
            field_bytes(1435, &[0x08, 0x01, 0x10, 0x02]),
        ]
        .concat();
        assert_eq!(matches_get_authkey_rsp(&payload), None);
    }

    // -- DoGachaRsp --------------------------------------------------------

    fn item_param(item_id: u64, count: u64) -> Vec<u8> {
        [field_varint(1, item_id), field_varint(2, count)].concat()
    }

    /// One `GachaItem` with the 7.1 field numbers: the pulled item, its
    /// Starglitter/Stardust tokens, and optionally a constellation transfer.
    fn gacha_item(item_id: u64, transfer: bool) -> Vec<u8> {
        let mut out = Vec::new();
        if transfer {
            let transfer_item = [
                field_bytes(3, &item_param(1_102_101, 1)),
                field_varint(12, 1),
            ]
            .concat();
            out.extend(field_bytes(5, &transfer_item));
        }
        out.extend(field_bytes(6, &item_param(item_id, 1)));
        out.extend(field_bytes(8, &item_param(222, 15)));
        if !transfer {
            out.extend(field_varint(12, 1));
        }
        out
    }

    /// `DoGachaRsp` with the 7.1 field numbers (Grasscutter's field set).
    fn do_gacha_rsp(gacha_type: u64, items: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(field_varint(1, gacha_type));
        out.extend(field_varint(2, 0x5f3a_91c2));
        out.extend(field_varint(3, u64::from(u32::MAX)));
        out.extend(field_varint(5, 223));
        out.extend(field_varint(6, 903));
        out.extend(field_varint(7, 1));
        out.extend(field_varint(9, u64::from(u32::MAX)));
        out.extend(field_varint(10, 10));
        out.extend(field_varint(11, items.len() as u64));
        out.extend(field_varint(14, 223));
        for item in items {
            out.extend(field_bytes(13, item));
        }
        out
    }

    fn ten_pull() -> Vec<Vec<u8>> {
        let mut items: Vec<Vec<u8>> = (0..8).map(|n| gacha_item(13_301 + n, false)).collect();
        items.push(gacha_item(10_000_031, true));
        items.push(gacha_item(10_000_089, false));
        items
    }

    #[test]
    fn a_ten_pull_is_read_with_its_banner() {
        assert_eq!(
            matches_do_gacha_rsp(&do_gacha_rsp(301, &ten_pull())),
            Some(GachaWish {
                gacha_type: Some(301),
                pulls: 10,
            })
        );
    }

    #[test]
    fn a_single_pull_on_each_banner_is_read() {
        for banner in GACHA_TYPES {
            let wish = matches_do_gacha_rsp(&do_gacha_rsp(
                u64::from(banner),
                &[gacha_item(15_401, false)],
            ));
            assert_eq!(
                wish,
                Some(GachaWish {
                    gacha_type: Some(banner),
                    pulls: 1,
                }),
                "banner {banner}"
            );
        }
    }

    #[test]
    fn wish_field_numbers_are_found_rather_than_assumed() {
        let mut out = Vec::new();
        out.extend(field_varint(2, 224));
        out.extend(field_varint(4, 1));
        out.extend(field_varint(1464, 3));
        out.extend(field_varint(7, 200));
        let item = [field_varint(2, 1), field_bytes(9, &item_param(11_401, 1))].concat();
        out.extend(field_bytes(3, &item));
        assert_eq!(
            matches_do_gacha_rsp(&out),
            Some(GachaWish {
                gacha_type: Some(200),
                pulls: 1,
            })
        );
    }

    #[test]
    fn two_banner_like_scalars_leave_the_banner_unknown() {
        let mut payload = do_gacha_rsp(302, &[gacha_item(15_401, false)]);
        // A daily wish count that happens to be 200.
        payload.extend(field_varint(1464, 200));
        assert_eq!(
            matches_do_gacha_rsp(&payload),
            Some(GachaWish {
                gacha_type: None,
                pulls: 1,
            })
        );
    }

    #[test]
    fn the_wish_answer_is_classified_as_a_wish_and_nothing_else() {
        let payload = do_gacha_rsp(400, &ten_pull());
        match classify_command(&command(21670, &payload)) {
            Some(CommandMatch::Wish(wish)) => assert_eq!(wish.gacha_type, Some(400)),
            other => panic!("expected a wish, got {other:?}"),
        }
    }

    #[test]
    fn a_failed_wish_is_not_a_wish() {
        // An error answer: a retcode and nothing else.
        assert_eq!(matches_do_gacha_rsp(&field_varint(4, 10_101)), None);
        assert_eq!(matches_do_gacha_rsp(&do_gacha_rsp(301, &[])), None);
    }

    #[test]
    fn pull_counts_other_than_one_and_ten_are_refused() {
        let three: Vec<Vec<u8>> = (0..3).map(|n| gacha_item(13_301 + n, false)).collect();
        assert_eq!(matches_do_gacha_rsp(&do_gacha_rsp(301, &three)), None);
    }

    #[test]
    fn a_banner_type_the_game_does_not_have_is_refused() {
        assert_eq!(
            matches_do_gacha_rsp(&do_gacha_rsp(303, &[gacha_item(15_401, false)])),
            None
        );
    }

    #[test]
    fn an_item_list_without_the_wish_currency_is_not_a_wish() {
        // The same pull list beside scalars that are not a wish's.
        let payload = [
            field_varint(1, 301),
            field_varint(11, 1),
            field_bytes(13, &gacha_item(15_401, false)),
        ]
        .concat();
        assert_eq!(matches_do_gacha_rsp(&payload), None);
    }

    #[test]
    fn an_item_hint_list_is_not_a_wish() {
        // ItemAddHintNotify-like: items carried directly, not wrapped, beside
        // the same scalars a wish has.
        let hint = |id: u64| {
            [
                field_varint(1, id),
                field_varint(2, 1),
                field_varint(3, 1),
                field_varint(4, (811_111_111u64 << 32) | 7),
            ]
            .concat()
        };
        let payload = [
            field_varint(1, 301),
            field_varint(2, 223),
            field_varint(3, 1),
            field_bytes(5, &hint(15_401)),
        ]
        .concat();
        assert_eq!(matches_do_gacha_rsp(&payload), None);
    }

    #[test]
    fn a_banner_list_is_not_a_wish() {
        // GetGachaInfoRsp-like: entries with strings and timestamps.
        let info = [
            field_varint(2, 301),
            field_varint(3, 1_790_000_000),
            field_varint(6, 1_780_000_000),
            field_varint(8, 223),
            field_bytes(15, b"GachaShowPanel_A001"),
            field_bytes(1343, &[0x0f, 0x10]),
        ]
        .concat();
        let payload = [
            field_varint(1, 1),
            field_varint(11, 223),
            field_bytes(14, &info),
        ]
        .concat();
        assert_eq!(matches_do_gacha_rsp(&payload), None);
    }

    #[test]
    fn an_entry_whose_item_is_not_a_character_or_weapon_is_refused() {
        // A material (Mora) where the pulled item should be.
        assert_eq!(
            matches_do_gacha_rsp(&do_gacha_rsp(301, &[gacha_item(202, false)])),
            None
        );
        // An entry with a counter beside its item.
        let entry = [field_bytes(6, &item_param(15_401, 1)), field_varint(7, 42)].concat();
        assert_eq!(matches_do_gacha_rsp(&do_gacha_rsp(301, &[entry])), None);
        // An entry with two pulled items.
        let entry = [
            field_bytes(6, &item_param(15_401, 1)),
            field_bytes(7, &item_param(15_402, 1)),
        ]
        .concat();
        assert_eq!(matches_do_gacha_rsp(&do_gacha_rsp(301, &[entry])), None);
    }

    #[test]
    fn a_second_list_or_a_fixed_width_field_is_not_a_wish() {
        let mut payload = do_gacha_rsp(301, &[gacha_item(15_401, false)]);
        payload.extend(field_bytes(20, &gacha_item(15_402, false)));
        assert_eq!(matches_do_gacha_rsp(&payload), None);

        let mut payload = do_gacha_rsp(301, &[gacha_item(15_401, false)]);
        payload.extend(varint((21 << 3) | 5));
        payload.extend([0, 0, 0, 0]);
        assert_eq!(matches_do_gacha_rsp(&payload), None);
    }

    #[test]
    fn the_wish_and_key_matchers_do_not_claim_each_other() {
        let key = authkey_rsp("webview_gacha", "hk4e_global", &synthetic_authkey());
        let wish = do_gacha_rsp(301, &ten_pull());
        assert_eq!(matches_do_gacha_rsp(&key), None);
        assert_eq!(matches_get_authkey_rsp(&wish), None);
    }

    // -- GetGachaInfoRsp -----------------------------------------------------

    const RECORD_QUERY: &str = "win_mode=fullscreen&no_joypad_close=1&authkey_ver=1&sign_type=2\
         &auth_appid=webview_gacha&init_type=301&gacha_id=0123456789abcdef0123456789abcdef01234567\
         &timestamp=1790000000";

    fn record_url(init_type: Option<u32>, gacha_id: &str) -> String {
        let init = init_type
            .map(|t| format!("&init_type={t}"))
            .unwrap_or_default();
        format!(
            "https://example.invalid/genshin/event/gacha/index.html?win_mode=fullscreen\
             &no_joypad_close=1&authkey_ver=1&sign_type=2&auth_appid=webview_gacha{init}\
             &gacha_id={gacha_id}&timestamp=1790000000"
        )
    }

    /// One `GachaInfo` with the 7.1 field numbers: the record link (twice),
    /// the details link (no `init_type`), names, times, costs.
    fn gacha_info(gacha_type: u64, init_type: u32, gacha_id: &str) -> Vec<u8> {
        [
            field_varint(1, 3923),
            field_varint(2, gacha_type),
            field_varint(3, 1_791_885_540),
            field_varint(4, 10),
            field_varint(5, u64::from(u32::MAX)),
            field_varint(6, 1_790_000_000),
            field_bytes(7, record_url(Some(init_type), gacha_id).as_bytes()),
            field_varint(8, 223),
            field_bytes(9, record_url(None, gacha_id).as_bytes()),
            field_bytes(10, b"UI_Tab_GachaShowPanel_A001"),
            field_varint(11, 9998),
            field_bytes(15, b"GachaShowPanel_A001"),
            field_bytes(600, record_url(Some(init_type), gacha_id).as_bytes()),
            field_bytes(2032, b"UI_GACHA_SHOW_PANEL_A001_TITLE"),
        ]
        .concat()
    }

    fn gacha_info_rsp(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = field_varint(11, 0x5f3a_91c2);
        for entry in entries {
            out.extend(field_bytes(14, entry));
        }
        out
    }

    const ID_301: &str = "0123456789abcdef0123456789abcdef01234567";
    const ID_400: &str = "76543210fedcba9876543210fedcba9876543210";

    #[test]
    fn every_banners_history_link_is_read_verbatim() {
        let payload = gacha_info_rsp(&[
            gacha_info(200, 200, ID_301),
            gacha_info(301, 301, ID_301),
            gacha_info(400, 301, ID_400),
        ]);
        let links = matches_get_gacha_info_rsp(&payload).unwrap();
        assert_eq!(links.len(), 3);
        assert_eq!(links[1].gacha_type, Some(301));
        assert_eq!(links[1].query, RECORD_QUERY);
        assert_eq!(links[2].gacha_type, Some(400));
        assert!(links[2].query.contains("init_type=301&gacha_id=7654"));
        assert!(links[0].query.contains("init_type=200&"));
    }

    #[test]
    fn the_beginners_banner_link_has_no_gacha_id_and_is_still_read() {
        let link = "https://example.invalid/index.html?win_mode=fullscreen&no_joypad_close=1&authkey_ver=1&sign_type=2&auth_appid=webview_gacha&init_type=100&timestamp=1780000000";
        let details = "https://example.invalid/index.html?win_mode=fullscreen&auth_appid=webview_gacha&timestamp=1780000000#/newbiegacha";
        let entry = [
            field_varint(2, 100),
            field_bytes(7, link.as_bytes()),
            field_bytes(9, details.as_bytes()),
        ]
        .concat();
        let links =
            matches_get_gacha_info_rsp(&gacha_info_rsp(&[gacha_info(301, 301, ID_301), entry]))
                .unwrap();
        assert_eq!(links[1].gacha_type, Some(100));
        assert!(
            links[1]
                .query
                .ends_with("init_type=100&timestamp=1780000000")
        );
    }

    #[test]
    fn the_banner_list_is_classified_as_such_and_nothing_else() {
        let payload = gacha_info_rsp(&[gacha_info(301, 301, ID_301)]);
        match classify_command(&command(29811, &payload)) {
            Some(CommandMatch::GachaInfo(links)) => assert_eq!(links.len(), 1),
            other => panic!("expected the banner list, got {other:?}"),
        }
    }

    #[test]
    fn a_banner_list_without_history_links_is_not_read() {
        // Only the details link (no init_type): nothing to build from.
        let entry = [
            field_varint(2, 301),
            field_bytes(9, record_url(None, ID_301).as_bytes()),
        ]
        .concat();
        assert_eq!(matches_get_gacha_info_rsp(&gacha_info_rsp(&[entry])), None);
        // A link with characters a plain query does not have.
        let odd = record_url(Some(301), ID_301).replace("timestamp=", "timestamp=%3C");
        let entry = [field_varint(2, 301), field_bytes(7, odd.as_bytes())].concat();
        assert_eq!(matches_get_gacha_info_rsp(&gacha_info_rsp(&[entry])), None);
        // A link to another web view.
        let other = record_url(Some(301), ID_301).replace("webview_gacha", "webview_other");
        let entry = [field_varint(2, 301), field_bytes(7, other.as_bytes())].concat();
        assert_eq!(matches_get_gacha_info_rsp(&gacha_info_rsp(&[entry])), None);
        // Not a list at all, or two lists.
        assert_eq!(matches_get_gacha_info_rsp(&field_varint(11, 1)), None);
        let mut two = gacha_info_rsp(&[gacha_info(301, 301, ID_301)]);
        two.extend(field_bytes(15, &gacha_info(302, 302, ID_400)));
        assert_eq!(matches_get_gacha_info_rsp(&two), None);
    }

    #[test]
    fn the_other_wish_messages_are_not_a_banner_list() {
        assert_eq!(
            matches_get_gacha_info_rsp(&do_gacha_rsp(301, &ten_pull())),
            None
        );
        let key = authkey_rsp("webview_gacha", "hk4e_global", &synthetic_authkey());
        assert_eq!(matches_get_gacha_info_rsp(&key), None);
        let list = gacha_info_rsp(&[gacha_info(301, 301, ID_301)]);
        assert_eq!(matches_do_gacha_rsp(&list), None);
        assert_eq!(matches_get_authkey_rsp(&list), None);
    }

    // -- the client version --------------------------------------------------

    const VERSION: &str = "OSRELWin7.1.0_R11111111_S22222222_D33333333";

    /// A `GetPlayerTokenReq`-like message: the version among other strings.
    fn token_req(version: &str) -> Vec<u8> {
        [
            field_varint(1, 1),
            field_bytes(3, b"v2_SyNtHeTiC-account-token"),
            field_bytes(9, b"Windows 11  (10.0.10000) 64bit"),
            field_bytes(11, version.as_bytes()),
            field_bytes(1206, b"OSRELWin7.1.0"),
            field_varint(1440, 33_333_333),
        ]
        .concat()
    }

    #[test]
    fn the_client_version_is_read_from_the_token_request() {
        assert_eq!(
            matches_client_version(&token_req(VERSION)).as_deref(),
            Some(VERSION)
        );
        assert_eq!(
            matches_client_version(&token_req("CNRELWin7.1.0_R1_S2_D3")).as_deref(),
            Some("CNRELWin7.1.0_R1_S2_D3")
        );
        match classify_command(&command(9282, &token_req(VERSION))) {
            Some(CommandMatch::ClientVersion(version)) => assert_eq!(version, VERSION),
            other => panic!("expected the client version, got {other:?}"),
        }
    }

    #[test]
    fn strings_that_only_look_like_a_version_are_not_one() {
        for not_version in [
            "OSRELWin7.1.0",
            "OSRELWin7.1_R1_S2",
            "osrelwin7.1.0_R1_S2",
            "OSRELWin7.1.0_R1",
            "OSRELWin7.1.0_R1_Sx",
            "OSREL7.1.0_R1_S2",
            "UI_GACHA_SHOW_PANEL_A001_TITLE",
            "hk4e_global",
        ] {
            assert!(!is_client_version(not_version), "{not_version}");
        }
        // Two different versions: nothing to tell apart.
        let mut two = token_req(VERSION);
        two.extend(field_bytes(12, b"OSRELWin7.2.0_R1_S2_D3"));
        assert_eq!(matches_client_version(&two), None);
    }

    #[test]
    fn garbage_is_neither() {
        for payload in [
            &b""[..],
            &[0xff, 0xff, 0xff],
            b"hk4e_global webview_gacha",
            &[0x0a, 0x02, 0x08, 0x01],
        ] {
            assert_eq!(matches_get_authkey_rsp(payload), None);
            assert_eq!(matches_do_gacha_rsp(payload), None);
            assert_eq!(matches_get_gacha_info_rsp(payload), None);
            assert_eq!(matches_client_version(payload), None);
        }
    }
}
