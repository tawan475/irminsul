//! Shape-based matchers for packets whose schema we do not have.
//!
//! The game's real `.proto` files are not public and its field numbers are
//! re-shuffled every major version, so a handful of packets cannot be parsed
//! with a generated type. Instead they are parsed as an empty message (`Unk`),
//! whose every field lands in protobuf's "unknown fields" map, and identified by
//! the *shape* of that map: how many repeated submessages there are, how many
//! varints each of them holds, and how the values are distributed.
//!
//! Two rules follow from that, and both are load-bearing:
//!
//! * A matcher must never reject a whole packet because one field inside it
//!   looked wrong. Real packets carry sibling fields we do not model (for
//!   example `AchievementAllDataNotify.reward_taken_goal_id_list`), so anything
//!   unrecognised is skipped, not fatal. These matchers are fed the payload
//!   *only* -- `GameCommand::proto_data`, with the `PacketHead` envelope kept
//!   apart in `proto_header` -- but they stay tolerant of a caller that hands
//!   over the two concatenated, and `ignores_a_prepended_packet_header` pins
//!   that as defence in depth.
//! * A matcher must not depend on a value that a particular account happens to
//!   own. Identification is structural first (which tag is unique across
//!   entries, which tag is always small, which tag looks like a unix timestamp)
//!   and only falls back to well-known sentinel values when structure alone is
//!   ambiguous.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use protobuf::Message;
use protobuf::UnknownValueRef::*;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

use crate::r#gen::protos::AvatarDataNotify;
use crate::r#gen::protos::AvatarInfo;
use crate::r#gen::protos::Item;
use crate::r#gen::protos::PacketWithItems;
use crate::r#gen::protos::Unk;

/// Upper bound on the number of truncation points tried when looking for the
/// end of the base64 seed field in a `GetPlayerTokenRsp`. Only a corrupt or
/// hostile payload gets anywhere near this; the real packet needs two or three.
const MAX_TOKEN_CUT_CANDIDATES: usize = 64;

/// End offsets at which a `GetPlayerTokenRsp` payload is worth parsing.
///
/// The session seed travels as a base64 string; the token is 256 bytes, which is
/// 1 modulo 3, so the encoded field always ends in `==`. Binary signature data
/// follows it and makes the buffer as a whole unparseable, which is why the
/// payload has to be cut before parsing.
///
/// The trap is that the trailing signature can itself contain the byte pair
/// `==`, and cutting there slices the buffer in the middle of a field. So every
/// `==` is a candidate rather than only the last one: the full buffer first,
/// then each `==` from the end backwards. Callers take the first candidate that
/// both parses and yields a seed.
fn token_candidate_ends(data: &[u8]) -> Vec<usize> {
    let mut ends = Vec::with_capacity(4);
    ends.push(data.len());
    for (i, window) in data.windows(2).enumerate().rev() {
        if ends.len() >= MAX_TOKEN_CUT_CANDIDATES {
            tracing::debug!(
                "stopping the GetPlayerTokenRsp scan after {} cut candidates",
                ends.len()
            );
            break;
        }
        if window == b"==" && !ends.contains(&(i + 2)) {
            ends.push(i + 2);
        }
    }
    ends
}

/// Every prefix of `data` (see [`token_candidate_ends`]) that parses as
/// protobuf, in the order they should be tried.
fn token_candidate_messages(data: &[u8]) -> impl Iterator<Item = Unk> + '_ {
    token_candidate_ends(data)
        .into_iter()
        .filter_map(move |end| Unk::parse_from_bytes(&data[..end]).ok())
}

/// RSA-decrypt every length-delimited field that is valid base64 and keep the
/// results that are exactly a `u64` wide.
fn decrypt_seeds(msg: &Unk, rsa_keys: &[RsaPrivateKey]) -> Vec<u64> {
    let mut seeds: Vec<u64> = Vec::new();
    for (field_number, field_data) in msg.unknown_fields().iter() {
        tracing::trace!("field: {}: {:?}", field_number, field_data);
        let LengthDelimited(encrypted_bytes) = field_data else {
            continue;
        };
        let Ok(encrypted) = BASE64_STANDARD.decode(encrypted_bytes) else {
            continue;
        };
        seeds.extend(
            rsa_keys
                .iter()
                .filter_map(|key| key.decrypt(Pkcs1v15Encrypt, &encrypted).ok())
                .filter_map(|seed| <[u8; 8]>::try_from(seed.as_slice()).ok())
                .map(u64::from_be_bytes),
        );
    }
    seeds
}

/// Recover the session seeds from a `GetPlayerTokenRsp` payload.
///
/// Returns every seed that one of `rsa_keys` could decrypt, or `None` if this is
/// not a token response (or is one we hold no key for).
///
/// `data` and `rsa_keys` are taken by `AsRef` so a caller holding a borrowed
/// capture buffer does not have to copy it; owned `Vec`s still work unchanged.
pub fn matches_get_player_token_rsp(
    data: impl AsRef<[u8]>,
    rsa_keys: impl AsRef<[RsaPrivateKey]>,
) -> Option<Vec<u64>> {
    let data = data.as_ref();
    let rsa_keys = rsa_keys.as_ref();

    let mut parsed = 0usize;
    for msg in token_candidate_messages(data) {
        parsed += 1;
        let seeds = decrypt_seeds(&msg, rsa_keys);
        if !seeds.is_empty() {
            return Some(seeds);
        }
    }

    if parsed == 0 {
        tracing::debug!("no prefix of the payload parsed as a token response");
    } else {
        tracing::debug!("{parsed} candidate cuts parsed, none carried a decryptable seed");
    }
    None
}

/// One achievement, as recovered from an `AchievementAllDataNotify`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Achievement {
    pub id: u32,
    pub status: u32,
    pub finish_timestamp: Option<u32>,
}

/// Why a payload was not accepted as an `AchievementAllDataNotify`.
///
/// Callers that only want the happy path can use
/// [`matches_achievement_all_data_notify`]; this exists so a caller can tell
/// "some other packet" apart from "the achievement packet, but its fields could
/// not be identified", which is worth surfacing to the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AchievementMatchError {
    /// Payload is far too small to be a full achievement dump.
    TooShort,
    /// Payload is not valid protobuf at all.
    Malformed,
    /// No repeated submessage field looked like a list of achievements.
    NoCandidateList,
    /// A plausible list was found, but its id/status/timestamp tags could not be
    /// told apart with enough confidence to be worth exporting.
    UnidentifiedFields,
}

impl fmt::Display for AchievementMatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::TooShort => "payload is too short to be an achievement dump",
            Self::Malformed => "payload is not valid protobuf",
            Self::NoCandidateList => "no field looked like a repeated achievement list",
            Self::UnidentifiedFields => "achievement field tags could not be identified",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for AchievementMatchError {}

/// A decoded submessage: its varint fields, keyed by tag.
type Entry = BTreeMap<u32, u64>;

/// Shortest payload worth inspecting. An achievement dump is several kilobytes;
/// this is the upstream value and is kept as-is.
const MIN_ACHIEVEMENT_PAYLOAD_LEN: usize = 1000;

/// How many conforming submessages a top-level field needs before it is treated
/// as the achievement list.
///
/// The payload-side siblings that survive the shape test are short -- chiefly
/// `reward_taken_goal_id_list`, packed varints some of which happen to decode as
/// submessages -- while the real list has hundreds of entries.
///
/// This floor is the one place this matcher is strictly tighter than the one it
/// replaced, which accepted a group of 1..9 entries. That is judged unreachable:
/// an entry is ~10-16 bytes, so a payload long enough to clear
/// [`MIN_ACHIEVEMENT_PAYLOAD_LEN`] already implies dozens of them, and the only
/// sibling big enough to pad a payload out to that length on its own
/// (`reward_taken_goal_id_list`) grows alongside the achievement list rather
/// than instead of it.
const MIN_ACHIEVEMENT_ENTRIES: usize = 10;

/// Wed Dec 31 2014 23:00:00 GMT+0000 — the game did not exist yet, so a field
/// holding values above this is a unix timestamp rather than a progress counter.
const MIN_PLAUSIBLE_FINISH_TIMESTAMP: u64 = 1_420_066_800;

/// `Achievement.Status` runs `INVALID`, `UNFINISHED`, `FINISHED`,
/// `REWARD_TAKEN` — so a status field never exceeds 3.
const MAX_ACHIEVEMENT_STATUS: u64 = 3;

/// "Onward and Upward" (ascend a character to Phase 2 for the first time).
///
/// Used only as a tie-break and as a last-resort fallback. It used to be the
/// primary way the id field was found, which meant an account that has not
/// unlocked this one achievement exported nothing at all, ever.
const SENTINEL_ACHIEVEMENT_ID: u64 = 80014;

/// Outcome of inspecting one top-level length-delimited field.
enum SubMessage {
    /// A submessage of two or more varint fields — a possible achievement.
    Entry(Entry),
    /// Parsed, but carries at most one field: too thin to identify anything
    /// from, so it must not seed the candidate tag sets.
    Degenerate,
    /// Not a submessage of varints at all, so the field it came from is not the
    /// achievement list.
    NotAnEntry,
}

fn classify_submessage(bytes: &[u8]) -> SubMessage {
    let Ok(inner) = Unk::parse_from_bytes(bytes) else {
        return SubMessage::NotAnEntry;
    };
    let mut entry = Entry::new();
    for (tag, value) in inner.unknown_fields().iter() {
        let Varint(value) = value else {
            // `Achievement` is varints only; anything else means this field is
            // some other repeated message.
            return SubMessage::NotAnEntry;
        };
        entry.insert(tag, value);
    }
    if entry.len() <= 1 {
        SubMessage::Degenerate
    } else {
        SubMessage::Entry(entry)
    }
}

/// Group the top-level length-delimited fields by tag, dropping the groups whose
/// contents cannot be a repeated `Achievement`.
///
/// Dropping is per group, never per packet: the achievement notify also carries
/// `reward_taken_goal_id_list` (packed repeated uint32, which decodes as
/// garbage), and callers pass the packet header in front of the payload, so
/// foreign top-level fields are the norm rather than a sign of the wrong packet.
fn achievement_candidate_groups(msg: &Unk) -> BTreeMap<u32, Vec<Entry>> {
    let mut groups: BTreeMap<u32, Vec<Entry>> = BTreeMap::new();
    let mut rejected: BTreeSet<u32> = BTreeSet::new();

    for (tag, field) in msg.unknown_fields().iter() {
        let LengthDelimited(bytes) = field else {
            continue;
        };
        if rejected.contains(&tag) {
            continue;
        }
        match classify_submessage(bytes) {
            SubMessage::Entry(entry) => groups.entry(tag).or_default().push(entry),
            SubMessage::Degenerate => {}
            SubMessage::NotAnEntry => {
                tracing::trace!("field {tag} is not a list of achievements, skipping it");
                rejected.insert(tag);
                groups.remove(&tag);
            }
        }
    }

    groups
}

/// The tags identified inside one candidate list.
struct AchievementTags {
    id: u32,
    status: u32,
    finish_timestamp: u32,
}

fn tags_present_in_every_entry(entries: &[Entry]) -> BTreeSet<u32> {
    let mut common: BTreeSet<u32> = match entries.first() {
        Some(first) => first.keys().copied().collect(),
        None => return BTreeSet::new(),
    };
    for entry in entries {
        common.retain(|tag| entry.contains_key(tag));
    }
    common
}

fn all_tags(entries: &[Entry]) -> BTreeSet<u32> {
    entries
        .iter()
        .flat_map(|entry| entry.keys().copied())
        .collect()
}

/// Does `tag` hold a different value in every entry that has it?
///
/// Achievement ids are unique per achievement; progress counters and statuses
/// repeat heavily. This is the structural signature that replaces the old
/// "look for the literal id 80014" bootstrap.
fn values_are_unique(entries: &[Entry], tag: u32) -> bool {
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    for entry in entries {
        if let Some(&value) = entry.get(&tag)
            && !seen.insert(value)
        {
            return false;
        }
    }
    true
}

/// How many entries agree with "finished achievements carry a timestamp".
///
/// `FINISHED`/`REWARD_TAKEN` (2 and 3) come with a finish timestamp,
/// `UNFINISHED` (1) does not. Used to rank status candidates rather than to
/// filter them, because pre-1.0 accounts are known to carry finished
/// achievements with no timestamp recorded.
fn status_correlation(entries: &[Entry], tag: u32, tag_finish_timestamp: u32) -> usize {
    entries
        .iter()
        .filter(|entry| {
            let has_timestamp = entry.contains_key(&tag_finish_timestamp);
            match entry.get(&tag) {
                Some(&value) => (value >= 2) == has_timestamp,
                // An absent status is `STATUS_INVALID`, which is not finished.
                None => !has_timestamp,
            }
        })
        .count()
}

/// Pick the highest-scoring candidate, breaking ties by the lowest tag so the
/// same capture always produces the same answer.
fn best_by<F: Fn(u32) -> u64>(candidates: &[u32], score: F) -> Option<u32> {
    let mut best: Option<(u32, u64)> = None;
    for &tag in candidates {
        let value = score(tag);
        if best.is_none_or(|(_, best_value)| value > best_value) {
            best = Some((tag, value));
        }
    }
    best.map(|(tag, _)| tag)
}

/// Work out which tag is the id, which is the status and which is the finish
/// timestamp, using only the distribution of the values.
fn identify_achievement_tags(entries: &[Entry]) -> Option<AchievementTags> {
    let common = tags_present_in_every_entry(entries);
    let all = all_tags(entries);

    // Timestamp: the one tag whose values reach past the 2015 epoch. It is not
    // required in every entry — unfinished achievements have none.
    let timestamp_tags: Vec<u32> = all
        .iter()
        .copied()
        .filter(|tag| {
            entries.iter().any(|entry| {
                entry
                    .get(tag)
                    .is_some_and(|&v| v > MIN_PLAUSIBLE_FINISH_TIMESTAMP)
            })
        })
        .collect();
    let finish_timestamp = match timestamp_tags.as_slice() {
        [tag] => *tag,
        [] => {
            tracing::debug!("no field held a plausible finish timestamp");
            return None;
        }
        tags => {
            tracing::debug!("{} fields look like timestamps: {tags:?}", tags.len());
            return None;
        }
    };

    // Status: every value it ever takes fits in the status enum.
    let small_valued: BTreeSet<u32> = all
        .iter()
        .copied()
        .filter(|&tag| tag != finish_timestamp)
        .filter(|tag| {
            entries
                .iter()
                .all(|entry| entry.get(tag).is_none_or(|&v| v <= MAX_ACHIEVEMENT_STATUS))
        })
        .collect();
    if small_valued.is_empty() {
        tracing::debug!("no field held only status-sized values");
        return None;
    }
    // Prefer candidates present in every entry, but do not insist on it: a dump
    // containing a `STATUS_INVALID` achievement omits the field entirely.
    let status_candidates: Vec<u32> = {
        let in_every: Vec<u32> = small_valued
            .iter()
            .copied()
            .filter(|tag| common.contains(tag))
            .collect();
        if in_every.is_empty() {
            small_valued.iter().copied().collect()
        } else {
            in_every
        }
    };
    if status_candidates.len() > 1 {
        tracing::debug!(
            "{} status candidates {status_candidates:?}, ranking them by timestamp correlation",
            status_candidates.len()
        );
    }
    let status = best_by(&status_candidates, |tag| {
        status_correlation(entries, tag, finish_timestamp) as u64
    })?;

    // Id: present everywhere, never status-sized, never the timestamp, and
    // unique across the list.
    let sentinel_tags: Vec<u32> = all
        .iter()
        .copied()
        .filter(|&tag| tag != finish_timestamp && !small_valued.contains(&tag))
        .filter(|tag| {
            entries
                .iter()
                .any(|entry| entry.get(tag) == Some(&SENTINEL_ACHIEVEMENT_ID))
        })
        .collect();
    let id_candidates: Vec<u32> = common
        .iter()
        .copied()
        .filter(|&tag| tag != finish_timestamp && !small_valued.contains(&tag))
        .filter(|&tag| values_are_unique(entries, tag))
        .collect();
    let id = match id_candidates.as_slice() {
        [tag] => *tag,
        [] => match sentinel_tags.as_slice() {
            // Nothing was structurally unique. Fall back to the historical
            // sentinel so captures that used to work keep working.
            [tag] => {
                tracing::warn!(
                    "no structurally unique achievement id field; falling back to the field \
                     holding id {SENTINEL_ACHIEVEMENT_ID}"
                );
                *tag
            }
            _ => {
                tracing::debug!("could not identify the achievement id field");
                return None;
            }
        },
        candidates => {
            // Several unique fields. Take the one carrying the sentinel if it is
            // among them, else the one whose values sit highest — real ids are
            // five-digit, counters are not.
            let chosen = candidates
                .iter()
                .copied()
                .find(|tag| sentinel_tags.contains(tag))
                .or_else(|| {
                    best_by(candidates, |tag| {
                        entries
                            .iter()
                            .filter_map(|entry| entry.get(&tag).copied())
                            .min()
                            .unwrap_or(0)
                    })
                })?;
            tracing::debug!(
                "{} unique id candidates {candidates:?}, chose {chosen}",
                candidates.len()
            );
            chosen
        }
    };

    Some(AchievementTags {
        id,
        status,
        finish_timestamp,
    })
}

fn collect_achievements(entries: &[Entry], tags: &AchievementTags) -> Vec<Achievement> {
    let mut achievements: Vec<Achievement> = Vec::with_capacity(entries.len());
    let mut skipped = 0usize;
    for entry in entries {
        let Some(id) = entry.get(&tags.id).and_then(|&v| u32::try_from(v).ok()) else {
            skipped += 1;
            continue;
        };
        achievements.push(Achievement {
            id,
            status: entry
                .get(&tags.status)
                .and_then(|&v| u32::try_from(v).ok())
                .unwrap_or_default(),
            finish_timestamp: entry
                .get(&tags.finish_timestamp)
                .and_then(|&v| u32::try_from(v).ok()),
        });
    }
    if skipped != 0 {
        tracing::debug!("skipped {skipped} entries with no usable achievement id");
    }
    achievements
}

/// Recover the achievement list from an `AchievementAllDataNotify` payload.
///
/// Every top-level repeated submessage is considered a candidate list; the one
/// with the most entries that also yields an identifiable id/status/timestamp
/// layout wins. Unrelated sibling fields — including a packet header prepended
/// by the caller — are ignored rather than treated as a mismatch.
pub fn try_match_achievement_all_data_notify(
    data: &[u8],
) -> Result<Vec<Achievement>, AchievementMatchError> {
    if data.len() < MIN_ACHIEVEMENT_PAYLOAD_LEN {
        return Err(AchievementMatchError::TooShort);
    }
    let msg = Unk::parse_from_bytes(data).map_err(|_| AchievementMatchError::Malformed)?;

    let groups = achievement_candidate_groups(&msg);
    if groups.is_empty() {
        return Err(AchievementMatchError::NoCandidateList);
    }

    let mut saw_candidate = false;
    let mut best: Option<(u32, Vec<Achievement>)> = None;
    for (&tag, entries) in &groups {
        if entries.len() < MIN_ACHIEVEMENT_ENTRIES {
            tracing::trace!("field {tag} holds only {} entries", entries.len());
            continue;
        }
        saw_candidate = true;
        let Some(tags) = identify_achievement_tags(entries) else {
            continue;
        };
        let achievements = collect_achievements(entries, &tags);
        if achievements.is_empty() {
            continue;
        }
        // Strictly greater, over tags visited in ascending order: ties keep the
        // lower tag, so the same capture always decodes the same way.
        if best
            .as_ref()
            .is_none_or(|(_, best)| achievements.len() > best.len())
        {
            best = Some((tag, achievements));
        }
    }

    match best {
        Some((tag, achievements)) => {
            tracing::info!("found {} achievements in field {}", achievements.len(), tag);
            Ok(achievements)
        }
        None if saw_candidate => Err(AchievementMatchError::UnidentifiedFields),
        None => Err(AchievementMatchError::NoCandidateList),
    }
}

/// Recover the achievement list from an `AchievementAllDataNotify` payload,
/// discarding the reason on failure.
///
/// The sibling `try_match_achievement_all_data_notify` returns the reason
/// instead, for callers that want to tell "some other packet" apart from "the
/// achievement packet, but unreadable".
/// `data` is taken by `AsRef` so a borrowed capture buffer need not be copied.
pub fn matches_achievement_all_data_notify(data: impl AsRef<[u8]>) -> Option<Vec<Achievement>> {
    match try_match_achievement_all_data_notify(data.as_ref()) {
        Ok(achievements) => Some(achievements),
        Err(err) => {
            tracing::trace!("not an achievement packet: {err}");
            None
        }
    }
}

pub fn matches_items_all_data_notify(data: &[u8]) -> Option<Vec<Item>> {
    let packet = PacketWithItems::parse_from_bytes(data).ok()?;

    // Filter out items with 0 (default) item ID. Virtual items like Mora may have guid = 0.
    let items: Vec<Item> = packet
        .items
        .into_iter()
        .filter(|item| item.item_id != 0)
        .collect();

    // Differentiate items packets from other that look alike.
    if items.len() < 10 {
        return None;
    }

    Some(items)
}

pub fn matches_avatars_all_data_notify(data: &[u8]) -> Option<Vec<AvatarInfo>> {
    let packet = AvatarDataNotify::parse_from_bytes(data).ok()?;
    let avatar_list: Vec<AvatarInfo> = packet
        .avatar_list
        .into_iter()
        .filter(|avatar| avatar.avatar_id != 0 && avatar.guid != 0)
        .collect();

    if avatar_list.is_empty() {
        return None;
    }

    Some(avatar_list)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Field numbers of the real `Achievement` message, as recovered from
    // Grasscutter. The matcher must not depend on them, but using the real ones
    // keeps the fixtures honest.
    const TAG_TOTAL_PROGRESS: u32 = 4;
    const TAG_ID: u32 = 5;
    const TAG_STATUS: u32 = 10;
    const TAG_FINISH_TIMESTAMP: u32 = 15;
    /// `AchievementAllDataNotify.reward_taken_goal_id_list`.
    const TAG_REWARD_TAKEN: u32 = 4;
    /// `AchievementAllDataNotify.achievement_list`.
    const TAG_LIST: u32 = 9;

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

    /// One `Achievement`: a progress counter, an id, a status and, when it is
    /// finished, a timestamp.
    fn achievement_entry(id: u64, status: u64, total_progress: u64, ts: Option<u64>) -> Vec<u8> {
        let mut out = field_varint(TAG_TOTAL_PROGRESS, total_progress);
        out.extend(field_varint(TAG_ID, id));
        out.extend(field_varint(TAG_STATUS, status));
        if let Some(ts) = ts {
            out.extend(field_varint(TAG_FINISH_TIMESTAMP, ts));
        }
        out
    }

    /// A list of `count` achievements with ids starting at `first_id`. Every
    /// other one is finished (status 3, with a timestamp); the rest are
    /// unfinished (status 1, no timestamp). Progress counters cycle through
    /// 1/5/10 so that field is neither status-sized nor unique.
    fn achievement_entries(first_id: u64, count: u64) -> Vec<Vec<u8>> {
        (0..count)
            .map(|i| {
                let finished = i % 2 == 0;
                achievement_entry(
                    first_id + i,
                    if finished { 3 } else { 1 },
                    [1, 5, 10][(i % 3) as usize],
                    finished.then_some(1_600_000_000 + i),
                )
            })
            .collect()
    }

    fn packet(fields: &[Vec<u8>]) -> Vec<u8> {
        fields.concat()
    }

    fn achievement_packet(first_id: u64, count: u64) -> Vec<u8> {
        packet(
            &achievement_entries(first_id, count)
                .iter()
                .map(|entry| field_bytes(TAG_LIST, entry))
                .collect::<Vec<_>>(),
        )
    }

    fn ids(achievements: &[Achievement]) -> Vec<u32> {
        achievements.iter().map(|a| a.id).collect()
    }

    #[test]
    fn achievement_packet_fixture_is_big_enough_to_be_considered() {
        assert!(achievement_packet(80001, 120).len() >= MIN_ACHIEVEMENT_PAYLOAD_LEN);
    }

    #[test]
    fn decodes_an_account_that_owns_the_sentinel_achievement() {
        let data = achievement_packet(80001, 120);
        let achievements = matches_achievement_all_data_notify(&data).expect("should match");

        assert_eq!(achievements.len(), 120);
        assert_eq!(ids(&achievements), (80001..80121).collect::<Vec<u32>>());
        assert!(ids(&achievements).contains(&(SENTINEL_ACHIEVEMENT_ID as u32)));
        assert_eq!(achievements[0].status, 3);
        assert_eq!(achievements[0].finish_timestamp, Some(1_600_000_000));
        assert_eq!(achievements[1].status, 1);
        assert_eq!(achievements[1].finish_timestamp, None);
    }

    /// The regression that used to lock those accounts out of every export path
    /// in irminsul: no field equal to 80014 anywhere in the dump.
    #[test]
    fn decodes_an_account_that_does_not_own_the_sentinel_achievement() {
        let data = achievement_packet(90001, 120);
        let sentinel = varint(SENTINEL_ACHIEVEMENT_ID);
        assert!(
            !data.windows(sentinel.len()).any(|w| w == sentinel),
            "fixture must not contain the sentinel id anywhere"
        );

        let achievements = matches_achievement_all_data_notify(&data).expect("should match");
        assert_eq!(ids(&achievements), (90001..90121).collect::<Vec<u32>>());
        assert_eq!(achievements[0].status, 3);
    }

    /// `reward_taken_goal_id_list` is a packed repeated uint32 sitting next to
    /// the achievement list. It used to take the whole packet down with it.
    #[test]
    fn ignores_the_reward_taken_goal_id_list_sibling() {
        let packed: Vec<u8> = (80001u64..80040).flat_map(varint).collect();
        let mut data = field_bytes(TAG_REWARD_TAKEN, &packed);
        data.extend(achievement_packet(80001, 120));

        let achievements = matches_achievement_all_data_notify(&data).expect("should match");
        assert_eq!(achievements.len(), 120);
        assert_eq!(ids(&achievements), (80001..80121).collect::<Vec<u32>>());
    }

    /// Matchers are fed the payload alone, but must stay tolerant of a caller
    /// that concatenates `PacketHead` onto it — the header's repeated `ext_map`
    /// entries have exactly the shape of an achievement, so a matcher that took
    /// them for entries would report nonsense.
    #[test]
    fn ignores_a_prepended_packet_header() {
        let mut header = packet(&[
            field_varint(1, 12345),             // packet_id
            field_varint(6, 1_700_000_000_000), // sent_ms
        ]);
        for i in 0..12u64 {
            // ext_map entries: two varint fields each, exactly like an entry.
            let pair = packet(&[field_varint(1, i), field_varint(2, i * 2)]);
            header.extend(field_bytes(23, &pair));
        }
        header.extend(achievement_packet(80001, 120));

        let achievements = matches_achievement_all_data_notify(&header).expect("should match");
        assert_eq!(achievements.len(), 120);
        assert_eq!(ids(&achievements), (80001..80121).collect::<Vec<u32>>());
    }

    /// A second small-valued field must not be able to win the status slot, and
    /// the choice must not depend on hash iteration order.
    #[test]
    fn status_tag_choice_is_deterministic_with_two_small_fields() {
        let entries: Vec<Vec<u8>> = achievement_entries(80001, 120)
            .into_iter()
            .map(|mut entry| {
                // A constant, status-sized decoy in every entry.
                entry.extend(field_varint(7, 1));
                entry
            })
            .collect();
        let data = packet(
            &entries
                .iter()
                .map(|entry| field_bytes(TAG_LIST, entry))
                .collect::<Vec<_>>(),
        );

        let first = matches_achievement_all_data_notify(&data).expect("should match");
        assert_eq!(first[0].status, 3, "should pick the real status field");
        assert_eq!(first[1].status, 1);
        for _ in 0..16 {
            assert_eq!(
                matches_achievement_all_data_notify(&data).expect("should match"),
                first,
                "the same capture must always decode the same way"
            );
        }
    }

    /// Structural identification cannot pick an id field when ids repeat, so the
    /// historical sentinel has to carry it — the path that keeps captures which
    /// work today working.
    #[test]
    fn falls_back_to_the_sentinel_when_no_field_is_unique() {
        let mut entries = achievement_entries(80001, 120);
        // Duplicate one id so the id field is no longer unique across the list.
        entries[119] = achievement_entry(80001, 1, 5, None);
        let data = packet(
            &entries
                .iter()
                .map(|entry| field_bytes(TAG_LIST, entry))
                .collect::<Vec<_>>(),
        );

        let achievements = matches_achievement_all_data_notify(&data).expect("should match");
        assert_eq!(achievements.len(), 120);
        assert_eq!(achievements[13].id, 80014);
    }

    #[test]
    fn rejects_a_list_with_no_timestamp_field() {
        let entries: Vec<Vec<u8>> = (0..120u64)
            .map(|i| achievement_entry(80001 + i, 1, 5, None))
            .collect();
        let data = packet(
            &entries
                .iter()
                .map(|entry| field_bytes(TAG_LIST, entry))
                .collect::<Vec<_>>(),
        );

        assert_eq!(
            try_match_achievement_all_data_notify(&data),
            Err(AchievementMatchError::UnidentifiedFields)
        );
    }

    #[test]
    fn rejects_a_short_payload() {
        assert_eq!(
            try_match_achievement_all_data_notify(&achievement_packet(80001, 4)),
            Err(AchievementMatchError::TooShort)
        );
    }

    #[test]
    fn rejects_a_payload_of_short_groups() {
        // Long enough to be considered, but no group reaches the entry floor.
        let mut data = achievement_packet(80001, 9);
        data.extend(field_bytes(20, &vec![b'x'; MIN_ACHIEVEMENT_PAYLOAD_LEN]));
        assert!(data.len() >= MIN_ACHIEVEMENT_PAYLOAD_LEN);
        assert!(matches_achievement_all_data_notify(&data).is_none());
    }

    #[test]
    fn one_field_submessages_do_not_seed_the_candidate_set() {
        assert!(matches!(
            classify_submessage(&field_varint(3, 7)),
            SubMessage::Degenerate
        ));
        assert!(matches!(
            classify_submessage(&packet(&[field_varint(3, 7), field_varint(4, 8)])),
            SubMessage::Entry(_)
        ));
        assert!(matches!(
            classify_submessage(&field_bytes(3, b"nested")),
            SubMessage::NotAnEntry
        ));
    }

    #[test]
    fn achievement_entries_survive_a_trailing_non_list_group() {
        let mut data = achievement_packet(80001, 120);
        // A repeated field of nested messages: shape-rejected, but only for
        // itself.
        for _ in 0..20 {
            data.extend(field_bytes(11, &field_bytes(1, b"nested")));
        }
        assert_eq!(
            matches_achievement_all_data_notify(&data)
                .expect("should match")
                .len(),
            120
        );
    }

    // --- GetPlayerTokenRsp -------------------------------------------------

    #[test]
    fn token_cut_candidates_are_ordered_and_deduplicated() {
        let data = b"aa==bb==";
        assert_eq!(token_candidate_ends(data), vec![8, 4]);

        let data = b"aa==bb";
        assert_eq!(token_candidate_ends(data), vec![6, 4]);

        assert_eq!(token_candidate_ends(b""), vec![0]);
        assert_eq!(token_candidate_ends(b"="), vec![1]);
    }

    #[test]
    fn token_cut_candidates_are_capped() {
        let data = vec![b'='; 4096];
        assert_eq!(token_candidate_ends(&data).len(), MAX_TOKEN_CUT_CANDIDATES);
    }

    /// The bug this replaces: the seed field was located by cutting at the last
    /// `==` in the buffer, which lands inside the trailing signature whenever it
    /// happens to contain that byte pair, and the parse then fails outright.
    #[test]
    fn token_field_is_recovered_when_the_signature_contains_equals() {
        let seed_field = b"QUJDREVGRw==";
        let mut data = field_bytes(1, seed_field);
        // A trailing signature that is not valid protobuf and contains "==".
        data.extend_from_slice(&[0xff, b'=', b'=', 0xff]);

        // What the old code did: cut at the last "==" and parse once.
        let last = data
            .windows(2)
            .rposition(|w| w == b"==")
            .map_or(data.len(), |pos| pos + 2);
        assert!(
            Unk::parse_from_bytes(&data[..last]).is_err(),
            "the last '==' must be the wrong cut for this fixture"
        );
        assert!(Unk::parse_from_bytes(&data).is_err());

        // What it does now: try every cut and take one that parses.
        let recovered: Vec<Vec<u8>> = token_candidate_messages(&data)
            .flat_map(|msg| {
                msg.unknown_fields()
                    .iter()
                    .filter_map(|(_, field)| match field {
                        LengthDelimited(bytes) => Some(bytes.to_vec()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(
            recovered.contains(&seed_field.to_vec()),
            "the base64 seed field should survive the signature"
        );
    }

    #[test]
    fn token_matcher_reports_no_seeds_without_keys() {
        let data = field_bytes(1, b"QUJDREVGRw==");
        let no_keys: &[RsaPrivateKey] = &[];
        assert_eq!(matches_get_player_token_rsp(&data, no_keys), None);
        // Owned arguments still compile, for callers that hold them.
        assert_eq!(
            matches_get_player_token_rsp(data, Vec::<RsaPrivateKey>::new()),
            None
        );
    }
}
