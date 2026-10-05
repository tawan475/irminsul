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
use std::ops::RangeInclusive;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use protobuf::Message;
use protobuf::UnknownValueRef::*;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

use crate::r#gen::protos::{AvatarInfo, Item, Unk};

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

/// Every top-level length-delimited field of `msg`, grouped by field number.
///
/// A repeated submessage field is one such value per entry, so each group is a
/// candidate list. The values of one field number keep their wire order, and
/// the groups come out in field-number order, so the same payload is always
/// read the same way whatever order the parser's own map iterates in.
fn length_delimited_fields(msg: &Unk) -> BTreeMap<u32, Vec<&[u8]>> {
    let mut groups: BTreeMap<u32, Vec<&[u8]>> = BTreeMap::new();
    for (tag, field) in msg.unknown_fields().iter() {
        if let LengthDelimited(bytes) = field {
            groups.entry(tag).or_default().push(bytes);
        }
    }
    groups
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

    'fields: for (tag, values) in length_delimited_fields(msg) {
        let mut entries = Vec::new();
        for bytes in values {
            match classify_submessage(bytes) {
                SubMessage::Entry(entry) => entries.push(entry),
                SubMessage::Degenerate => {}
                SubMessage::NotAnEntry => {
                    tracing::trace!("field {tag} is not a list of achievements, skipping it");
                    continue 'fields;
                }
            }
        }
        if !entries.is_empty() {
            groups.insert(tag, entries);
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

// --- Repeated lists found by shape --------------------------------------------
//
// `PlayerStoreNotify`'s item list and `AvatarDataNotify`'s avatar list move to a
// new field number in most game versions (5 -> 6 and 6 -> 7 in 7.1), while the
// `Item` and `AvatarInfo` messages inside them kept their numbering. So entries
// are still decoded with the generated types, but the field holding them is
// found the way the achievement list is: every top-level repeated field is
// decoded, and the one with by far the most believable entries wins.

/// Plausible entries a field needs before it is taken for the inventory.
///
/// The floor the fixed-number parse always had. A real `PlayerStoreNotify` is
/// the whole bag -- thousands of entries -- while a handful of item-shaped
/// entries turns up in other messages (`StoreItemChangeNotify`, pick-up
/// notifies).
const MIN_ITEM_ENTRIES: usize = 10;

/// Playable avatars live in one contiguous block of ids (`10000002` upwards);
/// monsters and NPCs are two orders of magnitude away. The block is left
/// deliberately wide so a new release cannot age this check out.
pub(crate) const PLAYER_AVATAR_IDS: RangeInclusive<u32> = 10_000_000..=10_999_999;

/// `PROP_LEVEL`: every avatar's `prop_map` carries its level under this id.
const PROP_LEVEL: u32 = 4001;

/// How many times as many plausible entries the winning field needs as any
/// other field before it is believed.
///
/// A real packet carries one such list, so anything close to a tie means the
/// payload is not the shape this expects, and picking one would export the
/// wrong list rather than none.
const CLEAR_WINNER_FACTOR: usize = 2;

/// What one kind of repeated list looks like, for [`discover_list`].
struct ListShape<T> {
    /// For the logs.
    name: &'static str,
    /// Entries returned at all: the filter the fixed-number parse applied, so
    /// callers get exactly the entries they always got.
    keep: fn(&T) -> bool,
    /// Kept entries that are evidence the field is this list. Gets the raw
    /// entry as well, to test it against messages that share its shape.
    plausible: fn(&T, &[u8]) -> bool,
    /// Plausible entries the winning field needs.
    min_plausible: usize,
    /// Whether the plausible entries also have to be most of the kept ones.
    needs_majority: bool,
}

/// One field's entries, scored.
struct Candidate<T> {
    field: u32,
    entries: Vec<T>,
    plausible: usize,
}

/// Find the top-level repeated field of `data` that holds a list of `T`, and
/// return its field number with its kept entries, in wire order.
///
/// Every length-delimited field is decoded entry by entry as `T`; an entry
/// that does not decode is skipped, never fatal (see the module docs). The
/// field with the most plausible entries wins if it clears the shape's floor
/// and holds [`CLEAR_WINNER_FACTOR`] times as many as any other field.
fn discover_list<T: Message>(data: &[u8], shape: &ListShape<T>) -> Option<(u32, Vec<T>)> {
    let msg = Unk::parse_from_bytes(data).ok()?;
    let name = shape.name;

    let mut candidates: Vec<Candidate<T>> = Vec::new();
    for (field, values) in length_delimited_fields(&msg) {
        let mut entries = Vec::with_capacity(values.len());
        let mut plausible = 0usize;
        for bytes in values {
            let Ok(entry) = T::parse_from_bytes(bytes) else {
                continue;
            };
            if !(shape.keep)(&entry) {
                continue;
            }
            if (shape.plausible)(&entry, bytes) {
                plausible += 1;
            }
            entries.push(entry);
        }
        if plausible > 0 {
            candidates.push(Candidate {
                field,
                entries,
                plausible,
            });
        }
    }

    // Most plausible first. The sort is stable, so ties stay in field order.
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.plausible));
    let mut ranked = candidates.into_iter();
    let best = ranked.next()?;
    let runner_up = ranked.next();

    if best.plausible < shape.min_plausible {
        tracing::trace!(
            field = best.field,
            plausible = best.plausible,
            "too few plausible {name} entries for a {name} list"
        );
        return None;
    }
    if shape.needs_majority && best.plausible * 2 <= best.entries.len() {
        tracing::trace!(
            field = best.field,
            plausible = best.plausible,
            total = best.entries.len(),
            "most {name} entries are implausible"
        );
        return None;
    }
    if let Some(other) = &runner_up
        && best.plausible <= other.plausible * CLEAR_WINNER_FACTOR
    {
        tracing::warn!(
            field = best.field,
            plausible = best.plausible,
            other_field = other.field,
            other_plausible = other.plausible,
            "two fields look like the {name} list; reading neither"
        );
        return None;
    }

    tracing::debug!(
        field = best.field,
        plausible = best.plausible,
        total = best.entries.len(),
        "found the {name} list"
    );
    Some((best.field, best.entries))
}

/// The inventory list: entries with an item id, of which at least
/// [`MIN_ITEM_ENTRIES`] carry real inventory evidence.
const ITEM_LIST: ListShape<Item> = ListShape {
    name: "item",
    keep: has_item_id,
    plausible: plausible_item,
    min_plausible: MIN_ITEM_ENTRIES,
    needs_majority: false,
};

/// The roster: entries with an id and a guid, most of them playable
/// characters. No floor beyond one: a new account owns a handful of
/// characters and still has to export.
const AVATAR_LIST: ListShape<AvatarInfo> = ListShape {
    name: "avatar",
    keep: has_avatar_id_and_guid,
    plausible: plausible_avatar,
    min_plausible: 1,
    needs_majority: true,
};

fn has_item_id(item: &Item) -> bool {
    item.item_id != 0
}

/// An entry that carries real inventory evidence: an account's guid and one of
/// the material/equip/furniture arms.
///
/// The game mints guids as `(uid << 32) + counter`, so a real item's guid
/// never fits in 32 bits (virtual items such as Mora carry none at all).
/// Requiring that is what keeps other lists out: a 7.1 session sends, minutes
/// after login, lists of 58 and 105 entries (command 27685, on field 8) that
/// decode as items with ids 2 to 4, an equip arm and guids below 2^32, and
/// with no field number to go by they passed for an inventory. A
/// `map<uint32, PropValue>` entry decodes as an `Item` whose guid reads 0 (its
/// field 2 is a submessage) and whose arms are all unset.
///
/// Counting these rather than requiring most entries to be them keeps an
/// inventory that is mostly virtual items acceptable.
fn plausible_item(item: &Item, bytes: &[u8]) -> bool {
    item.guid >> 32 != 0
        && (item.has_material() || item.has_equip() || item.has_furniture())
        && !is_avatar_entry(item.item_id, bytes)
}

/// Whether an entry is really an `AvatarInfo`.
///
/// An `AvatarInfo` can decode as an `Item`: its id and guid land on the
/// item's, and its packed equip and talent lists and its fight-prop map are
/// the material, equip and furniture arms' field numbers. Whether that decode
/// succeeds depends on the bytes inside those lists, so with the item list no
/// longer pinned to one field number a roster could pass for an inventory --
/// and the item matcher runs first -- unless entries that are plausible
/// avatars are ruled out. Item ids sit far below the avatar block, so a real
/// item never pays for the second decode.
fn is_avatar_entry(id: u32, bytes: &[u8]) -> bool {
    PLAYER_AVATAR_IDS.contains(&id)
        && AvatarInfo::parse_from_bytes(bytes).is_ok_and(|avatar| plausible_avatar(&avatar, bytes))
}

fn has_avatar_id_and_guid(avatar: &AvatarInfo) -> bool {
    avatar.avatar_id != 0 && avatar.guid != 0
}

/// A playable character: an id in the avatar block, a guid, and a level in
/// its `prop_map`. A bare `{id, guid}` pair has no `prop_map`; monsters and
/// NPCs sit outside the block.
fn plausible_avatar(avatar: &AvatarInfo, _bytes: &[u8]) -> bool {
    PLAYER_AVATAR_IDS.contains(&avatar.avatar_id)
        && avatar.guid != 0
        && avatar.prop_map.contains_key(&PROP_LEVEL)
}

/// [`matches_items_all_data_notify`], with the number of the field the list
/// was found on.
pub(crate) fn discover_items(data: &[u8]) -> Option<(u32, Vec<Item>)> {
    discover_list(data, &ITEM_LIST)
}

/// [`matches_avatars_all_data_notify`], with the number of the field the list
/// was found on.
pub(crate) fn discover_avatars(data: &[u8]) -> Option<(u32, Vec<AvatarInfo>)> {
    discover_list(data, &AVATAR_LIST)
}

/// Recover the inventory from a `PlayerStoreNotify` payload, or `None` if this
/// is not one.
///
/// The item list is found by shape, not by field number: whichever top-level
/// repeated field holds by far the most entries that decode as an `Item` with
/// an account's guid (`uid << 32 | counter`) and a material/equip/furniture
/// arm -- at least ten of them -- is the list. Every entry of it with a
/// non-zero item id is returned, virtual items (guid 0) included.
pub fn matches_items_all_data_notify(data: &[u8]) -> Option<Vec<Item>> {
    discover_items(data).map(|(_, items)| items)
}

/// Recover the character roster from an `AvatarDataNotify` payload, or `None`
/// if this is not one.
///
/// The avatar list is found by shape, not by field number: whichever top-level
/// repeated field holds by far the most entries that decode as an
/// `AvatarInfo` with a playable avatar id, a guid and a level, provided they
/// are most of its entries. Every entry of it with a non-zero id and guid is
/// returned. There is no minimum roster size.
pub fn matches_avatars_all_data_notify(data: &[u8]) -> Option<Vec<AvatarInfo>> {
    discover_avatars(data).map(|(_, avatars)| avatars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r#gen::protos::{Equip, Material, PropValue, Weapon};

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

    // --- item and avatar lists ---------------------------------------------

    /// Field numbers the lists have sat on (`PlayerStoreNotify` 5 then 6,
    /// `AvatarDataNotify` 6 then 7) and one standing for a later patch.
    const LIST_TAGS: [u32; 4] = [5, 6, 7, 12];

    /// The uid half of every fixture guid.
    const UID: u64 = 800_123_456;

    /// A guid as the game mints them: `(uid << 32) + counter`.
    fn guid(counter: u64) -> u64 {
        (UID << 32) | counter
    }

    fn material_item(item_id: u32, guid: u64) -> Vec<u8> {
        let mut item = Item::new();
        item.item_id = item_id;
        item.guid = guid;
        let mut material = Material::new();
        material.count = 3;
        item.set_material(material);
        item.write_to_bytes().unwrap()
    }

    /// `count` materials on field `tag`, with ids from `first_id`.
    fn item_list(tag: u32, first_id: u32, count: u32) -> Vec<u8> {
        (0..count)
            .flat_map(|i| {
                field_bytes(
                    tag,
                    &material_item(first_id + i, guid(u64::from(first_id + i))),
                )
            })
            .collect()
    }

    /// A `PlayerStoreNotify`: `count` items on `tag` between the two scalar
    /// siblings 7.1's carried (fields 9 and 11).
    fn store_payload(tag: u32, count: u32) -> Vec<u8> {
        let mut out = field_varint(9, 2_000);
        out.extend(item_list(tag, 100_000, count));
        out.extend(field_varint(11, 1));
        out
    }

    fn avatar(avatar_id: u32, guid: u64) -> AvatarInfo {
        let mut avatar = AvatarInfo::new();
        avatar.avatar_id = avatar_id;
        avatar.guid = guid;
        let mut level = PropValue::new();
        level.type_ = PROP_LEVEL;
        level.val = 90;
        avatar.prop_map.insert(PROP_LEVEL, level);
        avatar
    }

    fn roster(count: u32) -> Vec<AvatarInfo> {
        (0..count)
            .map(|i| avatar(10_000_002 + i, guid(u64::from(i) + 1)))
            .collect()
    }

    /// An `AvatarDataNotify`: `avatars` on `tag`, beside siblings shaped like
    /// the real ones -- a packed guid list, the current team id and two
    /// entries of the team map.
    fn roster_payload(tag: u32, avatars: &[AvatarInfo]) -> Vec<u8> {
        let packed_guids: Vec<u8> = (1..=4).flat_map(|i| varint(guid(i))).collect();
        let mut out = field_bytes(1, &packed_guids);
        out.extend(field_varint(2, 1));
        for avatar in avatars {
            out.extend(field_bytes(tag, &avatar.write_to_bytes().unwrap()));
        }
        for team in 1..=2u64 {
            // `map<uint32, AvatarTeam>`: the team id, then the team.
            let team_body = field_bytes(15, &packed_guids);
            out.extend(field_bytes(
                13,
                &packet(&[field_varint(1, team), field_bytes(2, &team_body)]),
            ));
        }
        out
    }

    #[test]
    fn an_item_list_is_found_on_any_field_number() {
        for tag in LIST_TAGS {
            let data = store_payload(tag, 40);
            let (field, items) = discover_items(&data).expect("an inventory");
            assert_eq!(field, tag);
            assert_eq!(items.len(), 40);
            assert_eq!(items[0].item_id, 100_000, "wire order is kept");
            assert_eq!(items[39].item_id, 100_039);
            assert_eq!(items[0].material().count, 3);
            assert_eq!(
                matches_items_all_data_notify(&data).map(|items| items.len()),
                Some(40)
            );
        }
    }

    #[test]
    fn an_avatar_list_is_found_on_any_field_number() {
        for tag in LIST_TAGS {
            let data = roster_payload(tag, &roster(5));
            let (field, avatars) = discover_avatars(&data).expect("a roster");
            assert_eq!(field, tag);
            assert_eq!(avatars.len(), 5);
            assert_eq!(avatars[0].avatar_id, 10_000_002);
            assert_eq!(avatars[0].prop_map[&PROP_LEVEL].val, 90);
            assert_eq!(
                matches_avatars_all_data_notify(&data).map(|avatars| avatars.len()),
                Some(5)
            );
        }
    }

    #[test]
    fn a_one_character_roster_is_a_roster() {
        let data = roster_payload(7, &roster(1));
        assert_eq!(discover_avatars(&data).expect("a roster").1.len(), 1);
    }

    /// Mora and friends carry no guid. They are returned, as they always
    /// were, but they are no evidence of an inventory.
    #[test]
    fn virtual_items_ride_along_but_are_not_evidence() {
        let mut data = item_list(6, 100_000, 10);
        for id in [201u32, 202, 102] {
            data.extend(field_bytes(6, &material_item(id, 0)));
        }
        assert_eq!(matches_items_all_data_notify(&data).unwrap().len(), 13);

        let mut data = item_list(6, 100_000, 9);
        for id in 1000..1030u32 {
            data.extend(field_bytes(6, &material_item(id, 0)));
        }
        assert!(matches_items_all_data_notify(&data).is_none());
    }

    #[test]
    fn ten_items_are_the_floor() {
        assert!(matches_items_all_data_notify(&store_payload(6, 9)).is_none());
        assert!(matches_items_all_data_notify(&store_payload(6, 10)).is_some());
    }

    /// The false positive the real 7.1 traffic turned up once the field number
    /// stopped being fixed: lists of 58 and 105 entries (command 27685, field
    /// 8) that decode as items with tiny ids, an equip arm and 32-bit guids.
    #[test]
    fn items_whose_guids_carry_no_uid_are_not_an_inventory() {
        let lookalike: Vec<u8> = (0..105u64)
            .flat_map(|i| {
                let mut item = Item::new();
                item.item_id = [2, 3, 4][(i % 3) as usize];
                item.guid = 1_000 + i;
                let mut equip = Equip::new();
                equip.set_weapon(Weapon::new());
                item.set_equip(equip);
                field_bytes(8, &item.write_to_bytes().unwrap())
            })
            .collect();
        let mut data = lookalike.clone();
        data.extend(field_varint(10, 1));
        assert!(matches_items_all_data_notify(&data).is_none());

        // Beside a real inventory it is no competition either.
        let mut data = lookalike;
        data.extend(store_payload(6, 40));
        assert_eq!(discover_items(&data).expect("an inventory").0, 6);
    }

    #[test]
    fn a_small_lookalike_list_does_not_outvote_the_inventory() {
        let mut data = item_list(1, 200_000, 3);
        data.extend(store_payload(6, 40));
        data.extend(item_list(12, 300_000, 15));
        let (field, items) = discover_items(&data).expect("an inventory");
        assert_eq!(field, 6);
        assert_eq!(items.len(), 40);
    }

    #[test]
    fn two_comparable_item_lists_are_read_as_neither() {
        let mut data = item_list(5, 100_000, 40);
        data.extend(item_list(12, 200_000, 30));
        let logged = crate::test_support::warnings(|| {
            assert!(matches_items_all_data_notify(&data).is_none());
        });
        assert!(
            logged
                .iter()
                .any(|line| line.contains("two fields look like the item list")
                    && line.contains("field=5")
                    && line.contains("other_field=12")),
            "an ambiguous payload has to say so: {logged:?}"
        );

        // An exact tie, too: no field order to fall back on.
        let mut data = item_list(5, 100_000, 30);
        data.extend(item_list(12, 200_000, 30));
        assert!(matches_items_all_data_notify(&data).is_none());
    }

    #[test]
    fn an_entry_that_does_not_decode_costs_only_itself() {
        let mut data = store_payload(6, 40);
        // A submessage that claims more bytes than it has.
        data.extend(field_bytes(6, &[0x0a, 0x05, 0x01]));
        assert_eq!(matches_items_all_data_notify(&data).unwrap().len(), 40);
    }

    /// An `AvatarInfo` can decode as an `Item` -- here its fight-prop map
    /// fills the furniture arm -- so without ruling avatars out a roster on
    /// any field would pass for an inventory, and the item matcher runs first.
    #[test]
    fn a_roster_is_not_taken_for_an_inventory() {
        let avatars: Vec<AvatarInfo> = roster(20)
            .into_iter()
            .map(|mut avatar| {
                avatar.fight_prop_map.insert(2000, 15_000.0);
                avatar.skill_depot_id = 501;
                avatar
            })
            .collect();
        for avatar in &avatars {
            let as_item = Item::parse_from_bytes(&avatar.write_to_bytes().unwrap())
                .expect("the fixture must decode as an item");
            assert!(
                as_item.has_furniture() && as_item.guid >> 32 != 0,
                "the fixture must look like an inventory entry"
            );
        }

        for tag in LIST_TAGS {
            let data = roster_payload(tag, &avatars);
            assert!(
                matches_items_all_data_notify(&data).is_none(),
                "field {tag}"
            );
            assert_eq!(discover_avatars(&data).expect("a roster").0, tag);
        }
    }

    #[test]
    fn an_inventory_is_not_taken_for_a_roster() {
        for tag in LIST_TAGS {
            assert!(matches_avatars_all_data_notify(&store_payload(tag, 40)).is_none());
        }
    }

    #[test]
    fn avatars_outside_the_playable_block_are_not_a_roster() {
        let monsters: Vec<AvatarInfo> = (0..20u32)
            .map(|i| avatar(24_000_000 + i, guid(u64::from(i) + 1)))
            .collect();
        assert!(matches_avatars_all_data_notify(&roster_payload(6, &monsters)).is_none());

        // Next to a real roster they do not compete with it.
        let mut data = roster_payload(6, &monsters);
        for avatar in roster(3) {
            data.extend(field_bytes(9, &avatar.write_to_bytes().unwrap()));
        }
        let (field, avatars) = discover_avatars(&data).expect("a roster");
        assert_eq!(field, 9);
        assert_eq!(avatars.len(), 3);
    }

    #[test]
    fn avatars_without_a_level_are_not_a_roster() {
        let unlevelled: Vec<AvatarInfo> = roster(5)
            .into_iter()
            .map(|mut avatar| {
                let level = avatar.prop_map.remove(&PROP_LEVEL).unwrap();
                avatar.prop_map.insert(1002, level);
                avatar
            })
            .collect();
        assert!(matches_avatars_all_data_notify(&roster_payload(7, &unlevelled)).is_none());
    }

    #[test]
    fn a_roster_has_to_be_mostly_playable_characters() {
        let mut mixed = roster(3);
        mixed.extend((0..3u32).map(|i| avatar(24_000_000 + i, guid(100 + u64::from(i)))));
        assert!(
            matches_avatars_all_data_notify(&roster_payload(7, &mixed)).is_none(),
            "half is not most"
        );

        mixed.push(avatar(10_000_099, guid(99)));
        assert_eq!(
            matches_avatars_all_data_notify(&roster_payload(7, &mixed))
                .unwrap()
                .len(),
            7,
            "every kept entry is returned, the implausible ones included"
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
