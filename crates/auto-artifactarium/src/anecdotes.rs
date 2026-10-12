//! The Travel Accounts ("anecdotes") book, recognised by shape.
//!
//! The server answers the book's data request with one message
//! (`AnecdoteGetDataRsp`, command 28234 in 7.1) carrying four things:
//!
//! * a repeated list of `{id, state, finish_count}` entries, one per anecdote
//!   the player has met;
//! * a submessage holding one packed list: the book's unlocked area tabs;
//! * a submessage with the wish ("I want to hear about...") state: the NPC
//!   currently wished for and when the last wish was made;
//! * a submessage with the reward track: every ten recorded anecdotes trade
//!   for a reward, and it says which exchange is next and how far along it is.
//!
//! Like every other message this library reads, its command id and every
//! field number are reshuffled by each game version, so nothing here names
//! one. The message is recognised by what its values are, and the parts are
//! told apart the same way.
//!
//! ## Why it does not claim other messages
//!
//! "A list of `{id, small, small}` entries whose ids are six digits" is not
//! rare: in a 7.1 session the gadget chain level maps (`map<uint32, uint32>`,
//! whose entries are `{1: key, 2: value}`, with keys in the very same
//! 100000-199999 block), a watcher list, and the achievement-shaped
//! `BeyondCosmeticDataNotify` all carry one. What none of them carries next to
//! it is the area tab list: a submessage whose only content is a packed list of
//! distinct small numbers (1-64). Both have to be present, the anecdote list
//! must be the message's only repeated field, and every value has to stay in
//! the ranges the contract with the tracker allows (`GI_ANECDOTES.md`): ids
//! 100000-199999, states 0-15, finish counts up to 100000, at most 2000
//! entries. Against a recorded 7.1 session that combination matched exactly
//! one command, the real one.
//!
//! The live update notifies (`AnecdoteInfoUpdateNotify`,
//! `AnecdoteFinishNotify`) are deliberately not matched: they are a bare list
//! of the same entries with no sibling, which is exactly the shape of the
//! gadget chain level maps above, so there is nothing to tell them apart by.
//! The next full list (the book is re-sent whenever it is opened) replaces
//! whatever was captured.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

use protobuf::Message;
use protobuf::UnknownValueRef::{Fixed32, Fixed64, LengthDelimited, Varint};

use crate::r#gen::protos::Unk;
use crate::unk_util::MIN_PLAUSIBLE_FINISH_TIMESTAMP;

/// Anecdote ids. The 7.1 table runs 100001-109701; the block is left wide so
/// a release cannot age it out, and it is what the tracker accepts.
pub const ANECDOTE_IDS: RangeInclusive<u32> = 100_000..=199_999;

/// The highest `state` believed. The game has no published enum for it; four
/// values (0-3) are known, and the contract leaves room for more.
pub const MAX_ANECDOTE_STATE: u32 = 15;

/// The highest finish count believed. Only the two repeatable loops ever go
/// above 1.
pub const MAX_ANECDOTE_FINISH_COUNT: u32 = 100_000;

/// Area tab ids: 1-8 (Mondstadt to Snezhnaya) in 7.1.
pub const ANECDOTE_AREA_IDS: RangeInclusive<u32> = 1..=64;

/// The most entries believed: about twelve times the 7.1 table (161 rows).
pub const MAX_ANECDOTES: usize = 2_000;

/// The `state` of an anecdote that has been recorded in the book. Inferred
/// from a 7.1 capture (nearly every entry, each with a finish count of at
/// least 1); used only to tell the state field from the finish count.
pub const ANECDOTE_FINISHED_STATE: u32 = 3;

/// Recorded anecdotes per reward exchange: the game's
/// `ANECDOTE_REWARD_TARGET_COUNT` constant (10 in 7.1). A game constant, not an
/// account value, and the only way to tell the target field from the exchange
/// index, which is just another small number.
const REWARD_TARGET_COUNT: u64 = 10;

/// Reward ids are item-sized (245990, 50 Primogems, in 7.1); the reward
/// track's counters never get near this.
const MIN_REWARD_ID: u64 = 1_000;

/// One anecdote the player has met.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Anecdote {
    pub id: u32,
    /// 3 = recorded, 2 = in progress, 0 = idle again (a repeatable one).
    /// Inferred, not documented; omitted on the wire when 0.
    pub state: u32,
    /// How many times it was completed.
    pub finish_count: u32,
}

/// The reward track: ten recorded anecdotes per exchange.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AnecdoteReward {
    /// Which exchange is next.
    pub index: u32,
    /// Anecdotes recorded toward it.
    pub progress: u32,
    /// Anecdotes it needs.
    pub target: u32,
}

/// The book's wish: the NPC the player asked to hear about.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AnecdoteWish {
    /// `None` when no wish is active.
    pub npc_id: Option<u32>,
    /// When the last wish was made, in unix seconds.
    pub last_wish_time: u32,
}

/// Everything an `AnecdoteGetDataRsp` says.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnecdoteData {
    /// In wire order; ids are unique.
    pub anecdotes: Vec<Anecdote>,
    /// Sorted, unique.
    pub unlocked_areas: Vec<u32>,
    /// `None` when the submessage was absent or its fields could not be told
    /// apart with confidence.
    pub reward: Option<AnecdoteReward>,
    /// `None` when the submessage was absent (no wish was ever made) or did
    /// not read as one.
    pub wish: Option<AnecdoteWish>,
}

/// What reading a top-level field as the anecdote list found.
#[derive(Debug, PartialEq, Eq)]
enum ListRead {
    /// Not a list of anecdote entries at all.
    NotAList,
    /// Entries with a unique anecdote id, but the state and the finish count
    /// could not be told apart: something to log, not to export.
    Unassigned,
    List(Vec<Anecdote>),
}

/// A submessage's varint fields, keyed by tag, or `None` if it holds
/// anything else or repeats a tag.
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

/// Read one top-level field's values as the anecdote list.
///
/// The id is the one tag present in every entry whose values are all anecdote
/// ids and all different. The other two are told apart by what a recorded
/// anecdote looks like: state [`ANECDOTE_FINISHED_STATE`] with a finish count
/// of at least one. Read the wrong way round, those entries would be "state 1,
/// finished three times" -- the reading that explains more entries wins, and a
/// tie is reported as [`ListRead::Unassigned`] rather than guessed.
fn read_anecdote_list(values: &[&[u8]]) -> ListRead {
    if values.is_empty() || values.len() > MAX_ANECDOTES {
        return ListRead::NotAList;
    }
    let mut entries = Vec::with_capacity(values.len());
    for bytes in values {
        match varint_fields(bytes) {
            Some(entry) if !entry.is_empty() => entries.push(entry),
            _ => return ListRead::NotAList,
        }
    }

    let mut common: BTreeSet<u32> = entries[0].keys().copied().collect();
    for entry in &entries {
        common.retain(|tag| entry.contains_key(tag));
    }
    let ids: Vec<u32> = common
        .into_iter()
        .filter(|tag| {
            let mut seen = BTreeSet::new();
            entries.iter().all(|entry| {
                let value = entry[tag];
                u32::try_from(value).is_ok_and(|id| ANECDOTE_IDS.contains(&id))
                    && seen.insert(value)
            })
        })
        .collect();
    let [id_tag] = ids.as_slice() else {
        return ListRead::NotAList;
    };
    let id_tag = *id_tag;

    let others: BTreeSet<u32> = entries
        .iter()
        .flat_map(|entry| entry.keys().copied())
        .filter(|&tag| tag != id_tag)
        .collect();
    let max_of = |tag: u32| {
        entries
            .iter()
            .filter_map(|entry| entry.get(&tag).copied())
            .max()
            .unwrap_or(0)
    };
    if others
        .iter()
        .any(|&tag| max_of(tag) > u64::from(MAX_ANECDOTE_FINISH_COUNT))
    {
        return ListRead::NotAList;
    }

    let (state_tag, count_tag) = match others.iter().copied().collect::<Vec<_>>().as_slice() {
        // Nothing but ids: every state and every count is 0, so there is
        // nothing to tell apart.
        [] => (None, None),
        // One field: a state-sized one could be either.
        [tag] if max_of(*tag) > u64::from(MAX_ANECDOTE_STATE) => (None, Some(*tag)),
        [_] => return ListRead::Unassigned,
        [a, b] => {
            let recorded = |state: u32, count: u32| {
                if max_of(state) > u64::from(MAX_ANECDOTE_STATE) {
                    return None;
                }
                Some(
                    entries
                        .iter()
                        .filter(|entry| {
                            entry.get(&state) == Some(&u64::from(ANECDOTE_FINISHED_STATE))
                                && entry.get(&count).is_some_and(|&n| n >= 1)
                        })
                        .count(),
                )
            };
            match (recorded(*a, *b), recorded(*b, *a)) {
                (Some(x), Some(y)) if x > y => (Some(*a), Some(*b)),
                (Some(x), Some(y)) if y > x => (Some(*b), Some(*a)),
                (Some(_), None) => (Some(*a), Some(*b)),
                (None, Some(_)) => (Some(*b), Some(*a)),
                _ => return ListRead::Unassigned,
            }
        }
        // A field this reader does not know: refuse rather than guess which
        // two of them are the state and the count.
        _ => return ListRead::Unassigned,
    };

    let read = |entry: &BTreeMap<u32, u64>, tag: Option<u32>| {
        // Every value was range-checked above, so it fits.
        tag.and_then(|tag| entry.get(&tag))
            .map_or(0, |&value| value as u32)
    };
    ListRead::List(
        entries
            .iter()
            .map(|entry| Anecdote {
                id: entry[&id_tag] as u32,
                state: read(entry, state_tag),
                finish_count: read(entry, count_tag),
            })
            .collect(),
    )
}

/// Read a submessage as the area tab list: one packed field of distinct area
/// ids and nothing else.
fn read_area_list(bytes: &[u8]) -> Option<Vec<u32>> {
    let msg = Unk::parse_from_bytes(bytes).ok()?;
    let mut fields = msg.unknown_fields().iter();
    let (_, LengthDelimited(packed)) = fields.next()? else {
        return None;
    };
    if fields.next().is_some() {
        return None;
    }
    let values = crate::decode_packed_varints(packed)?;
    if values.is_empty() || values.len() > ANECDOTE_AREA_IDS.clone().count() {
        return None;
    }
    let mut areas = BTreeSet::new();
    for value in values {
        let area = u32::try_from(value).ok()?;
        if !ANECDOTE_AREA_IDS.contains(&area) || !areas.insert(area) {
            return None;
        }
    }
    Some(areas.into_iter().collect())
}

fn is_timestamp(value: u64) -> bool {
    value >= MIN_PLAUSIBLE_FINISH_TIMESTAMP && value <= u64::from(u32::MAX)
}

/// Read a submessage as the wish: a timestamp, and at most one other value
/// (the wished NPC).
fn read_wish(bytes: &[u8]) -> Option<AnecdoteWish> {
    let fields = varint_fields(bytes)?;
    let (times, others): (Vec<u64>, Vec<u64>) = fields
        .values()
        .copied()
        .partition(|&value| is_timestamp(value));
    let [time] = times.as_slice() else {
        return None;
    };
    let npc_id = match others.as_slice() {
        [] => None,
        [npc] => Some(u32::try_from(*npc).ok().filter(|&npc| npc != 0)?),
        _ => return None,
    };
    Some(AnecdoteWish {
        npc_id,
        last_wish_time: *time as u32,
    })
}

/// What a submessage read as the reward track found.
enum RewardRead {
    NotReward,
    /// The reward track, but its counters could not be told apart.
    Ambiguous,
    Reward(AnecdoteReward),
}

/// Read a submessage as the reward track.
///
/// Its shape: one item-sized reward id, at most one packed list of anecdote
/// ids (those recorded toward the current exchange), and small counters --
/// the exchange index, the progress, the target -- plus two flags that are 1
/// when set. No timestamp, which is what sets it apart from the wish.
///
/// The counters are all small numbers, so they are told apart by meaning:
/// the progress is the length of the recorded list (the game sends both), the
/// target is the game's constant [`REWARD_TARGET_COUNT`], and the index is
/// what is left once the flags (1s) are set aside. Two fields with the same
/// value need no telling apart; anything that does not settle this way (a lone
/// leftover 1 could be index 1 or a set flag with index 0) is
/// [`RewardRead::Ambiguous`], and the export carries no reward rather than a
/// wrong one.
fn read_reward(bytes: &[u8]) -> RewardRead {
    let Ok(msg) = Unk::parse_from_bytes(bytes) else {
        return RewardRead::NotReward;
    };
    let mut varints: Vec<u64> = Vec::new();
    let mut lists: Vec<Vec<u64>> = Vec::new();
    for (_, value) in msg.unknown_fields().iter() {
        match value {
            Varint(value) => varints.push(value),
            LengthDelimited(bytes) => match crate::decode_packed_varints(bytes) {
                Some(list) => lists.push(list),
                None => return RewardRead::NotReward,
            },
            Fixed32(_) | Fixed64(_) => return RewardRead::NotReward,
        }
    }
    if varints.iter().any(|&value| is_timestamp(value)) {
        return RewardRead::NotReward;
    }
    let reward_ids = varints
        .iter()
        .filter(|&&value| value >= MIN_REWARD_ID)
        .count();
    if reward_ids != 1 {
        return RewardRead::NotReward;
    }
    let recorded = match lists.as_slice() {
        [] => 0,
        [list]
            if list
                .iter()
                .all(|&id| u32::try_from(id).is_ok_and(|id| ANECDOTE_IDS.contains(&id))) =>
        {
            list.len() as u64
        }
        _ => return RewardRead::NotReward,
    };

    let mut counters: Vec<u64> = varints
        .into_iter()
        .filter(|&value| value < MIN_REWARD_ID)
        .collect();
    // A zero is never on the wire, so a progress of 0 has no field to take.
    if recorded > 0 && !take(&mut counters, recorded) {
        return RewardRead::Ambiguous;
    }
    if !take(&mut counters, REWARD_TARGET_COUNT) || recorded > REWARD_TARGET_COUNT {
        return RewardRead::Ambiguous;
    }
    let ones = counters.iter().filter(|&&value| value == 1).count();
    let mut rest: Vec<u64> = counters.into_iter().filter(|&value| value != 1).collect();
    rest.sort_unstable();
    rest.dedup();
    let index = match (rest.as_slice(), ones) {
        ([index], _) => *index,
        ([], 0) => 0,
        _ => return RewardRead::Ambiguous,
    };
    RewardRead::Reward(AnecdoteReward {
        index: index as u32,
        progress: recorded as u32,
        target: REWARD_TARGET_COUNT as u32,
    })
}

/// Remove one counter holding `wanted`, reporting whether there was one.
fn take(counters: &mut Vec<u64>, wanted: u64) -> bool {
    match counters.iter().position(|&value| value == wanted) {
        Some(at) => {
            counters.remove(at);
            true
        }
        None => false,
    }
}

/// Recover the Travel Accounts data from an `AnecdoteGetDataRsp` payload, or
/// `None` if it is not one. See the module documentation for what the shape
/// is and why it is not met elsewhere.
pub fn matches_anecdote_get_data_rsp(data: &[u8]) -> Option<AnecdoteData> {
    let msg = Unk::parse_from_bytes(data).ok()?;

    let mut blobs: BTreeMap<u32, Vec<&[u8]>> = BTreeMap::new();
    for (tag, value) in msg.unknown_fields().iter() {
        match value {
            LengthDelimited(bytes) => blobs.entry(tag).or_default().push(bytes),
            // The retcode; anything else at the top level is not this message.
            Varint(_) => {}
            Fixed32(_) | Fixed64(_) => return None,
        }
    }

    let mut list: Option<(u32, ListRead)> = None;
    for (&tag, values) in &blobs {
        let read = read_anecdote_list(values);
        if read == ListRead::NotAList {
            continue;
        }
        if list.is_some() {
            tracing::trace!("two fields read as anecdote lists; not the anecdote data");
            return None;
        }
        list = Some((tag, read));
    }
    let (list_tag, read) = list?;

    // The only repeated field is the anecdote list; the rest are single
    // submessages.
    if blobs
        .iter()
        .any(|(&tag, values)| tag != list_tag && values.len() != 1)
    {
        return None;
    }
    let singles: Vec<&[u8]> = blobs
        .iter()
        .filter(|&(&tag, _)| tag != list_tag)
        .map(|(_, values)| values[0])
        .collect();

    let areas: Vec<Vec<u32>> = singles.iter().filter_map(|b| read_area_list(b)).collect();
    let [unlocked_areas] = areas.as_slice() else {
        return None;
    };

    let anecdotes = match read {
        ListRead::List(anecdotes) => anecdotes,
        _ => {
            tracing::warn!(
                field = list_tag,
                "this looks like the Travel Accounts data, but the state and finish count of \
                 its entries could not be told apart; not exporting anecdotes"
            );
            return None;
        }
    };

    let wishes: Vec<AnecdoteWish> = singles.iter().filter_map(|b| read_wish(b)).collect();
    let wish = match wishes.as_slice() {
        [wish] => Some(*wish),
        _ => None,
    };

    let mut rewards = Vec::new();
    let mut ambiguous = 0usize;
    for bytes in &singles {
        match read_reward(bytes) {
            RewardRead::Reward(reward) => rewards.push(reward),
            RewardRead::Ambiguous => ambiguous += 1,
            RewardRead::NotReward => {}
        }
    }
    let reward = match (rewards.as_slice(), ambiguous) {
        ([reward], 0) => Some(*reward),
        _ => {
            tracing::debug!(
                found = rewards.len(),
                ambiguous,
                "no single readable anecdote reward track"
            );
            None
        }
    };

    Some(AnecdoteData {
        anecdotes,
        unlocked_areas: unlocked_areas.clone(),
        reward,
        wish,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::warnings;
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

    fn packed(values: &[u64]) -> Vec<u8> {
        values.iter().flat_map(|value| varint(*value)).collect()
    }

    /// A message's field numbers. The matcher must not depend on them; the
    /// 7.1 ones keep the main fixture honest, and the tests below reshuffle
    /// them the way a game patch does.
    #[derive(Clone, Copy)]
    struct Layout {
        list: u32,
        id: u32,
        state: u32,
        count: u32,
        area: u32,
        area_list: u32,
        wish: u32,
        wish_time: u32,
        wish_npc: u32,
        reward: u32,
        reward_index: u32,
        reward_id: u32,
        reward_target: u32,
        reward_recorded: u32,
        reward_progress: u32,
        reward_flag: u32,
        retcode: u32,
    }

    /// `AnecdoteGetDataRsp` as the 7.1 protocol numbers it.
    const LAYOUT_7_1: Layout = Layout {
        list: 1,
        id: 5,
        state: 8,
        count: 13,
        area: 2,
        area_list: 6,
        wish: 4,
        wish_time: 13,
        wish_npc: 14,
        reward: 7,
        reward_index: 5,
        reward_id: 10,
        reward_target: 12,
        reward_recorded: 14,
        reward_progress: 15,
        reward_flag: 9,
        retcode: 14,
    };

    /// The same message with every number moved.
    const LAYOUT_SHUFFLED: Layout = Layout {
        list: 11,
        id: 3,
        state: 1,
        count: 2,
        area: 6,
        area_list: 1,
        wish: 9,
        wish_time: 2,
        wish_npc: 1,
        reward: 3,
        reward_index: 15,
        reward_id: 2,
        reward_target: 7,
        reward_recorded: 1,
        reward_progress: 4,
        reward_flag: 11,
        retcode: 5,
    };

    fn entry(layout: Layout, anecdote: Anecdote) -> Vec<u8> {
        // Zeroes are not on the wire, as in proto3.
        let mut out = field_varint(layout.id, u64::from(anecdote.id));
        if anecdote.state != 0 {
            out.extend(field_varint(layout.state, u64::from(anecdote.state)));
        }
        if anecdote.finish_count != 0 {
            out.extend(field_varint(layout.count, u64::from(anecdote.finish_count)));
        }
        out
    }

    fn reward_bytes(
        layout: Layout,
        reward: AnecdoteReward,
        recorded: &[u64],
        flag: bool,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        if reward.index != 0 {
            out.extend(field_varint(layout.reward_index, u64::from(reward.index)));
        }
        out.extend(field_varint(layout.reward_id, 245_990));
        out.extend(field_varint(layout.reward_target, u64::from(reward.target)));
        if !recorded.is_empty() {
            out.extend(field_bytes(layout.reward_recorded, &packed(recorded)));
        }
        if reward.progress != 0 {
            out.extend(field_varint(
                layout.reward_progress,
                u64::from(reward.progress),
            ));
        }
        if flag {
            out.extend(field_varint(layout.reward_flag, 1));
        }
        out
    }

    fn wish_bytes(layout: Layout, wish: AnecdoteWish) -> Vec<u8> {
        let mut out = field_varint(layout.wish_time, u64::from(wish.last_wish_time));
        if let Some(npc) = wish.npc_id {
            out.extend(field_varint(layout.wish_npc, u64::from(npc)));
        }
        out
    }

    fn anecdote(id: u32, state: u32, finish_count: u32) -> Anecdote {
        Anecdote {
            id,
            state,
            finish_count,
        }
    }

    /// What a 7.1 account's book looks like: mostly recorded anecdotes, the
    /// two repeatable loops idle again, one in progress.
    fn sample() -> AnecdoteData {
        let mut anecdotes: Vec<Anecdote> = (1..=30)
            .map(|n| anecdote(100_000 + n * 100 + 1, ANECDOTE_FINISHED_STATE, 1))
            .collect();
        anecdotes.push(anecdote(101_604, 0, 2));
        anecdotes.push(anecdote(103_702, 0, 1));
        anecdotes.push(anecdote(107_302, 2, 0));
        AnecdoteData {
            anecdotes,
            unlocked_areas: vec![1, 2, 3, 4, 5, 6, 7, 8],
            reward: Some(AnecdoteReward {
                index: 12,
                progress: 4,
                target: 10,
            }),
            wish: Some(AnecdoteWish {
                npc_id: Some(9801),
                last_wish_time: 1_790_000_000,
            }),
        }
    }

    /// The anecdote entries of `data`, as the top-level repeated field.
    fn list_bytes(layout: Layout, data: &AnecdoteData) -> Vec<u8> {
        let mut out = Vec::new();
        for item in &data.anecdotes {
            out.extend(field_bytes(layout.list, &entry(layout, *item)));
        }
        out
    }

    fn area_bytes(layout: Layout, areas: &[u64]) -> Vec<u8> {
        field_bytes(layout.area, &field_bytes(layout.area_list, &packed(areas)))
    }

    /// `data` as the server sends it; the reward's recorded ids are made up.
    fn encode(layout: Layout, data: &AnecdoteData) -> Vec<u8> {
        let mut out = list_bytes(layout, data);
        let areas: Vec<u64> = data.unlocked_areas.iter().map(|&a| u64::from(a)).collect();
        out.extend(area_bytes(layout, &areas));
        if let Some(wish) = data.wish {
            out.extend(field_bytes(layout.wish, &wish_bytes(layout, wish)));
        }
        if let Some(reward) = data.reward {
            let recorded: Vec<u64> = (0..u64::from(reward.progress))
                .map(|n| 100_001 + n * 100)
                .collect();
            out.extend(field_bytes(
                layout.reward,
                &reward_bytes(layout, reward, &recorded, false),
            ));
        }
        out
    }

    fn command(payload: &[u8]) -> GameCommand {
        let mut out = vec![0x45, 0x67];
        out.extend(28_234u16.to_be_bytes());
        out.extend(0u16.to_be_bytes());
        out.extend((payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out.extend([0x89, 0xAB]);
        GameCommand::try_new(out).expect("fixture should be a well formed command")
    }

    // -- recognised ------------------------------------------------------------

    #[test]
    fn the_7_1_message_is_read_in_full() {
        let data = sample();
        assert_eq!(
            matches_anecdote_get_data_rsp(&encode(LAYOUT_7_1, &data)),
            Some(data)
        );
    }

    #[test]
    fn field_numbers_are_found_rather_than_assumed() {
        let data = sample();
        assert_eq!(
            matches_anecdote_get_data_rsp(&encode(LAYOUT_SHUFFLED, &data)),
            Some(data)
        );
    }

    #[test]
    fn the_state_and_the_finish_count_are_told_apart_whichever_tag_is_lower() {
        // Swap only the two entry fields: a reader that took "the lower tag is
        // the state" would read every recorded anecdote as state 1, finished
        // three times.
        let layout = Layout {
            state: LAYOUT_7_1.count,
            count: LAYOUT_7_1.state,
            ..LAYOUT_7_1
        };
        let data = sample();
        assert_eq!(
            matches_anecdote_get_data_rsp(&encode(layout, &data)),
            Some(data)
        );
    }

    #[test]
    fn the_command_is_classified_as_anecdotes_and_nothing_else() {
        let payload = encode(LAYOUT_7_1, &sample());
        let warned = warnings(|| match classify_command(&command(&payload)) {
            Some(CommandMatch::Anecdotes(data)) => assert_eq!(data, sample()),
            other => panic!("expected anecdotes, got {other:?}"),
        });
        assert!(warned.is_empty(), "{warned:?}");
    }

    #[test]
    fn a_new_book_with_one_entry_and_no_wish_is_still_read() {
        let data = AnecdoteData {
            anecdotes: vec![anecdote(100_001, ANECDOTE_FINISHED_STATE, 1)],
            unlocked_areas: vec![1],
            reward: Some(AnecdoteReward {
                index: 0,
                progress: 1,
                target: 10,
            }),
            wish: None,
        };
        assert_eq!(
            matches_anecdote_get_data_rsp(&encode(LAYOUT_SHUFFLED, &data)),
            Some(data)
        );
    }

    #[test]
    fn a_wish_without_an_npc_and_a_reward_with_no_progress_are_read() {
        let mut data = sample();
        data.wish = Some(AnecdoteWish {
            npc_id: None,
            last_wish_time: 1_790_000_000,
        });
        data.reward = Some(AnecdoteReward {
            index: 13,
            progress: 0,
            target: 10,
        });
        assert_eq!(
            matches_anecdote_get_data_rsp(&encode(LAYOUT_7_1, &data)),
            Some(data)
        );
    }

    #[test]
    fn a_retcode_beside_the_data_is_tolerated() {
        let data = sample();
        let mut payload = encode(LAYOUT_7_1, &data);
        payload.extend(field_varint(LAYOUT_7_1.retcode, 1));
        assert_eq!(matches_anecdote_get_data_rsp(&payload), Some(data));
    }

    #[test]
    fn a_reward_whose_counters_cannot_be_told_apart_is_left_out_not_guessed() {
        // Index 0 with a flag set leaves a lone 1, which reads as index 1 just
        // as well. The rest of the book is still read.
        let mut data = sample();
        data.unlocked_areas = vec![1, 2];
        data.wish = None;
        data.reward = None;
        let reward = AnecdoteReward {
            index: 0,
            progress: 2,
            target: 10,
        };
        let payload = [
            list_bytes(LAYOUT_7_1, &data),
            area_bytes(LAYOUT_7_1, &[1, 2]),
            field_bytes(
                LAYOUT_7_1.reward,
                &reward_bytes(LAYOUT_7_1, reward, &[100_001, 100_101], true),
            ),
        ]
        .concat();
        assert_eq!(matches_anecdote_get_data_rsp(&payload), Some(data));
    }

    #[test]
    fn a_set_flag_beside_a_real_index_does_not_hide_the_reward() {
        let mut data = sample();
        let reward = AnecdoteReward {
            index: 3,
            progress: 10,
            target: 10,
        };
        data.wish = None;
        data.reward = Some(reward);
        let recorded: Vec<u64> = (0..10).map(|n| 100_001 + n * 100).collect();
        let payload = [
            list_bytes(LAYOUT_7_1, &data),
            area_bytes(LAYOUT_7_1, &[1, 2, 3, 4, 5, 6, 7, 8]),
            field_bytes(
                LAYOUT_7_1.reward,
                &reward_bytes(LAYOUT_7_1, reward, &recorded, true),
            ),
        ]
        .concat();
        assert_eq!(matches_anecdote_get_data_rsp(&payload), Some(data));
    }

    // -- not recognised ----------------------------------------------------------

    #[test]
    fn an_achievement_list_is_not_anecdotes() {
        // `AchievementAllDataNotify`: {id, status, finish time} entries plus a
        // packed list of small goal ids beside them.
        let mut payload = Vec::new();
        for n in 0..200u64 {
            let mut item = field_varint(14, 80_000 + n);
            item.extend(field_varint(3, 3));
            item.extend(field_varint(2, 1_650_000_000 + n));
            payload.extend(field_bytes(5, &item));
        }
        payload.extend(field_bytes(9, &field_bytes(1, &packed(&[1, 2, 3, 4]))));
        assert_eq!(matches_anecdote_get_data_rsp(&payload), None);
    }

    #[test]
    fn the_cosmetic_data_notify_is_not_anecdotes() {
        // `BeyondCosmeticDataNotify`, which the achievement matcher mistakes
        // for achievements: several repeated lists of {timestamp, six-digit
        // id} entries, packed id lists and scalars.
        let mut payload = field_varint(2, 4);
        for n in 0..187u64 {
            let mut item = field_varint(5, 1_760_000_000 + n);
            item.extend(field_varint(13, 260_001 + n));
            payload.extend(field_bytes(7, &item));
        }
        payload.extend(field_varint(8, 500));
        for n in 0..128u64 {
            let mut item = field_varint(2, 1_770_000_000 - n);
            item.extend(field_varint(7, 1));
            item.extend(field_varint(10, 270_001 + n));
            payload.extend(field_bytes(12, &item));
        }
        payload.extend(field_bytes(15, &packed(&[1, 2, 3, 4, 5])));
        assert_eq!(matches_anecdote_get_data_rsp(&payload), None);
    }

    #[test]
    fn a_map_keyed_by_six_digit_ids_is_not_anecdotes() {
        // `GadgetChainLevelUpdateNotify`: `map<uint32, uint32>`, whose entries
        // are {1: key, 2: value} with keys in the anecdote id block. It is
        // also exactly what the live anecdote update notify looks like, which
        // is why that one is not matched.
        let mut payload = Vec::new();
        for n in 0..11u64 {
            let mut item = field_varint(1, 100_001 + n);
            item.extend(field_varint(2, n % 4));
            payload.extend(field_bytes(5, &item));
        }
        assert_eq!(matches_anecdote_get_data_rsp(&payload), None);
        payload.extend(field_varint(13, 1));
        assert_eq!(matches_anecdote_get_data_rsp(&payload), None);
    }

    #[test]
    fn random_lists_of_small_varints_are_not_anecdotes() {
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = |bound: u64| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) % bound
        };
        for _ in 0..500 {
            let mut payload = Vec::new();
            let list_tag = 1 + next(15) as u32;
            for _ in 0..1 + next(40) {
                let mut item = Vec::new();
                for tag in 1..=1 + next(4) as u32 {
                    item.extend(field_varint(tag, next(1000)));
                }
                payload.extend(field_bytes(list_tag, &item));
            }
            // Even with an area-shaped sibling: no field holds unique ids.
            let areas: Vec<u64> = (1..=1 + next(8)).collect();
            payload.extend(field_bytes(list_tag + 1, &field_bytes(1, &packed(&areas))));
            assert_eq!(matches_anecdote_get_data_rsp(&payload), None);
        }
    }

    #[test]
    fn the_list_without_its_area_tabs_is_not_enough() {
        let list = list_bytes(LAYOUT_7_1, &sample());
        assert_eq!(matches_anecdote_get_data_rsp(&list), None);
        // Nor does an area list that is not one stand in for it.
        for areas in [&[1, 65][..], &[1, 1], &[0, 1], &[]] {
            let payload = [list.clone(), area_bytes(LAYOUT_7_1, areas)].concat();
            assert_eq!(matches_anecdote_get_data_rsp(&payload), None, "{areas:?}");
        }
        // Two of them is ambiguous.
        let two = [
            list.clone(),
            area_bytes(LAYOUT_7_1, &[1, 2]),
            field_bytes(3, &field_bytes(1, &packed(&[3, 4]))),
        ]
        .concat();
        assert_eq!(matches_anecdote_get_data_rsp(&two), None);
    }

    #[test]
    fn a_second_repeated_field_or_a_second_list_is_not_this_message() {
        let base = encode(LAYOUT_7_1, &sample());
        let extra_repeat = [
            base.clone(),
            field_bytes(9, &field_varint(1, 5)),
            field_bytes(9, &field_varint(1, 6)),
        ]
        .concat();
        assert_eq!(matches_anecdote_get_data_rsp(&extra_repeat), None);

        let mut second_list = base;
        for n in 0..5u64 {
            let mut item = field_varint(1, 150_000 + n);
            item.extend(field_varint(2, 3));
            second_list.extend(field_bytes(10, &item));
        }
        assert_eq!(matches_anecdote_get_data_rsp(&second_list), None);
    }

    #[test]
    fn values_outside_the_contracts_ranges_are_not_believed() {
        // A duplicated id is not a list of anecdotes.
        let mut data = sample();
        data.anecdotes.push(data.anecdotes[0]);
        assert_eq!(
            matches_anecdote_get_data_rsp(&encode(LAYOUT_7_1, &data)),
            None
        );

        let mut data = sample();
        data.anecdotes[0].id = 99_999;
        assert_eq!(
            matches_anecdote_get_data_rsp(&encode(LAYOUT_7_1, &data)),
            None
        );

        let mut data = sample();
        data.anecdotes[0].finish_count = MAX_ANECDOTE_FINISH_COUNT + 1;
        assert_eq!(
            matches_anecdote_get_data_rsp(&encode(LAYOUT_7_1, &data)),
            None
        );

        let mut data = sample();
        data.anecdotes = (0..=MAX_ANECDOTES as u32)
            .map(|n| anecdote(100_000 + n, ANECDOTE_FINISHED_STATE, 1))
            .collect();
        assert_eq!(
            matches_anecdote_get_data_rsp(&encode(LAYOUT_7_1, &data)),
            None
        );
    }

    #[test]
    fn entries_whose_state_cannot_be_told_from_the_count_are_refused_with_a_warning() {
        // Every entry in progress and none recorded: one small field, which
        // could be either.
        let mut data = sample();
        for item in &mut data.anecdotes {
            *item = anecdote(item.id, 2, 0);
        }
        let payload = encode(LAYOUT_7_1, &data);
        let warned = warnings(|| assert_eq!(matches_anecdote_get_data_rsp(&payload), None));
        assert_eq!(warned.len(), 1, "{warned:?}");
        assert!(warned[0].contains("could not be told apart"), "{warned:?}");
    }

    #[test]
    fn garbage_is_not_anecdotes() {
        assert_eq!(matches_anecdote_get_data_rsp(&[]), None);
        assert_eq!(matches_anecdote_get_data_rsp(&[0xff; 64]), None);
        let mut payload = encode(LAYOUT_7_1, &sample());
        payload.truncate(payload.len() - 3);
        assert_eq!(matches_anecdote_get_data_rsp(&payload), None);
    }
}
