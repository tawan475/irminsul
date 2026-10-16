//! The planner's routine, recognised by shape: today's Daily Commissions, the
//! Spiral Abyss period, expeditions, the Serenitea Pot's realm currency and
//! the Blessing of the Welkin Moon.
//!
//! Each of these is one message the server sends with every login's data
//! (`WorldOwnerDailyTaskNotify`, `TowerAllDataRsp`,
//! `AvatarExpeditionDataNotify`, `HomeResourceNotify`,
//! `PlayerRechargeDataNotify`). Like everything else this library reads,
//! their command ids and field numbers are reshuffled by every game version,
//! so nothing here names one: each message is recognised by what its values
//! are, and its fields are told apart the same way. Anything that cannot be
//! told apart with confidence is left out rather than guessed.
//!
//! Every matcher here was run over every command of recorded 7.1 sessions
//! (about 47,000 messages, login bundles wrapped and unwrapped) and matched
//! only the message it is for.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

use protobuf::Message;
use protobuf::UnknownValueRef::{Fixed32, Fixed64, LengthDelimited, Varint};

use crate::r#gen::protos::Unk;
use crate::unk_util::MIN_PLAUSIBLE_FINISH_TIMESTAMP;

/// Daily task (commission) ids. The 7.1 table runs 10100-49999; the block is
/// left wide so a release cannot age it out.
pub const DAILY_TASK_IDS: RangeInclusive<u64> = 10_000..=99_999;

/// The most commissions one day's list holds: 4 in 7.1.
pub const MAX_DAILY_TASKS: usize = 10;

/// Spiral Abyss floor ids: 1001-1008 for the corridor, four-digit ids for
/// each period's upper floors (1134-1139 in 7.1).
pub const ABYSS_FLOOR_IDS: RangeInclusive<u64> = 1_000..=9_999;

/// Stars one Abyss floor holds: three chambers of three.
pub const ABYSS_STARS_PER_FLOOR: u32 = 9;

/// The most floors a period opens: 4 in 7.1.
pub const MAX_ABYSS_FLOORS: usize = 12;

/// How long an Abyss period may last: a month in 7.1, half a month before
/// 4.7. The bounds only rule out a misread.
const ABYSS_PERIOD_SECS: RangeInclusive<u64> = 7 * 86_400..=62 * 86_400;

/// Expedition durations the game offers, in hours.
pub const EXPEDITION_HOURS: [u32; 4] = [4, 8, 12, 20];

/// Expedition ids: 101-706 in 7.1 (region times 100 plus a slot).
pub const EXPEDITION_IDS: RangeInclusive<u64> = 100..=99_999;

/// `AvatarExpeditionState`: 0 none, 1 doing, 2 finished and waiting for the
/// reward, 3 called back and waiting for it, 4 locked.
pub const MAX_EXPEDITION_STATE: u32 = 4;

/// The most map entries believed (one per character, ~110 in 7.1).
const MAX_EXPEDITION_ENTRIES: usize = 2_000;

/// The most realm currency a Serenitea Pot can store: 2400 at Trust Rank 10
/// in 7.1. Loose: only rules out a misread.
pub const MAX_REALM_CURRENCY: u32 = 100_000;

/// The most Welkin Moon days believed: one card is 30 days, and at most 180
/// can be held.
pub const MAX_WELKIN_DAYS: u32 = 400;

/// Today's Daily Commissions (`WorldOwnerDailyTaskNotify`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DailyCommissions {
    /// Commissions in today's list.
    pub total: u32,
    /// How many are finished, when that could be told apart from the city
    /// the list belongs to (see [`matches_daily_task_notify`]).
    pub finished: Option<u32>,
}

/// The Spiral Abyss period now running (`TowerAllDataRsp`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AbyssPeriod {
    /// When the period began, in unix seconds.
    pub start: u32,
    /// When it ends (the next period begins), in unix seconds.
    pub end: u32,
    /// Stars won on the period's floors.
    pub stars: u32,
    /// Stars those floors hold: [`ABYSS_STARS_PER_FLOOR`] each.
    pub max_stars: u32,
}

/// One character's expedition (`AvatarExpeditionDataNotify`).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Expedition {
    /// The character's avatar guid, as `AvatarInfo.guid` has it.
    pub avatar_guid: u64,
    /// See [`MAX_EXPEDITION_STATE`]; 0 for a character not out.
    pub state: u32,
    pub expedition_id: u32,
    pub hours: u32,
    /// When the expedition was sent, in unix seconds.
    pub start_time: u32,
    /// How much of the time a talent takes off (0.25 for 25%).
    pub shorten_ratio: f32,
}

impl Expedition {
    /// Whether the character is out (sent, or back and waiting to be
    /// collected).
    pub fn is_out(&self) -> bool {
        (1..=3).contains(&self.state)
    }

    /// When the expedition is done, in unix seconds.
    pub fn done_at(&self) -> u32 {
        let secs = f64::from(self.hours) * 3_600.0 * (1.0 - f64::from(self.shorten_ratio));
        self.start_time.saturating_add(secs.round() as u32)
    }
}

/// The Serenitea Pot's stores (`HomeResourceNotify`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HomeResources {
    /// Realm currency waiting in the Jar of Riches.
    pub realm_currency: u32,
    /// What the jar holds at most at this Trust Rank.
    pub realm_currency_limit: u32,
}

fn is_timestamp(value: u64) -> bool {
    value >= MIN_PLAUSIBLE_FINISH_TIMESTAMP && value <= u64::from(u32::MAX)
}

/// One field value, borrowed from the parsed message.
type Value<'a> = protobuf::UnknownValueRef<'a>;

/// A parsed message's fields grouped by tag, in wire order within each tag.
fn fields_by_tag(msg: &Unk) -> BTreeMap<u32, Vec<Value<'_>>> {
    let mut fields: BTreeMap<u32, Vec<Value<'_>>> = BTreeMap::new();
    for (tag, value) in msg.unknown_fields().iter() {
        fields.entry(tag).or_default().push(value);
    }
    fields
}

fn parse(bytes: &[u8]) -> Option<Unk> {
    Unk::parse_from_bytes(bytes).ok()
}

fn as_varint(value: &Value<'_>) -> Option<u64> {
    match value {
        Varint(v) => Some(*v),
        _ => None,
    }
}

fn as_bytes<'a>(value: &Value<'a>) -> Option<&'a [u8]> {
    match value {
        LengthDelimited(b) => Some(b),
        _ => None,
    }
}

/// A submessage's varint fields, keyed by tag, or `None` if it holds anything
/// else or repeats a tag.
fn varint_fields(bytes: &[u8]) -> Option<BTreeMap<u32, u64>> {
    let msg = parse(bytes)?;
    let fields = fields_by_tag(&msg);
    let mut out = BTreeMap::new();
    for (tag, values) in fields {
        let [value] = values.as_slice() else {
            return None;
        };
        out.insert(tag, as_varint(value)?);
    }
    Some(out)
}

/// The one tag present in every entry whose values pass `ok`, if exactly one
/// does.
fn only_common_tag(
    entries: &[BTreeMap<u32, u64>],
    skip: &[u32],
    ok: impl Fn(&[u64]) -> bool,
) -> Option<u32> {
    let mut common: BTreeSet<u32> = entries.first()?.keys().copied().collect();
    for entry in entries {
        common.retain(|tag| entry.contains_key(tag));
    }
    let found: Vec<u32> = common
        .into_iter()
        .filter(|tag| !skip.contains(tag))
        .filter(|tag| {
            let values: Vec<u64> = entries.iter().map(|entry| entry[tag]).collect();
            ok(&values)
        })
        .collect();
    match found.as_slice() {
        [tag] => Some(*tag),
        _ => None,
    }
}

fn all_distinct(values: &[u64]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

// ------------------------------------------------------------- commissions

/// Recover today's Daily Commissions from a `WorldOwnerDailyTaskNotify`
/// payload, or `None` if it is not one.
///
/// The shape: one repeated field of 1-[`MAX_DAILY_TASKS`] entries, each
/// varints only -- a unique daily task id ([`DAILY_TASK_IDS`]), one
/// item-sized reward id shared by the list's entries, and small counters
/// (the commission's target and progress) -- next to one or two small
/// numbers, and nothing else.
///
/// Those two numbers are the count of finished commissions and the city the
/// list belongs to (1 Mondstadt ... 4 Sumeru ...), both small, so they are
/// told apart by value: the count can never exceed the list. When both
/// readings give the same count (equal values), or only one value fits the
/// list, the count is known; otherwise [`DailyCommissions::finished`] is
/// `None`. A count of 0 is not on the wire, so a lone value larger than the
/// list is the city and the count is 0.
pub fn matches_daily_task_notify(data: &[u8]) -> Option<DailyCommissions> {
    let msg = parse(data)?;
    let fields = fields_by_tag(&msg);
    let mut list: Option<&Vec<Value>> = None;
    let mut numbers: Vec<u64> = Vec::new();
    for values in fields.values() {
        match values.first()? {
            Varint(_) => {
                let [Varint(value)] = values.as_slice() else {
                    return None;
                };
                numbers.push(*value);
            }
            LengthDelimited(_) => {
                if list.replace(values).is_some() {
                    return None;
                }
            }
            Fixed32(_) | Fixed64(_) => return None,
        }
    }
    let list = list?;
    if numbers.is_empty() || numbers.len() > 2 || numbers.iter().any(|&n| !(1..=64).contains(&n)) {
        return None;
    }
    if list.is_empty() || list.len() > MAX_DAILY_TASKS {
        return None;
    }
    let entries = list
        .iter()
        .map(|value| varint_fields(as_bytes(value)?).filter(|entry| entry.len() >= 2))
        .collect::<Option<Vec<_>>>()?;

    let id_tag = only_common_tag(&entries, &[], |values| {
        all_distinct(values) && values.iter().all(|v| DAILY_TASK_IDS.contains(v))
    })?;
    let reward_tag = only_common_tag(&entries, &[id_tag], |values| {
        values
            .iter()
            .all(|v| (1_000..DAILY_TASK_IDS.start().to_owned()).contains(v))
    })?;
    // Everything else is a small counter.
    if entries.iter().any(|entry| {
        entry
            .iter()
            .any(|(tag, &value)| *tag != id_tag && *tag != reward_tag && value > 1_000)
    }) {
        return None;
    }

    let total = list.len() as u64;
    let finished = match numbers.as_slice() {
        [only] if *only > total => Some(0),
        [a, b] if a == b => Some(*a),
        [a, b] if *a <= total && *b > total => Some(*a),
        [a, b] if *b <= total && *a > total => Some(*b),
        _ => None,
    };
    Some(DailyCommissions {
        total: total as u32,
        finished: finished.filter(|&n| n <= total).map(|n| n as u32),
    })
}

// ------------------------------------------------------------------- abyss

/// Read a submessage as a map entry from a floor id to a time: `{1: floor,
/// 2: unix seconds}`.
fn floor_open_time(bytes: &[u8]) -> Option<(u64, u64)> {
    let entry = varint_fields(bytes)?;
    if entry.len() != 2 {
        return None;
    }
    let (floor, time) = (*entry.get(&1)?, *entry.get(&2)?);
    (ABYSS_FLOOR_IDS.contains(&floor) && is_timestamp(time)).then_some((floor, time))
}

/// Read a submessage as one floor's record: exactly one varint is a floor id,
/// and its stars are the values of the one level-to-stars map it carries
/// (entries `{1: level, 2: stars <= 3}`). `None` if it is not a record or its
/// stars cannot be read unambiguously.
fn floor_record(bytes: &[u8]) -> Option<(u64, u32)> {
    let msg = parse(bytes)?;
    let fields = fields_by_tag(&msg);
    let mut floors = Vec::new();
    let mut maps = Vec::new();
    for values in fields.values() {
        for value in values {
            match value {
                Varint(v) if ABYSS_FLOOR_IDS.contains(v) => floors.push(*v),
                Varint(_) => {}
                Fixed32(_) | Fixed64(_) => return None,
                LengthDelimited(_) => {}
            }
        }
        // A repeated field all of whose entries are star map entries.
        let entries: Option<Vec<BTreeMap<u32, u64>>> = values
            .iter()
            .map(|value| {
                varint_fields(as_bytes(value)?).filter(|entry| {
                    !entry.is_empty()
                        && entry.keys().all(|tag| *tag == 1 || *tag == 2)
                        && entry.get(&2).is_none_or(|&stars| stars <= 3)
                })
            })
            .collect();
        if let Some(entries) = entries
            && entries.iter().any(|entry| entry.contains_key(&2))
        {
            maps.push(entries);
        }
    }
    let [floor] = floors.as_slice() else {
        return None;
    };
    let stars = match maps.as_slice() {
        [] => 0,
        [entries] => {
            let levels: Vec<u64> = entries.iter().filter_map(|e| e.get(&1).copied()).collect();
            if !all_distinct(&levels) {
                return None;
            }
            entries
                .iter()
                .map(|entry| entry.get(&2).copied().unwrap_or(0) as u32)
                .sum()
        }
        _ => return None,
    };
    (stars <= ABYSS_STARS_PER_FLOOR).then_some((*floor, stars))
}

/// Recover the Spiral Abyss period now running from a `TowerAllDataRsp`
/// payload, or `None` if it is not one.
///
/// The shape: a map from the period's floor ids to the time each opened, a
/// repeated list of floor records (each a floor id and its level-to-stars
/// map), and exactly two timestamps at the top level -- the period's start
/// and end -- with every floor opening inside the period. The stars are those
/// of the records of the period's own floors (the corridor's never count); a
/// floor never entered has no record and no stars.
pub fn matches_tower_all_data_rsp(data: &[u8]) -> Option<AbyssPeriod> {
    let msg = parse(data)?;
    let fields = fields_by_tag(&msg);
    let mut times: Vec<u64> = Vec::new();
    let mut open_maps: Vec<Vec<(u64, u64)>> = Vec::new();
    let mut record_lists: Vec<Vec<(u64, u32)>> = Vec::new();
    for values in fields.values() {
        match values.first()? {
            Varint(_) => {
                for value in values {
                    let value = as_varint(value)?;
                    if is_timestamp(value) {
                        times.push(value);
                    }
                }
            }
            LengthDelimited(_) => {
                let blobs: Option<Vec<&[u8]>> = values.iter().map(as_bytes).collect();
                let blobs = blobs?;
                if let Some(map) = blobs.iter().map(|b| floor_open_time(b)).collect() {
                    open_maps.push(map);
                } else if let Some(records) = blobs.iter().map(|b| floor_record(b)).collect() {
                    record_lists.push(records);
                }
            }
            Fixed32(_) | Fixed64(_) => {}
        }
    }

    let [open] = open_maps.as_slice() else {
        return None;
    };
    let records: &[(u64, u32)] = match record_lists.as_slice() {
        [] => &[],
        [records] => records,
        _ => return None,
    };
    if open.is_empty() || open.len() > MAX_ABYSS_FLOORS {
        return None;
    }
    let floors: BTreeSet<u64> = open.iter().map(|(floor, _)| *floor).collect();
    let record_floors: Vec<u64> = records.iter().map(|(floor, _)| *floor).collect();
    if floors.len() != open.len() || !all_distinct(&record_floors) {
        return None;
    }

    times.sort_unstable();
    times.dedup();
    let [start, end] = times.as_slice() else {
        return None;
    };
    if !ABYSS_PERIOD_SECS.contains(&(end - start))
        || open.iter().any(|(_, time)| time < start || time >= end)
    {
        return None;
    }

    let stars = records
        .iter()
        .filter(|(floor, _)| floors.contains(floor))
        .map(|(_, stars)| stars)
        .sum();
    Some(AbyssPeriod {
        start: *start as u32,
        end: *end as u32,
        stars,
        max_stars: floors.len() as u32 * ABYSS_STARS_PER_FLOOR,
    })
}

// ------------------------------------------------------------- expeditions

/// One expedition map value as read: its varints by tag and its one fixed32
/// (the shorten ratio), if any.
struct ExpeditionInfo {
    guid: u64,
    varints: BTreeMap<u32, u64>,
    ratio: Option<f32>,
}

/// Read a map entry `{1: avatar guid, 2: info}`; the info holds varints and
/// at most one fixed32.
fn expedition_entry(bytes: &[u8]) -> Option<ExpeditionInfo> {
    let msg = parse(bytes)?;
    let fields = fields_by_tag(&msg);
    if fields.keys().any(|tag| *tag != 1 && *tag != 2) {
        return None;
    }
    let [Varint(guid)] = fields.get(&1)?.as_slice() else {
        return None;
    };
    // An avatar guid carries the account's UID in its top half.
    if *guid <= u64::from(u32::MAX) {
        return None;
    }
    let mut info = ExpeditionInfo {
        guid: *guid,
        varints: BTreeMap::new(),
        ratio: None,
    };
    let Some(values) = fields.get(&2) else {
        return Some(info);
    };
    let [value] = values.as_slice() else {
        return None;
    };
    let inner = parse(as_bytes(value)?)?;
    for (tag, values) in fields_by_tag(&inner) {
        let [value] = values.as_slice() else {
            return None;
        };
        match value {
            Varint(v) => {
                info.varints.insert(tag, *v);
            }
            Fixed32(bits) if info.ratio.is_none() => {
                let ratio = f32::from_bits(*bits);
                if !(0.0..1.0).contains(&ratio) {
                    return None;
                }
                info.ratio = Some(ratio);
            }
            _ => return None,
        }
    }
    Some(info)
}

/// Recover every character's expedition from an `AvatarExpeditionDataNotify`
/// payload, or `None` if it is not one.
///
/// The shape: one repeated field of map entries from an avatar guid to the
/// character's expedition info (empty for a character never sent). The info
/// keeps the last expedition even after it was collected, so the state tells
/// who is out. Its fields are told apart by value across every entry: the
/// one timestamp is the start time, the one field whose values are all an
/// expedition length ([`EXPEDITION_HOURS`]) is the length, the one with
/// expedition ids the id, and what is left (0-[`MAX_EXPEDITION_STATE`],
/// absent when 0) the state. Any field that fits none, or two fields fitting
/// one role, and the message is not read.
pub fn matches_avatar_expedition_notify(data: &[u8]) -> Option<Vec<Expedition>> {
    let msg = parse(data)?;
    let fields = fields_by_tag(&msg);
    if fields.len() != 1 {
        return None;
    }
    let values = fields.values().next()?;
    if values.is_empty() || values.len() > MAX_EXPEDITION_ENTRIES {
        return None;
    }
    let infos = values
        .iter()
        .map(|value| expedition_entry(as_bytes(value)?))
        .collect::<Option<Vec<_>>>()?;
    let guids: Vec<u64> = infos.iter().map(|info| info.guid).collect();
    if !all_distinct(&guids) {
        return None;
    }

    let sent: Vec<BTreeMap<u32, u64>> = infos
        .iter()
        .filter(|info| !info.varints.is_empty())
        .map(|info| info.varints.clone())
        .collect();
    if sent.is_empty() {
        return None;
    }
    let time_tag = only_common_tag(&sent, &[], |values| values.iter().all(|&v| is_timestamp(v)))?;
    let hours_tag = only_common_tag(&sent, &[time_tag], |values| {
        values
            .iter()
            .all(|&v| EXPEDITION_HOURS.iter().any(|&h| u64::from(h) == v))
    })?;
    let id_tag = only_common_tag(&sent, &[time_tag, hours_tag], |values| {
        values.iter().all(|v| EXPEDITION_IDS.contains(v))
    })?;
    let rest: BTreeSet<u32> = sent
        .iter()
        .flat_map(|info| info.keys().copied())
        .filter(|tag| ![time_tag, hours_tag, id_tag].contains(tag))
        .collect();
    let state_tag = match rest.iter().copied().collect::<Vec<_>>().as_slice() {
        [] => None,
        [tag] => Some(*tag),
        _ => return None,
    };
    if let Some(tag) = state_tag
        && sent.iter().any(|info| {
            info.get(&tag)
                .is_some_and(|&s| s > u64::from(MAX_EXPEDITION_STATE))
        })
    {
        return None;
    }

    Some(
        infos
            .iter()
            .map(|info| {
                let get = |tag: Option<u32>| {
                    tag.and_then(|tag| info.varints.get(&tag))
                        .map_or(0, |&v| v as u32)
                };
                Expedition {
                    avatar_guid: info.guid,
                    state: get(state_tag),
                    expedition_id: get(Some(id_tag)),
                    hours: get(Some(hours_tag)),
                    start_time: get(Some(time_tag)),
                    shorten_ratio: info.ratio.unwrap_or(0.0),
                }
            })
            .collect(),
    )
}

// ------------------------------------------------------------------- realm

/// Read a submessage as one store: a fixed32 (the next refresh, all ones
/// when full) and the value and limit, `(value, limit)`. The value is never
/// above the limit; a value of 0 is not on the wire.
fn home_store(bytes: &[u8]) -> Option<(u32, u32)> {
    let msg = parse(bytes)?;
    let fields = fields_by_tag(&msg);
    let mut varints = Vec::new();
    let mut fixed = 0;
    for values in fields.values() {
        let [value] = values.as_slice() else {
            return None;
        };
        match value {
            Varint(v) => varints.push(*v),
            Fixed32(_) => fixed += 1,
            _ => return None,
        }
    }
    if fixed != 1 {
        return None;
    }
    let (value, limit) = match varints.as_slice() {
        [limit] => (0, *limit),
        [a, b] => (*a.min(b), *a.max(b)),
        _ => return None,
    };
    (limit >= 1 && limit <= u64::from(MAX_REALM_CURRENCY)).then_some((value as u32, limit as u32))
}

/// Recover the Serenitea Pot's realm currency from a `HomeResourceNotify`
/// payload, or `None` if it is not one.
///
/// The shape: exactly two submessages, each one store -- a fixed32 (the next
/// refresh), the stored value and its limit: the realm currency and the
/// companionship EXP. At every Trust Rank the realm currency's limit is the
/// larger (300-2400 against 50-500 in 7.1), so that is how they are told
/// apart; equal limits are not read.
pub fn matches_home_resource_notify(data: &[u8]) -> Option<HomeResources> {
    let msg = parse(data)?;
    let fields = fields_by_tag(&msg);
    let stores = fields
        .values()
        .map(|values| match values.as_slice() {
            [value] => home_store(as_bytes(value)?),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    let [a, b] = stores.as_slice() else {
        return None;
    };
    let (realm, _) = match a.1.cmp(&b.1) {
        std::cmp::Ordering::Greater => (a, b),
        std::cmp::Ordering::Less => (b, a),
        std::cmp::Ordering::Equal => return None,
    };
    Some(HomeResources {
        realm_currency: realm.0,
        realm_currency_limit: realm.1,
    })
}

// ------------------------------------------------------------------ welkin

/// Recover the Blessing of the Welkin Moon's days left from a
/// `PlayerRechargeDataNotify` payload, or `None` if it is not one.
///
/// The shape: the shop's price list -- a repeated field of at least three
/// entries, each exactly two text fields, one of them a store price tier
/// (`Tier_...`) -- next to at most one number, the days left (absent when 0).
pub fn matches_recharge_data_notify(data: &[u8]) -> Option<u32> {
    let msg = parse(data)?;
    let fields = fields_by_tag(&msg);
    let mut days: Option<u64> = None;
    let mut list: Option<&Vec<Value>> = None;
    for values in fields.values() {
        match values.first()? {
            Varint(v) => {
                if values.len() != 1 || days.replace(*v).is_some() {
                    return None;
                }
            }
            LengthDelimited(_) => {
                if list.replace(values).is_some() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    let list = list?;
    if list.len() < 3 {
        return None;
    }
    for value in list {
        let msg = parse(as_bytes(value)?)?;
        let entry = fields_by_tag(&msg);
        let texts = entry
            .values()
            .map(|values| match values.as_slice() {
                [value] => std::str::from_utf8(as_bytes(value)?).ok(),
                _ => None,
            })
            .collect::<Option<Vec<&str>>>()?;
        let [a, b] = texts.as_slice() else {
            return None;
        };
        let printable = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_graphic());
        if !printable(a) || !printable(b) || !(a.starts_with("Tier_") || b.starts_with("Tier_")) {
            return None;
        }
    }
    let days = days.unwrap_or(0);
    (days <= u64::from(MAX_WELKIN_DAYS)).then_some(days as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn v(tag: u32, value: u64) -> Vec<u8> {
        let mut out = varint(u64::from(tag) << 3);
        out.extend(varint(value));
        out
    }

    fn b(tag: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = varint((u64::from(tag) << 3) | 2);
        out.extend(varint(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    fn f32_field(tag: u32, bits: u32) -> Vec<u8> {
        let mut out = varint((u64::from(tag) << 3) | 5);
        out.extend_from_slice(&bits.to_le_bytes());
        out
    }

    fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.concat()
    }

    // -- commissions ----------------------------------------------------------

    /// A commission entry: target, reward id, task id (any field numbers).
    fn task(id: u64, target: u64) -> Vec<u8> {
        cat(&[v(7, target), v(11, 2112), v(14, id)])
    }

    fn commissions(list: u32, city: (u32, u64), done: (u32, u64)) -> Vec<u8> {
        let mut out = Vec::new();
        for (id, target) in [(32001, 6), (32002, 1), (32003, 1), (42001, 1)] {
            out.extend(b(list, &task(id, target)));
        }
        if city.1 > 0 {
            out.extend(v(city.0, city.1));
        }
        if done.1 > 0 {
            out.extend(v(done.0, done.1));
        }
        out
    }

    #[test]
    fn reads_commissions_when_the_count_is_unambiguous() {
        let read = |city, done| matches_daily_task_notify(&commissions(3, (5, city), (15, done)));
        // Equal: both readings agree.
        assert_eq!(
            read(4, 4),
            Some(DailyCommissions {
                total: 4,
                finished: Some(4)
            })
        );
        // A city past the list's length cannot be the count.
        assert_eq!(read(6, 2).unwrap().finished, Some(2));
        assert_eq!(read(6, 0).unwrap().finished, Some(0));
        // Both fit the list: not guessed.
        assert_eq!(read(2, 3).unwrap().finished, None);
        assert_eq!(read(4, 0).unwrap().finished, None);
    }

    #[test]
    fn commissions_do_not_depend_on_field_numbers() {
        let a = commissions(3, (5, 6), (15, 1));
        let b = commissions(9, (12, 6), (2, 1));
        assert_eq!(matches_daily_task_notify(&a), matches_daily_task_notify(&b));
        assert_eq!(matches_daily_task_notify(&b).unwrap().finished, Some(1));
    }

    #[test]
    fn other_lists_are_not_commissions() {
        // No number beside the list.
        let bare: Vec<u8> = [(32001, 6), (32002, 1)]
            .iter()
            .flat_map(|&(id, t)| b(3, &task(id, t)))
            .collect();
        assert_eq!(matches_daily_task_notify(&bare), None);
        // A one-field entry (an enum and an id).
        let chat = cat(&[b(9, &cat(&[v(1, 3), v(2, 21036)])), v(4, 1)]);
        assert_eq!(matches_daily_task_notify(&chat), None);
        // Ids not unique.
        let twice = cat(&[b(3, &task(32001, 6)), b(3, &task(32001, 6)), v(5, 4)]);
        assert_eq!(matches_daily_task_notify(&twice), None);
    }

    // -- abyss ----------------------------------------------------------------

    const START: u64 = 1_789_502_400;
    const END: u64 = 1_792_094_399;

    /// A floor record: level records, the star map, the reward progress and
    /// the floor id.
    fn floor(id: u64, stars: &[(u64, u64)]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(level, s) in stars {
            out.extend(b(7, &cat(&[v(4, level), b(13, &[1, 2, 3][..s as usize])])));
            out.extend(b(11, &cat(&[v(1, level), v(2, s)])));
        }
        out.extend(v(10, 3));
        out.extend(v(14, id));
        out
    }

    fn tower(records: &[Vec<u8>], open: &[u64]) -> Vec<u8> {
        let mut out = Vec::new();
        for record in records {
            out.extend(b(11, record));
        }
        for &id in open {
            out.extend(b(14, &cat(&[v(1, id), v(2, START)])));
        }
        out.extend(b(8, &cat(&[v(8, 36), v(9, 122), v(5, 12), v(13, 3)])));
        out.extend(v(1, 24));
        out.extend(v(4, 123));
        out.extend(v(6, END));
        out.extend(v(1330, START));
        out
    }

    #[test]
    fn reads_the_abyss_period() {
        let full = [(1, 3), (2, 3), (3, 3)];
        let records = vec![
            floor(1001, &full),
            floor(1008, &full),
            floor(1134, &full),
            floor(1135, &[(403, 3), (404, 2)]),
        ];
        let period = matches_tower_all_data_rsp(&tower(&records, &[1134, 1135, 1138, 1139]));
        assert_eq!(
            period,
            Some(AbyssPeriod {
                start: START as u32,
                end: END as u32,
                stars: 14,
                max_stars: 36
            })
        );
        // A fresh period: floors open, no records.
        let fresh = matches_tower_all_data_rsp(&tower(&[], &[1134, 1135, 1138, 1139])).unwrap();
        assert_eq!((fresh.stars, fresh.max_stars), (0, 36));
    }

    #[test]
    fn an_abyss_without_its_period_is_not_read() {
        let mut no_end = tower(&[], &[1134]);
        no_end.truncate(no_end.len() - v(1330, START).len());
        assert_eq!(matches_tower_all_data_rsp(&no_end), None);
        // A floor opening after the period ends.
        let mut late = Vec::new();
        late.extend(b(14, &cat(&[v(1, 1134), v(2, END + 10)])));
        late.extend(v(6, END));
        late.extend(v(1330, START));
        assert_eq!(matches_tower_all_data_rsp(&late), None);
    }

    // -- expeditions ----------------------------------------------------------

    const GUID: u64 = 812_345_678 << 32;

    /// A map entry: guid and info (state, id, hours, start, ratio).
    fn expedition(guid: u64, info: &[Vec<u8>]) -> Vec<u8> {
        cat(&[v(1, guid), b(2, &info.concat())])
    }

    fn expeditions() -> Vec<u8> {
        cat(&[
            b(3, &expedition(GUID + 1, &[])),
            b(
                3,
                &expedition(GUID + 2, &[v(2, 706), v(3, 20), v(4, 1_780_000_000)]),
            ),
            b(
                3,
                &expedition(
                    GUID + 3,
                    &[
                        v(2, 101),
                        v(3, 20),
                        v(4, 1_730_000_000),
                        f32_field(5, 0.25f32.to_bits()),
                    ],
                ),
            ),
            b(
                3,
                &expedition(
                    GUID + 4,
                    &[v(1, 1), v(2, 403), v(3, 12), v(4, 1_791_000_000)],
                ),
            ),
        ])
    }

    #[test]
    fn reads_who_is_on_an_expedition() {
        let all = matches_avatar_expedition_notify(&expeditions()).unwrap();
        assert_eq!(all.len(), 4);
        let out: Vec<_> = all.iter().filter(|e| e.is_out()).collect();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].avatar_guid, GUID + 4);
        assert_eq!(out[0].expedition_id, 403);
        assert_eq!(out[0].hours, 12);
        assert_eq!(out[0].done_at(), 1_791_000_000 + 12 * 3600);
        let shortened = all.iter().find(|e| e.avatar_guid == GUID + 3).unwrap();
        assert_eq!(shortened.done_at(), 1_730_000_000 + 15 * 3600);
        assert!(!shortened.is_out());
    }

    #[test]
    fn expeditions_without_a_sent_one_or_with_small_keys_are_not_read() {
        assert_eq!(
            matches_avatar_expedition_notify(&b(3, &expedition(GUID, &[]))),
            None
        );
        let small_key = b(
            3,
            &expedition(42, &[v(2, 706), v(3, 20), v(4, 1_780_000_000)]),
        );
        assert_eq!(matches_avatar_expedition_notify(&small_key), None);
    }

    // -- realm and welkin -----------------------------------------------------

    fn store(value: u64, limit: u64, next: u32) -> Vec<u8> {
        let mut out = Vec::new();
        if value > 0 {
            out.extend(v(8, value));
        }
        out.extend(f32_field(7, next));
        out.extend(v(15, limit));
        out
    }

    #[test]
    fn reads_the_realm_currency() {
        let full = cat(&[
            b(2, &store(2400, 2400, u32::MAX)),
            b(4, &store(400, 500, 1_791_100_000)),
        ]);
        assert_eq!(
            matches_home_resource_notify(&full),
            Some(HomeResources {
                realm_currency: 2400,
                realm_currency_limit: 2400
            })
        );
        // Either order, and an empty jar.
        let empty = cat(&[
            b(4, &store(50, 50, u32::MAX)),
            b(9, &store(0, 300, 1_791_100_000)),
        ]);
        assert_eq!(
            matches_home_resource_notify(&empty),
            Some(HomeResources {
                realm_currency: 0,
                realm_currency_limit: 300
            })
        );
        let equal = cat(&[b(2, &store(1, 300, 0)), b(4, &store(2, 300, 0))]);
        assert_eq!(matches_home_resource_notify(&equal), None);
    }

    fn price(product: &str, tier: &str) -> Vec<u8> {
        cat(&[b(1, product.as_bytes()), b(2, tier.as_bytes())])
    }

    #[test]
    fn reads_the_welkin_days() {
        let list: Vec<u8> = (1..=3)
            .flat_map(|n| b(15, &price(&format!("product_{n}"), &format!("Tier_{n}"))))
            .collect();
        assert_eq!(
            matches_recharge_data_notify(&cat(&[list.clone(), v(14, 59)])),
            Some(59)
        );
        assert_eq!(matches_recharge_data_notify(&list), Some(0));
        let other: Vec<u8> = (1..=3)
            .flat_map(|n| b(15, &price(&format!("product_{n}"), "label")))
            .collect();
        assert_eq!(matches_recharge_data_notify(&other), None);
    }

    // -- classification -------------------------------------------------------

    fn command(payload: &[u8]) -> crate::GameCommand {
        let mut out = vec![0x45, 0x67];
        out.extend(1_234u16.to_be_bytes());
        out.extend(0u16.to_be_bytes());
        out.extend((payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out.extend([0x89, 0xAB]);
        crate::GameCommand::try_new(out).expect("fixture should be a well formed command")
    }

    #[test]
    fn each_routine_message_is_claimed_by_its_own_matcher_only() {
        use crate::{CommandMatch, classify_command};
        // No other matcher may claim it too (that logs a warning).
        let kind = |payload: &[u8]| {
            let mut found = None;
            let warned = crate::test_support::warnings(|| {
                found = classify_command(&command(payload)).map(|m| m.kind());
            });
            assert_eq!(warned, Vec::<String>::new());
            found
        };
        assert_eq!(kind(&commissions(3, (5, 4), (15, 4))), Some("commissions"));
        assert_eq!(
            kind(&tower(&[floor(1134, &[(1, 3)])], &[1134, 1135])),
            Some("abyss")
        );
        assert_eq!(kind(&expeditions()), Some("expeditions"));
        let home = cat(&[
            b(2, &store(2400, 2400, u32::MAX)),
            b(4, &store(400, 500, 0)),
        ]);
        assert_eq!(kind(&home), Some("realm currency"));
        let prices: Vec<u8> = (1..=3)
            .flat_map(|n| b(15, &price(&format!("p{n}"), &format!("Tier_{n}"))))
            .collect();
        assert!(matches!(
            classify_command(&command(&cat(&[prices, v(14, 7)]))),
            Some(CommandMatch::Welkin(7))
        ));
    }
}
