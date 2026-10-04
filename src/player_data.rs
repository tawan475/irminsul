use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::RangeInclusive;

use anime_game_data::{AnimeGameData, Property, SkillType};
use anyhow::Result;
pub use auto_artifactarium::Achievement;
pub use auto_artifactarium::r#gen::protos::{AvatarInfo, Item, PropValue};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::good::{self, fake_uninitialized_4th_line};

/// Player properties that are exported as GOOD `materials` entries.
///
/// GOOD has no place for arbitrary player properties, and the tracker backend
/// interns every distinct material key as a permanent dictionary row, so an
/// open ended `Property_<id>` fallback turned every false positive of the
/// property matcher into persistent junk. These five currencies are the ones
/// Genshin Optimizer and the tracker's catalog actually understand.
const EXPORTED_CURRENCY_PROPERTIES: [(u32, &str); 5] = [
    (10015, "Primogem"),
    (10016, "Mora"),
    (10020, "OriginalResin"),
    (10025, "GenesisCrystal"),
    (10042, "RealmCurrency"),
];

/// Sanity bound on a character level, deliberately far above the game's cap.
///
/// `prop_map` values are int64 on the wire; narrowing them with `as u32` turned
/// a negative into a huge level that sailed past `min_character_level`, so a
/// bound is needed. It must NOT be the game's actual cap: this was 1..=90, the
/// cap at the time it was written, and the game has since raised it — which
/// silently dropped every level 95 and 100 character from the export, the exact
/// characters a user most wants exported. A bound this loose still rejects 0 and
/// anything that came from a negative, which is all it was ever for, and cannot
/// go stale the next time miHoYo raises the cap.
const CHARACTER_LEVEL_RANGE: RangeInclusive<u32> = 1..=1_000;

/// Sanity bound on a character ascension ("break level").
///
/// Loose for the same reason as [`CHARACTER_LEVEL_RANGE`]: 0..=6 was the game's
/// cap when this was written, and pinning the check to a cap the game can raise
/// is what dropped real characters from the export. A raised level cap very
/// plausibly comes with another ascension phase.
const CHARACTER_ASCENSION_RANGE: RangeInclusive<u32> = 0..=100;

/// The two placeholder avatars ConstValueExcelConfigData names
/// `CONST_VALUE_TPS_AVATAR_CONFIG_ID_FEMALE` and `..._MALE`: both are called
/// "Traveler", carry a crossbow and an empty skill depot, and are not playable.
/// The tracker excludes the same two ids.
/// Share of item guids that must agree on a top half for it to be taken as
/// the account UID.
const UID_MAJORITY: f64 = 0.9;

/// `AvatarInfo.avatar_type` of an owned character (0 none, 2 trial, 3 mirror).
const AVATAR_TYPE_FORMAL: u32 = 1;

const TPS_AVATAR_ID_FEMALE: u32 = 10000135;
const TPS_AVATAR_ID_MALE: u32 = 10000134;

/// Avatar ids that are never exported: the TPS placeholders.
///
/// `anime-game-data` reads them from ConstValueExcelConfigData, whose `value`
/// column is obfuscated from 7.1 on (`CBOMLBFIPJM` at dump 792978e5), so both
/// lookups fail and the exclusion used to do nothing at all. The ids have not
/// moved -- that dump still lists 10000135 and 10000134 under those names -- so
/// they stand in for whichever lookup fails.
fn tps_avatar_ids(game_data: &AnimeGameData) -> [u32; 2] {
    [
        game_data
            .get_tps_avatar_id_female()
            .unwrap_or(TPS_AVATAR_ID_FEMALE),
        game_data
            .get_tps_avatar_id_male()
            .unwrap_or(TPS_AVATAR_ID_MALE),
    ]
}

/// Whether an achievement counts as done: `FINISHED` (2) or `REWARD_TAKEN` (3).
/// `gi_achievements` and `gi_achievement_times` both use this, so they agree.
fn achievement_completed(achievement: &Achievement) -> bool {
    achievement.status == 2 || achievement.status == 3
}

/// 2020-09-15 00:00:00 UTC, two weeks before the game launched: nothing was
/// finished or obtained before it.
const EARLIEST_PLAUSIBLE_TIME: u64 = 1_600_128_000;

/// How far past this machine's clock a game time may be: a day, for a clock
/// that runs behind the server's.
const CLOCK_SLACK_SECS: u64 = 86_400;

/// Whether `secs` (unix seconds) can be a real moment in the game's history,
/// given that it is now `now_secs`. These times come from fields matched by
/// shape or from field numbers carried over from older versions, so a value
/// outside the window means the field was misread.
fn plausible_time(secs: u64, now_secs: u64) -> bool {
    (EARLIEST_PLAUSIBLE_TIME..=now_secs.saturating_add(CLOCK_SLACK_SECS)).contains(&secs)
}

/// A real friendship level. Characters start at 1. The Traveler has no
/// friendship in game and is expected to fail this, which is one reason a field
/// is only distrusted when most characters fail it.
const FRIENDSHIP_RANGE: RangeInclusive<u32> = 1..=10;

/// How one `gi_characters` field fared across an export's characters.
#[derive(Debug, Default)]
struct FieldTally {
    plausible: usize,
    /// `(character key, raw value)` for each value that failed its check.
    implausible: Vec<(String, u32)>,
}

impl FieldTally {
    /// Count one character's value; it is kept only when `plausible`.
    fn check(&mut self, key: &str, raw: u32, plausible: bool) -> Option<u32> {
        if plausible {
            self.plausible += 1;
            Some(raw)
        } else {
            self.implausible.push((key.to_string(), raw));
            None
        }
    }

    fn total(&self) -> usize {
        self.plausible + self.implausible.len()
    }

    /// Whether the field reads right in this game version: unless most
    /// characters failed it.
    fn trusted(&self) -> bool {
        self.implausible.len() * 2 <= self.total()
    }

    /// e.g. `friendship 96/97 plausible (implausible: TravelerAnemo 0)`.
    fn describe(&self, name: &str) -> String {
        let mut text = format!("{name} {}/{} plausible", self.plausible, self.total());
        if !self.implausible.is_empty() {
            let samples: Vec<String> = self
                .implausible
                .iter()
                .take(3)
                .map(|(key, raw)| format!("{key} {raw}"))
                .collect();
            text.push_str(&format!(" (implausible: {}", samples.join(", ")));
            if self.implausible.len() > samples.len() {
                text.push_str(", ...");
            }
            text.push(')');
        }
        if !self.trusted() {
            text.push_str(", so omitted");
        }
        text
    }
}

/// e.g. `HuTao friendship 10 obtained 2022-03-01`, for the log.
fn describe_character_extras(key: &str, extra: &good::GiCharacter) -> String {
    let mut text = key.to_string();
    if let Some(level) = extra.friendship {
        text.push_str(&format!(" friendship {level}"));
    }
    if let Some(obtained) = extra
        .obtained_at
        .and_then(|secs| chrono::DateTime::from_timestamp(i64::from(secs), 0))
    {
        text.push_str(&format!(" obtained {}", obtained.format("%Y-%m-%d")));
    }
    text
}

/// A player property `gi_player` reports: its client `PROP_*` id, and the range
/// a real value falls in.
///
/// The ids are the game's own enum rather than anything in the Excel data, so
/// `anime-game-data` cannot supply them. They have been stable since 1.0
/// (Grasscutter's `PlayerProperty.java` is the reference) and a 7.1 login
/// carries every one. A value outside its range is left out of `gi_player`
/// rather than sent: these numbers are only ever read as facts, and the
/// property matcher works by shape.
struct PlayerProp {
    id: u32,
    range: RangeInclusive<u64>,
}

/// `PROP_PLAYER_LEVEL`. 1..=60 is the tracker's own range for an account's
/// Adventure Rank, so nothing outside it could be stored anyway.
const PROP_ADVENTURE_RANK: PlayerProp = PlayerProp {
    id: 10013,
    range: 1..=60,
};
/// `PROP_PLAYER_EXP`, EXP toward the next rank. The bound only rules out a
/// misread (a timestamp, an id): a whole rank is far below it.
const PROP_ADVENTURE_EXP: PlayerProp = PlayerProp {
    id: 10014,
    range: 0..=10_000_000,
};
/// `PROP_PLAYER_WORLD_LEVEL`. 0..=9 is the tracker's range; World Level 9 is
/// real (a 7.1 account reports a limit of 9), Grasscutter's 0..=8 predates it.
const PROP_WORLD_LEVEL: PlayerProp = PlayerProp {
    id: 10019,
    range: 0..=9,
};
/// `PROP_PLAYER_WORLD_LEVEL_LIMIT`, the highest World Level the account may
/// choose.
const PROP_WORLD_LEVEL_LIMIT: PlayerProp = PlayerProp {
    id: 10039,
    range: 0..=9,
};
/// `PROP_PLAYER_RESIN`, Original Resin: refills can take it past the natural
/// cap, up to 2000.
const PROP_RESIN: PlayerProp = PlayerProp {
    id: 10020,
    range: 0..=2_000,
};
/// `PROP_PLAYER_LEGENDARY_KEY`, Story Keys. Loose: only rules out a misread.
const PROP_STORY_KEYS: PlayerProp = PlayerProp {
    id: 10027,
    range: 0..=1_000,
};
/// `PROP_MAX_STAMINA`, in the game's units (24000 is the 240 it shows). Loose,
/// so a raised cap is not dropped; zero is not a stamina bar.
const PROP_MAX_STAMINA: PlayerProp = PlayerProp {
    id: 10010,
    range: 1..=100_000,
};

/// Why, and how often, an export fell short of the captured data.
///
/// The game data is baked into the binary at build time, so after a Genshin
/// version bump a lookup for a brand new character, set, weapon or material
/// simply fails and the entity disappears from the snapshot — on the dashboard
/// that is indistinguishable from never having owned it. Counting the misses
/// lets the caller say so.
///
/// Two buckets, because the two failures are not the same size and the UI
/// cannot tell them apart from a single count:
///
/// * `dropped` — the entity is not in the snapshot at all. This is what
///   [`is_empty`](Self::is_empty) and [`summary`](Self::summary) report, and
///   what the UI turns into an "Export incomplete" error toast.
/// * `degraded` — the entity *is* in the snapshot, but one of its fields fell
///   back to a default. Logged, never toasted: `unknown_skill` fires on every
///   single export for anyone who owns Kamisato Ayaka or Mona, because
///   `anime-game-data` only ever indexes depot skill slots 0 and 1 plus the
///   energy skill, and their alternate-sprint skill (slot 2, e.g. 10013) is
///   absent from `skill_type_map` by construction rather than by version drift.
///   A permanent red toast for a condition that is always true would destroy
///   the signal value of the ones that mean something.
///
/// `saturated_currency` is deliberately left in the loud bucket: it is real,
/// rare data loss rather than a structural always-on miss.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExportReport {
    dropped: BTreeMap<&'static str, usize>,
    degraded: BTreeMap<&'static str, usize>,
}

impl ExportReport {
    /// An entity was left out of the export entirely.
    fn record_dropped(&mut self, reason: &'static str) {
        *self.dropped.entry(reason).or_default() += 1;
    }

    /// An entity was exported, but one of its fields kept a default value.
    fn record_degraded(&mut self, reason: &'static str) {
        *self.degraded.entry(reason).or_default() += 1;
    }

    /// Whether anything was dropped from the export.
    ///
    /// Degraded fields deliberately do not count: this is the predicate the UI
    /// uses to raise an error, and it must stay true only for gaps a user can
    /// act on.
    pub fn is_empty(&self) -> bool {
        self.dropped.is_empty()
    }

    /// One line, deterministically ordered summary of the dropped entities,
    /// e.g. `unknown_artifact: 3, unknown_material: 7`.
    pub fn summary(&self) -> String {
        summarize(&self.dropped)
    }

    /// Whether any exported entity had a field fall back to its default.
    pub fn has_degradations(&self) -> bool {
        !self.degraded.is_empty()
    }

    /// One line, deterministically ordered summary of the degraded fields.
    pub fn degraded_summary(&self) -> String {
        summarize(&self.degraded)
    }
}

fn summarize(counts: &BTreeMap<&'static str, usize>) -> String {
    counts
        .iter()
        .map(|(reason, count)| format!("{reason}: {count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Narrow a captured player property to the GOOD material count type.
///
/// The narrowing is this exporter's own choice, not an external constraint:
/// `Item.material.count` is a protobuf `uint32`, so every item-sourced count is
/// natively 32 bit and the map is typed to match, while player properties are
/// u64 (Mora alone caps at 9,999,999,999 in game). Nothing downstream requires
/// it — the tracker stores `Good.materials` as a Postgres `jsonb` column
/// (`prisma/schema.prisma`, `materials Json @default("{}")`) and writes the
/// value through verbatim, so a wider number would round-trip fine. Saturate
/// rather than wrap, so an implausible number stays implausibly large instead
/// of silently becoming a plausible small one, and report the saturation.
fn clamp_material_count(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// The GOOD (0 based) artifact level for a wire (1 based) level.
///
/// A real artifact is always level >= 1. A `Reliquary` that omits field 1
/// decodes as the proto3 default 0, and `0 - 1` underflows: a panic in debug,
/// `u32::MAX` in release. The release value then sails past `min_artifact_level`
/// — nothing is ever less than the minimum — and gets content hashed into
/// permanent tracker history, so drop the artifact instead.
fn artifact_export_level(wire_level: u32) -> Option<u32> {
    wire_level.checked_sub(1)
}

/// Read an avatar property and check it against the range the game can actually
/// report.
///
/// Reads the whole `PropValue`, not just field 4. The same number arrives in
/// `val` (field 4) or in the `value` oneof (`ival` field 2, `fval` field 3)
/// depending on the property and the game version, and reading only `val` made
/// every character whose level came through the oneof decode as 0 — out of
/// range, and so dropped from the export with the rest of its data. The decoder
/// lives in `auto_artifactarium` beside the one for player properties, which hit
/// exactly this on the same message type; duplicating it here is what let the
/// two drift apart in the first place.
fn validated_avatar_prop(prop: &PropValue, range: RangeInclusive<u32>) -> Option<u32> {
    let raw = auto_artifactarium::prop_value_any(prop)?;
    u32::try_from(raw).ok().filter(|v| range.contains(v))
}

/// A running GOOD material total, plus the first item id that contributed to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MaterialTotal {
    count: u32,
    first_item_id: u32,
}

/// What folding one item into the material map did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaterialMerge {
    /// Counted. Either the key was free, or the same item id is contributing a
    /// second stack (the same material under two guids), which is a real total.
    Merged,
    /// Counted, but a *differently* id'd item already owned this GOOD key, so
    /// the exported number is the sum of two distinct items.
    MergedColliding { first_item_id: u32 },
    /// The item's name has no GOOD key, so nothing was counted.
    NoKey,
}

/// Add `count` to the running total for `key`.
///
/// Distinct item ids can share a display name, so collecting `(key, count)`
/// pairs into a map let one silently overwrite the other, with the winner
/// depending on hash order. Summing instead is deterministic, but it is only
/// *right* for genuinely identical items: 1031 GOOD keys in the baked game data
/// are claimed by more than one item id, and dozens of those pair a commonly
/// held item with an identically named quest prop (`CrystalChunk` = 101003 and
/// 339011, `ChilledMeat` = 100094 and 100705, `DeliciousGoldenCrab` = 108103
/// and 100244, ...). Holding both then over-counts the real stack.
///
/// Nothing in `material_map` distinguishes a prop from an item — it is a bare
/// `id -> display name` table — so the collision cannot be resolved here
/// without a curated `item_id -> GOOD key` table. Report it instead, so the
/// inflation is visible rather than silent.
///
/// Items whose name has no GOOD key at all (16 items are literally named
/// "？？？") are dropped rather than exported under `""`.
fn merge_material(
    totals: &mut HashMap<String, MaterialTotal>,
    key: String,
    item_id: u32,
    count: u32,
) -> MaterialMerge {
    if key.is_empty() {
        return MaterialMerge::NoKey;
    }
    match totals.entry(key) {
        Entry::Vacant(slot) => {
            slot.insert(MaterialTotal {
                count,
                first_item_id: item_id,
            });
            MaterialMerge::Merged
        }
        Entry::Occupied(mut slot) => {
            let total = slot.get_mut();
            total.count = total.count.saturating_add(count);
            if total.first_item_id == item_id {
                MaterialMerge::Merged
            } else {
                MaterialMerge::MergedColliding {
                    first_item_id: total.first_item_id,
                }
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExportSettings {
    pub include_characters: bool,
    pub include_artifacts: bool,
    pub include_weapons: bool,
    pub include_materials: bool,
    pub fake_initialize_4th_line: bool,

    pub min_character_level: u32,
    pub min_character_ascension: u32,
    pub min_character_constellation: u32,

    pub min_artifact_level: u32,
    pub min_artifact_rarity: u32,

    pub min_weapon_level: u32,
    pub min_weapon_refinement: u32,
    pub min_weapon_ascension: u32,
    pub min_weapon_rarity: u32,
}

pub struct PlayerData {
    game_data: AnimeGameData,
    achievements: HashMap<u32, Achievement>,
    characters: HashMap<u32, AvatarInfo>,
    /// Captured inventory, keyed by `(item_id, guid)`.
    ///
    /// Virtual items (Primogem, Original Resin, Genesis Crystal, ...) all carry
    /// guid 0, so keying by guid alone made them overwrite one another and at
    /// most one of them ever reached the export.
    ///
    /// They now all survive, which is a visible output change: besides the four
    /// currencies the property pass overwrites anyway, the guid-0 ids include
    /// Character EXP (101), Adventure EXP (102), Companionship EXP (105) and
    /// Story Key (107), all four of which the tracker's material catalog
    /// accepts and would render as new rows. `export_genshin_optimizer_materials`
    /// drops zero counts so the empty ones do not appear; a real Story Key
    /// count does.
    items: HashMap<(u32, u64), Item>,
    properties: HashMap<u32, u64>,

    character_equip_guid_map: HashMap<u64, u32>,

    /// The dump commit `game_data` was built from, for `gi_player.gameData`.
    game_data_sha: Option<String>,
}

impl PlayerData {
    pub fn new(game_data: AnimeGameData) -> Self {
        Self {
            game_data,
            achievements: HashMap::new(),
            characters: HashMap::new(),
            items: HashMap::new(),
            properties: HashMap::new(),
            character_equip_guid_map: HashMap::new(),
            game_data_sha: None,
        }
    }

    /// Name the dump commit `game_data` was built from, which exports then
    /// report as `gi_player.gameData`.
    pub fn with_game_data_sha(mut self, sha: Option<&str>) -> Self {
        self.game_data_sha = sha.map(str::to_owned);
        self
    }

    /// Forget everything captured about the account, keeping the game data.
    ///
    /// Reached from the UI's "Clear data" control via `Message::ClearData`, and
    /// when a new game connection delivers its first data, which stops a second
    /// account's inventory being merged into the first one's. Still the only way to drop captured
    /// state the game never announces a change for: destroyed items are tracked
    /// by [`remove_items`](Self::remove_items), but a stack whose count merely
    /// falls is only corrected by the next full inventory notify, which the
    /// game sends at login.
    pub fn reset(&mut self) {
        self.achievements.clear();
        self.characters.clear();
        self.items.clear();
        self.properties.clear();
        self.character_equip_guid_map.clear();
    }

    /// Whether nothing at all has been captured.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.achievements.is_empty()
            && self.characters.is_empty()
            && self.items.is_empty()
            && self.properties.is_empty()
    }

    pub fn process_achievements(&mut self, achievements: &[Achievement]) {
        for achievement in achievements {
            self.achievements
                .insert(achievement.id, achievement.clone());
        }
    }

    pub fn process_properties(&mut self, new_props: &HashMap<u32, u64>) {
        for (k, v) in new_props {
            self.properties.insert(*k, *v);
        }
    }

    pub fn process_characters(&mut self, avatars: &[AvatarInfo]) {
        // Rebuild the equip map for exactly the avatars this packet describes,
        // so gear that was moved or unequipped stops being attributed to whoever
        // held it at login. Avatars the packet does not mention keep their
        // mapping: avatar packets have no minimum roster size, so a partial
        // notify must not wipe everyone else's equipment.
        let updated: HashSet<u32> = avatars.iter().map(|avatar| avatar.avatar_id).collect();
        self.character_equip_guid_map
            .retain(|_, avatar_id| !updated.contains(avatar_id));

        for avatar in avatars {
            // The roster can list a character twice: the owned (formal, type
            // 1) avatar and a mirror copy (type 3) under the same avatar id.
            // Seen on 7.1 for Varka, Vesna and the Traveler (108 entries, 104
            // ids). Characters are keyed by avatar id, so whichever came last
            // won, and a mirror replacing the owned avatar dropped the
            // character from the export. The owned one always wins.
            if avatar.avatar_type != AVATAR_TYPE_FORMAL
                && self
                    .characters
                    .get(&avatar.avatar_id)
                    .is_some_and(|kept| kept.avatar_type == AVATAR_TYPE_FORMAL)
            {
                tracing::debug!(
                    avatar_id = avatar.avatar_id,
                    avatar_type = avatar.avatar_type,
                    "keeping the owned avatar over a non-formal copy"
                );
                continue;
            }
            for guid in &avatar.equip_guid_list {
                self.character_equip_guid_map
                    .insert(*guid, avatar.avatar_id);
            }
            self.characters.insert(avatar.avatar_id, avatar.clone());
        }
    }

    /// Fold an inventory notify into the captured item set.
    ///
    /// Additions arrive here; destructions arrive at
    /// [`remove_items`](Self::remove_items), so the captured inventory tracks
    /// the account for the whole session rather than only growing.
    pub fn process_items(&mut self, items: &[Item]) {
        for item in items {
            // Item 120292 is a quest prop named `"Adventurer's Experience"`,
            // which maps onto the same GOOD key as the real item 104002. Keeping
            // it would inflate the real stack now that counts are summed.
            if item.item_id == 120292 && item.has_material() {
                continue;
            }

            // Mora is exported from the player property map (see
            // `EXPORTED_CURRENCY_PROPERTIES`), which is authoritative for it;
            // keeping the item too would give the same key two sources.
            if item.item_id == 202 && item.has_material() {
                continue;
            }

            if item.has_material() || item.has_equip() || item.has_furniture() {
                self.items.insert((item.item_id, item.guid), item.clone());
            }
        }
    }

    /// Drop items the game says are gone, returning how many were actually held.
    ///
    /// The guids come from `auto_artifactarium`'s delete matcher, which reports
    /// *candidates*: the packet shape it keys on is shared with roughly two
    /// dozen other messages. This intersection is what makes acting on them
    /// safe, and it is why the return value matters — a caller should treat
    /// zero as "that was some other packet" rather than as a deletion of
    /// nothing, and must not stamp an inventory-changed timestamp for it.
    ///
    /// Guid 0 is never removed. Virtual items (Primogems, resin) all carry it,
    /// so they are keyed by item id alone; a delete list cannot legitimately
    /// contain it, and honouring one would wipe every currency at once.
    pub fn remove_items(&mut self, guids: &[u64]) -> usize {
        let doomed: HashSet<u64> = guids.iter().copied().filter(|guid| *guid != 0).collect();
        if doomed.is_empty() {
            return 0;
        }

        let before = self.items.len();
        self.items.retain(|(_, guid), _| !doomed.contains(guid));
        let removed = before - self.items.len();

        // Gear is unequipped before it can be destroyed, so this is normally
        // already empty of these guids -- but a stale mapping would attribute a
        // destroyed artifact's slot to whoever last held it.
        self.character_equip_guid_map
            .retain(|guid, _| !doomed.contains(guid));

        removed
    }

    pub fn export_achievements(&self) -> Result<Vec<u32>> {
        let mut ids = Vec::new();
        for ach in self.achievements.values() {
            if achievement_completed(ach) {
                ids.push(ach.id);
            }
        }
        Ok(ids)
    }

    /// `gi_achievement_times`: when each completed achievement was finished,
    /// for those the game sent a plausible time for.
    ///
    /// The same achievements as [`export_achievements`](Self::export_achievements)
    /// and never more, so the two keys cannot disagree. A time outside
    /// [`plausible_time`]'s window is left out rather than sent; pre-1.0
    /// accounts are known to carry finished achievements with no time at all.
    fn export_achievement_times(&self, now_secs: u64) -> BTreeMap<u32, u32> {
        let mut times = BTreeMap::new();
        let mut implausible: Vec<(u32, u32)> = Vec::new();
        for ach in self.achievements.values() {
            if !achievement_completed(ach) {
                continue;
            }
            let Some(finished) = ach.finish_timestamp else {
                continue;
            };
            if plausible_time(u64::from(finished), now_secs) {
                times.insert(ach.id, finished);
            } else {
                implausible.push((ach.id, finished));
            }
        }
        if !implausible.is_empty() {
            implausible.sort_unstable();
            tracing::warn!(
                count = implausible.len(),
                sample = ?&implausible[..implausible.len().min(3)],
                "achievement finish times outside 2020-09-15..now were left out"
            );
        }
        times
    }

    /// A captured player property, if it lies in the range a real one can.
    ///
    /// An out-of-range value is pushed onto `rejected` as `(id, value)`.
    fn plausible_property(&self, prop: &PlayerProp, rejected: &mut Vec<(u32, u64)>) -> Option<u32> {
        let value = *self.properties.get(&prop.id)?;
        match u32::try_from(value) {
            Ok(narrow) if prop.range.contains(&value) => Some(narrow),
            _ => {
                rejected.push((prop.id, value));
                None
            }
        }
    }

    /// The account UID, read off the captured item guids.
    ///
    /// The game mints item guids as `(uid << 32) + counter` (Grasscutter's
    /// `Player::getNextGuid`; auto-artifactarium's delete matcher only accepts
    /// guid lists of that shape, and deletes match on live servers), so the
    /// top half of an item guid is the UID. Virtual items carry guid 0 and are
    /// skipped. The UID is the top half nearly every item agrees on
    /// ([`UID_MAJORITY`]); a few strays (an item from some other source) don't
    /// spoil it, a real split claims nothing. Avatar guids don't vote: their
    /// field is unverified on 7.1, and a capture of 7.1 found no UID while
    /// they did vote. One INFO line shows the top halves either way.
    fn account_uid(&self) -> Option<u32> {
        let mut item_tops: BTreeMap<u64, usize> = BTreeMap::new();
        for (_, guid) in self.items.keys() {
            if *guid != 0 {
                *item_tops.entry(guid >> 32).or_default() += 1;
            }
        }
        let mut avatar_tops: BTreeMap<u64, usize> = BTreeMap::new();
        for avatar in self.characters.values() {
            *avatar_tops.entry(avatar.guid >> 32).or_default() += 1;
        }
        let top_counts = |tops: &BTreeMap<u64, usize>| {
            let mut list: Vec<_> = tops.iter().map(|(top, n)| (*top, *n)).collect();
            list.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
            list.truncate(5);
            list
        };
        tracing::info!(
            items = ?top_counts(&item_tops),
            avatars = ?top_counts(&avatar_tops),
            "guid top halves (account UID check)"
        );

        let total: usize = item_tops.values().sum();
        let (top, count) = item_tops
            .iter()
            .filter(|(top, _)| **top != 0)
            .max_by_key(|(_, n)| **n)
            .map(|(top, n)| (*top, *n))?;
        if (count as f64) < (total as f64) * UID_MAJORITY {
            tracing::debug!(
                top,
                count,
                total,
                "no top half is a clear majority; not reporting a UID"
            );
            return None;
        }
        u32::try_from(top).ok()
    }

    /// `gi_player` for the captured data, plus every property value that was
    /// left out of it for failing its range check, as `(id, value)`.
    fn checked_gi_player(&self) -> (Option<good::GiPlayer>, Vec<(u32, u64)>) {
        let mut rejected = Vec::new();
        let player = good::GiPlayer {
            uid: self.account_uid(),
            ar: self.plausible_property(&PROP_ADVENTURE_RANK, &mut rejected),
            ar_exp: self.plausible_property(&PROP_ADVENTURE_EXP, &mut rejected),
            wl: self.plausible_property(&PROP_WORLD_LEVEL, &mut rejected),
            wl_limit: self.plausible_property(&PROP_WORLD_LEVEL_LIMIT, &mut rejected),
            resin: self.plausible_property(&PROP_RESIN, &mut rejected),
            story_keys: self.plausible_property(&PROP_STORY_KEYS, &mut rejected),
            max_stamina: self.plausible_property(&PROP_MAX_STAMINA, &mut rejected),
            game_data: None,
        };
        // Nothing about the account is known: say nothing, rather than send a
        // key that only names the game data.
        if player == good::GiPlayer::default() {
            return (None, rejected);
        }
        let player = good::GiPlayer {
            game_data: self.game_data_sha.clone(),
            ..player
        };
        (Some(player), rejected)
    }

    /// What the captured data says about the account: `gi_player`.
    pub fn gi_player(&self) -> Option<good::GiPlayer> {
        self.checked_gi_player().0
    }

    /// Build the GOOD export and report what had to be left out of it.
    ///
    /// Callers with a UI should surface [`ExportReport::summary`]: a snapshot
    /// that silently omits entities the baked-in game data does not know about
    /// looks exactly like a snapshot of an account that never owned them. The
    /// degraded-field half of the report is logged here rather than returned to
    /// the UI — see [`ExportReport`] for why those must not raise an error.
    pub fn export_genshin_optimizer_with_report(
        &self,
        settings: &ExportSettings,
    ) -> Result<(String, ExportReport)> {
        let mut report = ExportReport::default();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let good = self.build_good(settings, &mut report, now_ms);

        if report.has_degradations() {
            tracing::debug!(
                "export kept defaults for some fields: {}",
                report.degraded_summary()
            );
        }

        let json = serde_json::to_string(&good)?;
        tracing::trace!("{json}");
        Ok((json, report))
    }

    /// The export, stamped `now_ms` (epoch milliseconds).
    fn build_good(
        &self,
        settings: &ExportSettings,
        report: &mut ExportReport,
        now_ms: u64,
    ) -> good::Good {
        let (gi_player, rejected) = self.checked_gi_player();
        if !rejected.is_empty() {
            tracing::warn!(
                ?rejected,
                "player properties outside their plausible range were left out of gi_player"
            );
        }
        tracing::info!(?gi_player, "account values for this export");

        let mut good = good::Good {
            format: "GOOD".to_string(),
            version: 3,
            source: "Irminsul".to_string(),
            characters: Vec::new(),
            artifacts: Vec::new(),
            weapons: Vec::new(),
            materials: HashMap::new(),
            // Omitted, not empty, when nothing was captured. `Some(vec![])`
            // asserts "this account has completed no achievements", which the
            // tracker then records as fact. Since every handshake now clears
            // captured data and achievements only arrive when the player opens
            // the achievement menu, an export triggered after a mid-session
            // reconnect (co-op, a server hop) would otherwise upload a zero
            // where the truth is simply "not seen this session". The field is
            // `skip_serializing_if = "Option::is_none"`, so `None` leaves it out
            // of the JSON entirely and the backend keeps what it already had.
            gi_achievements: match self.export_achievements() {
                Ok(ids) if !ids.is_empty() => Some(ids),
                Ok(_) => None,
                Err(e) => {
                    tracing::warn!("could not collect achievements for the export: {e}");
                    None
                }
            },
            timestamp: Some(now_ms),
            gi_player,
            // Omitted when empty, for the same reason as `gi_achievements`.
            gi_achievement_times: Some(self.export_achievement_times(now_ms / 1000))
                .filter(|times| !times.is_empty()),
            // Filled in with the characters below.
            gi_characters: None,
        };

        if settings.include_characters {
            let exported = self.exported_characters(settings, report);
            good.gi_characters = self.export_character_extras(&exported, now_ms / 1000);
            good.characters = exported
                .into_iter()
                .map(|(character, _)| character)
                .collect();
        }

        if settings.include_artifacts {
            let artifacts = self.export_genshin_optimizer_artifacts(settings, report);
            good.artifacts = if settings.fake_initialize_4th_line {
                fake_uninitialized_4th_line(artifacts)
            } else {
                artifacts
            };
        }

        if settings.include_weapons {
            good.weapons = self.export_genshin_optimizer_weapons(settings, report);
        }

        if settings.include_materials {
            good.materials = self.export_genshin_optimizer_materials(report);
        }

        good
    }

    #[cfg(test)]
    pub fn export_genshin_optimizer_characters(
        &self,
        settings: &ExportSettings,
        report: &mut ExportReport,
    ) -> Vec<good::Character> {
        self.exported_characters(settings, report)
            .into_iter()
            .map(|(character, _)| character)
            .collect()
    }

    /// The GOOD characters, each with the captured avatar it was built from.
    fn exported_characters(
        &self,
        settings: &ExportSettings,
        report: &mut ExportReport,
    ) -> Vec<(good::Character, &AvatarInfo)> {
        // TPS avatars are not normal characters and are excluded from export.
        let tps_avatar_ids = tps_avatar_ids(&self.game_data);
        // Avatars left out without a warning of their own (wrong type,
        // placeholder, below the export minimums) and Travelers whose element
        // could not be read, so one log line accounts for the whole roster.
        let mut left_out: Vec<String> = Vec::new();
        let describe = |avatar_id: u32| match self.game_data.get_character(avatar_id) {
            Ok(name) => format!("{avatar_id} {name}"),
            Err(_) => avatar_id.to_string(),
        };

        let exported: Vec<_> = self
            .characters
            .values()
            .filter_map(|character| {
                if character.avatar_type != AVATAR_TYPE_FORMAL {
                    left_out.push(format!(
                        "{} (avatar type {})",
                        describe(character.avatar_id),
                        character.avatar_type
                    ));
                    return None;
                }
                if tps_avatar_ids.contains(&character.avatar_id) {
                    left_out.push(format!("{} (placeholder)", describe(character.avatar_id)));
                    return None;
                }

                let Ok(name) = self.game_data.get_character(character.avatar_id) else {
                    tracing::warn!(
                        avatar_id = character.avatar_id,
                        "no game data for avatar; dropping it from the export"
                    );
                    report.record_dropped("unknown_character");
                    return None;
                };

                // Fabricating a level for a character whose level is unknown
                // would inject wrong data into permanent snapshot history, so
                // the character is still dropped — but no longer in silence.
                let Some(level_prop) = character.prop_map.get(&4001) else {
                    tracing::warn!(
                        avatar_id = character.avatar_id,
                        "avatar has no level (prop 4001); dropping it from the export"
                    );
                    report.record_dropped("character_missing_level");
                    return None;
                };
                let Some(level) = validated_avatar_prop(level_prop, CHARACTER_LEVEL_RANGE) else {
                    tracing::warn!(
                        avatar_id = character.avatar_id,
                        val = level_prop.val,
                        decoded = ?auto_artifactarium::prop_value_any(level_prop),
                        "avatar level out of range; dropping it from the export"
                    );
                    report.record_dropped("character_invalid_level");
                    return None;
                };

                let Some(ascension_prop) = character.prop_map.get(&1002) else {
                    tracing::warn!(
                        avatar_id = character.avatar_id,
                        "avatar has no ascension (prop 1002); dropping it from the export"
                    );
                    report.record_dropped("character_missing_ascension");
                    return None;
                };
                let Some(ascension) =
                    validated_avatar_prop(ascension_prop, CHARACTER_ASCENSION_RANGE)
                else {
                    tracing::warn!(
                        avatar_id = character.avatar_id,
                        val = ascension_prop.val,
                        decoded = ?auto_artifactarium::prop_value_any(ascension_prop),
                        "avatar ascension out of range; dropping it from the export"
                    );
                    report.record_dropped("character_invalid_ascension");
                    return None;
                };

                let constellation = character.talent_id_list.len() as u32;

                let mut auto = 1;
                let mut skill = 1;
                let mut burst = 1;
                let mut element = None;

                for (id, level) in &character.skill_level_map {
                    let Ok(ty) = self.game_data.get_skill_type(*id) else {
                        // Not fatal, and usually not even a gap: the wire
                        // `skill_level_map` is the depot's whole `skills` list
                        // plus `energySkill`, while `anime-game-data` only
                        // indexes depot slots 0 and 1 plus the energy skill. So
                        // slot 2 — the alternate sprint that only Kamisato
                        // Ayaka and Mona have — always misses. Degraded, never
                        // dropped: the talent simply keeps its default level,
                        // and a genuinely new character after a version bump is
                        // already caught by `unknown_character`.
                        tracing::debug!(skill_id = *id, "no game data for skill; ignoring it");
                        report.record_degraded("unknown_skill");
                        continue;
                    };
                    match ty {
                        SkillType::Auto => auto = *level,
                        SkillType::Skill => skill = *level,
                        SkillType::Burst => {
                            burst = *level;
                            element = self.game_data.get_skill_element(*id).ok().copied();
                        }
                    }
                }

                if level < settings.min_character_level
                    || ascension < settings.min_character_ascension
                    || constellation < settings.min_character_constellation
                {
                    left_out.push(format!(
                        "{} (below the export minimums: level {level}, A{ascension}, C{constellation})",
                        describe(character.avatar_id)
                    ));
                    return None;
                }

                // The Traveler is the only character that can change elements.
                // The GOOD format lets you optionally suffix the Traveler's
                // name with their element (e.g. `TravelerCryo`).
                let mut key = good::to_good_key(name);
                if key == good::TRAVELER_KEY {
                    match element {
                        Some(element) => key.push_str(element.as_ref()),
                        None => left_out.push(format!(
                            "{} exported as plain Traveler (no burst element)",
                            describe(character.avatar_id)
                        )),
                    }
                }

                Some((
                    good::Character {
                        key,
                        level,
                        constellation,
                        ascension,
                        talent: good::TalentLevel { auto, skill, burst },
                    },
                    character,
                ))
            })
            .collect();

        tracing::info!(
            captured = self.characters.len(),
            exported = exported.len(),
            left_out = ?left_out,
            "character export"
        );
        exported
    }

    /// `gi_characters` for the characters the export holds: friendship and
    /// when each was obtained.
    ///
    /// Both come from `AvatarInfo` fields (`fetter_info.exp_level`, field 12 ->
    /// 2, and `born_time`, field 23) whose numbers are carried over from
    /// Grasscutter's 3.x protos and are not verified on 7.1 traffic, so each
    /// value is plausibility-checked, and a field most characters fail is taken
    /// to be read from the wrong place and left out for everyone. One INFO line
    /// per export says how each field fared, so a real login shows whether the
    /// numbers hold.
    fn export_character_extras(
        &self,
        exported: &[(good::Character, &AvatarInfo)],
        now_secs: u64,
    ) -> Option<BTreeMap<String, good::GiCharacter>> {
        if exported.is_empty() {
            return None;
        }

        let mut friendship = FieldTally::default();
        let mut obtained_at = FieldTally::default();
        let mut extras: BTreeMap<String, good::GiCharacter> = BTreeMap::new();
        for (character, avatar) in exported {
            let level = avatar
                .fetter_info
                .as_ref()
                .map_or(0, |fetter| fetter.exp_level);
            let born = avatar.born_time;
            extras.insert(
                character.key.clone(),
                good::GiCharacter {
                    friendship: friendship.check(
                        &character.key,
                        level,
                        FRIENDSHIP_RANGE.contains(&level),
                    ),
                    obtained_at: obtained_at.check(
                        &character.key,
                        born,
                        plausible_time(u64::from(born), now_secs),
                    ),
                },
            );
        }

        let keep_friendship = friendship.trusted();
        let keep_obtained_at = obtained_at.trusted();
        for extra in extras.values_mut() {
            if !keep_friendship {
                extra.friendship = None;
            }
            if !keep_obtained_at {
                extra.obtained_at = None;
            }
        }
        extras.retain(|_, extra| *extra != good::GiCharacter::default());

        let sample = extras
            .iter()
            .next()
            .map(|(key, extra)| describe_character_extras(key, extra))
            .unwrap_or_else(|| "none".to_string());
        tracing::info!(
            "character extras: {}, {}; sample {sample}",
            friendship.describe("friendship"),
            obtained_at.describe("obtainedAt"),
        );

        (!extras.is_empty()).then_some(extras)
    }

    pub fn round(property: Property, value: f32) -> f32 {
        // The game rounds percentages to 0.1 and non percentages to whole numbers.
        if property.is_percentage() {
            (value * 10.).round() / 10.
        } else {
            value.round()
        }
    }

    /// GOOD key of the character holding `guid`, or `""` when nothing does.
    fn equipped_location(&self, guid: u64, report: &mut ExportReport) -> String {
        let Some(avatar_id) = self.character_equip_guid_map.get(&guid) else {
            return String::new();
        };
        let Ok(name) = self.game_data.get_character(*avatar_id) else {
            // The gear is equipped, but it will export as unequipped.
            tracing::debug!(
                avatar_id = *avatar_id,
                "no game data for the avatar holding this item; exporting it as unequipped"
            );
            report.record_degraded("unknown_equip_location");
            return String::new();
        };
        good::to_good_key(name)
    }

    pub fn export_genshin_optimizer_artifacts(
        &self,
        settings: &ExportSettings,
        report: &mut ExportReport,
    ) -> Vec<good::Artifact> {
        self.items
            .values()
            .filter_map(|item| {
                if !item.has_equip() {
                    return None;
                }
                let equip = item.equip();
                if !equip.has_reliquary() {
                    return None;
                }

                let location = self.equipped_location(item.guid, report);
                let Ok(artifact_data) = self.game_data.get_artifact(item.item_id) else {
                    tracing::warn!(
                        item_id = item.item_id,
                        "no game data for artifact; dropping it from the export"
                    );
                    report.record_dropped("unknown_artifact");
                    return None;
                };
                let artifact = equip.reliquary();

                let mut substats: IndexMap<Property, (f32, f32)> = IndexMap::new();
                // Counted here rather than from `append_prop_id_list.len()` so
                // that `total_rolls` can never contradict `substats`.
                let mut total_rolls = 0u32;
                for substat_id in artifact.append_prop_id_list.iter() {
                    let Ok(substat) = self.game_data.get_affix(*substat_id) else {
                        tracing::warn!(
                            affix_id = *substat_id,
                            item_id = item.item_id,
                            "no game data for artifact affix; the substat is omitted"
                        );
                        report.record_dropped("unknown_affix");
                        continue;
                    };
                    total_rolls += 1;
                    let entry = substats
                        .entry(substat.property)
                        .or_insert((0., substat.value as f32));
                    entry.0 += substat.value as f32;
                }
                let substats = substats
                    .into_iter()
                    .map(|(property, (value, initial_value))| good::Substat {
                        key: property.good_name().to_string(),
                        value: Self::round(property, value),
                        initial_value: Self::round(property, initial_value),
                    })
                    .collect();
                let unactivated_substats = artifact
                    .unactivated_prop_id_list
                    .iter()
                    .filter_map(|substat_id| {
                        let Ok(substat) = self.game_data.get_affix(*substat_id) else {
                            tracing::warn!(
                                affix_id = *substat_id,
                                item_id = item.item_id,
                                "no game data for unactivated affix; the substat is omitted"
                            );
                            report.record_dropped("unknown_affix");
                            return None;
                        };
                        Some(good::Substat {
                            key: substat.property.good_name().to_string(),
                            value: Self::round(substat.property, substat.value as f32),
                            initial_value: Self::round(substat.property, substat.value as f32),
                        })
                    })
                    .collect();

                let Some(level) = artifact_export_level(artifact.level) else {
                    tracing::warn!(
                        item_id = item.item_id,
                        guid = item.guid,
                        "artifact reports level 0; dropping it from the export"
                    );
                    report.record_dropped("invalid_artifact_level");
                    return None;
                };
                let rarity = artifact_data.rarity;
                let astral_mark = artifact.starred;
                let elixer_crafted = !artifact.elixer_choices.is_empty();
                let Ok(main_stat) = self.game_data.get_property(artifact.main_prop_id) else {
                    tracing::warn!(
                        main_prop_id = artifact.main_prop_id,
                        item_id = item.item_id,
                        "no game data for artifact main stat; dropping it from the export"
                    );
                    report.record_dropped("unknown_artifact_main_stat");
                    return None;
                };
                let main_stat_key = main_stat.good_name().to_string();

                if level < settings.min_artifact_level || rarity < settings.min_artifact_rarity {
                    return None;
                }

                Some(good::Artifact {
                    set_key: good::to_good_key(&artifact_data.set),
                    slot_key: artifact_data.slot.good_name().to_string(),
                    level,
                    rarity,
                    main_stat_key,
                    location,
                    lock: equip.is_locked,
                    substats,
                    total_rolls,
                    astral_mark,
                    elixer_crafted,
                    unactivated_substats,
                })
            })
            .collect()
    }

    pub fn export_genshin_optimizer_weapons(
        &self,
        settings: &ExportSettings,
        report: &mut ExportReport,
    ) -> Vec<good::Weapon> {
        self.items
            .values()
            .filter_map(|item| {
                if !item.has_equip() {
                    return None;
                }
                let equip = item.equip();
                if !equip.has_weapon() {
                    return None;
                }

                let location = self.equipped_location(item.guid, report);
                let Ok(weapon_data) = self.game_data.get_weapon(item.item_id) else {
                    tracing::warn!(
                        item_id = item.item_id,
                        "no game data for weapon; dropping it from the export"
                    );
                    report.record_dropped("unknown_weapon");
                    return None;
                };
                let weapon = equip.weapon();
                let refinement = weapon
                    .affix_map
                    .values()
                    .cloned()
                    .next()
                    .unwrap_or_default()
                    + 1;

                let level = weapon.level;
                let ascension = weapon.promote_level;

                if level < settings.min_weapon_level
                    || refinement < settings.min_weapon_refinement
                    || ascension < settings.min_weapon_ascension
                    || weapon_data.rarity < settings.min_weapon_rarity
                {
                    return None;
                }

                Some(good::Weapon {
                    key: good::to_good_key(&weapon_data.name),
                    level,
                    ascension,
                    refinement,
                    location,
                    lock: equip.is_locked,
                })
            })
            .collect()
    }

    pub fn export_genshin_optimizer_materials(
        &self,
        report: &mut ExportReport,
    ) -> HashMap<String, u32> {
        let mut totals: HashMap<String, MaterialTotal> = HashMap::new();

        for item in self.items.values() {
            if !item.has_material() {
                continue;
            }

            // A zero count carries no information: absent and 0 mean the same
            // thing in GOOD. Skipping them keeps the virtual, guid-0 entries
            // that stopped colliding when `items` was re-keyed by
            // `(item_id, guid)` — Character EXP (101), Adventure EXP (102),
            // Companionship EXP (105), Story Key (107) — from minting empty
            // rows (and permanent dictionary entries) on the tracker for
            // materials nobody holds. A real, non-zero Story Key count still
            // exports.
            let count = item.material().count;
            if count == 0 {
                continue;
            }

            let Ok(name) = self.game_data.get_material(item.item_id) else {
                tracing::warn!(
                    item_id = item.item_id,
                    "no game data for material; dropping it from the export"
                );
                report.record_dropped("unknown_material");
                continue;
            };

            match merge_material(&mut totals, good::to_good_key(name), item.item_id, count) {
                MaterialMerge::Merged => {}
                MaterialMerge::MergedColliding { first_item_id } => {
                    // Debug, not warn: this fires dozens of times per export
                    // (13 ids share "Domain Reliquary: Tier I" alone), it is not
                    // actionable without a curated id -> GOOD key table, and
                    // most collisions are between variants of the same item,
                    // where summing is what the user wants anyway. The count
                    // still reaches the export report below, so the inflation is
                    // reported once instead of drowning the log.
                    tracing::debug!(
                        item_id = item.item_id,
                        first_item_id,
                        name,
                        "two different item ids share this GOOD key; the exported count is their \
                         sum and over-reports whichever one is the real inventory item"
                    );
                    report.record_degraded("merged_material_ids");
                }
                MaterialMerge::NoKey => {
                    tracing::debug!(
                        item_id = item.item_id,
                        "material name has no GOOD key; dropping it from the export"
                    );
                    report.record_dropped("unnamed_material");
                }
            }
        }

        let mut materials: HashMap<String, u32> = totals
            .into_iter()
            .map(|(key, total)| (key, total.count))
            .collect();

        // Currencies are reported both as (guid 0) items and as player
        // properties. The property is the authoritative source, so this pass
        // runs last and overwrites rather than merges.
        for (prop_id, key) in EXPORTED_CURRENCY_PROPERTIES {
            let Some(value) = self.properties.get(&prop_id) else {
                continue;
            };
            let count = clamp_material_count(*value);
            if u64::from(count) != *value {
                tracing::warn!(
                    prop_id,
                    value = *value,
                    "currency does not fit a GOOD material count; saturating"
                );
                report.record_dropped("saturated_currency");
            }
            materials.insert(key.to_string(), count);
        }

        materials
    }
}

#[cfg(test)]
mod tests {
    use auto_artifactarium::r#gen::protos::Material;

    use super::*;

    fn material_item(item_id: u32, guid: u64, count: u32) -> Item {
        let mut item = Item::new();
        item.item_id = item_id;
        item.guid = guid;
        item.set_material(Material {
            count,
            ..Default::default()
        });
        item
    }

    fn avatar(avatar_id: u32, equip_guids: &[u64]) -> AvatarInfo {
        let mut avatar = AvatarInfo::new();
        avatar.avatar_id = avatar_id;
        avatar.avatar_type = 1;
        avatar.equip_guid_list = equip_guids.to_vec();
        avatar
    }

    fn player_data() -> PlayerData {
        // An empty database: every game data lookup misses, which is exactly the
        // post-version-bump case the export report exists for.
        PlayerData::new(AnimeGameData::new())
    }

    /// A hand-built game-data database: the inside of each map as a JSON
    /// fragment, every one left out empty.
    ///
    /// `AnimeGameData` has no builder, but it deserializes its whole database
    /// from JSON, which is enough to reproduce the real-world shapes the export
    /// gets wrong.
    #[derive(Default)]
    struct TestGameData {
        affix_map: &'static str,
        artifact_map: &'static str,
        character_map: &'static str,
        material_map: &'static str,
        property_map: &'static str,
        skill_element_map: &'static str,
        skill_type_map: &'static str,
        weapon_map: &'static str,
        /// `(female, male)`; `None` is the 7.1 dump, where both are `null`.
        tps_avatar_ids: Option<(u32, u32)>,
    }

    impl TestGameData {
        fn build(&self) -> AnimeGameData {
            let (tps_female, tps_male) = match self.tps_avatar_ids {
                Some((female, male)) => (female.to_string(), male.to_string()),
                None => ("null".to_string(), "null".to_string()),
            };
            let json = format!(
                r#"{{
                    "version": 4,
                    "git_hash": "test",
                    "affix_map": {{{}}},
                    "artifact_map": {{{}}},
                    "character_map": {{{}}},
                    "material_map": {{{}}},
                    "property_map": {{{}}},
                    "set_map": {{}},
                    "skill_element_map": {{{}}},
                    "skill_type_map": {{{}}},
                    "tps_avatar_id_female": {tps_female},
                    "tps_avatar_id_male": {tps_male},
                    "weapon_map": {{{}}}
                }}"#,
                self.affix_map,
                self.artifact_map,
                self.character_map,
                self.material_map,
                self.property_map,
                self.skill_element_map,
                self.skill_type_map,
                self.weapon_map,
            );
            AnimeGameData::new_from_reader(json.as_bytes()).unwrap()
        }
    }

    /// A `PlayerData` over a hand-built game-data database: a skill id the
    /// database does not index and two item ids that share one display name
    /// are the two shapes the export report used to get wrong.
    fn player_data_with(
        character_map: &'static str,
        material_map: &'static str,
        skill_type_map: &'static str,
    ) -> PlayerData {
        PlayerData::new(
            TestGameData {
                character_map,
                material_map,
                skill_type_map,
                ..Default::default()
            }
            .build(),
        )
    }

    /// Export settings that filter nothing out.
    fn settings() -> ExportSettings {
        ExportSettings {
            include_characters: true,
            include_artifacts: true,
            include_weapons: true,
            include_materials: true,
            fake_initialize_4th_line: false,
            min_character_level: 0,
            min_character_ascension: 0,
            min_character_constellation: 0,
            min_artifact_level: 0,
            min_artifact_rarity: 0,
            min_weapon_level: 0,
            min_weapon_refinement: 0,
            min_weapon_ascension: 0,
            min_weapon_rarity: 0,
        }
    }

    fn character(avatar_id: u32, skill_levels: &[(u32, u32)]) -> AvatarInfo {
        let mut avatar = avatar(avatar_id, &[]);
        for (prop_id, val) in [(4001u32, 90i64), (1002, 6)] {
            let mut prop = auto_artifactarium::r#gen::protos::PropValue::new();
            prop.val = val;
            avatar.prop_map.insert(prop_id, prop);
        }
        for (skill_id, level) in skill_levels {
            avatar.skill_level_map.insert(*skill_id, *level);
        }
        avatar
    }

    #[test]
    fn artifact_level_zero_is_rejected_rather_than_underflowing() {
        assert_eq!(artifact_export_level(0), None);
        assert_eq!(artifact_export_level(1), Some(0));
        assert_eq!(artifact_export_level(21), Some(20));
    }

    #[test]
    fn material_counts_saturate_instead_of_wrapping() {
        assert_eq!(clamp_material_count(0), 0);
        assert_eq!(clamp_material_count(1_234), 1_234);
        assert_eq!(clamp_material_count(u64::from(u32::MAX)), u32::MAX);
        // Mora caps at 9,999,999,999 in game, which does not fit in a u32.
        assert_eq!(clamp_material_count(9_999_999_999), u32::MAX);
    }

    /// A `PropValue` carrying its number in `val`, field 4.
    fn prop_val(val: i64) -> PropValue {
        let mut prop = PropValue::new();
        prop.val = val;
        prop
    }

    /// A `PropValue` carrying its number in the `ival` oneof, field 2 — the
    /// encoding that used to read as 0 and get the character dropped.
    fn prop_ival(val: i64) -> PropValue {
        let mut prop = PropValue::new();
        prop.value = Some(auto_artifactarium::r#gen::protos::prop_value::Value::Ival(
            val,
        ));
        prop
    }

    #[test]
    fn avatar_props_reject_negatives_and_out_of_range_values() {
        assert_eq!(
            validated_avatar_prop(&prop_val(90), CHARACTER_LEVEL_RANGE),
            Some(90)
        );
        assert_eq!(
            validated_avatar_prop(&prop_val(1), CHARACTER_LEVEL_RANGE),
            Some(1)
        );
        assert_eq!(
            validated_avatar_prop(&prop_val(0), CHARACTER_LEVEL_RANGE),
            None
        );
        // Above the game's cap but plausible: must be exported, not dropped.
        // Levels 95 and 100 are real, and pinning this check to the old cap of
        // 90 silently threw those characters away.
        assert_eq!(
            validated_avatar_prop(&prop_val(95), CHARACTER_LEVEL_RANGE),
            Some(95)
        );
        assert_eq!(
            validated_avatar_prop(&prop_val(100), CHARACTER_LEVEL_RANGE),
            Some(100)
        );
        assert_eq!(
            validated_avatar_prop(&prop_val(1_001), CHARACTER_LEVEL_RANGE),
            None
        );
        // `as u32` used to turn this into 4294967295, which passes any minimum.
        assert_eq!(
            validated_avatar_prop(&prop_val(-1), CHARACTER_LEVEL_RANGE),
            None
        );
        assert_eq!(
            validated_avatar_prop(&prop_val(0), CHARACTER_ASCENSION_RANGE),
            Some(0)
        );
        assert_eq!(
            validated_avatar_prop(&prop_val(6), CHARACTER_ASCENSION_RANGE),
            Some(6)
        );
        assert_eq!(
            validated_avatar_prop(&prop_val(7), CHARACTER_ASCENSION_RANGE),
            Some(7)
        );
    }

    #[test]
    fn avatar_props_are_read_from_the_ival_oneof_too() {
        // The reported bug: eight characters dropped as `character_invalid_level`
        // because their level arrived in field 2 rather than field 4, decoded as
        // 0, and fell outside 1..=90. Reading only `val` is what did it.
        assert_eq!(
            validated_avatar_prop(&prop_ival(80), CHARACTER_LEVEL_RANGE),
            Some(80)
        );
        assert_eq!(
            validated_avatar_prop(&prop_ival(6), CHARACTER_ASCENSION_RANGE),
            Some(6)
        );
        // Still range checked, whichever field carried it.
        assert_eq!(
            validated_avatar_prop(&prop_ival(0), CHARACTER_LEVEL_RANGE),
            None
        );
        assert_eq!(
            validated_avatar_prop(&prop_ival(-1), CHARACTER_LEVEL_RANGE),
            None
        );
    }

    #[test]
    fn stacks_of_the_same_item_are_summed_not_overwritten() {
        let mut totals = HashMap::new();
        let key = "ChilledMeat".to_string();
        assert_eq!(
            merge_material(&mut totals, key.clone(), 100094, 3),
            MaterialMerge::Merged
        );
        // The same item id under a second guid: a real total, not a collision.
        assert_eq!(
            merge_material(&mut totals, key.clone(), 100094, 4),
            MaterialMerge::Merged
        );
        assert_eq!(totals[&key].count, 7);
    }

    #[test]
    fn two_item_ids_sharing_a_good_key_are_reported_as_a_collision() {
        let mut totals = HashMap::new();
        let key = "ChilledMeat".to_string();
        assert_eq!(
            merge_material(&mut totals, key.clone(), 100094, 3),
            MaterialMerge::Merged
        );
        // 100705 is the identically named quest prop. Summing is deterministic
        // but over-counts the real stack, so the caller has to hear about it.
        assert_eq!(
            merge_material(&mut totals, key.clone(), 100705, 1),
            MaterialMerge::MergedColliding {
                first_item_id: 100094
            }
        );
        assert_eq!(totals[&key].count, 4);
    }

    #[test]
    fn materials_without_a_good_key_are_dropped() {
        let mut totals = HashMap::new();
        // The 16 items named "？？？" all transform to the empty key.
        let key = good::to_good_key("？？？");
        assert!(key.is_empty());
        assert_eq!(
            merge_material(&mut totals, key, 100001, 5),
            MaterialMerge::NoKey
        );
        assert!(totals.is_empty());
    }

    #[test]
    fn material_totals_saturate() {
        let mut totals = HashMap::new();
        let key = "Mora".to_string();
        merge_material(&mut totals, key.clone(), 202, u32::MAX);
        merge_material(&mut totals, key.clone(), 202, 10);
        assert_eq!(totals[&key].count, u32::MAX);
    }

    #[test]
    fn virtual_items_sharing_guid_zero_do_not_overwrite_each_other() {
        let mut data = player_data();
        data.process_items(&[
            material_item(106, 0, 160),   // Original Resin
            material_item(201, 0, 1_234), // Primogem
            material_item(203, 0, 5),     // Genesis Crystal
            material_item(204, 0, 2_400), // Realm Currency
        ]);

        assert_eq!(data.items.len(), 4);
        assert_eq!(data.items[&(106, 0)].material().count, 160);
        assert_eq!(data.items[&(204, 0)].material().count, 2_400);
    }

    #[test]
    fn mora_and_the_quest_adventurers_experience_are_still_skipped() {
        let mut data = player_data();
        data.process_items(&[material_item(202, 0, 1_000), material_item(120292, 0, 1)]);
        assert!(data.items.is_empty());
    }

    #[test]
    fn equipment_moved_between_characters_is_reattributed() {
        let mut data = player_data();
        data.process_characters(&[avatar(10000021, &[1, 2]), avatar(10000022, &[3])]);
        assert_eq!(data.character_equip_guid_map.get(&2), Some(&10000021));

        // Artifact 2 is moved to 10000022 and both avatars are re-sent.
        data.process_characters(&[avatar(10000021, &[1]), avatar(10000022, &[3, 2])]);
        assert_eq!(data.character_equip_guid_map.get(&1), Some(&10000021));
        assert_eq!(data.character_equip_guid_map.get(&2), Some(&10000022));

        // Unequipping is reflected too, as long as the holder is in the packet.
        data.process_characters(&[avatar(10000022, &[3])]);
        assert_eq!(data.character_equip_guid_map.get(&2), None);
        // ... and an avatar the packet never mentions keeps its equipment.
        assert_eq!(data.character_equip_guid_map.get(&1), Some(&10000021));
    }

    #[test]
    fn only_known_currency_properties_reach_the_export() {
        let mut data = player_data();
        data.process_properties(&HashMap::from([
            (10016, 9_999_999_999), // Mora, larger than u32::MAX
            (10020, 160),           // Original Resin
            (10013, 60),            // Adventure Rank: real, but not a material
            (813152114, 145353067), // garbage id from a false positive match
        ]));

        let mut report = ExportReport::default();
        let materials = data.export_genshin_optimizer_materials(&mut report);

        assert_eq!(materials.get("Mora"), Some(&u32::MAX));
        assert_eq!(materials.get("OriginalResin"), Some(&160));
        assert_eq!(materials.len(), 2);
        assert!(!materials.keys().any(|key| key.starts_with("Property")));
        assert_eq!(report.summary(), "saturated_currency: 1");
    }

    #[test]
    fn unknown_materials_are_counted_rather_than_vanishing() {
        let mut data = player_data();
        data.process_items(&[material_item(104003, 7, 12)]);

        let mut report = ExportReport::default();
        let materials = data.export_genshin_optimizer_materials(&mut report);

        assert!(materials.is_empty());
        assert_eq!(report.summary(), "unknown_material: 1");
    }

    #[test]
    fn export_report_summary_is_deterministic() {
        let mut report = ExportReport::default();
        assert!(report.is_empty());
        report.record_dropped("unknown_material");
        report.record_dropped("unknown_artifact");
        report.record_dropped("unknown_material");
        assert!(!report.is_empty());
        assert_eq!(report.summary(), "unknown_artifact: 1, unknown_material: 2");
    }

    #[test]
    fn degraded_fields_never_make_the_report_look_like_a_dropped_entity() {
        let mut report = ExportReport::default();
        report.record_degraded("unknown_skill");
        report.record_degraded("unknown_skill");
        report.record_degraded("unknown_equip_location");

        // `is_empty` and `summary` drive the UI's error toast, so a degraded
        // field must leave both untouched.
        assert!(report.is_empty());
        assert_eq!(report.summary(), "");
        assert!(report.has_degradations());
        assert_eq!(
            report.degraded_summary(),
            "unknown_equip_location: 1, unknown_skill: 2"
        );
    }

    #[test]
    fn an_unindexed_alternate_sprint_skill_does_not_report_a_dropped_entity() {
        // Kamisato Ayaka's depot is `skills: [10024, 10018, 10013, 0]` with
        // `energySkill: 10019`; `anime-game-data` only indexes slots 0 and 1
        // plus the energy skill, so 10013 is missing from `skill_type_map` for
        // every build. Recording that as a dropped entity put a permanent red
        // "Export incomplete" toast in front of every Ayaka and Mona owner.
        let mut data = player_data_with(
            r#""10000002": "Kamisato Ayaka""#,
            "",
            r#""10024": "Auto", "10018": "Skill", "10019": "Burst""#,
        );
        data.process_characters(&[character(
            10000002,
            &[(10024, 9), (10018, 10), (10013, 1), (10019, 8)],
        )]);

        let mut report = ExportReport::default();
        let characters = data.export_genshin_optimizer_characters(&settings(), &mut report);

        // The character is exported in full; only the sprint level is ignored.
        assert_eq!(characters.len(), 1);
        assert_eq!(characters[0].key, "KamisatoAyaka");
        assert_eq!(characters[0].talent.auto, 9);
        assert_eq!(characters[0].talent.skill, 10);
        assert_eq!(characters[0].talent.burst, 8);

        assert!(report.is_empty(), "would toast: {}", report.summary());
        assert_eq!(report.degraded_summary(), "unknown_skill: 1");
    }

    #[test]
    fn an_owned_character_beats_its_mirror_copy_in_either_order() {
        // 7.1 lists Varka, Vesna and the Traveler twice: the owned avatar
        // (type 1) and a mirror copy (type 3) under the same avatar id. The
        // mirror arriving last used to replace the owned one and drop the
        // character from the export.
        let mirror = |avatar_id| {
            let mut copy = character(avatar_id, &[]);
            copy.avatar_type = 3;
            copy.prop_map.get_mut(&4001).unwrap().val = 1;
            copy
        };
        for roster in [
            vec![character(10000128, &[]), mirror(10000128)],
            vec![mirror(10000128), character(10000128, &[])],
        ] {
            let mut data = player_data_with(r#""10000128": "Varka""#, "", "");
            data.process_characters(&roster);
            let mut report = ExportReport::default();
            let characters = data.export_genshin_optimizer_characters(&settings(), &mut report);
            assert_eq!(characters.len(), 1);
            assert_eq!(characters[0].key, "Varka");
            assert_eq!(
                characters[0].level, 90,
                "the owned avatar's level, not the copy's"
            );
        }

        // A mirror on its own is still not an owned character.
        let mut data = player_data_with(r#""10000128": "Varka""#, "", "");
        data.process_characters(&[mirror(10000128)]);
        let mut report = ExportReport::default();
        assert!(
            data.export_genshin_optimizer_characters(&settings(), &mut report)
                .is_empty()
        );
    }

    #[test]
    fn tps_placeholders_are_left_out_when_the_game_data_lacks_their_ids() {
        // The 7.1 dump: both const lookups fail, and both placeholders are in
        // the avatar table as "Traveler".
        let mut data = player_data_with(
            r#""10000046": "Hu Tao", "10000134": "Traveler", "10000135": "Traveler""#,
            "",
            "",
        );
        data.process_characters(&[
            character(10000046, &[]),
            character(10000134, &[]),
            character(10000135, &[]),
        ]);

        let mut report = ExportReport::default();
        let characters = data.export_genshin_optimizer_characters(&settings(), &mut report);

        let keys: Vec<&str> = characters.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, ["HuTao"]);
        assert!(report.is_empty(), "{}", report.summary());
    }

    #[test]
    fn tps_avatar_ids_come_from_the_game_data_when_it_has_them() {
        let with_ids = TestGameData {
            tps_avatar_ids: Some((10000999, 10000998)),
            ..Default::default()
        };
        assert_eq!(tps_avatar_ids(&with_ids.build()), [10000999, 10000998]);

        let without = TestGameData::default();
        assert_eq!(
            tps_avatar_ids(&without.build()),
            [TPS_AVATAR_ID_FEMALE, TPS_AVATAR_ID_MALE]
        );
        assert_eq!(tps_avatar_ids(&AnimeGameData::new()), [10000135, 10000134]);
    }

    #[test]
    fn colliding_item_ids_are_summed_but_reported_without_toasting() {
        // 101003 is the Crystal Chunk you mine; 339011 is an identically named
        // quest prop. Both are real ids in the baked game data.
        let mut data = player_data_with(
            "",
            r#""101003": "Crystal Chunk", "339011": "Crystal Chunk""#,
            "",
        );
        data.process_items(&[material_item(101003, 11, 500), material_item(339011, 12, 1)]);

        let mut report = ExportReport::default();
        let materials = data.export_genshin_optimizer_materials(&mut report);

        assert_eq!(materials.get("CrystalChunk"), Some(&501));
        // Nothing was dropped, so no error toast -- but the inflation is
        // visible instead of silent.
        assert!(report.is_empty(), "would toast: {}", report.summary());
        assert_eq!(report.degraded_summary(), "merged_material_ids: 1");
    }

    #[test]
    fn zero_count_virtual_items_do_not_reach_the_export() {
        // Re-keying `items` by `(item_id, guid)` stopped the guid-0 virtual
        // items colliding, which un-hid Character EXP (101), Adventure EXP
        // (102), Companionship EXP (105) and Story Key (107). All four are in
        // the tracker's material catalog, so an empty one would mint a
        // permanent dictionary row and a 0 line on the Materials page.
        let mut data = player_data_with("", r#""101": "Character EXP", "107": "Story Key""#, "");
        data.process_items(&[material_item(101, 0, 0), material_item(107, 0, 3)]);

        let mut report = ExportReport::default();
        let materials = data.export_genshin_optimizer_materials(&mut report);

        assert_eq!(materials.get("CharacterEXP"), None);
        // A real holding still exports.
        assert_eq!(materials.get("StoryKey"), Some(&3));
        assert!(report.is_empty());
        assert!(!report.has_degradations());
    }

    #[test]
    fn reset_clears_captured_state() {
        let mut data = player_data();
        data.process_items(&[material_item(104003, 7, 12)]);
        data.process_characters(&[avatar(10000021, &[7])]);
        data.process_properties(&HashMap::from([(10016, 5)]));

        data.reset();

        assert!(data.items.is_empty());
        assert!(data.characters.is_empty());
        assert!(data.properties.is_empty());
        assert!(data.achievements.is_empty());
        assert!(data.character_equip_guid_map.is_empty());
    }

    #[test]
    fn destroyed_items_stop_being_exported() {
        let mut data = player_data();
        data.process_items(&[
            material_item(104003, 7, 12),
            material_item(104003, 8, 3),
            material_item(104004, 9, 1),
        ]);

        assert_eq!(data.remove_items(&[8, 9]), 2);

        assert_eq!(data.items.len(), 1);
        assert!(data.items.contains_key(&(104003, 7)));
    }

    #[test]
    fn a_delete_list_the_inventory_does_not_hold_changes_nothing() {
        // The delete matcher reports candidates, and the shape it keys on is
        // shared with avatar-team packets whose guids are drawn from the same
        // counter. Reporting 0 is what tells the caller not to stamp an
        // inventory-changed timestamp.
        let mut data = player_data();
        data.process_items(&[material_item(104003, 7, 12)]);

        assert_eq!(data.remove_items(&[8, 9, 10]), 0);
        assert_eq!(data.items.len(), 1);
    }

    #[test]
    fn destroying_gear_clears_its_character_attribution() {
        let mut data = player_data();
        data.process_items(&[material_item(104003, 7, 1)]);
        data.process_characters(&[avatar(10000021, &[7])]);
        assert_eq!(data.character_equip_guid_map.get(&7), Some(&10000021));

        data.remove_items(&[7]);

        assert!(data.character_equip_guid_map.is_empty());
    }

    #[test]
    fn guid_zero_is_never_honoured_in_a_delete_list() {
        // Every virtual item (Primogems, resin) carries guid 0, so honouring it
        // would wipe the lot in one packet.
        let mut data = player_data();
        data.process_items(&[material_item(201, 0, 1600), material_item(106, 0, 80)]);

        assert_eq!(data.remove_items(&[0]), 0);
        assert_eq!(data.items.len(), 2);
    }

    // -- gi_player ---------------------------------------------------------------

    /// The property values of a real 7.1 login notify that `gi_player` and the
    /// currency export read, as captured on 2026-10-04 (currencies changed).
    fn login_properties() -> HashMap<u32, u64> {
        HashMap::from([
            (10010, 24_000),        // max stamina
            (10011, 22_320),        // current stamina: not reported
            (10013, 60),            // Adventure Rank
            (10014, 0),             // AR EXP
            (10015, 1_600),         // Primogems
            (10016, 12_345_678),    // Mora
            (10019, 8),             // World Level
            (10020, 124),           // Original Resin
            (10025, 0),             // Genesis Crystals
            (10027, 3),             // Story Keys
            (10039, 9),             // World Level limit
            (10040, 1_790_953_954), // WL adjust cooldown: not reported
            (10042, 2_400),         // Realm Currency
        ])
    }

    /// `(uid << 32) + counter`, the way the game mints guids.
    fn minted_guid(uid: u64, counter: u64) -> u64 {
        (uid << 32) | counter
    }

    #[test]
    fn gi_player_reads_the_login_property_snapshot() {
        let mut data = player_data().with_game_data_sha(Some("792978e5"));
        data.process_properties(&login_properties());
        data.process_items(&[material_item(104003, minted_guid(813_152_114, 7), 12)]);

        assert_eq!(
            data.gi_player(),
            Some(good::GiPlayer {
                uid: Some(813_152_114),
                ar: Some(60),
                ar_exp: Some(0),
                wl: Some(8),
                wl_limit: Some(9),
                resin: Some(124),
                story_keys: Some(3),
                max_stamina: Some(24_000),
                game_data: Some("792978e5".to_string()),
            })
        );
    }

    #[test]
    fn the_currency_export_is_unchanged_by_gi_player() {
        let mut data = player_data();
        data.process_properties(&login_properties());

        let mut report = ExportReport::default();
        let materials = data.export_genshin_optimizer_materials(&mut report);

        assert_eq!(
            materials,
            HashMap::from([
                ("Primogem".to_string(), 1_600),
                ("Mora".to_string(), 12_345_678),
                ("OriginalResin".to_string(), 124),
                ("GenesisCrystal".to_string(), 0),
                ("RealmCurrency".to_string(), 2_400),
            ])
        );
        assert!(report.is_empty());
    }

    #[test]
    fn implausible_player_values_are_left_out() {
        let mut data = player_data();
        data.process_properties(&HashMap::from([
            (10013, 61),            // AR above the tracker's 60
            (10019, 10),            // WL above 9
            (10039, 9),             // fine
            (10020, 2_001),         // resin above the refill cap
            (10027, 3),             // fine
            (10010, 0),             // no stamina bar is empty
            (10014, 1_790_953_954), // a timestamp where EXP should be
        ]));

        let (player, mut rejected) = data.checked_gi_player();
        assert_eq!(
            player,
            Some(good::GiPlayer {
                wl_limit: Some(9),
                story_keys: Some(3),
                ..Default::default()
            })
        );
        rejected.sort_unstable();
        assert_eq!(
            rejected,
            [
                (10010, 0),
                (10013, 61),
                (10014, 1_790_953_954),
                (10019, 10),
                (10020, 2_001),
            ]
        );
    }

    #[test]
    fn the_range_edges_are_plausible() {
        let mut data = player_data();
        data.process_properties(&HashMap::from([(10013, 1), (10019, 0), (10020, 2_000)]));
        let player = data.gi_player().expect("values were captured");
        assert_eq!(player.ar, Some(1));
        assert_eq!(player.wl, Some(0));
        assert_eq!(player.resin, Some(2_000));
    }

    #[test]
    fn nothing_known_about_the_account_means_no_gi_player() {
        // Not even the game data is reported on its own.
        let data = player_data().with_game_data_sha(Some("792978e5"));
        assert_eq!(data.gi_player(), None);

        // Guids too small to carry a UID, and no properties.
        let mut data = player_data();
        data.process_items(&[material_item(104003, 7, 12)]);
        data.process_characters(&[avatar(10000046, &[])]);
        assert_eq!(data.gi_player(), None);
    }

    #[test]
    fn the_uid_is_the_top_half_nearly_every_item_agrees_on() {
        let mut data = player_data();
        // Virtual items carry guid 0 and say nothing either way.
        data.process_items(&[material_item(201, 0, 1_600)]);
        assert_eq!(data.account_uid(), None);

        let items: Vec<_> = (1..=20)
            .map(|n| material_item(104_000 + n, minted_guid(800_000_001, u64::from(n)), 3))
            .collect();
        data.process_items(&items);
        assert_eq!(data.account_uid(), Some(800_000_001));

        // Avatar guids don't vote, even when they disagree.
        let mut hu_tao = avatar(10000046, &[]);
        hu_tao.guid = minted_guid(123_456_789, 2);
        data.process_characters(&[hu_tao]);
        assert_eq!(data.account_uid(), Some(800_000_001));

        // One stray item among 21 doesn't spoil it (95% agree).
        data.process_items(&[material_item(105_000, minted_guid(800_000_002, 1), 1)]);
        assert_eq!(data.account_uid(), Some(800_000_001));
    }

    #[test]
    fn guids_that_split_claim_no_uid() {
        let mut data = player_data();
        data.process_items(&[
            material_item(104003, minted_guid(800_000_001, 1), 3),
            material_item(104004, minted_guid(800_000_002, 2), 3),
        ]);
        assert_eq!(data.account_uid(), None);
        assert_eq!(data.gi_player(), None);
    }

    #[test]
    fn reset_forgets_the_account_but_not_the_game_data() {
        let mut data = player_data().with_game_data_sha(Some("792978e5"));
        data.process_properties(&login_properties());
        data.reset();
        assert_eq!(data.gi_player(), None);

        data.process_properties(&HashMap::from([(10013, 45)]));
        assert_eq!(
            data.gi_player().and_then(|player| player.game_data),
            Some("792978e5".to_string())
        );
    }

    // -- the GOOD part stays byte-identical ----------------------------------------

    const GOLDEN_UID: u64 = 800_123_456;
    const GOLDEN_TIMESTAMP_MS: u64 = 1_756_000_000_000;

    /// One of everything GOOD carries -- a character, an artifact and a weapon
    /// on them, one material, one achievement -- and, with `extras`, everything
    /// Irminsul adds beside GOOD. The two differ in nothing GOOD can see.
    fn golden_player_data(extras: bool) -> PlayerData {
        let game_data = TestGameData {
            affix_map: r#""501204": {"property": "CritRate", "value": 3.89},
                          "501234": {"property": "CritDamage", "value": 7.77}"#,
            artifact_map: r#""81524": {"set": "Crimson Witch of Flames", "slot": "Flower", "rarity": 5}"#,
            character_map: r#""10000046": "Hu Tao""#,
            material_map: r#""104003": "Hero's Wit""#,
            property_map: r#""10001": "Hp""#,
            skill_type_map: r#""10461": "Auto", "10462": "Skill", "10465": "Burst""#,
            weapon_map: r#""13501": {"name": "Staff of Homa", "rarity": 5}"#,
            ..Default::default()
        };
        let mut data = PlayerData::new(game_data.build())
            .with_game_data_sha(Some("792978e5503ecfba73dcb3562ed44a0d35a2abe2"));

        // Guids only carry a UID with the extras; GOOD never shows a guid.
        let guid = |counter: u64| {
            if extras {
                minted_guid(GOLDEN_UID, counter)
            } else {
                counter
            }
        };

        let mut weapon = Item::new();
        weapon.item_id = 13501;
        weapon.guid = guid(1);
        let mut equip = auto_artifactarium::r#gen::protos::Equip::new();
        equip.is_locked = true;
        let mut homa = auto_artifactarium::r#gen::protos::Weapon::new();
        homa.level = 90;
        homa.promote_level = 6;
        homa.affix_map.insert(113501, 0);
        equip.set_weapon(homa);
        weapon.set_equip(equip);

        let mut artifact = Item::new();
        artifact.item_id = 81524;
        artifact.guid = guid(2);
        let mut equip = auto_artifactarium::r#gen::protos::Equip::new();
        equip.is_locked = true;
        let mut reliquary = auto_artifactarium::r#gen::protos::Reliquary::new();
        reliquary.level = 21;
        reliquary.main_prop_id = 10001;
        reliquary.append_prop_id_list = vec![501204, 501234, 501204];
        equip.set_reliquary(reliquary);
        artifact.set_equip(equip);

        data.process_items(&[weapon, artifact, material_item(104003, guid(3), 12)]);

        let mut hu_tao = character(10000046, &[(10461, 10), (10462, 9), (10465, 8)]);
        hu_tao.guid = guid(4);
        hu_tao.equip_guid_list = vec![guid(1), guid(2)];
        if extras {
            hu_tao.fetter_info.mut_or_insert_default().exp_level = 10;
            hu_tao.born_time = 1_646_092_800; // 2022-03-01
        }
        data.process_characters(&[hu_tao]);

        data.process_achievements(&[Achievement {
            id: 80014,
            status: 3,
            finish_timestamp: extras.then_some(1_650_000_000),
        }]);

        if extras {
            // Everything but the currencies, which GOOD exports as materials.
            data.process_properties(&HashMap::from([
                (10010, 24_000),
                (10013, 60),
                (10014, 0),
                (10019, 8),
                (10027, 3),
                (10039, 9),
            ]));
        }
        data
    }

    fn golden_json(data: &PlayerData) -> String {
        let mut report = ExportReport::default();
        let good = data.build_good(&settings(), &mut report, GOLDEN_TIMESTAMP_MS);
        assert!(report.is_empty(), "{}", report.summary());
        serde_json::to_string(&good).unwrap()
    }

    /// The GOOD part of an export, byte for byte. A change here is a change to
    /// what Genshin Optimizer, the old backend and the tracker all read.
    const GOLDEN_GOOD: &str = concat!(
        r#"{"format":"GOOD","version":3,"source":"Irminsul","#,
        r#""characters":[{"key":"HuTao","level":90,"constellation":0,"ascension":6,"#,
        r#""talent":{"auto":10,"skill":9,"burst":8}}],"#,
        r#""artifacts":[{"setKey":"CrimsonWitchOfFlames","slotKey":"flower","level":20,"#,
        r#""rarity":5,"mainStatKey":"hp","location":"HuTao","lock":true,"#,
        r#""substats":[{"key":"critRate_","value":7.8,"initialValue":3.9},"#,
        r#"{"key":"critDMG_","value":7.8,"initialValue":7.8}],"#,
        r#""totalRolls":3,"astralMark":false,"elixerCrafted":false,"unactivatedSubstats":[]}],"#,
        r#""weapons":[{"key":"StaffOfHoma","level":90,"ascension":6,"refinement":1,"#,
        r#""location":"HuTao","lock":true}],"#,
        r#""materials":{"HerosWit":12},"gi_achievements":[80014],"timestamp":1756000000000}"#,
    );

    /// What the extras append after the last GOOD field.
    const GOLDEN_EXTRAS: &str = concat!(
        r#","gi_player":{"uid":800123456,"ar":60,"arExp":0,"wl":8,"wlLimit":9,"#,
        r#""storyKeys":3,"maxStamina":24000,"#,
        r#""gameData":"792978e5503ecfba73dcb3562ed44a0d35a2abe2"},"#,
        r#""gi_achievement_times":{"80014":1650000000},"#,
        r#""gi_characters":{"HuTao":{"friendship":10,"obtainedAt":1646092800}}}"#,
    );

    #[test]
    fn the_good_part_of_an_export_is_byte_identical_with_and_without_the_extras() {
        let without = golden_json(&golden_player_data(false));
        assert_eq!(without, GOLDEN_GOOD);

        let with = golden_json(&golden_player_data(true));
        let good_part = GOLDEN_GOOD.strip_suffix('}').unwrap();
        assert_eq!(with, format!("{good_part}{GOLDEN_EXTRAS}"));
    }

    #[test]
    fn dropping_the_extras_from_an_export_leaves_exactly_its_good_part() {
        // A full login, currencies included, so `materials` has several
        // entries: hash order is only stable within one map, so this compares
        // one export against itself with the extras taken off.
        let mut data = golden_player_data(true);
        data.process_properties(&login_properties());

        let mut report = ExportReport::default();
        let mut good = data.build_good(&settings(), &mut report, GOLDEN_TIMESTAMP_MS);
        assert!(good.gi_player.is_some());
        assert!(good.gi_achievement_times.is_some());
        assert!(good.gi_characters.is_some());
        let with = serde_json::to_string(&good).unwrap();

        good.gi_player = None;
        good.gi_achievement_times = None;
        good.gi_characters = None;
        let without = serde_json::to_string(&good).unwrap();

        let good_part = without.strip_suffix('}').unwrap();
        assert!(with.starts_with(good_part), "{with}\n{without}");
        assert!(with[good_part.len()..].starts_with(r#","gi_player":"#));
    }

    // -- gi_achievement_times ------------------------------------------------------

    /// 2026-10-05 00:00:00 UTC, standing in for "now".
    const NOW_SECS: u64 = 1_791_158_400;

    fn achievement(id: u32, status: u32, finish_timestamp: Option<u32>) -> Achievement {
        Achievement {
            id,
            status,
            finish_timestamp,
        }
    }

    #[test]
    fn finish_times_are_exported_for_completed_achievements() {
        let mut data = player_data();
        data.process_achievements(&[
            achievement(80001, 2, Some(1_650_000_000)), // finished
            achievement(80002, 3, Some(1_700_000_000)), // reward taken
            achievement(80003, 1, Some(1_700_000_000)), // unfinished: not done
            achievement(80004, 3, None),                // done, time not recorded
        ]);

        assert_eq!(
            data.export_achievement_times(NOW_SECS),
            BTreeMap::from([(80001, 1_650_000_000), (80002, 1_700_000_000)])
        );
    }

    #[test]
    fn implausible_finish_times_are_left_out() {
        let tomorrow = (NOW_SECS + CLOCK_SLACK_SECS) as u32;
        let mut data = player_data();
        data.process_achievements(&[
            achievement(80001, 3, Some(1_600_127_999)), // before 2020-09-15
            achievement(80002, 3, Some(1_600_128_000)), // 2020-09-15: the edge
            achievement(80003, 3, Some(tomorrow)),      // a day ahead: the edge
            achievement(80004, 3, Some(tomorrow + 1)),  // further ahead
            achievement(80005, 3, Some(5)),             // a counter, not a time
        ]);

        assert_eq!(
            data.export_achievement_times(NOW_SECS),
            BTreeMap::from([(80002, 1_600_128_000), (80003, tomorrow)])
        );
    }

    #[test]
    fn finish_times_never_name_an_achievement_the_list_leaves_out() {
        let mut data = player_data();
        data.process_achievements(&[
            achievement(80001, 3, Some(1_650_000_000)),
            achievement(80002, 1, Some(1_650_000_000)),
            achievement(80003, 0, Some(1_650_000_000)),
            achievement(80004, 2, None),
        ]);

        let listed: HashSet<u32> = data.export_achievements().unwrap().into_iter().collect();
        let timed = data.export_achievement_times(NOW_SECS);
        assert!(timed.keys().all(|id| listed.contains(id)), "{timed:?}");
        assert_eq!(listed, HashSet::from([80001, 80004]));
    }

    #[test]
    fn no_finish_times_means_no_key() {
        let mut data = player_data();
        data.process_achievements(&[achievement(80001, 3, None)]);

        let mut report = ExportReport::default();
        let good = data.build_good(&settings(), &mut report, NOW_SECS * 1000);
        assert_eq!(good.gi_achievements, Some(vec![80001]));
        assert_eq!(good.gi_achievement_times, None);
    }

    // -- gi_characters ---------------------------------------------------------------

    /// A level 90 character with a friendship level and an obtained time as
    /// the 3.x field numbers carry them; 0 leaves a field unset.
    fn befriended(avatar_id: u32, friendship: u32, born_time: u32) -> AvatarInfo {
        let mut avatar = character(avatar_id, &[]);
        if friendship != 0 {
            avatar.fetter_info.mut_or_insert_default().exp_level = friendship;
        }
        avatar.born_time = born_time;
        avatar
    }

    fn roster_data() -> PlayerData {
        player_data_with(
            r#""10000002": "Kamisato Ayaka", "10000003": "Jean", "10000006": "Lisa",
               "10000046": "Hu Tao""#,
            "",
            "",
        )
    }

    fn character_extras(data: &PlayerData) -> Option<BTreeMap<String, good::GiCharacter>> {
        let mut report = ExportReport::default();
        data.build_good(&settings(), &mut report, NOW_SECS * 1000)
            .gi_characters
    }

    fn extra(friendship: Option<u32>, obtained_at: Option<u32>) -> good::GiCharacter {
        good::GiCharacter {
            friendship,
            obtained_at,
        }
    }

    #[test]
    fn friendship_and_obtained_dates_are_exported_by_good_key() {
        let mut data = roster_data();
        data.process_characters(&[
            befriended(10000046, 10, 1_646_092_800),
            befriended(10000003, 7, 1_601_510_400),
        ]);

        assert_eq!(
            character_extras(&data),
            Some(BTreeMap::from([
                ("HuTao".to_string(), extra(Some(10), Some(1_646_092_800))),
                ("Jean".to_string(), extra(Some(7), Some(1_601_510_400))),
            ]))
        );
    }

    #[test]
    fn an_implausible_value_is_left_out_of_its_character_only() {
        let mut data = roster_data();
        data.process_characters(&[
            befriended(10000046, 10, 1_646_092_800),
            befriended(10000003, 11, 1_601_510_400), // friendship above 10
            befriended(10000006, 4, 1_500_000_000),  // obtained before launch
            befriended(10000002, 0, 0),              // nothing recorded
        ]);

        assert_eq!(
            character_extras(&data),
            Some(BTreeMap::from([
                ("HuTao".to_string(), extra(Some(10), Some(1_646_092_800))),
                ("Jean".to_string(), extra(None, Some(1_601_510_400))),
                ("Lisa".to_string(), extra(Some(4), None)),
            ]))
        );
    }

    #[test]
    fn a_field_most_characters_fail_is_left_out_for_everyone() {
        // The obtained times look like small counters: the field number is
        // wrong for this version, so even the one value in range is dropped.
        let mut data = roster_data();
        data.process_characters(&[
            befriended(10000046, 10, 1_646_092_800),
            befriended(10000003, 7, 3),
            befriended(10000006, 4, 12),
        ]);

        assert_eq!(
            character_extras(&data),
            Some(BTreeMap::from([
                ("HuTao".to_string(), extra(Some(10), None)),
                ("Jean".to_string(), extra(Some(7), None)),
                ("Lisa".to_string(), extra(Some(4), None)),
            ]))
        );
    }

    #[test]
    fn half_the_roster_failing_does_not_distrust_a_field() {
        // A new account: the Traveler has no friendship level, and neither
        // does one other character yet.
        let mut data = roster_data();
        data.process_characters(&[
            befriended(10000046, 2, 1_646_092_800),
            befriended(10000003, 0, 1_601_510_400),
        ]);

        let extras = character_extras(&data).expect("both fields are trusted");
        assert_eq!(extras["HuTao"], extra(Some(2), Some(1_646_092_800)));
        assert_eq!(extras["Jean"], extra(None, Some(1_601_510_400)));
    }

    #[test]
    fn no_trusted_values_means_no_key() {
        let mut data = roster_data();
        data.process_characters(&[befriended(10000046, 0, 0), befriended(10000003, 0, 0)]);
        assert_eq!(character_extras(&data), None);
    }

    #[test]
    fn character_extras_follow_the_characters_the_export_holds() {
        let mut data = PlayerData::new(
            TestGameData {
                character_map: r#""10000046": "Hu Tao", "10000005": "Traveler""#,
                skill_type_map: r#""10067": "Burst""#,
                skill_element_map: r#""10067": "Anemo""#,
                ..Default::default()
            }
            .build(),
        );

        let mut traveler = befriended(10000005, 0, 1_601_510_400);
        traveler.skill_level_map.insert(10067, 1);
        let mut low_level = befriended(10000046, 10, 1_646_092_800);
        low_level.prop_map.insert(4001, prop_val(20));
        data.process_characters(&[traveler, low_level]);

        let mut settings = settings();
        settings.min_character_level = 50;
        let mut report = ExportReport::default();
        let good = data.build_good(&settings, &mut report, NOW_SECS * 1000);

        // Hu Tao is below the level filter, so in neither list; the Traveler
        // carries the element suffix in both.
        let keys: Vec<&str> = good.characters.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, ["TravelerAnemo"]);
        assert_eq!(
            good.gi_characters,
            Some(BTreeMap::from([(
                "TravelerAnemo".to_string(),
                extra(None, Some(1_601_510_400))
            )]))
        );

        // Characters left out of the export altogether take their extras along.
        settings.include_characters = false;
        let good = data.build_good(&settings, &mut report, NOW_SECS * 1000);
        assert_eq!(good.gi_characters, None);
    }

    #[test]
    fn the_extras_log_line_says_how_each_field_fared() {
        let mut friendship = FieldTally::default();
        friendship.check("HuTao", 10, true);
        friendship.check("TravelerAnemo", 0, false);
        friendship.check("Jean", 7, true);
        assert_eq!(
            friendship.describe("friendship"),
            "friendship 2/3 plausible (implausible: TravelerAnemo 0)"
        );

        let mut obtained = FieldTally::default();
        for (key, raw) in [("A", 1), ("B", 2), ("C", 3), ("D", 4)] {
            obtained.check(key, raw, false);
        }
        assert_eq!(
            obtained.describe("obtainedAt"),
            "obtainedAt 0/4 plausible (implausible: A 1, B 2, C 3, ...), so omitted"
        );

        assert_eq!(
            describe_character_extras("HuTao", &extra(Some(10), Some(1_646_092_800))),
            "HuTao friendship 10 obtained 2022-03-01"
        );
    }
}
