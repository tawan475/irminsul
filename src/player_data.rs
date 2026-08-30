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
        }
    }

    /// Forget everything captured about the account, keeping the game data.
    ///
    /// Captured state is otherwise insert-only for the lifetime of the process,
    /// which this tool requires to be long: it has to be running before the game
    /// starts. Artifacts fed as fodder and decomposed gear therefore linger in
    /// every later export. Reached from the UI's "Clear data" control via
    /// `Message::ClearData`, and from the handshake-latched reset that stops a
    /// second account's inventory being merged into the first one's.
    pub fn reset(&mut self) {
        self.achievements.clear();
        self.characters.clear();
        self.items.clear();
        self.properties.clear();
        self.character_equip_guid_map.clear();
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
            for guid in &avatar.equip_guid_list {
                self.character_equip_guid_map
                    .insert(*guid, avatar.avatar_id);
            }
            self.characters.insert(avatar.avatar_id, avatar.clone());
        }
    }

    /// Fold an inventory notify into the captured item set.
    ///
    /// **Known gap — the inventory is insert-only within a game session.** The
    /// game announces destroyed items in a delete notify (a repeated guid
    /// list); neither `auto_artifactarium` nor this type understands one yet, so
    /// there is no `remove_items`. Artifacts fed as fodder, decomposed gear and
    /// consumed materials therefore stay in every later export of that session,
    /// get content hashed, and are minted as permanent rows in the tracker's
    /// history. The two escapes are [`reset`](Self::reset): the UI's "Clear
    /// data" button, and the handshake latch that fires on a new game session.
    /// Until the delete notify is wired up, a snapshot taken after in-session
    /// fodder consumption over-reports the inventory, and restarting irminsul
    /// (or clearing captured data) before exporting is the workaround.
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

    pub fn export_achievements(&self) -> Result<Vec<u32>> {
        let mut ids = Vec::new();
        for ach in self.achievements.values() {
            if ach.status == 2 || ach.status == 3 {
                ids.push(ach.id);
            }
        }
        Ok(ids)
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
            timestamp: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
            ),
        };

        if settings.include_characters {
            good.characters = self.export_genshin_optimizer_characters(settings, &mut report);
        }

        if settings.include_artifacts {
            let artifacts = self.export_genshin_optimizer_artifacts(settings, &mut report);
            good.artifacts = if settings.fake_initialize_4th_line {
                fake_uninitialized_4th_line(artifacts)
            } else {
                artifacts
            };
        }

        if settings.include_weapons {
            good.weapons = self.export_genshin_optimizer_weapons(settings, &mut report);
        }

        if settings.include_materials {
            good.materials = self.export_genshin_optimizer_materials(&mut report);
        }

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

    pub fn export_genshin_optimizer_characters(
        &self,
        settings: &ExportSettings,
        report: &mut ExportReport,
    ) -> Vec<good::Character> {
        // TPS avatars are not normal characters and are excluded from export.
        let tps_avatar_ids: Vec<u32> = [
            self.game_data.get_tps_avatar_id_female(),
            self.game_data.get_tps_avatar_id_male(),
        ]
        .into_iter()
        .filter_map(Result::ok)
        .collect();

        self.characters
            .values()
            .filter_map(|character| {
                if character.avatar_type != 1 || tps_avatar_ids.contains(&character.avatar_id) {
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
                    return None;
                }

                // The Traveler is the only character that can change elements.
                // The GOOD format lets you optionally suffix the Traveler's
                // name with their element (e.g. `TravelerCryo`).
                let mut key = good::to_good_key(name);
                if key == good::TRAVELER_KEY
                    && let Some(element) = element
                {
                    key.push_str(element.as_ref());
                }

                Some(good::Character {
                    key,
                    level,
                    constellation,
                    ascension,
                    talent: good::TalentLevel { auto, skill, burst },
                })
            })
            .collect()
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

    /// A `PlayerData` over a hand-built game-data database.
    ///
    /// `AnimeGameData` has no builder, but it deserializes its whole database
    /// from JSON, which is enough to reproduce the two real-world shapes the
    /// export report gets wrong: a skill id the database does not index, and
    /// two item ids that share one display name.
    fn player_data_with(
        character_map: &str,
        material_map: &str,
        skill_type_map: &str,
    ) -> PlayerData {
        let json = format!(
            r#"{{
                "version": 4,
                "git_hash": "test",
                "affix_map": {{}},
                "artifact_map": {{}},
                "character_map": {{{character_map}}},
                "material_map": {{{material_map}}},
                "property_map": {{}},
                "set_map": {{}},
                "skill_element_map": {{}},
                "skill_type_map": {{{skill_type_map}}},
                "tps_avatar_id_female": null,
                "tps_avatar_id_male": null,
                "weapon_map": {{}}
            }}"#
        );
        PlayerData::new(AnimeGameData::new_from_reader(json.as_bytes()).unwrap())
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
}
