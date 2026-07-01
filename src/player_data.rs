use std::collections::HashMap;

use anime_game_data::{AnimeGameData, Property, SkillType};
use anyhow::Result;
pub use auto_artifactarium::Achievement;
pub use auto_artifactarium::r#gen::protos::{AvatarInfo, Item};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::good::{self, fake_uninitialized_4th_line};

fn map_property_id_to_name(id: u32) -> String {
    match id {
        1001 => "Exp".to_string(),
        1002 => "BreakLevel".to_string(),
        1003 => "SatiationVal".to_string(),
        1004 => "SatiationPenaltyTime".to_string(),
        4001 => "Level".to_string(),
        10001 => "LastChangeAvatarTime".to_string(),
        10002 => "MaxSpringVolume".to_string(),
        10003 => "CurSpringVolume".to_string(),
        10004 => "IsSpringAutoUse".to_string(),
        10005 => "SpringAutoUsePercent".to_string(),
        10006 => "IsFlyable".to_string(),
        10007 => "IsWeatherLocked".to_string(),
        10008 => "IsGameTimeLocked".to_string(),
        10009 => "IsTransferable".to_string(),
        10010 => "MaxStamina".to_string(),
        10011 => "CurPersistStamina".to_string(),
        10012 => "CurTemporaryStamina".to_string(),
        10013 => "AdventureRank".to_string(),
        10014 => "AdventureExp".to_string(),
        10015 => "Primogem".to_string(),
        10016 => "Mora".to_string(),
        10017 => "MpSettingType".to_string(),
        10018 => "IsMpModeAvailable".to_string(),
        10019 => "WorldLevel".to_string(),
        10020 => "OriginalResin".to_string(),
        10022 => "WaitSubHcoin".to_string(),
        10023 => "WaitSubScoin".to_string(),
        10024 => "IsOnlyMpWithPsPlayer".to_string(),
        10025 => "GenesisCrystal".to_string(),
        10026 => "WaitSubMcoin".to_string(),
        10027 => "StoryKeys".to_string(),
        10028 => "IsHasFirstShare".to_string(),
        10029 => "ForgePoint".to_string(),
        10035 => "CurClimateMeter".to_string(),
        10036 => "CurClimateType".to_string(),
        10037 => "CurClimateAreaId".to_string(),
        10038 => "CurClimateAreaClimateType".to_string(),
        10039 => "WorldLevelLimit".to_string(),
        10040 => "WorldLevelAdjustCd".to_string(),
        10041 => "LegendaryDailyTaskNum".to_string(),
        10042 => "RealmCurrency".to_string(),
        10043 => "WaitSubHomeCoin".to_string(),
        10044 => "IsAutoUnlockSpecificEquip".to_string(),
        10045 => "GcgCoin".to_string(),
        10046 => "WaitSubGcgCoin".to_string(),
        10047 => "OnlineTime".to_string(),
        10048 => "CanDive".to_string(),
        10049 => "DiveMaxStamina".to_string(),
        10050 => "DiveCurStamina".to_string(),
        _ => format!("Property_{}", id),
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
    items: HashMap<u64, Item>,
    properties: HashMap<u32, u32>,

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

    pub fn process_achievements(&mut self, achievements: &[Achievement]) {
        for achievement in achievements {
            self.achievements
                .insert(achievement.id, achievement.clone());
        }
    }

    pub fn process_properties(&mut self, new_props: &HashMap<u32, u32>) {
        for (k, v) in new_props {
            self.properties.insert(*k, *v);
        }
    }

    pub fn process_characters(&mut self, avatars: &[AvatarInfo]) {
        for avatar in avatars {
            for guid in &avatar.equip_guid_list {
                self.character_equip_guid_map
                    .insert(*guid, avatar.avatar_id);
            }
            self.characters.insert(avatar.avatar_id, avatar.clone());
        }
    }

    pub fn process_items(&mut self, items: &[Item]) {
        for item in items {
            // Virtual items like Mora have guid = 0, so they would collide if we inserted them into `self.items`.
            if item.item_id == 202 && item.has_material() {
                continue;
            }

            if item.item_id == 120292 && item.has_material() {
                continue;
            }

            if item.has_material() {
                self.items.insert(item.guid, item.clone());
            } else if item.has_equip() {
                self.items.insert(item.guid, item.clone());
            } else if item.has_furniture() {
                self.items.insert(item.guid, item.clone());
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

    pub fn export_genshin_optimizer(&self, settings: &ExportSettings) -> Result<String> {
        let mut good = good::Good {
            format: "GOOD".to_string(),
            version: 3,
            source: "Irminsul".to_string(),
            characters: Vec::new(),
            artifacts: Vec::new(),
            weapons: Vec::new(),
            materials: HashMap::new(),
            gi_achievements: Some(self.export_achievements().unwrap_or_default()),
            timestamp: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
            ),
        };

        if settings.include_characters {
            good.characters = self.export_genshin_optimizer_characters(settings);
        }

        if settings.include_artifacts {
            good.artifacts = if settings.fake_initialize_4th_line {
                let artifacts = self.export_genshin_optimizer_artifacts(settings);
                fake_uninitialized_4th_line(artifacts)
            } else {
                self.export_genshin_optimizer_artifacts(settings)
            };
        }

        if settings.include_weapons {
            good.weapons = self.export_genshin_optimizer_weapons(settings);
        }

        if settings.include_materials {
            good.materials = self.export_genshin_optimizer_materials();
        }

        let json = serde_json::to_string(&good)?;
        tracing::trace!("{json}");
        Ok(json)
    }

    pub fn export_genshin_optimizer_characters(
        &self,
        settings: &ExportSettings,
    ) -> Vec<good::Character> {
        self.characters
            .values()
            .filter_map(|character| {
                if character.avatar_type != 1 {
                    return None;
                }

                let name = self.game_data.get_character(character.avatar_id).ok()?;
                let level = character.prop_map.get(&4001).map(|prop| prop.val as u32)?;
                let ascension = character.prop_map.get(&1002).map(|prop| prop.val as u32)?;
                let constellation = character.talent_id_list.len() as u32;

                let mut auto = 1;
                let mut skill = 1;
                let mut burst = 1;

                for (id, level) in &character.skill_level_map {
                    let Some(ty) = self.game_data.get_skill_type(*id).ok() else {
                        continue;
                    };
                    match ty {
                        SkillType::Auto => auto = *level,
                        SkillType::Skill => skill = *level,
                        SkillType::Burst => burst = *level,
                    }
                }

                if level < settings.min_character_level
                    || ascension < settings.min_character_ascension
                    || constellation < settings.min_character_constellation
                {
                    return None;
                }

                Some(good::Character {
                    key: good::to_good_key(name),
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

    pub fn export_genshin_optimizer_artifacts(
        &self,
        settings: &ExportSettings,
    ) -> Vec<good::Artifact> {
        self.items
            .values()
            .filter_map(|item| {
                if !item.has_equip() {
                    return None;
                }
                let equip = item.equip();
                let location = self
                    .character_equip_guid_map
                    .get(&item.guid)
                    .and_then(|id| {
                        self.game_data
                            .get_character(*id)
                            .ok()
                            .map(|location| good::to_good_key(location).to_string())
                    })
                    .unwrap_or_default();

                if !equip.has_reliquary() {
                    return None;
                }
                let artifact_data = self.game_data.get_artifact(item.item_id).ok()?;
                let artifact = equip.reliquary();
                let mut substats: IndexMap<Property, (f32, f32)> = IndexMap::new();
                for substat_id in artifact.append_prop_id_list.iter() {
                    let Some(substat) = self.game_data.get_affix(*substat_id).ok() else {
                        continue;
                    };
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
                        let substat = self.game_data.get_affix(*substat_id).ok()?;
                        Some(good::Substat {
                            key: substat.property.good_name().to_string(),
                            value: Self::round(substat.property, substat.value as f32),
                            initial_value: Self::round(substat.property, substat.value as f32),
                        })
                    })
                    .collect();
                let total_rolls = artifact.append_prop_id_list.len() as u32;

                let level = artifact.level - 1;
                let rarity = artifact_data.rarity;
                let astral_mark = artifact.starred;
                let elixer_crafted = !artifact.elixer_choices.is_empty();
                let main_stat_key = self
                    .game_data
                    .get_property(artifact.main_prop_id)
                    .ok()?
                    .good_name()
                    .to_string();

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

    pub fn export_genshin_optimizer_weapons(&self, settings: &ExportSettings) -> Vec<good::Weapon> {
        self.items
            .values()
            .filter_map(|item| {
                if !item.has_equip() {
                    return None;
                }
                let equip = item.equip();
                let location = self
                    .character_equip_guid_map
                    .get(&item.guid)
                    .and_then(|id| {
                        self.game_data
                            .get_character(*id)
                            .ok()
                            .map(|location| good::to_good_key(location).to_string())
                    })
                    .unwrap_or_default();
                if !equip.has_weapon() {
                    return None;
                }
                let weapon_data = self.game_data.get_weapon(item.item_id).ok()?;
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

    pub fn export_genshin_optimizer_materials(&self) -> HashMap<String, u32> {
        let mut materials: HashMap<String, u32> = self
            .items
            .values()
            .filter_map(|item| {
                if !item.has_material() {
                    return None;
                }
                let material = item.material();

                let name = self.game_data.get_material(item.item_id).ok()?;

                Some((good::to_good_key(name), material.count))
            })
            .collect();

        // Export explicitly tracked properties as materials
        for (prop_id, value) in &self.properties {
            materials.insert(map_property_id_to_name(*prop_id), *value);
        }

        materials
    }
}
