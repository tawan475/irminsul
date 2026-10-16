//! A character's live updates, told apart by the account data in them.
//!
//! Levelling a talent, a character or an ascension, unlocking a constellation,
//! moving gear and pulling a new character each send a small message the
//! export never read: the roster arrives in full only at login, so the
//! materials went down live while the character stayed put until the next
//! login. Their shapes are shared with hundreds of other messages and their
//! command ids change every patch, so each is recognised by what it says about
//! a character this account holds (7.1 names and ids for reference):
//!
//! | message (7.1 id) | recognised by |
//! |---|---|
//! | `AvatarSkillChangeNotify` (20762), `AvatarSkillUpgradeRsp` (2562) | a held avatar's guid, one of its skill ids, its held level of that skill and that level + 1 |
//! | `AvatarPropNotify` (23634) | a held avatar's guid beside one `map<uint32, int64>` of avatar property ids holding a level (4001) or an ascension (1002) no lower than held |
//! | `AvatarUnlockTalentNotify` (8243) | a held avatar's guid, its skill depot id and the next constellation's talent id |
//! | `AvatarEquipChangeNotify` (24582) | a held avatar's guid, the guid of a held weapon or artifact and that item's id |
//! | `AvatarAddNotify` (20572) | one nested owned `AvatarInfo` whose guid is the account's and whose character is not held |
//!
//! Each applies only when it changes something, so the game's repeats (the
//! notify and the reply of one upgrade, the weapon re-sent on every scene
//! change) are no-ops.

use anime_game_data::ArtifactSlot;
use auto_artifactarium::{FlatMessage, parse_avatar_info};

use super::{
    AVATAR_TYPE_FORMAL, CHARACTER_ASCENSION_RANGE, CHARACTER_LEVEL_RANGE, Item, PlayerData,
    PropValue, validated_avatar_prop,
};

/// Avatar property ids: EXP, ascension, two satiation counters, level.
const AVATAR_PROP_IDS: [u64; 5] = [1001, 1002, 1003, 1004, 4001];
const PROP_LEVEL: u32 = 4001;
const PROP_ASCENSION: u32 = 1002;
const PROP_EXP: u32 = 1001;

/// The game's talent level cap, before constellation boosts.
const MAX_TALENT_LEVEL: u32 = 15;

/// Constellations per character.
const MAX_CONSTELLATION: usize = 6;

/// What a character's live update changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AvatarChange {
    Talent {
        avatar_id: u32,
        skill_id: u32,
        level: u32,
    },
    Props {
        avatar_id: u32,
        level: Option<u32>,
        ascension: Option<u32>,
    },
    Constellation {
        avatar_id: u32,
        talent_id: u32,
    },
    Equip {
        avatar_id: u32,
        guid: u64,
    },
    Added {
        avatar_id: u32,
    },
}

impl AvatarChange {
    /// Whether it moved gear (an item's location) rather than changing a
    /// character.
    pub fn is_equip(&self) -> bool {
        matches!(self, Self::Equip { .. })
    }
}

/// Where a piece of gear goes on a character.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EquipSlot {
    Weapon,
    Artifact(ArtifactSlot),
}

impl PlayerData {
    /// Apply a message if it is one of a held character's live updates (see
    /// the module docs), returning what changed; `None` means some other
    /// message, or nothing new.
    pub fn apply_avatar_change(&mut self, flat: &FlatMessage) -> Option<AvatarChange> {
        if let Some(change) = self.added_avatar(flat) {
            return Some(change);
        }

        // Exactly one varint names a held character.
        let mut named = flat.varints.iter().filter_map(|(field, value)| {
            self.formal_avatar_by_guid(*value)
                .map(|avatar_id| (*field, avatar_id))
        });
        let (guid_field, avatar_id) = named.next()?;
        if named.next().is_some() {
            return None;
        }
        let others: Vec<u64> = flat
            .varints
            .iter()
            .filter(|(field, _)| *field != guid_field)
            .map(|(_, value)| *value)
            .collect();

        if flat.maps.len() == 1 && flat.nested.is_empty() && others.is_empty() {
            return self.props_change(avatar_id, &flat.maps[0].1);
        }
        if flat.maps.is_empty() && flat.nested.is_empty() {
            if let Some(change) = self.talent_change(avatar_id, &others) {
                return Some(change);
            }
            if let Some(change) = self.constellation_change(avatar_id, &others) {
                return Some(change);
            }
        }
        // A nested `SceneWeaponInfo` of two varints reads as a map entry, so
        // the gear is told apart by its guid and item id alone.
        self.equip_change(avatar_id, &others)
    }

    /// The avatar id of the owned character with this guid.
    fn formal_avatar_by_guid(&self, guid: u64) -> Option<u32> {
        if guid < 1 << 32 {
            return None;
        }
        self.characters
            .values()
            .find(|avatar| avatar.guid == guid && avatar.avatar_type == AVATAR_TYPE_FORMAL)
            .map(|avatar| avatar.avatar_id)
    }

    /// A held avatar property as a number.
    fn avatar_prop(&self, avatar_id: u32, prop: u32) -> Option<u64> {
        self.characters
            .get(&avatar_id)?
            .prop_map
            .get(&prop)
            .and_then(auto_artifactarium::prop_value_any)
    }

    /// `AvatarPropNotify`: a level or an ascension, never lower than held.
    fn props_change(&mut self, avatar_id: u32, entries: &[(u64, u64)]) -> Option<AvatarChange> {
        if !entries.iter().all(|(key, _)| AVATAR_PROP_IDS.contains(key)) {
            return None;
        }
        let read = |prop: u32| {
            entries
                .iter()
                .find(|(key, _)| *key == u64::from(prop))
                .map(|(_, value)| *value)
        };
        let level = read(PROP_LEVEL);
        let ascension = read(PROP_ASCENSION);
        let in_range = |value: Option<u64>, range: std::ops::RangeInclusive<u32>| {
            value.is_none_or(|v| u32::try_from(v).is_ok_and(|v| range.contains(&v)))
        };
        if (level.is_none() && ascension.is_none())
            || !in_range(level, CHARACTER_LEVEL_RANGE)
            || !in_range(ascension, CHARACTER_ASCENSION_RANGE)
        {
            return None;
        }
        let not_lower = |value: Option<u64>, prop: u32| {
            value.is_none_or(|v| {
                self.avatar_prop(avatar_id, prop)
                    .is_none_or(|held| v >= held)
            })
        };
        if !not_lower(level, PROP_LEVEL) || !not_lower(ascension, PROP_ASCENSION) {
            return None;
        }
        let changed = [PROP_LEVEL, PROP_ASCENSION]
            .into_iter()
            .any(|prop| read(prop).is_some_and(|v| self.avatar_prop(avatar_id, prop) != Some(v)));
        if !changed {
            return None;
        }

        let avatar = self.characters.get_mut(&avatar_id)?;
        for prop in [PROP_LEVEL, PROP_ASCENSION, PROP_EXP] {
            if let Some(value) = read(prop) {
                let mut prop_value = PropValue::new();
                prop_value.type_ = prop;
                prop_value.val = i64::try_from(value).ok()?;
                avatar.prop_map.insert(prop, prop_value);
            }
        }
        let held = |prop: &PropValue, range| validated_avatar_prop(prop, range);
        Some(AvatarChange::Props {
            avatar_id,
            level: avatar
                .prop_map
                .get(&PROP_LEVEL)
                .and_then(|p| held(p, CHARACTER_LEVEL_RANGE)),
            ascension: avatar
                .prop_map
                .get(&PROP_ASCENSION)
                .and_then(|p| held(p, CHARACTER_ASCENSION_RANGE)),
        })
    }

    /// `AvatarSkillChangeNotify` / `AvatarSkillUpgradeRsp`: one of the
    /// character's skills, at its held level and one above.
    fn talent_change(&mut self, avatar_id: u32, others: &[u64]) -> Option<AvatarChange> {
        let avatar = self.characters.get(&avatar_id)?;
        let has = |value: u32| others.contains(&u64::from(value));
        let mut found = avatar.skill_level_map.iter().filter(|(skill_id, level)| {
            has(**skill_id) && has(**level) && **level < MAX_TALENT_LEVEL && has(**level + 1)
        });
        let (skill_id, level) = found.next().map(|(s, l)| (*s, *l))?;
        if found.next().is_some() {
            return None;
        }
        self.characters
            .get_mut(&avatar_id)?
            .skill_level_map
            .insert(skill_id, level + 1);
        Some(AvatarChange::Talent {
            avatar_id,
            skill_id,
            level: level + 1,
        })
    }

    /// `AvatarUnlockTalentNotify`: the character's skill depot and the talent
    /// id of its next constellation.
    fn constellation_change(&mut self, avatar_id: u32, others: &[u64]) -> Option<AvatarChange> {
        let avatar = self.characters.get(&avatar_id)?;
        if avatar.skill_depot_id == 0
            || !others.contains(&u64::from(avatar.skill_depot_id))
            || avatar.talent_id_list.len() >= MAX_CONSTELLATION
        {
            return None;
        }
        // Talents unlock in order, numbered on from the depot: depot 4201 has
        // talents 421..=426. The Travelers' depots break the rule, but their
        // next talent still follows the last one.
        let next = match avatar.talent_id_list.iter().max() {
            Some(last) => last + 1,
            None => avatar.skill_depot_id / 100 * 10 + 1,
        };
        if !others.contains(&u64::from(next)) {
            return None;
        }
        self.characters
            .get_mut(&avatar_id)?
            .talent_id_list
            .push(next);
        Some(AvatarChange::Constellation {
            avatar_id,
            talent_id: next,
        })
    }

    /// `AvatarEquipChangeNotify`: a held weapon or artifact (its guid and its
    /// item id) now on the character, replacing whatever it wore in that slot.
    fn equip_change(&mut self, avatar_id: u32, others: &[u64]) -> Option<AvatarChange> {
        let mut found = self.items.iter().filter(|((item_id, guid), item)| {
            *guid != 0
                && item.has_equip()
                && others.contains(guid)
                && others.contains(&u64::from(*item_id))
        });
        let ((_, guid), item) = found.next()?;
        if found.next().is_some() {
            return None;
        }
        let guid = *guid;
        let slot = self.equip_slot(item)?;
        if self.character_equip_guid_map.get(&guid) == Some(&avatar_id) {
            return None;
        }

        // What the character wore in that slot goes back to the bag, or to
        // whoever the game says next (its own notify follows).
        let replaced: Vec<u64> = self
            .character_equip_guid_map
            .iter()
            .filter(|(worn, holder)| {
                **holder == avatar_id
                    && **worn != guid
                    && self
                        .held_equip(**worn)
                        .and_then(|item| self.equip_slot(item))
                        == Some(slot)
            })
            .map(|(worn, _)| *worn)
            .collect();
        for worn in &replaced {
            self.character_equip_guid_map.remove(worn);
        }
        let previous = self.character_equip_guid_map.insert(guid, avatar_id);

        for avatar in self.characters.values_mut() {
            if avatar.avatar_id == avatar_id {
                avatar
                    .equip_guid_list
                    .retain(|worn| !replaced.contains(worn));
                if !avatar.equip_guid_list.contains(&guid) {
                    avatar.equip_guid_list.push(guid);
                }
            } else if Some(avatar.avatar_id) == previous {
                avatar.equip_guid_list.retain(|worn| *worn != guid);
            }
        }
        Some(AvatarChange::Equip { avatar_id, guid })
    }

    /// The held weapon or artifact with this guid.
    fn held_equip(&self, guid: u64) -> Option<&Item> {
        self.items
            .iter()
            .find(|((_, held), item)| *held == guid && item.has_equip())
            .map(|(_, item)| item)
    }

    fn equip_slot(&self, item: &Item) -> Option<EquipSlot> {
        let equip = item.equip();
        if equip.has_weapon() {
            return Some(EquipSlot::Weapon);
        }
        if equip.has_reliquary() {
            let artifact = self.game_data.get_artifact(item.item_id).ok()?;
            return Some(EquipSlot::Artifact(artifact.slot));
        }
        None
    }

    /// `AvatarAddNotify`: an owned character this account did not have, with
    /// the account's guid.
    fn added_avatar(&mut self, flat: &FlatMessage) -> Option<AvatarChange> {
        let [(_, bytes)] = flat.nested.as_slice() else {
            return None;
        };
        if !flat.maps.is_empty() || flat.varints.len() > 2 {
            return None;
        }
        let uid = self.account_uid()?;
        let avatar = parse_avatar_info(bytes)?;
        if avatar.avatar_type != AVATAR_TYPE_FORMAL
            || avatar.guid >> 32 != u64::from(uid)
            || avatar.skill_depot_id == 0
            || self
                .characters
                .get(&avatar.avatar_id)
                .is_some_and(|held| held.avatar_type == AVATAR_TYPE_FORMAL)
            || self.game_data.get_character(avatar.avatar_id).is_err()
            || avatar
                .prop_map
                .get(&PROP_LEVEL)
                .and_then(|p| validated_avatar_prop(p, CHARACTER_LEVEL_RANGE))
                .is_none()
        {
            return None;
        }
        let avatar_id = avatar.avatar_id;
        self.process_characters(&[avatar]);
        Some(AvatarChange::Added { avatar_id })
    }
}

#[cfg(test)]
mod tests;
