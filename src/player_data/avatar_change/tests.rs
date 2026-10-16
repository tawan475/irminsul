//! Each live update built as 7.1 lays it out, over a small held account.

use anime_game_data::AnimeGameData;
use auto_artifactarium::r#gen::protos::{AvatarInfo, Equip, Material, Reliquary, Weapon};
use auto_artifactarium::{GameCommand, flat_message};

use super::*;

const UID: u64 = 812_345_678;
const HU_TAO: u32 = 10000046;
const KAZUHA: u32 = 10000047;
const NEW_CHARACTER: u32 = 10000048;
const DEPOT: u32 = 7401;
const ATTACK: u32 = 10741;
const BURST: u32 = 10745;

fn guid(n: u64) -> u64 {
    (UID << 32) + n
}

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

/// The message as irminsul's monitor hands it over.
fn flat(fields: &[Vec<u8>]) -> FlatMessage {
    let payload = fields.concat();
    flat_message(&GameCommand {
        command_id: 1,
        header_len: 0,
        data_len: payload.len() as u32,
        proto_header: Vec::new(),
        proto_data: payload,
    })
    .expect("a possible character update")
}

fn prop(type_: u32, val: i64) -> PropValue {
    let mut prop = PropValue::new();
    prop.type_ = type_;
    prop.val = val;
    prop
}

fn character(avatar_id: u32, n: u64, equip: &[u64]) -> AvatarInfo {
    let mut avatar = AvatarInfo::new();
    avatar.avatar_id = avatar_id;
    avatar.guid = guid(n);
    avatar.avatar_type = AVATAR_TYPE_FORMAL;
    avatar.skill_depot_id = DEPOT;
    avatar.prop_map.insert(PROP_LEVEL, prop(PROP_LEVEL, 80));
    avatar
        .prop_map
        .insert(PROP_ASCENSION, prop(PROP_ASCENSION, 5));
    avatar.skill_level_map.insert(ATTACK, 9);
    avatar.skill_level_map.insert(10742, 8);
    avatar.skill_level_map.insert(BURST, 10);
    avatar.equip_guid_list = equip.to_vec();
    avatar
}

fn weapon(item_id: u32, n: u64) -> Item {
    let mut item = Item::new();
    item.item_id = item_id;
    item.guid = guid(n);
    let mut equip = Equip::new();
    equip.set_weapon(Weapon::new());
    item.set_equip(equip);
    item
}

fn flower(n: u64) -> Item {
    let mut item = Item::new();
    item.item_id = 81524;
    item.guid = guid(n);
    let mut equip = Equip::new();
    equip.set_reliquary(Reliquary::new());
    item.set_equip(equip);
    item
}

fn material(n: u64) -> Item {
    let mut item = Item::new();
    item.item_id = 104003;
    item.guid = guid(n);
    item.set_material(Material {
        count: 3,
        ..Default::default()
    });
    item
}

/// Hu Tao (guid 1) wears weapon 10 and flower 11; Kazuha (guid 2) wears
/// weapon 14 and flower 13; weapon 12 is in the bag.
fn data() -> PlayerData {
    let json = r#"{
        "version": 4, "git_hash": "test", "affix_map": {},
        "artifact_map": {"81524": {"set": "Crimson Witch of Flames", "slot": "Flower", "rarity": 5}},
        "character_map": {"10000046": "Hu Tao", "10000047": "Kazuha", "10000048": "Newcomer"},
        "material_map": {}, "property_map": {}, "set_map": {}, "skill_element_map": {},
        "skill_type_map": {}, "tps_avatar_id_female": null, "tps_avatar_id_male": null,
        "weapon_map": {}
    }"#;
    let mut data = PlayerData::new(AnimeGameData::new_from_reader(json.as_bytes()).unwrap());
    data.process_items(&[
        weapon(13501, 10),
        flower(11),
        weapon(13502, 12),
        flower(13),
        weapon(13503, 14),
        material(20),
    ]);
    data.process_characters(&[
        character(HU_TAO, 1, &[guid(10), guid(11)]),
        character(KAZUHA, 2, &[guid(14), guid(13)]),
    ]);
    data
}

fn held(data: &PlayerData, avatar_id: u32) -> &AvatarInfo {
    &data.characters[&avatar_id]
}

/// `AvatarSkillChangeNotify` as 7.1 lays it out.
fn skill_change(n: u64, skill: u32, old: u64, cur: u64) -> FlatMessage {
    flat(&[
        v(7, 16_777_300),
        v(15, u64::from(DEPOT)),
        v(3, guid(n)),
        v(10, cur),
        v(14, old),
        v(5, u64::from(skill)),
    ])
}

#[test]
fn a_talent_level_up_is_applied_once() {
    let mut data = data();
    assert_eq!(
        data.apply_avatar_change(&skill_change(1, ATTACK, 9, 10)),
        Some(AvatarChange::Talent {
            avatar_id: HU_TAO,
            skill_id: ATTACK,
            level: 10
        })
    );
    assert_eq!(held(&data, HU_TAO).skill_level_map[&ATTACK], 10);

    // The reply to the same upgrade (`AvatarSkillUpgradeRsp`) changes nothing.
    let reply = flat(&[v(9, guid(1)), v(8, 10), v(2, 9), v(15, u64::from(ATTACK))]);
    assert_eq!(data.apply_avatar_change(&reply), None);
    assert_eq!(held(&data, HU_TAO).skill_level_map[&ATTACK], 10);
}

#[test]
fn a_talent_reply_alone_is_applied_too() {
    let mut data = data();
    let reply = flat(&[v(9, guid(1)), v(8, 11), v(2, 10), v(15, u64::from(BURST))]);
    assert!(data.apply_avatar_change(&reply).is_some());
    assert_eq!(held(&data, HU_TAO).skill_level_map[&BURST], 11);
}

#[test]
fn what_only_looks_like_a_talent_change_is_ignored() {
    let mut data = data();
    // Not one of the character's skills.
    assert_eq!(
        data.apply_avatar_change(&skill_change(1, 10999, 9, 10)),
        None
    );
    // Not from the held level.
    assert_eq!(
        data.apply_avatar_change(&skill_change(1, ATTACK, 7, 8)),
        None
    );
    // The request: the old level only.
    let request = flat(&[v(1, guid(1)), v(2, u64::from(ATTACK)), v(3, 9)]);
    assert_eq!(data.apply_avatar_change(&request), None);
    // Another player's character.
    assert_eq!(
        data.apply_avatar_change(&skill_change(9, ATTACK, 9, 10)),
        None
    );
    assert_eq!(held(&data, HU_TAO).skill_level_map[&ATTACK], 9);
}

fn prop_notify(n: u64, props: &[(u64, u64)]) -> FlatMessage {
    let mut fields: Vec<Vec<u8>> = props
        .iter()
        .map(|(key, value)| b(10, &[v(1, *key), v(2, *value)].concat()))
        .collect();
    fields.push(v(1, guid(n)));
    flat(&fields)
}

fn prop_of(data: &PlayerData, avatar_id: u32, prop_id: u32) -> Option<u64> {
    data.avatar_prop(avatar_id, prop_id)
}

#[test]
fn a_level_and_an_ascension_are_applied() {
    let mut data = data();
    assert_eq!(
        data.apply_avatar_change(&prop_notify(1, &[(4001, 81), (1001, 1_200)])),
        Some(AvatarChange::Props {
            avatar_id: HU_TAO,
            level: Some(81),
            ascension: Some(5)
        })
    );
    assert!(
        data.apply_avatar_change(&prop_notify(1, &[(1002, 6)]))
            .is_some()
    );
    assert_eq!(prop_of(&data, HU_TAO, PROP_LEVEL), Some(81));
    assert_eq!(prop_of(&data, HU_TAO, PROP_ASCENSION), Some(6));
    // The same values again are nothing new.
    assert_eq!(
        data.apply_avatar_change(&prop_notify(1, &[(4001, 81)])),
        None
    );
}

#[test]
fn what_only_looks_like_a_level_change_is_ignored() {
    let mut data = data();
    // Levels never go down, and stay in range.
    assert_eq!(
        data.apply_avatar_change(&prop_notify(1, &[(4001, 79)])),
        None
    );
    assert_eq!(
        data.apply_avatar_change(&prop_notify(1, &[(4001, 5_000)])),
        None
    );
    // Satiation alone (eating), or keys that are not avatar properties.
    assert_eq!(
        data.apply_avatar_change(&prop_notify(1, &[(1003, 30)])),
        None
    );
    assert_eq!(
        data.apply_avatar_change(&prop_notify(1, &[(4001, 85), (2001, 3)])),
        None
    );
    // Not a held character.
    assert_eq!(
        data.apply_avatar_change(&prop_notify(9, &[(4001, 85)])),
        None
    );
    assert_eq!(prop_of(&data, HU_TAO, PROP_LEVEL), Some(80));
}

fn unlock_talent(n: u64, talent: u32) -> FlatMessage {
    flat(&[
        v(5, guid(n)),
        v(13, u64::from(talent)),
        v(7, 16_777_300),
        v(15, u64::from(DEPOT)),
    ])
}

#[test]
fn constellations_unlock_in_order() {
    let mut data = data();
    assert_eq!(
        data.apply_avatar_change(&unlock_talent(1, 742)),
        None,
        "C2 before C1"
    );
    assert_eq!(
        data.apply_avatar_change(&unlock_talent(1, 741)),
        Some(AvatarChange::Constellation {
            avatar_id: HU_TAO,
            talent_id: 741
        })
    );
    assert_eq!(
        data.apply_avatar_change(&unlock_talent(1, 741)),
        None,
        "once"
    );
    assert!(data.apply_avatar_change(&unlock_talent(1, 742)).is_some());
    assert_eq!(held(&data, HU_TAO).talent_id_list, vec![741, 742]);
}

/// `AvatarEquipChangeNotify` as 7.1 lays it out, with its nested
/// `SceneWeaponInfo` / `SceneReliquaryInfo`.
fn equip_change(n: u64, equip: u64, item_id: u32, equip_type: u64) -> FlatMessage {
    flat(&[
        b(13, &[v(1, 16_777_400), v(2, guid(equip))].concat()),
        v(12, guid(equip)),
        v(9, guid(n)),
        v(15, u64::from(item_id)),
        v(10, equip_type),
    ])
}

fn holder(data: &PlayerData, n: u64) -> Option<u32> {
    data.character_equip_guid_map.get(&guid(n)).copied()
}

#[test]
fn a_weapon_from_the_bag_replaces_the_one_worn() {
    let mut data = data();
    assert_eq!(
        data.apply_avatar_change(&equip_change(1, 12, 13502, 6)),
        Some(AvatarChange::Equip {
            avatar_id: HU_TAO,
            guid: guid(12)
        })
    );
    assert_eq!(holder(&data, 12), Some(HU_TAO));
    assert_eq!(holder(&data, 10), None, "back in the bag");
    assert_eq!(holder(&data, 11), Some(HU_TAO), "the flower stays");
    assert_eq!(
        held(&data, HU_TAO).equip_guid_list,
        vec![guid(11), guid(12)]
    );
    // The game re-sends the worn weapon on every scene change.
    assert_eq!(
        data.apply_avatar_change(&equip_change(1, 12, 13502, 6)),
        None
    );
}

#[test]
fn an_artifact_swap_between_characters_settles_in_either_order() {
    for kazuha_first in [false, true] {
        let mut data = data();
        let hu_tao = equip_change(1, 13, 81524, 1);
        let kazuha = equip_change(2, 11, 81524, 1);
        if kazuha_first {
            assert!(data.apply_avatar_change(&kazuha).is_some());
            assert!(data.apply_avatar_change(&hu_tao).is_some());
        } else {
            assert!(data.apply_avatar_change(&hu_tao).is_some());
            assert!(data.apply_avatar_change(&kazuha).is_some());
        }
        assert_eq!(holder(&data, 13), Some(HU_TAO));
        assert_eq!(holder(&data, 11), Some(KAZUHA));
        assert_eq!(holder(&data, 10), Some(HU_TAO), "weapons stay");
        assert_eq!(holder(&data, 14), Some(KAZUHA));
    }
}

#[test]
fn what_only_looks_like_an_equip_change_is_ignored() {
    let mut data = data();
    // The guid without its item id, an item that is not held, a material.
    assert_eq!(
        data.apply_avatar_change(&equip_change(1, 12, 99999, 6)),
        None
    );
    assert_eq!(
        data.apply_avatar_change(&equip_change(1, 30, 13502, 6)),
        None
    );
    assert_eq!(
        data.apply_avatar_change(&equip_change(1, 20, 104003, 6)),
        None
    );
    // Another player's character.
    assert_eq!(
        data.apply_avatar_change(&equip_change(9, 12, 13502, 6)),
        None
    );
    assert_eq!(holder(&data, 10), Some(HU_TAO));
    assert_eq!(holder(&data, 12), None);
}

/// `AvatarAddNotify`: the `AvatarInfo` on 11, `is_in_team` on 10.
fn avatar_add(avatar_id: u32, avatar_guid: u64, avatar_type: u64) -> FlatMessage {
    let level = b(
        3,
        &[v(1, 4001), b(2, &[v(1, 4001), v(4, 1)].concat())].concat(),
    );
    let info = [
        v(1, u64::from(avatar_id)),
        v(2, avatar_guid),
        level,
        v(11, 4801),
        v(19, avatar_type),
    ]
    .concat();
    flat(&[b(11, &info), v(10, 1)])
}

#[test]
fn a_new_character_is_added() {
    let mut data = data();
    assert_eq!(
        data.apply_avatar_change(&avatar_add(NEW_CHARACTER, guid(30), 1)),
        Some(AvatarChange::Added {
            avatar_id: NEW_CHARACTER
        })
    );
    assert_eq!(prop_of(&data, NEW_CHARACTER, PROP_LEVEL), Some(1));
    assert_eq!(
        data.apply_avatar_change(&avatar_add(NEW_CHARACTER, guid(30), 1)),
        None
    );
}

#[test]
fn trial_and_foreign_characters_are_not_added() {
    let mut data = data();
    // A trial character (type 2), another account's, an unknown one.
    assert_eq!(
        data.apply_avatar_change(&avatar_add(NEW_CHARACTER, guid(30), 2)),
        None
    );
    assert_eq!(
        data.apply_avatar_change(&avatar_add(NEW_CHARACTER, (7 << 32) + 30, 1)),
        None
    );
    assert_eq!(
        data.apply_avatar_change(&avatar_add(10000099, guid(30), 1)),
        None
    );
    assert!(!data.characters.contains_key(&NEW_CHARACTER));
}
