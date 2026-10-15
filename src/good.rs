use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Substat {
    pub key: String,
    pub value: f32,
    pub initial_value: f32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Artifact {
    pub set_key: String,
    pub slot_key: String,
    pub level: u32,
    pub rarity: u32,
    pub main_stat_key: String,
    pub location: String,
    pub lock: bool,
    pub substats: Vec<Substat>,

    // GOOD v3 fields.
    pub total_rolls: u32,
    pub astral_mark: bool,
    pub elixer_crafted: bool,
    pub unactivated_substats: Vec<Substat>,

    /// The game's id of this piece, as a decimal string (a u64 does not fit a
    /// JavaScript number): what live sync names it by (`delta.rs`). Tracker
    /// uploads only (`ExportSettings::item_guids`); omitted elsewhere. Not
    /// camelCase: irminsul's own keys keep their `gi_` names.
    #[serde(rename = "gi_guid", skip_serializing_if = "Option::is_none", default)]
    pub gi_guid: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Weapon {
    pub key: String,
    pub level: u32,
    pub ascension: u32,
    pub refinement: u32,
    pub location: String,
    pub lock: bool,
    /// The game's id of this weapon; see [`Artifact::gi_guid`].
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub gi_guid: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TalentLevel {
    pub auto: u32,
    pub skill: u32,
    pub burst: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Character {
    pub key: String,
    pub level: u32,
    pub constellation: u32,
    pub ascension: u32,
    pub talent: TalentLevel,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Good {
    pub format: String,
    pub version: u32,
    pub source: String,
    pub characters: Vec<Character>,
    pub artifacts: Vec<Artifact>,
    pub weapons: Vec<Weapon>,
    pub materials: HashMap<String, u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gi_achievements: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,

    // Irminsul's own additions. Not GOOD -- Genshin Optimizer owns that schema
    // -- so they ride as top-level keys of their own, like `gi_achievements`,
    // and come after every GOOD field: with all of them `None` the JSON is
    // byte for byte what it was before they existed. The tracker's importers
    // ignore top-level keys they do not know, so each can ship before the
    // tracker reads it. Append only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gi_player: Option<GiPlayer>,
    /// When each achievement in `gi_achievements` was finished, in unix
    /// seconds, keyed by achievement id (a JSON object key, so a string). Only
    /// achievements the game sent a plausible finish time for: a subset of
    /// `gi_achievements`, never more.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gi_achievement_times: Option<BTreeMap<u32, u32>>,
    /// Per-character values GOOD has no place for, keyed by the same GOOD key
    /// the character has in `characters` (Traveler with its element suffix).
    /// Only characters with at least one known value appear.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gi_characters: Option<BTreeMap<String, GiCharacter>>,
    /// The Travel Accounts book, as the game last sent it. Omitted when the
    /// book's data was not captured, never sent empty: an absent key leaves
    /// the tracker's copy alone and keeps the content hash of a file without
    /// it unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gi_anecdotes: Option<GiAnecdotes>,
    /// Why this snapshot was taken and which play session it belongs to
    /// (live sync, plan section 5.1). Tracker uploads only.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub gi_capture: Option<GiCapture>,
}

/// `gi_capture`: why a tracker snapshot was taken, and which game login it
/// belongs to. A wire contract with the tracker (`live/capture.ts`); append
/// fields and reasons only.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct GiCapture {
    /// Always 1.
    pub v: u32,
    /// `login`, `world`, `manual`, `collapse`, `logout`, `resync` or `change`.
    pub reason: String,
    /// irminsul's id of this game login: 16+ characters of `[A-Za-z0-9_-]`.
    pub session: String,
    /// 1 = the first world of the login, 2+ = each later full send of the
    /// account in the same connection, by order (irminsul cannot tell the
    /// player's own world from a co-op host's).
    pub world: u32,
    /// The journal this snapshot ends.
    pub journal: GiCaptureJournal,
}

/// `gi_capture.journal`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct GiCaptureJournal {
    /// The last batch sent on the journal this snapshot ends (0 at login).
    pub seq: u64,
}

/// How `gi_player.uid` was read off the item guids (see
/// `PlayerData::uid_check`; logged with every export, not exported): the top 32 bits of each non-zero item guid are
/// counted, and the most common value is the UID when enough items agree.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UidCheck {
    /// The UID reported in `gi_player.uid`, if any.
    pub uid: Option<u32>,
    /// Item guids whose top half is the most common one.
    pub agreeing: usize,
    /// Item guids counted (non-zero).
    pub total: usize,
    /// The most common item guid top halves, `[top, count]`, most first.
    pub item_top_halves: Vec<(u64, usize)>,
    /// The same for avatar guids, which don't vote (field unverified).
    pub avatar_top_halves: Vec<(u64, usize)>,
    /// Items whose guid top half is not the UID, grouped (most first, at most
    /// 100 groups): what they are, to explain where they came from.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub strays: Vec<UidStray>,
}

/// Items of one kind and id whose guids carry one foreign top half.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UidStray {
    /// The guid top half (another account's UID, if the scheme holds).
    pub top: u64,
    pub item_id: u32,
    /// `material`, `weapon`, `artifact`, `furniture` or `other`.
    pub kind: String,
    /// From the game data, when it knows the item.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub count: usize,
}

/// One character's entry in `gi_characters`.
///
/// Each value is omitted, never null, when it was not captured or failed its
/// plausibility check -- and for every character at once when most of them
/// failed it, since that means the field is read from the wrong place in this
/// game version.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GiCharacter {
    /// Friendship level, 1..=10.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub friendship: Option<u32>,
    /// When the character joined the account, in unix seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obtained_at: Option<u32>,
}

/// `gi_anecdotes`: the Travel Accounts book. The contract with the tracker is
/// `GI_ANECDOTES.md` (v1, 2026-10-12); append fields only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GiAnecdotes {
    /// Every anecdote the player has met, keyed by id (a JSON object key, so a
    /// string). An id that is absent was never met -- not "not done".
    pub anecdotes: BTreeMap<u32, GiAnecdote>,
    /// The book's unlocked area tabs, sorted and unique.
    pub unlocked_areas: Vec<u32>,
    /// The reward track. Omitted when its counters could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reward: Option<GiAnecdoteReward>,
    /// The last wish. Omitted when none was made (or none was read).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wish: Option<GiAnecdoteWish>,
}

/// One entry of `gi_anecdotes.anecdotes`. Both values are always written; a
/// state the game left off the wire is 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GiAnecdote {
    /// 3 = recorded, 2 = in progress, 0 = idle (inferred, see the contract).
    pub state: u32,
    /// Times completed; above 1 only for the repeatable loops.
    pub finish_count: u32,
}

/// `gi_anecdotes.reward`: every `target` recorded anecdotes trade for a reward.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GiAnecdoteReward {
    /// Which exchange is next.
    pub index: u32,
    /// Anecdotes recorded toward it.
    pub progress: u32,
    /// Anecdotes it needs (10 in 7.1).
    pub target: u32,
}

/// `gi_anecdotes.wish`: the NPC the player asked the book about.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GiAnecdoteWish {
    /// Omitted when no wish is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub npc_id: Option<u32>,
    /// When the last wish was made, in unix seconds.
    pub last_wish_time: u32,
}

/// Account values GOOD has no place for: `gi_player`.
///
/// The numbers are the property snapshot the game sends at login, not live
/// values (resin keeps regenerating after it). Every field is omitted, never
/// null, when it was not captured or failed its plausibility check, and the
/// whole key is omitted when nothing about the account is known.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GiPlayer {
    /// The account UID, from the item and avatar guids.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Adventure Rank.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ar: Option<u32>,
    /// Adventure EXP toward the next rank.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ar_exp: Option<u32>,
    /// World Level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wl: Option<u32>,
    /// The highest World Level the account may choose.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wl_limit: Option<u32>,
    /// Original Resin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resin: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub story_keys: Option<u32>,
    /// Maximum stamina in the game's units: 24000 is the 240 the game shows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_stamina: Option<u32>,
    /// The Dimbreath dump commit the export's GOOD keys were derived from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub game_data: Option<String>,
}

/// GOOD key for the Traveler before their element is appended.
pub const TRAVELER_KEY: &str = "Traveler";

pub fn to_good_key(value: &str) -> String {
    let mut result = String::new();
    let mut capitalize_next = true;

    for c in value.chars() {
        if c.is_ascii_alphanumeric() {
            if capitalize_next {
                result.extend(c.to_uppercase());
                capitalize_next = false;
            } else {
                result.push(c);
            }
        } else if c == ' ' {
            capitalize_next = true;
        }
    }

    result
}

pub fn fake_uninitialized_4th_line(artifacts: Vec<Artifact>) -> Vec<Artifact> {
    artifacts
        .into_iter()
        .map(|mut arti| {
            if arti.unactivated_substats.is_empty() || arti.rarity != 5 {
                return arti;
            }
            arti.substats.push(arti.unactivated_substats.pop().unwrap());
            Artifact {
                level: 4,
                total_rolls: 4,
                ..arti
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn good_keys_strip_symbols_and_pascal_case() {
        assert_eq!(to_good_key("Chilled Meat"), "ChilledMeat");
        assert_eq!(
            to_good_key("Adventurer's Experience"),
            "AdventurersExperience"
        );
        assert_eq!(to_good_key("Traveler"), TRAVELER_KEY);
        assert_eq!(to_good_key("Gladiator's Finale"), "GladiatorsFinale");
    }

    #[test]
    fn names_with_no_ascii_alphanumerics_have_no_good_key() {
        // 16 items are literally named "？？？" (fullwidth question marks);
        // exporting them would add a `"": n` entry to GOOD `materials`.
        assert_eq!(to_good_key("？？？"), "");
        assert_eq!(to_good_key(""), "");
        assert_eq!(to_good_key("   "), "");
    }

    fn substat(key: &str) -> Substat {
        Substat {
            key: key.to_string(),
            value: 1.0,
            initial_value: 1.0,
        }
    }

    fn artifact(rarity: u32, unactivated: Vec<Substat>) -> Artifact {
        Artifact {
            set_key: "GladiatorsFinale".to_string(),
            slot_key: "flower".to_string(),
            level: 0,
            rarity,
            main_stat_key: "hp".to_string(),
            location: String::new(),
            lock: false,
            substats: vec![substat("critRate_")],
            total_rolls: 1,
            astral_mark: false,
            elixer_crafted: false,
            unactivated_substats: unactivated,
            gi_guid: Some("3488998120056947072".to_string()),
        }
    }

    #[test]
    fn fake_4th_line_only_promotes_five_star_artifacts_with_an_unactivated_substat() {
        let faked = fake_uninitialized_4th_line(vec![
            artifact(5, vec![substat("critDMG_")]),
            artifact(5, Vec::new()),
            artifact(4, vec![substat("critDMG_")]),
        ]);

        assert_eq!(faked[0].substats.len(), 2);
        assert_eq!(faked[0].level, 4);
        assert_eq!(faked[0].total_rolls, 4);
        assert!(faked[0].unactivated_substats.is_empty());

        // Untouched: nothing to promote, and not a five star.
        assert_eq!(faked[1].substats.len(), 1);
        assert_eq!(faked[1].level, 0);
        assert_eq!(faked[2].substats.len(), 1);
        assert_eq!(faked[2].level, 0);
    }

    /// The JSON key names below are a cross-repo contract, not a style choice.
    ///
    /// `Good` is uploaded verbatim to the tracker's
    /// `POST /genshin-accounts-public/import-by-key`, which runs a bare
    /// `JSON.parse` and reads fields by name with no schema validation and no
    /// error on a miss (`genshin-accounts.service.ts::processImport`). So a
    /// rename here does not fail an import -- it silently drops whatever it
    /// renamed. The two easiest mistakes both look harmless in review:
    ///
    /// * adding `#[serde(rename_all = "camelCase")]` to `Good` turns
    ///   `gi_achievements` into `giAchievements`, and every snapshot then
    ///   imports zero achievements;
    /// * removing it from `Artifact` turns `setKey` into `set_key`, and every
    ///   artifact then hashes as `{"setKey":null,...}` -- one shared row for
    ///   the entire inventory.
    ///
    /// Neither raises anything anywhere. This test is the only thing that
    /// notices.
    #[test]
    fn good_json_keys_match_what_the_tracker_reads() {
        let good = Good {
            format: "GOOD".to_string(),
            version: 3,
            source: "Irminsul".to_string(),
            characters: vec![Character {
                key: "HuTao".to_string(),
                level: 90,
                constellation: 1,
                ascension: 6,
                talent: TalentLevel {
                    auto: 10,
                    skill: 9,
                    burst: 8,
                },
            }],
            artifacts: vec![artifact(5, vec![substat("critDMG_")])],
            weapons: vec![Weapon {
                key: "StaffOfHoma".to_string(),
                level: 90,
                ascension: 6,
                refinement: 1,
                location: "HuTao".to_string(),
                lock: true,
                gi_guid: Some("3488998120056947188".to_string()),
            }],
            materials: HashMap::from([("ChilledMeat".to_string(), 12)]),
            gi_achievements: Some(vec![80001]),
            timestamp: Some(1_756_000_000_000),
            gi_player: Some(GiPlayer {
                uid: Some(811_111_111),
                ar: Some(60),
                ar_exp: Some(0),
                wl: Some(8),
                wl_limit: Some(9),
                resin: Some(124),
                story_keys: Some(3),
                max_stamina: Some(24_000),
                game_data: Some("792978e5503ecfba73dcb3562ed44a0d35a2abe2".to_string()),
            }),
            gi_achievement_times: Some(BTreeMap::from([(80001, 1_650_000_000)])),
            gi_characters: Some(BTreeMap::from([(
                "HuTao".to_string(),
                GiCharacter {
                    friendship: Some(10),
                    obtained_at: Some(1_646_092_800),
                },
            )])),
            gi_anecdotes: Some(GiAnecdotes {
                anecdotes: BTreeMap::from([
                    (
                        100_001,
                        GiAnecdote {
                            state: 3,
                            finish_count: 1,
                        },
                    ),
                    (
                        101_604,
                        GiAnecdote {
                            state: 0,
                            finish_count: 3,
                        },
                    ),
                ]),
                unlocked_areas: vec![1, 2, 3],
                reward: Some(GiAnecdoteReward {
                    index: 12,
                    progress: 4,
                    target: 10,
                }),
                wish: Some(GiAnecdoteWish {
                    npc_id: Some(9801),
                    last_wish_time: 1_791_000_000,
                }),
            }),
            gi_capture: Some(GiCapture {
                v: 1,
                reason: "login".to_string(),
                session: "01J9ZK5Q8W3E7R2T".to_string(),
                world: 1,
                journal: GiCaptureJournal { seq: 0 },
            }),
        };

        let json = serde_json::to_value(&good).expect("Good must serialize");

        let keys = |value: &serde_json::Value| -> Vec<String> {
            let mut keys: Vec<String> = value
                .as_object()
                .expect("expected a JSON object")
                .keys()
                .cloned()
                .collect();
            keys.sort();
            keys
        };

        // `format`/`version`/`source` are inert for the tracker but are what
        // Genshin Optimizer identifies the file by, so they are part of the
        // contract too.
        assert_eq!(
            keys(&json),
            [
                "artifacts",
                "characters",
                "format",
                "gi_achievement_times",
                "gi_achievements",
                "gi_anecdotes",
                "gi_capture",
                "gi_characters",
                "gi_player",
                "materials",
                "source",
                "timestamp",
                "version",
                "weapons",
            ]
        );

        // CHARACTER_SCHEMA in the backend's data-packer.util.ts.
        assert_eq!(
            keys(&json["characters"][0]),
            ["ascension", "constellation", "key", "level", "talent"]
        );
        assert_eq!(
            keys(&json["characters"][0]["talent"]),
            ["auto", "burst", "skill"]
        );

        // WEAPON_SCHEMA in the backend's data-packer.util.ts.
        assert_eq!(
            keys(&json["weapons"][0]),
            [
                "ascension",
                "gi_guid",
                "key",
                "level",
                "location",
                "lock",
                "refinement"
            ]
        );

        // The first five feed the backend's SHA-256 artifact hash; `location`,
        // `lock` and `astralMark` are its mutable live state; `totalRolls`,
        // `elixerCrafted` and `substats` are stored on the row. Note
        // `elixerCrafted` really is spelled that way on both sides.
        assert_eq!(
            keys(&json["artifacts"][0]),
            [
                "astralMark",
                "elixerCrafted",
                "gi_guid",
                "level",
                "location",
                "lock",
                "mainStatKey",
                "rarity",
                "setKey",
                "slotKey",
                "substats",
                "totalRolls",
                "unactivatedSubstats",
            ]
        );

        // `initialValue` is hashed alongside `key`/`value`, so renaming it
        // would re-hash every artifact in every account exactly once and
        // orphan the old rows.
        assert_eq!(
            keys(&json["artifacts"][0]["substats"][0]),
            ["initialValue", "key", "value"]
        );

        // Epoch milliseconds as a JSON number: the backend's
        // `resolveImportTimestamp` dates the snapshot by this when the
        // multipart `timestamp` field is absent.
        assert_eq!(json["timestamp"], serde_json::json!(1_756_000_000_000u64));
        assert_eq!(json["materials"]["ChilledMeat"], serde_json::json!(12));

        // Irminsul's own account values. The UID is a JSON number; the
        // tracker's account UID is a string of 9 or 10 digits.
        assert_eq!(
            keys(&json["gi_player"]),
            [
                "ar",
                "arExp",
                "gameData",
                "maxStamina",
                "resin",
                "storyKeys",
                "uid",
                "wl",
                "wlLimit",
            ]
        );
        assert_eq!(json["gi_player"]["uid"], serde_json::json!(811_111_111));

        // Achievement id (a JSON object key, so a string) -> unix seconds.
        assert_eq!(
            json["gi_achievement_times"],
            serde_json::json!({ "80001": 1_650_000_000 })
        );

        // Keyed like `characters`; unix seconds for `obtainedAt`.
        assert_eq!(keys(&json["gi_characters"]), ["HuTao"]);
        assert_eq!(
            keys(&json["gi_characters"]["HuTao"]),
            ["friendship", "obtainedAt"]
        );

        // `GI_ANECDOTES.md`: anecdote ids are object keys (strings); the
        // state is written even when 0.
        assert_eq!(
            keys(&json["gi_anecdotes"]),
            ["anecdotes", "reward", "unlockedAreas", "wish"]
        );
        assert_eq!(
            json["gi_anecdotes"]["anecdotes"],
            serde_json::json!({
                "100001": { "state": 3, "finishCount": 1 },
                "101604": { "state": 0, "finishCount": 3 },
            })
        );
        assert_eq!(
            json["gi_anecdotes"]["unlockedAreas"],
            serde_json::json!([1, 2, 3])
        );
        assert_eq!(
            json["gi_anecdotes"]["reward"],
            serde_json::json!({ "index": 12, "progress": 4, "target": 10 })
        );
        assert_eq!(
            json["gi_anecdotes"]["wish"],
            serde_json::json!({ "npcId": 9801, "lastWishTime": 1_791_000_000 })
        );

        // Live sync (the tracker's `live/capture.ts` and `live/delta.ts`):
        // item guids are decimal strings, a u64 does not fit a JS number.
        assert_eq!(
            keys(&json["gi_capture"]),
            ["journal", "reason", "session", "v", "world"]
        );
        assert_eq!(keys(&json["gi_capture"]["journal"]), ["seq"]);
        assert_eq!(
            json["artifacts"][0]["gi_guid"],
            serde_json::json!("3488998120056947072")
        );
        assert_eq!(
            json["weapons"][0]["gi_guid"],
            serde_json::json!("3488998120056947188")
        );
    }

    #[test]
    fn absent_achievements_and_timestamp_are_omitted_rather_than_null() {
        // `skip_serializing_if` matters: the backend tests
        // `Array.isArray(parsedData.gi_achievements)` and falls back to `[]`,
        // and feeds `parsedData.timestamp` to `resolveImportTimestamp`, which
        // maps a null to "now". An explicit `null` would work, but only by
        // accident -- keep the omission the tracker was written against.
        let good = Good {
            format: "GOOD".to_string(),
            version: 3,
            source: "Irminsul".to_string(),
            characters: Vec::new(),
            artifacts: Vec::new(),
            weapons: Vec::new(),
            materials: HashMap::new(),
            gi_achievements: None,
            timestamp: None,
            gi_player: None,
            gi_achievement_times: None,
            gi_characters: None,
            gi_anecdotes: None,
            gi_capture: None,
        };

        let json = serde_json::to_value(&good).expect("Good must serialize");
        let object = json.as_object().expect("expected a JSON object");
        assert!(!object.contains_key("gi_achievements"));
        assert!(!object.contains_key("timestamp"));
        assert!(!object.contains_key("gi_player"));
        assert!(!object.contains_key("gi_achievement_times"));
        assert!(!object.contains_key("gi_characters"));
        assert!(!object.contains_key("gi_anecdotes"));
        assert!(!object.contains_key("gi_capture"));
    }

    #[test]
    fn unknown_account_values_are_omitted_rather_than_null() {
        let player = GiPlayer {
            ar: Some(60),
            ..Default::default()
        };
        assert_eq!(serde_json::to_string(&player).unwrap(), r#"{"ar":60}"#);

        let character = GiCharacter {
            obtained_at: Some(1_646_092_800),
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_string(&character).unwrap(),
            r#"{"obtainedAt":1646092800}"#
        );

        // A book with no reward read and no wish made, and a wish with no NPC.
        let book = GiAnecdotes {
            anecdotes: BTreeMap::from([(
                107_302,
                GiAnecdote {
                    state: 2,
                    finish_count: 0,
                },
            )]),
            unlocked_areas: vec![7],
            reward: None,
            wish: None,
        };
        assert_eq!(
            serde_json::to_string(&book).unwrap(),
            r#"{"anecdotes":{"107302":{"state":2,"finishCount":0}},"unlockedAreas":[7]}"#
        );
        let wish = GiAnecdoteWish {
            npc_id: None,
            last_wish_time: 1_791_000_000,
        };
        assert_eq!(
            serde_json::to_string(&wish).unwrap(),
            r#"{"lastWishTime":1791000000}"#
        );
    }
}
