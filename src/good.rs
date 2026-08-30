use std::collections::HashMap;

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
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Weapon {
    pub key: String,
    pub level: u32,
    pub ascension: u32,
    pub refinement: u32,
    pub location: String,
    pub lock: bool,
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
            }],
            materials: HashMap::from([("ChilledMeat".to_string(), 12)]),
            gi_achievements: Some(vec![80001]),
            timestamp: Some(1_756_000_000_000),
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
                "gi_achievements",
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
        };

        let json = serde_json::to_value(&good).expect("Good must serialize");
        let object = json.as_object().expect("expected a JSON object");
        assert!(!object.contains_key("gi_achievements"));
        assert!(!object.contains_key("timestamp"));
    }
}
