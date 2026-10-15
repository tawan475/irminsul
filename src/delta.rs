//! GOOD-X delta: the changes live sync sends between two snapshots.
//!
//! A wire contract with the tracker (`packages/shared/src/live/delta.ts`
//! there, which holds the path table; plan `docs/plans/live-sync.md` §5.2 and
//! §13). The fixture `tests/fixtures/good-x-delta.json` is the same file in
//! both repos and pins the shape: fields and path kinds are only appended.
//!
//! The journal is a diff of two exports, not a translation of each packet:
//! [`Keyed::of`] flattens an export into one value per GOOD path, and
//! [`diff`] compares two of those. Items are keyed by the game's guid
//! (`gi_guid`), so a levelled artifact is a field `set`, not a delete and an
//! add. An item without a guid never appears in a batch; the next snapshot
//! carries it.

use std::collections::BTreeMap;

use serde::de::Error as _;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value, json};

use crate::good::Good;

pub const DELTA_FORMAT: &str = "GOOD-X-delta";
/// At most this many changes per batch; anything bigger is a snapshot.
pub const MAX_CHANGES: usize = 2_000;
/// At most this many bytes of JSON per batch.
pub const MAX_BYTES: usize = 512 * 1024;

/// A GOOD path: every part a string (contract v1).
pub type Path = Vec<String>;

/// One change, serialised as a JSON array:
/// `["set", path, value]`, `["add", path, item]`, `["del", path]` or
/// `["del", path, hint]`. Always an absolute value.
#[derive(Clone, Debug, PartialEq)]
pub enum Change {
    Set(Path, Value),
    Add(Path, Value),
    Del(Path, Option<Value>),
}

impl Change {
    pub fn path(&self) -> &Path {
        match self {
            Self::Set(path, _) | Self::Add(path, _) | Self::Del(path, _) => path,
        }
    }
}

impl Serialize for Change {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (op, path, value) = match self {
            Self::Set(path, value) => ("set", path, Some(value)),
            Self::Add(path, value) => ("add", path, Some(value)),
            Self::Del(path, hint) => ("del", path, hint.as_ref()),
        };
        let mut seq = serializer.serialize_seq(Some(if value.is_some() { 3 } else { 2 }))?;
        seq.serialize_element(op)?;
        seq.serialize_element(path)?;
        if let Some(value) = value {
            seq.serialize_element(value)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Change {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let parts = Vec::<Value>::deserialize(deserializer)?;
        let op = parts.first().and_then(Value::as_str).unwrap_or_default();
        let path: Path = match parts.get(1) {
            Some(Value::Array(path)) => path
                .iter()
                .map(|part| match part {
                    Value::String(text) => Ok(text.clone()),
                    Value::Number(number) => Ok(number.to_string()),
                    _ => Err(D::Error::custom("a path part is a string or a number")),
                })
                .collect::<Result<_, _>>()?,
            _ => return Err(D::Error::custom("a change needs a path")),
        };
        let value = parts.get(2).cloned();
        match (op, value) {
            ("set", Some(value)) if parts.len() == 3 => Ok(Self::Set(path, value)),
            ("add", Some(value)) if parts.len() == 3 => Ok(Self::Add(path, value)),
            ("del", hint) if parts.len() <= 3 => Ok(Self::Del(path, hint)),
            _ => Err(D::Error::custom(format!("not a change: {op}"))),
        }
    }
}

/// The whole account's chart figures, counted like the tracker's snapshot
/// summary (plan §13).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sum {
    pub characters: u64,
    pub weapons: u64,
    pub artifacts: u64,
    /// Keys in `materials`.
    pub materials: u64,
    pub mora: u64,
    pub primogem: u64,
    /// Unlocked, unequipped 3★ artifacts.
    pub artifact3: u64,
    /// Unlocked, unequipped 4★ artifacts.
    pub artifact4: u64,
}

impl Sum {
    pub fn of(good: &Good) -> Self {
        let spare = |rarity: u32| {
            good.artifacts
                .iter()
                .filter(|a| a.rarity == rarity && !a.lock && a.location.is_empty())
                .count() as u64
        };
        Self {
            characters: good.characters.len() as u64,
            weapons: good.weapons.len() as u64,
            artifacts: good.artifacts.len() as u64,
            materials: good.materials.len() as u64,
            mora: good.materials.get("Mora").copied().unwrap_or(0).into(),
            primogem: good.materials.get("Primogem").copied().unwrap_or(0).into(),
            artifact3: spare(3),
            artifact4: spare(4),
        }
    }
}

/// One batch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GoodDelta {
    pub format: String,
    pub v: u8,
    pub uid: u32,
    /// irminsul's id of this game login (`gi_capture.session`).
    pub session: String,
    /// 1, 2, 3 … within the journal of `base`.
    pub seq: u64,
    /// The `live.base` the journal's snapshot was answered with.
    pub base: String,
    /// Unix ms when the batch was built.
    pub at: u64,
    pub changes: Vec<Change>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sum: Option<Sum>,
}

impl GoodDelta {
    pub fn new(uid: u32, session: &str, seq: u64, base: &str, at: u64) -> Self {
        Self {
            format: DELTA_FORMAT.to_string(),
            v: 1,
            uid,
            session: session.to_string(),
            seq,
            base: base.to_string(),
            at,
            changes: Vec::new(),
            sum: None,
        }
    }
}

/// An export flattened into one value per GOOD path, plus what a delete may
/// need to say about an item that is gone (`hints`: a weapon's rarity, which
/// GOOD's weapon object does not carry).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Keyed {
    pub entries: BTreeMap<Path, Value>,
    hints: BTreeMap<Path, Value>,
}

fn path(parts: &[&str]) -> Path {
    parts.iter().map(|part| (*part).to_string()).collect()
}

/// Paths whose value is a whole item: `add` / `del` and field changes.
fn is_item(path: &Path) -> bool {
    path.len() == 2 && matches!(path[0].as_str(), "artifacts" | "weapons" | "characters")
}

impl Keyed {
    /// `good` flattened. `weapon_rarity` says a weapon's rarity by its guid
    /// (the del hint). The values are read back from the export's own JSON,
    /// so a number is exactly what a snapshot upload of `good` holds (an f32
    /// substat written as `3.9`, not as its f64 widening).
    pub fn of(good: &Good, weapon_rarity: impl Fn(&str) -> Option<u32>) -> Self {
        let mut keyed = Self::default();
        keyed.read(&as_uploaded(good), &weapon_rarity);
        keyed
    }

    fn read(&mut self, good: &Value, weapon_rarity: &dyn Fn(&str) -> Option<u32>) {
        let entries = &mut self.entries;
        if let Some(materials) = good.get("materials").and_then(Value::as_object) {
            for (key, count) in materials {
                entries.insert(path(&["materials", key]), count.clone());
            }
        }
        for character in good["characters"].as_array().into_iter().flatten() {
            if let Some(key) = character.get("key").and_then(Value::as_str) {
                entries.insert(path(&["characters", key]), character.clone());
            }
        }
        for kind in ["artifacts", "weapons"] {
            for item in good[kind].as_array().into_iter().flatten() {
                let Some(mut item) = item.as_object().cloned() else {
                    continue;
                };
                let Some(Value::String(guid)) = item.remove("gi_guid") else {
                    continue;
                };
                let at = path(&[kind, &guid]);
                if kind == "weapons"
                    && let Some(rarity) = weapon_rarity(&guid)
                {
                    self.hints.insert(at.clone(), json!({ "rarity": rarity }));
                }
                entries.insert(at, Value::Object(item));
            }
        }
        if let Some(player) = good.get("gi_player").and_then(Value::as_object) {
            for (field, value) in player {
                entries.insert(path(&["gi_player", field]), value.clone());
            }
        }
        if let Some(extras) = good.get("gi_characters").and_then(Value::as_object) {
            for (key, extra) in extras {
                for (field, value) in extra.as_object().into_iter().flatten() {
                    entries.insert(path(&["gi_characters", key, field]), value.clone());
                }
            }
        }
        let times = good.get("gi_achievement_times").and_then(Value::as_object);
        for id in good["gi_achievements"].as_array().into_iter().flatten() {
            let id = id.to_string();
            let time = times
                .and_then(|times| times.get(&id))
                .cloned()
                .unwrap_or(json!(0));
            entries.insert(path(&["achievements", &id]), time);
        }
        if let Some(book) = good.get("gi_anecdotes").and_then(Value::as_object) {
            for (id, entry) in book
                .get("anecdotes")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
            {
                entries.insert(path(&["anecdotes", id]), entry.clone());
            }
            for field in ["unlockedAreas", "reward", "wish"] {
                if let Some(value) = book.get(field) {
                    entries.insert(path(&["gi_anecdotes", field]), value.clone());
                }
            }
        }
    }

    fn hint(&self, at: &Path, value: &Value) -> Option<Value> {
        match at[0].as_str() {
            "artifacts" => value
                .get("rarity")
                .map(|rarity| json!({ "rarity": rarity })),
            "weapons" => self.hints.get(at).cloned(),
            _ => None,
        }
    }
}

/// `good` as its upload's JSON reads: an f32 substat as the `3.9` the
/// upload writes, not the `3.9000000953674316` `serde_json::to_value` would
/// widen it to.
pub fn as_uploaded(good: &Good) -> Value {
    let json = serde_json::to_string(good).expect("a Good always serialises");
    serde_json::from_str(&json).expect("its own JSON parses")
}

/// What changed from `old` to `new`: `add` for a new item, field `set`s for a
/// changed one, `del` (with the rarity hint) for one that is gone, `set` /
/// `del` for every other path. Deterministic: in path order, deletes last.
pub fn diff(old: &Keyed, new: &Keyed) -> Vec<Change> {
    let mut out = Vec::new();
    for (at, value) in &new.entries {
        match old.entries.get(at) {
            None if is_item(at) => out.push(Change::Add(at.clone(), value.clone())),
            None => out.push(Change::Set(at.clone(), value.clone())),
            Some(previous) if previous != value => {
                if is_item(at) {
                    out.extend(item_field_changes(at, previous, value));
                } else {
                    out.push(Change::Set(at.clone(), value.clone()));
                }
            }
            Some(_) => {}
        }
    }
    for (at, value) in &old.entries {
        if !new.entries.contains_key(at) {
            let hint = if is_item(at) {
                old.hint(at, value)
            } else {
                None
            };
            out.push(Change::Del(at.clone(), hint));
        }
    }
    out
}

const CHARACTER_FIELDS: [&str; 3] = ["level", "ascension", "constellation"];
const TALENTS: [&str; 3] = ["auto", "skill", "burst"];

/// A changed item as field changes; a character that changed anywhere the
/// contract has no field path for is added again whole.
fn item_field_changes(at: &Path, old: &Value, new: &Value) -> Vec<Change> {
    let (Some(old), Some(new)) = (old.as_object(), new.as_object()) else {
        return vec![Change::Add(at.clone(), new.clone())];
    };
    let field = |name: &str| {
        let mut path = at.clone();
        path.push(name.to_string());
        path
    };
    let mut out = Vec::new();
    if at[0] == "characters" {
        let empty = Map::new();
        let old_talent = old
            .get("talent")
            .and_then(Value::as_object)
            .unwrap_or(&empty);
        let new_talent = new
            .get("talent")
            .and_then(Value::as_object)
            .unwrap_or(&empty);
        let other_change = new.keys().chain(old.keys()).any(|key| {
            !CHARACTER_FIELDS.contains(&key.as_str())
                && key != "talent"
                && old.get(key) != new.get(key)
        }) || new_talent.keys().chain(old_talent.keys()).any(|key| {
            !TALENTS.contains(&key.as_str()) && old_talent.get(key) != new_talent.get(key)
        }) || CHARACTER_FIELDS
            .iter()
            .any(|name| new.get(*name).is_none_or(|value| !value.is_number()))
            || TALENTS
                .iter()
                .any(|name| new_talent.get(*name).is_none_or(|value| !value.is_number()));
        if other_change {
            return vec![Change::Add(at.clone(), Value::Object(new.clone()))];
        }
        for name in CHARACTER_FIELDS {
            if old.get(name) != new.get(name) {
                out.push(Change::Set(field(name), new[name].clone()));
            }
        }
        for name in TALENTS {
            if old_talent.get(name) != new_talent.get(name) {
                let mut path = field("talent");
                path.push(name.to_string());
                out.push(Change::Set(path, new_talent[name].clone()));
            }
        }
        return out;
    }
    for (name, value) in new {
        if old.get(name) != Some(value) {
            out.push(Change::Set(field(name), value.clone()));
        }
    }
    for name in old.keys() {
        if !new.contains_key(name) {
            out.push(Change::Del(field(name), None));
        }
    }
    out
}

/// Whether a batch holds an "important" change (plan §4.3): a character's
/// level, ascension, talent, constellation or a new character; a weapon's
/// level, ascension or refinement; an artifact's level; a new 5★ item.
pub fn is_important(changes: &[Change], new: &Keyed) -> bool {
    changes.iter().any(|change| {
        let at = change.path();
        match (change, at[0].as_str(), at.get(2).map(String::as_str)) {
            (Change::Del(..), ..) => false,
            (_, "characters", _) => true,
            (Change::Set(..), "weapons", Some("level" | "ascension" | "refinement")) => true,
            (Change::Set(..), "artifacts", Some("level")) => true,
            (Change::Add(_, item), "artifacts", None) => item["rarity"] == json!(5),
            (Change::Add(..), "weapons", None) => new
                .hints
                .get(at)
                .is_some_and(|hint| hint["rarity"] == json!(5)),
            _ => false,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/good-x-delta.json");

    fn fixture() -> Value {
        serde_json::from_str(FIXTURE).unwrap()
    }

    /// Every number as an f64, so `14.0` and `14` compare equal.
    fn numeric(value: &Value) -> Value {
        match value {
            Value::Number(number) => json!(number.as_f64().unwrap()),
            Value::Array(items) => Value::Array(items.iter().map(numeric).collect()),
            Value::Object(fields) => Value::Object(
                fields
                    .iter()
                    .map(|(key, value)| (key.clone(), numeric(value)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    fn sorted(changes: &[Change]) -> Vec<String> {
        let mut out: Vec<String> = changes
            .iter()
            .map(|change| numeric(&serde_json::to_value(change).unwrap()).to_string())
            .collect();
        out.sort();
        out
    }

    fn rarity_of(good: &Value) -> impl Fn(&str) -> Option<u32> {
        // The fixture's weapons: the rarity GOOD leaves out, by key.
        let rarities: BTreeMap<String, u32> = good["weapons"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| {
                let rarity = match w["key"].as_str().unwrap() {
                    "DullBlade" => 1,
                    _ => 5,
                };
                (w["gi_guid"].as_str().unwrap().to_string(), rarity)
            })
            .collect();
        move |guid| rarities.get(guid).copied()
    }

    #[test]
    fn the_contract_fixture_diffs_to_its_own_changes() {
        let fixture = fixture();
        let base: Good = serde_json::from_value(fixture["base"].clone()).unwrap();
        let result: Good = serde_json::from_value(fixture["result"].clone()).unwrap();
        let old = Keyed::of(&base, rarity_of(&fixture["base"]));
        let new = Keyed::of(&result, rarity_of(&fixture["result"]));
        let delta: GoodDelta = serde_json::from_value(fixture["delta"].clone()).unwrap();
        assert_eq!(sorted(&diff(&old, &new)), sorted(&delta.changes));
        assert_eq!(Some(Sum::of(&result)), delta.sum);
    }

    #[test]
    fn the_contract_fixture_round_trips() {
        let fixture = fixture();
        let delta: GoodDelta = serde_json::from_value(fixture["delta"].clone()).unwrap();
        assert_eq!(delta.format, DELTA_FORMAT);
        assert_eq!(
            numeric(&serde_json::to_value(&delta).unwrap()),
            numeric(&fixture["delta"])
        );
    }

    #[test]
    fn a_change_is_a_tuple() {
        let set = Change::Set(path(&["materials", "Mora"]), json!(5));
        assert_eq!(
            serde_json::to_string(&set).unwrap(),
            r#"["set",["materials","Mora"],5]"#
        );
        let del = Change::Del(path(&["materials", "Mora"]), None);
        assert_eq!(
            serde_json::to_string(&del).unwrap(),
            r#"["del",["materials","Mora"]]"#
        );
        let back: Change = serde_json::from_str(r#"["del",["weapons",12],{"rarity":3}]"#).unwrap();
        assert_eq!(
            back,
            Change::Del(path(&["weapons", "12"]), Some(json!({ "rarity": 3 })))
        );
        assert!(serde_json::from_str::<Change>(r#"["put",["a"],1]"#).is_err());
        assert!(serde_json::from_str::<Change>(r#"["set",["a"]]"#).is_err());
    }

    fn keyed(value: Value) -> Keyed {
        let mut keyed = Keyed::default();
        keyed.read(&value, &|_| Some(4));
        keyed
    }

    fn good(extra: Value) -> Value {
        let mut base = json!({
            "format": "GOOD", "version": 3, "source": "Irminsul",
            "characters": [], "artifacts": [], "weapons": [], "materials": {}
        });
        for (key, value) in extra.as_object().unwrap() {
            base[key] = value.clone();
        }
        base
    }

    fn artifact(guid: &str, level: u32, location: &str, lock: bool) -> Value {
        json!({
            "setKey": "GoldenTroupe", "slotKey": "plume", "level": level, "rarity": 5,
            "mainStatKey": "atk", "location": location, "lock": lock,
            "substats": [{ "key": "critRate_", "value": 3.9, "initialValue": 3.9 }],
            "totalRolls": 4, "astralMark": false, "elixerCrafted": false,
            "unactivatedSubstats": [], "gi_guid": guid
        })
    }

    #[test]
    fn a_material_count_is_a_set_and_a_vanished_one_a_del() {
        let old = keyed(good(json!({ "materials": { "Mora": 10, "HerosWit": 3 } })));
        let new = keyed(good(json!({ "materials": { "Mora": 12, "Fish": 1 } })));
        assert_eq!(
            diff(&old, &new),
            vec![
                Change::Set(path(&["materials", "Fish"]), json!(1)),
                Change::Set(path(&["materials", "Mora"]), json!(12)),
                Change::Del(path(&["materials", "HerosWit"]), None),
            ]
        );
    }

    #[test]
    fn a_character_level_up_and_talent_are_field_sets() {
        let character = |level: u32, burst: u32| {
            json!({ "key": "Furina", "level": level, "constellation": 0, "ascension": 6,
                    "talent": { "auto": 1, "skill": 9, "burst": burst } })
        };
        let old = keyed(good(json!({ "characters": [character(80, 8)] })));
        let new = keyed(good(json!({ "characters": [character(90, 9)] })));
        assert_eq!(
            diff(&old, &new),
            vec![
                Change::Set(path(&["characters", "Furina", "level"]), json!(90)),
                Change::Set(path(&["characters", "Furina", "talent", "burst"]), json!(9)),
            ]
        );
        assert!(is_important(&diff(&old, &new), &new));
    }

    #[test]
    fn a_new_character_is_added_whole() {
        let nahida = json!({ "key": "Nahida", "level": 1, "constellation": 0, "ascension": 0,
                             "talent": { "auto": 1, "skill": 1, "burst": 1 } });
        let old = keyed(good(json!({})));
        let new = keyed(good(json!({ "characters": [nahida.clone()] })));
        assert_eq!(
            diff(&old, &new),
            vec![Change::Add(path(&["characters", "Nahida"]), nahida)]
        );
    }

    #[test]
    fn an_artifact_changes_field_by_field_and_never_as_del_plus_add() {
        let old = keyed(good(json!({ "artifacts": [artifact("7", 16, "", false)] })));
        let new = keyed(good(
            json!({ "artifacts": [artifact("7", 20, "Furina", true)] }),
        ));
        assert_eq!(
            diff(&old, &new),
            vec![
                Change::Set(path(&["artifacts", "7", "level"]), json!(20)),
                Change::Set(path(&["artifacts", "7", "location"]), json!("Furina")),
                Change::Set(path(&["artifacts", "7", "lock"]), json!(true)),
            ]
        );
    }

    #[test]
    fn items_come_and_go_with_a_rarity_hint() {
        let weapon = json!({ "key": "DullBlade", "level": 1, "ascension": 0, "refinement": 1,
                             "location": "", "lock": false, "gi_guid": "9" });
        let old = keyed(good(
            json!({ "artifacts": [artifact("7", 0, "", false)], "weapons": [weapon] }),
        ));
        let new = keyed(good(json!({ "artifacts": [artifact("8", 0, "", false)] })));
        let changes = diff(&old, &new);
        assert_eq!(changes.len(), 3);
        assert!(matches!(&changes[0], Change::Add(at, _) if at == &path(&["artifacts", "8"])));
        assert_eq!(
            changes[1],
            Change::Del(path(&["artifacts", "7"]), Some(json!({ "rarity": 5 })))
        );
        assert_eq!(
            changes[2],
            Change::Del(path(&["weapons", "9"]), Some(json!({ "rarity": 4 })))
        );
        // A new 5★ is important; a delete never is.
        assert!(is_important(&changes, &new));
        assert!(!is_important(&changes[1..], &new));
    }

    #[test]
    fn items_without_a_guid_stay_out_of_the_journal() {
        let mut no_guid = artifact("7", 0, "", false);
        no_guid.as_object_mut().unwrap().remove("gi_guid");
        let old = keyed(good(json!({})));
        let new = keyed(good(json!({ "artifacts": [no_guid] })));
        assert!(diff(&old, &new).is_empty());
    }

    #[test]
    fn a_finished_achievement_is_its_time_or_zero() {
        let old = keyed(good(json!({ "gi_achievements": [81000] })));
        let new = keyed(good(json!({
            "gi_achievements": [81000, 81001, 81002],
            "gi_achievement_times": { "81001": 1_792_000_000 }
        })));
        assert_eq!(
            diff(&old, &new),
            vec![
                Change::Set(path(&["achievements", "81001"]), json!(1_792_000_000)),
                Change::Set(path(&["achievements", "81002"]), json!(0)),
            ]
        );
    }

    #[test]
    fn the_diff_is_deterministic_and_empty_for_the_same_state() {
        let state = good(json!({
            "materials": { "Mora": 1, "Fish": 2, "Apple": 3 },
            "artifacts": [artifact("7", 0, "", false), artifact("8", 4, "", true)],
            "gi_player": { "uid": 812_345_678, "resin": 20 }
        }));
        assert!(diff(&keyed(state.clone()), &keyed(state.clone())).is_empty());
        let empty = keyed(good(json!({})));
        assert_eq!(
            diff(&empty, &keyed(state.clone())),
            diff(&empty, &keyed(state))
        );
    }

    /// A synthetic journal for the tracker's replay check, covering every
    /// path kind the recordings rarely hold: random edits of the fixture's
    /// base, a batch per step, a state every few steps. Run with
    /// `IRMINSUL_SYNTHETIC_JOURNAL=<out.ndjson> cargo test -- --ignored
    /// synthetic_journal`, then check it like a `--replay-journal` file.
    #[test]
    #[ignore = "writes a file for the tracker's replay check"]
    fn synthetic_journal() {
        use std::io::Write;

        let out = std::env::var("IRMINSUL_SYNTHETIC_JOURNAL").expect("set the output path");
        let mut file = std::fs::File::create(out).unwrap();
        let mut line = |value: Value| writeln!(file, "{value}").unwrap();
        let fixture = fixture();
        let mut good: Good = serde_json::from_value(fixture["base"].clone()).unwrap();
        let rarity = |_: &str| Some(4);
        let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        line(json!({ "type": "snapshot", "good": as_uploaded(&good) }));
        let mut acked = Keyed::of(&good, rarity);
        let mut guid = 3_488_998_120_056_948_000u64;
        let names = ["Furina", "Escoffier", "Nahida", "Mavuika"];
        let places = ["", "Furina", "Nahida"];
        for step in 1..=400u64 {
            for _ in 0..1 + next(6) {
                match next(12) {
                    0 => {
                        let key = format!("Thing{}", next(30));
                        good.materials.insert(key, next(1000) as u32 + 1);
                    }
                    1 => {
                        let key = format!("Thing{}", next(30));
                        good.materials.remove(&key);
                    }
                    2 if !good.artifacts.is_empty() => {
                        let at = next(good.artifacts.len() as u64) as usize;
                        let piece = &mut good.artifacts[at];
                        piece.level = (piece.level + 4).min(20);
                        piece.substats[0].value += 3.9;
                        piece.total_rolls += 1;
                    }
                    3 if !good.artifacts.is_empty() => {
                        let at = next(good.artifacts.len() as u64) as usize;
                        good.artifacts[at].lock ^= true;
                        good.artifacts[at].location = places[next(3) as usize].to_string();
                    }
                    4 => {
                        let mut piece = good.artifacts.first().cloned().unwrap_or_else(|| {
                            serde_json::from_value(fixture["base"]["artifacts"][0].clone()).unwrap()
                        });
                        guid += 1;
                        piece.gi_guid = Some(guid.to_string());
                        piece.level = 0;
                        piece.astral_mark = next(2) == 0;
                        good.artifacts.push(piece);
                    }
                    5 if good.artifacts.len() > 1 => {
                        let at = next(good.artifacts.len() as u64) as usize;
                        good.artifacts.remove(at);
                    }
                    6 if !good.weapons.is_empty() => {
                        let at = next(good.weapons.len() as u64) as usize;
                        good.weapons[at].refinement = 1 + next(5) as u32;
                        good.weapons[at].level = 1 + next(90) as u32;
                    }
                    7 => {
                        let key = names[next(4) as usize];
                        match good.characters.iter_mut().find(|c| c.key == key) {
                            Some(character) => {
                                character.level = 1 + next(90) as u32;
                                character.talent.burst = 1 + next(10) as u32;
                                character.constellation = next(7) as u32;
                            }
                            None => good.characters.push(crate::good::Character {
                                key: key.to_string(),
                                level: 1,
                                constellation: 0,
                                ascension: 0,
                                talent: crate::good::TalentLevel {
                                    auto: 1,
                                    skill: 1,
                                    burst: 1,
                                },
                            }),
                        }
                    }
                    8 => {
                        let id = 81_000 + next(40) as u32;
                        let ids = good.gi_achievements.get_or_insert_with(Vec::new);
                        if !ids.contains(&id) {
                            ids.push(id);
                            ids.sort_unstable();
                        }
                        if next(2) == 0 {
                            good.gi_achievement_times
                                .get_or_insert_with(BTreeMap::new)
                                .insert(id, 1_792_000_000 + step as u32);
                        }
                    }
                    9 => {
                        let book = good.gi_anecdotes.as_mut().unwrap();
                        let id = 100_000 + next(20) as u32;
                        let state = [0, 2, 3][next(3) as usize];
                        book.anecdotes.insert(
                            id,
                            crate::good::GiAnecdote {
                                state,
                                finish_count: next(3) as u32,
                            },
                        );
                        book.reward = Some(crate::good::GiAnecdoteReward {
                            index: 0,
                            progress: next(10) as u32,
                            target: 10,
                        });
                        if next(3) == 0 {
                            book.unlocked_areas.push(3 + next(5) as u32);
                            book.unlocked_areas.sort_unstable();
                            book.unlocked_areas.dedup();
                        }
                    }
                    10 => {
                        let player = good.gi_player.as_mut().unwrap();
                        player.resin = Some(next(200) as u32);
                        player.ar_exp = if next(4) == 0 {
                            None
                        } else {
                            Some(next(5000) as u32)
                        };
                    }
                    _ => {
                        let extras = good.gi_characters.get_or_insert_with(BTreeMap::new);
                        let key = names[next(2) as usize * 2].to_string();
                        if next(4) == 0 {
                            extras.remove(&key);
                        } else {
                            extras.entry(key).or_default().friendship = Some(1 + next(10) as u32);
                        }
                    }
                }
            }
            let now = Keyed::of(&good, rarity);
            let mut batch = GoodDelta::new(812_345_678, "SYNTHETIC0000001", step, "synth", step);
            batch.changes = diff(&acked, &now);
            batch.sum = Some(Sum::of(&good));
            line(json!({ "type": "batch", "delta": batch }));
            acked = now;
            if step % 25 == 0 {
                line(json!({ "type": "state", "good": as_uploaded(&good) }));
            }
        }
    }

    #[test]
    fn the_sum_counts_like_the_trackers_summary() {
        let fixture = fixture();
        let result: Good = serde_json::from_value(fixture["result"].clone()).unwrap();
        let sum = Sum::of(&result);
        assert_eq!(sum.mora, 48_211_930);
        assert_eq!(sum.materials, 4);
        let mut spare: Good = serde_json::from_value(fixture["base"].clone()).unwrap();
        // The 4★ flower is unlocked and unequipped.
        assert_eq!(Sum::of(&spare).artifact4, 1);
        spare.artifacts[1].lock = true;
        assert_eq!(Sum::of(&spare).artifact4, 0);
    }
}
