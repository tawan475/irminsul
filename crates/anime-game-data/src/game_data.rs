use serde::Deserialize;

// Starting with the 7.0.0 data dump, fields holding their default value
// (0, false, "", or the first enum variant) are omitted from the JSON
// entirely.  All fields are marked `#[serde(default)]` so entries missing
// them still deserialize, with optional id fields typed as `Option`.

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvatarExcelConfigDataEntry {
    #[serde(default)]
    pub id: u32,
    #[serde(default)]
    pub name_text_map_hash: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvatarSkillDepotExcelConfigDataEntry {
    #[serde(default)]
    pub energy_skill: Option<u32>,
    #[serde(default)]
    skills: Vec<u32>,
}

impl AvatarSkillDepotExcelConfigDataEntry {
    // Skill slots hold 0 as a placeholder for empty slots.
    pub fn skill(&self, index: usize) -> Option<u32> {
        self.skills.get(index).copied().filter(|&id| id != 0)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvatarSkillExcelConfigDataEntry {
    #[serde(default)]
    pub cost_elem_type: Option<String>,
    #[serde(default)]
    pub id: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConstValueExcelConfigDataEntry {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EquipAffixExcelConfigDataEntry {
    #[serde(default)]
    pub id: u32,
    #[serde(default)]
    pub name_text_map_hash: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaterialExcelConfigDataEntry {
    #[serde(default)]
    pub id: u32,
    #[serde(default)]
    pub name_text_map_hash: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReliquaryAffixExcelConfigDataEntry {
    #[serde(default)]
    pub id: u32,
    #[serde(default)]
    pub prop_type: String,
    #[serde(default)]
    pub prop_value: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReliquaryExcelConfigDataEntry {
    #[serde(default)]
    pub equip_type: String,
    #[serde(default)]
    pub id: u32,
    #[serde(default)]
    pub rank_level: u32,
    #[serde(default)]
    pub set_id: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReliquaryMainPropExcelConfigDataEntry {
    #[serde(default)]
    pub id: u32,
    #[serde(default)]
    pub prop_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReliquarySetExcelConfigDataEntry {
    #[serde(default)]
    pub equip_affix_id: Option<u32>,
    #[serde(default)]
    pub set_id: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WeaponExcelConfigDataEntry {
    #[serde(default)]
    pub id: u32,
    #[serde(default)]
    pub name_text_map_hash: u32,
    #[serde(default)]
    pub rank_level: u32,
}
