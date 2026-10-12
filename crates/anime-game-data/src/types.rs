use std::str::FromStr;

use anyhow::{Error, anyhow};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Affix {
    pub property: Property,
    pub value: f64,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Artifact {
    pub set: String,
    pub slot: ArtifactSlot,
    pub rarity: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ArtifactSlot {
    Flower,
    Plume,
    Sands,
    Goblet,
    Circlet,
}

impl ArtifactSlot {
    pub fn from_game_data_name(name: &str) -> Option<Self> {
        match name {
            "EQUIP_BRACER" => Some(Self::Flower),
            "EQUIP_NECKLACE" => Some(Self::Plume),
            "EQUIP_SHOES" => Some(Self::Sands),
            "EQUIP_RING" => Some(Self::Goblet),
            "EQUIP_DRESS" => Some(Self::Circlet),
            _ => None,
        }
    }

    pub fn good_name(&self) -> &str {
        match self {
            ArtifactSlot::Flower => "flower",
            ArtifactSlot::Plume => "plume",
            ArtifactSlot::Sands => "sands",
            ArtifactSlot::Goblet => "goblet",
            ArtifactSlot::Circlet => "circlet",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Element {
    Anemo,
    Geo,
    Electro,
    Hydro,
    Pyro,
    Cryo,
    Dendro,
}

impl AsRef<str> for Element {
    fn as_ref(&self) -> &str {
        match self {
            Element::Anemo => "Anemo",
            Element::Geo => "Geo",
            Element::Electro => "Electro",
            Element::Hydro => "Hydro",
            Element::Pyro => "Pyro",
            Element::Cryo => "Cryo",
            Element::Dendro => "Dendro",
        }
    }
}

impl FromStr for Element {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Wind" => Ok(Self::Anemo),
            "Rock" => Ok(Self::Geo),
            "Electric" => Ok(Self::Electro),
            "Water" => Ok(Self::Hydro),
            "Fire" => Ok(Self::Pyro),
            "Ice" => Ok(Self::Cryo),
            "Grass" => Ok(Self::Dendro),
            _ => Err(anyhow!("unknown element {s}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Property {
    Hp,
    HpPercent,
    Attack,
    AttackPercent,
    Defense,
    DefensePercent,
    ElementalMastery,
    EnergyRecharge,
    Healing,
    CritRate,
    CritDamage,
    PhysicalDamage,
    AnemoDamage,
    GeoDamage,
    ElectroDamage,
    HydroDamage,
    PyroDamage,
    CryoDamage,
    DendroDamage,
}

impl Property {
    pub fn good_name(&self) -> &str {
        match self {
            Property::Hp => "hp",
            Property::HpPercent => "hp_",
            Property::Attack => "atk",
            Property::AttackPercent => "atk_",
            Property::Defense => "def",
            Property::DefensePercent => "def_",
            Property::ElementalMastery => "eleMas",
            Property::EnergyRecharge => "enerRech_",
            Property::Healing => "heal_",
            Property::CritRate => "critRate_",
            Property::CritDamage => "critDMG_",
            Property::PhysicalDamage => "physical_dmg_",
            Property::AnemoDamage => "anemo_dmg_",
            Property::GeoDamage => "geo_dmg_",
            Property::ElectroDamage => "electro_dmg_",
            Property::HydroDamage => "hydro_dmg_",
            Property::PyroDamage => "pyro_dmg_",
            Property::CryoDamage => "cryo_dmg_",
            Property::DendroDamage => "dendro_dmg_",
        }
    }

    pub fn is_percentage(&self) -> bool {
        matches!(
            self,
            Property::HpPercent
                | Property::AttackPercent
                | Property::DefensePercent
                | Property::EnergyRecharge
                | Property::Healing
                | Property::CritRate
                | Property::CritDamage
                | Property::PhysicalDamage
                | Property::AnemoDamage
                | Property::GeoDamage
                | Property::ElectroDamage
                | Property::HydroDamage
                | Property::PyroDamage
                | Property::CryoDamage
                | Property::DendroDamage
        )
    }
}

impl FromStr for Property {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "FIGHT_PROP_HP" => Ok(Self::Hp),
            "FIGHT_PROP_HP_PERCENT" => Ok(Self::HpPercent),
            "FIGHT_PROP_ATTACK" => Ok(Self::Attack),
            "FIGHT_PROP_ATTACK_PERCENT" => Ok(Self::AttackPercent),
            "FIGHT_PROP_DEFENSE" => Ok(Self::Defense),
            "FIGHT_PROP_DEFENSE_PERCENT" => Ok(Self::DefensePercent),
            "FIGHT_PROP_ELEMENT_MASTERY" => Ok(Self::ElementalMastery),
            "FIGHT_PROP_CHARGE_EFFICIENCY" => Ok(Self::EnergyRecharge),
            "FIGHT_PROP_HEAL_ADD" => Ok(Self::Healing),
            "FIGHT_PROP_CRITICAL" => Ok(Self::CritRate),
            "FIGHT_PROP_CRITICAL_HURT" => Ok(Self::CritDamage),
            "FIGHT_PROP_PHYSICAL_ADD_HURT" => Ok(Self::PhysicalDamage),
            "FIGHT_PROP_WIND_ADD_HURT" => Ok(Self::AnemoDamage),
            "FIGHT_PROP_ROCK_ADD_HURT" => Ok(Self::GeoDamage),
            "FIGHT_PROP_ELEC_ADD_HURT" => Ok(Self::ElectroDamage),
            "FIGHT_PROP_WATER_ADD_HURT" => Ok(Self::HydroDamage),
            "FIGHT_PROP_FIRE_ADD_HURT" => Ok(Self::PyroDamage),
            "FIGHT_PROP_ICE_ADD_HURT" => Ok(Self::CryoDamage),
            "FIGHT_PROP_GRASS_ADD_HURT" => Ok(Self::DendroDamage),
            _ => Err(anyhow!("unknown property {s}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SkillType {
    Auto,
    Skill,
    Burst,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Weapon {
    pub name: String,
    pub rarity: u32,
}
