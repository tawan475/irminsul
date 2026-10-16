//! Messages read without their schema, for callers that recognise them by the
//! account data they mention.
//!
//! A character's live updates (a talent levelled, a level or an ascension, a
//! constellation, gear moved, a new character) are small messages of a few
//! numbers whose shapes are shared with hundreds of others, so no shape alone
//! can tell them apart. What can is the data: the avatar guid, its skill ids,
//! its current levels. The library only takes the message apart; the caller,
//! which holds the account, decides what it is (irminsul's
//! `PlayerData::apply_avatar_change`).

use protobuf::Message;
use protobuf::UnknownValueRef::{Fixed32, Fixed64, LengthDelimited, Varint};

use crate::GameCommand;
use crate::r#gen::protos::{AvatarInfo, Unk};

/// Guids are minted as `(uid << 32) + counter`, so a guid is at least this.
const MIN_GUID: u64 = 1 << 32;

/// The top level of a message, its fields sorted by kind.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlatMessage {
    /// Varint fields as `(field number, value)`.
    pub varints: Vec<(u32, u64)>,
    /// `map<varint, varint>` fields as `(field number, entries)`, every entry
    /// of one field number together.
    pub maps: Vec<(u32, Vec<(u64, u64)>)>,
    /// Every other length-delimited field, raw.
    pub nested: Vec<(u32, Vec<u8>)>,
}

impl FlatMessage {
    /// The map on `field`, if there is one.
    pub fn map(&self, field: u32) -> Option<&[(u64, u64)]> {
        self.maps
            .iter()
            .find(|(number, _)| *number == field)
            .map(|(_, entries)| entries.as_slice())
    }
}

/// A nested field read as an `AvatarInfo` (how a new character arrives), or
/// `None` if the bytes are not a message. Any message parses as one, so the
/// caller checks the result against the account.
pub fn parse_avatar_info(bytes: &[u8]) -> Option<AvatarInfo> {
    AvatarInfo::parse_from_bytes(bytes).ok()
}

/// `bytes` as a `map<varint, varint>` entry (key on 1, value on 2), if it is
/// exactly that.
fn varint_map_entry(bytes: &[u8]) -> Option<(u64, u64)> {
    let entry = Unk::parse_from_bytes(bytes).ok()?;
    let mut key = None;
    let mut value = None;
    for (number, data) in entry.unknown_fields().iter() {
        match (number, data) {
            (1, Varint(k)) if key.is_none() => key = Some(k),
            (2, Varint(v)) if value.is_none() => value = Some(v),
            _ => return None,
        }
    }
    // proto3 leaves a zero key or value out of the entry.
    if key.is_none() && value.is_none() {
        return None;
    }
    Some((key.unwrap_or(0), value.unwrap_or(0)))
}

/// Take a message apart, or `None` when it cannot be about a character.
///
/// Kept to what a character update can look like, so most traffic stops here:
/// no fixed-width fields (floats are combat and movement), and either a
/// guid-sized varint at the top level or a single nested message beside at
/// most two varints (a new character arrives as one `AvatarInfo` and a flag).
pub fn flat_message(game_command: &GameCommand) -> Option<FlatMessage> {
    let msg = Unk::parse_from_bytes(&game_command.proto_data).ok()?;
    let mut flat = FlatMessage::default();
    for (number, data) in msg.unknown_fields().iter() {
        match data {
            Varint(value) => flat.varints.push((number, value)),
            LengthDelimited(bytes) => match varint_map_entry(bytes) {
                Some(entry) => match flat.maps.iter_mut().find(|(field, _)| *field == number) {
                    Some((_, entries)) => entries.push(entry),
                    None => flat.maps.push((number, vec![entry])),
                },
                None => flat.nested.push((number, bytes.to_vec())),
            },
            Fixed32(_) | Fixed64(_) => return None,
        }
    }
    let has_guid = flat.varints.iter().any(|(_, value)| *value >= MIN_GUID);
    let one_nested = flat.nested.len() == 1 && flat.maps.is_empty() && flat.varints.len() <= 2;
    (has_guid || one_nested).then_some(flat)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn field_varint(tag: u32, value: u64) -> Vec<u8> {
        let mut out = varint(u64::from(tag) << 3);
        out.extend(varint(value));
        out
    }

    fn field_bytes(tag: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = varint((u64::from(tag) << 3) | 2);
        out.extend(varint(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    fn command(payload: Vec<u8>) -> GameCommand {
        GameCommand {
            command_id: 1,
            header_len: 0,
            data_len: payload.len() as u32,
            proto_header: Vec::new(),
            proto_data: payload,
        }
    }

    const GUID: u64 = (812_345_678 << 32) + 5;

    #[test]
    fn a_talent_change_is_taken_apart() {
        let payload = [
            field_varint(3, GUID),
            field_varint(5, 10_024),
            field_varint(10, 9),
            field_varint(14, 8),
        ]
        .concat();
        let mut flat = flat_message(&command(payload)).expect("a guid");
        // Unknown fields come back grouped by number, in no set order.
        flat.varints.sort_unstable();
        assert_eq!(flat.varints, vec![(3, GUID), (5, 10_024), (10, 9), (14, 8)]);
        assert!(flat.maps.is_empty() && flat.nested.is_empty());
    }

    #[test]
    fn a_prop_map_is_read_as_a_map() {
        let entry = |key: u64, value: u64| [field_varint(1, key), field_varint(2, value)].concat();
        let payload = [
            field_varint(1, GUID),
            field_bytes(10, &entry(4001, 80)),
            field_bytes(10, &entry(1002, 6)),
            field_bytes(10, &field_varint(1, 1001)), // EXP 0: proto3 drops the value
        ]
        .concat();
        let flat = flat_message(&command(payload)).expect("a guid");
        assert_eq!(flat.map(10), Some(&[(4001, 80), (1002, 6), (1001, 0)][..]));
    }

    #[test]
    fn traffic_that_cannot_be_a_character_update_is_dropped() {
        // No guid and nothing nested.
        assert!(
            flat_message(&command([field_varint(1, 5), field_varint(2, 6)].concat())).is_none()
        );
        // Floats: combat and movement.
        let mut float = field_varint(1, GUID);
        float.extend([0x15, 0, 0, 0x80, 0x3f]); // field 2, fixed32 1.0
        assert!(flat_message(&command(float)).is_none());
        // One nested message is a possible new character.
        let avatar = [
            field_varint(1, 10000046),
            field_varint(2, GUID),
            field_varint(19, 1),
        ]
        .concat();
        assert!(flat_message(&command(field_bytes(11, &avatar))).is_some());
    }
}
