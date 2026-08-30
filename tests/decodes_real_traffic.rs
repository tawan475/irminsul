//! End-to-end tests that a well-formed capture still decodes.
//!
//! The audit work touched packet parsing, key lookup and every matcher
//! heuristic, and all of those failure modes are silent: a matcher that stops
//! recognising a packet does not crash, it just exports nothing, and the user
//! finds out when their inventory never appears in the tracker. A suite made
//! only of "hostile input is rejected" tests passes happily in that state, so
//! these drive the whole chain -- Ethernet -> IP -> UDP -> KCP -> XOR ->
//! `GameCommand` -> matcher -- with traffic shaped like the real thing and
//! assert the payload comes back out.
//!
//! Encryption here is the game's own construction (XOR against a 4096-byte
//! keystream, keyed by version) with a key supplied through the public
//! `set_initial_keys`, so no private API is needed to reach the decrypt path.

use std::collections::HashMap;

use auto_artifactarium::r#gen::protos::{
    AvatarDataNotify, AvatarInfo, Equip, Item, Material, PacketHead, PacketWithItems,
    PlayerPropertyNotify, PropValue, Reliquary,
};
use auto_artifactarium::{
    CommandMatch, GameCommand, GamePacket, GameSniffer, classify_command, matches_avatar_packet,
    matches_item_packet, matches_player_property_packet,
};
use protobuf::Message;

/// Key version this fixture registers under.
///
/// `lookup_initial_key` derives the version from the first two bytes of the
/// ciphertext XOR the magic `0x4567`, and the plaintext's first two bytes *are*
/// the magic, so the version a key answers to is simply its own first two bytes.
const KEY_VERSION: u16 = 0x1234;

/// A non-trivial 4096-byte keystream whose first two bytes encode [`KEY_VERSION`].
///
/// Deliberately not all zeroes: a zero key makes ciphertext equal plaintext and
/// would let a broken XOR path pass.
fn test_key() -> Vec<u8> {
    let mut key = vec![0u8; 4096];
    key[0] = (KEY_VERSION >> 8) as u8;
    key[1] = KEY_VERSION as u8;
    // A small LCG, so the keystream is deterministic but not degenerate.
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    for byte in key.iter_mut().skip(2) {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *byte = (state >> 33) as u8;
    }
    key
}

fn encrypt(key: &[u8], plain: &mut [u8]) {
    for (i, byte) in plain.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

/// A plaintext `GameCommand` on the wire: magic, ids, lengths, header, payload,
/// magic.
fn command_bytes(command_id: u16, header: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x45u8, 0x67];
    out.extend(command_id.to_be_bytes());
    out.extend((header.len() as u16).to_be_bytes());
    out.extend((payload.len() as u32).to_be_bytes());
    out.extend_from_slice(header);
    out.extend_from_slice(payload);
    out.extend([0x89, 0xAB]);
    out
}

/// A game-format KCP push segment: the standard 24-byte header plus the two
/// extra 4-byte fields the game inserts at `4..8` and `28..32`.
fn push_segment(conv: u32, sn: u32, content: &[u8]) -> Vec<u8> {
    let mut seg = Vec::new();
    seg.extend_from_slice(&conv.to_le_bytes());
    seg.extend_from_slice(&[0xAA; 4]);
    seg.push(81); // cmd = KCP_CMD_PUSH
    seg.push(0); // frg = 0: a whole message in one segment
    seg.extend_from_slice(&1024u16.to_le_bytes()); // wnd
    seg.extend_from_slice(&0u32.to_le_bytes()); // ts
    seg.extend_from_slice(&sn.to_le_bytes());
    seg.extend_from_slice(&0u32.to_le_bytes()); // una
    seg.extend_from_slice(&(content.len() as u32).to_le_bytes());
    seg.extend_from_slice(&[0xBB; 4]);
    seg.extend_from_slice(content);
    seg
}

/// Ethernet II / IPv4 / UDP frame from a game port, so the sniffer reads it as
/// server-to-client traffic.
fn game_frame(payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
    p.extend_from_slice(&[6, 7, 8, 9, 10, 11]);
    p.extend_from_slice(&[0x08, 0x00]);
    p.push(0x45);
    p.push(0x00);
    p.extend_from_slice(&((20 + 8 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&[0x40, 0x00]);
    p.push(64);
    p.push(17);
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&[192, 168, 1, 1]);
    p.extend_from_slice(&[192, 168, 1, 2]);
    p.extend_from_slice(&22101u16.to_be_bytes());
    p.extend_from_slice(&40000u16.to_be_bytes());
    p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    p
}

/// A capture of one connection, handing out KCP sequence numbers in order.
struct Capture {
    sniffer: GameSniffer,
    key: Vec<u8>,
    next_sn: u32,
}

impl Capture {
    fn new() -> Self {
        let key = test_key();
        Capture {
            sniffer: GameSniffer::new()
                .set_initial_keys(HashMap::from([(KEY_VERSION, key.clone())])),
            key,
            next_sn: 0,
        }
    }

    /// Encrypt one command, wrap it in KCP and UDP, and feed it to the sniffer.
    fn send(&mut self, command_id: u16, header: &[u8], payload: &[u8]) -> Vec<GameCommand> {
        let mut cmd = command_bytes(command_id, header, payload);
        encrypt(&self.key, &mut cmd);
        let seg = push_segment(0x4321, self.next_sn, &cmd);
        self.next_sn += 1;

        match self.sniffer.receive_packet(game_frame(&seg)) {
            Some(GamePacket::Commands(commands)) => commands,
            Some(GamePacket::Connection(_)) => {
                panic!("frame decoded as connection management, not as commands")
            }
            None => panic!("frame was dropped before it reached the kcp layer"),
        }
    }

    /// Send one command and require exactly one command back.
    fn send_one(&mut self, command_id: u16, header: &[u8], payload: &[u8]) -> GameCommand {
        let mut commands = self.send(command_id, header, payload);
        assert_eq!(commands.len(), 1, "expected exactly one command");
        commands.remove(0)
    }
}

/// A realistic `PacketHead`, the envelope every command carries.
fn packet_head(packet_id: u32, sent_ms: u64) -> Vec<u8> {
    let mut head = PacketHead::new();
    head.packet_id = packet_id;
    head.client_sequence_id = 42;
    head.sent_ms = sent_ms;
    head.user_id = 800_000_001;
    head.write_to_bytes().unwrap()
}

fn prop(type_: u32, val: i64) -> PropValue {
    let mut prop = PropValue::new();
    prop.type_ = type_;
    prop.val = val;
    prop
}

// -- the whole chain -----------------------------------------------------------

/// The load-bearing test: a `PlayerStoreNotify`-shaped inventory goes in as
/// encrypted bytes on a synthetic wire and comes back out as items.
#[test]
fn an_inventory_capture_decodes_into_items() {
    let mut store = PacketWithItems::new();
    for i in 0..12u32 {
        let mut item = Item::new();
        item.item_id = 100_000 + i;
        item.guid = 0x1000_0000_0000_0000 + u64::from(i);
        let mut material = Material::new();
        material.count = 10 + i;
        item.set_material(material);
        store.items.push(item);
    }
    // One artifact, so the equip arm is exercised too.
    let mut artifact = Item::new();
    artifact.item_id = 51522;
    artifact.guid = 0x2000_0000_0000_0000;
    let mut reliquary = Reliquary::new();
    reliquary.level = 21;
    reliquary.main_prop_id = 15001;
    reliquary.append_prop_id_list = vec![501_221, 501_201];
    let mut equip = Equip::new();
    equip.is_locked = true;
    equip.set_reliquary(reliquary);
    artifact.set_equip(equip);
    store.items.push(artifact);

    let payload = store.write_to_bytes().unwrap();
    let mut capture = Capture::new();
    let command = capture.send_one(8132, &packet_head(8132, 1_756_400_000_000), &payload);

    assert_eq!(command.command_id, 8132);
    assert_eq!(
        command.proto_data, payload,
        "payload survived the round trip"
    );

    let items = matches_item_packet(&command).expect("a 13-item store notify must be recognised");
    assert_eq!(items.len(), 13);
    assert_eq!(items[0].item_id, 100_000);
    assert_eq!(items[0].guid, 0x1000_0000_0000_0000);
    assert_eq!(items[0].material().count, 10);
    assert_eq!(items[12].equip().reliquary().level, 21);

    // The same command through the single-entry-point API.
    match classify_command(&command) {
        Some(CommandMatch::Items(items)) => assert_eq!(items.len(), 13),
        other => panic!("classify_command said {:?}, expected items", other),
    }
}

/// A character roster decodes, including the small-roster case a new account
/// produces -- the matcher deliberately has no minimum size.
#[test]
fn an_avatar_capture_decodes_into_a_roster() {
    for count in [1u32, 3, 40] {
        let mut notify = AvatarDataNotify::new();
        for i in 0..count {
            let mut avatar = AvatarInfo::new();
            avatar.avatar_id = 10_000_002 + i;
            avatar.guid = 0x3000_0000_0000_0000 + u64::from(i);
            avatar.prop_map.insert(4001, prop(4001, 90)); // level
            avatar.prop_map.insert(1002, prop(1002, 6)); // ascension
            avatar.skill_depot_id = 501 + i;
            notify.avatar_list.push(avatar);
        }

        let payload = notify.write_to_bytes().unwrap();
        let mut capture = Capture::new();
        let command = capture.send_one(6586, &packet_head(6586, 1_756_400_001_000), &payload);

        let avatars =
            matches_avatar_packet(&command).unwrap_or_else(|| panic!("roster of {count} rejected"));
        assert_eq!(avatars.len() as u32, count);
        assert_eq!(avatars[0].avatar_id, 10_000_002);
        assert_eq!(avatars[0].prop_map[&4001].val, 90);
    }
}

/// Player properties decode, and the values come back from the declared
/// `PropValue` fields rather than from guesswork.
#[test]
fn a_property_capture_decodes_into_properties() {
    let mut notify = PlayerPropertyNotify::new();
    notify.prop_map1.insert(10015, prop(10015, 60)); // world level
    notify.prop_map1.insert(10016, prop(10016, 0)); // a zero: still a value
    notify.prop_map1.insert(1002, prop(1002, 160)); // resin
    notify.prop_map1.insert(1022, prop(1022, 1022)); // value == its own id
    notify.prop_map1.insert(1004, prop(1004, 9_999_999_999)); // Mora, capped
    notify.prop_map1.insert(1005, prop(1005, 2_400_000));

    let payload = notify.write_to_bytes().unwrap();
    let mut capture = Capture::new();
    let command = capture.send_one(2643, &packet_head(2643, 1_756_400_002_000), &payload);

    let properties =
        matches_player_property_packet(&command).expect("a six-property notify must be recognised");
    assert_eq!(properties.len(), 6);
    assert_eq!(properties[&10015], 60);
    assert_eq!(
        properties[&10016], 0,
        "a property worth zero is still a property"
    );
    assert_eq!(
        properties[&1022], 1022,
        "a value equal to its own id survives"
    );
    assert_eq!(
        properties[&1004], 9_999_999_999,
        "Mora at its cap does not fit in u32 and must not be truncated"
    );
}

/// The envelope is split off the payload: `proto_header` is the `PacketHead`,
/// `proto_data` is only the message. Before the split, `PacketHead`'s own fields
/// reached the matchers as top-level payload fields.
#[test]
fn the_packet_head_is_separated_from_the_payload() {
    let mut notify = AvatarDataNotify::new();
    let mut avatar = AvatarInfo::new();
    avatar.avatar_id = 10_000_007;
    avatar.guid = 7;
    avatar.prop_map.insert(4001, prop(4001, 80));
    notify.avatar_list.push(avatar);
    let payload = notify.write_to_bytes().unwrap();

    let header = packet_head(6586, 1_756_400_003_000);
    let mut capture = Capture::new();
    let command = capture.send_one(6586, &header, &payload);

    assert_eq!(command.proto_header, header);
    assert_eq!(command.proto_data, payload);
    assert_eq!(command.header_len as usize, header.len());
    assert_eq!(command.data_len as usize, payload.len());

    let head: PacketHead = command
        .parse_header()
        .expect("the header parses as a PacketHead");
    assert_eq!(head.packet_id, 6586);
    assert_eq!(head.sent_ms, 1_756_400_003_000);
    assert_eq!(head.user_id, 800_000_001);

    // And the payload alone is what the matchers see.
    assert_eq!(matches_avatar_packet(&command).unwrap().len(), 1);
}

/// Several commands over one connection, in sequence, on a single sniffer --
/// the shape of a real capture rather than one packet in isolation.
#[test]
fn a_sequence_of_commands_over_one_connection_all_decode() {
    let mut capture = Capture::new();

    let mut store = PacketWithItems::new();
    for i in 0..12u32 {
        let mut item = Item::new();
        item.item_id = 100_000 + i;
        item.guid = 1 + u64::from(i);
        let mut material = Material::new();
        material.count = 1;
        item.set_material(material);
        store.items.push(item);
    }
    let store_bytes = store.write_to_bytes().unwrap();

    let mut roster = AvatarDataNotify::new();
    let mut avatar = AvatarInfo::new();
    avatar.avatar_id = 10_000_021;
    avatar.guid = 99;
    avatar.prop_map.insert(4001, prop(4001, 90));
    roster.avatar_list.push(avatar);
    let roster_bytes = roster.write_to_bytes().unwrap();

    let mut props = PlayerPropertyNotify::new();
    for id in [10015u32, 1002, 1004, 1005, 1006] {
        props.prop_map1.insert(id, prop(id, i64::from(id) * 2));
    }
    let props_bytes = props.write_to_bytes().unwrap();

    let kinds: Vec<&'static str> = [
        (8132u16, store_bytes),
        (6586, roster_bytes),
        (2643, props_bytes),
    ]
    .into_iter()
    .map(|(id, payload)| {
        let command =
            capture.send_one(id, &packet_head(u32::from(id), 1_756_400_004_000), &payload);
        classify_command(&command)
            .unwrap_or_else(|| panic!("command {id} was not recognised"))
            .kind()
    })
    .collect();

    assert_eq!(kinds, ["items", "avatars", "properties"]);
}
