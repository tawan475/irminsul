//! Regression suite for the crafted-frame panics found in the audit.
//!
//! Every input below is one the audit fed to [`GameSniffer::receive_packet`] and
//! watched abort the process. They are kept here as *positive* assertions -- the
//! frame is ignored or rejected and control returns -- because of where this
//! library sits: irminsul runs it as Administrator over unvalidated bytes off
//! the wire, so anything able to put a datagram on a game port could otherwise
//! take the scanner down with a single packet.
//!
//! These go through the public entry point on purpose. The unit tests in `src/`
//! reach the guards directly; only an integration test proves the whole
//! Ethernet -> IP -> UDP -> KCP -> decrypt -> command chain survives them.

use auto_artifactarium::{GameCommand, GamePacket, GameSniffer};

/// Ethernet II / IPv4 / UDP frame carrying `payload`, built by hand so the exact
/// bytes the audit used are what the test sends.
fn frame(payload: &[u8], sport: u16, dport: u16) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&[0, 1, 2, 3, 4, 5]); // dst mac
    p.extend_from_slice(&[6, 7, 8, 9, 10, 11]); // src mac
    p.extend_from_slice(&[0x08, 0x00]); // ethertype: ipv4
    let total_len = (20 + 8 + payload.len()) as u16;
    p.push(0x45); // version 4, ihl 5
    p.push(0x00);
    p.extend_from_slice(&total_len.to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&[0x40, 0x00]);
    p.push(64); // ttl
    p.push(17); // protocol: udp
    p.extend_from_slice(&[0, 0]); // checksum (not verified on this path)
    p.extend_from_slice(&[192, 168, 1, 1]);
    p.extend_from_slice(&[192, 168, 1, 2]);
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    p
}

/// A frame on a game port, the only kind that gets past the port filter.
fn game_frame(payload: &[u8]) -> Vec<u8> {
    frame(payload, 22101, 40000)
}

/// A sniffer holding the all-zero dispatch key.
///
/// The key version is derived from the first two bytes of the message XOR the
/// magic `0x4567`, so an all-zero key -- which makes ciphertext equal plaintext
/// -- registers under version 0.
fn sniffer_with_zero_key() -> GameSniffer {
    GameSniffer::new().set_initial_keys([(0u16, vec![0u8; 4096])].into_iter().collect())
}

/// Feed one frame and report the commands it produced.
///
/// The assertion that matters here is the implicit one: this function returns.
fn commands(sniffer: &mut GameSniffer, bytes: Vec<u8>) -> Vec<GameCommand> {
    match sniffer.receive_packet(bytes) {
        Some(GamePacket::Commands(commands)) => commands,
        _ => Vec::new(),
    }
}

/// A game-format KCP push segment: the standard 24-byte header plus the two
/// extra 4-byte fields the game inserts at `4..8` and `28..32`.
fn push_segment(conv: u32, sn: u32, frg: u8, content: &[u8]) -> Vec<u8> {
    let mut seg = Vec::new();
    seg.extend_from_slice(&conv.to_le_bytes());
    seg.extend_from_slice(&[0xAA; 4]); // extra field, stripped
    seg.push(81); // cmd = KCP_CMD_PUSH
    seg.push(frg);
    seg.extend_from_slice(&128u16.to_le_bytes()); // wnd
    seg.extend_from_slice(&0u32.to_le_bytes()); // ts
    seg.extend_from_slice(&sn.to_le_bytes());
    seg.extend_from_slice(&0u32.to_le_bytes()); // una
    seg.extend_from_slice(&(content.len() as u32).to_le_bytes());
    seg.extend_from_slice(&[0xBB; 4]); // second extra field, stripped
    seg.extend_from_slice(content);
    seg
}

/// A plaintext command with honest lengths and a 40-byte body.
fn well_formed_command() -> Vec<u8> {
    let mut cmd = vec![0x45u8, 0x67];
    cmd.extend_from_slice(&1u16.to_be_bytes()); // command_id
    cmd.extend_from_slice(&0u16.to_be_bytes()); // header_len
    cmd.extend_from_slice(&40u32.to_be_bytes()); // data_len
    cmd.extend_from_slice(&[0u8; 40]);
    cmd.extend_from_slice(&[0x89, 0xAB]);
    cmd
}

// -- connection.rs: runt UDP payloads -----------------------------------------

/// `parse_connection_packet` read `payload[..4]` before checking the length, so
/// any datagram on a game port shorter than four bytes was fatal. An empty UDP
/// payload is trivially reachable: it is a legal datagram.
#[test]
fn a_runt_udp_payload_is_dropped() {
    for len in 0..4 {
        let mut sniffer = GameSniffer::new();
        assert!(
            commands(&mut sniffer, game_frame(&vec![0u8; len])).is_empty(),
            "payload of {len} byte(s) produced commands"
        );
    }
}

/// Sanity check on the fixture: traffic off the game ports is ignored outright,
/// so the tests above really are exercising the game path.
#[test]
fn a_frame_off_the_game_ports_is_ignored() {
    let mut sniffer = GameSniffer::new();
    assert!(
        sniffer
            .receive_packet(frame(&[1, 2, 3, 4, 5], 1234, 5678))
            .is_none()
    );
}

// -- kcp.rs: segment layout ----------------------------------------------------

/// `validate_kcp_segment` only required more than `KCP_OVERHEAD` (24) bytes,
/// while `reformat_kcp_segments` indexed up to `i + 32`. Anything landing in the
/// 25..=31 gap was read out of bounds; the floor is now the game's real 32-byte
/// header.
#[test]
fn a_segment_shorter_than_the_game_header_is_dropped() {
    for len in 0..32 {
        let mut sniffer = GameSniffer::new();
        let mut seg = vec![0u8; len];
        if len >= 4 {
            seg[0..4].copy_from_slice(&1u32.to_le_bytes());
        }
        assert!(
            commands(&mut sniffer, game_frame(&seg)).is_empty(),
            "segment of {len} byte(s) produced commands"
        );
    }
}

/// `content_len` is read straight out of the datagram and was used as a slice
/// bound with nothing checked against the bytes actually present.
#[test]
fn a_segment_that_lies_about_its_length_is_dropped() {
    for lie in [1u32, 0xFFFF, 0x7FFF_FFFF, 0xFFFF_FFFF] {
        let mut sniffer = GameSniffer::new();
        let mut seg = vec![0u8; 32];
        seg[0..4].copy_from_slice(&1u32.to_le_bytes());
        seg[8] = 81; // KCP_CMD_PUSH
        seg[24..28].copy_from_slice(&lie.to_le_bytes());
        assert!(
            commands(&mut sniffer, game_frame(&seg)).is_empty(),
            "content_len {lie} produced commands"
        );
    }
}

/// The walk advanced by `32 + content_len`, so a datagram whose length is not an
/// exact multiple of the segment layout ran off the end on the trailing partial
/// segment.
#[test]
fn a_trailing_partial_segment_is_dropped() {
    for stray in 1..32usize {
        let mut sniffer = GameSniffer::new();
        let mut seg = vec![0u8; 32 + stray];
        seg[0..4].copy_from_slice(&1u32.to_le_bytes());
        seg[8] = 81;
        seg[24..28].copy_from_slice(&0u32.to_le_bytes());
        assert!(
            commands(&mut sniffer, game_frame(&seg)).is_empty(),
            "{stray} stray trailing byte(s) produced commands"
        );
    }
}

// -- crypto.rs: key lookup on short messages -----------------------------------

/// A zero- or one-byte KCP message reached `lookup_initial_key`, which took
/// `bytes[..2]` unconditionally to read the key version.
#[test]
fn a_kcp_message_too_short_to_carry_a_key_version_is_dropped() {
    for len in 0..2 {
        let mut sniffer = GameSniffer::new();
        let seg = push_segment(1, 0, 0, &vec![0x45u8; len]);
        assert!(
            commands(&mut sniffer, game_frame(&seg)).is_empty(),
            "kcp message of {len} byte(s) produced commands"
        );
    }
}

// -- lib.rs: GameCommand length fields -----------------------------------------

/// `header_len` and `data_len` are attacker-supplied and were used as slice
/// bounds unchecked. Both the largest lie the header can express and a one-byte
/// overshoot of the buffer were fatal.
#[test]
fn a_command_whose_lengths_do_not_fit_is_rejected() {
    // data_len = 0xFFFF_FFF0 on a 12-byte buffer.
    let mut bytes = vec![0x45u8, 0x67, 0x00, 0x01, 0x00, 0x00];
    bytes.extend_from_slice(&0xFFFF_FFF0u32.to_be_bytes());
    bytes.extend_from_slice(&[0x89, 0xAB]);
    assert_eq!(bytes.len(), 12);
    assert!(GameCommand::try_new(bytes).is_none());

    // header_len = 1, data_len = 2: a one-byte overshoot of the same buffer.
    let mut bytes = vec![0x45u8, 0x67, 0x00, 0x01, 0x00, 0x01];
    bytes.extend_from_slice(&2u32.to_be_bytes());
    bytes.extend_from_slice(&[0x89, 0xAB]);
    assert_eq!(bytes.len(), 12);
    assert!(GameCommand::try_new(bytes).is_none());
}

/// The same lie, reached the way an attacker would: through `receive_packet`
/// with no prior sniffer state, using a dispatch key that ships with the app.
#[test]
fn a_command_with_lying_lengths_is_rejected_end_to_end() {
    let mut sniffer = sniffer_with_zero_key();

    let mut cmd = vec![0x45u8, 0x67];
    cmd.extend_from_slice(&1u16.to_be_bytes()); // command_id
    cmd.extend_from_slice(&0u16.to_be_bytes()); // header_len
    cmd.extend_from_slice(&0xFFFF_0000u32.to_be_bytes()); // data_len -- a lie
    cmd.extend_from_slice(&[0u8; 40]);
    cmd.extend_from_slice(&[0x89, 0xAB]);

    assert!(commands(&mut sniffer, game_frame(&push_segment(7, 0, 0, &cmd))).is_empty());
}

// -- breadth ------------------------------------------------------------------

/// Truncation sweep. The cases above are the ones the audit found; this is the
/// generalisation, so a future refactor that reintroduces an unchecked index at
/// some other offset is caught by the suite rather than by a crash report.
#[test]
fn every_truncation_of_a_well_formed_datagram_is_survivable() {
    let full = push_segment(7, 0, 0, &well_formed_command());

    for len in 0..=full.len() {
        let mut sniffer = sniffer_with_zero_key();
        let _ = sniffer.receive_packet(game_frame(&full[..len]));
    }
}

/// Byte-flip sweep over the segment header. Each offset is walked through a
/// handful of hostile values on a fresh sniffer; the only claim being made is
/// that none of them abort.
///
/// This sweep is what found the two remaining panics after the audit's own
/// reproductions were fixed -- both inside the `kcp` dependency, at
/// `frg == 255` and at a sequence number with its top bit set -- so it earns its
/// place ahead of the hand-written cases above.
#[test]
fn a_corrupted_segment_header_never_aborts() {
    let full = push_segment(7, 0, 0, &well_formed_command());

    for offset in 0..32 {
        for value in [0x00u8, 0x01, 0x7F, 0x80, 0xFF] {
            let mut corrupt = full.clone();
            corrupt[offset] = value;
            let mut sniffer = sniffer_with_zero_key();
            let _ = sniffer.receive_packet(game_frame(&corrupt));
        }
    }
}

/// Cross product of every KCP command with hostile fragment indices, sequence
/// numbers and timestamps.
///
/// The `kcp` crate compares sequence numbers and timestamps with non-wrapping
/// `as i32` arithmetic and sizes a fragment count in `u8`, so the interesting
/// values are the ones that straddle those boundaries rather than random noise.
#[test]
fn hostile_header_field_combinations_never_abort() {
    /// `conv(4) extra(4) cmd(1) frg(1) wnd(2) ts(4) sn(4) una(4) len(4) extra(4)`
    fn segment(cmd: u8, frg: u8, wnd: u16, ts: u32, sn: u32, una: u32, content: &[u8]) -> Vec<u8> {
        let mut seg = Vec::new();
        seg.extend_from_slice(&7u32.to_le_bytes());
        seg.extend_from_slice(&[0xAA; 4]);
        seg.push(cmd);
        seg.push(frg);
        seg.extend_from_slice(&wnd.to_le_bytes());
        seg.extend_from_slice(&ts.to_le_bytes());
        seg.extend_from_slice(&sn.to_le_bytes());
        seg.extend_from_slice(&una.to_le_bytes());
        seg.extend_from_slice(&(content.len() as u32).to_le_bytes());
        seg.extend_from_slice(&[0xBB; 4]);
        seg.extend_from_slice(content);
        seg
    }

    const HOSTILE: [u32; 10] = [
        0,
        1,
        1023,
        1024,
        1025,
        0x7FFF_FFFF,
        0x8000_0000,
        0x8000_0400,
        0xFFFF_0000,
        0xFFFF_FFFF,
    ];

    let content = well_formed_command();
    // 81 push, 82 ack, 83 window ask, 84 window tell, plus two undefined ones.
    for cmd in [81u8, 82, 83, 84, 0, 255] {
        for frg in [0u8, 1, 127, 128, 254, 255] {
            let mut sniffer = sniffer_with_zero_key();
            let seg = segment(cmd, frg, 1024, 0, 0, 0, &content);
            let _ = sniffer.receive_packet(game_frame(&seg));
        }
        for value in HOSTILE {
            for seg in [
                segment(cmd, 0, 1024, value, 0, 0, &content), // ts
                segment(cmd, 0, 1024, 0, value, 0, &content), // sn
                segment(cmd, 0, 1024, 0, 0, value, &content), // una
            ] {
                let mut sniffer = sniffer_with_zero_key();
                let _ = sniffer.receive_packet(game_frame(&seg));
            }
        }
        for wnd in [0u16, 1, 1024, u16::MAX] {
            let mut sniffer = sniffer_with_zero_key();
            let seg = segment(cmd, 0, wnd, 0, 0, 0, &content);
            let _ = sniffer.receive_packet(game_frame(&seg));
        }
    }
}

/// A hostile segment sharing a datagram with a good one, in both orders.
#[test]
fn a_hostile_segment_does_not_take_its_neighbours_down() {
    let content = well_formed_command();

    let hostile_frg = push_segment(7, 1, 255, &content);
    let hostile_sn = {
        let mut seg = push_segment(7, 0, 0, &content);
        seg[16..20].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        seg
    };

    for (first, second) in [
        (push_segment(7, 0, 0, &content), hostile_frg.clone()),
        (hostile_frg, push_segment(7, 1, 0, &content)),
        (push_segment(7, 0, 0, &content), hostile_sn.clone()),
        (hostile_sn, push_segment(7, 1, 0, &content)),
    ] {
        let mut datagram = first;
        datagram.extend_from_slice(&second);
        let mut sniffer = sniffer_with_zero_key();
        let _ = sniffer.receive_packet(game_frame(&datagram));
    }
}

/// Pure fuzz: pseudo-random datagrams on a game port, no structure at all.
///
/// Deterministic (fixed seed) so a failure is reproducible and CI cannot flake.
#[test]
fn random_datagrams_never_abort() {
    let mut state: u64 = 0xDEAD_BEEF_1234_5678;
    let mut next = move || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (state >> 33) as u32
    };

    for _ in 0..4000 {
        let len = (next() % 200) as usize;
        let payload: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        let mut sniffer = sniffer_with_zero_key();
        let _ = sniffer.receive_packet(game_frame(&payload));
    }
}

/// Structured fuzz: a valid segment with random bytes sprayed over its header,
/// which reaches far deeper into the reassembler than random noise does.
#[test]
fn random_header_corruption_never_aborts() {
    let base = push_segment(7, 0, 0, &well_formed_command());
    let mut state: u64 = 0x0BAD_C0DE_F00D_1111;
    let mut next = move || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (state >> 33) as u32
    };

    for _ in 0..4000 {
        let mut datagram = base.clone();
        // Randomise one to four bytes of cmd..una, leaving conv and len alone so
        // the datagram still parses as a single segment.
        for _ in 0..(1 + next() % 4) {
            let offset = 8 + (next() as usize % 16);
            datagram[offset] = next() as u8;
        }
        let mut sniffer = sniffer_with_zero_key();
        let _ = sniffer.receive_packet(game_frame(&datagram));
    }
}
