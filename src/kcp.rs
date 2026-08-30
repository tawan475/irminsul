use std::time::Instant;

use kcp::{KCP_OVERHEAD, Kcp, get_conv};
use tracing::{Level, error, info, instrument, span, trace, warn};

use crate::bytes_as_hex;

pub(crate) struct KcpSniffer {
    pub(crate) conv_id: u32,
    kcp: Kcp<Vec<u8>>,
    time_start: Instant,
}

impl KcpSniffer {
    #[instrument(skip(segment))]
    pub fn try_new(segment: &[u8]) -> Option<Self> {
        validate_kcp_segment(segment).map(Self::new).or_else(|| {
            error!("could not create new kcp instance");
            None
        })
    }

    #[instrument]
    fn new(conv_id: u32) -> Self {
        info!("new connection, created new kcp instance");

        KcpSniffer {
            conv_id,
            kcp: new_kcp(conv_id),
            time_start: Instant::now(),
        }
    }

    #[instrument(skip_all, fields(conv_id = self.conv_id, len = segments.len()))]
    pub fn receive_segments(&mut self, segments: &[u8]) -> Vec<Vec<u8>> {
        let Some(conv_id) = validate_kcp_segment(segments) else {
            return Vec::new();
        };

        trace!("message data: {}", bytes_as_hex(segments));

        if conv_id != self.conv_id {
            warn!(
                expected = self.conv_id,
                "packet did not belong to conversation"
            );
            return Vec::new();
        }

        // game uses special format which adds 4 bytes at index 4,
        // reprocess to discard bytes 4..8 of every segment
        let segments = reformat_kcp_segments(segments);

        match self.kcp.input(&segments) {
            Ok(size) => trace!(size, "input successful"),
            Err(e) => warn!("could not input to kcp: {e}"),
        }

        let mut recv = Vec::new();
        while let Ok(size) = self.kcp.peeksize() {
            let span = span!(Level::TRACE, "receiving", size);
            let _enter = span.enter();

            let mut bytes = vec![0; size];

            match self.kcp.recv(&mut bytes) {
                Ok(_size) => {
                    recv.push(bytes);
                }
                Err(e) => {
                    warn!(%e, "could not receive kcp bytes");
                }
            }
        }

        if let Err(e) = self.kcp.update(self.clock()) {
            warn!(%e, "could not update kcp state");
        }

        recv
    }

    /// Milliseconds since this connection was created.
    ///
    /// Uses [`Instant`], which is monotonic, so a backward wall-clock step
    /// (NTP correction, VM resume, manual change) cannot make this fail.
    #[inline]
    fn clock(&self) -> u32 {
        self.time_start.elapsed().as_millis() as u32
    }
}

#[inline]
fn new_kcp(conv_id: u32) -> Kcp<Vec<u8>> {
    let mut kcp = Kcp::new(conv_id, Vec::new());
    kcp.set_wndsize(1024, 1024);
    kcp
}

/// Size of the game's KCP segment header.
///
/// The game uses a variant of KCP whose header is the standard 24-byte one
/// ([`KCP_OVERHEAD`]) plus two extra 4-byte fields, at offsets `4..8` and
/// `28..32`. `reformat_kcp_segments` strips both to recover a standard header,
/// so nothing shorter than this can be parsed at all.
const GAME_KCP_OVERHEAD: usize = KCP_OVERHEAD + 8;

/// Offsets of the fields this module inspects, within a game KCP segment.
///
/// Layout: `conv(4) extra(4) cmd(1) frg(1) wnd(2) ts(4) sn(4) una(4) len(4)
/// extra(4)`.
const CMD_OFFSET: usize = 8;
const FRG_OFFSET: usize = 9;
const TS_OFFSET: usize = 12;
const SN_OFFSET: usize = 16;

/// `IKCP_CMD_ACK`, the only command whose `ts` the reassembler ever compares.
const KCP_CMD_ACK: u8 = 82;

/// Largest fragment index the reassembler can handle.
///
/// `frg` counts how many fragments of a message are still to come, so
/// reassembling one needs `frg + 1` segments -- a sum the `kcp` crate computes in
/// `u8` (`peeksize`, `kcp.rs:456`). At `frg == 255` that addition overflows: a
/// debug build aborts and a release build wraps to zero and mis-assembles the
/// message. Nothing is lost by refusing it, because no conforming sender can
/// emit it either: KCP caps a message at `KCP_WND_RCV` (128) fragments.
const MAX_FRAGMENT_INDEX: u8 = 254;

/// Exclusive upper bound on the sequence number and timestamp this sniffer will
/// forward.
///
/// The `kcp` crate compares both with `later as i32 - earlier as i32`
/// (`timediff`, `kcp.rs:75`) where the C original uses deliberately *wrapping*
/// arithmetic. Against the small values a freshly observed conversation holds
/// (`rcv_nxt` and the local clock both start near zero), any field with its top
/// bit set makes that subtraction overflow, and the debug build aborts.
///
/// Dropping those segments loses nothing the reassembler would have kept:
///
/// * For `sn`, the comparison that overflows *is* the receive-window test. A
///   segment two billion ahead of `rcv_nxt` is outside the 1024-wide window, so
///   `kcp` discards it anyway -- only the arithmetic deciding to discard it
///   panics. `sn` is also unreachable from a real conversation, which would need
///   two billion segments to get there.
/// * For `ts`, the *only* `timediff` that consumes it is the round-trip estimate
///   on the ACK path (`kcp.rs:712`). A `KCP_CMD_PUSH` segment's `ts` is merely
///   stored (`ack_push`, and the queued segment), never compared, so a push can
///   carry any `ts` at all without overflowing anything -- and a push is what
///   carries the game data. The bound is therefore applied to ACK segments only:
///   applying it to pushes would silently discard real traffic if the game's
///   clock ever set the top bit, and this sniffer never sends, so discarding an
///   ACK costs nothing (its `parse_ack`/`update_ack` work on a permanently empty
///   send queue).
const MAX_TIMEDIFF_OPERAND: u32 = 1 << 31;

fn validate_kcp_segment(payload: &[u8]) -> Option<u32> {
    if payload.len() < GAME_KCP_OVERHEAD {
        warn!(
            len = payload.len(),
            data = bytes_as_hex(payload),
            "kcp header was too short"
        );
        return None;
    }
    Some(get_conv(payload))
}

/// Rewrite the game's KCP segments into standard ones by dropping the two extra
/// header fields (`4..8` and `28..32` of every segment).
///
/// The datagram is attacker-supplied and unverified (no UDP checksum is checked
/// before this point), so every length here comes from the wire and is treated
/// as untrusted: a segment that does not fit ends the walk and whatever was
/// parsed before it is still returned.
fn reformat_kcp_segments(data: &[u8]) -> Vec<u8> {
    let span = span!(Level::TRACE, "split");
    let _enter = span.enter();

    let mut reformatted_bytes = Vec::new();

    trace!("before split: {}", bytes_as_hex(data));

    let mut i = 0;
    while i < data.len() {
        // `i < data.len()`, so this subtraction cannot underflow
        if data.len() - i < GAME_KCP_OVERHEAD {
            warn!(
                len = data.len(),
                offset = i,
                "truncated kcp segment header, dropping the remainder of the datagram"
            );
            break;
        }

        let conv_id = &data[i..i + 4];

        // bytes [i + 4..i + 8] are the game's first extra field; skipped

        let remaining_header = &data[i + 8..i + 28];
        let content_len = u32::from_le_bytes(data[i + 24..i + 28].try_into().unwrap()) as usize;

        // bytes [i + 28..i + 32] are the game's second extra field; skipped
        let header_end = i + GAME_KCP_OVERHEAD; // <= data.len() by the check above
        let Some(end) = header_end.checked_add(content_len) else {
            warn!(
                offset = i,
                content_len, "kcp segment content length overflowed the address space"
            );
            break;
        };
        if end > data.len() {
            warn!(
                len = data.len(),
                offset = i,
                content_len,
                "kcp segment claims more content than the datagram holds"
            );
            break;
        }
        let content = &data[header_end..end];

        // Header fields the reassembler cannot process without overflowing. Both
        // are bugs in the `kcp` crate's arithmetic rather than in this walk, so
        // the offending segment is skipped and the rest of the datagram is still
        // parsed -- a datagram that carries one hostile segment may well carry
        // good ones after it.
        let cmd = data[i + CMD_OFFSET];
        let frg = data[i + FRG_OFFSET];
        let ts = u32::from_le_bytes(data[i + TS_OFFSET..i + TS_OFFSET + 4].try_into().unwrap());
        let sn = u32::from_le_bytes(data[i + SN_OFFSET..i + SN_OFFSET + 4].try_into().unwrap());
        // Only an ACK's `ts` reaches `timediff`; a push's is stored and never
        // compared, so bounding it there would drop game data for nothing.
        let ts_overflows = cmd == KCP_CMD_ACK && ts >= MAX_TIMEDIFF_OPERAND;
        if frg > MAX_FRAGMENT_INDEX || sn >= MAX_TIMEDIFF_OPERAND || ts_overflows {
            warn!(
                offset = i,
                cmd, frg, ts, sn, "dropping a kcp segment the reassembler cannot process"
            );
            i = end;
            continue;
        }

        reformatted_bytes.extend(conv_id.iter().chain(remaining_header).chain(content));

        i = end;
    }

    trace!(" after split: {}", bytes_as_hex(&reformatted_bytes));

    reformatted_bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one segment in the game's KCP format:
    /// conv(4) extra(4) cmd(1) frg(1) wnd(2) ts(4) sn(4) una(4) len(4) extra(4) content
    fn game_segment(conv: u32, sn: u32, content: &[u8]) -> Vec<u8> {
        let mut s = Vec::with_capacity(GAME_KCP_OVERHEAD + content.len());
        s.extend_from_slice(&conv.to_le_bytes());
        s.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // first extra field
        s.push(81); // cmd: push
        s.push(0); // frg
        s.extend_from_slice(&128u16.to_le_bytes()); // wnd
        s.extend_from_slice(&0u32.to_le_bytes()); // ts
        s.extend_from_slice(&sn.to_le_bytes());
        s.extend_from_slice(&0u32.to_le_bytes()); // una
        s.extend_from_slice(&(content.len() as u32).to_le_bytes()); // len
        s.extend_from_slice(&0xFEED_FACEu32.to_le_bytes()); // second extra field
        s.extend_from_slice(content);
        assert_eq!(s.len(), GAME_KCP_OVERHEAD + content.len());
        s
    }

    #[test]
    fn game_header_is_standard_kcp_plus_two_extra_fields() {
        assert_eq!(GAME_KCP_OVERHEAD, 32);
        assert_eq!(GAME_KCP_OVERHEAD, KCP_OVERHEAD + 8);
    }

    #[test]
    fn reformat_strips_both_extra_fields() {
        let content = [1u8, 2, 3, 4, 5];
        let out = reformat_kcp_segments(&game_segment(7, 3, &content));

        assert_eq!(out.len(), KCP_OVERHEAD + content.len());
        // conv survives at the front, so the standard kcp parser agrees with us
        assert_eq!(get_conv(&out), 7);
        // len field lands where standard kcp expects it
        assert_eq!(
            u32::from_le_bytes(out[20..24].try_into().unwrap()) as usize,
            content.len()
        );
        assert_eq!(&out[KCP_OVERHEAD..], &content);
        // neither magic extra field made it through
        assert!(!out.windows(4).any(|w| w == 0xDEAD_BEEFu32.to_le_bytes()));
        assert!(!out.windows(4).any(|w| w == 0xFEED_FACEu32.to_le_bytes()));
    }

    #[test]
    fn reformat_handles_several_concatenated_segments() {
        let mut data = game_segment(7, 0, &[0xAA; 3]);
        data.extend(game_segment(7, 1, &[])); // ack-shaped, empty content
        data.extend(game_segment(7, 2, &[0xBB; 10]));

        let out = reformat_kcp_segments(&data);

        // three standard headers plus 3, 0 and 10 bytes of content
        assert_eq!(out.len(), 3 * KCP_OVERHEAD + 13);
        assert_eq!(&out[KCP_OVERHEAD..KCP_OVERHEAD + 3], &[0xAA; 3]);
    }

    #[test]
    fn reformat_keeps_segments_parsed_before_a_bad_one() {
        let good = game_segment(7, 0, &[0xAA; 4]);
        let good_len = good.len();
        let mut data = good;
        // trailing segment whose declared content runs past the end of the datagram
        let mut bad = game_segment(7, 1, &[0xBB; 4]);
        bad[24..28].copy_from_slice(&5_000u32.to_le_bytes());
        data.extend(bad);

        let out = reformat_kcp_segments(&data);

        // exactly the first segment, reformatted; the truncated one is dropped
        assert_eq!(out.len(), KCP_OVERHEAD + 4);
        assert_eq!(&out[KCP_OVERHEAD..], &[0xAA; 4]);
        assert!(good_len > out.len()); // the two extra fields really were removed
    }

    #[test]
    fn reformat_stops_on_truncated_trailing_header() {
        let mut data = game_segment(7, 0, &[0xAA; 2]);
        data.extend_from_slice(&[0u8; 28]); // 28 bytes: not even a full game header

        let out = reformat_kcp_segments(&data);

        assert_eq!(out.len(), KCP_OVERHEAD + 2);
    }

    #[test]
    fn reformat_survives_content_len_larger_than_datagram() {
        // this is the exact shape that used to panic: a well-formed 32-byte header
        // whose len field claims content the datagram does not carry
        let mut seg = game_segment(7, 0, &[]);
        seg[24..28].copy_from_slice(&500u32.to_le_bytes());

        assert!(reformat_kcp_segments(&seg).is_empty());
    }

    #[test]
    fn reformat_survives_content_len_at_u32_max() {
        // u32::MAX would overflow `header_end + content_len` on a 32-bit target
        let mut seg = game_segment(7, 0, &[]);
        seg[24..28].copy_from_slice(&u32::MAX.to_le_bytes());

        assert!(reformat_kcp_segments(&seg).is_empty());
    }

    #[test]
    fn reformat_survives_data_shorter_than_a_game_header() {
        for len in 0..GAME_KCP_OVERHEAD {
            assert!(
                reformat_kcp_segments(&vec![0u8; len]).is_empty(),
                "len {len} produced output"
            );
        }
    }

    #[test]
    fn validate_rejects_anything_shorter_than_the_game_header() {
        for len in 0..GAME_KCP_OVERHEAD {
            assert_eq!(
                validate_kcp_segment(&vec![0u8; len]),
                None,
                "len {len} was accepted"
            );
        }
    }

    #[test]
    fn validate_accepts_a_bare_game_header() {
        // an empty-content segment is exactly the header and must still parse
        let seg = game_segment(0x1234_5678, 0, &[]);
        assert_eq!(seg.len(), GAME_KCP_OVERHEAD);
        assert_eq!(validate_kcp_segment(&seg), Some(0x1234_5678));
    }

    #[test]
    fn clock_is_monotonic_and_never_panics() {
        let sniffer = KcpSniffer::new(1);
        let a = sniffer.clock();
        let b = sniffer.clock();
        assert!(b >= a, "clock went backwards: {a} -> {b}");
    }

    /// `frg == 255` makes the reassembler compute `frg + 1` in `u8`, which
    /// overflows before it can decide anything.
    #[test]
    fn reformat_drops_an_unassemblable_fragment_index() {
        let mut seg = game_segment(7, 0, &[0xAA; 4]);
        seg[FRG_OFFSET] = 255;
        assert!(reformat_kcp_segments(&seg).is_empty());

        // 254 is the largest index the reassembler can still add to, and every
        // value a conforming sender emits is far below it.
        for frg in [0u8, 1, 127, 128, MAX_FRAGMENT_INDEX] {
            let mut seg = game_segment(7, 0, &[0xAA; 4]);
            seg[FRG_OFFSET] = frg;
            assert_eq!(
                reformat_kcp_segments(&seg).len(),
                KCP_OVERHEAD + 4,
                "frg {frg} was dropped"
            );
        }
    }

    /// `sn` is fed to the `kcp` crate's non-wrapping `timediff` on every command,
    /// so a value with the top bit set can overflow the receive-window test.
    #[test]
    fn reformat_drops_sequence_numbers_that_overflow_timediff() {
        for value in [MAX_TIMEDIFF_OPERAND, 0x8000_0400, 0xFFFF_FFFF] {
            let mut seg = game_segment(7, 0, &[0xAA; 4]);
            seg[SN_OFFSET..SN_OFFSET + 4].copy_from_slice(&value.to_le_bytes());
            assert!(
                reformat_kcp_segments(&seg).is_empty(),
                "sn {value:#x} was forwarded"
            );
        }

        // Everything below the bound is untouched, including the largest value
        // that still compares safely.
        for value in [0u32, 1, 1024, MAX_TIMEDIFF_OPERAND - 1] {
            let mut seg = game_segment(7, 0, &[0xAA; 4]);
            seg[SN_OFFSET..SN_OFFSET + 4].copy_from_slice(&value.to_le_bytes());
            assert_eq!(
                reformat_kcp_segments(&seg).len(),
                KCP_OVERHEAD + 4,
                "sn {value:#x} was dropped"
            );
        }
    }

    /// An ACK's `ts` is the one field `timediff` compares against the local
    /// clock, so the bound applies there.
    #[test]
    fn reformat_drops_ack_timestamps_that_overflow_timediff() {
        for value in [MAX_TIMEDIFF_OPERAND, 0x8000_0400, 0xFFFF_FFFF] {
            let mut seg = game_segment(7, 0, &[0xAA; 4]);
            seg[CMD_OFFSET] = KCP_CMD_ACK;
            seg[TS_OFFSET..TS_OFFSET + 4].copy_from_slice(&value.to_le_bytes());
            assert!(
                reformat_kcp_segments(&seg).is_empty(),
                "ack ts {value:#x} was forwarded"
            );
        }

        for value in [0u32, 1, 1024, MAX_TIMEDIFF_OPERAND - 1] {
            let mut seg = game_segment(7, 0, &[0xAA; 4]);
            seg[CMD_OFFSET] = KCP_CMD_ACK;
            seg[TS_OFFSET..TS_OFFSET + 4].copy_from_slice(&value.to_le_bytes());
            assert_eq!(
                reformat_kcp_segments(&seg).len(),
                KCP_OVERHEAD + 4,
                "ack ts {value:#x} was dropped"
            );
        }
    }

    /// A push's `ts` is stored and never compared, so no value of it may cost
    /// the payload. Bounding it here would silently discard game data the moment
    /// the sender's millisecond clock set its top bit.
    #[test]
    fn reformat_keeps_a_push_whatever_its_timestamp() {
        for value in [
            0u32,
            1024,
            MAX_TIMEDIFF_OPERAND - 1,
            MAX_TIMEDIFF_OPERAND,
            0x8000_0400,
            0xFFFF_FFFF,
        ] {
            let mut seg = game_segment(7, 0, &[0xAA; 4]);
            seg[TS_OFFSET..TS_OFFSET + 4].copy_from_slice(&value.to_le_bytes());
            let out = reformat_kcp_segments(&seg);
            assert_eq!(
                out.len(),
                KCP_OVERHEAD + 4,
                "push ts {value:#x} was dropped"
            );
            assert_eq!(&out[KCP_OVERHEAD..], &[0xAA; 4]);
        }
    }

    /// The reassembler really does accept a push with the top bit of `ts` set --
    /// the reason the bound above is scoped to ACKs.
    #[test]
    fn kcp_delivers_a_push_whose_timestamp_has_the_top_bit_set() {
        for ts in [MAX_TIMEDIFF_OPERAND, 0x8000_0400, 0xFFFF_FFFF] {
            let mut sniffer = KcpSniffer::new(7);
            let mut seg = game_segment(7, 0, &[0xAA; 6]);
            seg[TS_OFFSET..TS_OFFSET + 4].copy_from_slice(&ts.to_le_bytes());

            let received = sniffer.receive_segments(&seg);

            assert_eq!(received, vec![vec![0xAA; 6]], "ts {ts:#x} lost its payload");
        }
    }

    /// One hostile segment does not cost the good segments sharing its datagram.
    #[test]
    fn reformat_skips_a_hostile_segment_and_keeps_its_neighbours() {
        let mut data = game_segment(7, 0, &[0xAA; 4]);
        let mut hostile = game_segment(7, 1, &[0xBB; 4]);
        hostile[FRG_OFFSET] = 255;
        data.extend(hostile);
        data.extend(game_segment(7, 2, &[0xCC; 4]));

        let out = reformat_kcp_segments(&data);

        // The two good segments survive; the hostile one in the middle does not.
        assert_eq!(out.len(), 2 * (KCP_OVERHEAD + 4));
        assert_eq!(&out[KCP_OVERHEAD..KCP_OVERHEAD + 4], &[0xAA; 4]);
        assert_eq!(&out[2 * KCP_OVERHEAD + 4..], &[0xCC; 4]);
    }
}
