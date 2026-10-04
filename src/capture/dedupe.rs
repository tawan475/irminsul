//! Drop the duplicate copies of a datagram that pktmon reports.
//!
//! pktmon logs a packet at several points of the network stack, so every
//! datagram on the game ports reaches irminsul several times -- eight in the
//! 2026-10-04 log, where every count of a connection event is a multiple of
//! eight. Some copies are Ethernet frames and some are bare IP packets that
//! `pktmon_backend` wraps in a synthetic Ethernet header, so the frames are
//! not byte-identical even when the datagram is the same.
//!
//! Dropping the copies is safe: KCP discards a segment it already has by its
//! sequence number, so a duplicate can never add anything, and a connection
//! event repeated eight times only repeats a reset. Keeping them cost eight
//! times the decoding work, eight resets per handshake, and a backlog behind
//! every multi-second session key search.

use std::collections::{HashSet, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::{Duration, Instant};

/// Datagrams remembered at once.
pub const DEDUPE_CAPACITY: usize = 1024;

/// How long a datagram is remembered. The copies of one datagram are logged
/// within microseconds of each other; a quarter second leaves a wide margin
/// without remembering anything for long.
pub const DEDUPE_WINDOW: Duration = Duration::from_millis(250);

/// A short memory of recently seen datagrams.
pub struct Deduper {
    capacity: usize,
    window: Duration,
    /// Keys in arrival order, for expiry and the capacity bound.
    recent: VecDeque<(u64, Instant)>,
    seen: HashSet<u64>,
}

impl Deduper {
    pub fn new(capacity: usize, window: Duration) -> Self {
        Self {
            capacity,
            window,
            recent: VecDeque::with_capacity(capacity),
            seen: HashSet::with_capacity(capacity),
        }
    }

    /// Whether `frame` carries a datagram already seen within the window. A
    /// duplicate is not remembered again, so the window runs from the first
    /// copy.
    pub fn is_duplicate(&mut self, frame: &[u8], now: Instant) -> bool {
        while let Some(&(key, at)) = self.recent.front() {
            if now.saturating_duration_since(at) < self.window {
                break;
            }
            self.recent.pop_front();
            self.seen.remove(&key);
        }

        let key = datagram_key(frame);
        if self.seen.contains(&key) {
            return true;
        }

        if self.recent.len() >= self.capacity
            && let Some((oldest, _)) = self.recent.pop_front()
        {
            self.seen.remove(&oldest);
        }
        self.recent.push_back((key, now));
        self.seen.insert(key);
        false
    }

    /// Datagrams currently remembered.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.recent.len()
    }
}

const ETHERNET_HEADER_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const PROTOCOL_UDP: u8 = 17;

/// What identifies a datagram across the copies pktmon reports: the IP
/// addresses, the UDP ports and the UDP payload.
///
/// Everything else is left out on purpose. The MAC addresses differ between
/// an Ethernet copy and a wrapped IP one, Ethernet padding is not part of the
/// datagram, and checksums can be filled in at different points of the stack.
/// A frame that does not parse as UDP over IP is keyed on all of its bytes.
fn datagram_key(frame: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    match udp_parts(frame) {
        Some(datagram) => datagram.hash(&mut hasher),
        None => frame.hash(&mut hasher),
    }
    hasher.finish()
}

/// The parts of a UDP datagram that identify it; see [`datagram_key`].
#[derive(Hash)]
struct Datagram<'a> {
    source: &'a [u8],
    destination: &'a [u8],
    ports: &'a [u8],
    payload: &'a [u8],
}

/// Source address, destination address, the two ports, and the payload
/// (bounded by the UDP length, so padding is excluded) of a UDP datagram in an
/// Ethernet frame.
fn udp_parts(frame: &[u8]) -> Option<Datagram<'_>> {
    let mut ethertype = u16::from_be_bytes(frame.get(12..14)?.try_into().ok()?);
    let mut ip_start = ETHERNET_HEADER_LEN;
    if ethertype == ETHERTYPE_VLAN {
        ethertype = u16::from_be_bytes(frame.get(16..18)?.try_into().ok()?);
        ip_start += 4;
    }
    let ip = frame.get(ip_start..)?;

    let (source, destination, udp) = match ethertype {
        ETHERTYPE_IPV4 => {
            let header_len = usize::from(ip.first()? & 0x0F) * 4;
            if *ip.get(9)? != PROTOCOL_UDP || header_len < 20 {
                return None;
            }
            (ip.get(12..16)?, ip.get(16..20)?, ip.get(header_len..)?)
        }
        ETHERTYPE_IPV6 => {
            if *ip.get(6)? != PROTOCOL_UDP {
                return None;
            }
            (ip.get(8..24)?, ip.get(24..40)?, ip.get(IPV6_HEADER_LEN..)?)
        }
        _ => return None,
    };

    let ports = udp.get(0..4)?;
    let udp_len = usize::from(u16::from_be_bytes(udp.get(4..6)?.try_into().ok()?));
    let payload = udp.get(UDP_HEADER_LEN..udp_len.max(UDP_HEADER_LEN).min(udp.len()))?;
    Some(Datagram {
        source,
        destination,
        ports,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An IPv4/UDP packet from 10.0.0.2:22102 to 10.0.0.1:50000.
    fn ip_packet(payload: &[u8], ttl: u8) -> Vec<u8> {
        let udp_len = (8 + payload.len()) as u16;
        let total_len = 20 + udp_len;
        let mut ip = vec![0x45, 0];
        ip.extend_from_slice(&total_len.to_be_bytes());
        ip.extend_from_slice(&[0x12, 0x34, 0x40, 0x00, ttl, 17, 0, 0]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&22102u16.to_be_bytes());
        ip.extend_from_slice(&50000u16.to_be_bytes());
        ip.extend_from_slice(&udp_len.to_be_bytes());
        ip.extend_from_slice(&[0xAB, 0xCD]); // checksum
        ip.extend_from_slice(payload);
        ip
    }

    fn ethernet(ip: &[u8], mac: u8) -> Vec<u8> {
        let mut frame = vec![mac; 12];
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(ip);
        frame
    }

    /// What `pktmon_backend::wrap_ip_in_ethernet` makes of a bare IP copy.
    fn wrapped(ip: &[u8]) -> Vec<u8> {
        ethernet(ip, 0)
    }

    fn deduper() -> Deduper {
        Deduper::new(DEDUPE_CAPACITY, DEDUPE_WINDOW)
    }

    #[test]
    fn identical_copies_are_dropped() {
        let mut dedupe = deduper();
        let now = Instant::now();
        let frame = ethernet(&ip_packet(b"segment", 64), 7);

        assert!(!dedupe.is_duplicate(&frame, now));
        for _ in 0..7 {
            assert!(dedupe.is_duplicate(&frame, now));
        }
    }

    #[test]
    fn an_ethernet_copy_and_its_wrapped_ip_copy_are_the_same_datagram() {
        let mut dedupe = deduper();
        let now = Instant::now();
        let ip = ip_packet(b"segment", 64);

        assert!(!dedupe.is_duplicate(&ethernet(&ip, 7), now));
        assert!(dedupe.is_duplicate(&wrapped(&ip), now));
    }

    #[test]
    fn ethernet_padding_does_not_make_a_copy_look_new() {
        // A short datagram is padded to the 60-byte Ethernet minimum on the
        // wire; the bare IP copy has no padding.
        let mut dedupe = deduper();
        let now = Instant::now();
        let ip = ip_packet(&[1, 2, 3, 4], 64);
        let mut padded = ethernet(&ip, 7);
        padded.resize(60, 0);

        assert!(!dedupe.is_duplicate(&padded, now));
        assert!(dedupe.is_duplicate(&wrapped(&ip), now));
    }

    #[test]
    fn the_same_payload_after_the_window_is_kept() {
        let mut dedupe = deduper();
        let start = Instant::now();
        let frame = ethernet(&ip_packet(b"segment", 64), 7);

        assert!(!dedupe.is_duplicate(&frame, start));
        let later = start + DEDUPE_WINDOW + Duration::from_millis(1);
        assert!(!dedupe.is_duplicate(&frame, later));
    }

    #[test]
    fn different_datagrams_are_kept() {
        let mut dedupe = deduper();
        let now = Instant::now();

        assert!(!dedupe.is_duplicate(&ethernet(&ip_packet(b"one", 64), 7), now));
        assert!(!dedupe.is_duplicate(&ethernet(&ip_packet(b"two", 64), 7), now));

        // Same payload, other port: another datagram.
        let mut other_port = ip_packet(b"one", 64);
        other_port[22..24].copy_from_slice(&50001u16.to_be_bytes());
        assert!(!dedupe.is_duplicate(&ethernet(&other_port, 7), now));
    }

    #[test]
    fn memory_is_bounded() {
        let mut dedupe = Deduper::new(16, DEDUPE_WINDOW);
        let now = Instant::now();
        for i in 0..100u32 {
            let frame = ethernet(&ip_packet(&i.to_le_bytes(), 64), 7);
            assert!(!dedupe.is_duplicate(&frame, now));
            assert!(dedupe.len() <= 16);
        }
        // The oldest were forgotten to make room, so a late copy of one is
        // let through rather than remembered forever.
        let first = ethernet(&ip_packet(&0u32.to_le_bytes(), 64), 7);
        assert!(!dedupe.is_duplicate(&first, now));
    }

    #[test]
    fn frames_that_are_not_udp_are_compared_whole() {
        let mut dedupe = deduper();
        let now = Instant::now();
        assert!(!dedupe.is_duplicate(&[1, 2, 3], now));
        assert!(dedupe.is_duplicate(&[1, 2, 3], now));
        assert!(!dedupe.is_duplicate(&[1, 2, 4], now));
        assert!(!dedupe.is_duplicate(&[], now));
    }
}
