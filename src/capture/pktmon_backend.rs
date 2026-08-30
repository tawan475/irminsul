use std::collections::HashSet;

use async_trait::async_trait;
use futures::StreamExt;
use futures::stream::FusedStream;
use pktmon::filter::{PktMonFilter, TransportProtocol};
use pktmon::{Capture, Packet, PacketPayload};

use crate::capture::{CaptureBackend, CaptureError, PORT_RANGE, Result};

/// Length of an Ethernet II header (destination MAC, source MAC, ethertype).
const ETHERNET_HEADER_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;

/// What had to be done to a payload that pktmon did not report as an Ethernet
/// frame. Used only for one-shot diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayloadNote {
    /// A bare IP packet was given a synthetic Ethernet header.
    WrappedIp,
    /// The payload was handed on unchanged and will most likely fail to parse.
    PassedThrough(&'static str),
}

impl PayloadNote {
    /// Key used to deduplicate warnings, so each surprising layer is reported
    /// once rather than once per packet.
    fn key(&self) -> &'static str {
        match self {
            PayloadNote::WrappedIp => "IP",
            PayloadNote::PassedThrough(kind) => kind,
        }
    }
}

pub struct PktmonBackend {
    stream: Box<dyn FusedStream<Item = Packet> + Unpin + Send>,
    /// Payload kinds already reported, so an unexpected link layer produces one
    /// log line rather than one per packet.
    warned_payload_kinds: HashSet<&'static str>,
}

impl PktmonBackend {
    pub fn new() -> Result<Self> {
        let mut capture = Capture::new().map_err(|e| CaptureError::Capture {
            has_captured: false,
            error: e.into(),
        })?;

        let filter = PktMonFilter {
            name: "UDP Filter".to_string(),
            transport_protocol: Some(TransportProtocol::UDP),
            port: PORT_RANGE.0.into(),
            ..PktMonFilter::default()
        };

        capture
            .add_filter(filter)
            .map_err(|e| CaptureError::Filter(e.into()))?;

        let filter = PktMonFilter {
            name: "UDP Filter".to_string(),
            transport_protocol: Some(TransportProtocol::UDP),
            port: PORT_RANGE.1.into(),
            ..PktMonFilter::default()
        };

        capture
            .add_filter(filter)
            .map_err(|e| CaptureError::Filter(e.into()))?;

        // `stream()` starts the pktmon session, so it fails when the session
        // cannot be started. Report that as a capture error instead of
        // panicking inside whatever task owns this backend.
        let stream = capture.stream().map_err(|e| CaptureError::Capture {
            has_captured: false,
            error: e.into(),
        })?;

        Ok(Self {
            stream: Box::new(stream.boxed().fuse()),
            warned_payload_kinds: HashSet::new(),
        })
    }

    fn note_payload(&mut self, note: PayloadNote) {
        let key = note.key();
        if !self.warned_payload_kinds.insert(key) {
            return;
        }

        match note {
            PayloadNote::WrappedIp => tracing::warn!(
                "pktmon reported a bare IP payload instead of an Ethernet frame; wrapping it in a \
                 synthetic Ethernet header so it can be parsed. Further IP payloads are not logged."
            ),
            PayloadNote::PassedThrough(kind) => tracing::warn!(
                "pktmon reported a {kind} payload instead of an Ethernet frame; passing it through \
                 unchanged, and it will most likely fail to parse. Further {kind} payloads are not \
                 logged."
            ),
        }
    }
}

/// Turn a pktmon payload into the Ethernet frame the packet parser expects.
///
/// Everything downstream (`GameSniffer::receive_packet`) parses these bytes
/// with `SlicedPacket::from_ethernet`, so a payload reported at another layer
/// is misread as a MAC header and silently dropped. A bare IP payload is given
/// a synthetic Ethernet header; anything else is passed through unchanged (the
/// historical behaviour) with a note so the failure is diagnosable.
fn to_ethernet_frame(payload: PacketPayload) -> (Vec<u8>, Option<PayloadNote>) {
    match payload {
        PacketPayload::Ethernet(data) => (data, None),
        PacketPayload::IP(data) => match wrap_ip_in_ethernet(&data) {
            Some(frame) => (frame, Some(PayloadNote::WrappedIp)),
            None => (data, Some(PayloadNote::PassedThrough("IP"))),
        },
        other => {
            let note = PayloadNote::PassedThrough(payload_kind(&other));
            (other.to_vec().clone(), Some(note))
        }
    }
}

/// Prepend a synthetic Ethernet II header to a bare IP packet.
///
/// The MAC addresses are zeroed (nothing downstream reads them) and the
/// ethertype comes from the IP version nibble. Returns `None` when the buffer
/// does not start with a plausible IPv4 or IPv6 header, in which case the
/// caller should leave the bytes alone rather than corrupt them further.
fn wrap_ip_in_ethernet(ip: &[u8]) -> Option<Vec<u8>> {
    let ethertype = match ip.first()? >> 4 {
        4 => ETHERTYPE_IPV4,
        6 => ETHERTYPE_IPV6,
        _ => return None,
    };

    let mut frame = Vec::with_capacity(ETHERNET_HEADER_LEN + ip.len());
    frame.extend_from_slice(&[0u8; 12]);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(ip);
    Some(frame)
}

/// Stable, allocation-free label for a payload variant, used in diagnostics.
fn payload_kind(payload: &PacketPayload) -> &'static str {
    match payload {
        PacketPayload::Unknown(_) => "Unknown",
        PacketPayload::Ethernet(_) => "Ethernet",
        PacketPayload::WiFi(_) => "WiFi",
        PacketPayload::IP(_) => "IP",
        PacketPayload::HTTP(_) => "HTTP",
        PacketPayload::TCP(_) => "TCP",
        PacketPayload::UDP(_) => "UDP",
        PacketPayload::ARP(_) => "ARP",
        PacketPayload::ICMP(_) => "ICMP",
        PacketPayload::ESP(_) => "ESP",
        PacketPayload::AH(_) => "AH",
        PacketPayload::L4Payload(_) => "L4Payload",
    }
}

#[async_trait]
impl CaptureBackend for PktmonBackend {
    async fn next_packet(&mut self) -> Result<Vec<u8>> {
        // The payload is pulled out of the `select!` before it is converted so
        // the mutable borrow of `self.stream` ends before `self` is reborrowed.
        let payload = futures::select! {
            packet = self.stream.select_next_some() => Some(packet.payload),
            complete => None,
        };

        let Some(payload) = payload else {
            return Err(CaptureError::CaptureClosed);
        };

        let (frame, note) = to_ethernet_frame(payload);
        if let Some(note) = note {
            self.note_payload(note);
        }
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_payloads_pass_through_unchanged_and_silently() {
        let data = vec![0xaa, 0xbb, 0xcc];
        let (frame, note) = to_ethernet_frame(PacketPayload::Ethernet(data.clone()));

        assert_eq!(frame, data);
        assert_eq!(note, None);
    }

    #[test]
    fn ipv4_payloads_gain_a_synthetic_ethernet_header() {
        // Minimal IPv4 header start: version 4, IHL 5.
        let ip = vec![0x45, 0x00, 0x00, 0x1c, 0xde, 0xad];
        let (frame, note) = to_ethernet_frame(PacketPayload::IP(ip.clone()));

        assert_eq!(note, Some(PayloadNote::WrappedIp));
        assert_eq!(frame.len(), ETHERNET_HEADER_LEN + ip.len());
        assert_eq!(&frame[0..12], &[0u8; 12]);
        assert_eq!(&frame[12..14], &ETHERTYPE_IPV4.to_be_bytes());
        assert_eq!(&frame[14..], &ip[..]);
    }

    #[test]
    fn ipv6_payloads_gain_the_ipv6_ethertype() {
        let ip = vec![0x60, 0x00, 0x00, 0x00];
        let (frame, note) = to_ethernet_frame(PacketPayload::IP(ip.clone()));

        assert_eq!(note, Some(PayloadNote::WrappedIp));
        assert_eq!(&frame[12..14], &ETHERTYPE_IPV6.to_be_bytes());
        assert_eq!(&frame[14..], &ip[..]);
    }

    #[test]
    fn unrecognisable_ip_payloads_are_left_alone() {
        // Version nibble 5 is not a real IP version.
        let ip = vec![0x55, 0x00];
        let (frame, note) = to_ethernet_frame(PacketPayload::IP(ip.clone()));

        assert_eq!(frame, ip);
        assert_eq!(note, Some(PayloadNote::PassedThrough("IP")));

        let (frame, note) = to_ethernet_frame(PacketPayload::IP(Vec::new()));
        assert!(frame.is_empty());
        assert_eq!(note, Some(PayloadNote::PassedThrough("IP")));
    }

    #[test]
    fn other_layers_are_passed_through_but_reported() {
        let data = vec![1, 2, 3, 4];
        let (frame, note) = to_ethernet_frame(PacketPayload::WiFi(data.clone()));

        assert_eq!(frame, data);
        assert_eq!(note, Some(PayloadNote::PassedThrough("WiFi")));
    }

    #[test]
    fn wrap_ip_in_ethernet_rejects_non_ip_buffers() {
        assert!(wrap_ip_in_ethernet(&[]).is_none());
        assert!(wrap_ip_in_ethernet(&[0x00]).is_none());
        assert!(wrap_ip_in_ethernet(&[0xf0]).is_none());
    }

    #[test]
    fn payload_kinds_are_distinct_labels() {
        let payloads = [
            PacketPayload::Unknown(Vec::new()),
            PacketPayload::Ethernet(Vec::new()),
            PacketPayload::WiFi(Vec::new()),
            PacketPayload::IP(Vec::new()),
            PacketPayload::HTTP(Vec::new()),
            PacketPayload::TCP(Vec::new()),
            PacketPayload::UDP(Vec::new()),
            PacketPayload::ARP(Vec::new()),
            PacketPayload::ICMP(Vec::new()),
            PacketPayload::ESP(Vec::new()),
            PacketPayload::AH(Vec::new()),
            PacketPayload::L4Payload(Vec::new()),
        ];

        let kinds: HashSet<&'static str> = payloads.iter().map(payload_kind).collect();
        assert_eq!(kinds.len(), payloads.len());
    }
}
