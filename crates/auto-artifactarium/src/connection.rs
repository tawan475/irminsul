use etherparse::{SlicedPacket, TransportSlice, UdpHeader};
use tracing::{debug, info, instrument, trace, warn};

use crate::{ConnectionPacket, PacketDirection};

#[instrument(skip_all)]
pub fn parse_connection_packet(port_filter: &[u16], bytes: Vec<u8>) -> Option<ConnectionPacket> {
    let (udp, payload) = parse_udp(bytes)?;
    let direction = validate_ports(port_filter, udp)?;

    if payload.len() <= 20 {
        // a connection-management packet always leads with a 4-byte code; anything
        // shorter is a runt datagram that happened to land on a game port
        let Some(code_bytes) = payload.first_chunk::<4>() else {
            trace!(len = payload.len(), "runt packet, no connection code");
            return None;
        };

        let code = u32::from_be_bytes(*code_bytes);
        match code {
            0xFF => {
                info!("handshake requested");
                Some(ConnectionPacket::HandshakeRequested)
            }
            404 => {
                warn!("disconnected packet");
                Some(ConnectionPacket::Disconnected)
            }
            _ => {
                trace!("handshake established");
                Some(ConnectionPacket::HandshakeEstablished)
            }
        }
    } else {
        Some(ConnectionPacket::SegmentData(direction, payload))
    }
}

#[instrument(skip_all, fields(len = data.len()))]
pub fn parse_udp(data: Vec<u8>) -> Option<(UdpHeader, Vec<u8>)> {
    let packet = match SlicedPacket::from_ethernet(&data) {
        Ok(p) => p,
        Err(e) => {
            debug!("failed: {e}");
            return None;
        }
    };

    // sanity checking the pcap filters
    let Some(transport) = packet.transport else {
        debug!("transport was not present");
        return None;
    };

    let TransportSlice::Udp(udp) = transport else {
        debug!("packet was not udp");
        return None;
    };

    trace!("complete");

    Some((udp.to_header(), udp.payload().to_vec()))
}

fn validate_ports(port_filter: &[u16], udp: UdpHeader) -> Option<PacketDirection> {
    let (src, dest) = (udp.source_port, udp.destination_port);
    if port_filter.contains(&src) {
        Some(PacketDirection::Received)
    } else if port_filter.contains(&dest) {
        Some(PacketDirection::Sent)
    } else {
        trace!(src, dest, "incorrect ports");
        None
    }
}

#[cfg(test)]
mod tests {
    use etherparse::PacketBuilder;

    use super::*;

    const PORTS: [u16; 2] = [22101, 22102];

    fn udp_frame(src_port: u16, dest_port: u16, payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64)
            .udp(src_port, dest_port);
        let mut out = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut out, payload).unwrap();
        out
    }

    fn parse(src_port: u16, dest_port: u16, payload: &[u8]) -> Option<ConnectionPacket> {
        parse_connection_packet(&PORTS, udp_frame(src_port, dest_port, payload))
    }

    #[test]
    fn runt_payloads_are_dropped_instead_of_panicking() {
        for len in 0..4 {
            let packet = parse(50000, 22102, &vec![0u8; len]);
            assert!(
                packet.is_none(),
                "{len}-byte payload should not produce a connection packet"
            );
        }
    }

    #[test]
    fn handshake_request_is_recognised() {
        let packet = parse(50000, 22102, &0xFFu32.to_be_bytes());
        assert!(matches!(packet, Some(ConnectionPacket::HandshakeRequested)));
    }

    #[test]
    fn disconnect_is_recognised() {
        let packet = parse(22102, 50000, &404u32.to_be_bytes());
        assert!(matches!(packet, Some(ConnectionPacket::Disconnected)));
    }

    #[test]
    fn any_other_short_code_is_an_established_handshake() {
        // exactly four bytes, and the largest payload the short branch accepts
        for len in [4usize, 20] {
            let mut payload = vec![0u8; len];
            payload[..4].copy_from_slice(&1u32.to_be_bytes());
            let packet = parse(22102, 50000, &payload);
            assert!(
                matches!(packet, Some(ConnectionPacket::HandshakeEstablished)),
                "len {len} was not treated as an established handshake"
            );
        }
    }

    #[test]
    fn longer_payloads_become_segment_data_with_a_direction() {
        let payload = vec![0xABu8; 21];

        let received = parse(22102, 50000, &payload);
        assert!(matches!(
            received,
            Some(ConnectionPacket::SegmentData(PacketDirection::Received, ref d)) if *d == payload
        ));

        let sent = parse(50000, 22101, &payload);
        assert!(matches!(
            sent,
            Some(ConnectionPacket::SegmentData(PacketDirection::Sent, ref d)) if *d == payload
        ));
    }

    #[test]
    fn traffic_on_other_ports_is_ignored() {
        assert!(parse(50000, 50001, &[0u8; 64]).is_none());
        // and a runt on other ports is still dropped before the length check
        assert!(parse(50000, 50001, &[]).is_none());
    }

    #[test]
    fn non_udp_bytes_are_ignored() {
        assert!(parse_connection_packet(&PORTS, Vec::new()).is_none());
        assert!(parse_connection_packet(&PORTS, vec![0u8; 8]).is_none());
    }
}
