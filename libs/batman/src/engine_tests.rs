use interfaces::{
    engine::{MeshRoutingEngine, RoutingAction},
    frame::{LinkFrame, LinkFrameDataMut, Mac},
};
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    BatmanEngine,
    wire::{
        BATADV_BCAST, BATADV_IV_OGM, BATADV_UNICAST, BatmanBroadcastPacket, BatmanOgmPacket,
        BatmanUnicastPacket, ETH_P_BATMAN,
    },
};

// Map a compact `u8` test identifier to a full MAC address, e.g. `mac(2)` ->
// `00:00:00:00:00:02`.  The engine is now concrete over [`Mac`], so the tests
// build node addresses through this helper instead of bare `u8` literals.
fn mac(n: u8) -> Mac {
    Mac([0, 0, 0, 0, 0, n])
}

// Helper to create a LinkFrame from raw bytes.  Ethernet-shaped layout:
// [dst][src][protocol big-endian][payload].
fn make_link_frame(src: u8, dst: u8, protocol: u16, payload: Vec<u8>) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(mac(dst).as_bytes());
    data.extend_from_slice(mac(src).as_bytes());
    data.extend_from_slice(&protocol.to_be_bytes());
    data.extend(payload);
    data
}

// Helper to parse a LinkFrame from bytes
fn parse_link_frame(data: &[u8]) -> &LinkFrame {
    LinkFrame::ref_from_prefix(data).unwrap().0
}

// Helper to create an OGM packet
fn make_ogm(orig: u8, prev_sender: u8, seqno: u32, tq: u8, ttl: u8) -> Vec<u8> {
    let ogm = BatmanOgmPacket {
        packet_type: BATADV_IV_OGM,
        version: 5,
        ttl,
        flags: 0,
        seqno: seqno.to_be(), // Network byte order
        orig: mac(orig),
        prev_sender: mac(prev_sender),
        reserved: 0,
        tq,
        tvlv_len: 0,
    };
    ogm.as_bytes().to_vec()
}

// Helper to create a unicast packet
fn make_unicast(dest: u8, ttl: u8, payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    let unicast = BatmanUnicastPacket {
        packet_type: BATADV_UNICAST,
        version: 5,
        ttl,
        dest: mac(dest),
    };
    data.extend_from_slice(unicast.as_bytes());
    data.extend_from_slice(payload);
    data
}

// Helper to create a broadcast packet wrapping an inner (e.g. ARP) frame.
// Wire layout: [BatmanBroadcastPacket header][inner payload ...].
fn make_broadcast(orig: u8, seqno: u32, ttl: u8, inner: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    let bcast = BatmanBroadcastPacket {
        packet_type: BATADV_BCAST,
        version: 5,
        ttl,
        seqno: seqno.to_be(), // Network byte order, like the OGM seqno
        orig: mac(orig),
    };
    data.extend_from_slice(bcast.as_bytes());
    data.extend_from_slice(inner);
    data
}

#[cfg(test)]
mod ogm_generation {
    use core::time::Duration;

    use super::*;

    #[test]
    fn test_generate_initial_ogm() {
        let mut tx_buf = [0u8; 1024];
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        let ogm_bytes = engine
            .produce_periodic_broadcast(Duration::ZERO, &mut tx_buf)
            .unwrap();
        let (ogm, _) = BatmanOgmPacket::ref_from_prefix(ogm_bytes).unwrap();

        assert_eq!(ogm.packet_type, BATADV_IV_OGM);
        assert_eq!(ogm.version, 5);
        assert_eq!(ogm.ttl, 50);
        assert_eq!(ogm.tq, 255); // Maximum quality at origin
        let seqno = ogm.seqno;
        assert_eq!(seqno, 1u32.to_be()); // First sequence number (in network byte order)
        assert_eq!(ogm.orig, mac(1));
        assert_eq!(ogm.prev_sender, mac(1));
    }

    #[test]
    fn test_sequence_number_increments() {
        let mut tx_buf = [0u8; 1024];
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Generate multiple OGMs
        for i in 1..=5 {
            let ogm_bytes = engine
                .produce_periodic_broadcast(Duration::ZERO, &mut tx_buf)
                .unwrap();
            let (ogm, _) = BatmanOgmPacket::ref_from_prefix(ogm_bytes).unwrap();
            let seqno = ogm.seqno;
            assert_eq!(seqno, (i as u32).to_be()); // Check in network byte order
        }
    }

    #[test]
    fn test_sequence_number_wraps() {
        let mut tx_buf = [0u8; 1024];
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));
        engine.sequence_number = u32::MAX - 1;

        engine
            .produce_periodic_broadcast(Duration::ZERO, &mut tx_buf)
            .unwrap();
        let ogm_bytes = engine
            .produce_periodic_broadcast(Duration::ZERO, &mut tx_buf)
            .unwrap();
        let (ogm, _) = BatmanOgmPacket::ref_from_prefix(ogm_bytes).unwrap();
        let seqno = ogm.seqno;
        // Should wrap to 0
        assert_eq!(seqno, 0u32.to_be());
    }
}

#[cfg(test)]
mod ogm_processing {
    use super::*;

    #[test]
    fn test_self_ogm_loop_prevention() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Receive our own OGM
        let ogm_payload = make_ogm(1, 1, 100, 255, 50);
        let frame_bytes = make_link_frame(1, 0xff, ETH_P_BATMAN, ogm_payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);

        // Should be consumed (dropped) without creating route
        assert!(matches!(action, RoutingAction::Consumed));
        assert_eq!(engine.originator_table.len(), 0);
    }

    #[test]
    fn test_new_originator_creation() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Receive OGM from node 2 via node 2 (direct neighbor)
        let ogm_payload = make_ogm(2, 2, 1, 255, 50);
        let frame_bytes = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm_payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);

        assert!(matches!(action, RoutingAction::Consumed));
        assert_eq!(engine.originator_table.len(), 1);

        let record = &engine.originator_table[&mac(2)];
        assert_eq!(record.neighbor_ident, mac(2));
        assert_eq!(record.best_next_hop, mac(2));
        assert_eq!(record.last_seqno, 1);
        // TQ should be 255 - 10 = 245 after attenuation
        assert_eq!(record.max_tq, 245);
    }

    #[test]
    fn test_tq_attenuation() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Receive OGM with TQ 255
        let ogm_payload = make_ogm(2, 2, 1, 255, 50);
        let frame_bytes = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm_payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);

        // Should attenuate by 10
        assert_eq!(engine.originator_table[&mac(2)].max_tq, 245);
    }

    #[test]
    fn test_tq_saturation_at_zero() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Receive OGM with very low TQ
        let ogm_payload = make_ogm(2, 2, 1, 5, 50);
        let frame_bytes = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm_payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);

        // 5 - 10 should saturate to 0, not underflow
        assert_eq!(engine.originator_table[&mac(2)].max_tq, 0);
    }

    #[test]
    fn test_ogm_forwarding() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Receive OGM from node 3 via node 2
        let ogm_payload = make_ogm(3, 2, 1, 245, 50);
        let frame_bytes = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm_payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);

        assert!(matches!(action, RoutingAction::Consumed));

        // Check that reply buffer contains forwarded OGM
        assert_eq!(reply.dst, Mac::BROADCAST);
        assert_eq!(reply.protocol, ETH_P_BATMAN);

        // Parse the forwarded OGM
        let (forwarded_ogm, _) = BatmanOgmPacket::ref_from_prefix(reply.payload).unwrap();
        assert_eq!(forwarded_ogm.orig, mac(3)); // Original source unchanged
        assert_eq!(forwarded_ogm.prev_sender, mac(1)); // Updated to self
        assert_eq!(forwarded_ogm.ttl, 49); // Decremented from 50 to 49
        assert_eq!(forwarded_ogm.tq, 235); // Attenuated from 245 to 235
    }

    #[test]
    fn test_ogm_ttl_expiration() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Receive OGM with TTL = 1
        let ogm_payload = make_ogm(2, 2, 1, 255, 1);
        let frame_bytes = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm_payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);

        // Should learn the route but NOT forward
        assert_eq!(engine.originator_table.len(), 1);
        // Reply should not have been populated for broadcast
        assert_eq!(reply.protocol, 0); // Default value, not set
    }

    #[test]
    fn test_multiple_paths_to_originator() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Receive OGM from node 5 via node 2 (first path)
        let ogm1 = make_ogm(5, 2, 1, 240, 50);
        let frame1 = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm1);
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
        engine.handle_rx(
            core::time::Duration::ZERO,
            parse_link_frame(&frame1),
            &mut reply,
        );

        // Receive OGM from node 5 via node 3 (second path, better quality)
        let ogm2 = make_ogm(5, 3, 2, 250, 50);
        let frame2 = make_link_frame(3, 0xff, ETH_P_BATMAN, ogm2);
        engine.handle_rx(
            core::time::Duration::ZERO,
            parse_link_frame(&frame2),
            &mut reply,
        );

        assert_eq!(engine.originator_table.len(), 1);
        let record = &engine.originator_table[&mac(5)];

        // Should track both paths
        assert_eq!(record.paths.len(), 2);

        // Best next hop should be node 3 (higher TQ: 250-10=240 vs 240-10=230)
        assert_eq!(record.best_next_hop, mac(3));
        assert_eq!(record.max_tq, 240);
    }

    #[test]
    fn test_path_limit_per_originator() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Add 5 different paths (limit is 4)
        for neighbor in 2..=6 {
            let ogm = make_ogm(10, neighbor, neighbor as u32, 200, 50);
            let frame = make_link_frame(neighbor, 0xff, ETH_P_BATMAN, ogm);
            let mut reply_buffer = [0u8; 256];
            let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
            engine.handle_rx(
                core::time::Duration::ZERO,
                parse_link_frame(&frame),
                &mut reply,
            );
        }

        let record = &engine.originator_table[&mac(10)];
        // Should only track 4 paths (the limit)
        assert_eq!(record.paths.len(), 4);
    }

    #[test]
    fn test_sequence_number_update() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Receive initial OGM
        let ogm1 = make_ogm(2, 2, 100, 255, 50);
        let frame1 = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm1);
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
        engine.handle_rx(
            core::time::Duration::ZERO,
            parse_link_frame(&frame1),
            &mut reply,
        );

        assert_eq!(engine.originator_table[&mac(2)].last_seqno, 100);

        // Receive newer OGM
        let ogm2 = make_ogm(2, 2, 105, 255, 50);
        let frame2 = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm2);
        engine.handle_rx(
            core::time::Duration::ZERO,
            parse_link_frame(&frame2),
            &mut reply,
        );

        assert_eq!(engine.originator_table[&mac(2)].last_seqno, 105);
    }

    #[test]
    fn test_old_sequence_number_ignored() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Receive initial OGM with seqno 100
        let ogm1 = make_ogm(2, 2, 100, 255, 50);
        let frame1 = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm1);
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
        engine.handle_rx(
            core::time::Duration::ZERO,
            parse_link_frame(&frame1),
            &mut reply,
        );

        let initial_tq = engine.originator_table[&mac(2)].max_tq;

        // Receive older OGM with seqno 95 and different TQ
        let ogm2 = make_ogm(2, 2, 95, 200, 50);
        let frame2 = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm2);
        engine.handle_rx(
            core::time::Duration::ZERO,
            parse_link_frame(&frame2),
            &mut reply,
        );

        // Sequence number and TQ should not change
        assert_eq!(engine.originator_table[&mac(2)].last_seqno, 100);
        assert_eq!(engine.originator_table[&mac(2)].max_tq, initial_tq);
    }

    #[test]
    fn test_full_table_evicts_least_recently_heard() {
        let mut engine: BatmanEngine<4> = BatmanEngine::new(mac(1));

        // Fill the table to capacity (4 originators), each first heard at a
        // distinct, increasing time so they have a clear staleness order.
        for (i, orig) in (10..14).enumerate() {
            let ogm = make_ogm(orig, orig, 1, 255, 50);
            let frame = make_link_frame(orig, 0xff, ETH_P_BATMAN, ogm);
            let mut reply_buffer = [0u8; 256];
            let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
            engine.handle_rx(
                core::time::Duration::from_secs(i as u64),
                parse_link_frame(&frame),
                &mut reply,
            );
        }
        assert_eq!(engine.originator_table.len(), 4);

        // A newly heard originator must be admitted, evicting the
        // least-recently-refreshed entry (originator 10, heard at t=0) rather
        // than being dropped.
        let ogm = make_ogm(20, 20, 1, 255, 50);
        let frame = make_link_frame(20, 0xff, ETH_P_BATMAN, ogm);
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
        engine.handle_rx(
            core::time::Duration::from_secs(100),
            parse_link_frame(&frame),
            &mut reply,
        );

        assert_eq!(engine.originator_table.len(), 4);
        assert!(
            engine.originator_table.contains_key(&mac(20)),
            "the newly heard originator must be admitted"
        );
        assert!(
            !engine.originator_table.contains_key(&mac(10)),
            "the least-recently-heard originator must be evicted"
        );
        // The other three are untouched.
        for orig in 11..14 {
            assert!(engine.originator_table.contains_key(&mac(orig)));
        }
    }
}

#[cfg(test)]
mod unicast_forwarding {
    use super::*;

    #[test]
    fn test_unicast_local_delivery() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Receive unicast packet destined for us
        let unicast_payload = make_unicast(1, 10, b"Hello");
        let frame_bytes = make_link_frame(2, 1, ETH_P_BATMAN, unicast_payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);

        assert!(matches!(action, RoutingAction::DeliverLocal));
    }

    #[test]
    fn test_unicast_ttl_expiration() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Add a route to node 5 via node 2
        let ogm = make_ogm(5, 2, 1, 255, 50);
        let frame_ogm = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm);
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
        engine.handle_rx(
            core::time::Duration::ZERO,
            parse_link_frame(&frame_ogm),
            &mut reply,
        );

        // Receive unicast with TTL=1 (should expire)
        let unicast_payload = make_unicast(5, 1, b"data");
        let frame_bytes = make_link_frame(3, 1, ETH_P_BATMAN, unicast_payload);
        let frame = parse_link_frame(&frame_bytes);

        let action = engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);

        // Should be consumed (dropped) due to TTL
        assert!(matches!(action, RoutingAction::Consumed));
    }

    #[test]
    fn test_unicast_forwarding_with_ttl_decrement() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Add a route to node 5 via node 2
        let ogm = make_ogm(5, 2, 1, 255, 50);
        let frame_ogm = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm);
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
        engine.handle_rx(
            core::time::Duration::ZERO,
            parse_link_frame(&frame_ogm),
            &mut reply,
        );

        // Receive unicast packet destined for node 5
        let unicast_payload = make_unicast(5, 10, b"payload");
        let frame_bytes = make_link_frame(3, 1, ETH_P_BATMAN, unicast_payload);
        let frame = parse_link_frame(&frame_bytes);

        let action = engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);

        assert!(matches!(action, RoutingAction::Consumed));

        // Check reply buffer
        assert_eq!(reply.dst, mac(2)); // Should forward to node 2
        assert_eq!(reply.protocol, ETH_P_BATMAN);

        // Parse the forwarded unicast header
        let (forwarded_unicast, _) = BatmanUnicastPacket::ref_from_prefix(reply.payload).unwrap();
        assert_eq!(forwarded_unicast.dest, mac(5)); // Destination unchanged
        assert_eq!(forwarded_unicast.ttl, 9); // TTL decremented from 10 to 9
    }

    #[test]
    fn test_unicast_unknown_destination() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Receive unicast for unknown destination
        let unicast_payload = make_unicast(99, 10, b"data");
        let frame_bytes = make_link_frame(2, 1, ETH_P_BATMAN, unicast_payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);

        // Should be consumed (dropped) - no route known
        assert!(matches!(action, RoutingAction::Consumed));
    }
}

#[cfg(test)]
mod routing_lookup {
    use super::*;

    #[test]
    fn test_lookup_route_exists() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Add a route to node 5 via node 2
        let ogm = make_ogm(5, 2, 1, 255, 50);
        let frame = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm);
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
        engine.handle_rx(
            core::time::Duration::ZERO,
            parse_link_frame(&frame),
            &mut reply,
        );

        let next_hop = engine.lookup_route(mac(5));
        assert_eq!(next_hop, Some(mac(2)));
    }

    #[test]
    fn test_lookup_route_not_exists() {
        let engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        let next_hop = engine.lookup_route(mac(99));
        assert_eq!(next_hop, None);
    }

    #[test]
    fn test_lookup_route_updates_with_better_path() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Add route to node 5 via node 2 (TQ=200)
        let ogm1 = make_ogm(5, 2, 1, 200, 50);
        let frame1 = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm1);
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
        engine.handle_rx(
            core::time::Duration::ZERO,
            parse_link_frame(&frame1),
            &mut reply,
        );

        assert_eq!(engine.lookup_route(mac(5)), Some(mac(2)));

        // Add better route to node 5 via node 3 (TQ=250)
        let ogm2 = make_ogm(5, 3, 2, 250, 50);
        let frame2 = make_link_frame(3, 0xff, ETH_P_BATMAN, ogm2);
        engine.handle_rx(
            core::time::Duration::ZERO,
            parse_link_frame(&frame2),
            &mut reply,
        );

        // Should now route via node 3
        assert_eq!(engine.lookup_route(mac(5)), Some(mac(3)));
    }
}

#[cfg(test)]
mod protocol_filtering {
    use super::*;

    #[test]
    fn test_wrong_protocol_ignored() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Send packet with wrong protocol number
        let frame_bytes = make_link_frame(2, 1, 0x0800, vec![1, 2, 3, 4]);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);

        assert!(matches!(action, RoutingAction::Consumed));
        assert_eq!(engine.originator_table.len(), 0);
    }

    #[test]
    fn test_empty_payload_ignored() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Send BATMAN packet with empty payload
        let frame_bytes = make_link_frame(2, 1, ETH_P_BATMAN, vec![]);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);

        assert!(matches!(action, RoutingAction::Consumed));
    }

    #[test]
    fn test_unknown_batman_packet_type() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Send packet with unknown BATMAN packet type destined for node 5 (not us)
        let frame_bytes = make_link_frame(2, 5, ETH_P_BATMAN, vec![0x99, 1, 2, 3]);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);

        // Unknown packet type should trigger the default match arm and be consumed (no route known)
        assert!(matches!(action, RoutingAction::Consumed));
    }

    #[test]
    fn test_malformed_ogm_ignored() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Send truncated OGM packet
        let frame_bytes = make_link_frame(2, 0xff, ETH_P_BATMAN, vec![BATADV_IV_OGM, 5, 50]);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);

        assert!(matches!(action, RoutingAction::Consumed));
        assert_eq!(engine.originator_table.len(), 0);
    }
}

#[cfg(test)]
mod edge_cases {
    use super::*;

    #[test]
    fn test_rapid_sequence_number_changes() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Rapidly changing sequence numbers
        for seqno in [1, 100, 50, 200, 75, 300] {
            let ogm = make_ogm(2, 2, seqno, 255, 50);
            let frame = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm);
            let mut reply_buffer = [0u8; 256];
            let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
            engine.handle_rx(
                core::time::Duration::ZERO,
                parse_link_frame(&frame),
                &mut reply,
            );
        }

        // Should have the highest sequence number
        assert_eq!(engine.originator_table[&mac(2)].last_seqno, 300);
    }

    #[test]
    fn test_same_originator_different_paths_simultaneous() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Receive OGMs from same originator via different neighbors in quick succession
        let neighbors = [2, 3, 4, 5];
        for (i, &neighbor) in neighbors.iter().enumerate() {
            let tq = 255 - (i as u8 * 10); // Different qualities
            let ogm = make_ogm(10, neighbor, 1, tq, 50);
            let frame = make_link_frame(neighbor, 0xff, ETH_P_BATMAN, ogm);
            let mut reply_buffer = [0u8; 256];
            let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
            engine.handle_rx(
                core::time::Duration::ZERO,
                parse_link_frame(&frame),
                &mut reply,
            );
        }

        assert_eq!(engine.originator_table.len(), 1);
        assert_eq!(engine.originator_table[&mac(10)].paths.len(), 4);
        // Best path should be via neighbor 2 (highest TQ)
        assert_eq!(engine.originator_table[&mac(10)].best_next_hop, mac(2));
    }

    #[test]
    fn test_zero_ttl_not_forwarded() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Receive OGM with TTL=0 (shouldn't happen in practice, but test boundary)
        let ogm = make_ogm(2, 2, 1, 255, 0);
        let frame = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm);
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        engine.handle_rx(
            core::time::Duration::ZERO,
            parse_link_frame(&frame),
            &mut reply,
        );

        // Should learn but not forward
        assert_eq!(engine.originator_table.len(), 1);
        assert_eq!(reply.protocol, 0); // Not populated for forwarding
    }

    #[test]
    fn test_path_metric_updates_on_same_neighbor() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // First OGM from originator 5 via neighbor 2
        let ogm1 = make_ogm(5, 2, 1, 200, 50);
        let frame1 = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm1);
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
        engine.handle_rx(
            core::time::Duration::ZERO,
            parse_link_frame(&frame1),
            &mut reply,
        );

        assert_eq!(engine.originator_table[&mac(5)].paths[0].last_tq, 190);

        // Second OGM from same originator via same neighbor with different TQ
        let ogm2 = make_ogm(5, 2, 2, 250, 50);
        let frame2 = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm2);
        engine.handle_rx(
            core::time::Duration::ZERO,
            parse_link_frame(&frame2),
            &mut reply,
        );

        // Path metric should be updated
        assert_eq!(engine.originator_table[&mac(5)].paths[0].last_tq, 240);
        assert_eq!(engine.originator_table[&mac(5)].paths.len(), 1); // Still just one path
    }
}

#[cfg(test)]
mod broadcast_processing {
    use super::*;

    // Stand-in for an encapsulated broadcast Ethernet frame (e.g. an ARP
    // request) that a broadcast packet floods across the mesh.
    const INNER: &[u8] = &[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03];

    /// A fresh broadcast from a neighbour, with TTL to spare, must be BOTH
    /// delivered to the local node (so its TAP sees the ARP) AND re-flooded
    /// with a decremented TTL.  The re-flood is written into the `reply`
    /// scratchpad exactly like OGM forwarding, and the inner frame is
    /// preserved verbatim so the next hop can deliver it too.
    #[test]
    fn test_broadcast_deliver_and_reflood() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Broadcast originated by node 2, relayed to us directly by node 2.
        let payload = make_broadcast(2, 100, 50, INNER);
        let frame_bytes = make_link_frame(2, 0xff, ETH_P_BATMAN, payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);

        // Deliver to the local TAP *and* keep the flood going to neighbours.
        // The forward destination is the broadcast address.
        assert!(matches!(
            action,
            RoutingAction::DeliverLocalAndForward(dst) if dst == Mac::BROADCAST
        ));

        // The re-flood lives in the reply scratchpad, addressed to broadcast.
        assert_eq!(reply.dst, Mac::BROADCAST);
        assert_eq!(reply.protocol, ETH_P_BATMAN);

        let (out, rest) = BatmanBroadcastPacket::ref_from_prefix(reply.payload).unwrap();
        assert_eq!(out.packet_type, BATADV_BCAST);
        assert_eq!(out.orig, mac(2)); // originator unchanged through the relay
        let seqno = out.seqno;
        assert_eq!(seqno, 100u32.to_be()); // seqno unchanged
        assert_eq!(out.ttl, 49); // decremented from 50
        // Inner frame preserved verbatim (reply buffer is over-sized, so only
        // the leading INNER.len() bytes are meaningful).
        assert_eq!(&rest[..INNER.len()], INNER);
    }

    /// A node must never act on its own re-flooded broadcast looping back.
    #[test]
    fn test_own_broadcast_dropped() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        let payload = make_broadcast(1, 100, 50, INNER); // orig == self_ident
        let frame_bytes = make_link_frame(2, 0xff, ETH_P_BATMAN, payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);

        assert!(matches!(action, RoutingAction::Consumed));
        assert_eq!(reply.protocol, 0); // nothing re-flooded
    }

    /// Re-seeing the same (orig, seqno) must be dropped so a broadcast cannot
    /// circulate forever around a cyclic mesh.
    #[test]
    fn test_duplicate_broadcast_dropped() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        let payload = make_broadcast(2, 100, 50, INNER);
        let frame_bytes = make_link_frame(2, 0xff, ETH_P_BATMAN, payload);

        // First sighting: delivered locally and re-flooded.
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
        let first = engine.handle_rx(
            core::time::Duration::ZERO,
            parse_link_frame(&frame_bytes),
            &mut reply,
        );
        assert!(matches!(first, RoutingAction::DeliverLocalAndForward(_)));

        // Same (orig, seqno) seen again (e.g. arriving via a different
        // neighbour): dropped, and crucially not re-flooded a second time.
        let mut reply2_buffer = [0u8; 256];
        let mut reply2 = LinkFrameDataMut::from(&mut reply2_buffer[..]);
        let second = engine.handle_rx(
            core::time::Duration::ZERO,
            parse_link_frame(&frame_bytes),
            &mut reply2,
        );
        assert!(matches!(second, RoutingAction::Consumed));
        assert_eq!(reply2.protocol, 0);
    }

    /// When TTL has run out the broadcast is still delivered to the local node
    /// but is NOT re-flooded — mirroring OGM TTL expiry.
    #[test]
    fn test_broadcast_ttl_expiry_delivers_without_reflood() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        let payload = make_broadcast(2, 100, 1, INNER); // ttl == 1, cannot forward
        let frame_bytes = make_link_frame(2, 0xff, ETH_P_BATMAN, payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);

        assert!(matches!(action, RoutingAction::DeliverLocal));
        assert_eq!(reply.protocol, 0); // not re-flooded
    }
}

#[cfg(test)]
mod ogm_tvlv {
    //! The OGM now matches batman-adv's `batadv_ogm_packet` layout and can
    //! carry a variable-length TVLV (Type-Version-Length-Value) tail after the
    //! fixed header, used to piggyback membership announcements onto OGMs.  The
    //! header's `tvlv_len` field (big-endian) gives the tail length in bytes.

    use super::*;
    use crate::wire::BatmanTvlvHdr;

    /// Build one TVLV record: `[type][version][len: be16][value ...]`.
    fn tvlv_record(tvlv_type: u8, value: &[u8]) -> Vec<u8> {
        let hdr = BatmanTvlvHdr {
            tvlv_type,
            version: 1,
            len: (value.len() as u16).to_be(),
        };
        let mut v = hdr.as_bytes().to_vec();
        v.extend_from_slice(value);
        v
    }

    /// An OGM carrying a TVLV tail must round-trip: the fixed header parses
    /// off the front (advertising the tail length via `tvlv_len`), and the
    /// TVLV record parses out of the tail intact.
    #[test]
    fn ogm_round_trips_with_tvlv_tail() {
        let value = [0xaa, 0xbb, 0xcc];
        let tvlv = tvlv_record(0x05, &value);

        let ogm = BatmanOgmPacket {
            packet_type: BATADV_IV_OGM,
            version: 5,
            ttl: 50,
            flags: 0,
            seqno: 1u32.to_be(),
            orig: mac(2),
            prev_sender: mac(2),
            reserved: 0,
            tq: 255,
            tvlv_len: (tvlv.len() as u16).to_be(),
        };
        let mut bytes = ogm.as_bytes().to_vec();
        bytes.extend_from_slice(&tvlv);

        let (parsed, tail) = BatmanOgmPacket::ref_from_prefix(&bytes).unwrap();
        assert_eq!(u16::from_be(parsed.tvlv_len) as usize, tvlv.len());
        assert_eq!(&tail[..tvlv.len()], &tvlv[..]);

        let (thdr, val) = BatmanTvlvHdr::ref_from_prefix(tail).unwrap();
        assert_eq!(thdr.tvlv_type, 0x05);
        assert_eq!(u16::from_be(thdr.len) as usize, value.len());
        assert_eq!(&val[..value.len()], &value);
    }

    /// When an intermediate node re-floods an OGM, it must preserve the TVLV
    /// tail verbatim (so membership announcements propagate) while still
    /// decrementing TTL, attenuating TQ, and stamping itself as prev_sender.
    #[test]
    fn forwarded_ogm_preserves_tvlv_tail() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        let value = [0x11, 0x22];
        let tvlv = tvlv_record(0x05, &value);

        // OGM originated by node 3, relayed to us by node 2, TTL to spare.
        let ogm = BatmanOgmPacket {
            packet_type: BATADV_IV_OGM,
            version: 5,
            ttl: 50,
            flags: 0,
            seqno: 1u32.to_be(),
            orig: mac(3),
            prev_sender: mac(2),
            reserved: 0,
            tq: 245,
            tvlv_len: (tvlv.len() as u16).to_be(),
        };
        let mut payload = ogm.as_bytes().to_vec();
        payload.extend_from_slice(&tvlv);

        let frame_bytes = make_link_frame(2, 0xff, ETH_P_BATMAN, payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);
        assert!(matches!(action, RoutingAction::Consumed));
        assert_eq!(reply.dst, Mac::BROADCAST);

        let (fwd, tail) = BatmanOgmPacket::ref_from_prefix(reply.payload).unwrap();
        assert_eq!(fwd.orig, mac(3)); // originator unchanged
        assert_eq!(fwd.prev_sender, mac(1)); // stamped as us
        assert_eq!(fwd.ttl, 49); // decremented
        assert_eq!(
            u16::from_be(fwd.tvlv_len) as usize,
            tvlv.len(),
            "tvlv_len must survive forwarding"
        );
        assert_eq!(
            &tail[..tvlv.len()],
            &tvlv[..],
            "tvlv tail must be preserved"
        );
    }
}

#[cfg(test)]
mod mcast_membership {
    //! Multicast group memberships are distributed across the mesh by
    //! piggybacking them on OGMs as a [`BATADV_TVLV_MCAST`] TVLV.  A node
    //! announces the groups its local host listens to, and learns which
    //! originators want which groups from the OGMs it receives.

    use core::time::Duration;

    use super::*;
    use crate::wire::{BATADV_TVLV_MCAST, BatmanTvlvHdr};

    /// A multicast group MAC (`01:00:5e:00:00:NN`, IPv4-multicast style).
    fn group(n: u8) -> Mac {
        Mac([0x01, 0x00, 0x5e, 0x00, 0x00, n])
    }

    /// Build a multicast TVLV record: header + the listed group MACs as value.
    fn mcast_tvlv(groups: &[Mac]) -> Vec<u8> {
        let mut value = Vec::new();
        for g in groups {
            value.extend_from_slice(g.as_bytes());
        }
        let hdr = BatmanTvlvHdr {
            tvlv_type: BATADV_TVLV_MCAST,
            version: 1,
            len: (value.len() as u16).to_be(),
        };
        let mut v = hdr.as_bytes().to_vec();
        v.extend_from_slice(&value);
        v
    }

    /// Build a received OGM wire frame from `orig` (relayed by `prev`) carrying
    /// a multicast TVLV announcing `groups`.
    fn ogm_with_groups(orig: u8, prev: u8, seqno: u32, groups: &[Mac]) -> Vec<u8> {
        let tvlv = mcast_tvlv(groups);
        let ogm = BatmanOgmPacket {
            packet_type: BATADV_IV_OGM,
            version: 5,
            ttl: 50,
            flags: 0,
            seqno: seqno.to_be(),
            orig: mac(orig),
            prev_sender: mac(prev),
            reserved: 0,
            tq: 255,
            tvlv_len: (tvlv.len() as u16).to_be(),
        };
        let mut payload = ogm.as_bytes().to_vec();
        payload.extend_from_slice(&tvlv);
        make_link_frame(orig, 0xff, ETH_P_BATMAN, payload)
    }

    /// Scan a TVLV tail and return the multicast TVLV's value bytes, if present.
    fn mcast_value(tail: &[u8]) -> Option<Vec<u8>> {
        let mut off = 0;
        while off + 4 <= tail.len() {
            let (hdr, _) = BatmanTvlvHdr::ref_from_prefix(&tail[off..]).ok()?;
            let len = u16::from_be(hdr.len) as usize;
            let vstart = off + 4;
            if hdr.tvlv_type == BATADV_TVLV_MCAST {
                return tail.get(vstart..vstart + len).map(|s| s.to_vec());
            }
            off = vstart + len;
        }
        None
    }

    /// A node's local multicast memberships are announced in the OGMs it
    /// produces, as a multicast TVLV listing the group MACs.
    #[test]
    fn local_memberships_are_announced_in_ogm() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));
        engine.set_local_mcast_groups(&[group(0x2a), group(0x2b)]);

        let mut tx = [0u8; 256];
        let bytes = engine
            .produce_periodic_broadcast(Duration::ZERO, &mut tx)
            .unwrap();
        let (_ogm, tail) = BatmanOgmPacket::ref_from_prefix(bytes).unwrap();

        let value = mcast_value(tail).expect("OGM must carry a multicast TVLV");
        assert_eq!(value.len(), 12, "two group MACs = 12 bytes");
        assert_eq!(&value[0..6], group(0x2a).as_bytes());
        assert_eq!(&value[6..12], group(0x2b).as_bytes());
    }

    /// An OGM with no local memberships carries no multicast TVLV.
    #[test]
    fn no_memberships_means_no_mcast_tvlv() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));
        let mut tx = [0u8; 256];
        let bytes = engine
            .produce_periodic_broadcast(Duration::ZERO, &mut tx)
            .unwrap();
        let (ogm, tail) = BatmanOgmPacket::ref_from_prefix(bytes).unwrap();
        assert_eq!(u16::from_be(ogm.tvlv_len), 0);
        assert!(mcast_value(tail).is_none());
    }

    /// Receiving an OGM with a multicast TVLV records the originator as a
    /// listener for each announced group; a later OGM announcing fewer groups
    /// prunes the memberships it dropped.
    #[test]
    fn received_memberships_are_tracked_and_pruned() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));
        let (g1, g2) = (group(1), group(2));

        // Node 5 announces interest in g1 and g2.
        let frame_bytes = ogm_with_groups(5, 5, 1, &[g1, g2]);
        let frame = parse_link_frame(&frame_bytes);
        let mut buf = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut buf[..]);
        engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);

        assert!(engine.mcast_listeners(g1).any(|m| m == mac(5)));
        assert!(engine.mcast_listeners(g2).any(|m| m == mac(5)));

        // A newer OGM from node 5 announcing only g1 must prune g2.
        let frame_bytes = ogm_with_groups(5, 5, 2, &[g1]);
        let frame = parse_link_frame(&frame_bytes);
        let mut buf = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut buf[..]);
        engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);

        assert!(engine.mcast_listeners(g1).any(|m| m == mac(5)));
        assert!(
            !engine.mcast_listeners(g2).any(|m| m == mac(5)),
            "g2 membership should have been pruned"
        );
    }
}

#[cfg(test)]
mod mcast_packet {
    //! The dedicated `BATADV_MCAST` packet type (batman-adv's
    //! `batadv_mcast_packet`).  A multicast frame is delivered to each
    //! interested originator as its own `BATADV_MCAST` packet, routed toward
    //! that node like a unicast and delivered locally on arrival.

    use super::*;
    use crate::wire::{BATADV_MCAST, BatmanMcastPacket};

    /// Build a BATADV_MCAST packet addressed to `dest`, wrapping `payload`.
    fn make_mcast(dest: u8, ttl: u8, payload: &[u8]) -> Vec<u8> {
        let hdr = BatmanMcastPacket {
            packet_type: BATADV_MCAST,
            version: 5,
            ttl,
            dest: mac(dest),
        };
        let mut data = hdr.as_bytes().to_vec();
        data.extend_from_slice(payload);
        data
    }

    /// A BATADV_MCAST packet addressed to us is delivered to the local host
    /// (the inner multicast frame is handed up), like a unicast-for-self.
    #[test]
    fn mcast_for_self_delivers_local() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        let payload = make_mcast(1, 10, b"multicast payload");
        let frame_bytes = make_link_frame(2, 1, ETH_P_BATMAN, payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut buf = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut buf[..]);
        let action = engine.handle_rx(core::time::Duration::ZERO, frame, &mut reply);

        assert!(matches!(action, RoutingAction::DeliverLocal));
    }

    /// An intermediate node forwards a BATADV_MCAST packet toward the next hop
    /// for its destination, decrementing TTL and preserving the inner payload.
    #[test]
    fn mcast_forwarded_to_next_hop() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Learn a route to node 5 via node 2.
        let ogm = make_ogm(5, 2, 1, 255, 50);
        let frame_ogm = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm);
        let mut buf = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut buf[..]);
        engine.handle_rx(
            core::time::Duration::ZERO,
            parse_link_frame(&frame_ogm),
            &mut reply,
        );

        // A BATADV_MCAST packet for node 5 arrives; forward it toward node 2.
        let payload = make_mcast(5, 10, b"group data");
        let frame_bytes = make_link_frame(3, 1, ETH_P_BATMAN, payload);
        let action = engine.handle_rx(
            core::time::Duration::ZERO,
            parse_link_frame(&frame_bytes),
            &mut reply,
        );

        assert!(matches!(action, RoutingAction::Consumed));
        assert_eq!(reply.dst, mac(2)); // next hop toward node 5
        assert_eq!(reply.protocol, ETH_P_BATMAN);
        let (fwd, rest) = BatmanMcastPacket::ref_from_prefix(reply.payload).unwrap();
        assert_eq!(fwd.packet_type, BATADV_MCAST);
        assert_eq!(fwd.dest, mac(5)); // final destination unchanged
        assert_eq!(fwd.ttl, 9); // decremented from 10
        assert_eq!(&rest[..b"group data".len()], b"group data");
    }
}

#[cfg(test)]
mod route_expiry {
    use core::time::Duration;

    use super::*;
    use crate::MAX_MISSED_OGMS;

    /// Feed one OGM for originator `orig` arriving via immediate neighbor `via`,
    /// driving the engine's receive path.  The path is stamped with the engine's
    /// **current OGM round** (`sequence_number`); advance that with
    /// [`advance_to_round`] to simulate elapsed rounds.  `now` is irrelevant to
    /// ageing (which is round-based) and only feeds the Trickle-timer reset.
    fn feed_ogm(engine: &mut BatmanEngine<8>, orig: u8, via: u8, seqno: u32, tq: u8) {
        let ogm = make_ogm(orig, via, seqno, tq, 50);
        let frame = make_link_frame(via, 0xff, ETH_P_BATMAN, ogm);
        let mut buf = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut buf[..]);
        engine.handle_rx(Duration::ZERO, parse_link_frame(&frame), &mut reply);
    }

    /// Jump the engine's own OGM round counter to `round`, as if it had emitted
    /// that many periodic broadcasts — the reference clock that gap-counting
    /// ages paths against.  (`sequence_number` is `pub`, so tests drive it
    /// directly instead of calling `produce_periodic_broadcast` repeatedly.)
    fn advance_to_round(engine: &mut BatmanEngine<8>, round: u32) {
        engine.sequence_number = round;
    }

    /// `next_hop` follows the highest-TQ path while it is fresh, but once that
    /// path goes stale (no refresh within `MAX_MISSED_OGMS` rounds) it falls
    /// back to a surviving lower-TQ path rather than returning the silent
    /// neighbor.
    #[test]
    fn next_hop_skips_stale_path_for_fresher_alternate() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Originator 9 is reachable via neighbor 2 (high TQ) and neighbor 3
        // (low TQ), both heard at round 0.
        feed_ogm(&mut engine, 9, 2, 1, 255);
        feed_ogm(&mut engine, 9, 3, 1, 100);
        assert_eq!(engine.next_hop(mac(9)), Some(mac(2)));

        // Rounds advance past the gap budget; only the via-3 path is refreshed,
        // so via-2 is now stale (last heard at round 0, current round 7 > 6).
        advance_to_round(&mut engine, MAX_MISSED_OGMS + 1);
        feed_ogm(&mut engine, 9, 3, 2, 100);

        // The stale higher-TQ via-2 path is skipped in favor of fresh via-3.
        assert_eq!(engine.next_hop(mac(9)), Some(mac(3)));
    }

    /// A destination all of whose paths have aged out has no next hop.
    #[test]
    fn next_hop_is_none_when_all_paths_stale() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));
        feed_ogm(&mut engine, 9, 2, 1, 255);

        advance_to_round(&mut engine, MAX_MISSED_OGMS + 1);
        assert_eq!(engine.next_hop(mac(9)), None);
    }

    /// A path refreshed every round stays live indefinitely: gap counting must
    /// reset on each refresh, not accumulate.
    #[test]
    fn next_hop_stays_live_while_refreshed_each_round() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));
        for round in 0..(MAX_MISSED_OGMS + 5) {
            advance_to_round(&mut engine, round);
            feed_ogm(&mut engine, 9, 2, round + 1, 255);
            assert_eq!(engine.next_hop(mac(9)), Some(mac(2)), "round {round}");
        }
    }

    /// The periodic sweep evicts originators heard on no path within the gap
    /// budget, prunes individual stale paths from survivors, and recomputes the
    /// cached best hop from what remains.
    #[test]
    fn purge_stale_evicts_dead_originator_and_recomputes_best() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));

        // Originator 9 via neighbor 2 (high TQ) and neighbor 3 (low TQ) at
        // round 0; originator 8 via neighbor 4 at round 0 only.
        feed_ogm(&mut engine, 9, 2, 1, 255);
        feed_ogm(&mut engine, 9, 3, 1, 100);
        feed_ogm(&mut engine, 8, 4, 1, 255);
        assert_eq!(engine.originator_table.len(), 2);
        // Initially 9's best hop is the high-TQ via-2 path.
        assert_eq!(engine.lookup_route(mac(9)), Some(mac(2)));

        // Refresh only 9-via-3 past the gap budget, then sweep: 9-via-2 and the
        // whole originator 8 have gone stale.
        advance_to_round(&mut engine, MAX_MISSED_OGMS + 1);
        feed_ogm(&mut engine, 9, 3, 2, 100);
        engine.purge_stale();

        // Originator 8 is gone; originator 9 survives on its one fresh path.
        assert_eq!(engine.originator_table.len(), 1);
        let r = &engine.originator_table[&mac(9)];
        assert_eq!(r.neighbor_ident, mac(9));
        assert_eq!(r.paths.len(), 1);
        assert_eq!(r.paths[0].neighbor_ident, mac(3));
        // Cached best hop recomputed from the surviving (lower-TQ) path.
        assert_eq!(r.best_next_hop, mac(3));
        assert_eq!(r.max_tq, 90);
    }
}

#[cfg(test)]
mod adaptive_backoff {
    use core::time::Duration;

    use super::*;

    const I_MIN: Duration = Duration::from_secs(1);
    const I_MAX: Duration = Duration::from_secs(64);

    /// Feed one OGM from `orig` via `via` through the receive path at `now`.
    fn feed_ogm(
        engine: &mut BatmanEngine<8>,
        orig: u8,
        via: u8,
        seqno: u32,
        tq: u8,
        now: Duration,
    ) {
        let ogm = make_ogm(orig, via, seqno, tq, 50);
        let frame = make_link_frame(via, 0xff, ETH_P_BATMAN, ogm);
        let mut buf = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut buf[..]);
        engine.handle_rx(now, parse_link_frame(&frame), &mut reply);
    }

    /// Interfaces configured with different bounds schedule on their own clocks:
    /// the faster link is due first and is the one `due_interface` selects.
    #[test]
    fn interfaces_with_distinct_bounds_schedule_independently() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));
        // Interface 0 is a fast link (sub-second floor); interface 1 is slow.
        engine.configure_interface_ogm(0, I_MIN, Duration::from_secs(4), Duration::ZERO);
        engine.configure_interface_ogm(1, Duration::from_secs(5), I_MAX, Duration::ZERO);

        // The soonest due is the fast link, within its [i_min/2, i_min) window.
        let next = engine.next_broadcast_after(Duration::ZERO);
        assert!(
            next < I_MIN,
            "fast link should be due within i_min, got {next:?}"
        );

        // Nothing is due at t=0 (both first-fires are strictly in the future).
        assert_eq!(engine.due_interface(Duration::ZERO), None);
        // By t=2s the fast link is overdue but the slow link (>=2.5s) is not.
        assert_eq!(engine.due_interface(Duration::from_secs(2)), Some(0));
    }

    /// Emitting on an interface backs its timer off; an inconsistent OGM (here a
    /// newly discovered originator) snaps every interface back to `i_min`, while
    /// a consistent re-heard OGM leaves the grown interval untouched.
    #[test]
    fn inconsistency_resets_backoff_consistency_does_not() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));
        engine.configure_interface_ogm(0, I_MIN, I_MAX, Duration::ZERO);

        // Back the interface off several rounds so its next fire is well beyond
        // i_min (each on_emit doubles the interval).
        for _ in 0..5 {
            engine.on_interface_emitted(0, Duration::ZERO);
        }
        let grown = engine.next_broadcast_after(Duration::ZERO);
        assert!(grown > I_MIN, "interval should have grown, got {grown:?}");

        // A consistent OGM we have already converged on must not reset backoff.
        feed_ogm(&mut engine, 9, 2, 1, 255, Duration::ZERO); // first sight => inconsistent
        engine.reset_ogm_timers(Duration::ZERO); // re-grow deterministically below
        for _ in 0..5 {
            engine.on_interface_emitted(0, Duration::ZERO);
        }
        let grown = engine.next_broadcast_after(Duration::ZERO);
        feed_ogm(&mut engine, 9, 2, 2, 255, Duration::ZERO); // re-heard, nothing new
        assert_eq!(
            engine.next_broadcast_after(Duration::ZERO),
            grown,
            "a consistent OGM must not disturb the backoff"
        );

        // A brand-new originator is an inconsistency: backoff snaps to i_min.
        feed_ogm(&mut engine, 8, 3, 1, 255, Duration::ZERO);
        let after = engine.next_broadcast_after(Duration::ZERO);
        assert!(
            after < I_MIN,
            "a new originator must reset backoff to i_min, got {after:?}"
        );
    }

    /// An equal-quality copy of an already-known route arriving via a *different*
    /// neighbor must not be treated as a topology change.  In a redundant mesh
    /// the same originator is heard via several equal-cost neighbors every round;
    /// if each such copy flipped `best_next_hop` it would latch a spurious
    /// inconsistency and pin the Trickle backoff at `i_min` forever (the
    /// "reflexive reset" failure).  The incumbent next hop must stick, leaving
    /// the grown backoff untouched.
    #[test]
    fn equal_quality_alternate_path_does_not_reset_backoff() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));
        engine.configure_interface_ogm(0, I_MIN, I_MAX, Duration::ZERO);

        // Converge on a route to originator 9 via neighbor 2, then clear the
        // resulting reset and back the interface off several rounds.
        feed_ogm(&mut engine, 9, 2, 1, 255, Duration::ZERO);
        engine.reset_ogm_timers(Duration::ZERO);
        for _ in 0..5 {
            engine.on_interface_emitted(0, Duration::ZERO);
        }
        let grown = engine.next_broadcast_after(Duration::ZERO);
        assert!(grown > I_MIN, "interval should have grown, got {grown:?}");

        // The same originator, same seqno, *equal* TQ, but heard via a different
        // neighbor (3).  This is a redundant equal-cost path, not a change.
        feed_ogm(&mut engine, 9, 3, 1, 255, Duration::ZERO);
        assert_eq!(
            engine.next_broadcast_after(Duration::ZERO),
            grown,
            "an equal-cost alternate path must not disturb the backoff"
        );
    }

    /// A *strictly better* next hop is a genuine inconsistency and must reset the
    /// backoff.  Once the incumbent next hop's quality degrades, a higher-quality
    /// alternate is allowed to take over and snap the Trickle timers to `i_min`.
    #[test]
    fn strictly_better_next_hop_resets_backoff() {
        let mut engine: BatmanEngine<8> = BatmanEngine::new(mac(1));
        engine.configure_interface_ogm(0, I_MIN, I_MAX, Duration::ZERO);

        // Converge on originator 9 via neighbor 2 at full quality, then let the
        // incumbent's quality degrade (a lower-TQ OGM via the same neighbor).
        feed_ogm(&mut engine, 9, 2, 1, 255, Duration::ZERO);
        feed_ogm(&mut engine, 9, 2, 2, 200, Duration::ZERO);

        // Clear the resulting resets and back the interface well off.
        engine.reset_ogm_timers(Duration::ZERO);
        for _ in 0..5 {
            engine.on_interface_emitted(0, Duration::ZERO);
        }
        let grown = engine.next_broadcast_after(Duration::ZERO);
        assert!(grown > I_MIN, "interval should have grown, got {grown:?}");

        // Neighbor 3 now offers a strictly higher quality than the degraded
        // incumbent: a real next-hop change that must reset the backoff.
        feed_ogm(&mut engine, 9, 3, 3, 255, Duration::ZERO);
        let after = engine.next_broadcast_after(Duration::ZERO);
        assert!(
            after < I_MIN,
            "a strictly better next hop must reset backoff to i_min, got {after:?}"
        );
    }
}
