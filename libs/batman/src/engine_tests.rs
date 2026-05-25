use std::time::Instant;

use interfaces::{
    engine::{MeshRoutingEngine, RoutingAction},
    frame::{LinkFrame, LinkFrameDataMut},
    link::MeshIdentifier,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::{
    BatmanEngine,
    wire::{BATADV_IV_OGM, BATADV_UNICAST, BatmanOgmPacket, BatmanUnicastPacket, ETH_P_BATMAN},
};

// Helper to create a LinkFrame from raw bytes
fn make_link_frame(src: u8, dst: u8, protocol: u16, payload: Vec<u8>) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(src.as_bytes());
    data.extend_from_slice(dst.as_bytes());
    data.extend_from_slice(&protocol.to_ne_bytes());
    data.extend(payload);
    data
}

// Helper to parse a LinkFrame from bytes
fn parse_link_frame(data: &[u8]) -> &LinkFrame<u8> {
    LinkFrame::<u8>::ref_from_prefix(data).unwrap().0
}

// Helper to create an OGM packet
fn make_ogm(orig: u8, prev_sender: u8, seqno: u32, tq: u8, ttl: u8) -> Vec<u8> {
    let ogm = BatmanOgmPacket {
        packet_type: BATADV_IV_OGM,
        version: 5,
        ttl,
        tq,
        seqno: seqno.to_be(), // Network byte order
        orig,
        prev_sender,
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
        dest: dest,
    };
    data.extend_from_slice(unicast.as_bytes());
    data.extend_from_slice(payload);
    data
}

#[cfg(test)]
mod ogm_generation {
    use super::*;

    #[test]
    fn test_generate_initial_ogm() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        let ogm_bytes = engine.produce_periodic_broadcast(Instant::now()).unwrap();
        let (ogm, _) = BatmanOgmPacket::<u8>::ref_from_prefix(ogm_bytes).unwrap();

        assert_eq!(ogm.packet_type, BATADV_IV_OGM);
        assert_eq!(ogm.version, 5);
        assert_eq!(ogm.ttl, 50);
        assert_eq!(ogm.tq, 255); // Maximum quality at origin
        let seqno = ogm.seqno;
        assert_eq!(seqno, 1u32.to_be()); // First sequence number (in network byte order)
        assert_eq!(ogm.orig, 1);
        assert_eq!(ogm.prev_sender, 1);
    }

    #[test]
    fn test_sequence_number_increments() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Generate multiple OGMs
        for i in 1..=5 {
            let ogm_bytes = engine.produce_periodic_broadcast(Instant::now()).unwrap();
            let (ogm, _) = BatmanOgmPacket::<u8>::ref_from_prefix(ogm_bytes).unwrap();
            let seqno = ogm.seqno;
            assert_eq!(seqno, (i as u32).to_be()); // Check in network byte order
        }
    }

    #[test]
    fn test_sequence_number_wraps() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);
        engine.sequence_number = u32::MAX - 1;

        engine.produce_periodic_broadcast(Instant::now()).unwrap();
        let ogm_bytes = engine.produce_periodic_broadcast(Instant::now()).unwrap();
        let (ogm, _) = BatmanOgmPacket::<u8>::ref_from_prefix(ogm_bytes).unwrap();
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
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Receive our own OGM
        let ogm_payload = make_ogm(1, 1, 100, 255, 50);
        let frame_bytes = make_link_frame(1, 0xff, ETH_P_BATMAN, ogm_payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(frame, &mut reply);

        // Should be consumed (dropped) without creating route
        assert!(matches!(action, RoutingAction::Consumed));
        assert_eq!(engine.originator_table.len(), 0);
    }

    #[test]
    fn test_new_originator_creation() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Receive OGM from node 2 via node 2 (direct neighbor)
        let ogm_payload = make_ogm(2, 2, 1, 255, 50);
        let frame_bytes = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm_payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(frame, &mut reply);

        assert!(matches!(action, RoutingAction::Consumed));
        assert_eq!(engine.originator_table.len(), 1);

        let record = &engine.originator_table[0];
        assert_eq!(record.neighbor_ident, 2);
        assert_eq!(record.best_next_hop, 2);
        assert_eq!(record.last_seqno, 1);
        // TQ should be 255 - 10 = 245 after attenuation
        assert_eq!(record.max_tq, 245);
    }

    #[test]
    fn test_tq_attenuation() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Receive OGM with TQ 255
        let ogm_payload = make_ogm(2, 2, 1, 255, 50);
        let frame_bytes = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm_payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        engine.handle_rx(frame, &mut reply);

        // Should attenuate by 10
        assert_eq!(engine.originator_table[0].max_tq, 245);
    }

    #[test]
    fn test_tq_saturation_at_zero() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Receive OGM with very low TQ
        let ogm_payload = make_ogm(2, 2, 1, 5, 50);
        let frame_bytes = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm_payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        engine.handle_rx(frame, &mut reply);

        // 5 - 10 should saturate to 0, not underflow
        assert_eq!(engine.originator_table[0].max_tq, 0);
    }

    #[test]
    fn test_ogm_forwarding() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Receive OGM from node 3 via node 2
        let ogm_payload = make_ogm(3, 2, 1, 245, 50);
        let frame_bytes = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm_payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(frame, &mut reply);

        assert!(matches!(action, RoutingAction::Consumed));

        // Check that reply buffer contains forwarded OGM
        assert_eq!(reply.dst, u8::BROADCAST);
        assert_eq!(reply.protocol, ETH_P_BATMAN);

        // Parse the forwarded OGM
        let (forwarded_ogm, _) = BatmanOgmPacket::<u8>::ref_from_prefix(reply.payload).unwrap();
        assert_eq!(forwarded_ogm.orig, 3); // Original source unchanged
        assert_eq!(forwarded_ogm.prev_sender, 1); // Updated to self
        assert_eq!(forwarded_ogm.ttl, 49); // Decremented from 50 to 49
        assert_eq!(forwarded_ogm.tq, 235); // Attenuated from 245 to 235
    }

    #[test]
    fn test_ogm_ttl_expiration() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Receive OGM with TTL = 1
        let ogm_payload = make_ogm(2, 2, 1, 255, 1);
        let frame_bytes = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm_payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        engine.handle_rx(frame, &mut reply);

        // Should learn the route but NOT forward
        assert_eq!(engine.originator_table.len(), 1);
        // Reply should not have been populated for broadcast
        assert_eq!(reply.protocol, 0); // Default value, not set
    }

    #[test]
    fn test_multiple_paths_to_originator() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Receive OGM from node 5 via node 2 (first path)
        let ogm1 = make_ogm(5, 2, 1, 240, 50);
        let frame1 = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm1);
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
        engine.handle_rx(parse_link_frame(&frame1), &mut reply);

        // Receive OGM from node 5 via node 3 (second path, better quality)
        let ogm2 = make_ogm(5, 3, 2, 250, 50);
        let frame2 = make_link_frame(3, 0xff, ETH_P_BATMAN, ogm2);
        engine.handle_rx(parse_link_frame(&frame2), &mut reply);

        assert_eq!(engine.originator_table.len(), 1);
        let record = &engine.originator_table[0];

        // Should track both paths
        assert_eq!(record.paths.len(), 2);

        // Best next hop should be node 3 (higher TQ: 250-10=240 vs 240-10=230)
        assert_eq!(record.best_next_hop, 3);
        assert_eq!(record.max_tq, 240);
    }

    #[test]
    fn test_path_limit_per_originator() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Add 5 different paths (limit is 4)
        for neighbor in 2..=6 {
            let ogm = make_ogm(10, neighbor, neighbor as u32, 200, 50);
            let frame = make_link_frame(neighbor, 0xff, ETH_P_BATMAN, ogm);
            let mut reply_buffer = [0u8; 256];
            let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
            engine.handle_rx(parse_link_frame(&frame), &mut reply);
        }

        let record = &engine.originator_table[0];
        // Should only track 4 paths (the limit)
        assert_eq!(record.paths.len(), 4);
    }

    #[test]
    fn test_sequence_number_update() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Receive initial OGM
        let ogm1 = make_ogm(2, 2, 100, 255, 50);
        let frame1 = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm1);
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
        engine.handle_rx(parse_link_frame(&frame1), &mut reply);

        assert_eq!(engine.originator_table[0].last_seqno, 100);

        // Receive newer OGM
        let ogm2 = make_ogm(2, 2, 105, 255, 50);
        let frame2 = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm2);
        engine.handle_rx(parse_link_frame(&frame2), &mut reply);

        assert_eq!(engine.originator_table[0].last_seqno, 105);
    }

    #[test]
    fn test_old_sequence_number_ignored() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Receive initial OGM with seqno 100
        let ogm1 = make_ogm(2, 2, 100, 255, 50);
        let frame1 = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm1);
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
        engine.handle_rx(parse_link_frame(&frame1), &mut reply);

        let initial_tq = engine.originator_table[0].max_tq;

        // Receive older OGM with seqno 95 and different TQ
        let ogm2 = make_ogm(2, 2, 95, 200, 50);
        let frame2 = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm2);
        engine.handle_rx(parse_link_frame(&frame2), &mut reply);

        // Sequence number and TQ should not change
        assert_eq!(engine.originator_table[0].last_seqno, 100);
        assert_eq!(engine.originator_table[0].max_tq, initial_tq);
    }

    #[test]
    fn test_originator_table_capacity() {
        let mut engine: BatmanEngine<4, u8> = BatmanEngine::new(1);

        // Fill table to capacity (4 originators)
        for orig in 10..14 {
            let ogm = make_ogm(orig, orig, 1, 255, 50);
            let frame = make_link_frame(orig, 0xff, ETH_P_BATMAN, ogm);
            let mut reply_buffer = [0u8; 256];
            let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
            engine.handle_rx(parse_link_frame(&frame), &mut reply);
        }

        assert_eq!(engine.originator_table.len(), 4);

        // Try to add one more (should be dropped)
        let ogm = make_ogm(20, 20, 1, 255, 50);
        let frame = make_link_frame(20, 0xff, ETH_P_BATMAN, ogm);
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
        engine.handle_rx(parse_link_frame(&frame), &mut reply);

        // Table should still be 4 (new entry dropped)
        assert_eq!(engine.originator_table.len(), 4);
    }
}

#[cfg(test)]
mod unicast_forwarding {
    use super::*;

    #[test]
    fn test_unicast_local_delivery() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Receive unicast packet destined for us
        let unicast_payload = make_unicast(1, 10, b"Hello");
        let frame_bytes = make_link_frame(2, 1, ETH_P_BATMAN, unicast_payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(frame, &mut reply);

        assert!(matches!(action, RoutingAction::DeliverLocal));
    }

    #[test]
    fn test_unicast_ttl_expiration() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Add a route to node 5 via node 2
        let ogm = make_ogm(5, 2, 1, 255, 50);
        let frame_ogm = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm);
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
        engine.handle_rx(parse_link_frame(&frame_ogm), &mut reply);

        // Receive unicast with TTL=1 (should expire)
        let unicast_payload = make_unicast(5, 1, b"data");
        let frame_bytes = make_link_frame(3, 1, ETH_P_BATMAN, unicast_payload);
        let frame = parse_link_frame(&frame_bytes);

        let action = engine.handle_rx(frame, &mut reply);

        // Should be consumed (dropped) due to TTL
        assert!(matches!(action, RoutingAction::Consumed));
    }

    #[test]
    fn test_unicast_forwarding_with_ttl_decrement() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Add a route to node 5 via node 2
        let ogm = make_ogm(5, 2, 1, 255, 50);
        let frame_ogm = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm);
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
        engine.handle_rx(parse_link_frame(&frame_ogm), &mut reply);

        // Receive unicast packet destined for node 5
        let unicast_payload = make_unicast(5, 10, b"payload");
        let frame_bytes = make_link_frame(3, 1, ETH_P_BATMAN, unicast_payload);
        let frame = parse_link_frame(&frame_bytes);

        let action = engine.handle_rx(frame, &mut reply);

        assert!(matches!(action, RoutingAction::Consumed));

        // Check reply buffer
        assert_eq!(reply.dst, 2); // Should forward to node 2
        assert_eq!(reply.protocol, ETH_P_BATMAN);

        // Parse the forwarded unicast header
        let (forwarded_unicast, _) =
            BatmanUnicastPacket::<u8>::ref_from_prefix(reply.payload).unwrap();
        assert_eq!(forwarded_unicast.dest, 5); // Destination unchanged
        assert_eq!(forwarded_unicast.ttl, 9); // TTL decremented from 10 to 9
    }

    #[test]
    fn test_unicast_unknown_destination() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Receive unicast for unknown destination
        let unicast_payload = make_unicast(99, 10, b"data");
        let frame_bytes = make_link_frame(2, 1, ETH_P_BATMAN, unicast_payload);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(frame, &mut reply);

        // Should be consumed (dropped) - no route known
        assert!(matches!(action, RoutingAction::Consumed));
    }
}

#[cfg(test)]
mod routing_lookup {
    use super::*;

    #[test]
    fn test_lookup_route_exists() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Add a route to node 5 via node 2
        let ogm = make_ogm(5, 2, 1, 255, 50);
        let frame = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm);
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
        engine.handle_rx(parse_link_frame(&frame), &mut reply);

        let next_hop = engine.lookup_route(5);
        assert_eq!(next_hop, Some(2));
    }

    #[test]
    fn test_lookup_route_not_exists() {
        let engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        let next_hop = engine.lookup_route(99);
        assert_eq!(next_hop, None);
    }

    #[test]
    fn test_lookup_route_updates_with_better_path() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Add route to node 5 via node 2 (TQ=200)
        let ogm1 = make_ogm(5, 2, 1, 200, 50);
        let frame1 = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm1);
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
        engine.handle_rx(parse_link_frame(&frame1), &mut reply);

        assert_eq!(engine.lookup_route(5), Some(2));

        // Add better route to node 5 via node 3 (TQ=250)
        let ogm2 = make_ogm(5, 3, 2, 250, 50);
        let frame2 = make_link_frame(3, 0xff, ETH_P_BATMAN, ogm2);
        engine.handle_rx(parse_link_frame(&frame2), &mut reply);

        // Should now route via node 3
        assert_eq!(engine.lookup_route(5), Some(3));
    }
}

#[cfg(test)]
mod protocol_filtering {
    use super::*;

    #[test]
    fn test_wrong_protocol_ignored() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Send packet with wrong protocol number
        let frame_bytes = make_link_frame(2, 1, 0x0800, vec![1, 2, 3, 4]);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(frame, &mut reply);

        assert!(matches!(action, RoutingAction::Consumed));
        assert_eq!(engine.originator_table.len(), 0);
    }

    #[test]
    fn test_empty_payload_ignored() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Send BATMAN packet with empty payload
        let frame_bytes = make_link_frame(2, 1, ETH_P_BATMAN, vec![]);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(frame, &mut reply);

        assert!(matches!(action, RoutingAction::Consumed));
    }

    #[test]
    fn test_unknown_batman_packet_type() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Send packet with unknown BATMAN packet type destined for node 5 (not us)
        let frame_bytes = make_link_frame(2, 5, ETH_P_BATMAN, vec![0x99, 1, 2, 3]);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(frame, &mut reply);

        // Unknown packet type should trigger the default match arm and be consumed (no route known)
        assert!(matches!(action, RoutingAction::Consumed));
    }

    #[test]
    fn test_malformed_ogm_ignored() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Send truncated OGM packet
        let frame_bytes = make_link_frame(2, 0xff, ETH_P_BATMAN, vec![BATADV_IV_OGM, 5, 50]);
        let frame = parse_link_frame(&frame_bytes);

        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        let action = engine.handle_rx(frame, &mut reply);

        assert!(matches!(action, RoutingAction::Consumed));
        assert_eq!(engine.originator_table.len(), 0);
    }
}

#[cfg(test)]
mod edge_cases {
    use super::*;

    #[test]
    fn test_rapid_sequence_number_changes() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Rapidly changing sequence numbers
        for seqno in [1, 100, 50, 200, 75, 300] {
            let ogm = make_ogm(2, 2, seqno, 255, 50);
            let frame = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm);
            let mut reply_buffer = [0u8; 256];
            let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
            engine.handle_rx(parse_link_frame(&frame), &mut reply);
        }

        // Should have the highest sequence number
        assert_eq!(engine.originator_table[0].last_seqno, 300);
    }

    #[test]
    fn test_same_originator_different_paths_simultaneous() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Receive OGMs from same originator via different neighbors in quick succession
        let neighbors = [2, 3, 4, 5];
        for (i, &neighbor) in neighbors.iter().enumerate() {
            let tq = 255 - (i as u8 * 10); // Different qualities
            let ogm = make_ogm(10, neighbor, 1, tq, 50);
            let frame = make_link_frame(neighbor, 0xff, ETH_P_BATMAN, ogm);
            let mut reply_buffer = [0u8; 256];
            let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
            engine.handle_rx(parse_link_frame(&frame), &mut reply);
        }

        assert_eq!(engine.originator_table.len(), 1);
        assert_eq!(engine.originator_table[0].paths.len(), 4);
        // Best path should be via neighbor 2 (highest TQ)
        assert_eq!(engine.originator_table[0].best_next_hop, 2);
    }

    #[test]
    fn test_zero_ttl_not_forwarded() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // Receive OGM with TTL=0 (shouldn't happen in practice, but test boundary)
        let ogm = make_ogm(2, 2, 1, 255, 0);
        let frame = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm);
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);

        engine.handle_rx(parse_link_frame(&frame), &mut reply);

        // Should learn but not forward
        assert_eq!(engine.originator_table.len(), 1);
        assert_eq!(reply.protocol, 0); // Not populated for forwarding
    }

    #[test]
    fn test_path_metric_updates_on_same_neighbor() {
        let mut engine: BatmanEngine<8, u8> = BatmanEngine::new(1);

        // First OGM from originator 5 via neighbor 2
        let ogm1 = make_ogm(5, 2, 1, 200, 50);
        let frame1 = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm1);
        let mut reply_buffer = [0u8; 256];
        let mut reply = LinkFrameDataMut::from(&mut reply_buffer[..]);
        engine.handle_rx(parse_link_frame(&frame1), &mut reply);

        assert_eq!(engine.originator_table[0].paths[0].last_tq, 190);

        // Second OGM from same originator via same neighbor with different TQ
        let ogm2 = make_ogm(5, 2, 2, 250, 50);
        let frame2 = make_link_frame(2, 0xff, ETH_P_BATMAN, ogm2);
        engine.handle_rx(parse_link_frame(&frame2), &mut reply);

        // Path metric should be updated
        assert_eq!(engine.originator_table[0].paths[0].last_tq, 240);
        assert_eq!(engine.originator_table[0].paths.len(), 1); // Still just one path
    }
}
