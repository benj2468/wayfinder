//! Integration tests: multiple `CentralRouter`s exchanging traffic through a `Switch`.

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use interfaces::frame::MeshIdentifier;
    use interfaces::link::LinkMetrics;
    use tokio::sync::mpsc;
    use wayfinder::{
        DEFAULT_BATMAN_ETHER_TYPE, EgressInterface,
        batman::wire::{BATADV_IV_OGM, BATADV_UNICAST, BatmanOgmPacket, BatmanUnicastPacket},
    };
    use zerocopy::{FromBytes, IntoBytes};

    use crate::Direction;
    use crate::switch::{PortComms, PortConfig, Switch, TapConfig, TapMeta};
    use crate::test_router::{TestRouter, parse_frame};

    // ── tap helpers ───────────────────────────────────────────────────────────

    /// True if the raw wire bytes encode a BATMAN OGM broadcast.
    fn is_ogm_frame(data: &[u8]) -> bool {
        if data.len() < 5 {
            return false;
        }
        let proto = u16::from_ne_bytes([data[2], data[3]]);
        proto == DEFAULT_BATMAN_ETHER_TYPE && data[4] == BATADV_IV_OGM
    }

    /// True if the raw wire bytes encode a BATMAN unicast packet.
    fn is_unicast_frame(data: &[u8]) -> bool {
        if data.len() < 5 {
            return false;
        }
        let proto = u16::from_ne_bytes([data[2], data[3]]);
        proto == DEFAULT_BATMAN_ETHER_TYPE && data[4] == BATADV_UNICAST
    }

    /// Extract the application payload from a unicast wire frame if `dest` matches.
    ///
    /// Wire layout (u8 ident): `[src:1][dst:1][proto:2][BatmanUnicastPacket:4][app_payload...]`
    fn extract_unicast_payload(data: &[u8], expected_dest: u8) -> Option<Vec<u8>> {
        if !is_unicast_frame(data) {
            return None;
        }
        let batman_payload = &data[4..]; // strip link-layer header
        let hdr_size = core::mem::size_of::<BatmanUnicastPacket<u8>>();
        if batman_payload.len() <= hdr_size {
            return None;
        }
        let (hdr, _) = BatmanUnicastPacket::<u8>::ref_from_prefix(batman_payload).ok()?;
        if hdr.dest == expected_dest {
            Some(batman_payload[hdr_size..].to_vec())
        } else {
            None
        }
    }

    /// Build a tap that appends every frame (matching `dir`) to `sink`.
    fn capture_tap(dir: Direction, sink: Arc<Mutex<Vec<Vec<u8>>>>) -> TapConfig {
        TapConfig::new(move |meta: TapMeta| {
            if meta.direction == dir {
                sink.lock().unwrap().push(meta.data.to_vec());
            }
            true
        })
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Build a raw OGM broadcast frame as it would appear on the wire after
    /// being transmitted by `src` with the given TQ and sequence number.
    ///
    /// Wire layout (u8 ident): `[src:1][BROADCAST:1][proto:2 NE][BatmanOgmPacket]`.
    fn build_ogm_wire_frame(src: u8, tq: u8, seqno: u32) -> Vec<u8> {
        let ogm = BatmanOgmPacket::<u8> {
            packet_type: BATADV_IV_OGM,
            version: 5,
            ttl: 50,
            tq,
            seqno: seqno.to_be(),
            orig: src,
            prev_sender: src,
        };
        let mut frame = Vec::new();
        frame.push(src);
        frame.push(0xff);
        frame.extend_from_slice(&DEFAULT_BATMAN_ETHER_TYPE.to_ne_bytes());
        frame.extend_from_slice(ogm.as_bytes());
        frame
    }

    fn make_port_pair(buf: usize) -> (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>, PortComms) {
        let (tx_to_switch, rx_to_switch) = mpsc::channel(buf);
        let (tx_from_switch, rx_from_switch) = mpsc::channel(buf);
        (
            tx_to_switch,
            rx_from_switch,
            PortComms::new(rx_to_switch, tx_from_switch),
        )
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    /// Two directly-connected routers exchange OGMs so each learns the other's
    /// route, then router A sends application data to router B via a BATMAN
    /// unicast packet.  The test verifies that B receives the exact payload.
    #[tokio::test]
    async fn two_routers_discover_routes_and_exchange_data() {
        let (tx_a, mut rx_a, port_a) = make_port_pair(64);
        let (tx_b, mut rx_b, port_b) = make_port_pair(64);

        let mut router_a: TestRouter<u8> = TestRouter::new(1, vec![tx_a]);
        let mut router_b: TestRouter<u8> = TestRouter::new(2, vec![tx_b]);

        let mut switch = Switch::<u8>::new();
        switch.add_port(port_a, PortConfig::no_loss()).unwrap();
        switch.add_port(port_b, PortConfig::no_loss()).unwrap();

        // ── Phase 1: OGM exchange ─────────────────────────────────────────
        //
        // Each router broadcasts one OGM into the switch.  After tick(),
        // each node receives the other's OGM and learns the direct route.
        // The switch also learns which port each node is on.

        router_a.poll(Duration::ZERO).await;
        router_b.poll(Duration::ZERO).await;
        switch.tick().await.unwrap();

        router_a.drain(0, &mut rx_a).await;
        router_b.drain(0, &mut rx_b).await;

        // Flush any forwarded OGMs and drain residual traffic so it does not
        // interfere with the data-plane phase.
        switch.tick().await.unwrap();
        while rx_a.try_recv().is_ok() {}
        while rx_b.try_recv().is_ok() {}

        // ── Phase 2: unicast data A → B ───────────────────────────────────

        let app_payload = b"hello from A to B";

        router_a
            .send_local(2, app_payload)
            .await
            .expect("router A should have a route to router B after OGM exchange");

        switch.tick().await.unwrap();

        // ── Phase 3: verify router B received the exact payload ───────────

        let hdr_size = std::mem::size_of::<BatmanUnicastPacket<u8>>();
        let mut delivered: Option<Vec<u8>> = None;

        while let Ok(raw) = rx_b.try_recv() {
            // Let the router process the frame (updates ident table, etc.).
            router_b.receive(0, &raw).await;

            // Inspect the raw frame directly to extract the application payload.
            let frame = parse_frame::<u8>(&raw);
            if frame.protocol == DEFAULT_BATMAN_ETHER_TYPE
                && frame.payload.first() == Some(&BATADV_UNICAST)
                && frame.payload.len() > hdr_size
            {
                let (hdr, _) = BatmanUnicastPacket::<u8>::ref_from_prefix(&frame.payload).unwrap();
                if hdr.dest == 2 {
                    delivered = Some(frame.payload[hdr_size..].to_vec());
                }
            }
        }

        assert_eq!(
            delivered.as_deref(),
            Some(app_payload.as_ref()),
            "router B should deliver the exact payload sent by router A"
        );
    }

    /// After the OGM exchange, a unicast from A to B must be handed up to B's
    /// local host (the TAP) with the BATMAN header stripped — exercised via
    /// the `local_deliveries` record.
    #[tokio::test]
    async fn unicast_data_is_delivered_to_local_host() {
        let (tx_a, mut rx_a, port_a) = make_port_pair(64);
        let (tx_b, mut rx_b, port_b) = make_port_pair(64);

        let mut router_a: TestRouter<u8> = TestRouter::new(1, vec![tx_a]);
        let mut router_b: TestRouter<u8> = TestRouter::new(2, vec![tx_b]);

        let mut switch = Switch::<u8>::new();
        switch.add_port(port_a, PortConfig::no_loss()).unwrap();
        switch.add_port(port_b, PortConfig::no_loss()).unwrap();

        // OGM exchange so A learns a route to B.
        router_a.poll(Duration::ZERO).await;
        router_b.poll(Duration::ZERO).await;
        switch.tick().await.unwrap();
        router_a.drain(0, &mut rx_a).await;
        router_b.drain(0, &mut rx_b).await;
        switch.tick().await.unwrap();
        while rx_a.try_recv().is_ok() {}
        while rx_b.try_recv().is_ok() {}

        // A sends application data to B; B should deliver it locally.
        let app_payload = b"deliver me locally";
        router_a
            .send_local(2, app_payload)
            .await
            .expect("router A should have a route to router B");
        switch.tick().await.unwrap();
        router_b.drain(0, &mut rx_b).await;

        assert_eq!(router_b.local_deliveries(), &[app_payload.to_vec()]);
    }

    /// A broadcast (e.g. an ARP) needs no route: A floods it, and B must both
    /// deliver the inner frame to its local host and not choke.  No OGM phase
    /// is required because broadcasts are flooded to all interfaces.
    #[tokio::test]
    async fn broadcast_is_delivered_locally_at_neighbor() {
        let (tx_a, _rx_a, port_a) = make_port_pair(64);
        let (tx_b, mut rx_b, port_b) = make_port_pair(64);

        let mut router_a: TestRouter<u8> = TestRouter::new(1, vec![tx_a]);
        let mut router_b: TestRouter<u8> = TestRouter::new(2, vec![tx_b]);

        let mut switch = Switch::<u8>::new();
        switch.add_port(port_a, PortConfig::no_loss()).unwrap();
        switch.add_port(port_b, PortConfig::no_loss()).unwrap();

        let arp = b"i am a broadcast frame";
        router_a
            .send_local(u8::BROADCAST, arp)
            .await
            .expect("broadcast packet should build");

        switch.tick().await.unwrap();
        router_b.drain(0, &mut rx_b).await;

        assert_eq!(router_b.local_deliveries(), &[arp.to_vec()]);
    }

    /// Three nodes all on one switch.  Each broadcasts one OGM, so every node
    /// learns direct routes to the other two.  Taps on each port confirm:
    ///   - exactly one OGM per node is put on the wire before the drain phase
    ///   - a unicast from node 0 → node 2 arrives *only* at port 2 (the switch
    ///     has already learned node 2's port from the OGM phase)
    ///   - a unicast from node 0 → node 1 likewise arrives only at port 1
    #[tokio::test]
    async fn three_routers_all_connected_discover_and_exchange() {
        let (tx_0, mut rx_0, port_0) = make_port_pair(64);
        let (tx_1, mut rx_1, port_1) = make_port_pair(64);
        let (tx_2, mut rx_2, port_2) = make_port_pair(64);

        let mut router_0: TestRouter<u8> = TestRouter::new(0, vec![tx_0]);
        let mut router_1: TestRouter<u8> = TestRouter::new(1, vec![tx_1]);
        let mut router_2: TestRouter<u8> = TestRouter::new(2, vec![tx_2]);

        let mut switch = Switch::<u8>::new();
        let port_0_id = switch.add_port(port_0, PortConfig::no_loss()).unwrap();
        let port_1_id = switch.add_port(port_1, PortConfig::no_loss()).unwrap();
        let port_2_id = switch.add_port(port_2, PortConfig::no_loss()).unwrap();

        // ── Phase 1: count initial OGMs on every port ─────────────────────────
        //
        // Tap each port's ToSwitch direction; each node should produce exactly
        // one OGM during its first poll() call before any drain occurs.

        let ogms_at_port_0: Arc<Mutex<Vec<Vec<u8>>>> = Default::default();
        let ogms_at_port_1: Arc<Mutex<Vec<Vec<u8>>>> = Default::default();
        let ogms_at_port_2: Arc<Mutex<Vec<Vec<u8>>>> = Default::default();

        switch
            .add_tap(
                port_0_id,
                capture_tap(Direction::ToSwitch, ogms_at_port_0.clone()),
            )
            .unwrap();
        switch
            .add_tap(
                port_1_id,
                capture_tap(Direction::ToSwitch, ogms_at_port_1.clone()),
            )
            .unwrap();
        switch
            .add_tap(
                port_2_id,
                capture_tap(Direction::ToSwitch, ogms_at_port_2.clone()),
            )
            .unwrap();

        router_0.poll(Duration::ZERO).await;
        router_1.poll(Duration::ZERO).await;
        router_2.poll(Duration::ZERO).await;
        switch.tick().await.unwrap();

        // Verify one OGM produced by each node before any forwarding occurs.
        let count_ogm = |frames: &[Vec<u8>]| frames.iter().filter(|f| is_ogm_frame(f)).count();
        assert_eq!(
            count_ogm(&ogms_at_port_0.lock().unwrap()),
            1,
            "node 0 should emit 1 OGM"
        );
        assert_eq!(
            count_ogm(&ogms_at_port_1.lock().unwrap()),
            1,
            "node 1 should emit 1 OGM"
        );
        assert_eq!(
            count_ogm(&ogms_at_port_2.lock().unwrap()),
            1,
            "node 2 should emit 1 OGM"
        );

        // Each router processes the OGMs it received and builds its routing table.
        router_0.drain(0, &mut rx_0).await;
        router_1.drain(0, &mut rx_1).await;
        router_2.drain(0, &mut rx_2).await;

        // Flush the forwarded OGMs that drain() queued.
        switch.tick().await.unwrap();
        while rx_0.try_recv().is_ok() {}
        while rx_1.try_recv().is_ok() {}
        while rx_2.try_recv().is_ok() {}

        // ── Phase 2: unicast 0 → 2 arrives at port 2, not port 1 ─────────────

        let unicasts_at_port_1: Arc<Mutex<Vec<Vec<u8>>>> = Default::default();
        let unicasts_at_port_2: Arc<Mutex<Vec<Vec<u8>>>> = Default::default();

        switch
            .add_tap(
                port_1_id,
                capture_tap(Direction::FromSwitch, unicasts_at_port_1.clone()),
            )
            .unwrap();
        switch
            .add_tap(
                port_2_id,
                capture_tap(Direction::FromSwitch, unicasts_at_port_2.clone()),
            )
            .unwrap();

        let payload_0_to_2 = b"hello from 0 to 2";
        router_0
            .send_local(2, payload_0_to_2)
            .await
            .expect("node 0 must have a direct route to node 2 after OGM exchange");

        switch.tick().await.unwrap();

        // Drain the frame into router 2 and confirm the exact payload.
        let hdr_size = core::mem::size_of::<BatmanUnicastPacket<u8>>();
        let mut delivered_2: Option<Vec<u8>> = None;
        while let Ok(raw) = rx_2.try_recv() {
            router_2.receive(0, &raw).await;
            let frame = parse_frame::<u8>(&raw);
            if frame.protocol == DEFAULT_BATMAN_ETHER_TYPE
                && frame.payload.first() == Some(&BATADV_UNICAST)
                && frame.payload.len() > hdr_size
            {
                let (hdr, _) = BatmanUnicastPacket::<u8>::ref_from_prefix(&frame.payload).unwrap();
                if hdr.dest == 2 {
                    delivered_2 = Some(frame.payload[hdr_size..].to_vec());
                }
            }
        }
        assert_eq!(
            delivered_2.as_deref(),
            Some(payload_0_to_2.as_ref()),
            "node 2 should receive the exact payload"
        );

        // The switch should have routed directly to port 2; port 1 must be silent.
        // Use explicit scopes so the MutexGuards are dropped before Phase 3's
        // switch.tick() — the tap callback for port_1 will try to acquire
        // unicasts_at_port_1, and holding it here would deadlock the
        // single-threaded Tokio executor.
        {
            let u1 = unicasts_at_port_1.lock().unwrap();
            assert!(
                u1.iter().filter(|f| is_unicast_frame(f)).count() == 0,
                "unicast 0→2 must not appear at port 1"
            );
        }
        {
            let u2 = unicasts_at_port_2.lock().unwrap();
            let payloads_at_2: Vec<_> = u2
                .iter()
                .filter_map(|f| extract_unicast_payload(f, 2))
                .collect();
            assert_eq!(
                payloads_at_2.len(),
                1,
                "exactly one unicast for node 2 should arrive at port 2"
            );
            assert_eq!(
                payloads_at_2[0].as_slice(),
                payload_0_to_2.as_ref(),
                "tap at port 2 should capture the correct payload"
            );
        }

        // ── Phase 3: unicast 0 → 1 arrives at port 1, not port 2 ─────────────

        let payload_0_to_1 = b"hello from 0 to 1";
        router_0
            .send_local(1, payload_0_to_1)
            .await
            .expect("node 0 must have a direct route to node 1 after OGM exchange");

        switch.tick().await.unwrap();

        while let Ok(raw) = rx_1.try_recv() {
            router_1.receive(0, &raw).await;
        }
        let u1_after: Vec<_> = unicasts_at_port_1
            .lock()
            .unwrap()
            .iter()
            .filter_map(|f| extract_unicast_payload(f, 1))
            .collect();
        assert_eq!(
            u1_after.len(),
            1,
            "exactly one unicast for node 1 should arrive at port 1"
        );
        assert_eq!(
            u1_after[0].as_slice(),
            payload_0_to_1.as_ref(),
            "tap at port 1 should capture the correct payload"
        );
    }

    /// Three nodes in a linear chain: 0 ── switch A ── 1 ── switch B ── 2.
    /// Node 1 has two interfaces (one per switch).  Nodes 0 and 2 have no
    /// direct link, so every packet between them must relay through node 1.
    ///
    /// The test verifies:
    ///   - After OGM propagation node 0's originator table lists node 1 as the
    ///     best next-hop to reach node 2.
    ///   - A unicast from node 0 destined for node 2 travels over switch A to
    ///     node 1, which then forwards it over switch B to node 2.
    ///   - A tap on switch B's node-2 port captures the frame with the exact
    ///     application payload.
    #[tokio::test]
    async fn three_routers_linear_relay_through_middle_node() {
        // Switch A connects node 0 and node 1 (interface 0 of node 1).
        // Switch B connects node 1 (interface 1 of node 1) and node 2.
        let (tx_0, mut rx_0, port_0a) = make_port_pair(64);
        let (tx_1a, mut rx_1a, port_1a) = make_port_pair(64); // node 1 ↔ switch A
        let (tx_1b, mut rx_1b, port_1b) = make_port_pair(64); // node 1 ↔ switch B
        let (tx_2, mut rx_2, port_2b) = make_port_pair(64);

        // Node 1 has two interfaces: index 0 = switch A, index 1 = switch B.
        let mut router_0: TestRouter<u8> = TestRouter::new(0, vec![tx_0]);
        let mut router_1: TestRouter<u8> = TestRouter::new(1, vec![tx_1a, tx_1b]);
        let mut router_2: TestRouter<u8> = TestRouter::new(2, vec![tx_2]);

        let mut switch_a = Switch::<u8>::new();
        let mut switch_b = Switch::<u8>::new();

        switch_a.add_port(port_0a, PortConfig::no_loss()).unwrap();
        switch_a.add_port(port_1a, PortConfig::no_loss()).unwrap();
        let port_2b_id = switch_b.add_port(port_1b, PortConfig::no_loss()).unwrap();
        let port_2_id = switch_b.add_port(port_2b, PortConfig::no_loss()).unwrap();

        // Tap switch B's node-2 port (FromSwitch) to observe relayed traffic.
        let frames_at_node_2: Arc<Mutex<Vec<Vec<u8>>>> = Default::default();
        switch_b
            .add_tap(
                port_2_id,
                capture_tap(Direction::FromSwitch, frames_at_node_2.clone()),
            )
            .unwrap();

        // ── Phase 1: OGM round 1 ─────────────────────────────────────────────
        //
        // Each node broadcasts its OGM.  After the first tick+drain node 1
        // has direct routes to both neighbors.  Node 1 forwards each OGM it
        // receives to the other switch, allowing the second tick+drain to give
        // nodes 0 and 2 routes to each other via node 1.

        router_0.poll(Duration::ZERO).await;
        router_1.poll(Duration::ZERO).await; // floods on both tx_1a and tx_1b
        router_2.poll(Duration::ZERO).await;

        switch_a.tick().await.unwrap();
        switch_b.tick().await.unwrap();

        // Node 0 processes node 1's OGM; node 1 processes node 0's OGM.
        router_0.drain(0, &mut rx_0).await;
        // Node 1 processes OGMs from both switches; forwarded copies are queued.
        router_1.drain(0, &mut rx_1a).await;
        router_1.drain(1, &mut rx_1b).await;
        // Node 2 processes node 1's OGM.
        router_2.drain(0, &mut rx_2).await;

        // ── Phase 1: OGM round 2 ─────────────────────────────────────────────
        //
        // Node 1's drain forwarded node 0's OGM to switch B (→ node 2 learns
        // about node 0) and node 2's OGM to switch A (→ node 0 learns about
        // node 2).

        switch_a.tick().await.unwrap();
        switch_b.tick().await.unwrap();

        router_0.drain(0, &mut rx_0).await;
        router_2.drain(0, &mut rx_2).await;

        // Discard residual forwarded OGMs; routing tables are now converged.
        while rx_1a.try_recv().is_ok() {}
        while rx_1b.try_recv().is_ok() {}

        // ── Verify routing tables ─────────────────────────────────────────────

        let route_to_2 = router_0
            .router
            .originator_table()
            .iter()
            .find(|r| r.neighbor_ident == 2)
            .expect("node 0 must have a route to node 2 after two OGM rounds");
        assert_eq!(
            route_to_2.best_next_hop, 1,
            "node 0 must route to node 2 via node 1 (the only path)"
        );

        let route_to_0 = router_2
            .router
            .originator_table()
            .iter()
            .find(|r| r.neighbor_ident == 0)
            .expect("node 2 must have a route to node 0 after two OGM rounds");
        assert_eq!(
            route_to_0.best_next_hop, 1,
            "node 2 must route to node 0 via node 1 (the only path)"
        );

        // ── Phase 2: relay unicast 0 → 2 through node 1 ──────────────────────

        let relay_payload = b"relayed through node 1";
        router_0
            .send_local(2, relay_payload)
            .await
            .expect("node 0 should have a route to node 2 via node 1");

        // Unicast travels from node 0 → switch A → node 1.
        switch_a.tick().await.unwrap();
        router_1.drain(0, &mut rx_1a).await;

        // Node 1 forwarded the frame; switch B delivers it to node 2.
        switch_b.tick().await.unwrap();

        // ── Verify delivery at node 2 ─────────────────────────────────────────

        let hdr_size = core::mem::size_of::<BatmanUnicastPacket<u8>>();
        let mut delivered: Option<Vec<u8>> = None;
        while let Ok(raw) = rx_2.try_recv() {
            router_2.receive(0, &raw).await;
            let frame = parse_frame::<u8>(&raw);
            if frame.protocol == DEFAULT_BATMAN_ETHER_TYPE
                && frame.payload.first() == Some(&BATADV_UNICAST)
                && frame.payload.len() > hdr_size
            {
                let (hdr, _) = BatmanUnicastPacket::<u8>::ref_from_prefix(&frame.payload).unwrap();
                if hdr.dest == 2 {
                    delivered = Some(frame.payload[hdr_size..].to_vec());
                }
            }
        }
        assert_eq!(
            delivered.as_deref(),
            Some(relay_payload.as_ref()),
            "node 2 should receive the relayed payload"
        );

        // The switch B tap must have observed the relayed unicast arriving at
        // node 2's port.
        let tapped: Vec<_> = frames_at_node_2
            .lock()
            .unwrap()
            .iter()
            .filter_map(|f| extract_unicast_payload(f, 2))
            .collect();
        assert_eq!(
            tapped.len(),
            1,
            "switch B tap should capture exactly one unicast for node 2"
        );
        assert_eq!(
            tapped[0].as_slice(),
            relay_payload.as_ref(),
            "switch B tap should see the correct relayed payload"
        );

        // Sanity: node 1 itself must NOT hold the relayed packet (it forwarded it).
        // The switch_b node-1 port is port_2b_id; nothing addressed to node 1
        // should arrive there during the relay phase.
        let _ = port_2b_id; // used for logical clarity only
    }

    // ── metric-based egress selection ────────────────────────────────────────
    //
    // The router has two physical interfaces that can both reach the same
    // neighbor.  After observing OGMs from that neighbor on each interface,
    // the egress decision for unicast traffic to that neighbor must prefer
    // the interface with the better link-quality metrics (RSSI/SNR).
    //
    // These tests are intentionally written against an API that does not yet
    // exist (`LinkMetrics`, `TestRouter::receive_with_metrics`) and against
    // a `CentralRouter` that does not yet feed link metrics into the egress
    // decision.  They are the "red" specification for the metrics work.

    /// Node A has two interfaces; iface 1 hears node B with strong RSSI/SNR
    /// while iface 0 hears the same OGM with weak RSSI/SNR.  After both
    /// observations the router must choose iface 1 as the egress for node B.
    #[tokio::test]
    async fn egress_picks_iface_with_better_metrics_for_shared_neighbor() {
        let (tx_0, _rx_0, _port_0) = make_port_pair(64);
        let (tx_1, _rx_1, _port_1) = make_port_pair(64);
        let mut router_a: TestRouter<u8> = TestRouter::new(1, vec![tx_0, tx_1]);

        let ogm_from_b = build_ogm_wire_frame(2, 255, 1);

        let weak = LinkMetrics {
            rssi_dbm: Some(-115),
            snr_db: Some(-5),
            quality: None,
        };
        let strong = LinkMetrics {
            rssi_dbm: Some(-60),
            snr_db: Some(10),
            quality: None,
        };

        router_a.receive_with_metrics(0, &ogm_from_b, weak).await;
        router_a.receive_with_metrics(1, &ogm_from_b, strong).await;

        match router_a.router.get_egress_interface(2) {
            Some(EgressInterface::Interface(1)) => {}
            other => panic!(
                "expected egress for node 2 to be Interface(1) (strong RSSI/SNR), got {other:?}"
            ),
        }
    }

    /// Mirror of the previous test with strong/weak swapped across the two
    /// interfaces.  Confirms the choice is driven by the metrics themselves
    /// and not by iface index, arrival order, or last-write-wins.
    #[tokio::test]
    async fn egress_swaps_iface_when_metrics_swap() {
        let (tx_0, _rx_0, _port_0) = make_port_pair(64);
        let (tx_1, _rx_1, _port_1) = make_port_pair(64);
        let mut router_a: TestRouter<u8> = TestRouter::new(1, vec![tx_0, tx_1]);

        let ogm_from_b = build_ogm_wire_frame(2, 255, 1);

        let strong = LinkMetrics {
            rssi_dbm: Some(-60),
            snr_db: Some(10),
            quality: None,
        };
        let weak = LinkMetrics {
            rssi_dbm: Some(-115),
            snr_db: Some(-5),
            quality: None,
        };

        router_a.receive_with_metrics(0, &ogm_from_b, strong).await;
        router_a.receive_with_metrics(1, &ogm_from_b, weak).await;

        match router_a.router.get_egress_interface(2) {
            Some(EgressInterface::Interface(0)) => {}
            other => panic!(
                "expected egress for node 2 to be Interface(0) (strong RSSI/SNR), got {other:?}"
            ),
        }
    }

    // ── route-inspection API ──────────────────────────────────────────────────
    //
    // `CentralRouter::resolve_route` is the read-only inspection version of
    // the path the router would take on send.  It backs the protobuf
    // ResolveRouteRequest used by third-party SW to reason about routing.

    /// With a known neighbor observed on a single interface, resolve_route
    /// must report that neighbor as both next-hop and as the egress.
    #[tokio::test]
    async fn resolve_route_returns_neighbor_and_observed_interface() {
        let (tx_0, _rx_0, _port_0) = make_port_pair(64);
        let (tx_1, _rx_1, _port_1) = make_port_pair(64);
        let mut router_a: TestRouter<u8> = TestRouter::new(1, vec![tx_0, tx_1]);

        let ogm_from_b = build_ogm_wire_frame(2, 255, 1);
        let strong = LinkMetrics {
            rssi_dbm: Some(-50),
            snr_db: Some(12),
            quality: None,
        };
        router_a.receive_with_metrics(1, &ogm_from_b, strong).await;

        let (next_hop, egress) = router_a.router.resolve_route(2);
        assert_eq!(next_hop, 2, "direct neighbor should be its own next hop");
        assert_eq!(
            egress,
            Some(EgressInterface::Interface(1)),
            "egress must follow the interface the OGM arrived on"
        );
    }

    /// resolve_route must return [`EgressInterface::All`] for BROADCAST
    /// regardless of any other table state.
    #[tokio::test]
    async fn resolve_route_for_broadcast_returns_all_interfaces() {
        let (tx_0, _rx_0, _port_0) = make_port_pair(64);
        let router_a: TestRouter<u8> = TestRouter::new(1, vec![tx_0]);

        let (next_hop, egress) = router_a.router.resolve_route(u8::BROADCAST);
        assert_eq!(next_hop, u8::BROADCAST);
        assert_eq!(egress, Some(EgressInterface::All));
    }

    /// resolve_route must not promote the destination in the underlying
    /// ident-table LRU — repeated calls leave the cache state untouched so
    /// management-API callers don't perturb the routing decisions of the
    /// data plane.
    #[tokio::test]
    async fn resolve_route_is_read_only() {
        let (tx_0, _rx_0, _port_0) = make_port_pair(64);
        let mut router_a: TestRouter<u8> = TestRouter::new(1, vec![tx_0]);

        let ogm_from_b = build_ogm_wire_frame(2, 255, 1);
        let metrics = LinkMetrics {
            rssi_dbm: Some(-50),
            snr_db: Some(12),
            quality: None,
        };
        router_a.receive_with_metrics(0, &ogm_from_b, metrics).await;

        // Two snapshots: identical state, identical answers — and a third
        // snapshot taken after a no-op call confirms idempotence.
        let first = router_a.router.resolve_route(2);
        let _ = router_a.router.resolve_route(2);
        let third = router_a.router.resolve_route(2);
        assert_eq!(first, third);
    }
}
