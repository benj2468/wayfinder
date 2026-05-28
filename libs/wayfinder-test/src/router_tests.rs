//! Integration tests: multiple `CentralRouter`s exchanging traffic through a `Switch`.

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use interfaces::frame::LinkFrame;
    use tokio::sync::mpsc;
    use wayfinder::{
        CentralRouter, DEFAULT_BATMAN_ETHER_TYPE,
        batman::wire::{BATADV_UNICAST, BatmanUnicastPacket},
    };
    use zerocopy::FromBytes;

    use crate::switch::{PortComms, PortConfig, Switch};

    // ── wire-format helpers ───────────────────────────────────────────────────

    /// Serialize a `LinkFrame<u8>` into a heap-allocated byte vector.
    ///
    /// Wire layout (matches `#[repr(C, packed)]`):
    /// ```text
    /// [src: u8][dst: u8][protocol: u16 native-endian][payload ...]
    /// ```
    fn build_wire_frame(src: u8, dst: u8, protocol: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + payload.len());
        bytes.push(src);
        bytes.push(dst);
        bytes.extend_from_slice(&protocol.to_ne_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    /// Parse raw bytes back into a `&LinkFrame<u8>`.
    ///
    /// The frame borrows directly from `bytes` — no copy.
    fn parse_wire_frame(bytes: &[u8]) -> &LinkFrame<u8> {
        LinkFrame::<u8>::ref_from_bytes(bytes).expect("failed to parse LinkFrame from bytes")
    }

    // ── test plumbing ─────────────────────────────────────────────────────────

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
    /// route, then router A sends application data to router B via a unicast
    /// BATMAN packet.  The test verifies that B receives the exact payload.
    #[tokio::test]
    async fn two_routers_discover_routes_and_exchange_data() {
        let mut router_a: CentralRouter<u8> = CentralRouter::new(1);
        let mut router_b: CentralRouter<u8> = CentralRouter::new(2);

        let (tx_a, mut rx_a, port_a) = make_port_pair(64);
        let (tx_b, mut rx_b, port_b) = make_port_pair(64);

        let mut switch = Switch::<u8>::new();
        switch.add_port(port_a, PortConfig::no_loss()).unwrap();
        switch.add_port(port_b, PortConfig::no_loss()).unwrap();

        // ── Phase 1: OGM broadcast ──────────────────────────────────────────
        //
        // Each router generates one OGM, sends it into the switch.
        // After switch.tick(), each router receives the other's OGM and learns
        // the direct route.  The switch also learns which port each node is on.

        let mut buf_a = [0u8; 512];
        let mut buf_b = [0u8; 512];

        let ogm_a = router_a.poll(Duration::ZERO, &mut buf_a).unwrap();
        let ogm_b = router_b.poll(Duration::ZERO, &mut buf_b).unwrap();

        tx_a.send(build_wire_frame(
            1,
            ogm_a.dst,
            ogm_a.protocol,
            ogm_a.payload,
        ))
        .await
        .unwrap();
        tx_b.send(build_wire_frame(
            2,
            ogm_b.dst,
            ogm_b.protocol,
            ogm_b.payload,
        ))
        .await
        .unwrap();

        // Switch distributes both OGMs.
        switch.tick().await.unwrap();

        // Router A processes B's OGM (and may queue a forwarded copy).
        let mut fwd_buf_a = [0u8; 512];
        while let Ok(raw) = rx_a.try_recv() {
            let frame = parse_wire_frame(&raw);
            if let Some(fwd) = router_a.handle_frame(0, frame, &mut fwd_buf_a) {
                let wire = build_wire_frame(1, fwd.dst, fwd.protocol, fwd.payload);
                tx_a.send(wire).await.unwrap();
            }
        }

        // Router B processes A's OGM.
        let mut fwd_buf_b = [0u8; 512];
        while let Ok(raw) = rx_b.try_recv() {
            let frame = parse_wire_frame(&raw);
            if let Some(fwd) = router_b.handle_frame(0, frame, &mut fwd_buf_b) {
                let wire = build_wire_frame(2, fwd.dst, fwd.protocol, fwd.payload);
                tx_b.send(wire).await.unwrap();
            }
        }

        // Flush any forwarded OGMs; drain receivers so they don't interfere with
        // the data-plane phase below.
        switch.tick().await.unwrap();
        while rx_a.try_recv().is_ok() {}
        while rx_b.try_recv().is_ok() {}

        // ── Phase 2: unicast data A → B ────────────────────────────────────

        let app_payload = b"hello from A to B";

        let data_frame = router_a
            .handle_local(2, app_payload, &mut buf_a)
            .expect("router A should have a route to router B after OGM exchange");

        tx_a.send(build_wire_frame(
            1,
            data_frame.dst,
            data_frame.protocol,
            data_frame.payload,
        ))
        .await
        .unwrap();

        // Switch delivers the unicast frame to router B's port.
        switch.tick().await.unwrap();

        // ── Phase 3: verify router B received the payload ─────────────────

        let mut delivered: Option<Vec<u8>> = None;

        let hdr_size = std::mem::size_of::<BatmanUnicastPacket<u8>>();

        while let Ok(raw) = rx_b.try_recv() {
            let frame = parse_wire_frame(&raw);
            let _ = router_b.handle_frame(0, frame, &mut fwd_buf_b);

            // The payload starts with a BatmanUnicastPacket header; the
            // application data follows immediately after.
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
}
