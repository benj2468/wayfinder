//! Integration tests: multiple `CentralRouter`s exchanging traffic through a `Switch`.

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::mpsc;
    use wayfinder::{
        DEFAULT_BATMAN_ETHER_TYPE,
        batman::wire::{BATADV_UNICAST, BatmanUnicastPacket},
    };
    use zerocopy::FromBytes;

    use crate::switch::{PortComms, PortConfig, Switch};
    use crate::test_router::{TestRouter, parse_frame};

    // ── helpers ───────────────────────────────────────────────────────────────

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
}
