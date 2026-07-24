//! End-to-end check that [`wayfinder_client::Client`] speaks the same wire
//! protocol as the production `wayfinder-server` TLS listener.
//!
//! The test spins up the real `serve_tls_server` backed by a canned data
//! provider, then drives it with an authenticated client, asserting the decoded
//! responses match what the provider returned. This exercises the full
//! RFC 7250 handshake → prost-encode → frame → decode path on both sides without
//! a TAP device.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;

use tokio::sync::{mpsc, oneshot};
use wayfinder_client::Client;
use wayfinder_protos::service::{
    EgressDecisionData, InterfaceThroughputData, KeepAliveEntryData, LinkQualityEntryData,
    NeighborPathData, NodeMetricsData, OgmScheduleEntryData, RouteResolutionData, RoutingEntryData,
    RuntimeConfigData, TableOccupancyData, WayfinderDataProvider, WayfinderService,
};
use wayfinder_protos::wayfinder_v1alpha::{
    WayfinderRequest, WayfinderResponse, resolve_route_response::Egress,
};

/// Render a 6-byte identifier as a colon-delimited MAC, else as plain hex.
fn format_mac(bytes: &[u8]) -> String {
    if bytes.len() == 6 {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    } else {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// A canned data provider with one originator, one link-quality row, and a
/// resolvable route, so every typed client method has something to return.
struct Mock;

impl WayfinderDataProvider for Mock {
    fn node_id(&self) -> Vec<u8> {
        vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]
    }
    fn num_originators(&self) -> u32 {
        2
    }
    fn auth_locked(&self) -> bool {
        true
    }
    fn routing_table(&self) -> Vec<RoutingEntryData> {
        vec![RoutingEntryData {
            destination: vec![0, 0, 0, 0, 0, 2],
            next_hop: vec![0, 0, 0, 0, 0, 3],
            tq: 240,
            last_seqno: 17,
            paths: vec![NeighborPathData {
                neighbor_id: vec![0, 0, 0, 0, 0, 3],
                tq: 240,
                last_seqno: 17,
            }],
        }]
    }
    fn link_quality_table(&self) -> Vec<LinkQualityEntryData> {
        vec![LinkQualityEntryData {
            neighbor_id: vec![0, 0, 0, 0, 0, 3],
            iface_idx: 0,
            ewma_quality: 200,
            sample_count: 9,
        }]
    }
    fn keepalive_table(&self) -> Vec<KeepAliveEntryData> {
        vec![KeepAliveEntryData {
            neighbor_id: vec![0, 0, 0, 0, 0, 3],
            ms_since_last_heard: 4200,
            interval_estimate_ms: 1000,
            missed: true,
        }]
    }
    fn ogm_schedule(&self) -> Vec<OgmScheduleEntryData> {
        vec![OgmScheduleEntryData {
            iface_idx: 0,
            current_interval_ms: 4000,
            min_interval_ms: 1000,
            max_interval_ms: 64000,
        }]
    }
    fn throughput(&self) -> Vec<InterfaceThroughputData> {
        vec![InterfaceThroughputData {
            iface_idx: 0,
            rx_bps: 1500.0,
            rx_fps: 12.0,
            tx_bps: 800.0,
            tx_fps: 6.0,
        }]
    }
    fn node_metrics(&self) -> NodeMetricsData {
        NodeMetricsData {
            uptime_secs: 7384,
            neighbor_count: 1,
            originators: TableOccupancyData {
                used: 1,
                capacity: 128,
            },
            broadcast_dedup: TableOccupancyData {
                used: 1,
                capacity: 128,
            },
            local_mcast_groups: TableOccupancyData {
                used: 0,
                capacity: 16,
            },
            mcast_memberships: TableOccupancyData {
                used: 0,
                capacity: 64,
            },
            tq_min: 240,
            tq_max: 240,
            tq_mean: 240.0,
            paths_max: 1,
            paths_mean: 1.0,
            oversize_drops: 2,
            relay_oversize_drops: 4,
            cert_store: TableOccupancyData {
                used: 3,
                capacity: 64,
            },
            in_flight_cert_requests: TableOccupancyData {
                used: 1,
                capacity: 16,
            },
            pending_cert_replies: TableOccupancyData {
                used: 2,
                capacity: 16,
            },
            cert_req_rate: 0.25,
            cert_reply_rate: 0.75,
        }
    }
    fn resolve_route(&self, _destination: &[u8]) -> Option<RouteResolutionData> {
        Some(RouteResolutionData {
            next_hop: vec![0, 0, 0, 0, 0, 3],
            egress: Some(EgressDecisionData::Interface(0)),
        })
    }

    fn set_auth(&mut self, _seed: &[u8], _cert: &[u8], _trust_anchor: &[u8]) -> Result<(), String> {
        Ok(())
    }

    fn set_config(&mut self, _config: RuntimeConfigData) -> Result<(), String> {
        Ok(())
    }

    fn runtime_config_active(&self) -> bool {
        false
    }

    fn get_trust_anchor(&self) -> Result<Vec<u8>, String> {
        Ok(vec![0xab; 36])
    }
}

/// Spawn the production `WayfinderService` query loop behind a channel and
/// return the sender the transport listeners forward decoded requests to.
fn spawn_service() -> mpsc::Sender<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)> {
    let (query_tx, mut query_rx) =
        mpsc::channel::<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>(16);
    tokio::spawn(async move {
        let mut service = WayfinderService::new(Mock);
        while let Some((req, resp_tx)) = query_rx.recv().await {
            let _ = resp_tx.send(service.handle(req));
        }
    });
    query_tx
}

/// Grab an almost-certainly-free localhost port by binding to :0 and releasing.
fn free_port() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

/// Assert every typed query returns the provider's canned values.
async fn assert_full_roundtrip(client: &mut Client) {
    let info = client.node_info().await.unwrap();
    assert_eq!(format_mac(&info.node_id), "aa:bb:cc:dd:ee:01");
    assert_eq!(info.num_originators, 2);
    assert!(info.auth_locked);
    assert!(!info.runtime_config_active);

    let routing = client.routing_table().await.unwrap();
    assert_eq!(routing.entries.len(), 1);
    let entry = &routing.entries[0];
    assert_eq!(format_mac(&entry.destination), "00:00:00:00:00:02");
    assert_eq!(format_mac(&entry.next_hop), "00:00:00:00:00:03");
    assert_eq!(entry.tq, 240);

    let links = client.link_quality_table().await.unwrap();
    assert_eq!(links.entries.len(), 1);
    assert_eq!(links.entries[0].ewma_quality, 200);

    let keepalive = client.keepalive_table().await.unwrap();
    assert_eq!(keepalive.entries.len(), 1);
    assert_eq!(keepalive.entries[0].interval_estimate_ms, 1000);
    assert!(keepalive.entries[0].missed);

    let schedule = client.ogm_schedule().await.unwrap();
    assert_eq!(schedule.entries[0].current_interval_ms, 4000);

    let throughput = client.throughput().await.unwrap();
    assert_eq!(throughput.interfaces[0].rx_bps, 1500.0);
    assert_eq!(throughput.total_tx_fps, 6.0);

    let metrics = client.node_metrics().await.unwrap();
    assert_eq!(metrics.uptime_secs, 7384);
    assert_eq!(metrics.originators.unwrap().capacity, 128);
    assert_eq!(metrics.oversize_drops, 2);
    assert_eq!(metrics.relay_oversize_drops, 4);
    assert_eq!(metrics.cert_store.unwrap().used, 3);
    assert_eq!(metrics.in_flight_cert_requests.unwrap().used, 1);
    assert_eq!(metrics.pending_cert_replies.unwrap().used, 2);
    assert_eq!(metrics.cert_req_rate, 0.25);
    assert_eq!(metrics.cert_reply_rate, 0.75);

    let route = client.resolve_route(vec![0, 0, 0, 0, 0, 2]).await.unwrap();
    assert_eq!(format_mac(&route.next_hop), "00:00:00:00:00:03");
    assert_eq!(route.egress, Some(Egress::InterfaceIndex(0)));

    // A provider RPC also round-trips over this transport (exercises the new
    // GetTrustAnchor request/response framing).
    let anchor = client.get_trust_anchor().await.unwrap();
    assert_eq!(anchor.trust_anchor, vec![0xab; 36]);

    // SetConfig round-trips too (exercises the mutating-request framing).
    client.set_trickle_config(0, 500, 4000).await.unwrap();
}

#[tokio::test]
async fn client_roundtrips_against_real_tls_server() {
    use wayfinder_client::Identity;

    let node_seed = [7u8; 32];
    // Derive the node's public key from its seed via the exported RPK helpers so
    // the client can pin it; in bootstrap the client holds the node's own seed.
    let ck = wayfinder_tls_mgmt::certified_key_from_seed(&node_seed).unwrap();
    let node_key = wayfinder_tls_mgmt::raw_ed25519_from_spki(ck.cert[0].as_ref()).unwrap();

    let query_tx = spawn_service();

    // Un-enrolled router snapshot responder (bootstrap mode): no anchor, nothing
    // revoked.
    let (snapshot_tx, mut snapshot_rx) =
        mpsc::channel::<oneshot::Sender<wayfinder_server::AuthSnapshot>>(8);
    tokio::spawn(async move {
        while let Some(reply) = snapshot_rx.recv().await {
            let _ = reply.send(wayfinder_server::AuthSnapshot {
                anchor: None,
                revoked: Vec::new(),
            });
        }
    });

    let listener = wayfinder_server::bind_tcp_server(free_port())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ =
            wayfinder_server::serve_tls_server(listener, node_seed, snapshot_tx, query_tx).await;
    });

    // Bootstrap: present the node's own seed and an empty cert; pin the node key.
    let identity = Identity {
        seed: node_seed,
        cert: Vec::new(),
    };
    let mut client = Client::connect_tls(addr, &node_key, &identity)
        .await
        .unwrap();
    assert_full_roundtrip(&mut client).await;
}
