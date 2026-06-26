//! End-to-end check that [`wayfinder_client::Client`] speaks the same wire
//! protocol as the production `wayfinder-server` listeners, over **both**
//! transports it supports.
//!
//! Each test spins up the real listener (`run_tcp_server` / `run_unix_server`)
//! backed by a canned data provider, then drives it with the client, asserting
//! the decoded responses match what the provider returned. This exercises the
//! full prost-encode → frame → decode path on both sides without a TAP device.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use wayfinder_client::{Client, ConnectTarget};
use wayfinder_protos::service::{
    EgressDecisionData, InterfaceThroughputData, LinkQualityEntryData, NeighborPathData,
    NodeMetricsData, OgmScheduleEntryData, RouteResolutionData, RoutingEntryData,
    TableOccupancyData, WayfinderDataProvider, WayfinderService,
};
use wayfinder_protos::wayfinder_v1alpha::{
    WayfinderRequest, WayfinderResponse, resolve_route_response::Egress,
};
use wayfinder_server::{run_tcp_server, run_unix_server};

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

/// A process-unique temp path for a test server's Unix socket.
fn unique_server_path() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("wf-client-test-{}-{}.sock", std::process::id(), n))
}

/// Connect with a few retries to absorb the gap before the listener is up.
async fn connect_with_retry(target: &ConnectTarget) -> Client {
    for _ in 0..50 {
        if let Ok(c) = Client::connect(target).await {
            return c;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("server never became reachable");
}

/// Assert every typed query returns the provider's canned values — the shared
/// body of the per-transport tests.
async fn assert_full_roundtrip(client: &mut Client) {
    let info = client.node_info().await.unwrap();
    assert_eq!(format_mac(&info.node_id), "aa:bb:cc:dd:ee:01");
    assert_eq!(info.num_originators, 2);

    let routing = client.routing_table().await.unwrap();
    assert_eq!(routing.entries.len(), 1);
    let entry = &routing.entries[0];
    assert_eq!(format_mac(&entry.destination), "00:00:00:00:00:02");
    assert_eq!(format_mac(&entry.next_hop), "00:00:00:00:00:03");
    assert_eq!(entry.tq, 240);

    let links = client.link_quality_table().await.unwrap();
    assert_eq!(links.entries.len(), 1);
    assert_eq!(links.entries[0].ewma_quality, 200);

    let schedule = client.ogm_schedule().await.unwrap();
    assert_eq!(schedule.entries[0].current_interval_ms, 4000);

    let throughput = client.throughput().await.unwrap();
    assert_eq!(throughput.interfaces[0].rx_bps, 1500.0);
    assert_eq!(throughput.total_tx_fps, 6.0);

    let metrics = client.node_metrics().await.unwrap();
    assert_eq!(metrics.uptime_secs, 7384);
    assert_eq!(metrics.originators.unwrap().capacity, 128);

    let route = client.resolve_route(vec![0, 0, 0, 0, 0, 2]).await.unwrap();
    assert_eq!(format_mac(&route.next_hop), "00:00:00:00:00:03");
    assert_eq!(route.egress, Some(Egress::InterfaceIndex(0)));

    // A provider RPC also round-trips over this transport (exercises the new
    // GetTrustAnchor request/response framing).
    let anchor = client.get_trust_anchor().await.unwrap();
    assert_eq!(anchor.trust_anchor, vec![0xab; 36]);
}

#[tokio::test]
async fn client_roundtrips_against_real_tcp_server() {
    let addr = free_port();
    let query_tx = spawn_service();
    tokio::spawn(async move {
        let _ = run_tcp_server(addr, query_tx).await;
    });

    let mut client = connect_with_retry(&ConnectTarget::Tcp(addr)).await;
    assert_full_roundtrip(&mut client).await;
}

#[tokio::test]
async fn client_roundtrips_against_real_unix_server() {
    let path = unique_server_path();
    let query_tx = spawn_service();
    {
        let path = path.clone();
        tokio::spawn(async move {
            let _ = run_unix_server(path, query_tx).await;
        });
    }

    let mut client = connect_with_retry(&ConnectTarget::Unix(path.clone())).await;
    assert_full_roundtrip(&mut client).await;

    // The listener tidy-up is best-effort; remove the server socket too.
    let _ = std::fs::remove_file(&path);
}
