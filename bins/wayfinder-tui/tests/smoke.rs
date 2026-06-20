//! End-to-end check that the TUI's TCP client speaks the same wire protocol as
//! the production `wayfinder-server` TCP listener.
//!
//! Spins up the real `run_tcp_server` backed by a mock data provider, then
//! drives it with the TUI's [`Client`], asserting the decoded responses match
//! what the provider returned. This exercises the full prost-encode →
//! length-delimited-frame → decode path on both sides without needing a TAP
//! device or root.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use wayfinder_protos::service::{
    InterfaceThroughputData, LinkQualityEntryData, NeighborPathData, NodeMetricsData,
    OgmScheduleEntryData, RouteResolutionData, RoutingEntryData, TableOccupancyData,
    WayfinderDataProvider, WayfinderService,
};
use wayfinder_protos::wayfinder_v1alpha::{WayfinderRequest, WayfinderResponse};
use wayfinder_server::run_tcp_server;
use wayfinder_tui::app::format_id;
use wayfinder_tui::client::Client;

/// A canned data provider with one originator and one link-quality row.
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
        None
    }
}

/// Grab an almost-certainly-free localhost port by binding to :0 and releasing.
fn free_port() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

/// Connect with a few retries to absorb the gap before the listener is up.
async fn connect_with_retry(addr: SocketAddr) -> Client {
    for _ in 0..50 {
        if let Ok(c) = Client::connect(addr).await {
            return c;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("server never became reachable");
}

#[tokio::test]
async fn client_roundtrips_against_real_tcp_server() {
    let addr = free_port();

    // Wire the real listener to a query-servicing loop over the production
    // WayfinderService, exactly as the node binary does.
    let (query_tx, mut query_rx) =
        mpsc::channel::<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>(16);
    tokio::spawn(async move {
        let _ = run_tcp_server(addr, query_tx).await;
    });
    tokio::spawn(async move {
        let service = WayfinderService::new(Mock);
        while let Some((req, resp_tx)) = query_rx.recv().await {
            let _ = resp_tx.send(service.handle(req));
        }
    });

    let mut client = connect_with_retry(addr).await;

    let info = client.node_info().await.unwrap();
    assert_eq!(format_id(&info.node_id), "aa:bb:cc:dd:ee:01");
    assert_eq!(info.num_originators, 2);

    let routing = client.routing_table().await.unwrap();
    assert_eq!(routing.entries.len(), 1);
    let entry = &routing.entries[0];
    assert_eq!(format_id(&entry.destination), "00:00:00:00:00:02");
    assert_eq!(format_id(&entry.next_hop), "00:00:00:00:00:03");
    assert_eq!(entry.tq, 240);
    assert_eq!(entry.last_seqno, 17);
    assert_eq!(entry.paths.len(), 1);
    assert_eq!(entry.paths[0].tq, 240);

    let links = client.link_quality_table().await.unwrap();
    assert_eq!(links.entries.len(), 1);
    let row = &links.entries[0];
    assert_eq!(format_id(&row.neighbor_id), "00:00:00:00:00:03");
    assert_eq!(row.iface_idx, 0);
    assert_eq!(row.ewma_quality, 200);
    assert_eq!(row.sample_count, 9);

    let schedule = client.ogm_schedule().await.unwrap();
    assert_eq!(schedule.entries.len(), 1);
    let sched = &schedule.entries[0];
    assert_eq!(sched.iface_idx, 0);
    assert_eq!(sched.current_interval_ms, 4000);
    assert_eq!(sched.min_interval_ms, 1000);
    assert_eq!(sched.max_interval_ms, 64000);

    let throughput = client.throughput().await.unwrap();
    assert_eq!(throughput.interfaces.len(), 1);
    let tp = &throughput.interfaces[0];
    assert_eq!(tp.iface_idx, 0);
    assert_eq!(tp.rx_bps, 1500.0);
    assert_eq!(tp.tx_bps, 800.0);
    // Totals are the per-interface sums.
    assert_eq!(throughput.total_rx_bps, 1500.0);
    assert_eq!(throughput.total_tx_fps, 6.0);

    let metrics = client.node_metrics().await.unwrap();
    assert_eq!(metrics.uptime_secs, 7384);
    assert_eq!(metrics.neighbor_count, 1);
    assert_eq!(metrics.originators.unwrap().capacity, 128);
    assert_eq!(metrics.tq_mean, 240.0);
    assert_eq!(metrics.paths_max, 1);
}
