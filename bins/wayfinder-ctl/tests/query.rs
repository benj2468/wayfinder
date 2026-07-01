//! `run_query` glue: parse the connect target, open a client to a real
//! in-process `wayfinder-server`, issue the RPC, and render the result.

use std::net::SocketAddr;

use tokio::sync::{mpsc, oneshot};
use wayfinder_protos::service::{
    InterfaceThroughputData, LinkQualityEntryData, NodeMetricsData, NodeSecurityData,
    OgmScheduleEntryData, RouteResolutionData, RoutingEntryData, SecurityStatusData,
    TableOccupancyData, WayfinderDataProvider, WayfinderService,
};
use wayfinder_protos::wayfinder_v1alpha::{WayfinderRequest, WayfinderResponse};
use wayfinder_server::run_tcp_server;
use wayfinderctl::output::OutputFormat;
use wayfinderctl::{Command, run_query};

/// Minimal provider: only `node_info` carries meaningful values; the rest return
/// empty/zero, which is all the `node-info` query exercises.
struct Mock;

fn occ() -> TableOccupancyData {
    TableOccupancyData {
        used: 0,
        capacity: 0,
    }
}

impl WayfinderDataProvider for Mock {
    fn node_id(&self) -> Vec<u8> {
        vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x07]
    }
    fn num_originators(&self) -> u32 {
        5
    }
    fn routing_table(&self) -> Vec<RoutingEntryData> {
        vec![]
    }
    fn link_quality_table(&self) -> Vec<LinkQualityEntryData> {
        vec![]
    }
    fn ogm_schedule(&self) -> Vec<OgmScheduleEntryData> {
        vec![]
    }
    fn throughput(&self) -> Vec<InterfaceThroughputData> {
        vec![]
    }
    fn node_metrics(&self) -> NodeMetricsData {
        NodeMetricsData {
            uptime_secs: 0,
            neighbor_count: 0,
            originators: occ(),
            broadcast_dedup: occ(),
            local_mcast_groups: occ(),
            mcast_memberships: occ(),
            tq_min: 0,
            tq_max: 0,
            tq_mean: 0.0,
            paths_max: 0,
            paths_mean: 0.0,
            oversize_drops: 0,
        }
    }
    fn resolve_route(&self, _destination: &[u8]) -> Option<RouteResolutionData> {
        None
    }
    fn set_auth(&mut self, _seed: &[u8], _cert: &[u8], _trust_anchor: &[u8]) -> Result<(), String> {
        Ok(())
    }
    fn security_status(&self) -> SecurityStatusData {
        SecurityStatusData {
            auth_enabled: true,
            mesh_id: 0xABCD,
            node_mac: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x07],
            cert_not_after: 1100,
            revocation_count: 1,
            nodes: vec![
                NodeSecurityData {
                    node_id: vec![0, 0, 0, 0, 0, 2],
                    verified: true,
                    cert_not_after: 1100,
                    revoked: false,
                },
                NodeSecurityData {
                    node_id: vec![0, 0, 0, 0, 0, 3],
                    verified: false,
                    cert_not_after: 0,
                    revoked: true,
                },
            ],
        }
    }
}

fn free_port() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn spawn_server() -> SocketAddr {
    let addr = free_port();
    let (query_tx, mut query_rx) =
        mpsc::channel::<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>(16);
    tokio::spawn(async move {
        let _ = run_tcp_server(addr, query_tx).await;
    });
    tokio::spawn(async move {
        let mut service = WayfinderService::new(Mock);
        while let Some((req, resp_tx)) = query_rx.recv().await {
            let _ = resp_tx.send(service.handle(req));
        }
    });
    // Give the listener a moment to bind.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    addr
}

#[tokio::test]
async fn node_info_query_renders_json_from_server() {
    let addr = spawn_server().await;
    let out = run_query(Command::NodeInfo, &addr.to_string(), OutputFormat::Json)
        .await
        .expect("query succeeds");
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["num_originators"], 5);
}

#[tokio::test]
async fn node_info_query_renders_human_from_server() {
    let addr = spawn_server().await;
    let out = run_query(Command::NodeInfo, &addr.to_string(), OutputFormat::Human)
        .await
        .unwrap();
    assert!(out.contains("aa:bb:cc:dd:ee:07"), "got: {out}");
    assert!(out.contains("originators: 5"), "got: {out}");
}

#[tokio::test]
async fn security_query_renders_json_from_server() {
    let addr = spawn_server().await;
    let out = run_query(Command::Security, &addr.to_string(), OutputFormat::Json)
        .await
        .expect("query succeeds");
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["auth_enabled"], true);
    assert_eq!(parsed["mesh_id"], 0xABCD);
    assert_eq!(parsed["nodes"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn security_query_renders_human_from_server() {
    let addr = spawn_server().await;
    let out = run_query(Command::Security, &addr.to_string(), OutputFormat::Human)
        .await
        .unwrap();
    assert!(out.contains("authentication: enabled"), "got: {out}");
    assert!(out.contains("revoked"), "got: {out}");
    assert!(out.contains("00:00:00:00:00:02"), "got: {out}");
}
