//! `run_query` glue: parse the connect target, open a client to a real
//! in-process `wayfinder-server`, issue the RPC, and render the result.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;

use tokio::sync::{mpsc, oneshot};
use wayfinder_protos::service::{
    InterfaceThroughputData, KeepAliveEntryData, LinkQualityEntryData, NodeMetricsData,
    NodeSecurityData, OgmScheduleEntryData, RouteResolutionData, RoutingEntryData,
    RuntimeConfigData, SecurityStatusData, TableOccupancyData, WayfinderDataProvider,
    WayfinderService,
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
    fn auth_locked(&self) -> bool {
        true
    }
    fn routing_table(&self) -> Vec<RoutingEntryData> {
        vec![]
    }
    fn link_quality_table(&self) -> Vec<LinkQualityEntryData> {
        vec![]
    }
    fn keepalive_table(&self) -> Vec<KeepAliveEntryData> {
        vec![KeepAliveEntryData {
            neighbor_id: vec![0, 0, 0, 0, 0, 2],
            ms_since_last_heard: 4200,
            interval_estimate_ms: 1000,
            missed: true,
        }]
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
            oversize_drops: 3,
            relay_oversize_drops: 9,
            cert_store: TableOccupancyData {
                used: 2,
                capacity: 64,
            },
            in_flight_cert_requests: TableOccupancyData {
                used: 1,
                capacity: 16,
            },
            pending_cert_replies: TableOccupancyData {
                used: 0,
                capacity: 16,
            },
            cert_req_rate: 0.5,
            cert_reply_rate: 1.5,
        }
    }
    fn resolve_route(&self, _destination: &[u8]) -> Option<RouteResolutionData> {
        None
    }
    fn set_auth(&mut self, _seed: &[u8], _cert: &[u8], _trust_anchor: &[u8]) -> Result<(), String> {
        Ok(())
    }
    fn set_config(&mut self, _config: RuntimeConfigData) -> Result<(), String> {
        Ok(())
    }
    fn runtime_config_active(&self) -> bool {
        true
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
    assert_eq!(parsed["auth_locked"], true);
    assert_eq!(parsed["runtime_config_active"], true);
}

#[tokio::test]
async fn node_info_query_renders_human_from_server() {
    let addr = spawn_server().await;
    let out = run_query(Command::NodeInfo, &addr.to_string(), OutputFormat::Human)
        .await
        .unwrap();
    assert!(out.contains("aa:bb:cc:dd:ee:07"), "got: {out}");
    assert!(out.contains("originators: 5"), "got: {out}");
    assert!(out.contains("locked: yes"), "got: {out}");
    assert!(out.contains("runtime config: yes"), "got: {out}");
}

#[tokio::test]
async fn keepalive_query_renders_json_from_server() {
    let addr = spawn_server().await;
    let out = run_query(Command::Keepalive, &addr.to_string(), OutputFormat::Json)
        .await
        .expect("query succeeds");
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["entries"][0]["ms_since_last_heard"], 4200);
    assert_eq!(parsed["entries"][0]["interval_estimate_ms"], 1000);
    assert_eq!(parsed["entries"][0]["missed"], true);
}

#[tokio::test]
async fn keepalive_query_renders_human_from_server() {
    let addr = spawn_server().await;
    let out = run_query(Command::Keepalive, &addr.to_string(), OutputFormat::Human)
        .await
        .unwrap();
    assert!(out.contains("00:00:00:00:00:02"), "got: {out}");
    assert!(out.contains("4200"), "got: {out}");
    assert!(out.contains("1000"), "got: {out}");
    assert!(out.contains("yes"), "got: {out}");
}

#[tokio::test]
async fn set_trickle_config_query_succeeds_against_server() {
    let addr = spawn_server().await;
    let out = run_query(
        Command::SetTrickleConfig {
            iface: 0,
            min_ms: 500,
            max_ms: 4000,
        },
        &addr.to_string(),
        OutputFormat::Human,
    )
    .await
    .expect("query succeeds");
    assert!(out.contains("trickle config"), "got: {out}");
}

#[tokio::test]
async fn set_link_features_query_succeeds_against_server() {
    let addr = spawn_server().await;
    let out = run_query(
        Command::SetLinkFeatures {
            iface: 0,
            tx_ogm: Some(false),
            rx_ogm: None,
            tx_data: None,
            rx_data: None,
            tx_keepalive_interval_ms: None,
            tx_keepalive_disable: false,
        },
        &addr.to_string(),
        OutputFormat::Human,
    )
    .await
    .expect("query succeeds");
    assert!(out.contains("link features"), "got: {out}");
}

#[tokio::test]
async fn set_lazy_cert_distribution_query_succeeds_against_server() {
    let addr = spawn_server().await;
    let out = run_query(
        Command::SetLazyCertDistribution { enabled: true },
        &addr.to_string(),
        OutputFormat::Human,
    )
    .await
    .expect("query succeeds");
    assert!(out.contains("lazy cert distribution"), "got: {out}");
}

#[tokio::test]
async fn metrics_query_renders_json_from_server() {
    let addr = spawn_server().await;
    let out = run_query(Command::Metrics, &addr.to_string(), OutputFormat::Json)
        .await
        .expect("query succeeds");
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["oversize_drops"], 3);
    assert_eq!(parsed["relay_oversize_drops"], 9);
    assert_eq!(parsed["cert_store"]["used"], 2);
    assert_eq!(parsed["in_flight_cert_requests"]["used"], 1);
    assert_eq!(parsed["cert_req_rate"], 0.5);
    assert_eq!(parsed["cert_reply_rate"], 1.5);
}

#[tokio::test]
async fn metrics_query_renders_human_from_server() {
    let addr = spawn_server().await;
    let out = run_query(Command::Metrics, &addr.to_string(), OutputFormat::Human)
        .await
        .unwrap();
    assert!(out.contains("oversize_drops: 3"), "got: {out}");
    assert!(out.contains("relay_oversize_drops: 9"), "got: {out}");
    assert!(out.contains("cert_store: 2/64"), "got: {out}");
    assert!(out.contains("in_flight_cert_requests: 1/16"), "got: {out}");
    assert!(out.contains("pending_cert_replies: 0/16"), "got: {out}");
    assert!(out.contains("cert_req_rate: 0.50"), "got: {out}");
    assert!(out.contains("cert_reply_rate: 1.50"), "got: {out}");
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
