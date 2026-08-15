//! A stand-in node, for tests and for developing the dashboard without hardware.
//!
//! Runs the production `wayfinder-server` TLS listener over a canned data
//! provider, so whatever drives it exercises the real handshake, framing and
//! dispatch rather than a stubbed client. The provider mirrors the `Mock` in
//! `libs/wayfinder-client/tests/transport.rs`, this repo's reference for one
//! that answers every RPC.
//!
//! Behind the off-by-default `mock-node` feature: it is a development tool, in
//! the same spirit as `libs/rylr998-sim`, and has no business in a release
//! build. `examples/mock_node.rs` is the runnable front end —
//! `cargo run -p wayfinder-web --features ssr,mock-node --example mock_node`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;

use tokio::sync::mpsc;
use tokio::sync::oneshot;
use wayfinder_protos::service::EgressDecisionData;
use wayfinder_protos::service::InterfaceThroughputData;
use wayfinder_protos::service::KeepAliveEntryData;
use wayfinder_protos::service::LinkFeaturesEntryData;
use wayfinder_protos::service::LinkQualityEntryData;
use wayfinder_protos::service::LogLevelData;
use wayfinder_protos::service::LogRecordData;
use wayfinder_protos::service::LogsData;
use wayfinder_protos::service::NeighborPathData;
use wayfinder_protos::service::NodeMetricsData;
use wayfinder_protos::service::OgmScheduleEntryData;
use wayfinder_protos::service::RouteResolutionData;
use wayfinder_protos::service::RoutingEntryData;
use wayfinder_protos::service::RuntimeConfigData;
use wayfinder_protos::service::TableOccupancyData;
use wayfinder_protos::service::WayfinderDataProvider;
use wayfinder_protos::service::WayfinderService;
use wayfinder_protos::wayfinder::v1alpha::WayfinderRequest;
use wayfinder_protos::wayfinder::v1alpha::WayfinderResponse;

/// A provider with one originator, one link-quality row and one interface, so
/// every field a snapshot reads has a distinguishable value to land in.
pub struct Mock;

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
            ewma_quality: Some(200),
            sample_count: 9,
            iface_name: "lora0".into(),
        }]
    }
    fn link_features_table(&self) -> Vec<LinkFeaturesEntryData> {
        vec![LinkFeaturesEntryData {
            iface_idx: 0,
            tx_ogm: true,
            rx_ogm: true,
            tx_data: false,
            rx_data: true,
            tx_keepalive_interval_ms: Some(2000),
            iface_name: "lora0".into(),
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
            iface_name: "lora0".into(),
        }]
    }
    fn throughput(&self) -> Vec<InterfaceThroughputData> {
        vec![InterfaceThroughputData {
            iface_idx: 0,
            rx_bps: 1500.0,
            rx_fps: 12.0,
            tx_bps: 800.0,
            tx_fps: 6.0,
            iface_name: "lora0".into(),
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
    fn logs(&self, since_seq: u64, max_records: u32) -> LogsData {
        let snapshot = wayfinder_log::logs_since(since_seq, max_records as usize);
        LogsData {
            records: snapshot
                .records
                .into_iter()
                .map(|r| LogRecordData {
                    seq: r.seq,
                    uptime_ms: r.uptime_ms,
                    level: match r.level {
                        wayfinder_log::Level::Error => LogLevelData::Error,
                        wayfinder_log::Level::Warn => LogLevelData::Warn,
                        wayfinder_log::Level::Info => LogLevelData::Info,
                        wayfinder_log::Level::Debug => LogLevelData::Debug,
                        wayfinder_log::Level::Trace => LogLevelData::Trace,
                    },
                    target: r.target.as_str().into(),
                    message: r.message.as_str().into(),
                })
                .collect(),
            next_seq: snapshot.next_seq,
            dropped: snapshot.dropped,
            filter: wayfinder_log::current_spec().as_str().into(),
        }
    }
    fn set_log_level(&mut self, directives: &str) -> Result<String, String> {
        wayfinder_log::set_filter(directives)
            .map(|()| wayfinder_log::current_spec().as_str().to_string())
            .map_err(|e| format!("{e}"))
    }
    fn get_trust_anchor(&self) -> Result<Vec<u8>, String> {
        Ok(vec![0xab; 36])
    }
}

/// Grab an almost-certainly-free localhost port by binding to :0 and releasing.
pub fn free_port() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

/// Start a TLS management server backed by [`Mock`] on an ephemeral port.
///
/// Returns the address it bound and the node's Ed25519 public key, which a
/// client pins. Authentication is bootstrap-style: a client presents the node's
/// own seed, [`NODE_SEED`].
pub async fn serve_mock_node() -> (SocketAddr, [u8; 32]) {
    let ck = wayfinder_tls_mgmt::certified_key_from_seed(&NODE_SEED).unwrap();
    let node_key = wayfinder_tls_mgmt::raw_ed25519_from_spki(ck.cert[0].as_ref()).unwrap();

    let (query_tx, mut query_rx) =
        mpsc::channel::<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>(16);
    tokio::spawn(async move {
        let mut service = WayfinderService::new(Mock);
        while let Some((req, resp_tx)) = query_rx.recv().await {
            let _ = resp_tx.send(service.handle(req));
        }
    });

    // Un-enrolled router snapshot responder: no anchor, nothing revoked.
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
            wayfinder_server::serve_tls_server(listener, NODE_SEED, snapshot_tx, query_tx).await;
    });

    (addr, node_key)
}

/// The mock node's identity seed. Fixed so a caller can write it to a file and
/// point a client at it; it is a test fixture, never a real key.
pub const NODE_SEED: [u8; 32] = [7u8; 32];
