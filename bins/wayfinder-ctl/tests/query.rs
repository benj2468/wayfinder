//! `run_query` glue: open an authenticated TLS client to a real in-process
//! `wayfinder-server`, issue the RPC, and render the result.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use wayfinder_auth::Keypair;
use wayfinder_client::Identity;
use wayfinder_protos::service::AlarmsData;
use wayfinder_protos::service::AuthorityDataProvider;
use wayfinder_protos::service::InterfaceThroughputData;
use wayfinder_protos::service::KeepAliveEntryData;
use wayfinder_protos::service::LinkFeaturesEntryData;
use wayfinder_protos::service::LinkQualityEntryData;
use wayfinder_protos::service::LogLevelData;
use wayfinder_protos::service::LogRecordData;
use wayfinder_protos::service::LogsData;
use wayfinder_protos::service::NodeMetricsData;
use wayfinder_protos::service::NodeSecurityData;
use wayfinder_protos::service::OgmScheduleEntryData;
use wayfinder_protos::service::PingSessionData;
use wayfinder_protos::service::PingStartData;
use wayfinder_protos::service::ProbeData;
use wayfinder_protos::service::ProbeStateData;
use wayfinder_protos::service::RouteResolutionData;
use wayfinder_protos::service::RouterReads;
use wayfinder_protos::service::RouterWrites;
use wayfinder_protos::service::RoutingEntryData;
use wayfinder_protos::service::RuntimeConfigData;
use wayfinder_protos::service::SecurityStatusData;
use wayfinder_protos::service::TableOccupancyData;
use wayfinder_protos::service::WayfinderService;
use wayfinder_protos::wayfinder::v1alpha::WayfinderRequest;
use wayfinder_protos::wayfinder::v1alpha::WayfinderResponse;
use wayfinder_server::AuthSnapshot;
use wayfinder_server::serve_tls_server;
use wayfinderctl::Command;
use wayfinderctl::Endpoint;
use wayfinderctl::auth::AuthCommand;
use wayfinderctl::link::LinkCommand;
use wayfinderctl::output::OutputFormat;
use wayfinderctl::run_query;

/// Minimal provider: only `node_info` carries meaningful values; the rest return
/// empty/zero, which is all the `node-info` query exercises.
struct Mock;

fn occ() -> TableOccupancyData {
    TableOccupancyData {
        used: 0,
        capacity: 0,
    }
}

impl RouterReads for Mock {
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

    fn link_features_table(&self) -> Vec<LinkFeaturesEntryData> {
        vec![LinkFeaturesEntryData {
            iface_idx: 0,
            tx_ogm: false,
            rx_ogm: true,
            tx_data: true,
            rx_data: true,
            tx_keepalive_interval_ms: Some(3000),
            iface_name: "lora0".into(),
        }]
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
            untaggable_drop_rate: 2.25,
            seqno_resyncs: 7,
            ogm_refloods_suppressed: 11,
            ogm_echoes_dropped: 13,
            ogm_tails_malformed: 5,
            proofs_swept: 3,
            unjudged_cert_admissions: 0,
        }
    }

    fn resolve_route(&self, _destination: &[u8]) -> Option<RouteResolutionData> {
        None
    }

    /// A finished two-probe session under the handle `start_ping` below
    /// issues, and nothing under any other handle — so a test can drive the
    /// whole start-poll-render path while the displaced-session case stays
    /// reachable, rather than being papered over by a mock that answers to
    /// anything.
    fn ping_session(&self, session_seq: u32) -> Option<PingSessionData> {
        if session_seq != 1 {
            return None;
        }
        Some(PingSessionData {
            session_seq: 1,
            destination: vec![0, 0, 0, 0, 0, 2],
            active: false,
            requested: 2,
            sent: 2,
            received: 1,
            lost: 1,
            rtt_min_us: 12_000,
            rtt_avg_us: 12_000,
            rtt_max_us: 12_000,
            rtt_mdev_us: 0,
            payload_bytes: 16,
            probes: vec![
                ProbeData {
                    seqno: 0,
                    state: ProbeStateData::Replied,
                    rtt_us: 12_000,
                    forward_hops: 2,
                    return_hops: 3,
                },
                ProbeData {
                    seqno: 1,
                    state: ProbeStateData::TimedOut,
                    rtt_us: 0,
                    forward_hops: 0,
                    return_hops: 0,
                },
            ],
        })
    }

    fn runtime_config_active(&self) -> bool {
        true
    }

    fn clock_posture(&self) -> wayfinder_protos::service::ClockPostureData {
        // A mock with no clock policy to report: `At` matches the `true` it
        // reports for `clock_trusted`, so the two do not contradict.
        wayfinder_protos::service::ClockPostureData::At
    }

    fn clock_trusted(&self) -> bool {
        true
    }

    /// Log access is served from a process-wide ring rather than from router
    /// state, so this stub synthesises a batch instead of consulting one — these
    /// tests exercise the transport and the query commands, not the ring itself
    /// (covered in `wayfinder-log` and `RouterAdapter`).
    ///
    /// The requested `since_seq` is echoed back through the record's `seq` and
    /// `max_records` through `dropped`, so a test can prove the CLI's `--since`
    /// and `--max` actually reach the wire rather than being parsed and
    /// discarded.
    fn alarms(&self) -> AlarmsData {
        // Nothing wrong: an empty board is the node's "all systems normal", and
        // none of these cases is about alarms.
        AlarmsData::default()
    }

    fn logs(&self, since_seq: u64, max_records: u32) -> LogsData {
        LogsData {
            records: vec![LogRecordData {
                seq: since_seq,
                uptime_ms: 12_345,
                level: LogLevelData::Warn,
                target: "wayfinder::router".to_string(),
                message: "staging buffer full".to_string(),
            }],
            next_seq: since_seq + 1,
            dropped: u64::from(max_records),
            filter: "info,batman=trace".to_string(),
        }
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
                    revocation_not_after: 0,
                },
                NodeSecurityData {
                    node_id: vec![0, 0, 0, 0, 0, 3],
                    verified: false,
                    cert_not_after: 0,
                    revoked: true,
                    revocation_not_after: 2100,
                },
            ],
            ..Default::default()
        }
    }
}

impl RouterWrites for Mock {
    fn set_auth(
        &mut self,
        _seed: &[u8],
        _cert: &[u8],
        _trust_anchor: &[u8],
        _provider: Option<wayfinder_protos::service::RenewalProviderData>,
        _installer_unix: u64,
    ) -> Result<(), String> {
        Ok(())
    }

    fn set_time(&mut self, _installer_unix: u64) -> Result<(), String> {
        Ok(())
    }

    fn set_config(&mut self, _config: RuntimeConfigData) -> Result<(), String> {
        Ok(())
    }

    /// Accepts a session and echoes back what was asked for, defaulting
    /// zeroes the way a real node does, but never emits anything: there is
    /// no mesh behind this mock to probe.
    fn start_ping(
        &mut self,
        destination: &[u8],
        count: u32,
        interval_ms: u32,
        timeout_ms: u32,
        payload_bytes: u32,
    ) -> Result<PingStartData, String> {
        if destination.len() != 6 {
            return Err("destination must be a 6-byte node identifier".into());
        }
        Ok(PingStartData {
            session_seq: 1,
            count: if count == 0 { 5 } else { count },
            interval_ms: if interval_ms == 0 { 1_000 } else { interval_ms },
            timeout_ms: if timeout_ms == 0 { 5_000 } else { timeout_ms },
            payload_bytes: if payload_bytes == 0 {
                16
            } else {
                payload_bytes
            },
        })
    }

    /// Honours the handle, answering with the same session the read side
    /// serves — so the CLI's cancel path is driven end to end and the
    /// wrong-handle case stays reachable.
    fn cancel_ping(&mut self, session_seq: u32) -> Option<PingSessionData> {
        RouterReads::ping_session(self, session_seq)
    }

    fn set_log_level(&mut self, directives: &str) -> Result<String, String> {
        Ok(directives.to_string())
    }
}

impl AuthorityDataProvider for Mock {}

/// Spawn a node serving the authenticated TLS management API in front of the
/// `Mock` provider, and return an [`Endpoint`] that bootstraps against it (the
/// node is un-enrolled, so proving its own key is admitted).
async fn spawn_server() -> Endpoint {
    // The node's TLS identity seed; the bootstrap client presents this same key.
    let seed = [9u8; 32];
    let node_key = Keypair::from_seed(&seed).ed_pubkey();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (query_tx, mut query_rx) =
        mpsc::channel::<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>(16);

    // Auth snapshot responder: un-enrolled (no anchor), nothing revoked — so the
    // client bootstrapping with the node's own key is granted.
    let (snapshot_tx, mut snapshot_rx) = mpsc::channel::<oneshot::Sender<AuthSnapshot>>(4);
    tokio::spawn(async move {
        while let Some(reply) = snapshot_rx.recv().await {
            let _ = reply.send(AuthSnapshot {
                own_key: Some(node_key),
                anchor: None,
                revoked: Vec::new(),
                own_mac: wayfinder_server::Mac([2, 0, 0, 0, 0, 1]),
            });
        }
    });
    tokio::spawn(async move {
        let _ = serve_tls_server(listener, seed, snapshot_tx, query_tx).await;
    });
    tokio::spawn(async move {
        let mut service = WayfinderService::new(Mock);
        while let Some((req, resp_tx)) = query_rx.recv().await {
            let _ = resp_tx.send(service.handle(req));
        }
    });
    // Give the listener a moment to bind.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    Endpoint {
        addr: addr.into(),
        node_key,
        identity: Identity {
            seed,
            cert: Vec::new(),
        },
    }
}

#[tokio::test]
async fn node_info_query_renders_json_from_server() {
    let endpoint = spawn_server().await;
    let out = run_query(Command::NodeInfo, &endpoint, OutputFormat::Json)
        .await
        .expect("query succeeds");
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["num_originators"], 5);
    assert_eq!(parsed["auth_locked"], true);
    assert_eq!(parsed["runtime_config_active"], true);
}

#[tokio::test]
async fn node_info_query_renders_human_from_server() {
    let endpoint = spawn_server().await;
    let out = run_query(Command::NodeInfo, &endpoint, OutputFormat::Human)
        .await
        .unwrap();
    assert!(out.contains("aa:bb:cc:dd:ee:07"), "got: {out}");
    assert!(out.contains("originators: 5"), "got: {out}");
    assert!(out.contains("locked: yes"), "got: {out}");
    assert!(out.contains("runtime config: yes"), "got: {out}");
}

#[tokio::test]
async fn keepalive_query_renders_json_from_server() {
    let endpoint = spawn_server().await;
    let out = run_query(Command::Keepalive, &endpoint, OutputFormat::Json)
        .await
        .expect("query succeeds");
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["entries"][0]["ms_since_last_heard"], 4200);
    assert_eq!(parsed["entries"][0]["interval_estimate_ms"], 1000);
    assert_eq!(parsed["entries"][0]["missed"], true);
}

#[tokio::test]
async fn keepalive_query_renders_human_from_server() {
    let endpoint = spawn_server().await;
    let out = run_query(Command::Keepalive, &endpoint, OutputFormat::Human)
        .await
        .unwrap();
    assert!(out.contains("00:00:00:00:00:02"), "got: {out}");
    assert!(out.contains("4200"), "got: {out}");
    assert!(out.contains("1000"), "got: {out}");
    assert!(out.contains("yes"), "got: {out}");
}

#[tokio::test]
async fn link_features_query_renders_json_from_server() {
    let endpoint = spawn_server().await;
    let out = run_query(
        Command::Link(LinkCommand::Features),
        &endpoint,
        OutputFormat::Json,
    )
    .await
    .expect("query succeeds");
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["entries"][0]["iface_idx"], 0);
    assert_eq!(parsed["entries"][0]["tx_ogm"], false);
    assert_eq!(parsed["entries"][0]["rx_ogm"], true);
    assert_eq!(parsed["entries"][0]["tx_keepalive_interval_ms"], 3000);
}

#[tokio::test]
async fn link_features_query_renders_human_from_server() {
    let endpoint = spawn_server().await;
    let out = run_query(
        Command::Link(LinkCommand::Features),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .unwrap();
    assert!(out.contains("3000"), "got: {out}");
    assert!(out.contains("mixed"), "got: {out}");
}

#[tokio::test]
async fn link_enable_query_succeeds_against_server() {
    let endpoint = spawn_server().await;
    let out = run_query(
        Command::Link(LinkCommand::Enable { iface: 0 }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect("query succeeds");
    assert!(out.contains("enabled"), "got: {out}");
}

#[tokio::test]
async fn link_disable_query_succeeds_against_server() {
    let endpoint = spawn_server().await;
    let out = run_query(
        Command::Link(LinkCommand::Disable { iface: 0 }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect("query succeeds");
    assert!(out.contains("disabled"), "got: {out}");
}

#[tokio::test]
async fn set_trickle_config_query_succeeds_against_server() {
    let endpoint = spawn_server().await;
    let out = run_query(
        Command::Link(LinkCommand::Trickle {
            iface: 0,
            min_ms: 500,
            max_ms: 4000,
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect("query succeeds");
    assert!(out.contains("trickle config"), "got: {out}");
}

#[tokio::test]
async fn set_link_features_query_succeeds_against_server() {
    let endpoint = spawn_server().await;
    let out = run_query(
        Command::Link(LinkCommand::Set {
            iface: 0,
            tx_ogm: Some(false),
            rx_ogm: None,
            tx_data: None,
            rx_data: None,
            tx_keepalive_interval_ms: None,
            tx_keepalive_disable: false,
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect("query succeeds");
    assert!(out.contains("link features"), "got: {out}");
}

#[tokio::test]
async fn set_lazy_cert_distribution_query_succeeds_against_server() {
    let endpoint = spawn_server().await;
    let out = run_query(
        Command::Auth(AuthCommand::LazyCerts { enabled: true }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect("query succeeds");
    assert!(out.contains("lazy cert distribution"), "got: {out}");
}

#[tokio::test]
async fn metrics_query_renders_json_from_server() {
    let endpoint = spawn_server().await;
    let out = run_query(Command::Metrics, &endpoint, OutputFormat::Json)
        .await
        .expect("query succeeds");
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["oversize_drops"], 3);
    assert_eq!(parsed["relay_oversize_drops"], 9);
    assert_eq!(parsed["cert_store"]["used"], 2);
    assert_eq!(parsed["in_flight_cert_requests"]["used"], 1);
    assert_eq!(parsed["cert_req_rate"], 0.5);
    assert_eq!(parsed["cert_reply_rate"], 1.5);
    assert_eq!(parsed["untaggable_drop_rate"], 2.25);
    // Counts, so they must survive the wire as integers rather than being
    // rendered like the rates beside them.
    assert_eq!(parsed["seqno_resyncs"], 7);
    assert_eq!(parsed["ogm_refloods_suppressed"], 11);
    assert_eq!(parsed["ogm_echoes_dropped"], 13);
    assert_eq!(parsed["ogm_tails_malformed"], 5);
    assert_eq!(parsed["proofs_swept"], 3);
}

#[tokio::test]
async fn metrics_query_renders_human_from_server() {
    let endpoint = spawn_server().await;
    let out = run_query(Command::Metrics, &endpoint, OutputFormat::Human)
        .await
        .unwrap();
    assert!(out.contains("oversize_drops: 3"), "got: {out}");
    assert!(out.contains("relay_oversize_drops: 9"), "got: {out}");
    assert!(out.contains("cert_store: 2/64"), "got: {out}");
    assert!(out.contains("in_flight_cert_requests: 1/16"), "got: {out}");
    assert!(out.contains("pending_cert_replies: 0/16"), "got: {out}");
    assert!(out.contains("cert_req_rate: 0.50"), "got: {out}");
    assert!(out.contains("cert_reply_rate: 1.50"), "got: {out}");
    assert!(out.contains("ogm_echoes_dropped: 13"), "got: {out}");
    assert!(out.contains("ogm_tails_malformed: 5"), "got: {out}");
    assert!(out.contains("untaggable_drop_rate: 2.25"), "got: {out}");
    assert!(out.contains("seqno_resyncs: 7"), "got: {out}");
    assert!(out.contains("ogm_refloods_suppressed: 11"), "got: {out}");
    assert!(out.contains("proofs_swept: 3"), "got: {out}");
}

#[tokio::test]
async fn security_query_renders_json_from_server() {
    let endpoint = spawn_server().await;
    let out = run_query(
        Command::Auth(AuthCommand::Status),
        &endpoint,
        OutputFormat::Json,
    )
    .await
    .expect("query succeeds");
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["auth_enabled"], true);
    assert_eq!(parsed["mesh_id"], 0xABCD);
    assert_eq!(parsed["nodes"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn security_query_renders_human_from_server() {
    let endpoint = spawn_server().await;
    let out = run_query(
        Command::Auth(AuthCommand::Status),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .unwrap();
    assert!(out.contains("authentication: enabled"), "got: {out}");
    assert!(out.contains("revoked"), "got: {out}");
    assert!(out.contains("00:00:00:00:00:02"), "got: {out}");
}

#[tokio::test]
async fn logs_query_renders_human_from_server() {
    let endpoint = spawn_server().await;
    let out = run_query(
        Command::Logs {
            since: 0,
            max: 0,
            follow: false,
        },
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect("query succeeds");
    assert!(out.contains("12.345s"), "got: {out}");
    assert!(out.contains("WARN"), "got: {out}");
    assert!(out.contains("wayfinder::router"), "got: {out}");
    assert!(out.contains("staging buffer full"), "got: {out}");
    assert!(out.contains("filter: info,batman=trace"), "got: {out}");
}

#[tokio::test]
async fn logs_query_sends_since_and_max_to_the_node() {
    let endpoint = spawn_server().await;
    let out = run_query(
        Command::Logs {
            since: 41,
            max: 7,
            follow: false,
        },
        &endpoint,
        OutputFormat::Json,
    )
    .await
    .expect("query succeeds");
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    // The mock echoes `since_seq` back as the record's seq and `max_records` as
    // `dropped`, so these assertions fail if either flag is dropped on the way
    // to the wire rather than merely mis-rendered.
    assert_eq!(parsed["records"][0]["seq"], 41);
    assert_eq!(parsed["next_seq"], 42);
    assert_eq!(parsed["dropped"], 7);
}

#[tokio::test]
async fn ping_query_runs_a_session_and_renders_it() {
    let endpoint = spawn_server().await;
    let out = run_query(
        Command::Ping {
            dest: "00:00:00:00:00:02".into(),
            count: 2,
            interval: 10,
            timeout: 100,
            size: 16,
        },
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect("query succeeds");

    // The replied probe reports both hop counts and a round trip; the lost one
    // says so instead of being silently dropped from the output.
    assert!(
        out.contains("16 bytes from 00:00:00:00:00:02: seq=0 hops=2/3 time=12.0 ms"),
        "got: {out}"
    );
    assert!(
        out.contains("no answer from 00:00:00:00:00:02: seq=1"),
        "got: {out}"
    );
    assert!(
        out.contains("2 probes attempted, 1 received, 50% loss"),
        "got: {out}"
    );
    assert!(out.contains("rtt min/avg/max/mdev"), "got: {out}");
}

#[tokio::test]
async fn ping_query_renders_json() {
    let endpoint = spawn_server().await;
    let out = run_query(
        Command::Ping {
            dest: "00:00:00:00:00:02".into(),
            count: 2,
            interval: 10,
            timeout: 100,
            size: 16,
        },
        &endpoint,
        OutputFormat::Json,
    )
    .await
    .expect("query succeeds");
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["sent"], 2);
    assert_eq!(parsed["received"], 1);
    assert_eq!(parsed["probes"][0]["rtt_us"], 12_000);
}

/// A destination that is not a node identifier is refused before anything
/// reaches the wire, rather than probing a truncated address.
#[tokio::test]
async fn ping_query_rejects_a_malformed_destination() {
    let endpoint = spawn_server().await;
    let err = run_query(
        Command::Ping {
            dest: "not-a-mac".into(),
            count: 1,
            interval: 10,
            timeout: 100,
            size: 0,
        },
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .expect_err("a malformed destination must be refused");
    assert!(
        format!("{err:#}").to_lowercase().contains("hex"),
        "got: {err:#}"
    );
}

/// Cancelling over the wire returns the session as it stood, so the client that
/// stopped it can print what it measured rather than discarding a run that
/// already cost the airtime.
#[tokio::test]
async fn cancel_ping_returns_the_stopped_session() {
    let endpoint = spawn_server().await;
    let mut client = wayfinder_client::Client::connect_tls(
        &endpoint.addr,
        &endpoint.node_key,
        &endpoint.identity,
    )
    .await
    .expect("connect");

    let started = client
        .ping(vec![0, 0, 0, 0, 0, 2], 5, 10, 100, 16)
        .await
        .expect("start");
    let cancelled = client
        .cancel_ping(started.session_seq)
        .await
        .expect("cancel succeeds");

    let session = cancelled
        .session
        .expect("our own handle cancels our session");
    assert!(!session.active, "a cancelled session has no work left");
    assert_eq!(session.received, 1, "and keeps what it measured");
}

/// A handle the node is not running cancels nothing, and that is success rather
/// than an error: cancelling is what a client does on its way out, and a
/// session that has already stopped is the outcome it wanted.
#[tokio::test]
async fn cancelling_an_unknown_handle_is_not_an_error() {
    let endpoint = spawn_server().await;
    let mut client = wayfinder_client::Client::connect_tls(
        &endpoint.addr,
        &endpoint.node_key,
        &endpoint.identity,
    )
    .await
    .expect("connect");

    let cancelled = client
        .cancel_ping(9_999)
        .await
        .expect("cancel is not an error");
    assert!(cancelled.session.is_none());
}
