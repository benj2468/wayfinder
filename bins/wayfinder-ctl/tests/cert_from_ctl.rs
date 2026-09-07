//! `wayfinderctl`'s own `--cert-from` wiring, which is not the same code as
//! [`ConnectArgs::resolve_target`].
//!
//! The CLI resolves its endpoint through `build_endpoint`, which has one
//! behavior the shared resolver has no concept of: a *stored login session*. An
//! operator who has run `wayfinderctl login` has a credential on disk, and
//! every command normally picks it up with no flags at all. `--cert-from` must
//! not compose with it — it asserts the certificate presented is a node's own,
//! and a node's certificate names the key in that node's identity seed, which
//! an operator's session key is not.
//!
//! So `build_endpoint` short-circuits to the identity path before it ever looks
//! for a session. That ordering is load-bearing and invisible: reverse the two
//! branches and an operator with a valid session would pair a node's
//! certificate with an *operator's* seed, and — worse — pin the node it fetches
//! from to that operator's key. Everything still compiles, and every test that
//! enters through `resolve_target` still passes, because that function cannot
//! reach a session at all. This file is what notices.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::Mutex;

use clap::Parser;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use wayfinder_auth::Authority;
use wayfinder_auth::Keypair;
use wayfinder_auth::TrustAnchor;
use wayfinder_protos::service::AlarmsData;
use wayfinder_protos::service::InterfaceThroughputData;
use wayfinder_protos::service::KeepAliveEntryData;
use wayfinder_protos::service::LinkFeaturesEntryData;
use wayfinder_protos::service::LinkQualityEntryData;
use wayfinder_protos::service::LogsData;
use wayfinder_protos::service::NodeMetricsData;
use wayfinder_protos::service::OgmScheduleEntryData;
use wayfinder_protos::service::OwnCertData;
use wayfinder_protos::service::PingSessionData;
use wayfinder_protos::service::PingStartData;
use wayfinder_protos::service::RouteResolutionData;
use wayfinder_protos::service::RouterReads;
use wayfinder_protos::service::RouterWrites;
use wayfinder_protos::service::RoutingEntryData;
use wayfinder_protos::service::RuntimeConfigData;
use wayfinder_protos::service::SecurityStatusData;
use wayfinder_protos::service::TableOccupancyData;
use wayfinder_protos::wayfinder::v1alpha::WayfinderRequest;
use wayfinder_protos::wayfinder::v1alpha::WayfinderResponse;
use wayfinder_server::AuthSnapshot;
use zerocopy::IntoBytes;

fn occ() -> TableOccupancyData {
    TableOccupancyData {
        used: 0,
        capacity: 0,
    }
}

/// A node that reports the certificate it runs under and records how many times
/// it was asked, so a test can prove the endpoint is resolved once per command
/// rather than once per connection.
struct NodeMock {
    keypair: Keypair,
    own_cert: Option<OwnCertData>,
    own_cert_calls: Arc<Mutex<u32>>,
}

impl RouterReads for NodeMock {
    fn node_id(&self) -> Vec<u8> {
        self.keypair.derived_mac().0.to_vec()
    }

    fn num_originators(&self) -> u32 {
        0
    }

    fn auth_locked(&self) -> bool {
        false
    }

    fn routing_table(&self) -> Vec<RoutingEntryData> {
        vec![]
    }

    fn link_quality_table(&self) -> Vec<LinkQualityEntryData> {
        vec![]
    }

    fn link_features_table(&self) -> Vec<LinkFeaturesEntryData> {
        vec![]
    }

    fn keepalive_table(&self) -> Vec<KeepAliveEntryData> {
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
            relay_oversize_drops: 0,
            cert_store: occ(),
            in_flight_cert_requests: occ(),
            pending_cert_replies: occ(),
            cert_req_rate: 0.0,
            cert_reply_rate: 0.0,
            untaggable_drop_rate: 0.0,
            seqno_resyncs: 0,
            ogm_refloods_suppressed: 0,
            proofs_swept: 0,
        }
    }

    fn resolve_route(&self, _destination: &[u8]) -> Option<RouteResolutionData> {
        None
    }

    /// This mock runs no ping session, and says so rather than
    /// fabricating one — a handle that always resolved would hide exactly
    /// the displaced-session case the handle exists to expose.
    fn ping_session(&self, _session_seq: u32) -> Option<PingSessionData> {
        None
    }

    fn runtime_config_active(&self) -> bool {
        false
    }

    fn clock_trusted(&self) -> bool {
        true
    }

    fn alarms(&self) -> AlarmsData {
        AlarmsData::default()
    }

    fn logs(&self, _since_seq: u64, _max_records: u32) -> LogsData {
        LogsData::default()
    }

    fn security_status(&self) -> SecurityStatusData {
        SecurityStatusData {
            own_ed_pubkey: self.keypair.ed_pubkey().to_vec(),
            own_x_pubkey: self.keypair.x_pubkey().to_vec(),
            self_revoked: false,
            self_revocation_not_after: 0,
            ..SecurityStatusData::default()
        }
    }

    fn own_cert(&self) -> Option<OwnCertData> {
        #[allow(clippy::unwrap_used)]
        {
            *self.own_cert_calls.lock().unwrap() += 1;
        }
        self.own_cert.clone()
    }
}

impl RouterWrites for NodeMock {
    fn set_auth(
        &mut self,
        _seed: &[u8],
        _cert: &[u8],
        _anchor: &[u8],
        _provider: Option<wayfinder_protos::service::RenewalProviderData>,
    ) -> Result<(), String> {
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

    /// Nothing to cancel: these mocks run no session. Distinct from a mock
    /// that cancelled anything asked of it, which would hide the wrong-handle
    /// case the handle exists to catch.
    fn cancel_ping(&mut self, _session_seq: u32) -> Option<PingSessionData> {
        None
    }

    fn set_log_level(&mut self, directives: &str) -> Result<String, String> {
        Ok(directives.to_string())
    }
}

/// Mint the credential a node that enrolled would be running under.
fn certified(seed: &[u8; 32]) -> OwnCertData {
    let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
    let kp = Keypair::from_seed(seed);
    let cert = authority.issue_cert(
        wayfinder_server::Mac(kp.derived_mac().0),
        kp.ed_pubkey(),
        kp.x_pubkey(),
        0,
        u64::MAX,
    );
    OwnCertData {
        cert: cert.as_bytes().to_vec(),
        trust_anchor: authority.trust_anchor().to_bytes().to_vec(),
    }
}

/// Spawn a node at `seed` holding `own_cert`; returns its address and the
/// counter of `GetOwnCert` calls it served.
async fn spawn_node(seed: [u8; 32], own_cert: Option<OwnCertData>) -> (String, Arc<Mutex<u32>>) {
    let node_key = Keypair::from_seed(&seed).ed_pubkey();
    let anchor = own_cert
        .as_ref()
        .and_then(|pair| TrustAnchor::from_bytes(&pair.trust_anchor));
    let calls = Arc::new(Mutex::new(0u32));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (query_tx, mut query_rx) =
        mpsc::channel::<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>(16);
    let (snapshot_tx, mut snapshot_rx) = mpsc::channel::<oneshot::Sender<AuthSnapshot>>(4);
    tokio::spawn(async move {
        while let Some(reply) = snapshot_rx.recv().await {
            let _ = reply.send(AuthSnapshot {
                own_key: Some(node_key),
                anchor,
                revoked: Vec::new(),
                own_mac: wayfinder_server::Mac([2, 0, 0, 0, 0, 1]),
            });
        }
    });
    tokio::spawn(async move {
        let _ = wayfinder_server::serve_tls_server(listener, seed, snapshot_tx, query_tx).await;
    });
    let provider_calls = Arc::clone(&calls);
    tokio::spawn(async move {
        let mut provider = NodeMock {
            keypair: Keypair::from_seed(&seed),
            own_cert,
            own_cert_calls: provider_calls,
        };
        while let Some((req, resp_tx)) = query_rx.recv().await {
            let resp = wayfinder_protos::service::handle_router(&mut provider, req)
                .unwrap_or_else(|_| wayfinder_server::not_a_provider_response());
            let _ = resp_tx.send(resp);
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr.to_string(), calls)
}

/// Plant an unexpired login session for a key that is *not* any node's, under a
/// throwaway config home, and return that home.
///
/// The seed is what matters: if `build_endpoint` ever preferred the session,
/// this key — not the node's — would be the one presented and the one the
/// `--cert-from` node is pinned to.
fn planted_session(dir: &std::path::Path, operator_seed: [u8; 32]) -> std::path::PathBuf {
    let config = dir.join("config");
    let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
    let kp = Keypair::from_seed(&operator_seed);
    let cert = authority.issue_user_cert(
        wayfinder_server::Mac([9, 9, 9, 9, 9, 9]),
        kp.ed_pubkey(),
        kp.x_pubkey(),
        0,
        u64::MAX,
        true,
    );
    wayfinderctl::session::store(
        &config,
        &operator_seed,
        cert.as_bytes(),
        &wayfinderctl::session::SessionMeta {
            username: "operator".to_string(),
            provider: "ca.example:7700".to_string(),
            provider_key: "00".repeat(32),
            not_before: 0,
            not_after: u64::MAX,
        },
    )
    .unwrap();
    config
}

/// With a valid login session on disk, `--cert-from` still runs on the node's
/// identity — never the operator's session key.
///
/// The assertion is indirect and has to be: if the session seed were used, the
/// `--cert-from` node would be pinned to the *operator's* public key, the
/// handshake would fail, and no certificate would come back at all. So a
/// successful fetch is itself the proof that the identity path won. That is
/// exactly the failure reversing the two branches in `build_endpoint` would
/// produce.
#[tokio::test]
async fn cert_from_ignores_a_stored_session_and_uses_the_node_identity() {
    let node_seed = [9u8; 32];
    let installed = certified(&node_seed);
    let (node_addr, calls) = spawn_node(node_seed, Some(installed.clone())).await;

    let dir = tempfile::tempdir().unwrap();
    let identity = dir.path().join("identity.seed");
    std::fs::write(&identity, node_seed).unwrap();
    let config = planted_session(dir.path(), [4u8; 32]);

    // `wayfinderctl` reads the session through `session::config_dir()`, which
    // honours this variable — so the planted session is genuinely visible to
    // the code under test, not merely present on disk somewhere.
    // SAFETY: single-threaded test setup, before any task reads the value.
    unsafe { std::env::set_var("WAYFINDER_CONFIG_HOME", &config) };

    // Parsed from real argv rather than hand-built, so the flag plumbing is
    // part of what is under test.
    let cli = wayfinderctl::Cli::parse_from([
        "wayfinderctl",
        "--connect",
        &node_addr,
        "--identity",
        identity.to_str().unwrap(),
        "--cert-from",
        &node_addr,
        "node-info",
    ]);
    let endpoint = wayfinderctl::build_endpoint(&cli)
        .await
        .expect("the node identity, not the session, must resolve this endpoint");

    unsafe { std::env::remove_var("WAYFINDER_CONFIG_HOME") };

    assert_eq!(
        endpoint.identity.seed, node_seed,
        "the seed presented must be the node's, not the session's"
    );
    assert_eq!(
        endpoint.identity.cert, installed.cert,
        "the certificate presented must be the one fetched from the node"
    );
    assert_eq!(
        *calls.lock().unwrap(),
        1,
        "the certificate is fetched exactly once per command, not once per connection"
    );
}
