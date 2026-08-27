//! Presenting the certificate a node *already* holds, fetched from the node.
//!
//! A node that enrolled once holds its membership certificate for good — in a
//! file under static auth, or in the runtime state a `SetAuth` install
//! persisted. Before `--cert-from`, an operator wanting to present that
//! certificate to the provider (to ask for a VPN credential, say) had no way to
//! obtain a *copy* of it except to run a whole second enrollment: `csr request`
//! at the node, `csr submit` at the CA, and a certificate file that duplicated
//! one the node already had.
//!
//! `--cert-from <node>` replaces that round trip with one request. It is not a
//! new credential: the seed in `--identity` is unchanged, and the certificate
//! names that same key — which is exactly why fetching it is safe, and why the
//! node it is fetched from is pinned to that key's own public half.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use clap::Parser;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use wayfinder_auth::Authority;
use wayfinder_auth::Keypair;
use wayfinder_auth::TrustAnchor;
use wayfinder_client::ConnectArgs;
use wayfinder_client::ConnectTarget;
use wayfinder_protos::service::AlarmsData;
use wayfinder_protos::service::InterfaceThroughputData;
use wayfinder_protos::service::KeepAliveEntryData;
use wayfinder_protos::service::LinkFeaturesEntryData;
use wayfinder_protos::service::LinkQualityEntryData;
use wayfinder_protos::service::LogsData;
use wayfinder_protos::service::NodeMetricsData;
use wayfinder_protos::service::OgmScheduleEntryData;
use wayfinder_protos::service::OwnCertData;
use wayfinder_protos::service::RouteResolutionData;
use wayfinder_protos::service::RouterDataProvider;
use wayfinder_protos::service::RoutingEntryData;
use wayfinder_protos::service::RuntimeConfigData;
use wayfinder_protos::service::SecurityStatusData;
use wayfinder_protos::service::TableOccupancyData;
use wayfinder_protos::wayfinder::v1alpha::WayfinderRequest;
use wayfinder_protos::wayfinder::v1alpha::WayfinderResponse;
use wayfinder_server::AuthSnapshot;
use zerocopy::IntoBytes;

/// A parser carrying nothing but the shared connection arguments, standing in
/// for `wayfinderctl` itself — the flag is what is under test, not the
/// subcommand behind it.
#[derive(Parser, Debug)]
struct Harness {
    #[command(flatten)]
    connection: ConnectArgs,
}

/// Parse `args` (with a program name prepended) into the connection arguments.
fn parse(args: &[&str]) -> ConnectArgs {
    let mut argv = vec!["harness"];
    argv.extend_from_slice(args);
    Harness::parse_from(argv).connection
}

fn occ() -> TableOccupancyData {
    TableOccupancyData {
        used: 0,
        capacity: 0,
    }
}

/// A node that answers exactly one question interestingly — "what certificate
/// are you running under?" — and gives every other request an empty answer.
///
/// `own_cert` is an `Option` so a test can spawn the un-enrolled case, which is
/// the one whose error message matters.
struct NodeMock {
    keypair: Keypair,
    own_cert: Option<OwnCertData>,
}

impl RouterDataProvider for NodeMock {
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
        }
    }
    fn resolve_route(&self, _destination: &[u8]) -> Option<RouteResolutionData> {
        None
    }
    fn set_auth(&mut self, _seed: &[u8], _cert: &[u8], _anchor: &[u8]) -> Result<(), String> {
        Ok(())
    }
    fn set_config(&mut self, _config: RuntimeConfigData) -> Result<(), String> {
        Ok(())
    }
    fn runtime_config_active(&self) -> bool {
        false
    }
    fn alarms(&self) -> AlarmsData {
        AlarmsData::default()
    }
    fn logs(&self, _since_seq: u64, _max_records: u32) -> LogsData {
        LogsData::default()
    }
    fn set_log_level(&mut self, directives: &str) -> Result<String, String> {
        Ok(directives.to_string())
    }
    fn security_status(&self) -> SecurityStatusData {
        SecurityStatusData {
            own_ed_pubkey: self.keypair.ed_pubkey().to_vec(),
            own_x_pubkey: self.keypair.x_pubkey().to_vec(),
            ..SecurityStatusData::default()
        }
    }
    fn own_cert(&self) -> Option<OwnCertData> {
        self.own_cert.clone()
    }
}

/// Spawn a node holding `own_cert`, reachable at the returned address with the
/// returned seed. The transport reports no trust anchor, so the client is
/// admitted on the self-key path — which is the posture an operator standing on
/// the node's own host is always in.
async fn spawn_node(seed: [u8; 32], own_cert: Option<OwnCertData>) -> String {
    let node_key = Keypair::from_seed(&seed).ed_pubkey();
    // A node holding a certificate necessarily holds the anchor it chains to —
    // `RouterAdapter::own_cert` reads both off one `router.auth()`. Reporting a
    // certificate with `anchor: None` would spawn a node that cannot exist, and
    // would pass only because `decide_access` short-circuits on the self-key
    // check before it looks at the anchor. Keeping the two consistent is what
    // makes this test able to notice if that ordering ever changes.
    let anchor = own_cert
        .as_ref()
        .and_then(|pair| TrustAnchor::from_bytes(&pair.trust_anchor));
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
        let _ =
            wayfinder_server::serve_tls_server(listener, seed, snapshot_tx, query_tx.clone()).await;
    });
    tokio::spawn(async move {
        let mut provider = NodeMock {
            keypair: Keypair::from_seed(&seed),
            own_cert,
        };
        while let Some((req, resp_tx)) = query_rx.recv().await {
            let resp = wayfinder_protos::service::handle_router(&mut provider, req)
                .unwrap_or_else(|_| wayfinder_server::not_a_provider_response());
            let _ = resp_tx.send(resp);
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    addr.to_string()
}

/// Mint a real membership certificate for `seed`'s identity, plus the anchor it
/// chains to — the credential a node that enrolled would actually be running
/// under.
///
/// Real rather than opaque bytes because the client now verifies what it
/// adopts: it checks the certificate parses, names the key being presented, and
/// belongs to the anchor's mesh. Placeholder bytes would exercise the rejection
/// path on every test instead of the path under test, and the neighbouring
/// suites (`csr_node.rs`, `enroll.rs`) build real credentials for the same
/// reason.
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

/// Write `seed` to a file and return its path, standing in for the node's
/// `/var/lib/wayfinder/identity.seed`.
fn seed_file(dir: &std::path::Path, seed: &[u8; 32]) -> String {
    let path = dir.join("identity.seed");
    std::fs::write(&path, seed).unwrap();
    path.to_str().unwrap().to_string()
}

/// The whole point: the certificate presented to `--connect` is the one the
/// node at `--cert-from` already holds, fetched over the management API. No
/// CSR is submitted, no certificate file exists on the operator's disk, and
/// nothing about where the client is *connecting* changes — only which
/// credential it presents when it gets there.
#[tokio::test]
async fn cert_from_presents_the_certificate_the_node_already_holds() {
    let seed = [9u8; 32];
    let installed = certified(&seed);
    let node_addr = spawn_node(seed, Some(installed.clone())).await;
    let dir = tempfile::tempdir().unwrap();
    let identity = seed_file(dir.path(), &seed);
    // A different node entirely — the certificate authority the credential is
    // being presented *to*. Never connected to here; what matters is that
    // resolving the credential leaves this address and its pin alone.
    let ca_key = Keypair::from_seed(&[3u8; 32]).ed_pubkey();
    let ca_key_hex: String = ca_key.iter().map(|b| format!("{b:02x}")).collect();

    let target = parse(&[
        "--connect",
        "ca.wayfndr.dev:7700",
        "--node-key",
        &ca_key_hex,
        "--identity",
        &identity,
        "--cert-from",
        &node_addr,
    ])
    .resolve_target()
    .await
    .expect("the node holds a certificate to hand over");

    match target {
        ConnectTarget::Tls(endpoint) => {
            assert_eq!(
                endpoint.identity.cert, installed.cert,
                "the credential presented is the node's own certificate"
            );
            assert_eq!(
                endpoint.addr.host(),
                "ca.wayfndr.dev",
                "--cert-from names where the certificate comes from, not where to connect"
            );
            assert_eq!(endpoint.node_key, ca_key, "--connect's pin is untouched");
            assert_eq!(endpoint.identity.seed, seed, "the key is unchanged");
        }
        ConnectTarget::Serial { .. } => panic!("no --serial was given"),
    }
}

/// A node that never enrolled has no certificate to hand over, and the failure
/// says so where it happened. The alternative — presenting an empty credential
/// — fails at the far end as an authorization refusal naming neither this node
/// nor the missing enrollment.
#[tokio::test]
async fn cert_from_a_node_holding_no_certificate_names_the_node() {
    let seed = [9u8; 32];
    let node_addr = spawn_node(seed, None).await;
    let dir = tempfile::tempdir().unwrap();
    let identity = seed_file(dir.path(), &seed);

    let error = match parse(&["--identity", &identity, "--cert-from", &node_addr])
        .resolve_target()
        .await
    {
        Err(error) => format!("{error:#}"),
        // `ConnectTarget` is deliberately not `Debug` (an `Endpoint` holds a
        // secret seed), so the success case is named rather than unwrapped.
        Ok(_) => panic!("a node with no certificate cannot supply one"),
    };

    assert!(
        error.contains(&node_addr),
        "the error should name the node it asked: {error}"
    );
    assert!(
        error.contains("enroll"),
        "the error should name how to get a certificate: {error}"
    );
}

/// A node whose certificate names a *different* key is refused here, with a
/// message about this node — not adopted and refused later by the far end.
///
/// Reachable despite the pin: the pin proves the node holds the seed being
/// presented, which a node with a mis-provisioned certificate store does. What
/// it cannot prove is that the certificate the node hands back matches. Without
/// the local check the client would present it and collect a deliberately
/// generic "authentication denied" from the far end, which names neither this
/// node nor the mismatch.
#[tokio::test]
async fn cert_from_refuses_a_certificate_naming_another_key() {
    let seed = [9u8; 32];
    // The node proves `seed` (so the pin is satisfied) but reports a
    // certificate minted for an entirely different identity.
    let node_addr = spawn_node(seed, Some(certified(&[7u8; 32]))).await;
    let dir = tempfile::tempdir().unwrap();
    let identity = seed_file(dir.path(), &seed);

    let error = match parse(&["--identity", &identity, "--cert-from", &node_addr])
        .resolve_target()
        .await
    {
        Err(error) => format!("{error:#}"),
        Ok(_) => panic!("a certificate for another key is not a credential this client can use"),
    };

    assert!(
        error.contains("different key"),
        "the error should name the mismatch: {error}"
    );
    assert!(
        error.contains("--identity"),
        "the error should say what to check: {error}"
    );
}

/// A certificate and an anchor from different meshes are refused as a pair.
///
/// This is the only reader the response's `trust_anchor` field has, and the
/// reason it is on the wire at all: the two halves are served together so that
/// nobody assembles a credential out of a certificate and somebody else's
/// anchor, and this is the check that makes that promise real rather than
/// merely documented.
#[tokio::test]
async fn cert_from_refuses_a_certificate_and_anchor_from_different_meshes() {
    let seed = [9u8; 32];
    let mut pair = certified(&seed);
    // The certificate is fine and names the right key; only the anchor beside
    // it belongs to another mesh.
    pair.trust_anchor = Authority::from_seed(&[2u8; 32], 0x1234)
        .trust_anchor()
        .to_bytes()
        .to_vec();
    let node_addr = spawn_node(seed, Some(pair)).await;
    let dir = tempfile::tempdir().unwrap();
    let identity = seed_file(dir.path(), &seed);

    let error = match parse(&["--identity", &identity, "--cert-from", &node_addr])
        .resolve_target()
        .await
    {
        Err(error) => format!("{error:#}"),
        Ok(_) => panic!("a certificate and anchor from different meshes do not hang together"),
    };

    assert!(
        error.contains("0xabcd") || error.contains("0x1234"),
        "the error should name the two meshes it found: {error}"
    );
}

/// The node a certificate is fetched from is pinned to `--identity`'s own
/// public key, with no flag to override it.
///
/// That is not a convenience default — it is the security property. A
/// certificate is only useful to the holder of the key it names, and
/// `--identity` is that key, so the only node with a certificate worth having
/// here is the node whose seed this is. Pinning to anything else would let a
/// wrong (or hostile) address hand back a certificate the client would then go
/// and present.
#[tokio::test]
async fn cert_from_refuses_a_node_that_is_not_the_identity_it_holds() {
    let other_seed = [1u8; 32];
    let node_addr = spawn_node(other_seed, Some(certified(&other_seed))).await;
    let dir = tempfile::tempdir().unwrap();
    // A seed that is *not* the spawned node's, so the pin cannot match.
    let identity = seed_file(dir.path(), &[9u8; 32]);

    let error = match parse(&["--identity", &identity, "--cert-from", &node_addr])
        .resolve_target()
        .await
    {
        Err(error) => format!("{error:#}"),
        Ok(_) => panic!(
            "a node presenting a key other than the identity's own must not be trusted \
             to supply that identity's certificate"
        ),
    };

    // Asserted on the *reason*, not merely on failure. A bare `is_err()` stays
    // green if the pin quietly stops being enforced and the call fails for some
    // unrelated reason — a bind race, a wrong address, a new `bail!` inside
    // `load_cert_from_node` — which is exactly the regression this test exists
    // to catch.
    assert!(
        error.contains("pinned node key"),
        "the failure must be the pin rejecting the node's key: {error}"
    );
    assert!(
        error.contains(&node_addr),
        "the error should name the node it refused: {error}"
    );
}
