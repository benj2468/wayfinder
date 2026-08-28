//! The offline-approval workflow driven entirely over the management API,
//! against an in-process node that is *not* a provider.
//!
//! These two commands exist for a node that cannot reach the provider over any
//! network. Online `enroll` needs the two ends mutually reachable; here the CSR
//! travels out-of-band instead — `csr request` writes it at the node, `cert
//! approve` signs it wherever the mesh root key lives, and `csr install` brings
//! the certificate back.
//!
//! Both ends ask the *node*, over the management API, rather than reading its
//! seed off a filesystem: it reports the identity it already runs under
//! (`GetNodeInfo` + `GetSecurityStatus`), and takes the signed result back
//! (`SetAuth` with an empty seed — "certify the identity I already have").
//! So the operator never holds the node's private key, which is what makes
//! this work for a node that minted its own identity.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::Mutex;

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use wayfinder_auth::Keypair;
use wayfinder_auth::MembershipCert;
use wayfinder_auth::TrustAnchor;
use wayfinder_client::Endpoint;
use wayfinder_client::Identity;
use wayfinder_protos::service::AlarmsData;
use wayfinder_protos::service::AuthorityDataProvider;
use wayfinder_protos::service::CsrOutcome;
use wayfinder_protos::service::EnrollmentPolicyStatusData;
use wayfinder_protos::service::InterfaceThroughputData;
use wayfinder_protos::service::IssuedCertData;
use wayfinder_protos::service::KeepAliveEntryData;
use wayfinder_protos::service::LinkFeaturesEntryData;
use wayfinder_protos::service::LinkQualityEntryData;
use wayfinder_protos::service::LogsData;
use wayfinder_protos::service::NodeMetricsData;
use wayfinder_protos::service::OgmScheduleEntryData;
use wayfinder_protos::service::PendingCsrData;
use wayfinder_protos::service::RouteResolutionData;
use wayfinder_protos::service::RouterReads;
use wayfinder_protos::service::RouterWrites;
use wayfinder_protos::service::RoutingEntryData;
use wayfinder_protos::service::RuntimeConfigData;
use wayfinder_protos::service::SecurityStatusData;
use wayfinder_protos::service::TableOccupancyData;
use wayfinder_protos::wayfinder::v1alpha::SubmitCsrRequest;
use wayfinder_protos::wayfinder::v1alpha::WayfinderRequest;
use wayfinder_protos::wayfinder::v1alpha::WayfinderResponse;
use wayfinder_server::AuthSnapshot;
use wayfinderctl::Command;
use wayfinderctl::auth::AuthCommand;
use wayfinderctl::cert::CertCommand;
use wayfinderctl::cert::{self};
use wayfinderctl::csr::CsrCommand;
use wayfinderctl::output::OutputFormat;
use wayfinderctl::run_query;

/// What a `SetAuth` reaching the node carried, captured so a test can assert on
/// the request the node actually received rather than only on the command's
/// exit status.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SetAuthCall {
    seed: Vec<u8>,
    cert: Vec<u8>,
    trust_anchor: Vec<u8>,
}

/// A plain member node — no certificate authority behind it, which is the whole
/// point: this is the node being enrolled, not the one doing the enrolling.
///
/// It reports the identity it runs under and records whatever `SetAuth` it is
/// handed. Every provider method is left refusing, so a test that accidentally
/// drives the online enrollment path against it fails loudly instead of quietly
/// passing for the wrong reason.
struct NodeMock {
    /// The identity the node runs under; its public halves are what a CSR for
    /// this node must name.
    keypair: Keypair,
    /// Whether the node reports having an identity at all. A node with no
    /// identity reports empty public keys, and there is nothing to certify.
    has_identity: bool,
    /// Whether this node reports itself as a provider (an `enrollment`
    /// policy present in `GetSecurityStatusResponse`) rather than a plain
    /// member — the wrong-endpoint case `csr request` must refuse.
    is_provider: bool,
    /// Every `SetAuth` this node received, in order.
    set_auth_calls: Arc<Mutex<Vec<SetAuthCall>>>,
}

fn occ() -> TableOccupancyData {
    TableOccupancyData {
        used: 0,
        capacity: 0,
    }
}

impl RouterReads for NodeMock {
    fn node_id(&self) -> Vec<u8> {
        self.keypair.derived_mac().0.to_vec()
    }

    fn num_originators(&self) -> u32 {
        0
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

    fn runtime_config_active(&self) -> bool {
        false
    }

    fn clock_trusted(&self) -> bool {
        true
    }

    fn alarms(&self) -> AlarmsData {
        // Nothing wrong: an empty board is the node's "all systems normal", and
        // none of these cases is about alarms.
        AlarmsData::default()
    }

    fn logs(&self, _since_seq: u64, _max_records: u32) -> LogsData {
        LogsData::default()
    }

    /// An un-enrolled member: auth off, no certificate, no mesh — but it still
    /// has an identity, and reporting it is exactly what makes a CSR for this
    /// node possible without holding its seed.
    fn security_status(&self) -> SecurityStatusData {
        let (ed, x) = if self.has_identity {
            (
                self.keypair.ed_pubkey().to_vec(),
                self.keypair.x_pubkey().to_vec(),
            )
        } else {
            (Vec::new(), Vec::new())
        };
        SecurityStatusData {
            auth_enabled: false,
            mesh_id: 0,
            node_mac: Vec::new(),
            cert_not_after: 0,
            revocation_count: 0,
            nodes: vec![],
            require_auth: true,
            lazy_cert_distribution: false,
            enrollment: self.is_provider.then_some(EnrollmentPolicyStatusData {
                auto_approve: false,
                cert_ttl_secs: 3600,
                enrollment_token_set: false,
            }),
            own_ed_pubkey: ed,
            own_x_pubkey: x,
            self_revoked: false,
            self_revocation_not_after: 0,
        }
    }
}

impl RouterWrites for NodeMock {
    fn set_auth(&mut self, seed: &[u8], cert: &[u8], trust_anchor: &[u8]) -> Result<(), String> {
        #[allow(clippy::unwrap_used)]
        self.set_auth_calls.lock().unwrap().push(SetAuthCall {
            seed: seed.to_vec(),
            cert: cert.to_vec(),
            trust_anchor: trust_anchor.to_vec(),
        });
        Ok(())
    }

    fn set_config(&mut self, _config: RuntimeConfigData) -> Result<(), String> {
        Ok(())
    }

    fn set_log_level(&mut self, directives: &str) -> Result<String, String> {
        Ok(directives.to_string())
    }
}

impl AuthorityDataProvider for NodeMock {
    // Not a provider: every certificate-authority operation refuses, the same
    // way a real member node's does.
    fn get_trust_anchor(&self) -> Result<Vec<u8>, String> {
        Err("not a provider".to_string())
    }
    fn submit_csr(
        &mut self,
        _node_mac: &[u8],
        _ed_pubkey: &[u8],
        _x_pubkey: &[u8],
        _enrollment_token: &str,
    ) -> Result<CsrOutcome, String> {
        Err("not a provider".to_string())
    }
    fn revoke_node(&mut self, _node_mac: &[u8]) -> Result<(), String> {
        Err("not a provider".to_string())
    }
    fn list_certs(&self) -> Result<Vec<IssuedCertData>, String> {
        Err("not a provider".to_string())
    }
    fn list_pending_csrs(&self) -> Result<Vec<PendingCsrData>, String> {
        Err("not a provider".to_string())
    }
    fn approve_csr(&mut self, _node_mac: &[u8]) -> Result<(), String> {
        Err("not a provider".to_string())
    }
    fn deny_csr(&mut self, _node_mac: &[u8]) -> Result<(), String> {
        Err("not a provider".to_string())
    }
}

/// Spawn an un-enrolled member node and return an [`Endpoint`] reaching it plus
/// the handle recording its `SetAuth` calls.
///
/// The node has an identity but no trust anchor, so `decide_access` admits the
/// client on the self-key path — the bootstrap posture these two commands exist
/// to serve.
async fn spawn_node(has_identity: bool) -> (Endpoint, Arc<Mutex<Vec<SetAuthCall>>>) {
    let seed = [9u8; 32];
    let node_key = Keypair::from_seed(&seed).ed_pubkey();
    let calls: Arc<Mutex<Vec<SetAuthCall>>> = Arc::new(Mutex::new(Vec::new()));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (query_tx, mut query_rx) =
        mpsc::channel::<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>(16);
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
    let (authority_tx, mut authority_rx) =
        tokio::sync::mpsc::channel::<wayfinder_server::AuthorityCommand>(8);
    tokio::spawn(async move {
        let _ = wayfinder_server::serve_tls_server_with_vpn(
            listener,
            seed,
            snapshot_tx,
            query_tx,
            wayfinder_server::ServerServices {
                authority_tx: Some(authority_tx),
                // No shared read handle: this harness has no driver behind
                // the listener, so reads travel the query channel as they
                // always did.
                ..Default::default()
            },
        )
        .await;
    });
    let provider_calls = Arc::clone(&calls);
    tokio::spawn(async move {
        let mut provider = NodeMock {
            keypair: Keypair::from_seed(&seed),
            has_identity,
            is_provider: false,
            set_auth_calls: provider_calls,
        };
        loop {
            tokio::select! {
                Some((req, resp_tx)) = query_rx.recv() => {
                    let resp = wayfinder_protos::service::handle_router(&mut provider, req)
                        .unwrap_or_else(|_| wayfinder_server::not_a_provider_response());
                    let _ = resp_tx.send(resp);
                }
                Some(command) = authority_rx.recv() => match command {
                    wayfinder_server::AuthorityCommand::Request(req, reply) => {
                        let resp = wayfinder_protos::service::handle_authority(&mut provider, req)
                            .unwrap_or_else(|_| wayfinder_server::not_a_provider_response());
                        let _ = reply.send(resp);
                    }
                    wayfinder_server::AuthorityCommand::SetEnrollmentPolicy(_, reply) => {
                        let _ = reply.send(Ok(()));
                    }
                },
                else => break,
            }
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    (
        Endpoint {
            addr: addr.into(),
            node_key,
            identity: Identity {
                seed,
                cert: Vec::new(),
            },
        },
        calls,
    )
}

/// Spawn a node that reports itself as a provider — the wrong end of the
/// enrollment workflow for `csr request`/`csr install` to be pointed at.
async fn spawn_provider_node() -> Endpoint {
    let seed = [11u8; 32];
    let node_key = Keypair::from_seed(&seed).ed_pubkey();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (query_tx, mut query_rx) =
        mpsc::channel::<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>(16);
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
    let (authority_tx, mut authority_rx) =
        tokio::sync::mpsc::channel::<wayfinder_server::AuthorityCommand>(8);
    tokio::spawn(async move {
        let _ = wayfinder_server::serve_tls_server_with_vpn(
            listener,
            seed,
            snapshot_tx,
            query_tx,
            wayfinder_server::ServerServices {
                authority_tx: Some(authority_tx),
                // No shared read handle: this harness has no driver behind
                // the listener, so reads travel the query channel as they
                // always did.
                ..Default::default()
            },
        )
        .await;
    });
    tokio::spawn(async move {
        let mut provider = NodeMock {
            keypair: Keypair::from_seed(&seed),
            has_identity: true,
            is_provider: true,
            set_auth_calls: Arc::new(Mutex::new(Vec::new())),
        };
        loop {
            tokio::select! {
                Some((req, resp_tx)) = query_rx.recv() => {
                    let resp = wayfinder_protos::service::handle_router(&mut provider, req)
                        .unwrap_or_else(|_| wayfinder_server::not_a_provider_response());
                    let _ = resp_tx.send(resp);
                }
                Some(command) = authority_rx.recv() => match command {
                    wayfinder_server::AuthorityCommand::Request(req, reply) => {
                        let resp = wayfinder_protos::service::handle_authority(&mut provider, req)
                            .unwrap_or_else(|_| wayfinder_server::not_a_provider_response());
                        let _ = reply.send(resp);
                    }
                    wayfinder_server::AuthorityCommand::SetEnrollmentPolicy(_, reply) => {
                        let _ = reply.send(Ok(()));
                    }
                },
                else => break,
            }
        }
    });
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

/// `csr request` builds the request out of what the *node* reports, so the
/// operator never has to hold — or even see — the node's identity seed.
///
/// The three fields it writes are exactly the three a `SubmitCsrRequest`
/// carries, so the file it produces is the same one `cert approve` already
/// signs; only where the keys came from has changed.
#[tokio::test]
async fn csr_request_names_the_identity_the_node_reports() {
    let (endpoint, _calls) = spawn_node(true).await;
    let dir = tempfile::tempdir().unwrap();
    let out_request = dir.path().join("request.json");

    run_query(
        Command::Csr(CsrCommand::Request {
            out_request: out_request.clone(),
            token: String::new(),
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .unwrap();

    let node = Keypair::from_seed(&[9u8; 32]);
    let req: SubmitCsrRequest =
        serde_json::from_slice(&std::fs::read(&out_request).unwrap()).unwrap();

    assert_eq!(req.ed_pubkey, node.ed_pubkey().to_vec());
    assert_eq!(req.x_pubkey, node.x_pubkey().to_vec());
    assert_eq!(
        req.node_mac,
        node.derived_mac().0.to_vec(),
        "the MAC must be the one the node reports itself running under, not one \
         the operator guessed — a certificate naming any other MAC is one the \
         node refuses to install"
    );
}

/// The enrollment token is the operator's to supply: it is a shared secret the
/// *provider* checks, and the node being enrolled has no idea what it is. So it
/// comes from the flag, not from the node.
#[tokio::test]
async fn csr_request_carries_the_operator_supplied_enrollment_token() {
    let (endpoint, _calls) = spawn_node(true).await;
    let dir = tempfile::tempdir().unwrap();
    let out_request = dir.path().join("request.json");

    run_query(
        Command::Csr(CsrCommand::Request {
            out_request: out_request.clone(),
            token: "let-me-in".to_string(),
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .unwrap();

    let req: SubmitCsrRequest =
        serde_json::from_slice(&std::fs::read(&out_request).unwrap()).unwrap();
    assert_eq!(req.enrollment_token, "let-me-in");
}

/// A node with no identity at all has nothing to certify. Writing a CSR with
/// empty public keys would produce a file the CA would happily sign into a
/// certificate bound to nothing — so this must fail at the point the emptiness
/// is observed, not several steps later.
#[tokio::test]
async fn csr_request_refuses_a_node_that_reports_no_identity() {
    let (endpoint, _calls) = spawn_node(false).await;
    let dir = tempfile::tempdir().unwrap();
    let out_request = dir.path().join("request.json");

    let err = run_query(
        Command::Csr(CsrCommand::Request {
            out_request: out_request.clone(),
            token: String::new(),
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .unwrap_err();

    assert!(
        err.to_string().contains("no identity"),
        "expected an error naming the missing identity, got: {err}"
    );
    assert!(
        !out_request.exists(),
        "a refused request must leave no half-written CSR behind for the \
         operator to carry to the CA"
    );
}

/// `csr request` asks the node being *enrolled* to describe itself — pointed
/// at a provider instead (an easy mistake in an unfamiliar out-of-band
/// procedure), it must refuse rather than silently mint a CSR for the
/// provider's own identity, a file that would look fine and install cleanly
/// onto the wrong node.
#[tokio::test]
async fn csr_request_refuses_a_provider_endpoint() {
    let endpoint = spawn_provider_node().await;
    let dir = tempfile::tempdir().unwrap();
    let out_request = dir.path().join("request.json");

    let err = run_query(
        Command::Csr(CsrCommand::Request {
            out_request: out_request.clone(),
            token: String::new(),
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .unwrap_err();

    assert!(
        err.to_string().contains("provider"),
        "expected an error naming the provider mismatch, got: {err}"
    );
    assert!(
        !out_request.exists(),
        "a refused request must leave no half-written CSR behind"
    );
}

/// `csr install` hands the signed result back over the wire, as the
/// certify-in-place shape: an **empty** seed, meaning "certify the identity I
/// already have".
///
/// The empty seed is the load-bearing part. Sending the node a new identity
/// while it runs leaves it signing frames under a certificate bound to a MAC
/// its peers do not know it by, until it restarts — so an install that reaches
/// a node whose seed the operator never held must never be able to replace it.
#[tokio::test]
async fn csr_install_certifies_the_identity_the_node_already_holds() {
    let (endpoint, calls) = spawn_node(true).await;
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, anchor_path) = issue_for_node(dir.path(), &Keypair::from_seed(&[9u8; 32]));

    run_query(
        Command::Csr(CsrCommand::Install {
            cert: cert_path.clone(),
            trust_anchor: anchor_path.clone(),
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "expected exactly one SetAuth");
    assert_eq!(
        calls[0].seed,
        Vec::<u8>::new(),
        "an install must certify the node's existing identity, never replace it"
    );
    assert_eq!(calls[0].cert, std::fs::read(&cert_path).unwrap());
    assert_eq!(calls[0].trust_anchor, std::fs::read(&anchor_path).unwrap());
}

/// `auth set` is the same `SetAuth` with the opposite intent: it carries a
/// **non-empty** seed, replacing the node's identity outright.
///
/// This is the pair to `csr_install_certifies_the_identity_the_node_already_holds`
/// above, and the two together are what keep the distinction real. One command
/// re-identifies a node and one cannot, and the difference is visible on the
/// wire as the seed field rather than only in the documentation.
#[tokio::test]
async fn auth_set_replaces_the_nodes_identity() {
    let (endpoint, calls) = spawn_node(true).await;
    let dir = tempfile::tempdir().unwrap();
    let node = Keypair::from_seed(&[9u8; 32]);
    let (cert_path, anchor_path) = issue_for_node(dir.path(), &node);
    let seed_path = dir.path().join("new.seed");
    std::fs::write(&seed_path, [7u8; 32]).unwrap();

    run_query(
        Command::Auth(AuthCommand::Set {
            seed: seed_path,
            cert: cert_path.clone(),
            trust_anchor: anchor_path.clone(),
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "expected exactly one SetAuth");
    assert_eq!(
        calls[0].seed,
        vec![7u8; 32],
        "auth set must carry the new identity seed"
    );
    assert_eq!(calls[0].cert, std::fs::read(&cert_path).unwrap());
    assert_eq!(calls[0].trust_anchor, std::fs::read(&anchor_path).unwrap());
}

/// A cross-mesh certificate and anchor are refused before anything is sent.
///
/// `auth set` gained this pre-flight when it moved; the check is shared with
/// `csr install` through `cert::read_credential`, and this pins that `auth set`
/// actually calls it. A pair that reached the node would leave it unable to
/// verify its own certificate.
#[tokio::test]
async fn auth_set_refuses_a_cross_mesh_pair_without_transmitting() {
    let (endpoint, calls) = spawn_node(true).await;
    let dir = tempfile::tempdir().unwrap();
    let node = Keypair::from_seed(&[9u8; 32]);
    let (cert_path, _) = issue_for_node(dir.path(), &node);
    // An anchor from a different mesh entirely, well-formed on its own.
    let other = wayfinder_auth::Authority::from_seed(&[2u8; 32], 0xBEEF);
    let anchor_path = dir.path().join("other.anchor");
    std::fs::write(&anchor_path, other.trust_anchor().to_bytes()).unwrap();
    let seed_path = dir.path().join("new.seed");
    std::fs::write(&seed_path, [7u8; 32]).unwrap();

    let err = run_query(
        Command::Auth(AuthCommand::Set {
            seed: seed_path,
            cert: cert_path,
            trust_anchor: anchor_path,
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .unwrap_err();

    assert!(err.to_string().contains("mesh_id"), "got: {err}");
    assert!(
        calls.lock().unwrap().is_empty(),
        "a refused pair must never reach the node"
    );
}

/// A seed that is not 32 bytes is refused locally rather than installed.
///
/// The seed is the node's private key; a truncated one is a node that cannot
/// sign. It is also the one input to `auth set` whose contents are otherwise
/// unexaminable, so nothing downstream would catch this in a way an operator
/// could act on.
#[tokio::test]
async fn auth_set_refuses_a_short_seed() {
    let (endpoint, calls) = spawn_node(true).await;
    let dir = tempfile::tempdir().unwrap();
    let node = Keypair::from_seed(&[9u8; 32]);
    let (cert_path, anchor_path) = issue_for_node(dir.path(), &node);
    let seed_path = dir.path().join("short.seed");
    std::fs::write(&seed_path, [7u8; 12]).unwrap();

    let err = run_query(
        Command::Auth(AuthCommand::Set {
            seed: seed_path,
            cert: cert_path,
            trust_anchor: anchor_path,
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .unwrap_err();

    assert!(err.to_string().contains("32 bytes"), "got: {err}");
    assert!(
        calls.lock().unwrap().is_empty(),
        "a refused seed must never reach the node"
    );
}

/// The workflow end to end, from an operator who never holds the node's seed:
/// ask the node what to certify, take that file to an offline CA, hand the
/// signed result back to the node.
///
/// The assertion that matters is the last one — the certificate the node is
/// handed verifies against the anchor and names the node's *own* key. That is
/// what `RouterAdapter::set_auth` checks before accepting an install, so a
/// round trip that got any step wrong is refused by a real node.
#[tokio::test]
async fn an_operator_without_the_seed_can_enroll_a_node_offline() {
    let (endpoint, calls) = spawn_node(true).await;
    let dir = tempfile::tempdir().unwrap();
    let out_request = dir.path().join("request.json");
    let ca_seed = dir.path().join("root.seed");
    let anchor_path = dir.path().join("anchor.bin");
    let cert_path = dir.path().join("node.cert");

    // 1. Ask the node for its CSR.
    run_query(
        Command::Csr(CsrCommand::Request {
            out_request: out_request.clone(),
            token: String::new(),
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .unwrap();

    // 2. Sign it on the offline CA host, which never sees the node.
    cert::run(CertCommand::InitCa {
        mesh_id: 0xABCD,
        seed: None,
        generate: true,
        out_seed: Some(ca_seed.clone()),
        out_anchor: anchor_path.clone(),
    })
    .unwrap();
    cert::run(CertCommand::Approve {
        ca_seed: ca_seed.clone(),
        mesh_id: 0xABCD,
        request: out_request.clone(),
        not_before: 0,
        not_after: 1_000_000_000,
        out_cert: cert_path.clone(),
        admin: false,
        viewer: false,
    })
    .unwrap();

    // 3. Hand the result back to the node.
    run_query(
        Command::Csr(CsrCommand::Install {
            cert: cert_path.clone(),
            trust_anchor: anchor_path.clone(),
        }),
        &endpoint,
        OutputFormat::Human,
    )
    .await
    .unwrap();

    let calls = calls.lock().unwrap();
    let installed = MembershipCert::from_bytes(&calls[0].cert).unwrap();
    let anchor = TrustAnchor::from_bytes(&calls[0].trust_anchor).unwrap();
    let verified = anchor
        .verify_cert(&installed, 500)
        .expect("the certificate the node is handed must verify against the anchor beside it");

    let node = Keypair::from_seed(&[9u8; 32]);
    assert_eq!(
        verified.ed_pubkey,
        node.ed_pubkey(),
        "the certificate must name the key the node actually signs with"
    );
    assert_eq!(verified.mac, node.derived_mac());
}

/// Issue a certificate and trust anchor for `node` through the offline CA
/// tooling, returning the (cert, anchor) paths.
fn issue_for_node(
    dir: &std::path::Path,
    node: &Keypair,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let ca_seed = dir.join("issue-root.seed");
    let anchor = dir.join("issue-anchor.bin");
    let cert = dir.join("issue-node.cert");
    let request = dir.join("issue-request.json");

    cert::run(CertCommand::InitCa {
        mesh_id: 0xABCD,
        seed: None,
        generate: true,
        out_seed: Some(ca_seed.clone()),
        out_anchor: anchor.clone(),
    })
    .unwrap();
    let req = SubmitCsrRequest {
        node_mac: node.derived_mac().0.to_vec(),
        ed_pubkey: node.ed_pubkey().to_vec(),
        x_pubkey: node.x_pubkey().to_vec(),
        enrollment_token: String::new(),
    };
    std::fs::write(&request, serde_json::to_vec(&req).unwrap()).unwrap();
    cert::run(CertCommand::Approve {
        ca_seed,
        mesh_id: 0xABCD,
        request,
        not_before: 0,
        not_after: 1_000_000_000,
        out_cert: cert.clone(),
        admin: false,
        viewer: false,
    })
    .unwrap();

    (cert, anchor)
}
