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
use wayfinder_protos::service::EnrollmentPolicyStatusData;
use wayfinder_protos::service::InterfaceThroughputData;
use wayfinder_protos::service::KeepAliveEntryData;
use wayfinder_protos::service::LinkFeaturesEntryData;
use wayfinder_protos::service::LinkQualityEntryData;
use wayfinder_protos::service::LogLevelData;
use wayfinder_protos::service::LogRecordData;
use wayfinder_protos::service::LogsData;
use wayfinder_protos::service::NeighborPathData;
use wayfinder_protos::service::NodeMetricsData;
use wayfinder_protos::service::NodeSecurityData;
use wayfinder_protos::service::OgmScheduleEntryData;
use wayfinder_protos::service::PendingCsrData;
use wayfinder_protos::service::RouteResolutionData;
use wayfinder_protos::service::RoutingEntryData;
use wayfinder_protos::service::RuntimeConfigData;
use wayfinder_protos::service::SecurityStatusData;
use wayfinder_protos::service::TableOccupancyData;
use wayfinder_protos::service::TokenUpdate;
use wayfinder_protos::service::WayfinderDataProvider;
use wayfinder_protos::service::WayfinderService;
use wayfinder_protos::wayfinder::v1alpha::WayfinderRequest;
use wayfinder_protos::wayfinder::v1alpha::WayfinderResponse;
use wayfinder_server::MeshAuthority;

/// The mock node's own Ed25519 identity key, as reported by
/// `GetSecurityStatus`.
///
/// A distinguishable constant rather than zeroes: what a client enrolling this
/// node sends in its CSR is precisely these bytes, so a test can assert the
/// request named the *node's* keys and not something invented along the way.
const MOCK_ED_PUBKEY: [u8; 32] = [0x11; 32];

/// The mock node's own X25519 key; see [`MOCK_ED_PUBKEY`].
const MOCK_X_PUBKEY: [u8; 32] = [0x22; 32];

/// The mesh root seed of [`Mock::authority`]. A test fixture, never a real key.
const MESH_ROOT_SEED: [u8; 32] = [0x33; 32];

/// The mesh id [`Mock::authority`] certifies for.
pub const MOCK_MESH_ID: u32 = 0xBEEF;

/// The enrollment token [`Mock::provider`] requires.
///
/// Distinctive on purpose: the provider panel copies this value without ever
/// rendering it, so a test asserts on its *absence* from the markup. A token of
/// "token" would match too much to prove anything.
pub const MOCK_ENROLLMENT_TOKEN: &str = "mock-join-secret-9f3a";

/// A provider with one originator, one link-quality row and one interface, so
/// every field a snapshot reads has a distinguishable value to land in.
///
/// Stateful only where the dashboard *writes*: a security setting changed here
/// is remembered and reported back, so the Security tab can be developed
/// against the same read-your-write behavior a real node has. Everything the
/// dashboard only reads stays canned.
pub struct Mock {
    /// The security posture and enrollment policy, as changed through
    /// `SetConfig`.
    security: SecurityStatusData,
    /// The CSR queue, present only on the provider flavor. `None` makes the
    /// enrollment RPCs error, the way they do on a plain member.
    ///
    /// Kept in step with `security.enrollment`, because on a real node the two
    /// come from the same fact: a node either is a certificate authority — with
    /// a policy *and* a queue — or is not, and a mock that reported a policy
    /// while refusing to list requests would let the dashboard get the
    /// combination wrong without any test noticing.
    pending_csrs: Option<Vec<PendingCsrData>>,
    /// The shared enrollment token, kept beside the status rather than on it —
    /// the polled status says only whether one is set, and this is what
    /// `reveal_enrollment_token` hands over when asked.
    enrollment_token: Option<String>,
    /// A real certificate authority, on the flavor that has one
    /// ([`Mock::authority`]).
    ///
    /// The canned `pending_csrs` above are enough to *render* a provider, but
    /// not to be one: enrollment is a conversation — submit, park, approve,
    /// collect — and a canned answer cannot hold state across it. So the flavor
    /// that an enrolling node talks to runs the production `CertAuthority` and
    /// really signs.
    ca: Option<wayfinder_server::CertAuthority>,
}

impl Default for Mock {
    /// A plain member: authenticated, but no certificate authority.
    fn default() -> Self {
        Self {
            security: SecurityStatusData {
                auth_enabled: true,
                mesh_id: 0xABCD,
                node_mac: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
                cert_not_after: 1_800_000_000,
                revocation_count: 0,
                nodes: vec![NodeSecurityData {
                    node_id: vec![0, 0, 0, 0, 0, 2],
                    verified: true,
                    cert_not_after: 1_800_000_000,
                    revoked: false,
                }],
                require_auth: true,
                lazy_cert_distribution: false,
                enrollment: None,
                own_ed_pubkey: MOCK_ED_PUBKEY.to_vec(),
                own_x_pubkey: MOCK_X_PUBKEY.to_vec(),
            },
            enrollment_token: None,
            pending_csrs: None,
            ca: None,
        }
    }
}

impl Mock {
    /// A node with mesh authentication switched off.
    ///
    /// Mirrors exactly what `RouterAdapter::security_status` reports when the
    /// router has no `OgmAuth`: the posture flags stand, and every field that
    /// describes an identity is left at its default — an *empty* `node_mac`,
    /// a zero mesh id, and no per-node rows at all. The emptiness is the point:
    /// the Security tab's other flavors all have an identity to render, so this
    /// is the only one that exercises the fields being absent.
    pub fn unauthenticated() -> Self {
        Self {
            security: SecurityStatusData {
                auth_enabled: false,
                mesh_id: 0,
                node_mac: Vec::new(),
                cert_not_after: 0,
                revocation_count: 0,
                nodes: Vec::new(),
                require_auth: false,
                lazy_cert_distribution: false,
                enrollment: None,
                // An un-enrolled node still has an identity of its own — that
                // is exactly what it asks a provider to certify — so this is
                // populated even though every other identity field is empty.
                own_ed_pubkey: MOCK_ED_PUBKEY.to_vec(),
                own_x_pubkey: MOCK_X_PUBKEY.to_vec(),
            },
            enrollment_token: None,
            pending_csrs: None,
            ca: None,
        }
    }

    /// A certificate authority: an enrollment policy with a token and hand
    /// approval, and one request waiting.
    ///
    /// The configuration with the most for an operator to look at, so every
    /// control on the Security tab has something real to act on.
    pub fn provider() -> Self {
        Self {
            security: SecurityStatusData {
                enrollment: Some(EnrollmentPolicyStatusData {
                    auto_approve: false,
                    cert_ttl_secs: 86_400,
                    enrollment_token_set: true,
                }),
                ..Self::default().security
            },
            enrollment_token: Some(MOCK_ENROLLMENT_TOKEN.to_string()),
            pending_csrs: Some(vec![PendingCsrData {
                node_mac: vec![0, 0, 0, 0, 0, 9],
                ed_pubkey: vec![0xab; 32],
                x_pubkey: vec![0xcd; 32],
                requested_at: 1_700_000_000,
            }]),
            ca: None,
        }
    }

    /// A certificate authority that really issues: the flavor an enrolling node
    /// is pointed at.
    ///
    /// `auto_approve` chooses which of the two enrollment paths it serves —
    /// signing on submission, or parking the request until an operator says
    /// yes. `token`, when set, is the enrollment token `submit_csr` requires
    /// before it will consider a request at all — the primary admission
    /// control for the whole feature.
    pub fn authority(auto_approve: bool, token: Option<&str>) -> Self {
        let mut ca = wayfinder_server::CertAuthority::new(
            &MESH_ROOT_SEED,
            MOCK_MESH_ID,
            86_400,
            token.map(str::to_string),
            auto_approve,
        );
        ca.set_now_unix(1_700_000_000);
        Self {
            security: SecurityStatusData {
                enrollment: Some(EnrollmentPolicyStatusData {
                    auto_approve,
                    cert_ttl_secs: 86_400,
                    enrollment_token_set: token.is_some(),
                }),
                ..Self::default().security
            },
            enrollment_token: token.map(str::to_string),
            pending_csrs: None,
            ca: Some(ca),
        }
    }
}

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
    fn security_status(&self) -> SecurityStatusData {
        self.security.clone()
    }
    fn reveal_enrollment_token(
        &self,
    ) -> Result<wayfinder_protos::service::EnrollmentAdmission, String> {
        use wayfinder_protos::service::EnrollmentAdmission;
        use wayfinder_protos::service::SharedSecret;

        if self.security.enrollment.is_none() {
            return Err("node is not a certificate-authority provider".to_string());
        }
        Ok(match &self.enrollment_token {
            Some(token) => EnrollmentAdmission::Token(SharedSecret::new(token.clone())),
            None => EnrollmentAdmission::Open,
        })
    }
    fn set_config(&mut self, config: RuntimeConfigData) -> Result<(), String> {
        // Applied to the reported status, so the dashboard's next poll shows
        // the change — a mock that accepted every write and reported the same
        // state forever would make a broken control look like a working one.
        if let Some(require_auth) = config.require_auth {
            self.security.require_auth = require_auth;
        }
        if let Some(lazy) = config.lazy_cert_distribution {
            self.security.lazy_cert_distribution = lazy;
        }
        if let Some(update) = &config.enrollment {
            let policy = self
                .security
                .enrollment
                .as_mut()
                .ok_or_else(|| "node is not a certificate-authority provider".to_string())?;
            if let Some(auto_approve) = update.auto_approve {
                policy.auto_approve = auto_approve;
            }
            if let Some(ttl) = update.cert_ttl_secs {
                policy.cert_ttl_secs = ttl;
            }
            // Both halves move together, as they do on a real node where they
            // are two projections of one `Option<String>` — a mock that set the
            // flag without storing the value would let the dashboard read a
            // token back that a real node would never have reported.
            // The flag and the value move together, as they do on a real node
            // where both come from one `Option<SharedSecret>` — but they travel
            // separately: the polled status says only that a token is set, and
            // the value is handed out by `reveal_enrollment_token`.
            match &update.enrollment_token {
                Some(TokenUpdate::Clear) => {
                    policy.enrollment_token_set = false;
                    self.enrollment_token = None;
                }
                Some(TokenUpdate::Set(token)) => {
                    policy.enrollment_token_set = true;
                    self.enrollment_token = Some(token.expose().to_string());
                }
                None => {}
            }
        }
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
        match &self.ca {
            Some(ca) => Ok(ca.trust_anchor_bytes()),
            None => Ok(vec![0xab; 36]),
        }
    }
    fn list_pending_csrs(&self) -> Result<Vec<PendingCsrData>, String> {
        if let Some(ca) = &self.ca {
            return Ok(ca.list_pending());
        }
        self.pending_csrs
            .clone()
            .ok_or_else(|| "node is not a certificate-authority provider".to_string())
    }
    fn submit_csr(
        &mut self,
        node_mac: &[u8],
        ed_pubkey: &[u8],
        x_pubkey: &[u8],
        enrollment_token: &str,
    ) -> Result<wayfinder_protos::service::CsrOutcome, String> {
        self.ca
            .as_mut()
            .ok_or_else(|| "node is not a certificate-authority provider".to_string())?
            .submit_csr(node_mac, ed_pubkey, x_pubkey, enrollment_token)
    }
    fn approve_csr(&mut self, node_mac: &[u8]) -> Result<(), String> {
        self.ca
            .as_mut()
            .ok_or_else(|| "node is not a certificate-authority provider".to_string())?
            .approve_csr(node_mac)
    }
    /// Install a certificate, the way a node does when it is enrolled.
    ///
    /// An empty seed means the node keeps the identity it has, so the reported
    /// keys are left alone; a seed that *is* supplied replaces them, exactly as
    /// a real node's would be re-derived. Reporting that faithfully is the
    /// point — it is how a test can tell which of the two happened.
    fn set_auth(&mut self, seed: &[u8], cert: &[u8], trust_anchor: &[u8]) -> Result<(), String> {
        let anchor = wayfinder_auth::TrustAnchor::from_bytes(trust_anchor)
            .ok_or_else(|| "unable to parse trust anchor".to_string())?;
        let cert = wayfinder_auth::MembershipCert::from_bytes(cert)
            .ok_or_else(|| "unable to parse membership cert".to_string())?;
        if !seed.is_empty() {
            let seed: [u8; 32] = seed
                .try_into()
                .map_err(|_| "seed must be exactly 32 bytes".to_string())?;
            let kp = wayfinder_auth::Keypair::from_seed(&seed);
            self.security.own_ed_pubkey = kp.ed_pubkey().to_vec();
            self.security.own_x_pubkey = kp.x_pubkey().to_vec();
        }
        self.security.auth_enabled = true;
        self.security.mesh_id = anchor.mesh_id;
        self.security.node_mac = cert.node_mac.to_vec();
        self.security.cert_not_after = cert.not_after.get();
        Ok(())
    }
}

/// Grab an almost-certainly-free localhost port by binding to :0 and releasing.
pub fn free_port() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

/// Start a TLS management server backed by a plain-member [`Mock`] on an
/// ephemeral port.
///
/// Returns the address it bound and the node's Ed25519 public key, which a
/// client pins. Authentication is bootstrap-style: a client presents the node's
/// own seed, [`NODE_SEED`].
pub async fn serve_mock_node() -> (SocketAddr, [u8; 32]) {
    serve_mock_node_with(Mock::default()).await
}

/// As [`serve_mock_node`], but backed by a certificate-authority [`Mock`]: the
/// flavor with an enrollment policy and a CSR queue.
pub async fn serve_mock_provider_node() -> (SocketAddr, [u8; 32]) {
    serve_mock_node_with(Mock::provider()).await
}

/// Start a TLS management server backed by the given [`Mock`].
pub async fn serve_mock_node_with(mock: Mock) -> (SocketAddr, [u8; 32]) {
    let ck = wayfinder_tls_mgmt::certified_key_from_seed(&NODE_SEED).unwrap();
    let node_key = wayfinder_tls_mgmt::raw_ed25519_from_spki(ck.cert[0].as_ref()).unwrap();

    let (query_tx, mut query_rx) =
        mpsc::channel::<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>(16);
    tokio::spawn(async move {
        let mut service = WayfinderService::new(mock);
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
                own_key: Some(node_key),
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
