//! A provider node in-process: a real `CertAuthority` behind the management
//! API, reachable over real TLS on a loopback port.
//!
//! Shared by the integration tests that need one — `enroll.rs` drives the
//! enrollment path against it, `user.rs` the account lifecycle — rather than
//! duplicated per test binary, because the two need the *same* provider: an
//! authority whose user store starts empty and whose mutations flood
//! revocations the way a real node's does.
//!
//! The mutating account requests go through a real [`AuthorityAdapter`], not
//! straight to the authority. That is the layer holding the last-administrator
//! guard and the flood gate, and a mock that reached past it would test a path
//! no node runs. What it signs is kept in [`ProviderMock::flooded`] for a test
//! to assert on, standing in for the router hop that would announce it.

#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use wayfinder_auth::Keypair;
use wayfinder_auth::RevocationRecord;
use wayfinder_auth::TrustAnchor;
use wayfinder_client::Identity;
use wayfinder_protos::service::AlarmsData;
use wayfinder_protos::service::AuthorityDataProvider;
use wayfinder_protos::service::CsrOutcome;
use wayfinder_protos::service::InterfaceThroughputData;
use wayfinder_protos::service::IssuedCertData;
use wayfinder_protos::service::KeepAliveEntryData;
use wayfinder_protos::service::LinkFeaturesEntryData;
use wayfinder_protos::service::LinkQualityEntryData;
use wayfinder_protos::service::LogsData;
use wayfinder_protos::service::NodeMetricsData;
use wayfinder_protos::service::OgmScheduleEntryData;
use wayfinder_protos::service::PendingCsrData;
use wayfinder_protos::service::PingSessionData;
use wayfinder_protos::service::PingStartData;
use wayfinder_protos::service::RegistrationStartedData;
use wayfinder_protos::service::RouteResolutionData;
use wayfinder_protos::service::RouterReads;
use wayfinder_protos::service::RouterWrites;
use wayfinder_protos::service::RoutingEntryData;
use wayfinder_protos::service::RuntimeConfigData;
use wayfinder_protos::service::TableOccupancyData;
use wayfinder_protos::service::UserAccountData;
use wayfinder_protos::service::UserAuthOutcome;
use wayfinder_protos::service::UserInviteData;
use wayfinder_protos::service::UserInviteMintedData;
use wayfinder_protos::wayfinder::v1alpha::WayfinderRequest;
use wayfinder_protos::wayfinder::v1alpha::WayfinderResponse;
use wayfinder_server::AuthSnapshot;
use wayfinder_server::AuthorityAdapter;
use wayfinder_server::AuthorityComms;
use wayfinder_server::CertAuthority;
use wayfinder_server::MeshAuthority;
use wayfinder_server::RouterFacts;
use wayfinder_server::RouterFactsRx;
use wayfinderctl::Endpoint;

/// A provider node: a real certificate authority behind the data-provider trait.
/// Only the provider methods carry behaviour; the rest are trivial.
pub struct ProviderMock {
    /// The real authority behind the mock, so a test can read the state its
    /// requests produced.
    pub ca: CertAuthority,
    /// What the router beside this authority publishes about itself — the live
    /// receiver a real `AuthorityAdapter` reads, seeded with `auth_present` so
    /// the flood gate lets a revocation through.
    facts: RouterFactsRx,
    /// Everything the adapter signed, standing in for the router hop that would
    /// flood it. Kept rather than dropped because dropping a signed revocation
    /// is the failure `AuthorityAdapter::finish` is `#[must_use]` about.
    pub flooded: Vec<RevocationRecord>,
}

impl ProviderMock {
    /// Serve one mutating account request through a real [`AuthorityAdapter`],
    /// keeping whatever it signed.
    fn adapted<T>(
        &mut self,
        f: impl FnOnce(&mut AuthorityAdapter<'_>) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut adapter = AuthorityAdapter::new(&mut self.ca, self.facts.clone());
        let out = f(&mut adapter);
        self.flooded.extend(adapter.finish());
        out
    }
}

/// An empty occupancy gauge, for the router projections this mock does not
/// model.
pub fn occ() -> TableOccupancyData {
    TableOccupancyData {
        used: 0,
        capacity: 0,
    }
}

impl RouterReads for ProviderMock {
    fn node_id(&self) -> Vec<u8> {
        vec![0, 0, 0, 0, 0, 1]
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

    /// Log access is served from a process-wide ring rather than from router
    /// state, so this stub reports an empty one — these tests exercise the
    /// transport and the query commands, not the log path (covered in
    /// `wayfinder-log` and `RouterAdapter`).
    fn alarms(&self) -> AlarmsData {
        // Nothing wrong: an empty board is the node's "all systems normal", and
        // none of these cases is about alarms.
        AlarmsData::default()
    }

    fn logs(&self, _since_seq: u64, _max_records: u32) -> LogsData {
        LogsData::default()
    }
}

impl RouterWrites for ProviderMock {
    fn set_auth(&mut self, _seed: &[u8], _cert: &[u8], _trust_anchor: &[u8]) -> Result<(), String> {
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

impl AuthorityDataProvider for ProviderMock {
    fn get_trust_anchor(&self) -> Result<Vec<u8>, String> {
        Ok(self.ca.trust_anchor_bytes())
    }
    fn submit_csr(
        &mut self,
        node_mac: &[u8],
        ed_pubkey: &[u8],
        x_pubkey: &[u8],
        enrollment_token: &str,
    ) -> Result<CsrOutcome, String> {
        self.ca
            .submit_csr(node_mac, ed_pubkey, x_pubkey, enrollment_token)
    }
    fn revoke_node(&mut self, node_mac: &[u8]) -> Result<(), String> {
        self.ca.revoke(node_mac).map(|_| ())
    }
    fn list_certs(&self) -> Result<Vec<IssuedCertData>, String> {
        Ok(self.ca.list_certs())
    }
    fn list_pending_csrs(&self) -> Result<Vec<PendingCsrData>, String> {
        Ok(self.ca.list_pending())
    }
    fn approve_csr(&mut self, node_mac: &[u8]) -> Result<(), String> {
        self.ca.approve_csr(node_mac)
    }
    fn deny_csr(&mut self, node_mac: &[u8]) -> Result<(), String> {
        self.ca.deny_csr(node_mac)
    }

    // ── the account lifecycle ────────────────────────────────────────────────
    //
    // Every mutation goes through `adapted`, so these tests exercise the guards
    // and the flood gate a real node applies rather than the raw store beneath
    // them.

    fn authenticate_user(
        &mut self,
        username: &str,
        password: &str,
        totp_code: &str,
        ed_pubkey: &[u8],
        x_pubkey: &[u8],
    ) -> Result<UserAuthOutcome, String> {
        self.ca
            .authenticate_user(username, password, totp_code, ed_pubkey, x_pubkey)
    }
    fn list_users(&self) -> Result<Vec<UserAccountData>, String> {
        Ok(MeshAuthority::list_users(&self.ca))
    }
    fn create_user(
        &mut self,
        username: &str,
        password: &str,
        admin: bool,
        session_ttl_secs: u64,
        no_totp: bool,
    ) -> Result<String, String> {
        self.adapted(|a| a.create_user(username, password, admin, session_ttl_secs, no_totp))
    }
    fn remove_user(&mut self, username: &str) -> Result<(), String> {
        self.adapted(|a| a.remove_user(username))
    }
    fn set_user_role(&mut self, username: &str, admin: bool) -> Result<(u32, bool), String> {
        self.adapted(|a| a.set_user_role(username, admin))
    }
    fn set_user_enabled(&mut self, username: &str, enabled: bool) -> Result<(u32, bool), String> {
        self.adapted(|a| a.set_user_enabled(username, enabled))
    }
    fn set_user_password(&mut self, username: &str, password: &str) -> Result<(), String> {
        self.adapted(|a| a.set_user_password(username, password))
    }
    fn revoke_user_sessions(&mut self, username: &str) -> Result<u32, String> {
        self.adapted(|a| a.revoke_user_sessions(username))
    }
    fn create_user_invite(
        &mut self,
        username: &str,
        admin: bool,
        session_ttl_secs: u64,
        invite_ttl_secs: u64,
    ) -> Result<UserInviteMintedData, String> {
        self.adapted(|a| a.create_user_invite(username, admin, session_ttl_secs, invite_ttl_secs))
    }
    fn list_user_invites(&self) -> Result<(Vec<UserInviteData>, u32), String> {
        let invites = self
            .ca
            .list_user_invites()
            .into_iter()
            .map(|i| UserInviteData {
                username: i.username,
                admin: i.role == wayfinder_server::UserRole::Admin,
                session_ttl_secs: i.session_ttl_secs,
                created_at: i.created_at,
                expires_at: i.expires_at,
                started_at: i.started_at.unwrap_or(0),
                handle_expires_at: i.handle_expires_at.unwrap_or(0),
            })
            .collect();
        Ok((invites, 8))
    }
    fn revoke_user_invite(&mut self, username: &str) -> Result<(), String> {
        self.adapted(|a| a.revoke_user_invite(username))
    }
    fn begin_user_registration(&mut self, token: &str) -> Result<RegistrationStartedData, String> {
        self.adapted(|a| a.begin_user_registration(token))
    }
    fn complete_user_registration(
        &mut self,
        handle: &str,
        password: &str,
        totp_code: &str,
    ) -> Result<(), String> {
        self.adapted(|a| a.complete_user_registration(handle, password, totp_code))
    }
}

/// Spawn an auto-approving provider node (mesh `0xABCD`, optional token) — one
/// that signs on submission — and return a bootstrap [`Endpoint`] for it.
pub async fn spawn_provider(token: Option<String>) -> Endpoint {
    spawn_provider_with(token, true).await
}

/// Spawn a provider node in the closed posture, which holds each request until
/// an operator approves it, and return a bootstrap [`Endpoint`] for it.
///
/// A named helper rather than a bool at the call site: which of the two
/// enrollment paths a test drives is the most important thing about it.
pub async fn spawn_approval_gated_provider() -> Endpoint {
    spawn_provider_with(None, false).await
}

/// Spawn a provider node, choosing its enrollment posture, and return an
/// [`Endpoint`] that bootstraps against it (the node is un-enrolled at the
/// transport layer, so proving its own key is admitted).
pub async fn spawn_provider_with(token: Option<String>, auto_approve: bool) -> Endpoint {
    spawn_provider_full(token, auto_approve, false).await
}

/// Spawn a provider node, and choose whether it is *itself* enrolled — whether
/// its transport reports a trust anchor, which is what a real certificate
/// authority looks like (it is a member of the mesh it certifies).
///
/// The returned endpoint's identity differs accordingly: against an un-enrolled
/// provider it presents the node's own key, and against an enrolled one it
/// presents a freshly-minted key with no certificate at all — a stranger, which
/// is exactly what a node asking to join is.
pub async fn spawn_provider_full(
    token: Option<String>,
    auto_approve: bool,
    provider_enrolled: bool,
) -> Endpoint {
    // The node's TLS identity seed; the bootstrap client presents this same key.
    let seed = [9u8; 32];
    let node_key = Keypair::from_seed(&seed).ed_pubkey();

    let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, token, auto_approve);
    ca.set_now_unix(100);

    // `auth_present: true` because this provider *is* an authenticating node:
    // the adapter's flood gate refuses to sign a revocation it could not
    // announce, and a mock that published `false` would refuse every demotion
    // for a reason no real provider has.
    let mut comms = AuthorityComms::new(100);
    comms.publish(RouterFacts {
        unix_secs: 100,
        auth_present: true,
    });
    let (_unused_tx, unused_rx) = mpsc::channel(1);
    let facts = comms.attach(unused_rx).facts;
    let anchor =
        provider_enrolled.then(|| TrustAnchor::from_bytes(&ca.trust_anchor_bytes()).unwrap());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (query_tx, mut query_rx) =
        mpsc::channel::<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>(16);

    // Auth snapshot responder: nothing revoked, and an anchor only when the
    // provider is enrolled.
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
        let mut provider = ProviderMock {
            ca,
            facts,
            flooded: Vec::new(),
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
            // A stranger's key against an enrolled provider; the node's own key
            // (the bootstrap path) against an un-enrolled one.
            seed: if provider_enrolled { [4u8; 32] } else { seed },
            cert: Vec::new(),
        },
    }
}
