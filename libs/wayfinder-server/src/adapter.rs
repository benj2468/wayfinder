//! The [`RouterReads`]/[`RouterWrites`] adapter over the router.
//!
//! Newtype so we can implement the external trait for the external
//! [`CentralRouter`]. This layer is `no_std` + `alloc` and carries no
//! transport dependencies. Most methods are pure projections of router state
//! into the management-API intermediate representation, but some — `set_auth`
//! and `set_config` — mutate the borrowed router in response to a request. The
//! certificate-authority half lives in `authority_task.rs` and is not reachable
//! from here.

use core::time::Duration;

use alloc::vec::Vec;

use wayfinder::CentralRouter;
use wayfinder::EgressInterface;
use wayfinder::auth::OgmAuth;
use wayfinder::interfaces::frame::Mac;
use wayfinder::ping::ProbeState;
use wayfinder::wayfinder_auth::Keypair;
use wayfinder::wayfinder_auth::MembershipCert;
use wayfinder::wayfinder_auth::TrustAnchor;
use wayfinder_protos::service::AlarmData;
use wayfinder_protos::service::AlarmKindData;
use wayfinder_protos::service::AlarmSeverityData;
use wayfinder_protos::service::AlarmSubjectData;
use wayfinder_protos::service::AlarmsData;
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
use wayfinder_protos::service::OwnCertData;
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
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

use crate::settings::NodeIdentity;
use crate::settings::NodeSettings;
use crate::settings::SettingsStore;

use alloc::string::String;
use alloc::string::ToString;

/// Adapts a borrowed [`CentralRouter`] to the management-API data provider
/// trait.  Node addresses are [`Mac`]; the adapter projects them as raw
/// 6-byte slices into the management-API intermediate representation.
///
/// Carries the instant `now` (the router's monotonic clock) at which the
/// snapshot is taken, because throughput is reported as a *rate* evaluated at
/// that instant — an idle interface must read as a decaying rate, not a stale
/// one.  Construct a fresh adapter per request so the rate reflects the time
/// the query is served.
pub struct RouterAdapter<
    'a,
    const ORIGINATORS: usize = { wayfinder::host::ORIGINATORS },
    const INTERFACES: usize = { wayfinder::host::INTERFACES },
    const MCAST_MEMBERS: usize = { wayfinder::host::MCAST_MEMBERS },
    const LOCAL_MCAST: usize = { wayfinder::host::LOCAL_MCAST },
    const IDENT_TABLE: usize = { wayfinder::host::IDENT_TABLE },
    const IDENT_LIVE: usize = { wayfinder::host::IDENT_LIVE },
    const LINK_QUALITY: usize = { wayfinder::host::LINK_QUALITY },
    const NEIGHBOR_KEYS: usize = { wayfinder::host::NEIGHBOR_KEYS },
    const REVOKED: usize = { wayfinder::host::REVOKED },
    const IN_FLIGHT_CERT_REQUESTS: usize = { wayfinder::host::IN_FLIGHT_CERT_REQUESTS },
    const PENDING_REPLIES: usize = { wayfinder::host::PENDING_REPLIES },
> {
    router: &'a mut CentralRouter<
        ORIGINATORS,
        INTERFACES,
        MCAST_MEMBERS,
        LOCAL_MCAST,
        IDENT_TABLE,
        IDENT_LIVE,
        LINK_QUALITY,
        NEIGHBOR_KEYS,
        REVOKED,
        IN_FLIGHT_CERT_REQUESTS,
        PENDING_REPLIES,
    >,
    epoch_unix: Duration,
    now: Duration,
    /// Whether the host's clock is disciplined enough to make credential
    /// decisions with, as the driver last determined.
    ///
    /// Injected rather than read here: this adapter is `no_std` + `alloc` and
    /// has no host to ask, and the answer must be the *same* one the driver's
    /// auth clock acted on. Defaults to `true`, so an embedded node — which has
    /// no NTP status and gets its time from elsewhere — reports the state it is
    /// actually in rather than a fabricated failure.
    clock_trusted: bool,
    /// The enrollment policy in force, as the authority last published it, or
    /// `None` on a node that runs no authority at all.
    ///
    /// A snapshot handed in by the caller, not a live borrow of the authority:
    /// the two are owned by different executors now, and this crate is
    /// `no_std` + `alloc`, so it cannot hold the `watch::Receiver` the host
    /// driver reads this from.
    enrollment: Option<EnrollmentPolicyStatusData>,
    /// Where an accepted security setting is recorded so it outlives a
    /// restart.  Absent on a node with no runtime state configured (and on
    /// every embedded node), where a change applies in memory only.
    settings: Option<&'a mut dyn SettingsStore>,
    /// This node's own identity seed — the one its management TLS terminates
    /// on, which is also its mesh identity once it holds a certificate.
    ///
    /// Held here rather than read from the router's auth state because the two
    /// operations that need it happen precisely when there is no auth state to
    /// read: reporting the keys an un-enrolled node wants certified, and
    /// installing the certificate that comes back.
    ///
    /// A mutable reference into the caller's own storage, not an owned copy:
    /// when [`set_auth`](Self::set_auth) installs a *different* seed, it
    /// writes the new value straight back through this reference so the
    /// caller's copy changes immediately rather than only after this adapter
    /// is dropped. That is what closes the self-key staleness window — the
    /// TLS accept loop's per-connection authorization snapshot
    /// (`wayfinder_server::transport::AuthSnapshot::own_key`) reads the same
    /// slot fresh on every connection, so a seed this call rotates away from
    /// stops granting access on the very next connection, not only at the
    /// next restart.
    ///
    /// The outer `Option` is builder-presence (absent where the host offered
    /// no identity storage at all — every embedded node, and a test that only
    /// reads router state); the inner one is whether a seed is currently
    /// known. Absent (either way) makes both operations above report "no
    /// identity" rather than guess at one.
    identity_seed: Option<&'a mut Option<[u8; 32]>>,
}

impl<
    'a,
    const ORIGINATORS: usize,
    const INTERFACES: usize,
    const MCAST_MEMBERS: usize,
    const LOCAL_MCAST: usize,
    const IDENT_TABLE: usize,
    const IDENT_LIVE: usize,
    const LINK_QUALITY: usize,
    const NEIGHBOR_KEYS: usize,
    const REVOKED: usize,
    const IN_FLIGHT_CERT_REQUESTS: usize,
    const PENDING_REPLIES: usize,
>
    RouterAdapter<
        'a,
        ORIGINATORS,
        INTERFACES,
        MCAST_MEMBERS,
        LOCAL_MCAST,
        IDENT_TABLE,
        IDENT_LIVE,
        LINK_QUALITY,
        NEIGHBOR_KEYS,
        REVOKED,
        IN_FLIGHT_CERT_REQUESTS,
        PENDING_REPLIES,
    >
{
    /// Wrap a borrowed router so its state can be served through the management
    /// API, evaluating time-varying metrics (throughput) as of `now` — the same
    /// monotonic instant the driver stamps on received frames.  The enrollment policy this adapter
    /// reports is supplied separately — see
    /// [`with_enrollment_policy`](Self::with_enrollment_policy).
    pub fn new(
        router: &'a mut CentralRouter<
            ORIGINATORS,
            INTERFACES,
            MCAST_MEMBERS,
            LOCAL_MCAST,
            IDENT_TABLE,
            IDENT_LIVE,
            LINK_QUALITY,
            NEIGHBOR_KEYS,
            REVOKED,
            IN_FLIGHT_CERT_REQUESTS,
            PENDING_REPLIES,
        >,
        now: Duration,
    ) -> Self {
        Self {
            router,
            now,
            enrollment: None,
            epoch_unix: Duration::default(),
            clock_trusted: true,
            settings: None,
            identity_seed: None,
        }
    }

    /// Update the unix offset for this adapter, used to convert between unix
    /// timestamps and [`Duration`] values.
    ///
    /// This is what [`unix_now`](Self::unix_now) feeds `set_auth`'s
    /// certificate-validity check: an adapter built without this defaults
    /// `epoch_unix` to zero, so `unix_now()` collapses to just `now` — a small
    /// monotonic duration, nowhere near a real certificate's validity window —
    /// and every `SetAuth` will then fail as "not yet valid" no matter how
    /// valid the certificate actually is. Every host caller must supply the
    /// same `epoch_unix` it advances the router's auth clock with elsewhere
    /// (see `refresh_auth_clock` in `wayfinder-driver`); an embedded node has
    /// no wall clock to supply here at all yet, which is why `SetAuth` over
    /// its management port is not wired up (see
    /// `wayfinder-embedded-driver`'s `run_once_with_mgmt`).
    pub fn with_epoch_unix(mut self, offset: Duration) -> Self {
        self.epoch_unix = offset;
        self
    }

    /// Tell the adapter whether the host's clock is currently trusted, so
    /// `GetNodeInfo` can report it.
    ///
    /// Supplied by the same caller that supplies
    /// [`with_epoch_unix`](Self::with_epoch_unix), and it must be the verdict
    /// that clock was resolved under — a node reporting "clock fine" while
    /// refusing every credential operation on the grounds that it is not would
    /// be worse than reporting nothing.
    pub fn with_clock_trusted(mut self, trusted: bool) -> Self {
        self.clock_trusted = trusted;
        self
    }

    /// Tell the adapter which identity-seed slot this node runs as, so it can
    /// report the public half (for a client enrolling this node), certify it
    /// when a certificate for it arrives, and — when [`set_auth`](Self::set_auth)
    /// installs a *different* seed — write the new one straight back into
    /// `seed`, so the caller's own copy (and anything reading it afterward,
    /// such as the TLS accept loop's per-connection authorization snapshot)
    /// observes the change immediately rather than only after a restart.
    ///
    /// A builder step for the same reason as [`with_settings`](Self::with_settings):
    /// most callers have no seed to offer — an embedded node keeps its own, and
    /// a test that only reads router state has none at all.
    pub fn with_identity(mut self, seed: &'a mut Option<[u8; 32]>) -> Self {
        self.identity_seed = Some(seed);
        self
    }

    /// The identity seed currently held in the caller's slot, if any — `None`
    /// both when no slot was offered ([`with_identity`](Self::with_identity)
    /// never called) and when one was offered but is still empty.
    fn current_identity_seed(&self) -> Option<[u8; 32]> {
        self.identity_seed.as_deref().copied().flatten()
    }

    /// Report `enrollment` as the enrollment policy in force.
    ///
    /// The host driver reads this from the authority task's published value,
    /// never by asking the authority — which may be mid-Argon2id when the
    /// router loop wants it.
    pub fn with_enrollment_policy(
        mut self,
        enrollment: Option<EnrollmentPolicyStatusData>,
    ) -> Self {
        self.enrollment = enrollment;
        self
    }

    /// Record accepted security settings in `settings` so they survive a
    /// restart.
    ///
    /// A builder step rather than a fourth constructor argument because most
    /// callers — every embedded node, and every test that only reads state —
    /// have no store to offer, and threading `None` through all of them would
    /// obscure the two call sites that actually persist.
    pub fn with_settings(mut self, settings: &'a mut dyn SettingsStore) -> Self {
        self.settings = Some(settings);
        self
    }

    /// Record `update` durably before it is applied to the router.
    ///
    /// The ordering is the point. Persisting first means a failure leaves the
    /// node running exactly what it was running before, so the answer the
    /// operator gets and the state the node is in never disagree — whereas
    /// applying first would leave a setting live that the next restart
    /// silently discards, which is the failure this whole feature exists to
    /// prevent. A node with no store configured skips the step entirely and
    /// applies in memory, the documented behavior of an unconfigured node.
    fn persist_settings(&mut self, update: NodeSettings) -> Result<(), String> {
        match self.settings.as_mut() {
            Some(store) => store.persist(update),
            None => Ok(()),
        }
    }

    /// Calculate the now time with the epoch unix offset.
    fn unix_now(&self) -> Duration {
        self.epoch_unix + self.now
    }
}

/// Project `wayfinder-alarm`'s severity onto the service-layer one.
///
/// Two enums rather than a re-export because the crates must not depend on each
/// other: `wayfinder-protos` names the wire's vocabulary and `wayfinder-alarm`
/// names the raise site's, and this adapter is the one place that knows both.
fn alarm_severity_data(severity: wayfinder_alarm::Severity) -> AlarmSeverityData {
    match severity {
        wayfinder_alarm::Severity::Info => AlarmSeverityData::Info,
        wayfinder_alarm::Severity::Warning => AlarmSeverityData::Warning,
        wayfinder_alarm::Severity::Critical => AlarmSeverityData::Critical,
    }
}

/// Project `wayfinder-alarm`'s condition kind onto the service-layer one.
///
/// Exhaustive on purpose: adding a condition the node can raise must force a
/// decision about what a client sees, rather than defaulting to a row nothing
/// can name.
fn alarm_kind_data(kind: wayfinder_alarm::AlarmKind) -> AlarmKindData {
    match kind {
        wayfinder_alarm::AlarmKind::UnauthenticatedTraffic => AlarmKindData::UnauthenticatedTraffic,
        wayfinder_alarm::AlarmKind::TrafficFlood => AlarmKindData::TrafficFlood,
        wayfinder_alarm::AlarmKind::ManagementAuthFailures => AlarmKindData::ManagementAuthFailures,
        wayfinder_alarm::AlarmKind::OgmReplay => AlarmKindData::OgmReplay,
        wayfinder_alarm::AlarmKind::RevokedPeer => AlarmKindData::RevokedPeer,
        wayfinder_alarm::AlarmKind::LinkErrors => AlarmKindData::LinkErrors,
        wayfinder_alarm::AlarmKind::TableSaturation => AlarmKindData::TableSaturation,
        wayfinder_alarm::AlarmKind::ClockUnsynchronized => AlarmKindData::ClockUnsynchronized,
        wayfinder_alarm::AlarmKind::SelfRevoked => AlarmKindData::SelfRevoked,
    }
}

/// Map a log-ring level onto the management API's own.
///
/// Two enums with the same five variants, kept apart on purpose: the ring's is
/// the logging crate's vocabulary and the other is the wire's, and neither crate
/// should have to depend on the other to name a level.
fn log_level_data(level: wayfinder_log::Level) -> LogLevelData {
    match level {
        wayfinder_log::Level::Error => LogLevelData::Error,
        wayfinder_log::Level::Warn => LogLevelData::Warn,
        wayfinder_log::Level::Info => LogLevelData::Info,
        wayfinder_log::Level::Debug => LogLevelData::Debug,
        wayfinder_log::Level::Trace => LogLevelData::Trace,
    }
}

/// A read-only projection of the router, and everything the sixteen `&self`
/// answers need to build a response.
///
/// Exists so those answers have exactly one implementation while being
/// reachable through two different borrows. A host serves them from a shared
/// read lock on its own connection task, several at once, while the driver's
/// event loop goes on forwarding frames; [`RouterAdapter`] — which holds the
/// `&mut` the three mutations need — answers them by building one of these and
/// delegating.
///
/// Carries `now` for the same reason [`RouterAdapter`] does: throughput is a
/// *rate* evaluated at an instant, so an idle interface must read as a decaying
/// rate rather than a stale one. Build a fresh view per request.
///
/// The identity seed is a *value* here, not the writable slot
/// [`RouterAdapter`] holds: nothing on this side installs one, and a read that
/// could write back through a shared borrow is precisely what this type exists
/// to make unrepresentable.
pub struct RouterView<
    'a,
    const ORIGINATORS: usize = { wayfinder::host::ORIGINATORS },
    const INTERFACES: usize = { wayfinder::host::INTERFACES },
    const MCAST_MEMBERS: usize = { wayfinder::host::MCAST_MEMBERS },
    const LOCAL_MCAST: usize = { wayfinder::host::LOCAL_MCAST },
    const IDENT_TABLE: usize = { wayfinder::host::IDENT_TABLE },
    const IDENT_LIVE: usize = { wayfinder::host::IDENT_LIVE },
    const LINK_QUALITY: usize = { wayfinder::host::LINK_QUALITY },
    const NEIGHBOR_KEYS: usize = { wayfinder::host::NEIGHBOR_KEYS },
    const REVOKED: usize = { wayfinder::host::REVOKED },
    const IN_FLIGHT_CERT_REQUESTS: usize = { wayfinder::host::IN_FLIGHT_CERT_REQUESTS },
    const PENDING_REPLIES: usize = { wayfinder::host::PENDING_REPLIES },
> {
    router: &'a CentralRouter<
        ORIGINATORS,
        INTERFACES,
        MCAST_MEMBERS,
        LOCAL_MCAST,
        IDENT_TABLE,
        IDENT_LIVE,
        LINK_QUALITY,
        NEIGHBOR_KEYS,
        REVOKED,
        IN_FLIGHT_CERT_REQUESTS,
        PENDING_REPLIES,
    >,
    now: Duration,
    /// Whether the host's clock is disciplined enough to make credential
    /// decisions with, as the driver last determined.
    ///
    /// Injected for the same reason [`RouterAdapter`] injects it: this crate is
    /// `no_std` + `alloc` and has no host to ask, and the answer must be the
    /// *same* one the driver's auth clock acted on rather than a second opinion
    /// formed here. Defaults to `true`, so an embedded node — which has no NTP
    /// status and gets its time from elsewhere — reports the state it is
    /// actually in rather than a fabricated failure.
    clock_trusted: bool,
    /// The enrollment policy in force, as the authority last published it, or
    /// `None` on a node that runs no authority at all.
    enrollment: Option<EnrollmentPolicyStatusData>,
    /// This node's identity seed, if it has one — reported by
    /// `security_status`, and by nothing else here.
    identity_seed: Option<[u8; 32]>,
}

impl<
    const ORIGINATORS: usize,
    const INTERFACES: usize,
    const MCAST_MEMBERS: usize,
    const LOCAL_MCAST: usize,
    const IDENT_TABLE: usize,
    const IDENT_LIVE: usize,
    const LINK_QUALITY: usize,
    const NEIGHBOR_KEYS: usize,
    const REVOKED: usize,
    const IN_FLIGHT_CERT_REQUESTS: usize,
    const PENDING_REPLIES: usize,
>
    RouterView<
        '_,
        ORIGINATORS,
        INTERFACES,
        MCAST_MEMBERS,
        LOCAL_MCAST,
        IDENT_TABLE,
        IDENT_LIVE,
        LINK_QUALITY,
        NEIGHBOR_KEYS,
        REVOKED,
        IN_FLIGHT_CERT_REQUESTS,
        PENDING_REPLIES,
    >
{
    /// Wrap a borrowed router for reading, evaluating time-varying metrics as
    /// of `now` — the same monotonic instant the driver stamps on received
    /// frames.
    pub fn new(
        router: &CentralRouter<
            ORIGINATORS,
            INTERFACES,
            MCAST_MEMBERS,
            LOCAL_MCAST,
            IDENT_TABLE,
            IDENT_LIVE,
            LINK_QUALITY,
            NEIGHBOR_KEYS,
            REVOKED,
            IN_FLIGHT_CERT_REQUESTS,
            PENDING_REPLIES,
        >,
        now: Duration,
    ) -> RouterView<
        '_,
        ORIGINATORS,
        INTERFACES,
        MCAST_MEMBERS,
        LOCAL_MCAST,
        IDENT_TABLE,
        IDENT_LIVE,
        LINK_QUALITY,
        NEIGHBOR_KEYS,
        REVOKED,
        IN_FLIGHT_CERT_REQUESTS,
        PENDING_REPLIES,
    > {
        RouterView {
            router,
            now,
            clock_trusted: true,
            enrollment: None,
            identity_seed: None,
        }
    }

    /// Report whether this node's clock is disciplined enough to make a
    /// credential decision against.
    ///
    /// The caller's verdict, not one taken here — see the field's doc comment.
    #[must_use]
    pub fn with_clock_trusted(mut self, trusted: bool) -> Self {
        self.clock_trusted = trusted;
        self
    }

    /// Report `enrollment` as the enrollment policy in force.
    #[must_use]
    pub fn with_enrollment_policy(
        mut self,
        enrollment: Option<EnrollmentPolicyStatusData>,
    ) -> Self {
        self.enrollment = enrollment;
        self
    }

    /// Report `seed` as the identity this node runs as, so `security_status`
    /// can name the keys a client would ask a provider to certify.
    #[must_use]
    pub fn with_identity(mut self, seed: Option<[u8; 32]>) -> Self {
        self.identity_seed = seed;
        self
    }

    /// Interface `idx`'s configured name, or the empty string when it was never
    /// named.  The wire carries "unnamed" as an empty `iface_name` rather than a
    /// synthesized placeholder, so a client can tell a deliberately-named
    /// interface from one that just fell back to its index.
    fn interface_name(&self, idx: usize) -> String {
        self.router.interface_name(idx).unwrap_or_default().into()
    }
}

/// Project a router-owned [`PingSession`] onto its wire shape.
///
/// Free rather than a method because both the status read and the cancel
/// return the same document, and the one thing here that is easy to get wrong —
/// how "unmeasured" is spelled — should be got wrong in at most one place.
fn project_session(session: &wayfinder::ping::PingSession) -> PingSessionData {
    PingSessionData {
        session_seq: session.session_seq(),
        destination: session.target().as_bytes().to_vec(),
        active: session.active(),
        requested: u32::from(session.requested()),
        sent: session.sent(),
        received: session.received(),
        lost: session.lost(),
        // Each unwraps to 0 before anything has been answered. The wire shape
        // has no room for "unmeasured", so `received` is what a client reads to
        // tell a genuine zero from a missing one — said once here and once in
        // the proto comment, because it is the only thing about these four
        // fields that can be got wrong.
        rtt_min_us: session.rtt_min_us().unwrap_or(0),
        rtt_avg_us: session.rtt_avg_us().unwrap_or(0),
        rtt_max_us: session.rtt_max_us().unwrap_or(0),
        rtt_mdev_us: session.rtt_mdev_us().unwrap_or(0),
        payload_bytes: u32::from(session.payload_len()),
        probes: session
            .probes()
            .map(|p| ProbeData {
                seqno: u32::from(p.seqno),
                state: match p.state {
                    ProbeState::Pending => ProbeStateData::Pending,
                    ProbeState::Replied => ProbeStateData::Replied,
                    ProbeState::TimedOut => ProbeStateData::TimedOut,
                    ProbeState::NoRoute => ProbeStateData::NoRoute,
                },
                rtt_us: p.rtt_us,
                forward_hops: u32::from(p.fwd_hops),
                return_hops: u32::from(p.rev_hops),
            })
            .collect(),
    }
}
impl<
    const ORIGINATORS: usize,
    const INTERFACES: usize,
    const MCAST_MEMBERS: usize,
    const LOCAL_MCAST: usize,
    const IDENT_TABLE: usize,
    const IDENT_LIVE: usize,
    const LINK_QUALITY: usize,
    const NEIGHBOR_KEYS: usize,
    const REVOKED: usize,
    const IN_FLIGHT_CERT_REQUESTS: usize,
    const PENDING_REPLIES: usize,
> RouterReads
    for RouterView<
        '_,
        ORIGINATORS,
        INTERFACES,
        MCAST_MEMBERS,
        LOCAL_MCAST,
        IDENT_TABLE,
        IDENT_LIVE,
        LINK_QUALITY,
        NEIGHBOR_KEYS,
        REVOKED,
        IN_FLIGHT_CERT_REQUESTS,
        PENDING_REPLIES,
    >
{
    fn node_id(&self) -> Vec<u8> {
        self.router.self_ident().as_bytes().to_vec()
    }

    fn num_originators(&self) -> u32 {
        self.router.originator_count() as u32
    }

    fn auth_locked(&self) -> bool {
        self.router.auth_locked()
    }

    fn routing_table(&self) -> Vec<RoutingEntryData> {
        self.router
            .originator_table()
            .map(|r| RoutingEntryData {
                destination: r.neighbor_ident.as_bytes().to_vec(),
                // Empty when nothing is selectable — notably while every path
                // is via a neighbor that has not proven itself. An unproven
                // next hop must never be reported as the route.
                next_hop: r
                    .best_next_hop
                    .map(|m| m.as_bytes().to_vec())
                    .unwrap_or_default(),
                tq: r.max_tq as u32,
                last_seqno: r.last_seqno,
                paths: r
                    .paths
                    .iter()
                    .map(|p| NeighborPathData {
                        neighbor_id: p.neighbor_ident.as_bytes().to_vec(),
                        tq: p.last_tq as u32,
                        last_seqno: p.last_seqno,
                        proven: self.router.proof_current(self.now, p.neighbor_ident),
                    })
                    .collect(),
            })
            .collect()
    }

    fn link_quality_table(&self) -> Vec<LinkQualityEntryData> {
        self.router
            .link_quality_records()
            .iter()
            .map(|r| LinkQualityEntryData {
                neighbor_id: r.neighbor.as_bytes().to_vec(),
                iface_idx: r.iface_idx as u32,
                ewma_quality: r.ewma_quality.map(u32::from),
                sample_count: r.sample_count,
                iface_name: self.interface_name(r.iface_idx),
            })
            .collect()
    }

    fn link_features_table(&self) -> Vec<LinkFeaturesEntryData> {
        (0..self.router.num_interfaces())
            .map(|idx| {
                let f = self.router.link_features(idx);
                LinkFeaturesEntryData {
                    iface_idx: idx as u32,
                    tx_ogm: f.tx_ogm,
                    rx_ogm: f.rx_ogm,
                    tx_data: f.tx_data,
                    rx_data: f.rx_data,
                    tx_keepalive_interval_ms: f.tx_keepalive.map(|k| k.interval_ms),
                    iface_name: self.interface_name(idx),
                }
            })
            .collect()
    }

    fn keepalive_table(&self) -> Vec<KeepAliveEntryData> {
        self.router
            .keepalive_table(self.now)
            .map(|e| KeepAliveEntryData {
                neighbor_id: e.neighbor.as_bytes().to_vec(),
                ms_since_last_heard: e.ms_since_last_heard,
                interval_estimate_ms: e.interval_estimate_ms,
                missed: e.missed,
            })
            .collect()
    }

    fn ogm_schedule(&self) -> Vec<OgmScheduleEntryData> {
        self.router
            .ogm_schedule()
            .map(|e| OgmScheduleEntryData {
                iface_idx: e.iface_idx as u32,
                // Intervals are sub-minute Trickle periods, so milliseconds fit
                // comfortably in u32; saturate defensively rather than wrap.
                current_interval_ms: e.current_interval.as_millis().min(u32::MAX as u128) as u32,
                min_interval_ms: e.min_interval.as_millis().min(u32::MAX as u128) as u32,
                max_interval_ms: e.max_interval.as_millis().min(u32::MAX as u128) as u32,
                iface_name: self.interface_name(e.iface_idx),
            })
            .collect()
    }

    fn throughput(&self) -> Vec<InterfaceThroughputData> {
        // Evaluate every interface's smoothed rate at the adapter's snapshot
        // instant, so an interface that has gone quiet reads as a decaying
        // rather than a stale rate.
        (0..self.router.num_interfaces())
            .filter_map(|idx| {
                self.router
                    .interface_throughput(idx, self.now)
                    .map(|t| InterfaceThroughputData {
                        iface_idx: idx as u32,
                        rx_bps: t.rx_bps,
                        rx_fps: t.rx_fps,
                        tx_bps: t.tx_bps,
                        tx_fps: t.tx_fps,
                        iface_name: self.interface_name(idx),
                    })
            })
            .collect()
    }

    fn security_status(&self) -> SecurityStatusData {
        // The posture flags and the enrollment policy are reported whether or
        // not auth is enabled: `require_auth` on a node with no cert is
        // precisely the state that keeps it off the mesh, so a dashboard that
        // hid it while auth was disabled would hide the reason.
        // The identity is likewise reported whether or not auth is enabled: an
        // un-enrolled node still has one, and reporting it is what lets a
        // client ask a provider to certify *this* node rather than mint some
        // new identity the node would then have to adopt.
        let identity = self.identity_seed.map(|seed| Keypair::from_seed(&seed));
        let posture = SecurityStatusData {
            require_auth: self.router.require_auth(),
            lazy_cert_distribution: self.router.lazy_cert_distribution(),
            enrollment: self.enrollment.clone(),
            own_ed_pubkey: identity
                .as_ref()
                .map(|kp| kp.ed_pubkey().to_vec())
                .unwrap_or_default(),
            own_x_pubkey: identity
                .as_ref()
                .map(|kp| kp.x_pubkey().to_vec())
                .unwrap_or_default(),
            // Reported with the posture rather than with the auth block below,
            // because a revoked node *has* no auth block — dropping the
            // certificate is what going inert means. Without it here, the one
            // state that most needs explaining would be the one the security
            // view could not describe.
            self_revoked: self.router.self_revoked(),
            self_revocation_not_after: self.router.self_revocation_not_after().unwrap_or(0),
            ..SecurityStatusData::default()
        };

        // No auth configured ⇒ report disabled, but still with the posture.
        let Some(auth) = self.router.auth() else {
            return posture;
        };
        let cert = auth.own_cert();

        // The set of MACs we hold any security knowledge about: routable
        // originators, verified neighbors, and revoked nodes — the last because a
        // revocation purges the node from routing, yet the operator still wants
        // to see that it is revoked. Deduplicate by MAC (the tables are small).
        let mut macs: Vec<wayfinder::interfaces::frame::Mac> = Vec::new();
        let originators = self.router.originator_table().map(|r| r.neighbor_ident);
        let verified_macs = auth.neighbors().iter().map(|n| n.cert.mac);
        for m in originators.chain(verified_macs).chain(auth.revoked_macs()) {
            if !macs.contains(&m) {
                macs.push(m);
            }
        }

        // An originator whose signed OGM we verified is cached (keyed by its MAC)
        // in `neighbors()`, carrying its cert expiry; anything else is reachable
        // or revoked but not (currently) verified.
        let nodes = macs
            .into_iter()
            .map(|mac| {
                let verified = auth.neighbors().iter().find(|n| n.cert.mac == mac);
                // Holding a record is no longer the same question as being
                // revoked: a node re-admitted with a certificate issued after
                // the record's instant survives it, and is routing normally.
                // `is_shunned` asks whether the record actually bites; the
                // record's `not_after` is still reported either way, as the
                // only date the row has once the cached cert has been evicted.
                let revocation_not_after = auth.revocation_not_after(mac);
                NodeSecurityData {
                    node_id: mac.as_bytes().to_vec(),
                    verified: verified.is_some(),
                    cert_not_after: verified.map(|n| n.cert.not_after).unwrap_or(0),
                    revoked: auth.is_shunned(mac),
                    revocation_not_after: revocation_not_after.unwrap_or(0),
                }
            })
            .collect();

        SecurityStatusData {
            auth_enabled: true,
            mesh_id: auth.anchor().mesh_id,
            node_mac: cert.node_mac.to_vec(),
            cert_not_after: cert.not_after.get(),
            revocation_count: auth.macs_to_purge().count() as u32,
            nodes,
            ..posture
        }
    }

    fn node_metrics(&self) -> NodeMetricsData {
        let occ = |(used, capacity): (usize, usize)| TableOccupancyData {
            used: used as u32,
            capacity: capacity as u32,
        };

        // Fold the TQ and path-diversity distributions in a single pass over the
        // originator table; all default to zero when no originators are known.
        let mut count: u32 = 0;
        let mut tq_min = u32::MAX;
        let mut tq_max = 0u32;
        let mut tq_sum = 0u64;
        let mut paths_max = 0u32;
        let mut paths_sum = 0u64;
        for r in self.router.originator_table() {
            count += 1;
            let tq = r.max_tq as u32;
            tq_min = tq_min.min(tq);
            tq_max = tq_max.max(tq);
            tq_sum += tq as u64;
            let paths = r.paths.len() as u32;
            paths_max = paths_max.max(paths);
            paths_sum += paths as u64;
        }
        let (tq_min, tq_mean, paths_mean) = if count == 0 {
            (0, 0.0, 0.0)
        } else {
            (
                tq_min,
                tq_sum as f64 / count as f64,
                paths_sum as f64 / count as f64,
            )
        };

        let (cert_store, in_flight_cert_requests, pending_cert_replies) = match self.router.auth() {
            Some(auth) => (
                occ(auth.cert_store_occupancy()),
                occ(auth.in_flight_cert_requests_occupancy()),
                occ(auth.pending_cert_replies_occupancy()),
            ),
            None => (
                TableOccupancyData::default(),
                TableOccupancyData::default(),
                TableOccupancyData::default(),
            ),
        };

        NodeMetricsData {
            uptime_secs: self.now.as_secs(),
            neighbor_count: self.router.neighbor_count() as u32,
            originators: occ(self.router.originator_occupancy()),
            broadcast_dedup: occ(self.router.broadcast_dedup_occupancy()),
            local_mcast_groups: occ(self.router.local_mcast_occupancy()),
            mcast_memberships: occ(self.router.mcast_member_occupancy()),
            tq_min,
            tq_max,
            tq_mean,
            paths_max,
            paths_mean,
            oversize_drops: self.router.oversize_drops(),
            relay_oversize_drops: self.router.relay_oversize_drops(),
            cert_store,
            in_flight_cert_requests,
            pending_cert_replies,
            cert_req_rate: self.router.cert_req_tx_rate(self.now),
            cert_reply_rate: self.router.cert_reply_tx_rate(self.now),
            untaggable_drop_rate: self.router.untaggable_drop_rate(self.now),
        }
    }

    fn resolve_route(&self, destination: &[u8]) -> Option<RouteResolutionData> {
        // Parse the request bytes as this router's identifier type, rejecting
        // any wrong-length input (`read_from_bytes` requires an exact match) so
        // the management API returns a structured error rather than silently
        // routing to a truncated or zero-padded address.
        let dest = Mac::read_from_bytes(destination).ok()?;
        let (next_hop, egress) = self.router.resolve_route(self.now, dest);
        Some(RouteResolutionData {
            next_hop: next_hop.as_bytes().to_vec(),
            egress: egress.map(|e| match e {
                EgressInterface::All => EgressDecisionData::AllInterfaces,
                EgressInterface::Interface(idx) => EgressDecisionData::Interface(idx as u32),
            }),
        })
    }

    fn own_cert(&self) -> Option<OwnCertData> {
        // Straight off the live auth state, so this reports what the node is
        // *running* under. Which is the whole value: an operator asking a node
        // for its certificate gets the one its OGMs are signed with, whether
        // that arrived through `set_auth` at runtime or out of a file at
        // startup, with no second source of truth that could disagree.
        let auth = self.router.auth()?;
        Some(OwnCertData {
            cert: auth.own_cert().as_bytes().to_vec(),
            trust_anchor: auth.anchor().to_bytes().to_vec(),
        })
    }

    fn ping_session(&self, session_seq: u32) -> Option<PingSessionData> {
        self.router.ping_session(session_seq).map(project_session)
    }

    fn runtime_config_active(&self) -> bool {
        self.router.runtime_config_active()
    }

    fn clock_trusted(&self) -> bool {
        self.clock_trusted
    }

    /// Read from the process-wide log ring.
    ///
    /// Takes nothing from `self`: the ring is filled by the installed logging
    /// subscriber, which is itself process-wide with no handle to thread
    /// anywhere. That is deliberate — it is what lets a node answer `GetLogs`
    /// without a reference to the ring being carried through the router, the
    /// driver, and every board's bring-up, on targets where none of those layers
    /// even exist in the same form.
    fn logs(&self, since_seq: u64, max_records: u32) -> LogsData {
        let snapshot = wayfinder_log::logs_since(since_seq, max_records as usize);
        LogsData {
            records: snapshot
                .records
                .into_iter()
                .map(|r| LogRecordData {
                    seq: r.seq,
                    uptime_ms: r.uptime_ms,
                    level: log_level_data(r.level),
                    target: r.target.as_str().into(),
                    message: r.message.as_str().into(),
                })
                .collect(),
            next_seq: snapshot.next_seq,
            dropped: snapshot.dropped,
            filter: wayfinder_log::current_spec().as_str().into(),
        }
    }

    /// Project the node's alarm board.
    ///
    /// Reads the process-global board directly, exactly as [`logs`](Self::logs)
    /// reads the process-global log ring, and for the same reason: what writes
    /// it is scattered across the stack with no handle to carry, so there is no
    /// router field to project from. Nothing here decides whether a condition
    /// holds — a detector did that when it raised the alarm — and nothing here
    /// filters: a latched-but-quiet row travels with `active: false` rather
    /// than being dropped, because "fired ten minutes ago and stopped" is the
    /// answer an operator who attached late came for.
    fn alarms(&self) -> AlarmsData {
        let snapshot = wayfinder_alarm::snapshot();
        let now_ms = snapshot.now_ms;
        AlarmsData {
            alarms: snapshot
                .alarms
                .into_iter()
                .map(|a| AlarmData {
                    kind: alarm_kind_data(a.kind),
                    severity: alarm_severity_data(a.severity),
                    subject: match a.subject {
                        wayfinder_alarm::Subject::Node(id) => {
                            AlarmSubjectData::Peer(id.as_bytes().into())
                        }
                        wayfinder_alarm::Subject::Interface(idx) => {
                            AlarmSubjectData::Interface(u32::from(idx))
                        }
                        wayfinder_alarm::Subject::None => AlarmSubjectData::Node,
                    },
                    first_ms: a.first_ms,
                    last_ms: a.last_ms,
                    count: a.count,
                    detail: a.detail.as_str().into(),
                    // Evaluated here rather than left to the client: the hold
                    // window is the node's policy and the uptime clock is the
                    // node's, so a client computing this itself would need both.
                    active: a.is_active(now_ms),
                })
                .collect(),
            dropped: snapshot.dropped,
            now_ms,
        }
    }
}

impl<
    const ORIGINATORS: usize,
    const INTERFACES: usize,
    const MCAST_MEMBERS: usize,
    const LOCAL_MCAST: usize,
    const IDENT_TABLE: usize,
    const IDENT_LIVE: usize,
    const LINK_QUALITY: usize,
    const NEIGHBOR_KEYS: usize,
    const REVOKED: usize,
    const IN_FLIGHT_CERT_REQUESTS: usize,
    const PENDING_REPLIES: usize,
>
    RouterAdapter<
        '_,
        ORIGINATORS,
        INTERFACES,
        MCAST_MEMBERS,
        LOCAL_MCAST,
        IDENT_TABLE,
        IDENT_LIVE,
        LINK_QUALITY,
        NEIGHBOR_KEYS,
        REVOKED,
        IN_FLIGHT_CERT_REQUESTS,
        PENDING_REPLIES,
    >
{
    /// A read-only view of this adapter's router, for answering the [`RouterReads`]
    /// half.
    ///
    /// Reborrows the adapter's `&mut` as shared, so the sixteen reads have one
    /// implementation rather than two that can drift.
    fn view(
        &self,
    ) -> RouterView<
        '_,
        ORIGINATORS,
        INTERFACES,
        MCAST_MEMBERS,
        LOCAL_MCAST,
        IDENT_TABLE,
        IDENT_LIVE,
        LINK_QUALITY,
        NEIGHBOR_KEYS,
        REVOKED,
        IN_FLIGHT_CERT_REQUESTS,
        PENDING_REPLIES,
    > {
        RouterView::new(self.router, self.now)
            .with_clock_trusted(self.clock_trusted)
            .with_enrollment_policy(self.enrollment.clone())
            .with_identity(self.current_identity_seed())
    }
}

impl<
    const ORIGINATORS: usize,
    const INTERFACES: usize,
    const MCAST_MEMBERS: usize,
    const LOCAL_MCAST: usize,
    const IDENT_TABLE: usize,
    const IDENT_LIVE: usize,
    const LINK_QUALITY: usize,
    const NEIGHBOR_KEYS: usize,
    const REVOKED: usize,
    const IN_FLIGHT_CERT_REQUESTS: usize,
    const PENDING_REPLIES: usize,
> RouterReads
    for RouterAdapter<
        '_,
        ORIGINATORS,
        INTERFACES,
        MCAST_MEMBERS,
        LOCAL_MCAST,
        IDENT_TABLE,
        IDENT_LIVE,
        LINK_QUALITY,
        NEIGHBOR_KEYS,
        REVOKED,
        IN_FLIGHT_CERT_REQUESTS,
        PENDING_REPLIES,
    >
{
    fn node_id(&self) -> Vec<u8> {
        self.view().node_id()
    }

    fn num_originators(&self) -> u32 {
        self.view().num_originators()
    }

    fn auth_locked(&self) -> bool {
        self.view().auth_locked()
    }

    fn routing_table(&self) -> Vec<RoutingEntryData> {
        self.view().routing_table()
    }

    fn link_quality_table(&self) -> Vec<LinkQualityEntryData> {
        self.view().link_quality_table()
    }

    fn link_features_table(&self) -> Vec<LinkFeaturesEntryData> {
        self.view().link_features_table()
    }

    fn keepalive_table(&self) -> Vec<KeepAliveEntryData> {
        self.view().keepalive_table()
    }

    fn ogm_schedule(&self) -> Vec<OgmScheduleEntryData> {
        self.view().ogm_schedule()
    }

    fn throughput(&self) -> Vec<InterfaceThroughputData> {
        self.view().throughput()
    }

    fn node_metrics(&self) -> NodeMetricsData {
        self.view().node_metrics()
    }

    fn resolve_route(&self, destination: &[u8]) -> Option<RouteResolutionData> {
        self.view().resolve_route(destination)
    }

    fn ping_session(&self, session_seq: u32) -> Option<PingSessionData> {
        self.view().ping_session(session_seq)
    }

    fn runtime_config_active(&self) -> bool {
        self.view().runtime_config_active()
    }

    fn clock_trusted(&self) -> bool {
        self.view().clock_trusted()
    }

    fn logs(&self, since_seq: u64, max_records: u32) -> LogsData {
        self.view().logs(since_seq, max_records)
    }

    fn alarms(&self) -> AlarmsData {
        self.view().alarms()
    }

    fn security_status(&self) -> SecurityStatusData {
        self.view().security_status()
    }

    fn own_cert(&self) -> Option<OwnCertData> {
        self.view().own_cert()
    }
}

impl<
    const ORIGINATORS: usize,
    const INTERFACES: usize,
    const MCAST_MEMBERS: usize,
    const LOCAL_MCAST: usize,
    const IDENT_TABLE: usize,
    const IDENT_LIVE: usize,
    const LINK_QUALITY: usize,
    const NEIGHBOR_KEYS: usize,
    const REVOKED: usize,
    const IN_FLIGHT_CERT_REQUESTS: usize,
    const PENDING_REPLIES: usize,
> RouterWrites
    for RouterAdapter<
        '_,
        ORIGINATORS,
        INTERFACES,
        MCAST_MEMBERS,
        LOCAL_MCAST,
        IDENT_TABLE,
        IDENT_LIVE,
        LINK_QUALITY,
        NEIGHBOR_KEYS,
        REVOKED,
        IN_FLIGHT_CERT_REQUESTS,
        PENDING_REPLIES,
    >
{
    fn set_auth(&mut self, seed: &[u8], cert: &[u8], trust_anchor: &[u8]) -> Result<(), String> {
        // An empty seed means "certify the identity I already have" — the
        // enrollment case, where the point is that the node's key (and so its
        // MAC) does not change. Anything else is a new identity being installed
        // wholesale, which the node adopts as given.
        let certifying_existing_identity = seed.is_empty();
        let seed: [u8; 32] = if certifying_existing_identity {
            self.current_identity_seed().ok_or_else(|| {
                "this node has no identity to certify; send the seed alongside the \
                 certificate"
                    .to_string()
            })?
        } else {
            seed.try_into()
                .map_err(|_| "seed must be exactly 32 bytes".to_string())?
        };
        let key_pair = Keypair::from_seed(&seed);
        let parsed_cert = MembershipCert::from_bytes(cert)
            .ok_or_else(|| "unable to parse membership cert".to_string())?;
        let anchor = TrustAnchor::from_bytes(trust_anchor)
            .ok_or_else(|| "unable to parse trust anchor".to_string())?;

        // Validate the certificate before we persist it.
        anchor
            .verify_cert(&parsed_cert, self.unix_now().as_secs())
            .map_err(|e| e.to_string())?;
        // The certificate must actually name the key being installed — a
        // provider bug or an operator approving the wrong pending row must
        // not leave this node signing OGMs under a certificate that does not
        // name its own key (every peer would then reject them while this
        // node reports itself enrolled). Applies in both shapes: certifying
        // the existing identity in place, and installing a wholesale new one.
        if parsed_cert.ed_pubkey != key_pair.ed_pubkey() {
            return Err("certificate key does not match the identity being installed".to_string());
        }
        // Certifying the identity already held must also keep the MAC that
        // identity already runs under — that is the whole promise of this
        // path (`SetAuth` with no seed), so a certificate for a *different*
        // MAC is a provider-side mismatch, not a legitimate answer. A
        // wholesale identity install is exempt: naming a new MAC is exactly
        // what it is for, and `wayfinder-tap` re-derives the router's MAC
        // from the installed certificate on the next boot.
        if certifying_existing_identity && Mac(parsed_cert.node_mac) != self.router.self_ident() {
            return Err("certificate MAC does not match the MAC this node runs under".to_string());
        }

        // A node under a revocation may only be re-admitted with a certificate
        // that revocation does not cancel. Refused here rather than installed
        // and quietly ignored, because the alternative is the one genuinely
        // misleading state: a node reporting itself enrolled while every peer
        // holding the record drops it, which looks like a routing fault and is
        // not one. The remedy is a certificate issued *after* the revocation
        // instant — what re-approving the node's enrollment produces.
        if self.router.self_revocation_cancels(&parsed_cert) {
            return Err("this node has been revoked from the mesh, and this certificate predates the revocation; it must be re-issued by the authority before this node can rejoin"
                .to_string());
        }

        // Recorded only once every blob has parsed, so a malformed request
        // cannot leave unusable identity material behind for the next boot to
        // trip over. The bytes as received are what is stored — they are what
        // the next boot will parse, so round-tripping them through the parsed
        // types first would only add a way for the two to disagree.
        self.persist_settings(NodeSettings {
            identity: Some(NodeIdentity {
                seed: seed.to_vec(),
                cert: cert.to_vec(),
                trust_anchor: trust_anchor.to_vec(),
            }),
            // Cleared in the same durable write that installs the identity:
            // this certificate has just been checked against the record above,
            // so leaving the record behind would only re-lock the node on its
            // next boot.
            self_revocation: Some(Vec::new()),
            ..Default::default()
        })?;

        let auth = OgmAuth::with_capacities(key_pair, parsed_cert, anchor);
        self.router.set_auth(auth);
        // Recorded last, once installation has actually succeeded: write the
        // now-current seed back into the caller's slot (a no-op when this is
        // the same seed the request certified in place) so a seed this call
        // *rotates away from* stops equalling `own_key` on the accept loop's
        // very next connection, rather than only after a restart. See
        // `with_identity` for why this is a mutable reference rather than a
        // copy.
        if let Some(slot) = self.identity_seed.as_deref_mut() {
            *slot = Some(seed);
        }
        Ok(())
    }

    fn set_config(&mut self, config: RuntimeConfigData) -> Result<(), String> {
        if let Some(t) = config.trickle {
            if t.min_interval_ms > t.max_interval_ms {
                return Err("min_interval_ms must not exceed max_interval_ms".to_string());
            }
            let applied = self.router.apply_runtime_trickle_config(
                t.iface_idx as usize,
                Duration::from_millis(t.min_interval_ms.into()),
                Duration::from_millis(t.max_interval_ms.into()),
                self.now,
            );
            if !applied {
                return Err("interface index out of range".to_string());
            }
        }
        // The two posture flags are recorded as one write before either is
        // applied, so a request naming both never lands half-durable.
        if config.require_auth.is_some() || config.lazy_cert_distribution.is_some() {
            self.persist_settings(NodeSettings {
                require_auth: config.require_auth,
                lazy_cert_distribution: config.lazy_cert_distribution,
                ..Default::default()
            })?;
        }
        if let Some(require_auth) = config.require_auth {
            self.router.apply_runtime_require_auth(require_auth);
        }
        if let Some(lazy) = config.lazy_cert_distribution {
            self.router.apply_runtime_lazy_cert_distribution(lazy);
        }
        if config.enrollment.is_some() {
            // The authority's state, and the authority no longer shares this
            // executor. On the host the connection task strips this field and
            // sends it on as an `AuthorityCommand::SetEnrollmentPolicy`, so
            // seeing one here means the caller has no authority to apply it —
            // an embedded node, or a host node without a provider. Refused
            // rather than ignored: answering `Empty` would tell the client a
            // policy it never applied is now in force.
            return Err("node is not a certificate-authority provider".to_string());
        }
        if let Some(lf) = config.link_features {
            let idx = lf.iface_idx as usize;
            // Merge the present flags onto the interface's current features so a
            // partial update flips only the gates it names, leaving the rest as
            // they are.
            let mut features = self.router.link_features(idx);
            if let Some(v) = lf.tx_ogm {
                features.tx_ogm = v;
            }
            if let Some(v) = lf.rx_ogm {
                features.rx_ogm = v;
            }
            if let Some(v) = lf.tx_data {
                features.tx_data = v;
            }
            if let Some(v) = lf.rx_data {
                features.rx_data = v;
            }
            if let Some(v) = lf.tx_keepalive {
                features.tx_keepalive =
                    v.map(|interval_ms| wayfinder::features::KeepAliveConfig { interval_ms });
            }
            if !self
                .router
                .apply_runtime_link_features(idx, features, self.now)
            {
                return Err("interface index out of range".to_string());
            }
        }
        Ok(())
    }

    /// Start a probe session against `destination`.
    ///
    /// A *write* because of what it does to the node, not because of what it
    /// records: it puts frames on the air at a caller-chosen cadence and
    /// replaces whatever session was running. Only the malformed-identifier
    /// case is an error — a well-formed request against a node this router
    /// cannot reach starts a session perfectly well and reports the
    /// unreachability probe by probe, which is the answer the operator asked
    /// for.
    fn start_ping(
        &mut self,
        destination: &[u8],
        count: u32,
        interval_ms: u32,
        timeout_ms: u32,
        payload_bytes: u32,
    ) -> Result<PingStartData, String> {
        // Exact-length parse, for the same reason `resolve_route` insists on
        // one: a truncated or zero-padded address would silently become a
        // different node's.
        let dest = Mac::read_from_bytes(destination).map_err(|_| {
            alloc::string::String::from("destination is not a valid node identifier")
        })?;

        // The session comes back with the call, so the settings reported below
        // are the ones the router actually applied — it owns the defaulting and
        // the clamping — and there is no lookup-by-handle to assume succeeded.
        let (session_seq, session) = self.router.start_ping(
            self.now,
            dest,
            count.try_into().unwrap_or(u16::MAX),
            Duration::from_millis(u64::from(interval_ms)),
            Duration::from_millis(u64::from(timeout_ms)),
            payload_bytes.try_into().unwrap_or(u16::MAX),
        );

        Ok(PingStartData {
            session_seq,
            count: u32::from(session.requested()),
            interval_ms: session.interval().as_millis() as u32,
            timeout_ms: session.timeout().as_millis() as u32,
            payload_bytes: u32::from(session.payload_len()),
        })
    }

    fn cancel_ping(&mut self, session_seq: u32) -> Option<PingSessionData> {
        self.router.cancel_ping(session_seq).map(project_session)
    }

    /// Install a new runtime log filter, and report the spec now in force.
    ///
    /// A spec that fails to parse leaves the previous filter untouched; the
    /// error text is the parser's own, so an operator sees which part of the
    /// grammar they missed rather than a generic refusal.
    fn set_log_level(&mut self, directives: &str) -> Result<String, String> {
        match wayfinder_log::set_filter(directives) {
            Ok(()) => Ok(wayfinder_log::current_spec().as_str().into()),
            Err(e) => Err(alloc::format!("{e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::MeshAuthority as _;
    use wayfinder::CentralRouter;
    use wayfinder::batman::wire::BatmanOgmPacket;
    use wayfinder::batman::wire::BatmanPacketType;
    use wayfinder::interfaces::frame::LinkFrame;
    use wayfinder::interfaces::frame::Mac;
    use wayfinder_protos::service::AuthorityDataProvider as _;
    use wayfinder_protos::service::EnrollmentAdmission;
    use wayfinder_protos::service::LinkFeaturesData;
    use wayfinder_protos::service::TrickleConfigData;
    use zerocopy::FromBytes;
    use zerocopy::IntoBytes;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// Mint a cert directly from the CA, returning the raw cert bytes — the
    /// setup shorthand these tests need.  Issues straight through `issue` rather
    /// than round-tripping the client-facing `submit_csr` path (which is about
    /// requesting a cert, not the deterministic setup these tests want).
    fn ca_issue(
        ca: &mut crate::CertAuthority,
        mac: &[u8],
        ed: &[u8],
        x: &[u8],
    ) -> alloc::vec::Vec<u8> {
        ca.issue(
            Mac::try_from(mac).unwrap(),
            ed.try_into().unwrap(),
            x.try_into().unwrap(),
        )
        .unwrap()
        .cert
    }

    /// Serialise a link frame carrying `payload` from `src` to `dst`.
    fn link_frame_bytes(src: Mac, dst: Mac, protocol: u16, payload: &[u8]) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::new();
        out.extend_from_slice(dst.as_bytes());
        out.extend_from_slice(src.as_bytes());
        out.extend_from_slice(&protocol.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Feed one direct OGM so the router learns `orig` as a one-hop neighbour at
    /// the engine's stored TQ of `tq - 10` (the per-hop penalty) with a single
    /// path.  A full TTL makes it a direct path.
    fn feed_direct_ogm(router: &mut CentralRouter, orig: Mac, seqno: u32, tq: u8) {
        let ogm = BatmanOgmPacket {
            packet_type: BatmanPacketType::Ogm.as_u8(),
            version: 5,
            ttl: 50,
            flags: 0,
            seqno: seqno.to_be(),
            orig,
            reserved: 0,
            tq,
            tvlv_len: 0,
        };
        let bytes = link_frame_bytes(
            orig,
            Mac::BROADCAST,
            wayfinder::DEFAULT_BATMAN_ETHER_TYPE,
            ogm.as_bytes(),
        );
        let frame = LinkFrame::ref_from_bytes(&bytes).unwrap();
        let mut tx = [0u8; 256];
        router.handle_frame(Duration::ZERO, 0, frame, &mut tx);
    }

    /// Every per-interface table carries the interface's configured name
    /// alongside its index, so a client can label a row without a second lookup
    /// — and an interface the operator never named carries an empty name rather
    /// than a synthesized placeholder, keeping the two cases distinguishable.
    #[test]
    fn per_interface_tables_carry_the_configured_name() {
        let mut router = CentralRouter::new(mac(1));
        for idx in 0..2 {
            router.configure_interface_ogm(
                idx,
                Duration::from_secs(1),
                Duration::from_secs(8),
                Duration::ZERO,
            );
        }
        router.set_interface_name(0, "lora-roof");
        // Give interface 0 a link-quality sample to project.
        feed_direct_ogm(&mut router, mac(2), 1, 255);

        let adapter = RouterAdapter::new(&mut router, Duration::ZERO);

        let lq = adapter.link_quality_table();
        assert_eq!(lq.len(), 1);
        assert_eq!(lq[0].iface_idx, 0);
        assert_eq!(lq[0].iface_name, "lora-roof");

        let features = adapter.link_features_table();
        assert_eq!(features[0].iface_name, "lora-roof");
        assert_eq!(features[1].iface_name, "", "interface 1 was never named");

        let schedule = adapter.ogm_schedule();
        let e0 = schedule.iter().find(|e| e.iface_idx == 0).unwrap();
        assert_eq!(e0.iface_name, "lora-roof");
        let e1 = schedule.iter().find(|e| e.iface_idx == 1).unwrap();
        assert_eq!(e1.iface_name, "");

        let tp = adapter.throughput();
        assert_eq!(tp[0].iface_name, "lora-roof");
        assert_eq!(tp[1].iface_name, "");
    }

    /// A router with interface 0 already registered (as startup wiring would
    /// do) has no runtime config override yet; `set_config` with the Trickle
    /// field present installs the new bounds and flips `runtime_config_active`
    /// to true.
    #[test]
    fn set_config_installs_trickle_bounds_and_marks_active() {
        let mut router = CentralRouter::new(mac(1));
        router.configure_interface_ogm(
            0,
            Duration::from_secs(1),
            Duration::from_secs(8),
            Duration::ZERO,
        );
        assert!(!RouterAdapter::new(&mut router, Duration::ZERO).runtime_config_active());

        let result =
            RouterAdapter::new(&mut router, Duration::ZERO).set_config(RuntimeConfigData {
                trickle: Some(TrickleConfigData {
                    iface_idx: 0,
                    min_interval_ms: 500,
                    max_interval_ms: 4000,
                }),
                ..Default::default()
            });
        assert!(result.is_ok());

        let adapter = RouterAdapter::new(&mut router, Duration::ZERO);
        assert!(adapter.runtime_config_active());
        let entry = adapter
            .ogm_schedule()
            .into_iter()
            .find(|e| e.iface_idx == 0)
            .unwrap();
        assert_eq!(entry.min_interval_ms, 500);
        assert_eq!(entry.max_interval_ms, 4000);
    }

    /// `set_config` with `lazy_cert_distribution` set flips the router's
    /// runtime OGM-emission mode (full cert vs. fingerprint) and marks the
    /// runtime config as active — the same `apply_*`-style contract as the
    /// trickle path above, distinct from the startup-only
    /// `CentralRouter::set_lazy_cert_distribution` wiring which does not
    /// touch `runtime_config_active`.
    #[test]
    fn set_config_installs_lazy_cert_distribution_and_marks_active() {
        use crate::CertAuthority;
        use wayfinder::auth::OgmAuth;
        use wayfinder::batman::wire::TvlvType;
        use wayfinder::batman::wire::find_tvlv;
        use wayfinder::wayfinder_auth::Keypair;
        use wayfinder::wayfinder_auth::MembershipCert;
        use wayfinder::wayfinder_auth::TrustAnchor;

        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None, true);
        ca.set_now_unix(100);
        let anchor = TrustAnchor::from_bytes(&ca.trust_anchor_bytes()).unwrap();
        let me = mac(1);
        let kp = Keypair::from_seed(&[2; 32]);
        let cert =
            MembershipCert::from_bytes(&ca_issue(&mut ca, &me.0, &kp.ed_pubkey(), &kp.x_pubkey()))
                .unwrap();

        let mut router = CentralRouter::new(me);
        router.set_auth(OgmAuth::new(kp, cert, anchor));
        router.auth_mut().unwrap().set_time(100);

        assert!(!RouterAdapter::new(&mut router, Duration::ZERO).runtime_config_active());

        let result =
            RouterAdapter::new(&mut router, Duration::ZERO).set_config(RuntimeConfigData {
                lazy_cert_distribution: Some(true),
                ..Default::default()
            });
        assert!(result.is_ok());
        assert!(RouterAdapter::new(&mut router, Duration::ZERO).runtime_config_active());

        let mut tx = [0u8; 1500];
        let ogm = router.poll(Duration::ZERO, &mut tx).unwrap().payload;
        let hdr_len = core::mem::size_of::<BatmanOgmPacket>();
        assert!(
            find_tvlv(&ogm[hdr_len..], TvlvType::Cert).is_none(),
            "must switch to fingerprint-only emission"
        );
        assert!(find_tvlv(&ogm[hdr_len..], TvlvType::CertFp).is_some());
    }

    /// `set_config` with a `link_features` update merges the present flags onto
    /// the interface's current features (leaving unnamed gates untouched),
    /// applies them live, and marks the runtime config active.
    #[test]
    fn set_config_updates_link_features_partially_and_marks_active() {
        let mut router = CentralRouter::new(mac(1));
        // Register interface 0 as startup wiring would; it starts fully
        // participating.
        router.configure_interface_ogm(
            0,
            Duration::from_secs(1),
            Duration::from_secs(8),
            Duration::ZERO,
        );
        assert!(router.link_features(0).tx_ogm);
        assert!(router.link_features(0).rx_ogm);

        // Flip only tx_ogm off — every other gate must stay as it was.
        let result =
            RouterAdapter::new(&mut router, Duration::ZERO).set_config(RuntimeConfigData {
                link_features: Some(LinkFeaturesData {
                    iface_idx: 0,
                    tx_ogm: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            });
        assert!(result.is_ok());

        let f = router.link_features(0);
        assert!(!f.tx_ogm, "named flag flipped");
        assert!(
            f.rx_ogm && f.tx_data && f.rx_data,
            "unnamed flags left untouched"
        );
        assert!(RouterAdapter::new(&mut router, Duration::ZERO).runtime_config_active());
    }

    /// `set_config` with a `tx_keepalive` update arms the heartbeat schedule
    /// at the given cadence, leaving every other gate untouched — the same
    /// partial-merge contract as the plain bool flags.
    #[test]
    fn set_config_tx_keepalive_arms_schedule() {
        let mut router = CentralRouter::new(mac(1));
        router.configure_interface_ogm(
            0,
            Duration::from_secs(1),
            Duration::from_secs(8),
            Duration::ZERO,
        );
        assert!(router.link_features(0).tx_keepalive.is_none());

        let result =
            RouterAdapter::new(&mut router, Duration::ZERO).set_config(RuntimeConfigData {
                link_features: Some(LinkFeaturesData {
                    iface_idx: 0,
                    tx_keepalive: Some(Some(2_000)),
                    ..Default::default()
                }),
                ..Default::default()
            });
        assert!(result.is_ok());

        let f = router.link_features(0);
        assert_eq!(
            f.tx_keepalive.map(|ka| ka.interval_ms),
            Some(2_000),
            "keep-alive armed at the requested cadence"
        );
        assert!(
            f.tx_ogm && f.rx_ogm && f.tx_data && f.rx_data,
            "unnamed flags left untouched"
        );
    }

    /// A `tx_keepalive` update with no interval (the "disabled" oneof
    /// variant) tears down a previously armed schedule.
    #[test]
    fn set_config_tx_keepalive_disable_clears_schedule() {
        let mut router = CentralRouter::new(mac(1));
        router.configure_interface_ogm(
            0,
            Duration::from_secs(1),
            Duration::from_secs(8),
            Duration::ZERO,
        );
        RouterAdapter::new(&mut router, Duration::ZERO)
            .set_config(RuntimeConfigData {
                link_features: Some(LinkFeaturesData {
                    iface_idx: 0,
                    tx_keepalive: Some(Some(2_000)),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .unwrap();
        assert!(router.link_features(0).tx_keepalive.is_some());

        RouterAdapter::new(&mut router, Duration::ZERO)
            .set_config(RuntimeConfigData {
                link_features: Some(LinkFeaturesData {
                    iface_idx: 0,
                    tx_keepalive: Some(None),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .unwrap();
        assert!(
            router.link_features(0).tx_keepalive.is_none(),
            "the disabled update must clear a previously armed schedule"
        );
    }

    /// `link_features_table` reflects a live `set_config` update: after
    /// flipping `tx_ogm` off on interface 0 via `set_config`, the query
    /// projection reports it off while the other gates stay true — proving
    /// the read path actually consults live router state, not a static
    /// default.
    #[test]
    fn link_features_table_reflects_set_config_update() {
        let mut router = CentralRouter::new(mac(1));
        router.configure_interface_ogm(
            0,
            Duration::from_secs(1),
            Duration::from_secs(8),
            Duration::ZERO,
        );
        RouterAdapter::new(&mut router, Duration::ZERO)
            .set_config(RuntimeConfigData {
                link_features: Some(LinkFeaturesData {
                    iface_idx: 0,
                    tx_ogm: Some(false),
                    tx_keepalive: Some(Some(2_000)),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .unwrap();

        let table = RouterAdapter::new(&mut router, Duration::ZERO).link_features_table();
        assert_eq!(table.len(), 1);
        let e = &table[0];
        assert_eq!(e.iface_idx, 0);
        assert!(!e.tx_ogm, "flipped flag reflected");
        assert!(
            e.rx_ogm && e.tx_data && e.rx_data,
            "untouched flags stay true"
        );
        assert_eq!(e.tx_keepalive_interval_ms, Some(2_000));
    }

    /// An interface registered at startup but never touched by `set_config`
    /// reports full participation (the `LinkFeatures` default) rather than
    /// being absent from the table.
    #[test]
    fn link_features_table_defaults_to_full_participation() {
        let mut router = CentralRouter::new(mac(1));
        router.configure_interface_ogm(
            0,
            Duration::from_secs(1),
            Duration::from_secs(8),
            Duration::ZERO,
        );

        let table = RouterAdapter::new(&mut router, Duration::ZERO).link_features_table();
        assert_eq!(table.len(), 1);
        let e = &table[0];
        assert_eq!(e.iface_idx, 0);
        assert!(e.tx_ogm && e.rx_ogm && e.tx_data && e.rx_data);
        assert_eq!(e.tx_keepalive_interval_ms, None);
    }

    /// A `link_features` update targeting an unregistered interface index is
    /// rejected rather than silently ignored.
    #[test]
    fn set_config_link_features_out_of_range_iface_idx_errors() {
        let mut router = CentralRouter::new(mac(1));
        let result =
            RouterAdapter::new(&mut router, Duration::ZERO).set_config(RuntimeConfigData {
                link_features: Some(LinkFeaturesData {
                    iface_idx: 0, // nothing registered yet
                    tx_data: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            });
        let err = result.unwrap_err();
        assert!(err.contains("out of range"), "got: {err}");
        assert!(!RouterAdapter::new(&mut router, Duration::ZERO).runtime_config_active());
    }

    /// `set_config` with no fields set is a no-op that still succeeds.
    #[test]
    fn set_config_with_no_fields_is_a_no_op() {
        let mut router = CentralRouter::new(mac(1));
        let result = RouterAdapter::new(&mut router, Duration::ZERO)
            .set_config(RuntimeConfigData::default());
        assert!(result.is_ok());
        assert!(!RouterAdapter::new(&mut router, Duration::ZERO).runtime_config_active());
    }

    /// An out-of-range interface index is rejected rather than silently
    /// ignored (which is what the underlying router primitive does).
    #[test]
    fn set_config_out_of_range_iface_idx_errors() {
        let mut router = CentralRouter::new(mac(1));
        let result =
            RouterAdapter::new(&mut router, Duration::ZERO).set_config(RuntimeConfigData {
                trickle: Some(TrickleConfigData {
                    iface_idx: wayfinder::MAX_INTERFACES as u32,
                    min_interval_ms: 500,
                    max_interval_ms: 4000,
                }),
                ..Default::default()
            });
        let err = result.unwrap_err();
        assert!(err.contains("out of range"), "got: {err}");
        assert!(!RouterAdapter::new(&mut router, Duration::ZERO).runtime_config_active());
    }

    /// An index within `MAX_INTERFACES` capacity but not yet registered by
    /// startup wiring is rejected too — `SetConfig` may only override an
    /// interface that already exists, not fabricate a new one out of thin air.
    #[test]
    fn set_config_unregistered_iface_idx_errors() {
        let mut router = CentralRouter::new(mac(1));
        router.configure_interface_ogm(
            0,
            Duration::from_secs(1),
            Duration::from_secs(8),
            Duration::ZERO,
        );

        let result =
            RouterAdapter::new(&mut router, Duration::ZERO).set_config(RuntimeConfigData {
                trickle: Some(TrickleConfigData {
                    iface_idx: 1,
                    min_interval_ms: 500,
                    max_interval_ms: 4000,
                }),
                ..Default::default()
            });
        let err = result.unwrap_err();
        assert!(err.contains("out of range"), "got: {err}");
        assert!(!RouterAdapter::new(&mut router, Duration::ZERO).runtime_config_active());
    }

    /// An inverted range (`min_interval_ms > max_interval_ms`) is rejected
    /// rather than silently well-ordered by the underlying `TrickleTimer`, so
    /// an operator who swaps the two arguments gets a clear error instead of a
    /// success response that quietly installed something else.
    #[test]
    fn set_config_inverted_bounds_errors() {
        let mut router = CentralRouter::new(mac(1));
        router.configure_interface_ogm(
            0,
            Duration::from_secs(1),
            Duration::from_secs(8),
            Duration::ZERO,
        );

        let result =
            RouterAdapter::new(&mut router, Duration::ZERO).set_config(RuntimeConfigData {
                trickle: Some(TrickleConfigData {
                    iface_idx: 0,
                    min_interval_ms: 5000,
                    max_interval_ms: 1000,
                }),
                ..Default::default()
            });
        let err = result.unwrap_err();
        assert!(err.contains("min_interval_ms"), "got: {err}");
        assert!(!RouterAdapter::new(&mut router, Duration::ZERO).runtime_config_active());
    }

    /// An empty originator table must fold to all-zero metrics — in particular a
    /// zero (not NaN) mean, since the fold guards the divide-by-zero — and report
    /// the table capacities, not just the (zero) usage.
    #[test]
    fn node_metrics_empty_table_folds_to_zero_not_nan() {
        let mut router = CentralRouter::new(mac(1));
        let m = RouterAdapter::new(&mut router, Duration::from_secs(5)).node_metrics();

        assert_eq!(m.neighbor_count, 0);
        assert_eq!((m.tq_min, m.tq_max), (0, 0));
        assert_eq!(m.tq_mean, 0.0);
        assert_eq!(m.paths_max, 0);
        assert_eq!(m.paths_mean, 0.0);
        assert_eq!(m.uptime_secs, 5);
        assert_eq!((m.originators.used, m.originators.capacity), (0, 128));
    }

    /// The TQ / path-diversity fold reports the true min / mean / max across
    /// originators (not, say, a `tq_min` stuck at its `u32::MAX` seed or a mean
    /// divided by the wrong count).  Direct OGMs at input TQ 255 / 205 / 155 are
    /// stored as 245 / 195 / 145 after the engine's `-10` per-hop penalty, each a
    /// single-path neighbour, so the mean is exactly 195 and path diversity is a
    /// flat 1.
    #[test]
    fn node_metrics_fold_reports_tq_and_path_distribution() {
        let mut router = CentralRouter::new(mac(1));
        feed_direct_ogm(&mut router, mac(2), 1, 255);
        feed_direct_ogm(&mut router, mac(3), 1, 205);
        feed_direct_ogm(&mut router, mac(4), 1, 155);

        let m = RouterAdapter::new(&mut router, Duration::from_secs(10)).node_metrics();

        assert_eq!(m.neighbor_count, 3);
        assert_eq!(m.tq_min, 145);
        assert_eq!(m.tq_max, 245);
        assert_eq!(m.tq_mean, 195.0);
        assert_eq!(m.paths_max, 1);
        assert_eq!(m.paths_mean, 1.0);
        assert_eq!((m.originators.used, m.originators.capacity), (3, 128));
    }

    /// With auth disabled, the cert-distribution occupancy/rate metrics all
    /// read as empty/zero rather than `None` or garbage — mirroring how the
    /// other table-occupancy gauges default when their table is untouched.
    #[test]
    fn node_metrics_cert_fields_zero_without_auth() {
        let mut router = CentralRouter::new(mac(1));
        let m = RouterAdapter::new(&mut router, Duration::from_secs(5)).node_metrics();

        assert_eq!((m.cert_store.used, m.cert_store.capacity), (0, 0));
        assert_eq!(
            (
                m.in_flight_cert_requests.used,
                m.in_flight_cert_requests.capacity
            ),
            (0, 0)
        );
        assert_eq!(
            (m.pending_cert_replies.used, m.pending_cert_replies.capacity),
            (0, 0)
        );
        assert_eq!(m.cert_req_rate, 0.0);
        assert_eq!(m.cert_reply_rate, 0.0);
        assert_eq!(m.untaggable_drop_rate, 0.0);
    }

    /// With auth enabled, a verified neighbor's cert lands in the cert-store
    /// occupancy count reported through `node_metrics` — exercising the real
    /// adapter projection, not just the underlying `OgmAuth` accessor.
    #[test]
    fn node_metrics_reports_cert_store_occupancy_when_auth_enabled() {
        use crate::CertAuthority;
        use wayfinder::auth::OgmAuth;
        use wayfinder::wayfinder_auth::Keypair;
        use wayfinder::wayfinder_auth::MembershipCert;
        use wayfinder::wayfinder_auth::TrustAnchor;

        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None, true);
        ca.set_now_unix(100);
        let anchor = TrustAnchor::from_bytes(&ca.trust_anchor_bytes()).unwrap();

        let me = mac(1);
        let kp1 = Keypair::from_seed(&[2; 32]);
        let cert1 = MembershipCert::from_bytes(&ca_issue(
            &mut ca,
            &me.0,
            &kp1.ed_pubkey(),
            &kp1.x_pubkey(),
        ))
        .unwrap();
        let mut router = CentralRouter::new(me);
        router.set_auth(OgmAuth::new(kp1, cert1, anchor));
        router.auth_mut().unwrap().set_time(100);

        let peer = mac(2);
        let kp2 = Keypair::from_seed(&[3; 32]);
        let cert2 = MembershipCert::from_bytes(&ca_issue(
            &mut ca,
            &peer.0,
            &kp2.ed_pubkey(),
            &kp2.x_pubkey(),
        ))
        .unwrap();
        let mut peer_auth = OgmAuth::new(kp2, cert2, anchor);
        peer_auth.set_time(100);
        let ogm = BatmanOgmPacket {
            packet_type: BatmanPacketType::Ogm.as_u8(),
            version: 5,
            ttl: 50,
            flags: 0,
            seqno: 1u32.to_be(),
            orig: peer,
            reserved: 0,
            tq: 255,
            tvlv_len: 0,
        };
        let mut buf = [0u8; 512];
        let hdr = ogm.as_bytes();
        buf[..hdr.len()].copy_from_slice(hdr);
        let len = peer_auth.augment_ogm(&mut buf, hdr.len()).expect("augment");
        let bytes = link_frame_bytes(
            peer,
            Mac::BROADCAST,
            wayfinder::DEFAULT_BATMAN_ETHER_TYPE,
            &buf[..len],
        );
        let frame = LinkFrame::ref_from_bytes(&bytes).unwrap();
        let mut tx = [0u8; 512];
        router.handle_frame(Duration::ZERO, 0, frame, &mut tx);

        let m = RouterAdapter::new(&mut router, Duration::from_secs(5)).node_metrics();
        assert_eq!(m.cert_store.used, 1);
        assert_eq!(m.cert_store.capacity, 64);
    }

    /// An alarm raised anywhere in the process is readable through the provider
    /// — the same join the log ring rests on, and the reason neither needs a
    /// handle threaded through the router.
    ///
    /// Raised into a scoped board rather than the process-global one: the
    /// harness runs these tests on shared threads, and a test that wrote the
    /// global would be visible to every other test that reads it.
    #[test]
    fn alarms_project_a_raise_from_the_ambient_board() {
        let mut router = CentralRouter::new(mac(1));
        let adapter = RouterAdapter::new(&mut router, Duration::from_secs(0));

        let board = alloc::sync::Arc::new(wayfinder_alarm::SharedBoard::new());
        let projected = wayfinder_alarm::with_board(&board, || {
            board.raise_at(
                wayfinder_alarm::AlarmKind::ManagementAuthFailures,
                wayfinder_alarm::Subject::Node(wayfinder_alarm::NodeId::new(&[0xab, 0xcd])),
                wayfinder_alarm::Severity::Warning,
                format_args!("attempts=3"),
                1_000,
            );
            adapter.alarms()
        });

        assert_eq!(projected.alarms.len(), 1);
        let alarm = &projected.alarms[0];
        assert_eq!(alarm.kind, AlarmKindData::ManagementAuthFailures);
        assert_eq!(alarm.severity, AlarmSeverityData::Warning);
        assert_eq!(
            alarm.subject,
            AlarmSubjectData::Peer(alloc::vec![0xab, 0xcd])
        );
        assert_eq!(alarm.first_ms, 1_000);
        assert_eq!(alarm.count, 1);
        assert_eq!(alarm.detail, "attempts=3");
    }

    /// A condition that has gone quiet past its hold window is still on the
    /// board, reported as inactive rather than dropped.
    ///
    /// That distinction is the whole point of latching: an operator who
    /// attaches after a burst ended must still learn it happened, and an
    /// adapter that filtered on `active` would delete exactly that.
    #[test]
    fn alarms_report_a_quiet_condition_as_latched_but_inactive() {
        let mut router = CentralRouter::new(mac(1));
        let adapter = RouterAdapter::new(&mut router, Duration::from_secs(0));

        let board = alloc::sync::Arc::new(wayfinder_alarm::SharedBoard::new());
        board.raise_at(
            wayfinder_alarm::AlarmKind::LinkErrors,
            wayfinder_alarm::Subject::Interface(2),
            wayfinder_alarm::Severity::Warning,
            format_args!("errors=5"),
            0,
        );

        // Inside the hold window: still firing.
        let fresh = wayfinder_alarm::with_board(&board, || adapter.alarms());
        assert!(fresh.alarms[0].active);

        // The board's `now_ms` comes from the shared uptime clock, which a test
        // cannot wind forward, so the staleness check is made against the row's
        // own hold window directly — the same computation the projection runs.
        let hold = wayfinder_alarm::Severity::Warning.hold_ms();
        let stale = board.snapshot_at(hold + 1);
        assert_eq!(
            stale.alarms.len(),
            1,
            "a quiet condition stays on the board"
        );
        assert!(!stale.alarms[0].is_active(stale.now_ms));
    }

    /// A record written through the logging crate is readable through the
    /// provider — the one join this whole feature rests on, since the adapter
    /// reaches the ring through a `static` rather than through anything the
    /// router hands it.
    #[test]
    fn logs_projects_records_from_the_global_ring() {
        let mut router = CentralRouter::new(mac(1));
        let adapter = RouterAdapter::new(&mut router, Duration::from_secs(0));

        let start = adapter.logs(0, 0).next_seq;
        wayfinder_log::record(
            wayfinder_log::Level::Warn,
            "wayfinder_server::adapter::test",
            "drop: no route",
        );

        let batch = adapter.logs(start, 0);
        let record = batch
            .records
            .iter()
            .find(|r| r.target == "wayfinder_server::adapter::test")
            .expect("the record written above is visible through the provider");
        assert_eq!(record.level, LogLevelData::Warn);
        assert_eq!(record.message, "drop: no route");
        assert!(batch.next_seq > start);
    }

    /// Setting a filter reports back the spec now in force, and a spec that
    /// doesn't parse is an error carrying the parser's own reason.
    #[test]
    fn set_log_level_installs_a_valid_spec_and_rejects_an_invalid_one() {
        let mut router = CentralRouter::new(mac(1));
        let mut adapter = RouterAdapter::new(&mut router, Duration::from_secs(0));

        assert_eq!(
            adapter.set_log_level("info,batman=trace"),
            Ok("info,batman=trace".to_string())
        );

        let error = adapter
            .set_log_level("wayfinder=verbose")
            .expect_err("an unknown level must be refused");
        assert!(error.contains("unknown log level"), "got {error:?}");

        // Restored so this test leaves the process-wide filter as it found it —
        // it is shared with every other test in the binary.
        let _ = adapter.set_log_level(wayfinder_log::DEFAULT_SPEC);
    }

    /// With auth disabled, the security view reports it off and carries no
    /// per-node state.
    #[test]
    fn security_status_reports_auth_disabled_by_default() {
        let mut router = CentralRouter::new(mac(1));
        let s = RouterAdapter::new(&mut router, Duration::from_secs(0)).security_status();
        assert!(!s.auth_enabled);
        assert_eq!(s.mesh_id, 0);
        assert!(s.node_mac.is_empty());
        assert!(s.nodes.is_empty());
    }

    /// With auth on, the view reports the mesh header and, per originator,
    /// whether its signed OGM verified (with cert expiry) and whether it is
    /// revoked — the revoked node staying visible even after routing purges it.
    #[test]
    fn security_status_reports_verified_expiry_and_revocation() {
        use crate::CertAuthority;
        use wayfinder::auth::OgmAuth;
        use wayfinder::wayfinder_auth::Keypair;
        use wayfinder::wayfinder_auth::MembershipCert;
        use wayfinder::wayfinder_auth::TrustAnchor;

        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None, true);
        ca.set_now_unix(100);
        let anchor = TrustAnchor::from_bytes(&ca.trust_anchor_bytes()).unwrap();

        // Self node mac(1), authenticated by the CA (cert not_after = 100 + 1000).
        let me = mac(1);
        let kp1 = Keypair::from_seed(&[2; 32]);
        let cert1 = MembershipCert::from_bytes(&ca_issue(
            &mut ca,
            &me.0,
            &kp1.ed_pubkey(),
            &kp1.x_pubkey(),
        ))
        .unwrap();
        let mut router = CentralRouter::new(me);
        router.set_auth(OgmAuth::new(kp1, cert1, anchor));
        router.auth_mut().unwrap().set_time(100);

        // Peer mac(2) emits a signed OGM; feed it so the router verifies + caches
        // it as an originator carrying its cert expiry.
        let peer = mac(2);
        let kp2 = Keypair::from_seed(&[3; 32]);
        let cert2 = MembershipCert::from_bytes(&ca_issue(
            &mut ca,
            &peer.0,
            &kp2.ed_pubkey(),
            &kp2.x_pubkey(),
        ))
        .unwrap();
        let mut peer_auth = OgmAuth::new(kp2, cert2, anchor);
        peer_auth.set_time(100);
        let ogm = BatmanOgmPacket {
            packet_type: BatmanPacketType::Ogm.as_u8(),
            version: 5,
            ttl: 50,
            flags: 0,
            seqno: 1u32.to_be(),
            orig: peer,
            reserved: 0,
            tq: 255,
            tvlv_len: 0,
        };
        let mut buf = [0u8; 512];
        let hdr = ogm.as_bytes();
        buf[..hdr.len()].copy_from_slice(hdr);
        let len = peer_auth.augment_ogm(&mut buf, hdr.len()).expect("augment");
        let bytes = link_frame_bytes(
            peer,
            Mac::BROADCAST,
            wayfinder::DEFAULT_BATMAN_ETHER_TYPE,
            &buf[..len],
        );
        let frame = LinkFrame::ref_from_bytes(&bytes).unwrap();
        let mut tx = [0u8; 512];
        router.handle_frame(Duration::ZERO, 0, frame, &mut tx);
        assert!(
            router
                .auth()
                .unwrap()
                .neighbors()
                .iter()
                .any(|n| n.cert.mac == peer),
            "peer became a verified originator"
        );

        let s = RouterAdapter::new(&mut router, Duration::from_secs(0)).security_status();
        assert!(s.auth_enabled);
        assert_eq!(s.mesh_id, 0xABCD);
        assert_eq!(s.node_mac, me.0.to_vec());
        assert_eq!(s.cert_not_after, 1100, "own cert expiry = now + ttl");
        let row = s
            .nodes
            .iter()
            .find(|n| n.node_id == peer.0.to_vec())
            .expect("peer row present");
        assert!(row.verified);
        assert_eq!(row.cert_not_after, 1100);
        assert!(!row.revoked);
        assert_eq!(
            row.revocation_not_after, 0,
            "a node we hold no revocation for has no enforcement window"
        );

        // Revocation is two acts by two owners now: the authority signs and
        // persists, the router ingests and floods. Driven here exactly as the
        // authority task and the driver loop drive them.
        let record = {
            let mut authority = crate::AuthorityAdapter::new(
                &mut ca,
                tokio::sync::watch::channel(crate::RouterFacts {
                    unix_secs: 1_700_000_000,
                    auth_present: true,
                })
                .1,
            );
            authority.revoke_node(&peer.0).expect("revoke");
            authority
                .finish()
                .pop()
                .expect("a successful revoke signs a record for the router to flood")
        };
        router.ingest_revocation(&record, Duration::from_secs(0));
        let s = RouterAdapter::new(&mut router, Duration::from_secs(0)).security_status();
        assert_eq!(s.revocation_count, 1);
        let row = s
            .nodes
            .iter()
            .find(|n| n.node_id == peer.0.to_vec())
            .expect("revoked peer still listed");
        assert!(
            row.revoked,
            "revoked node stays visible in the security view"
        );
        // The record the CA signs runs to `now + cert_ttl`, so this is also
        // when the row stops saying "revoked" and disappears: the one number
        // that answers "how long will I keep seeing this?".
        assert_eq!(
            row.revocation_not_after, 1100,
            "the row carries when the revocation stops being enforced"
        );
    }

    // ── Persisting security settings ───────────────────────────────────────────

    /// A settings store that records what it was asked to persist, and can be
    /// made to fail, so a test can tell "recorded then applied" from "applied
    /// and hopefully recorded".
    #[derive(Default)]
    struct RecordingStore {
        settings: NodeSettings,
        /// Every update handed to `persist`, in order.
        writes: alloc::vec::Vec<NodeSettings>,
        /// When set, `persist` fails with this message and records nothing —
        /// standing in for a full disk or an unwritable path.
        fail_with: Option<String>,
    }

    impl SettingsStore for RecordingStore {
        fn settings(&self) -> &NodeSettings {
            &self.settings
        }

        fn persist(&mut self, update: NodeSettings) -> Result<(), String> {
            if let Some(message) = &self.fail_with {
                return Err(message.clone());
            }
            self.writes.push(update.clone());
            self.settings.merge(update);
            Ok(())
        }
    }

    /// The fail-closed gate reaches the router *and* the store, so it is in
    /// force now and still in force after a restart.
    #[test]
    fn set_config_require_auth_applies_and_persists() {
        let mut router = CentralRouter::new(mac(1));
        let mut store = RecordingStore::default();

        RouterAdapter::new(&mut router, Duration::ZERO)
            .with_settings(&mut store)
            .set_config(RuntimeConfigData {
                require_auth: Some(true),
                ..Default::default()
            })
            .unwrap();

        assert!(router.require_auth(), "in force now");
        assert_eq!(
            store.settings().require_auth,
            Some(true),
            "and recorded for next boot"
        );
    }

    /// Both posture flags in one request are recorded as a single write, so a
    /// crash between them cannot leave one durable and the other not.
    #[test]
    fn set_config_persists_both_posture_flags_in_one_write() {
        let mut router = CentralRouter::new(mac(1));
        let mut store = RecordingStore::default();

        RouterAdapter::new(&mut router, Duration::ZERO)
            .with_settings(&mut store)
            .set_config(RuntimeConfigData {
                require_auth: Some(true),
                lazy_cert_distribution: Some(true),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(store.writes.len(), 1, "one write, not two");
        assert_eq!(store.writes[0].require_auth, Some(true));
        assert_eq!(store.writes[0].lazy_cert_distribution, Some(true));
    }

    /// A change that cannot be recorded is refused outright and leaves the
    /// router alone: reporting success would tell an operator a security
    /// setting is in force that the next restart silently discards.
    #[test]
    fn set_config_that_cannot_persist_leaves_the_router_untouched() {
        let mut router = CentralRouter::new(mac(1));
        let mut store = RecordingStore {
            fail_with: Some("disk full".into()),
            ..Default::default()
        };

        let result = RouterAdapter::new(&mut router, Duration::ZERO)
            .with_settings(&mut store)
            .set_config(RuntimeConfigData {
                require_auth: Some(true),
                ..Default::default()
            });

        assert!(result.is_err());
        assert!(
            !router.require_auth(),
            "the router must not run a setting the node could not record"
        );
    }

    /// A node with no store configured still applies the change — it simply
    /// cannot carry it across a restart, which is the documented behavior of a
    /// node without a runtime state path, not an error.
    #[test]
    fn set_config_without_a_store_still_applies_in_memory() {
        let mut router = CentralRouter::new(mac(1));

        RouterAdapter::new(&mut router, Duration::ZERO)
            .set_config(RuntimeConfigData {
                require_auth: Some(true),
                ..Default::default()
            })
            .unwrap();

        assert!(router.require_auth());
    }

    /// Per-interface knobs are deliberately *not* persisted: they are keyed by
    /// a position in the startup config's link list, so a stored override would
    /// re-point at a different link the moment an operator reorders one.
    #[test]
    fn set_config_does_not_persist_per_interface_knobs() {
        let mut router = CentralRouter::new(mac(1));
        router.configure_interface_ogm(
            0,
            Duration::from_secs(1),
            Duration::from_secs(8),
            Duration::ZERO,
        );
        let mut store = RecordingStore::default();

        RouterAdapter::new(&mut router, Duration::ZERO)
            .with_settings(&mut store)
            .set_config(RuntimeConfigData {
                trickle: Some(TrickleConfigData {
                    iface_idx: 0,
                    min_interval_ms: 500,
                    max_interval_ms: 4000,
                }),
                ..Default::default()
            })
            .unwrap();

        assert!(store.writes.is_empty());
    }

    /// An identity installed over the management API is recorded verbatim, so
    /// a node enrolled at runtime comes back enrolled rather than reverting to
    /// an unauthenticated one.
    #[test]
    fn set_auth_persists_the_installed_identity() {
        let mut router = CentralRouter::new(mac(1));
        let mut ca = crate::CertAuthority::new(&[9; 32], 0xABCD, 10_000, None, true);
        ca.set_now_unix(1_000);
        let kp = wayfinder::wayfinder_auth::Keypair::from_seed(&[3; 32]);
        let cert = ca_issue(
            &mut ca,
            &kp.derived_mac().0,
            &kp.ed_pubkey(),
            &kp.x_pubkey(),
        );
        let anchor = ca.trust_anchor_bytes();
        let mut store = RecordingStore::default();

        RouterAdapter::new(&mut router, Duration::ZERO)
            .with_epoch_unix(Duration::from_secs(1_000))
            .with_settings(&mut store)
            .set_auth(&[3; 32], &cert, &anchor)
            .unwrap();

        let identity = store
            .settings()
            .identity
            .clone()
            .expect("the identity was recorded");
        assert_eq!(identity.seed, [3u8; 32].to_vec());
        assert_eq!(identity.cert, cert);
        assert_eq!(identity.trust_anchor, anchor);
    }

    /// A node under a revocation refuses a certificate that revocation still
    /// cancels, rather than installing one that leaves it inert while
    /// reporting itself enrolled.
    ///
    /// The failure this prevents is a node that looks healthy locally and is
    /// invisible to every peer holding the record — which reads as a routing
    /// fault and is not one.
    #[test]
    fn set_auth_refuses_a_certificate_the_revocation_still_cancels() {
        use wayfinder::wayfinder_auth::Authority;

        let authority = Authority::from_seed(&[9; 32], 0xABCD);
        let kp = wayfinder::wayfinder_auth::Keypair::from_seed(&[3; 32]);
        let node = kp.derived_mac();

        let mut router = CentralRouter::new(node);
        // Enrolled, then revoked at 1_000.
        let old_cert = authority.issue_cert(node, kp.ed_pubkey(), kp.x_pubkey(), 0, 100_000);
        router.set_auth(wayfinder::auth::OgmAuth::new(
            wayfinder::wayfinder_auth::Keypair::from_seed(&[3; 32]),
            old_cert,
            authority.trust_anchor(),
        ));
        router.auth_mut().unwrap().set_time(2_000);
        router.ingest_revocation(&authority.revoke(node, 1_000, 100_000), Duration::ZERO);
        assert!(router.self_revoked());

        let anchor = authority.trust_anchor();
        let anchor_bytes = anchor.to_bytes().to_vec();
        let mut store = RecordingStore::default();

        // A certificate from before the revocation is refused...
        let stale = authority.issue_cert(node, kp.ed_pubkey(), kp.x_pubkey(), 500, 100_000);
        let err = RouterAdapter::new(&mut router, Duration::ZERO)
            .with_epoch_unix(Duration::from_secs(2_000))
            .with_settings(&mut store)
            .set_auth(&[3; 32], stale.as_bytes(), &anchor_bytes)
            .expect_err("a cancelled certificate is refused");
        assert!(err.contains("revoked"), "the reason names the cause: {err}");
        assert!(router.auth_locked(), "and the node stays inert");

        // ...while one issued after it re-admits the node and clears the
        // stored record in the same write.
        let fresh = authority.issue_cert(node, kp.ed_pubkey(), kp.x_pubkey(), 1_500, 100_000);
        RouterAdapter::new(&mut router, Duration::ZERO)
            .with_epoch_unix(Duration::from_secs(2_000))
            .with_settings(&mut store)
            .set_auth(&[3; 32], fresh.as_bytes(), &anchor_bytes)
            .expect("a certificate issued after the revocation re-admits the node");
        assert!(!router.self_revoked());
        assert!(!router.auth_locked());
        assert!(
            store.settings().self_revocation.is_none(),
            "the stored record is cleared, or the next boot would re-lock the node"
        );
    }

    /// Online enrollment needs to name the keys it is asking a provider to
    /// certify, so the node reports them — and reports them *before* it is
    /// enrolled, which is the only moment at which they are needed.
    #[test]
    fn security_status_reports_the_identity_of_an_un_enrolled_node() {
        let mut router = CentralRouter::new(mac(1));
        let kp = wayfinder::wayfinder_auth::Keypair::from_seed(&[3; 32]);
        let mut identity_seed = Some([3u8; 32]);

        let status = RouterAdapter::new(&mut router, Duration::ZERO)
            .with_identity(&mut identity_seed)
            .security_status();

        assert!(!status.auth_enabled, "no certificate yet");
        assert_eq!(status.own_ed_pubkey, kp.ed_pubkey().to_vec());
        assert_eq!(status.own_x_pubkey, kp.x_pubkey().to_vec());
    }

    /// The certificate a node runs under is readable over the management API,
    /// as the exact bytes it was installed with, paired with the anchor it
    /// chains to. That pairing is the point: a caller gets a usable credential
    /// from one request, rather than a certificate it must then go and find an
    /// anchor for.
    ///
    /// Read from live router state, so this is the certificate the node is
    /// *running* under — an `SetAuth` install and a file loaded at startup are
    /// indistinguishable here, which is what makes one client work against
    /// both.
    #[test]
    fn own_cert_reports_the_installed_pair_verbatim() {
        let mut router = CentralRouter::new(mac(1));
        let mut ca = crate::CertAuthority::new(&[9; 32], 0xABCD, 10_000, None, true);
        ca.set_now_unix(1_000);
        let kp = wayfinder::wayfinder_auth::Keypair::from_seed(&[3; 32]);
        let cert = ca_issue(
            &mut ca,
            &kp.derived_mac().0,
            &kp.ed_pubkey(),
            &kp.x_pubkey(),
        );
        let anchor = ca.trust_anchor_bytes();
        let mut store = RecordingStore::default();
        let mut adapter = RouterAdapter::new(&mut router, Duration::ZERO)
            .with_epoch_unix(Duration::from_secs(1_000))
            .with_settings(&mut store);
        adapter.set_auth(&[3; 32], &cert, &anchor).unwrap();

        let pair = adapter.own_cert().expect("the node is certified");

        assert_eq!(pair.cert, cert);
        assert_eq!(pair.trust_anchor, anchor);
    }

    /// A node with no auth installed has no certificate to report, and says so
    /// rather than reporting an empty one — a client that presented an empty
    /// certificate would be refused by the far end for a reason that named
    /// neither this node nor the missing enrollment.
    #[test]
    fn own_cert_is_absent_on_an_uncertified_node() {
        let mut router = CentralRouter::new(mac(1));
        let mut identity_seed = Some([3u8; 32]);

        let adapter =
            RouterAdapter::new(&mut router, Duration::ZERO).with_identity(&mut identity_seed);

        assert!(
            adapter.own_cert().is_none(),
            "an identity is not a certificate: the node has a key but nothing signed it"
        );
    }

    /// A node whose identity was never handed to the adapter reports none,
    /// rather than an empty key that would look like a real one.
    #[test]
    fn security_status_reports_no_identity_when_the_node_has_none() {
        let mut router = CentralRouter::new(mac(1));

        let status = RouterAdapter::new(&mut router, Duration::ZERO).security_status();

        assert!(status.own_ed_pubkey.is_empty());
        assert!(status.own_x_pubkey.is_empty());
    }

    /// The install half of online enrollment: a certificate arrives for the key
    /// the node already has, with no seed. The node keeps its identity — and so
    /// its MAC, which is derived from it — and simply becomes authenticated.
    #[test]
    fn set_auth_without_a_seed_certifies_the_existing_identity() {
        let mut router = CentralRouter::new(mac(1));
        let mut ca = crate::CertAuthority::new(&[9; 32], 0xABCD, 10_000, None, true);
        ca.set_now_unix(1_000);
        let kp = wayfinder::wayfinder_auth::Keypair::from_seed(&[3; 32]);
        // Bound to the MAC the node is *running* under, not the one its key
        // derives to: that is what an enrolling node asks for, since its
        // address on the mesh must not change underneath it.
        let cert = ca_issue(&mut ca, mac(1).as_bytes(), &kp.ed_pubkey(), &kp.x_pubkey());
        let anchor = ca.trust_anchor_bytes();
        let mut store = RecordingStore::default();
        let mut identity_seed = Some([3u8; 32]);

        RouterAdapter::new(&mut router, Duration::ZERO)
            .with_epoch_unix(Duration::from_secs(1_000))
            .with_identity(&mut identity_seed)
            .with_settings(&mut store)
            .set_auth(&[], &cert, &anchor)
            .unwrap();

        assert!(router.auth().is_some(), "the node is now authenticated");
        let identity = store
            .settings()
            .identity
            .clone()
            .expect("the identity was recorded");
        assert_eq!(
            identity.seed,
            [3u8; 32].to_vec(),
            "the seed it already had is what gets recorded, so the next boot \
             comes up as the same node"
        );
        assert_eq!(identity.cert, cert);
    }

    /// `set_auth` writes the seed it actually installed back into the caller's
    /// slot, not just into persisted settings — the piece that closes the
    /// self-key staleness window (§3.2): the TLS accept loop's per-connection
    /// authorization snapshot reads the very same slot fresh on every
    /// connection, so a seed this call rotates *away* from must stop being
    /// `own_key` immediately, not only after the process restarts.
    ///
    /// Covers both shapes `set_auth` accepts: a non-empty seed installs a
    /// wholesale new identity (the slot must become the *new* seed), and an
    /// empty seed certifies the identity already in the slot in place (the
    /// slot must still read back the *same* seed afterward — this is not
    /// about the value changing, only about the write-back path always
    /// running on success).
    #[test]
    fn set_auth_writes_the_installed_seed_back_to_the_caller() {
        let old_seed = [3u8; 32];
        let new_seed = [4u8; 32];

        // A wholesale identity replacement: the slot must end up holding the
        // *new* seed, not the one it started with.
        {
            let mut router = CentralRouter::new(mac(1));
            let mut ca = crate::CertAuthority::new(&[9; 32], 0xABCD, 10_000, None, true);
            ca.set_now_unix(1_000);
            let new_kp = wayfinder::wayfinder_auth::Keypair::from_seed(&new_seed);
            let cert = ca_issue(
                &mut ca,
                &new_kp.derived_mac().0,
                &new_kp.ed_pubkey(),
                &new_kp.x_pubkey(),
            );
            let anchor = ca.trust_anchor_bytes();
            let mut identity_seed = Some(old_seed);

            RouterAdapter::new(&mut router, Duration::ZERO)
                .with_epoch_unix(Duration::from_secs(1_000))
                .with_identity(&mut identity_seed)
                .set_auth(&new_seed, &cert, &anchor)
                .unwrap();

            assert_eq!(
                identity_seed,
                Some(new_seed),
                "the slot must reflect the seed just installed, not the one it \
                 started with — this is the write-back that closes the \
                 self-key staleness window"
            );
        }

        // Certifying the existing identity in place (empty seed): the slot
        // still reads back the same seed, and the write-back path still runs.
        {
            let mut router = CentralRouter::new(mac(1));
            let mut ca = crate::CertAuthority::new(&[9; 32], 0xABCD, 10_000, None, true);
            ca.set_now_unix(1_000);
            let kp = wayfinder::wayfinder_auth::Keypair::from_seed(&old_seed);
            let cert = ca_issue(&mut ca, mac(1).as_bytes(), &kp.ed_pubkey(), &kp.x_pubkey());
            let anchor = ca.trust_anchor_bytes();
            let mut identity_seed = Some(old_seed);

            RouterAdapter::new(&mut router, Duration::ZERO)
                .with_epoch_unix(Duration::from_secs(1_000))
                .with_identity(&mut identity_seed)
                .set_auth(&[], &cert, &anchor)
                .unwrap();

            assert_eq!(identity_seed, Some(old_seed));
        }
    }

    /// Asking a node to certify an identity it does not have is refused with a
    /// reason, rather than silently installing a certificate for some key
    /// nobody holds.
    #[test]
    fn set_auth_without_a_seed_needs_an_identity_to_certify() {
        let mut router = CentralRouter::new(mac(1));
        let mut ca = crate::CertAuthority::new(&[9; 32], 0xABCD, 10_000, None, true);
        ca.set_now_unix(1_000);
        let kp = wayfinder::wayfinder_auth::Keypair::from_seed(&[3; 32]);
        let cert = ca_issue(&mut ca, mac(1).as_bytes(), &kp.ed_pubkey(), &kp.x_pubkey());
        let anchor = ca.trust_anchor_bytes();

        let err = RouterAdapter::new(&mut router, Duration::ZERO)
            .set_auth(&[], &cert, &anchor)
            .expect_err("no identity to certify");

        assert!(err.contains("identity"), "got: {err}");
        assert!(router.auth().is_none());
    }

    /// Malformed identity material is rejected before anything is written, so
    /// a bad request cannot leave an unusable identity for the next boot to
    /// trip over.
    #[test]
    fn set_auth_records_nothing_when_the_material_is_malformed() {
        let mut router = CentralRouter::new(mac(1));
        let mut store = RecordingStore::default();

        let result = RouterAdapter::new(&mut router, Duration::ZERO)
            .with_settings(&mut store)
            .set_auth(&[3; 32], b"not a cert", b"not an anchor");

        assert!(result.is_err());
        assert!(store.writes.is_empty());
    }

    /// A cert that verifies as well-formed but does not chain to the given
    /// trust anchor (signed by a different mesh's root key) must not be
    /// installed — that is exactly the forgery `verify_cert` exists to catch,
    /// so `set_auth` has to consult it rather than trusting parseable bytes.
    #[test]
    fn set_auth_rejects_a_cert_with_a_bad_signature() {
        let mut router = CentralRouter::new(mac(1));
        let mut ca = crate::CertAuthority::new(&[9; 32], 0xABCD, 10_000, None, true);
        ca.set_now_unix(1_000);
        let kp = wayfinder::wayfinder_auth::Keypair::from_seed(&[3; 32]);
        let cert = ca_issue(&mut ca, mac(1).as_bytes(), &kp.ed_pubkey(), &kp.x_pubkey());

        // A different root key, same mesh id: the anchor a node would hold if
        // it belonged to a *different* mesh that happened to share an id.
        let other_ca = crate::CertAuthority::new(&[99; 32], 0xABCD, 10_000, None, true);
        let foreign_anchor = other_ca.trust_anchor_bytes();
        let mut store = RecordingStore::default();

        let err = RouterAdapter::new(&mut router, Duration::ZERO)
            .with_epoch_unix(Duration::from_secs(1_000))
            .with_settings(&mut store)
            .set_auth(&[3; 32], &cert, &foreign_anchor)
            .expect_err("cert does not chain to this anchor");

        assert!(err.contains("signature"), "got: {err}");
        assert!(router.auth().is_none(), "never installed");
        assert!(store.writes.is_empty(), "never persisted");
    }

    /// A cert minted for one mesh must not be accepted by a node whose trust
    /// anchor names a different mesh, even when both anchors share a root key
    /// — mesh segregation is enforced by id, not merely by signature.
    #[test]
    fn set_auth_rejects_a_cert_for_the_wrong_mesh() {
        let mut router = CentralRouter::new(mac(1));
        let mut ca = crate::CertAuthority::new(&[9; 32], 0xABCD, 10_000, None, true);
        ca.set_now_unix(1_000);
        let kp = wayfinder::wayfinder_auth::Keypair::from_seed(&[3; 32]);
        let cert = ca_issue(&mut ca, mac(1).as_bytes(), &kp.ed_pubkey(), &kp.x_pubkey());

        // Same root key, a different mesh id — a client presenting the wrong
        // anchor for the cert it holds.
        let mut anchor = TrustAnchor::from_bytes(&ca.trust_anchor_bytes()).unwrap();
        anchor.mesh_id = 0x1234;
        let wrong_mesh_anchor = anchor.to_bytes().to_vec();
        let mut store = RecordingStore::default();

        let err = RouterAdapter::new(&mut router, Duration::ZERO)
            .with_epoch_unix(Duration::from_secs(1_000))
            .with_settings(&mut store)
            .set_auth(&[3; 32], &cert, &wrong_mesh_anchor)
            .expect_err("cert is for a different mesh");

        assert!(err.contains("mesh"), "got: {err}");
        assert!(router.auth().is_none(), "never installed");
        assert!(store.writes.is_empty(), "never persisted");
    }

    /// A cert past its `not_after` must be refused even though every other
    /// field checks out — an expired cert is exactly the case the validity
    /// window exists to catch.
    #[test]
    fn set_auth_rejects_an_expired_cert() {
        let mut router = CentralRouter::new(mac(1));
        let mut ca = crate::CertAuthority::new(&[9; 32], 0xABCD, 10, None, true);
        ca.set_now_unix(1_000);
        let kp = wayfinder::wayfinder_auth::Keypair::from_seed(&[3; 32]);
        // not_before = 1_000, not_after = 1_010.
        let cert = ca_issue(&mut ca, mac(1).as_bytes(), &kp.ed_pubkey(), &kp.x_pubkey());
        let anchor = ca.trust_anchor_bytes();
        let mut store = RecordingStore::default();

        let err = RouterAdapter::new(&mut router, Duration::ZERO)
            // Well past not_after.
            .with_epoch_unix(Duration::from_secs(2_000))
            .with_settings(&mut store)
            .set_auth(&[3; 32], &cert, &anchor)
            .expect_err("cert has expired");

        assert!(err.contains("expired"), "got: {err}");
        assert!(router.auth().is_none(), "never installed");
        assert!(store.writes.is_empty(), "never persisted");
    }

    /// A cert whose `not_before` is still in the future must be refused —
    /// installing it now would let the node authenticate before the CA meant
    /// it to.
    #[test]
    fn set_auth_rejects_a_not_yet_valid_cert() {
        let mut router = CentralRouter::new(mac(1));
        let mut ca = crate::CertAuthority::new(&[9; 32], 0xABCD, 10_000, None, true);
        ca.set_now_unix(1_000);
        let kp = wayfinder::wayfinder_auth::Keypair::from_seed(&[3; 32]);
        // not_before = 1_000.
        let cert = ca_issue(&mut ca, mac(1).as_bytes(), &kp.ed_pubkey(), &kp.x_pubkey());
        let anchor = ca.trust_anchor_bytes();
        let mut store = RecordingStore::default();

        let err = RouterAdapter::new(&mut router, Duration::ZERO)
            // Adapter clock defaults to unix time 0, well before not_before.
            .with_settings(&mut store)
            .set_auth(&[3; 32], &cert, &anchor)
            .expect_err("cert is not yet valid");

        assert!(err.contains("not yet valid"), "got: {err}");
        assert!(router.auth().is_none(), "never installed");
        assert!(store.writes.is_empty(), "never persisted");
    }

    /// A certificate that verifies against the anchor but names a *different*
    /// key than the one actually being installed must be refused — otherwise
    /// the node ends up signing every OGM under a certificate that does not
    /// name its own key, which every peer then rejects while the node itself
    /// reports `auth_enabled: true`. Applies to both `set_auth` shapes: here,
    /// a wholesale identity install (a seed is supplied) with a cert for
    /// somebody else's key.
    #[test]
    fn set_auth_rejects_a_cert_for_the_wrong_key() {
        let mut router = CentralRouter::new(mac(1));
        let mut ca = crate::CertAuthority::new(&[9; 32], 0xABCD, 10_000, None, true);
        ca.set_now_unix(1_000);
        // The cert names a key other than the one the request is installing.
        let other_kp = wayfinder::wayfinder_auth::Keypair::from_seed(&[4; 32]);
        let cert = ca_issue(
            &mut ca,
            mac(1).as_bytes(),
            &other_kp.ed_pubkey(),
            &other_kp.x_pubkey(),
        );
        let anchor = ca.trust_anchor_bytes();
        let mut store = RecordingStore::default();

        let err = RouterAdapter::new(&mut router, Duration::ZERO)
            .with_epoch_unix(Duration::from_secs(1_000))
            .with_settings(&mut store)
            .set_auth(&[3; 32], &cert, &anchor)
            .expect_err("cert names a different key than the seed being installed");

        assert!(err.contains("key"), "got: {err}");
        assert!(router.auth().is_none(), "never installed");
        assert!(store.writes.is_empty(), "never persisted");
    }

    /// Certifying the identity already held (empty seed) must be refused when
    /// the certificate is bound to a *different* MAC than the one this node
    /// actually runs under — the scenario the enrollment flow opens up: a
    /// provider's operator approving the wrong pending row, or a MAC
    /// collision in its queue, must not leave this node signing OGMs under a
    /// certificate for somebody else's address.
    #[test]
    fn set_auth_rejects_a_cert_for_the_wrong_mac_when_certifying_in_place() {
        let mut router = CentralRouter::new(mac(1));
        let mut ca = crate::CertAuthority::new(&[9; 32], 0xABCD, 10_000, None, true);
        ca.set_now_unix(1_000);
        let kp = wayfinder::wayfinder_auth::Keypair::from_seed(&[3; 32]);
        // Bound to a MAC other than the one the router actually runs under.
        let cert = ca_issue(&mut ca, mac(2).as_bytes(), &kp.ed_pubkey(), &kp.x_pubkey());
        let anchor = ca.trust_anchor_bytes();
        let mut store = RecordingStore::default();
        let mut identity_seed = Some([3u8; 32]);

        let err = RouterAdapter::new(&mut router, Duration::ZERO)
            .with_epoch_unix(Duration::from_secs(1_000))
            .with_identity(&mut identity_seed)
            .with_settings(&mut store)
            .set_auth(&[], &cert, &anchor)
            .expect_err("cert is bound to a MAC other than the one this router runs under");

        assert!(err.to_lowercase().contains("mac"), "got: {err}");
        assert!(router.auth().is_none(), "never installed");
        assert!(store.writes.is_empty(), "never persisted");
    }

    /// A wholesale identity install (a seed is supplied) is exempt from the
    /// MAC check above: it is exactly how a node's MAC is meant to change,
    /// taking effect once `wayfinder-tap` re-derives it from the newly
    /// installed certificate on the next boot.
    #[test]
    fn set_auth_with_a_seed_allows_a_new_mac() {
        let mut router = CentralRouter::new(mac(1));
        let mut ca = crate::CertAuthority::new(&[9; 32], 0xABCD, 10_000, None, true);
        ca.set_now_unix(1_000);
        let kp = wayfinder::wayfinder_auth::Keypair::from_seed(&[3; 32]);
        // Bound to a MAC different from the router's current identity —
        // exactly what a fresh re-key looks like.
        let cert = ca_issue(&mut ca, mac(2).as_bytes(), &kp.ed_pubkey(), &kp.x_pubkey());
        let anchor = ca.trust_anchor_bytes();
        let mut store = RecordingStore::default();

        RouterAdapter::new(&mut router, Duration::ZERO)
            .with_epoch_unix(Duration::from_secs(1_000))
            .with_settings(&mut store)
            .set_auth(&[3; 32], &cert, &anchor)
            .unwrap();

        assert!(router.auth().is_some());
    }

    /// The posture is reported even with auth disabled: `require_auth` on a
    /// node with no cert is exactly what keeps it off the mesh, so hiding it
    /// would hide the reason the node is inert.
    #[test]
    fn security_status_reports_posture_with_auth_disabled() {
        let mut router = CentralRouter::new(mac(1));
        router.set_require_auth(true);
        router.set_lazy_cert_distribution(true);

        let status = RouterAdapter::new(&mut router, Duration::ZERO).security_status();

        assert!(!status.auth_enabled);
        assert!(status.require_auth);
        assert!(status.lazy_cert_distribution);
    }

    /// A node that is not a provider reports no enrollment policy, and refuses
    /// to be given one — there is nothing on it that a policy would govern.
    #[test]
    fn enrollment_policy_is_absent_and_unsettable_without_a_provider() {
        let mut router = CentralRouter::new(mac(1));

        let status = RouterAdapter::new(&mut router, Duration::ZERO).security_status();
        assert!(status.enrollment.is_none());

        // An enrollment policy is the authority's state, and this adapter has
        // no authority. On the host the connection task strips the field and
        // sends it to the authority task, so one arriving here means nobody can
        // apply it — an embedded node, or a host node with no provider.
        // Refused, never silently accepted: answering `Empty` would tell the
        // client a policy it never applied is now in force.
        let result =
            RouterAdapter::new(&mut router, Duration::ZERO).set_config(RuntimeConfigData {
                enrollment: Some(wayfinder_protos::service::EnrollmentPolicyData {
                    auto_approve: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            });
        assert!(
            result.is_err(),
            "an unappliable enrollment policy is refused"
        );
    }

    /// The policy an authority publishes is what `GetSecurityStatus` reports.
    /// The write no longer travels with it: `SetConfig`'s enrollment half is
    /// split off by the connection task, so this test drives the two sides
    /// separately, exactly as production does.
    #[test]
    fn enrollment_policy_round_trips_through_the_provider() {
        let mut router = CentralRouter::new(mac(1));
        let mut ca = crate::CertAuthority::new(&[9; 32], 0xABCD, 10_000, None, true);

        // The write is the authority's, and no longer reachable through a
        // `SetConfig` served here: the connection task splits that request and
        // sends this half on as an `AuthorityCommand::SetEnrollmentPolicy`.
        ca.set_enrollment_policy(&wayfinder_protos::service::EnrollmentPolicyData {
            auto_approve: Some(false),
            cert_ttl_secs: Some(4242),
            ..Default::default()
        })
        .unwrap();

        // The read is the router's, from what the authority published — never
        // by asking the authority, which may be mid-Argon2id.
        let status = RouterAdapter::new(&mut router, Duration::ZERO)
            .with_enrollment_policy(Some(ca.enrollment_policy()))
            .security_status();
        let policy = status.enrollment.expect("a provider reports its policy");
        assert!(!policy.auto_approve);
        assert_eq!(policy.cert_ttl_secs, 4242);
    }

    /// The token is reached through its own request, and a node with no
    /// authority answers with an error rather than with "open".
    ///
    /// The distinction is the whole point: "this node issues no certificates"
    /// and "anyone may join this mesh" are opposite claims, and a client that
    /// read the second for the first would tell an operator their mesh is
    /// ungated when it has no gate to be through.
    #[test]
    fn the_enrollment_token_is_revealed_only_by_a_provider() {
        // No `RouterAdapter` case here any more: it does not implement the
        // authority half at all, so "a router with no authority cannot reveal a
        // token" is a compile error rather than a runtime one. What is left to
        // check is that a real authority reveals the token it was configured
        // with.
        let mut ca = crate::CertAuthority::new(
            &[9; 32],
            0xABCD,
            10_000,
            Some(alloc::string::String::from("hunter2")),
            true,
        );
        assert_eq!(
            crate::AuthorityAdapter::new(
                &mut ca,
                tokio::sync::watch::channel(crate::RouterFacts {
                    unix_secs: 1_700_000_000,
                    auth_present: true,
                })
                .1
            )
            .reveal_enrollment_token(),
            Ok(EnrollmentAdmission::Token(
                wayfinder_protos::service::SharedSecret::new("hunter2")
            ))
        );
    }

    /// A provider with no token answers `Open`: a CSR is admitted on the
    /// policy's other terms, which is a different state from "empty token".
    #[test]
    fn a_provider_with_no_token_reveals_open_admission() {
        let mut ca = crate::CertAuthority::new(&[9; 32], 0xABCD, 10_000, None, false);

        assert_eq!(
            crate::AuthorityAdapter::new(
                &mut ca,
                tokio::sync::watch::channel(crate::RouterFacts {
                    unix_secs: 1_700_000_000,
                    auth_present: true,
                })
                .1
            )
            .reveal_enrollment_token(),
            Ok(EnrollmentAdmission::Open)
        );
    }
}
