use crate::wayfinder::v1alpha::Alarm;
use crate::wayfinder::v1alpha::AlarmKind;
use crate::wayfinder::v1alpha::AlarmSeverity;
use crate::wayfinder::v1alpha::Alarms;
use crate::wayfinder::v1alpha::AllInterfacesEgress;
use crate::wayfinder::v1alpha::AuthenticateUserResponse;
use crate::wayfinder::v1alpha::BeginUserRegistrationResponse;
use crate::wayfinder::v1alpha::CreateUserInviteResponse;
use crate::wayfinder::v1alpha::CreateUserResponse;
use crate::wayfinder::v1alpha::CsrIssued;
use crate::wayfinder::v1alpha::CsrPending;
use crate::wayfinder::v1alpha::CsrRejected;
use crate::wayfinder::v1alpha::Empty;
use crate::wayfinder::v1alpha::EnrollmentPolicy;
use crate::wayfinder::v1alpha::EnrollmentPolicyStatus;
use crate::wayfinder::v1alpha::ErrorResponse;
use crate::wayfinder::v1alpha::GetOwnCertResponse;
use crate::wayfinder::v1alpha::GetSecurityStatusResponse;
use crate::wayfinder::v1alpha::GetTrustAnchorResponse;
use crate::wayfinder::v1alpha::InterfaceThroughput;
use crate::wayfinder::v1alpha::IssuedCert;
use crate::wayfinder::v1alpha::KeepAliveEntry;
use crate::wayfinder::v1alpha::KeepAliveTable;
use crate::wayfinder::v1alpha::LinkFeaturesEntry;
use crate::wayfinder::v1alpha::LinkFeaturesTable;
use crate::wayfinder::v1alpha::LinkQualityEntry;
use crate::wayfinder::v1alpha::LinkQualityTable;
use crate::wayfinder::v1alpha::ListCertsResponse;
use crate::wayfinder::v1alpha::ListPendingCsrsResponse;
use crate::wayfinder::v1alpha::ListUserInvitesResponse;
use crate::wayfinder::v1alpha::ListUsersResponse;
use crate::wayfinder::v1alpha::LogFilter;
use crate::wayfinder::v1alpha::LogLevel;
use crate::wayfinder::v1alpha::LogRecord;
use crate::wayfinder::v1alpha::LogRecords;
use crate::wayfinder::v1alpha::NeighborPath;
use crate::wayfinder::v1alpha::NodeInfo;
use crate::wayfinder::v1alpha::NodeMetrics;
use crate::wayfinder::v1alpha::NodeSecurity;
use crate::wayfinder::v1alpha::OgmSchedule;
use crate::wayfinder::v1alpha::OgmScheduleEntry;
use crate::wayfinder::v1alpha::PendingCsr;
use crate::wayfinder::v1alpha::ResolveRouteResponse;
use crate::wayfinder::v1alpha::RevealEnrollmentTokenResponse;
use crate::wayfinder::v1alpha::RevokeUserSessionsResponse;
use crate::wayfinder::v1alpha::RoutingEntry;
use crate::wayfinder::v1alpha::RoutingTable;
use crate::wayfinder::v1alpha::SetUserEnabledResponse;
use crate::wayfinder::v1alpha::SetUserRoleResponse;
use crate::wayfinder::v1alpha::SubmitCsrResponse;
use crate::wayfinder::v1alpha::TableOccupancy;
use crate::wayfinder::v1alpha::Throughput;
use crate::wayfinder::v1alpha::UserAccount;
use crate::wayfinder::v1alpha::UserInvite;
use crate::wayfinder::v1alpha::UserSessionIssued;
use crate::wayfinder::v1alpha::UserSessionRejected;
use crate::wayfinder::v1alpha::WayfinderRequest;
use crate::wayfinder::v1alpha::WayfinderResponse;
use crate::wayfinder::v1alpha::alarm::Subject as AlarmSubjectKind;
use crate::wayfinder::v1alpha::authenticate_user_response::Outcome as AuthenticateUserOutcomeKind;
use crate::wayfinder::v1alpha::resolve_route_response::Egress as EgressKind;
use crate::wayfinder::v1alpha::reveal_enrollment_token_response::Admission;
use crate::wayfinder::v1alpha::submit_csr_response::Outcome as CsrOutcomeKind;
use crate::wayfinder::v1alpha::wayfinder_request::Request as RequestKind;
use crate::wayfinder::v1alpha::wayfinder_response::Response as ResponseKind;
use alloc::string::String;
use alloc::vec::Vec;
use tracing::info;

/// Intermediate representation of a single per-hop path, returned by
/// [`WayfinderDataProvider::routing_table`].  Decoupled from both the
/// wire-format structs and the generated proto types.
pub struct NeighborPathData {
    /// Immediate neighbor this path routes through.
    pub neighbor_id: Vec<u8>,
    /// Transmission quality (0..=255) of this path.
    pub tq: u32,
    /// Sequence number of the most recent OGM accepted on this path.
    pub last_seqno: u32,
    /// Whether this neighbor currently holds a valid next-hop proof. Only a
    /// proven path can be selected as the next hop; always `true` on an
    /// unauthenticated mesh, which has no pairwise keys to prove with.
    pub proven: bool,
}

/// Intermediate representation of a routing table entry.
pub struct RoutingEntryData {
    /// The destination originator this entry routes to.
    pub destination: Vec<u8>,
    /// Immediate neighbor on the currently-selected best path, or empty when
    /// no path is currently usable — including when every known path is via a
    /// neighbor that has not proven itself.
    pub next_hop: Vec<u8>,
    /// Best-path transmission quality (0..=255) to the destination.
    pub tq: u32,
    /// Sequence number of the most recent OGM accepted for the destination.
    pub last_seqno: u32,
    /// All known alternate paths to the destination.
    pub paths: Vec<NeighborPathData>,
}

/// Intermediate representation of one row in the link-quality table:
/// the smoothed signal observed for a specific neighbor on a specific
/// physical interface.
#[derive(Clone)]
pub struct LinkQualityEntryData {
    /// Neighbor whose link quality this row describes.
    pub neighbor_id: Vec<u8>,
    /// Physical-interface index the neighbor was observed on.
    pub iface_idx: u32,
    /// EWMA-smoothed normalized quality on the `0..=255` scale, or `None` when
    /// the link has never carried a physical-layer measurement (a metric-less
    /// transport: raw L2, UDP, Unix).  `None` means *unknown*, not zero.
    pub ewma_quality: Option<u32>,
    /// Number of frames received on this pair, including unmeasured ones — so
    /// it can be non-zero while `ewma_quality` is `None`.
    pub sample_count: u32,
    /// Human-readable name of the interface `iface_idx` refers to; empty when
    /// the interface was never named.
    pub iface_name: String,
}

/// Intermediate representation of one interface's live participation-feature
/// state, returned by [`WayfinderDataProvider::link_features_table`] — the
/// read counterpart to [`LinkFeaturesData`].
#[derive(Clone)]
pub struct LinkFeaturesEntryData {
    /// Physical-interface index this row describes, in registration order.
    pub iface_idx: u32,
    /// Whether this link currently sends OGMs (own + re-flooded).
    pub tx_ogm: bool,
    /// Whether this link currently accepts and learns from inbound OGMs.
    pub rx_ogm: bool,
    /// Whether this link currently sends data-plane traffic.
    pub tx_data: bool,
    /// Whether this link currently accepts inbound data-plane traffic.
    pub rx_data: bool,
    /// The armed keep-alive cadence in milliseconds, or `None` if keep-alive
    /// transmission is disabled on this link.
    pub tx_keepalive_interval_ms: Option<u64>,
    /// Human-readable name of this interface; empty when it was never named.
    pub iface_name: String,
}

/// Intermediate representation of one row in the keep-alive liveness table,
/// returned by [`WayfinderDataProvider::keepalive_table`].
#[derive(Clone)]
pub struct KeepAliveEntryData {
    /// Neighbor this row describes.
    pub neighbor_id: Vec<u8>,
    /// Milliseconds elapsed since this neighbor's last heard heartbeat.
    pub ms_since_last_heard: u64,
    /// The learned heartbeat cadence, in milliseconds; zero until a second
    /// heartbeat has provided a real gap to measure.
    pub interval_estimate_ms: u64,
    /// Whether this neighbor has missed its keep-alive budget.
    pub missed: bool,
}

/// Intermediate representation of one interface's adaptive OGM emission
/// schedule, returned by [`WayfinderDataProvider::ogm_schedule`].  All
/// intervals are in milliseconds.
#[derive(Clone)]
pub struct OgmScheduleEntryData {
    /// Physical-interface index this schedule describes, in registration order.
    pub iface_idx: u32,
    /// Current OGM emission interval — the live publish period — in ms.
    pub current_interval_ms: u32,
    /// Backoff floor (Trickle `i_min`): the interval reset to on a topology
    /// change, in ms.
    pub min_interval_ms: u32,
    /// Backoff ceiling (Trickle `i_max`): the longest interval reached while
    /// stable, in ms.
    pub max_interval_ms: u32,
    /// Human-readable name of this interface; empty when it was never named.
    pub iface_name: String,
}

/// Intermediate representation of a request to install new Trickle/OGM bounds
/// for one mesh interface, carried by [`RuntimeConfigData`] into
/// [`WayfinderDataProvider::set_config`].  All intervals are in milliseconds.
#[derive(Clone)]
pub struct TrickleConfigData {
    /// Physical-interface index to reconfigure, in registration order.
    pub iface_idx: u32,
    /// New backoff floor (Trickle `i_min`), in ms.
    pub min_interval_ms: u32,
    /// New backoff ceiling (Trickle `i_max`), in ms.
    pub max_interval_ms: u32,
}

/// Intermediate representation of a request to override one mesh interface's
/// participation features, carried by [`RuntimeConfigData`] into
/// [`WayfinderDataProvider::set_config`].  Each flag is independently optional:
/// `None` leaves that capability unchanged from the interface's current
/// setting, so a caller can flip one gate without restating the others.
#[derive(Clone, Default)]
pub struct LinkFeaturesData {
    /// Physical-interface index to reconfigure, in registration order.
    pub iface_idx: u32,
    /// Send OGMs (own + re-flooded) onto this link, if present.
    pub tx_ogm: Option<bool>,
    /// Receive OGMs on this link and learn routes from them, if present.
    pub rx_ogm: Option<bool>,
    /// Send data-plane traffic (unicast/multicast/broadcast) onto this link, if
    /// present.  Also governs route re-advertisement (see the core
    /// `LinkFeatures::tx_data`).
    pub tx_data: Option<bool>,
    /// Accept data-plane traffic (unicast/multicast/broadcast) on this link, if
    /// present.
    pub rx_data: Option<bool>,
    /// Send keep-alive heartbeats on this link, if present: the outer
    /// `Option` is "leave unchanged" (`None`) vs. "override" (`Some`); the
    /// inner `Option<u64>` is the override itself — `None` disables
    /// transmission, `Some(interval_ms)` arms (or re-arms) it at that
    /// cadence.
    pub tx_keepalive: Option<Option<u64>>,
}

/// Intermediate representation of a partial runtime-configuration update,
/// passed to [`WayfinderDataProvider::set_config`].  Each field is
/// independently optional: `None` leaves that piece of configuration
/// unchanged.  New runtime-editable knobs are added here as additional
/// fields, rather than as new provider methods.
#[derive(Clone, Default)]
pub struct RuntimeConfigData {
    /// Present to update the Trickle/OGM bounds for one mesh interface.
    pub trickle: Option<TrickleConfigData>,
    /// Present to switch lazy cert distribution on (`true`) or off (`false`).
    pub lazy_cert_distribution: Option<bool>,
    /// Present to override the participation features for one mesh interface.
    pub link_features: Option<LinkFeaturesData>,
    /// Present to switch the fail-closed gate on (`true`) or off (`false`):
    /// whether the node stays inert on the mesh while it holds no membership
    /// cert.
    pub require_auth: Option<bool>,
    /// Present to update the enrollment policy of a provider-mode node.
    pub enrollment: Option<EnrollmentPolicyData>,
}

/// Intermediate representation of a partial enrollment-policy update, carried
/// by [`RuntimeConfigData`] into [`WayfinderDataProvider::set_config`].  Each
/// field is independently optional: `None` leaves that piece of the policy
/// unchanged.
///
/// Already validated by the time it reaches a provider — the dispatch layer
/// rejects a zero `cert_ttl_secs` and an empty token before constructing this,
/// so an implementation does not have to re-check either.
#[derive(Clone, Default)]
pub struct EnrollmentPolicyData {
    /// Present to sign submitted CSRs on submission (`true`) or to park them
    /// pending operator approval (`false`).
    pub auto_approve: Option<bool>,
    /// Present to set the validity window applied to certificates issued from
    /// now on, in seconds.  Never zero.
    pub cert_ttl_secs: Option<u64>,
    /// Present to change the shared enrollment token.  The outer `Option` is
    /// "leave unchanged" (`None`) vs. "change it" (`Some`); the inner
    /// [`TokenUpdate`] distinguishes clearing it from setting one, which an
    /// `Option<String>` alone would conflate with an empty token.
    pub enrollment_token: Option<TokenUpdate>,
}

/// What a [`EnrollmentPolicyData::enrollment_token`] update does to the shared
/// enrollment token.  A closed two-variant enum rather than an `Option<String>`
/// so "open enrollment to everyone" and "require a token nobody can present"
/// cannot be confused for one another at any layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenUpdate {
    /// Clear the token: enrollment becomes open (TOFU).
    Clear,
    /// Require this token on a submitted CSR.  Never empty.
    Set(SharedSecret),
}

/// A secret that several parties hold in common — today, the shared enrollment
/// token.
///
/// A newtype for one reason: its [`Debug`] prints a placeholder. The derived
/// `Debug` on a `String` field prints the value, and this crate's types are
/// formatted with `{:?}` in error paths and `tracing` fields — one of which
/// feeds the bounded log ring that `GetLogs` serves to a browser. Reading the
/// value takes [`expose`](Self::expose), which is a word the reader of a diff
/// can search for.
#[derive(Clone, PartialEq, Eq)]
pub struct SharedSecret(String);

impl SharedSecret {
    /// Wrap a secret value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Read the secret. Deliberately not `Display`/`AsRef`: every place the
    /// value escapes should be one a search for this name finds.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedSecret(<redacted>)")
    }
}

/// How a provider decides who may enroll, as answered by
/// [`WayfinderDataProvider::reveal_enrollment_token`].
///
/// A sum type rather than a flag beside an optional string: "no token is
/// required" and "the required token is the empty string" are different
/// states, and a `(bool, Option<String>)` pair admits two more that mean
/// nothing at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnrollmentAdmission {
    /// No token is required; a CSR is admitted on the policy's other terms.
    Open,
    /// A CSR must present this token.
    Token(SharedSecret),
}

/// Intermediate representation of the enrollment policy a provider-mode node
/// is currently applying, reported inside [`SecurityStatusData`].
///
/// Says whether a token is required and never what it is: this travels on a
/// polled response, and the value is handed over one request at a time by
/// [`WayfinderDataProvider::reveal_enrollment_token`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnrollmentPolicyStatusData {
    /// Whether a submitted CSR is signed on submission, rather than parked
    /// pending operator approval.
    pub auto_approve: bool,
    /// The validity window applied to issued certificates, in seconds.
    pub cert_ttl_secs: u64,
    /// Whether a shared enrollment token is configured.
    pub enrollment_token_set: bool,
}

/// Intermediate representation of one interface's smoothed throughput,
/// returned by [`WayfinderDataProvider::throughput`].  Rates are bytes/sec and
/// frames/sec in each direction, evaluated at the moment the snapshot was
/// taken; not cumulative counters.
#[derive(Clone)]
pub struct InterfaceThroughputData {
    /// Physical-interface index this row describes, in registration order.
    pub iface_idx: u32,
    /// Smoothed receive rate in bytes per second.
    pub rx_bps: f64,
    /// Smoothed receive rate in frames per second.
    pub rx_fps: f64,
    /// Smoothed transmit rate in bytes per second.
    pub tx_bps: f64,
    /// Smoothed transmit rate in frames per second.
    pub tx_fps: f64,
    /// Human-readable name of this interface; empty when it was never named.
    pub iface_name: String,
}

/// Intermediate representation of one fixed-capacity table's occupancy.
#[derive(Clone, Copy, Default)]
pub struct TableOccupancyData {
    /// Entries currently held.
    pub used: u32,
    /// Maximum entries before eviction/drop.
    pub capacity: u32,
}

/// Intermediate representation of the node's aggregate health and topology
/// metrics, returned by [`WayfinderDataProvider::node_metrics`].  A flat
/// snapshot derived from the router's live state at call time.
#[derive(Clone, Default)]
pub struct NodeMetricsData {
    /// Seconds the router has been running.
    pub uptime_secs: u64,
    /// Distinct directly-reachable (one-hop) neighbours.
    pub neighbor_count: u32,
    /// Originator (routing) table occupancy.
    pub originators: TableOccupancyData,
    /// Broadcast-deduplication table occupancy.
    pub broadcast_dedup: TableOccupancyData,
    /// Locally-joined multicast group table occupancy.
    pub local_mcast_groups: TableOccupancyData,
    /// Learned multicast-membership table occupancy.
    pub mcast_memberships: TableOccupancyData,
    /// Lowest best-path TQ (0–255) across originators, 0 when none are known.
    pub tq_min: u32,
    /// Highest best-path TQ (0–255) across originators, 0 when none are known.
    pub tq_max: u32,
    /// Mean best-path TQ (0–255) across originators, 0.0 when none are known.
    pub tq_mean: f64,
    /// Largest alternate-path count held for any originator (0–4).
    pub paths_max: u32,
    /// Mean alternate-path count per originator, 0.0 when none are known.
    pub paths_mean: f64,
    /// Locally originated host frames dropped because they exceeded the mesh's
    /// carrying capacity once encapsulated — non-zero signals a too-high MTU.
    pub oversize_drops: u32,
    /// Relayed frames dropped because they didn't fit an outbound link's
    /// buffer — non-zero signals an MTU mismatch between two of this node's
    /// links, distinct from `oversize_drops` (locally originated frames only).
    pub relay_oversize_drops: u32,
    /// Verified-neighbor cert cache occupancy. Zero (0/0) when auth is
    /// disabled.
    pub cert_store: TableOccupancyData,
    /// Requester-side in-flight lazy-cert-fetch table occupancy. Zero (0/0)
    /// when auth is disabled.
    pub in_flight_cert_requests: TableOccupancyData,
    /// Responder-side parked-reply table occupancy. Zero (0/0) when auth is
    /// disabled.
    pub pending_cert_replies: TableOccupancyData,
    /// Smoothed rate (frames/sec) at which this node sends `CertReq`. Zero
    /// when auth is disabled.
    pub cert_req_rate: f64,
    /// Smoothed rate (frames/sec) at which this node sends `CertReply`. Zero
    /// when auth is disabled.
    pub cert_reply_rate: f64,
    /// Smoothed frames/sec at which directed frames are dropped for want of a
    /// pairwise key with their next hop — a silent drop from the sender's
    /// point of view, and the only signal it is happening.
    pub untaggable_drop_rate: f64,
}

/// Egress decision a router would make for a destination.  Mirrors
/// `wayfinder::EgressInterface` without coupling this crate to it.
#[derive(Clone)]
pub enum EgressDecisionData {
    /// Flood out every interface (broadcast).
    AllInterfaces,
    /// Send out a specific physical interface by its index.
    Interface(u32),
}

/// Intermediate representation of the answer to "how would a packet to
/// `destination` be routed right now?".  Returned by
/// [`WayfinderDataProvider::resolve_route`].
#[derive(Clone)]
pub struct RouteResolutionData {
    /// Immediate next-hop neighbor that would receive the packet.  Mirrors
    /// the `lookup_route(dest).unwrap_or(dest)` fallback used inside
    /// `CentralRouter::handle_local`.
    pub next_hop: Vec<u8>,
    /// Egress decision, or `None` if no quality / ident-table data exists
    /// for this destination yet.
    pub egress: Option<EgressDecisionData>,
}

/// The security posture of one originator, as the local node sees it.  Mirrors
/// the `NodeSecurity` proto without coupling providers to the generated types.
#[derive(Clone)]
pub struct NodeSecurityData {
    /// The originator's node MAC (raw bytes).
    pub node_id: Vec<u8>,
    /// Whether we hold a verified membership cert for it (its OGM signature
    /// chained to our trust anchor).
    pub verified: bool,
    /// Its certificate expiry (unix seconds) when `verified`, else 0.
    pub cert_not_after: u64,
    /// Whether we currently hold a revocation for it.
    pub revoked: bool,
    /// When that revocation stops being enforced (unix seconds) when
    /// `revoked`, else 0.  The record is dropped at that instant, so it is
    /// also when the originator leaves this list.
    pub revocation_not_after: u64,
}

/// This node's mesh authentication / security posture.  Mirrors the
/// `GetSecurityStatusResponse` proto.  The [`Default`] (all-zero / `nodes`
/// empty) represents auth being disabled.
#[derive(Clone, Default)]
pub struct SecurityStatusData {
    /// Whether mesh authentication is enabled on this node.
    pub auth_enabled: bool,
    /// The mesh id this node authenticates for; 0 when auth is disabled.
    pub mesh_id: u32,
    /// This node's own certificate MAC (raw bytes); empty when auth disabled.
    pub node_mac: Vec<u8>,
    /// This node's own certificate expiry (unix seconds); 0 when auth disabled.
    pub cert_not_after: u64,
    /// Number of revocations this node currently holds.
    pub revocation_count: u32,
    /// One entry per originator with a known security posture.
    pub nodes: Vec<NodeSecurityData>,
    /// Whether this node fails closed, staying inert on the mesh while it
    /// holds no membership cert.
    pub require_auth: bool,
    /// Whether this node's OGMs carry a cert fingerprint rather than the full
    /// membership cert.
    pub lazy_cert_distribution: bool,
    /// The enrollment policy in force; `None` on a node that is not running in
    /// provider mode and so has none to report.
    pub enrollment: Option<EnrollmentPolicyStatusData>,
    /// This node's own Ed25519 identity public key; empty when the node has no
    /// identity at all.  Reported whether or not auth is enabled — an
    /// un-enrolled node still has an identity, and this is the key a client
    /// enrolling it on its behalf must name in the CSR.
    pub own_ed_pubkey: Vec<u8>,
    /// This node's own X25519 public key, on the same terms as
    /// [`own_ed_pubkey`](Self::own_ed_pubkey).
    pub own_x_pubkey: Vec<u8>,
}

/// The membership credential a node is running under: its certificate and the
/// trust anchor that certificate chains to.  Mirrors the `GetOwnCertResponse`
/// proto.
///
/// Both halves together, never one: a certificate without the anchor it
/// verifies against is not a usable credential, and a caller that had to source
/// the two separately would be the caller that eventually pairs a certificate
/// with the wrong mesh's anchor.
///
/// There is no [`Default`], deliberately.  A node with no certificate is
/// represented by `None` at the call site ([`RouterDataProvider::own_cert`]),
/// not by an all-empty value of this type — an empty certificate is not a
/// certificate, and a type that could hold one would let it travel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnCertData {
    /// The membership certificate, verbatim as it was installed and as it
    /// travels on the wire.  Never empty.
    pub cert: Vec<u8>,
    /// The mesh trust anchor `cert` verifies against.
    pub trust_anchor: Vec<u8>,
}

/// The verbosity of one log record.  Mirrors the `LogLevel` proto enum, minus
/// its proto3-mandated zero value — a record always has a real level, so
/// "unspecified" is unrepresentable here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LogLevelData {
    /// A failure an operator must act on, originating in this node.
    Error,
    /// Unexpected but handled, worth operator attention.
    Warn,
    /// A lifecycle or topology event an observer wants.
    Info,
    /// A developer-facing state transition.
    Debug,
    /// Per-frame/packet flow — the bulk of the records.
    Trace,
}

/// One log record, as the management API reports it.  Mirrors the `LogRecord`
/// proto.
#[derive(Clone)]
pub struct LogRecordData {
    /// Monotonic position in the node's log stream, starting at 0 on boot.
    pub seq: u64,
    /// Milliseconds since boot, at the moment the record was emitted.
    pub uptime_ms: u64,
    /// The record's verbosity.
    pub level: LogLevelData,
    /// The emitting module path.
    pub target: String,
    /// The rendered message and its structured fields — never payload bytes.
    pub message: String,
}

/// A batch of log records plus where the caller should resume.  Mirrors the
/// `LogRecords` proto.
#[derive(Clone, Default)]
pub struct LogsData {
    /// The matching records, oldest first.
    pub records: Vec<LogRecordData>,
    /// The sequence number to request on the next poll.
    pub next_seq: u64,
    /// How many records this caller missed between the sequence number it
    /// asked for and the oldest the node still retains.
    pub dropped: u64,
    /// The filter spec currently in force, so a polling client can display what
    /// is actually being recorded without a second query.
    pub filter: String,
}

/// How bad a condition an alarm reports is.  Mirrors `wayfinder-alarm`'s
/// `Severity` and the `AlarmSeverity` proto, so neither this crate nor a client
/// has to depend on the alarm crate to name one.
///
/// Ordered worst-last so `>` means "worse", which is what a client sorting or
/// thresholding a board compares.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlarmSeverityData {
    /// Worth recording, not worth waking anyone.
    #[default]
    Info,
    /// Something is wrong and an operator should look.
    Warning,
    /// Something is wrong now and is degrading or attacking the mesh.
    Critical,
}

/// What kind of condition an alarm reports.  Mirrors `wayfinder-alarm`'s
/// `AlarmKind` and the `AlarmKind` proto.
///
/// A closed set: what a node can flag is a design decision, not caller data,
/// and a fixed set is what lets a client render a condition it has never seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlarmKindData {
    /// Frames arriving from a source that fails authentication, in volume.
    UnauthenticatedTraffic,
    /// Frames offered far faster than this mesh's configured cadence explains.
    TrafficFlood,
    /// Repeated management-API authentication failures.
    ManagementAuthFailures,
    /// An OGM whose sequence number this node has already processed.
    OgmReplay,
    /// Traffic from a peer holding a certificate this node knows to be revoked.
    RevokedPeer,
    /// A link failing I/O persistently rather than transiently.
    LinkErrors,
    /// A bounded table at capacity and evicting.
    TableSaturation,
}

/// Who or what an alarm is about.
///
/// Deliberately raw bytes rather than a parsed identifier, for the same reason
/// the management API's other `node_id` fields are: the projection must not
/// need to know this deployment's address family, and rendering is the client's
/// job.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AlarmSubjectData {
    /// About the node as a whole rather than any one peer or interface.
    #[default]
    Node,
    /// About the peer with these raw identifier bytes, at most 8 of them.
    Peer(Vec<u8>),
    /// About the interface at this index.
    Interface(u32),
}

/// One latched condition from a node's alarm board.  Mirrors the `Alarm` proto.
#[derive(Clone, Debug)]
pub struct AlarmData {
    /// What kind of condition this is.
    pub kind: AlarmKindData,
    /// The worst severity yet observed for it; ratchets up and never down.
    pub severity: AlarmSeverityData,
    /// Who or what it is about.
    pub subject: AlarmSubjectData,
    /// Node uptime in milliseconds when the condition started.
    pub first_ms: u64,
    /// Node uptime in milliseconds at the most recent observation.
    pub last_ms: u64,
    /// How many observations have folded into this row, saturating.
    pub count: u32,
    /// The most recent observation, rendered by the detector.  Metadata only.
    pub detail: String,
    /// Whether the node is still asserting the condition as of
    /// [`AlarmsData::now_ms`] — evaluated by the node so a client needs no
    /// clock of its own.  A `false` here means "fired and has since gone
    /// quiet", not "gone": the board latches.
    pub active: bool,
}

/// A node's whole alarm board as one snapshot.  Mirrors the `Alarms` proto.
#[derive(Clone, Default)]
pub struct AlarmsData {
    /// The latched conditions, worst first and — among equal severities — most
    /// recent first.  Ordered by the node so every reader agrees on the top.
    pub alarms: Vec<AlarmData>,
    /// How many raises the board's capacity policy refused or evicted since
    /// boot, so a gap stays visible as a gap.
    pub dropped: u64,
    /// Node uptime in milliseconds when the snapshot was taken.
    pub now_ms: u64,
}

/// Router-facing state for [`WayfinderService`]: the routing and link tables,
/// node settings, alarms and logs a node answers from its own router, with no
/// certificate authority involved.
///
/// Split from [`AuthorityDataProvider`] so the two halves can be owned by
/// different executors — see
/// `docs/design/implemented/13-certificate-authority-off-the-router-loop.md`. Intentionally
/// transport- and protocol-agnostic so callers can implement it for whatever
/// router type they have.
pub trait RouterDataProvider {
    /// This node's own identifier (raw MAC bytes).
    fn node_id(&self) -> Vec<u8>;
    /// Number of originators (reachable nodes) currently in the routing table.
    fn num_originators(&self) -> u32;
    /// Whether this node requires authentication but has no membership cert
    /// installed yet (inert on the mesh until provisioned).
    fn auth_locked(&self) -> bool;
    /// Snapshot of the routing table: one entry per known destination.
    fn routing_table(&self) -> Vec<RoutingEntryData>;
    /// Snapshot of the per-(neighbor, interface) link-quality table.
    fn link_quality_table(&self) -> Vec<LinkQualityEntryData>;
    /// Snapshot of the per-interface participation-feature state (the tx/rx
    /// OGM/data gates and keep-alive cadence set via
    /// [`set_config`](WayfinderDataProvider::set_config), or the interface's
    /// startup default).
    fn link_features_table(&self) -> Vec<LinkFeaturesEntryData>;
    /// Snapshot of the per-neighbor keep-alive heartbeat liveness table,
    /// evaluated as of the moment of the call.
    fn keepalive_table(&self) -> Vec<KeepAliveEntryData>;
    /// Snapshot of the per-interface adaptive OGM emission schedule (the
    /// current OGM publish rate per interface and its backoff bounds).
    fn ogm_schedule(&self) -> Vec<OgmScheduleEntryData>;
    /// Snapshot of the per-interface smoothed throughput (bytes/sec and
    /// frames/sec in each direction), evaluated as of the moment of the call.
    fn throughput(&self) -> Vec<InterfaceThroughputData>;
    /// Aggregate node health and topology metrics, derived from live router
    /// state at the moment of the call.
    fn node_metrics(&self) -> NodeMetricsData;
    /// Resolve how a packet to `destination` would be routed.  Returns
    /// `None` if the raw bytes can't be parsed as a valid identifier for
    /// this provider's address family.
    fn resolve_route(&self, destination: &[u8]) -> Option<RouteResolutionData>;
    /// Set the auth state on the node
    fn set_auth(&mut self, seed: &[u8], cert: &[u8], trust_anchor: &[u8]) -> Result<(), String>;

    /// Apply a partial update to the node's runtime configuration. Only the
    /// fields present in `config` are changed; unset fields are left as they
    /// are. In-memory only — does not persist across a restart.
    fn set_config(&mut self, config: RuntimeConfigData) -> Result<(), String>;

    /// Whether this node currently has a runtime configuration override
    /// applied via [`set_config`](WayfinderDataProvider::set_config), as
    /// opposed to running purely off its startup configuration.
    fn runtime_config_active(&self) -> bool;

    /// Recent log records from this node's bounded in-memory ring, from
    /// `since_seq` onward and at most `max_records` of them (0 meaning the
    /// node's default batch size).
    ///
    /// Not router state — the ring is filled by the installed logging
    /// subscriber, which is process-wide — but served here so a node's logs are
    /// reachable over the same transport as everything else, which on a board
    /// with no debug probe attached is the only way to read them at all.
    fn logs(&self, since_seq: u64, max_records: u32) -> LogsData;
    /// The conditions this node currently believes are wrong.
    ///
    /// Not derived from the router: the board is process-global precisely
    /// because what raises an alarm is scattered across the whole stack with no
    /// handle to carry, so an implementor reads that global rather than
    /// projecting state it owns.  A node that has never raised one answers with
    /// an empty board, which is the "all systems normal" a client renders.
    fn alarms(&self) -> AlarmsData;

    /// Install `directives` as the node's runtime log filter, across every sink
    /// it writes to.  Returns the spec now in force, for readback.
    ///
    /// The `Err` variant is a spec that failed to parse, and leaves the previous
    /// filter untouched: an operator typo must never blind a node.
    fn set_log_level(&mut self, directives: &str) -> Result<String, String>;

    /// This node's mesh authentication / security posture, evaluated from live
    /// auth state at the moment of the call.  The default reports auth disabled;
    /// a provider with router-auth wired overrides it.
    fn security_status(&self) -> SecurityStatusData {
        SecurityStatusData::default()
    }

    /// The membership certificate this node is currently running under, with
    /// the trust anchor it chains to, or `None` on a node holding none.
    ///
    /// Read from live state rather than from wherever the material was loaded,
    /// which is what makes one answer cover both provisioning modes: a
    /// certificate installed at runtime by [`set_auth`](Self::set_auth) and one
    /// read from a file at startup are the same certificate here, and cannot
    /// disagree.
    ///
    /// The default is `None` — a node has no certificate until something gives
    /// it one, and an implementor that never overrides this is telling the
    /// truth.
    fn own_cert(&self) -> Option<OwnCertData> {
        None
    }
}

/// The answer every authority-facing request gives on a node that runs no
/// certificate authority.
///
/// One definition, because two code paths produce it — this trait's defaults on
/// a router-only node, and the connection task when no authority is wired — and
/// a client that distinguishes them would be distinguishing a detail of which
/// task answered.
pub const NOT_A_PROVIDER: &str = "node is not a certificate-authority provider";

/// The answer `GetOwnCert` gives on a node that holds no membership
/// certificate.
///
/// One definition because a client matches on it to tell "this node has not
/// enrolled" — a state an operator can fix, and can be told how to — apart from
/// a transport failure, which is a different problem with a different remedy.
pub const NO_MEMBERSHIP_CERT: &str = "node holds no membership certificate";

/// Build the response a node with no certificate authority gives to a request
/// only one could serve.
///
/// Lives here rather than beside the authority task because an embedded node —
/// which never links that task, or `std` at all — needs the same answer.
pub fn not_a_provider_response() -> WayfinderResponse {
    WayfinderResponse {
        response: Some(ResponseKind::Error(ErrorResponse {
            message: NOT_A_PROVIDER.into(),
        })),
    }
}

/// Certificate-authority state for [`WayfinderService`]: enrollment, the user
/// store, revocation and the issued-certificate log.
///
/// Every method defaults to "this node is not a certificate-authority
/// provider", so a node that only routes satisfies this trait with an empty
/// impl and only a provider overrides anything. That default is also what makes
/// the split cheap: no existing implementor gains a method it has to write.
pub trait AuthorityDataProvider {
    /// Provider mode: the mesh trust anchor as raw `TrustAnchor` bytes.  The
    /// default errors — only a node running as a certificate-authority provider
    /// overrides these three methods.
    fn get_trust_anchor(&self) -> Result<Vec<u8>, String> {
        Err(NOT_A_PROVIDER.into())
    }

    /// Provider mode: submit a certificate-signing request.  Returns the CSR's
    /// [`CsrOutcome`] — issued (with the cert + anchor), pending operator
    /// approval, or rejected — so a polling client can drive enrollment to a
    /// terminal state.  The `Err` variant is reserved for the request being
    /// unserviceable (this node is not a provider, the authority clock is unset,
    /// or the inputs are malformed), as distinct from a `Rejected` *outcome* of
    /// a well-formed CSR.  Default errors (not a provider).
    fn submit_csr(
        &mut self,
        node_mac: &[u8],
        ed_pubkey: &[u8],
        x_pubkey: &[u8],
        enrollment_token: &str,
    ) -> Result<CsrOutcome, String> {
        let _ = (node_mac, ed_pubkey, x_pubkey, enrollment_token);
        Err(NOT_A_PROVIDER.into())
    }

    /// Provider mode: exchange a user's credentials for a short-lived
    /// management certificate bound to the session keys they name.  Default
    /// errors (not a provider).
    ///
    /// The `Err` variant is reserved for the request being *unserviceable* —
    /// this node is not a provider, the authority clock is unset, the keys are
    /// malformed — and never for the credentials being wrong, which is
    /// [`UserAuthOutcome::Rejected`].  Keeping the two apart is what lets a
    /// misconfigured client be told what is wrong with its request while a
    /// guessing one is told nothing at all.
    fn authenticate_user(
        &mut self,
        username: &str,
        password: &str,
        totp_code: &str,
        ed_pubkey: &[u8],
        x_pubkey: &[u8],
    ) -> Result<UserAuthOutcome, String> {
        let _ = (username, password, totp_code, ed_pubkey, x_pubkey);
        Err(NOT_A_PROVIDER.into())
    }

    /// Provider mode: the admission rule this node applies to a submitted CSR
    /// — open, or a shared token whose value this returns.  Default errors
    /// (not a provider).
    ///
    /// Split from [`security_status`](Self::security_status) because that one
    /// is polled: a secret riding a poll is disclosed continuously and cannot
    /// be told apart from the traffic it rides on, while one that only travels
    /// when asked for can be logged as a disclosure. An implementation should
    /// treat every call as an audited read.
    fn reveal_enrollment_token(&self) -> Result<EnrollmentAdmission, String> {
        Err(NOT_A_PROVIDER.into())
    }

    /// Provider mode: revoke a node, signing and flooding a revocation record.
    /// Default errors.
    fn revoke_node(&mut self, node_mac: &[u8]) -> Result<(), String> {
        let _ = node_mac;
        Err(NOT_A_PROVIDER.into())
    }

    /// Provider mode: list the certificates this provider has issued.  Default
    /// errors.
    fn list_certs(&self) -> Result<Vec<IssuedCertData>, String> {
        Err(NOT_A_PROVIDER.into())
    }

    /// Provider mode: list the CSRs currently awaiting operator approval.
    /// Default errors (not a provider).
    fn list_pending_csrs(&self) -> Result<Vec<PendingCsrData>, String> {
        Err(NOT_A_PROVIDER.into())
    }

    /// Provider mode: list the user accounts this authority holds.  Default
    /// errors (not a provider).
    ///
    /// Never the password hashes or TOTP secrets — see [`UserAccountData`].
    fn list_users(&self) -> Result<Vec<UserAccountData>, String> {
        Err(NOT_A_PROVIDER.into())
    }

    /// Provider mode: create a user account, returning the `otpauth://`
    /// enrolment URI for its second factor (empty when created without one).
    /// Default errors (not a provider).
    ///
    /// `Err` covers both "this node is not a provider" and "that name is
    /// already taken" — unlike the sign-in path, which is deliberately mute
    /// about which account exists. There is no oracle to protect here: this
    /// request needs a full management grant, and a client holding one can list
    /// the accounts outright.
    fn create_user(
        &mut self,
        username: &str,
        password: &str,
        admin: bool,
        session_ttl_secs: u64,
        no_totp: bool,
    ) -> Result<String, String> {
        let _ = (username, password, admin, session_ttl_secs, no_totp);
        Err(NOT_A_PROVIDER.into())
    }

    /// Provider mode: remove the named user account.  Default errors (not a
    /// provider).
    ///
    /// Ends the account's ability to obtain *new* sessions; a certificate
    /// already issued to it keeps working until it expires or is revoked.
    ///
    /// `Err` covers a name that is not on file as well as an implementation's
    /// refusal to remove the last account that can still administer the mesh —
    /// see [`RemoveUserRequest`](crate::wayfinder::v1alpha::RemoveUserRequest).
    fn remove_user(&mut self, username: &str) -> Result<(), String> {
        let _ = username;
        Err(NOT_A_PROVIDER.into())
    }

    /// Provider mode: mint a one-time invite for `username`, returning its
    /// token — the one moment that token is readable anywhere.  Default errors
    /// (not a provider).
    ///
    /// `session_ttl_secs` and `invite_ttl_secs` of zero each mean "the
    /// authority's default", so a caller with no opinion need not know what the
    /// defaults are.
    ///
    /// `Err` covers a name that is already taken *or* already invited, and a
    /// store at capacity. There is no oracle to protect: this needs a full
    /// management grant, and a client holding one can list both stores outright.
    fn create_user_invite(
        &mut self,
        username: &str,
        admin: bool,
        session_ttl_secs: u64,
        invite_ttl_secs: u64,
    ) -> Result<UserInviteMintedData, String> {
        let _ = (username, admin, session_ttl_secs, invite_ttl_secs);
        Err(NOT_A_PROVIDER.into())
    }

    /// Provider mode: the invites on file, and the store's capacity.  Default
    /// errors (not a provider).
    ///
    /// The capacity travels with the listing rather than in a separate metric
    /// because it is what makes the listing readable: without it a full store
    /// looks like an unexplained refusal at the next mint.
    fn list_user_invites(&self) -> Result<(Vec<UserInviteData>, u32), String> {
        Err(NOT_A_PROVIDER.into())
    }

    /// Provider mode: revoke every session certificate `username` currently
    /// holds, leaving the account in place, and report how many were revoked.
    /// Default errors (not a provider).
    ///
    /// The difference from removing the account is the account: this ends what
    /// it is currently holding and leaves it able to sign in again.
    ///
    /// An implementation must skip sessions it has already revoked and sessions
    /// that have expired, so **zero is an ordinary success** rather than a
    /// failure to find the account. `Err` is for a name that is not on file, and
    /// for a store that cannot be made durable.
    fn revoke_user_sessions(&mut self, username: &str) -> Result<u32, String> {
        let _ = username;
        Err(NOT_A_PROVIDER.into())
    }

    /// Provider mode: set `username`'s role, revoking the sessions the change
    /// invalidates, and report how many were revoked.  Default errors (not a
    /// provider).
    ///
    /// **A demotion must revoke the account's live sessions**, as one durable
    /// act with the role change. The capability is stamped on the certificate,
    /// so a session minted while the account was an administrator keeps
    /// administering until it is revoked or expires; an implementation that
    /// changed only what is issued *next* would report an access as removed
    /// while its holder still had it.
    ///
    /// A promotion revokes nothing — the certificates the account holds now
    /// grant less than it does, which costs a sign-in and no access.
    ///
    /// Returns how many sessions were revoked and **whether anything actually
    /// changed**. Restating the role an account already holds is a success that
    /// revokes nothing: an operator unsure whether the first call landed will
    /// make the second one, and it must not cut off a session on the way
    /// through. The second half of the pair is why the implementation answers
    /// it rather than a caller re-reading the roster — a promotion also revokes
    /// nothing, so the count alone cannot distinguish the two, and two
    /// independently-derived answers to one predicate drift.
    ///
    /// `Err` covers a name that is not on file, an implementation's refusal to
    /// demote the last account that can still administer the mesh, and a store
    /// that cannot be made durable.
    fn set_user_role(&mut self, username: &str, admin: bool) -> Result<(u32, bool), String> {
        let _ = (username, admin);
        Err(NOT_A_PROVIDER.into())
    }

    /// Provider mode: enable or disable `username`, revoking the sessions the
    /// change invalidates, and report how many were revoked.  Default errors
    /// (not a provider).
    ///
    /// **Disabling must revoke the account's live sessions**, for the reason
    /// the demotion above does: an account that obtains no new session while
    /// every certificate it already holds keeps working is disabled only in the
    /// future tense. Enabling revokes nothing and must clear any lockout.
    ///
    /// `Err` covers a name that is not on file, an implementation's refusal to
    /// disable the last account that can still administer the mesh, and a store
    /// that cannot be made durable.
    fn set_user_enabled(&mut self, username: &str, enabled: bool) -> Result<(u32, bool), String> {
        let _ = (username, enabled);
        Err(NOT_A_PROVIDER.into())
    }

    /// Provider mode: replace `username`'s password, clearing any lockout.
    /// Default errors (not a provider).
    ///
    /// The administrative reset. It must leave the second factor alone: an
    /// operator who could replace both would be able to take an account over in
    /// one request, leaving its owner no signal.
    ///
    /// It revokes nothing, deliberately — a forgotten password is the common
    /// case, and ending every device its owner is signed in on is a larger act
    /// than was asked for. When the reset answers a compromise, the request that
    /// ends the sessions is
    /// [`revoke_user_sessions`](Self::revoke_user_sessions).
    ///
    /// `Err` covers a name that is not on file, an empty password, and a store
    /// that cannot be made durable.
    fn set_user_password(&mut self, username: &str, password: &str) -> Result<(), String> {
        let _ = (username, password);
        Err(NOT_A_PROVIDER.into())
    }

    /// Provider mode: delete the invite minted for `username`, at any status.
    /// Default errors (not a provider).
    ///
    /// `Err` for a name with no invite on file: whoever sent it has a wrong
    /// idea about what is pending.
    fn revoke_user_invite(&mut self, username: &str) -> Result<(), String> {
        let _ = username;
        Err(NOT_A_PROVIDER.into())
    }

    /// Provider mode: **consume** `token` and reveal the account's second
    /// factor, returning it with the handle that alone can complete the
    /// registration.  Default errors (not a provider).
    ///
    /// Consuming is the point, not an implementation detail: a start that could
    /// be repeated would let anyone who read the invite URL take the TOTP
    /// secret while the legitimate registration still completed, leaving no
    /// record anywhere. An implementation that reveals the secret without
    /// spending the invite has not implemented this method.
    ///
    /// `Err` covers an unknown, expired or already-started invite. An unknown
    /// token must be refused *without* spending password-hashing work — see
    /// [`BeginUserRegistrationRequest`](crate::wayfinder::v1alpha::BeginUserRegistrationRequest).
    fn begin_user_registration(&mut self, token: &str) -> Result<RegistrationStartedData, String> {
        let _ = token;
        Err(NOT_A_PROVIDER.into())
    }

    /// Provider mode: verify `handle` and `totp_code`, create the account with
    /// `password`, and delete the invite — as one durable act.  Default errors
    /// (not a provider).
    ///
    /// The two halves must not be separately durable: a crash between them
    /// leaves a burnt invite and no account, which is unrecoverable by the
    /// person holding the handle.
    ///
    /// The step `totp_code` is accepted at must be carried into the new
    /// account's replay guard, or the code typed here stays valid at sign-in
    /// for the rest of its skew window.
    fn complete_user_registration(
        &mut self,
        handle: &str,
        password: &str,
        totp_code: &str,
    ) -> Result<(), String> {
        let _ = (handle, password, totp_code);
        Err(NOT_A_PROVIDER.into())
    }

    /// Provider mode: approve the pending CSR bound to `node_mac`, so the
    /// enrolling node collects its certificate on the next `submit_csr` poll.
    /// Errors if no CSR for that MAC is pending.  Default errors (not a
    /// provider).
    fn approve_csr(&mut self, node_mac: &[u8]) -> Result<(), String> {
        let _ = node_mac;
        Err(NOT_A_PROVIDER.into())
    }

    /// Provider mode: deny the pending CSR bound to `node_mac`; the enrolling
    /// node observes a `Rejected` outcome on its next poll.  Errors if no CSR for
    /// that MAC is pending.  Default errors (not a provider).
    fn deny_csr(&mut self, node_mac: &[u8]) -> Result<(), String> {
        let _ = node_mac;
        Err(NOT_A_PROVIDER.into())
    }
}

/// Both halves at once: what a single-owner node supplies to one
/// [`WayfinderService`].
///
/// Blanket-implemented over the two halves, so implementing them is all that is
/// ever required and nothing names this trait in an `impl`. It exists so the
/// combined dispatcher keeps one bound, and so callers that genuinely hold both
/// — today's `RouterAdapter`, the web mock, the client tests — are unchanged by
/// the split.
pub trait WayfinderDataProvider: RouterDataProvider + AuthorityDataProvider {}

impl<T: RouterDataProvider + AuthorityDataProvider> WayfinderDataProvider for T {}

/// The disposition of a login attempt against the certificate authority's user
/// store.
///
/// Two variants, not five: unknown account, wrong password, wrong code, locked
/// and disabled all land on [`UserAuthOutcome::Rejected`], because the caller
/// is unauthenticated by definition — the request rides the enrollment tier —
/// and every distinction is an oracle.
#[derive(Debug)]
pub enum UserAuthOutcome {
    /// The credentials verified; carries the session certificate and the anchor
    /// it chains to.
    Issued(EnrollData),
    /// The credentials did not verify, for a reason the caller does not learn.
    Rejected,
}

/// The disposition of a submitted certificate-signing request.  Models the three
/// mutually-exclusive terminal-or-waiting states so an invalid combination (e.g.
/// "pending" alongside an issued certificate) is unrepresentable.
#[derive(Debug)]
pub enum CsrOutcome {
    /// The certificate was issued; carries the cert and the anchor it chains to.
    Issued(EnrollData),
    /// The CSR was accepted and is awaiting operator approval.  The client
    /// should poll `submit_csr` again with the same request.
    Pending,
    /// The CSR was rejected and will not be issued.  Carries a human-readable
    /// reason (bad enrollment token, or an operator denied it).
    Rejected(String),
}

/// One CSR awaiting operator approval, as the management API reports it.
#[derive(Clone)]
pub struct PendingCsrData {
    /// The enrolling node's MAC the certificate would be bound to (raw bytes).
    pub node_mac: Vec<u8>,
    /// The node's Ed25519 identity public key (32 bytes).
    pub ed_pubkey: Vec<u8>,
    /// The node's X25519 public key (32 bytes).
    pub x_pubkey: Vec<u8>,
    /// When the provider first saw this CSR (unix seconds).
    pub requested_at: u64,
}

/// One certificate a provider has issued, as the management API reports it.
#[derive(Clone)]
pub struct IssuedCertData {
    /// The node MAC the certificate is bound to (raw bytes).
    pub node_mac: Vec<u8>,
    /// The node's Ed25519 identity public key (32 bytes).
    pub ed_pubkey: Vec<u8>,
    /// Validity-window start (unix seconds).
    pub not_before: u64,
    /// Validity-window end (unix seconds).
    pub not_after: u64,
    /// Whether the provider has since revoked this node.
    pub revoked: bool,
    /// Whether this is a person's session certificate (`CERT_FLAG_USER`)
    /// rather than a device's membership certificate.
    pub user: bool,
    /// Whether the certificate carries the management-administration
    /// capability (`CERT_FLAG_ADMIN`).
    pub admin: bool,
    /// Whether the certificate carries the read-only management capability
    /// (`CERT_FLAG_VIEWER`).
    pub viewer: bool,
    /// The stable id of the account whose sign-in produced this certificate,
    /// or empty for a device's membership certificate — and for any session
    /// recorded before the authority linked the two.
    ///
    /// A CA-side fact that never reaches the wire: no field of the `IssuedCert`
    /// protobuf carries it, and this type is the authority's in-memory record
    /// as well as its projection.  It is what makes "revoke this account's
    /// sessions" answerable, and it is an *id* rather than a username because a
    /// name can be recycled — see `wayfinder-server`'s `AccountId`.
    pub account_id: Vec<u8>,
}

/// One user account, as the management API reports it.
///
/// Deliberately not `wayfinder-server`'s `UserSummary`: this crate is the wire
/// format and depends on nothing above it. The two say the same thing and the
/// conversion is one `map`, which is the price of that direction of dependency.
///
/// Carries no password hash and no TOTP secret. Neither is recoverable from the
/// authority in the first place, and a projection that could carry one is a
/// projection that eventually does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserAccountData {
    /// The account name presented at sign-in.
    pub username: String,
    /// Whether this account's sessions carry the administration capability.
    pub admin: bool,
    /// Validity window for this account's session certificates, in seconds.
    pub session_ttl_secs: u64,
    /// Whether a second factor is enrolled.
    pub totp_enrolled: bool,
    /// Whether the account can obtain no new sessions.
    pub disabled: bool,
    /// Whether the account is currently locked out after failed sign-ins.
    pub locked: bool,
}

/// A freshly minted invite, as the management API reports it.
///
/// The one moment [`token`](Self::token) exists in readable form: the authority
/// keeps only a domain-separated hash of it, so a caller that drops this value
/// has to revoke the invite and mint another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserInviteMintedData {
    /// The account name the invite will create.
    pub username: String,
    /// The invite token, base32 and unpadded. A bearer credential.
    pub token: String,
    /// Unix seconds after which the invite is refused.
    pub expires_at: u64,
}

/// One pending invite, as an admin triaging them sees it.
///
/// Carries neither the token nor the TOTP secret. The first is stored only as a
/// hash; the second is the thing this whole path exists to keep out of an
/// admin's hands, so a projection that *could* carry it is a projection that
/// eventually does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserInviteData {
    /// The account name the invite will create.
    pub username: String,
    /// Whether the created account will hold the administration capability.
    pub admin: bool,
    /// Validity window for the created account's session certificates.
    pub session_ttl_secs: u64,
    /// Unix seconds the invite was minted at.
    pub created_at: u64,
    /// Unix seconds after which the invite is refused.
    pub expires_at: u64,
    /// Unix seconds registration was started at — when the TOTP secret was
    /// revealed — or 0 if it has not been. The security-relevant field: a
    /// non-zero value with no account to show for it means somebody took the
    /// second factor and did not finish.
    pub started_at: u64,
    /// Unix seconds after which the handle issued at start is dead, or 0.
    pub handle_expires_at: u64,
}

/// What starting a registration reveals: the account's identity and second
/// factor, plus the handle that alone can finish it.
///
/// Returned exactly once per invite — the call that produces it consumes the
/// token — so an implementation must hand it back here or not at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationStartedData {
    /// The account name the invite creates. Not the redeemer's to choose.
    pub username: String,
    /// The `otpauth://` enrolment URI for the account's second factor.
    pub totp_enrolment_uri: String,
    /// The registration handle, base32 and unpadded. Single-use.
    pub handle: String,
    /// Unix seconds after which the handle is dead and the invite is spent.
    pub handle_expires_at: u64,
}

/// The result of a successful CSR: the issued certificate plus the trust anchor
/// it chains to (both raw `wayfinder-auth` wire bytes).
#[derive(Debug)]
pub struct EnrollData {
    /// Raw `MembershipCert` bytes, signed by the mesh root.
    pub cert: Vec<u8>,
    /// Raw `TrustAnchor` bytes for the enrolling node to verify against.
    pub trust_anchor: Vec<u8>,
}

/// Map a provider's log level onto the proto enum.  Total, and deliberately
/// never producing `LOG_LEVEL_UNSPECIFIED`: that value exists only to satisfy
/// proto3's zero-value rule, and a node emitting it would be reporting a record
/// with no level.
/// Project an alarm severity onto its wire enum.
fn proto_alarm_severity(severity: AlarmSeverityData) -> AlarmSeverity {
    match severity {
        AlarmSeverityData::Info => AlarmSeverity::Info,
        AlarmSeverityData::Warning => AlarmSeverity::Warning,
        AlarmSeverityData::Critical => AlarmSeverity::Critical,
    }
}

/// Project an alarm kind onto its wire enum.
///
/// Exhaustive on purpose: a new condition must be given a wire name here rather
/// than falling through to `Unspecified`, which a client renders as "a node
/// newer than this build".
fn proto_alarm_kind(kind: AlarmKindData) -> AlarmKind {
    match kind {
        AlarmKindData::UnauthenticatedTraffic => AlarmKind::UnauthenticatedTraffic,
        AlarmKindData::TrafficFlood => AlarmKind::TrafficFlood,
        AlarmKindData::ManagementAuthFailures => AlarmKind::ManagementAuthFailures,
        AlarmKindData::OgmReplay => AlarmKind::OgmReplay,
        AlarmKindData::RevokedPeer => AlarmKind::RevokedPeer,
        AlarmKindData::LinkErrors => AlarmKind::LinkErrors,
        AlarmKindData::TableSaturation => AlarmKind::TableSaturation,
    }
}

fn proto_log_level(level: LogLevelData) -> LogLevel {
    match level {
        LogLevelData::Error => LogLevel::Error,
        LogLevelData::Warn => LogLevel::Warn,
        LogLevelData::Info => LogLevel::Info,
        LogLevelData::Debug => LogLevel::Debug,
        LogLevelData::Trace => LogLevel::Trace,
    }
}

/// Convert a wire [`EnrollmentPolicy`] into its validated intermediate form,
/// or explain why it cannot be honored.
///
/// The two rejections are values whose *only* possible effect is one no caller
/// could have wanted: a zero certificate lifetime issues certificates that
/// have already expired, and an empty token gates enrollment on a secret no
/// client can present. Both would otherwise be applied silently and lock the
/// mesh against every node that tries to join afterwards.
///
/// `enrollment_token_cleared: false` is rejected on a different ground: the
/// field names the act of clearing the token, so `false` states nothing at
/// all. Treating it as "leave the token alone" would answer `Empty` to a
/// request that changed nothing, which reads to the caller as success.
/// Public because the connection task splits a `SetConfig` between the router
/// and the certificate authority, and the authority half has to be converted
/// before it is sent — the router-side adapter that used to do it no longer
/// sees this field.
pub fn enrollment_policy_data(policy: EnrollmentPolicy) -> Result<EnrollmentPolicyData, String> {
    use crate::wayfinder::v1alpha::enrollment_policy::EnrollmentTokenUpdate;

    if policy.cert_ttl_secs == Some(0) {
        return Err(
            "cert_ttl_secs must be greater than zero: a zero-second certificate \
                    lifetime issues certificates that are already expired"
                .into(),
        );
    }

    let enrollment_token = match policy.enrollment_token_update {
        None => None,
        Some(EnrollmentTokenUpdate::EnrollmentTokenCleared(true)) => Some(TokenUpdate::Clear),
        Some(EnrollmentTokenUpdate::EnrollmentTokenCleared(false)) => {
            return Err(
                "enrollment_token_cleared must be true to clear the token; omit the \
                        field entirely to leave it unchanged"
                    .into(),
            );
        }
        Some(EnrollmentTokenUpdate::EnrollmentToken(token)) if token.is_empty() => {
            return Err(
                "enrollment_token must not be empty: an empty token can never be \
                        presented by an enrolling node. Set enrollment_token_cleared to open \
                        enrollment instead"
                    .into(),
            );
        }
        Some(EnrollmentTokenUpdate::EnrollmentToken(token)) => {
            Some(TokenUpdate::Set(SharedSecret::new(token)))
        }
    };

    Ok(EnrollmentPolicyData {
        auto_approve: policy.auto_approve,
        cert_ttl_secs: policy.cert_ttl_secs,
        enrollment_token,
    })
}

/// A short, stable, non-secret name for a request variant, for logging.
/// Never derived from `Debug` on the whole variant: some request payloads
/// (`SetAuthRequest`'s identity seed, CSR key material) are secret, so only
/// the kind — never the fields — may be logged.
pub fn request_kind_name(k: &RequestKind) -> &'static str {
    match k {
        RequestKind::GetNodeInfo(_) => "GetNodeInfo",
        RequestKind::GetRoutingTable(_) => "GetRoutingTable",
        RequestKind::GetLinkQualityTable(_) => "GetLinkQualityTable",
        RequestKind::ResolveRoute(_) => "ResolveRoute",
        RequestKind::GetOgmSchedule(_) => "GetOgmSchedule",
        RequestKind::GetThroughput(_) => "GetThroughput",
        RequestKind::GetMetrics(_) => "GetMetrics",
        RequestKind::SetAuth(_) => "SetAuth",
        RequestKind::GetTrustAnchor(_) => "GetTrustAnchor",
        RequestKind::SubmitCsr(_) => "SubmitCsr",
        RequestKind::RevokeNode(_) => "RevokeNode",
        RequestKind::GetSecurityStatus(_) => "GetSecurityStatus",
        RequestKind::ListCerts(_) => "ListCerts",
        RequestKind::ListPendingCsrs(_) => "ListPendingCsrs",
        RequestKind::ApproveCsr(_) => "ApproveCsr",
        RequestKind::DenyCsr(_) => "DenyCsr",
        RequestKind::SetConfig(_) => "SetConfig",
        RequestKind::GetKeepaliveTable(_) => "GetKeepaliveTable",
        RequestKind::Authenticate(_) => "Authenticate",
        RequestKind::GetLinkFeaturesTable(_) => "GetLinkFeaturesTable",
        RequestKind::GetLogs(_) => "GetLogs",
        RequestKind::GetAlarms(_) => "GetAlarms",
        RequestKind::GetOwnCert(_) => "GetOwnCert",
        RequestKind::SetLogLevel(_) => "SetLogLevel",
        RequestKind::RevealEnrollmentToken(_) => "RevealEnrollmentToken",
        RequestKind::AuthenticateUser(_) => "AuthenticateUser",
        RequestKind::ListUsers(_) => "ListUsers",
        RequestKind::CreateUser(_) => "CreateUser",
        RequestKind::RemoveUser(_) => "RemoveUser",
        RequestKind::GetVpnEnrollment(_) => "GetVpnEnrollment",
        RequestKind::ListVpnPeers(_) => "ListVpnPeers",
        RequestKind::RevokeVpnPeer(_) => "RevokeVpnPeer",
        RequestKind::CreateUserInvite(_) => "CreateUserInvite",
        RequestKind::ListUserInvites(_) => "ListUserInvites",
        RequestKind::RevokeUserInvite(_) => "RevokeUserInvite",
        RequestKind::BeginUserRegistration(_) => "BeginUserRegistration",
        RequestKind::CompleteUserRegistration(_) => "CompleteUserRegistration",
        RequestKind::RevokeUserSessions(_) => "RevokeUserSessions",
        RequestKind::SetUserRole(_) => "SetUserRole",
        RequestKind::SetUserEnabled(_) => "SetUserEnabled",
        RequestKind::SetUserPassword(_) => "SetUserPassword",
    }
}

/// What kind of record a request deserves in the node's log.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Audited {
    /// Changes node or provider state: new auth material, a config change, a
    /// CSR issued/approved/denied, a node revoked.
    Mutation,
    /// Changes nothing but hands out a secret. Worth the same record as a
    /// mutation and for the same reason — an operator asking "who learned the
    /// enrollment token, and when?" has nowhere else to look — but it is not a
    /// mutation, and a log line calling it one would be a lie about what
    /// happened.
    Disclosure,
    /// Reads public state. Frequent (a dashboard polls several per second), so
    /// logged at `debug!` and off by default.
    Query,
}

/// Classify `k` for [`WayfinderService::handle`]'s audit record.
///
/// Deliberately exhaustive (no wildcard arm) so a newly added `RequestKind`
/// variant forces an explicit classification here rather than silently
/// defaulting to the quietest one.
fn audited(k: &RequestKind) -> Audited {
    match k {
        RequestKind::RevealEnrollmentToken(_) => Audited::Disclosure,

        RequestKind::SetAuth(_)
        | RequestKind::SetConfig(_)
        | RequestKind::SubmitCsr(_)
        | RequestKind::RevokeNode(_)
        | RequestKind::ApproveCsr(_)
        | RequestKind::DenyCsr(_)
        // Changing what a node records is an operator action worth an audit
        // trail, and infrequent enough to afford one.
        | RequestKind::SetLogLevel(_)
        // A login mints a certificate the whole mesh honours, and the record is
        // the only place "who logged in, and when" is answerable. Logged
        // whatever the outcome — a failed login is the more interesting half —
        // and never with the credentials, which `request_kind_name` guarantees
        // by naming the kind and never the fields.
        | RequestKind::AuthenticateUser(_)
        // Creating an account is creating something that can mint a certificate
        // the whole mesh honours. If any request deserves a durable record of
        // who asked, it is this one — and, as above, the record names the kind
        // and never the fields, so the password it carries is never in it.
        | RequestKind::CreateUser(_)
        // And removing one ends somebody's access. Both halves of an account's
        // lifetime leave a record, or the record answers "who was given access"
        // without ever answering "who took it away".
        | RequestKind::RemoveUser(_)
        // Minting a tunnel credential is handing out a bearer secret, so it is
        // audited for the same reason RevealEnrollmentToken is — except that
        // this one also *creates* the thing it discloses, and creates it at a
        // remote coordination server this node cannot later query for "when was
        // this issued". The record here is the only account of it.
        | RequestKind::GetVpnEnrollment(_)
        // Removing a peer's tunnel reachability is an operator action that
        // takes access away, and the retry path for a partially-failed mesh
        // revocation runs through it.
        | RequestKind::RevokeVpnPeer(_)
        // Minting an invite is deciding that an account will exist, with a role
        // chosen now and applied up to a week later. The same reasoning as
        // CreateUser beside it, one step earlier in time.
        | RequestKind::CreateUserInvite(_)
        // And revoking one takes that decision back — often *because* the
        // record shows a start nobody expected.
        | RequestKind::RevokeUserInvite(_)
        // Taking away access somebody currently holds, which is the same
        // reasoning that audits RemoveUser beside it — and this is the half of
        // RemoveUser that actually ends a session, reachable on its own.
        | RequestKind::RevokeUserSessions(_)
        // A mutation, not a Disclosure, despite handing out the account's
        // `otpauth://` URI: it consumes the invite, so classifying it as "reads
        // public state but hands out a secret" would be a lie about what
        // happened.
        //
        // **This record is the durable one.** The invitation's own `started_at`
        // is the shorter-lived account of the same event, not the longer one —
        // a started invite is swept fifteen minutes later when its handle
        // window closes (`CertAuthority::evict_expired_invites`), taking the
        // name and the signal with it. What persists is the log: on a host CA
        // this line reaches the process's journal, which outlives both this
        // bounded ring and the invite record. `started_at` is the *operator's*
        // signal — the thing an admin triaging the panel acts on now — and its
        // disappearance is logged too, for the same reason this is.
        | RequestKind::BeginUserRegistration(_)
        // Creating an account that can mint a certificate the whole mesh
        // honours, *from an anonymous connection*. Strictly more deserving of a
        // record than CreateUser, which at least required a grant to reach.
        | RequestKind::CompleteUserRegistration(_)
        // Changing what an account may do, and — on a demotion — ending the
        // admin sessions it already held. The same reasoning that audits
        // RemoveUser and RevokeUserSessions beside it: this is how somebody's
        // administrative access begins and ends without the account itself
        // changing, and a log that recorded only creation and deletion would
        // answer "who can administer this mesh?" with a roster that was never
        // true.
        | RequestKind::SetUserRole(_)
        // Cutting an account off, and restoring it. Both directions matter: the
        // record of who re-enabled a disabled account is the one an operator
        // wants when the account turns out to have been disabled for a reason.
        | RequestKind::SetUserEnabled(_)
        // Replacing the credential of an account that can mint a certificate
        // the whole mesh honours. As with CreateUser, the record names the kind
        // and never the fields, so the password it carries is never in it.
        | RequestKind::SetUserPassword(_) => Audited::Mutation,

        RequestKind::GetNodeInfo(_)
        | RequestKind::GetRoutingTable(_)
        | RequestKind::GetLinkQualityTable(_)
        | RequestKind::ResolveRoute(_)
        | RequestKind::GetOgmSchedule(_)
        | RequestKind::GetThroughput(_)
        | RequestKind::GetMetrics(_)
        | RequestKind::GetTrustAnchor(_)
        | RequestKind::GetSecurityStatus(_)
        | RequestKind::ListCerts(_)
        | RequestKind::ListPendingCsrs(_)
        | RequestKind::GetKeepaliveTable(_)
        | RequestKind::Authenticate(_)
        | RequestKind::GetLinkFeaturesTable(_)
        // Deliberately a query, and deliberately unlogged: a client polls this
        // on every refresh tick, and a record emitted per poll would fill the
        // very ring the poll is reading.
        | RequestKind::GetLogs(_)
        // A poll, on the same tick as GetLogs and unlogged for the same reason:
        // a record per poll would fill the ring an operator reads next to it.
        | RequestKind::GetAlarms(_)
        // Hands out no secret, so it is a query rather than the disclosure
        // record `RevealEnrollmentToken` earns. A membership certificate is
        // public-key material plus the root's signature over it: every field
        // it carries is already served by `GetSecurityStatus` beside it, and
        // what this adds is the signature, which is what one *verifies* with.
        //
        // Note the reason is that overlap and not "it is on the air anyway" —
        // under `lazy_cert_distribution` this node's OGMs carry an 8-byte
        // fingerprint instead of the certificate, so an argument resting on
        // the medium would be false in a configuration this build supports.
        | RequestKind::GetOwnCert(_)
        // A read of provider state, like ListCerts beside it. Not a disclosure:
        // it hands out no secret, only the roster — and only to a client that
        // already holds a full management grant.
        | RequestKind::ListUsers(_)
        // A read of the coordination server's roster, like ListCerts beside it,
        // and polled by the dashboard the same way.
        | RequestKind::ListVpnPeers(_)
        // A read of provider state, beside ListUsers. The security-relevant
        // signal it carries — a started-but-unfinished invite — is durable in
        // the record itself, so it needs no log line to survive.
        | RequestKind::ListUserInvites(_) => Audited::Query,
    }
}

/// Which owner answers a given request.
///
/// The management API is served from three different places, and a caller that
/// knows which one *before* it sends anything can route a request to the right
/// owner rather than discovering the answer from an error. That is what lets
/// the certificate authority live off the router's event loop — see
/// `docs/design/implemented/13-certificate-authority-off-the-router-loop.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestFacet {
    /// Answered from router state alone, by [`handle_router`].
    Router,
    /// Answered from certificate-authority state alone, by [`handle_authority`].
    Authority,
    /// Answered by the transport itself rather than by either dispatcher: the
    /// VPN requests are served in the connection task (they are scoped to the
    /// caller's own identity, which no provider holds), and `Authenticate` is
    /// the transport's own first frame.
    ///
    /// A fork on this enum must still handle one arriving anyway — an
    /// `Authenticate` repeated mid-connection reaches the router half, which
    /// declines it. Answer that with [`handle_unowned`], which names the
    /// protocol error, not with the not-a-provider message.
    Transport,
}

/// Classify `kind` by the owner that answers it.
///
/// Exhaustive over [`RequestKind`] on purpose — a new request kind must be
/// given an owner here before it will compile, which is the check that keeps a
/// forked caller from silently sending it to the wrong half.
pub fn request_facet(kind: &RequestKind) -> RequestFacet {
    match kind {
        RequestKind::GetAlarms(_)
        | RequestKind::GetKeepaliveTable(_)
        | RequestKind::GetLinkFeaturesTable(_)
        | RequestKind::GetLinkQualityTable(_)
        | RequestKind::GetLogs(_)
        | RequestKind::GetMetrics(_)
        | RequestKind::GetNodeInfo(_)
        | RequestKind::GetOgmSchedule(_)
        // Answered from the router's live auth state, like the security status
        // beside it — never from wherever the certificate was loaded, which is
        // the authority's business and not every node has one.
        | RequestKind::GetOwnCert(_)
        | RequestKind::GetRoutingTable(_)
        | RequestKind::GetSecurityStatus(_)
        | RequestKind::GetThroughput(_)
        | RequestKind::ResolveRoute(_)
        | RequestKind::SetAuth(_)
        | RequestKind::SetConfig(_)
        | RequestKind::SetLogLevel(_) => RequestFacet::Router,
        RequestKind::ApproveCsr(_)
        | RequestKind::AuthenticateUser(_)
        | RequestKind::CreateUser(_)
        | RequestKind::DenyCsr(_)
        | RequestKind::GetTrustAnchor(_)
        | RequestKind::ListCerts(_)
        | RequestKind::ListPendingCsrs(_)
        | RequestKind::ListUsers(_)
        | RequestKind::RemoveUser(_)
        | RequestKind::RevealEnrollmentToken(_)
        | RequestKind::RevokeNode(_)
        | RequestKind::SubmitCsr(_)
        // The invite store lives beside the user store, on the authority. The
        // two redemption kinds included: an anonymous registrant reaches them
        // with no credential, but what answers them is still authority state
        // and nothing the router holds.
        | RequestKind::CreateUserInvite(_)
        | RequestKind::ListUserInvites(_)
        | RequestKind::RevokeUserInvite(_)
        | RequestKind::BeginUserRegistration(_)
        | RequestKind::CompleteUserRegistration(_)
        | RequestKind::RevokeUserSessions(_)
        | RequestKind::SetUserRole(_)
        | RequestKind::SetUserEnabled(_)
        | RequestKind::SetUserPassword(_) => RequestFacet::Authority,
        RequestKind::Authenticate(_)
        | RequestKind::GetVpnEnrollment(_)
        | RequestKind::ListVpnPeers(_)
        | RequestKind::RevokeVpnPeer(_) => RequestFacet::Transport,
    }
}

/// Emit the audit record for `request`, if its kind warrants one.
///
/// Split out of [`WayfinderService::handle`] so a caller that forks a request
/// between the two dispatchers still records it exactly once, where the request
/// arrives rather than once per half.
pub fn audit_request(request: &WayfinderRequest) {
    if let Some(kind) = &request.request {
        let name = request_kind_name(kind);
        match audited(kind) {
            Audited::Mutation => info!(kind = name, "management API mutation"),
            Audited::Disclosure => info!(kind = name, "management API secret disclosed"),
            Audited::Query => {}
        }
    }
}

/// Answer `request` from router state.
///
/// Returns the request unconsumed as `Err` when it is not
/// [`RequestFacet::Router`], so a caller holding only this half can forward it
/// to the owner that can answer it — rather than returning an error from a half
/// that was never asked. Does not audit; see [`audit_request`].
pub fn handle_router<P: RouterDataProvider>(
    provider: &mut P,
    request: WayfinderRequest,
) -> Result<WayfinderResponse, WayfinderRequest> {
    let response = match request.request {
        Some(RequestKind::GetNodeInfo(_)) => ResponseKind::NodeInfo(NodeInfo {
            node_id: provider.node_id(),
            num_originators: provider.num_originators(),
            auth_locked: provider.auth_locked(),
            runtime_config_active: provider.runtime_config_active(),
        }),
        Some(RequestKind::GetRoutingTable(_)) => {
            let entries = provider
                .routing_table()
                .into_iter()
                .map(|e| RoutingEntry {
                    destination: e.destination,
                    next_hop: e.next_hop,
                    tq: e.tq,
                    last_seqno: e.last_seqno,
                    paths: e
                        .paths
                        .into_iter()
                        .map(|p| NeighborPath {
                            neighbor_id: p.neighbor_id,
                            tq: p.tq,
                            last_seqno: p.last_seqno,
                            proven: p.proven,
                        })
                        .collect(),
                })
                .collect();
            ResponseKind::RoutingTable(RoutingTable { entries })
        }
        Some(RequestKind::GetLinkQualityTable(_)) => {
            let entries = provider
                .link_quality_table()
                .into_iter()
                .map(|e| LinkQualityEntry {
                    neighbor_id: e.neighbor_id,
                    iface_idx: e.iface_idx,
                    ewma_quality: e.ewma_quality,
                    sample_count: e.sample_count,
                    iface_name: e.iface_name,
                })
                .collect();
            ResponseKind::LinkQualityTable(LinkQualityTable { entries })
        }
        Some(RequestKind::GetLinkFeaturesTable(_)) => {
            let entries = provider
                .link_features_table()
                .into_iter()
                .map(|e| LinkFeaturesEntry {
                    iface_idx: e.iface_idx,
                    tx_ogm: e.tx_ogm,
                    rx_ogm: e.rx_ogm,
                    tx_data: e.tx_data,
                    rx_data: e.rx_data,
                    tx_keepalive_interval_ms: e.tx_keepalive_interval_ms,
                    iface_name: e.iface_name,
                })
                .collect();
            ResponseKind::LinkFeaturesTable(LinkFeaturesTable { entries })
        }
        Some(RequestKind::GetLogs(req)) => {
            let batch = provider.logs(req.since_seq, req.max_records);
            ResponseKind::Logs(LogRecords {
                records: batch
                    .records
                    .into_iter()
                    .map(|r| LogRecord {
                        seq: r.seq,
                        uptime_ms: r.uptime_ms,
                        level: proto_log_level(r.level) as i32,
                        target: r.target,
                        message: r.message,
                    })
                    .collect(),
                next_seq: batch.next_seq,
                dropped: batch.dropped,
                filter: batch.filter,
            })
        }
        Some(RequestKind::GetAlarms(_)) => {
            let board = provider.alarms();
            ResponseKind::Alarms(Alarms {
                alarms: board
                    .alarms
                    .into_iter()
                    .map(|a| Alarm {
                        kind: proto_alarm_kind(a.kind) as i32,
                        severity: proto_alarm_severity(a.severity) as i32,
                        first_ms: a.first_ms,
                        last_ms: a.last_ms,
                        count: a.count,
                        detail: a.detail,
                        active: a.active,
                        subject: match a.subject {
                            AlarmSubjectData::Node => None,
                            AlarmSubjectData::Peer(id) => Some(AlarmSubjectKind::NodeId(id)),
                            AlarmSubjectData::Interface(idx) => {
                                Some(AlarmSubjectKind::InterfaceIndex(idx))
                            }
                        },
                    })
                    .collect(),
                dropped: board.dropped,
                now_ms: board.now_ms,
            })
        }
        Some(RequestKind::SetLogLevel(req)) => {
            match provider.set_log_level(&req.directives) {
                Ok(directives) => ResponseKind::LogFilter(LogFilter { directives }),
                // A spec that didn't parse. The previous filter is still in
                // force, so this is a report, not a state change.
                Err(message) => ResponseKind::Error(ErrorResponse { message }),
            }
        }
        Some(RequestKind::GetOgmSchedule(_)) => {
            let entries = provider
                .ogm_schedule()
                .into_iter()
                .map(|e| OgmScheduleEntry {
                    iface_idx: e.iface_idx,
                    current_interval_ms: e.current_interval_ms,
                    min_interval_ms: e.min_interval_ms,
                    max_interval_ms: e.max_interval_ms,
                    iface_name: e.iface_name,
                })
                .collect();
            ResponseKind::OgmSchedule(OgmSchedule { entries })
        }
        Some(RequestKind::GetThroughput(_)) => {
            let mut total_rx_bps = 0.0;
            let mut total_rx_fps = 0.0;
            let mut total_tx_bps = 0.0;
            let mut total_tx_fps = 0.0;
            let interfaces = provider
                .throughput()
                .into_iter()
                .map(|e| {
                    // The node-wide rate is the sum of the per-interface
                    // rates, accumulated as we project each entry.
                    total_rx_bps += e.rx_bps;
                    total_rx_fps += e.rx_fps;
                    total_tx_bps += e.tx_bps;
                    total_tx_fps += e.tx_fps;
                    InterfaceThroughput {
                        iface_idx: e.iface_idx,
                        rx_bps: e.rx_bps,
                        rx_fps: e.rx_fps,
                        tx_bps: e.tx_bps,
                        tx_fps: e.tx_fps,
                        iface_name: e.iface_name,
                    }
                })
                .collect();
            ResponseKind::Throughput(Throughput {
                interfaces,
                total_rx_bps,
                total_rx_fps,
                total_tx_bps,
                total_tx_fps,
            })
        }
        Some(RequestKind::GetMetrics(_)) => {
            let m = provider.node_metrics();
            let occ = |o: TableOccupancyData| {
                Some(TableOccupancy {
                    used: o.used,
                    capacity: o.capacity,
                })
            };
            ResponseKind::Metrics(NodeMetrics {
                uptime_secs: m.uptime_secs,
                neighbor_count: m.neighbor_count,
                originators: occ(m.originators),
                broadcast_dedup: occ(m.broadcast_dedup),
                local_mcast_groups: occ(m.local_mcast_groups),
                mcast_memberships: occ(m.mcast_memberships),
                tq_min: m.tq_min,
                tq_max: m.tq_max,
                tq_mean: m.tq_mean,
                paths_max: m.paths_max,
                paths_mean: m.paths_mean,
                oversize_drops: m.oversize_drops,
                relay_oversize_drops: m.relay_oversize_drops,
                cert_store: occ(m.cert_store),
                in_flight_cert_requests: occ(m.in_flight_cert_requests),
                pending_cert_replies: occ(m.pending_cert_replies),
                cert_req_rate: m.cert_req_rate,
                cert_reply_rate: m.cert_reply_rate,
                untaggable_drop_rate: m.untaggable_drop_rate,
            })
        }
        Some(RequestKind::GetSecurityStatus(_)) => {
            let s = provider.security_status();
            ResponseKind::SecurityStatus(GetSecurityStatusResponse {
                auth_enabled: s.auth_enabled,
                mesh_id: s.mesh_id,
                node_mac: s.node_mac,
                cert_not_after: s.cert_not_after,
                revocation_count: s.revocation_count,
                nodes: s
                    .nodes
                    .into_iter()
                    .map(|n| NodeSecurity {
                        node_id: n.node_id,
                        verified: n.verified,
                        cert_not_after: n.cert_not_after,
                        revoked: n.revoked,
                        revocation_not_after: n.revocation_not_after,
                    })
                    .collect(),
                require_auth: s.require_auth,
                lazy_cert_distribution: s.lazy_cert_distribution,
                enrollment: s.enrollment.map(|e| EnrollmentPolicyStatus {
                    auto_approve: e.auto_approve,
                    cert_ttl_secs: e.cert_ttl_secs,
                    enrollment_token_set: e.enrollment_token_set,
                }),
                own_ed_pubkey: s.own_ed_pubkey,
                own_x_pubkey: s.own_x_pubkey,
            })
        }
        Some(RequestKind::GetOwnCert(_)) => match provider.own_cert() {
            Some(pair) => ResponseKind::OwnCert(GetOwnCertResponse {
                cert: pair.cert,
                trust_anchor: pair.trust_anchor,
            }),
            // An error rather than an empty pair: a client that received one
            // would present it, and the refusal would then arrive from the far
            // end, about a credential, naming neither this node nor the
            // enrollment it never had.
            None => ResponseKind::Error(ErrorResponse {
                message: NO_MEMBERSHIP_CERT.into(),
            }),
        },
        Some(RequestKind::ResolveRoute(req)) => match provider.resolve_route(&req.destination) {
            Some(resolution) => ResponseKind::ResolveRoute(ResolveRouteResponse {
                next_hop: resolution.next_hop,
                egress: resolution.egress.map(|d| match d {
                    EgressDecisionData::AllInterfaces => {
                        EgressKind::AllInterfaces(AllInterfacesEgress {})
                    }
                    EgressDecisionData::Interface(idx) => EgressKind::InterfaceIndex(idx),
                }),
            }),
            None => ResponseKind::Error(ErrorResponse {
                message: "invalid destination identifier".into(),
            }),
        },
        Some(RequestKind::SetAuth(set_auth)) => {
            match provider.set_auth(&set_auth.seed, &set_auth.cert, &set_auth.trust_anchor) {
                Ok(_) => ResponseKind::Empty(Empty {}),
                Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
            }
        }
        Some(RequestKind::SetConfig(set_config)) => {
            let raw_config = set_config.config.unwrap_or_default();
            // Validated here rather than in each provider: a rejected value
            // is one that cannot mean what any caller intended, which is a
            // property of the *request* rather than of the node's state, so
            // every implementation would otherwise repeat the same check.
            let enrollment = raw_config
                .enrollment
                .map(enrollment_policy_data)
                .transpose();
            let enrollment = match enrollment {
                Ok(enrollment) => enrollment,
                Err(message) => {
                    return Ok(WayfinderResponse {
                        response: Some(ResponseKind::Error(ErrorResponse { message })),
                    });
                }
            };
            let config = RuntimeConfigData {
                    trickle: raw_config.trickle.map(|t| TrickleConfigData {
                        iface_idx: t.iface_idx,
                        min_interval_ms: t.min_interval_ms,
                        max_interval_ms: t.max_interval_ms,
                    }),
                    lazy_cert_distribution: raw_config.lazy_cert_distribution,
                    link_features: raw_config.link_features.map(|f| LinkFeaturesData {
                        iface_idx: f.iface_idx,
                        tx_ogm: f.tx_ogm,
                        rx_ogm: f.rx_ogm,
                        tx_data: f.tx_data,
                        rx_data: f.rx_data,
                        tx_keepalive: f.tx_keepalive_update.map(|u| match u {
                            crate::wayfinder::v1alpha::link_features::TxKeepaliveUpdate::TxKeepaliveDisabled(_) => None,
                            crate::wayfinder::v1alpha::link_features::TxKeepaliveUpdate::TxKeepaliveIntervalMs(ms) => {
                                Some(ms)
                            }
                        }),
                    }),
                    require_auth: raw_config.require_auth,
                    enrollment,
                };
            match provider.set_config(config) {
                Ok(_) => ResponseKind::Empty(Empty {}),
                Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
            }
        }
        Some(RequestKind::GetKeepaliveTable(_)) => {
            let entries = provider
                .keepalive_table()
                .into_iter()
                .map(|e| KeepAliveEntry {
                    neighbor_id: e.neighbor_id,
                    ms_since_last_heard: e.ms_since_last_heard,
                    interval_estimate_ms: e.interval_estimate_ms,
                    missed: e.missed,
                })
                .collect();
            ResponseKind::KeepaliveTable(KeepAliveTable { entries })
        }

        other => return Err(WayfinderRequest { request: other }),
    };

    Ok(WayfinderResponse {
        response: Some(response),
    })
}

/// Answer `request` from certificate-authority state.
///
/// The mirror of [`handle_router`]: returns the request unconsumed as `Err`
/// when it is not [`RequestFacet::Authority`].
pub fn handle_authority<P: AuthorityDataProvider>(
    provider: &mut P,
    request: WayfinderRequest,
) -> Result<WayfinderResponse, WayfinderRequest> {
    let response = match request.request {
        Some(RequestKind::RevealEnrollmentToken(_)) => match provider.reveal_enrollment_token() {
            Ok(admission) => ResponseKind::EnrollmentToken(RevealEnrollmentTokenResponse {
                admission: Some(match admission {
                    EnrollmentAdmission::Open => Admission::Open(Empty {}),
                    EnrollmentAdmission::Token(token) => Admission::Token(token.expose().into()),
                }),
            }),
            Err(message) => ResponseKind::Error(ErrorResponse { message }),
        },
        Some(RequestKind::GetTrustAnchor(_)) => match provider.get_trust_anchor() {
            Ok(trust_anchor) => ResponseKind::TrustAnchor(GetTrustAnchorResponse { trust_anchor }),
            Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
        },
        Some(RequestKind::SubmitCsr(req)) => match provider.submit_csr(
            &req.node_mac,
            &req.ed_pubkey,
            &req.x_pubkey,
            &req.enrollment_token,
        ) {
            Ok(outcome) => {
                let variant = match outcome {
                    CsrOutcome::Issued(data) => CsrOutcomeKind::Issued(CsrIssued {
                        cert: data.cert,
                        trust_anchor: data.trust_anchor,
                    }),
                    CsrOutcome::Pending => CsrOutcomeKind::Pending(CsrPending {}),
                    CsrOutcome::Rejected(reason) => {
                        CsrOutcomeKind::Rejected(CsrRejected { reason })
                    }
                };
                ResponseKind::SubmitCsr(SubmitCsrResponse {
                    outcome: Some(variant),
                })
            }
            Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
        },
        Some(RequestKind::AuthenticateUser(req)) => match provider.authenticate_user(
            &req.username,
            &req.password,
            &req.totp_code,
            &req.ed_pubkey,
            &req.x_pubkey,
        ) {
            Ok(outcome) => {
                let variant = match outcome {
                    UserAuthOutcome::Issued(data) => {
                        AuthenticateUserOutcomeKind::Issued(UserSessionIssued {
                            cert: data.cert,
                            trust_anchor: data.trust_anchor,
                        })
                    }
                    // One message for every reason, composed here rather
                    // than by the provider so no implementation can widen
                    // it into something branchable.
                    UserAuthOutcome::Rejected => {
                        AuthenticateUserOutcomeKind::Rejected(UserSessionRejected {
                            message: "authentication denied".into(),
                        })
                    }
                };
                ResponseKind::AuthenticateUser(AuthenticateUserResponse {
                    outcome: Some(variant),
                })
            }
            Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
        },
        Some(RequestKind::RevokeNode(req)) => match provider.revoke_node(&req.node_mac) {
            Ok(()) => ResponseKind::Empty(Empty {}),
            Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
        },
        Some(RequestKind::ListCerts(_)) => match provider.list_certs() {
            Ok(certs) => ResponseKind::ListCerts(ListCertsResponse {
                certs: certs
                    .into_iter()
                    .map(|c| IssuedCert {
                        node_mac: c.node_mac,
                        ed_pubkey: c.ed_pubkey,
                        not_before: c.not_before,
                        not_after: c.not_after,
                        revoked: c.revoked,
                        user: c.user,
                        admin: c.admin,
                        viewer: c.viewer,
                    })
                    .collect(),
            }),
            Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
        },
        Some(RequestKind::ListUsers(_)) => match provider.list_users() {
            Ok(users) => ResponseKind::ListUsers(ListUsersResponse {
                users: users
                    .into_iter()
                    .map(|u| UserAccount {
                        username: u.username,
                        admin: u.admin,
                        session_ttl_secs: u.session_ttl_secs,
                        totp_enrolled: u.totp_enrolled,
                        disabled: u.disabled,
                        locked: u.locked,
                    })
                    .collect(),
            }),
            Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
        },
        Some(RequestKind::CreateUser(req)) => match provider.create_user(
            &req.username,
            &req.password,
            req.admin,
            req.session_ttl_secs,
            req.no_totp,
        ) {
            Ok(totp_enrolment_uri) => {
                ResponseKind::CreateUser(CreateUserResponse { totp_enrolment_uri })
            }
            Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
        },
        Some(RequestKind::RemoveUser(req)) => match provider.remove_user(&req.username) {
            Ok(()) => ResponseKind::Empty(Empty {}),
            Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
        },
        Some(RequestKind::CreateUserInvite(req)) => match provider.create_user_invite(
            &req.username,
            req.admin,
            req.session_ttl_secs,
            req.invite_ttl_secs,
        ) {
            Ok(minted) => ResponseKind::CreateUserInvite(CreateUserInviteResponse {
                username: minted.username,
                token: minted.token,
                expires_at: minted.expires_at,
            }),
            Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
        },
        Some(RequestKind::ListUserInvites(_)) => match provider.list_user_invites() {
            Ok((invites, capacity)) => ResponseKind::ListUserInvites(ListUserInvitesResponse {
                invites: invites
                    .into_iter()
                    .map(|i| UserInvite {
                        username: i.username,
                        admin: i.admin,
                        session_ttl_secs: i.session_ttl_secs,
                        created_at: i.created_at,
                        expires_at: i.expires_at,
                        started_at: i.started_at,
                        handle_expires_at: i.handle_expires_at,
                    })
                    .collect(),
                capacity,
            }),
            Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
        },
        Some(RequestKind::RevokeUserSessions(req)) => {
            match provider.revoke_user_sessions(&req.username) {
                Ok(revoked) => {
                    ResponseKind::RevokeUserSessions(RevokeUserSessionsResponse { revoked })
                }
                Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
            }
        }
        Some(RequestKind::SetUserRole(req)) => {
            match provider.set_user_role(&req.username, req.admin) {
                Ok((revoked, changed)) => ResponseKind::SetUserRole(SetUserRoleResponse {
                    revoked,
                    unchanged: !changed,
                }),
                Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
            }
        }
        Some(RequestKind::SetUserEnabled(req)) => {
            match provider.set_user_enabled(&req.username, req.enabled) {
                Ok((revoked, changed)) => ResponseKind::SetUserEnabled(SetUserEnabledResponse {
                    revoked,
                    unchanged: !changed,
                }),
                Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
            }
        }
        Some(RequestKind::SetUserPassword(req)) => {
            match provider.set_user_password(&req.username, &req.password) {
                Ok(()) => ResponseKind::Empty(Empty {}),
                Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
            }
        }
        Some(RequestKind::RevokeUserInvite(req)) => {
            match provider.revoke_user_invite(&req.username) {
                Ok(()) => ResponseKind::Empty(Empty {}),
                Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
            }
        }
        Some(RequestKind::BeginUserRegistration(req)) => {
            match provider.begin_user_registration(&req.token) {
                Ok(started) => ResponseKind::BeginUserRegistration(BeginUserRegistrationResponse {
                    username: started.username,
                    totp_enrolment_uri: started.totp_enrolment_uri,
                    handle: started.handle,
                    handle_expires_at: started.handle_expires_at,
                }),
                Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
            }
        }
        Some(RequestKind::CompleteUserRegistration(req)) => {
            match provider.complete_user_registration(&req.handle, &req.password, &req.totp_code) {
                Ok(()) => ResponseKind::Empty(Empty {}),
                Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
            }
        }
        Some(RequestKind::ListPendingCsrs(_)) => match provider.list_pending_csrs() {
            Ok(pending) => ResponseKind::ListPendingCsrs(ListPendingCsrsResponse {
                pending: pending
                    .into_iter()
                    .map(|p| PendingCsr {
                        node_mac: p.node_mac,
                        ed_pubkey: p.ed_pubkey,
                        x_pubkey: p.x_pubkey,
                        requested_at: p.requested_at,
                    })
                    .collect(),
            }),
            Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
        },
        Some(RequestKind::ApproveCsr(req)) => match provider.approve_csr(&req.node_mac) {
            Ok(()) => ResponseKind::Empty(Empty {}),
            Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
        },
        Some(RequestKind::DenyCsr(req)) => match provider.deny_csr(&req.node_mac) {
            Ok(()) => ResponseKind::Empty(Empty {}),
            Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
        },

        other => return Err(WayfinderRequest { request: other }),
    };

    Ok(WayfinderResponse {
        response: Some(response),
    })
}

/// Answer a request no provider owns: one the transport should already have
/// handled, or an empty one.  Reaching here is a protocol error by the client
/// rather than a capability the node lacks, and each arm says which.
///
/// `pub` because every dispatcher fork needs it as its fallback.  Answering one
/// of these with the not-a-provider error instead — which is what a fork that
/// only knows `handle_router` will reach for — tells a client debugging its
/// handshake that the node is not a certificate authority, which is both false
/// and pointed at the wrong subsystem.
pub fn handle_unowned(request: WayfinderRequest) -> WayfinderResponse {
    let response = match request.request {
        // The VPN requests are answered by the management *transport*, which
        // is the only layer that holds the caller's verified certificate —
        // `GetVpnEnrollment` carries no fields because the identity it
        // mints for is the connection's, and a provider here has no
        // connection to read it from. Reaching this arm means a transport
        // forwarded one instead of handling it, so it fails closed and
        // says so rather than answering with something plausible.
        Some(RequestKind::GetVpnEnrollment(_))
        | Some(RequestKind::ListVpnPeers(_))
        | Some(RequestKind::RevokeVpnPeer(_)) => ResponseKind::Error(ErrorResponse {
            message: "VPN coordination is not served on this transport".into(),
        }),

        // Authentication is handled by the transport before any request
        // reaches this dispatcher (it needs the TLS-authenticated key, which
        // the router-facing provider has no access to). Seeing one here means
        // the client sent it out of order — after already authenticating —
        // which is a protocol error, not a router query.
        Some(RequestKind::Authenticate(_)) => ResponseKind::Error(ErrorResponse {
            message: "unexpected Authenticate request: authentication must be the first \
                          message on a connection and may not be repeated"
                .into(),
        }),
        None => ResponseKind::Error(ErrorResponse {
            message: "empty request".into(),
        }),

        // Unreachable as called: this function only ever sees what both
        // dispatchers declined, which is exactly the transport-owned kinds and
        // `None`. Answered rather than unreachable!() so that a request kind
        // added later without an owner degrades to an error the client can read
        // instead of taking the node down.
        _ => ResponseKind::Error(ErrorResponse {
            message: "request has no handler on this node".into(),
        }),
    };

    WayfinderResponse {
        response: Some(response),
    }
}

/// Stateful handler that maps [`WayfinderRequest`] → [`WayfinderResponse`].
///
/// `P` is any type implementing [`WayfinderDataProvider`]; pass a reference
/// (`WayfinderService::new(&router)`) or an owned wrapper.
pub struct WayfinderService<P> {
    provider: P,
}

impl<P: WayfinderDataProvider> WayfinderService<P> {
    /// Wrap a data provider in a request handler.
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    /// Dispatch one request to the provider and build the matching response,
    /// mapping any provider error into an [`ErrorResponse`].
    ///
    /// Tries each half in turn against the single provider that implements
    /// both. A caller that owns the halves separately should classify with
    /// [`request_facet`] and call [`handle_router`] / [`handle_authority`]
    /// directly instead.
    pub fn handle(&mut self, request: WayfinderRequest) -> WayfinderResponse {
        audit_request(&request);

        let request = match handle_router(&mut self.provider, request) {
            Ok(response) => return response,
            Err(request) => request,
        };
        match handle_authority(&mut self.provider, request) {
            Ok(response) => response,
            Err(request) => handle_unowned(request),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wayfinder::v1alpha::AuthenticateRequest;
    use crate::wayfinder::v1alpha::GetLinkFeaturesTableRequest;
    use crate::wayfinder::v1alpha::GetLinkQualityTableRequest;
    use crate::wayfinder::v1alpha::GetMetricsRequest;
    use crate::wayfinder::v1alpha::GetNodeInfoRequest;
    use crate::wayfinder::v1alpha::GetOgmScheduleRequest;
    use crate::wayfinder::v1alpha::GetOwnCertRequest;
    use crate::wayfinder::v1alpha::GetRoutingTableRequest;
    use crate::wayfinder::v1alpha::GetSecurityStatusRequest;
    use crate::wayfinder::v1alpha::GetThroughputRequest;
    use crate::wayfinder::v1alpha::GetTrustAnchorRequest;
    use crate::wayfinder::v1alpha::ListUsersRequest;
    use crate::wayfinder::v1alpha::ListVpnPeersRequest;
    use crate::wayfinder::v1alpha::ResolveRouteRequest;
    use crate::wayfinder::v1alpha::RevealEnrollmentTokenRequest;
    use crate::wayfinder::v1alpha::RuntimeConfig;
    use crate::wayfinder::v1alpha::SetConfigRequest;
    use crate::wayfinder::v1alpha::TrickleConfig;
    use crate::wayfinder::v1alpha::enrollment_policy;
    use alloc::vec;

    /// Test double that returns canned responses and records the last
    /// `resolve_route` destination it was called with.
    #[derive(Default)]
    struct MockProvider {
        link_quality: Vec<LinkQualityEntryData>,
        link_features: Vec<LinkFeaturesEntryData>,
        keepalive: Vec<KeepAliveEntryData>,
        ogm_schedule: Vec<OgmScheduleEntryData>,
        throughput: Vec<InterfaceThroughputData>,
        node_metrics: NodeMetricsData,
        route_resolution: Option<RouteResolutionData>,
        // RefCell would be nicer but no_std + alloc here — a Cell of an
        // owned Vec would require Clone gymnastics, so we just leave the
        // resolution as a single fixed answer per test.
        runtime_config_active: bool,
        last_set_config: Option<RuntimeConfigData>,
        /// What `logs` reports back.
        logs: LogsData,
        /// The `(since_seq, max_records)` the last `logs` call was given, so a
        /// test can prove the request's fields reach the provider rather than
        /// being dropped on the way.  A `Cell` because `logs` takes `&self`.
        last_logs_query: core::cell::Cell<(u64, u32)>,
        /// When set, `set_log_level` reports this parse error instead of
        /// accepting the spec.
        set_log_level_error: Option<String>,
        /// The posture this provider reports, so a test can prove the fields
        /// reach the wire rather than being dropped in the projection.
        security_status: SecurityStatusData,
        /// The admission rule this provider reveals, or `None` for a node that
        /// is not a provider at all.
        enrollment_admission: Option<EnrollmentAdmission>,
        /// The board this provider reports, so a test can prove every field
        /// reaches the wire rather than being dropped in the projection.
        alarms: AlarmsData,
        /// What a `create_user_invite` mints, or `None` for a node that is not
        /// a provider.
        invite: Option<UserInviteMintedData>,
        /// The invites `list_user_invites` reports.
        invites: Vec<UserInviteData>,
        /// The invite store's capacity, reported beside the listing.  Zero
        /// stands for "not a provider", so a default `MockProvider` refuses the
        /// listing rather than answering an empty one.
        invite_capacity: u32,
        /// What a `begin_user_registration` reveals, or `None` for a node that
        /// is not a provider.
        registration: Option<RegistrationStartedData>,
        /// Whether `complete_user_registration` succeeds.
        registration_completes: bool,
        /// The certificate pair this node runs under, or `None` for a node
        /// holding none — which is a default `MockProvider`, so a test has to
        /// say it is certified before it can be asked for a certificate.
        own_cert: Option<OwnCertData>,
    }

    impl RouterDataProvider for MockProvider {
        fn node_id(&self) -> Vec<u8> {
            vec![]
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
            self.link_quality.clone()
        }
        fn link_features_table(&self) -> Vec<LinkFeaturesEntryData> {
            self.link_features.clone()
        }
        fn keepalive_table(&self) -> Vec<KeepAliveEntryData> {
            self.keepalive.clone()
        }
        fn ogm_schedule(&self) -> Vec<OgmScheduleEntryData> {
            self.ogm_schedule.clone()
        }
        fn throughput(&self) -> Vec<InterfaceThroughputData> {
            self.throughput.clone()
        }
        fn node_metrics(&self) -> NodeMetricsData {
            self.node_metrics.clone()
        }
        fn resolve_route(&self, _destination: &[u8]) -> Option<RouteResolutionData> {
            self.route_resolution.clone()
        }
        fn set_auth(
            &mut self,
            _seed: &[u8],
            _cert: &[u8],
            _trust_anchor: &[u8],
        ) -> Result<(), String> {
            Ok(())
        }
        fn set_config(&mut self, config: RuntimeConfigData) -> Result<(), String> {
            if let Some(t) = &config.trickle
                && t.iface_idx == u32::MAX
            {
                return Err("interface index out of range".into());
            }
            self.runtime_config_active =
                config.trickle.is_some() || config.lazy_cert_distribution.is_some();
            self.last_set_config = Some(config);
            Ok(())
        }
        fn runtime_config_active(&self) -> bool {
            self.runtime_config_active
        }
        fn alarms(&self) -> AlarmsData {
            self.alarms.clone()
        }
        fn logs(&self, since_seq: u64, max_records: u32) -> LogsData {
            self.last_logs_query.set((since_seq, max_records));
            self.logs.clone()
        }
        fn security_status(&self) -> SecurityStatusData {
            self.security_status.clone()
        }
        fn own_cert(&self) -> Option<OwnCertData> {
            self.own_cert.clone()
        }
        fn set_log_level(&mut self, directives: &str) -> Result<String, String> {
            match &self.set_log_level_error {
                Some(error) => Err(error.clone()),
                // A real node's readback is the spec it just installed, so the
                // mock echoes what it was handed.
                None => Ok(directives.into()),
            }
        }
    }

    impl AuthorityDataProvider for MockProvider {
        fn reveal_enrollment_token(&self) -> Result<EnrollmentAdmission, String> {
            self.enrollment_admission
                .clone()
                .ok_or_else(|| "node is not a certificate-authority provider".into())
        }

        fn create_user_invite(
            &mut self,
            _username: &str,
            _admin: bool,
            _session_ttl_secs: u64,
            _invite_ttl_secs: u64,
        ) -> Result<UserInviteMintedData, String> {
            self.invite.clone().ok_or_else(|| NOT_A_PROVIDER.into())
        }

        fn list_user_invites(&self) -> Result<(Vec<UserInviteData>, u32), String> {
            if self.invite_capacity == 0 {
                return Err(NOT_A_PROVIDER.into());
            }
            Ok((self.invites.clone(), self.invite_capacity))
        }

        fn revoke_user_invite(&mut self, _username: &str) -> Result<(), String> {
            Err(NOT_A_PROVIDER.into())
        }

        fn begin_user_registration(
            &mut self,
            _token: &str,
        ) -> Result<RegistrationStartedData, String> {
            self.registration
                .clone()
                .ok_or_else(|| NOT_A_PROVIDER.into())
        }

        fn complete_user_registration(
            &mut self,
            _handle: &str,
            _password: &str,
            _totp_code: &str,
        ) -> Result<(), String> {
            if self.registration_completes {
                Ok(())
            } else {
                Err(NOT_A_PROVIDER.into())
            }
        }
    }

    /// A `GetLogs` request reaches the provider with its fields intact, and the
    /// batch it returns is projected onto the wire whole — records, resume
    /// point, and the missed-record count alike.
    #[test]
    fn get_logs_forwards_the_query_and_projects_the_batch() {
        let provider = MockProvider {
            logs: LogsData {
                records: vec![LogRecordData {
                    seq: 7,
                    uptime_ms: 1234,
                    level: LogLevelData::Warn,
                    target: "wayfinder::router".into(),
                    message: "drop: no route".into(),
                }],
                next_seq: 8,
                dropped: 3,
                filter: "info".into(),
            },
            ..Default::default()
        };

        let response = handle(
            provider,
            RequestKind::GetLogs(crate::wayfinder::v1alpha::GetLogsRequest {
                since_seq: 5,
                max_records: 20,
            }),
        );

        match response {
            ResponseKind::Logs(logs) => {
                assert_eq!(logs.next_seq, 8);
                assert_eq!(logs.dropped, 3, "the gap must survive onto the wire");
                assert_eq!(logs.records.len(), 1);
                let r = &logs.records[0];
                assert_eq!(r.seq, 7);
                assert_eq!(r.uptime_ms, 1234);
                assert_eq!(r.level, LogLevel::Warn as i32);
                assert_eq!(r.target, "wayfinder::router");
                assert_eq!(r.message, "drop: no route");
            }
            other => panic!("expected Logs, got {}", proto_kind_name(&other)),
        }
    }

    /// The paging fields are the whole contract of a polling client; a dispatch
    /// that dropped them would silently re-send the same batch forever.
    #[test]
    fn get_logs_passes_since_seq_and_max_records_through() {
        let provider = MockProvider::default();
        let mut service = WayfinderService::new(provider);
        service.handle(WayfinderRequest {
            request: Some(RequestKind::GetLogs(
                crate::wayfinder::v1alpha::GetLogsRequest {
                    since_seq: 42,
                    max_records: 9,
                },
            )),
        });
        assert_eq!(service.provider.last_logs_query.get(), (42, 9));
    }

    /// An empty ring is an empty batch, not an error — a node that has logged
    /// nothing yet is a normal node.
    #[test]
    fn get_logs_with_an_empty_ring_returns_an_empty_batch() {
        let response = handle(
            MockProvider::default(),
            RequestKind::GetLogs(Default::default()),
        );
        match response {
            ResponseKind::Logs(logs) => {
                assert!(logs.records.is_empty());
                assert_eq!(logs.dropped, 0);
            }
            other => panic!("expected Logs, got {}", proto_kind_name(&other)),
        }
    }

    /// The board is projected whole: every field of every row, the eviction
    /// count, and the instant `active` was evaluated against.
    ///
    /// `now_ms` and `active` are the two that a projection can plausibly drop
    /// and still look right, and both are load-bearing — without them a client
    /// cannot tell a condition firing now from one that fired an hour ago, and
    /// has no clock of the node's to work it out for itself.
    #[test]
    fn get_alarms_projects_the_whole_board() {
        let provider = MockProvider {
            alarms: AlarmsData {
                alarms: vec![
                    AlarmData {
                        kind: AlarmKindData::ManagementAuthFailures,
                        severity: AlarmSeverityData::Critical,
                        subject: AlarmSubjectData::Peer(vec![0xaa, 0xbb]),
                        first_ms: 1_000,
                        last_ms: 9_000,
                        count: 412,
                        detail: "attempts=412".into(),
                        active: true,
                    },
                    AlarmData {
                        kind: AlarmKindData::LinkErrors,
                        severity: AlarmSeverityData::Warning,
                        subject: AlarmSubjectData::Interface(3),
                        first_ms: 2_000,
                        last_ms: 3_000,
                        count: 7,
                        detail: "errors=7".into(),
                        active: false,
                    },
                ],
                dropped: 5,
                now_ms: 10_000,
            },
            ..Default::default()
        };

        let response = handle(provider, RequestKind::GetAlarms(Default::default()));

        match response {
            ResponseKind::Alarms(board) => {
                assert_eq!(
                    board.dropped, 5,
                    "an evicted row must stay visible as a gap"
                );
                assert_eq!(board.now_ms, 10_000);
                assert_eq!(board.alarms.len(), 2);

                let first = &board.alarms[0];
                assert_eq!(first.kind, AlarmKind::ManagementAuthFailures as i32);
                assert_eq!(first.severity, AlarmSeverity::Critical as i32);
                assert_eq!(first.first_ms, 1_000);
                assert_eq!(first.last_ms, 9_000);
                assert_eq!(first.count, 412);
                assert_eq!(first.detail, "attempts=412");
                assert!(first.active);
                assert_eq!(
                    first.subject,
                    Some(AlarmSubjectKind::NodeId(vec![0xaa, 0xbb]))
                );

                let second = &board.alarms[1];
                assert_eq!(second.kind, AlarmKind::LinkErrors as i32);
                assert_eq!(second.severity, AlarmSeverity::Warning as i32);
                assert!(
                    !second.active,
                    "a latched-but-quiet row is reported, and reported as quiet"
                );
                assert_eq!(second.subject, Some(AlarmSubjectKind::InterfaceIndex(3)));
            }
            other => panic!("expected Alarms, got {}", proto_kind_name(&other)),
        }
    }

    /// An alarm about the node itself carries no subject at all, rather than a
    /// zero-length identifier a client would render as a peer named "".
    #[test]
    fn get_alarms_leaves_a_node_wide_condition_without_a_subject() {
        let provider = MockProvider {
            alarms: AlarmsData {
                alarms: vec![AlarmData {
                    kind: AlarmKindData::TableSaturation,
                    severity: AlarmSeverityData::Warning,
                    subject: AlarmSubjectData::Node,
                    first_ms: 1,
                    last_ms: 2,
                    count: 1,
                    detail: "originators 64/64".into(),
                    active: true,
                }],
                dropped: 0,
                now_ms: 3,
            },
            ..Default::default()
        };

        let response = handle(provider, RequestKind::GetAlarms(Default::default()));

        match response {
            ResponseKind::Alarms(board) => assert_eq!(board.alarms[0].subject, None),
            other => panic!("expected Alarms, got {}", proto_kind_name(&other)),
        }
    }

    /// A node with nothing wrong answers with an empty board, not an error.
    /// That answer *is* the "all systems normal" a client renders, so it has to
    /// be a successful response rather than something a client has to
    /// interpret.
    #[test]
    fn get_alarms_with_an_empty_board_is_a_successful_empty_answer() {
        let response = handle(
            MockProvider::default(),
            RequestKind::GetAlarms(Default::default()),
        );
        match response {
            ResponseKind::Alarms(board) => {
                assert!(board.alarms.is_empty());
                assert_eq!(board.dropped, 0);
            }
            other => panic!("expected Alarms, got {}", proto_kind_name(&other)),
        }
    }

    /// A successful `SetLogLevel` answers with the spec now in force, so a
    /// client can display what it actually got rather than what it asked for.
    #[test]
    fn set_log_level_answers_with_the_effective_spec() {
        let response = handle(
            MockProvider::default(),
            RequestKind::SetLogLevel(crate::wayfinder::v1alpha::SetLogLevelRequest {
                directives: "info,batman=trace".into(),
            }),
        );
        match response {
            ResponseKind::LogFilter(filter) => {
                assert_eq!(filter.directives, "info,batman=trace");
            }
            other => panic!("expected LogFilter, got {}", proto_kind_name(&other)),
        }
    }

    /// A spec the node refuses comes back as an error carrying the reason —
    /// never as a `LogFilter`, which a client would read as "applied".
    #[test]
    fn set_log_level_parse_failure_surfaces_as_an_error_response() {
        let provider = MockProvider {
            set_log_level_error: Some("unknown log level".into()),
            ..Default::default()
        };
        let response = handle(
            provider,
            RequestKind::SetLogLevel(crate::wayfinder::v1alpha::SetLogLevelRequest {
                directives: "wayfinder=verbose".into(),
            }),
        );
        match response {
            ResponseKind::Error(e) => assert_eq!(e.message, "unknown log level"),
            other => panic!("expected Error, got {}", proto_kind_name(&other)),
        }
    }

    /// A node that holds a certificate hands back the pair it is *running*
    /// under — the certificate and the anchor it chains to — so a client can
    /// present that certificate elsewhere without a round trip to the CA to
    /// obtain a copy of something the node already has.
    #[test]
    fn own_cert_reports_the_pair_the_node_runs_under() {
        let provider = MockProvider {
            own_cert: Some(OwnCertData {
                cert: vec![0xc0, 0xff, 0xee],
                trust_anchor: vec![0xa1, 0xa2],
            }),
            ..Default::default()
        };

        match handle(provider, RequestKind::GetOwnCert(GetOwnCertRequest {})) {
            ResponseKind::OwnCert(response) => {
                assert_eq!(response.cert, vec![0xc0, 0xff, 0xee]);
                assert_eq!(response.trust_anchor, vec![0xa1, 0xa2]);
            }
            other => panic!("expected OwnCert, got {}", proto_kind_name(&other)),
        }
    }

    /// A node holding no certificate refuses rather than answering with an
    /// empty pair. The difference matters: an empty `cert` field would reach a
    /// client as a certificate, and it would present it — the request has to
    /// fail where the certificate is missing, not where it is used.
    #[test]
    fn own_cert_on_an_uncertified_node_is_an_error() {
        let provider = MockProvider::default();

        match handle(provider, RequestKind::GetOwnCert(GetOwnCertRequest {})) {
            ResponseKind::Error(e) => assert_eq!(e.message, NO_MEMBERSHIP_CERT),
            other => panic!("expected Error, got {}", proto_kind_name(&other)),
        }
    }

    /// Reading a certificate that already travels on every OGM this node emits
    /// discloses nothing, so it is a query — not the disclosure record
    /// `RevealEnrollmentToken` earns, and not a mutation.
    #[test]
    fn own_cert_is_a_query_answered_by_the_router_half() {
        let kind = RequestKind::GetOwnCert(GetOwnCertRequest {});
        assert_eq!(request_facet(&kind), RequestFacet::Router);
        assert_eq!(request_kind_name(&kind), "GetOwnCert");
        assert_eq!(audited(&kind), Audited::Query);
    }

    fn handle(provider: MockProvider, req: RequestKind) -> ResponseKind {
        WayfinderService::new(provider)
            .handle(WayfinderRequest { request: Some(req) })
            .response
            .expect("service always sets response")
    }

    #[test]
    fn link_quality_request_returns_entries() {
        let provider = MockProvider {
            link_quality: vec![LinkQualityEntryData {
                neighbor_id: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                iface_idx: 1,
                ewma_quality: Some(200),
                sample_count: 42,
                iface_name: "lora0".into(),
            }],
            ..Default::default()
        };

        match handle(
            provider,
            RequestKind::GetLinkQualityTable(GetLinkQualityTableRequest {}),
        ) {
            ResponseKind::LinkQualityTable(table) => {
                assert_eq!(table.entries.len(), 1);
                let e = &table.entries[0];
                assert_eq!(e.neighbor_id, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
                assert_eq!(e.iface_idx, 1);
                assert_eq!(e.ewma_quality, Some(200));
                assert_eq!(e.sample_count, 42);
                assert_eq!(e.iface_name, "lora0", "the interface's name is projected");
            }
            other => panic!(
                "expected LinkQualityTable, got {:?}",
                proto_kind_name(&other)
            ),
        }
    }

    #[test]
    fn link_quality_entry_projects_an_absent_measurement_as_absent() {
        // A metric-less link (raw L2, UDP) is heard but never measured.  The
        // row must reach the wire with `ewma_quality` unset rather than 0, or
        // every consumer renders a healthy wired neighbor as 0% quality.
        let provider = MockProvider {
            link_quality: vec![LinkQualityEntryData {
                neighbor_id: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                iface_idx: 0,
                ewma_quality: None,
                sample_count: 9,
                iface_name: "rawl20".into(),
            }],
            ..Default::default()
        };

        match handle(
            provider,
            RequestKind::GetLinkQualityTable(GetLinkQualityTableRequest {}),
        ) {
            ResponseKind::LinkQualityTable(table) => {
                let e = &table.entries[0];
                assert_eq!(e.ewma_quality, None);
                assert_eq!(
                    e.sample_count, 9,
                    "an unmeasured row still reports the frames it heard"
                );
            }
            other => panic!(
                "expected LinkQualityTable, got {:?}",
                proto_kind_name(&other)
            ),
        }
    }

    #[test]
    fn link_quality_request_with_empty_table_returns_empty_entries() {
        match handle(
            MockProvider::default(),
            RequestKind::GetLinkQualityTable(GetLinkQualityTableRequest {}),
        ) {
            ResponseKind::LinkQualityTable(table) => assert!(table.entries.is_empty()),
            other => panic!(
                "expected LinkQualityTable, got {:?}",
                proto_kind_name(&other)
            ),
        }
    }

    #[test]
    fn link_features_request_returns_entries() {
        let provider = MockProvider {
            link_features: vec![
                LinkFeaturesEntryData {
                    iface_idx: 0,
                    tx_ogm: false,
                    rx_ogm: true,
                    tx_data: true,
                    rx_data: true,
                    tx_keepalive_interval_ms: Some(3000),
                    iface_name: "lora0".into(),
                },
                LinkFeaturesEntryData {
                    iface_idx: 1,
                    tx_ogm: true,
                    rx_ogm: true,
                    tx_data: true,
                    rx_data: true,
                    tx_keepalive_interval_ms: None,
                    // An interface nobody named stays empty on the wire.
                    iface_name: String::new(),
                },
            ],
            ..Default::default()
        };

        match handle(
            provider,
            RequestKind::GetLinkFeaturesTable(GetLinkFeaturesTableRequest {}),
        ) {
            ResponseKind::LinkFeaturesTable(table) => {
                assert_eq!(table.entries.len(), 2);
                let e0 = &table.entries[0];
                assert_eq!(e0.iface_idx, 0);
                assert!(!e0.tx_ogm);
                assert!(e0.rx_ogm);
                assert!(e0.tx_data);
                assert!(e0.rx_data);
                assert_eq!(e0.tx_keepalive_interval_ms, Some(3000));
                assert_eq!(e0.iface_name, "lora0");
                assert_eq!(table.entries[1].tx_keepalive_interval_ms, None);
                assert_eq!(
                    table.entries[1].iface_name, "",
                    "an unnamed interface carries an empty name, not a placeholder"
                );
            }
            other => panic!(
                "expected LinkFeaturesTable, got {:?}",
                proto_kind_name(&other)
            ),
        }
    }

    #[test]
    fn link_features_request_with_no_interfaces_returns_empty_entries() {
        match handle(
            MockProvider::default(),
            RequestKind::GetLinkFeaturesTable(GetLinkFeaturesTableRequest {}),
        ) {
            ResponseKind::LinkFeaturesTable(table) => assert!(table.entries.is_empty()),
            other => panic!(
                "expected LinkFeaturesTable, got {:?}",
                proto_kind_name(&other)
            ),
        }
    }

    #[test]
    fn resolve_route_returns_next_hop_and_interface_index() {
        let provider = MockProvider {
            route_resolution: Some(RouteResolutionData {
                next_hop: vec![1, 2, 3, 4, 5, 6],
                egress: Some(EgressDecisionData::Interface(2)),
            }),
            ..Default::default()
        };

        match handle(
            provider,
            RequestKind::ResolveRoute(ResolveRouteRequest {
                destination: vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            }),
        ) {
            ResponseKind::ResolveRoute(resp) => {
                assert_eq!(resp.next_hop, vec![1, 2, 3, 4, 5, 6]);
                match resp.egress {
                    Some(EgressKind::InterfaceIndex(idx)) => assert_eq!(idx, 2),
                    other => panic!("expected InterfaceIndex egress, got {other:?}"),
                }
            }
            other => panic!("expected ResolveRoute, got {:?}", proto_kind_name(&other)),
        }
    }

    #[test]
    fn resolve_route_with_broadcast_returns_all_interfaces() {
        let provider = MockProvider {
            route_resolution: Some(RouteResolutionData {
                next_hop: vec![0xff; 6],
                egress: Some(EgressDecisionData::AllInterfaces),
            }),
            ..Default::default()
        };

        match handle(
            provider,
            RequestKind::ResolveRoute(ResolveRouteRequest {
                destination: vec![0xff; 6],
            }),
        ) {
            ResponseKind::ResolveRoute(resp) => {
                assert_eq!(resp.next_hop, vec![0xff; 6]);
                assert!(
                    matches!(resp.egress, Some(EgressKind::AllInterfaces(_))),
                    "expected AllInterfaces egress"
                );
            }
            other => panic!("expected ResolveRoute, got {:?}", proto_kind_name(&other)),
        }
    }

    #[test]
    fn resolve_route_unknown_destination_returns_no_egress() {
        let provider = MockProvider {
            route_resolution: Some(RouteResolutionData {
                next_hop: vec![0x99; 6],
                egress: None,
            }),
            ..Default::default()
        };

        match handle(
            provider,
            RequestKind::ResolveRoute(ResolveRouteRequest {
                destination: vec![0x99; 6],
            }),
        ) {
            ResponseKind::ResolveRoute(resp) => {
                assert_eq!(resp.next_hop, vec![0x99; 6]);
                assert!(resp.egress.is_none(), "egress should be unset");
            }
            other => panic!("expected ResolveRoute, got {:?}", proto_kind_name(&other)),
        }
    }

    #[test]
    fn resolve_route_with_invalid_destination_returns_error() {
        // Provider returns None to signal "destination bytes don't match
        // this address family" — service must surface that as an Error.
        let provider = MockProvider {
            route_resolution: None,
            ..Default::default()
        };

        match handle(
            provider,
            RequestKind::ResolveRoute(ResolveRouteRequest {
                destination: vec![0x01, 0x02], // wrong length for MAC
            }),
        ) {
            ResponseKind::Error(err) => assert!(!err.message.is_empty()),
            other => panic!("expected Error, got {:?}", proto_kind_name(&other)),
        }
    }

    #[test]
    fn set_config_with_trickle_forwards_to_provider_and_returns_empty() {
        match handle(
            MockProvider::default(),
            RequestKind::SetConfig(SetConfigRequest {
                config: Some(RuntimeConfig {
                    trickle: Some(TrickleConfig {
                        iface_idx: 2,
                        min_interval_ms: 500,
                        max_interval_ms: 4000,
                    }),
                    lazy_cert_distribution: None,
                    link_features: None,
                    ..Default::default()
                }),
            }),
        ) {
            ResponseKind::Empty(_) => {}
            other => panic!("expected Empty, got {:?}", proto_kind_name(&other)),
        }
    }

    #[test]
    fn set_config_with_no_fields_set_is_a_no_op() {
        match handle(
            MockProvider::default(),
            RequestKind::SetConfig(SetConfigRequest {
                config: Some(RuntimeConfig {
                    trickle: None,
                    lazy_cert_distribution: None,
                    link_features: None,

                    ..Default::default()
                }),
            }),
        ) {
            ResponseKind::Empty(_) => {}
            other => panic!("expected Empty, got {:?}", proto_kind_name(&other)),
        }
    }

    /// Setting `lazy_cert_distribution` alone (no trickle field) is forwarded
    /// to the provider and answered with an empty response, mirroring the
    /// trickle-only case above.
    #[test]
    fn set_config_with_lazy_cert_distribution_forwards_to_provider_and_returns_empty() {
        match handle(
            MockProvider::default(),
            RequestKind::SetConfig(SetConfigRequest {
                config: Some(RuntimeConfig {
                    trickle: None,
                    lazy_cert_distribution: Some(true),
                    link_features: None,

                    ..Default::default()
                }),
            }),
        ) {
            ResponseKind::Empty(_) => {}
            other => panic!("expected Empty, got {:?}", proto_kind_name(&other)),
        }
    }

    /// The fail-closed gate reaches the provider as a present `require_auth`,
    /// distinct from the "leave it alone" that every other request carries.
    #[test]
    fn set_config_with_require_auth_forwards_to_provider_and_returns_empty() {
        let mut service = WayfinderService::new(MockProvider::default());
        let response = service.handle(WayfinderRequest {
            request: Some(RequestKind::SetConfig(SetConfigRequest {
                config: Some(RuntimeConfig {
                    require_auth: Some(true),
                    ..Default::default()
                }),
            })),
        });

        match response.response.expect("service always sets response") {
            ResponseKind::Empty(_) => {}
            other => panic!("expected Empty, got {:?}", proto_kind_name(&other)),
        }
        assert_eq!(
            service
                .provider
                .last_set_config
                .as_ref()
                .expect("set_config was called")
                .require_auth,
            Some(true)
        );
    }

    /// An enrollment-policy update reaches the provider field by field, with
    /// the token's `oneof` resolved into the closed [`TokenUpdate`].
    #[test]
    fn set_config_with_enrollment_policy_forwards_each_field() {
        let mut service = WayfinderService::new(MockProvider::default());
        service.handle(WayfinderRequest {
            request: Some(RequestKind::SetConfig(SetConfigRequest {
                config: Some(RuntimeConfig {
                    enrollment: Some(EnrollmentPolicy {
                        auto_approve: Some(false),
                        cert_ttl_secs: Some(3600),
                        enrollment_token_update: Some(
                            enrollment_policy::EnrollmentTokenUpdate::EnrollmentToken(
                                "hunter2".into(),
                            ),
                        ),
                    }),
                    ..Default::default()
                }),
            })),
        });

        let policy = service
            .provider
            .last_set_config
            .as_ref()
            .expect("set_config was called")
            .enrollment
            .as_ref()
            .expect("enrollment policy forwarded");
        assert_eq!(policy.auto_approve, Some(false));
        assert_eq!(policy.cert_ttl_secs, Some(3600));
        assert_eq!(
            policy.enrollment_token,
            Some(TokenUpdate::Set(SharedSecret::new("hunter2")))
        );
    }

    /// Clearing the token is the one thing a default-constructed
    /// `EnrollmentPolicy` must never do by accident, so only an explicit
    /// `true` clears it.
    #[test]
    fn set_config_enrollment_token_cleared_true_clears_the_token() {
        let mut service = WayfinderService::new(MockProvider::default());
        service.handle(WayfinderRequest {
            request: Some(RequestKind::SetConfig(SetConfigRequest {
                config: Some(RuntimeConfig {
                    enrollment: Some(EnrollmentPolicy {
                        enrollment_token_update: Some(
                            enrollment_policy::EnrollmentTokenUpdate::EnrollmentTokenCleared(true),
                        ),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            })),
        });

        assert_eq!(
            service
                .provider
                .last_set_config
                .as_ref()
                .expect("set_config was called")
                .enrollment
                .as_ref()
                .expect("enrollment policy forwarded")
                .enrollment_token,
            Some(TokenUpdate::Clear)
        );
    }

    /// `enrollment_token_cleared: false` is refused rather than read as
    /// "leave it unchanged": the field means "clear the token", and a client
    /// that sent `false` did not mean it, so answering `Empty` would report a
    /// change that never happened.
    #[test]
    fn set_config_rejects_enrollment_token_cleared_false() {
        match handle(
            MockProvider::default(),
            RequestKind::SetConfig(SetConfigRequest {
                config: Some(RuntimeConfig {
                    enrollment: Some(EnrollmentPolicy {
                        enrollment_token_update: Some(
                            enrollment_policy::EnrollmentTokenUpdate::EnrollmentTokenCleared(false),
                        ),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            }),
        ) {
            ResponseKind::Error(err) => assert!(!err.message.is_empty()),
            other => panic!("expected Error, got {:?}", proto_kind_name(&other)),
        }
    }

    /// An empty token would gate enrollment on a secret no client can present,
    /// locking the mesh against every future member.
    #[test]
    fn set_config_rejects_an_empty_enrollment_token() {
        match handle(
            MockProvider::default(),
            RequestKind::SetConfig(SetConfigRequest {
                config: Some(RuntimeConfig {
                    enrollment: Some(EnrollmentPolicy {
                        enrollment_token_update: Some(
                            enrollment_policy::EnrollmentTokenUpdate::EnrollmentToken(String::new()),
                        ),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            }),
        ) {
            ResponseKind::Error(err) => assert!(!err.message.is_empty()),
            other => panic!("expected Error, got {:?}", proto_kind_name(&other)),
        }
    }

    /// A zero certificate lifetime issues certificates that have already
    /// expired, so every node enrolling afterwards would be refused by the
    /// mesh it just joined.
    #[test]
    fn set_config_rejects_a_zero_cert_ttl() {
        match handle(
            MockProvider::default(),
            RequestKind::SetConfig(SetConfigRequest {
                config: Some(RuntimeConfig {
                    enrollment: Some(EnrollmentPolicy {
                        cert_ttl_secs: Some(0),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            }),
        ) {
            ResponseKind::Error(err) => assert!(!err.message.is_empty()),
            other => panic!("expected Error, got {:?}", proto_kind_name(&other)),
        }
    }

    /// The posture fields and the provider's enrollment policy are projected
    /// onto the wire, so the dashboard can show what it is about to edit.
    #[test]
    fn security_status_projects_posture_and_enrollment_policy() {
        let provider = MockProvider {
            security_status: SecurityStatusData {
                auth_enabled: true,
                require_auth: true,
                lazy_cert_distribution: true,
                enrollment: Some(EnrollmentPolicyStatusData {
                    auto_approve: false,
                    cert_ttl_secs: 86_400,
                    enrollment_token_set: true,
                }),
                ..Default::default()
            },
            ..Default::default()
        };

        match handle(
            provider,
            RequestKind::GetSecurityStatus(GetSecurityStatusRequest {}),
        ) {
            ResponseKind::SecurityStatus(status) => {
                assert!(status.require_auth);
                assert!(status.lazy_cert_distribution);
                let enrollment = status.enrollment.expect("provider reports a policy");
                assert!(!enrollment.auto_approve);
                assert_eq!(enrollment.cert_ttl_secs, 86_400);
                assert!(
                    enrollment.enrollment_token_set,
                    "the status reports that a token is set"
                );
            }
            other => panic!("expected SecurityStatus, got {:?}", proto_kind_name(&other)),
        }
    }

    /// The polled status says a token is required and never what it is.
    ///
    /// This response rides a once-a-second poll into a browser; a secret on it
    /// is disclosed continuously to everything that touches the snapshot, for
    /// the sake of an operator who reads it perhaps twice in the life of a
    /// mesh.
    #[test]
    fn the_polled_security_status_carries_no_secret() {
        let provider = MockProvider {
            security_status: SecurityStatusData {
                enrollment: Some(EnrollmentPolicyStatusData {
                    auto_approve: true,
                    cert_ttl_secs: 86_400,
                    enrollment_token_set: true,
                }),
                ..Default::default()
            },
            ..Default::default()
        };

        let ResponseKind::SecurityStatus(status) = handle(
            provider,
            RequestKind::GetSecurityStatus(GetSecurityStatusRequest {}),
        ) else {
            panic!("expected SecurityStatus");
        };
        let mut buf = Vec::new();
        prost::Message::encode(&status, &mut buf).unwrap();
        assert!(
            !buf.windows(7).any(|w| w == b"join-us"),
            "no token value appears anywhere in the encoded status"
        );
    }

    /// The token is handed over by its own request, and a provider with none
    /// says so as a distinct answer rather than as an empty string.
    #[test]
    fn revealing_the_token_is_its_own_request() {
        let provider = MockProvider {
            enrollment_admission: Some(EnrollmentAdmission::Token(SharedSecret::new("join-us"))),
            ..Default::default()
        };
        match handle(
            provider,
            RequestKind::RevealEnrollmentToken(RevealEnrollmentTokenRequest {}),
        ) {
            ResponseKind::EnrollmentToken(response) => assert_eq!(
                response.admission,
                Some(
                    crate::wayfinder::v1alpha::reveal_enrollment_token_response::Admission::Token(
                        "join-us".into()
                    )
                )
            ),
            other => panic!(
                "expected EnrollmentToken, got {:?}",
                proto_kind_name(&other)
            ),
        }

        let open = MockProvider {
            enrollment_admission: Some(EnrollmentAdmission::Open),
            ..Default::default()
        };
        match handle(
            open,
            RequestKind::RevealEnrollmentToken(RevealEnrollmentTokenRequest {}),
        ) {
            ResponseKind::EnrollmentToken(response) => assert!(
                matches!(
                    response.admission,
                    Some(crate::wayfinder::v1alpha::reveal_enrollment_token_response::Admission::Open(_))
                ),
                "an open provider answers Open, not an empty token"
            ),
            other => panic!("expected EnrollmentToken, got {:?}", proto_kind_name(&other)),
        }
    }

    /// A node that is not a provider has no token to reveal, and says so as an
    /// error rather than as "open" — which would read as "anyone may join".
    #[test]
    fn revealing_the_token_on_a_non_provider_is_an_error() {
        match handle(
            MockProvider::default(),
            RequestKind::RevealEnrollmentToken(RevealEnrollmentTokenRequest {}),
        ) {
            ResponseKind::Error(_) => {}
            other => panic!("expected Error, got {:?}", proto_kind_name(&other)),
        }
    }

    /// A secret does not print itself.
    ///
    /// The derived `Debug` on the prost type printed the token in full through
    /// any `{:?}`, which is one `tracing` call away from the log ring that
    /// `GetLogs` serves to a browser.
    #[test]
    fn a_shared_secret_redacts_itself_in_debug() {
        let secret = SharedSecret::new("join-us");

        assert!(
            !alloc::format!("{secret:?}").contains("join-us"),
            "the secret must not print itself: {secret:?}"
        );
        assert_eq!(
            secret.expose(),
            "join-us",
            "and is still readable on purpose"
        );
    }

    /// A node that is not a provider reports no enrollment policy at all,
    /// rather than a default-valued one: "no policy to change here" and "a
    /// policy that happens to be all-defaults" are different claims, and the
    /// dashboard hides the editor on the former.
    #[test]
    fn security_status_omits_the_enrollment_policy_on_a_non_provider() {
        match handle(
            MockProvider::default(),
            RequestKind::GetSecurityStatus(GetSecurityStatusRequest {}),
        ) {
            ResponseKind::SecurityStatus(status) => assert!(status.enrollment.is_none()),
            other => panic!("expected SecurityStatus, got {:?}", proto_kind_name(&other)),
        }
    }

    #[test]
    fn set_config_provider_error_surfaces_as_error_response() {
        match handle(
            MockProvider::default(),
            RequestKind::SetConfig(SetConfigRequest {
                config: Some(RuntimeConfig {
                    trickle: Some(TrickleConfig {
                        iface_idx: u32::MAX,
                        min_interval_ms: 500,
                        max_interval_ms: 4000,
                    }),
                    lazy_cert_distribution: None,
                    link_features: None,
                    ..Default::default()
                }),
            }),
        ) {
            ResponseKind::Error(err) => assert!(!err.message.is_empty()),
            other => panic!("expected Error, got {:?}", proto_kind_name(&other)),
        }
    }

    #[test]
    fn node_info_reports_runtime_config_active() {
        let provider = MockProvider {
            runtime_config_active: true,
            ..Default::default()
        };

        match handle(provider, RequestKind::GetNodeInfo(GetNodeInfoRequest {})) {
            ResponseKind::NodeInfo(info) => assert!(info.runtime_config_active),
            other => panic!("expected NodeInfo, got {:?}", proto_kind_name(&other)),
        }
    }

    #[test]
    fn ogm_schedule_request_returns_per_interface_entries() {
        let provider = MockProvider {
            ogm_schedule: vec![
                OgmScheduleEntryData {
                    iface_idx: 0,
                    current_interval_ms: 4000,
                    min_interval_ms: 1000,
                    max_interval_ms: 64000,
                    iface_name: "lora0".into(),
                },
                OgmScheduleEntryData {
                    iface_idx: 1,
                    current_interval_ms: 1000,
                    min_interval_ms: 1000,
                    max_interval_ms: 32000,
                    iface_name: "udp1".into(),
                },
            ],
            ..Default::default()
        };

        match handle(
            provider,
            RequestKind::GetOgmSchedule(GetOgmScheduleRequest {}),
        ) {
            ResponseKind::OgmSchedule(schedule) => {
                assert_eq!(schedule.entries.len(), 2);
                let e = &schedule.entries[0];
                assert_eq!(e.iface_idx, 0);
                assert_eq!(e.current_interval_ms, 4000);
                assert_eq!(e.min_interval_ms, 1000);
                assert_eq!(e.max_interval_ms, 64000);
                assert_eq!(e.iface_name, "lora0");
                // Second interface backed off less far and has a lower ceiling.
                assert_eq!(schedule.entries[1].current_interval_ms, 1000);
                assert_eq!(schedule.entries[1].max_interval_ms, 32000);
            }
            other => panic!("expected OgmSchedule, got {:?}", proto_kind_name(&other)),
        }
    }

    #[test]
    fn ogm_schedule_request_with_no_interfaces_returns_empty() {
        match handle(
            MockProvider::default(),
            RequestKind::GetOgmSchedule(GetOgmScheduleRequest {}),
        ) {
            ResponseKind::OgmSchedule(schedule) => assert!(schedule.entries.is_empty()),
            other => panic!("expected OgmSchedule, got {:?}", proto_kind_name(&other)),
        }
    }

    #[test]
    fn throughput_request_returns_entries_and_summed_totals() {
        let provider = MockProvider {
            throughput: vec![
                InterfaceThroughputData {
                    iface_idx: 0,
                    rx_bps: 1000.0,
                    rx_fps: 10.0,
                    tx_bps: 500.0,
                    tx_fps: 5.0,
                    iface_name: "lora0".into(),
                },
                InterfaceThroughputData {
                    iface_idx: 1,
                    rx_bps: 250.0,
                    rx_fps: 2.0,
                    tx_bps: 100.0,
                    tx_fps: 1.0,
                    iface_name: "udp1".into(),
                },
            ],
            ..Default::default()
        };

        match handle(
            provider,
            RequestKind::GetThroughput(GetThroughputRequest {}),
        ) {
            ResponseKind::Throughput(tp) => {
                assert_eq!(tp.interfaces.len(), 2);
                assert_eq!(tp.interfaces[0].iface_idx, 0);
                assert_eq!(tp.interfaces[0].iface_name, "lora0");
                assert_eq!(tp.interfaces[1].rx_bps, 250.0);
                assert_eq!(tp.interfaces[1].iface_name, "udp1");
                // Totals are the per-interface sums.
                assert_eq!(tp.total_rx_bps, 1250.0);
                assert_eq!(tp.total_rx_fps, 12.0);
                assert_eq!(tp.total_tx_bps, 600.0);
                assert_eq!(tp.total_tx_fps, 6.0);
            }
            other => panic!("expected Throughput, got {:?}", proto_kind_name(&other)),
        }
    }

    #[test]
    fn throughput_request_with_no_interfaces_returns_zero_totals() {
        match handle(
            MockProvider::default(),
            RequestKind::GetThroughput(GetThroughputRequest {}),
        ) {
            ResponseKind::Throughput(tp) => {
                assert!(tp.interfaces.is_empty());
                assert_eq!(tp.total_rx_bps, 0.0);
                assert_eq!(tp.total_tx_bps, 0.0);
            }
            other => panic!("expected Throughput, got {:?}", proto_kind_name(&other)),
        }
    }

    #[test]
    fn metrics_request_projects_all_fields() {
        let provider = MockProvider {
            node_metrics: NodeMetricsData {
                uptime_secs: 3600,
                neighbor_count: 3,
                originators: TableOccupancyData {
                    used: 12,
                    capacity: 128,
                },
                broadcast_dedup: TableOccupancyData {
                    used: 5,
                    capacity: 128,
                },
                local_mcast_groups: TableOccupancyData {
                    used: 2,
                    capacity: 16,
                },
                mcast_memberships: TableOccupancyData {
                    used: 7,
                    capacity: 64,
                },
                tq_min: 180,
                tq_max: 255,
                tq_mean: 220.5,
                paths_max: 4,
                paths_mean: 1.75,
                oversize_drops: 9,
                relay_oversize_drops: 6,
                cert_store: TableOccupancyData {
                    used: 4,
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
                cert_req_rate: 0.5,
                cert_reply_rate: 1.25,
                untaggable_drop_rate: 0.75,
            },
            ..Default::default()
        };

        match handle(provider, RequestKind::GetMetrics(GetMetricsRequest {})) {
            ResponseKind::Metrics(m) => {
                assert_eq!(m.uptime_secs, 3600);
                assert_eq!(m.neighbor_count, 3);
                let orig = m.originators.expect("originators set");
                assert_eq!((orig.used, orig.capacity), (12, 128));
                assert_eq!(m.mcast_memberships.unwrap().capacity, 64);
                assert_eq!(m.tq_min, 180);
                assert_eq!(m.tq_max, 255);
                assert_eq!(m.tq_mean, 220.5);
                assert_eq!(m.paths_max, 4);
                assert_eq!(m.paths_mean, 1.75);
                assert_eq!(m.oversize_drops, 9);
                assert_eq!(m.relay_oversize_drops, 6);
                assert_eq!(m.cert_store.unwrap().used, 4);
                assert_eq!(m.in_flight_cert_requests.unwrap().used, 1);
                assert_eq!(m.pending_cert_replies.unwrap().used, 2);
                assert_eq!(m.cert_req_rate, 0.5);
                assert_eq!(m.cert_reply_rate, 1.25);
                assert_eq!(m.untaggable_drop_rate, 0.75);
            }
            other => panic!("expected Metrics, got {:?}", proto_kind_name(&other)),
        }
    }

    #[test]
    fn request_kind_name_covers_representative_variants() {
        assert_eq!(
            request_kind_name(&RequestKind::GetNodeInfo(GetNodeInfoRequest {})),
            "GetNodeInfo"
        );
        assert_eq!(
            request_kind_name(&RequestKind::SetConfig(SetConfigRequest { config: None })),
            "SetConfig"
        );
        assert_eq!(
            request_kind_name(&RequestKind::GetLinkFeaturesTable(
                GetLinkFeaturesTableRequest {}
            )),
            "GetLinkFeaturesTable"
        );
    }

    /// Mutations (writes to node/provider state) log at `info!`; queries
    /// (reads) log at `debug!` in [`WayfinderService::handle`], and a
    /// disclosure earns a record of its own — this is the classification those
    /// decisions rest on, so every variant is exercised rather than a
    /// representative sample.
    #[test]
    fn audited_classifies_writes_disclosures_and_reads() {
        use crate::wayfinder::v1alpha::ApproveCsrRequest;
        use crate::wayfinder::v1alpha::AuthenticateRequest;
        use crate::wayfinder::v1alpha::DenyCsrRequest;
        use crate::wayfinder::v1alpha::GetKeepAliveTableRequest;
        use crate::wayfinder::v1alpha::GetRoutingTableRequest;
        use crate::wayfinder::v1alpha::GetSecurityStatusRequest;
        use crate::wayfinder::v1alpha::GetTrustAnchorRequest;
        use crate::wayfinder::v1alpha::ListCertsRequest;
        use crate::wayfinder::v1alpha::ListPendingCsrsRequest;
        use crate::wayfinder::v1alpha::ResolveRouteRequest;
        use crate::wayfinder::v1alpha::RevokeNodeRequest;
        use crate::wayfinder::v1alpha::SetAuthRequest;
        use crate::wayfinder::v1alpha::SubmitCsrRequest;

        // Mutations: change node/provider state.
        assert_eq!(
            Audited::Mutation,
            audited(&RequestKind::SetAuth(SetAuthRequest {
                seed: Vec::new(),
                cert: Vec::new(),
                trust_anchor: Vec::new(),
            }))
        );
        assert_eq!(
            Audited::Mutation,
            audited(&RequestKind::SetConfig(SetConfigRequest { config: None }))
        );
        assert_eq!(
            Audited::Mutation,
            audited(&RequestKind::SubmitCsr(SubmitCsrRequest {
                node_mac: Vec::new(),
                ed_pubkey: Vec::new(),
                x_pubkey: Vec::new(),
                enrollment_token: String::new(),
            }))
        );
        assert_eq!(
            Audited::Mutation,
            audited(&RequestKind::RevokeNode(RevokeNodeRequest {
                node_mac: Vec::new(),
            }))
        );
        assert_eq!(
            Audited::Mutation,
            audited(&RequestKind::ApproveCsr(ApproveCsrRequest {
                node_mac: Vec::new(),
            }))
        );
        assert_eq!(
            Audited::Mutation,
            audited(&RequestKind::DenyCsr(DenyCsrRequest {
                node_mac: Vec::new(),
            }))
        );

        // Queries: read-only.
        assert_eq!(
            Audited::Query,
            audited(&RequestKind::GetNodeInfo(GetNodeInfoRequest {}))
        );
        assert_eq!(
            Audited::Query,
            audited(&RequestKind::GetRoutingTable(GetRoutingTableRequest {}))
        );
        assert_eq!(
            Audited::Query,
            audited(&RequestKind::GetLinkQualityTable(
                GetLinkQualityTableRequest {}
            ))
        );
        assert_eq!(
            Audited::Query,
            audited(&RequestKind::ResolveRoute(ResolveRouteRequest {
                destination: Vec::new(),
            }))
        );
        assert_eq!(
            Audited::Query,
            audited(&RequestKind::GetOgmSchedule(GetOgmScheduleRequest {}))
        );
        assert_eq!(
            Audited::Query,
            audited(&RequestKind::GetThroughput(GetThroughputRequest {}))
        );
        assert_eq!(
            Audited::Query,
            audited(&RequestKind::GetMetrics(GetMetricsRequest {}))
        );
        assert_eq!(
            Audited::Query,
            audited(&RequestKind::GetTrustAnchor(GetTrustAnchorRequest {}))
        );
        assert_eq!(
            Audited::Query,
            audited(&RequestKind::GetSecurityStatus(GetSecurityStatusRequest {}))
        );
        assert_eq!(
            Audited::Query,
            audited(&RequestKind::ListCerts(ListCertsRequest {}))
        );
        assert_eq!(
            Audited::Query,
            audited(&RequestKind::ListPendingCsrs(ListPendingCsrsRequest {}))
        );
        assert_eq!(
            Audited::Query,
            audited(&RequestKind::GetKeepaliveTable(GetKeepAliveTableRequest {}))
        );
        assert_eq!(
            Audited::Query,
            audited(&RequestKind::Authenticate(AuthenticateRequest {
                cert: Vec::new()
            }))
        );
        assert_eq!(
            Audited::Query,
            audited(&RequestKind::GetLinkFeaturesTable(
                GetLinkFeaturesTableRequest {}
            ))
        );
        // A login mints a certificate the whole mesh honours; "who logged in,
        // and when" has nowhere else to be answered from.
        assert_eq!(
            Audited::Mutation,
            audited(&RequestKind::AuthenticateUser(
                crate::wayfinder::v1alpha::AuthenticateUserRequest::default()
            ))
        );
        // Creating an account creates something that can mint such a
        // certificate, which is the same record for the same reason.
        assert_eq!(
            Audited::Mutation,
            audited(&RequestKind::CreateUser(
                crate::wayfinder::v1alpha::CreateUserRequest::default()
            ))
        );
        // Reading the roster is a read, like ListCerts beside it.
        assert_eq!(
            Audited::Query,
            audited(&RequestKind::ListUsers(
                crate::wayfinder::v1alpha::ListUsersRequest {}
            ))
        );
        // And removing one ends somebody's ability to administer the mesh,
        // which is the half of the account lifecycle nobody can undo by
        // reading a log. It is recorded for the same reason its creation is.
        assert_eq!(
            Audited::Mutation,
            audited(&RequestKind::RemoveUser(
                crate::wayfinder::v1alpha::RemoveUserRequest::default()
            ))
        );
    }

    fn proto_kind_name(k: &ResponseKind) -> &'static str {
        match k {
            ResponseKind::NodeInfo(_) => "NodeInfo",
            ResponseKind::RoutingTable(_) => "RoutingTable",
            ResponseKind::LinkQualityTable(_) => "LinkQualityTable",
            ResponseKind::LinkFeaturesTable(_) => "LinkFeaturesTable",
            ResponseKind::KeepaliveTable(_) => "KeepaliveTable",
            ResponseKind::ResolveRoute(_) => "ResolveRoute",
            ResponseKind::OgmSchedule(_) => "OgmSchedule",
            ResponseKind::Throughput(_) => "Throughput",
            ResponseKind::Metrics(_) => "Metrics",
            ResponseKind::Error(_) => "Error",
            ResponseKind::Empty(_) => "Empty",
            ResponseKind::ListCerts(_) => "ListCerts",
            ResponseKind::EnrollmentToken(_) => "EnrollmentToken",
            ResponseKind::ListPendingCsrs(_) => "ListPendingCsrs",
            ResponseKind::TrustAnchor(_) => "TrustAnchor",
            ResponseKind::SubmitCsr(_) => "SubmitCsr",
            ResponseKind::VpnEnrollment(_) => "VpnEnrollment",
            ResponseKind::ListVpnPeers(_) => "ListVpnPeers",
            ResponseKind::SecurityStatus(_) => "SecurityStatus",
            ResponseKind::Logs(_) => "Logs",
            ResponseKind::LogFilter(_) => "LogFilter",
            ResponseKind::AuthenticateUser(_) => "AuthenticateUser",
            ResponseKind::ListUsers(_) => "ListUsers",
            ResponseKind::CreateUser(_) => "CreateUser",
            ResponseKind::Alarms(_) => "Alarms",
            ResponseKind::CreateUserInvite(_) => "CreateUserInvite",
            ResponseKind::ListUserInvites(_) => "ListUserInvites",
            ResponseKind::BeginUserRegistration(_) => "BeginUserRegistration",
            ResponseKind::RevokeUserSessions(_) => "RevokeUserSessions",
            ResponseKind::SetUserRole(_) => "SetUserRole",
            ResponseKind::SetUserEnabled(_) => "SetUserEnabled",
            ResponseKind::OwnCert(_) => "OwnCert",
        }
    }

    /// A provider implementing *only* the authority half.
    ///
    /// That this compiles at all is the property the split exists to create:
    /// before it, an authority had to satisfy the whole thirty-method surface,
    /// including every router projection it has no state to answer from.  Every
    /// method here is a default, so the body is empty by design.
    #[derive(Default)]
    struct AuthorityOnly;

    impl AuthorityDataProvider for AuthorityOnly {}

    /// Dispatch a request through the router half alone.
    fn router_handle<P: RouterDataProvider>(
        provider: &mut P,
        req: RequestKind,
    ) -> Result<ResponseKind, WayfinderRequest> {
        handle_router(provider, WayfinderRequest { request: Some(req) })
            .map(|r| r.response.expect("dispatch always sets a response"))
    }

    /// Dispatch a request through the authority half alone.
    fn authority_handle<P: AuthorityDataProvider>(
        provider: &mut P,
        req: RequestKind,
    ) -> Result<ResponseKind, WayfinderRequest> {
        handle_authority(provider, WayfinderRequest { request: Some(req) })
            .map(|r| r.response.expect("dispatch always sets a response"))
    }

    /// Every request kind belongs to exactly one facet, and the classification
    /// is what lets a connection task pick a channel before it sends anything.
    #[test]
    fn request_facet_assigns_each_kind_to_one_half() {
        assert_eq!(
            request_facet(&RequestKind::GetRoutingTable(GetRoutingTableRequest {})),
            RequestFacet::Router
        );
        assert_eq!(
            request_facet(&RequestKind::ListUsers(ListUsersRequest {})),
            RequestFacet::Authority
        );
        // Answered before dispatch is reached: the VPN requests in the
        // connection task, `Authenticate` by the transport's own first frame.
        assert_eq!(
            request_facet(&RequestKind::ListVpnPeers(ListVpnPeersRequest {})),
            RequestFacet::Transport
        );
        assert_eq!(
            request_facet(&RequestKind::Authenticate(AuthenticateRequest::default())),
            RequestFacet::Transport
        );
    }

    /// The router dispatcher answers a router request from a provider that
    /// knows nothing about certificates.
    #[test]
    fn router_dispatch_answers_a_router_request() {
        let mut provider = MockProvider::default();

        match router_handle(
            &mut provider,
            RequestKind::GetNodeInfo(GetNodeInfoRequest {}),
        ) {
            Ok(ResponseKind::NodeInfo(info)) => assert_eq!(info.num_originators, 0),
            Ok(other) => panic!("expected NodeInfo, got {}", proto_kind_name(&other)),
            Err(_) => panic!("GetNodeInfo is a router request and must be handled here"),
        }
    }

    /// An authority request handed to the router dispatcher comes back
    /// untouched, so the caller can forward it to the other half rather than
    /// receiving a misleading "not a provider" error from the wrong owner.
    #[test]
    fn router_dispatch_returns_an_authority_request_untouched() {
        let mut provider = MockProvider::default();

        let returned = router_handle(&mut provider, RequestKind::ListUsers(ListUsersRequest {}))
            .expect_err("ListUsers belongs to the authority half");

        assert!(
            matches!(returned.request, Some(RequestKind::ListUsers(_))),
            "the request must be returned intact for the caller to re-route"
        );
    }

    /// The authority dispatcher answers an authority request from a provider
    /// that holds no router state at all.
    #[test]
    fn authority_dispatch_answers_an_authority_request() {
        let mut provider = AuthorityOnly;

        // The default authority impl is a node that is not a provider, so the
        // answer is that error -- the point being that it is *this* half that
        // produced it.
        match authority_handle(
            &mut provider,
            RequestKind::GetTrustAnchor(GetTrustAnchorRequest {}),
        ) {
            Ok(ResponseKind::Error(e)) => {
                assert_eq!(e.message, "node is not a certificate-authority provider")
            }
            Ok(other) => panic!("expected Error, got {}", proto_kind_name(&other)),
            Err(_) => panic!("GetTrustAnchor is an authority request and must be handled here"),
        }
    }

    /// The mirror of the router case: a router request handed to the authority
    /// dispatcher comes back untouched.
    #[test]
    fn authority_dispatch_returns_a_router_request_untouched() {
        let mut provider = AuthorityOnly;

        let returned = authority_handle(
            &mut provider,
            RequestKind::GetRoutingTable(GetRoutingTableRequest {}),
        )
        .expect_err("GetRoutingTable belongs to the router half");

        assert!(
            matches!(returned.request, Some(RequestKind::GetRoutingTable(_))),
            "the request must be returned intact for the caller to re-route"
        );
    }

    /// Backwards compatibility: a single provider implementing both halves is
    /// still served by one `WayfinderService`, answering both kinds exactly as
    /// it did before the split.  This is what keeps every existing caller --
    /// the driver loop, the web mock, the client tests -- working unchanged.
    #[test]
    fn combined_service_still_answers_both_halves() {
        let router = handle(
            MockProvider::default(),
            RequestKind::GetNodeInfo(GetNodeInfoRequest {}),
        );
        match router {
            ResponseKind::NodeInfo(info) => assert_eq!(info.num_originators, 0),
            other => panic!("expected NodeInfo, got {}", proto_kind_name(&other)),
        }

        let authority = handle(
            MockProvider::default(),
            RequestKind::GetTrustAnchor(GetTrustAnchorRequest {}),
        );
        match authority {
            ResponseKind::Error(e) => {
                assert_eq!(e.message, "node is not a certificate-authority provider")
            }
            other => panic!("expected Error, got {}", proto_kind_name(&other)),
        }
    }

    /// A minted invite's token reaches the wire exactly as the provider
    /// returned it.
    ///
    /// The token is a bearer credential the authority stores only as a hash, so
    /// this response is the single moment it exists in readable form anywhere.
    /// A dispatch that dropped or mangled it would leave the admin with an
    /// invite they cannot deliver and no way to recover it.
    #[test]
    fn create_user_invite_carries_the_token_and_its_expiry() {
        use crate::wayfinder::v1alpha::CreateUserInviteRequest;

        let provider = MockProvider {
            invite: Some(UserInviteMintedData {
                username: "rowan".into(),
                token: "JBSWY3DPEHPK3PXP".into(),
                expires_at: 1_800_086_400,
            }),
            ..Default::default()
        };

        match handle(
            provider,
            RequestKind::CreateUserInvite(CreateUserInviteRequest {
                username: "rowan".into(),
                admin: false,
                session_ttl_secs: 0,
                invite_ttl_secs: 0,
            }),
        ) {
            ResponseKind::CreateUserInvite(response) => {
                assert_eq!(response.username, "rowan");
                assert_eq!(response.token, "JBSWY3DPEHPK3PXP");
                assert_eq!(response.expires_at, 1_800_086_400);
            }
            other => panic!("expected CreateUserInvite, got {}", proto_kind_name(&other)),
        }
    }

    /// The listing carries the whole triage answer: who was invited, and — the
    /// state §3.6 of the design exists for — who took the second factor and did
    /// not finish.  Plus the store's capacity, so "nothing more can be minted"
    /// is readable rather than inferred from a failed mint.
    #[test]
    fn list_user_invites_projects_the_started_state_and_the_capacity() {
        use crate::wayfinder::v1alpha::ListUserInvitesRequest;

        let provider = MockProvider {
            invites: vec![
                UserInviteData {
                    username: "rowan".into(),
                    admin: true,
                    session_ttl_secs: 3600,
                    created_at: 1_800_000_000,
                    expires_at: 1_800_086_400,
                    started_at: 1_800_000_600,
                    handle_expires_at: 1_800_001_500,
                },
                UserInviteData {
                    username: "wren".into(),
                    admin: false,
                    session_ttl_secs: 28800,
                    created_at: 1_800_000_100,
                    expires_at: 1_800_086_500,
                    started_at: 0,
                    handle_expires_at: 0,
                },
            ],
            invite_capacity: 32,
            ..Default::default()
        };

        match handle(
            provider,
            RequestKind::ListUserInvites(ListUserInvitesRequest {}),
        ) {
            ResponseKind::ListUserInvites(response) => {
                assert_eq!(response.capacity, 32, "current-vs-cap, not a bare count");
                assert_eq!(response.invites.len(), 2);
                let started = &response.invites[0];
                assert_eq!(started.username, "rowan");
                assert!(started.admin);
                assert_eq!(
                    started.started_at, 1_800_000_600,
                    "a started invite must say when its secret was revealed"
                );
                assert_eq!(started.handle_expires_at, 1_800_001_500);
                let pending = &response.invites[1];
                assert_eq!(pending.username, "wren");
                assert_eq!(
                    pending.started_at, 0,
                    "an unstarted invite reports no start, not a fabricated one"
                );
            }
            other => panic!("expected ListUserInvites, got {}", proto_kind_name(&other)),
        }
    }

    /// Starting a registration hands back the account name, the `otpauth://`
    /// URI and the short-lived handle that alone can complete it.
    #[test]
    fn begin_user_registration_carries_the_uri_and_the_handle() {
        use crate::wayfinder::v1alpha::BeginUserRegistrationRequest;

        let provider = MockProvider {
            registration: Some(RegistrationStartedData {
                username: "rowan".into(),
                totp_enrolment_uri: "otpauth://totp/wayfinder:rowan?secret=AAAA".into(),
                handle: "handle-abc".into(),
                handle_expires_at: 1_800_001_500,
            }),
            ..Default::default()
        };

        match handle(
            provider,
            RequestKind::BeginUserRegistration(BeginUserRegistrationRequest {
                token: "JBSWY3DPEHPK3PXP".into(),
            }),
        ) {
            ResponseKind::BeginUserRegistration(response) => {
                assert_eq!(response.username, "rowan");
                assert!(response.totp_enrolment_uri.starts_with("otpauth://totp/"));
                assert_eq!(response.handle, "handle-abc");
                assert_eq!(response.handle_expires_at, 1_800_001_500);
            }
            other => panic!(
                "expected BeginUserRegistration, got {}",
                proto_kind_name(&other)
            ),
        }
    }

    /// Completion answers `Empty`: the account now exists and the caller's next
    /// act is an ordinary sign-in.  Nothing is handed back, because there is
    /// nothing left that only this response could carry.
    #[test]
    fn complete_user_registration_answers_empty() {
        use crate::wayfinder::v1alpha::CompleteUserRegistrationRequest;

        let provider = MockProvider {
            registration_completes: true,
            ..Default::default()
        };

        match handle(
            provider,
            RequestKind::CompleteUserRegistration(CompleteUserRegistrationRequest {
                handle: "handle-abc".into(),
                password: "correct horse battery staple".into(),
                totp_code: "287082".into(),
            }),
        ) {
            ResponseKind::Empty(_) => {}
            other => panic!("expected Empty, got {}", proto_kind_name(&other)),
        }
    }

    /// A node that is not a certificate authority has no invite store, and says
    /// so rather than answering with an empty listing — which would read as
    /// "nobody has been invited" on a node that could not know.
    #[test]
    fn the_invite_requests_are_errors_on_a_non_provider() {
        use crate::wayfinder::v1alpha::BeginUserRegistrationRequest;
        use crate::wayfinder::v1alpha::ListUserInvitesRequest;

        for request in [
            RequestKind::ListUserInvites(ListUserInvitesRequest {}),
            RequestKind::BeginUserRegistration(BeginUserRegistrationRequest {
                token: "anything".into(),
            }),
        ] {
            match handle(MockProvider::default(), request) {
                ResponseKind::Error(_) => {}
                other => panic!("expected Error, got {}", proto_kind_name(&other)),
            }
        }
    }

    /// All five are answered from certificate-authority state, so a forked
    /// caller must send them to that half — including the two an anonymous
    /// registrant reaches, which hold no router state at all.
    #[test]
    fn the_invite_requests_are_owned_by_the_authority_facet() {
        use crate::wayfinder::v1alpha::BeginUserRegistrationRequest;
        use crate::wayfinder::v1alpha::CompleteUserRegistrationRequest;
        use crate::wayfinder::v1alpha::CreateUserInviteRequest;
        use crate::wayfinder::v1alpha::ListUserInvitesRequest;
        use crate::wayfinder::v1alpha::RevokeUserInviteRequest;

        for kind in [
            RequestKind::CreateUserInvite(CreateUserInviteRequest::default()),
            RequestKind::ListUserInvites(ListUserInvitesRequest {}),
            RequestKind::RevokeUserInvite(RevokeUserInviteRequest::default()),
            RequestKind::BeginUserRegistration(BeginUserRegistrationRequest::default()),
            RequestKind::CompleteUserRegistration(CompleteUserRegistrationRequest::default()),
        ] {
            assert_eq!(
                request_facet(&kind),
                RequestFacet::Authority,
                "{} is answered from authority state",
                request_kind_name(&kind)
            );
        }
    }

    /// Four of the five change the account store and are audited as mutations;
    /// the listing is a read.
    ///
    /// `BeginUserRegistration` is a mutation and not a `Disclosure` despite
    /// handing out the TOTP secret, because it *also* consumes the invite. The
    /// record this produces is the durable account of who took that secret: the
    /// invite's own `started_at` is swept fifteen minutes later with the
    /// invitation, while a log line on a host CA reaches the journal.
    #[test]
    fn audited_classifies_the_invite_requests() {
        use crate::wayfinder::v1alpha::BeginUserRegistrationRequest;
        use crate::wayfinder::v1alpha::CompleteUserRegistrationRequest;
        use crate::wayfinder::v1alpha::CreateUserInviteRequest;
        use crate::wayfinder::v1alpha::ListUserInvitesRequest;
        use crate::wayfinder::v1alpha::RevokeUserInviteRequest;

        for kind in [
            RequestKind::CreateUserInvite(CreateUserInviteRequest::default()),
            RequestKind::RevokeUserInvite(RevokeUserInviteRequest::default()),
            RequestKind::BeginUserRegistration(BeginUserRegistrationRequest::default()),
            RequestKind::CompleteUserRegistration(CompleteUserRegistrationRequest::default()),
        ] {
            assert_eq!(
                Audited::Mutation,
                audited(&kind),
                "{} changes the account store",
                request_kind_name(&kind)
            );
        }
        assert_eq!(
            Audited::Query,
            audited(&RequestKind::ListUserInvites(ListUserInvitesRequest {}))
        );
    }

    /// The kind names are what the audit record carries, and a request whose
    /// fields are a token, a password and a TOTP code must be identified by its
    /// kind alone.
    #[test]
    fn request_kind_name_covers_the_invite_requests() {
        use crate::wayfinder::v1alpha::BeginUserRegistrationRequest;
        use crate::wayfinder::v1alpha::CompleteUserRegistrationRequest;
        use crate::wayfinder::v1alpha::CreateUserInviteRequest;

        assert_eq!(
            request_kind_name(&RequestKind::CreateUserInvite(
                CreateUserInviteRequest::default()
            )),
            "CreateUserInvite"
        );
        assert_eq!(
            request_kind_name(&RequestKind::BeginUserRegistration(
                BeginUserRegistrationRequest {
                    token: "a-secret-token".into(),
                }
            )),
            "BeginUserRegistration"
        );
        assert_eq!(
            request_kind_name(&RequestKind::CompleteUserRegistration(
                CompleteUserRegistrationRequest {
                    handle: "h".into(),
                    password: "hunter2".into(),
                    totp_code: "000000".into(),
                }
            )),
            "CompleteUserRegistration"
        );
    }
}
