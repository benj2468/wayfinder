use crate::wayfinder::v1alpha::AllInterfacesEgress;
use crate::wayfinder::v1alpha::CsrIssued;
use crate::wayfinder::v1alpha::CsrPending;
use crate::wayfinder::v1alpha::CsrRejected;
use crate::wayfinder::v1alpha::Empty;
use crate::wayfinder::v1alpha::ErrorResponse;
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
use crate::wayfinder::v1alpha::RoutingEntry;
use crate::wayfinder::v1alpha::RoutingTable;
use crate::wayfinder::v1alpha::SubmitCsrResponse;
use crate::wayfinder::v1alpha::TableOccupancy;
use crate::wayfinder::v1alpha::Throughput;
use crate::wayfinder::v1alpha::WayfinderRequest;
use crate::wayfinder::v1alpha::WayfinderResponse;
use crate::wayfinder::v1alpha::resolve_route_response::Egress as EgressKind;
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
}

/// Intermediate representation of a routing table entry.
pub struct RoutingEntryData {
    /// The destination originator this entry routes to.
    pub destination: Vec<u8>,
    /// Immediate neighbor on the currently-selected best path.
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
    /// EWMA-smoothed normalized quality on the `0..=255` scale.
    pub ewma_quality: u32,
    /// Number of samples folded into the EWMA.
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

/// Implemented by anything that can supply router state to [`WayfinderService`].
/// Intentionally transport- and protocol-agnostic so callers can implement it
/// for whatever router type they have without pulling in a dependency on this crate.
pub trait WayfinderDataProvider {
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

    /// Provider mode: the mesh trust anchor as raw `TrustAnchor` bytes.  The
    /// default errors — only a node running as a certificate-authority provider
    /// overrides these three methods.
    fn get_trust_anchor(&self) -> Result<Vec<u8>, String> {
        Err("node is not a certificate-authority provider".into())
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
        Err("node is not a certificate-authority provider".into())
    }

    /// Provider mode: revoke a node, signing and flooding a revocation record.
    /// Default errors.
    fn revoke_node(&mut self, node_mac: &[u8]) -> Result<(), String> {
        let _ = node_mac;
        Err("node is not a certificate-authority provider".into())
    }

    /// Provider mode: list the certificates this provider has issued.  Default
    /// errors.
    fn list_certs(&self) -> Result<Vec<IssuedCertData>, String> {
        Err("node is not a certificate-authority provider".into())
    }

    /// Provider mode: list the CSRs currently awaiting operator approval.
    /// Default errors (not a provider).
    fn list_pending_csrs(&self) -> Result<Vec<PendingCsrData>, String> {
        Err("node is not a certificate-authority provider".into())
    }

    /// Provider mode: approve the pending CSR bound to `node_mac`, so the
    /// enrolling node collects its certificate on the next `submit_csr` poll.
    /// Errors if no CSR for that MAC is pending.  Default errors (not a
    /// provider).
    fn approve_csr(&mut self, node_mac: &[u8]) -> Result<(), String> {
        let _ = node_mac;
        Err("node is not a certificate-authority provider".into())
    }

    /// Provider mode: deny the pending CSR bound to `node_mac`; the enrolling
    /// node observes a `Rejected` outcome on its next poll.  Errors if no CSR for
    /// that MAC is pending.  Default errors (not a provider).
    fn deny_csr(&mut self, node_mac: &[u8]) -> Result<(), String> {
        let _ = node_mac;
        Err("node is not a certificate-authority provider".into())
    }
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
fn proto_log_level(level: LogLevelData) -> LogLevel {
    match level {
        LogLevelData::Error => LogLevel::Error,
        LogLevelData::Warn => LogLevel::Warn,
        LogLevelData::Info => LogLevel::Info,
        LogLevelData::Debug => LogLevel::Debug,
        LogLevelData::Trace => LogLevel::Trace,
    }
}

/// A short, stable, non-secret name for a request variant, for logging.
/// Never derived from `Debug` on the whole variant: some request payloads
/// (`SetAuthRequest`'s identity seed, CSR key material) are secret, so only
/// the kind — never the fields — may be logged.
fn request_kind_name(k: &RequestKind) -> &'static str {
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
        RequestKind::SetLogLevel(_) => "SetLogLevel",
    }
}

/// Whether `k` mutates node/provider state, as opposed to a read-only query.
/// Drives the log level in [`WayfinderService::handle`]: mutations are
/// `info!` (infrequent, operator-relevant audit trail — new auth material,
/// a config change, a CSR issued/approved/denied, a node revoked); queries
/// are `debug!` (frequent — e.g. every TUI refresh tick — and off by
/// default). Deliberately exhaustive (no wildcard arm) so a newly added
/// `RequestKind` variant forces an explicit classification here rather than
/// silently defaulting to one side.
fn request_is_mutation(k: &RequestKind) -> bool {
    match k {
        RequestKind::SetAuth(_)
        | RequestKind::SetConfig(_)
        | RequestKind::SubmitCsr(_)
        | RequestKind::RevokeNode(_)
        | RequestKind::ApproveCsr(_)
        | RequestKind::DenyCsr(_)
        // Changing what a node records is an operator action worth an audit
        // trail, and infrequent enough to afford one.
        | RequestKind::SetLogLevel(_) => true,

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
        | RequestKind::GetLogs(_) => false,
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
    pub fn handle(&mut self, request: WayfinderRequest) -> WayfinderResponse {
        if let Some(kind) = &request.request {
            let name = request_kind_name(kind);
            if request_is_mutation(kind) {
                info!(kind = name, "management API mutation");
            }
        }

        let response = match request.request {
            Some(RequestKind::GetNodeInfo(_)) => ResponseKind::NodeInfo(NodeInfo {
                node_id: self.provider.node_id(),
                num_originators: self.provider.num_originators(),
                auth_locked: self.provider.auth_locked(),
                runtime_config_active: self.provider.runtime_config_active(),
            }),

            Some(RequestKind::GetRoutingTable(_)) => {
                let entries = self
                    .provider
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
                            })
                            .collect(),
                    })
                    .collect();
                ResponseKind::RoutingTable(RoutingTable { entries })
            }

            Some(RequestKind::GetLinkQualityTable(_)) => {
                let entries = self
                    .provider
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
                let entries = self
                    .provider
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
                let batch = self.provider.logs(req.since_seq, req.max_records);
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

            Some(RequestKind::SetLogLevel(req)) => {
                match self.provider.set_log_level(&req.directives) {
                    Ok(directives) => ResponseKind::LogFilter(LogFilter { directives }),
                    // A spec that didn't parse. The previous filter is still in
                    // force, so this is a report, not a state change.
                    Err(message) => ResponseKind::Error(ErrorResponse { message }),
                }
            }

            Some(RequestKind::GetOgmSchedule(_)) => {
                let entries = self
                    .provider
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
                let interfaces = self
                    .provider
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
                let m = self.provider.node_metrics();
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
                })
            }

            Some(RequestKind::GetSecurityStatus(_)) => {
                let s = self.provider.security_status();
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
                        })
                        .collect(),
                })
            }

            Some(RequestKind::ResolveRoute(req)) => {
                match self.provider.resolve_route(&req.destination) {
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
                }
            }

            Some(RequestKind::SetAuth(set_auth)) => {
                match self
                    .provider
                    .set_auth(&set_auth.seed, &set_auth.cert, &set_auth.trust_anchor)
                {
                    Ok(_) => ResponseKind::Empty(Empty {}),
                    Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
                }
            }

            Some(RequestKind::SetConfig(set_config)) => {
                let raw_config = set_config.config.unwrap_or_default();
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
                };
                match self.provider.set_config(config) {
                    Ok(_) => ResponseKind::Empty(Empty {}),
                    Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
                }
            }

            Some(RequestKind::GetKeepaliveTable(_)) => {
                let entries = self
                    .provider
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

            Some(RequestKind::GetTrustAnchor(_)) => match self.provider.get_trust_anchor() {
                Ok(trust_anchor) => {
                    ResponseKind::TrustAnchor(GetTrustAnchorResponse { trust_anchor })
                }
                Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
            },

            Some(RequestKind::SubmitCsr(req)) => match self.provider.submit_csr(
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

            Some(RequestKind::RevokeNode(req)) => match self.provider.revoke_node(&req.node_mac) {
                Ok(()) => ResponseKind::Empty(Empty {}),
                Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
            },

            Some(RequestKind::ListCerts(_)) => match self.provider.list_certs() {
                Ok(certs) => ResponseKind::ListCerts(ListCertsResponse {
                    certs: certs
                        .into_iter()
                        .map(|c| IssuedCert {
                            node_mac: c.node_mac,
                            ed_pubkey: c.ed_pubkey,
                            not_before: c.not_before,
                            not_after: c.not_after,
                            revoked: c.revoked,
                        })
                        .collect(),
                }),
                Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
            },

            Some(RequestKind::ListPendingCsrs(_)) => match self.provider.list_pending_csrs() {
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

            Some(RequestKind::ApproveCsr(req)) => match self.provider.approve_csr(&req.node_mac) {
                Ok(()) => ResponseKind::Empty(Empty {}),
                Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
            },

            Some(RequestKind::DenyCsr(req)) => match self.provider.deny_csr(&req.node_mac) {
                Ok(()) => ResponseKind::Empty(Empty {}),
                Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
            },

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
        };

        WayfinderResponse {
            response: Some(response),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wayfinder::v1alpha::GetLinkFeaturesTableRequest;
    use crate::wayfinder::v1alpha::GetLinkQualityTableRequest;
    use crate::wayfinder::v1alpha::GetMetricsRequest;
    use crate::wayfinder::v1alpha::GetNodeInfoRequest;
    use crate::wayfinder::v1alpha::GetOgmScheduleRequest;
    use crate::wayfinder::v1alpha::GetThroughputRequest;
    use crate::wayfinder::v1alpha::ResolveRouteRequest;
    use crate::wayfinder::v1alpha::RuntimeConfig;
    use crate::wayfinder::v1alpha::SetConfigRequest;
    use crate::wayfinder::v1alpha::TrickleConfig;
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
    }

    impl WayfinderDataProvider for MockProvider {
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
        fn logs(&self, since_seq: u64, max_records: u32) -> LogsData {
            self.last_logs_query.set((since_seq, max_records));
            self.logs.clone()
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
                ewma_quality: 200,
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
                assert_eq!(e.ewma_quality, 200);
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
                }),
            }),
        ) {
            ResponseKind::Empty(_) => {}
            other => panic!("expected Empty, got {:?}", proto_kind_name(&other)),
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
    /// (reads) log at `debug!` in [`WayfinderService::handle`] — this is the
    /// classification that decision rests on, so every variant is exercised
    /// rather than a representative sample.
    #[test]
    fn request_is_mutation_classifies_writes_vs_reads() {
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
        assert!(request_is_mutation(&RequestKind::SetAuth(SetAuthRequest {
            seed: Vec::new(),
            cert: Vec::new(),
            trust_anchor: Vec::new(),
        })));
        assert!(request_is_mutation(&RequestKind::SetConfig(
            SetConfigRequest { config: None }
        )));
        assert!(request_is_mutation(&RequestKind::SubmitCsr(
            SubmitCsrRequest {
                node_mac: Vec::new(),
                ed_pubkey: Vec::new(),
                x_pubkey: Vec::new(),
                enrollment_token: String::new(),
            }
        )));
        assert!(request_is_mutation(&RequestKind::RevokeNode(
            RevokeNodeRequest {
                node_mac: Vec::new(),
            }
        )));
        assert!(request_is_mutation(&RequestKind::ApproveCsr(
            ApproveCsrRequest {
                node_mac: Vec::new(),
            }
        )));
        assert!(request_is_mutation(&RequestKind::DenyCsr(DenyCsrRequest {
            node_mac: Vec::new(),
        })));

        // Queries: read-only.
        assert!(!request_is_mutation(&RequestKind::GetNodeInfo(
            GetNodeInfoRequest {}
        )));
        assert!(!request_is_mutation(&RequestKind::GetRoutingTable(
            GetRoutingTableRequest {}
        )));
        assert!(!request_is_mutation(&RequestKind::GetLinkQualityTable(
            GetLinkQualityTableRequest {}
        )));
        assert!(!request_is_mutation(&RequestKind::ResolveRoute(
            ResolveRouteRequest {
                destination: Vec::new(),
            }
        )));
        assert!(!request_is_mutation(&RequestKind::GetOgmSchedule(
            GetOgmScheduleRequest {}
        )));
        assert!(!request_is_mutation(&RequestKind::GetThroughput(
            GetThroughputRequest {}
        )));
        assert!(!request_is_mutation(&RequestKind::GetMetrics(
            GetMetricsRequest {}
        )));
        assert!(!request_is_mutation(&RequestKind::GetTrustAnchor(
            GetTrustAnchorRequest {}
        )));
        assert!(!request_is_mutation(&RequestKind::GetSecurityStatus(
            GetSecurityStatusRequest {}
        )));
        assert!(!request_is_mutation(&RequestKind::ListCerts(
            ListCertsRequest {}
        )));
        assert!(!request_is_mutation(&RequestKind::ListPendingCsrs(
            ListPendingCsrsRequest {}
        )));
        assert!(!request_is_mutation(&RequestKind::GetKeepaliveTable(
            GetKeepAliveTableRequest {}
        )));
        assert!(!request_is_mutation(&RequestKind::Authenticate(
            AuthenticateRequest { cert: Vec::new() }
        )));
        assert!(!request_is_mutation(&RequestKind::GetLinkFeaturesTable(
            GetLinkFeaturesTableRequest {}
        )));
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
            ResponseKind::ListPendingCsrs(_) => "ListPendingCsrs",
            ResponseKind::TrustAnchor(_) => "TrustAnchor",
            ResponseKind::SubmitCsr(_) => "SubmitCsr",
            ResponseKind::SecurityStatus(_) => "SecurityStatus",
            ResponseKind::Logs(_) => "Logs",
            ResponseKind::LogFilter(_) => "LogFilter",
        }
    }
}
