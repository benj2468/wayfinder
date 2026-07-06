use crate::wayfinder_v1alpha::Empty;
use crate::wayfinder_v1alpha::{
    AllInterfacesEgress, CsrIssued, CsrPending, CsrRejected, ErrorResponse,
    GetSecurityStatusResponse, GetTrustAnchorResponse, InterfaceThroughput, IssuedCert,
    LinkQualityEntry, LinkQualityTable, ListCertsResponse, ListPendingCsrsResponse, NeighborPath,
    NodeInfo, NodeMetrics, NodeSecurity, OgmSchedule, OgmScheduleEntry, PendingCsr,
    ResolveRouteResponse, RoutingEntry, RoutingTable, SubmitCsrResponse, TableOccupancy,
    Throughput, WayfinderRequest, WayfinderResponse, resolve_route_response::Egress as EgressKind,
    submit_csr_response::Outcome as CsrOutcomeKind, wayfinder_request::Request as RequestKind,
    wayfinder_response::Response as ResponseKind,
};
use alloc::string::String;
use alloc::vec::Vec;

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

/// Intermediate representation of a partial runtime-configuration update,
/// passed to [`WayfinderDataProvider::set_config`].  Each field is
/// independently optional: `None` leaves that piece of configuration
/// unchanged.  New runtime-editable knobs are added here as additional
/// fields, rather than as new provider methods.
#[derive(Clone, Default)]
pub struct RuntimeConfigData {
    /// Present to update the Trickle/OGM bounds for one mesh interface.
    pub trickle: Option<TrickleConfigData>,
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
                    })
                    .collect();
                ResponseKind::LinkQualityTable(LinkQualityTable { entries })
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
                let config = RuntimeConfigData {
                    trickle: set_config
                        .config
                        .and_then(|c| c.trickle)
                        .map(|t| TrickleConfigData {
                            iface_idx: t.iface_idx,
                            min_interval_ms: t.min_interval_ms,
                            max_interval_ms: t.max_interval_ms,
                        }),
                };
                match self.provider.set_config(config) {
                    Ok(_) => ResponseKind::Empty(Empty {}),
                    Err(e) => ResponseKind::Error(ErrorResponse { message: e }),
                }
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
    use crate::wayfinder_v1alpha::{
        GetLinkQualityTableRequest, GetMetricsRequest, GetNodeInfoRequest, GetOgmScheduleRequest,
        GetThroughputRequest, ResolveRouteRequest, RuntimeConfig, SetConfigRequest, TrickleConfig,
    };
    use alloc::vec;

    /// Test double that returns canned responses and records the last
    /// `resolve_route` destination it was called with.
    #[derive(Default)]
    struct MockProvider {
        link_quality: Vec<LinkQualityEntryData>,
        ogm_schedule: Vec<OgmScheduleEntryData>,
        throughput: Vec<InterfaceThroughputData>,
        node_metrics: NodeMetricsData,
        route_resolution: Option<RouteResolutionData>,
        // RefCell would be nicer but no_std + alloc here — a Cell of an
        // owned Vec would require Clone gymnastics, so we just leave the
        // resolution as a single fixed answer per test.
        runtime_config_active: bool,
        last_set_config: Option<RuntimeConfigData>,
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
            self.runtime_config_active = config.trickle.is_some();
            self.last_set_config = Some(config);
            Ok(())
        }
        fn runtime_config_active(&self) -> bool {
            self.runtime_config_active
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
                config: Some(RuntimeConfig { trickle: None }),
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
                },
                OgmScheduleEntryData {
                    iface_idx: 1,
                    current_interval_ms: 1000,
                    min_interval_ms: 1000,
                    max_interval_ms: 32000,
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
                },
                InterfaceThroughputData {
                    iface_idx: 1,
                    rx_bps: 250.0,
                    rx_fps: 2.0,
                    tx_bps: 100.0,
                    tx_fps: 1.0,
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
                assert_eq!(tp.interfaces[1].rx_bps, 250.0);
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
            }
            other => panic!("expected Metrics, got {:?}", proto_kind_name(&other)),
        }
    }

    fn proto_kind_name(k: &ResponseKind) -> &'static str {
        match k {
            ResponseKind::NodeInfo(_) => "NodeInfo",
            ResponseKind::RoutingTable(_) => "RoutingTable",
            ResponseKind::LinkQualityTable(_) => "LinkQualityTable",
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
        }
    }
}
