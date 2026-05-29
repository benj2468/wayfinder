use crate::wayfinder_v1alpha::{
    AllInterfacesEgress, ErrorResponse, LinkQualityEntry, LinkQualityTable, NeighborPath, NodeInfo,
    ResolveRouteResponse, RoutingEntry, RoutingTable, WayfinderRequest, WayfinderResponse,
    resolve_route_response::Egress as EgressKind, wayfinder_request::Request as RequestKind,
    wayfinder_response::Response as ResponseKind,
};
use alloc::vec::Vec;

/// Intermediate representation of a single per-hop path, returned by
/// [`WayfinderDataProvider::routing_table`].  Decoupled from both the
/// wire-format structs and the generated proto types.
pub struct NeighborPathData {
    pub neighbor_id: Vec<u8>,
    pub tq: u32,
    pub last_seqno: u32,
}

/// Intermediate representation of a routing table entry.
pub struct RoutingEntryData {
    pub destination: Vec<u8>,
    pub next_hop: Vec<u8>,
    pub tq: u32,
    pub last_seqno: u32,
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

/// Implemented by anything that can supply router state to [`WayfinderService`].
/// Intentionally transport- and protocol-agnostic so callers can implement it
/// for whatever router type they have without pulling in a dependency on this crate.
pub trait WayfinderDataProvider {
    fn node_id(&self) -> Vec<u8>;
    fn num_originators(&self) -> u32;
    fn routing_table(&self) -> Vec<RoutingEntryData>;
    /// Snapshot of the per-(neighbor, interface) link-quality table.
    fn link_quality_table(&self) -> Vec<LinkQualityEntryData>;
    /// Resolve how a packet to `destination` would be routed.  Returns
    /// `None` if the raw bytes can't be parsed as a valid identifier for
    /// this provider's address family.
    fn resolve_route(&self, destination: &[u8]) -> Option<RouteResolutionData>;
}

impl<T: WayfinderDataProvider> WayfinderDataProvider for &T {
    fn node_id(&self) -> Vec<u8> {
        (**self).node_id()
    }
    fn num_originators(&self) -> u32 {
        (**self).num_originators()
    }
    fn routing_table(&self) -> Vec<RoutingEntryData> {
        (**self).routing_table()
    }
    fn link_quality_table(&self) -> Vec<LinkQualityEntryData> {
        (**self).link_quality_table()
    }
    fn resolve_route(&self, destination: &[u8]) -> Option<RouteResolutionData> {
        (**self).resolve_route(destination)
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
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    pub fn handle(&self, request: WayfinderRequest) -> WayfinderResponse {
        let response = match request.request {
            Some(RequestKind::GetNodeInfo(_)) => ResponseKind::NodeInfo(NodeInfo {
                node_id: self.provider.node_id(),
                num_originators: self.provider.num_originators(),
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
    use crate::wayfinder_v1alpha::{GetLinkQualityTableRequest, ResolveRouteRequest};
    use alloc::vec;

    /// Test double that returns canned responses and records the last
    /// `resolve_route` destination it was called with.
    #[derive(Default)]
    struct MockProvider {
        link_quality: Vec<LinkQualityEntryData>,
        route_resolution: Option<RouteResolutionData>,
        // RefCell would be nicer but no_std + alloc here — a Cell of an
        // owned Vec would require Clone gymnastics, so we just leave the
        // resolution as a single fixed answer per test.
    }

    impl WayfinderDataProvider for MockProvider {
        fn node_id(&self) -> Vec<u8> {
            vec![]
        }
        fn num_originators(&self) -> u32 {
            0
        }
        fn routing_table(&self) -> Vec<RoutingEntryData> {
            vec![]
        }
        fn link_quality_table(&self) -> Vec<LinkQualityEntryData> {
            self.link_quality.clone()
        }
        fn resolve_route(&self, _destination: &[u8]) -> Option<RouteResolutionData> {
            self.route_resolution.clone()
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

    fn proto_kind_name(k: &ResponseKind) -> &'static str {
        match k {
            ResponseKind::NodeInfo(_) => "NodeInfo",
            ResponseKind::RoutingTable(_) => "RoutingTable",
            ResponseKind::LinkQualityTable(_) => "LinkQualityTable",
            ResponseKind::ResolveRoute(_) => "ResolveRoute",
            ResponseKind::Error(_) => "Error",
        }
    }
}
