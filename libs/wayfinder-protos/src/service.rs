use crate::wayfinder_v1alpha::{
    ErrorResponse, NeighborPath, NodeInfo, RoutingEntry, RoutingTable, WayfinderRequest,
    WayfinderResponse, wayfinder_request::Request as RequestKind,
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

/// Implemented by anything that can supply router state to [`WayfinderService`].
/// Intentionally transport- and protocol-agnostic so callers can implement it
/// for whatever router type they have without pulling in a dependency on this crate.
pub trait WayfinderDataProvider {
    fn node_id(&self) -> Vec<u8>;
    fn num_originators(&self) -> u32;
    fn routing_table(&self) -> Vec<RoutingEntryData>;
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

            None => ResponseKind::Error(ErrorResponse {
                message: "empty request".into(),
            }),
        };

        WayfinderResponse {
            response: Some(response),
        }
    }
}
