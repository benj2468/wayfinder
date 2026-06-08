//! The [`WayfinderDataProvider`] adapter over the router.
//!
//! Newtype so we can implement the external trait for the external
//! [`CentralRouter`]. This layer is `no_std` + `alloc`: it is pure projection
//! from router state into the management-API intermediate representation and
//! carries no transport dependencies.

use alloc::vec::Vec;

use wayfinder::CentralRouter;
use wayfinder::EgressInterface;
use wayfinder::interfaces::frame::Mac;
use wayfinder_protos::service::{
    EgressDecisionData, LinkQualityEntryData, NeighborPathData, RouteResolutionData,
    RoutingEntryData, WayfinderDataProvider,
};
use zerocopy::{FromBytes, IntoBytes};

/// Adapts a borrowed [`CentralRouter`] to the management-API data provider
/// trait.  Node addresses are [`Mac`]; the adapter projects them as raw
/// 6-byte slices into the management-API intermediate representation.
pub struct RouterAdapter<'a>(&'a CentralRouter);

impl<'a> RouterAdapter<'a> {
    /// Wrap a borrowed router so its state can be served through the
    /// management API.
    pub fn new(router: &'a CentralRouter) -> Self {
        Self(router)
    }
}

impl WayfinderDataProvider for RouterAdapter<'_> {
    fn node_id(&self) -> Vec<u8> {
        self.0.self_ident().as_bytes().to_vec()
    }

    fn num_originators(&self) -> u32 {
        self.0.originator_count() as u32
    }

    fn routing_table(&self) -> Vec<RoutingEntryData> {
        self.0
            .originator_table()
            .map(|r| RoutingEntryData {
                destination: r.neighbor_ident.as_bytes().to_vec(),
                next_hop: r.best_next_hop.as_bytes().to_vec(),
                tq: r.max_tq as u32,
                last_seqno: r.last_seqno,
                paths: r
                    .paths
                    .iter()
                    .map(|p| NeighborPathData {
                        neighbor_id: p.neighbor_ident.as_bytes().to_vec(),
                        tq: p.last_tq as u32,
                        last_seqno: p.last_seqno,
                    })
                    .collect(),
            })
            .collect()
    }

    fn link_quality_table(&self) -> Vec<LinkQualityEntryData> {
        self.0
            .link_quality_records()
            .iter()
            .map(|r| LinkQualityEntryData {
                neighbor_id: r.neighbor.as_bytes().to_vec(),
                iface_idx: r.iface_idx as u32,
                ewma_quality: r.ewma_quality as u32,
                sample_count: r.sample_count,
            })
            .collect()
    }

    fn resolve_route(&self, destination: &[u8]) -> Option<RouteResolutionData> {
        // Parse the request bytes as this router's identifier type, rejecting
        // any wrong-length input (`read_from_bytes` requires an exact match) so
        // the management API returns a structured error rather than silently
        // routing to a truncated or zero-padded address.
        let dest = Mac::read_from_bytes(destination).ok()?;
        let (next_hop, egress) = self.0.resolve_route(dest);
        Some(RouteResolutionData {
            next_hop: next_hop.as_bytes().to_vec(),
            egress: egress.map(|e| match e {
                EgressInterface::All => EgressDecisionData::AllInterfaces,
                EgressInterface::Interface(idx) => EgressDecisionData::Interface(idx as u32),
            }),
        })
    }
}
