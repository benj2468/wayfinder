//! The [`WayfinderDataProvider`] adapter over the router.
//!
//! Newtype so we can implement the external trait for the external
//! [`CentralRouter`]. This layer is `no_std` + `alloc`: it is pure projection
//! from router state into the management-API intermediate representation and
//! carries no transport dependencies.

use core::time::Duration;

use alloc::vec::Vec;

use wayfinder::CentralRouter;
use wayfinder::EgressInterface;
use wayfinder::interfaces::frame::Mac;
use wayfinder_protos::service::{
    EgressDecisionData, InterfaceThroughputData, LinkQualityEntryData, NeighborPathData,
    NodeMetricsData, OgmScheduleEntryData, RouteResolutionData, RoutingEntryData,
    TableOccupancyData, WayfinderDataProvider,
};
use zerocopy::{FromBytes, IntoBytes};

/// Adapts a borrowed [`CentralRouter`] to the management-API data provider
/// trait.  Node addresses are [`Mac`]; the adapter projects them as raw
/// 6-byte slices into the management-API intermediate representation.
///
/// Carries the instant `now` (the router's monotonic clock) at which the
/// snapshot is taken, because throughput is reported as a *rate* evaluated at
/// that instant — an idle interface must read as a decaying rate, not a stale
/// one.  Construct a fresh adapter per request so the rate reflects the time
/// the query is served.
pub struct RouterAdapter<'a> {
    router: &'a CentralRouter,
    now: Duration,
}

impl<'a> RouterAdapter<'a> {
    /// Wrap a borrowed router so its state can be served through the management
    /// API, evaluating time-varying metrics (throughput) as of `now` — the same
    /// monotonic instant the driver stamps on received frames.
    pub fn new(router: &'a CentralRouter, now: Duration) -> Self {
        Self { router, now }
    }
}

impl WayfinderDataProvider for RouterAdapter<'_> {
    fn node_id(&self) -> Vec<u8> {
        self.router.self_ident().as_bytes().to_vec()
    }

    fn num_originators(&self) -> u32 {
        self.router.originator_count() as u32
    }

    fn routing_table(&self) -> Vec<RoutingEntryData> {
        self.router
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
        self.router
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
                    })
            })
            .collect()
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
        }
    }

    fn resolve_route(&self, destination: &[u8]) -> Option<RouteResolutionData> {
        // Parse the request bytes as this router's identifier type, rejecting
        // any wrong-length input (`read_from_bytes` requires an exact match) so
        // the management API returns a structured error rather than silently
        // routing to a truncated or zero-padded address.
        let dest = Mac::read_from_bytes(destination).ok()?;
        let (next_hop, egress) = self.router.resolve_route(dest);
        Some(RouteResolutionData {
            next_hop: next_hop.as_bytes().to_vec(),
            egress: egress.map(|e| match e {
                EgressInterface::All => EgressDecisionData::AllInterfaces,
                EgressInterface::Interface(idx) => EgressDecisionData::Interface(idx as u32),
            }),
        })
    }
}
