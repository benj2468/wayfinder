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
use wayfinder::auth::OgmAuth;
use wayfinder::interfaces::frame::Mac;
use wayfinder::wayfinder_auth::Keypair;
use wayfinder::wayfinder_auth::MembershipCert;
use wayfinder::wayfinder_auth::RevocationRecord;
use wayfinder::wayfinder_auth::TrustAnchor;
use wayfinder_protos::service::{
    EgressDecisionData, EnrollData, InterfaceThroughputData, LinkQualityEntryData,
    NeighborPathData, NodeMetricsData, OgmScheduleEntryData, RouteResolutionData, RoutingEntryData,
    TableOccupancyData, WayfinderDataProvider,
};
use zerocopy::{FromBytes, IntoBytes};

use crate::provider::MeshAuthority;

use alloc::string::{String, ToString};

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
    router: &'a mut CentralRouter,
    now: Duration,
    /// The mesh certificate authority, present only when this node runs in
    /// provider mode.  Drives the enrollment requests (`get_trust_anchor`,
    /// `submit_csr`, `revoke_node`); absent ⇒ those return an error.
    ca: Option<&'a mut dyn MeshAuthority>,
}

impl<'a> RouterAdapter<'a> {
    /// Wrap a borrowed router so its state can be served through the management
    /// API, evaluating time-varying metrics (throughput) as of `now` — the same
    /// monotonic instant the driver stamps on received frames.  `ca` is the
    /// optional provider-mode certificate authority.
    pub fn new(
        router: &'a mut CentralRouter,
        ca: Option<&'a mut dyn MeshAuthority>,
        now: Duration,
    ) -> Self {
        Self { router, now, ca }
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

    fn set_auth(&mut self, seed: &[u8], cert: &[u8], trust_anchor: &[u8]) -> Result<(), String> {
        let key_pair = Keypair::from_seed(
            seed.try_into()
                .map_err(|_| "seed must be exactly 32 bytes".to_string())?,
        );
        let cert = MembershipCert::from_bytes(cert)
            .ok_or_else(|| "unable to parse membership cert".to_string())?;
        let anchor = TrustAnchor::from_bytes(trust_anchor)
            .ok_or_else(|| "unable to parse trust anchor".to_string())?;
        let auth = OgmAuth::new(key_pair, cert, anchor);
        self.router.set_auth(auth);
        Ok(())
    }

    fn get_trust_anchor(&self) -> Result<Vec<u8>, String> {
        match &self.ca {
            Some(ca) => Ok(ca.trust_anchor_bytes()),
            None => Err("node is not a certificate-authority provider".to_string()),
        }
    }

    fn submit_csr(
        &mut self,
        node_mac: &[u8],
        ed_pubkey: &[u8],
        x_pubkey: &[u8],
        enrollment_token: &str,
    ) -> Result<EnrollData, String> {
        let ca = self
            .ca
            .as_mut()
            .ok_or_else(|| "node is not a certificate-authority provider".to_string())?;
        let cert = ca.issue_cert(node_mac, ed_pubkey, x_pubkey, enrollment_token)?;
        let trust_anchor = ca.trust_anchor_bytes();
        Ok(EnrollData { cert, trust_anchor })
    }

    fn revoke_node(&mut self, node_mac: &[u8]) -> Result<(), String> {
        // Flooding a revocation requires the provider node to itself be an
        // authenticated member (the revoke record rides this node's OGMs).
        // Reject up front rather than sign a record that would silently never
        // propagate, leaving the operator believing the node was revoked.
        if self.router.auth().is_none() {
            return Err(
                "cannot revoke: this provider node has mesh authentication disabled, \
                 so the revocation cannot be flooded"
                    .to_string(),
            );
        }
        // Sign the revocation with the CA, then fold it into our own router so it
        // floods across the mesh (provider node is also a member).
        let record_bytes = {
            let ca = self
                .ca
                .as_mut()
                .ok_or_else(|| "node is not a certificate-authority provider".to_string())?;
            ca.revoke(node_mac)?
        };
        let (record, _) = RevocationRecord::ref_from_prefix(&record_bytes)
            .map_err(|_| "authority produced a malformed revocation record".to_string())?;
        self.router.ingest_revocation(record, self.now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wayfinder::CentralRouter;
    use wayfinder::batman::wire::{BATADV_IV_OGM, BatmanOgmPacket};
    use wayfinder::interfaces::frame::{LinkFrame, Mac};
    use zerocopy::{FromBytes, IntoBytes};

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
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
    /// path.  `prev_sender == orig` and a full TTL make it a direct path.
    fn feed_direct_ogm(router: &mut CentralRouter, orig: Mac, seqno: u32, tq: u8) {
        let ogm = BatmanOgmPacket {
            packet_type: BATADV_IV_OGM,
            version: 5,
            ttl: 50,
            flags: 0,
            seqno: seqno.to_be(),
            orig,
            prev_sender: orig,
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

    /// An empty originator table must fold to all-zero metrics — in particular a
    /// zero (not NaN) mean, since the fold guards the divide-by-zero — and report
    /// the table capacities, not just the (zero) usage.
    #[test]
    fn node_metrics_empty_table_folds_to_zero_not_nan() {
        let mut router = CentralRouter::new(mac(1));
        let m = RouterAdapter::new(&mut router, None, Duration::from_secs(5)).node_metrics();

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

        let m = RouterAdapter::new(&mut router, None, Duration::from_secs(10)).node_metrics();

        assert_eq!(m.neighbor_count, 3);
        assert_eq!(m.tq_min, 145);
        assert_eq!(m.tq_max, 245);
        assert_eq!(m.tq_mean, 195.0);
        assert_eq!(m.paths_max, 1);
        assert_eq!(m.paths_mean, 1.0);
        assert_eq!((m.originators.used, m.originators.capacity), (3, 128));
    }

    /// `revoke_node` on a provider whose router *is* authenticated signs the
    /// record and folds it into the router so it floods — exercising the real
    /// adapter path (CA → parse → `ingest_revocation`), not just the CA.
    #[test]
    fn revoke_node_floods_when_provider_router_is_authenticated() {
        use crate::CertAuthority;
        use wayfinder::auth::OgmAuth;
        use wayfinder::wayfinder_auth::{Keypair, MembershipCert, TrustAnchor};

        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None);
        ca.set_now_unix(100);

        // The provider node is itself an authenticated member: its own CA issues
        // its cert.
        let kp = Keypair::from_seed(&[2; 32]);
        let me = mac(1);
        let cert_bytes = ca
            .issue_cert(&me.0, &kp.ed_pubkey(), &kp.x_pubkey(), "")
            .unwrap();
        let cert = MembershipCert::from_bytes(&cert_bytes).unwrap();
        let anchor = TrustAnchor::from_bytes(&ca.trust_anchor_bytes()).unwrap();

        let mut router = CentralRouter::new(me);
        router.set_auth(OgmAuth::new(kp, cert, anchor));
        router.auth_mut().unwrap().set_time(100);

        {
            let mut adapter =
                RouterAdapter::new(&mut router, Some(&mut ca), Duration::from_secs(0));
            adapter.revoke_node(&mac(9).0).expect("revoke succeeds");
        }
        // The provider's own router now holds (and will flood) the revocation.
        assert!(router.auth().unwrap().revoked_macs().any(|m| m == mac(9)));
    }

    /// `revoke_node` on a provider whose router has auth *disabled* errors rather
    /// than signing a record that would silently never flood.
    #[test]
    fn revoke_node_errors_when_provider_router_has_no_auth() {
        use crate::CertAuthority;

        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None);
        ca.set_now_unix(100);
        let mut router = CentralRouter::new(mac(1)); // auth disabled
        let mut adapter = RouterAdapter::new(&mut router, Some(&mut ca), Duration::from_secs(0));
        let err = adapter.revoke_node(&mac(9).0).unwrap_err();
        assert!(err.contains("authentication disabled"), "got: {err}");
    }
}
