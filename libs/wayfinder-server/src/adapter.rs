//! The [`WayfinderDataProvider`] adapter over the router.
//!
//! Newtype so we can implement the external trait for the external
//! [`CentralRouter`]. This layer is `no_std` + `alloc` and carries no
//! transport dependencies. Most methods are pure projections of router state
//! into the management-API intermediate representation, but some — `set_auth`,
//! `set_config`, `revoke_node`, `approve_csr`, `deny_csr` — mutate the borrowed
//! router (or the provider-mode CA) in response to a request.

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
use wayfinder_protos::service::CsrOutcome;
use wayfinder_protos::service::EgressDecisionData;
use wayfinder_protos::service::InterfaceThroughputData;
use wayfinder_protos::service::IssuedCertData;
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
use wayfinder_protos::service::PendingCsrData;
use wayfinder_protos::service::RouteResolutionData;
use wayfinder_protos::service::RoutingEntryData;
use wayfinder_protos::service::RuntimeConfigData;
use wayfinder_protos::service::SecurityStatusData;
use wayfinder_protos::service::TableOccupancyData;
use wayfinder_protos::service::WayfinderDataProvider;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

use crate::provider::MeshAuthority;

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
    now: Duration,
    /// The mesh certificate authority, present only when this node runs in
    /// provider mode.  Drives the enrollment requests (`get_trust_anchor`,
    /// `submit_csr`, `revoke_node`); absent ⇒ those return an error.
    ca: Option<&'a mut dyn MeshAuthority>,
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
    /// monotonic instant the driver stamps on received frames.  `ca` is the
    /// optional provider-mode certificate authority.
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
        ca: Option<&'a mut dyn MeshAuthority>,
        now: Duration,
    ) -> Self {
        Self { router, now, ca }
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
> WayfinderDataProvider
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

    fn security_status(&self) -> SecurityStatusData {
        // No auth configured ⇒ report disabled (the Default).
        let Some(auth) = self.router.auth() else {
            return SecurityStatusData::default();
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
                NodeSecurityData {
                    node_id: mac.as_bytes().to_vec(),
                    verified: verified.is_some(),
                    cert_not_after: verified.map(|n| n.cert.not_after).unwrap_or(0),
                    revoked: auth.revoked_macs().any(|m| m == mac),
                }
            })
            .collect();

        SecurityStatusData {
            auth_enabled: true,
            mesh_id: auth.anchor().mesh_id,
            node_mac: cert.node_mac.to_vec(),
            cert_not_after: cert.not_after.get(),
            revocation_count: auth.revoked_macs().count() as u32,
            nodes,
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

    fn set_auth(&mut self, seed: &[u8], cert: &[u8], trust_anchor: &[u8]) -> Result<(), String> {
        let key_pair = Keypair::from_seed(
            seed.try_into()
                .map_err(|_| "seed must be exactly 32 bytes".to_string())?,
        );
        let cert = MembershipCert::from_bytes(cert)
            .ok_or_else(|| "unable to parse membership cert".to_string())?;
        let anchor = TrustAnchor::from_bytes(trust_anchor)
            .ok_or_else(|| "unable to parse trust anchor".to_string())?;
        let auth = OgmAuth::with_capacities(key_pair, cert, anchor);
        self.router.set_auth(auth);
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
        if let Some(lazy) = config.lazy_cert_distribution {
            self.router.apply_runtime_lazy_cert_distribution(lazy);
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

    fn runtime_config_active(&self) -> bool {
        self.router.runtime_config_active()
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
    ) -> Result<CsrOutcome, String> {
        self.ca
            .as_mut()
            .ok_or_else(|| "node is not a certificate-authority provider".to_string())?
            .submit_csr(node_mac, ed_pubkey, x_pubkey, enrollment_token)
    }

    fn list_pending_csrs(&self) -> Result<Vec<PendingCsrData>, String> {
        match &self.ca {
            Some(ca) => Ok(ca.list_pending()),
            None => Err("node is not a certificate-authority provider".to_string()),
        }
    }

    fn approve_csr(&mut self, node_mac: &[u8]) -> Result<(), String> {
        self.ca
            .as_mut()
            .ok_or_else(|| "node is not a certificate-authority provider".to_string())?
            .approve_csr(node_mac)
    }

    fn deny_csr(&mut self, node_mac: &[u8]) -> Result<(), String> {
        self.ca
            .as_mut()
            .ok_or_else(|| "node is not a certificate-authority provider".to_string())?
            .deny_csr(node_mac)
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

    fn list_certs(&self) -> Result<Vec<IssuedCertData>, String> {
        match &self.ca {
            Some(ca) => Ok(ca.list_certs()),
            None => Err("node is not a certificate-authority provider".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wayfinder::CentralRouter;
    use wayfinder::batman::wire::BATADV_IV_OGM;
    use wayfinder::batman::wire::BatmanOgmPacket;
    use wayfinder::interfaces::frame::LinkFrame;
    use wayfinder::interfaces::frame::Mac;
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
            packet_type: BATADV_IV_OGM,
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
        assert!(!RouterAdapter::new(&mut router, None, Duration::ZERO).runtime_config_active());

        let result =
            RouterAdapter::new(&mut router, None, Duration::ZERO).set_config(RuntimeConfigData {
                trickle: Some(TrickleConfigData {
                    iface_idx: 0,
                    min_interval_ms: 500,
                    max_interval_ms: 4000,
                }),
                ..Default::default()
            });
        assert!(result.is_ok());

        let adapter = RouterAdapter::new(&mut router, None, Duration::ZERO);
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

        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None, false);
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

        assert!(!RouterAdapter::new(&mut router, None, Duration::ZERO).runtime_config_active());

        let result =
            RouterAdapter::new(&mut router, None, Duration::ZERO).set_config(RuntimeConfigData {
                lazy_cert_distribution: Some(true),
                ..Default::default()
            });
        assert!(result.is_ok());
        assert!(RouterAdapter::new(&mut router, None, Duration::ZERO).runtime_config_active());

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
            RouterAdapter::new(&mut router, None, Duration::ZERO).set_config(RuntimeConfigData {
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
        assert!(RouterAdapter::new(&mut router, None, Duration::ZERO).runtime_config_active());
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
            RouterAdapter::new(&mut router, None, Duration::ZERO).set_config(RuntimeConfigData {
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
        RouterAdapter::new(&mut router, None, Duration::ZERO)
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

        RouterAdapter::new(&mut router, None, Duration::ZERO)
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
        RouterAdapter::new(&mut router, None, Duration::ZERO)
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

        let table = RouterAdapter::new(&mut router, None, Duration::ZERO).link_features_table();
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

        let table = RouterAdapter::new(&mut router, None, Duration::ZERO).link_features_table();
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
            RouterAdapter::new(&mut router, None, Duration::ZERO).set_config(RuntimeConfigData {
                link_features: Some(LinkFeaturesData {
                    iface_idx: 0, // nothing registered yet
                    tx_data: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            });
        let err = result.unwrap_err();
        assert!(err.contains("out of range"), "got: {err}");
        assert!(!RouterAdapter::new(&mut router, None, Duration::ZERO).runtime_config_active());
    }

    /// `set_config` with no fields set is a no-op that still succeeds.
    #[test]
    fn set_config_with_no_fields_is_a_no_op() {
        let mut router = CentralRouter::new(mac(1));
        let result = RouterAdapter::new(&mut router, None, Duration::ZERO)
            .set_config(RuntimeConfigData::default());
        assert!(result.is_ok());
        assert!(!RouterAdapter::new(&mut router, None, Duration::ZERO).runtime_config_active());
    }

    /// An out-of-range interface index is rejected rather than silently
    /// ignored (which is what the underlying router primitive does).
    #[test]
    fn set_config_out_of_range_iface_idx_errors() {
        let mut router = CentralRouter::new(mac(1));
        let result =
            RouterAdapter::new(&mut router, None, Duration::ZERO).set_config(RuntimeConfigData {
                trickle: Some(TrickleConfigData {
                    iface_idx: wayfinder::MAX_INTERFACES as u32,
                    min_interval_ms: 500,
                    max_interval_ms: 4000,
                }),
                ..Default::default()
            });
        let err = result.unwrap_err();
        assert!(err.contains("out of range"), "got: {err}");
        assert!(!RouterAdapter::new(&mut router, None, Duration::ZERO).runtime_config_active());
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
            RouterAdapter::new(&mut router, None, Duration::ZERO).set_config(RuntimeConfigData {
                trickle: Some(TrickleConfigData {
                    iface_idx: 1,
                    min_interval_ms: 500,
                    max_interval_ms: 4000,
                }),
                ..Default::default()
            });
        let err = result.unwrap_err();
        assert!(err.contains("out of range"), "got: {err}");
        assert!(!RouterAdapter::new(&mut router, None, Duration::ZERO).runtime_config_active());
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
            RouterAdapter::new(&mut router, None, Duration::ZERO).set_config(RuntimeConfigData {
                trickle: Some(TrickleConfigData {
                    iface_idx: 0,
                    min_interval_ms: 5000,
                    max_interval_ms: 1000,
                }),
                ..Default::default()
            });
        let err = result.unwrap_err();
        assert!(err.contains("min_interval_ms"), "got: {err}");
        assert!(!RouterAdapter::new(&mut router, None, Duration::ZERO).runtime_config_active());
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

    /// With auth disabled, the cert-distribution occupancy/rate metrics all
    /// read as empty/zero rather than `None` or garbage — mirroring how the
    /// other table-occupancy gauges default when their table is untouched.
    #[test]
    fn node_metrics_cert_fields_zero_without_auth() {
        let mut router = CentralRouter::new(mac(1));
        let m = RouterAdapter::new(&mut router, None, Duration::from_secs(5)).node_metrics();

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

        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None, false);
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
            packet_type: BATADV_IV_OGM,
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

        let m = RouterAdapter::new(&mut router, None, Duration::from_secs(5)).node_metrics();
        assert_eq!(m.cert_store.used, 1);
        assert_eq!(m.cert_store.capacity, 64);
    }

    /// `revoke_node` on a provider whose router *is* authenticated signs the
    /// record and folds it into the router so it floods — exercising the real
    /// adapter path (CA → parse → `ingest_revocation`), not just the CA.
    #[test]
    fn revoke_node_floods_when_provider_router_is_authenticated() {
        use crate::CertAuthority;
        use wayfinder::auth::OgmAuth;
        use wayfinder::wayfinder_auth::Keypair;
        use wayfinder::wayfinder_auth::MembershipCert;
        use wayfinder::wayfinder_auth::TrustAnchor;

        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None, false);
        ca.set_now_unix(100);

        // The provider node is itself an authenticated member: its own CA issues
        // its cert.
        let kp = Keypair::from_seed(&[2; 32]);
        let me = mac(1);
        let cert_bytes = ca_issue(&mut ca, &me.0, &kp.ed_pubkey(), &kp.x_pubkey());
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

    /// A record written through the logging crate is readable through the
    /// provider — the one join this whole feature rests on, since the adapter
    /// reaches the ring through a `static` rather than through anything the
    /// router hands it.
    #[test]
    fn logs_projects_records_from_the_global_ring() {
        let mut router = CentralRouter::new(mac(1));
        let adapter = RouterAdapter::new(&mut router, None, Duration::from_secs(0));

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
        let mut adapter = RouterAdapter::new(&mut router, None, Duration::from_secs(0));

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
        let s = RouterAdapter::new(&mut router, None, Duration::from_secs(0)).security_status();
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

        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None, false);
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
            packet_type: BATADV_IV_OGM,
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

        let s = RouterAdapter::new(&mut router, None, Duration::from_secs(0)).security_status();
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

        // Revoke the peer through the provider path (signs + floods into our auth).
        {
            let mut adapter =
                RouterAdapter::new(&mut router, Some(&mut ca), Duration::from_secs(0));
            adapter.revoke_node(&peer.0).expect("revoke");
        }
        let s = RouterAdapter::new(&mut router, None, Duration::from_secs(0)).security_status();
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
    }

    /// `revoke_node` on a provider whose router has auth *disabled* errors rather
    /// than signing a record that would silently never flood.
    #[test]
    fn revoke_node_errors_when_provider_router_has_no_auth() {
        use crate::CertAuthority;

        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None, false);
        ca.set_now_unix(100);
        let mut router = CentralRouter::new(mac(1)); // auth disabled
        let mut adapter = RouterAdapter::new(&mut router, Some(&mut ca), Duration::from_secs(0));
        let err = adapter.revoke_node(&mac(9).0).unwrap_err();
        assert!(err.contains("authentication disabled"), "got: {err}");
    }
}
