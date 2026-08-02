use interfaces::engine::MeshRoutingEngine;
use interfaces::engine::RoutingAction;
use interfaces::frame::LinkFrame;
use interfaces::frame::LinkFrameDataMut;
use interfaces::frame::Mac;
use tracing::debug;
use tracing::info;
use tracing::trace;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

use crate::BatmanEngine;
use crate::KeepAliveStats;
use crate::NeighborStats;
use crate::OriginatorRecord;
use crate::TrickleTimer;
use crate::wire::BATADV_BCAST;
use crate::wire::BATADV_CERT_REPLY;
use crate::wire::BATADV_CERT_REQ;
use crate::wire::BATADV_IV_OGM;
use crate::wire::BATADV_KEEPALIVE;
use crate::wire::BATADV_MCAST;
use crate::wire::BATADV_UNICAST;
use crate::wire::BatmanBroadcastPacket;
use crate::wire::BatmanCertReplyPacket;
use crate::wire::BatmanCertReqPacket;
use crate::wire::BatmanMcastPacket;
use crate::wire::BatmanOgmPacket;
use crate::wire::BatmanTvlvHdr;
use crate::wire::BatmanUnicastPacket;
use crate::wire::ETH_P_BATMAN;
use crate::wire::TvlvType;
use crate::wire::find_tvlv;

impl<
    const MAX_ORIGINATORS: usize,
    const MAX_INTERFACES: usize,
    const MAX_MCAST_MEMBERS: usize,
    const MAX_LOCAL_MCAST: usize,
> BatmanEngine<MAX_ORIGINATORS, MAX_INTERFACES, MAX_MCAST_MEMBERS, MAX_LOCAL_MCAST>
{
    /// Actively queries the BATMAN routing table for a given destination.
    /// Returns the immediate next-hop MAC address if a route exists.
    ///
    /// This returns the cached `best_next_hop`, kept current by the periodic
    /// [`purge_stale`](Self::purge_stale) sweep.  Forwarding decisions on the
    /// receive hot path use the time-aware [`next_hop`](Self::next_hop) instead,
    /// which additionally ignores paths that have gone stale since the last
    /// sweep.
    pub fn lookup_route(&self, destination: Mac) -> Option<Mac> {
        // O(1) keyed lookup of the destination's record.
        self.originator_table
            .get(&destination)
            .map(|record| record.best_next_hop)
    }

    /// The best next hop toward `destination` as of `now`, ignoring any path
    /// that has gone stale — one not refreshed within [`MAX_MISSED_OGMS`] of its
    /// own learned emission interval.  Returns `None` when the destination is
    /// unknown or every path to it is stale, so a caller never forwards toward a
    /// neighbor that has gone silent, even between periodic sweeps.
    ///
    /// Among the surviving (non-OGM-stale) paths, selection uses
    /// [`effective_tq`](Self::effective_tq) rather than the raw
    /// [`NeighborStats::last_tq`] — so a path whose neighbor has missed its
    /// keep-alive budget loses to any live alternative even if its
    /// OGM-advertised TQ was higher, without being evicted outright the way
    /// OGM staleness is.
    ///
    /// [`MAX_MISSED_OGMS`]: crate::MAX_MISSED_OGMS
    pub fn next_hop(&self, now: core::time::Duration, destination: Mac) -> Option<Mac> {
        let seed = self.seed_interval();
        let record = self.originator_table.get(&destination)?;
        record
            .paths
            .iter()
            .filter(|p| !Self::path_stale(now, p, seed))
            .max_by_key(|p| self.effective_tq(now, p))
            .map(|p| p.neighbor_ident)
    }

    /// `path.last_tq`, hard-zeroed when [`keepalive_missed`](Self::keepalive_missed)
    /// is true for this path's relaying neighbor — guaranteeing such a path
    /// can never outrank any live alternative with a nonzero TQ, matching the
    /// deprioritization-not-eviction contract unconditionally. A **read-time
    /// overlay** used only inside [`next_hop`](Self::next_hop)'s comparison —
    /// it never mutates `path.last_tq` itself, so it is self-healing the
    /// instant a keep-alive resumes and needs no periodic decay/reset.
    /// Deliberately not used by
    /// [`recompute_best`](Self::recompute_best)/[`purge_stale`](Self::purge_stale):
    /// the cached `OriginatorRecord::max_tq`/`best_next_hop` stay driven by
    /// OGM data alone, mirroring the same cache/hot-path asymmetry
    /// [`path_stale`](Self::path_stale) already has.
    fn effective_tq(&self, now: core::time::Duration, path: &NeighborStats) -> u8 {
        if self.keepalive_missed(now, path.neighbor_ident) {
            0
        } else {
            path.last_tq
        }
    }

    /// Whether a `(last_heard, interval_estimate)` pair has aged out as of
    /// `now`: true once `now` has advanced more than `max_missed` of the
    /// *expected* interval past the last refresh. The expected interval is the
    /// learned cadence (`interval_estimate`), or `seed` until a second sample
    /// has been measured. Saturating arithmetic keeps the budget finite.
    /// Shared by [`path_stale`](Self::path_stale) (OGM paths) and
    /// [`keepalive_missed`](Self::keepalive_missed) (keep-alive heartbeats) —
    /// the same ageing shape, applied to two independent signals.
    fn is_stale(
        now: core::time::Duration,
        last_heard: core::time::Duration,
        interval_estimate: core::time::Duration,
        seed: core::time::Duration,
        max_missed: u32,
    ) -> bool {
        let expected = if interval_estimate.is_zero() {
            seed
        } else {
            interval_estimate
        };
        let budget = expected.saturating_mul(max_missed);
        now.saturating_sub(last_heard) > budget
    }

    /// Whether `path` has aged out as of `now`: true once `now` has advanced
    /// more than [`MAX_MISSED_OGMS`] of the path's *expected* OGM interval past
    /// its last refresh.  The expected interval is the path's learned cadence
    /// ([`NeighborStats::interval_estimate`]), or `seed` until the second OGM
    /// has been measured.  Saturating arithmetic keeps the budget finite.
    ///
    /// [`MAX_MISSED_OGMS`]: crate::MAX_MISSED_OGMS
    fn path_stale(
        now: core::time::Duration,
        path: &NeighborStats,
        seed: core::time::Duration,
    ) -> bool {
        Self::is_stale(
            now,
            path.last_heard,
            path.interval_estimate,
            seed,
            crate::MAX_MISSED_OGMS,
        )
    }

    /// The interval to seed a freshly-heard neighbor's keep-alive miss budget
    /// with, before a second heartbeat provides a real gap to measure: the
    /// largest configured keep-alive `i_max` across interfaces (the quietest
    /// cadence a stable link settles into), or
    /// [`DEFAULT_KEEPALIVE_INTERVAL`](crate::DEFAULT_KEEPALIVE_INTERVAL) if no
    /// interface has keep-alive configured.
    fn keepalive_seed_interval(&self) -> core::time::Duration {
        self.keepalive_timers
            .iter()
            .filter_map(|t| t.as_ref())
            .map(|t| t.i_max())
            .max()
            .unwrap_or(crate::DEFAULT_KEEPALIVE_INTERVAL)
    }

    /// Whether `neighbor` has missed its keep-alive budget as of `now`.
    /// `false` when we have never heard a keep-alive from `neighbor` at all —
    /// the opt-in-by-observation contract: a neighbor (or link) not running
    /// this feature is never penalized for silence it was never expected to
    /// break. Otherwise ages the neighbor's last heartbeat against
    /// [`MAX_MISSED_KEEPALIVES`](crate::MAX_MISSED_KEEPALIVES) of its learned
    /// (or seeded) cadence, via the same [`is_stale`](Self::is_stale) rule
    /// [`path_stale`](Self::path_stale) uses for OGM paths.
    ///
    /// `pub` (not just used internally by [`effective_tq`](Self::effective_tq)):
    /// also the basis of `CentralRouter`'s keep-alive observability, so an
    /// operator/app can see a link's direct liveness degrade before it shows
    /// up as a route switching away.
    pub fn keepalive_missed(&self, now: core::time::Duration, neighbor: Mac) -> bool {
        match self.keepalive.get(&neighbor) {
            None => false,
            Some(stats) => Self::is_stale(
                now,
                stats.last_heard,
                stats.interval_estimate,
                self.keepalive_seed_interval(),
                crate::MAX_MISSED_KEEPALIVES,
            ),
        }
    }

    /// The interval to seed a freshly discovered path's purge budget with, before
    /// its own cadence has been measured: the quietest cadence a stable neighbor
    /// settles into, i.e. the largest `i_max` across configured interfaces.
    /// Falls back to [`DEFAULT_OGM_INTERVAL`] when no interface is configured.
    ///
    /// [`DEFAULT_OGM_INTERVAL`]: crate::DEFAULT_OGM_INTERVAL
    fn seed_interval(&self) -> core::time::Duration {
        self.ogm_timers
            .iter()
            .map(|t| t.i_max())
            .max()
            .unwrap_or(crate::DEFAULT_OGM_INTERVAL)
    }

    /// Fold a freshly observed inter-OGM `gap` into a path's cadence estimate as
    /// a slow-decaying **peak hold**: `max(gap, old × 7/8)`.
    ///
    /// The estimate tracks the *slowest* cadence the path settles into, not its
    /// average.  This is deliberate, and the crux of stable convergence: a
    /// multi-interface node emits a burst of distinct-seqno OGMs each Trickle
    /// round, so a path sees many tiny intra-burst gaps interleaved with the real
    /// inter-round gap.  An average (EWMA) would collapse toward the tiny gaps and
    /// shrink the purge budget below the real cadence, purging a live neighbor the
    /// instant its Trickle interval doubled — which then re-discovers it, resets
    /// the timers, and pins the whole mesh at `i_min`.  Holding the peak instead
    /// keeps the budget at `MAX_MISSED_OGMS ×` the largest recent gap; since
    /// `MAX_MISSED_OGMS` (6) comfortably exceeds Trickle's doubling factor (2),
    /// the budget always covers the next, longer interval as the backoff grows,
    /// and only a neighbor that has genuinely gone silent ages out.  The gentle
    /// `×7/8` decay lets the estimate relax back down after a transient long gap.
    fn blend_interval(
        old: core::time::Duration,
        gap: core::time::Duration,
    ) -> core::time::Duration {
        if old.is_zero() {
            return gap;
        }
        // Decay the held peak by 1/8, in nanos to stay no_std, then hold the max
        // against the freshly observed gap.
        let decayed =
            core::time::Duration::from_nanos((old.as_nanos() * 7 / 8).min(u64::MAX as u128) as u64);
        decayed.max(gap)
    }

    /// Drop routing state that has aged out as of `now`: any individual path not
    /// refreshed within [`MAX_MISSED_OGMS`] of its learned interval is pruned,
    /// `best_next_hop` / `max_tq` recomputed from what remains, and any
    /// originator left with no live path is evicted entirely.  Runs off the hot
    /// path, on the periodic-broadcast tick, to reclaim table slots and keep the
    /// cached best hop honest after a neighbor disappears.  Latches
    /// [`topology_changed`](BatmanEngine::topology_changed) if it dropped
    /// anything, so the Trickle timers reset and the node re-announces promptly.
    ///
    /// [`MAX_MISSED_OGMS`]: crate::MAX_MISSED_OGMS
    pub fn purge_stale(&mut self, now: core::time::Duration) {
        let seed = self.seed_interval();
        let before = self.originator_table.len();

        let mut pruned_path = false;
        for record in self.originator_table.values_mut() {
            let paths_before = record.paths.len();
            record.paths.retain(|p| !Self::path_stale(now, p, seed));
            pruned_path |= record.paths.len() != paths_before;
            Self::recompute_best(record);
        }

        // An originator reachable on no live path is gone; drop the record.
        self.originator_table.retain(|_, r| !r.paths.is_empty());

        if self.originator_table.len() != before || pruned_path {
            self.topology_changed = true;
        }
    }

    /// Recompute `best_next_hop` and `max_tq` from a record's current paths,
    /// choosing the highest-TQ path.  Called after pruning so the cached best
    /// hop reflects only live paths.  Leaves the fields unchanged when no paths
    /// remain (such a record is evicted by [`purge_stale`](Self::purge_stale)).
    fn recompute_best(record: &mut OriginatorRecord) {
        let mut best: Option<&NeighborStats> = None;
        for p in record.paths.iter() {
            if best.is_none_or(|b| p.last_tq >= b.last_tq) {
                best = Some(p);
            }
        }
        if let Some(b) = best {
            record.max_tq = b.last_tq;
            record.best_next_hop = b.neighbor_ident;
        }
    }

    /// Record one relayed frame dropped because it didn't fit the caller's
    /// `reply` scratchpad (e.g. relaying across a smaller-MTU link).  `trace!`
    /// only — never `warn!` — because unlike a locally originated oversize
    /// frame, this is reachable by any neighbor relaying traffic through this
    /// node and must not let a peer drive log volume.
    fn note_relay_oversize_drop(&mut self, kind: &'static str, total: usize, reply_len: usize) {
        trace!(
            kind,
            total, reply_len, "drop: relay too large for reply buffer"
        );
        self.relay_oversize_drops = self.relay_oversize_drops.saturating_add(1);
    }

    /// Replace the set of multicast groups the local host listens to.  These
    /// are announced to the mesh in the multicast TVLV of every OGM this node
    /// produces.  Groups beyond this engine's `MAX_LOCAL_MCAST` are dropped.
    pub fn set_local_mcast_groups(&mut self, groups: &[Mac]) {
        self.local_mcast.clear();
        for g in groups {
            if self.local_mcast.push(*g).is_err() {
                break; // table full; drop the rest
            }
        }
    }

    /// The multicast groups the local host currently listens to.
    pub fn local_mcast_groups(&self) -> &[Mac] {
        &self.local_mcast
    }

    /// Iterate the originators that have announced interest in `group`.
    /// Drives selective multicast forwarding.
    pub fn mcast_listeners(&self, group: Mac) -> impl Iterator<Item = Mac> + '_ {
        self.mcast_members
            .iter()
            .filter(move |(g, _)| *g == group)
            .map(|(_, m)| *m)
    }

    /// Replace `orig`'s recorded multicast memberships with the groups carried
    /// in `tail` (the TVLV region following an OGM header).  An OGM with no
    /// multicast TVLV prunes all of `orig`'s memberships.  Called when an OGM
    /// is accepted; keeps [`Self::mcast_members`] in sync with the latest
    /// announcement from each originator.  Returns whether the set of groups
    /// attributed to `orig` actually changed.
    fn update_mcast_membership(&mut self, orig: Mac, frame: &LinkFrame) -> bool {
        let header_size = core::mem::size_of::<BatmanOgmPacket>();
        let tail = frame.payload.get(header_size..).unwrap_or(&[]);
        // Snapshot the prior membership so we can report whether it changed.
        let before = self.mcast_groups_for(orig);

        // Drop every membership currently attributed to this originator;
        // the incoming announcement is authoritative for it.
        let mut i = 0;
        while i < self.mcast_members.len() {
            if self.mcast_members[i].1 == orig {
                self.mcast_members.swap_remove(i);
            } else {
                i += 1;
            }
        }

        // Re-add the groups the originator now announces (6 bytes per MAC).
        if let Some(value) = find_tvlv(tail, TvlvType::Mcast) {
            for chunk in value.as_chunks::<6>().0 {
                if self.mcast_members.push((Mac(*chunk), orig)).is_err() {
                    break; // table full; drop the rest
                }
            }
        }

        // Report whether the membership set for this originator actually
        // changed, so the caller can treat a membership change as an
        // inconsistency that resets the Trickle backoff.
        let after = self.mcast_groups_for(orig);
        before != after
    }

    /// The sorted set of multicast group MACs currently attributed to `orig`.
    /// Used to detect whether an OGM's membership announcement changed anything.
    fn mcast_groups_for(&self, orig: Mac) -> heapless::Vec<Mac, MAX_MCAST_MEMBERS> {
        let mut groups: heapless::Vec<Mac, MAX_MCAST_MEMBERS> = self
            .mcast_members
            .iter()
            .filter(|(_, m)| *m == orig)
            .map(|(g, _)| *g)
            .collect();
        groups.sort_unstable_by_key(|g| g.0);
        groups
    }

    // ── per-interface Trickle (adaptive OGM emission) ─────────────────────────

    /// Install (or replace) the adaptive OGM schedule for interface `idx`,
    /// supplying that link's `i_min`/`i_max` at runtime.  Slots between the
    /// current length and `idx` are back-filled with the same bounds so the
    /// table stays dense and index-addressable.  Interfaces at or beyond
    /// `MAX_INTERFACES` (this engine's parameter, not the crate default) are
    /// ignored.
    pub fn configure_interface_ogm(
        &mut self,
        idx: usize,
        i_min: core::time::Duration,
        i_max: core::time::Duration,
        now: core::time::Duration,
    ) {
        if idx >= MAX_INTERFACES {
            return;
        }
        let seed = self.jitter_seed(idx, 0);
        Self::backfill(
            &mut self.ogm_timers,
            idx,
            TrickleTimer::new(i_min, i_max, now, seed),
        );
        self.ogm_timers[idx] = TrickleTimer::new(i_min, i_max, now, seed);
    }

    /// Per-node, per-interface jitter seed: folds the node identity with the
    /// interface index so each interface — and each node — fires on its own
    /// offset. `salt` distinguishes independent timer schedules on the same
    /// interface (e.g. OGM vs keep-alive) so they don't jitter in lockstep;
    /// pass `0` for a schedule with no sibling to distinguish from.
    fn jitter_seed(&self, idx: usize, salt: u32) -> u32 {
        u32::from_le_bytes([
            self.self_ident.0[2],
            self.self_ident.0[3],
            self.self_ident.0[4],
            self.self_ident.0[5],
        ]) ^ (idx as u32).wrapping_mul(0x0100_0193)
            ^ salt
    }

    /// Grow `v` with clones of `fill` until it has at least `idx + 1`
    /// elements, so `v[idx]` can be written unconditionally afterward.
    fn backfill<T: Clone, const N: usize>(v: &mut heapless::Vec<T, N>, idx: usize, fill: T) {
        while v.len() <= idx {
            let _ = v.push(fill.clone());
        }
    }

    /// Time until the soonest interface is next due to emit an OGM, as of `now`.
    /// The owning driver sleeps for this long before the next emission.  With no
    /// interfaces configured there is nothing to emit, so this reports a long
    /// idle interval rather than busy-looping.
    pub fn next_broadcast_after(&self, now: core::time::Duration) -> core::time::Duration {
        self.ogm_timers
            .iter()
            .map(|t| t.time_until(now))
            .min()
            .unwrap_or(core::time::Duration::from_secs(3600))
    }

    /// The index of the interface most overdue to emit as of `now`, or `None`
    /// when none is yet due.  Drives the driver's per-interface OGM emission:
    /// the soonest-scheduled due interface fires first.
    pub fn due_interface(&self, now: core::time::Duration) -> Option<usize> {
        self.ogm_timers
            .iter()
            .enumerate()
            .filter(|(_, t)| t.due(now))
            .min_by_key(|(_, t)| t.time_until(now))
            .map(|(idx, _)| idx)
    }

    /// Snapshot the adaptive OGM schedule of every configured interface: its
    /// current emission interval (the live publish rate) and the `i_min`/`i_max`
    /// bounds it adapts between.  Yields one [`OgmScheduleEntry`] per interface
    /// in registration order; empty when no interface has been configured.
    pub fn ogm_schedule(&self) -> impl Iterator<Item = crate::OgmScheduleEntry> + '_ {
        self.ogm_timers
            .iter()
            .enumerate()
            .map(|(iface_idx, t)| crate::OgmScheduleEntry {
                iface_idx,
                current_interval: t.interval(),
                min_interval: t.i_min(),
                max_interval: t.i_max(),
            })
    }

    /// Record that interface `idx` just emitted an OGM at `now`, advancing that
    /// interface's Trickle schedule (and doubling its interval toward `i_max`).
    pub fn on_interface_emitted(&mut self, idx: usize, now: core::time::Duration) {
        if let Some(timer) = self.ogm_timers.get_mut(idx) {
            timer.on_emit(now);
        }
    }

    /// Reset every interface's Trickle schedule to its `i_min`, used after an
    /// inconsistency so the node re-announces promptly on all links.
    pub fn reset_ogm_timers(&mut self, now: core::time::Duration) {
        for timer in self.ogm_timers.iter_mut() {
            timer.reset(now);
        }
    }

    // ── per-interface keep-alive (fixed-cadence heartbeat) ────────────────────

    /// Install (or replace) interface `idx`'s keep-alive transmit schedule.
    /// `Some(interval)` arms a fixed-cadence timer (built as a [`TrickleTimer`]
    /// with equal `i_min`/`i_max`, so it jitters each fire but never backs
    /// off); `None` disarms it — that interface then never appears from
    /// [`due_keepalive_interface`](Self::due_keepalive_interface). Slots
    /// between the current length and `idx` are back-filled with `None` so
    /// the table stays dense and index-addressable. Interfaces at or beyond
    /// `MAX_INTERFACES` (this engine's parameter, not the crate default) are
    /// ignored.
    pub fn configure_interface_keepalive(
        &mut self,
        idx: usize,
        interval: Option<core::time::Duration>,
        now: core::time::Duration,
    ) {
        if idx >= MAX_INTERFACES {
            return;
        }
        let seed = self.jitter_seed(idx, 0x9e3779b9);
        Self::backfill(&mut self.keepalive_timers, idx, None);
        self.keepalive_timers[idx] = interval.map(|iv| TrickleTimer::new(iv, iv, now, seed));
    }

    /// Time until the soonest interface is next due to emit a keep-alive, as
    /// of `now`. With no interface configured for keep-alive there is nothing
    /// to emit, so this reports a long idle interval rather than
    /// busy-looping (mirrors [`next_broadcast_after`](Self::next_broadcast_after)).
    pub fn next_keepalive_after(&self, now: core::time::Duration) -> core::time::Duration {
        self.keepalive_timers
            .iter()
            .filter_map(|t| t.as_ref())
            .map(|t| t.time_until(now))
            .min()
            .unwrap_or(core::time::Duration::from_secs(3600))
    }

    /// The index of the interface most overdue to emit a keep-alive as of
    /// `now`, or `None` when none is configured or due. Mirrors
    /// [`due_interface`](Self::due_interface) for the keep-alive schedule.
    pub fn due_keepalive_interface(&self, now: core::time::Duration) -> Option<usize> {
        self.keepalive_timers
            .iter()
            .enumerate()
            .filter_map(|(idx, t)| t.as_ref().map(|t| (idx, t)))
            .filter(|(_, t)| t.due(now))
            .min_by_key(|(_, t)| t.time_until(now))
            .map(|(idx, _)| idx)
    }

    /// Record that interface `idx` just emitted a keep-alive at `now`,
    /// advancing that interface's fixed-cadence schedule. A no-op if `idx`
    /// has no keep-alive timer configured.
    pub fn on_keepalive_emitted(&mut self, idx: usize, now: core::time::Duration) {
        if let Some(Some(timer)) = self.keepalive_timers.get_mut(idx) {
            timer.on_emit(now);
        }
    }

    /// Drop all *learned* routing state — the originator table, the
    /// broadcast-dedup table, and learned multicast memberships.  The node's own
    /// sequence numbers (kept monotonic so peers don't reject its next OGM as
    /// stale), locally-joined multicast groups, and per-interface Trickle timers
    /// are preserved, so the node keeps emitting on its normal schedule and
    /// simply re-learns the topology from the OGMs it now receives.
    ///
    /// Used when the node's authentication changes at runtime
    /// ([`CentralRouter::set_auth`](../wayfinder/struct.CentralRouter.html)), so
    /// routes learned under the previous (or no) auth regime are not retained
    /// under the new identity/anchor.
    ///
    /// Deliberately does *not* latch a topology change: that flag is consumed
    /// part-way through a per-interface emission round and would reset the other
    /// interfaces' timers mid-round, skipping their emission — so forcing a
    /// re-announce here would perturb convergence.  Routes are simply dropped and
    /// re-learned.
    pub fn reset(&mut self) {
        self.originator_table.clear();
        self.broadcast_seqno.clear();
        self.mcast_members.clear();
    }

    /// Revoke all originators that have been marked as stale.
    pub fn revoke_originators(&mut self, revoked: impl Iterator<Item = Mac>) {
        for revoked_mac in revoked {
            debug!(revoked = ?revoked_mac, "revoking originator");
            self.originator_table.retain(|mac, _| revoked_mac != *mac);
            for record in self.originator_table.values_mut() {
                record
                    .paths
                    .retain(|path| revoked_mac != path.neighbor_ident);
            }
        }
    }

    /// If a topology change was latched, clear it and reset all Trickle timers
    /// so emission accelerates back to `i_min`.  Called at the end of OGM
    /// processing and of the periodic broadcast.
    fn apply_topology_change(&mut self, now: core::time::Duration) {
        if core::mem::take(&mut self.topology_changed) {
            self.reset_ogm_timers(now);
        }
    }

    // ── per-packet-type receive handlers ──────────────────────────────────────
    //
    // [`handle_rx`](MeshRoutingEngine::handle_rx) is a thin dispatcher: it
    // applies the protocol filter, reads the BATMAN sub-type tag, and forwards
    // to one of these handlers.  Each owns the routing logic for a single packet
    // type — parsing its own wire header up front, then acting — so the business
    // logic stays separate from the dispatch and each type can be read in
    // isolation.

    /// Route an incoming OGM (`BATADV_IV_OGM`): learn/refresh the originator's
    /// paths and their observed cadence, fold in its multicast memberships,
    /// latch any topology change, and re-flood the OGM once per fresh sequence
    /// number.  OGMs are control traffic, so this always returns
    /// [`Consumed`](RoutingAction::Consumed); a re-flood is written into `reply`.
    fn handle_ogm<'rx, 'tx>(
        &mut self,
        now: core::time::Duration,
        frame: &'tx LinkFrame,
        local_quality: Option<u8>,
        reply: &mut LinkFrameDataMut<'rx>,
    ) -> RoutingAction {
        let Ok((ogm, _)) = BatmanOgmPacket::read_from_prefix(&frame.payload) else {
            trace!("drop: malformed OGM");
            return RoutingAction::Consumed;
        };
        trace!(?ogm, "rx OGM");

        let orig_ident = ogm.orig;

        // Rule 1: Drop our own looped back OGMs
        if orig_ident == self.self_ident {
            return RoutingAction::Consumed;
        }

        let incoming_seqno = u32::from_be(ogm.seqno);

        // Find or create the originator's record, keyed by its MAC.
        // A freshly discovered originator is itself a topology change.
        let is_new_orig = !self.originator_table.contains_key(&orig_ident);
        if is_new_orig {
            // Table full: evict the least-recently-heard originator to make room
            // rather than dropping this newly heard one.
            if self.originator_table.len() >= MAX_ORIGINATORS
                && let Some(oldest) = self
                    .originator_table
                    .values()
                    .min_by_key(|r| r.last_heard)
                    .map(|r| r.neighbor_ident)
            {
                self.originator_table.remove(&oldest);
            }
            let new_record = OriginatorRecord {
                last_heard: now,
                neighbor_ident: orig_ident,
                best_next_hop: frame.src,
                max_tq: 0,
                last_seqno: 0,
                paths: heapless::Vec::new(),
            };
            info!(orig = ?orig_ident, "discovered new originator");
            let _ = self.originator_table.insert(orig_ident, new_record);
        }

        // `orig_ident` is now guaranteed present: either it already existed
        // (`is_new_orig` false) or the block above just inserted it (eviction,
        // if any, only ever removes a *different* key since `orig_ident` was
        // absent at that point).
        #[expect(
            clippy::expect_used,
            reason = "orig_ident was just looked up or inserted above"
        )]
        let record = self
            .originator_table
            .get_mut(&orig_ident)
            .expect("orig_ident was just looked up or inserted above");

        // Whether this OGM carries a *strictly newer* sequence number than any
        // we've already processed from this originator.  Captured before
        // `last_seqno` is advanced below, because it gates re-forwarding: a copy
        // of a seqno we have already forwarded (`==`, e.g. the same OGM reaching
        // us via a second neighbor) must update our path metrics but must NOT be
        // re-flooded — otherwise it circulates until its TTL drains, flooding the
        // mesh.  A new record starts at `last_seqno == 0`, below the first real
        // seqno (1), so an originator's first OGM is always treated as new.
        let is_new_seqno = incoming_seqno > record.last_seqno;

        // Rule 2: accept this OGM for path/metric learning when it is at least as
        // fresh as the newest seen.  Same-seqno copies via other neighbors are
        // still recorded as alternate paths.
        if incoming_seqno >= record.last_seqno {
            record.last_seqno = incoming_seqno;
            // Hearing this originator on any path keeps the whole record alive;
            // `last_heard` tracks the freshest path.
            record.last_heard = now;

            // Attenuate the advertised path TQ by one hop, then clamp it by our
            // locally-measured link quality to the relaying neighbor: a node
            // cannot make a path look better than the physical link we actually
            // observe to it, which blunts an attacker advertising an inflated TQ
            // to attract traffic.
            let computed_tq = ogm.tq.saturating_sub(10);
            let computed_tq = match local_quality {
                Some(local) => computed_tq.min(local),
                None => computed_tq,
            };

            // Track the path via this specific immediate neighbor.  Stamp it with
            // `now`, and on each genuinely newer seqno fold the observed gap into
            // the path's EWMA cadence estimate — so the path ages on the rate we
            // actually hear *it* (its own Trickle pacing, however fast or slow),
            // not on how fast this node happens to emit.
            if let Some(path) = record
                .paths
                .iter_mut()
                .find(|p| p.neighbor_ident == frame.src)
            {
                if incoming_seqno > path.last_seqno {
                    let gap = now.saturating_sub(path.last_heard);
                    path.interval_estimate = Self::blend_interval(path.interval_estimate, gap);
                }
                path.last_tq = computed_tq;
                path.last_seqno = incoming_seqno;
                path.last_heard = now;
            } else if record.paths.len() < 4 {
                let _ = record.paths.push(NeighborStats {
                    neighbor_ident: frame.src,
                    last_tq: computed_tq,
                    last_seqno: incoming_seqno,
                    last_heard: now,
                    // Unsampled until a second OGM gives a gap to measure; the
                    // seed budget covers the gap (see `path_stale`).
                    interval_estimate: core::time::Duration::ZERO,
                });
            }

            // Update routing-table selection with hysteresis.  Always refresh the
            // incumbent next hop's metric when we hear it again (its quality may
            // have risen or fallen), but only *switch* the next hop for a path
            // that is strictly better.  An equal-quality copy arriving via a
            // different neighbor — the common case in a redundant mesh — is kept
            // as an alternate path (above) without displacing the incumbent.
            if frame.src == record.best_next_hop {
                record.max_tq = computed_tq;
            } else if computed_tq > record.max_tq {
                record.max_tq = computed_tq;
                record.best_next_hop = frame.src;
            }

            // Fold this originator's multicast memberships (carried in the OGM's
            // TVLV tail) into the membership table.  The `record` borrow has
            // ended above, so taking `&mut self` here is fine.
            let mcast_changed = self.update_mcast_membership(orig_ident, frame);

            // Reset the Trickle backoff only for changes to *our own advertised
            // state* — gaining a neighbor (we are likely newly reachable too) or a
            // change to the multicast groups we announce.  A change to our chosen
            // next hop toward some *other* originator is deliberately NOT an
            // inconsistency: our OGM advertises only ourselves, so re-announcing
            // faster would tell neighbors nothing new — and in a dense mesh the
            // per-seqno TQ jitter from varying flood paths would otherwise flip
            // `best_next_hop` every round, pinning the whole mesh at `i_min` and
            // never letting it quieten.  A genuinely lost route still resets via
            // [`purge_stale`], and forwarding always follows the current best live
            // path regardless.
            if is_new_orig || mcast_changed {
                self.topology_changed = true;
            }

            // --- REACTIVE STEP: Forward OGM (Flood Routing Propagation) ---
            // Re-flood only the first time we see a sequence number, and only
            // while TTL remains, so each (originator, seqno) is forwarded by this
            // node at most once.
            if is_new_seqno && ogm.ttl > 1 {
                let mut outbound_ogm = ogm;
                outbound_ogm.ttl -= 1;
                outbound_ogm.tq = computed_tq;

                // Write the fixed header into the caller's scratchpad, then copy
                // the TVLV tail (membership announcements) verbatim from the
                // incoming frame so it propagates unchanged with the re-flood.
                let size = core::mem::size_of::<BatmanOgmPacket>();
                let tvlv_len = u16::from_be(ogm.tvlv_len) as usize;
                let total = size + tvlv_len;

                // The reply scratchpad may be smaller than this OGM (e.g. it was
                // received on a large-MTU link but is being re-flooded out one
                // with a smaller one); drop the re-flood rather than panic.
                if total <= reply.payload.len() {
                    reply.dst = Mac::BROADCAST;
                    reply.protocol = ETH_P_BATMAN;
                    reply.payload[..size].copy_from_slice(&outbound_ogm.as_bytes()[..size]);
                    if let Some(src) = frame.payload.get(size..total) {
                        reply.payload[size..total].copy_from_slice(src);
                    }
                } else {
                    self.note_relay_oversize_drop("ogm_reflood", total, reply.payload.len());
                }

                self.apply_topology_change(now);
                return RoutingAction::Consumed;
            }
        }
        self.apply_topology_change(now);
        RoutingAction::Consumed
    }

    /// Route an incoming keep-alive heartbeat (`BATADV_KEEPALIVE`): link-local
    /// only — never forwarded, never delivered locally, no reply written.
    /// Records that `frame.src` is alive as of `now` so
    /// [`next_hop`](Self::next_hop) can deprioritize routes through it the
    /// instant it goes quiet, without waiting for OGM-interval-based
    /// staleness. Always [`Consumed`](RoutingAction::Consumed).
    fn handle_keepalive(&mut self, now: core::time::Duration, frame: &LinkFrame) -> RoutingAction {
        let Ok((_hdr, _)) = crate::wire::BatmanKeepAlivePacket::read_from_prefix(&frame.payload)
        else {
            trace!("drop: malformed keepalive");
            return RoutingAction::Consumed;
        };
        if frame.src != self.self_ident {
            self.note_keepalive(now, frame.src);
        }
        RoutingAction::Consumed
    }

    /// Record one keep-alive heartbeat from `neighbor` at `now`: folds the
    /// observed gap into its learned cadence via the same peak-hold technique
    /// as OGM paths ([`blend_interval`](Self::blend_interval)) on any second
    /// or later heartbeat, or arms a fresh entry on first sight. Evicts the
    /// least-recently-heard neighbor when the table is full, mirroring
    /// [`handle_ogm`](Self::handle_ogm)'s originator-table eviction.
    fn note_keepalive(&mut self, now: core::time::Duration, neighbor: Mac) {
        if let Some(stats) = self.keepalive.get_mut(&neighbor) {
            let gap = now.saturating_sub(stats.last_heard);
            stats.interval_estimate = Self::blend_interval(stats.interval_estimate, gap);
            stats.last_heard = now;
            return;
        }

        if self.keepalive.len() >= MAX_ORIGINATORS
            && let Some(oldest) = self
                .keepalive
                .iter()
                .min_by_key(|(_, s)| s.last_heard)
                .map(|(m, _)| *m)
        {
            self.keepalive.remove(&oldest);
        }
        let _ = self.keepalive.insert(
            neighbor,
            KeepAliveStats {
                last_heard: now,
                interval_estimate: core::time::Duration::ZERO,
            },
        );
    }

    /// Route an incoming flooded broadcast (`BATADV_BCAST`): drop our own and
    /// duplicates, deliver locally, and re-flood with a decremented TTL until it
    /// expires.  Returns [`DeliverLocalAndForward`] when it both delivers and
    /// re-floods (the re-flood is written into `reply`).
    ///
    /// [`DeliverLocalAndForward`]: RoutingAction::DeliverLocalAndForward
    fn handle_broadcast<'rx, 'tx>(
        &mut self,
        frame: &'tx LinkFrame,
        reply: &mut LinkFrameDataMut<'rx>,
    ) -> RoutingAction {
        let Ok((bcast, inner)) = BatmanBroadcastPacket::read_from_prefix(&frame.payload) else {
            trace!("drop: malformed broadcast");
            return RoutingAction::Consumed;
        };
        trace!(?bcast, "rx broadcast");

        let orig_ident = bcast.orig;

        // Rule 1: never act on our own broadcast looping back.
        if orig_ident == self.self_ident {
            return RoutingAction::Consumed;
        }

        let incoming_seqno = u32::from_be(bcast.seqno);

        // Rule 2: deduplicate on (orig, seqno).  A broadcast arriving via several
        // paths must be flooded onward only once, or it would circulate forever
        // on a cyclic mesh.
        if let Some(entry) = self.broadcast_seqno.iter_mut().find(|e| e.0 == orig_ident) {
            if incoming_seqno <= entry.1 {
                return RoutingAction::Consumed; // duplicate or stale
            }
            entry.1 = incoming_seqno;
        } else if self
            .broadcast_seqno
            .push((orig_ident, incoming_seqno))
            .is_err()
        {
            return RoutingAction::Consumed; // table full, drop packet
        }

        // Rule 3: TTL exhausted — deliver to the local node but do not re-flood
        // (mirrors OGM TTL expiry).
        if bcast.ttl <= 1 {
            return RoutingAction::DeliverLocal;
        }

        // Rule 4: re-flood with a decremented TTL.  The inner frame is copied
        // verbatim after the header so the next hop can deliver it too.  The
        // local delivery of the inner frame is the caller's responsibility — it
        // strips this header off `frame`.
        let mut outbound = bcast;
        outbound.ttl -= 1;

        let header_size = core::mem::size_of::<BatmanBroadcastPacket>();
        let total = header_size + inner.len();

        // As above: the reply scratchpad may not have room for a large frame
        // relayed toward a smaller-MTU link. Skip the re-flood rather than
        // panic; local delivery still happens from `frame`, independent of
        // `reply`.
        if total <= reply.payload.len() {
            reply.dst = Mac::BROADCAST;
            reply.protocol = ETH_P_BATMAN;
            reply.payload[..header_size].copy_from_slice(&outbound.as_bytes()[..header_size]);
            reply.payload[header_size..total].copy_from_slice(inner);
        } else {
            self.note_relay_oversize_drop("broadcast_reflood", total, reply.payload.len());
        }

        RoutingAction::DeliverLocalAndForward(Mac::BROADCAST)
    }

    /// Route an incoming unicast (`BATADV_UNICAST`): deliver locally when it is
    /// addressed to us, otherwise relay toward the next live hop with a
    /// decremented TTL (written into `reply`).  Dropped when the TTL is exhausted
    /// or no live route to the destination is known.
    fn handle_unicast<'rx, 'tx>(
        &mut self,
        now: core::time::Duration,
        frame: &'tx LinkFrame,
        reply: &mut LinkFrameDataMut<'rx>,
    ) -> RoutingAction {
        let Ok((unicast_hdr, _)) = BatmanUnicastPacket::read_from_prefix(&frame.payload) else {
            trace!("drop: malformed unicast");
            return RoutingAction::Consumed;
        };
        trace!(unicast = ?unicast_hdr, "rx unicast");
        let dst = unicast_hdr.dest;

        // Rule 1: Is this packet meant for US?
        if dst == self.self_ident {
            // Yes! Return a modified action so the central router knows to strip
            // the header and deliver just the inner application data payload.
            return RoutingAction::DeliverLocal;
        }

        // Rule 2: Check TTL to prevent infinite routing bouncing
        if unicast_hdr.ttl <= 1 {
            return RoutingAction::Consumed; // Drop packet, expired
        }

        // Rule 3: We are an intermediate relay node. Look up the next live hop
        // for the final destination (stale hops are skipped).
        if let Some(next) = self.next_hop(now, dst) {
            // Re-write the mutable scratchpad/response buffer with the updated
            // header and preserve the inner application payload after the header.
            let mut updated_hdr = unicast_hdr;
            updated_hdr.ttl -= 1;

            let size = core::mem::size_of::<BatmanUnicastPacket>();
            let inner = frame.payload.get(size..).unwrap_or(&[]);
            let total = size + inner.len();

            // As above: skip the relay rather than panic if it doesn't fit the
            // reply scratchpad (e.g. relaying toward a smaller-MTU link).
            if total <= reply.payload.len() {
                reply.dst = next;
                reply.protocol = ETH_P_BATMAN;
                reply.payload[..size].copy_from_slice(updated_hdr.as_bytes());
                reply.payload[size..total].copy_from_slice(inner);
            } else {
                self.note_relay_oversize_drop("unicast_relay", total, reply.payload.len());
            }
        }

        RoutingAction::Consumed // Route unknown, drop packet
    }

    /// Route an incoming multicast copy (`BATADV_MCAST`).  Structurally
    /// identical to [`handle_unicast`](Self::handle_unicast): each copy is
    /// addressed to one listener node and travels toward it hop by hop, delivered
    /// locally on arrival and dropped on TTL expiry or unknown route.
    fn handle_mcast<'rx, 'tx>(
        &mut self,
        now: core::time::Duration,
        frame: &'tx LinkFrame,
        reply: &mut LinkFrameDataMut<'rx>,
    ) -> RoutingAction {
        let Ok((mcast_hdr, _)) = BatmanMcastPacket::read_from_prefix(&frame.payload) else {
            trace!("drop: malformed multicast");
            return RoutingAction::Consumed;
        };
        trace!(mcast = ?mcast_hdr, "rx multicast");
        let dst = mcast_hdr.dest;

        // Rule 1: this copy reached its target listener — deliver up.
        if dst == self.self_ident {
            return RoutingAction::DeliverLocal;
        }

        // Rule 2: drop if TTL is exhausted.
        if mcast_hdr.ttl <= 1 {
            return RoutingAction::Consumed;
        }

        // Rule 3: relay toward the next live hop for the target listener.
        if let Some(next) = self.next_hop(now, dst) {
            let mut updated_hdr = mcast_hdr;
            updated_hdr.ttl -= 1;

            let size = core::mem::size_of::<BatmanMcastPacket>();
            let inner = frame.payload.get(size..).unwrap_or(&[]);
            let total = size + inner.len();

            // As above: skip the relay rather than panic if it doesn't fit the
            // reply scratchpad (e.g. relaying toward a smaller-MTU link).
            if total <= reply.payload.len() {
                reply.dst = next;
                reply.protocol = ETH_P_BATMAN;
                reply.payload[..size].copy_from_slice(updated_hdr.as_bytes());
                reply.payload[size..total].copy_from_slice(inner);
            } else {
                self.note_relay_oversize_drop("mcast_relay", total, reply.payload.len());
            }
        }

        RoutingAction::Consumed // Route unknown, drop packet
    }

    /// Route an incoming lazy-cert-distribution fetch request
    /// (`BATADV_CERT_REQ`): deliver locally when addressed to us (so the
    /// router's auth state can answer it), otherwise relay toward the next
    /// live hop for the requested originator, exactly like
    /// [`handle_unicast`](Self::handle_unicast). Crypto-free: the engine only
    /// moves bytes, never inspects the requester's cert/signature body.
    fn handle_cert_req<'rx, 'tx>(
        &mut self,
        now: core::time::Duration,
        frame: &'tx LinkFrame,
        reply: &mut LinkFrameDataMut<'rx>,
    ) -> RoutingAction {
        let Ok((hdr, _)) = BatmanCertReqPacket::read_from_prefix(&frame.payload) else {
            trace!("drop: malformed cert request");
            return RoutingAction::Consumed;
        };
        trace!(cert_req = ?hdr, "rx cert request");
        let dst = hdr.dest;

        if dst == self.self_ident {
            return RoutingAction::DeliverLocal;
        }
        if hdr.ttl <= 1 {
            return RoutingAction::Consumed; // Drop packet, expired
        }
        if let Some(next) = self.next_hop(now, dst) {
            let mut updated_hdr = hdr;
            updated_hdr.ttl -= 1;

            let size = core::mem::size_of::<BatmanCertReqPacket>();
            let inner = frame.payload.get(size..).unwrap_or(&[]);
            let total = size + inner.len();

            if total <= reply.payload.len() {
                reply.dst = next;
                reply.protocol = ETH_P_BATMAN;
                reply.payload[..size].copy_from_slice(updated_hdr.as_bytes());
                reply.payload[size..total].copy_from_slice(inner);
            } else {
                self.note_relay_oversize_drop("cert_req_relay", total, reply.payload.len());
            }
        }

        RoutingAction::Consumed // Route unknown, drop packet
    }

    /// Route an incoming lazy-cert-distribution reply (`BATADV_CERT_REPLY`):
    /// deliver locally when addressed to us, otherwise relay toward the next
    /// live hop for the original requester. Structurally identical to
    /// [`handle_cert_req`](Self::handle_cert_req).
    fn handle_cert_reply<'rx, 'tx>(
        &mut self,
        now: core::time::Duration,
        frame: &'tx LinkFrame,
        reply: &mut LinkFrameDataMut<'rx>,
    ) -> RoutingAction {
        let Ok((hdr, _)) = BatmanCertReplyPacket::read_from_prefix(&frame.payload) else {
            trace!("drop: malformed cert reply");
            return RoutingAction::Consumed;
        };
        trace!(cert_reply = ?hdr, "rx cert reply");
        let dst = hdr.dest;

        if dst == self.self_ident {
            return RoutingAction::DeliverLocal;
        }
        if hdr.ttl <= 1 {
            return RoutingAction::Consumed; // Drop packet, expired
        }
        if let Some(next) = self.next_hop(now, dst) {
            let mut updated_hdr = hdr;
            updated_hdr.ttl -= 1;

            let size = core::mem::size_of::<BatmanCertReplyPacket>();
            let inner = frame.payload.get(size..).unwrap_or(&[]);
            let total = size + inner.len();

            if total <= reply.payload.len() {
                reply.dst = next;
                reply.protocol = ETH_P_BATMAN;
                reply.payload[..size].copy_from_slice(updated_hdr.as_bytes());
                reply.payload[size..total].copy_from_slice(inner);
            } else {
                self.note_relay_oversize_drop("cert_reply_relay", total, reply.payload.len());
            }
        }

        RoutingAction::Consumed // Route unknown, drop packet
    }

    /// Route a BATMAN-protocol frame whose sub-type tag is none of the known
    /// packet types, treating it as a bare payload addressed by `frame.dst`:
    /// deliver locally when it is for us, forward toward the best live next hop
    /// otherwise, or drop when no live path is known.
    fn route_by_dest(&self, now: core::time::Duration, frame: &LinkFrame) -> RoutingAction {
        if frame.dst == self.self_ident {
            RoutingAction::DeliverLocal
        } else if let Some(next) = self.next_hop(now, frame.dst) {
            // Forwarding decision dictated dynamically by the current best *live*
            // path (stale next hops are skipped).
            RoutingAction::ForwardTo(next)
        } else {
            RoutingAction::Consumed // No live path known, drop packet
        }
    }
}

impl<
    const MAX_ORIGINATORS: usize,
    const MAX_INTERFACES: usize,
    const MAX_MCAST_MEMBERS: usize,
    const MAX_LOCAL_MCAST: usize,
> MeshRoutingEngine
    for BatmanEngine<MAX_ORIGINATORS, MAX_INTERFACES, MAX_MCAST_MEMBERS, MAX_LOCAL_MCAST>
{
    #[tracing::instrument(skip(self, frame, reply), fields(ident = ?self.self_ident), level = "info")]
    fn handle_rx<'rx, 'tx>(
        &mut self,
        now: core::time::Duration,
        frame: &'tx LinkFrame,
        local_quality: Option<u8>,
        reply: &mut LinkFrameDataMut<'rx>,
    ) -> RoutingAction {
        trace!(
            src = ?frame.src,
            dst = ?frame.dst,
            protocol = %format_args!("0x{:04x}", frame.protocol.get()),
            payload_len = frame.payload.len(),
            "rx frame"
        );

        // Core protocol routing filter: only BATMAN frames with a sub-type byte.
        if frame.protocol.get() != ETH_P_BATMAN || frame.payload.is_empty() {
            return RoutingAction::Consumed;
        }

        // Dispatch on the BATMAN sub-type tag (first payload byte) to the handler
        // that owns that packet type's routing logic.
        match frame.payload[0] {
            BATADV_IV_OGM => self.handle_ogm(now, frame, local_quality, reply),
            BATADV_BCAST => self.handle_broadcast(frame, reply),
            BATADV_UNICAST => self.handle_unicast(now, frame, reply),
            BATADV_MCAST => self.handle_mcast(now, frame, reply),
            BATADV_CERT_REQ => self.handle_cert_req(now, frame, reply),
            BATADV_CERT_REPLY => self.handle_cert_reply(now, frame, reply),
            BATADV_KEEPALIVE => self.handle_keepalive(now, frame),
            _ => self.route_by_dest(now, frame),
        }
    }

    #[tracing::instrument(skip(self, now, tx_buffer), fields(ident = ?self.self_ident), level = "info")]
    fn produce_periodic_broadcast<'tx>(
        &mut self,
        now: core::time::Duration,
        tx_buffer: &'tx mut [u8],
    ) -> Option<&'tx [u8]> {
        // Age out routes to neighbors that have gone quiet.  Done on this
        // periodic tick — off the receive hot path — so a stale next hop is
        // never left in the table for long.  A route lost here is a topology
        // change, so reset the Trickle timers to re-announce promptly.
        self.purge_stale(now);
        self.apply_topology_change(now);

        // Increment sequence allocation for this ticker frame
        self.sequence_number = self.sequence_number.wrapping_add(1);

        let header_size = core::mem::size_of::<BatmanOgmPacket>();
        let tvlv_hdr_size = core::mem::size_of::<BatmanTvlvHdr>();

        // A multicast TVLV is attached only when the local host has joined at
        // least one group; its value is those group MACs back-to-back.
        let mcast_value_len = self.local_mcast.len() * core::mem::size_of::<Mac>();
        let tvlv_len = if mcast_value_len == 0 {
            0
        } else {
            tvlv_hdr_size + mcast_value_len
        };

        let ogm = BatmanOgmPacket {
            packet_type: BATADV_IV_OGM,
            version: 5,
            ttl: 50,
            flags: 0,
            seqno: self.sequence_number.to_be(),
            orig: self.self_ident,
            reserved: 0,
            tq: 255, // Max link capability score from original anchor source
            tvlv_len: (tvlv_len as u16).to_be(),
        };

        tx_buffer[..header_size].copy_from_slice(ogm.as_bytes());

        if tvlv_len > 0 {
            let hdr = BatmanTvlvHdr {
                tvlv_type: TvlvType::Mcast.as_u8(),
                version: 1,
                len: (mcast_value_len as u16).to_be(),
            };
            tx_buffer[header_size..header_size + tvlv_hdr_size].copy_from_slice(hdr.as_bytes());
            let mut off = header_size + tvlv_hdr_size;
            for group in &self.local_mcast {
                tx_buffer[off..off + core::mem::size_of::<Mac>()].copy_from_slice(group.as_bytes());
                off += core::mem::size_of::<Mac>();
            }
        }

        Some(&tx_buffer[..header_size + tvlv_len])
    }
}

impl<
    const MAX_ORIGINATORS: usize,
    const MAX_INTERFACES: usize,
    const MAX_MCAST_MEMBERS: usize,
    const MAX_LOCAL_MCAST: usize,
> BatmanEngine<MAX_ORIGINATORS, MAX_INTERFACES, MAX_MCAST_MEMBERS, MAX_LOCAL_MCAST>
{
    /// Write a keep-alive heartbeat into `tx_buffer`, returning the produced
    /// slice. Stateless — no sequence number or timestamp on the wire, since
    /// a keep-alive only needs to prove *that* this node is alive, not carry
    /// any ordering information (it is never relayed, so there is nothing to
    /// deduplicate). Returns `None` if `tx_buffer` is too small to hold the
    /// (2-byte) packet.
    pub fn produce_keepalive<'tx>(&self, tx_buffer: &'tx mut [u8]) -> Option<&'tx [u8]> {
        let header_size = core::mem::size_of::<crate::wire::BatmanKeepAlivePacket>();
        if header_size > tx_buffer.len() {
            return None;
        }
        let pkt = crate::wire::BatmanKeepAlivePacket {
            packet_type: BATADV_KEEPALIVE,
            version: 5,
        };
        tx_buffer[..header_size].copy_from_slice(pkt.as_bytes());
        Some(&tx_buffer[..header_size])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// A neighbor we have never received a keep-alive from is never treated
    /// as having missed one — the opt-in-by-observation contract. True at
    /// `now == 0` and stays true arbitrarily far into the future, since there
    /// is no entry to age out.
    #[test]
    fn keepalive_missed_is_false_when_never_heard() {
        let engine = BatmanEngine::<4>::new(mac(1));
        assert!(!engine.keepalive_missed(core::time::Duration::ZERO, mac(2)));
        assert!(!engine.keepalive_missed(core::time::Duration::from_secs(1_000_000), mac(2)));
    }

    fn keepalive_frame(src: u8, dst: u8) -> Vec<u8> {
        let pkt = crate::wire::BatmanKeepAlivePacket {
            packet_type: crate::wire::BATADV_KEEPALIVE,
            version: 5,
        };
        let mut data = Vec::new();
        data.extend_from_slice(mac(dst).as_bytes());
        data.extend_from_slice(mac(src).as_bytes());
        data.extend_from_slice(&ETH_P_BATMAN.to_be_bytes());
        data.extend_from_slice(pkt.as_bytes());
        data
    }

    /// One keep-alive from a neighbor arms `keepalive_missed` (no longer
    /// unconditionally `false`); a second heartbeat folds the observed gap
    /// into the learned `interval_estimate` via the same peak-hold technique
    /// as OGM paths.
    #[test]
    fn handle_rx_keepalive_arms_and_learns_gap() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let mut tx = [0u8; 64];

        let frame1 = keepalive_frame(2, 1);
        let parsed1 = LinkFrame::ref_from_prefix(&frame1).unwrap().0;
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        engine.handle_rx(core::time::Duration::ZERO, parsed1, None, &mut reply);

        let stats = engine.keepalive.get(&mac(2)).expect("armed after 1st hb");
        assert_eq!(stats.last_heard, core::time::Duration::ZERO);
        assert_eq!(stats.interval_estimate, core::time::Duration::ZERO);

        let frame2 = keepalive_frame(2, 1);
        let parsed2 = LinkFrame::ref_from_prefix(&frame2).unwrap().0;
        let mut reply2: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        engine.handle_rx(
            core::time::Duration::from_secs(5),
            parsed2,
            None,
            &mut reply2,
        );
        let stats = engine.keepalive.get(&mac(2)).unwrap();
        assert_eq!(stats.last_heard, core::time::Duration::from_secs(5));
        assert_eq!(stats.interval_estimate, core::time::Duration::from_secs(5));
    }

    /// A keep-alive frame truncated shorter than its 2-byte header is
    /// dropped rather than treated as a valid heartbeat — matching every
    /// sibling handler's malformed-input handling (see e.g.
    /// `handle_cert_req`).
    #[test]
    fn handle_rx_keepalive_drops_truncated_frame() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let mut tx = [0u8; 64];

        // A 1-byte payload: just the type tag, no version byte.
        let mut data = Vec::new();
        data.extend_from_slice(mac(1).as_bytes());
        data.extend_from_slice(mac(2).as_bytes());
        data.extend_from_slice(&ETH_P_BATMAN.to_be_bytes());
        data.push(BATADV_KEEPALIVE);
        let frame = LinkFrame::ref_from_prefix(&data).unwrap().0;

        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        engine.handle_rx(core::time::Duration::ZERO, frame, None, &mut reply);

        assert!(
            engine.keepalive.get(&mac(2)).is_none(),
            "a truncated keep-alive must not arm liveness state"
        );
    }

    /// Once armed with a learned 5s cadence, `keepalive_missed` flips true
    /// once the budget (`MAX_MISSED_KEEPALIVES` × 5s = 15s) since the last
    /// heartbeat is exceeded, and flips back false the instant a fresh
    /// heartbeat arrives — no ratchet, purely self-healing.
    #[test]
    fn keepalive_missed_flips_past_budget_and_self_heals() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let mut tx = [0u8; 64];

        // Two heartbeats 5s apart teach the engine a 5s cadence.
        for t in [0u64, 5] {
            let frame = keepalive_frame(2, 1);
            let parsed = LinkFrame::ref_from_prefix(&frame).unwrap().0;
            let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
            engine.handle_rx(core::time::Duration::from_secs(t), parsed, None, &mut reply);
        }

        // Budget is 3 * 5s = 15s past last_heard (5s), i.e. stale after t=20s.
        assert!(!engine.keepalive_missed(core::time::Duration::from_secs(20), mac(2)));
        assert!(engine.keepalive_missed(core::time::Duration::from_secs(21), mac(2)));

        // A fresh heartbeat immediately clears the miss — self-healing, no
        // persisted ratchet from having been missed.
        let frame = keepalive_frame(2, 1);
        let parsed = LinkFrame::ref_from_prefix(&frame).unwrap().0;
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        engine.handle_rx(
            core::time::Duration::from_secs(30),
            parsed,
            None,
            &mut reply,
        );
        assert!(!engine.keepalive_missed(core::time::Duration::from_secs(30), mac(2)));
    }

    /// A keep-alive is never forwarded or delivered locally — always
    /// `Consumed`, with an untouched reply buffer.
    #[test]
    fn handle_rx_keepalive_is_consumed_never_forwarded() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let mut tx = [0u8; 64];
        let frame = keepalive_frame(2, 1);
        let parsed = LinkFrame::ref_from_prefix(&frame).unwrap().0;
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        let action = engine.handle_rx(core::time::Duration::ZERO, parsed, None, &mut reply);
        assert!(matches!(action, RoutingAction::Consumed));
        assert_eq!(reply.protocol, 0);
    }

    /// Once the keep-alive table is at capacity, a heartbeat from a new
    /// neighbor evicts the least-recently-heard entry rather than being
    /// dropped — mirroring `test_full_table_evicts_least_recently_heard`'s
    /// coverage of the (separate) originator table's own eviction.
    #[test]
    fn keepalive_table_evicts_least_recently_heard_when_full() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let mut tx = [0u8; 64];

        // Fill the keep-alive table to capacity (4 neighbors), each first
        // heard at a distinct, increasing time.
        for (i, src) in (10..14).enumerate() {
            let frame = keepalive_frame(src, 1);
            let parsed = LinkFrame::ref_from_prefix(&frame).unwrap().0;
            let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
            engine.handle_rx(
                core::time::Duration::from_secs(i as u64),
                parsed,
                None,
                &mut reply,
            );
        }
        assert_eq!(engine.keepalive.len(), 4);
        assert!(engine.keepalive.contains_key(&mac(10)));

        // A new neighbor's heartbeat must be admitted, evicting the
        // least-recently-heard entry (neighbor 10, heard at t=0).
        let frame = keepalive_frame(20, 1);
        let parsed = LinkFrame::ref_from_prefix(&frame).unwrap().0;
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        engine.handle_rx(
            core::time::Duration::from_secs(100),
            parsed,
            None,
            &mut reply,
        );

        assert_eq!(engine.keepalive.len(), 4, "table stays at capacity");
        assert!(
            !engine.keepalive.contains_key(&mac(10)),
            "the least-recently-heard neighbor must be evicted"
        );
        assert!(
            engine.keepalive.contains_key(&mac(20)),
            "the new neighbor must be admitted"
        );
    }

    /// `produce_keepalive` writes the minimal 2-byte packet with the correct
    /// type tag and version.
    #[test]
    fn produce_keepalive_writes_minimal_packet() {
        let engine = BatmanEngine::<4>::new(mac(1));
        let mut buf = [0xffu8; 64];
        let produced = engine
            .produce_keepalive(&mut buf)
            .expect("buffer is plenty");
        assert_eq!(produced.len(), 2);
        assert_eq!(produced[0], crate::wire::BATADV_KEEPALIVE);
        assert_eq!(produced[1], 5);
    }

    /// A buffer too small for the (2-byte) header yields `None` rather than
    /// panicking or writing a truncated packet.
    #[test]
    fn produce_keepalive_none_when_buffer_too_small() {
        let engine = BatmanEngine::<4>::new(mac(1));
        let mut buf = [0u8; 1];
        assert_eq!(engine.produce_keepalive(&mut buf), None);
    }
}
