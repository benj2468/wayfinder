use interfaces::{
    engine::{MeshRoutingEngine, RoutingAction},
    frame::{LinkFrame, LinkFrameDataMut, Mac},
};
use tracing::{debug, info, trace};
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    BatmanEngine, NeighborStats, OriginatorRecord, TrickleTimer,
    wire::{
        BATADV_BCAST, BATADV_IV_OGM, BATADV_MCAST, BATADV_UNICAST, BatmanBroadcastPacket,
        BatmanMcastPacket, BatmanOgmPacket, BatmanTvlvHdr, BatmanUnicastPacket, ETH_P_BATMAN,
        TvlvType, find_tvlv,
    },
};

impl<const MAX_ORIGINATORS: usize> BatmanEngine<MAX_ORIGINATORS> {
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
    /// [`MAX_MISSED_OGMS`]: crate::MAX_MISSED_OGMS
    pub fn next_hop(&self, now: core::time::Duration, destination: Mac) -> Option<Mac> {
        let seed = self.seed_interval();
        let record = self.originator_table.get(&destination)?;
        record
            .paths
            .iter()
            .filter(|p| !Self::path_stale(now, p, seed))
            .max_by_key(|p| p.last_tq)
            .map(|p| p.neighbor_ident)
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
        let expected = if path.interval_estimate.is_zero() {
            seed
        } else {
            path.interval_estimate
        };
        let budget = expected.saturating_mul(crate::MAX_MISSED_OGMS);
        now.saturating_sub(path.last_heard) > budget
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

    /// Replace the set of multicast groups the local host listens to.  These
    /// are announced to the mesh in the multicast TVLV of every OGM this node
    /// produces.  Groups beyond [`MAX_LOCAL_MCAST`] are dropped.
    ///
    /// [`MAX_LOCAL_MCAST`]: crate::MAX_LOCAL_MCAST
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
            for chunk in value.chunks_exact(6) {
                let mut bytes = [0u8; 6];
                bytes.copy_from_slice(chunk);
                if self.mcast_members.push((Mac(bytes), orig)).is_err() {
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
    fn mcast_groups_for(&self, orig: Mac) -> heapless::Vec<Mac, { crate::MAX_MCAST_MEMBERS }> {
        let mut groups: heapless::Vec<Mac, { crate::MAX_MCAST_MEMBERS }> = self
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
    /// [`MAX_INTERFACES`](crate::MAX_INTERFACES) are ignored.
    pub fn configure_interface_ogm(
        &mut self,
        idx: usize,
        i_min: core::time::Duration,
        i_max: core::time::Duration,
        now: core::time::Duration,
    ) {
        if idx >= crate::MAX_INTERFACES {
            return;
        }
        // Jitter seed: fold the node identity with the interface index so each
        // interface — and each node — fires on its own offset.
        let seed = u32::from_le_bytes([
            self.self_ident.0[2],
            self.self_ident.0[3],
            self.self_ident.0[4],
            self.self_ident.0[5],
        ]) ^ (idx as u32).wrapping_mul(0x0100_0193);
        while self.ogm_timers.len() <= idx {
            let _ = self
                .ogm_timers
                .push(TrickleTimer::new(i_min, i_max, now, seed));
        }
        self.ogm_timers[idx] = TrickleTimer::new(i_min, i_max, now, seed);
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

        let record = self.originator_table.get_mut(&orig_ident).unwrap();

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
                outbound_ogm.prev_sender = self.self_ident;

                // Write the fixed header into the caller's scratchpad, then copy
                // the TVLV tail (membership announcements) verbatim from the
                // incoming frame so it propagates unchanged with the re-flood.
                let size = core::mem::size_of::<BatmanOgmPacket>();
                let tvlv_len = u16::from_be(ogm.tvlv_len) as usize;
                let total = size + tvlv_len;

                reply.dst = Mac::BROADCAST;
                reply.protocol = ETH_P_BATMAN;
                reply
                    .payload
                    .get_mut(0..size)
                    .unwrap()
                    .copy_from_slice(&outbound_ogm.as_bytes()[..size]);
                if let (Some(dst), Some(src)) = (
                    reply.payload.get_mut(size..total),
                    frame.payload.get(size..total),
                ) {
                    dst.copy_from_slice(src);
                }

                self.apply_topology_change(now);
                return RoutingAction::Consumed;
            }
        }
        self.apply_topology_change(now);
        RoutingAction::Consumed
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

        reply.dst = Mac::BROADCAST;
        reply.protocol = ETH_P_BATMAN;
        reply
            .payload
            .get_mut(0..header_size)
            .unwrap()
            .copy_from_slice(&outbound.as_bytes()[..header_size]);
        reply
            .payload
            .get_mut(header_size..total)
            .unwrap_or(&mut [])
            .copy_from_slice(inner);

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

            reply.dst = next;
            reply.protocol = ETH_P_BATMAN;
            reply
                .payload
                .get_mut(0..size)
                .unwrap()
                .copy_from_slice(updated_hdr.as_bytes());
            reply
                .payload
                .get_mut(size..total)
                .unwrap_or(&mut [])
                .copy_from_slice(inner);
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

            reply.dst = next;
            reply.protocol = ETH_P_BATMAN;
            reply
                .payload
                .get_mut(0..size)
                .unwrap()
                .copy_from_slice(updated_hdr.as_bytes());
            reply
                .payload
                .get_mut(size..total)
                .unwrap_or(&mut [])
                .copy_from_slice(inner);
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

impl<const MAX_ORIGINATORS: usize> MeshRoutingEngine for BatmanEngine<MAX_ORIGINATORS> {
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
            prev_sender: self.self_ident,
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
