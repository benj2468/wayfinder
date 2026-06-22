use interfaces::{
    engine::{MeshRoutingEngine, RoutingAction},
    frame::{LinkFrame, LinkFrameDataMut, Mac},
};
use tracing::trace;
use tracing::warn;
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    BatmanEngine, NeighborStats, OriginatorRecord, TrickleTimer,
    wire::{
        BATADV_BCAST, BATADV_IV_OGM, BATADV_MCAST, BATADV_TVLV_MCAST, BATADV_UNICAST,
        BatmanBroadcastPacket, BatmanMcastPacket, BatmanOgmPacket, BatmanTvlvHdr,
        BatmanUnicastPacket, ETH_P_BATMAN, find_tvlv,
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

    /// The best next hop toward `destination`, ignoring any path that has gone
    /// stale — one not refreshed within the last [`MAX_MISSED_OGMS`] of this
    /// node's own OGM rounds.  Returns `None` when the destination is unknown or
    /// every path to it is stale, so a caller never forwards toward a neighbor
    /// that has gone silent, even between periodic sweeps.
    ///
    /// [`MAX_MISSED_OGMS`]: crate::MAX_MISSED_OGMS
    pub fn next_hop(&self, destination: Mac) -> Option<Mac> {
        let record = self.originator_table.get(&destination)?;
        let round = self.sequence_number;
        record
            .paths
            .iter()
            .filter(|p| !Self::round_stale(round, p.last_heard_round))
            .max_by_key(|p| p.last_tq)
            .map(|p| p.neighbor_ident)
    }

    /// Whether a record stamped at `stamp` has aged out as of round `now`: true
    /// once `now` has advanced more than [`MAX_MISSED_OGMS`] rounds past
    /// `stamp`.  Wrapping subtraction matches the wrapping OGM round counter.
    ///
    /// [`MAX_MISSED_OGMS`]: crate::MAX_MISSED_OGMS
    fn round_stale(now: u32, stamp: u32) -> bool {
        now.wrapping_sub(stamp) > crate::MAX_MISSED_OGMS
    }

    /// Drop routing state that has aged out: originators heard on no path within
    /// the last [`MAX_MISSED_OGMS`] OGM rounds are removed entirely, and for the
    /// survivors any individual stale path is pruned and `best_next_hop` /
    /// `max_tq` recomputed from what remains.  Runs off the hot path, on the
    /// periodic-broadcast tick, to reclaim table slots and keep the cached best
    /// hop honest after a neighbor disappears.  Latches
    /// [`topology_changed`](BatmanEngine::topology_changed) if it dropped
    /// anything, so the Trickle timers reset and the node re-announces promptly.
    ///
    /// [`MAX_MISSED_OGMS`]: crate::MAX_MISSED_OGMS
    pub fn purge_stale(&mut self) {
        let round = self.sequence_number;
        let before = self.originator_table.len();

        // Evict originators not heard from on any path recently.  Because
        // `record.last_heard_round` is the freshest of its paths' stamps, a
        // surviving record always keeps at least one fresh path.
        self.originator_table
            .retain(|_, r| !Self::round_stale(round, r.last_heard_round));

        let mut pruned_path = false;
        for record in self.originator_table.values_mut() {
            let paths_before = record.paths.len();
            record
                .paths
                .retain(|p| !Self::round_stale(round, p.last_heard_round));
            pruned_path |= record.paths.len() != paths_before;
            Self::recompute_best(record);
        }

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
    fn update_mcast_membership(&mut self, orig: Mac, tail: &[u8]) -> bool {
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
        if let Some(value) = find_tvlv(tail, BATADV_TVLV_MCAST) {
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

    /// If a topology change was latched, clear it and reset all Trickle timers
    /// so emission accelerates back to `i_min`.  Called at the end of OGM
    /// processing and of the periodic broadcast.
    fn apply_topology_change(&mut self, now: core::time::Duration) {
        if core::mem::take(&mut self.topology_changed) {
            self.reset_ogm_timers(now);
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
        let src = frame.src;
        let dst = frame.dst;
        let protocol = frame.protocol.get();

        tracing::trace!(
            "handling src = {:?}, dest = {:?}, proto = {:?}, payload_len = {:?}",
            src,
            dst,
            protocol,
            frame.payload.len()
        );

        // Core protocol routing filter
        if frame.protocol.get() != ETH_P_BATMAN || frame.payload.is_empty() {
            return RoutingAction::Consumed;
        }

        // Identify packet sub-type safely via zero-copy parsing
        match frame.payload[0] {
            BATADV_IV_OGM => {
                let parsed = BatmanOgmPacket::read_from_prefix(&frame.payload);

                let Ok((ogm, _)) = parsed else {
                    warn!("Unable to parse OGM Packet");
                    return RoutingAction::Consumed;
                };

                trace!("parsed OGM packet: {:?}", ogm);

                let orig_ident = ogm.orig;

                // Rule 1: Drop our own looped back OGMs
                if orig_ident == self.self_ident {
                    return RoutingAction::Consumed;
                }

                let incoming_seqno = u32::from_be(ogm.seqno);
                // This node's current OGM round; paths are stamped with it so
                // ageing is counted in rounds, not wall-clock (see `purge_stale`).
                let round = self.sequence_number;

                // Find or create the originator's record, keyed by its MAC.
                // A freshly discovered originator is itself a topology change.
                let is_new_orig = !self.originator_table.contains_key(&orig_ident);
                if is_new_orig {
                    // Table full: evict the least-recently-refreshed originator
                    // to make room rather than dropping this newly heard one.
                    if self.originator_table.len() >= MAX_ORIGINATORS
                        && let Some(oldest) = self
                            .originator_table
                            .values()
                            .min_by_key(|r| r.last_heard_round)
                            .map(|r| r.neighbor_ident)
                    {
                        self.originator_table.remove(&oldest);
                    }
                    let new_record = OriginatorRecord {
                        last_heard_round: round,
                        neighbor_ident: orig_ident,
                        best_next_hop: frame.src,
                        max_tq: 0,
                        last_seqno: 0,
                        paths: heapless::Vec::new(),
                    };
                    tracing::info!("Discovered new originator: {:?}", orig_ident);
                    let _ = self.originator_table.insert(orig_ident, new_record);
                }

                let record = self.originator_table.get_mut(&orig_ident).unwrap();
                // Best next hop before this OGM, to detect a route change below.
                let old_best = record.best_next_hop;

                // Whether this OGM carries a *strictly newer* sequence number
                // than any we've already processed from this originator.
                // Captured before `last_seqno` is advanced below, because it
                // gates re-forwarding: a copy of a seqno we have already
                // forwarded (`==`, e.g. the same OGM reaching us via a second
                // neighbor) must update our path metrics but must NOT be
                // re-flooded — otherwise it circulates until its TTL drains,
                // flooding the mesh.  A new record starts at `last_seqno == 0`,
                // below the first real seqno (1), so an originator's first OGM
                // is always treated as new.
                let is_new_seqno = incoming_seqno > record.last_seqno;

                // Rule 2: accept this OGM for path/metric learning when it is at
                // least as fresh as the newest seen.  Same-seqno copies via
                // other neighbors are still recorded as alternate paths.
                if incoming_seqno >= record.last_seqno {
                    record.last_seqno = incoming_seqno;
                    // Hearing this originator on any path keeps the whole record
                    // alive; `last_heard_round` tracks the freshest path.
                    record.last_heard_round = round;

                    // Attenuate the advertised path TQ by one hop, then clamp it
                    // by our locally-measured link quality to the relaying
                    // neighbor: a node cannot make a path look better than the
                    // physical link we actually observe to it, which blunts an
                    // attacker advertising an inflated TQ to attract traffic.
                    let computed_tq = ogm.tq.saturating_sub(10);
                    let computed_tq = match local_quality {
                        Some(local) => computed_tq.min(local),
                        None => computed_tq,
                    };

                    // Track path via this specific immediate neighbor, stamping
                    // it with the current round so a neighbor that later goes
                    // quiet ages out once the round gap exceeds MAX_MISSED_OGMS.
                    if let Some(path) = record.paths.iter_mut().find(|p| p.neighbor_ident == src) {
                        path.last_tq = computed_tq;
                        path.last_seqno = incoming_seqno;
                        path.last_heard_round = round;
                    } else if record.paths.len() < 4 {
                        let _ = record.paths.push(NeighborStats {
                            neighbor_ident: frame.src,
                            last_tq: computed_tq,
                            last_seqno: incoming_seqno,
                            last_heard_round: round,
                        });
                    }

                    // Update routing-table selection with hysteresis.  Always
                    // refresh the incumbent next hop's metric when we hear it
                    // again (its quality may have risen or fallen), but only
                    // *switch* the next hop for a path that is strictly better.
                    // An equal-quality copy arriving via a different neighbor —
                    // the common case in a redundant mesh, where the same
                    // originator is heard via several equal-cost neighbors every
                    // round — is recorded as an alternate path (above) without
                    // displacing the incumbent.  Without this, `best_next_hop`
                    // would flip-flop between equal-cost neighbors on every
                    // duplicate OGM, latching a spurious topology change each
                    // round (`best_changed` below) and pinning every node's
                    // Trickle backoff at `i_min` via the reflexive resets that
                    // ripple across the mesh.
                    if frame.src == record.best_next_hop {
                        record.max_tq = computed_tq;
                    } else if computed_tq > record.max_tq {
                        record.max_tq = computed_tq;
                        record.best_next_hop = frame.src;
                    }
                    // A changed best next hop is a genuine topology change (the
                    // `record` borrow ends here, before the `&mut self` call
                    // below).
                    let best_changed = record.best_next_hop != old_best;

                    // Fold this originator's multicast memberships (carried in
                    // the OGM's TVLV tail) into the membership table.  The
                    // `record` borrow has ended above, so taking `&mut self`
                    // here is fine.
                    let header_size = core::mem::size_of::<BatmanOgmPacket>();
                    let tail = frame.payload.get(header_size..).unwrap_or(&[]);
                    let mcast_changed = self.update_mcast_membership(orig_ident, tail);

                    // Treat any change to our routing view as a Trickle
                    // inconsistency: latch it so the timers reset and the node
                    // re-announces promptly (applied before we return below).
                    if is_new_orig || best_changed || mcast_changed {
                        self.topology_changed = true;
                    }

                    // --- REACTIVE STEP: Forward OGM (Flood Routing Propagation) ---
                    // Re-flood only the first time we see a sequence number, and
                    // only while TTL remains, so each (originator, seqno) is
                    // forwarded by this node at most once.
                    if is_new_seqno && ogm.ttl > 1 {
                        let mut outbound_ogm = ogm;
                        outbound_ogm.ttl -= 1;
                        outbound_ogm.tq = computed_tq;
                        outbound_ogm.prev_sender = self.self_ident;

                        // Write the fixed header into the caller's scratchpad,
                        // then copy the TVLV tail (membership announcements)
                        // verbatim from the incoming frame so it propagates
                        // unchanged with the re-flooded OGM.
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

            BATADV_BCAST => {
                let parsed = BatmanBroadcastPacket::read_from_prefix(&frame.payload);

                let Ok((bcast, inner)) = parsed else {
                    warn!("Unable to parse Broadcast Packet");
                    return RoutingAction::Consumed;
                };

                trace!("parsed broadcast packet: {:?}", bcast);

                let orig_ident = bcast.orig;

                // Rule 1: never act on our own broadcast looping back.
                if orig_ident == self.self_ident {
                    return RoutingAction::Consumed;
                }

                let incoming_seqno = u32::from_be(bcast.seqno);

                // Rule 2: deduplicate on (orig, seqno).  A broadcast arriving
                // via several paths must be flooded onward only once, or it
                // would circulate forever on a cyclic mesh.
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

                // Rule 3: TTL exhausted — deliver to the local node but do not
                // re-flood (mirrors OGM TTL expiry).
                if bcast.ttl <= 1 {
                    return RoutingAction::DeliverLocal;
                }

                // Rule 4: re-flood with a decremented TTL.  The inner frame is
                // copied verbatim after the header so the next hop can deliver
                // it too.  The local delivery of the inner frame is the
                // caller's responsibility — it strips this header off `frame`.
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

            BATADV_UNICAST => {
                let parsed = BatmanUnicastPacket::read_from_prefix(&frame.payload);
                if parsed.is_err() {
                    return RoutingAction::Consumed;
                }
                let (unicast_hdr, _) = parsed.unwrap();
                let dst = unicast_hdr.dest;

                // Rule 1: Is this packet meant for US?
                if dst == self.self_ident {
                    // Yes! Return a modified action so the central router knows
                    // to strip the header and deliver just the inner application data payload.
                    return RoutingAction::DeliverLocal;
                }

                // Rule 2: Check TTL to prevent infinite routing bouncing
                if unicast_hdr.ttl <= 1 {
                    return RoutingAction::Consumed; // Drop packet, expired
                }

                // Rule 3: We are an intermediate relay node. Look up the next
                // live hop for the final destination (stale hops are skipped).
                if let Some(next) = self.next_hop(dst) {
                    // Re-write the mutable scratchpad/response buffer with the updated header
                    // and preserve the inner application payload that follows the header.
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

            BATADV_MCAST => {
                // Structurally identical to unicast routing: each multicast
                // copy is addressed to one listener node and travels toward it
                // hop by hop, delivered locally on arrival.
                let parsed = BatmanMcastPacket::read_from_prefix(&frame.payload);
                if parsed.is_err() {
                    return RoutingAction::Consumed;
                }
                let (mcast_hdr, _) = parsed.unwrap();
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
                if let Some(next) = self.next_hop(dst) {
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

            // Unicast payload frames routing paths
            _ => {
                if dst == self.self_ident {
                    RoutingAction::DeliverLocal
                } else if let Some(next) = self.next_hop(dst) {
                    // Forwarding decision dictated dynamically by the current
                    // best *live* path (stale next hops are skipped).
                    RoutingAction::ForwardTo(next)
                } else {
                    RoutingAction::Consumed // No live path known, drop packet
                }
            }
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
        self.purge_stale();
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
                tvlv_type: BATADV_TVLV_MCAST,
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
