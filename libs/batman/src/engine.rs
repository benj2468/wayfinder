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
use crate::BroadcastSeqnoEntry;
use crate::KeepAliveStats;
use crate::NeighborStats;
use crate::OriginatorRecord;
use crate::TrickleTimer;
use crate::wire::BatmanBroadcastPacket;
use crate::wire::BatmanCertReplyPacket;
use crate::wire::BatmanCertReqPacket;
use crate::wire::BatmanEchoPacket;
use crate::wire::BatmanMcastPacket;
use crate::wire::BatmanOgmPacket;
use crate::wire::BatmanPacketType;
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
    ///
    /// Deliberately **not** `pub`: it takes no `now`, so it cannot answer the
    /// time-dependent question of whether the cached hop's proof is still
    /// current. Every production caller wants [`next_hop`](Self::next_hop);
    /// this exists for tests that assert on the cache itself.
    #[cfg(test)]
    pub(crate) fn lookup_route(&self, destination: Mac) -> Option<Mac> {
        // O(1) keyed lookup of the destination's record.  `best_next_hop` is
        // already `None` for a record whose paths are all unproven, so the
        // proof gate needs no separate check here.
        self.originator_table
            .get(&destination)
            .and_then(|record| record.best_next_hop)
    }

    /// The best next hop toward `destination` as of `now`, ignoring any path
    /// that has gone stale — one not refreshed within [`MAX_MISSED_OGMS`] of its
    /// own learned emission interval.  Returns `None` when the destination is
    /// unknown or every path to it is stale, so a caller never forwards toward a
    /// neighbor that has gone silent, even between periodic sweeps.
    ///
    /// Also `None` when a route exists but no live path's neighbor holds a
    /// current next-hop proof (authenticated meshes only). That is a *distinct*
    /// state from "destination unknown", and callers must not conflate the two
    /// — doing so is how the `unwrap_or(dest)` fallback this gate removed gets
    /// reintroduced. See [`CentralRouter::resolve_next_hop`] for the split.
    ///
    /// [`CentralRouter::resolve_next_hop`]: ../wayfinder/struct.CentralRouter.html
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
            // The proof gate. Separate from `recompute_best`'s because this is
            // the hot path: it recomputes from `paths` rather than reading the
            // cached `best_next_hop`, so gating only the cache would leave
            // forwarding open to exactly the next hop the cache refused.
            .filter(|p| self.proof_current(now, p.neighbor_ident))
            .max_by_key(|p| self.effective_tq(now, p))
            .map(|p| p.neighbor_ident)
    }

    /// The best next hop toward `destination` as of `now`, **ignoring the proof
    /// gate** — the same selection [`next_hop`](Self::next_hop) makes, minus
    /// the requirement that the relay have proven itself.
    ///
    /// Exists for the certificate-control plane alone, and is a deliberate
    /// hole. Proving a neighbor needs its pairwise key, which needs its
    /// certificate; under lazy cert distribution that certificate may itself
    /// have to be fetched over the mesh. Gating the fetch on proof deadlocks
    /// bootstrap: nobody can prove anything because nobody can obtain the keys
    /// to prove with.
    ///
    /// Safe precisely because of what travels this path. A certificate is
    /// public data and a `CertReq` carries the requester's own signed cert, so
    /// an attacker attracting this traffic learns nothing it could not read off
    /// the air, and can at worst blackhole cert distribution — which it could
    /// already do by jamming. **The data plane must never use this.**
    pub fn next_hop_unproven_ok(&self, now: core::time::Duration, destination: Mac) -> Option<Mac> {
        let seed = self.seed_interval();
        let record = self.originator_table.get(&destination)?;
        record
            .paths
            .iter()
            .filter(|p| !Self::path_stale(now, p, seed))
            .max_by_key(|p| self.effective_tq(now, p))
            .map(|p| p.neighbor_ident)
    }

    /// Record that `neighbor` has just proven itself a legitimate next hop.
    ///
    /// Called by the router when a challenge response verifies; the engine
    /// holds the timestamp but never the key material.
    pub fn note_proven(&mut self, now: core::time::Duration, neighbor: Mac, iface: usize) {
        if self.proven.insert(neighbor, (now, iface)).is_err() {
            // Table full: evict the least-recently-proven to make room, rather
            // than refusing a fresh proof and stranding the route it unlocks.
            if let Some(oldest) = self
                .proven
                .iter()
                .min_by_key(|(_, (t, _))| *t)
                .map(|(m, _)| *m)
            {
                self.proven.remove(&oldest);
                let _ = self.proven.insert(neighbor, (now, iface));
            }
        }
        // The peer answered, so whatever backoff its unanswered attempts had
        // grown is spent: the next renewal starts from `i_min` again. Without
        // this, one bad patch would permanently slow every future renewal of an
        // otherwise healthy neighbor.
        //
        // Dropped outright rather than zeroed, so the *next* attempt is the
        // first of a new run rather than the second of the old one. Nothing is
        // challenged early as a result: `proof_needs_refresh` is false for a
        // neighbor that has just proven itself, and it is the later of the two
        // waits that governs in `next_challenge_after`.
        self.challenged.remove(&neighbor);
        // A fresh proof can unlock a route immediately; don't make it wait for
        // the next periodic sweep.
        self.recompute_all_best(now);
    }

    /// Recompute every record's cached `best_next_hop`/`max_tq` against the
    /// current proof state.
    ///
    /// Run both after paths age out and the moment a neighbor proves itself:
    /// a proof arriving is precisely when a route becomes usable, and waiting
    /// for the next periodic sweep would leave the management API reporting no
    /// route for a link that already works.
    fn recompute_all_best(&mut self, now: core::time::Duration) {
        let seed = self.seed_interval();
        // Snapshot which neighbors are selectable before taking the mutable
        // borrow on the table, since the proof check reads `&self`.
        let require_proof = self.require_proof;
        let selectable: heapless::Vec<Mac, MAX_ORIGINATORS> = self
            .proven
            .iter()
            .filter(|(_, (last, _))| {
                !Self::is_stale(
                    now,
                    *last,
                    core::time::Duration::ZERO,
                    seed,
                    crate::MAX_MISSED_PROOFS,
                )
            })
            .map(|(m, _)| *m)
            .collect();
        let is_selectable = |m: Mac| !require_proof || selectable.contains(&m);

        for record in self.originator_table.values_mut() {
            Self::recompute_best(record, &is_selectable);
        }
    }

    /// Whether `neighbor`'s proof is current as of `now`.
    ///
    /// Always `true` when proof is not required (see
    /// [`set_require_proof`](Self::set_require_proof)), so an unauthenticated
    /// mesh — which has no pairwise keys and therefore no way to prove
    /// anything — routes exactly as it did before.
    pub fn proof_current(&self, now: core::time::Duration, neighbor: Mac) -> bool {
        if !self.require_proof {
            return true;
        }
        let seed = self.seed_interval();
        self.proven.get(&neighbor).is_some_and(|(last, _)| {
            !Self::is_stale(
                now,
                *last,
                core::time::Duration::ZERO,
                seed,
                crate::MAX_MISSED_PROOFS,
            )
        })
    }

    /// The interface `neighbor` most recently answered a challenge on, if its
    /// proof is still current.
    ///
    /// What egress resolution pins to, in preference to the link-quality
    /// table — see the `proven` field for why that table cannot be
    /// trusted to locate a peer under attack.
    pub fn proven_interface(&self, now: core::time::Duration, neighbor: Mac) -> Option<usize> {
        if !self.require_proof {
            return None;
        }
        let seed = self.seed_interval();
        self.proven.get(&neighbor).and_then(|(last, iface)| {
            (!Self::is_stale(
                now,
                *last,
                core::time::Duration::ZERO,
                seed,
                crate::MAX_MISSED_PROOFS,
            ))
            .then_some(*iface)
        })
    }

    /// Set whether a next hop must prove itself before it can be selected.
    ///
    /// The router turns this on exactly when mesh authentication is enabled.
    pub fn set_require_proof(&mut self, require: bool) {
        self.require_proof = require;
    }

    /// Whether `neighbor`'s proof should be renewed now.
    ///
    /// True well *before* [`proof_current`](Self::proof_current) goes false —
    /// after one expected interval against that call's
    /// [`MAX_MISSED_PROOFS`](crate::MAX_MISSED_PROOFS). Refreshing only once a
    /// proof has already lapsed would drop the route for however long the
    /// round trip takes, so a steady-state mesh would flap its next hop on
    /// every proof cycle. The gap between the two thresholds is the margin the
    /// exchange gets to complete in.
    fn proof_needs_refresh(&self, now: core::time::Duration, neighbor: Mac) -> bool {
        let seed = self.seed_interval();
        match self.proven.get(&neighbor) {
            None => true,
            Some((last, _)) => Self::is_stale(now, *last, core::time::Duration::ZERO, seed, 1),
        }
    }

    /// Every neighbor offering a path whose proof is missing, lapsed, or due
    /// for renewal — the set a driver should challenge.
    ///
    /// Empty when proof is not required. Yields each neighbor once even when it
    /// relays for several originators, so a driver does not challenge the same
    /// peer repeatedly in one pass.
    pub fn challenge_candidates(
        &self,
        now: core::time::Duration,
    ) -> impl Iterator<Item = Mac> + '_ {
        let mut seen: heapless::Vec<Mac, MAX_ORIGINATORS> = heapless::Vec::new();
        self.originator_table
            .values()
            .flat_map(|r| r.paths.iter())
            .map(|p| p.neighbor_ident)
            .filter(move |m| {
                if !self.require_proof || seen.contains(m) || !self.proof_needs_refresh(now, *m) {
                    return false;
                }
                // Back off between attempts at the same neighbor, so a peer
                // that never answers costs one challenge per `seed_interval`
                // rather than one per driver tick — but reach that rate by
                // doubling from `i_min`, not by starting there. See the
                // `challenged` field for why the first attempt is the one that
                // most often needs a prompt retry.
                if let Some((last, misses)) = self.challenged.get(m)
                    && now.saturating_sub(*last) < self.challenge_backoff(*misses)
                {
                    return false;
                }
                let _ = seen.push(*m);
                true
            })
    }

    /// Record that `neighbor` has just been challenged, extending its retry
    /// backoff by one doubling. Called by the router when it puts a challenge
    /// on the wire.
    ///
    /// The miss count only grows here and is cleared in
    /// [`note_proven`](Self::note_proven), so it counts *consecutive
    /// unanswered* attempts: an attempt that is answered before the next one
    /// is issued never lengthens the backoff. It saturates rather than wraps,
    /// which is what keeps a long-silent peer's backoff at the cap instead of
    /// snapping back to `i_min`.
    pub fn note_challenged(&mut self, now: core::time::Duration, neighbor: Mac) {
        let misses = self
            .challenged
            .get(&neighbor)
            .map_or(0, |(_, n)| n.saturating_add(1));
        if self.challenged.insert(neighbor, (now, misses)).is_err()
            && let Some(oldest) = self
                .challenged
                .iter()
                .min_by_key(|(_, (t, _))| *t)
                .map(|(m, _)| *m)
        {
            self.challenged.remove(&oldest);
            let _ = self.challenged.insert(neighbor, (now, misses));
        }
    }

    /// How long to wait after a challenge that has gone unanswered `misses`
    /// times before trying again: `i_min << misses`, capped at
    /// [`seed_interval`](Self::seed_interval).
    ///
    /// The floor is the *smallest* configured `i_min` for the same reason
    /// `seed_interval` takes the largest `i_max` — a node challenges out every
    /// interface at once (see `poll_due_challenges`), so the cadence that
    /// matters is the one of the fastest link carrying the attempt, and the
    /// budget that matters is the one of the slowest.
    fn challenge_backoff(&self, misses: u32) -> core::time::Duration {
        let cap = self.seed_interval();
        let floor = self
            .ogm_timers
            .iter()
            .map(|t| t.i_min())
            .min()
            .unwrap_or(crate::DEFAULT_OGM_INTERVAL)
            .min(cap);
        // `checked_mul` rather than a shift: the doubling reaches the cap after
        // a handful of misses and must saturate there, not overflow into a
        // short wait.
        1u32.checked_shl(misses)
            .and_then(|factor| floor.checked_mul(factor))
            .unwrap_or(cap)
            .min(cap)
    }

    /// How long until the soonest next-hop challenge falls due, or `None` when
    /// there is nothing to challenge.
    ///
    /// What a driver's periodic arm sleeps on, alongside the OGM and keep-alive
    /// deadlines. Without it the proof exchange rides the OGM timer, and a
    /// newly discovered originator is not challenged until the next Trickle
    /// deadline — up to a full `i_max` after the path was learned, on a mesh
    /// that has settled. `Some(ZERO)` means one is due now.
    pub fn next_challenge_after(&self, now: core::time::Duration) -> Option<core::time::Duration> {
        if !self.require_proof {
            return None;
        }
        let mut seen: heapless::Vec<Mac, MAX_ORIGINATORS> = heapless::Vec::new();
        let mut soonest: Option<core::time::Duration> = None;
        for neighbor in self
            .originator_table
            .values()
            .flat_map(|r| r.paths.iter())
            .map(|p| p.neighbor_ident)
        {
            if seen.contains(&neighbor) {
                continue;
            }
            let _ = seen.push(neighbor);
            // Two independent waits, and the later one governs: a proof that is
            // still fresh is not due however long ago it was last attempted,
            // and an attempt inside its backoff is not due however stale the
            // proof is.
            let refresh = match self.proven.get(&neighbor) {
                None => core::time::Duration::ZERO,
                Some((last, _)) => self
                    .seed_interval()
                    .saturating_sub(now.saturating_sub(*last)),
            };
            let retry = match self.challenged.get(&neighbor) {
                None => core::time::Duration::ZERO,
                Some((last, misses)) => self
                    .challenge_backoff(*misses)
                    .saturating_sub(now.saturating_sub(*last)),
            };
            let due = refresh.max(retry);
            soonest = Some(soonest.map_or(due, |s: core::time::Duration| s.min(due)));
        }
        soonest
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
        }
        self.recompute_all_best(now);

        // An originator reachable on no live path is gone; drop the record.
        self.originator_table.retain(|_, r| !r.paths.is_empty());

        if self.originator_table.len() != before || pruned_path {
            self.topology_changed = true;
        }
    }

    /// Recompute `best_next_hop` and `max_tq` from a record's current paths,
    /// choosing the highest-TQ path that `selectable` admits — on an
    /// authenticated mesh, one whose next-hop proof is current.  Called after
    /// pruning so the cached best hop reflects only live paths.
    ///
    /// **Clears** both fields when no path is selectable — including when none
    /// remain — so a cached next hop never outlives the proof behind it.
    fn recompute_best(record: &mut OriginatorRecord, selectable: &dyn Fn(Mac) -> bool) {
        let mut best: Option<&NeighborStats> = None;
        for p in record.paths.iter() {
            if !selectable(p.neighbor_ident) {
                continue;
            }
            if best.is_none_or(|b| p.last_tq >= b.last_tq) {
                best = Some(p);
            }
        }
        match best {
            Some(b) => {
                record.max_tq = b.last_tq;
                record.best_next_hop = Some(b.neighbor_ident);
            }
            // No selectable path: clear rather than leave the previous next hop
            // standing. Keeping a stale one is how an unproven — possibly
            // spoofed — neighbor would survive its own demotion.
            None => {
                record.max_tq = 0;
                record.best_next_hop = None;
            }
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
        // A proof answered (or a challenge issued) under the previous auth
        // regime's pairwise key material says nothing about the one just
        // installed — the same reasoning that drops routes/link-quality/ident
        // mappings above. Leaving it behind would let a MAC proven under a
        // stale key keep carrying data for up to `MAX_MISSED_PROOFS` proof
        // cycles after re-anchoring.
        self.proven.clear();
        self.challenged.clear();
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
            // A revoked neighbor's next-hop proof is worthless: it was
            // answered before the revocation, and must not keep carrying data
            // on that strength for up to `MAX_MISSED_PROOFS` more cycles.
            self.proven.remove(&revoked_mac);
            self.challenged.remove(&revoked_mac);
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

    /// Route an incoming OGM (`BatmanPacketType::Ogm`): learn/refresh the originator's
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

        // Whether the relaying neighbor may be *selected* as a next hop. Read
        // before the mutable borrow on the originator table below, since the
        // proof check needs `&self`.
        let src_proven = self.proof_current(now, frame.src);

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
                // Deliberately not `Some(frame.src)`: a first-contact sender
                // is exactly what must not be installed before the proof gate
                // has had a chance to run. `recompute_best` below fills this in
                // if — and only if — the path is selectable.
                best_next_hop: None,
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

            // Update routing-table selection with hysteresis, under the proof
            // gate.  Refresh the incumbent next hop's metric when we hear it
            // again (its quality may have risen or fallen) — unless its proof
            // has lapsed, in which case demote it here rather than waiting for
            // the next `purge_stale`.  Promote a *different* sender only if it
            // is proven, and only when there is no incumbent or its TQ is
            // strictly better.  An equal-quality copy arriving via a different
            // neighbor — the common case in a redundant mesh — is kept as an
            // alternate path (above) without displacing the incumbent.
            if record.best_next_hop == Some(frame.src) {
                if src_proven {
                    record.max_tq = computed_tq;
                } else {
                    // The incumbent's proof has lapsed. Demote it here rather
                    // than waiting for the next `purge_stale`, so the cached
                    // next hop the management API reports never outlives the
                    // proof behind it.
                    record.best_next_hop = None;
                    record.max_tq = 0;
                }
            } else if src_proven && (record.best_next_hop.is_none() || computed_tq > record.max_tq)
            {
                record.max_tq = computed_tq;
                record.best_next_hop = Some(frame.src);
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

    /// Route an incoming keep-alive heartbeat (`BatmanPacketType::Keepalive`): link-local
    /// only — never forwarded, never delivered locally, no reply written.
    /// Records that `frame.src` is alive as of `now` so
    /// [`next_hop`](Self::next_hop) can deprioritize routes through it the
    /// instant it goes quiet, without waiting for OGM-interval-based
    /// staleness. Always [`Consumed`](RoutingAction::Consumed).
    ///
    /// Only accepted for a neighbor already known via a real OGM
    /// (`orig_ident` in [`originator_table`](Self::originator_table)) — a
    /// keep-alive proves the link is physically alive, not that the sender
    /// is a validated originator, and this table is what the management
    /// API's keep-alive query surfaces as neighbor liveness. Without this
    /// gate a neighbor whose OGMs never reach this node (an asymmetric or
    /// otherwise broken link) could still show as "alive" purely off
    /// heartbeats, despite never appearing as a routable destination.
    fn handle_keepalive(&mut self, now: core::time::Duration, frame: &LinkFrame) -> RoutingAction {
        let Ok((_hdr, _)) = crate::wire::BatmanKeepAlivePacket::read_from_prefix(&frame.payload)
        else {
            trace!("drop: malformed keepalive");
            return RoutingAction::Consumed;
        };
        if frame.src != self.self_ident {
            if self.originator_table.contains_key(&frame.src) {
                self.note_keepalive(now, frame.src);
            } else {
                trace!(neighbor = ?frame.src, "drop: keepalive from a neighbor with no OGM-established route");
            }
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

    /// Route an incoming flooded broadcast (`BatmanPacketType::Bcast`): drop our own and
    /// duplicates, deliver locally, and re-flood with a decremented TTL until it
    /// expires.  Returns [`DeliverLocalAndForward`] when it both delivers and
    /// re-floods (the re-flood is written into `reply`).
    ///
    /// The dedup step is the security-relevant half: a `Bcast` reaches here
    /// with no authenticator, keyed on fields inside that unauthenticated
    /// payload.  [`BroadcastSeqnoEntry::admit`](crate::BroadcastSeqnoEntry::admit)
    /// is what keeps that from being a denial of service.
    ///
    /// [`DeliverLocalAndForward`]: RoutingAction::DeliverLocalAndForward
    fn handle_broadcast<'rx, 'tx>(
        &mut self,
        now: core::time::Duration,
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
        //
        // Both halves of that key are read from inside the payload and nothing
        // authenticated them, so an outsider chooses which entry to touch and
        // what to write into it.  What makes that survivable is not a check on
        // the frame — a keyless attacker passes every check available — but that
        // `admit` makes any wrong high-water self-correcting, and that a full
        // table evicts rather than refusing.  See `BroadcastSeqnoEntry`.
        if let Some(entry) = self.broadcast_seqno.get_mut(&orig_ident) {
            if !entry.admit(incoming_seqno, now) {
                trace!(?orig_ident, incoming_seqno, "drop: broadcast not admitted");
                return RoutingAction::Consumed;
            }
        } else {
            // A full table must make room rather than refuse the packet: refusing
            // black-holes every originator not already present, for the life of
            // the process, and the entries crowding it out need no credential to
            // create.  Evicting costs at worst a duplicate re-flood, which the
            // TTL bounds — per eviction, though a sustained flood sustains the
            // churn.
            //
            // Least-recently-updated, matching `handle_ogm`'s originator-table
            // eviction and `note_keepalive`'s.  Under a saturation flood no
            // recency policy helps (the attacker's entries are always the
            // freshest); the property that matters there is that the damage is
            // transient, which `admit` provides, not which entry goes.
            if self.broadcast_seqno.len() >= MAX_ORIGINATORS
                && let Some(evicted) = self
                    .broadcast_seqno
                    .iter()
                    .min_by_key(|(_, e)| e.last_updated)
                    .map(|(m, _)| *m)
            {
                trace!(orig = ?evicted, "broadcast dedup table full, evicting least-recently-updated");
                self.broadcast_seqno.remove(&evicted);
            }
            // Infallible: the eviction above guarantees a free slot, and
            // `MAX_ORIGINATORS` is a non-zero power of two (a `heapless` map
            // requirement, asserted at compile time).  Traced rather than
            // ignored so that if a future edit breaks that reasoning it does not
            // become a silent, self-sustaining re-flood loop.
            if self
                .broadcast_seqno
                .insert(orig_ident, BroadcastSeqnoEntry::seeded(incoming_seqno, now))
                .is_err()
            {
                trace!(
                    ?orig_ident,
                    "drop: broadcast dedup insert failed after eviction"
                );
                return RoutingAction::Consumed;
            }
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

    /// Route an incoming unicast (`BatmanPacketType::Unicast`): deliver locally when it is
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

    /// Route an incoming multicast copy (`BatmanPacketType::Mcast`).  Structurally
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
    /// (`BatmanPacketType::CertReq`): deliver locally when addressed to us (so the
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

    /// Route an incoming lazy-cert-distribution reply (`BatmanPacketType::CertReply`):
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

    /// Route one half of the reachability-probe pair
    /// ([`BatmanPacketType::EchoRequest`] / [`BatmanPacketType::EchoReply`]):
    /// deliver locally when addressed to us — a request so the router can
    /// answer it, a reply so the router can credit it against the probe it
    /// answers — otherwise relay toward the next live hop for `dest`, exactly
    /// like [`handle_unicast`](Self::handle_unicast).
    ///
    /// One thing sets it apart from every other relay here: it increments the
    /// header's `hops`, so a probe carries its own path length to the far end
    /// and back. Saturating rather than wrapping, since a rolled-over count
    /// would report a two-hop path as a 258-hop one; `ttl` is what actually
    /// bounds the relay, and it expires long before `hops` could saturate.
    ///
    /// Measurement-free at this layer, in the same spirit as
    /// [`handle_cert_req`](Self::handle_cert_req) being crypto-free: the engine
    /// counts hops and moves bytes, while what a probe *means* — a session, an
    /// interval, a round-trip time — lives in the router.
    fn handle_echo<'rx, 'tx>(
        &mut self,
        now: core::time::Duration,
        frame: &'tx LinkFrame,
        reply: &mut LinkFrameDataMut<'rx>,
    ) -> RoutingAction {
        let Ok((hdr, _)) = BatmanEchoPacket::read_from_prefix(&frame.payload) else {
            trace!("drop: malformed echo packet");
            return RoutingAction::Consumed;
        };
        trace!(echo = ?hdr, "rx echo packet");
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
            updated_hdr.hops = hdr.hops.saturating_add(1);

            let size = core::mem::size_of::<BatmanEchoPacket>();
            let inner = frame.payload.get(size..).unwrap_or(&[]);
            let total = size + inner.len();

            if total <= reply.payload.len() {
                reply.dst = next;
                reply.protocol = ETH_P_BATMAN;
                reply.payload[..size].copy_from_slice(updated_hdr.as_bytes());
                reply.payload[size..total].copy_from_slice(inner);
            } else {
                self.note_relay_oversize_drop("echo_relay", total, reply.payload.len());
            }
        } else {
            // Traced, unlike the equivalent drop in `handle_unicast`, because
            // this is the one frame an operator is running *specifically* to
            // find out where it dies. A probe that vanishes with no record on
            // the relay leaves them with the one answer the tool exists to
            // improve on: "somewhere".
            trace!(?dst, "drop: no live route to relay this probe toward");
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
        // that owns that packet type's routing logic.  A tag this build does not
        // know (`None`) is not an error — a newer peer may speak a type we don't,
        // so it falls back to plain destination-based routing.
        match BatmanPacketType::from_u8(frame.payload[0]) {
            Some(BatmanPacketType::Ogm) => self.handle_ogm(now, frame, local_quality, reply),
            Some(BatmanPacketType::Bcast) => self.handle_broadcast(now, frame, reply),
            Some(BatmanPacketType::Unicast) => self.handle_unicast(now, frame, reply),
            Some(BatmanPacketType::Mcast) => self.handle_mcast(now, frame, reply),
            Some(BatmanPacketType::CertReq) => self.handle_cert_req(now, frame, reply),
            Some(BatmanPacketType::CertReply) => self.handle_cert_reply(now, frame, reply),
            Some(BatmanPacketType::Keepalive) => self.handle_keepalive(now, frame),
            Some(BatmanPacketType::EchoRequest) | Some(BatmanPacketType::EchoReply) => {
                self.handle_echo(now, frame, reply)
            }
            // Next-hop proof frames are consumed here and handled by the router,
            // which owns the pairwise key material they are checked against.
            // Consumed rather than routed by destination: they are link-local by
            // construction (no `dest`, no `ttl`), and a proof the mesh would
            // relay on an attacker's behalf would prove nothing.
            Some(BatmanPacketType::NextHopChallenge) | Some(BatmanPacketType::NextHopResponse) => {
                RoutingAction::Consumed
            }
            None => self.route_by_dest(now, frame),
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
            packet_type: BatmanPacketType::Ogm.as_u8(),
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
            packet_type: BatmanPacketType::Keepalive.as_u8(),
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
            packet_type: crate::wire::BatmanPacketType::Keepalive.as_u8(),
            version: 5,
        };
        let mut data = Vec::new();
        data.extend_from_slice(mac(dst).as_bytes());
        data.extend_from_slice(mac(src).as_bytes());
        data.extend_from_slice(&ETH_P_BATMAN.to_be_bytes());
        data.extend_from_slice(pkt.as_bytes());
        data
    }

    /// A one-hop OGM: `neighbor` is both the originator and the immediate
    /// sender, matching how a directly-heard neighbor's own OGM looks on the
    /// wire. Used to give a neighbor an originator-table entry before a test
    /// exercises keep-alive handling for it.
    fn ogm_frame(neighbor: u8, dst: u8, seqno: u32) -> Vec<u8> {
        let ogm = BatmanOgmPacket {
            packet_type: BatmanPacketType::Ogm.as_u8(),
            version: 5,
            ttl: 5,
            flags: 0,
            seqno: seqno.to_be(),
            orig: mac(neighbor),
            reserved: 0,
            tq: 200,
            tvlv_len: 0,
        };
        let mut data = Vec::new();
        data.extend_from_slice(mac(dst).as_bytes());
        data.extend_from_slice(mac(neighbor).as_bytes());
        data.extend_from_slice(&ETH_P_BATMAN.to_be_bytes());
        data.extend_from_slice(ogm.as_bytes());
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

        // A keep-alive is only accepted for a neighbor already known via a
        // real OGM.
        let ogm = ogm_frame(2, 1, 1);
        let parsed_ogm = LinkFrame::ref_from_prefix(&ogm).unwrap().0;
        let mut ogm_reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        engine.handle_rx(core::time::Duration::ZERO, parsed_ogm, None, &mut ogm_reply);

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

    /// A keep-alive from a neighbor with no OGM-established originator-table
    /// entry must not arm liveness state — a physically-heard heartbeat is
    /// not proof of a route, and the mgmt API's keep-alive table must never
    /// report a neighbor the routing table has never known.
    #[test]
    fn handle_rx_keepalive_dropped_for_unknown_originator() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let mut tx = [0u8; 64];

        let frame = keepalive_frame(2, 1);
        let parsed = LinkFrame::ref_from_prefix(&frame).unwrap().0;
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        engine.handle_rx(core::time::Duration::ZERO, parsed, None, &mut reply);

        assert!(
            engine.keepalive.get(&mac(2)).is_none(),
            "a keep-alive from an unknown originator must not arm liveness state"
        );
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
        data.push(BatmanPacketType::Keepalive.as_u8());
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

        // A keep-alive is only accepted for a neighbor already known via a
        // real OGM.
        let ogm = ogm_frame(2, 1, 1);
        let parsed_ogm = LinkFrame::ref_from_prefix(&ogm).unwrap().0;
        let mut ogm_reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        engine.handle_rx(core::time::Duration::ZERO, parsed_ogm, None, &mut ogm_reply);

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

    /// Build an OGM for `orig` relayed by link-layer source `src`, with an
    /// explicit TQ — the two-path shape a next-hop contest needs.
    fn ogm_via(orig: u8, src: u8, seqno: u32, tq: u8) -> Vec<u8> {
        let ogm = BatmanOgmPacket {
            packet_type: BatmanPacketType::Ogm.as_u8(),
            version: 5,
            ttl: 5,
            flags: 0,
            seqno: seqno.to_be(),
            orig: mac(orig),
            reserved: 0,
            tq,
            tvlv_len: 0,
        };
        let mut data = Vec::new();
        data.extend_from_slice(mac(1).as_bytes());
        data.extend_from_slice(mac(src).as_bytes());
        data.extend_from_slice(&ETH_P_BATMAN.to_be_bytes());
        data.extend_from_slice(ogm.as_bytes());
        data
    }

    fn feed(engine: &mut BatmanEngine<4>, now: u64, frame: &[u8]) {
        let mut tx = [0u8; 128];
        let parsed = LinkFrame::ref_from_prefix(frame).unwrap().0;
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        engine.handle_rx(
            core::time::Duration::from_secs(now),
            parsed,
            None,
            &mut reply,
        );
    }

    /// An engine on an authenticated mesh, where a next hop must prove itself.
    fn proving_engine() -> BatmanEngine<4> {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        engine.set_require_proof(true);
        engine
    }

    /// The gap-1/gap-2 fix, at its narrowest: a neighbor that has not answered
    /// a challenge is never forwarded to, however good its advertised metric.
    ///
    /// Both selection paths are asserted, because they are independent:
    /// `lookup_route` reads the cached `best_next_hop`, while `next_hop`
    /// recomputes from `paths` on the hot path. Gating only the cache would
    /// leave forwarding wide open.
    #[test]
    fn an_unproven_next_hop_is_never_selected() {
        let mut engine = proving_engine();
        feed(&mut engine, 0, &ogm_via(2, 2, 1, 255));

        assert_eq!(engine.next_hop(core::time::Duration::ZERO, mac(2)), None);
        assert_eq!(engine.lookup_route(mac(2)), None);
    }

    /// Discovery still has to work, or there would be nobody to challenge:
    /// the record and its path are recorded, they are simply not selectable.
    #[test]
    fn discovery_records_an_unproven_path_so_it_can_be_challenged() {
        let mut engine = proving_engine();
        feed(&mut engine, 0, &ogm_via(2, 2, 1, 255));

        let record = engine.originator_table.get(&mac(2)).expect("discovered");
        assert_eq!(record.paths.len(), 1, "the path is known");
        assert_eq!(record.best_next_hop, None, "but not selected");
        assert!(
            engine
                .challenge_candidates(core::time::Duration::ZERO)
                .any(|m| m == mac(2)),
            "and it is offered to the driver as a candidate to challenge"
        );
    }

    /// An unanswered challenge must be retried promptly, and only slow down if
    /// it keeps going unanswered.
    ///
    /// The regression this pins: the retry backoff was a flat
    /// [`seed_interval`](BatmanEngine::seed_interval) — the OGM `i_max`, the
    /// *configured worst case* — so a challenge lost for any reason was not
    /// retried for a full `i_max` even while the mesh was still emitting OGMs
    /// every second. That is not a corner case: a node's **first** challenge
    /// routinely races the lazy certificate exchange and is dropped by a peer
    /// that does not hold this node's certificate yet, which is exactly when
    /// the mesh is at `i_min` and a retry would be nearly free. Measured on
    /// the three-node sim, the hub challenged once at t=1.39 s, again at
    /// t=142.17 s, and carried no traffic in between.
    ///
    /// Retrying from `i_min` and doubling keeps the steady-state cost
    /// unchanged — a neighbor that never answers still settles at one frame
    /// per `seed_interval`, the rate the duty-cycle budget in
    /// `docs/design/09-mesh-auth-gaps.md` was written against.
    #[test]
    fn an_unanswered_challenge_is_retried_on_an_exponential_backoff() {
        let mut engine = proving_engine();
        engine.configure_interface_ogm(
            0,
            core::time::Duration::from_secs(1),
            core::time::Duration::from_secs(128),
            core::time::Duration::ZERO,
        );
        feed(&mut engine, 0, &ogm_via(2, 2, 1, 255));

        // A freshly discovered path is challenged at once.
        let mut at = core::time::Duration::ZERO;
        assert_eq!(
            engine.challenge_candidates(at).next(),
            Some(mac(2)),
            "a newly discovered path is challenged immediately"
        );
        engine.note_challenged(at, mac(2));

        // Unanswered: the retry falls due after `i_min`, not `i_max`.
        assert_eq!(
            engine
                .challenge_candidates(core::time::Duration::from_millis(500))
                .next(),
            None,
            "still inside the first backoff"
        );
        at = core::time::Duration::from_millis(1_500);
        assert_eq!(
            engine.challenge_candidates(at).next(),
            Some(mac(2)),
            "retried one i_min after the unanswered attempt, not one i_max"
        );
        engine.note_challenged(at, mac(2));

        // Still unanswered: the next wait is twice as long.
        assert_eq!(
            engine
                .challenge_candidates(at + core::time::Duration::from_millis(1_500))
                .next(),
            None,
            "the second backoff is longer than the first"
        );
        at += core::time::Duration::from_millis(2_500);
        assert_eq!(
            engine.challenge_candidates(at).next(),
            Some(mac(2)),
            "retried again after 2 x i_min"
        );
    }

    /// The doubling stops at `seed_interval()`, so a neighbor that never
    /// answers costs exactly what it cost before this backoff existed: one
    /// challenge per interval, forever. Without a cap the retry would drift
    /// past the point at which the proof itself lapses.
    #[test]
    fn the_challenge_backoff_is_capped_at_the_seed_interval() {
        let mut engine = proving_engine();
        engine.configure_interface_ogm(
            0,
            core::time::Duration::from_secs(1),
            core::time::Duration::from_secs(128),
            core::time::Duration::ZERO,
        );
        feed(&mut engine, 0, &ogm_via(2, 2, 1, 255));

        // Twenty unanswered attempts: 2^20 x i_min would be ~12 days uncapped.
        let mut at = core::time::Duration::ZERO;
        for _ in 0..20 {
            engine.note_challenged(at, mac(2));
            at += core::time::Duration::from_secs(200);
        }
        engine.note_challenged(at, mac(2));

        assert_eq!(
            engine
                .challenge_candidates(at + core::time::Duration::from_secs(127))
                .next(),
            None,
            "still inside the capped backoff"
        );
        assert_eq!(
            engine
                .challenge_candidates(at + core::time::Duration::from_secs(129))
                .next(),
            Some(mac(2)),
            "the backoff caps at seed_interval rather than doubling without bound"
        );
    }

    /// A neighbor that answers starts over: the next time its proof needs
    /// renewing, the first retry is an `i_min` away again, not wherever the
    /// backoff had climbed to. Otherwise one bad patch would permanently
    /// slow every future renewal of an otherwise healthy peer.
    #[test]
    fn proving_resets_the_challenge_backoff() {
        let mut engine = proving_engine();
        engine.configure_interface_ogm(
            0,
            core::time::Duration::from_secs(1),
            core::time::Duration::from_secs(128),
            core::time::Duration::ZERO,
        );
        feed(&mut engine, 0, &ogm_via(2, 2, 1, 255));

        // Four misses, so the backoff has grown to 8 x i_min.
        let mut at = core::time::Duration::ZERO;
        for _ in 0..4 {
            engine.note_challenged(at, mac(2));
            at += core::time::Duration::from_secs(60);
        }
        // Then it answers.
        engine.note_proven(at, mac(2), 0);

        // Once the proof is due for renewal again, the first retry after an
        // unanswered attempt is back to one i_min.
        at += core::time::Duration::from_secs(200);
        engine.note_challenged(at, mac(2));
        assert_eq!(
            engine
                .challenge_candidates(at + core::time::Duration::from_millis(1_500))
                .next(),
            Some(mac(2)),
            "an answered challenge resets the backoff to i_min"
        );
    }

    /// How long until the soonest challenge falls due — what a driver sleeps
    /// on so a proof is not welded to the OGM schedule.
    ///
    /// Before this existed, `poll_due_challenges` ran only on the OGM /
    /// keep-alive timer arm, so a newly discovered originator waited for the
    /// next Trickle deadline (up to `i_max`) before it was challenged at all,
    /// and a retry whose backoff had already expired waited there too.
    #[test]
    fn a_due_challenge_has_its_own_deadline() {
        let mut engine = proving_engine();
        engine.configure_interface_ogm(
            0,
            core::time::Duration::from_secs(1),
            core::time::Duration::from_secs(128),
            core::time::Duration::ZERO,
        );

        assert_eq!(
            engine.next_challenge_after(core::time::Duration::ZERO),
            None,
            "nothing to challenge, so nothing to wake for"
        );

        feed(&mut engine, 0, &ogm_via(2, 2, 1, 255));
        assert_eq!(
            engine.next_challenge_after(core::time::Duration::ZERO),
            Some(core::time::Duration::ZERO),
            "a freshly discovered path is due at once, not at the next OGM"
        );

        engine.note_challenged(core::time::Duration::ZERO, mac(2));
        assert_eq!(
            engine.next_challenge_after(core::time::Duration::ZERO),
            Some(core::time::Duration::from_secs(1)),
            "after an attempt, due one i_min later — the retry backoff, not i_max"
        );

        engine.note_proven(core::time::Duration::ZERO, mac(2), 0);
        assert_eq!(
            engine.next_challenge_after(core::time::Duration::ZERO),
            Some(core::time::Duration::from_secs(128)),
            "a proven neighbor is next due when its proof needs refreshing"
        );
    }

    /// Once proven, the same path is selectable by both routes.
    #[test]
    fn a_proven_next_hop_becomes_selectable() {
        let mut engine = proving_engine();
        feed(&mut engine, 0, &ogm_via(2, 2, 1, 255));
        engine.note_proven(core::time::Duration::ZERO, mac(2), 0);

        assert_eq!(
            engine.next_hop(core::time::Duration::ZERO, mac(2)),
            Some(mac(2))
        );
        assert_eq!(engine.lookup_route(mac(2)), Some(mac(2)));
    }

    /// A proof is not permanent. Past its budget the path stops being
    /// selectable again, so a neighbor that has gone away — or an attacker who
    /// stopped relaying — cannot hold a route open forever.
    #[test]
    fn a_lapsed_proof_demotes_the_path() {
        let mut engine = proving_engine();
        feed(&mut engine, 0, &ogm_via(2, 2, 1, 255));
        engine.note_proven(core::time::Duration::ZERO, mac(2), 0);
        assert!(
            engine
                .next_hop(core::time::Duration::ZERO, mac(2))
                .is_some()
        );

        // Past MAX_MISSED_PROOFS x the seeded interval.
        let late = core::time::Duration::from_secs(u64::from(crate::MAX_MISSED_PROOFS) + 2);
        feed(&mut engine, late.as_secs(), &ogm_via(2, 2, 2, 255));
        assert_eq!(
            engine.next_hop(late, mac(2)),
            None,
            "a lapsed proof must stop carrying the route"
        );
    }

    /// Timeout falls back rather than dropping: a worse but proven path beats
    /// a better unproven one, which is what keeps a mesh routing while a
    /// candidate is still being challenged.
    #[test]
    fn an_unproven_better_path_loses_to_a_proven_worse_one() {
        let mut engine = proving_engine();
        // orig 4 heard via neighbor 2 (weak) and neighbor 3 (strong).
        feed(&mut engine, 0, &ogm_via(4, 2, 1, 100));
        feed(&mut engine, 0, &ogm_via(4, 3, 1, 255));
        engine.note_proven(core::time::Duration::ZERO, mac(2), 0);

        assert_eq!(
            engine.next_hop(core::time::Duration::ZERO, mac(4)),
            Some(mac(2)),
            "the proven path carries traffic even though its TQ is lower"
        );
        assert_eq!(engine.lookup_route(mac(4)), Some(mac(2)));
    }

    /// An unauthenticated mesh has no pairwise keys, so nothing could ever be
    /// proven. Requiring proof there would break every route — the gate is off
    /// unless the router turns it on.
    #[test]
    fn proof_is_not_required_when_the_mesh_is_unauthenticated() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        feed(&mut engine, 0, &ogm_via(2, 2, 1, 255));

        assert_eq!(
            engine.next_hop(core::time::Duration::ZERO, mac(2)),
            Some(mac(2))
        );
        assert_eq!(engine.lookup_route(mac(2)), Some(mac(2)));
    }

    /// A next-hop proof frame is the router's business, not the engine's: the
    /// nonce and tag are checked against pairwise key material the engine has
    /// no dependency on. The engine's only job is to make sure one never
    /// *moves* — neither forwarded toward a destination nor re-flooded — since
    /// a proof that the mesh could relay for an attacker would defeat itself.
    #[test]
    fn next_hop_proof_frames_are_consumed_never_routed() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let mut tx = [0u8; 64];

        for packet_type in [
            crate::wire::BatmanPacketType::NextHopChallenge,
            crate::wire::BatmanPacketType::NextHopResponse,
        ] {
            let mut data = Vec::new();
            data.extend_from_slice(mac(1).as_bytes());
            data.extend_from_slice(mac(2).as_bytes());
            data.extend_from_slice(&ETH_P_BATMAN.to_be_bytes());
            data.push(packet_type.as_u8());
            data.push(5);
            data.extend_from_slice(&[0xAB; 16]); // nonce or tag body
            let frame = LinkFrame::ref_from_prefix(&data).unwrap().0;

            let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
            let action = engine.handle_rx(core::time::Duration::ZERO, frame, None, &mut reply);
            assert!(
                matches!(action, RoutingAction::Consumed),
                "{packet_type:?} must not be routed by the engine"
            );
            assert_eq!(reply.protocol, 0, "{packet_type:?} must not be forwarded");
        }
    }

    /// A revoked neighbor's next-hop proof state must not survive the
    /// revocation, or it could keep carrying data on the strength of a proof
    /// answered before it was revoked, for up to `MAX_MISSED_PROOFS` proof
    /// cycles.
    #[test]
    fn revoking_an_originator_also_drops_its_proof_state() {
        let mut engine = proving_engine();
        engine.note_proven(core::time::Duration::ZERO, mac(2), 0);
        engine.note_challenged(core::time::Duration::ZERO, mac(2));
        assert!(engine.proven.contains_key(&mac(2)));
        assert!(engine.challenged.contains_key(&mac(2)));

        engine.revoke_originators(core::iter::once(mac(2)));

        assert!(
            !engine.proven.contains_key(&mac(2)),
            "a revoked neighbor's proof must not survive its revocation"
        );
        assert!(
            !engine.challenged.contains_key(&mac(2)),
            "a revoked neighbor's challenge state must not survive its revocation"
        );
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
        // heard at a distinct, increasing time. Each neighbor needs an OGM
        // first — a keep-alive is only accepted for a known originator.
        for (i, src) in (10..14).enumerate() {
            let t = core::time::Duration::from_secs(i as u64);
            let ogm = ogm_frame(src, 1, 1);
            let parsed_ogm = LinkFrame::ref_from_prefix(&ogm).unwrap().0;
            let mut ogm_reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
            engine.handle_rx(t, parsed_ogm, None, &mut ogm_reply);

            let frame = keepalive_frame(src, 1);
            let parsed = LinkFrame::ref_from_prefix(&frame).unwrap().0;
            let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
            engine.handle_rx(t, parsed, None, &mut reply);
        }
        assert_eq!(engine.keepalive.len(), 4);
        assert!(engine.keepalive.contains_key(&mac(10)));

        // A new neighbor's heartbeat must be admitted, evicting the
        // least-recently-heard entry (neighbor 10, heard at t=0).
        let t = core::time::Duration::from_secs(100);
        let ogm = ogm_frame(20, 1, 1);
        let parsed_ogm = LinkFrame::ref_from_prefix(&ogm).unwrap().0;
        let mut ogm_reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        engine.handle_rx(t, parsed_ogm, None, &mut ogm_reply);

        let frame = keepalive_frame(20, 1);
        let parsed = LinkFrame::ref_from_prefix(&frame).unwrap().0;
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        engine.handle_rx(t, parsed, None, &mut reply);

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
        assert_eq!(
            produced[0],
            crate::wire::BatmanPacketType::Keepalive.as_u8()
        );
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

    /// A flooded broadcast frame: `orig` is the node that generated it,
    /// `src` the immediate relay putting it on the wire, addressed to the
    /// link-layer broadcast address the way a real flood is.
    fn bcast_frame(orig: u8, src: u8, seqno: u32, ttl: u8) -> Vec<u8> {
        let pkt = BatmanBroadcastPacket {
            packet_type: BatmanPacketType::Bcast.as_u8(),
            version: 5,
            ttl,
            seqno: seqno.to_be(),
            orig: mac(orig),
        };
        let mut data = Vec::new();
        data.extend_from_slice(Mac::BROADCAST.as_bytes());
        data.extend_from_slice(mac(src).as_bytes());
        data.extend_from_slice(&ETH_P_BATMAN.to_be_bytes());
        data.extend_from_slice(pkt.as_bytes());
        // A token inner frame so the re-flood path has something to copy.
        data.extend_from_slice(&[0xaa; 8]);
        data
    }

    /// Every invariant the dedup table has that is not expressed in its types.
    /// Called after each `rx_bcast` below, per the repo's convention for
    /// stateful structures.
    fn assert_invariants<const N: usize>(engine: &BatmanEngine<N>) {
        assert!(
            engine.broadcast_seqno.len() <= N,
            "dedup table over capacity"
        );
        for (orig, entry) in engine.broadcast_seqno.iter() {
            assert_ne!(*orig, engine.self_ident, "own ident must never be tracked");
            if let Some(watch) = entry.resync_watch {
                assert!(
                    watch.since >= entry.last_updated,
                    "a watch is opened by a refusal, which always postdates the \
                     last acceptance"
                );
            }
        }
    }

    /// Feed one broadcast into `engine` at `now` with the given TTL and report
    /// what it decided.
    fn rx_bcast_ttl<const N: usize>(
        engine: &mut BatmanEngine<N>,
        now: core::time::Duration,
        orig: u8,
        src: u8,
        seqno: u32,
        ttl: u8,
    ) -> RoutingAction {
        let frame = bcast_frame(orig, src, seqno, ttl);
        let parsed = LinkFrame::ref_from_prefix(&frame).unwrap().0;
        let mut tx = [0u8; 128];
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        let action = engine.handle_rx(now, parsed, None, &mut reply);
        assert_invariants(engine);
        action
    }

    /// A broadcast with enough TTL to be re-flooded — the usual case.
    fn rx_bcast<const N: usize>(
        engine: &mut BatmanEngine<N>,
        now: core::time::Duration,
        orig: u8,
        src: u8,
        seqno: u32,
    ) -> RoutingAction {
        rx_bcast_ttl(engine, now, orig, src, seqno, 5)
    }

    /// Whether the broadcast was accepted for delivery *and* re-flooding.
    fn flooded(action: RoutingAction) -> bool {
        matches!(action, RoutingAction::DeliverLocalAndForward(_))
    }

    /// The high-water for `orig`, or `None` when it holds no dedup entry.
    fn bcast_high_water<const N: usize>(engine: &BatmanEngine<N>, orig: u8) -> Option<u32> {
        engine.broadcast_seqno.get(&mac(orig)).map(|e| e.last_seqno)
    }

    const PROTECTION: core::time::Duration = crate::BROADCAST_SEQNO_RESET_PROTECTION;
    const WINDOW: u32 = crate::BROADCAST_SEQNO_WINDOW;
    const TOLERANCE: u32 = crate::BROADCAST_SEQNO_REORDER_TOLERANCE;

    /// Baseline dedup, which nothing below may weaken: a genuinely newer seqno
    /// floods on, and a repeat or a slightly older copy of one already seen —
    /// the same flood arriving by a second path — is consumed.
    #[test]
    fn broadcast_dedup_consumes_repeat_and_older_seqnos() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let t = core::time::Duration::ZERO;

        assert!(flooded(rx_bcast(&mut engine, t, 2, 3, 5)));
        assert!(!flooded(rx_bcast(&mut engine, t, 2, 4, 5)));
        assert!(!flooded(rx_bcast(&mut engine, t, 2, 4, 4)));
        assert!(flooded(rx_bcast(&mut engine, t, 2, 3, 6)));
        assert_eq!(bcast_high_water(&engine, 2), Some(6));
    }

    /// The three bands `classify` sorts the 32-bit space into, checked at their
    /// exact edges — the boundaries are one `<=` apart and a `RoutingAction`
    /// alone cannot tell a `Duplicate` from an `Implausible`, so this asserts
    /// on the verdict directly.
    #[test]
    fn broadcast_seqno_bands_are_exact_at_their_edges() {
        let entry = BroadcastSeqnoEntry::seeded(10_000, core::time::Duration::ZERO);
        use crate::SeqnoVerdict::*;

        assert_eq!(entry.classify(10_001), Advance);
        assert_eq!(entry.classify(10_000 + WINDOW), Advance);
        assert_eq!(entry.classify(10_000 + WINDOW + 1), Implausible);

        assert_eq!(entry.classify(10_000), Duplicate);
        assert_eq!(entry.classify(10_000 - TOLERANCE), Duplicate);
        assert_eq!(entry.classify(10_000 - TOLERANCE - 1), Implausible);
    }

    /// The wrapping comparison is direction-aware across the `u32` boundary: a
    /// counter stepping off the end of the space reads as one ahead, and the
    /// antipodal point — where a naive signed cast would misread the direction
    /// — is refused rather than accepted.
    #[test]
    fn broadcast_seqno_bands_wrap_at_the_u32_boundary() {
        use crate::SeqnoVerdict::*;
        let at_max = BroadcastSeqnoEntry::seeded(u32::MAX, core::time::Duration::ZERO);
        assert_eq!(at_max.classify(0), Advance);
        assert_eq!(at_max.classify(u32::MAX), Duplicate);

        let low = BroadcastSeqnoEntry::seeded(5, core::time::Duration::ZERO);
        assert_eq!(low.classify(u32::MAX), Duplicate, "six behind, wrapped");
        assert_eq!(low.classify(5u32.wrapping_add(1 << 31)), Implausible);
    }

    /// Failure mode A of issue #29: the dedup table is filled with fabricated
    /// originators, which used to make every *subsequent* originator's
    /// broadcasts undeliverable for the life of the process ("table full, drop
    /// packet").  A full table must evict its least-recently-updated entry
    /// instead, the way the originator and keep-alive tables already do.
    #[test]
    fn broadcast_dedup_table_evicts_least_recently_updated_when_full() {
        let mut engine = BatmanEngine::<4>::new(mac(1));

        // Saturate the table (capacity 4) with ghost origs, each updated at a
        // distinct, increasing time.
        for (i, orig) in (10..14).enumerate() {
            rx_bcast(
                &mut engine,
                core::time::Duration::from_secs(i as u64),
                orig,
                9,
                1,
            );
        }
        assert_eq!(engine.broadcast_seqno.len(), 4);
        assert_eq!(bcast_high_water(&engine, 10), Some(1));

        // A genuine originator not yet in the table must still be flooded.
        let t = core::time::Duration::from_secs(100);
        assert!(
            flooded(rx_bcast(&mut engine, t, 20, 21, 1)),
            "a saturated dedup table must not black-hole a new originator"
        );
        assert_eq!(engine.broadcast_seqno.len(), 4, "table stays at capacity");
        assert_eq!(
            bcast_high_water(&engine, 10),
            None,
            "the least-recently-updated entry must be the one evicted"
        );
        assert_eq!(bcast_high_water(&engine, 20), Some(1));
    }

    /// A stream of non-advancing frames must not keep a poisoned entry pinned
    /// in the eviction order.  `last_updated` therefore tracks the last
    /// *advance*, not the last frame seen — unlike the originator and
    /// keep-alive tables, where every frame heard refreshes the key.
    #[test]
    fn broadcast_dedup_eviction_key_tracks_advances_not_arrivals() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let secs = core::time::Duration::from_secs;

        rx_bcast(&mut engine, secs(0), 2, 2, 5);
        // Duplicates of the same flood, arriving much later by other paths.
        rx_bcast(&mut engine, secs(50), 2, 3, 5);
        rx_bcast(&mut engine, secs(60), 2, 4, 5);

        let entry = engine.broadcast_seqno.get(&mac(2)).expect("entry");
        assert_eq!(
            entry.last_updated,
            secs(0),
            "a duplicate must not refresh the eviction key"
        );
    }

    /// Failure mode B of issue #29: one unauthenticated frame carrying a
    /// victim's `orig` and `seqno = u32::MAX` used to pin that victim's
    /// high-water at the maximum, silencing it forever.  Measured by wrapping
    /// distance, `u32::MAX` sits six *behind* a high-water of five, so it is
    /// discarded as a stale duplicate and the victim is untouched.
    #[test]
    fn broadcast_dedup_treats_a_forged_max_seqno_as_stale() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let secs = core::time::Duration::from_secs;

        rx_bcast(&mut engine, secs(0), 2, 2, 5);
        assert!(!flooded(rx_bcast(&mut engine, secs(1), 2, 9, u32::MAX)));
        assert_eq!(
            bcast_high_water(&engine, 2),
            Some(5),
            "a forged seqno behind the high-water must not become it"
        );
        assert!(
            flooded(rx_bcast(&mut engine, secs(2), 2, 2, 6)),
            "one forged frame must not durably silence a member"
        );
    }

    /// The same forgery landing *before* the victim has ever broadcast, so it
    /// seeds the entry rather than updating one.  The victim's low seqnos are
    /// then a short wrapping distance *ahead* of `u32::MAX`, so they are
    /// admitted — the wrap the old strict `<=` comparison could not see.
    #[test]
    fn broadcast_dedup_survives_a_forged_max_seqno_seeding_the_entry() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let secs = core::time::Duration::from_secs;

        rx_bcast(&mut engine, secs(0), 2, 9, u32::MAX);
        assert!(
            flooded(rx_bcast(&mut engine, secs(1), 2, 2, 1)),
            "a wrapped-around seqno must be read as newer, not stale"
        );
        assert_eq!(bcast_high_water(&engine, 2), Some(1));
    }

    /// The attack the first cut of this fix missed, and the reason the
    /// *behind* band has to be narrow: a forgery does not need an implausible
    /// leap, only one inside the window, which is accepted as a genuine
    /// advance.  Every genuine broadcast the victim then emits sits behind the
    /// poisoned high-water.  If that band were merely dropped as "duplicate",
    /// the victim would stay silent until its own counter climbed past the
    /// forged value — thousands of frames, hours at ARP rates, from one frame.
    /// It must instead be read as evidence the high-water is wrong, and heal.
    #[test]
    fn broadcast_dedup_heals_a_forged_in_window_jump() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let secs = core::time::Duration::from_secs;

        rx_bcast(&mut engine, secs(0), 2, 2, 5);
        // Inside the window, so accepted — the attacker's best move.
        assert!(flooded(rx_bcast(&mut engine, secs(1), 2, 9, 5 + WINDOW)));
        assert_eq!(bcast_high_water(&engine, 2), Some(5 + WINDOW));

        // The victim keeps broadcasting; these are refused for now, but they
        // must open a watch rather than vanish.
        assert!(!flooded(rx_bcast(&mut engine, secs(2), 2, 2, 6)));
        assert!(!flooded(rx_bcast(&mut engine, secs(3), 2, 2, 7)));

        // Once the run has persisted, the high-water snaps back to where the
        // victim actually is and its broadcasts flow again.
        let healed = secs(2) + PROTECTION;
        assert!(
            flooded(rx_bcast(&mut engine, healed, 2, 2, 8)),
            "a forged in-window jump must heal within the protection window"
        );
        assert!(flooded(rx_bcast(&mut engine, healed, 2, 2, 9)));
    }

    /// Eviction must not become a way around the window: an attacker can force
    /// a victim's entry out of a full table cheaply, and the re-seeded entry
    /// takes its first seqno on trust.  That is deliberate — a check there
    /// would buy nothing — and it is safe only because the victim's own next
    /// frames correct it.
    #[test]
    fn broadcast_dedup_heals_after_eviction_reseeds_a_victim() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let secs = core::time::Duration::from_secs;

        rx_bcast(&mut engine, secs(0), 2, 2, 5);
        for (i, ghost) in (10..14).enumerate() {
            rx_bcast(&mut engine, secs(1 + i as u64), ghost, 9, 1);
        }
        assert_eq!(bcast_high_water(&engine, 2), None, "victim evicted");

        // Re-seeded under the victim's name with an unreachable value.
        rx_bcast(&mut engine, secs(10), 2, 9, 1 << 31);
        assert!(!flooded(rx_bcast(&mut engine, secs(11), 2, 2, 6)));

        let healed = secs(11) + PROTECTION;
        assert!(
            flooded(rx_bcast(&mut engine, healed, 2, 2, 7)),
            "an evicted-and-reseeded entry must heal like any other"
        );
        assert_eq!(bcast_high_water(&engine, 2), Some(7));
    }

    /// A genuine reboot, which is why refusing an implausible seqno cannot be
    /// unconditional: the broadcast counter restarts at zero and is never
    /// persisted, so a restarted originator's frames sit far below the
    /// high-water its neighbours hold.
    #[test]
    fn broadcast_dedup_resyncs_a_rebooted_originator() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let secs = core::time::Duration::from_secs;

        rx_bcast(&mut engine, secs(0), 2, 2, 5_000);

        assert!(!flooded(rx_bcast(&mut engine, secs(10), 2, 2, 1)));
        assert_eq!(bcast_high_water(&engine, 2), Some(5_000));

        // One tick short of the deadline: still refused.
        let almost = secs(10) + PROTECTION - core::time::Duration::from_millis(1);
        assert!(!flooded(rx_bcast(&mut engine, almost, 2, 2, 2)));
        assert_eq!(bcast_high_water(&engine, 2), Some(5_000));

        // At the deadline: the entry snaps back to where the run started.
        let later = secs(10) + PROTECTION;
        assert!(
            flooded(rx_bcast(&mut engine, later, 2, 2, 3)),
            "a persistent restart must resynchronise the high-water"
        );
        assert_eq!(bcast_high_water(&engine, 2), Some(3));
    }

    /// The resync restores the seqno that *opened* the run, not whichever
    /// frame trips the deadline — otherwise an attacker waits out a run an
    /// honest, rebooting originator earned and substitutes its own number,
    /// reconstructing failure mode B from two frames thirty seconds apart.
    #[test]
    fn broadcast_dedup_resync_does_not_admit_a_third_party_seqno() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let secs = core::time::Duration::from_secs;

        rx_bcast(&mut engine, secs(0), 2, 2, 5_000);
        // The victim reboots and opens the run with its own seqno.
        rx_bcast(&mut engine, secs(10), 2, 2, 1);

        // The attacker cashes it in at the deadline.
        let deadline = secs(10) + PROTECTION;
        assert!(!flooded(rx_bcast(&mut engine, deadline, 2, 9, 1 << 30)));
        assert_eq!(
            bcast_high_water(&engine, 2),
            Some(1),
            "the run must restore the seqno that opened it"
        );
        assert!(
            flooded(rx_bcast(&mut engine, deadline, 2, 2, 2)),
            "the victim keeps the run it earned"
        );
    }

    /// A run has to *persist*: later implausible frames must not push the
    /// deadline back, or an attacker could hold the correction off forever
    /// simply by continuing to send.
    #[test]
    fn broadcast_dedup_watch_is_not_refreshed_by_a_continuing_run() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let secs = core::time::Duration::from_secs;

        rx_bcast(&mut engine, secs(0), 2, 2, 5_000);
        rx_bcast(&mut engine, secs(10), 2, 2, 1);
        for i in 1..30 {
            rx_bcast(&mut engine, secs(10 + i), 2, 2, 1 + i as u32);
        }
        let later = secs(10) + PROTECTION;
        assert!(
            flooded(rx_bcast(&mut engine, later, 2, 2, 40)),
            "a continuing run must still complete on its original deadline"
        );
    }

    /// An advance clears the watch, so a run only completes if it is genuinely
    /// uninterrupted — an attacker cannot arm one and return later to a live,
    /// advancing originator to collect it.
    #[test]
    fn broadcast_dedup_an_advance_clears_the_watch() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let secs = core::time::Duration::from_secs;

        rx_bcast(&mut engine, secs(0), 2, 2, 5);
        rx_bcast(&mut engine, secs(1), 2, 9, 5 + WINDOW + 1); // implausible: opens a watch
        rx_bcast(&mut engine, secs(2), 2, 2, 6); // genuine advance: clears it
        assert!(
            engine
                .broadcast_seqno
                .get(&mac(2))
                .expect("entry")
                .resync_watch
                .is_none()
        );

        let later = secs(2) + PROTECTION;
        assert!(
            !flooded(rx_bcast(&mut engine, later, 2, 9, 6 + WINDOW + 1)),
            "a fresh run must start its own clock"
        );
        assert_eq!(bcast_high_water(&engine, 2), Some(6));
    }

    /// A clock that goes backwards must never complete a run early.
    #[test]
    fn broadcast_dedup_a_backwards_clock_never_resyncs_early() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let secs = core::time::Duration::from_secs;

        rx_bcast(&mut engine, secs(100), 2, 2, 5_000);
        rx_bcast(&mut engine, secs(100), 2, 2, 1);
        assert!(!flooded(rx_bcast(&mut engine, secs(1), 2, 2, 2)));
        assert_eq!(bcast_high_water(&engine, 2), Some(5_000));
    }

    /// A TTL-exhausted broadcast is delivered locally without being re-flooded
    /// — and is still deduplicated, because Rule 2 runs before Rule 3.  A
    /// second copy of it must not be delivered twice.
    #[test]
    fn broadcast_ttl_exhausted_delivers_locally_and_still_dedups() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let t = core::time::Duration::ZERO;

        assert!(matches!(
            rx_bcast_ttl(&mut engine, t, 2, 3, 7, 1),
            RoutingAction::DeliverLocal
        ));
        assert_eq!(bcast_high_water(&engine, 2), Some(7));
        assert!(matches!(
            rx_bcast_ttl(&mut engine, t, 2, 4, 7, 1),
            RoutingAction::Consumed
        ));
    }

    /// This node's own broadcast looping back is dropped before the dedup
    /// table is touched, so an echo cannot occupy a slot in it.
    #[test]
    fn broadcast_from_self_is_dropped_without_a_dedup_entry() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let t = core::time::Duration::ZERO;

        assert!(matches!(
            rx_bcast(&mut engine, t, 1, 3, 9),
            RoutingAction::Consumed
        ));
        assert!(engine.broadcast_seqno.is_empty());
    }

    /// Re-anchoring auth drops the dedup table with the rest of the routing
    /// state, so a peer's broadcasts are re-learned from whatever it sends
    /// next rather than judged against a high-water from the old regime.
    #[test]
    fn reset_clears_the_broadcast_dedup_table() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let t = core::time::Duration::ZERO;

        rx_bcast(&mut engine, t, 2, 2, 5_000);
        engine.reset();
        assert!(engine.broadcast_seqno.is_empty());
        assert!(
            flooded(rx_bcast(&mut engine, t, 2, 2, 1)),
            "a lower seqno is admitted once the old high-water is gone"
        );
    }
}
