use interfaces::engine::FrameSink;
use interfaces::engine::MeshRoutingEngine;
use interfaces::engine::RoutingAction;
use interfaces::frame::LinkFrame;
use interfaces::frame::LinkFrameData;
use interfaces::frame::LinkFrameDataMut;
use interfaces::frame::Mac;
use interfaces::time::Millis;
use tracing::debug;
use tracing::info;
use tracing::trace;
use tracing::warn;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

/// The oldest a stored [`Millis`] stamp is allowed to get, in milliseconds.
///
/// **This is a type precondition, not a routing decision.**
/// [`Millis::elapsed_since`] answers on the *signed* wrapping difference, so it
/// is correct only while the two stamps lie within 24.8 days of each other —
/// half the `u32` millisecond range. Past that the sign flips and an ancient
/// stamp reads as **zero elapsed**, which every caller here takes to mean "just
/// now". A proof that should have expired reads as current and stops being
/// re-challenged; a neighbour dead for a month reports a live heartbeat.
///
/// The originator table cannot reach it — `purge_stale` prunes paths on their
/// own learned cadence, in minutes. `proven`, `challenged` and `keepalive` can:
/// each is otherwise removed only when its table is full, on a revocation, or
/// on a re-anchor, so an entry for a neighbour that walked away sits untouched
/// for as long as the node runs.
///
/// A day is chosen to be far past every real ageing rule in this engine (the
/// longest is `MAX_MISSED_OGMS` × a 128 s Trickle `i_max`, under fourteen
/// minutes) and far short of the 24.8-day limit it defends. So dropping at this
/// point is never the decision that ages something out — by a day every one of
/// these entries is long since stale by its own rule — it only stops a stamp
/// living long enough to lie.
///
/// **This works because `purge_stale` runs far more often than the half-range,
/// not because it can detect a stamp that already wrapped.** Age is measured
/// with the same `elapsed_since` the ceiling defends, so a stamp already past
/// 24.8 days reads as zero and is unreachable. Every shell calls `purge_stale`
/// on its periodic tick — seconds to minutes — so an entry is caught at a day
/// and never approaches the limit. `the_ceiling_needs_purge_to_run_before_the_
/// half_range` pins that boundary rather than leaving it to be discovered.
const STAMP_AGE_CEILING_MS: u32 = 24 * 60 * 60 * 1000;

/// A configured interval as whole milliseconds, saturating.
///
/// The inputs are Trickle bounds and the crate's default intervals — values of
/// seconds, set by configuration rather than measured — so saturating at 49.7
/// days is unreachable in practice and is the safe direction if it ever were:
/// an over-long seed makes a path age out later, never sooner.
///
/// Distinct from [`Millis::from_duration`], which *wraps* because it converts a
/// monotonic `now` that legitimately runs past the rollover.
fn as_millis_u32(d: core::time::Duration) -> u32 {
    d.as_millis().min(u128::from(u32::MAX)) as u32
}

use crate::BatmanEngine;
use crate::BroadcastSeqnoEntry;
use crate::KeepAliveStats;
use crate::MAX_MCAST_DESTS;
use crate::NeighborStats;
use crate::OriginatorRecord;
use crate::TrickleTimer;
use crate::wire::BATMAN_VERSION;
use crate::wire::BatmanBroadcastPacket;
use crate::wire::BatmanCertReplyPacket;
use crate::wire::BatmanCertReqPacket;
use crate::wire::BatmanEchoPacket;
use crate::wire::BatmanOgmPacket;
use crate::wire::BatmanPacketType;
use crate::wire::BatmanRenewReplyPacket;
use crate::wire::BatmanRenewReqPacket;
use crate::wire::BatmanTvlvHdr;
use crate::wire::BatmanUnicastPacket;
use crate::wire::ETH_P_BATMAN;
use crate::wire::MCAST_HEADER_LEN;
use crate::wire::McastAuthForm;
use crate::wire::McastPacketView;
use crate::wire::TvlvType;
use crate::wire::find_tvlv;
use crate::wire::write_mcast;

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
        let seed_ms = self.seed_interval_ms();
        let record = self.originator_table.get(&destination)?;
        record
            .paths
            .iter()
            .filter(|p| !Self::path_stale(Millis::from_duration(now), p, seed_ms))
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
        let seed_ms = self.seed_interval_ms();
        let record = self.originator_table.get(&destination)?;
        record
            .paths
            .iter()
            .filter(|p| !Self::path_stale(Millis::from_duration(now), p, seed_ms))
            .max_by_key(|p| self.effective_tq(now, p))
            .map(|p| p.neighbor_ident)
    }

    /// Record that `neighbor` has just proven itself a legitimate next hop.
    ///
    /// Called by the router when a challenge response verifies; the engine
    /// holds the timestamp but never the key material.
    pub fn note_proven(&mut self, now: core::time::Duration, neighbor: Mac, iface: usize) {
        let now_ms = Millis::from_duration(now);
        if self.proven.insert(neighbor, (now_ms, iface)).is_err() {
            // Table full: evict the least-recently-proven to make room, rather
            // than refusing a fresh proof and stranding the route it unlocks.
            //
            // "Least recently" is the *largest* elapsed rather than the
            // smallest stamp: stamps wrap every 49.7 days, and a raw `min`
            // would then evict the freshest entry. See `interfaces::time`.
            if let Some(oldest) = self
                .proven
                .iter()
                .max_by_key(|(_, (t, _))| now_ms.elapsed_since(*t))
                .map(|(m, _)| *m)
            {
                self.proven.remove(&oldest);
                let _ = self.proven.insert(neighbor, (now_ms, iface));
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
        let seed_ms = self.seed_interval_ms();
        // Snapshot which neighbors are selectable before taking the mutable
        // borrow on the table, since the proof check reads `&self`.
        let require_proof = self.require_proof;
        let selectable: heapless::Vec<Mac, MAX_ORIGINATORS> = self
            .proven
            .iter()
            .filter(|(_, (last, _))| {
                !Self::is_stale(
                    Millis::from_duration(now),
                    *last,
                    0,
                    seed_ms,
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
        let seed_ms = self.seed_interval_ms();
        self.proven.get(&neighbor).is_some_and(|(last, _)| {
            !Self::is_stale(
                Millis::from_duration(now),
                *last,
                0,
                seed_ms,
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
        let seed_ms = self.seed_interval_ms();
        self.proven.get(&neighbor).and_then(|(last, iface)| {
            (!Self::is_stale(
                Millis::from_duration(now),
                *last,
                0,
                seed_ms,
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
        let seed_ms = self.seed_interval_ms();
        match self.proven.get(&neighbor) {
            None => true,
            Some((last, _)) => Self::is_stale(Millis::from_duration(now), *last, 0, seed_ms, 1),
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
                    && Millis::from_duration(now).elapsed_since(*last)
                        < self.challenge_backoff_ms(*misses)
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
        let now_ms = Millis::from_duration(now);
        let misses = self
            .challenged
            .get(&neighbor)
            .map_or(0, |(_, n)| n.saturating_add(1));
        // Evicted by largest elapsed, not smallest stamp -- see `note_proven`.
        if self.challenged.insert(neighbor, (now_ms, misses)).is_err()
            && let Some(oldest) = self
                .challenged
                .iter()
                .max_by_key(|(_, (t, _))| now_ms.elapsed_since(*t))
                .map(|(m, _)| *m)
        {
            self.challenged.remove(&oldest);
            let _ = self.challenged.insert(neighbor, (now_ms, misses));
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
    fn challenge_backoff_ms(&self, misses: u32) -> u32 {
        let cap_ms = self.seed_interval_ms();
        let floor_ms = as_millis_u32(
            self.ogm_timers
                .iter()
                .map(|t| t.i_min())
                .min()
                .unwrap_or(crate::DEFAULT_OGM_INTERVAL),
        )
        .min(cap_ms);
        // `checked_mul` rather than a shift: the doubling reaches the cap after
        // a handful of misses and must saturate there, not overflow into a
        // short wait.
        1u32.checked_shl(misses)
            .and_then(|factor| floor_ms.checked_mul(factor))
            .unwrap_or(cap_ms)
            .min(cap_ms)
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
        let now_ms = Millis::from_duration(now);
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
            let refresh_ms = match self.proven.get(&neighbor) {
                None => 0,
                Some((last, _)) => self
                    .seed_interval_ms()
                    .saturating_sub(now_ms.elapsed_since(*last)),
            };
            let retry_ms = match self.challenged.get(&neighbor) {
                None => 0,
                Some((last, misses)) => self
                    .challenge_backoff_ms(*misses)
                    .saturating_sub(now_ms.elapsed_since(*last)),
            };
            let due = core::time::Duration::from_millis(u64::from(refresh_ms.max(retry_ms)));
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

    /// Whether a `(last_heard, interval_estimate_ms)` pair has aged out as of
    /// `now`: true once `now` has advanced more than `max_missed` of the
    /// *expected* interval past the last refresh. The expected interval is the
    /// learned cadence (`interval_estimate_ms`), or `seed` until a second sample
    /// has been measured. Saturating arithmetic keeps the budget finite.
    /// Shared by [`path_stale`](Self::path_stale) (OGM paths) and
    /// [`keepalive_missed`](Self::keepalive_missed) (keep-alive heartbeats) —
    /// the same ageing shape, applied to two independent signals.
    fn is_stale(
        now: Millis,
        last_heard: Millis,
        interval_estimate_ms: u32,
        seed_ms: u32,
        max_missed: u32,
    ) -> bool {
        let expected_ms = if interval_estimate_ms == 0 {
            seed_ms
        } else {
            interval_estimate_ms
        };
        let budget_ms = expected_ms.saturating_mul(max_missed);
        now.elapsed_since(last_heard) > budget_ms
    }

    /// Whether `path` has aged out as of `now`: true once `now` has advanced
    /// more than [`MAX_MISSED_OGMS`] of the path's *expected* OGM interval past
    /// its last refresh.  The expected interval is the path's learned cadence
    /// ([`NeighborStats::interval_estimate_ms`]), or `seed` until the second OGM
    /// has been measured.  Saturating arithmetic keeps the budget finite.
    ///
    /// [`MAX_MISSED_OGMS`]: crate::MAX_MISSED_OGMS
    fn path_stale(now: Millis, path: &NeighborStats, seed_ms: u32) -> bool {
        Self::is_stale(
            now,
            path.last_heard,
            path.interval_estimate_ms,
            seed_ms,
            crate::MAX_MISSED_OGMS,
        )
    }

    /// The interval to seed a freshly-heard neighbor's keep-alive miss budget
    /// with, before a second heartbeat provides a real gap to measure: the
    /// largest configured keep-alive `i_max` across interfaces (the quietest
    /// cadence a stable link settles into), or
    /// [`DEFAULT_KEEPALIVE_INTERVAL`](crate::DEFAULT_KEEPALIVE_INTERVAL) if no
    /// interface has keep-alive configured.
    fn keepalive_seed_interval_ms(&self) -> u32 {
        as_millis_u32(
            self.keepalive_timers
                .iter()
                .filter_map(|t| t.as_ref())
                .map(|t| t.i_max())
                .max()
                .unwrap_or(crate::DEFAULT_KEEPALIVE_INTERVAL),
        )
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
                Millis::from_duration(now),
                stats.last_heard,
                stats.interval_estimate_ms,
                self.keepalive_seed_interval_ms(),
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
    fn seed_interval_ms(&self) -> u32 {
        as_millis_u32(
            self.ogm_timers
                .iter()
                .map(|t| t.i_max())
                .max()
                .unwrap_or(crate::DEFAULT_OGM_INTERVAL),
        )
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
    fn blend_interval_ms(old_ms: u32, gap_ms: u32) -> u32 {
        if old_ms == 0 {
            return gap_ms;
        }
        // Decay the held peak by 1/8, then hold the max against the freshly
        // observed gap. Widened to `u64` for the multiply so the decay of a
        // near-`u32::MAX` estimate cannot overflow.
        let decayed_ms = (u64::from(old_ms) * 7 / 8) as u32;
        decayed_ms.max(gap_ms)
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
        let seed_ms = self.seed_interval_ms();
        let before = self.originator_table.len();

        let mut pruned_path = false;
        for record in self.originator_table.values_mut() {
            let paths_before = record.paths.len();
            record
                .paths
                .retain(|p| !Self::path_stale(Millis::from_duration(now), p, seed_ms));
            pruned_path |= record.paths.len() != paths_before;
        }
        self.recompute_all_best(now);

        // An originator reachable on no live path is gone; drop the record.
        self.originator_table.retain(|_, r| !r.paths.is_empty());

        if self.originator_table.len() != before || pruned_path {
            self.topology_changed = true;
        }

        // Bound the age of every stamp the engine still holds, so
        // `Millis::elapsed_since`'s signed half-range is never approached. See
        // [`STAMP_AGE_CEILING_MS`] — this enforces a precondition of the
        // timestamp type rather than making a routing judgement, and by a day
        // each of these is already stale under its own rule.
        //
        // Deliberately *not* folded into the ageing above: these tables are
        // keyed by neighbour rather than by originator and have their own
        // freshness rules (`proof_current`, `keepalive_missed`), which stay
        // exactly as they were. Nothing observable changes at any age below the
        // ceiling.
        let now_ms = Millis::from_duration(now);
        let recent = |stamp: &Millis| now_ms.elapsed_since(*stamp) < STAMP_AGE_CEILING_MS;
        self.proven.retain(|_, (last, _)| recent(last));
        self.challenged.retain(|_, (last, _)| recent(last));
        self.keepalive.retain(|_, s| recent(&s.last_heard));
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

    /// How many sequence-number high-waters this node has resynchronised,
    /// across both the broadcast and OGM spaces — see
    /// [`seqno_resyncs`](Self::seqno_resyncs).
    ///
    /// A count rather than a rate, unlike most of this router's observability.
    /// A correction cannot fire more often than the bands' reset protection
    /// (30s), while `RateEstimator`'s memory is five seconds — so a rate would
    /// read zero at almost every poll and an operator would see nothing at all
    /// unless they happened to sample within a few seconds of the event. The
    /// same reasoning the existing `oversize_drops` counters were built on: for
    /// a rare fault, "how many so far" is the readable signal and "per second"
    /// is not.
    pub fn seqno_resyncs(&self) -> u32 {
        self.seqno_resyncs
    }

    /// How many OGMs this node declined to re-flood while an originator's
    /// high-water was under correction — see
    /// [`ogm_refloods_suppressed`](Self::ogm_refloods_suppressed).
    pub fn ogm_refloods_suppressed(&self) -> u32 {
        self.ogm_refloods_suppressed
    }

    /// How many OGMs this node dropped as its own re-flood echoed back by a
    /// neighbour — a `PrevSender` record naming this node (see
    /// [`crate::wire::TvlvType::PrevSender`]).
    ///
    /// Steadily non-zero is normal and not a fault: it is the ordinary cost of
    /// flooding out every interface. What it is *for* is sizing that cost — a
    /// node whose echo count rivals its real OGM intake is spending a large
    /// share of a shared segment's airtime on frames that are discarded on
    /// arrival, which is an argument about topology rather than a bug here.
    ///
    /// Counts **frames**, not distinct phantom paths: one stub neighbour
    /// echoing every originator's OGM contributes many increments against the
    /// single path that is not learned. Read it against this node's OGM
    /// intake, not on its own.
    ///
    /// A count rather than a rate — but not for the reason
    /// [`seqno_resyncs`](Self::seqno_resyncs) is one, which is that a resync is
    /// rare and bounded by a 30-second window. This signal is the opposite,
    /// high-rate and continuous; it stays a count because the quantity an
    /// operator compares it against is another count.
    pub fn ogm_echoes_dropped(&self) -> u32 {
        self.ogm_echoes_dropped
    }

    /// How many OGMs this node refused to re-flood because the TVLV tail the
    /// sender supplied could not be parsed — a record claiming more bytes than
    /// the tail holds, or a stated `tvlv_len` its frame cannot back.
    ///
    /// Distinct from [`relay_oversize_drops`](Self::relay_oversize_drops) on
    /// purpose, because the two point an operator in opposite directions: an
    /// oversize drop is this node's own scratchpad being too small for a link
    /// it is relaying onto, and is fixed by sizing an MTU; a malformed tail is
    /// a *peer* emitting frames this node cannot forward, and no amount of
    /// buffer will help. Collapsing them into one counter — which an earlier
    /// draft of this guard did — makes the oversize metric climb for a reason
    /// resizing a buffer cannot fix.
    ///
    /// Any steady rate here means a peer is emitting frames no node in the
    /// mesh can relay, so unlike [`ogm_echoes_dropped`](Self::ogm_echoes_dropped)
    /// a persistently non-zero value *is* a fault worth chasing.
    pub fn ogm_tails_malformed(&self) -> u32 {
        self.ogm_tails_malformed
    }

    /// How many originators a full broadcast dedup table has evicted to make
    /// room for a new one.
    ///
    /// The companion the dedup occupancy gauge needs: with nothing ageing
    /// entries out, that gauge saturates on first contact and stays pinned, so
    /// it reads the same on a healthy busy mesh as under a ghost-originator
    /// flood. This counter is what tells them apart: it stays at zero while the
    /// node has heard no more distinct originators than the table holds, and a
    /// flood of fabricated ones drives it continuously. Nothing ages an entry
    /// out, so a long-running node on a churning mesh can also climb slowly
    /// with no attacker involved; it is the *rate* of climb that separates the
    /// two. Each eviction also costs at
    /// worst one duplicate re-flood of the victim's next broadcast, so a steady
    /// climb is airtime being spent as well as a signal.
    ///
    /// A count rather than a rate, for the same reason as
    /// [`ogm_tails_malformed`](Self::ogm_tails_malformed): on a healthy mesh
    /// it is zero, and "how many so far" is what an operator compares across
    /// polls.
    pub fn broadcast_dedup_evictions(&self) -> u32 {
        self.broadcast_dedup_evictions
    }

    /// How many flooded broadcasts this node refused because their seqno sat
    /// out of band against the originator's dedup high-water — a resync watch
    /// opening or continuing, or a completed resync that still did not admit
    /// the frame.
    ///
    /// This is the refusal that suppresses a member: once a high-water has been
    /// pushed out of band (most sharply by an outsider forging one frame with
    /// a far-ahead seqno), every honest broadcast from that originator lands
    /// here until [`BROADCAST_SEQNO_RESET_PROTECTION`](crate::BROADCAST_SEQNO_RESET_PROTECTION)
    /// has passed. An exact duplicate or an in-tolerance straggler is *not*
    /// counted: those are the same flood arriving by a second path, the
    /// ordinary cost of a redundant mesh, and would bury the signal. So on a
    /// healthy mesh this stays at zero, and an originator that reboots and
    /// restarts its counter is the one benign way to move it.
    ///
    /// A count rather than a rate for the same reason as
    /// [`seqno_resyncs`](Self::seqno_resyncs): broadcasts are sparse,
    /// application-driven traffic, so a five-second rate would read zero at
    /// most polls even while a suppression is under way.
    pub fn broadcast_seqno_refusals(&self) -> u32 {
        self.broadcast_seqno_refusals
    }

    /// How many next-hop proofs this node has dropped because the key behind
    /// them was no longer usable — see [`proofs_swept`](Self::proofs_swept).
    pub fn proofs_swept(&self) -> u32 {
        self.proofs_swept
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
    pub fn set_local_mcast_groups(&mut self, now: core::time::Duration, groups: &[Mac]) {
        let before = self.local_mcast.clone();
        self.local_mcast.clear();
        for g in groups {
            if self.local_mcast.push(*g).is_err() {
                break; // table full; drop the rest
            }
        }
        // A change to the groups *we* advertise is an inconsistency in the
        // Trickle sense: our next OGM will say something new, so say it
        // promptly rather than up to `i_max` from now. This is what the reset
        // is for — see `handle_ogm`, which deliberately does *not* reset for
        // another originator's membership change.
        //
        // Reset here and now rather than latching `topology_changed`, because
        // the latch would not do what it looks like it does on this path.
        // `apply_topology_change` is only reached from `produce_periodic_broadcast`
        // (which the driver calls only once the timer is *already* due) and
        // from `handle_ogm` (an inbound frame). A local IGMP join is neither,
        // so a latch would leave the OGM that first carries the new group up
        // to `i_max` away — exactly the delay this is meant to remove — and
        // only bring forward the one after it.
        //
        // Safe to reset from here: the caller is the driver's local-frame arm,
        // a different `select!` branch from `poll_due_ogms`, so this cannot
        // land inside that loop's iteration.
        //
        // Guarded on an actual change so this is safe for *any* caller to
        // invoke unconditionally. The shipping caller already filters —
        // `plan_host_frame` only calls this when `McastSnooper::observe`
        // reported a change, so a repeated IGMP report never reaches here —
        // but this is `pub`, the filtering lives a crate away, and an
        // unguarded latch would pin the node at `i_min` for as long as
        // anything on the host is joined to a group.
        //
        // The comparison is element-wise (`heapless::Vec`), so it depends on
        // the caller passing a stable order; `McastSnooper::groups` sorts for
        // exactly this reason, and its doc comment carries the argument.
        if self.local_mcast != before {
            self.reset_ogm_timers(now);
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
    /// announcement from each originator.
    ///
    /// Deliberately reports nothing back. It used to return whether `orig`'s
    /// group set had changed, so `handle_ogm` could treat that as a Trickle
    /// inconsistency — which was backwards (see the reset comment there), and
    /// cost a pair of sorted `heapless::Vec<Mac, MAX_MCAST_MEMBERS>` snapshots
    /// on every accepted OGM to compute an answer nothing should have acted on.
    fn update_mcast_membership(&mut self, orig: Mac, frame: &LinkFrame) {
        let header_size = core::mem::size_of::<BatmanOgmPacket>();
        let tail = frame.payload.get(header_size..).unwrap_or(&[]);

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

    /// Drop every next-hop proof whose neighbor `usable` no longer admits, and
    /// recompute route selection against what is left.
    ///
    /// A proof is a claim about a neighbor that was answered *with a pairwise
    /// key*, so it is only worth as much as this node's ability to still use
    /// that key. When the key goes — a certificate lapsing, most often, but
    /// equally an entry evicted from a full neighbor cache — the proof it
    /// backed becomes a statement the data plane cannot act on, and leaving it
    /// standing is worse than having no proof at all: selection keeps choosing
    /// the hop while every directed frame over it is dropped at dispatch for
    /// want of a key to tag it with. The route reports healthy and the traffic
    /// vanishes (`docs/design/implemented/09-mesh-auth-gaps.md` §8.10).
    ///
    /// Written as a reconciliation against the key material rather than as a
    /// handler for one eviction event, because the ways a key can go are not a
    /// closed set and the two states must agree however it went. The engine
    /// cannot judge `usable` itself — key material lives in `wayfinder`'s
    /// `OgmAuth`, a crate this one does not depend on — so whoever holds both
    /// supplies it; see `CentralRouter::set_auth_time`.
    ///
    /// `challenged` is deliberately left alone — unlike
    /// [`revoke_originators`](Self::revoke_originators), which clears it and
    /// can afford to, because it deletes the record and the MAC stops being a
    /// challenge candidate at all. Here the neighbor stays a candidate, and
    /// `challenged` is the retry *backoff*: a neighbor with no key is exactly
    /// one whose challenges will keep failing closed, so clearing it would
    /// un-throttle the retries rather than tidy anything up. It clears on its
    /// own the moment the neighbor proves itself again
    /// ([`note_proven`](Self::note_proven)).
    pub fn retain_proven(&mut self, now: core::time::Duration, usable: impl Fn(Mac) -> bool) {
        // Capacity matched to `proven`'s own, so the collect can never
        // truncate. `heapless` truncates *silently*, and a truncated sweep
        // would leave exactly the stale proofs this exists to remove — so if
        // the two capacities are ever decoupled, this needs a different shape,
        // not a bigger number.
        let doomed: heapless::Vec<Mac, MAX_ORIGINATORS> = self
            .proven
            .keys()
            .filter(|m| !usable(**m))
            .copied()
            .collect();
        if doomed.is_empty() {
            return;
        }
        self.proofs_swept = self.proofs_swept.saturating_add(doomed.len() as u32);
        for mac in &doomed {
            debug!(neighbor = ?mac, "dropping next-hop proof: its key is gone");
            self.proven.remove(mac);
        }
        // The cached next hop is what the management API and the forwarding
        // fast path read, so it has to be re-derived here rather than left to
        // the next OGM or periodic sweep — that gap is the whole defect.
        self.recompute_all_best(now);
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
        let now_ms = Millis::from_duration(now);
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

        // This OGM's TVLV region, bounded by the length the OGM itself states
        // rather than by everything after the header. Two reasons, and the
        // second is why a length the frame cannot back is refused outright
        // instead of being read as an empty tail:
        //
        //   * A buffer a frame was parsed out of can carry trailing bytes this
        //     OGM does not claim, and scanning those would let padding an
        //     attacker chose be read as a record.
        //   * `tvlv_len` is a remote-supplied `u16` that nothing else on the
        //     receive path validates. Treating an over-claiming one as an
        //     *empty* tail would let the re-flood below stamp that empty region
        //     and forward it — silently stripping the certificate, signature,
        //     memberships and revocations the originator sent, and leaving
        //     every downstream neighbour on an authenticated mesh to reject the
        //     laundered copy for a missing signature. One malformed frame per
        //     interval would then suppress an originator through this relay.
        let ogm_hdr_len = core::mem::size_of::<BatmanOgmPacket>();
        let Some(ogm_tail) = frame
            .payload
            .get(ogm_hdr_len..ogm_hdr_len.saturating_add(u16::from_be(ogm.tvlv_len) as usize))
        else {
            trace!(
                tvlv_len = u16::from_be(ogm.tvlv_len),
                payload_len = frame.payload.len(),
                "drop: OGM tvlv_len exceeds the frame",
            );
            self.ogm_tails_malformed = self.ogm_tails_malformed.saturating_add(1);
            return RoutingAction::Consumed;
        };

        // Rule 1b: drop an OGM this node forwarded, coming back.
        //
        // The sender stamped who *it* heard this copy from; naming us means it
        // is repeating our own re-flood rather than offering a path. Learning
        // from it would manufacture a path that does not exist — and selecting
        // that path is a loop, since the sender forwards right back here.
        //
        // It does not prove the sender's *route* to `orig` runs through us: a
        // node re-floods only the first copy of each seqno it sees, so a
        // neighbour that has a genuine independent path but happened to hear
        // our copy first stamps us too, and is dropped with the phantoms. That
        // is the accepted cost — it forgoes at most one seqno's worth of path
        // evidence from that neighbour, and the next seqno re-tests it.
        //
        // Checked before the originator record is touched, so a laundered echo
        // cannot create a record, occupy one of the four `paths` slots, or
        // refresh an eviction key. An OGM with no such record (an originated
        // one, or a peer too old to stamp it) is unaffected, which is what
        // keeps this compatible with a mesh that has not fully upgraded.
        if crate::wire::prev_sender(ogm_tail) == Some(self.self_ident) {
            trace!(
                orig = ?orig_ident,
                relay = ?frame.src,
                "drop: OGM we forwarded, echoed back by a neighbour",
            );
            self.ogm_echoes_dropped = self.ogm_echoes_dropped.saturating_add(1);
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
            // Least-recently-heard is the *largest* elapsed, not the smallest
            // stamp -- see `note_proven` and `interfaces::time`.
            if self.originator_table.len() >= MAX_ORIGINATORS
                && let Some(oldest) = self
                    .originator_table
                    .values()
                    .max_by_key(|r| now_ms.elapsed_since(r.last_heard))
                    .map(|r| r.neighbor_ident)
            {
                trace!(orig = ?oldest, "originator table full, evicting least-recently-heard");
                self.originator_table.remove(&oldest);
            }
            let new_record = OriginatorRecord {
                last_heard: now_ms,
                neighbor_ident: orig_ident,
                // Deliberately not `Some(frame.src)`: a first-contact sender
                // is exactly what must not be installed before the proof gate
                // has had a chance to run. `recompute_best` below fills this in
                // if — and only if — the path is selectable.
                best_next_hop: None,
                max_tq: 0,
                // Seeded from this OGM's own sequence number below; a first
                // sighting has no high-water to judge against.
                last_seqno: 0,
                resync_watch: None,
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

        // Rule 2: judge this sequence number against the originator's
        // high-water, which decides three separate things.
        //
        // *Whether to re-flood.* Only a number that advances the high-water is
        // forwarded, so this node repeats each `(originator, seqno)` once and a
        // copy reaching us by a second neighbor does not circulate until its TTL
        // drains. A first sighting has no high-water to judge against, so it
        // seeds one from the OGM's own number rather than being classified
        // against zero: a member already far past `OGM_SEQNO_WINDOW` when first
        // heard would otherwise read as out of band on contact.
        //
        // *Whether to learn the path it arrived on.* Almost always yes — and
        // deliberately **not** conditioned on the high-water advancing. The
        // high-water is keyed on the originator named inside the OGM, not on the
        // forwarder, so anyone who can repeat a member's signed OGM writes it;
        // letting it decide path learning is what turned one replayed frame into
        // a targeted route denial
        // (`docs/design/implemented/09-mesh-auth-gaps.md` §8.11). The one
        // exception is a number strictly behind the high-water but inside the
        // reorder tolerance: that band is where a stale copy of something
        // already seen is the likelier explanation, so the *frame* is what is
        // disbelieved. Outside it — a leap too far forward, or far enough
        // behind — the frame is admitted for topology purposes and
        // `admit_seqno` opens a run against the high-water; the run, not this
        // frame, is what eventually decides which of the two was wrong.
        //
        // *Whether to believe what it asserts.* Multicast memberships are state
        // the originator claims rather than something this node observed, so
        // they follow the freshest OGM and no other: an out-of-date copy must
        // not be able to revert a live member's groups.
        let admission = if is_new_orig {
            // Taken on trust, exactly as `BroadcastSeqnoEntry::seeded` takes a
            // first broadcast, and safe for the same reason rather than in
            // spite of it: a wrong seed — including one an outsider forced by
            // evicting the live record — is corrected by the originator's own
            // next OGMs within `OGM_SEQNO_RESET_PROTECTION`.
            record.last_seqno = incoming_seqno;
            crate::SeqnoAdmission::Advanced
        } else {
            crate::admit_seqno(
                &mut record.last_seqno,
                &mut record.resync_watch,
                incoming_seqno,
                now,
                &crate::SeqnoBands::OGM,
            )
        };
        let is_new_seqno = admission.advanced();
        if matches!(admission, crate::SeqnoAdmission::Resynchronised { .. }) {
            self.seqno_resyncs = self.seqno_resyncs.saturating_add(1);
        }
        // Counted only while a correction is actually in flight: an ordinary
        // duplicate is not re-flooded either, and is the common case carrying
        // no information at all. What this names is the interval in which this
        // node keeps a route to a member for itself while silently declining to
        // pass its OGMs on — which no node behind this one can observe.
        if matches!(admission, crate::SeqnoAdmission::Watching) && ogm.ttl > 1 {
            self.ogm_refloods_suppressed = self.ogm_refloods_suppressed.saturating_add(1);
        }

        if admission.is_stale_copy() {
            trace!(
                orig = ?orig_ident,
                incoming_seqno,
                high_water = record.last_seqno,
                "drop: stale OGM copy"
            );
        }

        if !admission.is_stale_copy() {
            // Hearing this originator keeps the whole record alive — but only
            // on a *current* OGM. This field is purely the eviction key
            // (`min_by_key` when a new originator needs a slot), and the rule
            // its broadcast counterpart states applies unchanged here: an
            // attacker's stream of non-advancing frames must not be able to pin
            // a record at the top of the eviction order. Leaving it alone while
            // a high-water is under correction is also the useful direction —
            // a jammed record then sorts old, and being evicted reseeds it,
            // which cures the jam outright. Path liveness is tracked separately
            // in `NeighborStats::last_heard` below and is what routing reads.
            if admission.contents_are_current() {
                record.last_heard = now_ms;
            }

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
                // Only a genuinely newer number on *this* path measures a
                // cadence: an originator that has restarted its counter is
                // still heard, but the gap across the restart is not an
                // interval it will ever emit at again.
                if incoming_seqno > path.last_seqno {
                    let gap_ms = now_ms.elapsed_since(path.last_heard);
                    path.interval_estimate_ms =
                        Self::blend_interval_ms(path.interval_estimate_ms, gap_ms);
                }
                path.last_tq = computed_tq;
                path.last_seqno = incoming_seqno;
                path.last_heard = now_ms;
            } else if record.paths.len() < 4 {
                let _ = record.paths.push(NeighborStats {
                    neighbor_ident: frame.src,
                    last_tq: computed_tq,
                    last_seqno: incoming_seqno,
                    last_heard: now_ms,
                    // Unsampled until a second OGM gives a gap to measure; the
                    // seed budget covers the gap (see `path_stale`).
                    interval_estimate_ms: 0,
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
            //
            // Gated on the OGM being current, unlike the path learning above,
            // because this is *content* the originator asserts rather than an
            // observation this node made: a replayed old OGM would otherwise
            // revert a live member's groups to whatever they were when it was
            // captured. While a wrong high-water is being corrected the groups
            // simply hold, which is the conservative direction.
            if admission.contents_are_current() {
                self.update_mcast_membership(orig_ident, frame);
            } else {
                trace!(
                    orig = ?orig_ident,
                    incoming_seqno,
                    "drop: OGM memberships not current, holding groups"
                );
            }

            // Reset the Trickle backoff only for changes to *our own advertised
            // state* — which, on this path, means gaining a neighbor and
            // nothing else: we are likely newly reachable too, so neighbors
            // have something new to hear from us.
            //
            // Two things deliberately do NOT reset it, for the same reason.
            // Our OGM advertises only ourselves, so re-announcing faster tells
            // neighbors nothing they did not already have:
            //
            // * A change to our chosen next hop toward some *other*
            //   originator. In a dense mesh the per-seqno TQ jitter from
            //   varying flood paths would otherwise flip `best_next_hop` every
            //   round, pinning the whole mesh at `i_min` and never letting it
            //   quieten.
            // * A change to *that originator's* multicast membership (folded
            //   in by `update_mcast_membership` just above), rather than ours. Every neighbor of ours that cares about it received
            //   the very same OGM we just did. Resetting on it meant any one
            //   node's join pinned every other node near `i_min`, which is
            //   exactly the pinning the backoff exists to prevent, and it grew
            //   worse the denser the mesh got. Our *own* membership changing
            //   is the case that genuinely warrants a reset, and that is
            //   handled where it happens, in `set_local_mcast_groups`,
            //   which resets the timers directly.
            //
            // A genuinely lost route still resets via [`purge_stale`], and
            // forwarding always follows the current best live path regardless.
            if is_new_orig {
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

                // Build the outgoing TVLV tail directly in the caller's
                // scratchpad: every record the originator sent propagates
                // unchanged, with only our `PrevSender` stamp rewritten onto
                // it. Naming the neighbour we heard this from is what lets
                // *that* neighbour recognise its own re-flood when we send it
                // back (see Rule 1b) — the guard is useless unless every
                // forwarder stamps.
                //
                // The tail is written before the header because the header
                // carries its length, which is only known once the rewrite has
                // run: `stamp_prev_sender` drops any stamp the previous hop
                // left, so the tail can shrink as well as grow.
                let size = core::mem::size_of::<BatmanOgmPacket>();

                // Ask how long the rewrite will be before attempting it, which
                // is what lets the two ways it can fail be reported as the
                // different faults they are: a tail this node cannot parse
                // (a peer's problem, no buffer size fixes it) versus a reply
                // scratchpad too small for the result (this node's own, e.g.
                // received on a large-MTU link and re-flooded onto a smaller
                // one). Both used to arrive as a single "oversize" drop, which
                // sent an operator to resize an MTU that was never at fault.
                let Some(out_tvlv_len) = crate::wire::stamped_len(ogm_tail) else {
                    trace!(
                        relay = ?frame.src,
                        tvlv_len = ogm_tail.len(),
                        "drop: OGM tail malformed, not re-flooded",
                    );
                    self.ogm_tails_malformed = self.ogm_tails_malformed.saturating_add(1);
                    self.apply_topology_change(now);
                    return RoutingAction::Consumed;
                };

                // Exact, not an upper bound: `stamped_len` has already
                // accounted for the previous hop's record being replaced
                // rather than appended, so this is the number an operator
                // would size a link by.
                let needed = size + out_tvlv_len;
                let stamped = reply
                    .payload
                    .get_mut(size..)
                    .filter(|out| out.len() >= out_tvlv_len)
                    .and_then(|out| crate::wire::stamp_prev_sender(ogm_tail, out, frame.src))
                    .and_then(|len| u16::try_from(len).ok());

                if let Some(wire_len) = stamped {
                    outbound_ogm.tvlv_len = wire_len.to_be();
                    reply.dst = Mac::BROADCAST;
                    reply.protocol = ETH_P_BATMAN;
                    reply.payload[..size].copy_from_slice(&outbound_ogm.as_bytes()[..size]);
                } else {
                    self.note_relay_oversize_drop("ogm_reflood", needed, reply.payload.len());
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
    /// as OGM paths ([`blend_interval_ms`](Self::blend_interval_ms)) on any second
    /// or later heartbeat, or arms a fresh entry on first sight. Evicts the
    /// least-recently-heard neighbor when the table is full, mirroring
    /// [`handle_ogm`](Self::handle_ogm)'s originator-table eviction.
    fn note_keepalive(&mut self, now: core::time::Duration, neighbor: Mac) {
        let now_ms = Millis::from_duration(now);
        if let Some(stats) = self.keepalive.get_mut(&neighbor) {
            let gap_ms = now_ms.elapsed_since(stats.last_heard);
            stats.interval_estimate_ms =
                Self::blend_interval_ms(stats.interval_estimate_ms, gap_ms);
            stats.last_heard = now_ms;
            return;
        }

        // Least-recently-heard is the largest elapsed -- see `note_proven`.
        if self.keepalive.len() >= MAX_ORIGINATORS
            && let Some(oldest) = self
                .keepalive
                .iter()
                .max_by_key(|(_, s)| now_ms.elapsed_since(s.last_heard))
                .map(|(m, _)| *m)
        {
            self.keepalive.remove(&oldest);
        }
        let _ = self.keepalive.insert(
            neighbor,
            KeepAliveStats {
                last_heard: now_ms,
                interval_estimate_ms: 0,
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
            let admission = entry.admit(incoming_seqno, now);
            if matches!(admission, crate::SeqnoAdmission::Resynchronised { .. }) {
                self.seqno_resyncs = self.seqno_resyncs.saturating_add(1);
            }
            if !admission.advanced() {
                if !matches!(admission, crate::SeqnoAdmission::Duplicate { .. }) {
                    self.broadcast_seqno_refusals = self.broadcast_seqno_refusals.saturating_add(1);
                }
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
                    .max_by_key(|(_, e)| Millis::from_duration(now).elapsed_since(e.last_updated))
                    .map(|(m, _)| *m)
            {
                trace!(orig = ?evicted, "broadcast dedup table full, evicting least-recently-updated");
                self.broadcast_seqno.remove(&evicted);
                self.broadcast_dedup_evictions = self.broadcast_dedup_evictions.saturating_add(1);
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

    /// Route an incoming multicast frame, which names an **explicit list of
    /// destinations** rather than one listener (design 17 §4.3).
    ///
    /// At every hop: deliver if this node is named, remove itself from the
    /// list, split the rest by next hop, and emit one frame per group into
    /// `out`. The list therefore strictly shrinks along any path, and because
    /// the grouping is a partition a destination appears in exactly one
    /// outgoing frame — which is why this needs no deduplication.
    ///
    /// A frame carrying [`McastAuthForm::Signature`] is delivered and **never
    /// forwarded**: one transmission already carried it to every next hop, and
    /// the merge that produced it discarded the per-next-hop grouping, so
    /// forwarding the remainder would storm the medium.
    ///
    /// Nothing is written to `reply` — the outgoing frames are shorter than the
    /// one that caused them and there may be several, which is what `out`
    /// exists for. `scratch` is borrowed to build each frame in turn.
    fn handle_mcast(
        &mut self,
        now: core::time::Duration,
        frame: &LinkFrame,
        out: &mut dyn FrameSink,
        scratch: &mut [u8],
    ) -> RoutingAction {
        let Some(view) = McastPacketView::parse(&frame.payload) else {
            trace!("drop: malformed multicast");
            return RoutingAction::Consumed;
        };
        trace!(
            n_dests = view.dests.len(),
            form = ?view.form,
            ttl = view.header.ttl,
            "rx multicast"
        );

        // A list longer than this node can group is refused whole rather than
        // processed in part. An honest sender never exceeds `MCAST_FANOUT`
        // (past it the group is flooded instead), so this is only reachable
        // from a member forging a list, and the number of groups is bounded by
        // the number of destinations — bounding one bounds the other.
        if view.dests.len() > MAX_MCAST_DESTS {
            self.mcast_oversize_lists = self.mcast_oversize_lists.saturating_add(1);
            trace!(
                n_dests = view.dests.len(),
                max = MAX_MCAST_DESTS,
                "drop: multicast destination list past capacity"
            );
            return RoutingAction::Consumed;
        }

        // Rule 1: deliver if this node is named, and take itself out of the
        // list. The sender excludes itself for the same reason, which is why
        // nothing is ever sent back toward the originator.
        let deliver = view.dests.contains(&self.self_ident);

        // Rule 2: **a fan-out frame is never forwarded.** One transmission
        // carried it to every next hop at once, and the merge that produced it
        // discarded the per-next-hop grouping — so a receiver cannot tell which
        // of the remaining destinations are its to carry and which were already
        // delivered to a neighbour beside it. It would forward to all of them,
        // and so would every other receiver, storming the medium the fan-out
        // exists to spare.
        //
        // The driver only ever merges groups whose destination *is* their next
        // hop, so nothing in such a frame needs onward routing and this costs
        // no delivery. Enforced here rather than trusted: the rule must hold
        // against a frame some other node built, and a forwarding storm is a
        // far worse failure than a dropped multicast.
        if view.form == McastAuthForm::Signature {
            trace!("fan-out multicast: delivered only, never forwarded");
            return if deliver {
                RoutingAction::DeliverLocal
            } else {
                RoutingAction::Consumed
            };
        }

        // Rule 3: the TTL is a loop backstop. Nothing sizes it to the
        // topology; it only bounds a transient loop during reconvergence.
        if view.header.ttl > 1 {
            // Resolve each remaining destination to its next hop. A pair list
            // rather than a map of groups: at most `MAX_MCAST_DESTS` entries of
            // twelve bytes, against a nested list that would cost the square of
            // that on a stack an embedded node shares with everything else.
            let mut routed: heapless::Vec<(Mac, Mac), MAX_MCAST_DESTS> = heapless::Vec::new();
            for &dest in view.dests {
                if dest == self.self_ident {
                    continue;
                }
                let Some(next) = self.next_hop(now, dest) else {
                    // The quiet failure of the whole scheme, so it is counted:
                    // the rest of the list is still forwarded.
                    self.mcast_unroutable_dests = self.mcast_unroutable_dests.saturating_add(1);
                    trace!(?dest, "drop: no route for multicast destination");
                    continue;
                };
                let _ = routed.push((next, dest));
            }

            // Emit one frame per distinct next hop, carrying only that group's
            // destinations. The grouping is a partition, so a destination
            // appears in exactly one outgoing frame and traverses exactly one
            // path — which is what makes this need no dedup.
            let mut done: heapless::Vec<Mac, MAX_MCAST_DESTS> = heapless::Vec::new();
            for &(next, _) in routed.iter() {
                if done.contains(&next) {
                    continue;
                }
                let _ = done.push(next);

                let mut group: heapless::Vec<Mac, MAX_MCAST_DESTS> = heapless::Vec::new();
                for &(n, dest) in routed.iter() {
                    if n == next {
                        let _ = group.push(dest);
                    }
                }

                // One next hop is a directed frame like any other and keeps the
                // pairwise tag. Collapsing several next hops onto one
                // transmission is the driver's call (it owns `LinkT::fan_out`),
                // so the engine always emits per next hop and marks the frame
                // for the tag it will carry unless the driver merges it.
                let Some(len) = write_mcast(
                    view.header.ttl - 1,
                    McastAuthForm::Tag,
                    &group,
                    view.inner,
                    scratch,
                ) else {
                    self.note_relay_oversize_drop(
                        "mcast_relay",
                        MCAST_HEADER_LEN + group.len() * 6 + view.inner.len(),
                        scratch.len(),
                    );
                    continue;
                };

                if !out.push(LinkFrameData {
                    dst: next,
                    protocol: ETH_P_BATMAN,
                    payload: &scratch[..len],
                }) {
                    // Never silent: this is the overflow the design exists to
                    // avoid, so it is counted and warned rather than dropped.
                    self.mcast_emit_overflows = self.mcast_emit_overflows.saturating_add(1);
                    // `trace!`, not `warn!`: reachable from a received
                    // multicast, which is arbitrary remote input on a per-frame
                    // path, and a `warn!` there evicts the bounded log ring a
                    // probe-less board depends on. The counter above is the
                    // observability.
                    trace!(
                        ?next,
                        group = group.len(),
                        "drop: no room to emit a multicast destination group"
                    );
                }
            }
        }

        if deliver {
            RoutingAction::DeliverLocal
        } else {
            RoutingAction::Consumed
        }
    }

    /// Route one of the four credential-control packets — the
    /// `CertReq`/`CertReply` pair that lazy cert distribution moves, and the
    /// `RenewReq`/`RenewReply` pair design 24 renews a board with.
    ///
    /// All four are structurally one thing: a unicast-shaped header carrying a
    /// `dest` and a `ttl`, an opaque body, and the same three outcomes —
    /// deliver locally when `dest` is us (so the router's auth state can act on
    /// it), drop at `ttl <= 1`, otherwise decrement and relay toward the next
    /// live hop, exactly like [`handle_unicast`](Self::handle_unicast). They
    /// share one implementation rather than four copies of the same nine lines
    /// because the copies are what drift: a fourth arm that forgot its
    /// decrement is a renewal that circulates forever on a mesh with a
    /// transient loop, and nothing else here would catch it.
    ///
    /// Crypto-free by construction. The engine only moves bytes; every
    /// signature, certificate and revocation check in these packets belongs to
    /// the router, which is the layer that holds the keys. That is what keeps
    /// `libs/batman` linkable on a board that will never be an authority.
    ///
    /// `what` names the packet in the drop accounting and the trace line, and
    /// is a `&'static str` rather than the packet type so the label reads the
    /// same in both.
    fn handle_credential_control<'rx, 'tx, H>(
        &mut self,
        now: core::time::Duration,
        frame: &'tx LinkFrame,
        reply: &mut LinkFrameDataMut<'rx>,
        what: &'static str,
    ) -> RoutingAction
    where
        H: CredentialControlHeader,
    {
        let Ok((hdr, _)) = H::read_from_prefix(&frame.payload) else {
            trace!(packet = what, "drop: malformed credential-control packet");
            return RoutingAction::Consumed;
        };
        let dst = hdr.dest();
        trace!(
            packet = what,
            ?dst,
            ttl = hdr.ttl(),
            "rx credential control"
        );

        if dst == self.self_ident {
            return RoutingAction::DeliverLocal;
        }
        if hdr.ttl() <= 1 {
            return RoutingAction::Consumed; // Drop packet, expired
        }
        if let Some(next) = self.next_hop(now, dst) {
            let mut updated_hdr = hdr;
            updated_hdr.decrement_ttl();

            let size = core::mem::size_of::<H>();
            let inner = frame.payload.get(size..).unwrap_or(&[]);
            let total = size + inner.len();

            if total <= reply.payload.len() {
                reply.dst = next;
                reply.protocol = ETH_P_BATMAN;
                reply.payload[..size].copy_from_slice(updated_hdr.as_bytes());
                reply.payload[size..total].copy_from_slice(inner);
            } else {
                self.note_relay_oversize_drop(what, total, reply.payload.len());
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
    /// [`handle_credential_control`](Self::handle_credential_control) being
    /// crypto-free: the engine
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
    #[tracing::instrument(skip(self, frame, reply, out), fields(ident = ?self.self_ident), level = "info")]
    fn handle_rx<'rx, 'tx>(
        &mut self,
        now: core::time::Duration,
        frame: &'tx LinkFrame,
        local_quality: Option<u8>,
        reply: &mut LinkFrameDataMut<'rx>,
        out: &mut dyn FrameSink,
    ) -> RoutingAction {
        trace!(
            src = ?frame.src,
            dst = ?frame.dst,
            protocol = %format_args!("0x{:04x}", frame.protocol.get()),
            payload_len = frame.payload.len(),
            "rx frame"
        );

        // Core protocol routing filter: only BATMAN frames with a sub-type byte
        // and a version field behind it.
        if frame.protocol.get() != ETH_P_BATMAN || frame.payload.len() < 2 {
            return RoutingAction::Consumed;
        }

        // Every BATMAN header puts `version` at byte 1, so one check covers
        // every sub-type — including one this build does not recognise, which
        // `route_by_dest` would otherwise route on an inner `dest` it has no
        // business trusting the offset of.
        //
        // Dropping rather than guessing is the point: a peer speaking another
        // version disagrees about what the bytes *after* the header mean, and a
        // misparse there is a garbage MAC routed as if it were real. `trace!`,
        // not `warn!` — this is remotely-supplied input, and a version-skewed
        // neighbour would otherwise flood the log at its OGM interval.
        if frame.payload[1] != BATMAN_VERSION {
            trace!(
                src = ?frame.src,
                version = frame.payload[1],
                expected = BATMAN_VERSION,
                "drop: unsupported protocol version"
            );
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
            Some(BatmanPacketType::Mcast) => {
                // Multicast never uses `reply`: its outgoing frames are
                // shorter than the one that caused them (the list shrinks at
                // every hop) and there may be several, and `reply`'s forward
                // path trims to the *incoming* length. `reply.payload` is
                // borrowed purely as the scratchpad each frame is built in,
                // and handed to the sink — which copies — one frame at a time.
                self.handle_mcast(now, frame, out, reply.payload)
            }
            Some(BatmanPacketType::CertReq) => self
                .handle_credential_control::<BatmanCertReqPacket>(
                    now,
                    frame,
                    reply,
                    "cert_req_relay",
                ),
            Some(BatmanPacketType::CertReply) => self
                .handle_credential_control::<BatmanCertReplyPacket>(
                    now,
                    frame,
                    reply,
                    "cert_reply_relay",
                ),
            Some(BatmanPacketType::RenewReq) => self
                .handle_credential_control::<BatmanRenewReqPacket>(
                    now,
                    frame,
                    reply,
                    "renew_req_relay",
                ),
            Some(BatmanPacketType::RenewReply) => self
                .handle_credential_control::<BatmanRenewReplyPacket>(
                    now,
                    frame,
                    reply,
                    "renew_reply_relay",
                ),
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
            version: BATMAN_VERSION,
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
            version: BATMAN_VERSION,
        };
        tx_buffer[..header_size].copy_from_slice(pkt.as_bytes());
        Some(&tx_buffer[..header_size])
    }
}

/// The shape every credential-control packet header shares: a `dest` to route
/// toward and a `ttl` to bound the hops.
///
/// A private trait rather than four identical relay arms, so
/// [`BatmanEngine::handle_credential_control`] can be written once. It exists
/// only to name the two fields generically — `#[repr(C, packed)]` forbids
/// taking a reference to a field, so accessors are the way to read them, and
/// the impls below are the whole of it.
trait CredentialControlHeader: FromBytes + IntoBytes + Copy + Sized + Immutable {
    /// The node this packet is routed toward.
    fn dest(&self) -> Mac;
    /// The remaining hop budget.
    fn ttl(&self) -> u8;
    /// Spend one hop of that budget. Callers check `ttl() > 1` first, so this
    /// never underflows.
    fn decrement_ttl(&mut self);
}

/// Implement [`CredentialControlHeader`] for a header with the standard
/// `packet_type`/`version`/`ttl`/`dest` layout.
macro_rules! credential_control_header {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl CredentialControlHeader for $ty {
                fn dest(&self) -> Mac {
                    self.dest
                }
                fn ttl(&self) -> u8 {
                    self.ttl
                }
                fn decrement_ttl(&mut self) {
                    self.ttl -= 1;
                }
            }
        )+
    };
}

credential_control_header!(
    BatmanCertReqPacket,
    BatmanCertReplyPacket,
    BatmanRenewReqPacket,
    BatmanRenewReplyPacket,
);

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
            version: BATMAN_VERSION,
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
            version: BATMAN_VERSION,
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

    // ── multicast membership and the Trickle backoff ──────────────────────────

    /// An OGM from `neighbor` announcing interest in `groups`, so the engine
    /// records it as a multicast listener for them.
    fn ogm_frame_with_mcast(neighbor: u8, dst: u8, seqno: u32, groups: &[Mac]) -> Vec<u8> {
        let mut value = Vec::new();
        for g in groups {
            value.extend_from_slice(g.as_bytes());
        }
        let tvlv_hdr = BatmanTvlvHdr {
            tvlv_type: TvlvType::Mcast.as_u8(),
            version: 1,
            len: (value.len() as u16).to_be(),
        };
        let tvlv_total = core::mem::size_of::<BatmanTvlvHdr>() + value.len();
        let ogm = BatmanOgmPacket {
            packet_type: BatmanPacketType::Ogm.as_u8(),
            version: BATMAN_VERSION,
            ttl: 5,
            flags: 0,
            seqno: seqno.to_be(),
            orig: mac(neighbor),
            reserved: 0,
            tq: 200,
            tvlv_len: (tvlv_total as u16).to_be(),
        };
        let mut data = Vec::new();
        data.extend_from_slice(mac(dst).as_bytes());
        data.extend_from_slice(mac(neighbor).as_bytes());
        data.extend_from_slice(&ETH_P_BATMAN.to_be_bytes());
        data.extend_from_slice(ogm.as_bytes());
        data.extend_from_slice(tvlv_hdr.as_bytes());
        data.extend_from_slice(&value);
        data
    }

    /// A multicast group MAC (`01:00:5e:00:00:NN`).
    /// [`ogm_frame_with_mcast`] with the link-layer source split from the
    /// originator, so a relayed — or replayed — membership announcement can be
    /// built.
    fn ogm_mcast_via(orig: u8, src: u8, seqno: u32, groups: &[Mac]) -> Vec<u8> {
        let mut frame = ogm_frame_with_mcast(orig, 1, seqno, groups);
        frame[6..12].copy_from_slice(mac(src).as_bytes());
        frame
    }

    fn mcast_group(n: u8) -> Mac {
        Mac([0x01, 0x00, 0x5e, 0x00, 0x00, n])
    }

    const I_MIN: core::time::Duration = core::time::Duration::from_millis(100);
    const I_MAX: core::time::Duration = core::time::Duration::from_secs(10);

    /// An engine with interface 0 on a Trickle schedule already backed off
    /// well past `i_min`, so a reset is visible as the interval snapping back.
    fn engine_with_backed_off_timer() -> BatmanEngine<4> {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        engine.configure_interface_ogm(0, I_MIN, I_MAX, core::time::Duration::ZERO);
        for _ in 0..4 {
            engine.ogm_timers[0].on_emit(core::time::Duration::ZERO);
        }
        assert!(
            engine.ogm_timers[0].interval() > I_MIN,
            "the timer must be backed off for the reset to be observable"
        );
        engine
    }

    /// Joining a local multicast group changes what *this node's* OGMs
    /// advertise, so it is an inconsistency: the Trickle backoff resets and the
    /// mesh learns the new membership promptly rather than up to `i_max` later.
    ///
    /// The reset lands **immediately**, not on the next emission. That
    /// distinction is the whole point: latching `topology_changed` here would
    /// do nothing until `produce_periodic_broadcast` ran, and that only runs
    /// once the timer is *already* due — so the OGM that first carries the new
    /// group would still be up to `i_max` away, exactly as before, and only
    /// the one after it would come sooner. Asserted without calling
    /// `produce_periodic_broadcast` for that reason: a test that calls it
    /// bypasses the due-gate and passes either way.
    #[test]
    fn joining_a_local_group_resets_the_trickle_backoff_immediately() {
        let mut engine = engine_with_backed_off_timer();

        engine.set_local_mcast_groups(core::time::Duration::ZERO, &[mcast_group(5)]);

        assert_eq!(
            engine.ogm_timers[0].interval(),
            I_MIN,
            "a local join must snap the backoff back to i_min there and then"
        );
    }

    /// The join is also reflected in the *next* OGM the node emits, which is
    /// what the reset exists to bring forward.
    #[test]
    fn the_next_ogm_after_a_local_join_carries_the_group() {
        let mut engine = engine_with_backed_off_timer();
        let mut tx = [0u8; 256];

        engine.set_local_mcast_groups(core::time::Duration::ZERO, &[mcast_group(5)]);
        let ogm = engine
            .produce_periodic_broadcast(core::time::Duration::ZERO, &mut tx)
            .expect("an OGM is produced");

        assert!(
            ogm.windows(6).any(|w| w == mcast_group(5).as_bytes()),
            "the joined group must appear in the OGM's multicast TVLV"
        );
    }

    /// Re-announcing the *same* local groups changes nothing this node
    /// advertises, so it is not an inconsistency — otherwise every IGMP report
    /// the host repeats (they are periodic) would pin the mesh at `i_min`.
    #[test]
    fn re_announcing_the_same_local_groups_does_not_reset_the_backoff() {
        let mut engine = engine_with_backed_off_timer();
        engine.set_local_mcast_groups(core::time::Duration::ZERO, &[mcast_group(5)]);
        for _ in 0..4 {
            engine.ogm_timers[0].on_emit(core::time::Duration::ZERO);
        }
        let backed_off = engine.ogm_timers[0].interval();

        engine.set_local_mcast_groups(core::time::Duration::ZERO, &[mcast_group(5)]);

        assert_eq!(
            engine.ogm_timers[0].interval(),
            backed_off,
            "an unchanged membership set must leave the backoff where it was"
        );
    }

    /// A *remote* originator changing its multicast membership must NOT reset
    /// our Trickle backoff.
    ///
    /// Our OGM advertises only our own groups, so re-announcing faster tells
    /// our neighbors nothing they did not already get from that same
    /// originator's OGM. Resetting on it means any node's join pins every
    /// other node near `i_min` — the denser the mesh, the worse — which is
    /// precisely the pinning the Trickle backoff exists to avoid.
    #[test]
    fn a_remote_membership_change_does_not_reset_our_trickle_backoff() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        engine.configure_interface_ogm(0, I_MIN, I_MAX, core::time::Duration::ZERO);
        let mut tx = [0u8; 256];

        // Learn the originator first: a *new* originator is a genuine
        // inconsistency (we are likely newly reachable too), and that reset is
        // not what this test is about.
        let first = ogm_frame_with_mcast(2, 1, 1, &[mcast_group(5)]);
        let parsed = LinkFrame::ref_from_prefix(&first).unwrap().0;
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        engine.handle_rx(
            core::time::Duration::ZERO,
            parsed,
            None,
            &mut reply,
            &mut (),
        );

        for _ in 0..4 {
            engine.ogm_timers[0].on_emit(core::time::Duration::ZERO);
        }
        let backed_off = engine.ogm_timers[0].interval();
        assert!(backed_off > I_MIN);

        // Same originator, different groups: a real membership change, but
        // one that says nothing about us.
        let second = ogm_frame_with_mcast(2, 1, 2, &[mcast_group(6), mcast_group(7)]);
        let parsed = LinkFrame::ref_from_prefix(&second).unwrap().0;
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        engine.handle_rx(
            core::time::Duration::ZERO,
            parsed,
            None,
            &mut reply,
            &mut (),
        );

        assert_eq!(
            engine.ogm_timers[0].interval(),
            backed_off,
            "another node's membership change must not reset our backoff"
        );
        // The change is still recorded — this is about the timer, not about
        // dropping the announcement.
        let listeners: Vec<Mac> = engine.mcast_listeners(mcast_group(6)).collect();
        assert_eq!(listeners, vec![mac(2)]);
    }

    /// One keep-alive from a neighbor arms `keepalive_missed` (no longer
    /// unconditionally `false`); a second heartbeat folds the observed gap
    /// into the learned `interval_estimate_ms` via the same peak-hold technique
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
        engine.handle_rx(
            core::time::Duration::ZERO,
            parsed_ogm,
            None,
            &mut ogm_reply,
            &mut (),
        );

        let frame1 = keepalive_frame(2, 1);
        let parsed1 = LinkFrame::ref_from_prefix(&frame1).unwrap().0;
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        engine.handle_rx(
            core::time::Duration::ZERO,
            parsed1,
            None,
            &mut reply,
            &mut (),
        );

        let stats = engine.keepalive.get(&mac(2)).expect("armed after 1st hb");
        assert_eq!(stats.last_heard, Millis::ZERO);
        assert_eq!(stats.interval_estimate_ms, 0);

        let frame2 = keepalive_frame(2, 1);
        let parsed2 = LinkFrame::ref_from_prefix(&frame2).unwrap().0;
        let mut reply2: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        engine.handle_rx(
            core::time::Duration::from_secs(5),
            parsed2,
            None,
            &mut reply2,
            &mut (),
        );
        let stats = engine.keepalive.get(&mac(2)).unwrap();
        assert_eq!(stats.last_heard, Millis::from_millis(5_000));
        assert_eq!(stats.interval_estimate_ms, 5_000);
    }

    /// `Millis::elapsed_since` clamps a gap past its 24.8-day signed half-range
    /// to **zero**, which reads as "just now". That is the right answer for a
    /// clock that stepped backwards and exactly the wrong one for a stamp that
    /// is genuinely ancient — so nothing in these tables may be allowed to get
    /// that old.
    ///
    /// Only `purge_stale` can enforce it. `proven`, `challenged` and
    /// `keepalive` are otherwise removed only when their table is full, on a
    /// revocation, or on a re-anchor, so an entry for a neighbour that walked
    /// away sits untouched forever. Past the half-range its proof reads as
    /// current and it stops being re-challenged — the freshness gate silently
    /// `Millis::elapsed_since` clamps a gap past its 24.8-day signed half-range
    /// to **zero**, which reads as "just now". That is the right answer for a
    /// clock that stepped backwards and exactly the wrong one for a stamp that
    /// is genuinely ancient — so nothing in these tables may be allowed to get
    /// that old.
    ///
    /// Only `purge_stale` can enforce it. `proven`, `challenged` and
    /// `keepalive` are otherwise removed only when their table is full, on a
    /// revocation, or on a re-anchor, so an entry for a neighbour that walked
    /// away sits untouched for as long as the node runs. Past the half-range
    /// its proof reads as current and it stops being re-challenged — the
    /// freshness gate silently stops holding.
    #[test]
    fn a_day_old_proof_is_dropped_before_its_stamp_can_wrap() {
        let secs = core::time::Duration::from_secs;
        let mut engine: BatmanEngine<16> = BatmanEngine::new(mac(1));
        engine.set_require_proof(true);
        engine.note_proven(secs(0), mac(2), 0);
        assert!(
            engine.proof_current(secs(1), mac(2)),
            "fresh a second later"
        );

        engine.purge_stale(secs(25 * 3600));
        assert!(
            !engine.proven.contains_key(&mac(2)),
            "past the stamp ceiling the record is dropped, not left to wrap"
        );
        assert!(
            engine.proof_needs_refresh(secs(25 * 3600), mac(2)),
            "and the neighbour is challenged again rather than trusted"
        );
    }

    /// The ceiling is enforced while the stamp is still *readable*, which is
    /// why it lives on the periodic path. A single jump past the half-range
    /// cannot be detected — age is measured with the very function the ceiling
    /// defends — and no shell produces one, because every one of them purges
    /// on its Trickle tick. Pinned so the limitation is stated rather than
    /// discovered.
    #[test]
    fn the_ceiling_needs_purge_to_run_before_the_half_range() {
        let secs = core::time::Duration::from_secs;
        let mut engine: BatmanEngine<16> = BatmanEngine::new(mac(1));
        engine.note_proven(secs(0), mac(2), 0);

        engine.purge_stale(secs(30 * 24 * 3600));
        assert!(
            engine.proven.contains_key(&mac(2)),
            "not a bug to fix here but a precondition to keep: a shell that \
             skipped a month of ticks is outside what this can repair"
        );
    }

    /// The same ceiling for the keep-alive table, which feeds the liveness
    /// The same ceiling for the keep-alive table, which feeds the liveness
    /// overlay `next_hop` reads — and it must leave that table's own rule
    /// untouched at every age below it.
    #[test]
    fn a_day_old_keepalive_record_is_dropped_before_its_stamp_can_wrap() {
        let secs = core::time::Duration::from_secs;
        let mut engine: BatmanEngine<16> = BatmanEngine::new(mac(1));
        engine.note_keepalive(secs(0), mac(2));
        engine.note_keepalive(secs(5), mac(2));

        engine.purge_stale(secs(60));
        assert!(
            engine.keepalive.contains_key(&mac(2)),
            "still within the day"
        );
        assert!(
            engine.keepalive_missed(secs(60), mac(2)),
            "and still deprioritised by its own rule, which the ceiling leaves alone"
        );

        engine.purge_stale(secs(25 * 3600));
        assert!(
            !engine.keepalive.contains_key(&mac(2)),
            "past the ceiling it is dropped; left in place its stamp would wrap \
             and report a month-dead peer as live"
        );
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
        engine.handle_rx(
            core::time::Duration::ZERO,
            parsed,
            None,
            &mut reply,
            &mut (),
        );

        assert!(
            engine.keepalive.get(&mac(2)).is_none(),
            "a keep-alive from an unknown originator must not arm liveness state"
        );
    }

    /// A keep-alive frame truncated shorter than its 2-byte header is
    /// dropped rather than treated as a valid heartbeat — matching every
    /// sibling handler's malformed-input handling (see e.g.
    /// `handle_credential_control`).
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
        engine.handle_rx(core::time::Duration::ZERO, frame, None, &mut reply, &mut ());

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
        engine.handle_rx(
            core::time::Duration::ZERO,
            parsed_ogm,
            None,
            &mut ogm_reply,
            &mut (),
        );

        // Two heartbeats 5s apart teach the engine a 5s cadence.
        for t in [0u64, 5] {
            let frame = keepalive_frame(2, 1);
            let parsed = LinkFrame::ref_from_prefix(&frame).unwrap().0;
            let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
            engine.handle_rx(
                core::time::Duration::from_secs(t),
                parsed,
                None,
                &mut reply,
                &mut (),
            );
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
            &mut (),
        );
        assert!(!engine.keepalive_missed(core::time::Duration::from_secs(30), mac(2)));
    }

    /// Build an OGM for `orig` relayed by link-layer source `src`, with an
    /// explicit TQ — the two-path shape a next-hop contest needs.
    fn ogm_via(orig: u8, src: u8, seqno: u32, tq: u8) -> Vec<u8> {
        let ogm = BatmanOgmPacket {
            packet_type: BatmanPacketType::Ogm.as_u8(),
            version: BATMAN_VERSION,
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

    /// The steady-state relay case: an OGM that *already* carries someone
    /// else's stamp is forwarded with that stamp replaced by ours, and the
    /// header's `tvlv_len` follows the rewrite.
    ///
    /// The pure-function tests cover the replacement; this covers the header.
    /// Past hop two every OGM in the mesh takes this path, and `tvlv_len` is
    /// the one piece of arithmetic here that would corrupt all of them
    /// silently — a header still stating the *incoming* length leaves a
    /// `tvlv_len`-bounded reader parsing a truncated tail, losing the
    /// certificate and signature rather than just the stamp.
    #[test]
    fn a_relayed_ogm_replaces_the_previous_hops_stamp_and_restates_its_length() {
        let mut engine: BatmanEngine<4> = BatmanEngine::new(mac(1));
        let mut tx = [0u8; 256];
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();

        // A tail as hop two would emit it: a foreign record, then hop two's
        // own stamp naming hop one.
        let value = [7u8, 7, 7];
        let hdr = crate::wire::BatmanTvlvHdr {
            tvlv_type: TvlvType::Mcast.as_u8(),
            version: 1,
            len: (value.len() as u16).to_be(),
        };
        let mut tail = Vec::new();
        tail.extend_from_slice(hdr.as_bytes());
        tail.extend_from_slice(&value);
        let mut stamped = [0u8; 64];
        let stamped_len = crate::wire::stamp_prev_sender(&tail, &mut stamped, mac(9)).unwrap();

        let bytes = ogm_with_tail(3, 2, 1, 235, &stamped[..stamped_len]);
        let frame = LinkFrame::ref_from_prefix(&bytes).unwrap().0;
        engine.handle_rx(core::time::Duration::ZERO, frame, None, &mut reply, &mut ());

        let size = core::mem::size_of::<BatmanOgmPacket>();
        let out = BatmanOgmPacket::ref_from_prefix(reply.payload).unwrap().0;
        let out_len = u16::from_be(out.tvlv_len) as usize;
        let out_tail = &reply.payload[size..size + out_len];

        assert_eq!(reply.protocol, ETH_P_BATMAN);
        assert_eq!(
            out_len, stamped_len,
            "one stamp replaces another, so the tail is the same size — and \
             the header must say so"
        );
        assert_eq!(
            crate::wire::prev_sender(out_tail),
            Some(mac(2)),
            "the stamp names who *we* heard it from"
        );
        assert_eq!(
            crate::wire::find_tvlv(out_tail, TvlvType::Mcast),
            Some(&value[..]),
            "and the originator's record still rides along"
        );
        assert_eq!(
            count_records(out_tail, TvlvType::PrevSender),
            1,
            "exactly one stamp — records must not accumulate per hop"
        );
    }

    /// A re-flood that no longer fits the outgoing scratchpad once stamped is
    /// dropped and counted as oversize — the small-MTU relay case the stamp's
    /// wire cost actually bears on.
    #[test]
    fn a_reflood_that_does_not_fit_once_stamped_is_an_oversize_drop() {
        let mut engine: BatmanEngine<4> = BatmanEngine::new(mac(1));

        let value = [7u8; 8];
        let hdr = crate::wire::BatmanTvlvHdr {
            tvlv_type: TvlvType::Mcast.as_u8(),
            version: 1,
            len: (value.len() as u16).to_be(),
        };
        let mut tail = Vec::new();
        tail.extend_from_slice(hdr.as_bytes());
        tail.extend_from_slice(&value);

        // Exactly big enough for the OGM and its incoming tail, one byte short
        // of the stamp.
        let size = core::mem::size_of::<BatmanOgmPacket>();
        let mut tx = vec![0u8; size + tail.len() + crate::wire::PREV_SENDER_RECORD_LEN - 1];
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();

        let bytes = ogm_with_tail(3, 2, 1, 235, &tail);
        let frame = LinkFrame::ref_from_prefix(&bytes).unwrap().0;
        engine.handle_rx(core::time::Duration::ZERO, frame, None, &mut reply, &mut ());

        assert_eq!(reply.protocol, 0, "it must not be truncated onto the wire");
        assert_eq!(engine.relay_oversize_drops(), 1);
        assert_eq!(
            engine.ogm_tails_malformed(),
            0,
            "the tail was well-formed; only the scratchpad was short"
        );
    }

    /// Count records of one type in a TVLV region.
    fn count_records(tail: &[u8], ty: TvlvType) -> usize {
        crate::wire::iter_tvlv(tail, ty).count()
    }

    /// [`ogm_via`], with an arbitrary TVLV tail and an honest `tvlv_len`.
    fn ogm_with_tail(orig: u8, src: u8, seqno: u32, tq: u8, tail: &[u8]) -> Vec<u8> {
        let ogm = BatmanOgmPacket {
            packet_type: BatmanPacketType::Ogm.as_u8(),
            version: BATMAN_VERSION,
            ttl: 5,
            flags: 0,
            seqno: seqno.to_be(),
            orig: mac(orig),
            reserved: 0,
            tq,
            tvlv_len: (tail.len() as u16).to_be(),
        };
        let mut data = Vec::new();
        data.extend_from_slice(mac(1).as_bytes());
        data.extend_from_slice(mac(src).as_bytes());
        data.extend_from_slice(&ETH_P_BATMAN.to_be_bytes());
        data.extend_from_slice(ogm.as_bytes());
        data.extend_from_slice(tail);
        data
    }

    /// An OGM whose `tvlv_len` claims more bytes than its frame carries is
    /// dropped outright, not forwarded with a fabricated tail.
    ///
    /// `tvlv_len` is a remote-supplied `u16` that nothing on the receive path
    /// validates against the frame, so a peer can state any length it likes.
    /// Treating an out-of-range slice as an *empty* tail is the dangerous
    /// reading: `stamp_prev_sender` then succeeds against nothing and the node
    /// re-floods an OGM whose TVLV region holds only its own stamp — the
    /// originator's certificate, signature, memberships and revocations all
    /// silently stripped. Downstream neighbours on an authenticated mesh then
    /// reject the laundered copy for a missing signature, so one malformed
    /// frame per interval suppresses an originator through this relay with
    /// nothing counted anywhere.
    ///
    /// It also disables Rule 1b, since the guard reads the same empty tail.
    #[test]
    fn an_ogm_whose_tvlv_len_exceeds_its_frame_is_dropped() {
        let mut engine: BatmanEngine<4> = BatmanEngine::new(mac(1));
        let mut tx = [0u8; 512];
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();

        let mut bytes = ogm_via(3, 2, 1, 235);
        // A real 10-byte Mcast record, but a `tvlv_len` that claims 0xFFFF.
        let value = [9u8; 6];
        let hdr = crate::wire::BatmanTvlvHdr {
            tvlv_type: TvlvType::Mcast.as_u8(),
            version: 1,
            len: (value.len() as u16).to_be(),
        };
        bytes.extend_from_slice(hdr.as_bytes());
        bytes.extend_from_slice(&value);
        let ogm_off = 2 * core::mem::size_of::<Mac>() + core::mem::size_of::<u16>();
        let tvlv_len_off = ogm_off + core::mem::size_of::<BatmanOgmPacket>() - 2;
        bytes[tvlv_len_off..tvlv_len_off + 2].copy_from_slice(&0xFFFFu16.to_be_bytes());

        let frame = LinkFrame::ref_from_prefix(&bytes).unwrap().0;
        let action = engine.handle_rx(core::time::Duration::ZERO, frame, None, &mut reply, &mut ());

        assert!(matches!(action, RoutingAction::Consumed));
        assert_eq!(
            reply.protocol, 0,
            "an OGM whose tvlv_len overruns its frame must not be re-flooded — \
             forwarding it strips every record the originator sent"
        );
        assert!(
            engine.originator_table.is_empty(),
            "nor may it be learned from"
        );
    }

    /// A malformed TVLV tail is reported as its own condition, not as the
    /// scratchpad being too small.
    ///
    /// Both reach the same `None` from `stamp_prev_sender`, but they are
    /// different faults with different fixes: an oversize drop tells an
    /// operator to look at an MTU, while a malformed tail tells them to look
    /// at a peer. Collapsing them makes `relay_oversize_drops` climb for a
    /// reason resizing a buffer cannot fix — and emits a self-refuting log
    /// line claiming 16 bytes did not fit a 512-byte buffer.
    #[test]
    fn a_malformed_tail_is_not_counted_as_an_oversize_drop() {
        let mut engine: BatmanEngine<4> = BatmanEngine::new(mac(1));
        let mut tx = [0u8; 512];
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();

        // One record claiming 200 value bytes while carrying 2; `tvlv_len` is
        // honest about the 6 bytes that follow the header.
        let hdr = crate::wire::BatmanTvlvHdr {
            tvlv_type: TvlvType::Mcast.as_u8(),
            version: 1,
            len: 200u16.to_be(),
        };
        let mut tail = Vec::new();
        tail.extend_from_slice(hdr.as_bytes());
        tail.extend_from_slice(&[1u8, 2]);

        let mut bytes = ogm_with_tail(3, 2, 1, 235, &tail);
        let ogm_off = 2 * core::mem::size_of::<Mac>() + core::mem::size_of::<u16>();
        let tvlv_len_off = ogm_off + core::mem::size_of::<BatmanOgmPacket>() - 2;
        bytes[tvlv_len_off..tvlv_len_off + 2].copy_from_slice(&(tail.len() as u16).to_be_bytes());

        let frame = LinkFrame::ref_from_prefix(&bytes).unwrap().0;
        engine.handle_rx(core::time::Duration::ZERO, frame, None, &mut reply, &mut ());

        assert_eq!(
            engine.relay_oversize_drops(),
            0,
            "the 512-byte scratchpad was never the problem"
        );
        assert_eq!(
            engine.ogm_tails_malformed(),
            1,
            "the malformed tail must be counted as itself"
        );
    }

    /// `stamp_prev_sender` refuses a tail whose record overruns it, rather
    /// than forwarding a truncated one.
    #[test]
    fn stamping_refuses_a_malformed_tail() {
        let hdr = crate::wire::BatmanTvlvHdr {
            tvlv_type: TvlvType::Mcast.as_u8(),
            version: 1,
            len: 200u16.to_be(),
        };
        let mut tail = Vec::new();
        tail.extend_from_slice(hdr.as_bytes());
        tail.extend_from_slice(&[1u8, 2]);

        let mut out = [0u8; 128];
        assert_eq!(
            crate::wire::stamp_prev_sender(&tail, &mut out, mac(4)),
            None
        );
    }

    /// `stamp_prev_sender` refuses rather than truncates when `out` cannot
    /// hold the result.
    #[test]
    fn stamping_refuses_an_output_buffer_that_is_too_small() {
        let mut out = [0u8; crate::wire::PREV_SENDER_RECORD_LEN - 1];
        assert_eq!(crate::wire::stamp_prev_sender(&[], &mut out, mac(4)), None);
    }

    /// A `PrevSender` record whose value is not exactly one `Mac` is not a
    /// stamp, and must not be read as one.
    #[test]
    fn a_prev_sender_record_of_the_wrong_length_is_not_a_stamp() {
        let hdr = crate::wire::BatmanTvlvHdr {
            tvlv_type: TvlvType::PrevSender.as_u8(),
            version: 1,
            len: 4u16.to_be(),
        };
        let mut tail = Vec::new();
        tail.extend_from_slice(hdr.as_bytes());
        tail.extend_from_slice(&[1u8, 2, 3, 4]);

        assert_eq!(crate::wire::prev_sender(&tail), None);
    }

    /// A forwarded OGM names the neighbour it was heard from, so that
    /// neighbour can recognise its own re-flood coming back.
    ///
    /// The stamp is what the whole loop guard rests on: it is written by the
    /// forwarder and read by the node it is sent to, so a forwarder that
    /// omitted it would silently disable the guard on its neighbours rather
    /// than on itself.
    #[test]
    fn a_forwarded_ogm_names_the_neighbour_it_was_heard_from() {
        let mut engine: BatmanEngine<4> = BatmanEngine::new(mac(1));
        let mut tx = [0u8; 256];
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();

        // mac(2) relays mac(3)'s OGM to us.
        let bytes = ogm_via(3, 2, 1, 255);
        let frame = LinkFrame::ref_from_prefix(&bytes).unwrap().0;
        engine.handle_rx(core::time::Duration::ZERO, frame, None, &mut reply, &mut ());

        let size = core::mem::size_of::<BatmanOgmPacket>();
        assert_eq!(reply.protocol, ETH_P_BATMAN, "the OGM must be re-flooded");
        assert_eq!(
            crate::wire::prev_sender(&reply.payload[size..]),
            Some(mac(2)),
            "the stamp names who we heard it from, not ourselves"
        );
    }

    /// An OGM a neighbour echoes back to us — one whose stamp names *this*
    /// node — is dropped, and leaves no trace: no originator record, no path,
    /// no re-flood.
    ///
    /// This is the defect the guard exists for. Without it the echo is learned
    /// as a path to `orig`, which is a path that does not exist: the sender's
    /// own route to `orig` runs back through this node, so selecting it is a
    /// loop.
    #[test]
    fn an_ogm_we_forwarded_is_dropped_when_a_neighbour_echoes_it_back() {
        let mut engine: BatmanEngine<4> = BatmanEngine::new(mac(1));
        let mut tx = [0u8; 256];

        // mac(2) relays mac(3)'s OGM, stamped as having been heard from *us*.
        let bytes = ogm_via_stamped(3, 2, 1, 235, mac(1));
        let frame = LinkFrame::ref_from_prefix(&bytes).unwrap().0;
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        let action = engine.handle_rx(core::time::Duration::ZERO, frame, None, &mut reply, &mut ());

        assert!(matches!(action, RoutingAction::Consumed));
        assert_eq!(reply.protocol, 0, "an echo must not be re-flooded");
        assert!(
            engine.originator_table.is_empty(),
            "an echo must not even create an originator record, or it would \
             occupy a `paths` slot and refresh an eviction key"
        );
        assert_eq!(engine.ogm_echoes_dropped(), 1);
    }

    /// A stamp from the previous hop is *replaced*, not accumulated, so the
    /// cost of the guard is flat rather than proportional to path length.
    #[test]
    fn stamping_replaces_the_previous_hops_record() {
        let mut out = [0u8; 128];
        let first = crate::wire::stamp_prev_sender(&[], &mut out, mac(7)).unwrap();
        assert_eq!(first, crate::wire::PREV_SENDER_RECORD_LEN);
        assert_eq!(crate::wire::prev_sender(&out[..first]), Some(mac(7)));

        // Re-stamping an already-stamped tail must not grow it.
        let tail = out[..first].to_vec();
        let mut out2 = [0u8; 128];
        let second = crate::wire::stamp_prev_sender(&tail, &mut out2, mac(9)).unwrap();
        assert_eq!(second, first, "a re-stamp replaces rather than appends");
        assert_eq!(crate::wire::prev_sender(&out2[..second]), Some(mac(9)));
    }

    /// Records the relay is not entitled to touch — the originator's cert, its
    /// signature, memberships — survive the rewrite byte-for-byte and in
    /// order. Reordering or dropping any of them would break signature
    /// verification downstream.
    #[test]
    fn stamping_preserves_every_other_record_in_order() {
        // Two foreign records around where the stamp lands.
        let mut tail = Vec::new();
        for (ty, value) in [
            (TvlvType::Mcast, &[9u8, 9, 9][..]),
            (TvlvType::Revoke, &[1, 2]),
        ] {
            let hdr = crate::wire::BatmanTvlvHdr {
                tvlv_type: ty.as_u8(),
                version: 1,
                len: (value.len() as u16).to_be(),
            };
            tail.extend_from_slice(hdr.as_bytes());
            tail.extend_from_slice(value);
        }

        let mut out = [0u8; 128];
        let len = crate::wire::stamp_prev_sender(&tail, &mut out, mac(4)).unwrap();

        assert_eq!(
            len,
            tail.len() + crate::wire::PREV_SENDER_RECORD_LEN,
            "an unstamped tail grows by exactly one record"
        );
        assert_eq!(
            &out[..tail.len()],
            &tail[..],
            "foreign records pass through"
        );
        assert_eq!(crate::wire::prev_sender(&out[..len]), Some(mac(4)));
        assert_eq!(
            crate::wire::find_tvlv(&out[..len], TvlvType::Mcast),
            Some(&[9u8, 9, 9][..])
        );
    }

    /// [`ogm_via`], plus a `PrevSender` stamp naming `heard_from` — an OGM as
    /// a relay actually puts it on the wire.
    fn ogm_via_stamped(orig: u8, src: u8, seqno: u32, tq: u8, heard_from: Mac) -> Vec<u8> {
        let mut tail = [0u8; 32];
        let tail_len = crate::wire::stamp_prev_sender(&[], &mut tail, heard_from).unwrap();

        let ogm = BatmanOgmPacket {
            packet_type: BatmanPacketType::Ogm.as_u8(),
            version: BATMAN_VERSION,
            ttl: 5,
            flags: 0,
            seqno: seqno.to_be(),
            orig: mac(orig),
            reserved: 0,
            tq,
            tvlv_len: (tail_len as u16).to_be(),
        };
        let mut data = Vec::new();
        data.extend_from_slice(mac(1).as_bytes());
        data.extend_from_slice(mac(src).as_bytes());
        data.extend_from_slice(&ETH_P_BATMAN.to_be_bytes());
        data.extend_from_slice(ogm.as_bytes());
        data.extend_from_slice(&tail[..tail_len]);
        data
    }

    /// Every invariant the originator table has that its types do not express.
    /// Called after each `feed` below, per the repo's convention for stateful
    /// structures.
    fn assert_originator_invariants<const N: usize>(engine: &BatmanEngine<N>) {
        for (orig, record) in engine.originator_table.iter() {
            assert_ne!(*orig, engine.self_ident, "own ident must never be tracked");
            if let Some(watch) = record.resync_watch {
                assert_eq!(
                    crate::SeqnoBands::OGM.classify(record.last_seqno, watch.seqno),
                    crate::SeqnoVerdict::Implausible,
                    "a watch only ever holds a number out of band against the \
                     high-water it is evidence against: anything else would have \
                     advanced it or been dropped as a stale copy"
                );
            }
            if let Some(hop) = record.best_next_hop {
                assert!(
                    record.paths.iter().any(|p| p.neighbor_ident == hop),
                    "the selected next hop must be one of the known paths"
                );
            }
        }
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
            &mut (),
        );
        assert_originator_invariants(engine);
    }

    /// [`feed`], reporting whether the OGM was re-flooded: the caller forwards
    /// `reply` only when its protocol was filled in.
    fn feed_reflooded(engine: &mut BatmanEngine<4>, now: u64, frame: &[u8]) -> bool {
        let mut tx = [0u8; 128];
        let parsed = LinkFrame::ref_from_prefix(frame).unwrap().0;
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        engine.handle_rx(
            core::time::Duration::from_secs(now),
            parsed,
            None,
            &mut reply,
            &mut (),
        );
        assert_originator_invariants(engine);
        reply.protocol != 0
    }

    /// The high-water an originator's OGMs are judged against.
    fn ogm_high_water(engine: &BatmanEngine<4>, orig: u8) -> Option<u32> {
        engine
            .originator_table
            .get(&mac(orig))
            .map(|r| r.last_seqno)
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

    /// A proof whose key is gone is dropped, and the route it was holding up
    /// is re-derived on the spot rather than at the next sweep.
    ///
    /// The cached `best_next_hop` is what the management API and the
    /// forwarding fast path read, so leaving it standing until the next OGM is
    /// the whole of §8.10: the route reports healthy while every directed frame
    /// over it is dropped at dispatch for want of a key to tag it with.
    #[test]
    fn a_proof_whose_key_is_gone_is_dropped_and_the_route_recomputed() {
        let mut engine = proving_engine();
        engine.note_proven(core::time::Duration::ZERO, mac(2), 0);
        feed(&mut engine, 0, &ogm_via(2, 2, 1, 255));
        assert_eq!(engine.lookup_route(mac(2)), Some(mac(2)), "setup: routed");

        engine.retain_proven(core::time::Duration::from_secs(1), |m| m != mac(2));

        assert!(!engine.proof_current(core::time::Duration::from_secs(1), mac(2)));
        assert_eq!(
            engine.lookup_route(mac(2)),
            None,
            "the cached next hop must go in the same call, not at the next sweep"
        );
        assert!(
            engine.originator_table.contains_key(&mac(2)),
            "the path itself survives, so a renewed neighbor is re-challenged \
             rather than rediscovered"
        );
    }

    /// The sweep keeps a still-usable alternative rather than dropping the
    /// destination outright.
    #[test]
    fn a_sweep_falls_back_to_a_path_whose_key_is_still_live() {
        let mut engine = proving_engine();
        engine.note_proven(core::time::Duration::ZERO, mac(2), 0);
        engine.note_proven(core::time::Duration::ZERO, mac(3), 0);
        // Two paths to originator 4, the one via 2 preferred on TQ.
        feed(&mut engine, 0, &ogm_via(4, 2, 1, 255));
        feed(&mut engine, 0, &ogm_via(4, 3, 1, 200));
        assert_eq!(
            engine.lookup_route(mac(4)),
            Some(mac(2)),
            "setup: best path"
        );

        engine.retain_proven(core::time::Duration::from_secs(1), |m| m != mac(2));

        assert_eq!(
            engine.lookup_route(mac(4)),
            Some(mac(3)),
            "the surviving proven path takes over immediately"
        );
    }

    /// The sweep leaves the retry backoff alone.
    ///
    /// `challenged` is the throttle on re-probing, and a neighbor with no key
    /// is exactly one whose challenges keep failing closed — clearing it would
    /// un-throttle the retries rather than tidy anything up.
    #[test]
    fn a_sweep_does_not_reset_the_challenge_backoff() {
        let mut engine = proving_engine();
        engine.note_proven(core::time::Duration::ZERO, mac(2), 0);
        engine.note_challenged(core::time::Duration::ZERO, mac(2));

        engine.retain_proven(core::time::Duration::from_secs(1), |_| false);

        assert!(
            engine.challenged.contains_key(&mac(2)),
            "the backoff survives the proof it outlived"
        );
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

    /// A replayed high sequence number must not deny a live originator its
    /// route (`docs/design/implemented/09-mesh-auth-gaps.md` §8.11).
    ///
    /// Eve holds no credential, so she cannot forge a sequence number — but she
    /// does not need to. She replays a *genuine* signed OGM she captured from
    /// hq at a high seqno, under her own link-layer source. The forged path "hq
    /// via eve" is correctly refused (she can never answer a challenge), yet the
    /// high-water is keyed on the originator inside the OGM rather than on the
    /// forwarder, so it takes the replayed number anyway. Every OGM the
    /// genuinely-adjacent hq emits afterwards then sits below it.
    ///
    /// The high-water's job is re-flood dedup, and nothing else: it must not be
    /// able to decide whether this node learns a path at all, or the one piece
    /// of per-originator state a keyless outsider can write becomes a targeted
    /// route denial against any member whose OGMs she once recorded.
    #[test]
    fn a_replayed_high_seqno_does_not_deny_a_live_originator_a_route() {
        let mut engine = proving_engine();

        // Eve (3) pins hq's (2) high-water with a captured high-seqno OGM.
        feed(&mut engine, 0, &ogm_via(2, 3, 5_000, 255));
        assert_eq!(
            engine.lookup_route(mac(2)),
            None,
            "the forged path via eve is refused: she cannot prove herself"
        );

        // hq is genuinely adjacent, has proven itself, and — having rebooted —
        // emits from a low sequence number again.
        engine.note_proven(core::time::Duration::from_secs(1), mac(2), 0);
        for seqno in 1..=3u32 {
            feed(
                &mut engine,
                1 + u64::from(seqno),
                &ogm_via(2, 2, seqno, 255),
            );
        }

        let at = core::time::Duration::from_secs(4);
        assert_eq!(
            engine.lookup_route(mac(2)),
            Some(mac(2)),
            "hq is present and proven, so the route must be acquired"
        );
        assert_eq!(
            engine.next_hop(at, mac(2)),
            Some(mac(2)),
            "and the recomputing selection path must agree"
        );
    }

    /// ...and the pinned high-water itself is corrected, so a relay resumes
    /// re-flooding the jammed member's OGMs to the nodes behind it.
    ///
    /// The route-denial half above is what the victim suffers directly; this is
    /// what it would otherwise inflict on everyone downstream of it, which no
    /// amount of local path learning reaches. Mirrors
    /// [`BroadcastSeqnoEntry::admit`](crate::BroadcastSeqnoEntry::admit), whose
    /// two load-bearing details carry over unchanged: a run of out-of-band
    /// numbers must *persist* before it is believed, and the high-water
    /// resynchronises to the number that **opened** the run rather than to
    /// whichever frame happens to trip the deadline — or a third party could
    /// substitute its own number for the one an honest originator earned.
    #[test]
    fn a_pinned_ogm_high_water_resynchronises_to_the_run_that_opened() {
        let mut engine = proving_engine();

        // Eve's captured OGM is the first sighting, so it seeds the high-water
        // — there is nothing yet to judge it against.
        assert!(feed_reflooded(&mut engine, 0, &ogm_via(2, 3, 5_000, 255)));
        assert_eq!(ogm_high_water(&engine, 2), Some(5_000));

        // hq, restarted, emits from 1 again. A short run is not yet evidence
        // against the high-water, and is not re-flooded.
        assert!(!feed_reflooded(&mut engine, 1, &ogm_via(2, 2, 1, 255)));
        assert!(!feed_reflooded(&mut engine, 2, &ogm_via(2, 2, 2, 255)));
        assert_eq!(
            ogm_high_water(&engine, 2),
            Some(5_000),
            "a run that has not persisted must not move the high-water"
        );

        // Once it has persisted for `OGM_SEQNO_RESET_PROTECTION` the high-water
        // snaps back to the number the run opened at (1), and the frame that
        // tripped the deadline is then judged afresh against it.
        let deadline = 1 + crate::OGM_SEQNO_RESET_PROTECTION.as_secs();
        assert!(feed_reflooded(
            &mut engine,
            deadline,
            &ogm_via(2, 2, 3, 255)
        ));
        assert_eq!(
            ogm_high_water(&engine, 2),
            Some(3),
            "resynchronised to the run, not to the replayed number"
        );

        // And hq's subsequent OGMs flow normally again.
        assert!(feed_reflooded(
            &mut engine,
            deadline + 1,
            &ogm_via(2, 2, 4, 255)
        ));
    }

    /// The three observability counters, at the edges that matter: zero when
    /// nothing has gone wrong, and counting the event rather than the frames
    /// around it.
    ///
    /// Zero is the load-bearing case. Each of these names a fault, so a healthy
    /// node must read `0` on all three — a counter that ticks during ordinary
    /// operation is one an operator learns to ignore.
    #[test]
    fn the_fault_counters_stay_at_zero_on_an_untroubled_node() {
        let mut engine = proving_engine();
        engine.note_proven(core::time::Duration::ZERO, mac(2), 0);
        for seqno in 1..=4u32 {
            feed(&mut engine, u64::from(seqno), &ogm_via(2, 2, seqno, 255));
        }
        // A same-seqno copy via a second neighbor: not re-flooded, but nothing
        // is wrong and nothing must be counted.
        feed(&mut engine, 5, &ogm_via(2, 3, 4, 255));

        assert_eq!(engine.seqno_resyncs(), 0);
        assert_eq!(
            engine.ogm_refloods_suppressed(),
            0,
            "an ordinary duplicate is not a suppressed re-flood"
        );
        assert_eq!(engine.proofs_swept(), 0);
    }

    /// A pinned high-water counts the OGMs it suppresses, then counts the
    /// correction that ends it.
    #[test]
    fn a_pinned_high_water_counts_its_suppression_and_its_correction() {
        let mut engine = proving_engine();
        feed(&mut engine, 0, &ogm_via(2, 3, 5_000, 255));

        // Three genuine OGMs refused while the run is still short.
        for seqno in 1..=3u32 {
            feed(&mut engine, u64::from(seqno), &ogm_via(2, 2, seqno, 255));
        }
        assert_eq!(
            engine.ogm_refloods_suppressed(),
            3,
            "each OGM this node declined to pass on is one nodes behind it lost"
        );
        assert_eq!(engine.seqno_resyncs(), 0, "no correction has fired yet");

        // Past the deadline the correction fires, and is counted once.
        let deadline = 1 + crate::OGM_SEQNO_RESET_PROTECTION.as_secs();
        feed(&mut engine, deadline, &ogm_via(2, 2, 4, 255));
        assert_eq!(engine.seqno_resyncs(), 1);
        assert_eq!(
            engine.ogm_refloods_suppressed(),
            3,
            "the frame that trips the correction is re-flooded, not suppressed"
        );
    }

    /// The counter spans both sequence-number spaces, because the failure and
    /// the machinery behind it are the same in each.
    #[test]
    fn a_broadcast_resync_counts_on_the_same_tally_as_an_ogm_one() {
        let secs = core::time::Duration::from_secs;
        let mut engine = BatmanEngine::<4>::new(mac(1));
        // Seed a high-water, then open a run far below it.
        assert!(flooded(rx_bcast(&mut engine, secs(0), 2, 2, 5_000)));
        assert!(!flooded(rx_bcast(&mut engine, secs(1), 2, 2, 1)));
        assert_eq!(engine.seqno_resyncs(), 0);

        let deadline = secs(1) + crate::BROADCAST_SEQNO_RESET_PROTECTION;
        assert!(flooded(rx_bcast(&mut engine, deadline, 2, 2, 3)));
        assert_eq!(
            engine.seqno_resyncs(),
            1,
            "the broadcast space has been equally silent since its own fix; one \
             tally covers both"
        );
    }

    /// A swept proof is counted per neighbor, not per sweep.
    #[test]
    fn proofs_swept_counts_neighbors_not_sweeps() {
        let mut engine = proving_engine();
        engine.note_proven(core::time::Duration::ZERO, mac(2), 0);
        engine.note_proven(core::time::Duration::ZERO, mac(3), 0);

        engine.retain_proven(core::time::Duration::from_secs(1), |_| true);
        assert_eq!(
            engine.proofs_swept(),
            0,
            "a sweep that drops nothing counts nothing"
        );

        engine.retain_proven(core::time::Duration::from_secs(2), |_| false);
        assert_eq!(engine.proofs_swept(), 2, "both neighbors, one sweep");
    }

    /// The OGM bands are exact at their edges, and are *not* the broadcast ones.
    ///
    /// Pins the *shape* — that each band is inclusive at its edge and exclusive
    /// one past it — not the widths, which it names symbolically and therefore
    /// cannot guard. The widths are pinned behaviourally by
    /// [`a_low_pin_does_not_read_a_restarted_originator_as_stale_copies`], which
    /// is the test that fails if the broadcast tolerance is inherited.
    #[test]
    fn ogm_seqno_bands_are_exact_at_their_edges() {
        use crate::SeqnoVerdict::Advance;
        use crate::SeqnoVerdict::Duplicate;
        use crate::SeqnoVerdict::Implausible;
        let b = crate::SeqnoBands::OGM;
        assert_eq!(b.classify(10_000, 10_001), Advance);
        assert_eq!(
            b.classify(10_000, 10_000 + crate::OGM_SEQNO_WINDOW),
            Advance
        );
        assert_eq!(
            b.classify(10_000, 10_000 + crate::OGM_SEQNO_WINDOW + 1),
            Implausible,
            "a leap past the window is evidence to be weighed, not a fresh number"
        );
        assert_eq!(b.classify(10_000, 10_000), Duplicate);
        assert_eq!(
            b.classify(10_000, 10_000 - crate::OGM_SEQNO_REORDER_TOLERANCE),
            Duplicate
        );
        assert_eq!(
            b.classify(10_000, 10_000 - crate::OGM_SEQNO_REORDER_TOLERANCE - 1),
            Implausible,
            "past the tolerance the high-water, not the frame, is what looks wrong"
        );
    }

    /// The bands are direction-aware across the `u32` wrap, so an originator
    /// whose counter crosses `u32::MAX` is not pinned by its own arithmetic —
    /// the latent non-attack bug the old plain `>=` comparison carried.
    #[test]
    fn ogm_seqno_bands_wrap_at_the_u32_boundary() {
        use crate::SeqnoVerdict::Advance;
        use crate::SeqnoVerdict::Duplicate;
        let b = crate::SeqnoBands::OGM;
        assert_eq!(
            b.classify(u32::MAX, 0),
            Advance,
            "one past the wrap is newer"
        );
        assert_eq!(b.classify(u32::MAX, 1), Advance);
        assert_eq!(
            b.classify(5, u32::MAX),
            Duplicate,
            "and a maxed number lands just *behind* a low high-water rather than \
             far ahead of it — near enough to read as a stale copy, which is the \
             arm that discards it outright"
        );
    }

    /// End to end over the engine: an originator whose counter wraps keeps being
    /// re-flooded across the boundary.
    #[test]
    fn an_ogm_seqno_wrapping_past_u32_max_keeps_reflooding() {
        let mut engine = proving_engine();
        assert!(feed_reflooded(
            &mut engine,
            0,
            &ogm_via(2, 2, u32::MAX - 1, 255)
        ));
        assert!(feed_reflooded(
            &mut engine,
            1,
            &ogm_via(2, 2, u32::MAX, 255)
        ));
        assert!(
            feed_reflooded(&mut engine, 2, &ogm_via(2, 2, 0, 255)),
            "the wrap is one step forward, not a plunge backwards"
        );
        assert_eq!(ogm_high_water(&engine, 2), Some(0));
        assert!(feed_reflooded(&mut engine, 3, &ogm_via(2, 2, 1, 255)));
    }

    /// A third party's maxed sequence number is not a new high-water — the OGM
    /// twin of the `Bcast` fix: it lands *behind* a live high-water under the
    /// wrapping comparison, so the member's own next OGM still re-floods.
    #[test]
    fn a_replayed_max_ogm_seqno_does_not_become_the_high_water() {
        let mut engine = proving_engine();
        feed(&mut engine, 0, &ogm_via(2, 2, 5, 255));
        feed(&mut engine, 1, &ogm_via(2, 3, u32::MAX, 255));
        assert_eq!(
            ogm_high_water(&engine, 2),
            Some(5),
            "the maxed number is behind, not ahead"
        );
        assert!(feed_reflooded(&mut engine, 2, &ogm_via(2, 2, 6, 255)));
    }

    /// Implementation note 1 of §8.11, as a behaviour rather than a comment: a
    /// pin only *tens* above a restarted originator must still be corrected.
    ///
    /// This is the case that fails if the broadcast reorder tolerance (64) is
    /// inherited — the restarted originator's numbers land inside the band,
    /// every one reads as an ordinary duplicate, no run is ever watched, and the
    /// correction never fires. It is also the shape the red-team scenario
    /// actually produces (a pin in the fifties), so the margin is pinned here
    /// rather than left to an emergent number in a simulation.
    #[test]
    fn a_low_pin_does_not_read_a_restarted_originator_as_stale_copies() {
        let mut engine = proving_engine();
        feed(&mut engine, 0, &ogm_via(2, 3, 56, 255));

        engine.note_proven(core::time::Duration::from_secs(1), mac(2), 0);
        for seqno in 1..=3u32 {
            feed(
                &mut engine,
                1 + u64::from(seqno),
                &ogm_via(2, 2, seqno, 255),
            );
        }
        assert_eq!(
            engine.lookup_route(mac(2)),
            Some(mac(2)),
            "a pin inside a too-wide tolerance would swallow these as duplicates"
        );

        // The run opened on hq's first genuine OGM, at t=2.
        let deadline = 2 + crate::OGM_SEQNO_RESET_PROTECTION.as_secs();
        assert!(feed_reflooded(
            &mut engine,
            deadline,
            &ogm_via(2, 2, 4, 255)
        ));
        assert_eq!(ogm_high_water(&engine, 2), Some(4));
    }

    /// A third party must not cash in the run an honest originator earned.
    ///
    /// The claim the resync test's prose makes and could not itself show: the
    /// high-water snaps to the number that *opened* the run, so a frame an
    /// attacker times to arrive at the deadline is judged against that rather
    /// than installed as the new high-water.
    #[test]
    fn a_resync_does_not_admit_a_third_partys_seqno() {
        let mut engine = proving_engine();
        feed(&mut engine, 0, &ogm_via(2, 3, 5_000, 255));
        feed(&mut engine, 1, &ogm_via(2, 2, 1, 255));

        let deadline = 1 + crate::OGM_SEQNO_RESET_PROTECTION.as_secs();
        feed(&mut engine, deadline, &ogm_via(2, 3, 4_000, 255));
        assert_eq!(
            ogm_high_water(&engine, 2),
            Some(1),
            "restored to the run's opening number, with eve's own number judged \
             against it and refused rather than installed"
        );
    }

    /// A run must *persist* before it is believed: one tick short of the
    /// deadline the high-water still stands, or a single well-timed frame would
    /// be enough to force a correction.
    #[test]
    fn an_ogm_resync_waits_out_the_full_reset_protection() {
        let mut engine = proving_engine();
        feed(&mut engine, 0, &ogm_via(2, 3, 5_000, 255));
        feed(&mut engine, 1, &ogm_via(2, 2, 1, 255));

        let just_short = core::time::Duration::from_secs(1) + crate::OGM_SEQNO_RESET_PROTECTION
            - core::time::Duration::from_millis(1);
        let frame = ogm_via(2, 2, 2, 255);
        let parsed = LinkFrame::ref_from_prefix(&frame).unwrap().0;
        let mut tx = [0u8; 128];
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        engine.handle_rx(just_short, parsed, None, &mut reply, &mut ());
        assert_eq!(
            ogm_high_water(&engine, 2),
            Some(5_000),
            "one millisecond short of the deadline, the high-water still stands"
        );
    }

    /// A record whose high-water is under correction must not be pinned at the
    /// top of the eviction order by the very frames doing the pinning.
    ///
    /// The rule `BroadcastSeqnoEntry::last_updated` states, applied to the
    /// originator table: eviction is keyed on `last_heard`, and being evicted
    /// *reseeds* a jammed high-water — so holding a poisoned record in place
    /// with a stream of non-advancing frames must not be possible.
    #[test]
    fn an_out_of_band_ogm_does_not_refresh_the_eviction_key() {
        let mut engine = proving_engine();
        feed(&mut engine, 0, &ogm_via(2, 3, 5_000, 255));
        let seeded = engine
            .originator_table
            .get(&mac(2))
            .expect("seeded")
            .last_heard;

        feed(&mut engine, 10, &ogm_via(2, 2, 1, 255));
        let record = engine.originator_table.get(&mac(2)).expect("kept");
        assert_eq!(
            record.last_heard, seeded,
            "an OGM judged against a high-water under correction is heard, and \
             its path learned, but it does not restamp the eviction key"
        );
        assert_eq!(
            record.paths.len(),
            2,
            "the path really was learned — this is not the stale-copy path"
        );
    }

    /// A stale replayed OGM must not revert a live member's multicast groups.
    ///
    /// Memberships are state the originator *asserts*, unlike the arrival of a
    /// frame, which this node observes for itself — so they follow the freshest
    /// OGM and no other. Both refusal paths are covered: a straggler inside the
    /// reorder tolerance, dropped whole as a stale copy, and an out-of-band
    /// replay, which *is* believed about the topology and must still not be
    /// believed about the groups.
    #[test]
    fn a_stale_replayed_ogm_does_not_revert_a_live_members_mcast_groups() {
        let mut engine = proving_engine();
        let joined_g5 = ogm_mcast_via(2, 2, 100, &[mcast_group(5)]);

        feed(&mut engine, 0, &joined_g5);
        feed(&mut engine, 1, &ogm_mcast_via(2, 2, 101, &[mcast_group(6)]));
        assert_eq!(
            engine.mcast_listeners(mcast_group(6)).collect::<Vec<_>>(),
            vec![mac(2)],
            "the newer announcement landed"
        );
        assert_eq!(
            engine.mcast_listeners(mcast_group(5)).count(),
            0,
            "and replaced the older one"
        );

        // A straggler inside the reorder tolerance: dropped as a stale copy.
        feed(&mut engine, 2, &joined_g5);
        assert_eq!(
            engine.mcast_listeners(mcast_group(6)).collect::<Vec<_>>(),
            vec![mac(2)],
            "a stale copy must not revert the groups"
        );

        // Far out of band, under eve's own source: learned as topology
        // evidence, refused as content.
        feed(&mut engine, 3, &ogm_mcast_via(2, 3, 1, &[mcast_group(5)]));
        assert_eq!(
            engine.mcast_listeners(mcast_group(6)).collect::<Vec<_>>(),
            vec![mac(2)],
            "nor may a replay judged against a high-water under correction"
        );
    }

    /// The converse, so the freshness gate cannot be tightened into refusing
    /// current state: a copy *at* the high-water, arriving via a second
    /// neighbor, still carries current contents and must still be folded in.
    ///
    /// The two copies are given different group sets only to make the branch
    /// observable — a genuine second copy of one flood carries the same TVLV,
    /// so applying it is a no-op and nothing would distinguish the arms.
    #[test]
    fn an_equal_seqno_ogm_copy_still_refreshes_membership() {
        let mut engine = proving_engine();
        feed(&mut engine, 0, &ogm_mcast_via(2, 2, 100, &[mcast_group(5)]));
        feed(
            &mut engine,
            1,
            &ogm_mcast_via(2, 4, 100, &[mcast_group(5), mcast_group(6)]),
        );
        assert_eq!(
            engine.mcast_listeners(mcast_group(6)).collect::<Vec<_>>(),
            vec![mac(2)],
            "an equal-seqno copy is current, not stale"
        );
    }

    /// A restarted originator's OGMs are re-flooded again within one
    /// reset-protection interval — the reason the correction exists at all.
    ///
    /// This, not the replay attack, is what makes the resync load-bearing, and
    /// the argument is easy to get backwards. Before the high-water was
    /// decoupled from path learning, an originator that restarted its counter
    /// had its OGMs refused outright, so `NeighborStats::last_heard` was never
    /// refreshed, its paths aged out, and `purge_stale` dropped the record —
    /// whereupon the next OGM re-seeded a correct high-water. **Eviction was
    /// the self-healing path.** Decoupling deliberately refreshes those paths,
    /// which removes it: without the resync a restarted originator's
    /// high-water would stand forever and every relay in the mesh would stop
    /// forwarding its OGMs, permanently, with the route to it looking healthy
    /// one hop away. No attacker is involved.
    #[test]
    fn a_restarted_originator_is_reflooded_again_within_the_reset_protection() {
        let mut engine = proving_engine();

        // A long-lived originator, then a restart back to a low counter.
        assert!(feed_reflooded(&mut engine, 0, &ogm_via(2, 2, 9_000, 255)));
        assert!(!feed_reflooded(&mut engine, 1, &ogm_via(2, 2, 1, 255)));

        // Its paths stay live throughout — which is precisely why eviction can
        // no longer be relied on to clear the stale high-water.
        engine.purge_stale(core::time::Duration::from_secs(2));
        assert!(
            engine.originator_table.contains_key(&mac(2)),
            "the record survives, so nothing evicts the wrong high-water"
        );

        let deadline = 1 + crate::OGM_SEQNO_RESET_PROTECTION.as_secs();
        assert!(
            feed_reflooded(&mut engine, deadline, &ogm_via(2, 2, 2, 255)),
            "re-flooding must resume once the run has persisted"
        );
        assert_eq!(ogm_high_water(&engine, 2), Some(2));
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
    /// `docs/design/implemented/09-mesh-auth-gaps.md` was written against.
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
            let action =
                engine.handle_rx(core::time::Duration::ZERO, frame, None, &mut reply, &mut ());
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
        let action = engine.handle_rx(
            core::time::Duration::ZERO,
            parsed,
            None,
            &mut reply,
            &mut (),
        );
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
            engine.handle_rx(t, parsed_ogm, None, &mut ogm_reply, &mut ());

            let frame = keepalive_frame(src, 1);
            let parsed = LinkFrame::ref_from_prefix(&frame).unwrap().0;
            let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
            engine.handle_rx(t, parsed, None, &mut reply, &mut ());
        }
        assert_eq!(engine.keepalive.len(), 4);
        assert!(engine.keepalive.contains_key(&mac(10)));

        // A new neighbor's heartbeat must be admitted, evicting the
        // least-recently-heard entry (neighbor 10, heard at t=0).
        let t = core::time::Duration::from_secs(100);
        let ogm = ogm_frame(20, 1, 1);
        let parsed_ogm = LinkFrame::ref_from_prefix(&ogm).unwrap().0;
        let mut ogm_reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        engine.handle_rx(t, parsed_ogm, None, &mut ogm_reply, &mut ());

        let frame = keepalive_frame(20, 1);
        let parsed = LinkFrame::ref_from_prefix(&frame).unwrap().0;
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        engine.handle_rx(t, parsed, None, &mut reply, &mut ());

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
        assert_eq!(produced[1], BATMAN_VERSION);
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
            version: BATMAN_VERSION,
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
                    watch.since.is_at_or_after(entry.last_updated),
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
        let action = engine.handle_rx(now, parsed, None, &mut reply, &mut ());
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

    /// Failure mode A of issue #31: the dedup table is filled with fabricated
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

    /// Issue #38: the dedup table's occupancy gauge saturates on first contact
    /// and stays pinned, so the only signal that separates a busy mesh from a
    /// ghost-originator flood is how often a full table has to evict. Filling
    /// the table and re-hearing a known originator must not count; each new
    /// originator admitted into a full table counts exactly once.
    #[test]
    fn broadcast_dedup_evictions_counts_each_full_table_eviction() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        assert_eq!(engine.broadcast_dedup_evictions(), 0);

        for (i, orig) in (10..14).enumerate() {
            rx_bcast(
                &mut engine,
                core::time::Duration::from_secs(i as u64),
                orig,
                9,
                1,
            );
        }
        assert_eq!(
            engine.broadcast_dedup_evictions(),
            0,
            "filling the table up to capacity evicts nothing"
        );

        // A known originator advancing its seqno updates in place.
        rx_bcast(&mut engine, core::time::Duration::from_secs(10), 13, 9, 2);
        assert_eq!(engine.broadcast_dedup_evictions(), 0);

        rx_bcast(&mut engine, core::time::Duration::from_secs(20), 20, 9, 1);
        assert_eq!(engine.broadcast_dedup_evictions(), 1);
        rx_bcast(&mut engine, core::time::Duration::from_secs(21), 21, 9, 1);
        assert_eq!(engine.broadcast_dedup_evictions(), 2);
        assert_eq!(engine.broadcast_seqno.len(), 4, "table stays at capacity");
    }

    /// Issue #38: a member whose broadcasts are being suppressed — its dedup
    /// high-water pushed out of band, so every honest frame it sends is refused
    /// until the resync watch completes — must be countable without trace
    /// logging. Only the out-of-band refusals count: an exact duplicate (the
    /// same flood by a second path) and an in-tolerance straggler are the
    /// ordinary cost of flooding a redundant mesh, and counting them would bury
    /// the signal under every healthy node's second-path arrivals.
    #[test]
    fn broadcast_seqno_refusals_count_only_out_of_band_frames() {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let secs = core::time::Duration::from_secs;
        assert_eq!(engine.broadcast_seqno_refusals(), 0);

        assert!(flooded(rx_bcast(&mut engine, secs(0), 2, 3, 1_000)));
        assert!(!flooded(rx_bcast(&mut engine, secs(0), 2, 4, 1_000)));
        assert!(!flooded(rx_bcast(
            &mut engine,
            secs(0),
            2,
            4,
            1_000 - TOLERANCE
        )));
        assert!(flooded(rx_bcast(&mut engine, secs(0), 2, 3, 1_001)));
        assert_eq!(
            engine.broadcast_seqno_refusals(),
            0,
            "duplicates and stragglers are benign and must not count"
        );

        // Out of band ahead: opens a resync watch, refused.
        let opening = 1_001 + WINDOW + 1;
        assert!(!flooded(rx_bcast(&mut engine, secs(1), 2, 3, opening)));
        assert_eq!(engine.broadcast_seqno_refusals(), 1);
        // Out of band behind: the watch continues, refused.
        assert!(!flooded(rx_bcast(
            &mut engine,
            secs(2),
            2,
            3,
            1_001 - TOLERANCE - 1
        )));
        assert_eq!(engine.broadcast_seqno_refusals(), 2);

        // The watch completes and the tripping frame advances past the rewound
        // high-water: admitted, so not a refusal.
        assert!(flooded(rx_bcast(
            &mut engine,
            secs(1) + PROTECTION,
            2,
            3,
            opening + 1
        )));
        assert_eq!(engine.seqno_resyncs(), 1);
        assert_eq!(engine.broadcast_seqno_refusals(), 2);
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
            Millis::ZERO,
            "a duplicate must not refresh the eviction key"
        );
    }

    /// Failure mode B of issue #31: one unauthenticated frame carrying a
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
        assert_eq!(
            engine
                .broadcast_seqno
                .get(&mac(2))
                .expect("entry")
                .last_updated,
            Millis::from_duration(later),
            "a resync writes the high-water, so it must restamp the eviction key \
             too — the one thing `SeqnoAdmission::high_water_written` is for, and \
             not something the verdict alone can tell a caller"
        );
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

    // ── certificate renewal over the mesh (design 24) ─────────────────────────

    /// A renewal request on the wire: routed toward `dest` like a unicast,
    /// with a body the engine never looks at.
    fn renew_req_frame(src: u8, link_dst: u8, dest: u8, ttl: u8) -> Vec<u8> {
        let pkt = crate::wire::BatmanRenewReqPacket {
            packet_type: BatmanPacketType::RenewReq.as_u8(),
            version: BATMAN_VERSION,
            ttl,
            dest: mac(dest),
        };
        let mut data = Vec::new();
        data.extend_from_slice(mac(link_dst).as_bytes());
        data.extend_from_slice(mac(src).as_bytes());
        data.extend_from_slice(&ETH_P_BATMAN.to_be_bytes());
        data.extend_from_slice(pkt.as_bytes());
        // A token body, standing in for the requester's cert + signature.
        data.extend_from_slice(&[0xcd; 16]);
        data
    }

    /// The reply half, addressed back toward the requester.
    fn renew_reply_frame(src: u8, link_dst: u8, dest: u8, ttl: u8) -> Vec<u8> {
        let pkt = crate::wire::BatmanRenewReplyPacket {
            packet_type: BatmanPacketType::RenewReply.as_u8(),
            version: BATMAN_VERSION,
            ttl,
            dest: mac(dest),
        };
        let mut data = Vec::new();
        data.extend_from_slice(mac(link_dst).as_bytes());
        data.extend_from_slice(mac(src).as_bytes());
        data.extend_from_slice(&ETH_P_BATMAN.to_be_bytes());
        data.extend_from_slice(pkt.as_bytes());
        data.extend_from_slice(&[0xef; 16]);
        data
    }

    /// An engine at `mac(1)` that has learned a route to `mac(2)` from that
    /// node's own one-hop OGM — the setup every relay assertion below needs,
    /// since a packet with no next hop is dropped before the TTL is touched.
    fn engine_with_route_to_two() -> BatmanEngine<4> {
        let mut engine = BatmanEngine::<4>::new(mac(1));
        let frame = ogm_frame(2, 1, 1);
        let parsed = LinkFrame::ref_from_prefix(&frame).unwrap().0;
        let mut tx = [0u8; 256];
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();
        engine.handle_rx(
            core::time::Duration::ZERO,
            parsed,
            None,
            &mut reply,
            &mut (),
        );
        engine
    }

    /// A `RenewReq` this node is only a waypoint for is forwarded toward the
    /// next live hop with its TTL decremented — the loop bound design 24 §5.1
    /// relies on, and the only thing that stops a renewal circulating on a mesh
    /// with a transient routing loop.
    #[test]
    fn a_renew_req_is_relayed_with_a_decremented_ttl() {
        let mut engine = engine_with_route_to_two();
        let frame = renew_req_frame(3, 1, 2, 5);
        let parsed = LinkFrame::ref_from_prefix(&frame).unwrap().0;
        let mut tx = [0u8; 256];
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();

        let action = engine.handle_rx(
            core::time::Duration::ZERO,
            parsed,
            None,
            &mut reply,
            &mut (),
        );

        assert!(
            matches!(action, RoutingAction::Consumed),
            "a relayed renewal is never delivered to the local node"
        );
        assert_eq!(reply.dst, mac(2), "relayed toward the next hop for dest");
        assert_eq!(reply.protocol, ETH_P_BATMAN);
        let (hdr, body) =
            crate::wire::BatmanRenewReqPacket::ref_from_prefix(reply.payload).unwrap();
        assert_eq!(hdr.ttl, 4, "the TTL must be decremented on relay");
        assert_eq!(hdr.dest, mac(2), "the destination is carried unchanged");
        assert_eq!(&body[..16], &[0xcd; 16], "the body is relayed verbatim");
    }

    /// The reply half relays identically. Written out rather than folded into
    /// the test above because each packet type is a separate *instantiation* of
    /// `handle_credential_control`, and this is what pins that the dispatch arm
    /// for the reply reaches it with the right header type. (This rationale
    /// used to say "separate arms... a copy-paste that forgot one decrement" —
    /// true when the test was written, and made false by the very commit that
    /// collapsed the four arms into one generic function.)
    #[test]
    fn a_renew_reply_is_relayed_with_a_decremented_ttl() {
        let mut engine = engine_with_route_to_two();
        let frame = renew_reply_frame(3, 1, 2, 9);
        let parsed = LinkFrame::ref_from_prefix(&frame).unwrap().0;
        let mut tx = [0u8; 256];
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();

        let action = engine.handle_rx(
            core::time::Duration::ZERO,
            parsed,
            None,
            &mut reply,
            &mut (),
        );

        assert!(matches!(action, RoutingAction::Consumed));
        assert_eq!(reply.dst, mac(2));
        let (hdr, _) = crate::wire::BatmanRenewReplyPacket::ref_from_prefix(reply.payload).unwrap();
        assert_eq!(hdr.ttl, 8);
    }

    /// A renewal addressed to this node terminates here: it is handed up for
    /// the router's auth state to verify, never relayed and never put on the
    /// host device.
    #[test]
    fn a_renew_req_addressed_to_us_is_delivered_locally() {
        let mut engine = engine_with_route_to_two();
        let frame = renew_req_frame(3, 1, 1, 5);
        let parsed = LinkFrame::ref_from_prefix(&frame).unwrap().0;
        let mut tx = [0u8; 256];
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();

        let action = engine.handle_rx(
            core::time::Duration::ZERO,
            parsed,
            None,
            &mut reply,
            &mut (),
        );

        assert!(matches!(action, RoutingAction::DeliverLocal));
        assert_eq!(reply.protocol, 0, "nothing is relayed on local delivery");
    }

    /// At `ttl <= 1` the packet has used its budget and is dropped rather than
    /// forwarded with a wrapped TTL.
    #[test]
    fn a_renew_req_at_ttl_one_is_dropped() {
        let mut engine = engine_with_route_to_two();
        let frame = renew_req_frame(3, 1, 2, 1);
        let parsed = LinkFrame::ref_from_prefix(&frame).unwrap().0;
        let mut tx = [0u8; 256];
        let mut reply: LinkFrameDataMut<'_> = (&mut tx[..]).into();

        let action = engine.handle_rx(
            core::time::Duration::ZERO,
            parsed,
            None,
            &mut reply,
            &mut (),
        );

        assert!(matches!(action, RoutingAction::Consumed));
        assert_eq!(reply.protocol, 0, "an expired renewal is not relayed");
    }
}
