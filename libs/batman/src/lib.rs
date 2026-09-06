//! A `no_std`, heap-free implementation of the BATMAN-adv mesh routing
//! protocol.
//!
//! [`BatmanEngine`] is the core: it maintains an originator table for topology
//! discovery via periodic OGM broadcasts ([`wire::BatmanOgmPacket`]), routes
//! [`wire`]-format unicast/multicast/broadcast packets, and paces its own OGM
//! emission with an adaptive [`trickle`] timer. The engine is crypto-free —
//! authentication is layered on top by the router — and uses `heapless` fixed
//! capacity collections so it runs unchanged on an embedded node or a host.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod engine;
pub mod trickle;
/// On-wire BATMAN packet formats (OGM, unicast, broadcast, multicast, TVLV) and
/// their protocol constants, laid out to match batman-adv.
pub mod wire;

#[cfg(test)]
mod capacity_tests;
#[cfg(test)]
mod engine_tests;

use core::time::Duration;

use heapless::Vec as HVec;
use heapless::index_map::FnvIndexMap;
use interfaces::frame::Mac;

pub use trickle::TrickleTimer;

/// Maximum number of multicast groups this node's local host can join at once.
pub const MAX_LOCAL_MCAST: usize = 16;
/// Maximum number of `(group, listener-originator)` memberships tracked across
/// the whole mesh.  Bounds the footprint for embedded targets.
pub const MAX_MCAST_MEMBERS: usize = 64;

/// Most destinations one multicast frame may name, and so the most groups one
/// hop can split it into.
///
/// Matches `wayfinder::MCAST_FANOUT`, which is the cap the *sender* already
/// applies: past it a group is flooded instead of unicast, so no honest frame
/// ever carries more. Bounding the list bounds the emitted groups too — groups
/// are bounded by distinct next hops, which are bounded by destinations — which
/// is why one constant covers both and why it is **not** the interface count.
/// Several neighbours can sit behind one interface, and each is its own group
/// until the driver collapses them onto a shared medium.
pub const MAX_MCAST_DESTS: usize = 16;

/// Maximum number of mesh interfaces whose OGM emission this engine paces with
/// an independent [`TrickleTimer`].  Bounds the per-interface timer table for
/// embedded targets.
pub const MAX_INTERFACES: usize = 8;

/// How many *expected* OGM intervals a path may go without a refreshing OGM
/// before it — or a whole originator reachable on no fresher path — is treated
/// as dead: skipped when choosing a next hop and evicted by
/// [`purge_stale`](BatmanEngine::purge_stale).
///
/// Ageing is keyed on each path's *learned* emission cadence
/// ([`NeighborStats::interval_estimate`]), not on this node's own OGM rate, so a
/// well-connected node that talks fast no longer ages out a neighbour that talks
/// slow.  The purge budget is `MAX_MISSED_OGMS × interval_estimate`: a neighbour
/// that has quietened into a long Trickle interval is given a correspondingly
/// long grace, and a chatty one is reclaimed quickly.  Six intervals preserves
/// the few-consecutive-misses tolerance of the former 60 s/10 s timeout.
pub const MAX_MISSED_OGMS: u32 = 6;

/// Fallback expected OGM interval used to seed a freshly discovered path's purge
/// budget before its second OGM provides a real gap to measure, and whenever no
/// interface has been configured to derive a cadence from.  Once an interface is
/// configured the seed is its `i_max` (the quietest cadence a stable neighbour
/// settles into); this constant only applies in its absence.
pub const DEFAULT_OGM_INTERVAL: Duration = Duration::from_secs(1);

/// How many *expected* keep-alive intervals an immediate neighbor may go
/// without a heartbeat before [`BatmanEngine::next_hop`] deprioritizes every
/// path relayed through it. Smaller than [`MAX_MISSED_OGMS`] because
/// keep-alives exist specifically to react faster than OGM-interval staleness
/// — three tolerates two consecutive drops on a lossy link (so one missed
/// heartbeat doesn't flap a route) while still reacting in a few seconds
/// rather than the minutes an OGM-interval timeout can take in steady state.
pub const MAX_MISSED_KEEPALIVES: u32 = 3;

/// How many expected intervals a next-hop proof stays current for before the
/// path it vouches for stops being selectable.
///
/// Smaller than [`MAX_MISSED_OGMS`] on purpose: an OGM path aging out costs a
/// route, but a *proof* aging out is the only thing standing between a spoofed
/// next hop and the traffic aimed at it, so it should lapse well before the
/// path it guards does. See `docs/design/implemented/09-mesh-auth-gaps.md` §4.
pub const MAX_MISSED_PROOFS: u32 = 3;

/// Fallback expected keep-alive interval used to seed a freshly-heard
/// neighbor's miss budget before a second heartbeat provides a real gap to
/// measure, and whenever no interface has a keep-alive schedule configured.
/// Mirrors [`DEFAULT_OGM_INTERVAL`]'s role for the OGM path.
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

/// How far ahead of an originator's broadcast high-water a sequence number may
/// leap and still be accepted immediately as genuinely newer.
///
/// A flooded broadcast carries its `orig` and `seqno` inside the payload, and
/// nothing on the ingress path authenticates either — only OGMs and keep-alives
/// are gated — so both are attacker-chosen. The receive-side dedup table is
/// therefore the one piece of routing state an outsider writes to directly, and
/// what stops that being a denial of service is not any check on the frame (a
/// keyless attacker passes every check available) but the guarantee in
/// [`BROADCAST_SEQNO_RESET_PROTECTION`]: whatever the high-water holds, the
/// originator's own traffic corrects it within a bounded time.
///
/// This window's job is narrower than it looks. It is *not* what bounds the
/// damage — the reset protection is. It only decides how large a gap is
/// accepted at once, without waiting for that correction: a receiver that
/// missed this many consecutive broadcasts resumes instantly, a larger gap
/// costs one reset-protection interval of delay. That asymmetry is why it is
/// sized small rather than generously — being too small costs a bounded delay
/// on a rare event, while being too large lets a forged frame be accepted and
/// re-flooded rather than dropped.
pub const BROADCAST_SEQNO_WINDOW: u32 = 1_024;

/// How far *behind* an originator's broadcast high-water a sequence number may
/// sit and still be treated as an ordinary duplicate rather than as evidence
/// that the high-water itself is wrong.
///
/// The same flood reaches a node by several paths, and the later copies are the
/// whole reason the table exists — they must be dropped quietly, without
/// disturbing any state. But "behind the high-water" is *also* exactly what a
/// victim's genuine broadcasts look like once an attacker has pushed that
/// high-water forward, and those must not be dropped quietly, or the forgery is
/// permanent. This constant is the line between the two: small enough that a
/// poisoned high-water is noticed within a few of the victim's own frames,
/// large enough to absorb real multi-path reordering. Mirrors the size of
/// batman-adv's own backward reordering window.
pub const BROADCAST_SEQNO_REORDER_TOLERANCE: u32 = 64;

/// How long a run of broadcast sequence numbers that do not advance an
/// originator's high-water must persist before the entry resynchronises to the
/// run — the bound on how long *any* wrong high-water can suppress a node.
///
/// A window alone would trade one denial of service for another: a node's
/// broadcast counter starts at zero on every boot and is never persisted, so a
/// genuine reboot re-emits sequence numbers far below the high-water its
/// neighbours still hold. Refusing those outright silences a restarted node
/// exactly as durably as an attacker's forgery does.
///
/// Without a credential there is nothing in a frame that separates the two, so
/// the separation has to come from time: a forgery is a one-shot, whereas an
/// originator that is genuinely out of step keeps broadcasting. A run of
/// non-advancing sequence numbers is therefore refused while it is short, and
/// once it has persisted this long the entry resynchronises — **to the sequence
/// number that started the run, not to whichever frame happens to arrive at the
/// deadline**. That distinction is what stops a third party cashing in a run an
/// honest originator earned.
///
/// The residual, which authentication is the only real answer to (see
/// `docs/design/implemented/09-mesh-auth-gaps.md` §8 item 6): an attacker
/// injecting *continuously*, faster than the victim broadcasts, keeps advancing
/// the high-water and so keeps clearing the watch. That is a sustained flood,
/// which an outsider can mount against this protocol anyway; what it can no
/// longer be is a one-shot with permanent effect.
///
/// In the spirit of batman-adv's `BATADV_RESET_PROTECTION_MS`.
pub const BROADCAST_SEQNO_RESET_PROTECTION: Duration = Duration::from_secs(30);

/// How far ahead of an originator's OGM high-water a sequence number may leap
/// and still be accepted immediately as genuinely newer.
///
/// Narrower than [`BROADCAST_SEQNO_WINDOW`] because the two spaces are refilled
/// at different rates: a node emits an OGM on a Trickle interval measured in
/// seconds, so this many missed OGMs is already a long absence, while a
/// broadcast counter advances with application traffic. The asymmetry that
/// governs the size is the same one — too small costs a bounded delay on a rare
/// event, too large lets a replayed number be taken as current and re-flooded.
pub const OGM_SEQNO_WINDOW: u32 = 256;

/// How far *behind* an originator's OGM high-water a sequence number may sit
/// and still be judged a stale copy of something already seen, rather than
/// evidence that the high-water itself is wrong.
///
/// This is the line between disbelieving the *frame* and disbelieving the
/// *high-water*, and it is set much tighter than
/// [`BROADCAST_SEQNO_REORDER_TOLERANCE`] because OGM reordering is bounded by
/// something broadcast reordering is not: an OGM is re-flooded hop by hop under
/// a draining TTL, so a delayed copy arrives at most a few OGM intervals — and
/// therefore a few sequence numbers — behind the high-water, not tens.
///
/// Sizing it wide would be the quiet way to reintroduce the jam this banding
/// exists to close (`docs/design/implemented/09-mesh-auth-gaps.md` §8.11): a
/// rebooted originator re-emitting from 1 against a high-water an attacker
/// pinned at 56 sits *inside* a tolerance of 64, so every one of its OGMs would
/// read as an ordinary duplicate, no run would ever be watched, and the
/// correction would never fire.
pub const OGM_SEQNO_REORDER_TOLERANCE: u32 = 16;

/// How long a run of OGM sequence numbers that do not advance an originator's
/// high-water must persist before the record resynchronises to the run.
///
/// The same value and the same argument as
/// [`BROADCAST_SEQNO_RESET_PROTECTION`] — a forgery is a one-shot while a
/// genuinely out-of-step originator keeps transmitting, so the separation comes
/// from time rather than from anything in the frame. Named separately because
/// the two spaces are free to diverge: this one bounds how long a wrong
/// high-water may suppress *re-flooding* of a member's OGMs, where the
/// broadcast constant bounds suppression of its payloads.
pub const OGM_SEQNO_RESET_PROTECTION: Duration = Duration::from_secs(30);

// Every band is compared as an `i32` distance, so none may reach the point
// where that cast changes its sign.
const _: () = assert!(BROADCAST_SEQNO_WINDOW < i32::MAX as u32);
const _: () = assert!(BROADCAST_SEQNO_REORDER_TOLERANCE < i32::MAX as u32);
const _: () = assert!(OGM_SEQNO_WINDOW < i32::MAX as u32);
const _: () = assert!(OGM_SEQNO_REORDER_TOLERANCE < i32::MAX as u32);

/// What an incoming sequence number means relative to a recorded high-water,
/// under one set of [`SeqnoBands`]. The three arms partition the whole 32-bit
/// space; see [`admit_seqno`], which is the single implementation both
/// sequence-number spaces are judged by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqnoVerdict {
    /// Plausibly the next thing this originator sent: within the bands'
    /// window ahead of the high-water ([`BROADCAST_SEQNO_WINDOW`] for a flooded
    /// broadcast, the narrower [`OGM_SEQNO_WINDOW`] for an OGM).
    Advance,
    /// A copy of something already seen, reaching us by another path: at or
    /// within the bands' reorder tolerance behind the high-water
    /// ([`BROADCAST_SEQNO_REORDER_TOLERANCE`], or the much tighter
    /// [`OGM_SEQNO_REORDER_TOLERANCE`] — the difference is load-bearing, see
    /// that constant).
    Duplicate,
    /// Neither — a leap too far forward, or far enough behind that the
    /// high-water, rather than the frame, is what looks wrong.
    Implausible,
}

/// An in-progress run of [`SeqnoVerdict::Implausible`] sequence numbers from one
/// originator, and the evidence needed to act on it once it has persisted for
/// the bands' reset protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeqnoResyncWatch {
    /// When the run began. Not refreshed by later frames in the same run — the
    /// run has to *persist*, and refreshing it would let an attacker hold the
    /// correction off indefinitely by continuing to send.
    pub since: Duration,
    /// The sequence number that started the run, and the value the high-water
    /// resynchronises to when it completes. Deliberately not the value carried
    /// by the frame that trips the deadline: an attacker must not be able to
    /// substitute its own number for the one an honest originator's run is
    /// about to restore.
    pub seqno: u32,
}

/// One originator's flooded-broadcast dedup state: the highest sequence number
/// seen from it, plus the bookkeeping that keeps that high-water from being
/// weaponised by an outsider who chooses it (see [`BROADCAST_SEQNO_WINDOW`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BroadcastSeqnoEntry {
    /// Highest broadcast sequence number accepted from this originator.
    /// Advanced only by a [`SeqnoVerdict::Advance`], compared with wrapping
    /// arithmetic so the counter's wrap past `u32::MAX` reads as a small step
    /// forward rather than a plunge backwards.
    pub last_seqno: u32,
    /// When `last_seqno` was last set — on creation, on an advance, or on a
    /// resync. Purely the eviction key: nothing ages an entry out, so this is
    /// never read as a staleness gate, only compared against its peers when a
    /// full table has to make room.
    ///
    /// Deliberately *not* refreshed by a duplicate or an implausible frame,
    /// unlike the originator and keep-alive tables' `last_heard`, which every
    /// frame bumps. An attacker's stream of non-advancing frames must not be
    /// able to pin a poisoned entry at the top of the eviction order.
    pub last_updated: Duration,
    /// The run of implausible sequence numbers currently being watched, or
    /// `None` if the last frame from this originator advanced the high-water.
    pub resync_watch: Option<SeqnoResyncWatch>,
}

/// The band widths and dwell time one sequence-number space is judged by.
///
/// Two spaces need the same three-arm decision on different numbers — flooded
/// broadcasts ([`BROADCAST`](Self::BROADCAST)) and OGMs ([`OGM`](Self::OGM)) —
/// and the decision, not the numbers, is the part that was hard to get right.
/// Parameterising it keeps [`admit_seqno`] the single implementation of the
/// poisoning defence rather than two copies free to drift apart.
///
/// Deliberately crate-private, with only the two values that exist reachable as
/// associated constants: judging one space by the other's bands compiles fine
/// and is exactly the mistake [`OGM_SEQNO_REORDER_TOLERANCE`] documents as
/// fatal, so no caller is given the chance to make it. The widths themselves
/// stay public as plain constants for tests and prose to name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SeqnoBands {
    /// How far ahead of the high-water a number may leap and still be taken as
    /// genuinely newer. Held pre-cast so the comparison never casts.
    window: i32,
    /// How far behind the high-water a number may sit and still be read as a
    /// stale copy rather than as evidence against the high-water.
    reorder_tolerance: i32,
    /// How long a run of non-advancing numbers must persist before the
    /// high-water resynchronises to it.
    reset_protection: Duration,
}

impl SeqnoBands {
    /// Build a band set, rejecting a width that would change sign under the
    /// `i32` comparison in [`classify`](Self::classify).
    ///
    /// Both associated constants below are `const`, so these assertions are
    /// evaluated at compile time exactly as a `const _: () = assert!(..)` would
    /// be — but they cover *every* band set rather than only the two spelled
    /// out here. The hazard is worth an assertion rather than a comment: a
    /// width past `i32::MAX` casts to a negative number, and the failure is
    /// silent in the direction that matters — every frame would classify as
    /// `Duplicate` or `Implausible`, which is the dedup table failing into a
    /// route denial.
    const fn new(window: u32, reorder_tolerance: u32, reset_protection: Duration) -> Self {
        assert!(
            window < i32::MAX as u32,
            "seqno window must survive the i32 comparison"
        );
        assert!(
            reorder_tolerance < i32::MAX as u32,
            "seqno reorder tolerance must survive negation in the i32 comparison"
        );
        Self {
            window: window as i32,
            reorder_tolerance: reorder_tolerance as i32,
            reset_protection,
        }
    }

    /// The bands a flooded broadcast's dedup high-water is judged by.
    pub(crate) const BROADCAST: Self = Self::new(
        BROADCAST_SEQNO_WINDOW,
        BROADCAST_SEQNO_REORDER_TOLERANCE,
        BROADCAST_SEQNO_RESET_PROTECTION,
    );

    /// The bands an originator's OGM high-water is judged by.
    pub(crate) const OGM: Self = Self::new(
        OGM_SEQNO_WINDOW,
        OGM_SEQNO_REORDER_TOLERANCE,
        OGM_SEQNO_RESET_PROTECTION,
    );

    /// Classify `seqno` against `high_water` under these bands.
    ///
    /// The comparison is a wrapping `i32` distance, so it is direction-aware
    /// across the `u32` wrap: a counter stepping from `u32::MAX` to `0` reads as
    /// one ahead, not four billion behind.
    pub(crate) fn classify(&self, high_water: u32, seqno: u32) -> SeqnoVerdict {
        let ahead_by = seqno.wrapping_sub(high_water) as i32;
        if ahead_by > 0 && ahead_by <= self.window {
            SeqnoVerdict::Advance
        } else if ahead_by <= 0 && ahead_by >= -self.reorder_tolerance {
            SeqnoVerdict::Duplicate
        } else {
            SeqnoVerdict::Implausible
        }
    }
}

/// What [`admit_seqno`] did with a sequence number.
///
/// A sum rather than a verdict plus flags, because the combinations that do not
/// occur must not be representable: a caller that could build "a duplicate that
/// wrote the high-water" would be describing a state this machine never enters.
/// Each variant also carries exactly what a caller needs to act without
/// re-deriving the classification for itself.
///
/// Public, unlike the [`SeqnoBands`] and [`admit_seqno`] that produce it: this
/// is a verdict a caller *reads*, so it carries none of the misuse risk that
/// keeps those crate-private, and both sequence-number spaces report their
/// [`Resynchronised`](Self::Resynchronised) outcome through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqnoAdmission {
    /// The high-water advanced to this number: genuinely newer than anything
    /// seen from this originator.
    Advanced,
    /// At or behind the high-water, near enough that a stale copy of something
    /// already seen is the likelier explanation than a wrong high-water.
    /// Nothing was written.
    Duplicate {
        /// True when the number *is* the high-water — the same flood reaching
        /// us by a second neighbor, which is how a redundant mesh learns its
        /// backup path, and whose contents are still current. False when it
        /// sits behind: a straggler, and the frame is what to disbelieve.
        exact: bool,
    },
    /// Out of band against the high-water, with a resync watch now open or
    /// continuing. Nothing was written — the run has not yet persisted long
    /// enough to be believed over the high-water it contradicts.
    Watching,
    /// The watch completed: the high-water was rewound to the number that
    /// *opened* the run — never to whichever frame tripped the deadline, or a
    /// third party could substitute its own number for the one an honest
    /// originator earned — and this frame was then judged afresh against it.
    Resynchronised {
        /// That second judgement. `Advance` means the high-water moved on to
        /// this frame's number after the rewind.
        verdict: SeqnoVerdict,
    },
}

impl SeqnoAdmission {
    /// Whether the high-water now holds this frame's number.
    pub fn advanced(&self) -> bool {
        matches!(
            self,
            Self::Advanced
                | Self::Resynchronised {
                    verdict: SeqnoVerdict::Advance
                }
        )
    }

    /// Whether the high-water was written at all — by an advance, or by a
    /// resynchronisation, whether or not the frame that tripped it was then
    /// admitted. Callers keeping an eviction stamp beside the high-water use
    /// this to decide whether to restamp it.
    pub fn high_water_written(&self) -> bool {
        matches!(self, Self::Advanced | Self::Resynchronised { .. })
    }

    /// Whether the state this frame *asserts* — as opposed to what its arrival
    /// merely observes — may be believed: it is either the newest thing this
    /// originator has sent or an exact copy of it. False for a straggler and
    /// for anything judged against a high-water still under correction.
    pub fn contents_are_current(&self) -> bool {
        self.advanced() || matches!(self, Self::Duplicate { exact: true })
    }

    /// Whether this frame is a stale copy of something already seen, and so
    /// carries no evidence about the topology worth acting on.
    pub fn is_stale_copy(&self) -> bool {
        matches!(self, Self::Duplicate { exact: false })
    }
}

/// Fold `seqno` into a high-water and its resync watch, and report what was
/// done. The single implementation of the seqno-poisoning defence, shared by
/// every space that keeps one (see [`SeqnoBands`]).
///
/// - an [`Advance`](SeqnoVerdict::Advance) moves the high-water and clears any
///   watch, because a high-water tracking real forward progress is not one that
///   needs correcting;
/// - a [`Duplicate`](SeqnoVerdict::Duplicate) changes nothing at all — the
///   common case, and the one that must stay free;
/// - an [`Implausible`](SeqnoVerdict::Implausible) opens (or continues) a
///   [`SeqnoResyncWatch`], and once that run has persisted for the bands'
///   `reset_protection` the high-water resynchronises to the number that
///   *started* the run, after which the frame that tripped the deadline is
///   judged afresh against the restored value and may itself advance it.
///
/// The third arm is what makes every wrong high-water self-correcting, whether
/// it got there by an attacker's forgery, by a reseed after eviction, or by the
/// originator rebooting — none of which this code can tell apart, and none of
/// which it has to.
pub(crate) fn admit_seqno(
    last_seqno: &mut u32,
    resync_watch: &mut Option<SeqnoResyncWatch>,
    seqno: u32,
    now: Duration,
    bands: &SeqnoBands,
) -> SeqnoAdmission {
    match bands.classify(*last_seqno, seqno) {
        SeqnoVerdict::Advance => {
            *last_seqno = seqno;
            *resync_watch = None;
            SeqnoAdmission::Advanced
        }
        SeqnoVerdict::Duplicate => SeqnoAdmission::Duplicate {
            exact: seqno == *last_seqno,
        },
        SeqnoVerdict::Implausible => {
            let watch = *resync_watch.get_or_insert(SeqnoResyncWatch { since: now, seqno });
            if now.saturating_sub(watch.since) < bands.reset_protection {
                return SeqnoAdmission::Watching;
            }
            // The run has persisted. Restore the high-water to where the run
            // started, then judge this frame afresh against it — so the frame
            // that happens to trip the deadline is admitted only if it would
            // have been admitted anyway.
            *last_seqno = watch.seqno;
            *resync_watch = None;
            let verdict = bands.classify(*last_seqno, seqno);
            if verdict == SeqnoVerdict::Advance {
                *last_seqno = seqno;
            }
            SeqnoAdmission::Resynchronised { verdict }
        }
    }
}

impl BroadcastSeqnoEntry {
    /// Create an entry for an originator seen for the first time, taking its
    /// sequence number on trust.
    ///
    /// There is nothing else to do — a first sighting has no high-water to
    /// judge against. That is safe *because* of [`Self::admit`]'s resync path
    /// rather than in spite of it: an outsider can force a first sighting at
    /// will by flooding the table until a live entry is evicted, so a check
    /// here would buy nothing, and a wrong seed is corrected by the
    /// originator's own next frames within
    /// [`BROADCAST_SEQNO_RESET_PROTECTION`].
    pub fn seeded(seqno: u32, now: Duration) -> Self {
        Self {
            last_seqno: seqno,
            last_updated: now,
            resync_watch: None,
        }
    }

    /// Classify `seqno` against this entry's high-water, under
    /// [`SeqnoBands::BROADCAST`].
    pub fn classify(&self, seqno: u32) -> SeqnoVerdict {
        SeqnoBands::BROADCAST.classify(self.last_seqno, seqno)
    }

    /// Fold `seqno` into this entry and report what was done — flood the frame
    /// onward only when the result [`advanced`](SeqnoAdmission::advanced).
    ///
    /// The decision itself is [`admit_seqno`], shared with the OGM high-water;
    /// what this adds is the eviction stamp, which is restamped whenever the
    /// high-water is *written* and left alone otherwise — see
    /// [`last_updated`](Self::last_updated) for why a non-advancing frame must
    /// not be able to touch it.
    ///
    /// Returns the whole admission rather than a bare "flood it": a
    /// resynchronisation is this node concluding its own recorded state was
    /// wrong, which is worth counting, and a `bool` would throw that away at
    /// the one place both spaces can be counted alike.
    pub fn admit(&mut self, seqno: u32, now: Duration) -> SeqnoAdmission {
        let admission = admit_seqno(
            &mut self.last_seqno,
            &mut self.resync_watch,
            seqno,
            now,
            &SeqnoBands::BROADCAST,
        );
        if admission.high_water_written() {
            self.last_updated = now;
        }
        admission
    }
}

/// Per-neighbor keep-alive liveness, tracked only for neighbors this engine
/// has actually heard a heartbeat from at least once — a neighbor with no
/// entry here is never treated as having missed anything (see
/// [`BatmanEngine::keepalive_missed`]), so a peer/link not running this
/// feature is never penalized for silence.
#[derive(Debug, Clone)]
pub struct KeepAliveStats {
    /// Monotonic engine clock at the moment the most recent keep-alive from
    /// this neighbor was received.
    pub last_heard: Duration,
    /// Slow-decaying peak hold of the wall-clock interval between successive
    /// keep-alives from this neighbor — the same technique as
    /// [`NeighborStats::interval_estimate`], for the same reason: it tracks
    /// the *slowest* cadence this neighbor settles into rather than an
    /// average, so a burst of closely-spaced heartbeats doesn't shrink the
    /// miss budget below the neighbor's real configured rate. Zero until a
    /// second heartbeat gives a first gap to measure.
    pub interval_estimate: Duration,
}

/// Track metrics for a specific path to an originator via a specific immediate neighbor
#[derive(Debug, Clone)]
pub struct NeighborStats {
    /// The immediate neighbor that relays OGMs for this path to the originator.
    pub neighbor_ident: Mac,
    /// Transmission quality (0..=255) of the most recent OGM accepted on this
    /// path, after per-hop penalty and any local-link clamp.
    pub last_tq: u8,
    /// Sequence number of the most recent OGM accepted on this path, used to
    /// reject stale/duplicate OGMs arriving out of order.
    pub last_seqno: u32,
    /// Monotonic engine clock (the `now` passed to `handle_rx`) at the moment
    /// the most recent OGM refreshed this path.  A path is stale once `now` has
    /// advanced more than [`MAX_MISSED_OGMS`] × [`interval_estimate`] beyond
    /// this stamp: its neighbor has gone quiet relative to the cadence we
    /// learned for it, so it is skipped when selecting a next hop and pruned by
    /// [`BatmanEngine::purge_stale`].
    ///
    /// [`interval_estimate`]: Self::interval_estimate
    pub last_heard: Duration,
    /// Slow-decaying **peak hold** of the wall-clock interval between successive
    /// OGMs accepted on this path: the *slowest* cadence at which we settle into
    /// hearing this originator via this neighbor.  Tracking the peak (not the
    /// average) is what keeps convergence stable — see
    /// [`BatmanEngine::blend_interval`] — because a multi-interface node emits a
    /// burst of distinct-seqno OGMs per round, and an average would collapse
    /// toward the tiny intra-burst gaps and prematurely purge a live neighbor.
    /// Zero until the second OGM gives a first gap to measure, at which point the
    /// purge budget tracks this observed rate instead of any fixed timeout.
    /// Keyed per path, not per node, so each relaying neighbor ages on its own
    /// measured rate.
    pub interval_estimate: Duration,
}

/// A destination node in the mesh network
#[derive(Debug, Clone)]
pub struct OriginatorRecord {
    /// Monotonic engine clock when the most recent OGM for this originator was
    /// accepted via *any* path (the freshest of its
    /// [`NeighborStats::last_heard`]).  Used to evict the least-recently-heard
    /// originator when the table is full; per-path ageing
    /// ([`BatmanEngine::purge_stale`]) drives the actual staleness decision.
    pub last_heard: Duration,
    /// This originator's own address — the *destination* this record
    /// describes, and the key it is stored under in the originator table.
    ///
    /// The name is historical and reads as though it were a relay; it is not.
    /// The relays are in [`paths`](Self::paths), and the selected one is
    /// [`best_next_hop`](Self::best_next_hop). `best_next_hop ==
    /// Some(neighbor_ident)` is precisely the test for "reachable directly",
    /// which is how `CentralRouter::neighbor_count` counts one-hop neighbors.
    pub neighbor_ident: Mac,
    /// The next-hop MAC that packets for this originator are forwarded to —
    /// the immediate neighbor of the best path — or `None` when no path is
    /// currently usable.
    ///
    /// `None` is not merely "no paths known": on an authenticated mesh a path
    /// whose neighbor has not proven itself is deliberately not selectable, so
    /// a freshly discovered originator sits here with `None` and a populated
    /// [`paths`](Self::paths) until its next hop answers a challenge. Modelled
    /// as an `Option` rather than defaulting to the first sender precisely so
    /// that state cannot be skipped: an attacker's spoofed OGM would otherwise
    /// install itself here before any gate ran.
    pub best_next_hop: Option<Mac>,
    /// Transmission quality (0..=255) of the *currently selected* path — the
    /// highest among **selectable** paths, not among all known ones; the metric
    /// the best next hop is chosen by.  Zero when nothing is selectable,
    /// including while every path's neighbor is still unproven, so a `0`
    /// alongside populated `paths` reads as "being challenged", not "dead
    /// link".
    pub max_tq: u8,
    /// Highest OGM sequence number seen from this originator, compared under
    /// [`SeqnoBands::OGM`] so the counter's wrap past `u32::MAX` reads as a
    /// small step forward rather than a plunge backwards.
    ///
    /// Its job is re-flood dedup — this node forwards each
    /// `(originator, seqno)` once — plus the freshness gate on the state an OGM
    /// *asserts*, currently its multicast memberships. It deliberately does
    /// **not** decide whether a path is learned or selected: it is keyed on the
    /// originator named *inside* the OGM rather than on the forwarder, so anyone
    /// able to repeat a member's signed OGM can write it, and a high-water that
    /// also decided whether a path was learned would turn that into a targeted
    /// route denial — see `docs/design/implemented/09-mesh-auth-gaps.md` §8.11.
    pub last_seqno: u32,
    /// The run of OGM sequence numbers currently being watched as evidence
    /// against [`last_seqno`](Self::last_seqno), or `None` if the last OGM from
    /// this originator advanced it. See [`admit_seqno`].
    pub resync_watch: Option<SeqnoResyncWatch>,
    // Track stats per neighbor routing path to this originator
    /// Up to four alternate paths to this originator via different neighbors,
    /// each with its own [`NeighborStats`]; the best-TQ entry backs the fields
    /// above.
    pub paths: HVec<NeighborStats, 4>,
}

/// A snapshot of one interface's adaptive OGM emission schedule, as paced by
/// its [`TrickleTimer`].  Reported by [`BatmanEngine::ogm_schedule`] so the
/// management API can surface the *current* OGM publish rate per link together
/// with the configured backoff bounds it adapts between.
#[derive(Debug, Clone)]
pub struct OgmScheduleEntry {
    /// Index of the interface this schedule belongs to, in the order interfaces
    /// were registered via [`BatmanEngine::configure_interface_ogm`].
    pub iface_idx: usize,
    /// The interval `I` the link is currently emitting at: the live OGM publish
    /// period, which doubles toward `max_interval` while the topology is stable
    /// and snaps back to `min_interval` on any inconsistency.
    pub current_interval: core::time::Duration,
    /// The most aggressive interval the timer resets to on a topology change
    /// (the Trickle `i_min`).
    pub min_interval: core::time::Duration,
    /// The quietest interval the doubling backoff is capped at (the Trickle
    /// `i_max`).
    pub max_interval: core::time::Duration,
}

/// The BATMAN-adv routing engine: an originator table, broadcast dedup state,
/// multicast membership tables, and per-interface Trickle OGM timers, sized for
/// `MAX_ORIGINATORS` known nodes with heap-free `heapless` storage so the same
/// code runs on an MCU and a host. Implements
/// [`MeshRoutingEngine`](interfaces::engine::MeshRoutingEngine).
/// The engine's table capacities are const-generic so one routing core serves
/// both a Linux gateway and a RAM-constrained MCU.  The three trailing
/// parameters default to the crate-wide [`MAX_INTERFACES`],
/// [`MAX_MCAST_MEMBERS`], and [`MAX_LOCAL_MCAST`], so `BatmanEngine<N>` keeps
/// exactly the sizing it had before they existed.
///
/// Every bound the engine enforces at runtime is read from these parameters
/// rather than from the crate constants: a profile that shrinks
/// `MAX_INTERFACES` must also reject the interface indices its tables can no
/// longer hold.
pub struct BatmanEngine<
    const MAX_ORIGINATORS: usize,
    const MAX_INTERFACES: usize = { crate::MAX_INTERFACES },
    const MAX_MCAST_MEMBERS: usize = { crate::MAX_MCAST_MEMBERS },
    const MAX_LOCAL_MCAST: usize = { crate::MAX_LOCAL_MCAST },
> {
    /// This node's own MAC; OGMs and broadcasts bearing it as originator are
    /// dropped for loop prevention.
    pub self_ident: Mac,
    /// Monotonic sequence number stamped on OGMs this node originates.
    pub sequence_number: u32,
    /// Monotonic sequence number stamped on broadcasts this node originates.
    /// Kept separate from the OGM `sequence_number` because broadcast and OGM
    /// sequence numbers are independent number spaces (see
    /// [`Self::broadcast_seqno`] for the receive-side dedup table).
    pub broadcast_sequence_number: u32,
    /// Routes to every known originator, keyed by the originator's MAC for
    /// O(1) lookup on the receive and forward hot paths.  `MAX_ORIGINATORS`
    /// **must be a power of two** (a `heapless` map requirement).  When full, a
    /// newly heard originator evicts the least-recently-refreshed entry rather
    /// than being dropped.
    pub originator_table: FnvIndexMap<Mac, OriginatorRecord, MAX_ORIGINATORS>,
    /// Highest broadcast sequence number seen per originator, used to drop
    /// duplicate flooded broadcasts.  Broadcast and OGM sequence numbers are
    /// independent number spaces, so this is tracked separately from
    /// [`OriginatorRecord::last_seqno`].  Keyed by the `orig` named inside the
    /// broadcast header — not by the immediate relay's `frame.src` — so the
    /// same flood arriving by several paths collapses to one entry.
    /// `MAX_ORIGINATORS` **must be a power of two** (a `heapless` map
    /// requirement).  When full, a newly heard originator evicts the
    /// least-recently-updated entry rather than being dropped.
    ///
    /// Both the key and the value are read from inside an unauthenticated
    /// payload, so this is the one routing table an outsider writes to
    /// directly, and neither its occupancy nor any high-water can be trusted.
    /// [`BroadcastSeqnoEntry::admit`] is what keeps that from being a denial of
    /// service; nothing about this field's contents is load-bearing on its own.
    pub broadcast_seqno: FnvIndexMap<Mac, BroadcastSeqnoEntry, MAX_ORIGINATORS>,
    /// Multicast groups the local host currently listens to.  Announced to the
    /// mesh in the OGM's multicast TVLV; set via
    /// [`set_local_mcast_groups`](BatmanEngine::set_local_mcast_groups).
    pub local_mcast: HVec<Mac, MAX_LOCAL_MCAST>,
    /// `(group, listener-originator)` memberships learned from other nodes'
    /// OGM multicast TVLVs.  Drives selective multicast forwarding: a frame to
    /// a group is sent only toward the originators listed here for that group.
    pub mcast_members: HVec<(Mac, Mac), MAX_MCAST_MEMBERS>,
    /// Per-interface adaptive OGM emission schedules, indexed by interface
    /// index.  Configured at runtime via
    /// [`configure_interface_ogm`](Self::configure_interface_ogm) — each link
    /// supplies its own `i_min`/`i_max`, so a fast link and a slow link back off
    /// independently.  Empty until the owning driver configures its interfaces.
    pub ogm_timers: HVec<TrickleTimer, MAX_INTERFACES>,
    /// Per-neighbor keep-alive liveness, populated only once a heartbeat has
    /// actually been heard from that neighbor (see [`KeepAliveStats`] and
    /// [`BatmanEngine::keepalive_missed`]). Bounded like `originator_table`;
    /// a newly-heard neighbor evicts the least-recently-heard entry when full.
    pub keepalive: FnvIndexMap<Mac, KeepAliveStats, MAX_ORIGINATORS>,
    /// When a neighbor last proved itself a legitimate next hop by answering a
    /// challenge, and **which interface the answer arrived on**. Only consulted
    /// while [`require_proof`](Self::require_proof) is set; bounded like
    /// `originator_table`.
    ///
    /// The interface is recorded because egress resolution cannot be trusted to
    /// find the peer on its own: it goes through the link-quality table, which
    /// is written on frame receipt before any authentication verdict, so an
    /// attacker spoofing a member's source address can make its own link look
    /// like the best way to reach that member. An answered challenge cannot be
    /// *manufactured* — only the key holder could have produced the tag — so it
    /// is what egress pins to. Note the narrower guarantee: the tag is
    /// unforgeable, but the interface is whichever link delivered the answer
    /// first, which a wormhole relaying the genuine answer can be (see
    /// "Residual: wormhole" in `docs/design/implemented/09-mesh-auth-gaps.md`).
    pub(crate) proven: FnvIndexMap<Mac, (Duration, usize), MAX_ORIGINATORS>,
    /// When each neighbor was last *challenged*, and how many attempts have
    /// gone unanswered since it last proved itself — so a candidate is
    /// re-probed on a bounded cadence rather than on every driver tick.
    /// Independent of [`proven`](Self::proven): a neighbor that never answers
    /// stays in here and out of there.
    ///
    /// The count is what makes the retry *exponential* rather than flat, and
    /// the distinction is the difference between a mesh that converges in a
    /// second and one that takes over two minutes. A node's first challenge
    /// routinely loses a race it cannot see: it fires as soon as an originator
    /// appears, which under lazy certificate distribution is before the peer
    /// holds this node's certificate, and the peer drops it as an unverified
    /// directed frame. A flat backoff of one
    /// [`seed_interval`](BatmanEngine::seed_interval) charged a full OGM
    /// `i_max` for that, even while the mesh was still emitting at `i_min`.
    /// Doubling from `i_min` instead recovers in about a second and still
    /// settles at one frame per `seed_interval` for a peer that genuinely
    /// never answers, so the duty-cycle budget in
    /// `docs/design/implemented/09-mesh-auth-gaps.md` is unchanged.
    pub(crate) challenged: FnvIndexMap<Mac, (Duration, u32), MAX_ORIGINATORS>,
    /// How many times this node has resynchronised a sequence-number
    /// high-water — concluded that its own recorded state, not the frame in
    /// front of it, was the thing that was wrong.
    ///
    /// Counts both spaces: a flooded broadcast's dedup high-water and an
    /// originator's OGM high-water, which share one decision
    /// ([`admit_seqno`]) and one failure mode. A correction is bounded by the
    /// bands' reset protection, so this is a slow counter by construction; a
    /// *fast*-growing one means something is repeatedly pushing a high-water
    /// out of band — an originator flapping, or an outsider replaying a
    /// captured frame to hold it there (`docs/design/implemented/`
    /// `09-mesh-auth-gaps.md` §8.11).
    ///
    /// A count rather than a [`RateEstimator`](crate::) — see the accessor.
    pub(crate) seqno_resyncs: u32,
    /// How many OGMs this node declined to re-flood because the originator's
    /// high-water was under correction at the time.
    ///
    /// The residual §8.11 leaves standing, made visible: while a wrong
    /// high-water is being corrected, this node keeps routing to that member
    /// itself but stops propagating its OGMs, so nodes *behind* this one lose
    /// the route and nothing on their side can say why. This is the counter
    /// that names it on the node actually doing the suppressing.
    ///
    /// Deliberately not incremented for an ordinary duplicate, which is the
    /// common case and carries no information — only for a frame refused while
    /// a resync watch is open.
    pub(crate) ogm_refloods_suppressed: u32,
    /// How many next-hop proofs this node has dropped because the pairwise key
    /// they were answered with is no longer usable.
    ///
    /// The event `docs/design/implemented/09-mesh-auth-gaps.md` §8.10 exists
    /// for: a proof is worth no more than this node's ability to still use the
    /// key behind it, and when the two disagree the route reports healthy while
    /// the traffic over it vanishes. A steady climb means neighbour
    /// certificates are lapsing without renewal, or the neighbour key cache is
    /// churning under pressure — different remedies, but both start here.
    pub(crate) proofs_swept: u32,
    /// Whether a next hop must have proven itself to be selectable.
    ///
    /// Off by default and set by the router when mesh authentication is
    /// enabled: proof rests on pairwise keys, which an unauthenticated mesh
    /// does not have, so requiring it there would break every route rather
    /// than securing anything.
    pub(crate) require_proof: bool,
    /// Per-interface fixed-cadence keep-alive emission schedules, indexed by
    /// interface index. `None` (the default for every slot) means that
    /// interface never transmits keep-alives — opt-in per
    /// [`configure_interface_keepalive`](Self::configure_interface_keepalive),
    /// unlike [`ogm_timers`](Self::ogm_timers) which is always armed. Kept in
    /// its own bank, separate from `ogm_timers`, so an OGM-driven topology
    /// change ([`reset_ogm_timers`](Self::reset_ogm_timers)) never resets a
    /// keep-alive schedule — the two are independent signals.
    pub keepalive_timers: HVec<Option<TrickleTimer>, MAX_INTERFACES>,
    /// Latched whenever this engine's view of the topology changes (a new
    /// originator, a changed best next hop, a changed multicast membership, or a
    /// purged route).  Consumed at the end of OGM processing and of
    /// [`produce_periodic_broadcast`] to reset every Trickle timer back to its
    /// `i_min`, so the node re-announces promptly after any change.
    ///
    /// [`produce_periodic_broadcast`]: interfaces::engine::MeshRoutingEngine::produce_periodic_broadcast
    topology_changed: bool,
    /// Count of relayed frames (OGM re-floods, broadcast re-floods, unicast/
    /// multicast relays) dropped because the caller's `reply` scratchpad was
    /// too small to hold the rebuilt packet — i.e. this frame arrived on a
    /// link whose MTU is larger than an egress link's.  A bounded,
    /// here-and-now signal an operator can query; see
    /// [`relay_oversize_drops`](Self::relay_oversize_drops).  Distinct from
    /// [`CentralRouter::oversize_drops`](../../wayfinder/struct.CentralRouter.html#method.oversize_drops),
    /// which counts locally originated frames dropped for the analogous
    /// reason — this one is remotely triggerable (any neighbor relaying
    /// through this node can cause it), so unlike that counter it never
    /// escalates to `warn!`, only `trace!`.
    relay_oversize_drops: u32,

    /// Multicast frames refused whole because their destination list exceeded
    /// [`MAX_MCAST_DESTS`]. Only reachable from a member forging a longer list
    /// than `MCAST_FANOUT` ever produces, so — like `relay_oversize_drops` —
    /// remotely triggerable and never escalated past `trace!`.
    mcast_oversize_lists: u32,
    /// Multicast destinations dropped from a list for want of a route, the
    /// rest of the list still forwarded.
    ///
    /// **The quiet failure of multi-destination multicast**: delivery to one
    /// listener stops while every other listener in the same frame is served,
    /// so nothing else about the node looks wrong. Counted for exactly that
    /// reason.
    mcast_unroutable_dests: u32,
    /// Destination groups that could not be emitted because the shell's frame
    /// sink was full.
    ///
    /// Distinct from the two above: those are frames this node declined to
    /// route, this one is routing this node *decided* on and then could not
    /// carry out, which is why it is the one that warns.
    mcast_emit_overflows: u32,
}

impl<
    const MAX_ORIGINATORS: usize,
    const MAX_INTERFACES: usize,
    const MAX_MCAST_MEMBERS: usize,
    const MAX_LOCAL_MCAST: usize,
> BatmanEngine<MAX_ORIGINATORS, MAX_INTERFACES, MAX_MCAST_MEMBERS, MAX_LOCAL_MCAST>
{
    /// Create an engine for a node with address `self_ident` and empty routing,
    /// broadcast, multicast, and OGM-timer state.
    pub fn new(self_ident: Mac) -> Self {
        Self {
            self_ident,
            sequence_number: 0,
            broadcast_sequence_number: 0,
            originator_table: FnvIndexMap::new(),
            broadcast_seqno: FnvIndexMap::new(),
            local_mcast: HVec::new(),
            mcast_members: HVec::new(),
            ogm_timers: HVec::new(),
            keepalive: FnvIndexMap::new(),
            proven: FnvIndexMap::new(),
            seqno_resyncs: 0,
            ogm_refloods_suppressed: 0,
            proofs_swept: 0,
            challenged: FnvIndexMap::new(),
            require_proof: false,
            keepalive_timers: HVec::new(),
            topology_changed: false,
            relay_oversize_drops: 0,
            mcast_oversize_lists: 0,
            mcast_unroutable_dests: 0,
            mcast_emit_overflows: 0,
        }
    }

    /// Allocate the next sequence number for a broadcast this node originates.
    /// Wraps at `u32::MAX`, matching the OGM sequence allocation.
    pub fn next_broadcast_seqno(&mut self) -> u32 {
        self.broadcast_sequence_number = self.broadcast_sequence_number.wrapping_add(1);
        self.broadcast_sequence_number
    }

    /// Number of relayed frames dropped because they didn't fit the egress
    /// `reply` buffer.  A non-zero, growing value signals an MTU mismatch
    /// between two of this node's links.
    pub fn relay_oversize_drops(&self) -> u32 {
        self.relay_oversize_drops
    }

    /// Multicast frames refused for a destination list past
    /// [`MAX_MCAST_DESTS`]. See [`mcast_oversize_lists`](Self::mcast_oversize_lists).
    pub fn mcast_oversize_lists(&self) -> u32 {
        self.mcast_oversize_lists
    }

    /// Multicast destinations dropped for want of a route — the quiet failure
    /// of multi-destination multicast.
    pub fn mcast_unroutable_dests(&self) -> u32 {
        self.mcast_unroutable_dests
    }

    /// Destination groups this node routed but could not emit, the shell's
    /// frame sink being full.
    pub fn mcast_emit_overflows(&self) -> u32 {
        self.mcast_emit_overflows
    }
}
