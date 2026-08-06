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

/// Fallback expected keep-alive interval used to seed a freshly-heard
/// neighbor's miss budget before a second heartbeat provides a real gap to
/// measure, and whenever no interface has a keep-alive schedule configured.
/// Mirrors [`DEFAULT_OGM_INTERVAL`]'s role for the OGM path.
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

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
    /// neighbor_ident` is precisely the test for "reachable directly", which
    /// is how `CentralRouter::neighbor_count` counts one-hop neighbors.
    pub neighbor_ident: Mac,
    /// The next-hop MAC that packets for this originator are forwarded to —
    /// the immediate neighbor of the best path.
    pub best_next_hop: Mac,
    /// The highest transmission quality (0..=255) among all known paths to this
    /// originator; the metric the best next hop is chosen by.
    pub max_tq: u8,
    /// Sequence number of the most recent OGM accepted for this originator via
    /// any path.
    pub last_seqno: u32,
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
    /// [`OriginatorRecord::last_seqno`].  An entry is created on first sight
    /// of an originator's broadcast; the table is bounded at `MAX_ORIGINATORS`
    /// and further originators are dropped once it is full.
    pub broadcast_seqno: HVec<(Mac, u32), MAX_ORIGINATORS>,
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
            broadcast_seqno: HVec::new(),
            local_mcast: HVec::new(),
            mcast_members: HVec::new(),
            ogm_timers: HVec::new(),
            keepalive: FnvIndexMap::new(),
            keepalive_timers: HVec::new(),
            topology_changed: false,
            relay_oversize_drops: 0,
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
}
