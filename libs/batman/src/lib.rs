#![cfg_attr(not(test), no_std)]

mod engine;
pub mod trickle;
pub mod wire;

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

/// Track metrics for a specific path to an originator via a specific immediate neighbor
#[derive(Debug, Clone)]
pub struct NeighborStats {
    pub neighbor_ident: Mac,
    pub last_tq: u8,
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
    pub neighbor_ident: Mac,
    pub best_next_hop: Mac,
    pub max_tq: u8,
    pub last_seqno: u32,
    // Track stats per neighbor routing path to this originator
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

pub struct BatmanEngine<const MAX_ORIGINATORS: usize> {
    pub self_ident: Mac,
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
    /// Latched whenever this engine's view of the topology changes (a new
    /// originator, a changed best next hop, a changed multicast membership, or a
    /// purged route).  Consumed at the end of OGM processing and of
    /// [`produce_periodic_broadcast`] to reset every Trickle timer back to its
    /// `i_min`, so the node re-announces promptly after any change.
    ///
    /// [`produce_periodic_broadcast`]: interfaces::engine::MeshRoutingEngine::produce_periodic_broadcast
    topology_changed: bool,
}

impl<const MAX_ORIGINATORS: usize> BatmanEngine<MAX_ORIGINATORS> {
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
            topology_changed: false,
        }
    }

    /// Allocate the next sequence number for a broadcast this node originates.
    /// Wraps at `u32::MAX`, matching the OGM sequence allocation.
    pub fn next_broadcast_seqno(&mut self) -> u32 {
        self.broadcast_sequence_number = self.broadcast_sequence_number.wrapping_add(1);
        self.broadcast_sequence_number
    }
}
