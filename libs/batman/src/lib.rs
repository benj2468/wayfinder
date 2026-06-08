#![cfg_attr(not(test), no_std)]

mod engine;
pub mod wire;

#[cfg(test)]
mod engine_tests;

use core::time::Duration;

use heapless::Vec as HVec;
use heapless::index_map::FnvIndexMap;
use interfaces::frame::Mac;

/// Maximum number of multicast groups this node's local host can join at once.
pub const MAX_LOCAL_MCAST: usize = 16;
/// Maximum number of `(group, listener-originator)` memberships tracked across
/// the whole mesh.  Bounds the footprint for embedded targets.
pub const MAX_MCAST_MEMBERS: usize = 64;

/// How long a path (or a whole originator) may go without a refreshing OGM
/// before it is treated as dead: ignored when choosing a next hop and evicted
/// by the periodic sweep.  At the default ~10 s OGM interval this tolerates a
/// handful of consecutive misses before a route is dropped.
pub const ORIGINATOR_TIMEOUT: Duration = Duration::from_secs(60);

/// Track metrics for a specific path to an originator via a specific immediate neighbor
#[derive(Debug, Clone)]
pub struct NeighborStats {
    pub neighbor_ident: Mac,
    pub last_tq: u8,
    pub last_seqno: u32,
    /// Instant (on the engine's clock) of the most recent OGM that refreshed
    /// this path.  A path whose `rx_time` is older than [`ORIGINATOR_TIMEOUT`]
    /// is stale: its neighbor has gone quiet, so it is skipped when selecting a
    /// next hop and pruned by [`BatmanEngine::purge_stale`].
    pub rx_time: Duration,
}

/// A destination node in the mesh network
#[derive(Debug, Clone)]
pub struct OriginatorRecord {
    /// Instant of the most recent OGM accepted for this originator via *any*
    /// path (i.e. the freshest of its [`NeighborStats::rx_time`]).  When this is
    /// older than [`ORIGINATOR_TIMEOUT`] the originator has been heard from on
    /// no path and the whole record is evicted.
    pub rx_time: Duration,
    pub neighbor_ident: Mac,
    pub best_next_hop: Mac,
    pub max_tq: u8,
    pub last_seqno: u32,
    // Track stats per neighbor routing path to this originator
    pub paths: HVec<NeighborStats, 4>,
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
        }
    }

    /// Allocate the next sequence number for a broadcast this node originates.
    /// Wraps at `u32::MAX`, matching the OGM sequence allocation.
    pub fn next_broadcast_seqno(&mut self) -> u32 {
        self.broadcast_sequence_number = self.broadcast_sequence_number.wrapping_add(1);
        self.broadcast_sequence_number
    }
}
