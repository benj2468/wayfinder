#![cfg_attr(not(test), no_std)]

mod engine;
pub mod wire;

#[cfg(test)]
mod engine_tests;

use heapless::Vec as HVec;

/// Track metrics for a specific path to an originator via a specific immediate neighbor
#[derive(Debug, Clone)]
pub struct NeighborStats<Ident> {
    pub neighbor_ident: Ident,
    pub last_tq: u8,
    pub last_seqno: u32,
}

/// A destination node in the mesh network
#[derive(Debug, Clone)]
pub struct OriginatorRecord<Ident> {
    pub neighbor_ident: Ident,
    pub best_next_hop: Ident,
    pub max_tq: u8,
    pub last_seqno: u32,
    // Track stats per neighbor routing path to this originator
    pub paths: HVec<NeighborStats<Ident>, 4>,
}

pub struct BatmanEngine<const MAX_ORIGINATORS: usize, Ident> {
    pub self_ident: Ident,
    pub sequence_number: u32,
    pub originator_table: HVec<OriginatorRecord<Ident>, MAX_ORIGINATORS>,
    /// Highest broadcast sequence number seen per originator, used to drop
    /// duplicate flooded broadcasts.  Broadcast and OGM sequence numbers are
    /// independent number spaces, so this is tracked separately from
    /// [`OriginatorRecord::last_seqno`].  An entry is created on first sight
    /// of an originator's broadcast; the table is bounded at `MAX_ORIGINATORS`
    /// and further originators are dropped once it is full.
    pub broadcast_seqno: HVec<(Ident, u32), MAX_ORIGINATORS>,
}

impl<const MAX_ORIGINATORS: usize, Ident> BatmanEngine<MAX_ORIGINATORS, Ident> {
    pub fn new(self_ident: Ident) -> Self {
        Self {
            self_ident,
            sequence_number: 0,
            originator_table: HVec::new(),
            broadcast_seqno: HVec::new(),
        }
    }
}
