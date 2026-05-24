mod engine;
mod wire;

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
    // Buffer used to hold outgoing OGM payloads safely
    pub tx_buffer: [u8; 32],
}

impl<const MAX_ORIGINATORS: usize, Ident> BatmanEngine<MAX_ORIGINATORS, Ident> {
    pub fn new(self_ident: Ident) -> Self {
        Self {
            self_ident,
            sequence_number: 0,
            originator_table: HVec::new(),
            tx_buffer: [0u8; 32],
        }
    }
}
