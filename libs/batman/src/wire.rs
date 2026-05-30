use interfaces::frame::MeshIdentifier;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const ETH_P_BATMAN: u16 = 0x4305;

// Core BATMAN packet identifiers
pub const BATADV_IV_OGM: u8 = 0x01;

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
#[repr(C, packed)]
pub struct BatmanOgmPacket<Ident: MeshIdentifier> {
    pub packet_type: u8,    // Always BATADV_IV_OGM for this baseline
    pub version: u8,        // Protocol version (typically 5)
    pub ttl: u8,            // Time-to-live to prevent infinite loops
    pub tq: u8,             // Transmission Quality metric of the path
    pub seqno: u32,         // Sequence number (Network Byte Order / Big Endian)
    pub orig: Ident,        // The node that originally generated this message
    pub prev_sender: Ident, // The immediate neighbor who relayed it to us
}

/// Packet sub-type for a flooded broadcast frame.  Matches batman-adv's
/// `BATADV_BCAST`.  Used to carry broadcast/multicast link-layer frames
/// (e.g. ARP) across the mesh, deduplicated and TTL-limited so they reach
/// every node exactly once without looping.
pub const BATADV_BCAST: u8 = 0x02;

/// Header for a broadcast frame flooded across the mesh.
///
/// The encapsulated link-layer frame (the thing actually being broadcast,
/// e.g. an ARP request) immediately follows this header on the wire.  A node
/// floods a broadcast by re-transmitting it with `ttl` decremented, dropping
/// it once `ttl` reaches 1 or once it has already seen this `(orig, seqno)`
/// pair — see the broadcast handling in the engine.  Unlike the OGM there is
/// no `prev_sender`: only the originator and sequence number are needed for
/// duplicate suppression.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
#[repr(C, packed)]
pub struct BatmanBroadcastPacket<Ident: MeshIdentifier> {
    /// Always [`BATADV_BCAST`] for this packet type.
    pub packet_type: u8,
    /// Protocol version (typically 5), matching the OGM/unicast convention.
    pub version: u8,
    /// Time-to-live, decremented at each hop to bound the flood radius and
    /// prevent broadcast storms on cyclic topologies.
    pub ttl: u8,
    /// Per-originator sequence number in network byte order (big endian).
    /// Combined with `orig` it uniquely identifies a broadcast so that
    /// duplicate copies arriving via different paths are dropped.
    pub seqno: u32,
    /// The node that originally generated this broadcast.  Preserved
    /// unchanged as the frame is re-flooded so every node deduplicates
    /// against the true source rather than the immediate relay.
    pub orig: Ident,
}

pub const BATADV_UNICAST: u8 = 0x03;

#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct BatmanUnicastPacket<Ident: MeshIdentifier> {
    pub packet_type: u8, // Always BATADV_UNICAST
    pub version: u8,     // Protocol version
    pub ttl: u8,         // Time-to-live to prevent routing loops for data
    pub dest: Ident,     // The FINAL destination node address in the mesh
}
