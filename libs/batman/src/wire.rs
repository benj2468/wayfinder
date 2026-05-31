use interfaces::frame::Mac;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const ETH_P_BATMAN: u16 = 0x4305;

// Core BATMAN packet identifiers
pub const BATADV_IV_OGM: u8 = 0x01;

/// Originator Message header, laid out to match batman-adv's
/// `batadv_ogm_packet`.  A variable-length TVLV region of `tvlv_len` bytes
/// (a sequence of [`BatmanTvlvHdr`]-prefixed records) follows this fixed
/// header on the wire; it carries piggybacked announcements such as
/// multicast group memberships.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
#[repr(C, packed)]
pub struct BatmanOgmPacket {
    /// Always [`BATADV_IV_OGM`] for this packet type.
    pub packet_type: u8,
    /// Protocol version (typically 5).
    pub version: u8,
    /// Time-to-live, decremented at each hop to bound flood radius.
    pub ttl: u8,
    /// Reserved flag bits (batman-adv `BATADV_*_FLAG`); unused here, sent as 0.
    pub flags: u8,
    /// Sequence number (network byte order / big endian).
    pub seqno: u32,
    /// The node that originally generated this message.
    pub orig: Mac,
    /// The immediate neighbor who relayed it to us.
    pub prev_sender: Mac,
    /// Reserved padding byte, matching the batman-adv layout; sent as 0.
    pub reserved: u8,
    /// Transmission Quality metric of the path (0..=255).
    pub tq: u8,
    /// Length in bytes of the TVLV region that follows this header
    /// (network byte order / big endian).  Zero when no TVLV is attached.
    pub tvlv_len: u16,
}

/// Header prefixing one record in an OGM's TVLV (Type-Version-Length-Value)
/// region, matching batman-adv's `batadv_tvlv_hdr`.  The `len` bytes of value
/// follow immediately; records are packed back-to-back to fill `tvlv_len`.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
#[repr(C, packed)]
pub struct BatmanTvlvHdr {
    /// What the value encodes (e.g. [`BATADV_TVLV_MCAST`]).
    pub tvlv_type: u8,
    /// Version of this TVLV type's value format.
    pub version: u8,
    /// Length of the value following this header, in bytes (big endian).
    pub len: u16,
}

/// TVLV type identifying a multicast-membership announcement, matching
/// batman-adv's `BATADV_TVLV_MCAST`.  Its value is the list of multicast
/// group MAC addresses the originating node currently listens for.
pub const BATADV_TVLV_MCAST: u8 = 0x06;

/// Scan a TVLV region (`tail`, the bytes following an OGM's fixed header) for
/// the first record of type `tvlv_type` and return its value bytes, or `None`
/// if absent or malformed.  Records are `[`[`BatmanTvlvHdr`]`][value]` packed
/// back-to-back; a record whose advertised length runs past the end of `tail`
/// terminates the scan.
pub fn find_tvlv(tail: &[u8], tvlv_type: u8) -> Option<&[u8]> {
    let hdr_size = core::mem::size_of::<BatmanTvlvHdr>();
    let mut off = 0;
    while off + hdr_size <= tail.len() {
        let (hdr, _) = BatmanTvlvHdr::ref_from_prefix(&tail[off..]).ok()?;
        let len = u16::from_be(hdr.len) as usize;
        let value_start = off + hdr_size;
        let value_end = value_start.checked_add(len)?;
        if value_end > tail.len() {
            return None; // record claims more bytes than the tail holds
        }
        if hdr.tvlv_type == tvlv_type {
            return tail.get(value_start..value_end);
        }
        off = value_end;
    }
    None
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
pub struct BatmanBroadcastPacket {
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
    pub orig: Mac,
}

pub const BATADV_UNICAST: u8 = 0x03;

/// Packet sub-type for a selectively-forwarded multicast frame, mirroring
/// batman-adv's `batadv_mcast_packet`.  A multicast frame with a bounded set
/// of interested listeners is delivered as one [`BatmanMcastPacket`] per
/// listener, each addressed to that listener's node and routed toward it like
/// a unicast.  Kept distinct from [`BATADV_UNICAST`] so multicast traffic
/// stays identifiable on the wire.
pub const BATADV_MCAST: u8 = 0x04;

/// Header for a [`BATADV_MCAST`] packet.  Structurally a unicast header: the
/// encapsulated multicast frame follows it, and the packet is routed hop by
/// hop toward `dest` (the listener node this copy targets), TTL-limited to
/// prevent loops, and delivered to the local host on arrival at `dest`.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct BatmanMcastPacket {
    /// Always [`BATADV_MCAST`].
    pub packet_type: u8,
    /// Protocol version.
    pub version: u8,
    /// Time-to-live, decremented per hop to bound routing loops.
    pub ttl: u8,
    /// The listener node this copy is addressed to (final destination).
    pub dest: Mac,
}

#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct BatmanUnicastPacket {
    pub packet_type: u8, // Always BATADV_UNICAST
    pub version: u8,     // Protocol version
    pub ttl: u8,         // Time-to-live to prevent routing loops for data
    pub dest: Mac,       // The FINAL destination node address in the mesh
}
