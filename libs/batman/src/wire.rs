use interfaces::link::MeshIdentifier;
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
