use core::fmt::Debug;
use core::hash::Hash;
use zerocopy::byteorder::network_endian::U16;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub trait MeshIdentifier:
    Copy
    + PartialEq
    + Eq
    + FromBytes
    + IntoBytes
    + Immutable
    + Default
    + KnownLayout
    + Hash
    + Debug
    + Send
    + Sync
{
    const BROADCAST: Self;
}

impl MeshIdentifier for u8 {
    const BROADCAST: Self = 0xff;
}

/// A 48-bit IEEE 802 MAC address — the mesh node identifier used everywhere
/// on the wire and in the routing engine.
///
/// A `#[repr(transparent)]` newtype over `[u8; 6]` so it has the exact byte
/// layout of a raw MAC address (and so `etherparse`'s `[u8; 6]` source/dest
/// fields convert for free via [`From`]).  The newtype exists to attach MAC
/// semantics — the [`is_multicast`](Mac::is_multicast) /
/// [`is_broadcast`](Mac::is_broadcast) helpers below — that the routing engine
/// and the multicast machinery rely on.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Default,
    Debug,
    FromBytes,
    IntoBytes,
    Immutable,
    KnownLayout,
    PartialOrd,
    Ord,
)]
#[repr(transparent)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    /// The all-ones (`ff:ff:ff:ff:ff:ff`) link-layer broadcast address.
    pub const BROADCAST: Mac = Mac([0xff; 6]);

    /// Whether this is a group address (multicast or broadcast), i.e. the
    /// I/G bit — the least-significant bit of the first octet — is set.
    /// Such frames are flooded or selectively forwarded across the mesh
    /// rather than routed to a single next hop.
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Whether this is the all-ones broadcast address specifically.  A
    /// broadcast is always also a multicast ([`is_multicast`](Mac::is_multicast)),
    /// but not vice versa.
    pub fn is_broadcast(&self) -> bool {
        *self == Mac::BROADCAST
    }

    /// Map an IPv4 multicast group address to its Ethernet MAC per RFC 1112:
    /// the `01:00:5e` prefix followed by the low 23 bits of the group address.
    /// Because only 23 of the group's 28 multicast bits map, groups differing
    /// only in the top bit of the second octet (e.g. `224.x` vs `224.128+x`)
    /// alias onto the same MAC.
    pub fn from_ipv4_multicast(group: core::net::Ipv4Addr) -> Mac {
        let o = group.octets();
        Mac([0x01, 0x00, 0x5e, o[1] & 0x7f, o[2], o[3]])
    }
}

impl From<[u8; 6]> for Mac {
    fn from(bytes: [u8; 6]) -> Self {
        Mac(bytes)
    }
}

impl From<Mac> for [u8; 6] {
    fn from(mac: Mac) -> Self {
        mac.0
    }
}

impl MeshIdentifier for Mac {
    const BROADCAST: Self = Mac::BROADCAST;
}

/// A unified link-layer frame passed around your central router.
///
/// The byte layout deliberately matches a real Ethernet frame —
/// `[dst][src][ethertype][payload]` — so a raw L2 carrier (`AF_PACKET`) can
/// reinterpret these bytes as an Ethernet frame with no conversion, and every
/// other transport carries the identical shape.  Hence `dst` precedes `src` and
/// `protocol` is stored big-endian (network byte order), exactly as an on-wire
/// EtherType.  Use [`U16::get`]/[`U16::new`] to read or set it as a host `u16`.
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(C, packed)]
pub struct LinkFrame {
    /// Destination node MAC (or [`Mac::BROADCAST`]) — first on the wire, as in
    /// Ethernet.
    pub dst: Mac,
    /// Source node MAC, stamped by the link layer on send.
    pub src: Mac,
    /// EtherType-style protocol identifier (e.g. `0x4305` for BATMAN), stored
    /// big-endian to match a real Ethernet frame's type field.
    pub protocol: U16,
    /// Variable-length frame payload.
    pub payload: [u8],
}

/// Data that a sender must construct when sending a packet. This is the same as LinkFrame, except is
/// doesn't include the src, because that is applied by the link layer.
#[derive(Debug)]
pub struct LinkFrameData<'a> {
    pub dst: Mac,
    pub protocol: u16,
    pub payload: &'a [u8],
}

#[derive(Debug)]
pub struct LinkFrameDataMut<'a> {
    pub dst: Mac,
    pub protocol: u16,
    pub payload: &'a mut [u8],
}

impl<'a> From<LinkFrameDataMut<'a>> for LinkFrameData<'a> {
    fn from(value: LinkFrameDataMut<'a>) -> Self {
        Self {
            dst: value.dst,
            protocol: value.protocol,
            payload: value.payload,
        }
    }
}

impl<'a> From<&'a mut [u8]> for LinkFrameDataMut<'a> {
    fn from(value: &'a mut [u8]) -> Self {
        Self {
            dst: Mac::default(),
            protocol: 0,
            payload: value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv4Addr;

    /// An IPv4 multicast group maps to a `01:00:5e`-prefixed MAC whose low 23
    /// bits come from the group address (RFC 1112): the top bit of the second
    /// octet is masked off, so `239.1.1.1` and `239.129.1.1` collide onto the
    /// same MAC.
    #[test]
    fn ipv4_multicast_maps_to_01005e_mac() {
        assert_eq!(
            Mac::from_ipv4_multicast(Ipv4Addr::new(239, 1, 1, 1)),
            Mac([0x01, 0x00, 0x5e, 0x01, 0x01, 0x01])
        );
        assert_eq!(
            Mac::from_ipv4_multicast(Ipv4Addr::new(224, 0, 0, 22)),
            Mac([0x01, 0x00, 0x5e, 0x00, 0x00, 0x16])
        );
        // The high bit of the second octet is dropped (only 23 bits map).
        assert_eq!(
            Mac::from_ipv4_multicast(Ipv4Addr::new(239, 129, 1, 1)),
            Mac([0x01, 0x00, 0x5e, 0x01, 0x01, 0x01])
        );
    }
}
