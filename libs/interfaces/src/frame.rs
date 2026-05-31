use core::fmt::Debug;
use core::hash::Hash;
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
    Clone, Copy, PartialEq, Eq, Hash, Default, Debug, FromBytes, IntoBytes, Immutable, KnownLayout,
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

/// A unified link-layer frame passed around your central router
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(C, packed)]
pub struct LinkFrame {
    pub src: Mac,
    pub dst: Mac,
    pub protocol: u16, // Equivalent to EtherType (e.g., 0x4305 for BATMAN)
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
