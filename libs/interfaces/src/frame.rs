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

impl MeshIdentifier for [u8; 6] {
    const BROADCAST: Self = [0xff; 6];
}

/// A unified link-layer frame passed around your central router
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(C, packed)]
pub struct LinkFrame<Ident> {
    pub src: Ident,
    pub dst: Ident,
    pub protocol: u16, // Equivalent to EtherType (e.g., 0x4305 for BATMAN)
    pub payload: [u8],
}

/// Data that a sender must construct when sending a packet. This is the same as LinkFrame, except is
/// doesn't include the src, because that is applied by the link layer.
#[derive(Debug)]
pub struct LinkFrameData<'a, Ident> {
    pub dst: Ident,
    pub protocol: u16,
    pub payload: &'a [u8],
}

pub struct LinkFrameDataMut<'a, Ident> {
    pub dst: Ident,
    pub protocol: u16,
    pub payload: &'a mut [u8],
}

impl<'a, Ident> From<LinkFrameDataMut<'a, Ident>> for LinkFrameData<'a, Ident> {
    fn from(value: LinkFrameDataMut<'a, Ident>) -> Self {
        Self {
            dst: value.dst,
            protocol: value.protocol,
            payload: value.payload,
        }
    }
}

impl<'a, Ident> From<&'a mut [u8]> for LinkFrameDataMut<'a, Ident>
where
    Ident: Default,
{
    fn from(value: &'a mut [u8]) -> Self {
        Self {
            dst: Ident::default(),
            protocol: 0,
            payload: value,
        }
    }
}
