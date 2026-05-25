use interfaces::link::MeshIdentifier;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

mod mesh;
mod tap;

/*
 * Identifier Types
 */

#[derive(Copy, PartialEq, Eq, Default, Clone, IntoBytes, FromBytes, Immutable, KnownLayout)]
struct Ident(u8);

impl MeshIdentifier for Ident {
    const BROADCAST: Self = Ident(0xff);
}

/*
 * Node Types
 */

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
pub struct NodeId(u32);

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
pub enum Direction {
    ToSwitch,
    FromSwitch,
}
