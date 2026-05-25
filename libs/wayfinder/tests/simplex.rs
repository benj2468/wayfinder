use std::{
    collections::{BTreeMap, HashMap},
    fmt::Display,
};

use runner::CentralRouter;

use interfaces::link::MeshIdentifier;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(Copy, PartialEq, Eq, Default, Clone, IntoBytes, FromBytes, Immutable, KnownLayout)]
struct Ident(u8);

impl MeshIdentifier for Ident {
    const BROADCAST: Self = Ident(0xff);
}

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
pub struct NodeId(u32);

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
pub enum Direction {
    ToSwitch,
    FromSwitch,
}

pub struct TapMeta<'a> {
    pub id: NodeId,
    pub direction: Direction,
    pub data: &'a [u8],
}

impl Display for TapMeta<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dir = match self.direction {
            Direction::ToSwitch => "to switch",
            Direction::FromSwitch => "from switch",
        };
        write!(
            f,
            "id={} direction={:?} data={:?}",
            self.id.0, dir, self.data
        )
    }
}

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
pub struct PairedNode {
    node_id: NodeId,
    direction: Direction,
}

#[derive(Default)]
pub struct Mesh {
    nodes: HashMap<PairedNode, tokio::io::DuplexStream>,
    taps: HashMap<NodeId, Vec<Box<dyn FnMut(TapMeta<'_>)>>>,
}

impl Mesh {
    pub fn add_node(&mut self) -> (NodeId, tokio::io::DuplexStream) {
        let id = NodeId(self.nodes.len() as u32);

        let (id, to_switch) = self.add_node_inner(id, Direction::ToSwitch);
        self.add_node_inner(id, Direction::FromSwitch);

        (id, to_switch)
    }

    fn add_node_inner(
        &mut self,
        id: NodeId,
        direction: Direction,
    ) -> (NodeId, tokio::io::DuplexStream) {
        let (to_switch, from_switch) = tokio::io::duplex(1);
        self.nodes.insert(
            PairedNode {
                node_id: id,
                direction,
            },
            from_switch,
        );
        (id, to_switch)
    }

    fn add_tap(&mut self, node_id: NodeId, tap: impl FnMut(TapMeta<'_>) + 'static) {
        self.taps.entry(node_id).or_default().push(Box::new(tap));
    }

    pub fn tick(&mut self) {
        for (node_id, stream) in &mut self.nodes {
            // Poll every message off the stream
        }
    }
}
