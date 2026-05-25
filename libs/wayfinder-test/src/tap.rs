use crate::Direction;
use crate::NodeId;
use std::fmt::Display;

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
