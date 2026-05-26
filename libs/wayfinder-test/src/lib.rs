mod switch;

#[derive(Hash, PartialEq, Eq, Clone, Copy, Debug)]
pub enum Direction {
    ToSwitch,
    FromSwitch,
}
