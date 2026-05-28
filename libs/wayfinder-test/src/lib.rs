pub mod switch;
mod router_tests;

#[derive(Hash, PartialEq, Eq, Clone, Copy, Debug)]
pub enum Direction {
    ToSwitch,
    FromSwitch,
}
