mod driver;
mod router_tests;
pub mod switch;
pub mod test_router;

#[derive(Hash, PartialEq, Eq, Clone, Copy, Debug)]
pub enum Direction {
    ToSwitch,
    FromSwitch,
}
