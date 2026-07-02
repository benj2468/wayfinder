#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod driver;
pub mod switch;
pub mod test_router;

pub mod prelude {
    pub use super::driver::{TestConfig, TestHarness, TestMachineConfig, TestSwitchConfig, mac};
    pub use super::test_router::{TestRouter, build_frame, host_frame};
}

#[cfg(test)]
mod integration_tests;

#[derive(Hash, PartialEq, Eq, Clone, Copy, Debug)]
pub enum Direction {
    ToSwitch,
    FromSwitch,
}
