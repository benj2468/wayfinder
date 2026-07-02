//! Test-only harness for multi-node mesh integration tests over `tokio` mpsc
//! channels — no hardware required.
//!
//! [`switch`] provides a `Switch` simulator that fans frames out between
//! connected nodes, [`test_router`] wraps a `CentralRouter` with per-interface
//! egress channels, and [`driver`] assembles whole multi-node topologies from a
//! declarative config. The [`prelude`] re-exports the common entry points.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// Declarative multi-node test topologies ([`TestHarness`](driver::TestHarness))
/// built from a [`TestConfig`](driver::TestConfig).
pub mod driver;
/// The in-process [`Switch`](switch::Switch) frame-fanout simulator.
pub mod switch;
/// The [`TestRouter`](test_router::TestRouter) wrapper around a `CentralRouter`.
pub mod test_router;

/// The common entry points for writing a mesh integration test.
pub mod prelude {
    pub use super::driver::{TestConfig, TestHarness, TestMachineConfig, TestSwitchConfig, mac};
    pub use super::test_router::{TestRouter, build_frame, host_frame};
}

#[cfg(test)]
mod integration_tests;

/// Which side of a switch connection a frame is travelling on, used to key the
/// switch's per-direction channels.
#[derive(Hash, PartialEq, Eq, Clone, Copy, Debug)]
pub enum Direction {
    /// A frame heading from a node into the switch.
    ToSwitch,
    /// A frame heading from the switch out to a node.
    FromSwitch,
}
