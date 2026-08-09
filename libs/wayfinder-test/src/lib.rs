//! Test-only harness for multi-node mesh integration tests — no hardware, no
//! executor, no wall clock.
//!
//! [`switch`] provides a `Switch` simulator that fans frames out between
//! connected nodes, [`test_router`] drives one node's `wayfinder-tick-driver`
//! over those ports **synchronously**, and [`driver`] assembles whole
//! multi-node topologies from a declarative config. The [`prelude`] re-exports
//! the common entry points.
//!
//! [`link_router`] is the exception: an async harness over the production
//! `wayfinder-driver` for the two suites that need a real `LinkT` (link I/O
//! error policy, and a real `RylrClient`), which the tick driver cannot host
//! because its interfaces are plain queues.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// Declarative multi-node test topologies ([`TestHarness`](driver::TestHarness))
/// built from a [`TestConfig`](driver::TestConfig).
pub mod driver;
/// The async [`LinkTestRouter`](link_router::LinkTestRouter), for the two
/// suites that need a real `LinkT` rather than the tick driver's queues.
pub mod link_router;
/// The in-process [`Switch`](switch::Switch) frame-fanout simulator.
pub mod switch;
/// The [`TestRouter`](test_router::TestRouter) wrapper around a `CentralRouter`.
pub mod test_router;

/// The common entry points for writing a mesh integration test.
pub mod prelude {
    pub use super::driver::TestConfig;
    pub use super::driver::TestHarness;
    pub use super::driver::TestMachineConfig;
    pub use super::driver::TestSwitchConfig;
    pub use super::driver::mac;
    pub use super::test_router::TestRouter;
    pub use super::test_router::build_frame;
    pub use super::test_router::host_frame;
}

#[cfg(test)]
mod integration_tests;

#[cfg(test)]
mod link_error_tests;

#[cfg(test)]
mod rylr998_integration_tests;

/// Which side of a switch connection a frame is travelling on, used to key the
/// switch's per-direction channels.
#[derive(Hash, PartialEq, Eq, Clone, Copy, Debug)]
pub enum Direction {
    /// A frame heading from a node into the switch.
    ToSwitch,
    /// A frame heading from the switch out to a node.
    FromSwitch,
}
