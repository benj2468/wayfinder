//! Library surface of the Wayfinder TUI, split out from the binary so the
//! rendering and snapshot logic can be exercised by integration tests.  The
//! management-API client now lives in the shared `wayfinder-client` crate.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod app;
pub mod persist;
pub mod ui;
