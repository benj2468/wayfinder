//! Core abstractions shared by every layer of the mesh stack.
//!
//! These are the traits and types the protocol, engine, router, and driver
//! layers all speak: the [`frame`] link-layer frame and node-address ([`Mac`]),
//! the [`engine`] routing-engine trait and its action enum, and the [`link`]
//! per-frame metrics and error types. The crate is `no_std` (except under
//! `test`) so the same definitions compile for embedded and host builds.
//!
//! [`Mac`]: frame::Mac
#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// The routing-engine trait ([`MeshRoutingEngine`](engine::MeshRoutingEngine))
/// and its [`RoutingAction`](engine::RoutingAction) result.
pub mod engine;
/// The zero-copy link-layer frame ([`LinkFrame`](frame::LinkFrame)) and the
/// node-address type ([`Mac`](frame::Mac)).
pub mod frame;
/// Per-frame link measurements ([`LinkMetrics`](link::LinkMetrics)) and the
/// link-layer error type ([`LinkError`](link::LinkError)).
pub mod link;
