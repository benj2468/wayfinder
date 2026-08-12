//! A `std`/`tokio` driver for a Wayfinder mesh node.
//!
//! The driver owns the router event loop and is deliberately transport-agnostic:
//! the local host device and every mesh interface are [`FrameIo`] carriers, so
//! the *same* loop runs against real sockets in production (a TAP plus UDP/Unix
//! links) and against in-process channels in tests.  See [`Driver`] for the two
//! ways to drive it.
//!
//! The transport-agnostic surface ([`FrameIo`], [`McastSnooper`]) is always
//! available; the tokio event loop, the concrete `tokio::net` transports, and
//! the link-building helpers are gated behind the (default) `tokio` feature.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod raw;
mod snoop;
mod transport;

pub use snoop::McastSnooper;
pub use transport::FrameIo;

#[cfg(feature = "ble")]
mod blue;
#[cfg(feature = "tokio")]
mod driver;
#[cfg(feature = "tokio")]
mod net;
#[cfg(feature = "tokio")]
mod rylr998;

#[cfg(feature = "ble")]
pub use blue::build_ble_link;
#[cfg(feature = "tokio")]
pub use driver::Driver;
#[cfg(feature = "tokio")]
pub use net::UdpMultiLink;
#[cfg(feature = "tokio")]
pub use net::build_udp_link;
#[cfg(feature = "tokio")]
pub use net::build_udp_multi_link;
// Re-exported so a node assembling a BLE link configures it without taking a
// direct `blue` dependency, matching how `Rylr998LinkParams` is surfaced.
#[cfg(feature = "ble")]
pub use ::blue::BleLinkParams;
#[cfg(feature = "tokio")]
pub use raw::RawL2Link;
#[cfg(feature = "tokio")]
pub use raw::build_raw_ip_link;
#[cfg(feature = "tokio")]
pub use raw::build_raw_l2_link;
#[cfg(feature = "tokio")]
pub use rylr998::Rylr998LinkParams;
#[cfg(feature = "tokio")]
pub use rylr998::build_rylr998_link;
#[cfg(feature = "tokio")]
pub use transport::Link;
// The mesh-interface trait now lives in `wayfinder`; re-export it (and the
// `dynosaur`-generated `DynLinkT` dynamic-dispatch wrapper) so callers keep
// importing it from the driver.
#[cfg(feature = "tokio")]
pub use wayfinder::link::DynLinkT;
pub use wayfinder::link::LinkT;
pub use wayfinder::link::Received;

// Re-export the management-server wiring so callers configure the driver's
// query path without depending on `wayfinder-server` directly.
#[cfg(feature = "tokio")]
pub use wayfinder_server::AuthSnapshot;
#[cfg(feature = "tokio")]
pub use wayfinder_server::AuthSnapshotRx;
#[cfg(feature = "tokio")]
pub use wayfinder_server::AuthSnapshotTx;
#[cfg(feature = "tokio")]
pub use wayfinder_server::ChannelServerRx;
#[cfg(feature = "tokio")]
pub use wayfinder_server::ChannelServerTx;
#[cfg(feature = "tokio")]
pub use wayfinder_server::QueryRx;
#[cfg(feature = "tokio")]
pub use wayfinder_server::QueryTx;
#[cfg(feature = "tokio")]
pub use wayfinder_server::bind_tcp_server;
#[cfg(feature = "tokio")]
pub use wayfinder_server::run_channel_server;
#[cfg(feature = "tokio")]
pub use wayfinder_server::serve_tls_server;
