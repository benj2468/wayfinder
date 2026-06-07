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

mod raw;
mod snoop;
mod transport;

pub use snoop::McastSnooper;
pub use transport::FrameIo;

#[cfg(feature = "tokio")]
mod driver;
#[cfg(feature = "tokio")]
mod net;

#[cfg(feature = "tokio")]
pub use driver::Driver;
#[cfg(feature = "tokio")]
pub use net::build_udp_link;
#[cfg(feature = "tokio")]
pub use raw::{RawL2Link, build_raw_ip_link, build_raw_l2_link};
#[cfg(feature = "tokio")]
pub use transport::Link;
// The mesh-interface trait now lives in `wayfinder`; re-export it (and the
// `dynosaur`-generated `DynLinkT` dynamic-dispatch wrapper) so callers keep
// importing it from the driver.
#[cfg(feature = "tokio")]
pub use wayfinder::link::DynLinkT;
pub use wayfinder::link::{LinkT, Received};

// Re-export the management-server wiring so callers configure the driver's
// query path without depending on `wayfinder-server` directly.
#[cfg(feature = "tokio")]
pub use wayfinder_server::{
    ChannelServerRx, ChannelServerTx, QueryRx, QueryTx, run_channel_server, run_tcp_server,
    run_udp_server, run_unix_server,
};
