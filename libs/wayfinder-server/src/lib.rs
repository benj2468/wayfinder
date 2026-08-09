//! The Wayfinder management-API server.
//!
//! The crate splits into three layers:
//!
//! * [`RouterAdapter`] — a `no_std` + `alloc` adapter that exposes a borrowed
//!   [`wayfinder::CentralRouter`] through the management-API
//!   [`WayfinderDataProvider`](wayfinder_protos::service::WayfinderDataProvider)
//!   trait. This is the part embedded callers can reuse without a runtime.
//! * the `std` transport layer (gated behind the `std` feature) — the
//!   authenticated TLS-over-TCP listener loop ([`bind_tcp_server`] /
//!   [`serve_tls_server`]), the in-process [`run_channel_server`], and the
//!   [`QueryTx`]/[`QueryRx`] channel they use to forward queries to a
//!   single-threaded router loop so the router is never shared across tasks.
//! * the embedded transport layer (gated behind the `embedded` feature,
//!   `no_std` + `alloc`) — length-delimited framing over an
//!   `embedded-io-async` byte stream (e.g. a UART), and the
//!   [`EmbeddedQueryTx`]/[`EmbeddedQueryRx`] `embassy-sync` channel + [`serve`]
//!   loop that play the same role as the `std` layer's listeners/channel.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

extern crate alloc;

mod adapter;
pub use adapter::RouterAdapter;

mod authz;
pub use authz::MgmtAccess;
pub use authz::MgmtDenied;
pub use authz::authorize_admin;
pub use authz::decide_access;

#[cfg(feature = "embedded")]
mod framing;
#[cfg(feature = "embedded")]
pub use framing::FrameError;
#[cfg(feature = "embedded")]
pub use framing::MAX_FRAME_LEN;
#[cfg(feature = "embedded")]
pub use framing::read_frame;
#[cfg(feature = "embedded")]
pub use framing::write_frame;

#[cfg(feature = "embedded")]
mod embedded;
#[cfg(feature = "embedded")]
pub use embedded::EmbeddedQueryChannel;
#[cfg(feature = "embedded")]
pub use embedded::EmbeddedQueryRx;
#[cfg(feature = "embedded")]
pub use embedded::EmbeddedQueryTx;
#[cfg(feature = "embedded")]
pub use embedded::serve;

#[cfg(feature = "std")]
mod tls;
#[cfg(feature = "std")]
pub use tls::server_config;

mod provider;
pub use provider::MeshAuthority;

#[cfg(feature = "std")]
mod persistence;

#[cfg(feature = "std")]
mod authority;
#[cfg(feature = "std")]
pub use authority::CertAuthority;

#[cfg(feature = "std")]
mod transport;
#[cfg(feature = "std")]
pub use transport::AuthContext;
#[cfg(feature = "std")]
pub use transport::AuthSnapshot;
#[cfg(feature = "std")]
pub use transport::AuthSnapshotRx;
#[cfg(feature = "std")]
pub use transport::AuthSnapshotTx;
#[cfg(feature = "std")]
pub use transport::ChannelRequest;
#[cfg(feature = "std")]
pub use transport::ChannelServerRx;
#[cfg(feature = "std")]
pub use transport::ChannelServerTx;
#[cfg(feature = "std")]
pub use transport::QueryRx;
#[cfg(feature = "std")]
pub use transport::QueryTx;
#[cfg(feature = "std")]
pub use transport::bind_tcp_server;
#[cfg(feature = "std")]
pub use transport::run_channel_server;
#[cfg(feature = "std")]
pub use transport::serve_authenticated_stream;
#[cfg(feature = "std")]
pub use transport::serve_tls_server;
