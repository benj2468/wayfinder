//! The Wayfinder management-API server.
//!
//! The crate splits into two layers:
//!
//! * [`RouterAdapter`] — a `no_std` + `alloc` adapter that exposes a borrowed
//!   [`wayfinder::CentralRouter`] through the management-API
//!   [`WayfinderDataProvider`](wayfinder_protos::service::WayfinderDataProvider)
//!   trait. This is the part embedded callers can reuse without a runtime.
//! * the transport layer (gated behind the `std` feature) — the per-transport
//!   listener loops (TCP, Unix datagram, UDP) and the [`QueryTx`]/[`QueryRx`]
//!   channel they use to forward queries to a single-threaded router loop so the
//!   router is never shared across tasks.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

extern crate alloc;

mod adapter;
pub use adapter::RouterAdapter;

mod authz;
pub use authz::{MgmtAccess, MgmtDenied, authorize_admin, decide_access};

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
pub use transport::{
    AuthContext, AuthSnapshot, AuthSnapshotRx, AuthSnapshotTx, ChannelRequest, ChannelServerRx,
    ChannelServerTx, QueryRx, QueryTx, bind_tcp_server, run_channel_server,
    serve_authenticated_stream, serve_tls_server,
};
