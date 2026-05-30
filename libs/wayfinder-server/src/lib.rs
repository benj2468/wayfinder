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

extern crate alloc;

mod adapter;
pub use adapter::RouterAdapter;

#[cfg(feature = "std")]
mod transport;
#[cfg(feature = "std")]
pub use transport::{QueryRx, QueryTx, run_tcp_server, run_udp_server, run_unix_server};
