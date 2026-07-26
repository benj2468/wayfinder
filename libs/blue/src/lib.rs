//! `LinkT` adapters carrying the mesh over Bluetooth Low Energy.
//!
//! Connectionless advertising broadcast only (no GATT/connections), matching
//! the fire-and-forget `LinkT` model used by the other radio drivers in this
//! workspace — see `libs/blue/CLAUDE.md`.
//!
//! Backends share one on-air format (`ad.rs`/`frame.rs`), so nodes on any of
//! them can talk to each other:
//!
//! - [`NrfBleLink`] (`hardware` feature) — the nRF52840's built-in 2.4 GHz
//!   radio via `nrf-softdevice`, `no_std`, for `bins/wayfinder-nrf52840`.
//! - [`StdBleLink`] (`std` feature) — a Linux host's controller via BlueZ's
//!   D-Bus API, for `bins/wayfinder-tap`.
//! - a UniFFI-hosted Android node (`android` feature), for
//!   `bins/wayfinder-pixel` — the UniFFI plumbing exists; the real hardware/
//!   scan-callback wiring on the Kotlin side is still a later phase.
//!
//! The latter two both build on [`BleLink`], generic over a
//! platform-supplied [`BleAdvertiser`]; see `generic_link.rs`.
//!
//! `std` is on by default (needed by `wayfinder-driver`'s host build, and it
//! pulls in `android` too); `wayfinder-pixel`'s NDK build opts into `android`
//! alone. Only `hardware` (real SoftDevice hardware, no host-side stub) is
//! off by default for every consumer.
#![cfg_attr(all(not(test), not(any(feature = "std", feature = "android"))), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod ad;
mod addr;
mod error;
mod frame;

#[cfg(feature = "hardware")]
mod nrf_link;

#[cfg(feature = "hardware")]
pub use nrf_link::NrfBleLink;

#[cfg(any(feature = "std", feature = "android"))]
mod generic_link;

#[cfg(any(feature = "std", feature = "android"))]
pub use generic_link::BleAdvertiser;
#[cfg(any(feature = "std", feature = "android"))]
pub use generic_link::BleLink;
#[cfg(any(feature = "std", feature = "android"))]
pub use generic_link::BleReportSink;

#[cfg(feature = "std")]
mod std_link;

#[cfg(feature = "std")]
pub use std_link::BleLinkParams;
#[cfg(feature = "std")]
pub use std_link::StdBleLink;

pub use error::BleError;
