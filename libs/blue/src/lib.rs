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
//!
//! [`StdBleLink`] builds on [`BleLink`], generic over a platform-supplied
//! [`BleAdvertiser`]; see `generic_link.rs`.
//!
//! `std` is on by default (needed by `wayfinder-driver`'s host build). Only
//! `hardware` (real SoftDevice hardware, no host-side stub) is off by
//! default for every consumer.
#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod ad;
mod addr;
mod error;
mod frame;

#[cfg(feature = "hardware")]
mod nrf_link;

#[cfg(feature = "hardware")]
pub use nrf_link::NrfBleLink;

#[cfg(feature = "generic")]
mod generic_link;

#[cfg(feature = "generic")]
pub use generic_link::BleAdvertiser;
#[cfg(feature = "generic")]
pub use generic_link::BleLink;
#[cfg(feature = "generic")]
pub use generic_link::BleReportSink;
// Exported in every configuration: it is the reassembly key both backends
// share, and it appears in `BleReportSink::submit`/`RawReport::new`, so
// gating it would leave those signatures unnameable.
pub use addr::BleAddr;

#[cfg(feature = "std")]
mod std_link;

#[cfg(feature = "std")]
pub use std_link::BleLinkParams;
#[cfg(feature = "std")]
pub use std_link::StdBleLink;

pub use error::BleError;
