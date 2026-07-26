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
//! - [`AndroidBleLink`] (`android` feature) — generic over a
//!   platform-supplied [`BleAdvertiser`], for a future JNI-hosted Android
//!   node; see `android_link.rs`.
//!
//! None is on by default: the crate's own default build is the
//! host-testable framing logic alone.
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

#[cfg(feature = "std")]
mod std_link;

#[cfg(feature = "std")]
pub use std_link::BleLinkParams;
#[cfg(feature = "std")]
pub use std_link::StdBleLink;

#[cfg(feature = "android")]
mod android_link;

#[cfg(feature = "android")]
pub use android_link::AndroidBleLink;
#[cfg(feature = "android")]
pub use android_link::AndroidBleReportSink;
#[cfg(feature = "android")]
pub use android_link::BleAdvertiser;

pub use error::BleError;
