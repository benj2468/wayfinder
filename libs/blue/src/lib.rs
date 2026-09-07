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
//! - `StdBleLink` (`std` feature, Linux hosts only) — a Linux host's
//!   controller via BlueZ's D-Bus API, for `bins/wayfinder-tap`. BlueZ has no
//!   counterpart on other operating systems, so on a non-Linux host the `std`
//!   feature builds everything here *except* this backend.
//!
//! `StdBleLink` builds on [`BleLink`], generic over a platform-supplied
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
mod mode;

// Exported in every configuration, like `BleAddr`: `BleAdvFormat` appears in
// `BleAdvertiser::advertise`'s signature and `BleSendMode` is plain
// configuration both backends read, so gating either would leave them
// unnameable on one target or the other.
pub use mode::BleAdvFormat;
pub use mode::BleSendMode;

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
// Exported in every configuration: it appears in
// `BleReportSink::submit`/`RawReport::new`, so gating it would leave those
// signatures unnameable. No longer the reassembly key — see `addr`'s module
// doc comment.
pub use addr::BleAddr;

// The BlueZ backend is Linux-only — `bluer` speaks D-Bus to `bluetoothd` and
// `compile_error!`s on any other OS (its `libc` constants don't exist there
// either), so the dependency is target-gated in `Cargo.toml` and the module
// with it. Everything else under `std` — the generic `BleLink` core, the AD
// framing, the fragmentation — is portable and keeps building and testing on
// a macOS host, which is the point of gating this narrowly rather than
// switching off `std` wholesale.
#[cfg(all(feature = "std", target_os = "linux"))]
mod std_link;

#[cfg(all(feature = "std", target_os = "linux"))]
pub use std_link::StdBleLink;

// Deliberately *not* target-gated: `BleLinkParams` is plain configuration, so
// a host node's config types and CLI plumbing still name it on a platform
// where the link itself can't be built.
#[cfg(feature = "std")]
mod params;

#[cfg(feature = "std")]
pub use params::BleLinkParams;

pub use error::BleError;
