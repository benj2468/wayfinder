//! A minimal `tracing` subscriber for the wayfinder bare-metal boards.
//!
//! The mesh stack logs through [`tracing`] on every target, but a bare-metal
//! board has no subscriber installed by default, so `tracing`'s dispatcher
//! drops every record — the `trace!`/`warn!` calls in the shared router core,
//! embedded driver, and radio drivers produce no output on hardware. [`init`]
//! installs one that formats each event onto RTT (Real-Time Transfer), which a
//! host reads over the debug probe (e.g. `probe-rs rtt`). RTT is the boards'
//! only free channel — their one UART carries the LoRa radio.
//!
//! The subscriber is deliberately tiny and heap-free: each event renders into a
//! fixed stack buffer (spans are ignored beyond issuing ids), so it costs no
//! `alloc` beyond what `tracing-core`'s dispatcher already uses. It reuses the
//! maintained [`rtt-target`] (transport) and [`tracing-core`] (subscriber trait)
//! crates rather than reimplementing either.
//!
//! On non-bare-metal targets (a host build/test of the workspace) [`init`] is a
//! no-op, so this crate stays a host-buildable workspace member without pulling
//! an RTT backend it couldn't link.
//!
//! [`tracing`]: https://docs.rs/tracing
//! [`rtt-target`]: https://docs.rs/rtt-target
//! [`tracing-core`]: https://docs.rs/tracing-core
#![no_std]

#[cfg(target_os = "none")]
mod rtt;

/// Install the global `tracing` subscriber that writes events to RTT.
///
/// Call once, early in `main`, before the first `tracing` event. On the boards
/// this initializes the RTT channel and registers the subscriber; the call is
/// idempotent-safe (a second call, or a subscriber already set by something
/// else, is ignored rather than panicking). On non-bare-metal targets this is a
/// no-op.
pub fn init() {
    #[cfg(target_os = "none")]
    rtt::init();
}
