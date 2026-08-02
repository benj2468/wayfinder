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
//! # Third-party crates log through `log`, not `tracing`
//!
//! Only wayfinder's own crates use `tracing`. The third-party embedded crates
//! ([`embassy-nrf`] and the rest of `embassy-*`, [`nrf-softdevice`]) log through
//! the embassy `fmt.rs` facade, which emits `defmt` or `log` records depending
//! on which of those two features is enabled — and *nothing at all* when
//! neither is, which is why their diagnostics are invisible by default.
//!
//! [`init`] therefore also installs a `log` sink on the same RTT channel, so
//! enabling those crates' `log` feature surfaces their records alongside the
//! mesh stack's own. Their `defmt` feature is deliberately *not* used: `defmt`
//! defers formatting to a host decoder holding the ELF, so its records cannot be
//! rendered to text on-device, and its `defmt-rtt` transport defines a second
//! `_SEGGER_RTT` control block that collides with [`rtt-target`]'s — a probe
//! finds only one of the two.
//!
//! [`embassy-nrf`]: https://docs.rs/embassy-nrf
//! [`nrf-softdevice`]: https://github.com/embassy-rs/nrf-softdevice
//!
//! On non-bare-metal targets (a host build/test of the workspace) [`init`] is a
//! no-op, so this crate stays a host-buildable workspace member without pulling
//! an RTT backend it couldn't link.
//!
//! [`tracing`]: https://docs.rs/tracing
//! [`rtt-target`]: https://docs.rs/rtt-target
//! [`tracing-core`]: https://docs.rs/tracing-core
#![cfg_attr(not(test), no_std)]

// Host builds compile the formatter for its unit tests but link no transport,
// so every `LineBuf` method is unused there.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
mod fmt;
#[cfg(target_os = "none")]
mod rtt;

/// Install the global sinks that write `tracing` events and `log` records to
/// RTT.
///
/// Call once, early in `main`, before the first event. On the boards this
/// initializes the RTT channel, registers the `tracing` subscriber, and
/// registers the `log` logger (raising `log`'s max level, which defaults to
/// `Off`); the call is idempotent-safe (a second call, or a sink already set by
/// something else, is ignored rather than panicking). On non-bare-metal targets
/// this is a no-op.
pub fn init() {
    #[cfg(target_os = "none")]
    rtt::init();
}
