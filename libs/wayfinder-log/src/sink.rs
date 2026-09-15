//! The bare-metal **text sink**: where a rendered log line is written, and the
//! only part of [`crate::bare`] that differs between boards.
//!
//! Two `no_std` targets in this repo want different transports and neither can
//! serve the other. The Cortex-M boards write to RTT, which a debug probe reads
//! over SWD. The ESP32 has no probe in its bring-up at all — it is flashed over
//! a USB-serial bridge on UART0 — so RTT there would render every record into a
//! control block nobody ever reads, which is indistinguishable from logging
//! being broken.
//!
//! So the transport is a feature, not a `cfg(target_os = "none")`: that `cfg`
//! stopped being the discriminator the moment there were two bare-metal
//! targets. Everything above this module — the subscriber, the `log` bridge,
//! the filter gating, the ring push — is shared, because only these two
//! functions were ever RTT-specific.
//!
//! # Selecting one
//!
//! Exactly one of `sink-rtt` and `sink-esp-println` may be on. **Neither is
//! also legal**, and deliberately so: a board that serves `GetLogs` and has no
//! console worth writing to (no probe attached, no free UART) still wants the
//! subscriber installed, because the ring is fed from the same path. Such a
//! build writes nowhere and keeps its records.

/// Prepare the transport. Called once by [`crate::init`], before any record.
#[cfg(feature = "sink-rtt")]
pub fn init() {
    rtt_target::rtt_init_print!();
}

/// Prepare the transport — nothing to do for `esp-println`, which writes to a
/// UART `esp-hal` has already configured by the time logging is installed.
#[cfg(feature = "sink-esp-println")]
pub fn init() {}

/// Prepare the transport — nothing to prepare, this build has none.
#[cfg(not(any(feature = "sink-rtt", feature = "sink-esp-println")))]
pub fn init() {}

/// Write one already-rendered, already-filtered line, followed by a newline.
///
/// Infallible by contract: logging must never fault the router, so a transport
/// that cannot accept the line drops it. Both backends below already behave
/// that way (RTT overwrites or blocks per its channel mode; `esp-println`
/// ignores UART errors).
#[cfg(feature = "sink-rtt")]
pub fn write_line(line: &str) {
    rtt_target::rprintln!("{}", line);
}

/// Write one already-rendered line. See the RTT variant for the contract.
#[cfg(feature = "sink-esp-println")]
pub fn write_line(line: &str) {
    esp_println::println!("{}", line);
}

/// Discard one already-rendered line: this build selected no text sink, so the
/// record reaches [`crate::ring`] and nothing else. See the module docs.
#[cfg(not(any(feature = "sink-rtt", feature = "sink-esp-println")))]
pub fn write_line(_line: &str) {}

/// Two transports would each render every record, so a board would see every
/// line twice and pay for it twice. Caught here rather than left to whichever
/// `write_line` the resolver happened to pick.
#[cfg(all(feature = "sink-rtt", feature = "sink-esp-println"))]
compile_error!(
    "wayfinder-log: `sink-rtt` and `sink-esp-println` are mutually exclusive; \
     enable exactly one, or neither to keep only the `GetLogs` ring"
);
