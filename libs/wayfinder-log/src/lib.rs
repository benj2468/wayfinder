//! The mesh stack's logging plumbing, shared by the bare-metal boards and the
//! host node.
//!
//! Three target-independent pieces, with a thin facade per target on top:
//!
//! - [`filter`](crate::set_filter) — the runtime `RUST_LOG`-style filter every
//!   sink gates on, changed at runtime by the management API's `SetLogLevel`.
//! - [`ring`](crate::logs_since) — the bounded record ring the management API
//!   serves `GetLogs` from.
//! - `fmt` — the line formatter both facades render through.
//!
//! # Reading a board's logs without a probe
//!
//! The mesh stack logs through [`tracing`] on every target, but a bare-metal
//! board has no subscriber installed by default, so `tracing`'s dispatcher
//! drops every record — the `trace!`/`warn!` calls in the shared router core,
//! embedded driver, and radio drivers produce no output on hardware. [`init`]
//! installs one that formats each event onto RTT (Real-Time Transfer), which a
//! host reads over the debug probe (e.g. `probe-rs rtt`).
//!
//! RTT needs that probe, which is exactly what an nRF52840 **dongle** does not
//! have — and on any board, it is unavailable the moment the debug cable is
//! not attached. So every record also goes into the ring, which the management
//! API serves over whatever transport the node already speaks (USB CDC-ACM on
//! the nRF, a socket on a host). That is what makes a deployed node's logs
//! readable at all.
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
//! # On the host
//!
//! On non-bare-metal targets [`init`] is a no-op — the RTT backend cannot link
//! there — but the filter and the ring are fully live, so this stays a
//! host-buildable workspace member that `wayfinder-server` reads and
//! `cargo test` covers. A host *node* installs the equivalent facade with
//! [`subscriber::init`], behind the `subscriber` feature, and thereby serves the
//! same `GetLogs` a board does.
//!
//! [`tracing`]: https://docs.rs/tracing
//! [`rtt-target`]: https://docs.rs/rtt-target
//! [`tracing-core`]: https://docs.rs/tracing-core
#![cfg_attr(target_os = "none", no_std)]
// `unwrap`/`expect` are denied workspace-wide in production code; tests opt back
// out, matching every other crate here.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

extern crate alloc;

// Host builds compile the formatter for its unit tests but link no transport,
// so every `LineBuf` method is unused there.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
mod fmt;
#[cfg(target_os = "none")]
mod rtt;

mod clock;
mod filter;
mod ring;
#[cfg(feature = "subscriber")]
pub mod subscriber;
mod sync;

pub use filter::DEFAULT_SPEC;
pub use filter::Filter;
pub use filter::FilterParseError;
pub use filter::Level;
pub use filter::LevelFilter;
pub use filter::MAX_DIRECTIVES;
pub use filter::SPEC_CAP;
pub use filter::TARGET_CAP;
pub use filter::current_spec;
pub use filter::enabled;
pub use filter::level_enabled;
pub use filter::set_filter;
pub use ring::LogRecord;
pub use ring::LogSnapshot;
pub use ring::MESSAGE_CAP;
pub use ring::RING_CAPACITY;
pub use ring::logs_since;
pub use ring::record;

/// Install the bare-metal sinks: `tracing` events and `log` records onto RTT
/// and into the log ring.
///
/// Call once, early in `main`, before the first event. On the boards this
/// initializes the RTT channel, registers the `tracing` subscriber, and
/// registers the `log` logger (raising `log`'s max level, which defaults to
/// `Off`); the call is idempotent-safe (a second call, or a sink already set by
/// something else, is ignored rather than panicking). On non-bare-metal targets
/// this is a no-op — a host node calls [`subscriber::init`] instead.
///
/// The ring and the filter need no initialization and work before this is
/// called; only the sinks that feed them are installed here.
pub fn init() {
    #[cfg(target_os = "none")]
    rtt::init();
}
