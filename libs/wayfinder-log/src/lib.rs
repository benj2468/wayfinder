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
//! Every record goes to both a text sink and the ring. The ring is not a
//! convenience: RTT needs a debug probe, which an nRF52840 dongle does not have
//! and any board lacks the moment its cable is out, so `GetLogs` over the
//! node's own transport is what makes a deployed node observable at all.
//!
//! Two non-obvious consequences of that split:
//!
//! - The bare-metal subscriber renders each event into a fixed stack buffer and
//!   ignores spans beyond issuing ids, so it costs no `alloc` of its own.
//! - The embedded third-party crates (`embassy-*`, `nrf-softdevice`) emit
//!   through `log`, not `tracing`, and nothing at all unless their `log`
//!   feature is on — hence the second sink [`init`] installs. Their `defmt`
//!   feature must stay off: it cannot render to text on-device, and
//!   `defmt-rtt` defines a second `_SEGGER_RTT` control block that collides
//!   with [`rtt-target`]'s, leaving a probe to find only one of the two.
//!
//! On non-bare-metal targets [`init`] is a no-op — the RTT backend cannot link
//! there — but the filter and the ring are fully live, so this stays a
//! host-buildable workspace member. A host *node* installs the equivalent
//! facade with [`subscriber::init`], behind the `subscriber` feature.
//!
//! [`rtt-target`]: https://docs.rs/rtt-target
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
