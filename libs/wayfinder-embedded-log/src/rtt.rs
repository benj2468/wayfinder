//! The RTT-backed adapters for both logging facades, compiled only for bare
//! metal. Each renders through [`crate::fmt::LineBuf`] onto the same RTT print
//! channel, so `tracing` and `log` records interleave in one stream.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use rtt_target::rprintln;
use rtt_target::rtt_init_print;
use tracing_core::Dispatch;
use tracing_core::Event;
use tracing_core::Metadata;
use tracing_core::Subscriber;
use tracing_core::field::Field;
use tracing_core::field::Visit;
use tracing_core::span::Attributes;
use tracing_core::span::Id;
use tracing_core::span::Record;

use crate::fmt::LineBuf;

/// Initialize RTT and install both facades' global sinks: [`RttSubscriber`] for
/// `tracing` and [`RttLogger`] for `log`. A failure to install either (one is
/// already registered) is ignored — logging is best-effort and must never fault
/// the router.
pub fn init() {
    rtt_init_print!();
    let _ = tracing_core::dispatcher::set_global_default(Dispatch::new(RttSubscriber::new()));
    let _ = log::set_logger(&RttLogger);
    // `log`'s default max level is `Off`, which would discard every record
    // before `RttLogger::enabled` is consulted. Filtering is left to the
    // compile-time `max_level_*` features and the host-side RTT reader, matching
    // `RttSubscriber::enabled`. No consumer currently sets a `max_level_*`
    // feature on its `embassy-*` deps, so today that means unfiltered —
    // deliberately, while this bring-up phase wants maximum SoftDevice/embassy
    // visibility. If that chatter ever crowds out the mesh stack's own events
    // on the shared RTT channel, cap it via those Cargo features rather than
    // lowering this constant (which would blind every consumer at once).
    log::set_max_level(log::LevelFilter::Trace);
}

/// The `log` sink for the third-party embedded crates (`embassy-*`,
/// `nrf-softdevice`), which log through their own `fmt.rs` facade and so emit
/// `log` records — never `tracing` ones — when built with their `log` feature.
///
/// A unit struct rather than a configured instance so it can be installed as a
/// `&'static dyn Log`: `log::set_logger` takes a `'static` reference, and the
/// heap-allocating `set_boxed_logger` needs `std`.
struct RttLogger;

impl log::Log for RttLogger {
    /// Every record is enabled except `nrf-softdevice`'s own `trace!`/`debug!`
    /// diagnostics, capped at `Info` — by far the noisiest `log` producer on
    /// this shared RTT channel, easily crowding out the mesh stack's own
    /// `tracing` events. Everything else (embassy-*) stays unfiltered; see
    /// [`init`] on the global-level fallback this sits underneath.
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        if metadata.target().starts_with("nrf_softdevice") {
            metadata.level() <= log::Level::Info
        } else {
            true
        }
    }

    /// Render one record to RTT in the same shape as a `tracing` event. `log`
    /// formats eagerly, so the whole message arrives as one preformatted
    /// `Arguments` rather than as separate structured fields.
    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let mut line = LineBuf::new(record.level(), record.target());
        line.push_args(record.args());
        rprintln!("{}", line.as_str());
    }

    /// RTT writes are already pushed to the control block synchronously, so
    /// there is nothing buffered on this side to flush.
    fn flush(&self) {}
}

/// A `no_std`, heap-free tracing subscriber that prints each event to the RTT
/// up-channel.
///
/// Spans are handed monotonically increasing ids so the dispatcher's contract
/// is satisfied, but are otherwise not tracked: the mesh stack carries its
/// per-frame context in event *fields*, not span state, so flattening spans
/// costs no information on these boards while keeping the subscriber stateless.
struct RttSubscriber {
    /// Source of unique span ids (ids must be non-zero and distinct for the
    /// lifetime of the dispatcher). 32-bit because Cortex-M4 has no 64-bit
    /// atomics; widened to the id's `u64` on issue — that widening happens
    /// *after* the counter itself wraps at `u32::MAX`, so it doesn't raise
    /// the effective period. At one span per received frame
    /// (`handle_frame_with_metrics`), sustained traffic reaches 2^32 spans
    /// over a long-lived node's uptime, so [`RttSubscriber::new_span`] must
    /// tolerate the wrap rather than assume it away.
    next_span: AtomicU32,
}

impl RttSubscriber {
    /// Create a subscriber whose first issued span id is 1.
    fn new() -> Self {
        Self {
            next_span: AtomicU32::new(1),
        }
    }
}

impl Subscriber for RttSubscriber {
    /// Every event is enabled; level filtering is left to the compile-time
    /// `tracing` max-level features and to the host-side RTT reader.
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    /// Issue a fresh span id. `fetch_add` guarantees distinctness modulo the
    /// counter's `u32` period; on the one call in ~4 billion where that wrap
    /// lands on exactly 0, draw again rather than hand `Id::from_u64` the one
    /// input it panics on. Spans aren't tracked by this subscriber (`record`/
    /// `enter`/`exit` below are all no-ops), so the id's value is otherwise
    /// inert — a wrapped counter must not be able to fault the router.
    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        let mut id = self.next_span.fetch_add(1, Ordering::Relaxed);
        if id == 0 {
            id = self.next_span.fetch_add(1, Ordering::Relaxed);
        }
        Id::from_u64(u64::from(id))
    }

    /// Spans are not tracked, so recorded span fields are dropped.
    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    /// Span causal links are not tracked.
    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    /// Render one event to RTT as `LEVEL target: message field=value …`, using a
    /// fixed stack buffer (no heap). All write failures are truncations and are
    /// intentionally ignored.
    fn event(&self, event: &Event<'_>) {
        let meta = event.metadata();
        let mut line = LineBuf::new(meta.level(), meta.target());
        event.record(&mut FieldVisitor(&mut line));
        rprintln!("{}", line.as_str());
    }

    /// Spans are not tracked, so entering one is a no-op.
    fn enter(&self, _span: &Id) {}

    /// Spans are not tracked, so exiting one is a no-op.
    fn exit(&self, _span: &Id) {}
}

/// Appends an event's fields to the line buffer. The reserved `message` field
/// (the static event text) is written bare; every other field as ` name=value`.
/// The typed `record_*` methods all fall through to `record_debug`'s default,
/// so implementing it alone captures integers, bools, and strings too.
struct FieldVisitor<'a>(&'a mut LineBuf);

impl Visit for FieldVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn core::fmt::Debug) {
        if field.name() == "message" {
            self.0.push_message(value);
        } else {
            self.0.push_field(field.name(), value);
        }
    }
}
