//! The bare-metal adapters for both logging facades. Each renders through
//! [`crate::fmt::LineBuf`] onto the same text sink, so `tracing` and `log`
//! records interleave in one stream — and each also pushes the record into
//! [`crate::ring`], which is how a board with no console attached still has
//! observable logs.
//!
//! Both facades gate on [`crate::filter`] first, so one `SetLogLevel` moves
//! every sink at once.
//!
//! Nothing here names a transport: which one a board writes to is
//! [`crate::sink`]'s single pair of functions, chosen by feature. This file
//! used to be `rtt.rs` and hard-coded `rprintln!`, which was fine while every
//! `no_std` target in the repo had a debug probe; the ESP32 has none.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use tracing_core::Dispatch;
use tracing_core::Event;
use tracing_core::Interest;
use tracing_core::Metadata;
use tracing_core::Subscriber;
use tracing_core::field::Field;
use tracing_core::field::Visit;
use tracing_core::span::Attributes;
use tracing_core::span::Id;
use tracing_core::span::Record;

use crate::filter;
use crate::filter::Level;
use crate::fmt::LineBuf;
use crate::ring;
use crate::sink;

/// Map a `log` level onto this crate's own, which the ring and the filter speak.
fn level_from_log(level: log::Level) -> Level {
    match level {
        log::Level::Error => Level::Error,
        log::Level::Warn => Level::Warn,
        log::Level::Info => Level::Info,
        log::Level::Debug => Level::Debug,
        log::Level::Trace => Level::Trace,
    }
}

/// Initialize the text sink and install both facades' global subscribers:
/// [`BareSubscriber`] for `tracing` and [`BareLogger`] for `log`. A failure to
/// install either (one is already registered) is ignored — logging is
/// best-effort and must never fault the router.
pub fn init() {
    sink::init();
    let _ = tracing_core::dispatcher::set_global_default(Dispatch::new(BareSubscriber::new()));
    let _ = log::set_logger(&BareLogger);
    // A *static* ceiling applied before `BareLogger` is consulted, so anything
    // lower would put records permanently out of the runtime filter's reach and
    // make `SetLogLevel trace` a lie. Same reason no crate here may set a
    // `max_level_*` Cargo feature on `log`/`tracing`.
    log::set_max_level(log::LevelFilter::Trace);
}

/// The `log` sink for the third-party embedded crates (`embassy-*`, `esp-hal`),
/// which emit `log` records rather than `tracing` ones.
///
/// A unit struct so it can be installed as the `&'static dyn Log`
/// `log::set_logger` wants; the boxing alternative needs `std`.
struct BareLogger;

impl log::Log for BareLogger {
    /// Whether a record passes the installed runtime filter.
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        filter::enabled(level_from_log(metadata.level()), metadata.target())
    }

    /// Render one record to the text sink and push it to the ring, in the same shape as a
    /// `tracing` event. `log` formats eagerly, so the message arrives as one
    /// preformatted `Arguments` rather than as structured fields.
    ///
    /// The filter check stays *inside* this method: `log`'s macros consult the
    /// static `max_level` and then call `Log::log` directly, never
    /// `Log::enabled`, so filtering solely there would filter nothing.
    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let level = level_from_log(record.level());
        let mut line = LineBuf::new(record.level(), record.target());
        line.push_args(record.args());
        sink::write_line(line.as_str());
        ring::record(level, record.target(), line.body());
    }

    /// Both sinks write synchronously, so there is nothing buffered on this
    /// side to flush.
    fn flush(&self) {}
}

/// A `no_std`, heap-free tracing subscriber that prints each event to the
/// board's text sink.
///
/// Spans are handed monotonically increasing ids so the dispatcher's contract
/// is satisfied, but are otherwise not tracked: the mesh stack carries its
/// per-frame context in event *fields*, not span state.
struct BareSubscriber {
    /// Source of unique span ids, which must be non-zero and distinct.
    /// 32-bit because Cortex-M4 has no 64-bit atomics, so at one span per
    /// received frame a long-lived node really does reach the wrap —
    /// [`BareSubscriber::new_span`] tolerates it rather than assuming it away.
    next_span: AtomicU32,
}

impl BareSubscriber {
    /// Create a subscriber whose first issued span id is 1.
    fn new() -> Self {
        Self {
            next_span: AtomicU32::new(1),
        }
    }
}

impl Subscriber for BareSubscriber {
    /// Whether an event passes the installed runtime filter.
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        filter::enabled(Level::from(*metadata.level()), metadata.target())
    }

    /// Always [`Interest::sometimes`], so [`enabled`](Self::enabled) is
    /// consulted for every event.
    ///
    /// **This override is what makes the runtime filter work at all.** The
    /// default caches an always/never verdict per callsite forever, freezing
    /// every already-hit line at its boot-time verbosity — the busiest lines
    /// first. The cost is a per-event `enabled` call, which is why
    /// [`crate::filter::level_enabled`] screens lock-free before target
    /// matching.
    fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    /// Issue a fresh span id. On the one call in ~4 billion where the counter
    /// wraps onto 0, draw again rather than hand `Id::from_u64` the one input
    /// it panics on — a wrapped counter must not be able to fault the router.
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

    /// Render one event to the text sink as `LEVEL target: message field=value …` in a
    /// fixed stack buffer, and push the same record to the ring. One formatting
    /// pass feeds both. Write failures are truncations, intentionally ignored.
    fn event(&self, event: &Event<'_>) {
        let meta = event.metadata();
        let mut line = LineBuf::new(meta.level(), meta.target());
        event.record(&mut FieldVisitor(&mut line));
        sink::write_line(line.as_str());
        ring::record(Level::from(*meta.level()), meta.target(), line.body());
    }

    /// Spans are not tracked, so entering one is a no-op.
    fn enter(&self, _span: &Id) {}

    /// Spans are not tracked, so exiting one is a no-op.
    fn exit(&self, _span: &Id) {}
}

/// Appends an event's fields to the line buffer: the reserved `message` field
/// bare, every other as ` name=value`. The typed `record_*` methods all fall
/// through to `record_debug`, so implementing it alone covers every type.
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
