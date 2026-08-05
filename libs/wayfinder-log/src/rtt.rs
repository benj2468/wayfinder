//! The RTT-backed adapters for both logging facades, compiled only for bare
//! metal. Each renders through [`crate::fmt::LineBuf`] onto the same RTT print
//! channel, so `tracing` and `log` records interleave in one stream — and each
//! also pushes the record into [`crate::ring`], which is how a board with no
//! debug probe attached still has observable logs.
//!
//! Both facades gate on [`crate::filter`] first, so one `SetLogLevel` moves
//! every sink at once.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use rtt_target::rprintln;
use rtt_target::rtt_init_print;
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

/// Map a `log` level onto this crate's own.
///
/// `log` and `tracing` each have their own level type; the ring and the filter
/// speak one, so both facades convert on the way in.
fn level_from_log(level: log::Level) -> Level {
    match level {
        log::Level::Error => Level::Error,
        log::Level::Warn => Level::Warn,
        log::Level::Info => Level::Info,
        log::Level::Debug => Level::Debug,
        log::Level::Trace => Level::Trace,
    }
}

/// Initialize RTT and install both facades' global sinks: [`RttSubscriber`] for
/// `tracing` and [`RttLogger`] for `log`. A failure to install either (one is
/// already registered) is ignored — logging is best-effort and must never fault
/// the router.
pub fn init() {
    rtt_init_print!();
    let _ = tracing_core::dispatcher::set_global_default(Dispatch::new(RttSubscriber::new()));
    let _ = log::set_logger(&RttLogger);
    // Deliberately left wide open: this is a *static* ceiling applied before
    // `RttLogger` is ever consulted, so anything lower here would put records
    // permanently out of reach of the runtime filter — `SetLogLevel trace` would
    // silently fail to produce trace records. All filtering happens in
    // `RttLogger::log`, against the one filter every sink shares.
    //
    // For the same reason, no crate in this workspace may set a `max_level_*`
    // Cargo feature on `log` or `tracing`: those compile the records out
    // entirely, and no runtime filter can bring them back.
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
    /// Whether a record passes the installed runtime filter.
    ///
    /// This used to hard-cap `nrf-softdevice`'s own diagnostics at `Info` — by
    /// far the noisiest `log` producer on the shared RTT channel. That cap is
    /// now the filter's job: the default `info` filter has exactly the same
    /// effect, and an operator who deliberately asks for `trace` gets what they
    /// asked for (and can write `trace,nrf_softdevice=info` to keep the cap).
    /// A hardcoded ceiling here would be one no `SetLogLevel` could lift.
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        filter::enabled(level_from_log(metadata.level()), metadata.target())
    }

    /// Render one record to RTT and push it to the ring, in the same shape as a
    /// `tracing` event. `log` formats eagerly, so the whole message arrives as
    /// one preformatted `Arguments` rather than as separate structured fields.
    ///
    /// The filter check stays *inside* this method rather than being left to the
    /// caller: `log`'s macros consult only the static `max_level` and then call
    /// `Log::log` directly — they never call `Log::enabled` on the way — so a
    /// logger that filters solely in `enabled` does no filtering at all.
    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let level = level_from_log(record.level());
        let mut line = LineBuf::new(record.level(), record.target());
        line.push_args(record.args());
        rprintln!("{}", line.as_str());
        ring::record(level, record.target(), line.body());
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
    /// Whether an event passes the installed runtime filter.
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        filter::enabled(Level::from(*metadata.level()), metadata.target())
    }

    /// Always [`Interest::sometimes`], so [`enabled`](Self::enabled) is
    /// consulted for every event.
    ///
    /// **This override is what makes the runtime filter work at all.**
    /// `tracing-core`'s default `register_callsite` calls `enabled` once per
    /// callsite and returns `Interest::always()`/`never()`, which the dispatcher
    /// then caches permanently — so a `SetLogLevel` would take effect only for
    /// callsites that had never yet been reached, and a node's busiest log lines
    /// would be exactly the ones frozen at their boot-time verbosity.
    ///
    /// The cost is that `enabled` runs per event rather than per callsite, which
    /// is why [`crate::filter::level_enabled`] screens lock-free before any
    /// target matching happens.
    fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
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
    /// fixed stack buffer (no heap), and push the same record to the ring. All
    /// write failures are truncations and are intentionally ignored.
    ///
    /// One formatting pass feeds both sinks: RTT takes the whole line, the ring
    /// takes [`LineBuf::body`] plus the level and target as their own fields.
    fn event(&self, event: &Event<'_>) {
        let meta = event.metadata();
        let mut line = LineBuf::new(meta.level(), meta.target());
        event.record(&mut FieldVisitor(&mut line));
        rprintln!("{}", line.as_str());
        ring::record(Level::from(*meta.level()), meta.target(), line.body());
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
