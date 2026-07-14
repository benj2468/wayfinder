//! The RTT-backed `tracing` subscriber, compiled only for bare metal.

use core::fmt::Write;
use core::sync::atomic::{AtomicU32, Ordering};

use rtt_target::{rprintln, rtt_init_print};
use tracing_core::field::{Field, Visit};
use tracing_core::span::{Attributes, Id, Record};
use tracing_core::{Dispatch, Event, Metadata, Subscriber};

/// Longest event line rendered to RTT; anything past this is truncated. Sized
/// for a level + target + a handful of the short structured fields the mesh
/// stack logs (macs, lengths, seqnos) — never payload bytes.
const LINE_CAP: usize = 256;

/// Initialize RTT and install [`RttSubscriber`] as the global tracing
/// subscriber. A failure to set the global default (one is already installed)
/// is ignored — logging is best-effort and must never fault the router.
pub fn init() {
    rtt_init_print!();
    let _ = tracing_core::dispatcher::set_global_default(Dispatch::new(RttSubscriber::new()));
}

/// A `no_std`, heap-free tracing subscriber that prints each event to the RTT
/// up-channel.
///
/// Spans are handed monotonically increasing ids so the dispatcher's contract
/// is satisfied, but are otherwise not tracked: the mesh stack carries its
/// per-frame context in event *fields*, not span state, so flattening spans
/// costs no information on these boards while keeping the subscriber stateless.
struct RttSubscriber {
    /// Source of unique, never-reused span ids (ids must be non-zero and
    /// distinct for the lifetime of the dispatcher). 32-bit because Cortex-M4
    /// has no 64-bit atomics; widened to the id's `u64` on issue.
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

    /// Issue a fresh, unique span id. `fetch_add` guarantees distinctness; the
    /// counter starting at 1 keeps ids non-zero. Wrap-around is unreachable in
    /// practice (2^64 spans on a mesh node).
    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(u64::from(self.next_span.fetch_add(1, Ordering::Relaxed)))
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
        let mut line: heapless::String<LINE_CAP> = heapless::String::new();
        let _ = write!(line, "{:<5} {}:", meta.level(), meta.target());
        event.record(&mut FieldVisitor(&mut line));
        rprintln!("{}", line);
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
struct FieldVisitor<'a>(&'a mut heapless::String<LINE_CAP>);

impl Visit for FieldVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn core::fmt::Debug) {
        // Ignore write failures: an over-long line is simply truncated.
        let _ = if field.name() == "message" {
            write!(self.0, " {value:?}")
        } else {
            write!(self.0, " {}={:?}", field.name(), value)
        };
    }
}
