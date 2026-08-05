//! The host-side subscriber stack: the `std` counterpart to [`crate::rtt`].
//!
//! A host node ([`wayfinder-tap`]) runs the same mesh stack and answers the same
//! management API, so it serves `GetLogs` from the same ring the boards do. That
//! also makes the TUI's log view work against a host node — useful well beyond
//! convenience, since it is what lets the whole path be exercised without
//! hardware.
//!
//! [`wayfinder-tap`]: https://git.haganah.net
//!
//! Two layers, both installed by [`init`]:
//!
//! - [`FilterLayer`] gates the whole subscriber on [`crate::filter`], so
//!   `SetLogLevel` moves the console and the ring together — exactly as it moves
//!   RTT and the ring on a board.
//! - [`RingLayer`] renders each surviving event into [`crate::ring`].
//!
//! The console output stays `tracing_subscriber::fmt`, unchanged.

use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

use crate::filter;
use crate::filter::Level;
use crate::fmt::LineBuf;
use crate::ring;

/// Gates every layer in the stack on this crate's runtime filter.
///
/// A `Layer` with no writer of its own: `Layer::enabled` participates in the
/// subscriber's global filter, so returning `false` here suppresses the event
/// for the console and the ring alike.
struct FilterLayer;

impl<S: tracing_core::Subscriber> Layer<S> for FilterLayer {
    /// Whether an event passes the installed runtime filter.
    fn enabled(&self, metadata: &tracing_core::Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        filter::enabled(Level::from(*metadata.level()), metadata.target())
    }

    /// Always [`Interest::sometimes`], so `enabled` is consulted per event
    /// rather than once per callsite.
    ///
    /// Same trap as on the bare-metal side: the default implementation caches an
    /// `always`/`never` verdict for the life of the process, which would freeze
    /// every already-hit callsite at its startup verbosity and make
    /// `SetLogLevel` look like it silently did nothing.
    fn register_callsite(
        &self,
        _metadata: &'static tracing_core::Metadata<'static>,
    ) -> tracing_core::Interest {
        tracing_core::Interest::sometimes()
    }
}

/// Renders each event into the log ring the management API serves.
struct RingLayer;

impl<S> Layer<S> for RingLayer
where
    S: tracing_core::Subscriber + for<'a> LookupSpan<'a>,
{
    /// Format the event the same way the boards do and push it to the ring.
    ///
    /// Deliberately the same [`LineBuf`] renderer as RTT: a record read out of a
    /// host node and one read off a board should be the same shape, so one TUI
    /// view can present both without knowing which it is talking to.
    fn on_event(&self, event: &tracing_core::Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut line = LineBuf::new(meta.level(), meta.target());
        event.record(&mut FieldVisitor(&mut line));
        ring::record(Level::from(*meta.level()), meta.target(), line.body());
    }
}

/// Appends an event's fields to the line buffer, exactly as the bare-metal
/// visitor does — the reserved `message` field bare, everything else as
/// ` name=value`.
struct FieldVisitor<'a>(&'a mut LineBuf);

impl tracing_core::field::Visit for FieldVisitor<'_> {
    fn record_debug(&mut self, field: &tracing_core::field::Field, value: &dyn core::fmt::Debug) {
        if field.name() == "message" {
            self.0.push_message(value);
        } else {
            self.0.push_field(field.name(), value);
        }
    }
}

/// Install the host subscriber: console output, the log ring, and the runtime
/// filter gating both.
///
/// The filter is seeded from `spec` — pass `RUST_LOG`'s value, or `None` to
/// start at [`crate::DEFAULT_SPEC`]. A spec that doesn't parse is reported on
/// the returned `Err` and the default is installed instead, since refusing to
/// start a node over a malformed environment variable is worse than starting it
/// noisy.
///
/// Call once, early in `main`. A second call (or a subscriber already installed
/// by something else, e.g. a test harness) is ignored rather than panicking.
pub fn init(spec: Option<&str>) -> Result<(), crate::FilterParseError> {
    let outcome = match spec {
        Some(spec) => filter::set_filter(spec),
        None => Ok(()),
    };

    tracing_subscriber::registry()
        .with(FilterLayer)
        .with(tracing_subscriber::fmt::layer())
        .with(RingLayer)
        .try_init()
        .ok();

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The host layer renders an event into the ring in the same shape the
    /// bare-metal subscriber does: level and target in their own fields, message
    /// and structured fields in the body.
    ///
    /// Drives the layer directly rather than through a global subscriber, since
    /// only one can be installed per process and the rest of the suite would
    /// then be racing this test's filter.
    #[test]
    fn ring_layer_records_message_and_fields() {
        use tracing_subscriber::layer::SubscriberExt;

        let start = ring::logs_since(0, 0).next_seq;
        let subscriber = tracing_subscriber::registry().with(RingLayer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(payload_len = 12, "rx frame");
        });

        let snap = ring::logs_since(start, 0);
        let record = snap
            .records
            .iter()
            .find(|r| r.target.starts_with("wayfinder_log"))
            .expect("the event reached the ring");
        assert_eq!(record.level, Level::Info);
        // Unquoted: a `tracing` event's `message` arrives as `fmt::Arguments`,
        // whose `Debug` renders bare — unlike a plain `&str`, which would come
        // out quoted.
        assert_eq!(record.message.as_str(), "rx frame payload_len=12");
    }
}
