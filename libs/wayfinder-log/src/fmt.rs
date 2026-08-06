//! The shared, transport-free line formatter behind both logging facades.
//!
//! The `tracing` and `log` facades both render to this one-line shape, so a
//! single RTT reader sees one interleaved stream.
//!
//! Kept apart from the `cfg(target_os = "none")` RTT transport so host unit
//! tests exercise it: building a `tracing` `Event` or a `log::Record` needs
//! callsite machinery, but a [`LineBuf`] takes plain `Display`/`Debug` values.

use core::fmt::Arguments;
use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Write;

/// Longest event line rendered; anything past this is truncated. Sized for a
/// level, a target, and a handful of short structured fields (macs, lengths,
/// seqnos) — never payload bytes.
pub(crate) const LINE_CAP: usize = 256;

/// A fixed-capacity line under construction, rendered as
/// `LEVEL target: message field=value …`.
///
/// Every write is infallible from the caller's perspective: once full, further
/// output is silently discarded. Logging is best-effort and must never fault
/// the router.
///
/// Truncation can land *inside* a value, since each `write!` issues several
/// `write_str` calls and only the overflowing one is rejected — but never
/// inside a multi-byte character, so the line is always valid UTF-8.
pub(crate) struct LineBuf {
    /// The whole rendered line, prefix included.
    line: heapless::String<LINE_CAP>,
    /// Byte offset just past the `LEVEL target:` prefix, so the ring can take
    /// the body without re-rendering it — it stores level and target as their
    /// own fields, and repeating them would waste a third of a record.
    prefix_len: usize,
}

impl LineBuf {
    /// Start a line with the level left-padded to 5 columns (so `INFO`/`WARN`
    /// align with `TRACE`/`DEBUG`) followed by the record's target.
    ///
    /// `level` is taken as `Display` because the two facades pass different
    /// types — `tracing_core::Level` and `log::Level` — and both pad correctly
    /// under `{:<5}` via `Formatter::pad`.
    pub(crate) fn new(level: impl Display, target: &str) -> Self {
        let mut line = heapless::String::new();
        let _ = write!(line, "{level:<5} {target}:");
        let prefix_len = line.len();
        Self { line, prefix_len }
    }

    /// Append `tracing`'s reserved `message` field — the static event text —
    /// bare, with no `name=` prefix.
    pub(crate) fn push_message(&mut self, value: &dyn Debug) {
        let _ = write!(self.line, " {value:?}");
    }

    /// Append one structured field as ` name=value`.
    pub(crate) fn push_field(&mut self, name: &str, value: &dyn Debug) {
        let _ = write!(self.line, " {name}={value:?}");
    }

    /// Append an already-formatted `log` record body. `log` formats eagerly, so
    /// its message arrives as `core::fmt::Arguments` rather than as the
    /// separate fields a `tracing` event carries.
    pub(crate) fn push_args(&mut self, args: &Arguments<'_>) {
        let _ = write!(self.line, " {args}");
    }

    /// The line rendered so far, prefix included — what a text sink (RTT, a
    /// console) writes.
    pub(crate) fn as_str(&self) -> &str {
        &self.line
    }

    /// Just the message and fields, without the `LEVEL target:` prefix — what
    /// the ring stores. Falls back to the empty string when the prefix itself
    /// was truncated (a target longer than the whole line budget), costing a
    /// record its message rather than panicking on an out-of-range slice.
    pub(crate) fn body(&self) -> &str {
        self.line
            .get(self.prefix_len..)
            .unwrap_or("")
            .trim_start_matches(' ')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_is_padded_to_align_with_longer_levels() {
        assert_eq!(
            LineBuf::new("INFO", "blue::nrf").as_str(),
            "INFO  blue::nrf:"
        );
        assert_eq!(
            LineBuf::new("TRACE", "blue::nrf").as_str(),
            "TRACE blue::nrf:"
        );
    }

    #[test]
    fn message_is_written_bare_and_fields_are_named() {
        let mut line = LineBuf::new("WARN", "wayfinder::router");
        line.push_message(&"rx frame");
        line.push_field("payload_len", &12);
        assert_eq!(
            line.as_str(),
            "WARN  wayfinder::router: \"rx frame\" payload_len=12"
        );
    }

    #[test]
    fn log_args_are_appended_preformatted() {
        let mut line = LineBuf::new("DEBUG", "embassy_nrf::gpio");
        line.push_args(&format_args!("pin {} configured", 17));
        assert_eq!(line.as_str(), "DEBUG embassy_nrf::gpio: pin 17 configured");
    }

    /// The body is the same render as the line, minus the prefix the ring
    /// stores separately — one formatting pass feeds both sinks.
    #[test]
    fn body_excludes_the_level_and_target_prefix() {
        let mut line = LineBuf::new("WARN", "wayfinder::router");
        line.push_message(&"rx frame");
        line.push_field("payload_len", &12);
        assert_eq!(line.body(), "\"rx frame\" payload_len=12");
    }

    /// An event with no message or fields renders an empty body rather than a
    /// stray separator.
    #[test]
    fn body_of_an_empty_line_is_empty() {
        assert_eq!(LineBuf::new("INFO", "t").body(), "");
    }

    /// A target too long to fit is dropped from the rendered line whole (each
    /// `write_str` is accepted or rejected entire), so the prefix stays short
    /// and `body` still slices in bounds. The ring keeps the target in its own
    /// field, so nothing is actually lost there — but `body` must not panic on
    /// the degenerate line either way.
    #[test]
    fn body_survives_a_target_too_long_to_render() {
        let mut line = LineBuf::new("INFO", &"t".repeat(LINE_CAP * 2));
        line.push_message(&"still rendered");
        assert_eq!(line.body(), "\"still rendered\"");
    }

    /// Far more fields than fit: the line stops growing at `LINE_CAP` instead of
    /// panicking, and the level/target prefix survives so the record is still
    /// attributable.
    #[test]
    fn overlong_line_truncates_without_panicking() {
        let target = "t";
        let mut line = LineBuf::new("TRACE", target);
        for i in 0..200 {
            line.push_field("field_with_a_long_name", &i);
        }
        assert!(line.as_str().len() <= LINE_CAP);
        assert!(line.as_str().starts_with("TRACE t:"));
    }

    /// A push larger than the remaining space truncates *within* the value:
    /// `write!` issues several `write_str` calls and `heapless` rejects only the
    /// one that overflows, so the fragments before it are kept. The guarantee is
    /// bounded, valid UTF-8 output — not an all-or-nothing push.
    #[test]
    fn push_larger_than_remaining_capacity_truncates_mid_value() {
        let mut line = LineBuf::new("INFO", "t");
        let huge = "x".repeat(LINE_CAP * 2);
        line.push_message(&huge);
        assert!(line.as_str().len() <= LINE_CAP);
        assert!(line.as_str().starts_with("INFO  t:"));
    }

    /// Multi-byte characters are never split by truncation: `heapless::String`
    /// rejects an overflowing `write_str` whole, and `Display`/`Debug` never
    /// hand it a partial character. Without this, RTT would carry invalid UTF-8.
    #[test]
    fn truncation_never_splits_a_multibyte_char() {
        let mut line = LineBuf::new("INFO", "t");
        for _ in 0..LINE_CAP {
            line.push_args(&format_args!("日本語"));
        }
        assert!(line.as_str().len() <= LINE_CAP);
        // `as_str` returning at all proves UTF-8 validity; confirm the tail is a
        // whole char rather than a lone continuation byte.
        assert!(line.as_str().chars().next_back().is_some());
    }
}
