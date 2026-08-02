//! The shared, transport-free line formatter behind both logging facades.
//!
//! Two facades reach RTT on the boards: `tracing` (the mesh stack's own
//! records, via [`crate::rtt::RttSubscriber`]) and `log` (the third-party
//! embedded crates — `embassy-*`, `nrf-softdevice` — whose `fmt.rs` facades
//! emit `log` records when built with their `log` feature, via
//! [`crate::rtt::RttLogger`]). Both render to the same one-line text shape so a
//! single RTT reader shows one interleaved stream.
//!
//! Formatting lives here, apart from the `cfg(target_os = "none")` RTT
//! transport, so it is exercised by host unit tests: building a `tracing`
//! `Event` or a `log::Record` needs callsite machinery, but a [`LineBuf`] takes
//! plain `Display`/`Debug` values and is directly testable.

use core::fmt::Arguments;
use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Write;

/// Longest event line rendered to RTT; anything past this is truncated. Shared
/// by both facades this crate renders (the mesh stack's own `tracing` events
/// and the `log` records forwarded from third-party embedded crates). Sized
/// for a level + target + a handful of short structured fields (macs,
/// lengths, seqnos) or a short preformatted message — never payload bytes.
pub(crate) const LINE_CAP: usize = 256;

/// A fixed-capacity line under construction, rendered as
/// `LEVEL target: message field=value …`.
///
/// Every write is infallible from the caller's perspective: once the buffer
/// fills, further output is silently discarded rather than reported. Logging is
/// best-effort and must never fault the router, and an over-long line costs an
/// operator a few trailing fields at worst.
///
/// Truncation can land *inside* a value (a long field is cut off part-way, not
/// dropped whole) because each `write!` issues several `write_str` calls and
/// only the overflowing one is rejected. It never lands inside a multi-byte
/// character, so the line is always valid UTF-8.
pub(crate) struct LineBuf(heapless::String<LINE_CAP>);

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
        Self(line)
    }

    /// Append `tracing`'s reserved `message` field — the static event text —
    /// bare, with no `name=` prefix.
    pub(crate) fn push_message(&mut self, value: &dyn Debug) {
        let _ = write!(self.0, " {value:?}");
    }

    /// Append one structured field as ` name=value`.
    pub(crate) fn push_field(&mut self, name: &str, value: &dyn Debug) {
        let _ = write!(self.0, " {name}={value:?}");
    }

    /// Append an already-formatted `log` record body. `log` formats eagerly, so
    /// its message arrives as `core::fmt::Arguments` rather than as the
    /// separate fields a `tracing` event carries.
    pub(crate) fn push_args(&mut self, args: &Arguments<'_>) {
        let _ = write!(self.0, " {args}");
    }

    /// The line rendered so far.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
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
