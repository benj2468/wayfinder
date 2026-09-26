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

/// An `f64` field value rendered as a fixed three-decimal number (`-12.500`)
/// with integer arithmetic only.
///
/// Exists to keep `core`'s float formatter out of a bare-metal image. The bare
/// subscriber receives fields through `dyn Visit`, so every `record_*` method
/// is in the vtable and reachable whether or not anything logs a float; the
/// default `record_f64` formats via `Debug`, which links `flt2dec` (~11 KiB on
/// a Cortex-M4). Routing the value through this instead links none of it —
/// and, since it reads the IEEE-754 bits rather than multiplying by `1000.0`,
/// none of the soft-float builtins either.
///
/// Rounds the exact binary value half away from zero. `NaN` and the infinities
/// render as `NaN`/`inf`/`-inf`; a magnitude too large for three decimals in an
/// `i64` renders as `<f64>` rather than as a saturated wrong number.
pub(crate) struct Fixed3(pub(crate) f64);

impl Debug for Fixed3 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let bits = self.0.to_bits();
        let negative = bits >> 63 == 1;
        let exp_field = (bits >> 52) & 0x7ff;
        let fraction = bits & ((1 << 52) - 1);

        if exp_field == 0x7ff {
            return f.write_str(match (fraction != 0, negative) {
                (true, _) => "NaN",
                (false, false) => "inf",
                (false, true) => "-inf",
            });
        }

        // value = mantissa * 2^shift, exactly. Subnormals have no implicit bit
        // and the minimum exponent.
        let (mantissa, shift) = if exp_field == 0 {
            (fraction, -1074)
        } else {
            (fraction | (1 << 52), exp_field as i32 - 1075)
        };
        // mantissa < 2^53 and 1000 < 2^10, so this cannot overflow.
        let scaled = mantissa * 1000;
        let millis = if shift >= 0 {
            let limit = (i64::MAX as u64) >> shift.min(63);
            if shift >= 64 || scaled > limit {
                return f.write_str("<f64>");
            }
            scaled << shift
        } else {
            let s = shift.unsigned_abs();
            // scaled < 2^63, so adding the half-unit cannot overflow a u64.
            if s >= 64 {
                0
            } else {
                (scaled + (1 << (s - 1))) >> s
            }
        };
        if millis > i64::MAX as u64 {
            return f.write_str("<f64>");
        }

        let sign = if negative && millis != 0 { "-" } else { "" };
        write!(f, "{sign}{}.{:03}", millis / 1000, millis % 1000)
    }
}

/// A 128-bit integer field value, rendered in full without `u128`'s own
/// formatter.
///
/// The bare subscriber's default `record_u128`/`record_i128` format via
/// `Debug`, which links `<u128>::_fmt_inner` into every bare-metal image for
/// fields nothing logs. This splits the magnitude into base-10^19 chunks and
/// prints each through the `u64` path the image already carries.
pub(crate) struct Wide128 {
    /// Whether to print a leading `-`. Never set for zero.
    negative: bool,
    /// The absolute value — a `u128` so `i128::MIN`'s magnitude fits.
    magnitude: u128,
}

impl From<u128> for Wide128 {
    fn from(value: u128) -> Self {
        Self {
            negative: false,
            magnitude: value,
        }
    }
}

impl From<i128> for Wide128 {
    fn from(value: i128) -> Self {
        Self {
            negative: value < 0,
            magnitude: value.unsigned_abs(),
        }
    }
}

impl Debug for Wide128 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        /// The largest power of ten that fits a `u64`; `u128::MAX` has 39
        /// digits, so three chunks always suffice.
        const CHUNK: u128 = 10_000_000_000_000_000_000;
        if self.negative {
            f.write_str("-")?;
        }
        let low = (self.magnitude % CHUNK) as u64;
        let rest = self.magnitude / CHUNK;
        let mid = (rest % CHUNK) as u64;
        let high = (rest / CHUNK) as u64;
        if high != 0 {
            write!(f, "{high}{mid:019}{low:019}")
        } else if mid != 0 {
            write!(f, "{mid}{low:019}")
        } else {
            write!(f, "{low}")
        }
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

    /// Render a value through the wrapper's `Debug`, which is how the bare
    /// visitor hands it to [`LineBuf::push_field`].
    fn render(value: &dyn Debug) -> String {
        format!("{value:?}")
    }

    /// A float renders as a scaled integer with three decimals, rounded half
    /// away from zero — never through `core`'s float formatter, whose `flt2dec`
    /// machinery is the ~13 KiB this wrapper exists to keep out of a board image.
    #[test]
    fn f64_renders_three_fixed_decimals() {
        assert_eq!(render(&Fixed3(12.5)), "12.500");
        assert_eq!(render(&Fixed3(0.0)), "0.000");
        assert_eq!(render(&Fixed3(0.0005)), "0.001");
        assert_eq!(render(&Fixed3(-0.0005)), "-0.001");
        assert_eq!(render(&Fixed3(1234.5678)), "1234.568");
    }

    /// A negative value whose integer part is zero keeps its sign: splitting on
    /// `/ 1000` and `% 1000` alone would render `-0.25` as `0.250`.
    #[test]
    fn f64_between_minus_one_and_zero_keeps_its_sign() {
        assert_eq!(render(&Fixed3(-0.25)), "-0.250");
        assert_eq!(render(&Fixed3(-12.5)), "-12.500");
    }

    /// Non-finite and out-of-range values render as a marker rather than a
    /// saturated, plausible-looking wrong number.
    #[test]
    fn f64_non_finite_and_out_of_range_render_as_markers() {
        assert_eq!(render(&Fixed3(f64::NAN)), "NaN");
        assert_eq!(render(&Fixed3(f64::INFINITY)), "inf");
        assert_eq!(render(&Fixed3(f64::NEG_INFINITY)), "-inf");
        assert_eq!(render(&Fixed3(1e300)), "<f64>");
        assert_eq!(render(&Fixed3(-1e300)), "<f64>");
    }

    /// 128-bit integers render in full, including middle chunks that need
    /// zero-padding, without `u128`'s own formatter.
    #[test]
    fn u128_renders_every_digit() {
        for v in [
            0,
            42,
            u128::from(u64::MAX),
            u128::from(u64::MAX) + 1,
            5 * 10u128.pow(19) + 7,
            10u128.pow(38) + 3,
            u128::MAX,
        ] {
            assert_eq!(render(&Wide128::from(v)), v.to_string(), "{v}");
        }
    }

    /// Signed 128-bit values, including `i128::MIN`, whose magnitude does not
    /// fit an `i128`.
    #[test]
    fn i128_renders_every_digit_and_its_sign() {
        for v in [0, -1, 17, i128::from(i64::MIN) - 1, i128::MIN, i128::MAX] {
            assert_eq!(render(&Wide128::from(v)), v.to_string(), "{v}");
        }
    }
}
