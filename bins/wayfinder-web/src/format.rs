//! Display helpers shared by the tab components.
//!
//! Every value the dashboard renders is formatted here rather than inline in a
//! `view!` macro, for two reasons. A macro body cannot be unit tested, and these
//! are exactly the conversions worth testing — an off-by-one in a percentage or
//! a unit scale is invisible in review and obvious to whoever is staring at the
//! number at 3am.
//!
//! Semantics deliberately match `wayfinder-tui`'s (`ui.rs`'s `fmt_*` helpers and
//! `app::format_id`). The two dashboards are read against each other when
//! something looks wrong, so `42s` in one has to mean `42s` in the other.

use wayfinder_protos::wayfinder::v1alpha::LinkFeaturesEntry;
use wayfinder_protos::wayfinder::v1alpha::LogLevel;

/// Format an opaque mesh identifier for display.
///
/// Six-byte identifiers render as colon-delimited MACs; any other length falls
/// back to space-free hex, so a 1-byte LoRa short address and an unexpected
/// length both stay readable rather than being punctuated as something they are
/// not. An empty identifier renders as an em dash.
pub fn id(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "—".to_string();
    }
    let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
    if bytes.len() == 6 {
        hex.join(":")
    } else {
        hex.concat()
    }
}

/// Render an uptime in seconds as a compact `d h m s` string, dropping leading
/// zero units so a fresh node reads as `42s` and a long-lived one as `3d 4h`.
pub fn uptime(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m {s}s")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Render a bytes-per-second rate, scaling through B/s, KiB/s and MiB/s so both
/// a near-idle LoRa link and a busy Ethernet-carried link read clearly.
pub fn rate(bps: f64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    if bps < KIB {
        format!("{bps:.0} B/s")
    } else if bps < MIB {
        format!("{:.1} KiB/s", bps / KIB)
    } else {
        format!("{:.2} MiB/s", bps / MIB)
    }
}

/// Render a frames-per-second rate with adaptive precision: whole numbers once
/// past 10 fps, one decimal below that so slow links don't read as a flat 0.
pub fn fps(fps: f64) -> String {
    if fps >= 10.0 {
        format!("{fps:.0}/s")
    } else {
        format!("{fps:.1}/s")
    }
}

/// Render a millisecond interval compactly: sub-second values in `ms`,
/// everything else in seconds with one decimal.
pub fn interval(ms: u32) -> String {
    if ms < 1000 {
        format!("{ms} ms")
    } else {
        format!("{:.1} s", f64::from(ms) / 1000.0)
    }
}

/// Convert a BATMAN transmission quality (0..=255) to a percentage.
///
/// The dashboard leads with this and keeps the raw TQ as secondary detail: "94%"
/// means something to a reader who has never heard of TQ, which is the whole
/// reason this dashboard exists. Input above the documented range is clamped —
/// the field is a `uint32` on the wire, so a malformed peer must not be able to
/// produce a percentage over 100.
pub fn tq_percent(tq: u32) -> u32 {
    tq.min(255) * 100 / 255
}

/// Render a unix timestamp as a UTC date and time.
///
/// Zero means "not set" throughout this API (an unverified node has no expiry),
/// and renders as an em dash rather than as 1970 — a date from the Unix epoch in
/// a certificate-expiry column reads as a real, alarming value.
///
/// UTC rather than local time, and computed here rather than in the browser:
/// nodes stamp in UTC, an operator comparing a dashboard against a node's own
/// logs should not have to apply an offset in their head, and a pure function is
/// testable where a `Date` call is not.
pub fn timestamp(unix_secs: u64) -> String {
    if unix_secs == 0 {
        return "—".to_string();
    }
    let days = (unix_secs / 86_400) as i64;
    let secs_of_day = unix_secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    let (hh, mm) = (secs_of_day / 3600, secs_of_day % 3600 / 60);
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02} UTC")
}

/// Convert days since the Unix epoch to a civil (year, month, day).
///
/// Howard Hinnant's `civil_from_days`, which is exact over the whole range and
/// needs no calendar tables — cheaper than taking a date-time dependency into
/// the wasm bundle for one column.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Abbreviate a public key to its leading bytes.
///
/// A 32-byte key is 64 hex characters — too long to scan and too long to lay out
/// beside a MAC. The leading bytes are enough for an operator to match a request
/// against a key they were given out of band, which is the actual task.
pub fn key(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "—".to_string();
    }
    let head: String = bytes.iter().take(4).map(|b| format!("{b:02x}")).collect();
    if bytes.len() > 4 {
        format!("{head}…")
    } else {
        head
    }
}

/// Render a record's uptime as a right-aligned seconds stamp.
///
/// Right-aligned so the seconds column stays put as a node's uptime grows, and
/// in uptime rather than wall-clock because a board has no RTC — this is what
/// correlates with the mesh's own timers, and it matches what the TUI shows.
pub fn log_uptime(uptime_ms: u64) -> String {
    format!("{:>10.3}s", uptime_ms as f64 / 1000.0)
}

/// Render a duration in seconds using the largest unit it divides exactly by.
///
/// For a certificate lifetime, which an operator thinks of as "a day" or "an
/// hour" rather than as 86400. Deliberately exact: a value that is not a whole
/// number of the larger unit keeps its seconds rather than being rounded, since
/// this is a security setting and showing 90000 back as "1 day" would misstate
/// how long a certificate an operator is about to issue stays valid.
pub fn duration_secs(secs: u64) -> String {
    /// Pluralize `unit` for `n`, since every unit here is regular.
    fn plural(n: u64, unit: &str) -> String {
        if n == 1 {
            format!("{n} {unit}")
        } else {
            format!("{n} {unit}s")
        }
    }
    if secs > 0 && secs.is_multiple_of(86_400) {
        plural(secs / 86_400, "day")
    } else if secs > 0 && secs.is_multiple_of(3_600) {
        plural(secs / 3_600, "hour")
    } else if secs > 0 && secs.is_multiple_of(60) {
        plural(secs / 60, "minute")
    } else {
        plural(secs, "second")
    }
}

/// The aggregate state of one interface's four participation gates.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GateStatus {
    /// All four gates are open: the link participates fully.
    On,
    /// All four gates are closed: the link carries nothing.
    Off,
    /// Some open, some closed — a deliberately asymmetric link (e.g. one that
    /// listens but does not transmit), or a half-applied change.
    Mixed,
}

impl GateStatus {
    /// Short label for the status column.
    pub fn label(self) -> &'static str {
        match self {
            GateStatus::On => "on",
            GateStatus::Off => "off",
            GateStatus::Mixed => "mixed",
        }
    }

    /// CSS class carrying this status's colour. Distinct per variant so the
    /// stylesheet colours them independently.
    pub fn css_class(self) -> &'static str {
        match self {
            GateStatus::On => "wf-status-on",
            GateStatus::Off => "wf-status-off",
            GateStatus::Mixed => "wf-status-mixed",
        }
    }
}

/// Derive the aggregate [`GateStatus`] of one interface's participation gates.
pub fn gate_status(e: &LinkFeaturesEntry) -> GateStatus {
    match (e.tx_ogm, e.rx_ogm, e.tx_data, e.rx_data) {
        (true, true, true, true) => GateStatus::On,
        (false, false, false, false) => GateStatus::Off,
        _ => GateStatus::Mixed,
    }
}

/// Name a log level for display.
///
/// Takes the raw `i32` the wire carries rather than a [`LogLevel`], because a
/// newer node can send a discriminant this build has no name for; that renders
/// as `?` rather than panicking or silently reading as `ERROR`. The proto3
/// zero value is treated the same way — a node never emits it, so seeing one
/// means something upstream is wrong and should look wrong.
pub fn level_label(level: i32) -> &'static str {
    match LogLevel::try_from(level) {
        Ok(LogLevel::Error) => "ERROR",
        Ok(LogLevel::Warn) => "WARN",
        Ok(LogLevel::Info) => "INFO",
        Ok(LogLevel::Debug) => "DEBUG",
        Ok(LogLevel::Trace) => "TRACE",
        Ok(LogLevel::Unspecified) | Err(_) => "?",
    }
}

/// CSS class colouring a log record by level.
///
/// Warm for the things that need acting on and cold for the routine, so the
/// shape of a screenful reads before any of the words do — the same reasoning
/// as the TUI's `level_style`.
pub fn level_class(level: i32) -> &'static str {
    match LogLevel::try_from(level) {
        Ok(LogLevel::Error) => "wf-level-error",
        Ok(LogLevel::Warn) => "wf-level-warn",
        Ok(LogLevel::Info) => "wf-level-info",
        Ok(LogLevel::Debug) => "wf-level-debug",
        _ => "wf-level-trace",
    }
}

/// How an interface is labelled in the dashboard: its configured name when the
/// node reported one, else `#idx`. Interfaces are still *addressed* by index
/// over the management API — the name is display metadata — so the fallback
/// keeps an unnamed interface identifiable rather than blank.
pub fn iface_label(iface_name: &str, iface_idx: u32) -> String {
    if iface_name.is_empty() {
        format!("#{iface_idx}")
    } else {
        iface_name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `LinkFeaturesEntry` with all four gates set as given.
    fn entry(tx_ogm: bool, rx_ogm: bool, tx_data: bool, rx_data: bool) -> LinkFeaturesEntry {
        LinkFeaturesEntry {
            iface_idx: 0,
            tx_ogm,
            rx_ogm,
            tx_data,
            rx_data,
            tx_keepalive_interval_ms: None,
            iface_name: String::new(),
        }
    }

    /// A named interface is labelled by its name; an unnamed one falls back to
    /// a `#`-prefixed index so the cell is never blank.
    #[test]
    fn iface_label_prefers_the_name_and_falls_back_to_the_index() {
        assert_eq!(iface_label("lora-roof", 3), "lora-roof");
        assert_eq!(iface_label("", 3), "#3");
    }

    #[test]
    fn id_renders_six_bytes_as_a_colon_delimited_mac() {
        assert_eq!(id(&[0x02, 0, 0, 0, 0, 0x01]), "02:00:00:00:00:01");
    }

    #[test]
    fn id_renders_other_lengths_as_bare_hex() {
        // A 1-byte LoRa short address, and an unexpected length: both must stay
        // readable rather than being punctuated as if they were MACs.
        assert_eq!(id(&[0x07]), "07");
        assert_eq!(id(&[0xde, 0xad, 0xbe]), "deadbe");
    }

    #[test]
    fn id_renders_empty_as_a_dash() {
        assert_eq!(id(&[]), "—");
    }

    #[test]
    fn uptime_drops_leading_zero_units() {
        assert_eq!(uptime(42), "42s");
        assert_eq!(uptime(90), "1m 30s");
        assert_eq!(uptime(7384), "2h 3m 4s");
        assert_eq!(uptime(273_784), "3d 4h 3m");
    }

    #[test]
    fn uptime_of_zero_reads_as_zero_seconds() {
        assert_eq!(uptime(0), "0s");
    }

    #[test]
    fn rate_scales_through_byte_units() {
        assert_eq!(rate(0.0), "0 B/s");
        assert_eq!(rate(512.0), "512 B/s");
        assert_eq!(rate(1536.0), "1.5 KiB/s");
        assert_eq!(rate(3_145_728.0), "3.00 MiB/s");
    }

    #[test]
    fn fps_keeps_a_decimal_only_below_ten() {
        // A slow LoRa link must not read as a flat 0.
        assert_eq!(fps(0.4), "0.4/s");
        assert_eq!(fps(12.0), "12/s");
    }

    #[test]
    fn interval_switches_from_milliseconds_to_seconds() {
        assert_eq!(interval(750), "750 ms");
        assert_eq!(interval(4000), "4.0 s");
    }

    #[test]
    fn tq_percent_maps_the_full_byte_range_onto_zero_to_a_hundred() {
        // TQ is a 0..=255 byte. The dashboard leads with a percentage because
        // "94%" means something to a reader who has never heard of TQ.
        assert_eq!(tq_percent(0), 0);
        assert_eq!(tq_percent(255), 100);
        assert_eq!(tq_percent(240), 94);
    }

    #[test]
    fn tq_percent_clamps_out_of_range_input() {
        // The field is a `uint32` on the wire, so a malformed peer can exceed
        // the documented range; it must not produce a percentage over 100.
        assert_eq!(tq_percent(4096), 100);
    }

    #[test]
    fn gate_status_reports_all_on_all_off_and_anything_between() {
        assert_eq!(gate_status(&entry(true, true, true, true)), GateStatus::On);
        assert_eq!(
            gate_status(&entry(false, false, false, false)),
            GateStatus::Off
        );
        assert_eq!(
            gate_status(&entry(true, true, false, true)),
            GateStatus::Mixed
        );
    }

    #[test]
    fn gate_status_carries_its_own_label_and_css_class() {
        assert_eq!(GateStatus::On.label(), "on");
        assert_eq!(GateStatus::Off.label(), "off");
        assert_eq!(GateStatus::Mixed.label(), "mixed");
        // Distinct classes, so the stylesheet can colour them independently.
        assert_ne!(GateStatus::On.css_class(), GateStatus::Off.css_class());
        assert_ne!(GateStatus::On.css_class(), GateStatus::Mixed.css_class());
    }

    #[test]
    fn level_label_names_every_log_level() {
        use wayfinder_protos::wayfinder::v1alpha::LogLevel;
        assert_eq!(level_label(LogLevel::Error as i32), "ERROR");
        assert_eq!(level_label(LogLevel::Warn as i32), "WARN");
        assert_eq!(level_label(LogLevel::Info as i32), "INFO");
        assert_eq!(level_label(LogLevel::Debug as i32), "DEBUG");
        assert_eq!(level_label(LogLevel::Trace as i32), "TRACE");
    }

    #[test]
    fn level_label_falls_back_on_an_unknown_discriminant() {
        // `level` is an `i32` on the wire, so a newer node could send a level
        // this build has no name for. It must render as something, not panic.
        assert_eq!(level_label(99), "?");
    }

    #[test]
    fn timestamp_renders_a_utc_date_and_time() {
        // 2023-11-14 22:13:20 UTC
        assert_eq!(timestamp(1_700_000_000), "2023-11-14 22:13 UTC");
    }

    #[test]
    fn timestamp_of_zero_reads_as_unset() {
        // Zero means "no expiry recorded" across this API. Rendering it as 1970
        // would put a real-looking, alarming date in an expiry column.
        assert_eq!(timestamp(0), "—");
    }

    #[test]
    fn timestamp_handles_a_leap_day() {
        // 2024-02-29 00:00:00 UTC — the case a hand-rolled calendar gets wrong.
        assert_eq!(timestamp(1_709_164_800), "2024-02-29 00:00 UTC");
    }

    #[test]
    fn key_abbreviates_to_its_leading_bytes() {
        assert_eq!(key(&[0xab; 32]), "abababab…");
    }

    #[test]
    fn key_of_a_short_value_is_not_marked_truncated() {
        assert_eq!(key(&[0xde, 0xad]), "dead");
        assert_eq!(key(&[]), "—");
    }

    #[test]
    fn log_uptime_is_right_aligned_on_the_seconds_column() {
        // The column must not shift as a node's uptime grows past a digit.
        assert_eq!(log_uptime(12_345), "    12.345s");
        assert_eq!(log_uptime(0), "     0.000s");
        assert_eq!(
            log_uptime(12_345).len(),
            log_uptime(0).len(),
            "every stamp is the same width"
        );
    }

    /// A certificate lifetime reads in the unit an operator would have typed
    /// it in, so a policy of "one day" is not shown back as 86400 seconds.
    #[test]
    fn duration_secs_uses_the_largest_whole_unit() {
        assert_eq!(duration_secs(86_400), "1 day");
        assert_eq!(duration_secs(7 * 86_400), "7 days");
        assert_eq!(duration_secs(3_600), "1 hour");
        assert_eq!(duration_secs(12 * 3_600), "12 hours");
        assert_eq!(duration_secs(60), "1 minute");
        assert_eq!(duration_secs(90), "90 seconds");
    }

    /// A lifetime that is not a whole number of larger units keeps its exact
    /// value rather than being rounded into a friendlier-looking lie — this is
    /// a security setting, and "about a day" is not a certificate lifetime.
    #[test]
    fn duration_secs_does_not_round_an_inexact_value() {
        assert_eq!(duration_secs(90_061), "90061 seconds");
        assert_eq!(duration_secs(3_661), "3661 seconds");
    }

    /// A value that divides exactly by a larger unit uses it, even when that
    /// unit is not the one an operator would have reached for first: 90000
    /// seconds is exactly 25 hours, and saying so is more useful than
    /// restating the seconds.
    #[test]
    fn duration_secs_uses_a_larger_unit_whenever_it_divides_exactly() {
        assert_eq!(duration_secs(90_000), "25 hours");
        assert_eq!(duration_secs(5_400), "90 minutes");
    }

    /// Zero is a value the node rejects, but the dashboard can still be asked
    /// to render one (an older node, a hand-edited state file), and must not
    /// produce an empty cell.
    #[test]
    fn duration_secs_renders_zero() {
        assert_eq!(duration_secs(0), "0 seconds");
    }
}
