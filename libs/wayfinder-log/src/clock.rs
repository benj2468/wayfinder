//! The record timestamp source, in the two forms the two targets can supply.
//!
//! Both report **milliseconds since boot** rather than wall-clock time. A board
//! has no RTC and no notion of the epoch, so uptime is the one reading available
//! identically everywhere — and it is the reading that correlates with the
//! mesh's own timers, which is what an operator is usually trying to line a log
//! record up against.

/// Milliseconds since this node started.
#[cfg(target_os = "none")]
pub(crate) fn uptime_ms() -> u64 {
    // Every board in this repo already runs an `embassy-time` driver for the
    // router's `Clock`, so this reads a clock they keep anyway. Before that
    // driver is initialised (a record emitted during early bring-up) this reads
    // as a near-zero timestamp rather than failing — an early record with a
    // slightly wrong time is worth far more than no early record.
    embassy_time::Instant::now().as_millis()
}

/// Milliseconds since this process started.
#[cfg(not(target_os = "none"))]
pub(crate) fn uptime_ms() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;

    /// Fixed on first use rather than at `init`, so records emitted before any
    /// subscriber is installed still get a sane timestamp.
    static START: OnceLock<Instant> = OnceLock::new();

    // Saturating: `as_millis` is `u128` and a process would have to run for
    // ~584 million years to overflow `u64` here, but a wrap would silently
    // reorder records, so it is worth not being able to happen.
    u64::try_from(START.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX)
}
