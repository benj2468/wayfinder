//! The record timestamp source, in the two forms the two targets can supply.
//!
//! Both report **milliseconds since boot**, not wall-clock time: a board has no
//! RTC and no notion of the epoch, and uptime is what correlates with the mesh's
//! own timers anyway.

/// Milliseconds since this node started.
#[cfg(target_os = "none")]
pub(crate) fn uptime_ms() -> u64 {
    // Reads the `embassy-time` driver every board already runs for the router's
    // `Clock`. A record emitted before that driver is initialised gets a
    // near-zero timestamp rather than failing — a slightly wrong time beats no
    // early record.
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

    // Saturating rather than wrapping: an overflow needs ~584 million years of
    // uptime, but it would silently reorder records if it ever happened.
    u64::try_from(START.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX)
}
