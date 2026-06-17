//! A Trickle-style adaptive broadcast timer (after RFC 6206), used to pace OGM
//! emission on a single interface.
//!
//! The classic fixed-interval flood wastes airtime when the topology is stable
//! yet still reacts no faster than one interval when it changes.  A Trickle
//! timer instead **doubles** its interval from `i_min` toward `i_max` for as
//! long as nothing changes, and is **reset to `i_min`** the instant the engine
//! detects an inconsistency (a new originator, a changed next hop, a lost
//! route, a membership change).  The result is near-silence in steady state and
//! fast reconvergence on change.
//!
//! Unlike the redundancy-suppression half of RFC 6206 (the `k`/consistency
//! counter, which lets one node's transmission satisfy a whole neighborhood),
//! every node *must* emit its **own** OGM — its identity and sequence number are
//! not interchangeable with a neighbor's — so this timer always fires at its
//! scheduled instant and never suppresses.  Only the adaptive-interval and
//! reset-on-inconsistency behaviour is borrowed.
//!
//! Each fire is jittered within `[interval/2, interval)` (as RFC 6206 prescribes)
//! so neighbours that reset together do not then march in lock-step and collide.

use core::time::Duration;

/// One interface's adaptive OGM emission schedule.
///
/// Times are expressed on the engine's monotonic clock (the same `now` passed
/// to [`handle_rx`](crate::BatmanEngine) and
/// [`produce_periodic_broadcast`](interfaces::engine::MeshRoutingEngine::produce_periodic_broadcast)),
/// so the owning engine and its driver share one timebase.
#[derive(Debug, Clone)]
pub struct TrickleTimer {
    /// Smallest (most aggressive) interval; the value the timer resets to on an
    /// inconsistency, and the interval it starts at.
    i_min: Duration,
    /// Largest (quietest) interval the doubling backoff is capped at.
    i_max: Duration,
    /// The current interval `I`; doubles on each emission up to `i_max`.
    interval: Duration,
    /// Absolute instant of the next scheduled emission, on the engine clock.
    next_fire: Duration,
    /// xorshift32 state for per-fire jitter.  Seeded non-zero from the owning
    /// node's identity so different nodes jitter independently.
    rng: u32,
}

impl TrickleTimer {
    /// Build a timer with the given bounds, seeded for jitter, scheduling its
    /// first emission within `[i_min/2, i_min)` after `now`.  `i_max` is clamped
    /// up to `i_min` so the bounds are always well-ordered, and `i_min` is
    /// floored at 1 ns so the interval is never zero.
    pub fn new(i_min: Duration, i_max: Duration, now: Duration, seed: u32) -> Self {
        let i_min = i_min.max(Duration::from_nanos(1));
        let i_max = i_max.max(i_min);
        // A zero seed would make xorshift stick at zero forever; fold in a
        // non-zero constant so any node identity yields a usable stream.
        let rng = seed ^ 0x9E37_79B9;
        let mut timer = Self {
            i_min,
            i_max,
            interval: i_min,
            next_fire: now,
            rng: if rng == 0 { 0x9E37_79B9 } else { rng },
        };
        timer.next_fire = now + timer.jittered(i_min);
        timer
    }

    /// Advance the xorshift32 state and return the next pseudo-random word.
    fn next_rand(&mut self) -> u32 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.rng = x;
        x
    }

    /// A jittered duration uniformly within `[span/2, span)`, per RFC 6206.
    fn jittered(&mut self, span: Duration) -> Duration {
        let span_ns = span.as_nanos() as u64;
        let half = span_ns / 2;
        // Width of the half-open window; at least 1 ns so the modulo is defined.
        let width = (span_ns - half).max(1);
        let offset = half + (self.next_rand() as u64) % width;
        Duration::from_nanos(offset)
    }

    /// Record that an emission just happened at `now`: schedule the next fire
    /// within `[interval/2, interval)`, then double the interval toward `i_max`.
    pub fn on_emit(&mut self, now: Duration) {
        let wait = self.jittered(self.interval);
        self.next_fire = now + wait;
        self.interval = (self.interval * 2).min(self.i_max);
    }

    /// Reset to the most aggressive interval after an inconsistency and
    /// reschedule the next fire within `[i_min/2, i_min)` after `now`.
    pub fn reset(&mut self, now: Duration) {
        self.interval = self.i_min;
        let wait = self.jittered(self.i_min);
        self.next_fire = now + wait;
    }

    /// Time remaining until the next scheduled emission, saturating at zero once
    /// the fire instant has passed.
    pub fn time_until(&self, now: Duration) -> Duration {
        self.next_fire.saturating_sub(now)
    }

    /// Whether an emission is due as of `now`.
    pub fn due(&self, now: Duration) -> bool {
        now >= self.next_fire
    }

    /// The current interval `I`.  Exposed for assertions on backoff progression.
    pub fn interval(&self) -> Duration {
        self.interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const I_MIN: Duration = Duration::from_secs(1);
    const I_MAX: Duration = Duration::from_secs(64);

    /// A fresh timer schedules its first fire within `[i_min/2, i_min)` and
    /// starts at the `i_min` interval.
    #[test]
    fn first_fire_is_within_i_min_window() {
        let t = TrickleTimer::new(I_MIN, I_MAX, Duration::ZERO, 1);
        assert_eq!(t.interval(), I_MIN);
        let until = t.time_until(Duration::ZERO);
        assert!(until >= I_MIN / 2 && until < I_MIN, "first fire {until:?}");
    }

    /// Each emission doubles the interval, and the scheduled wait always falls
    /// within `[interval/2, interval)` of the new interval.
    #[test]
    fn interval_doubles_on_each_emit() {
        let mut t = TrickleTimer::new(I_MIN, I_MAX, Duration::ZERO, 7);
        let mut now = Duration::ZERO;
        let mut expected = I_MIN;
        for _ in 0..5 {
            // The wait scheduled by this emit must lie in [expected/2, expected).
            t.on_emit(now);
            let wait = t.time_until(now);
            assert!(
                wait >= expected / 2 && wait < expected,
                "wait {wait:?} not within [{:?}, {:?})",
                expected / 2,
                expected
            );
            now = t.next_fire;
            expected = (expected * 2).min(I_MAX);
            assert_eq!(t.interval(), expected);
        }
    }

    /// The interval saturates at `i_max` rather than growing without bound.
    #[test]
    fn interval_caps_at_i_max() {
        let mut t = TrickleTimer::new(I_MIN, I_MAX, Duration::ZERO, 3);
        let mut now = Duration::ZERO;
        for _ in 0..20 {
            t.on_emit(now);
            now = t.next_fire;
        }
        assert_eq!(t.interval(), I_MAX);
    }

    /// `reset` collapses a grown interval back to `i_min` and reschedules the
    /// next fire into the aggressive window.
    #[test]
    fn reset_returns_to_i_min() {
        let mut t = TrickleTimer::new(I_MIN, I_MAX, Duration::ZERO, 11);
        let mut now = Duration::ZERO;
        for _ in 0..6 {
            t.on_emit(now);
            now = t.next_fire;
        }
        assert!(t.interval() > I_MIN, "interval should have grown");

        t.reset(now);
        assert_eq!(t.interval(), I_MIN);
        let until = t.time_until(now);
        assert!(
            until >= I_MIN / 2 && until < I_MIN,
            "post-reset fire {until:?}"
        );
    }

    /// Two timers with different bounds progress independently — the per-link
    /// requirement: a fast link and a slow link back off on their own schedules.
    #[test]
    fn distinct_bounds_progress_independently() {
        let fast_min = Duration::from_millis(100);
        let fast_max = Duration::from_secs(2);
        let slow_min = Duration::from_secs(5);
        let slow_max = Duration::from_secs(300);

        let mut fast = TrickleTimer::new(fast_min, fast_max, Duration::ZERO, 1);
        let mut slow = TrickleTimer::new(slow_min, slow_max, Duration::ZERO, 2);

        // The fast link's first fire is strictly sooner than the slow link's.
        assert!(fast.time_until(Duration::ZERO) < slow.time_until(Duration::ZERO));

        // Drive each a few rounds; they cap at their own ceilings.
        let mut now = Duration::ZERO;
        for _ in 0..12 {
            fast.on_emit(now);
            now = fast.next_fire;
        }
        assert_eq!(fast.interval(), fast_max);

        let mut now = Duration::ZERO;
        for _ in 0..12 {
            slow.on_emit(now);
            now = slow.next_fire;
        }
        assert_eq!(slow.interval(), slow_max);
        assert_ne!(fast_max, slow_max);
    }
}
