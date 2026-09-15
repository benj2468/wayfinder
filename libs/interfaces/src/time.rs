//! A compact monotonic instant for the routing core's stored records.
//!
//! [`Millis`] is a four-byte stand-in for [`core::time::Duration`] *in storage
//! only*. The engine's API still speaks `Duration` — a driver hands it
//! `now: Duration` and reads durations back out — but a `Duration` is sixteen
//! bytes, and the routing tables hold a great many of them: two per path, four
//! paths per originator and one more for the originator itself — nine before
//! the keep-alive table (two each) and the broadcast-dedup table (up to two
//! each) are counted. At a board's capacities that arithmetic dominates the
//! router's footprint.
//!
//! Every consumer outside the engine already converts these to milliseconds —
//! `ms_since_last_heard` and `interval_estimate_ms` on the management API, the
//! Python bindings, the TUI — so storing milliseconds is aligning the
//! representation with how it is actually read, not adding an abstraction.
//!
//! # Wrapping, and why there is no `Ord`
//!
//! A `u32` of milliseconds covers 49.7 days and then wraps. That is fine for
//! every question this type is asked, because all of them are *differences*
//! against windows measured in seconds to minutes (`batman`'s
//! `MAX_MISSED_OGMS` of 6 × a Trickle `i_max` of 128 s is under fourteen
//! minutes), and a wrapping
//! subtraction returns the true difference whenever that difference is under
//! **24.8 days** — half the range, because the sign of the difference is what
//! distinguishes "later" from "earlier". Beyond it the relation inverts, which
//! is why `batman` bounds how old a stored stamp may get (its
//! `STAMP_AGE_CEILING_MS`) rather than assuming the windows are enough on
//! their own.
//!
//! What is *not* fine is comparing two instants directly: `a < b` is wrong
//! either side of the wrap, and that is exactly the bug that would surface
//! seven weeks into an unattended deployment and nowhere in a test suite. So
//! this type deliberately implements neither [`Ord`] nor [`PartialOrd`]: there
//! is no way to spell the broken comparison *by accident*, and code that wants
//! "least recently heard" has to say [`elapsed_since`](Millis::elapsed_since)
//! and take the *largest*, which is wrap-correct. Ordering by a raw stamp
//! becomes a compile error rather than a latent one.
//!
//! [`raw`](Millis::raw) still permits it deliberately — it exists for wire
//! encoding and tests — so "no way" means "no way without saying so".
//!
//! [`PartialEq`] *is* derived, and the asymmetry is deliberate rather than an
//! oversight. `Ord` would be silently wrong for two stamps seconds apart that
//! straddle the rollover, which is the common case on any node up seven weeks.
//! `PartialEq` is only wrong for two stamps exactly 49.7 days apart — the same
//! aliasing [`elapsed_since`](Millis::elapsed_since) already accepts, and which
//! no window here can hold.

use core::time::Duration;

/// A monotonic instant on this node's own clock, in whole milliseconds.
///
/// Four bytes, where the [`Duration`] the engine's API speaks is sixteen. See
/// the module docs for why this exists, and for why it has no [`Ord`].
///
/// The value is meaningless on its own — it is an offset from whatever the
/// node's clock called zero, and it wraps every 49.7 days. The only questions
/// it answers are differences: [`elapsed_since`](Self::elapsed_since).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct Millis(u32);

impl Millis {
    /// The node's clock epoch, and the value a record carries before anything
    /// has been heard on it.
    pub const ZERO: Self = Self(0);

    /// Build a stamp from a raw millisecond count.
    #[must_use]
    pub const fn from_millis(ms: u32) -> Self {
        Self(ms)
    }

    /// Convert the `now` a driver supplies into a stamp.
    ///
    /// Truncates to whole milliseconds, and **wraps** rather than saturating
    /// past 49.7 days of uptime: saturating would pin every later stamp to
    /// `u32::MAX` and make every elapsed reading zero, where wrapping keeps
    /// [`elapsed_since`](Self::elapsed_since) correct indefinitely.
    #[must_use]
    pub const fn from_duration(now: Duration) -> Self {
        Self(now.as_millis() as u32)
    }

    /// This stamp as a [`Duration`], for handing back across an API that
    /// speaks `Duration`.
    ///
    /// Note this is the *stamp*, not a point in the caller's own time base:
    /// after a wrap it is 49.7 days behind the driver's `now`. Use it for a
    /// value that was derived as a difference, not to reconstruct an instant.
    #[must_use]
    pub const fn to_duration(self) -> Duration {
        Duration::from_millis(self.0 as u64)
    }

    /// The raw millisecond count. For tests and for encoding onto the
    /// management API; ordinary logic should be asking
    /// [`elapsed_since`](Self::elapsed_since) instead.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Milliseconds from `earlier` to `self`, or zero if `earlier` is in the
    /// future.
    ///
    /// Two properties, and both are load-bearing.
    ///
    /// It is **wrapping**, so a gap straddling the rollover measures correctly
    /// rather than reading as nearly 49.7 days. The answer is the true elapsed
    /// time for any gap under 24.8 days — half the range, because the sign of
    /// the difference is what distinguishes "later" from "earlier" — which
    /// every window in this codebase is by four orders of magnitude.
    ///
    /// It **saturates at zero** for a stamp that is ahead of `self`, which is
    /// what a clock that has gone backwards produces. That is not a detail:
    /// it is the behaviour of the `Duration::saturating_sub` this replaced,
    /// and every caller here depends on it. A backwards clock must not make
    /// every path look infinitely stale (purging a healthy routing table) nor
    /// blow through a sequence-number reset-protection window early — see
    /// `batman`'s `broadcast_dedup_a_backwards_clock_never_resyncs_early`,
    /// which is what caught this being wrong.
    #[must_use]
    pub const fn elapsed_since(self, earlier: Self) -> u32 {
        let delta = self.0.wrapping_sub(earlier.0) as i32;
        if delta < 0 { 0 } else { delta as u32 }
    }

    /// Whether this stamp is at or after `other`, judged on the *signed*
    /// difference so the answer stays correct across the rollover.
    ///
    /// This is the wrap-correct spelling of the `>=` that [`Ord`] would have
    /// given, and the reason it is a named method rather than an operator
    /// impl: it is only meaningful for two stamps known to lie within 24.8
    /// days of each other, which is every pair this codebase compares and is
    /// *not* a guarantee `Ord` could state. Beyond that half-range the
    /// relation inverts, exactly as it does for a `seqno` high-water.
    ///
    /// **No production caller today**, by design rather than neglect: it exists
    /// so the comparison [`Ord`] would have given has a correct spelling when
    /// one is needed. Its only use is an invariant assertion in `batman`'s
    /// tests, which without it would have been written with [`raw`](Self::raw)
    /// and would have been wrong.
    #[must_use]
    pub const fn is_at_or_after(self, other: Self) -> bool {
        (self.0.wrapping_sub(other.0) as i32) >= 0
    }

    /// This stamp advanced by `ms`, wrapping at the rollover.
    ///
    /// **Test-only.** Nothing in the routing core advances a stamp by
    /// arithmetic — every one is built by [`from_duration`](Self::from_duration)
    /// from a `Clock`'s `now` — so this exists to construct the far side of a
    /// rollover in the tests below. It was `pub` with no caller but its own
    /// tests, on a type whose whole point is a surface too small to misuse.
    #[cfg(test)]
    #[must_use]
    const fn wrapping_add_millis(self, ms: u32) -> Self {
        Self(self.0.wrapping_add(ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entire reason this type exists: four bytes where a `Duration` is
    /// sixteen. If this fails the refactor has bought nothing.
    #[test]
    fn a_stamp_is_four_bytes() {
        assert_eq!(core::mem::size_of::<Millis>(), 4);
        assert_eq!(core::mem::align_of::<Millis>(), 4);
    }

    /// An ordinary elapsed measurement, nowhere near the wrap.
    #[test]
    fn elapsed_since_an_earlier_stamp_is_the_gap() {
        let earlier = Millis::from_millis(1_000);
        let now = Millis::from_millis(4_500);
        assert_eq!(now.elapsed_since(earlier), 3_500);
    }

    /// Zero elapsed is a legal reading, not an edge case: two events in the
    /// same millisecond are ordinary on a fast link.
    #[test]
    fn elapsed_since_the_same_instant_is_zero() {
        let t = Millis::from_millis(7);
        assert_eq!(t.elapsed_since(t), 0);
    }

    /// The property the whole design rests on: a gap that straddles the `u32`
    /// wrap still measures correctly. A node that has been up 49.7 days must
    /// not suddenly believe every neighbour went quiet.
    #[test]
    fn elapsed_is_correct_across_the_wrap() {
        // 2 s before the wrap, to 3 s after it: a real gap of 5 s.
        let before = Millis::from_millis(u32::MAX - 1_999);
        let after = before.wrapping_add_millis(5_000);
        assert_eq!(after.elapsed_since(before), 5_000);
    }

    /// The same, stated from the other direction: adding past the wrap lands
    /// on a smaller raw value, and that is not an error.
    #[test]
    fn a_stamp_past_the_wrap_has_a_smaller_raw_value() {
        let before = Millis::from_millis(u32::MAX - 10);
        let after = before.wrapping_add_millis(100);
        assert!(
            after.raw() < before.raw(),
            "the point of the type: raw order is not time order"
        );
        assert_eq!(after.elapsed_since(before), 100);
    }

    /// "Least recently heard" is expressed as the *largest* elapsed, and that
    /// selection stays correct across the wrap where ordering by raw stamp
    /// would silently invert.
    #[test]
    fn largest_elapsed_picks_the_least_recently_heard_across_the_wrap() {
        let now = Millis::from_millis(500); // 500 ms past the wrap
        let heard_recently = Millis::from_millis(100); // 400 ms ago
        let heard_long_ago = Millis::from_millis(u32::MAX - 4_499); // 5 s ago

        assert_eq!(now.elapsed_since(heard_recently), 400);
        assert_eq!(now.elapsed_since(heard_long_ago), 5_000);

        let stalest = [heard_recently, heard_long_ago]
            .into_iter()
            .max_by_key(|t| now.elapsed_since(*t))
            .expect("two candidates");
        assert_eq!(
            stalest.raw(),
            heard_long_ago.raw(),
            "the older stamp has the larger raw value here, so a raw `min` \
             would have chosen the wrong one"
        );
    }

    /// The wrap-correct `>=`: true for equal stamps and for a later one.
    #[test]
    fn is_at_or_after_orders_two_nearby_stamps() {
        let earlier = Millis::from_millis(1_000);
        let later = Millis::from_millis(1_001);
        assert!(later.is_at_or_after(earlier));
        assert!(earlier.is_at_or_after(earlier), "at, not just after");
        assert!(!earlier.is_at_or_after(later));
    }

    /// And it stays correct across the rollover, where a raw `>=` on the
    /// underlying `u32` reports the exact opposite.
    #[test]
    fn is_at_or_after_survives_the_wrap() {
        let earlier = Millis::from_millis(u32::MAX - 10);
        let later = earlier.wrapping_add_millis(20);
        assert!(later.is_at_or_after(earlier));
        assert!(!earlier.is_at_or_after(later));
        assert!(
            earlier.raw() >= later.raw(),
            "the raw comparison really does disagree here"
        );
    }

    /// The driver hands the engine a `Duration`; this is the boundary
    /// conversion, and it truncates to whole milliseconds.
    #[test]
    fn from_duration_truncates_to_whole_milliseconds() {
        assert_eq!(
            Millis::from_duration(Duration::from_micros(1_999)).raw(),
            1,
            "sub-millisecond precision is dropped, not rounded"
        );
        assert_eq!(Millis::from_duration(Duration::from_secs(3)).raw(), 3_000);
    }

    /// A stamp from the future — a clock that has stepped backwards — reads
    /// as no elapsed time at all, never as an enormous gap. Everything
    /// downstream treats a large elapsed as "stale", so the wrapping answer
    /// would purge a healthy routing table on a backwards step.
    #[test]
    fn elapsed_since_a_future_stamp_saturates_at_zero() {
        let now = Millis::from_millis(1_000);
        let ahead = Millis::from_millis(4_000);
        assert_eq!(now.elapsed_since(ahead), 0);
    }

    /// And that clamp is judged on the *signed* difference, so it does not
    /// mistake an ordinary gap across the rollover for a backwards clock.
    #[test]
    fn the_backwards_clamp_does_not_swallow_a_wrapped_gap() {
        let before = Millis::from_millis(u32::MAX - 100);
        let after = before.wrapping_add_millis(250);
        assert_eq!(after.elapsed_since(before), 250);
        assert_eq!(before.elapsed_since(after), 0);
    }

    /// A node up longer than 49.7 days keeps producing usable stamps: the
    /// conversion wraps rather than saturating, which is what keeps
    /// `elapsed_since` correct forever rather than pinning every stamp to
    /// `u32::MAX`.
    #[test]
    fn from_duration_wraps_rather_than_saturating() {
        let wrap_ms = u64::from(u32::MAX) + 1;
        assert_eq!(
            Millis::from_duration(Duration::from_millis(wrap_ms)).raw(),
            0
        );
        assert_eq!(
            Millis::from_duration(Duration::from_millis(wrap_ms + 250)).raw(),
            250
        );
    }

    /// Reading a stamp back out at an API boundary.
    #[test]
    fn to_duration_returns_whole_milliseconds() {
        let t = Millis::from_millis(4_200);
        assert_eq!(t.to_duration(), Duration::from_millis(4_200));
    }

    /// The clock starts here, and `ZERO` is usable as a `const` initializer —
    /// the routing records are built in `const` contexts.
    #[test]
    fn zero_is_the_epoch() {
        assert_eq!(Millis::ZERO.raw(), 0);
        const _: Millis = Millis::ZERO;
    }
}
