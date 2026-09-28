//! What a verifier knows about the time — the input every dated check in this
//! crate takes, in place of a bare `now_unix: u64`.
//!
//! A bare-metal node has no RTC and no NTP, so "the current time" is not a
//! value it can always produce. Spelling that absence as `0` made the two
//! honest answers — *I know the time* and *I do not* — indistinguishable from
//! a third, *it is 1970*, and the resulting behaviour was neither: four sites
//! treated zero as "judge no window" while two failed closed on it, so an
//! unclocked node half-skipped validity and the half it enforced was the half
//! that partitioned it (design 20 §2.2, Bug A).
//!
//! [`Clocked`] replaces the sentinel with the three states that actually
//! exist, and the rule that falls out is short enough to hold in one line:
//!
//! > **Signature always, window when known.**
//!
//! The signature check is the real trust boundary — it segregates one mesh
//! from another and binds a key to a MAC — and needs no clock at all. The
//! window check is a revocation *optimisation*, which the mesh enforces
//! collectively whether or not any individual board can (design 20 §5.1).

use core::time::Duration;

/// 2025-01-01T00:00:00Z: the floor below which a wall-clock reading is treated
/// as no reading at all.
///
/// A host whose real-time clock has died, or which booted before NTP answered,
/// reports a time near the epoch — and unlike an unset clock, that reading
/// *looks* like a valid instant. Certificates stamped from it would carry
/// validity windows decades in the past, and every expiry check would read
/// "not yet expired" forever.
///
/// The floor only has to be late enough that no real deployment predates it
/// and early enough never to reject a working clock; the gap between those is
/// decades wide, so the exact value is not delicate.
///
/// It catches a clock that was never *set*. It does not catch a clock that is
/// plausible and wrong — off by hours because the node booted before NTP
/// reached it, the ordinary condition of a field-deployed mesh with no
/// upstream. That is `wayfinder-clock-trust`'s question, and the two are
/// deliberately separate checks: either failing means the same thing to a
/// caller (there is no usable time here) but they fail for different reasons
/// and an operator told the wrong one will fix the wrong thing.
pub const MIN_PLAUSIBLE_UNIX: u64 = 1_735_689_600;

/// What a verifier knows about the time, and therefore which of a
/// certificate's guarantees it can check.
///
/// Every variant checks the signature, the mesh id, the key↔MAC binding and
/// the reserved-address refusal identically. Only the *validity window* varies:
///
/// | posture | `now < not_before` | `now > not_after` |
/// |---|---|---|
/// | [`At(t)`](Self::At) | `NotYetValid` | `Expired` |
/// | [`AtLeast(f)`](Self::AtLeast) | **never checked** | `Expired` when `f > not_after` |
/// | [`Unknown`](Self::Unknown) | not checked | not checked |
///
/// A host constructs `At` from a usable reading and `Unknown` from none. Only
/// a board constructs `AtLeast`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Clocked {
    /// An authoritative reading, in unix seconds. Both ends of every window
    /// are enforced.
    At(u64),
    /// A **lower bound**, in unix seconds: "it is at least this". Proves
    /// expiry; never proves not-yet-validity.
    ///
    /// This is what a board's clock actually is, and modelling it honestly is
    /// what makes the design safe rather than merely lucky (design 20 §4.2).
    /// Every source of a board's estimate under-counts — a persisted
    /// checkpoint cannot measure powered-off time, and free-running from an
    /// anchor drifts on an internal RC oscillator — so a floor is the true
    /// shape of the knowledge. Three things follow at once:
    ///
    /// - **It cannot partition the node.** There is no `not_before`
    ///   comparison an `AtLeast` node can fail, so it can never reject a
    ///   healthy peer for being "too early", and the fast-clock disaster (a
    ///   remote board bricking itself because its oscillator drifted) becomes
    ///   *unreachable* rather than merely unlikely.
    /// - **It still enforces expiry** whenever it has evidence — the property
    ///   passive revocation rests on.
    /// - **It is monotone by construction**, so latching at the maximum makes
    ///   rollback impossible rather than merely detected.
    ///
    /// The asymmetry is the right one: accepting a certificate slightly early
    /// is benign; honouring a revoked one is not, and `AtLeast` can only err
    /// the first way.
    AtLeast(u64),
    /// No usable clock. Signature, mesh id and key-to-MAC binding are still
    /// checked; windows are not judged.
    ///
    /// A supported *running* state, not a failure — a node here still routes.
    /// What it gives up is passive revocation-by-expiry, which its clocked
    /// peers still enforce on its behalf.
    Unknown,
}

impl Clocked {
    /// The posture for a wall-clock reading in unix seconds, treating anything
    /// below [`MIN_PLAUSIBLE_UNIX`] — including the zero that every unset
    /// clock and every fail-closed path produces — as [`Unknown`](Self::Unknown).
    ///
    /// The conversion a host makes. It is deliberately not a `From<u64>` impl:
    /// an implicit `u64 → Clocked` would let the sentinel this type exists to
    /// abolish slip back in at any call site that forgot to think about it.
    pub fn from_unix(secs: u64) -> Clocked {
        if secs < MIN_PLAUSIBLE_UNIX {
            Clocked::Unknown
        } else {
            Clocked::At(secs)
        }
    }

    /// Whether this posture **proves** `instant` is in the past.
    ///
    /// True only on evidence: a lower bound past `instant` is evidence, and
    /// [`Unknown`](Self::Unknown) never is. This is the expiry test — a
    /// certificate is refused only when the verifier can show its `not_after`
    /// has gone by.
    pub fn proves_past(self, instant: u64) -> bool {
        match self {
            Clocked::At(t) | Clocked::AtLeast(t) => t > instant,
            Clocked::Unknown => false,
        }
    }

    /// Whether this posture **proves** `instant` has not arrived yet.
    ///
    /// Only [`At`](Self::At) can: a lower bound says nothing about how far
    /// ahead the true time is, so [`AtLeast`](Self::AtLeast) never proves this
    /// and an `AtLeast` verifier therefore never reports `NotYetValid`. That
    /// is the property the whole design turns on — see
    /// [`AtLeast`](Self::AtLeast).
    pub fn proves_before(self, instant: u64) -> bool {
        match self {
            Clocked::At(t) => t < instant,
            Clocked::AtLeast(_) | Clocked::Unknown => false,
        }
    }

    /// Whether this posture **proves** `instant` has been reached — that the
    /// time is at or past it.
    ///
    /// The companion to [`proves_past`](Self::proves_past), and distinct from
    /// it at the boundary: `proves_past` answers a strict `now > instant`,
    /// which is what a certificate's half-open `not_after` wants, while this
    /// answers `now >= instant`, which is what a revocation record's half-open
    /// `not_after` wants. Two comparisons that differ by one, spelled once
    /// each, rather than a single predicate every caller adjusts by hand.
    pub fn proves_reached(self, instant: u64) -> bool {
        match self {
            Clocked::At(t) | Clocked::AtLeast(t) => t >= instant,
            Clocked::Unknown => false,
        }
    }

    /// Whether this posture judges validity windows at all.
    ///
    /// Observability, not policy: a node that answers `false` here is routing
    /// while enforcing no expiry, which is a supported state an operator
    /// nonetheless needs told about.
    pub fn judges_windows(self) -> bool {
        !matches!(self, Clocked::Unknown)
    }

    /// The underlying reading, when there is one — `None` under
    /// [`Unknown`](Self::Unknown).
    ///
    /// Under [`AtLeast`](Self::AtLeast) this is the floor, not the time. A
    /// caller that treats it as the time is making a claim this posture does
    /// not support, which is why this is **private**: the predicates
    /// ([`proves_past`](Self::proves_past),
    /// [`proves_before`](Self::proves_before),
    /// [`proves_reached`](Self::proves_reached)) cannot be misread, and an
    /// escape hatch beside them would let a caller reach around the one
    /// invariant this type exists to guarantee.
    fn reading(self) -> Option<u64> {
        match self {
            Clocked::At(t) | Clocked::AtLeast(t) => Some(t),
            Clocked::Unknown => None,
        }
    }

    /// [`reading`](Self::reading) with the historical zero sentinel for
    /// `Unknown`, for the dated paths design 20 deliberately left alone —
    /// revocation-record windows, whose behaviour at zero is load-bearing and
    /// documented where it is consumed.
    ///
    /// Only for those. New code takes the posture.
    pub fn unix_or_zero(self) -> u64 {
        self.reading().unwrap_or(0)
    }
}

/// A node's own wall clock when it has no way to measure one: an **anchor**
/// somebody handed it, plus however much monotonic time has passed since.
///
/// The whole type is built around two invariants (design 20 §4.4), and the
/// design rests on them:
///
/// * **The estimate never runs ahead of true time, and never decreases within
///   a boot session.** Free-running advance is monotone by construction, and a
///   new anchor is taken as `max` against the current estimate. Across a
///   reboot it *does* fall back — to whatever was last persisted, which cannot
///   account for powered-off time — and that is safe precisely because the
///   posture is a floor rather than a reading.
/// * **No caller may move it from something that arrived over the radio.** Not
///   a peer's certificate, not a signed beacon from the authority. This one is
///   a convention rather than a type guarantee — [`anchor`](Self::anchor)
///   takes a bare `u64` — so it is stated here and kept by there being exactly
///   two production callers, both in `RouterAdapter`. A `max` over
///   peers' `not_before`s looks attractive and is defeated in exactly the case
///   it exists for: the max resets on reboot, so an attacker who isolates a
///   booting node chooses which certificates it hears and therefore picks its
///   floor — and one misissued far-future certificate is public, replayable
///   forever, and would pin every board that read it, with no revocation path,
///   because the poisoning works through a field read *before* anything can be
///   judged.
///
/// What it produces is therefore always [`Clocked::AtLeast`] or
/// [`Clocked::Unknown`], never [`Clocked::At`]: every source under-counts. The
/// oscillator is an internal RC part on both nRF boards (the dongle has no
/// crystal), roughly ±250 ppm or twenty seconds a day; and a checkpoint cannot
/// measure how long the board was powered off, so on restore it can claim only
/// "at least the last thing I wrote down". Behind is safe. Ahead is not.
///
/// Deliberately owns no clock of its own: every method takes the caller's
/// monotonic `now`. That keeps it a plain deterministic value a host test can
/// drive on a virtual clock, with the board supplying the real `embassy_time`
/// reading — the same split `AlarmBoard` uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WallClock {
    /// The anchor: the unix second believed true at a monotonic instant, and
    /// that instant. `None` until something anchors it.
    ///
    /// Stored as the pair rather than as a running estimate so the free-run is
    /// recomputed from an immutable origin — an estimate updated in place would
    /// need every reader to have advanced it, and a reader that forgot would
    /// silently report a stale floor.
    anchor: Option<(u64, Duration)>,
}

impl WallClock {
    /// A node that has never been anchored: [`Clocked::Unknown`], and routing.
    pub const fn new() -> WallClock {
        WallClock { anchor: None }
    }

    /// The current estimate in unix seconds, or `None` while unanchored.
    ///
    /// A **floor**, not a reading — see the type's doc. `now` is the caller's
    /// monotonic clock, the same one the anchor was taken against.
    pub fn estimate(&self, now: Duration) -> Option<u64> {
        let (unix, at) = self.anchor?;
        Some(unix.saturating_add(now.saturating_sub(at).as_secs()))
    }

    /// The posture to hand certificate verification.
    pub fn posture(&self, now: Duration) -> Clocked {
        match self.estimate(now) {
            Some(secs) => Clocked::AtLeast(secs),
            None => Clocked::Unknown,
        }
    }

    /// Take `unix` as the node's anchor, if it is plausible and later than what
    /// the node already believes. Returns whether the estimate moved.
    ///
    /// The `max` is what makes rollback impossible rather than merely
    /// detected, and it is taken against the *current* estimate rather than
    /// against the stored anchor — otherwise a correction equal to an old
    /// anchor would discard the free-run since.
    ///
    /// # The boot rule, for whoever persists a checkpoint (#54)
    ///
    /// Restoring a checkpoint at boot is this call, with the persisted value —
    /// and going through the `max` is the point, so a stale page read after a
    /// later correction cannot pull the estimate back. [`estimate`](Self::estimate)
    /// is what to persist.
    ///
    /// **Restore from the checkpoint and nothing else.** In particular never
    /// anchor from the node's own certificate's `not_before` at boot: that
    /// resets the expiry clock on every power cycle, by an amount that grows
    /// with the certificate's age, and anyone who can power-cycle the board
    /// triggers it. The damage is not mainly to its own credential — clocked
    /// peers reject that anyway — but to its judgement of *everyone else's*: a
    /// board with a one-year certificate rebooting at month eleven would
    /// believe it is month zero and honour any peer certificate valid then,
    /// including ones revoked-by-expiry ten months earlier.
    ///
    /// A checkpoint always under-counts — it cannot measure powered-off time —
    /// and that deficit is safe precisely because the posture is a floor.
    pub fn anchor(&mut self, unix: u64, now: Duration) -> bool {
        if unix < MIN_PLAUSIBLE_UNIX {
            return false;
        }
        if self.estimate(now).is_some_and(|current| unix <= current) {
            return false;
        }
        self.anchor = Some((unix, now));
        true
    }

    /// Anchor at a credential install: the later of the installer's clock and
    /// the certificate's own start.
    ///
    /// Taking a [`VerifiedCert`](crate::VerifiedCert) rather than a bare
    /// `not_before` is the point: **only a certificate that has already
    /// verified may move this clock**, and that precondition is the whole
    /// security of the install path — reading `not_before` off an unverified
    /// certificate would let anyone who can reach a node's management port set
    /// its clock to any instant they liked. A type that is only produced by
    /// `TrustAnchor::verify_cert` carries the precondition where a doc comment
    /// merely asserts it, and it removes the other hazard of the earlier
    /// signature, which took two same-typed `u64`s in an order nothing
    /// enforced.
    ///
    /// The certificate's start is the *stronger* of the two inputs — it is
    /// CA-signed where `installer_unix` is merely trusted — and it matters
    /// because the two are stamped by *different machines at different times*:
    /// a certificate minted three weeks ago and hand-carried on a USB stick is
    /// the intended out-of-band flow, not an edge case.
    ///
    /// A zero `installer_unix` (a host that could not vouch for its own clock)
    /// contributes nothing, leaving the certificate's start to carry the anchor
    /// on its own — so a fail-closed stamp does not mean the node is left
    /// undated.
    pub fn install_anchor(
        &mut self,
        installer_unix: u64,
        cert: &crate::cert::VerifiedCert,
        now: Duration,
    ) -> bool {
        self.anchor(installer_unix.max(cert.not_before), now)
    }
}

#[cfg(test)]
mod wall_clock_tests {
    use super::*;
    use core::time::Duration;

    /// A node that has never been anchored knows nothing, and says so.
    #[test]
    fn unanchored_is_unknown() {
        let clock = WallClock::new();
        assert_eq!(clock.posture(Duration::ZERO), Clocked::Unknown);
        assert_eq!(clock.posture(Duration::from_secs(86_400)), Clocked::Unknown);
        assert_eq!(clock.estimate(Duration::from_secs(10)), None);
        assert_eq!(clock.estimate(Duration::from_secs(10)), None);
    }

    /// An anchored node reports a **floor**, never a reading: every source of
    /// the estimate under-counts, so `AtLeast` is the honest shape and `At`
    /// would be a claim the node cannot support.
    #[test]
    fn an_anchored_node_reports_a_floor() {
        let mut clock = WallClock::new();
        assert!(clock.anchor(MIN_PLAUSIBLE_UNIX, Duration::from_secs(5)));
        assert_eq!(
            clock.posture(Duration::from_secs(5)),
            Clocked::AtLeast(MIN_PLAUSIBLE_UNIX)
        );
    }

    /// An anchor below the plausibility floor is refused and leaves the node
    /// unanchored — that is what catches a source that was never set and reads
    /// as 1970, and the zero every fail-closed host path sends.
    #[test]
    fn an_implausible_anchor_is_refused() {
        let mut clock = WallClock::new();
        assert!(!clock.anchor(0, Duration::ZERO));
        assert!(!clock.anchor(MIN_PLAUSIBLE_UNIX - 1, Duration::ZERO));
        assert_eq!(clock.posture(Duration::ZERO), Clocked::Unknown);
    }

    /// Free-running advance is monotone by construction: the estimate is the
    /// anchor plus elapsed monotonic time, and monotonic time does not go
    /// backwards.
    #[test]
    fn free_running_advance_never_decreases() {
        let mut clock = WallClock::new();
        clock.anchor(MIN_PLAUSIBLE_UNIX, Duration::from_secs(100));
        let mut last = 0;
        for elapsed in [100, 101, 160, 3_700, 90_000] {
            let now = Duration::from_secs(elapsed);
            let est = clock.estimate(now).expect("anchored");
            assert!(est >= last, "estimate went backwards at {elapsed}");
            last = est;
        }
        assert_eq!(
            clock.estimate(Duration::from_secs(160)),
            Some(MIN_PLAUSIBLE_UNIX + 60),
            "60 monotonic seconds after the anchor is 60 unix seconds after it"
        );
    }

    /// **An anchor is taken as `max` against the current estimate.** A lower
    /// one does not move the node backwards — which is what makes rollback
    /// impossible rather than merely detected, and what stops a stale
    /// `installer_unix` from undoing a correction.
    #[test]
    fn a_lower_anchor_does_not_move_the_clock_backwards() {
        let mut clock = WallClock::new();
        clock.anchor(MIN_PLAUSIBLE_UNIX + 10_000, Duration::ZERO);
        assert!(
            !clock.anchor(MIN_PLAUSIBLE_UNIX, Duration::ZERO),
            "a lower anchor is not adopted"
        );
        assert_eq!(
            clock.posture(Duration::ZERO),
            Clocked::AtLeast(MIN_PLAUSIBLE_UNIX + 10_000)
        );
        // ...and not even one that is lower only because time has passed
        // since the estimate was taken.
        assert!(!clock.anchor(MIN_PLAUSIBLE_UNIX + 10_000, Duration::from_secs(60)));
        assert_eq!(
            clock.posture(Duration::from_secs(60)),
            Clocked::AtLeast(MIN_PLAUSIBLE_UNIX + 10_060)
        );
    }

    /// A checkpoint is a high-water mark, so restoring one comes up at exactly
    /// what was written — the deficit (powered-off time, plus time since the
    /// last write) is unmeasurable and is left as slack in the floor.
    ///
    /// Persisting is `estimate` and restoring is `anchor`; #54 owns the storage
    /// either side. What this pins is the property that makes those two safe to
    /// use that way, which is design 20 §4.4's boot rule.
    #[test]
    fn a_checkpoint_restores_as_a_floor() {
        let mut clock = WallClock::new();
        clock.anchor(MIN_PLAUSIBLE_UNIX, Duration::from_secs(10));
        let written = clock
            .estimate(Duration::from_secs(3_610))
            .expect("anchored");
        assert_eq!(written, MIN_PLAUSIBLE_UNIX + 3_600);

        // A fresh boot: the monotonic clock restarts at zero.
        let mut rebooted = WallClock::new();
        rebooted.anchor(written, Duration::ZERO);
        assert_eq!(rebooted.posture(Duration::ZERO), Clocked::AtLeast(written));
    }

    /// **Restoring never moves the estimate backwards either.** A checkpoint
    /// read after a later anchor — a stale page, a re-read — must not undo it,
    /// which is why a restore goes through `anchor`'s `max` rather than
    /// assigning.
    #[test]
    fn a_stale_checkpoint_does_not_move_the_clock_backwards() {
        let mut clock = WallClock::new();
        clock.anchor(MIN_PLAUSIBLE_UNIX + 10_000, Duration::ZERO);
        clock.anchor(MIN_PLAUSIBLE_UNIX, Duration::ZERO);
        assert_eq!(
            clock.posture(Duration::ZERO),
            Clocked::AtLeast(MIN_PLAUSIBLE_UNIX + 10_000)
        );
    }

    /// A [`VerifiedCert`](crate::VerifiedCert) with the given window, for the
    /// install-anchor tests. Built by hand rather than issued: what
    /// `install_anchor` reads is `not_before`, and the point of taking a
    /// `VerifiedCert` is that only verification produces one — not that this
    /// test re-checks verification.
    fn verified_with(not_before: u64) -> crate::cert::VerifiedCert {
        crate::cert::VerifiedCert {
            mac: interfaces::frame::Mac([0, 0, 0, 0, 0, 1]),
            ed_pubkey: [0u8; 32],
            x_pubkey: [0u8; 32],
            not_before,
            not_after: not_before + 1_000,
            admin: false,
            viewer: false,
            user: false,
            member: true,
        }
    }

    /// **`install_anchor` floors at the verified certificate's own start.**
    ///
    /// A certificate minted three weeks ago and hand-carried on a USB stick is
    /// the intended out-of-band flow, so `installer_unix` and `not_before` are
    /// stamped by different machines at different times — and `not_before` is
    /// the CA-signed one. A stale installer clock therefore cannot drag the
    /// node back past the instant its own credential began.
    #[test]
    fn the_install_anchor_is_floored_at_the_certificates_start() {
        let not_before = MIN_PLAUSIBLE_UNIX + 100_000;
        let cert = verified_with(not_before);
        let mut clock = WallClock::new();
        // The installer's clock is behind the certificate's start.
        assert!(clock.install_anchor(MIN_PLAUSIBLE_UNIX, &cert, Duration::ZERO));
        assert_eq!(clock.posture(Duration::ZERO), Clocked::AtLeast(not_before));

        // And a zero stamp — an installer that could not vouch for its clock —
        // still contributes the certificate's start.
        let mut clock = WallClock::new();
        assert!(clock.install_anchor(0, &cert, Duration::ZERO));
        assert_eq!(clock.posture(Duration::ZERO), Clocked::AtLeast(not_before));
    }

    /// A certificate whose `not_before` predates the plausibility floor
    /// contributes nothing, rather than pulling the estimate below it.
    #[test]
    fn an_implausible_certificate_start_contributes_nothing() {
        let mut clock = WallClock::new();
        assert!(!clock.install_anchor(0, &verified_with(1_000), Duration::ZERO));
        assert_eq!(clock.posture(Duration::ZERO), Clocked::Unknown);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `At` is the only posture that judges both ends of a window.
    #[test]
    fn at_judges_both_ends() {
        let now = Clocked::At(150);
        assert!(now.proves_before(200), "150 is before 200");
        assert!(!now.proves_before(100));
        assert!(now.proves_past(100), "150 is past 100");
        assert!(!now.proves_past(200));
    }

    /// A lower bound proves expiry and never proves not-yet-validity, for any
    /// floor whatever — the property that makes an `AtLeast` node
    /// unpartitionable.
    #[test]
    fn at_least_proves_expiry_but_never_earliness() {
        for floor in [0, 1, 150, MIN_PLAUSIBLE_UNIX, u64::MAX] {
            assert!(
                !Clocked::AtLeast(floor).proves_before(u64::MAX),
                "a lower bound must never prove an instant is still ahead"
            );
        }
        assert!(Clocked::AtLeast(201).proves_past(200));
        assert!(
            !Clocked::AtLeast(200).proves_past(200),
            "the boundary itself is not past"
        );
        assert!(!Clocked::AtLeast(1).proves_past(200));
    }

    /// `Unknown` proves nothing in either direction, so it judges no window.
    #[test]
    fn unknown_proves_nothing() {
        assert!(!Clocked::Unknown.proves_past(0));
        assert!(!Clocked::Unknown.proves_past(u64::MAX));
        assert!(!Clocked::Unknown.proves_before(0));
        assert!(!Clocked::Unknown.proves_before(u64::MAX));
        assert!(!Clocked::Unknown.judges_windows());
        assert_eq!(Clocked::Unknown.reading(), None);
        assert_eq!(Clocked::Unknown.unix_or_zero(), 0);
    }

    /// A host reading below the plausibility floor — an unset clock reading as
    /// 1970, or the zero every fail-closed path produces — is no reading.
    #[test]
    fn an_implausible_reading_is_no_reading() {
        assert_eq!(Clocked::from_unix(0), Clocked::Unknown);
        assert_eq!(Clocked::from_unix(MIN_PLAUSIBLE_UNIX - 1), Clocked::Unknown);
        assert_eq!(
            Clocked::from_unix(MIN_PLAUSIBLE_UNIX),
            Clocked::At(MIN_PLAUSIBLE_UNIX)
        );
    }
}
