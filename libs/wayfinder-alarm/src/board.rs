//! The alarm table: plain owned state, an explicit clock, and no side effects.
//!
//! Everything that decides *what the board holds* lives here — coalescing, the
//! severity ratchet, the capacity policy, staleness — so all of it is
//! deterministic on a virtual clock and testable without a global, a lock, a
//! subscriber, or a running node. The ambient plumbing that makes it reachable
//! from a raise site is [`crate::global`]'s problem, and the mirroring into the
//! log is too.

use alloc::vec::Vec;
use core::fmt::Arguments;
use core::fmt::Write;

use crate::AlarmKind;
use crate::Raised;
use crate::Severity;
use crate::Subject;

/// Longest rendered detail retained per alarm, in bytes.
///
/// Sized for the handful of short structured values that explain a condition —
/// an observed rate, an attempt count, a window — on the same principle as the
/// logging rules: metadata, never payload bytes.
pub const DETAIL_CAP: usize = 64;

/// Distinct conditions the board holds before its capacity policy engages.
///
/// Split by target for the same reason `wayfinder-log`'s ring capacity is. On a
/// board this is a `static` competing with the router for 256 KiB of RAM (at
/// roughly 100 bytes an alarm, 16 of them is ~1.6 KiB), and there are not many
/// more distinct things a single-radio node can be simultaneously wrong about.
/// A host node has no such pressure and can be neighbours with far more peers.
#[cfg(target_os = "none")]
pub const ALARM_CAPACITY: usize = 16;
/// Distinct conditions the board holds before its capacity policy engages. See
/// the bare-metal definition.
#[cfg(not(target_os = "none"))]
pub const ALARM_CAPACITY: usize = 64;

/// One latched condition.
///
/// Identified by `(kind, subject)`: every raise of that pair folds into this
/// one row rather than adding another, which is what keeps a flood from
/// becoming a flood of alarms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alarm {
    /// What kind of condition this is.
    pub kind: AlarmKind,
    /// Who or what it is about.
    pub subject: Subject,
    /// The worst severity yet observed for this condition. Ratchets up on a
    /// raise and never down — see [`AlarmBoard::raise`].
    pub severity: Severity,
    /// Uptime in milliseconds at the first raise: when the condition started,
    /// preserved across every later observation.
    pub first_ms: u64,
    /// Uptime in milliseconds at the most recent raise. What
    /// [`is_active`](Alarm::is_active) measures from.
    pub last_ms: u64,
    /// How many raises have folded into this row, saturating. The magnitude of
    /// the condition, where the row itself is only its existence.
    pub count: u32,
    /// The most recent raise's rendered detail, truncated to [`DETAIL_CAP`].
    ///
    /// Last-writer-wins on purpose: `first_ms` and `count` already carry the
    /// history, so the useful thing for the detail to carry is the newest
    /// observation rather than the one that happened to be first.
    pub detail: heapless::String<DETAIL_CAP>,
}

impl Alarm {
    /// Whether this condition is still being asserted as of `now_ms` — that is,
    /// whether it has been re-raised within its severity's
    /// [hold window](Severity::hold_ms).
    ///
    /// Computed at read time rather than stored, and nothing expires on a
    /// timer: there is no timer to hang one on inside the `no_std` core, and a
    /// board that needed a background task to stay correct would be wrong on
    /// every target that has no executor to spare. The same reasoning that puts
    /// the routing core's rate estimates on a read-time decay.
    ///
    /// A stale alarm stays on the board. That is the point of latching: an
    /// operator who polls after a burst has ended still learns it happened.
    #[must_use]
    pub fn is_active(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_ms) <= self.severity.hold_ms()
    }
}

/// What one [`AlarmBoard::snapshot`] found.
pub struct AlarmSnapshot {
    /// Every alarm the board holds, worst first and — among equal severities —
    /// most recent first. Ordered here rather than at the consumer so every
    /// reader of a node agrees on what is at the top.
    pub alarms: Vec<Alarm>,
    /// How many raises the board's capacity policy has refused or evicted since
    /// boot. Reported so a gap is visible as a gap, exactly as
    /// `wayfinder-log`'s `LogSnapshot::dropped` is.
    pub dropped: u64,
    /// The instant this snapshot was taken, so a reader can call
    /// [`Alarm::is_active`] without a clock of its own.
    pub now_ms: u64,
}

/// The set of conditions a node currently believes are wrong.
///
/// Fixed-capacity and allocation-free on the raise path: an alarm is raised
/// from inside the very flood it reports, so it must not be able to make that
/// flood worse.
pub struct AlarmBoard {
    /// The latched conditions, at most one row per `(kind, subject)`.
    alarms: heapless::Vec<Alarm, ALARM_CAPACITY>,
    /// Raises the capacity policy refused or evicted, saturating.
    dropped: u64,
}

impl Default for AlarmBoard {
    fn default() -> Self {
        Self::new()
    }
}

impl AlarmBoard {
    /// An empty board. `const` so the process-global instance lives in a
    /// `static` with no runtime initializer — an alarm must be raisable from
    /// the first instruction, before anything has had a chance to call an
    /// `init`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            alarms: heapless::Vec::new(),
            dropped: 0,
        }
    }

    /// Report that `kind` holds for `subject`, as of `now_ms`.
    ///
    /// If the condition is already on the board this folds into its row: the
    /// count and `last_ms` advance and `detail` is replaced. The row's severity
    /// **ratchets up only** — a later, milder observation of a condition must
    /// not talk the node down from what it already saw, so the row keeps the
    /// worst severity yet reported and the raise reads as
    /// [`Coalesced`](Raised::Coalesced) rather than as a change.
    ///
    /// If it is new and the board is full, see [`evict_for`](Self::evict_for)
    /// for which of the two gives way.
    ///
    /// Infallible by construction: a detail too long for [`DETAIL_CAP`] is
    /// truncated, never rejected. Raising an alarm must never itself fail.
    pub fn raise(
        &mut self,
        kind: AlarmKind,
        subject: Subject,
        severity: Severity,
        detail: Arguments<'_>,
        now_ms: u64,
    ) -> Raised {
        if let Some(existing) = self
            .alarms
            .iter_mut()
            .find(|a| a.kind == kind && a.subject == subject)
        {
            existing.count = existing.count.saturating_add(1);
            existing.last_ms = now_ms;
            existing.detail = render(detail);
            // Capacity governs new conditions only: an update to something
            // already tracked needs no room, so a full board never freezes a
            // standing alarm at a stale count.
            return if severity > existing.severity {
                existing.severity = severity;
                Raised::Escalated
            } else {
                Raised::Coalesced
            };
        }

        if self.alarms.is_full() && !self.evict_for(severity) {
            self.dropped = self.dropped.saturating_add(1);
            return Raised::Dropped;
        }

        let alarm = Alarm {
            kind,
            subject,
            severity,
            first_ms: now_ms,
            last_ms: now_ms,
            count: 1,
            detail: render(detail),
        };
        // Either the board had room or `evict_for` just made some; a failure
        // here would drop an alarm we already paid a row for.
        let _ = self.alarms.push(alarm);
        Raised::New
    }

    /// Make room for an incoming alarm of `severity`, reporting whether it
    /// succeeded.
    ///
    /// The victim is the least severe row, and among those the stalest. It
    /// gives way only to something **strictly worse** than itself, which is
    /// what makes the policy safe in both directions:
    ///
    /// - a critical alarm always lands, so an attacker cannot fill the board
    ///   with cheap noise and hide behind it;
    /// - nothing already held is displaced by more of the same, so a flood of
    ///   fresh subjects cannot scroll a standing alarm off the board.
    ///
    /// Either outcome is counted in [`dropped`](Self::dropped) by the caller or
    /// here, because a row that silently vanished would be indistinguishable
    /// from a condition that never happened.
    fn evict_for(&mut self, severity: Severity) -> bool {
        let Some((index, victim_severity)) = self
            .alarms
            .iter()
            .enumerate()
            .min_by_key(|(_, a)| (a.severity, a.last_ms))
            .map(|(i, a)| (i, a.severity))
        else {
            return false;
        };

        if victim_severity >= severity {
            return false;
        }

        self.alarms.swap_remove(index);
        self.dropped = self.dropped.saturating_add(1);
        true
    }

    /// Forget the condition, reporting whether it was there.
    ///
    /// The board latches, so this is the only way a row leaves other than
    /// capacity pressure — for a caller that knows a condition has genuinely
    /// been resolved rather than merely gone quiet.
    pub fn clear(&mut self, kind: AlarmKind, subject: &Subject) -> bool {
        let Some(index) = self
            .alarms
            .iter()
            .position(|a| a.kind == kind && a.subject == *subject)
        else {
            return false;
        };
        self.alarms.swap_remove(index);
        true
    }

    /// Every latched condition, in no particular order — [`snapshot`](
    /// Self::snapshot) is what imposes one.
    #[must_use]
    pub fn alarms(&self) -> &[Alarm] {
        &self.alarms
    }

    /// How many raises the capacity policy has refused or evicted since boot.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The board as a reader sees it: ordered worst first, then most recent
    /// first, and stamped with `now_ms` so the reader can judge staleness
    /// without a clock of its own.
    #[must_use]
    pub fn snapshot(&self, now_ms: u64) -> AlarmSnapshot {
        let mut alarms: Vec<Alarm> = self.alarms.iter().cloned().collect();
        // Reverse on both keys: worst severity first, then most recently seen.
        alarms.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| b.last_ms.cmp(&a.last_ms))
        });
        AlarmSnapshot {
            alarms,
            dropped: self.dropped,
            now_ms,
        }
    }

    /// Check what every reader relies on: at most one row per `(kind, subject)`,
    /// each row's window well-formed, and no row over the string budget.
    #[cfg(test)]
    fn assert_invariants(&self) {
        assert!(
            self.alarms.len() <= ALARM_CAPACITY,
            "board over capacity: {} rows",
            self.alarms.len()
        );
        for (i, alarm) in self.alarms.iter().enumerate() {
            assert!(
                !self.alarms[..i]
                    .iter()
                    .any(|other| other.kind == alarm.kind && other.subject == alarm.subject),
                "duplicate row for {:?}/{:?} — a raise failed to coalesce",
                alarm.kind,
                alarm.subject
            );
            assert!(
                alarm.first_ms <= alarm.last_ms,
                "a condition cannot have been last seen before it started"
            );
            assert!(
                alarm.count >= 1,
                "a row on the board was raised at least once"
            );
            assert!(alarm.detail.len() <= DETAIL_CAP);
        }
    }
}

/// Render `detail` into the fixed-capacity string, truncating on a character
/// boundary.
///
/// `heapless::String`'s own `write_str` rejects a whole write that does not fit
/// rather than taking a prefix of it, which would silently turn a long detail
/// into *no* detail — so the writer below takes what fits instead. It also
/// reports success unconditionally: formatting a detail must never fail a
/// raise, and a partial explanation beats none.
fn render(detail: Arguments<'_>) -> heapless::String<DETAIL_CAP> {
    let mut out = heapless::String::new();
    let _ = Truncating(&mut out).write_fmt(detail);
    out
}

/// A `core::fmt::Write` that fills its target up to capacity and discards the
/// rest, splitting only on character boundaries so the result stays valid UTF-8
/// — which the protobuf `string` this is destined for requires.
struct Truncating<'a>(&'a mut heapless::String<DETAIL_CAP>);

impl Write for Truncating<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let room = DETAIL_CAP - self.0.len();
        let mut end = s.len().min(room);
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        // Bounded by the remaining room above, so this cannot fail.
        let _ = self.0.push_str(&s[..end]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ALARM_CAPACITY;
    use crate::AlarmKind;
    use crate::DETAIL_CAP;
    use crate::NodeId;
    use crate::Raised;
    use crate::Severity;
    use crate::Subject;

    /// A MAC-shaped subject from a compact literal, mirroring the `mac(n)`
    /// helper the engine tests use rather than spelling out six-byte arrays.
    fn node(n: u8) -> Subject {
        Subject::Node(NodeId::new(&[0, 0, 0, 0, 0, n]))
    }

    /// Raise with an empty detail and check the board's invariants afterwards.
    /// Most tests care about the bookkeeping, not the rendered text.
    fn raise(
        board: &mut AlarmBoard,
        kind: AlarmKind,
        subject: Subject,
        severity: Severity,
        now_ms: u64,
    ) -> Raised {
        let outcome = board.raise(kind, subject, severity, format_args!(""), now_ms);
        board.assert_invariants();
        outcome
    }

    /// The row for `(kind, subject)`, which the caller expects to exist.
    fn row<'a>(board: &'a AlarmBoard, kind: AlarmKind, subject: &Subject) -> &'a Alarm {
        board
            .alarms()
            .iter()
            .find(|a| a.kind == kind && a.subject == *subject)
            .expect("alarm should be on the board")
    }

    /// Fill the board to capacity with distinct subjects of one kind, one
    /// millisecond apart so "stalest" is unambiguous, and return the severity
    /// they all share.
    fn fill(board: &mut AlarmBoard, severity: Severity) {
        for i in 0..ALARM_CAPACITY {
            raise(
                board,
                AlarmKind::TrafficFlood,
                node(i as u8),
                severity,
                i as u64,
            );
        }
        assert_eq!(board.alarms().len(), ALARM_CAPACITY);
    }

    #[test]
    fn a_fresh_board_holds_nothing_and_has_dropped_nothing() {
        let board = AlarmBoard::new();
        board.assert_invariants();
        assert!(board.alarms().is_empty());
        assert_eq!(board.dropped(), 0);
    }

    /// The first raise of a condition is a new row carrying everything the
    /// caller supplied, with the raise instant as both ends of its window.
    #[test]
    fn a_first_raise_records_the_condition_as_a_new_row() {
        let mut board = AlarmBoard::new();

        let outcome = board.raise(
            AlarmKind::ManagementAuthFailures,
            node(3),
            Severity::Warning,
            format_args!("attempts={}", 12),
            5_000,
        );
        board.assert_invariants();

        assert_eq!(outcome, Raised::New);
        assert_eq!(board.alarms().len(), 1);
        let alarm = row(&board, AlarmKind::ManagementAuthFailures, &node(3));
        assert_eq!(alarm.severity, Severity::Warning);
        assert_eq!(alarm.count, 1);
        assert_eq!(alarm.first_ms, 5_000);
        assert_eq!(alarm.last_ms, 5_000);
        assert_eq!(alarm.detail.as_str(), "attempts=12");
    }

    /// Re-raising a condition folds into its existing row: the count and the
    /// recency advance, the detail is replaced by the newest observation, and
    /// `first_ms` still marks when the condition started.
    #[test]
    fn re_raising_a_condition_coalesces_into_its_row() {
        let mut board = AlarmBoard::new();
        board.raise(
            AlarmKind::TrafficFlood,
            node(1),
            Severity::Warning,
            format_args!("fps={}", 100),
            1_000,
        );

        let outcome = board.raise(
            AlarmKind::TrafficFlood,
            node(1),
            Severity::Warning,
            format_args!("fps={}", 900),
            4_000,
        );
        board.assert_invariants();

        assert_eq!(outcome, Raised::Coalesced);
        assert_eq!(board.alarms().len(), 1, "coalescing must not add a row");
        let alarm = row(&board, AlarmKind::TrafficFlood, &node(1));
        assert_eq!(alarm.count, 2);
        assert_eq!(alarm.first_ms, 1_000, "the condition still started at 1s");
        assert_eq!(alarm.last_ms, 4_000);
        assert_eq!(
            alarm.detail.as_str(),
            "fps=900",
            "the detail is the latest observation, not the first"
        );
    }

    /// The headline property. A flood raises per frame; the board must answer
    /// with one row and a count, because an alarm system that floods under
    /// attack is worse than no alarm system.
    #[test]
    fn a_storm_of_raises_stays_one_row() {
        let mut board = AlarmBoard::new();

        for i in 0..10_000u64 {
            board.raise(
                AlarmKind::UnauthenticatedTraffic,
                node(9),
                Severity::Critical,
                format_args!(""),
                i,
            );
        }
        board.assert_invariants();

        assert_eq!(board.alarms().len(), 1);
        assert_eq!(board.dropped(), 0, "coalescing is not a drop");
        let alarm = row(&board, AlarmKind::UnauthenticatedTraffic, &node(9));
        assert_eq!(alarm.count, 10_000);
        assert_eq!(alarm.first_ms, 0);
        assert_eq!(alarm.last_ms, 9_999);
    }

    /// The dedup key is the pair, so one misbehaving peer never masks another.
    #[test]
    fn the_same_kind_from_different_subjects_are_separate_rows() {
        let mut board = AlarmBoard::new();

        raise(
            &mut board,
            AlarmKind::TrafficFlood,
            node(1),
            Severity::Warning,
            0,
        );
        let outcome = raise(
            &mut board,
            AlarmKind::TrafficFlood,
            node(2),
            Severity::Warning,
            0,
        );

        assert_eq!(outcome, Raised::New);
        assert_eq!(board.alarms().len(), 2);
    }

    /// ...and the other half of the key: one peer doing two different wrong
    /// things is two conditions, not one.
    #[test]
    fn different_kinds_about_one_subject_are_separate_rows() {
        let mut board = AlarmBoard::new();

        raise(
            &mut board,
            AlarmKind::TrafficFlood,
            node(1),
            Severity::Warning,
            0,
        );
        let outcome = raise(
            &mut board,
            AlarmKind::OgmReplay,
            node(1),
            Severity::Warning,
            0,
        );

        assert_eq!(outcome, Raised::New);
        assert_eq!(board.alarms().len(), 2);
    }

    /// A condition that gets worse is reported at its worst: severity ratchets
    /// up on a coalescing raise, and the outcome says so.
    #[test]
    fn a_worse_raise_escalates_an_existing_alarm() {
        let mut board = AlarmBoard::new();
        raise(
            &mut board,
            AlarmKind::TrafficFlood,
            node(1),
            Severity::Info,
            0,
        );

        let outcome = raise(
            &mut board,
            AlarmKind::TrafficFlood,
            node(1),
            Severity::Critical,
            10,
        );

        assert_eq!(outcome, Raised::Escalated);
        assert_eq!(board.alarms().len(), 1);
        assert_eq!(
            row(&board, AlarmKind::TrafficFlood, &node(1)).severity,
            Severity::Critical
        );
    }

    /// The ratchet only turns one way: a later, milder observation of a
    /// condition must not talk the node down from what it already saw.
    #[test]
    fn a_milder_raise_never_de_escalates_an_existing_alarm() {
        let mut board = AlarmBoard::new();
        raise(
            &mut board,
            AlarmKind::TrafficFlood,
            node(1),
            Severity::Critical,
            0,
        );

        let outcome = raise(
            &mut board,
            AlarmKind::TrafficFlood,
            node(1),
            Severity::Info,
            10,
        );

        assert_eq!(outcome, Raised::Coalesced);
        let alarm = row(&board, AlarmKind::TrafficFlood, &node(1));
        assert_eq!(alarm.severity, Severity::Critical);
        assert_eq!(
            alarm.count, 2,
            "it is still an observation of the condition"
        );
    }

    /// Nothing expires on a timer — there is no timer to hang it on, on a board
    /// or in the sim. "Is this still happening?" is answered against the `now`
    /// of whoever asks.
    #[test]
    fn an_alarm_is_active_until_its_hold_window_elapses() {
        let mut board = AlarmBoard::new();
        raise(
            &mut board,
            AlarmKind::TrafficFlood,
            node(1),
            Severity::Warning,
            1_000,
        );
        let alarm = row(&board, AlarmKind::TrafficFlood, &node(1));
        let hold = Severity::Warning.hold_ms();

        assert!(alarm.is_active(1_000));
        assert!(alarm.is_active(1_000 + hold - 1));
        assert!(
            !alarm.is_active(1_000 + hold + 1),
            "a condition nobody has re-raised is no longer firing"
        );
    }

    /// A stale alarm stays on the board — that is the point of latching — and
    /// re-raising it makes it current again rather than starting a second row.
    #[test]
    fn a_stale_alarm_is_retained_and_can_be_re_raised() {
        let mut board = AlarmBoard::new();
        raise(
            &mut board,
            AlarmKind::TrafficFlood,
            node(1),
            Severity::Warning,
            0,
        );
        let long_after = Severity::Warning.hold_ms() * 10;
        assert!(!row(&board, AlarmKind::TrafficFlood, &node(1)).is_active(long_after));

        raise(
            &mut board,
            AlarmKind::TrafficFlood,
            node(1),
            Severity::Warning,
            long_after,
        );

        assert_eq!(board.alarms().len(), 1);
        let alarm = row(&board, AlarmKind::TrafficFlood, &node(1));
        assert!(alarm.is_active(long_after));
        assert_eq!(alarm.first_ms, 0, "the condition still started at boot");
    }

    /// The worse a condition is, the longer the node keeps claiming it until
    /// proven quiet — a de-assert delay, so a slow poller cannot miss the
    /// serious ones.
    #[test]
    fn a_worse_severity_is_held_longer() {
        assert!(Severity::Critical.hold_ms() > Severity::Warning.hold_ms());
        assert!(Severity::Warning.hold_ms() > Severity::Info.hold_ms());
    }

    /// A full board must still admit something worse than what it holds:
    /// otherwise an attacker fills it with noise and the real alarm never
    /// lands.
    #[test]
    fn a_full_board_evicts_the_stalest_least_severe_row_for_a_worse_alarm() {
        let mut board = AlarmBoard::new();
        fill(&mut board, Severity::Info);
        let stalest = node(0);

        let outcome = raise(
            &mut board,
            AlarmKind::UnauthenticatedTraffic,
            node(200),
            Severity::Critical,
            10_000,
        );

        assert_eq!(outcome, Raised::New);
        assert_eq!(board.alarms().len(), ALARM_CAPACITY);
        assert_eq!(board.dropped(), 1, "an evicted row is a visible gap");
        assert!(
            !board
                .alarms()
                .iter()
                .any(|a| a.kind == AlarmKind::TrafficFlood && a.subject == stalest),
            "the stalest of the least severe is the one that gives way"
        );
        assert_eq!(
            row(&board, AlarmKind::UnauthenticatedTraffic, &node(200)).severity,
            Severity::Critical
        );
    }

    /// The other side of that policy: what the board already holds is not
    /// displaced by more of the same, so a flood of fresh subjects cannot
    /// scroll a standing alarm off the board.
    #[test]
    fn a_full_board_drops_an_alarm_no_worse_than_what_it_holds() {
        let mut board = AlarmBoard::new();
        fill(&mut board, Severity::Warning);
        let before: alloc::vec::Vec<Alarm> = board.alarms().to_vec();

        let equal = raise(
            &mut board,
            AlarmKind::OgmReplay,
            node(200),
            Severity::Warning,
            10_000,
        );
        let lower = raise(
            &mut board,
            AlarmKind::OgmReplay,
            node(201),
            Severity::Info,
            10_001,
        );

        assert_eq!(equal, Raised::Dropped);
        assert_eq!(lower, Raised::Dropped);
        assert_eq!(board.dropped(), 2);
        assert_eq!(board.alarms(), before.as_slice(), "no row was disturbed");
    }

    /// Capacity governs *new* conditions only. An update to something the board
    /// is already tracking needs no room, and losing it would freeze a standing
    /// alarm at a stale count for as long as the board stayed full.
    #[test]
    fn a_full_board_still_coalesces_a_condition_it_already_holds() {
        let mut board = AlarmBoard::new();
        fill(&mut board, Severity::Warning);

        let outcome = raise(
            &mut board,
            AlarmKind::TrafficFlood,
            node(0),
            Severity::Warning,
            10_000,
        );

        assert_eq!(outcome, Raised::Coalesced);
        assert_eq!(board.dropped(), 0);
        let alarm = row(&board, AlarmKind::TrafficFlood, &node(0));
        assert_eq!(alarm.count, 2);
        assert_eq!(alarm.last_ms, 10_000);
    }

    #[test]
    fn clearing_removes_a_row_and_reports_whether_it_did() {
        let mut board = AlarmBoard::new();
        raise(
            &mut board,
            AlarmKind::TrafficFlood,
            node(1),
            Severity::Warning,
            0,
        );

        assert!(board.clear(AlarmKind::TrafficFlood, &node(1)));
        board.assert_invariants();
        assert!(board.alarms().is_empty());
        assert!(
            !board.clear(AlarmKind::TrafficFlood, &node(1)),
            "clearing what is not there is not an error, but it is not a change either"
        );
    }

    /// An over-long detail is truncated, not discarded: the fixed-capacity
    /// string must degrade to a prefix, and it must stay valid UTF-8 because
    /// this ends up in a protobuf `string`.
    #[test]
    fn an_over_long_detail_truncates_on_a_character_boundary() {
        let mut board = AlarmBoard::new();
        // 3 ASCII bytes then two-byte characters, so the byte budget lands
        // mid-character and the truncation has to walk back.
        let long: alloc::string::String = alloc::format!("abc{}", "é".repeat(DETAIL_CAP));

        board.raise(
            AlarmKind::TrafficFlood,
            node(1),
            Severity::Warning,
            format_args!("{long}"),
            0,
        );
        board.assert_invariants();

        let detail = &row(&board, AlarmKind::TrafficFlood, &node(1)).detail;
        assert!(detail.len() <= DETAIL_CAP);
        assert!(
            long.starts_with(detail.as_str()),
            "truncation keeps a prefix"
        );
        assert!(
            detail.len() > DETAIL_CAP - 4,
            "it truncates rather than dropping the detail on the floor"
        );
    }

    /// A snapshot is what an operator reads, so its order is part of the
    /// contract: worst first, and among equals the most recent first.
    #[test]
    fn a_snapshot_is_ordered_worst_and_most_recent_first() {
        let mut board = AlarmBoard::new();
        raise(
            &mut board,
            AlarmKind::TrafficFlood,
            node(1),
            Severity::Info,
            10,
        );
        raise(
            &mut board,
            AlarmKind::TrafficFlood,
            node(2),
            Severity::Warning,
            20,
        );
        raise(
            &mut board,
            AlarmKind::TrafficFlood,
            node(3),
            Severity::Critical,
            30,
        );
        raise(
            &mut board,
            AlarmKind::TrafficFlood,
            node(4),
            Severity::Warning,
            40,
        );

        let snapshot = board.snapshot(100);

        let order: alloc::vec::Vec<(Severity, u64)> = snapshot
            .alarms
            .iter()
            .map(|a| (a.severity, a.last_ms))
            .collect();
        assert_eq!(
            order,
            alloc::vec![
                (Severity::Critical, 30),
                (Severity::Warning, 40),
                (Severity::Warning, 20),
                (Severity::Info, 10),
            ]
        );
        assert_eq!(
            snapshot.now_ms, 100,
            "the reader needs it to judge staleness"
        );
        assert_eq!(snapshot.dropped, 0);
    }
}
