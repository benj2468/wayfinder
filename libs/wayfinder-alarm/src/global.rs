//! Making a board reachable from a raise site that holds no handle.
//!
//! A detector lives wherever the state it watches lives — deep in the routing
//! core, in a link's receive path, in the management transport's authentication
//! check. Threading a board reference to all of those would mean changing every
//! signature between here and there, and on an embedded node several of those
//! call sites have no owner to thread it from. So the board is ambient, the way
//! a `tracing` subscriber is.
//!
//! [`PROCESS_BOARD`] is the default and, on a real node, the only one: a board
//! or a host running one `wayfinder-tap` is one node per process. The simulator
//! is the exception — many nodes, one process — and [`with_board`] is what gives
//! it per-node attribution, exactly as `tracing`'s `Dispatch` has both a global
//! default and a scoped override.
//!
//! This layer also owns the side effect the pure board deliberately does not:
//! mirroring a *new* or *escalated* alarm into the log.

use core::fmt::Arguments;

use crate::AlarmBoard;
use crate::AlarmKind;
use crate::AlarmSnapshot;
use crate::Raised;
use crate::Severity;
use crate::Subject;

use wayfinder_log::Lock;

/// An [`AlarmBoard`] usable through a shared reference, and the layer that
/// stamps and mirrors what goes onto it.
///
/// A raise site holds no exclusive reference to anything — that is the whole
/// point — so every method here takes `&self`.
pub struct SharedBoard {
    /// The board proper. The lock is `wayfinder-log`'s, so the
    /// `critical-section`-versus-`std::sync::Mutex` decision, and the reasoning
    /// about how long a board's interrupts stay masked, exist in one place
    /// rather than two that can drift.
    inner: Lock<AlarmBoard>,
}

impl Default for SharedBoard {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedBoard {
    /// An empty board. `const` so [`PROCESS_BOARD`] needs no initializer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: Lock::new(AlarmBoard::new()),
        }
    }

    /// Raise, stamped with the shared uptime clock.
    ///
    /// The timebase is `wayfinder-log`'s, so an alarm's timestamp and the
    /// timestamps of the log records around it are directly comparable.
    pub fn raise(
        &self,
        kind: AlarmKind,
        subject: Subject,
        severity: Severity,
        detail: Arguments<'_>,
    ) -> Raised {
        self.raise_at(kind, subject, severity, detail, wayfinder_log::uptime_ms())
    }

    /// Raise at an explicit instant, for a caller that keeps its own clock —
    /// a tick-driven simulation, or a test.
    pub fn raise_at(
        &self,
        kind: AlarmKind,
        subject: Subject,
        severity: Severity,
        detail: Arguments<'_>,
        now_ms: u64,
    ) -> Raised {
        let outcome = self
            .inner
            .with(|board| board.raise(kind, subject, severity, detail, now_ms));
        self.mirror(outcome, kind, subject, severity, now_ms);
        outcome
    }

    /// Mirror a raise into the log, if it was news.
    ///
    /// Only [`New`](Raised::New) and [`Escalated`](Raised::Escalated) produce a
    /// record. A coalesced raise must not, or the log becomes the flood the
    /// alarm is reporting; a *dropped* one must not either, and that is the less
    /// obvious half — a full board under a storm of fresh subjects is exactly
    /// when a per-raise record would do the most damage. What a drop costs is
    /// carried by [`AlarmSnapshot::dropped`] instead, which is a count and
    /// cannot flood.
    ///
    /// The level is `warn!` for anything actionable and `info!` for the rest,
    /// with the alarm's own severity as a field. Not `error!`, deliberately:
    /// this project reserves that for failures originating in *this* node and
    /// not reachable by peer input, and most alarms are precisely the opposite
    /// — a remote party's behaviour is what raises them.
    fn mirror(
        &self,
        outcome: Raised,
        kind: AlarmKind,
        subject: Subject,
        severity: Severity,
        now_ms: u64,
    ) {
        if !matches!(outcome, Raised::New | Raised::Escalated) {
            return;
        }
        // Read back the row so the record carries the coalesced count and the
        // detail exactly as the board stored them, rather than a second
        // rendering that could disagree with what a reader later sees.
        let (count, detail) = self.inner.with(|board| {
            board
                .alarms()
                .iter()
                .find(|a| a.kind == kind && a.subject == subject)
                .map_or((0, heapless::String::new()), |a| {
                    (a.count, a.detail.clone())
                })
        });
        let escalated = matches!(outcome, Raised::Escalated);
        match severity {
            Severity::Info => tracing::info!(
                alarm = kind.as_str(),
                severity = severity.as_str(),
                %subject,
                count,
                escalated,
                uptime_ms = now_ms,
                detail = detail.as_str(),
                "alarm raised"
            ),
            Severity::Warning | Severity::Critical => tracing::warn!(
                alarm = kind.as_str(),
                severity = severity.as_str(),
                %subject,
                count,
                escalated,
                uptime_ms = now_ms,
                detail = detail.as_str(),
                "alarm raised"
            ),
        }
    }

    /// Forget a condition. See [`AlarmBoard::clear`].
    pub fn clear(&self, kind: AlarmKind, subject: &Subject) -> bool {
        self.inner.with(|board| board.clear(kind, subject))
    }

    /// The board as a reader sees it, as of the shared uptime clock.
    #[must_use]
    pub fn snapshot(&self) -> AlarmSnapshot {
        self.snapshot_at(wayfinder_log::uptime_ms())
    }

    /// The board as a reader sees it, as of an explicit instant.
    #[must_use]
    pub fn snapshot_at(&self, now_ms: u64) -> AlarmSnapshot {
        self.inner.with(|board| board.snapshot(now_ms))
    }
}

/// The node's board.
///
/// A `static` for the same reason `wayfinder-log`'s ring is one: what writes it
/// is scattered across the whole stack with no handle to carry, and what reads
/// it — a management-API adapter — has no path to a reference either. On every
/// real node this is *the* board, because a node is a process.
static PROCESS_BOARD: SharedBoard = SharedBoard::new();

/// The process-wide default board.
///
/// Reading a node's alarms means reading this one, unless the reader is itself
/// inside a [`with_board`] scope.
#[must_use]
pub fn process_board() -> &'static SharedBoard {
    &PROCESS_BOARD
}

/// The board ambient raises currently land on: the innermost [`with_board`]
/// scope on this thread, or [`PROCESS_BOARD`].
#[cfg(not(target_os = "none"))]
fn with_current<R>(f: impl FnOnce(&SharedBoard) -> R) -> R {
    match scope::current() {
        Some(board) => f(&board),
        None => f(&PROCESS_BOARD),
    }
}

/// The board ambient raises land on. Bare metal has one node and no threads to
/// scope per, so it is always the process board.
#[cfg(target_os = "none")]
fn with_current<R>(f: impl FnOnce(&SharedBoard) -> R) -> R {
    f(&PROCESS_BOARD)
}

/// Report that `kind` holds for `subject`, on whichever board is current.
///
/// This is what the [`alarm!`](crate::alarm) macro expands to and what a raise
/// site should reach for: it needs no handle, no clock and no `&mut` anything.
pub fn raise(
    kind: AlarmKind,
    subject: Subject,
    severity: Severity,
    detail: Arguments<'_>,
) -> Raised {
    with_current(|board| board.raise(kind, subject, severity, detail))
}

/// As [`raise`], at an explicit instant — for a caller that keeps its own
/// clock.
pub fn raise_at(
    kind: AlarmKind,
    subject: Subject,
    severity: Severity,
    detail: Arguments<'_>,
    now_ms: u64,
) -> Raised {
    with_current(|board| board.raise_at(kind, subject, severity, detail, now_ms))
}

/// The current board as a reader sees it.
#[must_use]
pub fn snapshot() -> AlarmSnapshot {
    with_current(SharedBoard::snapshot)
}

/// Run `f` with `board` as the target of every ambient [`raise`] on this
/// thread, restoring the previous target afterwards.
///
/// A real node never calls this: it has one board and one node, and the
/// process-global default is already right. This exists for the case that
/// breaks that assumption — the simulator running many nodes in one process,
/// where merging every node's alarms into one board would erase exactly the
/// per-node attribution its adversarial scenarios exist to show. Wrapping a
/// node's tick restores it.
///
/// Scopes nest, and the previous board is restored even if `f` panics: a
/// failing node's scope must not leak into whichever node ticks next.
///
/// Bare metal has neither threads to scope per nor a thread-local to hang the
/// scope on, and every consumer that needs one (the simulator, the test
/// harnesses) is a host — so this is host-only, the same target gate
/// `wayfinder-log` uses throughout.
#[cfg(not(target_os = "none"))]
pub fn with_board<R>(board: &alloc::sync::Arc<SharedBoard>, f: impl FnOnce() -> R) -> R {
    let _restore = scope::enter(board);
    f()
}

/// The thread-local current-board slot behind [`with_board`].
#[cfg(not(target_os = "none"))]
mod scope {
    use super::SharedBoard;
    use alloc::sync::Arc;
    use core::cell::RefCell;

    std::thread_local! {
        /// The innermost scope's board, if this thread is inside one.
        ///
        /// `Arc` rather than a borrowed reference: the simulator's boards are
        /// owned by node objects with no `'static` lifetime, and a raw pointer
        /// would need `unsafe` to justify what a refcount justifies for free.
        static CURRENT: RefCell<Option<Arc<SharedBoard>>> = const { RefCell::new(None) };
    }

    /// The board in scope on this thread, if any.
    ///
    /// Clones the `Arc` out rather than lending from inside the `RefCell`: a
    /// raise runs arbitrary formatting code, which could re-enter this module,
    /// and a live borrow across that would be a panic instead of an alarm.
    pub(super) fn current() -> Option<Arc<SharedBoard>> {
        CURRENT.with(|slot| slot.borrow().clone())
    }

    /// Install `board` as this thread's current board until the returned guard
    /// drops.
    pub(super) fn enter(board: &Arc<SharedBoard>) -> Restore {
        let previous = CURRENT.with(|slot| slot.borrow_mut().replace(Arc::clone(board)));
        Restore(previous)
    }

    /// Puts back whatever the scope displaced — the enclosing scope's board for
    /// a nested call, or `None` for an outermost one. A `Drop` impl rather than
    /// an explicit restore so an unwinding panic cannot leave a dead node's
    /// board installed.
    pub(super) struct Restore(Option<Arc<SharedBoard>>);

    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            CURRENT.with(|slot| *slot.borrow_mut() = previous);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AlarmKind;
    use crate::NodeId;
    use crate::Raised;
    use crate::Severity;
    use crate::Subject;
    use crate::alarm;
    use alloc::sync::Arc;
    use std::io::Write;
    use std::sync::Mutex;

    /// A MAC-shaped subject from a compact literal. Every test picks numbers no
    /// other test uses: the process board is genuinely shared with whatever else
    /// the suite is running in parallel, so assertions about it name a specific
    /// condition rather than counting rows.
    fn node(n: u8) -> Subject {
        Subject::Node(NodeId::new(&[0, 0, 0, 0, 0, n]))
    }

    fn board() -> Arc<SharedBoard> {
        Arc::new(SharedBoard::new())
    }

    /// Whether `board` holds a row for this condition.
    fn holds(board: &SharedBoard, kind: AlarmKind, subject: &Subject) -> bool {
        board
            .snapshot_at(0)
            .alarms
            .iter()
            .any(|a| a.kind == kind && a.subject == *subject)
    }

    /// A `SharedBoard` is written through `&self` — a raise site holds no
    /// exclusive reference to anything, which is the whole point of the layer.
    #[test]
    fn a_shared_board_is_raised_through_a_shared_reference() {
        let board = SharedBoard::new();

        let outcome = board.raise_at(
            AlarmKind::TrafficFlood,
            node(10),
            Severity::Warning,
            format_args!("fps={}", 7),
            1_234,
        );

        assert_eq!(outcome, Raised::New);
        let snapshot = board.snapshot_at(1_234);
        assert_eq!(snapshot.alarms.len(), 1);
        assert_eq!(snapshot.alarms[0].last_ms, 1_234);
        assert_eq!(snapshot.alarms[0].detail.as_str(), "fps=7");
    }

    /// Inside a scope, an ambient raise lands on the scoped board and nowhere
    /// else — this is what gives the simulator per-node attribution when many
    /// nodes share one process.
    #[test]
    fn a_scoped_board_receives_ambient_raises() {
        let scoped = board();

        with_board(&scoped, || {
            raise(
                AlarmKind::TrafficFlood,
                node(11),
                Severity::Warning,
                format_args!(""),
            );
        });

        assert!(holds(&scoped, AlarmKind::TrafficFlood, &node(11)));
        assert!(
            !holds(process_board(), AlarmKind::TrafficFlood, &node(11)),
            "a scoped raise must not also land on the process board"
        );
    }

    /// Leaving the scope restores the default, so a node that never sets one —
    /// which is every real node — still gets its alarms recorded.
    #[test]
    fn leaving_a_scope_restores_the_process_board() {
        let scoped = board();

        with_board(&scoped, || {});
        raise(
            AlarmKind::TrafficFlood,
            node(12),
            Severity::Warning,
            format_args!(""),
        );

        assert!(holds(process_board(), AlarmKind::TrafficFlood, &node(12)));
        assert!(!holds(&scoped, AlarmKind::TrafficFlood, &node(12)));
    }

    /// Nested scopes restore the *enclosing* board, not the process default.
    #[test]
    fn a_nested_scope_restores_the_board_it_replaced() {
        let outer = board();
        let inner = board();

        with_board(&outer, || {
            with_board(&inner, || {
                raise(
                    AlarmKind::TrafficFlood,
                    node(13),
                    Severity::Warning,
                    format_args!(""),
                );
            });
            raise(
                AlarmKind::TrafficFlood,
                node(14),
                Severity::Warning,
                format_args!(""),
            );
        });

        assert!(holds(&inner, AlarmKind::TrafficFlood, &node(13)));
        assert!(holds(&outer, AlarmKind::TrafficFlood, &node(14)));
        assert!(!holds(&outer, AlarmKind::TrafficFlood, &node(13)));
    }

    /// A panic inside the scope must not leave it installed: the next node's
    /// tick would otherwise file its alarms against whichever node happened to
    /// fail last.
    ///
    /// Prints a panic backtrace to stderr; that output is expected.
    #[test]
    fn a_panicking_scope_is_still_unwound() {
        let scoped = board();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_board(&scoped, || panic!("boom"));
        }));
        assert!(result.is_err());

        raise(
            AlarmKind::TrafficFlood,
            node(15),
            Severity::Warning,
            format_args!(""),
        );
        assert!(
            !holds(&scoped, AlarmKind::TrafficFlood, &node(15)),
            "the scope outlived the panic that should have ended it"
        );
    }

    /// The scope is per-thread, so two nodes ticking concurrently keep their
    /// alarms apart.
    #[test]
    fn scopes_on_two_threads_do_not_cross_contaminate() {
        let first = board();
        let second = board();

        std::thread::scope(|s| {
            for (b, n) in [(&first, 16u8), (&second, 17u8)] {
                s.spawn(move || {
                    with_board(b, || {
                        for _ in 0..1_000 {
                            raise(
                                AlarmKind::TrafficFlood,
                                node(n),
                                Severity::Warning,
                                format_args!(""),
                            );
                        }
                    });
                });
            }
        });

        assert_eq!(first.snapshot_at(0).alarms.len(), 1);
        assert_eq!(second.snapshot_at(0).alarms.len(), 1);
        assert!(holds(&first, AlarmKind::TrafficFlood, &node(16)));
        assert!(holds(&second, AlarmKind::TrafficFlood, &node(17)));
    }

    /// The macro is the raise site's actual API; it must carry the severity,
    /// the kind, the subject and the formatted detail through unchanged.
    #[test]
    fn the_macro_raises_onto_the_current_board() {
        let scoped = board();

        with_board(&scoped, || {
            alarm!(
                Severity::Critical,
                AlarmKind::UnauthenticatedTraffic,
                node(18),
                "src={} fps={}",
                "02:00:00:00:00:12",
                4200
            );
        });

        let snapshot = scoped.snapshot_at(0);
        assert_eq!(snapshot.alarms.len(), 1);
        let alarm = &snapshot.alarms[0];
        assert_eq!(alarm.kind, AlarmKind::UnauthenticatedTraffic);
        assert_eq!(alarm.subject, node(18));
        assert_eq!(alarm.severity, Severity::Critical);
        assert_eq!(alarm.detail.as_str(), "src=02:00:00:00:00:12 fps=4200");
    }

    // ── log mirroring ─────────────────────────────────────────────────────────

    /// A `tracing` writer collecting into a shared buffer, so a test can assert
    /// on what was emitted. Mirrors `wayfinder-test`'s link-error suite.
    #[derive(Clone)]
    struct LogCapture(Arc<Mutex<alloc::vec::Vec<u8>>>);

    impl LogCapture {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(alloc::vec::Vec::new())))
        }

        fn contents(&self) -> alloc::string::String {
            let buf = self.0.lock().expect("log buffer mutex poisoned");
            alloc::string::String::from_utf8_lossy(&buf).into_owned()
        }

        /// How many mirrored alarm records the buffer holds.
        fn mirrored(&self) -> usize {
            self.contents().matches("alarm raised").count()
        }
    }

    impl Write for LogCapture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("log buffer mutex poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Install a scoped subscriber capturing everything for the returned guard.
    fn capture() -> (LogCapture, tracing::subscriber::DefaultGuard) {
        let capture = LogCapture::new();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (capture, guard)
    }

    /// A new alarm mirrors into the log once, so it is correlatable with the
    /// frames around it — and a coalesced one mirrors not at all, which is what
    /// keeps a flood from turning the log into the thing it is flooding.
    #[test]
    fn only_a_new_or_escalated_alarm_reaches_the_log() {
        let scoped = board();
        let (logs, _guard) = capture();

        with_board(&scoped, || {
            scoped.raise_at(
                AlarmKind::TrafficFlood,
                node(19),
                Severity::Warning,
                format_args!(""),
                0,
            );
            assert_eq!(logs.mirrored(), 1, "a new alarm is worth one record");

            for i in 1..1_000 {
                scoped.raise_at(
                    AlarmKind::TrafficFlood,
                    node(19),
                    Severity::Warning,
                    format_args!(""),
                    i,
                );
            }
            assert_eq!(
                logs.mirrored(),
                1,
                "999 more observations of a known condition are not news"
            );

            scoped.raise_at(
                AlarmKind::TrafficFlood,
                node(19),
                Severity::Critical,
                format_args!(""),
                1_000,
            );
            assert_eq!(logs.mirrored(), 2, "getting worse is news again");
        });
    }

    /// The mirrored record carries what an operator needs to find the alarm it
    /// came from, and nothing that this project's logging rules forbid.
    #[test]
    fn the_mirrored_record_names_the_condition() {
        let scoped = board();
        let (logs, _guard) = capture();

        with_board(&scoped, || {
            scoped.raise_at(
                AlarmKind::ManagementAuthFailures,
                node(20),
                Severity::Critical,
                format_args!("attempts={}", 512),
                0,
            );
        });

        let line = logs.contents();
        assert!(line.contains("alarm raised"), "got: {line}");
        assert!(line.contains(AlarmKind::ManagementAuthFailures.as_str()));
        assert!(line.contains("critical"));
        assert!(line.contains("attempts=512"));
    }

    /// A raise the board had no room for is counted, never logged: at capacity,
    /// a flood of fresh subjects is exactly when a per-raise record would be
    /// most damaging.
    #[test]
    fn a_dropped_raise_does_not_reach_the_log() {
        let scoped = board();
        let (logs, _guard) = capture();

        with_board(&scoped, || {
            for i in 0..crate::ALARM_CAPACITY {
                scoped.raise_at(
                    AlarmKind::TrafficFlood,
                    Subject::Interface(i as u8),
                    Severity::Warning,
                    format_args!(""),
                    i as u64,
                );
            }
            let mirrored_when_full = logs.mirrored();

            for i in 0..1_000u64 {
                let outcome = scoped.raise_at(
                    AlarmKind::OgmReplay,
                    node(u8::try_from(i % 200).unwrap_or(0)),
                    Severity::Info,
                    format_args!(""),
                    10_000 + i,
                );
                assert_eq!(outcome, Raised::Dropped);
            }

            assert_eq!(logs.mirrored(), mirrored_when_full);
            assert_eq!(scoped.snapshot_at(0).dropped, 1_000);
        });
    }
}
