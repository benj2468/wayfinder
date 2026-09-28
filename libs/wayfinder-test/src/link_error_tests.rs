//! Link I/O error policy tests (issue #7).
//!
//! A mesh link's `send`/`recv` errors are transient by design — a serial
//! cable wiggle, a radio brownout, a reconnecting transport returning
//! `LinkError::Io` until its next call retries. The driver's event loop must
//! treat both directions with one posture: **log and continue**, never crash
//! the node on `send` and never swallow a `recv` error silently.
//!
//! These tests drive the real `Driver` (via `LinkTestRouter::from_links`) with
//! purpose-built failing links.

use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use interfaces::frame::LinkFrameData;
use interfaces::frame::Mac;
use interfaces::link::LinkError;
use tokio::time::timeout;
use wayfinder::link::LinkT;
use wayfinder::link::Received;
use wayfinder_driver::DynLinkT;

use crate::link_router::LinkTestRouter;

fn mac(n: u8) -> Mac {
    Mac([0, 0, 0, 0, 0, n])
}

// ── link doubles ──────────────────────────────────────────────────────────────

/// A link whose `send` always fails with [`LinkError::Io`], counting the
/// attempts; `recv` stays pending forever (nothing to receive).
struct SendFailLink {
    attempts: Arc<AtomicUsize>,
}

impl LinkT for SendFailLink {
    async fn send(&mut self, _origin: Mac, _data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Err(LinkError::Io)
    }

    async fn recv(&mut self) -> Result<Received<'_>, LinkError> {
        std::future::pending().await
    }
}

/// A link recording the payload of every frame sent through it; `recv` stays
/// pending forever.
struct RecordingLink {
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl LinkT for RecordingLink {
    async fn send(&mut self, _origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        #[expect(
            clippy::expect_used,
            reason = "test double: a poisoned mutex means the test already panicked"
        )]
        self.sent
            .lock()
            .expect("sent mutex poisoned")
            .push(data.payload.to_vec());
        Ok(data.payload.len())
    }

    async fn recv(&mut self) -> Result<Received<'_>, LinkError> {
        std::future::pending().await
    }
}

/// A link whose `recv` fails once with [`LinkError::Io`] and then stays
/// pending — the shape of a reconnecting transport surfacing one transient
/// error. `send` succeeds.
struct RecvFailOnceLink {
    failed: bool,
}

impl LinkT for RecvFailOnceLink {
    async fn send(&mut self, _origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        Ok(data.payload.len())
    }

    async fn recv(&mut self) -> Result<Received<'_>, LinkError> {
        if !self.failed {
            self.failed = true;
            return Err(LinkError::Io);
        }
        std::future::pending().await
    }
}

// ── log capture ───────────────────────────────────────────────────────────────

/// A `tracing` writer appending to a shared buffer, so a test can assert on
/// the log lines the driver emitted while it ran.
#[derive(Clone)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl LogCapture {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    fn contents(&self) -> String {
        #[expect(
            clippy::expect_used,
            reason = "test helper: a poisoned mutex means the test already panicked"
        )]
        let buf = self.0.lock().expect("log buffer mutex poisoned");
        String::from_utf8_lossy(&buf).into_owned()
    }
}

impl Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        #[expect(
            clippy::expect_used,
            reason = "test helper: a poisoned mutex means the test already panicked"
        )]
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

/// Install a scoped subscriber capturing records at `level`-and-up for the
/// duration of the returned guard.
fn capture_at(level: tracing::Level) -> (LogCapture, tracing::subscriber::DefaultGuard) {
    let capture = LogCapture::new();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    (capture, guard)
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// A `send` I/O error on a mesh link must not abort the event loop: the OGM
/// dispatch attempts the send, the link fails, and `poll_due` still returns
/// `Ok` — the production `run()` loop would keep running and retry on the
/// next tick, giving a reconnecting link its chance.
#[tokio::test]
async fn send_error_does_not_abort_the_loop() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let link = SendFailLink {
        attempts: attempts.clone(),
    };
    let mut tr = LinkTestRouter::from_links(mac(1), vec![DynLinkT::new_box(link)], Vec::new());

    let result = tr.driver().poll_due(Duration::from_secs(1)).await;

    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "the OGM send must have been attempted on the failing link"
    );
    assert!(
        result.is_ok(),
        "a link send error must not propagate out of the event loop: {result:?}"
    );
}

/// A `send` failure on one interface must not prevent the same frame from
/// going out the remaining interfaces: a broadcast fanned out to
/// [failing, healthy] still reaches the healthy link.
#[tokio::test]
async fn send_error_on_one_link_does_not_block_others() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let sent = Arc::new(Mutex::new(Vec::new()));
    let failing = SendFailLink {
        attempts: attempts.clone(),
    };
    let recording = RecordingLink { sent: sent.clone() };
    let mut tr = LinkTestRouter::from_links(
        mac(1),
        vec![DynLinkT::new_box(failing), DynLinkT::new_box(recording)],
        Vec::new(),
    );

    // A broadcast host frame floods out every interface (Egress::Auto → All);
    // interface 0 fails, interface 1 must still transmit.
    tr.send_local(Mac::BROADCAST, b"payload-past-a-failing-link")
        .await
        .unwrap_or_else(|e| panic!("send_local failed: {e:?}"));
    let result = tr.driver().process_pending().await;

    assert!(
        result.is_ok(),
        "a link send error must not propagate out of the event loop: {result:?}"
    );
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "the failing link must have been attempted"
    );
    #[expect(
        clippy::expect_used,
        reason = "test: a poisoned mutex means the test already panicked"
    )]
    let recorded_len = sent.lock().expect("sent mutex poisoned").len();
    assert_eq!(
        recorded_len, 1,
        "the healthy link after the failing one must still have transmitted"
    );

    // And the bytes actually reached the router's counters — on the link that
    // sent them, and only that one.
    //
    // `record_tx` used to happen inside `send_on_link`, right after the await.
    // It is now collected and applied in a batch once every send has finished,
    // so that no router lock is held across a radio transmission. Nothing
    // asserted it afterwards: delete the batch loop and `GetThroughput` reports
    // zero forever on every host node, with the whole suite green.
    //
    // Asserted as "some vs none" rather than an exact byte count, because the
    // frame carries a header and an auth trailer whose sizes are not this
    // test's business — what is being pinned is that the recording happens at
    // all, and that a failed send records nothing.
    // Evaluated against the driver's own clock, a second on from the send it
    // stamped. A fixed instant of this test's choosing does not work: the
    // driver stamps `record_tx` with `start.elapsed()` — real time — so a
    // literal like `1ms` is *behind* the send on any run where startup and
    // dispatch took longer than that, and `RateEstimator::rate` then reports
    // the un-blended (zero) EWMA for a link that did transmit.
    let now = tr.driver().elapsed() + Duration::from_secs(1);
    let (failed_iface, healthy_iface) = tr
        .with_router(|router| {
            (
                router.interface_throughput(0, now).map(|t| t.tx_bps),
                router.interface_throughput(1, now).map(|t| t.tx_bps),
            )
        })
        .await;
    assert_eq!(
        failed_iface.unwrap_or(0.0),
        0.0,
        "a link whose send failed must record no transmitted bytes"
    );
    assert!(
        healthy_iface.unwrap_or(0.0) > 0.0,
        "the healthy link transmitted, so its bytes must reach the router's \
         throughput counters: got {healthy_iface:?}"
    );
}

/// A `recv` error must neither wedge nor kill the loop iteration — with only
/// the mesh arm enabled, `run_once` must complete `Ok` (today the error is
/// mapped to a disabled select arm, which panics the bare-mesh select) — and
/// it must leave a WARN record rather than vanishing silently.
#[tokio::test]
async fn recv_error_is_logged_and_survived() {
    // TRACE rather than WARN — see `process_pending_survives_recv_error`.
    let (capture, _guard) = capture_at(tracing::Level::TRACE);

    let link = RecvFailOnceLink { failed: false };
    let mut tr = LinkTestRouter::from_links(mac(1), vec![DynLinkT::new_box(link)], Vec::new());

    let result = timeout(
        Duration::from_secs(1),
        tr.driver()
            .run_once(Duration::from_secs(1), false, true, false, false),
    )
    .await;

    let outcome = result.unwrap_or_else(|_| panic!("run_once hung on a link recv error"));
    assert!(
        outcome.is_ok(),
        "a link recv error must not propagate out of the event loop: {outcome:?}"
    );

    let logs = capture.contents();
    assert!(
        logs.contains("TRACE") && logs.contains("drop: link recv error"),
        "a link recv error must be traced, not swallowed; captured logs: {logs:?}"
    );
}

/// The deterministic drain path (`process_pending`) shares the same policy: a
/// `recv` error is logged and skipped, and the sweep completes `Ok` instead of
/// bailing out.
#[tokio::test]
async fn process_pending_survives_recv_error() {
    // TRACE, not WARN: a link recv error is per-frame and reachable by ambient
    // conditions (a noisy or jammed radio can fail every `recv`), so logging it
    // at WARN would flood the bounded `GetLogs` ring that is the only
    // observability a board without a debug probe has.
    let (capture, _guard) = capture_at(tracing::Level::TRACE);

    let link = RecvFailOnceLink { failed: false };
    let mut tr = LinkTestRouter::from_links(mac(1), vec![DynLinkT::new_box(link)], Vec::new());

    let result = tr.driver().process_pending().await;

    assert!(
        result.is_ok(),
        "a link recv error must not fail the deterministic drain: {result:?}"
    );
    let logs = capture.contents();
    assert!(
        logs.contains("TRACE") && logs.contains("drop: link recv error"),
        "a link recv error must be traced, not swallowed; captured logs: {logs:?}"
    );
}

/// A node configured with no mesh links at all (`links: []`, a valid
/// dashboard-only/no-radio config) must not crash the production event loop.
/// `futures::future::select_all` panics if constructed over an empty
/// iterator, and the mesh arm's `select!` guard (`if check_mesh && ...`)
/// only gates whether the already-constructed future is *polled* — Rust
/// evaluates every branch's expression up front regardless of its guard, so
/// the panic fires during construction, before the guard is ever consulted.
/// Every iteration of the production `run()` loop on a linkless node hits
/// this line.
#[tokio::test]
async fn run_once_with_no_mesh_links_does_not_panic() {
    let mut tr = LinkTestRouter::from_links(mac(1), Vec::new(), Vec::new());
    tr.send_local(mac(2), b"payload")
        .await
        .unwrap_or_else(|e| panic!("send_local failed: {e:?}"));

    let result = timeout(
        Duration::from_secs(1),
        tr.driver()
            .run_once(Duration::from_secs(1), true, true, false, false),
    )
    .await;

    let outcome = result.unwrap_or_else(|_| panic!("run_once hung with no mesh links"));
    assert!(
        outcome.is_ok(),
        "an empty mesh interfaces list must not propagate out of the event loop: {outcome:?}"
    );
}

// ── the tokio shell's periodic arm ───────────────────────────────────────────
//
// These drive `Driver::run_once` — the *production* loop body — rather than the
// `poll_due`/`poll_due_keepalive` test helpers beside it. That distinction is
// the whole point: the periodic arm enumerates its `poll_due_*` calls by hand
// while the sleep above it folds in every schedule's deadline, so a schedule
// can be waited on and never serviced. It happened: `poll_due_pings` was added
// to `poll_due_all` and to the tick and embedded shells, and missed here — the
// one shell `bins/wayfinder-tap` actually runs. Every test in the repo passed,
// because they all drive the tick driver.

/// A probe that has fallen due must actually be serviced when the tokio
/// driver's own periodic arm runs.
///
/// Asserts against `run_once` — the production loop body — rather than the
/// `poll_due`/`poll_due_keepalive` helpers beside it, so it fails if a future
/// schedule is folded into that arm's sleep and left out of the arm.
///
/// The assertion is the session's own counter rather than a frame on the wire:
/// this harness has no route to the target, so `plan_dispatch` resolves no
/// egress and drops the frame after the router has counted it. What is under
/// test is whether the arm *services the schedule*, which is exactly what was
/// missing; the wire path is covered by the multi-hop integration tests.
#[tokio::test]
async fn the_periodic_arm_services_a_due_probe() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let recording = RecordingLink { sent };
    let mut tr = LinkTestRouter::from_links(mac(1), vec![DynLinkT::new_box(recording)], Vec::new());

    tr.with_router_mut(|r| {
        r.start_ping(
            Duration::ZERO,
            mac(9),
            2,
            Duration::from_millis(100),
            Duration::from_secs(5),
            0,
        );
    })
    .await;

    // Only the periodic arm, so nothing races it. The probe is due, so the
    // arm's sleep is zero-length; the timeout is a backstop against the bug
    // this test exists for, whose symptom is a loop that never settles.
    timeout(
        Duration::from_secs(5),
        tr.driver()
            .run_once(Duration::ZERO, false, false, false, true),
    )
    .await
    .expect("the periodic arm must not hang on a due probe")
    .expect("run_once");

    assert_eq!(
        tr.with_router(|r| r.ping_session(1).map(|s| s.sent()))
            .await,
        Some(1),
        "the periodic arm must service the probe schedule"
    );
}

/// And the deadline it was woken by must be discharged.
///
/// The other half of the same bug, and the more damaging half: a fresh session
/// is due *now*, so `next_ping_after` returns zero and the arm's sleep is
/// zero-length. An arm that waits on that deadline without servicing it
/// re-sleeps zero forever — the node busy-spins at full tilt holding the router
/// write lock, from one `Ping` RPC, with no way to stop it short of a restart.
#[tokio::test]
async fn servicing_a_probe_clears_the_deadline_it_woke_on() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let recording = RecordingLink { sent };
    let mut tr = LinkTestRouter::from_links(mac(1), vec![DynLinkT::new_box(recording)], Vec::new());

    // A long cadence, so "the next probe is due" and "the deadline never
    // moved" are distinguishable instants. At the default 100 ms they are not,
    // and the assertion below would pass or fail on scheduling noise.
    tr.with_router_mut(|r| {
        r.start_ping(
            Duration::ZERO,
            mac(9),
            2,
            Duration::from_secs(10),
            Duration::from_secs(30),
            0,
        );
    })
    .await;

    assert_eq!(
        tr.with_router(|r| r.next_ping_after(Duration::ZERO)).await,
        Some(Duration::ZERO),
        "a fresh session is due at once — this is the deadline that spins"
    );

    timeout(
        Duration::from_secs(5),
        tr.driver()
            .run_once(Duration::ZERO, false, false, false, true),
    )
    .await
    .expect("the periodic arm must not hang")
    .expect("run_once");

    // Read at a `now` past the arm's own instant: the arm re-samples the clock
    // from the driver's start (`start.elapsed()`), so querying at zero would
    // ask what was due *before* the probe went out and get zero back for a
    // reason that has nothing to do with the bug.
    let next = tr
        .with_router(|r| r.next_ping_after(Duration::from_secs(1)))
        .await
        .expect("the session still has a probe to send");
    assert!(
        !next.is_zero(),
        "after servicing, the deadline must move forward — a zero here is a busy-spin"
    );
}
