//! Link I/O error policy tests (issue #5).
//!
//! A mesh link's `send`/`recv` errors are transient by design — a serial
//! cable wiggle, a radio brownout, a reconnecting transport returning
//! `LinkError::Io` until its next call retries. The driver's event loop must
//! treat both directions with one posture: **log and continue**, never crash
//! the node on `send` and never swallow a `recv` error silently.
//!
//! These tests drive the real `Driver` (via `TestRouter::from_links`) with
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

use crate::test_router::TestRouter;

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
    let mut tr = TestRouter::from_links(mac(1), vec![DynLinkT::new_box(link)], Vec::new());

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
    let mut tr = TestRouter::from_links(
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
    let recorded = sent.lock().expect("sent mutex poisoned");
    assert_eq!(
        recorded.len(),
        1,
        "the healthy link after the failing one must still have transmitted"
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
    let mut tr = TestRouter::from_links(mac(1), vec![DynLinkT::new_box(link)], Vec::new());

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
    let mut tr = TestRouter::from_links(mac(1), vec![DynLinkT::new_box(link)], Vec::new());

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
