//! What ends this node's process, and why.
//!
//! Two things the `main` loop got wrong before this module existed.
//!
//! **A background task could die silently.** Every listener and carrier this
//! binary spawns goes into one [`JoinSet`] that nothing ever joined, while
//! `driver.run()` was awaited as the last statement. A `serve_tls_server` whose
//! `accept()` returns an error therefore left the node routing perfectly with
//! no management API, no log line, and no exit — the one failure an operator
//! has no way to notice, because everything else about the node looks healthy.
//!
//! **No signal was handled at all.** `containers/Dockerfile`'s `tap` image runs
//! this binary as PID 1 with no init wrapper
//! (`ENTRYPOINT ["/usr/local/bin/wayfinder-tap"]`), and Linux gives PID 1
//! special treatment: a signal with no explicitly installed handler is ignored
//! outright, even ones — like `SIGTERM`/`SIGINT` — that would terminate an
//! ordinary process by default. So `docker stop` did nothing at all and the
//! container died only when the caller gave up and sent `SIGKILL`. Under
//! systemd the same gap shows up as `TimeoutStopSec` elapsing on every restart.
//!
//! Only [`shutdown_signal`] is shared with `bins/wayfinder-web/src/shutdown.rs`,
//! and it is deliberately a copy rather than a shared crate: twenty lines with
//! no state, where a `libs/` crate whose entire content is one `select!` would
//! cost more to find than to re-read. The `JoinSet` supervision above it has no
//! counterpart there — that binary spawns nothing it has to outlive.

use anyhow::anyhow;
use tokio::signal::unix::SignalKind;
use tokio::signal::unix::signal;
use tokio::task::JoinError;
use tokio::task::JoinSet;

/// Run `driver` until it stops, a spawned task ends, or the operator asks the
/// node to stop — whichever happens first.
///
/// Takes the driver as a future rather than a `Driver` so the three outcomes
/// can be tested without building a node.
pub async fn run_until_shutdown(
    driver: impl Future<Output = anyhow::Result<()>>,
    join_set: &mut JoinSet<anyhow::Result<()>>,
) -> anyhow::Result<()> {
    tokio::select! {
        outcome = driver => outcome,
        // `join_next` yields `None` on an empty set, which disables this branch
        // rather than resolving it — exactly right for a node with no links and
        // no management server, which has nothing here to lose.
        Some(joined) = join_set.join_next() => background_task_ended(joined),
        () = shutdown_signal() => {
            tracing::info!("shutting down on operator signal");
            Ok(())
        }
    }
}

/// Turn a finished background task into the node's exit status.
///
/// Every task in the set is something the node needs for its whole life — a
/// management listener, a UDP or raw-IP carrier, the certificate authority — so
/// there is no such thing as one of them finishing successfully. Returning
/// `Ok(())` on a clean exit would restore the silent-degradation this module
/// exists to remove: the process would end with status 0 and systemd would not
/// restart it.
fn background_task_ended(joined: Result<anyhow::Result<()>, JoinError>) -> anyhow::Result<()> {
    match joined {
        Err(e) => Err(anyhow!("a background task panicked: {e}")),
        Ok(Err(e)) => Err(e.context("a background task failed")),
        Ok(Ok(())) => Err(anyhow!(
            "a background task exited unexpectedly; this node needs every one of them \
             for its whole life"
        )),
    }
}

/// Resolves on the first `SIGINT` or `SIGTERM`.
async fn shutdown_signal() {
    tokio::select! {
        () = arm(tokio::signal::ctrl_c(), "SIGINT") => {}
        () = arm(async {
            let mut stream = signal(SignalKind::terminate())?;
            stream.recv().await;
            Ok(())
        }, "SIGTERM") => {}
    }
}

/// Resolve when `delivery` reports its signal; park forever if the handler
/// could not be installed.
///
/// Parking, never resolving, is the whole point. `tokio::signal::ctrl_c` and
/// `signal()` both fail by returning *immediately*, so a caller that treats
/// their result as "the signal arrived" reports a shutdown nobody asked for —
/// and `run_until_shutdown` would return `Ok(())`, so the process would exit 0
/// at startup and systemd's `Restart=on-failure` would not bring it back. The
/// other signal is still armed on the other branch, which is the only useful
/// thing left to do.
///
/// `error!` because it is permanent and an operator has to know: this node
/// cannot be stopped by that signal for the rest of its life.
async fn arm(delivery: impl Future<Output = std::io::Result<()>>, signal_name: &str) {
    if let Err(error) = delivery.await {
        tracing::error!(
            ?error,
            signal_name,
            "could not install the signal handler; this node will not stop on that signal"
        );
        std::future::pending::<()>().await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;
    use std::time::Duration;

    use tokio::time::timeout;

    use super::run_until_shutdown;

    /// Serialises every test in this module.
    ///
    /// `libc::raise` is process-wide and so is tokio's signal registry, so the
    /// `SIGTERM` test below wakes *any* concurrently-running test that happens
    /// to be inside `run_until_shutdown` — and `cargo nextest run` runs them on
    /// several threads in one process. Held across each test, only one stream
    /// is ever subscribed when the signal lands. Without it this suite fails
    /// intermittently and points at the wrong test.
    static SERIAL: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

    /// A listener that dies takes the node down with it, carrying its reason.
    ///
    /// This is the regression the module exists for: before it, a
    /// `serve_tls_server` whose `accept()` errored left the node routing with no
    /// management API and nothing said about it.
    #[tokio::test]
    async fn a_failed_background_task_brings_the_node_down_with_its_error() {
        let _serial = SERIAL.lock().await;
        let mut join_set = tokio::task::JoinSet::new();
        join_set.spawn(async { Err(anyhow::anyhow!("listener accept failed")) });

        let err = timeout(
            Duration::from_secs(2),
            run_until_shutdown(std::future::pending(), &mut join_set),
        )
        .await
        .expect("a dead task must not leave the node hanging")
        .expect_err("a dead task is a node failure");

        assert!(
            format!("{err:#}").contains("listener accept failed"),
            "the operator needs the original reason, got: {err:#}"
        );
    }

    /// A panicking task is reported as a panic, not swallowed into the generic
    /// case: it points at a bug in this process rather than at the network.
    #[tokio::test]
    async fn a_panicking_background_task_is_reported_as_one() {
        let _serial = SERIAL.lock().await;
        let mut join_set = tokio::task::JoinSet::new();
        join_set.spawn(async { panic!("carrier thread blew up") });

        let err = timeout(
            Duration::from_secs(2),
            run_until_shutdown(std::future::pending(), &mut join_set),
        )
        .await
        .expect("a panicking task must not leave the node hanging")
        .expect_err("a panicking task is a node failure");

        assert!(format!("{err:#}").contains("panicked"), "got: {err:#}");
    }

    /// Even a *clean* exit is a failure. Every task in the set is something the
    /// node needs for its whole life, so one returning `Ok` means the node has
    /// silently lost a capability — the exact condition this module removes.
    #[tokio::test]
    async fn a_background_task_that_exits_cleanly_is_still_a_failure() {
        let _serial = SERIAL.lock().await;
        let mut join_set = tokio::task::JoinSet::new();
        join_set.spawn(async { Ok(()) });

        timeout(
            Duration::from_secs(2),
            run_until_shutdown(std::future::pending(), &mut join_set),
        )
        .await
        .expect("must not hang")
        .expect_err("a task the node needs for life must not end quietly");
    }

    /// An empty `JoinSet` must not disable the whole `select!`.
    ///
    /// A node with no links and no management server is a valid configuration,
    /// and `join_next` resolves to `None` immediately on an empty set. If that
    /// took the other branches down with it, the least-equipped node would be
    /// the one that exited at startup.
    #[tokio::test]
    async fn an_empty_join_set_leaves_the_node_running() {
        let _serial = SERIAL.lock().await;
        let mut join_set = tokio::task::JoinSet::new();

        let outcome = timeout(
            Duration::from_millis(200),
            run_until_shutdown(std::future::pending(), &mut join_set),
        )
        .await;

        assert!(
            outcome.is_err(),
            "a node with nothing spawned must keep running, not exit"
        );
    }

    /// The driver's own failure is still what comes back when it is the thing
    /// that broke.
    #[tokio::test]
    async fn the_drivers_own_error_is_reported() {
        let _serial = SERIAL.lock().await;
        let mut join_set = tokio::task::JoinSet::new();
        join_set.spawn(std::future::pending());

        let err = timeout(
            Duration::from_secs(2),
            run_until_shutdown(
                async { Err(anyhow::anyhow!("local device closed")) },
                &mut join_set,
            ),
        )
        .await
        .expect("must not hang")
        .expect_err("a driver failure is a node failure");

        assert!(
            format!("{err:#}").contains("local device closed"),
            "got: {err:#}"
        );
    }

    /// A handler that could not be installed must PARK, never resolve.
    ///
    /// `tokio::signal::ctrl_c` fails by returning immediately, so treating its
    /// result as "the signal arrived" makes the node log a shutdown nobody
    /// requested and exit — with status 0, so systemd's `Restart=on-failure`
    /// would leave it down. This is the shape of that bug, and it is not
    /// hypothetical: it is what `let _ = tokio::signal::ctrl_c().await` does.
    #[tokio::test]
    async fn a_handler_that_cannot_be_installed_parks_rather_than_firing() {
        let _serial = SERIAL.lock().await;

        let fired = timeout(
            Duration::from_millis(200),
            super::arm(
                async { Err(std::io::Error::other("handler refused")) },
                "SIGINT",
            ),
        )
        .await;

        assert!(
            fired.is_err(),
            "a signal that could not be armed must never resolve — resolving reports a \
             shutdown nobody asked for, and exits 0 doing it"
        );
    }

    /// The arming wrapper is transparent when the handler *does* install: the
    /// signal still gets through.
    #[tokio::test]
    async fn an_armed_handler_still_resolves_when_its_signal_arrives() {
        let _serial = SERIAL.lock().await;

        timeout(
            Duration::from_secs(2),
            super::arm(async { Ok(()) }, "SIGINT"),
        )
        .await
        .expect("a delivered signal must resolve");
    }

    /// A single `SIGTERM` — what `docker stop` and `systemctl stop` both send —
    /// brings the node down cleanly, with a zero exit status rather than an
    /// error.
    ///
    /// Raised for real (`libc::raise`) rather than mocked: what this guards is
    /// whether the process's *actual* signal disposition reacts, which is
    /// precisely what a fake trigger would not exercise. It is also the half
    /// that PID 1 in a container gets wrong by default.
    #[tokio::test]
    async fn a_single_sigterm_shuts_the_node_down_cleanly() {
        let _serial = SERIAL.lock().await;
        let mut join_set = tokio::task::JoinSet::new();
        join_set.spawn(std::future::pending());

        let node = async {
            // Give the `select!` a beat to install the signal handler before the
            // signal is raised, or the raise races the subscription and the
            // default disposition kills the test process.
            let armed = run_until_shutdown(std::future::pending(), &mut join_set);
            tokio::pin!(armed);
            tokio::select! {
                outcome = &mut armed => return outcome,
                () = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
            // SAFETY: `libc::raise` sends a signal to this process; it has no
            // memory-safety precondition of its own.
            let rc = unsafe { libc::raise(libc::SIGTERM) };
            assert_eq!(rc, 0, "raising SIGTERM");
            armed.await
        };

        timeout(Duration::from_secs(2), node)
            .await
            .expect("the node did not stop within 2s of a single SIGTERM")
            .expect("a requested shutdown is not a failure");
    }
}
