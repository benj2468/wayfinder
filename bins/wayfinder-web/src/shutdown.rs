//! The signal this dashboard's server shuts down on.
//!
//! `containers/Dockerfile`'s `web` image runs this binary as PID 1 with no
//! init wrapper (`ENTRYPOINT ["/usr/local/bin/wayfinder-web"]`). Linux gives
//! PID 1 special treatment: a signal with no explicitly installed handler is
//! ignored outright, even ones — like `SIGTERM`/`SIGINT` — that would
//! terminate an ordinary process by default. Without this, `docker stop` (or
//! a first Ctrl-C on `docker run`) does nothing at all, and the container
//! only dies when the caller gives up waiting and sends `SIGKILL`.

use tokio::signal::unix::SignalKind;
use tokio::signal::unix::signal;
use tracing::warn;

/// Resolves on the first `SIGINT` or `SIGTERM`, for `axum::serve`'s
/// `with_graceful_shutdown`.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        // Only fails if the OS refuses to install the handler at all, which
        // leaves nothing useful to do but wait on the other branch instead.
        let _ = tokio::signal::ctrl_c().await;
    };
    let terminate = async {
        match signal(SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            // Same reasoning as `ctrl_c` above: nothing to recover into.
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    };

    warn!("Shutting Down");
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::Router;
    use axum::routing::get;
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    use super::shutdown_signal;

    /// A single `SIGTERM` — the signal `docker stop` and a first Ctrl-C on
    /// `docker run` both send — is enough to bring the server down, without
    /// needing a second or third signal.
    ///
    /// Raised for real (`libc::raise`) rather than mocked: the behavior this
    /// guards is exactly whether the process's *actual* signal disposition
    /// reacts to it, which a fake trigger would not exercise.
    #[tokio::test]
    async fn single_sigterm_triggers_graceful_shutdown() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let app = Router::new().route("/", get(|| async { "ok" }));
        let serve = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await
        });

        // Give the serve task a beat to reach `.await` and install the signal
        // handler before the signal is raised, or it races the subscription.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // SAFETY: `libc::raise` sends a signal to the current process, which
        // has no memory-safety precondition of its own.
        let rc = unsafe { libc::raise(libc::SIGTERM) };
        assert_eq!(rc, 0, "raising SIGTERM");

        let result = timeout(Duration::from_secs(2), serve)
            .await
            .expect("server did not shut down within 2s of a single SIGTERM")
            .expect("serve task panicked");
        assert!(
            result.is_ok(),
            "graceful shutdown returned an error: {result:?}"
        );
    }
}
