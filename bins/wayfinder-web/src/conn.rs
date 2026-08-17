//! The dashboard's connection to a node's management API.
//!
//! Server-side only, and the only place in this crate that speaks the
//! management protocol. Lives in the axum state and is reached from `#[server]`
//! functions; the browser never touches it.
//!
//! # Why a single client behind a mutex
//!
//! [`Client`] owns one stream and takes `&mut self` per request, so it cannot be
//! shared. Rather than a pool, this holds one connection and serialises polls
//! through it — a dashboard polls roughly once a second, and one lock per poll
//! costs nothing. Several concurrent viewers would queue behind each other; if
//! that ever matters, a pool goes here and no caller changes.
//!
//! The reconnect policy is the TUI's (`wayfinder-tui`'s `refresh`): connect
//! lazily, and on any failure drop the client so the next poll reconnects. A
//! node restarting, or a cable moving, then costs one failed poll rather than a
//! dashboard that is wedged until someone restarts it.

use tokio::sync::Mutex;
use tracing::debug;
use tracing::info;
use tracing::trace;
use tracing::warn;
use wayfinder_client::Client;
use wayfinder_client::Endpoint;

/// How the dashboard reaches the node.
///
/// The same two transports the TUI offers: the authenticated TLS management API
/// of a host node, or the unauthenticated serial port an embedded node exposes
/// for debugging.
pub enum Target {
    /// The node's TLS management API, with the pinned node key and this
    /// dashboard's client identity.
    Tls(Endpoint),
    /// A serial port opened at a fixed baud rate. No TLS and no authentication
    /// — an embedded node's debug management port (e.g. the nRF52840's USB
    /// CDC-ACM port).
    Serial {
        /// The serial device path.
        path: String,
        /// The baud rate to open it at.
        baud: u32,
    },
}

impl Target {
    /// Open a fresh [`Client`] over this target.
    pub async fn connect(&self) -> anyhow::Result<Client> {
        match self {
            Target::Tls(endpoint) => {
                Client::connect_tls(endpoint.addr, &endpoint.node_key, &endpoint.identity).await
            }
            Target::Serial { path, baud } => Client::connect_serial(path, *baud).await,
        }
    }

    /// A short human-readable label naming what the dashboard is pointed at,
    /// shown in the header so it is never ambiguous which node is on screen.
    pub fn label(&self) -> String {
        match self {
            Target::Tls(endpoint) => endpoint.addr.to_string(),
            Target::Serial { path, baud } => format!("{path} @ {baud} baud"),
        }
    }
}

/// What has already been said about the connection's health.
///
/// The dashboard polls roughly once a second, so an unreachable node produces a
/// failure per second. Logging each one would bury the first — the only one that
/// carries new information — under sixty copies a minute, and a node left down
/// overnight would fill the log with a single repeated line. So a failure is
/// reported when it *changes*: the first one, a different one, and the recovery
/// that ends it.
///
/// Suppression is by error text rather than a timer on purpose. A repeat is
/// silent for as long as nothing changes, however long that is, and the moment
/// the cause changes — refused, then denied, then a timeout — the operator sees
/// it, which is exactly when the log is worth reading.
#[derive(Default)]
struct Health {
    /// The failure already reported, or `None` while the node is reachable.
    reported: Option<String>,
}

impl Health {
    /// Record a failed attempt, returning whether it is news: `true` for the
    /// first failure and for one whose cause differs from the last reported.
    fn failed(&mut self, error: &str) -> bool {
        if self.reported.as_deref() == Some(error) {
            return false;
        }
        self.reported = Some(error.to_string());
        true
    }

    /// Record a successful attempt, returning whether it is a *recovery* — a
    /// success that ends a reported failure, and so closes the story that
    /// failure opened. Steady success on a healthy node returns `false`.
    fn succeeded(&mut self) -> bool {
        self.reported.take().is_some()
    }
}

/// The mutable half of a [`NodeConnection`], behind one lock.
///
/// The health tracker shares the client's lock rather than taking its own: they
/// are updated together on every poll, so a second lock could only let the two
/// disagree about whether the node is up.
#[derive(Default)]
struct State {
    /// The live client, or `None` before the first poll and after a failure.
    client: Option<Client>,
    /// What has already been reported about this connection.
    health: Health,
}

/// A lazily-established, automatically-reconnecting connection to one node.
pub struct NodeConnection {
    /// What to connect to, and how.
    target: Target,
    /// The client and what has been said about it.
    state: Mutex<State>,
}

impl NodeConnection {
    /// Build a connection to `target`. Does no I/O — the first [`run`] call
    /// establishes the connection, so the server starts even with the node
    /// down and recovers on its own when the node comes back.
    ///
    /// [`run`]: NodeConnection::run
    pub fn new(target: Target) -> Self {
        Self {
            target,
            state: Mutex::new(State::default()),
        }
    }

    /// The connection's display label; see [`Target::label`].
    pub fn label(&self) -> String {
        self.target.label()
    }

    /// Whether a connection is currently established.
    ///
    /// Intended for the status strip and for tests asserting the connection is
    /// reused across polls; correctness never depends on it, since [`run`]
    /// connects on demand anyway.
    ///
    /// [`run`]: NodeConnection::run
    pub fn is_connected(&self) -> bool {
        self.state
            .try_lock()
            .is_ok_and(|guard| guard.client.is_some())
    }

    /// Run one exchange against the node, connecting first if needed.
    ///
    /// `op` gets the connected client and may issue any number of requests; it
    /// is passed the whole client rather than one request at a time so a poll
    /// that reads ten tables takes one lock and one connection decision instead
    /// of ten.
    ///
    /// On failure — whether connecting or inside `op` — the client is dropped so
    /// the next call reconnects. A half-consumed stream is unusable for framing
    /// reasons anyway: a response that arrived late would be read as the answer
    /// to the *next* request, which is worse than reconnecting.
    ///
    /// Failures are also logged, gated by [`Health`] so a node that stays down
    /// is reported once rather than once per poll. The `stage` field separates
    /// the two ways a poll can fail, because they have different causes:
    /// `connect` is the address, TLS or authentication, while `request` is a
    /// node that accepted the connection and then failed to answer.
    pub async fn run<T, F>(&self, op: F) -> anyhow::Result<T>
    where
        F: AsyncFnOnce(&mut Client) -> anyhow::Result<T>,
    {
        let mut guard = self.state.lock().await;
        let node = self.target.label();

        // `stage` rides along with the error so the report below can name which
        // half failed without inspecting the error's text.
        let outcome = match guard.client.as_mut() {
            Some(client) => op(client).await.map_err(|e| ("request", e)),
            None => {
                debug!(%node, "opening a management connection");
                match self.target.connect().await {
                    Ok(client) => {
                        debug!(%node, "management connection established");
                        op(guard.client.insert(client))
                            .await
                            .map_err(|e| ("request", e))
                    }
                    Err(e) => Err(("connect", e)),
                }
            }
        };

        match outcome {
            Ok(value) => {
                if guard.health.succeeded() {
                    info!(%node, "node reachable again");
                }
                Ok(value)
            }
            Err((stage, e)) => {
                // Drop the client on any failure; see the doc comment above.
                guard.client = None;
                // `{e:#}` renders the whole `anyhow` chain on one line — the
                // outer context ("TLS handshake with the management API") is
                // rarely the part that identifies the fault.
                let error = format!("{e:#}");
                if guard.health.failed(&error) {
                    warn!(%node, stage, %error, "cannot reach the node's management API");
                } else {
                    trace!(%node, stage, %error, "node still unreachable");
                }
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first failure is worth an operator's attention; the identical
    /// failure on the next poll is not. A dashboard polls about once a second,
    /// so reporting every attempt would bury the one line that mattered under
    /// sixty copies a minute.
    #[test]
    fn a_repeated_failure_is_reported_once() {
        let mut health = Health::default();

        assert!(health.failed("connection refused"));
        assert!(!health.failed("connection refused"));
        assert!(!health.failed("connection refused"));
    }

    /// A *different* failure is a different fact about the node — the operator
    /// fixed one thing and hit the next — so it is reported even though the
    /// connection was already down.
    #[test]
    fn a_changed_failure_is_reported_again() {
        let mut health = Health::default();

        assert!(health.failed("connection refused"));
        assert!(health.failed("authentication denied"));
        assert!(!health.failed("authentication denied"));
    }

    /// Recovery is only worth saying if something was wrong: it closes the
    /// story the failure line opened. Steady polling of a healthy node says
    /// nothing at all.
    #[test]
    fn recovery_is_reported_only_after_a_failure() {
        let mut health = Health::default();

        assert!(!health.succeeded(), "a first success is unremarkable");

        assert!(health.failed("connection refused"));
        assert!(health.succeeded(), "back after a failure is worth saying");
        assert!(!health.succeeded());
    }

    /// Recovering clears the reported failure, so the *same* error returning
    /// later is a fresh event rather than a suppressed repeat. Without this a
    /// node flapping between up and down would go silent after its first cycle.
    #[test]
    fn a_failure_returning_after_recovery_is_reported() {
        let mut health = Health::default();

        assert!(health.failed("connection refused"));
        assert!(health.succeeded());
        assert!(health.failed("connection refused"));
    }
}
