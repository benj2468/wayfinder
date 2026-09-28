//! A management-API client bound to a physical board.
//!
//! Every test drives a node through [`wayfinder_client::Client`] and never
//! through a transport of its own. That is deliberate: the board's port is
//! unauthenticated today (#59), and when it stops being so, this is the
//! one place that changes.

use std::time::Duration;
use std::time::Instant;

use std::ops::Deref;
use std::ops::DerefMut;

use wayfinder_client::Client;

use crate::board::Board;
use crate::diagnostics::Diagnostics;

/// The baud rate a board's CDC-ACM port is opened at.
///
/// Nominal: CDC-ACM is a USB pipe and the line rate is not honoured by
/// anything, but `tokio_serial` requires one.
pub const DEFAULT_BAUD: u32 = 115_200;

/// How long [`Node::attach`] keeps retrying a board that has not finished
/// enumerating, at least.
///
/// A floor rather than a ceiling: the deadline is checked between attempts, so
/// one attempt in flight when it passes still runs to completion.
///
/// A board re-enumerates after a reset, and the device node reappears before it
/// is ready to answer. Retrying here rather than making every test sleep is
/// what keeps the tests free of the arbitrary waits that make a rig flaky.
pub const ATTACH_TIMEOUT: Duration = Duration::from_secs(20);

/// A live management connection to a board.
pub struct Node {
    client: Client,
    role: String,
}

impl Node {
    /// Open `board`'s management port, retrying until it answers or
    /// [`ATTACH_TIMEOUT`] elapses.
    ///
    /// Readiness is a successful `GetNodeInfo`, not a successful `open`: the
    /// device node appears while the far side is still bringing USB up, so an
    /// open that succeeds proves nothing about the node behind it.
    pub async fn attach(board: &Board) -> anyhow::Result<Node> {
        let deadline = Instant::now() + ATTACH_TIMEOUT;
        let mut last: Option<anyhow::Error> = None;

        while Instant::now() < deadline {
            match Node::try_attach(board).await {
                Ok(node) => return Ok(node),
                Err(e) => last = Some(e),
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        Err(match last {
            Some(e) => e.context(format!(
                "board {:?} did not answer its management port within {:?}",
                board.role(),
                ATTACH_TIMEOUT
            )),
            None => anyhow::anyhow!("board {:?}: attach deadline already passed", board.role()),
        })
    }

    /// One attach attempt: resolve the port, open it, and prove the node
    /// answers.
    async fn try_attach(board: &Board) -> anyhow::Result<Node> {
        let port = board.management_port()?;
        let path = port
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("management port path is not UTF-8: {port:?}"))?;
        let mut client = Client::connect_serial(path, DEFAULT_BAUD).await?;
        client.node_info().await?;
        Ok(Node {
            client,
            role: board.role().to_string(),
        })
    }

    /// The role of the board behind this connection.
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Print what this board says about itself, to stderr.
    ///
    /// For a test whose value is the *record* rather than an assertion — a
    /// smoke run, or a soak whose interesting output is what the board reports
    /// afterwards. [`with_diagnostics`](Self::with_diagnostics) is the
    /// assertion-shaped counterpart.
    pub async fn report(&mut self) {
        eprintln!("{}", Diagnostics::collect(self).await);
    }

    /// Run `body`, and on failure attach a [`Diagnostics`] dump to the error.
    ///
    /// Lives here rather than in each test because the test that most needs a
    /// dump is the one that failed in a way its author did not anticipate
    /// (design 21 §4.5) — so remembering to ask for one is exactly the wrong
    /// thing to leave to the caller. A bare assertion failure against a board
    /// is nearly useless: the interesting state is on the part, and the part
    /// may have reset.
    ///
    /// Wrap the assertions, not the setup. A failure during setup should say
    /// what could not be arranged; only once the board is in the state under
    /// test does its own account of itself become the interesting evidence.
    pub async fn with_diagnostics<F>(&mut self, body: F) -> anyhow::Result<()>
    where
        F: AsyncFnOnce(&mut Node) -> anyhow::Result<()>,
    {
        match body(self).await {
            Ok(()) => Ok(()),
            Err(e) => {
                let dump = Diagnostics::collect(self).await;
                Err(e.context(format!("\n{dump}")))
            }
        }
    }
}

impl Deref for Node {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl DerefMut for Node {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.client
    }
}
