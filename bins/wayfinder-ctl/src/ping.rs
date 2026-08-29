//! `wayfinderctl ping` — drive a node's reachability-probe session and report
//! it the way `ping(8)` does.
//!
//! The node does the probing. This module starts a session, polls its status,
//! and turns the rows it gets back into lines and a summary. Two properties are
//! worth stating because both are easy to get wrong:
//!
//! * **The session handle is checked, not assumed.** A node runs one session at
//!   a time, so another operator starting a ping displaces ours. The node
//!   answers a displaced handle with "no session", and this stops there rather
//!   than reporting somebody else's round trips under our destination.
//! * **The per-probe lines are append-only.** Each poll returns the node's
//!   whole recent window, most of which has already been printed; only rows
//!   that have newly *stopped being pending* produce a line, tracked by
//!   sequence number.
//!
//! Ctrl+C stops the node's session rather than only this process. The node owns
//! the session, so a client that merely exited would leave it running — probes
//! on the air, airtime spent, and a session in the way of the next operator's —
//! for as long as the run had left. `ping(8)` gets this for free by being the
//! thing that sends; here it takes an explicit cancel on the way out.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::bail;
use wayfinder_client::Client;
use wayfinder_protos::wayfinder::v1alpha::PingProbeState;
use wayfinder_protos::wayfinder::v1alpha::PingSession;

use crate::output;
use crate::output::OutputFormat;

/// What the caller asked for. Every field is passed to the node as given, and 0
/// means "your default" — the node owns those, so a client that substituted its
/// own would be answering a question the node had already answered.
#[derive(Clone, Copy, Debug)]
pub struct PingArgs {
    /// Probes to send; 0 for the node's default.
    pub count: u32,
    /// Milliseconds between probes; 0 for the node's default.
    pub interval_ms: u32,
    /// Milliseconds a probe waits before counting as lost; 0 for the node's
    /// default.
    pub timeout_ms: u32,
    /// Pad bytes per probe; 0 for the node's default.
    pub payload_bytes: u32,
}

/// Run a ping session to completion and return its rendered result.
///
/// `stream` prints the banner and each probe line as it resolves — what an
/// operator at a terminal wants. It is ignored for
/// [`OutputFormat::Json`](crate::output::OutputFormat::Json), which has one
/// document to emit and cannot emit it incrementally; a JSON caller gets the
/// finished session and nothing before it.
pub async fn run(
    client: &mut Client,
    destination: Vec<u8>,
    args: PingArgs,
    output: OutputFormat,
    stream: bool,
) -> anyhow::Result<String> {
    let started = client
        .ping(
            destination.clone(),
            args.count,
            args.interval_ms,
            args.timeout_ms,
            args.payload_bytes,
        )
        .await?;

    let stream = stream && output == OutputFormat::Human;
    if stream {
        println!(
            "{}",
            output::ping_banner(&destination, started.payload_bytes, started.count)
        );
    }

    // Poll a little faster than the probe cadence, so a reply is reported near
    // when it arrived rather than up to a whole interval later. Floored, since
    // a node may report a cadence of zero if it ever grows one.
    let poll = Duration::from_millis(u64::from(started.interval_ms).max(100) / 2);

    // How long the session the node just described can possibly take, plus
    // generous slack. A loop whose only exits are "the node says it finished"
    // and "the transport broke" hangs forever on any node-side condition that
    // leaves a session perpetually active — and a client that can hang on
    // remote state is one an operator has to notice and kill. Derived from the
    // node's own echoed settings, so it adapts to whatever it actually applied.
    let budget = Duration::from_millis(
        u64::from(started.count)
            .saturating_mul(u64::from(started.interval_ms) + u64::from(started.timeout_ms))
            .saturating_add(30_000),
    );
    let deadline = tokio::time::Instant::now() + budget;

    let mut printed: HashSet<u32> = HashSet::new();
    let mut last: Option<PingSession> = None;

    loop {
        // Race the poll against Ctrl+C so an interrupt is handled here, where
        // the session handle is, rather than by the default handler killing the
        // process and leaving the node probing.
        let status = tokio::select! {
            status = client.ping_status(started.session_seq) => status?,
            _ = tokio::signal::ctrl_c() => {
                return cancel(client, started.session_seq, output, stream).await;
            }
        };
        let Some(session) = status.session else {
            // The node is no longer running our session. If we never saw it at
            // all, something displaced it before the first poll; if we did, we
            // report what we had rather than losing the run.
            let Some(last) = last else {
                bail!(
                    "the node replaced this ping session before it could be read \
                     — another client started one"
                );
            };
            if stream {
                println!("{}", output::ping_summary(&last));
            }
            // Reported, then failed. The statistics above are real but they
            // describe a *truncated* run, and printing them over a zero exit
            // code makes a partial result indistinguishable from a complete
            // one — which a monitoring wrapper would read as a genuine loss
            // figure for a link that may be fine.
            eprintln!("{}", output::ping(&last, output)?);
            bail!(
                "the node stopped running this ping session before it finished \
                 — another client started one, or the node restarted; \
                 the statistics above cover only the probes that completed"
            );
        };

        if stream {
            for probe in &session.probes {
                if probe.state() == PingProbeState::Pending || !printed.insert(probe.seqno) {
                    continue;
                }
                println!(
                    "{}",
                    output::ping_probe(
                        probe,
                        &crate::output::format_mac(&session.destination),
                        session.payload_bytes
                    )
                );
            }
        }

        if !session.active {
            if stream {
                println!("{}", output::ping_summary(&session));
            }
            return output::ping(&session, output);
        }
        // Kept only so a session displaced *between* polls can still be
        // reported from the last state we saw, rather than losing the run.
        last = Some(session);

        if tokio::time::Instant::now() >= deadline {
            bail!(
                "this ping session did not finish within {} s — the node reports it \
                 as still running with {} of {} probes sent, which it should not be",
                budget.as_secs(),
                last.as_ref().map_or(0, |s| s.sent),
                started.count,
            );
        }
        tokio::time::sleep(poll).await;
    }
}

/// Stop the node's session and report what it measured.
///
/// Reached on Ctrl+C. The summary is printed rather than discarded, exactly as
/// `ping(8)` does: an operator interrupts a ping *because they have seen
/// enough*, so the statistics up to that point are the answer they were waiting
/// for — and the airtime is spent either way.
///
/// A session the node no longer knows is reported plainly rather than as a
/// failure. Cancelling is what this does on the way out, and one that has
/// already stopped is the outcome it wanted.
async fn cancel(
    client: &mut Client,
    session_seq: u32,
    output: OutputFormat,
    stream: bool,
) -> anyhow::Result<String> {
    let cancelled = client.cancel_ping(session_seq).await?;
    let Some(session) = cancelled.session else {
        if stream {
            println!("\nthe node was no longer running this session");
        }
        return Ok(String::new());
    };
    if stream {
        println!("{}", output::ping_summary(&session));
    }
    output::ping(&session, output)
}
