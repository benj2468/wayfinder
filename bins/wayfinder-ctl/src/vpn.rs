//! Operator-side VPN peer management, and the tunnel-join half of enrollment.
//!
//! Two audiences in one module, matching the authorization tiers behind them.
//! `list`/`revoke` are provider-side operator actions needing a full
//! management grant. [`join`] is the other end: it runs as part of
//! `wayfinderctl enroll`, on a connection carrying the certificate that was
//! just issued — or, on the coordination server itself, on a connection
//! carrying that node's own identity seed. Either proves a *device*, which is
//! what a tunnel credential is scoped to; an operator's session certificate
//! does not and is refused.
//!
//! Nothing here writes a file a node is expected to read. The credential goes
//! straight from the management API into the tunnel daemon's own CLI, and the
//! daemon owns its state from there.

use anyhow::Context;
use clap::Subcommand;
use wayfinder_client::Client;

use crate::output;
use crate::output::OutputFormat;
use crate::parse_mac6;

/// Operator actions against the provider's VPN coordination server.
#[derive(Subcommand, Debug)]
pub enum VpnCommand {
    /// List the peers registered with the coordination server.
    List,
    /// Ask the provider for *this* device's tunnel credential and join with it.
    ///
    /// `enroll` already does this as its last step, so this is for a node that
    /// enrolled before the mesh had a VPN, one whose join failed and is being
    /// retried, or the certificate authority putting itself on the tunnel it
    /// coordinates.
    ///
    /// It needs the connection to prove a *device* identity, in one of the two
    /// ways there are: this device's own membership certificate
    /// (`--identity`/`--cert`), or — connecting to a node from the host it
    /// runs on — that node's own identity seed with no certificate at all,
    /// which is the node asking on its own behalf. An operator's session
    /// certificate is refused however privileged it is, since the credential
    /// is scoped to a device and an operator is not one.
    Enrollment {
        /// Print the `tailscale up` command instead of running it.
        #[arg(long)]
        print_command: bool,
    },
    /// Remove a node's VPN registration, leaving its mesh membership alone.
    ///
    /// `wayfinderctl revoke` already does this as part of removing a node, so
    /// this is the retry for the case where that second half failed — which the
    /// revoke reports rather than hiding. Removing a registration that is
    /// already gone succeeds, so retrying is always safe.
    Revoke {
        /// MAC of the node whose VPN registration to remove.
        #[arg(long)]
        mac: String,
    },
}

/// Run one `vpn` subcommand against an already-connected node.
pub async fn run(
    command: VpnCommand,
    client: &mut Client,
    fmt: OutputFormat,
) -> anyhow::Result<String> {
    Ok(match command {
        VpnCommand::List => output::vpn_peers(&client.list_vpn_peers().await?, fmt)?,
        VpnCommand::Enrollment { print_command } => {
            // `join` never fails the caller — it is written for the enrollment
            // path, where the certificate is already on disk and a VPN problem
            // must not undo it. Invoked directly, though, the operator asked
            // for exactly this, so a failure is the result and has to exit
            // non-zero. Matched on the outcome variant itself, not the
            // sentence it renders to — the two must never be able to drift
            // apart.
            let outcome = join(client, print_command).await;
            if outcome.is_failure() {
                anyhow::bail!("{}", outcome.enrollment_note().trim_start_matches("; "));
            }
            outcome
                .enrollment_note()
                .trim_start_matches("; ")
                .to_string()
        }
        VpnCommand::Revoke { mac } => {
            let mac_bytes = parse_mac6(&mac)?;
            client
                .revoke_vpn_peer(&mac_bytes)
                .await
                .context("VPN revocation failed")?;
            format!("removed the VPN registration for {mac}")
        }
    })
}

/// What happened when [`join`] asked the provider for a tunnel credential.
///
/// A typed result rather than prose the two callers each re-derive success or
/// failure from: `enroll` always appends [`enrollment_note`](Self::enrollment_note)
/// as a non-fatal suffix to its summary, while `wayfinderctl vpn enrollment`
/// needs to know whether to exit non-zero. Matching on the variant keeps that
/// decision tied to the actual outcome instead of to substrings of a message
/// meant for a human — which broke silently before this type existed, since
/// nothing tied the two spellings together.
pub enum VpnJoinOutcome {
    /// Joined the tunnel.
    Joined {
        /// The Headscale login server the tunnel joined.
        login_server: String,
    },
    /// `print_only` was set: the `tailscale up` command to run by hand.
    PrintCommand(String),
    /// No credential was minted. Not itself a failure: the provider may simply
    /// have no VPN configured, and enrollment already succeeded either way.
    /// Carries why there is no tunnel to join.
    NotConfigured(String),
    /// A credential was minted but running the tunnel daemon failed.
    Failed {
        /// What `tailscale up` (or reaching it) reported.
        error: String,
        /// The `tailscale up` command to retry by hand. The key it carries is
        /// single-use and expires in minutes.
        retry_command: String,
    },
}

impl VpnJoinOutcome {
    /// Whether `wayfinderctl vpn enrollment` (invoked directly, not as part of
    /// `enroll`) should exit non-zero for this outcome.
    fn is_failure(&self) -> bool {
        matches!(self, Self::NotConfigured(_) | Self::Failed { .. })
    }

    /// The sentence to append to `enroll`'s summary line, whatever happened.
    pub fn enrollment_note(&self) -> String {
        match self {
            Self::Joined { login_server } => format!("; joined the VPN at {login_server}"),
            Self::PrintCommand(command) => format!("\nrun this to join the VPN:\n  {command}"),
            Self::NotConfigured(reason) => format!("; VPN not joined ({reason})"),
            Self::Failed {
                error,
                retry_command,
            } => format!(
                "; VPN join failed ({error}).\nRetry with:\n  {retry_command}\n\
                 The key is single-use and expires in minutes."
            ),
        }
    }
}

/// Ask the provider for a tunnel credential over `client` and join the VPN with
/// it.
///
/// `client` must be connected as a *device*: the enrolling node's own
/// certificate (the member tier), or the node's own identity seed presented to
/// the node itself (the self-key tier). Called by `enroll` after the
/// certificate is written, on a second connection opened with it, and by
/// `wayfinderctl vpn enrollment` — which is how the certificate authority
/// joins its own tunnel, over the same RPC as every other node.
///
/// A provider with no VPN configured is not a failure: enrollment succeeded,
/// there is simply no tunnel to join, and the caller keeps its certificate.
pub async fn join(client: &mut Client, print_only: bool) -> VpnJoinOutcome {
    let enrollment = match client.get_vpn_enrollment().await {
        Ok(enrollment) => enrollment,
        // Deliberately not an error the caller propagates. By the time this
        // runs the certificate and trust anchor are already on disk, so failing
        // enrollment here would discard a completed enrollment over an optional
        // second step — and the retry (re-running `enroll`) would then have to
        // redo the part that already worked.
        Err(e) => return VpnJoinOutcome::NotConfigured(first_line(&e.to_string()).to_string()),
    };
    let command = format!(
        "tailscale up --login-server={} --authkey={}",
        enrollment.vpn_login_server, enrollment.vpn_preauth_key
    );
    if print_only {
        return VpnJoinOutcome::PrintCommand(command);
    }
    match run_tailscale_up(&enrollment.vpn_login_server, &enrollment.vpn_preauth_key) {
        Ok(()) => VpnJoinOutcome::Joined {
            login_server: enrollment.vpn_login_server,
        },
        Err(e) => VpnJoinOutcome::Failed {
            error: e.to_string(),
            retry_command: command,
        },
    }
}

/// Shell out to the tunnel daemon's CLI.
///
/// Never logged and never echoed: the key is passed as an argument to one
/// process. That is visible in this host's own process table for the duration
/// of the call, which is a real exposure and the reason the key is single-use
/// and minutes-lived rather than a standing credential.
fn run_tailscale_up(login_server: &str, authkey: &str) -> anyhow::Result<()> {
    let status = std::process::Command::new("tailscale")
        .arg("up")
        .arg(format!("--login-server={login_server}"))
        .arg(format!("--authkey={authkey}"))
        .status()
        .context("running `tailscale up` (is tailscale installed and tailscaled running?)")?;
    if !status.success() {
        anyhow::bail!("`tailscale up` exited with {status}");
    }
    Ok(())
}

/// The first line of `text`, so a multi-line transport error stays on one line
/// in the summary `enroll` prints.
fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A multi-line error is summarised to its first line, so the enrollment
    /// result stays one readable line.
    #[test]
    fn a_multi_line_error_is_summarised() {
        assert_eq!(first_line("first\nsecond\nthird"), "first");
        assert_eq!(first_line("only"), "only");
        assert_eq!(first_line(""), "");
    }

    /// `wayfinderctl vpn enrollment` exits non-zero exactly for the two
    /// outcomes that mean no tunnel was joined — never by matching substrings
    /// of the rendered sentence, which is what let this decision silently
    /// break if `enrollment_note`'s wording ever changed.
    #[test]
    fn only_the_two_failure_outcomes_are_reported_as_a_failure() {
        let joined = VpnJoinOutcome::Joined {
            login_server: "https://vpn.example".to_string(),
        };
        let print_command = VpnJoinOutcome::PrintCommand("tailscale up ...".to_string());
        let not_configured = VpnJoinOutcome::NotConfigured("no VPN configured".to_string());
        let failed = VpnJoinOutcome::Failed {
            error: "tailscale not installed".to_string(),
            retry_command: "tailscale up ...".to_string(),
        };

        assert!(!joined.is_failure());
        assert!(!print_command.is_failure());
        assert!(not_configured.is_failure());
        assert!(failed.is_failure());
    }

    /// Each outcome renders to the sentence `enroll` and `vpn enrollment` have
    /// always shown; pinned so the wording — including a login server or an
    /// error message supplied by the coordination server — can't accidentally
    /// start containing another variant's trigger phrase unnoticed.
    #[test]
    fn each_outcome_renders_its_documented_sentence() {
        assert_eq!(
            VpnJoinOutcome::Joined {
                login_server: "https://vpn.example".to_string()
            }
            .enrollment_note(),
            "; joined the VPN at https://vpn.example"
        );
        assert_eq!(
            VpnJoinOutcome::PrintCommand("tailscale up --authkey=x".to_string()).enrollment_note(),
            "\nrun this to join the VPN:\n  tailscale up --authkey=x"
        );
        assert_eq!(
            VpnJoinOutcome::NotConfigured("no VPN configured".to_string()).enrollment_note(),
            "; VPN not joined (no VPN configured)"
        );
        assert_eq!(
            VpnJoinOutcome::Failed {
                error: "tailscale not installed".to_string(),
                retry_command: "tailscale up --authkey=x".to_string(),
            }
            .enrollment_note(),
            "; VPN join failed (tailscale not installed).\nRetry with:\n  \
             tailscale up --authkey=x\nThe key is single-use and expires in minutes."
        );
    }
}
