//! The node as the mesh's certificate authority: who may join, who has been
//! ejected, and the accounts that decide.
//!
//! This mirrors `wayfinder_web::Scope::Provider`, and for the same reason the
//! web dashboard gives it its own tab bar: a node can be doing two jobs at
//! once, and they are not the same job. Almost every node only routes. A
//! handful are *also* the CA, and that job is about other nodes.
//!
//! The CLI has one extra reason the dashboards do not: **these commands are
//! pointed at a different node.** Everything else in `wayfinderctl` asks the
//! node you name about itself; everything here asks a provider about the mesh,
//! and needs `--connect <ca-host>` rather than your own node's address. That
//! was invisible when `revoke` and `list-certs` sat in one flat list of
//! twenty-seven names alongside `routes` and `metrics`.
//!
//! `ca` is a visible alias, so the grouping costs two characters rather than
//! eight on the commands run most often.

use anyhow::Context;
use clap::Subcommand;
use wayfinder_client::Client;

use crate::output;
use crate::output::OutputFormat;
use crate::parse_mac6;
use crate::user;
use crate::vpn;

/// The provider-side operator actions.
#[derive(Subcommand, Debug)]
pub enum ProviderCommand {
    /// List the certificates this provider has issued — the mesh's members.
    Members,
    /// Revoke a node from the mesh, taking its VPN registration with it.
    ///
    /// Both halves are one operator action. The half-completed case is
    /// reported rather than hidden, and `provider vpn revoke` is the retry for
    /// the tunnel half alone.
    Revoke {
        /// MAC of the node to revoke.
        #[arg(long)]
        mac: String,
    },
    /// The queue of certificate signing requests awaiting a decision.
    ///
    /// These are the provider-side half of enrollment, and the same actions the
    /// web and TUI screens drive. The node-side half — carrying a request out
    /// and the certificate back — is `csr`.
    #[command(subcommand)]
    Requests(RequestsCommand),
    /// Administration of this provider's user accounts, over the management
    /// API.
    ///
    /// Bootstrapping included: with no account on file yet, an operator on the
    /// provider host creates the first administrator by presenting the node's
    /// own identity seed (`--identity /var/lib/wayfinder/identity.seed`), which
    /// authenticates as the node itself.
    #[command(subcommand)]
    User(user::UserCommand),
    /// The VPN peers registered with this provider's coordination server.
    #[command(subcommand)]
    Vpn(vpn::VpnCommand),
}

/// Acting on the CSRs a provider is holding for approval.
#[derive(Subcommand, Debug)]
pub enum RequestsCommand {
    /// List the CSRs currently awaiting approval.
    List,
    /// Approve a pending CSR, so the enrolling node collects its certificate.
    Approve {
        /// MAC of the pending CSR to approve.
        #[arg(long)]
        mac: String,
    },
    /// Deny a pending CSR; the enrolling node observes a rejection.
    Deny {
        /// MAC of the pending CSR to deny.
        #[arg(long)]
        mac: String,
    },
}

/// Dispatch one `provider` subcommand against an already-connected `client`,
/// which must be connected to a provider node.
pub async fn run(
    cmd: ProviderCommand,
    client: &mut Client,
    fmt: OutputFormat,
) -> anyhow::Result<String> {
    Ok(match cmd {
        ProviderCommand::Members => output::list_certs(&client.list_certs().await?, fmt)?,
        ProviderCommand::Revoke { mac } => {
            let mac_bytes = parse_mac6(&mac)?;
            client
                .revoke_node(&mac_bytes)
                .await
                .context("revocation failed")?;
            format!("revoked {mac}")
        }
        ProviderCommand::Requests(cmd) => requests(cmd, client, fmt).await?,
        ProviderCommand::User(cmd) => user::run(cmd, client).await?,
        ProviderCommand::Vpn(cmd) => vpn::run(cmd, client, fmt).await?,
    })
}

/// Dispatch one `provider requests` subcommand.
async fn requests(
    cmd: RequestsCommand,
    client: &mut Client,
    fmt: OutputFormat,
) -> anyhow::Result<String> {
    Ok(match cmd {
        RequestsCommand::List => {
            output::list_pending_csrs(&client.list_pending_csrs().await?, fmt)?
        }
        RequestsCommand::Approve { mac } => {
            let mac_bytes = parse_mac6(&mac)?;
            client
                .approve_csr(&mac_bytes)
                .await
                .context("approving CSR failed")?;
            format!("approved CSR for {mac}")
        }
        RequestsCommand::Deny { mac } => {
            let mac_bytes = parse_mac6(&mac)?;
            client
                .deny_csr(&mac_bytes)
                .await
                .context("denying CSR failed")?;
            format!("denied CSR for {mac}")
        }
    })
}
