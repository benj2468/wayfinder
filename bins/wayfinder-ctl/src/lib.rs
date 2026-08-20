//! `wayfinderctl` — a command-line client for the Wayfinder management API.
//!
//! Two families of subcommands:
//! * **Query** commands open a [`wayfinder_client::Client`] to a running node
//!   (TCP or Unix-datagram) and print one management-API response.
//! * **`cert`** commands run entirely offline, minting the seed / certificate /
//!   trust-anchor files a node loads to join an authenticated mesh.
//!
//! The library surface exists so the renderers and the cert tooling can be unit-
//! tested; `main.rs` is a thin `clap` front end over [`run`].

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod cert;
pub mod output;
pub mod session;
pub mod user;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::bail;
use clap::Parser;
use clap::Subcommand;
use wayfinder_auth::Keypair;
use wayfinder_auth::MembershipCert;
use wayfinder_client::Client;
// Re-exported so integration tests (and any embedder) can build the connection
// endpoint the same way `run` does.
pub use wayfinder_client::Endpoint;
use wayfinder_protos::wayfinder::v1alpha::CsrIssued;
use wayfinder_protos::wayfinder::v1alpha::LinkFeatures;
use wayfinder_protos::wayfinder::v1alpha::authenticate_user_response::Outcome as UserOutcome;
use wayfinder_protos::wayfinder::v1alpha::link_features::TxKeepaliveUpdate;
use wayfinder_protos::wayfinder::v1alpha::submit_csr_response::Outcome as CsrOutcome;

use crate::output::OutputFormat;

/// Top-level command-line interface.
#[derive(Parser, Debug)]
#[command(
    name = "wayfinder-ctl",
    version,
    about = "Command-line client for the Wayfinder management API"
)]
pub struct Cli {
    /// Management-API endpoint: the node's `IP:port` TLS listener. Ignored by
    /// the offline `cert` subcommands.
    #[arg(
        long,
        short = 'c',
        global = true,
        env = "WAYFINDERCTL_CONNECT",
        default_value = "127.0.0.1:7700"
    )]
    pub connect: SocketAddr,

    /// Path to this client's 32-byte Ed25519 identity seed (secret), presented
    /// as an RFC 7250 raw public key in the TLS handshake. Required by every
    /// query command; ignored by the offline `cert` subcommands. To bootstrap
    /// an un-enrolled node, point this at the node's own identity seed and omit
    /// `--cert`.
    #[arg(long, global = true, env = "WAYFINDERCTL_IDENTITY")]
    pub identity: Option<PathBuf>,

    /// Path to this client's membership certificate, binding its identity to an
    /// admin capability. Omit to bootstrap an un-enrolled node (the client then
    /// authenticates by proving the node's own key via `--identity`).
    #[arg(long, global = true, env = "WAYFINDERCTL_CERT")]
    pub cert: Option<PathBuf>,

    /// The node's Ed25519 public key (64 hex chars) to pin, so a man-in-the-
    /// middle can't impersonate it. When omitted it defaults to the public key
    /// of `--identity` — correct when bootstrapping a node with its own seed,
    /// but you must pass it explicitly to reach a *different* node.
    #[arg(long, global = true, env = "WAYFINDERCTL_NODE_KEY")]
    pub node_key: Option<String>,

    /// Serial port of an embedded node's *unauthenticated* management API (e.g.
    /// `/dev/ttyACMX` for an nRF52840 over its onboard-VCOM UART), and the
    /// connection carries no TLS or authentication. `--identity`/`--cert`/
    /// `--node-key` cannot be combined with this (clap rejects it, since they'd
    /// imply a TLS handshake this transport never performs); `--connect` is
    /// simply unused. Ignored by the offline `cert` subcommands.
    #[arg(long, global = true, conflicts_with_all = ["identity", "cert", "node_key"])]
    pub serial: Option<String>,

    /// Baud rate for `--serial` (the nRF52840 firmware's VCOM UART runs at
    /// 115200).
    #[arg(long, global = true, default_value_t = 115_200)]
    pub baud: u32,

    /// Output format for query commands.
    #[arg(long, short = 'o', global = true, default_value = "human")]
    pub output: OutputFormat,

    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Every `wayfinderctl` subcommand.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Basic identity and capacity of the node.
    NodeInfo,
    /// The BATMAN originator (routing) table.
    Routes,
    /// The per-(neighbor, interface) link-quality table.
    Links,
    /// The per-neighbor keep-alive heartbeat liveness table.
    Keepalive,
    /// The current per-interface participation-feature state (the tx/rx
    /// OGM/data gates and keep-alive cadence), with a derived on/off/mixed
    /// status per interface.
    LinkFeatures,
    /// Turn a link fully on: set all four participation gates (tx_ogm,
    /// rx_ogm, tx_data, rx_data) to true. Does not re-arm keep-alive — there
    /// is no prior cadence to restore, so a link disabled with an armed
    /// keep-alive stays keep-alive-silent after enabling; arm it explicitly
    /// with `set-link-features --tx-keepalive-interval-ms` if wanted.
    LinkEnable {
        /// Index of the interface to enable, in registration order.
        #[arg(long)]
        iface: u32,
    },
    /// Turn a link fully off: set all four participation gates to false and
    /// disarm keep-alive transmission, so a disabled link goes fully silent
    /// rather than continuing to send heartbeats. This is a routing-layer
    /// silence, not a transport shutdown — the underlying socket/serial/radio
    /// stays open and polled.
    LinkDisable {
        /// Index of the interface to disable, in registration order.
        #[arg(long)]
        iface: u32,
    },
    /// The per-interface adaptive OGM emission schedule.
    OgmSchedule,
    /// Per-interface and node-wide throughput estimates.
    Throughput,
    /// Aggregate node health and topology metrics.
    Metrics,
    /// Mesh authentication / security posture: auth on/off, the mesh and
    /// own-cert header, and per-originator verified / expiry / revoked state.
    Security,
    /// Read recent log records from the node's in-memory ring.
    ///
    /// This is how a board's logs are read with no debug probe attached, and on
    /// a board whose probe is unplugged it is the only way at all. It also
    /// works *after* a fault: the ring survives whatever went wrong, so a poll
    /// that starts once the node is already misbehaving still shows the lead-up.
    Logs {
        /// Return records from this sequence number onward. Defaults to 0,
        /// meaning everything the node still retains; pass the `next_seq` from
        /// a previous run to resume without re-reading records.
        #[arg(long, default_value_t = 0)]
        since: u64,
        /// Maximum records to return per poll. 0 means the node's own default
        /// batch size.
        #[arg(long, default_value_t = 0)]
        max: u32,
        /// Keep polling and stream new records as they are recorded, like
        /// `tail -f`, until interrupted. Each poll resumes from the previous
        /// response's `next_seq`, so no record is shown twice or skipped.
        #[arg(long, short = 'f')]
        follow: bool,
    },
    /// Resolve the next hop and egress interface for a destination.
    Resolve {
        /// Destination identifier: a MAC like `02:00:00:00:00:09`, or raw hex.
        dest: String,
    },
    /// Set the Trickle/OGM emission bounds for one mesh interface at runtime.
    /// Applied in memory only — it does not persist across a restart. Resets
    /// the interface's live Trickle timer, discarding any backoff already
    /// grown toward the old bound — expect a burst of OGMs shortly after this
    /// on a live interface. `iface` must refer to an interface the node
    /// already has configured; this cannot provision a new one.
    SetTrickleConfig {
        /// Index of the interface to reconfigure, in registration order.
        #[arg(long)]
        iface: u32,
        /// New backoff floor (Trickle i_min), in milliseconds.
        #[arg(long)]
        min_ms: u32,
        /// New backoff ceiling (Trickle i_max), in milliseconds.
        #[arg(long)]
        max_ms: u32,
    },
    /// Override one interface's participation features at runtime. Each flag is
    /// optional (`--tx-ogm true|false`, etc.): omit it to leave that gate
    /// unchanged, so you can flip one capability without restating the others.
    /// `--tx-keepalive-interval-ms`/`--tx-keepalive-disable` behave the same
    /// way but are mutually exclusive with each other (a cadence to arm, or a
    /// bare disable). Applied in memory only — it does not persist across a
    /// restart. `--iface` must refer to an interface the node already has
    /// configured.
    SetLinkFeatures {
        /// Index of the interface to reconfigure, in registration order.
        #[arg(long)]
        iface: u32,
        /// Send OGMs (own + re-flooded) onto this link.
        #[arg(long)]
        tx_ogm: Option<bool>,
        /// Receive OGMs on this link and learn routes from them.
        #[arg(long)]
        rx_ogm: Option<bool>,
        /// Send data-plane traffic (unicast/multicast/broadcast) onto this link.
        /// Also governs route re-advertisement.
        #[arg(long)]
        tx_data: Option<bool>,
        /// Accept data-plane traffic (unicast/multicast/broadcast) on this link.
        #[arg(long)]
        rx_data: Option<bool>,
        /// Arm (or re-arm) keep-alive heartbeat transmission on this link at
        /// this cadence, in milliseconds. Mutually exclusive with
        /// `--tx-keepalive-disable`; omit both to leave the schedule
        /// unchanged.
        #[arg(long)]
        tx_keepalive_interval_ms: Option<u64>,
        /// Disable keep-alive heartbeat transmission on this link. Mutually
        /// exclusive with `--tx-keepalive-interval-ms`.
        #[arg(long)]
        tx_keepalive_disable: bool,
    },
    /// Switch lazy cert distribution on or off at runtime. Applied in memory
    /// only — it does not persist across a restart. A flag-day, wire-
    /// incompatible switch with un-upgraded auth nodes: only flip this on a
    /// mesh where every node has already been upgraded.
    SetLazyCertDistribution {
        /// `true` to emit an 8-byte cert fingerprint on OGMs instead of the
        /// full membership cert; `false` to emit the full cert as before.
        #[arg(long)]
        enabled: bool,
    },
    /// Store authenticate data into the application
    SetAuth {
        /// Seed for the node
        seed: PathBuf,
        /// Certificate for the node, signed by the CA
        cert: PathBuf,
        /// Trust anchor of the CA
        trust_anchor: PathBuf,
    },
    /// Enroll with a provider: generate a keypair, submit a CSR, and write the
    /// returned certificate and trust anchor (online enrollment).
    Enroll {
        /// This node's MAC, bound into the issued certificate. Defaults to the
        /// MAC deterministically derived from the enrolling keypair (the same
        /// derivation `wayfinder-tap` applies at startup), so the enrolled
        /// cert matches the MAC the node will actually run under; pass this to
        /// override that default.
        #[arg(long)]
        mac: Option<String>,
        /// Enrollment token, if the provider requires one.
        #[arg(long, default_value = "")]
        token: String,
        /// Where to write the generated 32-byte identity seed (secret).
        #[arg(long)]
        out_seed: PathBuf,
        /// Where to write the issued certificate.
        #[arg(long)]
        out_cert: PathBuf,
        /// Where to write the mesh trust anchor.
        #[arg(long)]
        out_anchor: PathBuf,
    },
    /// Revoke a node from the mesh (talks to a provider node).
    Revoke {
        /// MAC of the node to revoke.
        #[arg(long)]
        mac: String,
    },
    /// List the certificates a provider node has issued.
    ListCerts,
    /// Inspect and act on CSRs awaiting operator approval (provider node).
    #[command(subcommand)]
    Csr(CsrCommand),
    /// Offline certificate / trust-anchor tooling (no node connection).
    #[command(subcommand)]
    Cert(cert::CertCommand),
    /// Offline administration of a provider's user accounts (no node
    /// connection).
    #[command(subcommand)]
    User(user::UserCommand),
    /// Log in to a provider and store the session it issues, so every other
    /// subcommand finds a credential with no flags.
    Login {
        /// The provider's `IP:port`. Defaults to `--connect`.
        #[arg(long)]
        provider: Option<SocketAddr>,
        /// The account to log in as.
        #[arg(long)]
        user: String,
    },
    /// Delete the stored session.
    Logout,
    /// Print what credential this client is holding and when it stops working.
    Whoami,
}

/// Operator actions on pending certificate-signing requests (provider mode).
#[derive(Subcommand, Debug)]
pub enum CsrCommand {
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

/// Assemble the [`Endpoint`] a query command connects over from the parsed CLI,
/// erroring if `--identity` (required to reach a node's TLS management API) was
/// not supplied.  The seed/cert reads and node-key resolution live in
/// [`Endpoint::load`], shared with the TUI so both accept the same inputs.
fn build_endpoint(cli: &Cli) -> anyhow::Result<Endpoint> {
    // An explicit `--identity` still wins: it is how a node is bootstrapped
    // with its own seed, which no login can substitute for.
    if let Some(identity_path) = cli.identity.as_ref() {
        return Endpoint::load(
            cli.connect,
            identity_path,
            cli.cert.as_deref(),
            cli.node_key.as_deref(),
        );
    }
    // Otherwise a stored session is the credential, and the recorded pin is the
    // node key — which is what removes all three flags from routine use.
    let config = session::config_dir()?;
    let session = session::load(&config)?.context(
        "no credential: pass --identity <seed-path>, or run `wayfinderctl login --user <name>`",
    )?;
    let now = now_unix()?;
    if session.meta.expired(now) {
        bail!(
            "the stored session for {} expired at {}; run `wayfinderctl login --user {}` again",
            session.meta.username,
            session.meta.not_after,
            session.meta.username
        );
    }
    let addr = cli.connect.to_string();
    let node_key = match cli.node_key.as_deref() {
        Some(hex) => wayfinder_client::parse_key32(hex).context("parsing --node-key")?,
        None => session::pinned_key(&config, &addr)?.with_context(|| {
            format!(
                "no key recorded for {addr}: pass --node-key <hex>, or connect once \
                 interactively to record it"
            )
        })?,
    };
    Ok(Endpoint {
        addr: cli.connect,
        node_key,
        identity: wayfinder_client::Identity {
            seed: session.seed,
            cert: session.cert,
        },
    })
}

/// The current time in unix seconds, for session expiry arithmetic.
fn now_unix() -> anyhow::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .context("system clock is before the Unix epoch")
}

/// Log in to `provider` as `username`, storing the session it issues.
///
/// The keypair is generated here and never leaves this process, so what the
/// provider signs is bound to a key only this client holds: a captured
/// transcript of the exchange is useless without it. The password and code are
/// read from the terminal and are not stored anywhere on either side.
async fn login(provider: SocketAddr, username: &str, node_key: Option<&str>) -> anyhow::Result<()> {
    // A login runs on the enrollment tier, so the connection needs an identity
    // only to complete the TLS handshake — the session key it is about to have
    // certified serves, and is the key the certificate will name.
    let mut seed = [0u8; 32];
    rand::fill(&mut seed);
    let keypair = Keypair::from_seed(&seed);

    let addr = provider.to_string();
    // The provider's key has to be pinned *before* the handshake, so this is
    // where trust-on-first-use happens.
    //
    // An explicit `--node-key` is the operator stating the fingerprint out of
    // band, which is a stronger claim than anything this could learn by asking
    // the network — so it wins, and it is checked against the recorded pin
    // rather than silently replacing it. Without one, `resolve_pin` shows the
    // fingerprint the node offers and asks, or refuses if the recorded one has
    // changed. This is also what makes a non-interactive login possible at all:
    // the prompt needs a terminal, and `--node-key` is the answer to the
    // question the prompt would have asked.
    let config = session::config_dir()?;
    let node_key = match node_key {
        Some(hex) => {
            let stated = wayfinder_client::parse_key32(hex).context("parsing --node-key")?;
            session::pin_stated(&config, &addr, &stated)?
        }
        None => match session::pinned_key(&config, &addr)? {
            Some(recorded) => recorded,
            None => {
                let offered = probe_node_key(provider).await?;
                session::resolve_pin(&config, &addr, &offered)?
            }
        },
    };

    let password = rpassword::prompt_password("Password: ").context("reading password")?;
    let totp = prompt_line("TOTP code (empty if none): ")?;

    let identity = wayfinder_client::Identity {
        seed,
        // No certificate: this connection is a stranger, which is exactly what
        // someone who has not logged in yet is.
        cert: Vec::new(),
    };
    let mut client = Client::connect_tls(provider, &node_key, &identity).await?;
    let response = client
        .authenticate_user(
            username,
            &password,
            totp.trim(),
            &keypair.ed_pubkey(),
            &keypair.x_pubkey(),
        )
        .await?;

    let issued = match response.outcome {
        Some(UserOutcome::Issued(issued)) => issued,
        // One message for every reason, by design: the provider does not say
        // which of unknown-account / wrong-password / wrong-code / locked /
        // disabled applied, so neither can this.
        Some(UserOutcome::Rejected(_)) | None => {
            bail!("authentication denied")
        }
    };

    let cert = MembershipCert::from_bytes(&issued.cert)
        .context("the provider returned a certificate this build cannot parse")?;
    let meta = session::SessionMeta {
        username: username.to_string(),
        provider: addr,
        provider_key: hex(&node_key),
        not_before: cert.not_before.get(),
        not_after: cert.not_after.get(),
    };
    session::store(&config, &seed, &issued.cert, &meta)?;

    println!("logged in as {username}");
    println!("  session valid until: {} unix", meta.not_after);
    println!("  capability:          {}", cert_capability(cert.flags));
    Ok(())
}

/// Complete a TLS handshake against `addr` purely to learn the key it presents,
/// so it can be shown to the operator for confirmation.
///
/// Necessary because pinning happens before the connection that would otherwise
/// reveal the key: there is no way to ask "what key do you have?" without
/// speaking to the node, and no way to speak to it safely without a pin. The
/// resolution is the same one SSH reaches — connect once, show the fingerprint,
/// let a human decide — and it is why `resolve_pin` refuses without a terminal.
async fn probe_node_key(addr: SocketAddr) -> anyhow::Result<[u8; 32]> {
    wayfinder_client::probe_node_key(addr).await
}

/// Delete the stored session.
fn logout() -> anyhow::Result<()> {
    if session::clear(&session::config_dir()?)? {
        println!("logged out");
    } else {
        println!("no stored session");
    }
    Ok(())
}

/// Print what credential this client holds and when it stops working.
fn whoami() -> anyhow::Result<()> {
    let Some(session) = session::load(&session::config_dir()?)? else {
        println!("no stored session (use `wayfinderctl login --user <name>`)");
        return Ok(());
    };
    let cert = MembershipCert::from_bytes(&session.cert)
        .context("the stored session certificate does not parse")?;
    let now = now_unix()?;

    println!("user:       {}", session.meta.username);
    println!("provider:   {}", session.meta.provider);
    println!("mesh id:    {:#x}", cert.mesh_id.get());
    println!("mac:        {}", output::format_mac(&cert.node_mac));
    println!("capability: {}", cert_capability(cert.flags));
    let not_after = session.meta.not_after;
    if session.meta.expired(now) {
        println!("expiry:     {not_after} unix (EXPIRED — log in again)");
    } else if session.meta.due_renewal(now) {
        println!(
            "expiry:     {not_after} unix (in {}s — due renewal)",
            not_after - now
        );
    } else {
        println!("expiry:     {not_after} unix (in {}s)", not_after - now);
    }
    Ok(())
}

/// Describe a certificate's signed capability bits in one phrase.
fn cert_capability(flags: u8) -> String {
    let mut parts = Vec::new();
    if flags & wayfinder_auth::CERT_FLAG_ADMIN != 0 {
        parts.push("admin");
    }
    if flags & wayfinder_auth::CERT_FLAG_VIEWER != 0 {
        parts.push("viewer");
    }
    if flags & wayfinder_auth::CERT_FLAG_USER != 0 {
        parts.push("user session");
    }
    if parts.is_empty() {
        return "none (routing membership only)".to_string();
    }
    parts.join(", ")
}

/// Read one line from the terminal, echoing it (for a TOTP code, which is not a
/// secret worth hiding and is easier to get right when visible).
fn prompt_line(prompt: &str) -> anyhow::Result<String> {
    use std::io::Write;
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading from the terminal")?;
    Ok(line)
}

/// Lower-case hex, for keys in operator-facing output.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// How often `logs --follow` re-polls the node's ring.
///
/// The management protocol is strictly one request to one response, so a follow
/// is a poll rather than a subscription. Half a second is slow enough not to
/// saturate a 115200-baud serial link to a board, and fast enough that the
/// stream reads as live.
const FOLLOW_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Run the parsed CLI: dispatch offline `cert` work synchronously, else open a
/// client, service one query, and print the rendered result.
pub async fn run(cli: Cli) -> anyhow::Result<()> {
    // The offline tooling needs no node connection.
    match cli.command {
        Command::Cert(cmd) => return cert::run(cmd),
        Command::User(cmd) => return user::run(cmd),
        Command::Logout => return logout(),
        Command::Whoami => return whoami(),
        Command::Login { provider, user } => {
            return login(
                provider.unwrap_or(cli.connect),
                &user,
                cli.node_key.as_deref(),
            )
            .await;
        }
        _ => {}
    }
    // A serial target reaches an embedded node's unauthenticated management API
    // directly; otherwise connect over the authenticated TLS endpoint.
    let mut client = match cli.serial.clone() {
        Some(path) => Client::connect_serial(&path, cli.baud).await?,
        None => {
            let endpoint = build_endpoint(&cli)?;
            Client::connect_tls(endpoint.addr, &endpoint.node_key, &endpoint.identity).await?
        }
    };
    // Streaming is the one command that outlives a single response, so it is
    // handled here rather than in `dispatch_query`.
    if let Command::Logs {
        since,
        max,
        follow: true,
    } = cli.command
    {
        return follow_logs(&mut client, since, max, cli.output).await;
    }
    println!(
        "{}",
        dispatch_query(cli.command, &mut client, cli.output).await?
    );
    Ok(())
}

/// Poll the node's log ring forever, printing each batch as it arrives.
///
/// Resumes from the previous response's `next_seq` every time, so a record is
/// neither shown twice nor skipped, and a node that evicted records while we
/// were between polls reports the gap rather than closing over it. Silent polls
/// print nothing at all — a `tail -f` that emitted a line per empty poll would
/// bury the records it is there to show. Returns only on error; the operator
/// ends it with Ctrl+C.
async fn follow_logs(
    client: &mut Client,
    since: u64,
    max: u32,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let mut since = since;
    let mut shown_filter: Option<String> = None;
    loop {
        let batch = client.logs(since, max).await?;
        since = batch.next_seq;
        // Announced on the first poll and again whenever it changes, so the
        // stream always says what is actually being recorded — including a
        // change some other client made mid-follow.
        if shown_filter.as_deref() != Some(batch.filter.as_str()) {
            println!("filter: {}", batch.filter);
            shown_filter = Some(batch.filter.clone());
        }
        if !batch.records.is_empty() || batch.dropped > 0 {
            print!("{}", output::log_lines(&batch, output)?);
        }
        tokio::time::sleep(FOLLOW_POLL_INTERVAL).await;
    }
}

/// Open a client to `endpoint`, issue one query `command`, and return the
/// rendered response (so callers/tests can print or assert it).  `command` must
/// not be [`Command::Cert`], which is handled offline by [`run`].
pub async fn run_query(
    command: Command,
    endpoint: &Endpoint,
    output: OutputFormat,
) -> anyhow::Result<String> {
    let mut client =
        Client::connect_tls(endpoint.addr, &endpoint.node_key, &endpoint.identity).await?;
    dispatch_query(command, &mut client, output).await
}

/// Dispatch one query `command` against an already-connected `client`, returning
/// the rendered response. Shared by the TLS path ([`run_query`]) and the
/// unauthenticated serial path (`--serial`), so every command works identically
/// over either transport.
async fn dispatch_query(
    command: Command,
    client: &mut Client,
    output: OutputFormat,
) -> anyhow::Result<String> {
    Ok(match command {
        Command::NodeInfo => output::node_info(&client.node_info().await?, output)?,
        Command::Routes => output::routing_table(&client.routing_table().await?, output)?,
        Command::Links => output::link_quality_table(&client.link_quality_table().await?, output)?,
        Command::Keepalive => output::keepalive_table(&client.keepalive_table().await?, output)?,
        Command::LinkFeatures => {
            output::link_features_table(&client.link_features_table().await?, output)?
        }
        Command::LinkEnable { iface } => {
            client
                .set_link_features(LinkFeatures {
                    iface_idx: iface,
                    tx_ogm: Some(true),
                    rx_ogm: Some(true),
                    tx_data: Some(true),
                    rx_data: Some(true),
                    tx_keepalive_update: None,
                })
                .await
                .context("failed to enable link")?;
            format!("link {iface} enabled")
        }
        Command::LinkDisable { iface } => {
            client
                .set_link_features(LinkFeatures {
                    iface_idx: iface,
                    tx_ogm: Some(false),
                    rx_ogm: Some(false),
                    tx_data: Some(false),
                    rx_data: Some(false),
                    tx_keepalive_update: Some(TxKeepaliveUpdate::TxKeepaliveDisabled(true)),
                })
                .await
                .context("failed to disable link")?;
            format!("link {iface} disabled")
        }
        Command::OgmSchedule => output::ogm_schedule(&client.ogm_schedule().await?, output)?,
        Command::Throughput => output::throughput(&client.throughput().await?, output)?,
        Command::Metrics => output::node_metrics(&client.node_metrics().await?, output)?,
        Command::Security => output::security(&client.security_status().await?, output)?,
        // `--follow` never reaches here: `run` intercepts it, since a stream of
        // batches cannot be returned as the one rendered response every other
        // command produces.
        Command::Logs { since, max, .. } => output::logs(&client.logs(since, max).await?, output)?,
        Command::Resolve { dest } => {
            let id = parse_id(&dest)?;
            output::resolve(&client.resolve_route(id).await?, output)?
        }
        Command::SetTrickleConfig {
            iface,
            min_ms,
            max_ms,
        } => {
            client
                .set_trickle_config(iface, min_ms, max_ms)
                .await
                .context("failed to set trickle config")?;
            "trickle config updated".to_string()
        }
        Command::SetLinkFeatures {
            iface,
            tx_ogm,
            rx_ogm,
            tx_data,
            rx_data,
            tx_keepalive_interval_ms,
            tx_keepalive_disable,
        } => {
            let tx_keepalive_update = match (tx_keepalive_disable, tx_keepalive_interval_ms) {
                (true, Some(_)) => anyhow::bail!(
                    "--tx-keepalive-disable and --tx-keepalive-interval-ms are mutually exclusive"
                ),
                (true, None) => Some(TxKeepaliveUpdate::TxKeepaliveDisabled(true)),
                (false, Some(ms)) => Some(TxKeepaliveUpdate::TxKeepaliveIntervalMs(ms)),
                (false, None) => None,
            };
            client
                .set_link_features(LinkFeatures {
                    iface_idx: iface,
                    tx_ogm,
                    rx_ogm,
                    tx_data,
                    rx_data,
                    tx_keepalive_update,
                })
                .await
                .context("failed to set link features")?;
            "link features updated".to_string()
        }
        Command::SetLazyCertDistribution { enabled } => {
            client
                .set_lazy_cert_distribution(enabled)
                .await
                .context("failed to set lazy cert distribution")?;
            format!(
                "lazy cert distribution {}",
                if enabled { "enabled" } else { "disabled" }
            )
        }
        Command::SetAuth {
            seed,
            cert,
            trust_anchor,
        } => {
            client
                .set_auth(
                    &std::fs::read(&seed)?,
                    &std::fs::read(&cert)?,
                    &std::fs::read(&trust_anchor)?,
                )
                .await
                .context("failed to set auth")?;
            "auth updated".to_string()
        }
        Command::Enroll {
            mac,
            token,
            out_seed,
            out_cert,
            out_anchor,
        } => {
            // Enrollment can be retried against the same `out_seed` path (e.g. a
            // provider that holds requests for operator approval, polled across
            // process restarts). Reuse whatever identity is already on disk there
            // rather than minting a fresh keypair each time: against a provider
            // in that posture a new key on every retry looks like a different
            // node reclaiming the MAC and is rejected. Persist a
            // freshly-generated seed immediately, before polling, so a later
            // retry finds it.
            let seed: [u8; 32] = if out_seed.exists() {
                cert::read_seed(&out_seed)
                    .with_context(|| format!("reading existing seed at {}", out_seed.display()))?
            } else {
                let seed: [u8; 32] = rand::random();
                cert::write_secret(&out_seed, &seed)?;
                seed
            };
            let kp = Keypair::from_seed(&seed);
            let mac_bytes = match &mac {
                Some(mac) => parse_mac6(mac)?,
                None => kp.derived_mac().0,
            };
            let issued = poll_enroll(client, &mac_bytes, &kp, &token).await?;
            // The seed is already on disk (reused from `out_seed`, or written
            // above before polling), so it needs no second write here.
            std::fs::write(&out_cert, &issued.cert)
                .with_context(|| format!("writing certificate to {}", out_cert.display()))?;
            std::fs::write(&out_anchor, &issued.trust_anchor)
                .with_context(|| format!("writing trust anchor to {}", out_anchor.display()))?;
            format!(
                "enrolled {}: wrote seed, certificate, and trust anchor",
                output::format_mac(&mac_bytes)
            )
        }
        Command::Revoke { mac } => {
            let mac_bytes = parse_mac6(&mac)?;
            client
                .revoke_node(&mac_bytes)
                .await
                .context("revocation failed")?;
            format!("revoked {mac}")
        }
        Command::ListCerts => output::list_certs(&client.list_certs().await?, output)?,
        Command::Csr(CsrCommand::List) => {
            output::list_pending_csrs(&client.list_pending_csrs().await?, output)?
        }
        Command::Csr(CsrCommand::Approve { mac }) => {
            let mac_bytes = parse_mac6(&mac)?;
            client
                .approve_csr(&mac_bytes)
                .await
                .context("approving CSR failed")?;
            format!("approved CSR for {mac}")
        }
        Command::Csr(CsrCommand::Deny { mac }) => {
            let mac_bytes = parse_mac6(&mac)?;
            client
                .deny_csr(&mac_bytes)
                .await
                .context("denying CSR failed")?;
            format!("denied CSR for {mac}")
        }
        // Every command that needs no node connection is dispatched by `run`
        // before a client is opened; listing them here rather than under a
        // wildcard keeps a newly added offline command from silently reaching
        // a code path that would try to connect for it.
        Command::Cert(_)
        | Command::User(_)
        | Command::Login { .. }
        | Command::Logout
        | Command::Whoami => {
            unreachable!("offline commands are dispatched before a client is opened")
        }
    })
}

/// Poll `submit_csr`. A provider configured to require operator approval parks the
/// CSR as pending; re-submitting the identical request is how the enrolling node
/// collects the certificate once an operator approves it.
async fn poll_enroll(
    client: &mut Client,
    mac: &[u8],
    kp: &Keypair,
    token: &str,
) -> anyhow::Result<CsrIssued> {
    let resp = client
        .submit_csr(mac, &kp.ed_pubkey(), &kp.x_pubkey(), token)
        .await
        .context("enrollment (submit_csr) failed")?;
    match resp.outcome {
        Some(CsrOutcome::Issued(issued)) => Ok(issued),
        Some(CsrOutcome::Rejected(r)) => bail!("enrollment rejected: {}", r.reason),
        // Pending (or an empty outcome, treated the same): the caller should keep polling until
        // until the requset is approval.
        Some(CsrOutcome::Pending(_)) | None => {
            bail!(
                "CSR still awaiting operator approval; approve it with \
                    `wayfinderctl csr approve --mac <mac>` and retry",
            );
        }
    }
}

/// Parse a node identifier from `s`: a colon-delimited MAC
/// (`02:00:00:00:00:09`) or a bare hex string (`020000000009`), into raw bytes.
pub fn parse_id(s: &str) -> anyhow::Result<Vec<u8>> {
    if s.contains(':') {
        s.split(':')
            .map(|byte| u8::from_str_radix(byte, 16))
            .collect::<Result<Vec<u8>, _>>()
            .with_context(|| format!("'{s}' is not a colon-delimited hex identifier"))
    } else {
        if !s.len().is_multiple_of(2) {
            anyhow::bail!("hex identifier '{s}' must have an even number of digits");
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .with_context(|| format!("'{s}' is not a valid hex identifier"))
    }
}

/// Parse a 6-byte MAC from `s` (colon-delimited or bare hex), erroring if it is
/// not exactly six bytes.
pub fn parse_mac6(s: &str) -> anyhow::Result<[u8; 6]> {
    let bytes = parse_id(s)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("'{s}' must be a 6-byte MAC, got {} bytes", bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_id_colon_mac() {
        assert_eq!(
            parse_id("02:00:00:00:00:09").unwrap(),
            vec![0x02, 0, 0, 0, 0, 9]
        );
    }

    #[test]
    fn parse_id_bare_even_hex() {
        // The previously-inverted guard rejected valid even-length bare hex.
        assert_eq!(parse_id("020000000009").unwrap(), vec![0x02, 0, 0, 0, 0, 9]);
        assert_eq!(parse_id("ff00").unwrap(), vec![0xff, 0x00]);
    }

    #[test]
    fn parse_id_bare_odd_hex_rejected() {
        let err = parse_id("abc").unwrap_err().to_string();
        assert!(err.contains("even number"), "got: {err}");
    }

    #[test]
    fn parse_id_non_hex_rejected() {
        assert!(parse_id("zz:00").is_err());
        assert!(parse_id("gggg").is_err());
    }

    #[test]
    fn parse_mac6_requires_six_bytes() {
        assert_eq!(parse_mac6("01:02:03:04:05:06").unwrap(), [1, 2, 3, 4, 5, 6]);
        assert!(parse_mac6("01:02:03").is_err());
        assert!(parse_mac6("0102030405").is_err()); // 5 bytes
    }
}
