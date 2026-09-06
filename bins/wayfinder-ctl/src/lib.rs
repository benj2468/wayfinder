//! `wayfinderctl` — a command-line client for the Wayfinder management API.
//!
//! Subcommands are grouped by subject, and the groups answer four different
//! questions:
//! * **The node you name** — `node-info`, `routes`, `keepalive`, `throughput`,
//!   `metrics`, `logs`, `resolve`, and the [`link`] and [`auth`] groups. These
//!   open a [`wayfinder_client::Client`] and ask a node about itself.
//! * **[`provider`]** asks a *different* node — the mesh's certificate
//!   authority — about the mesh: its members, its enrollment queue, its
//!   accounts and VPN peers. This is the group that needs its own `--connect`.
//! * **[`cert`]** runs entirely offline, minting the seed / certificate /
//!   trust-anchor files a node loads to join an authenticated mesh.
//! * **[`csr`]** enrolls a node that cannot reach the provider, by carrying its
//!   signing request there as a file and the certificate back.
//!
//! The library surface exists so the renderers and the cert tooling can be unit-
//! tested; `main.rs` is a thin `clap` front end over [`run`].

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod auth;
pub mod cert;
pub mod csr;
pub mod link;
pub mod output;
pub mod ping;
pub mod provider;
pub mod session;
pub mod user;

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

pub mod vpn;
pub use vpn::VpnCommand;
use wayfinder_protos::wayfinder::v1alpha::authenticate_user_response::Outcome as UserOutcome;

use wayfinder_client::ConnectArgs;
use wayfinder_client::NodeAddr;

use crate::csr::CsrCommand;
use crate::output::OutputFormat;

/// Top-level command-line interface.
#[derive(Parser, Debug)]
#[command(
    name = "wayfinder-ctl",
    version,
    about = "Command-line client for the Wayfinder management API"
)]
pub struct Cli {
    /// How to reach the node: address, credentials, or a serial port.
    ///
    /// Shared with the TUI so both clients take the same flags, defaults and
    /// environment variables. Ignored by the subcommands that open no
    /// connection: `cert` (which works on the mesh root seed) and
    /// `login`/`logout`/`whoami` (which work on the stored session file).
    /// `provider user` is *not* among them any more — see its module docs for
    /// why administering accounts through the provider's state file was removed
    /// rather than documented.
    #[command(flatten)]
    pub connection: ConnectArgs,

    /// Output format for query commands.
    #[arg(long, short = 'o', global = true, default_value = "human")]
    pub output: OutputFormat,

    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Every `wayfinderctl` subcommand.
///
/// Grouped by subject rather than by verb, so the read of a setting and the
/// write of it sit together: an operator looks at a table and then changes a
/// row in it, and splitting those into "queries" and "set-*" put them several
/// screens apart in `--help`.
///
/// The one axis that is not a subject is [`Command::Provider`], and it earns
/// its place by being the one thing that changes *which node you are talking
/// to* — see that module's header.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Basic identity and capacity of the node.
    NodeInfo,
    /// The BATMAN originator (routing) table.
    Routes,
    /// The per-neighbor keep-alive heartbeat liveness table.
    Keepalive,
    /// Per-interface and node-wide throughput estimates.
    Throughput,
    /// Aggregate node health and topology metrics.
    Metrics,
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
    /// Probe whether this node can actually reach another, and how fast.
    ///
    /// `resolve` above answers what the routing table *believes*; this answers
    /// whether the path works. There are no IP addresses on a mesh, so this is
    /// not ICMP: the node emits probes addressed to the target's identifier,
    /// routed hop by hop like any data, and the target answers them.
    ///
    /// The node runs the session — this starts it and reports it. A node runs
    /// one at a time, so starting a ping displaces another client's.
    Ping {
        /// Destination identifier: a MAC like `02:00:00:00:00:09`, or raw hex.
        dest: String,
        /// Probes to send. 0 uses the node's default.
        #[arg(long, short = 'c', default_value_t = 0)]
        count: u32,
        /// Milliseconds between probes. 0 uses the node's default.
        #[arg(long, short = 'i', default_value_t = 0)]
        interval: u32,
        /// Milliseconds a probe waits for its reply before counting as lost.
        /// 0 uses the node's default, which is generous — a multi-hop LoRa
        /// round trip is measured in seconds.
        #[arg(long, short = 'W', default_value_t = 0)]
        timeout: u32,
        /// Pad bytes each probe carries, echoed back by the target — so a
        /// probe can be sized against a link's MTU. 0 uses the node's default.
        ///
        /// Ctrl+C stops the node's session as well as this command, and prints
        /// the statistics for what it measured — the node owns the session, so
        /// merely exiting would leave it probing.
        #[arg(long, short = 's', default_value_t = 0)]
        size: u32,
    },
    /// Per-interface state: link quality, participation features, OGM schedule,
    /// and the runtime overrides for each.
    #[command(subcommand)]
    Link(link::LinkCommand),
    /// This node's own membership credential: its posture, how it is obtained,
    /// and how it is advertised.
    #[command(subcommand)]
    Auth(auth::AuthCommand),
    /// Enroll a node that cannot reach the provider, by carrying its request
    /// there as a file.
    ///
    /// `request` and `install` talk to the node being **enrolled**: ask it what
    /// to certify, then hand the signed result back. `submit` takes the file in
    /// between to a **provider** and brings the certificate home. Acting on
    /// what is waiting at that provider is `provider requests`; signing the
    /// file directly, wherever the mesh root key lives, is `cert approve`.
    #[command(subcommand)]
    Csr(CsrCommand),
    /// The node as the mesh's certificate authority: members, revocations, the
    /// enrollment queue, accounts and VPN peers.
    ///
    /// Every command here is pointed at a provider, not at your own node.
    #[command(subcommand, visible_alias = "ca")]
    Provider(provider::ProviderCommand),
    /// Offline certificate / trust-anchor tooling (no node connection).
    #[command(subcommand)]
    Cert(cert::CertCommand),
    /// Log in to a provider and store the session it issues, so every other
    /// subcommand finds a credential with no flags.
    Login {
        /// The provider's `host:port`. Defaults to `--connect`.
        #[arg(long)]
        provider: Option<NodeAddr>,
        /// The account to log in as.
        #[arg(long)]
        user: String,
    },
    /// Delete the stored session.
    Logout,
    /// Print what credential this client is holding and when it stops working.
    Whoami,

    // ── Compatibility spellings ─────────────────────────────────────────────
    //
    // Hidden rather than removed. Between them these three account for roughly
    // seventy call sites across `docs/design/implemented/**`, the nix modules,
    // the VM tests and `scripts/`, and the design docs in particular are a
    // record of what shipped — rewriting them to match a later rename would
    // falsify that record. They forward to the grouped spelling, which is what
    // `--help` teaches and what new writing should use.
    //
    // Each carries the *same* type as the command it aliases rather than a
    // restatement of its fields. `--help` still renders for a hidden alias, so
    // an alias with its own copy of the arguments has its own copy of their
    // documentation — which is exactly how the first version of this drifted,
    // dropping `--mac`'s defaulting rule from the spelling most call sites
    // use.
    /// Alias for `provider user`.
    #[command(hide = true, subcommand)]
    User(user::UserCommand),
    /// Alias for `provider vpn`.
    #[command(hide = true, subcommand)]
    Vpn(vpn::VpnCommand),
    /// Alias for `auth enroll`.
    #[command(hide = true)]
    Enroll(auth::EnrollArgs),
    /// Alias for `auth status`.
    ///
    /// Kept visible, unlike the three above: "Security" is what the TUI tab and
    /// the web tab are both called, and the three clients answering to the same
    /// word is worth one extra spelling.
    Security,
}

impl Command {
    /// Rewrite a compatibility spelling into the grouped command it stands for.
    ///
    /// Done once, here, rather than by duplicating dispatch arms: the aliases
    /// then cannot drift from what they alias, because after this point they no
    /// longer exist.
    ///
    /// `pub` because it is the second half of parsing: `Cli::parse_from` yields
    /// whichever spelling was typed, and this is what says which command that
    /// spelling *is*. An embedder — or a test asserting on the grammar — needs
    /// both halves to know what an argv actually reaches.
    #[must_use]
    pub fn canonical(self) -> Self {
        match self {
            Command::User(cmd) => Command::Provider(provider::ProviderCommand::User(cmd)),
            Command::Vpn(cmd) => Command::Provider(provider::ProviderCommand::Vpn(cmd)),
            Command::Security => Command::Auth(auth::AuthCommand::Status),
            Command::Enroll(args) => Command::Auth(auth::AuthCommand::Enroll(args)),
            other => other,
        }
    }
}

/// Assemble the [`Endpoint`] a query command connects over from the parsed CLI,
/// erroring if `--identity` (required to reach a node's TLS management API) was
/// not supplied.  The seed/cert reads and node-key resolution live in
/// [`Endpoint::load`], shared with the TUI so both accept the same inputs.
///
/// `pub` so an integration test can drive credential resolution directly, the
/// same reason [`run_query`] is.  It is worth reaching: the `--cert-from`
/// branch below is the one piece of this decision that
/// [`ConnectArgs::resolve_target`] does not share, because only this side has a
/// stored login session to choose against.
pub async fn build_endpoint(cli: &Cli) -> anyhow::Result<Endpoint> {
    // `--cert-from` decides the credential outright, and decides it *before*
    // the identity question below: it says the certificate presented is a
    // node's own, and a node's certificate names the key in its identity seed.
    // A stored login session is therefore never the right seed to pair it with
    // — that key is an operator's, and no node's certificate names it — so this
    // takes the identity path (`--identity`, else the default a node's own host
    // has) rather than falling through to the session.
    if let Some(source) = cli.connection.cert_from.as_ref() {
        let mut endpoint = Endpoint::load(
            cli.connection.connect.clone(),
            cli.connection.identity_path(),
            // No certificate read from disk: fetching one is the whole point,
            // and clap has already refused `--cert` alongside this.
            None,
            cli.connection.node_key.as_deref(),
        )?;
        endpoint.load_cert_from_node(source).await?;
        return Ok(endpoint);
    }
    // An explicit `--identity` still wins: it is how a node is bootstrapped
    // with its own seed, which no login can substitute for.
    if let Some(identity_path) = cli.connection.identity.as_ref() {
        return Endpoint::load(
            cli.connection.connect.clone(),
            identity_path,
            cli.connection.cert.as_deref(),
            cli.connection.node_key.as_deref(),
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
    let addr = cli.connection.connect.to_string();
    let node_key = match cli.connection.node_key.as_deref() {
        Some(hex) => wayfinder_client::parse_key32(hex).context("parsing --node-key")?,
        None => session::pinned_key(&config, &addr)?.with_context(|| {
            format!(
                "no key recorded for {addr}: pass --node-key <hex>, or connect once \
                 interactively to record it"
            )
        })?,
    };
    Ok(Endpoint {
        addr: cli.connection.connect.clone(),
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
async fn login(provider: NodeAddr, username: &str, node_key: Option<&str>) -> anyhow::Result<()> {
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
                let offered = probe_node_key(&provider).await?;
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
    let mut client = Client::connect_tls(&provider, &node_key, &identity).await?;
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
async fn probe_node_key(addr: &NodeAddr) -> anyhow::Result<[u8; 32]> {
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
pub async fn run(mut cli: Cli) -> anyhow::Result<()> {
    // Folded before anything inspects the command, so the offline check and the
    // `--follow` interception below each need to know only the grouped form.
    cli.command = cli.command.canonical();
    // The offline tooling needs no node connection.
    match cli.command {
        Command::Cert(cmd) => return cert::run(cmd),
        Command::Logout => return logout(),
        Command::Whoami => return whoami(),
        Command::Login { provider, user } => {
            return login(
                provider.unwrap_or_else(|| cli.connection.connect.clone()),
                &user,
                cli.connection.node_key.as_deref(),
            )
            .await;
        }
        _ => {}
    }
    // Resolved once and reused below, rather than rebuilt per connection: with
    // `--cert-from` the resolution itself talks to a node, and doing that twice
    // would double the round trips for one command.
    //
    // `None` for a serial target: that transport has no endpoint, and cannot
    // join a VPN anyway (an embedded node runs no tunnel daemon).
    let endpoint = match cli.connection.serial {
        Some(_) => None,
        None => Some(build_endpoint(&cli).await?),
    };
    // A serial target reaches an embedded node's unauthenticated management API
    // directly; otherwise connect over the authenticated TLS endpoint.
    let mut client = match (cli.connection.serial.clone(), &endpoint) {
        (Some(path), _) => Client::connect_serial(&path, cli.connection.baud).await?,
        (None, Some(endpoint)) => {
            Client::connect_tls(&endpoint.addr, &endpoint.node_key, &endpoint.identity).await?
        }
        // Unreachable: the match above gives every non-serial target an
        // endpoint, and every serial one takes the first arm.
        (None, None) => bail!("internal: a TLS target resolved to no endpoint"),
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
    // A ping outlives a single response too, and an operator wants each probe
    // as it resolves rather than a block at the end. `dispatch_query` runs the
    // same session without the streaming, for an embedder calling `run_query`.
    if let Command::Ping {
        dest,
        count,
        interval,
        timeout,
        size,
    } = &cli.command
    {
        let destination = parse_id(dest)?;
        let args = ping::PingArgs {
            count: *count,
            interval_ms: *interval,
            timeout_ms: *timeout,
            payload_bytes: *size,
        };
        let rendered = ping::run(&mut client, destination, args, cli.output, true).await?;
        // The human path has already streamed its lines and summary; printing
        // the rendered form again would double every one of them. Empty means
        // there was nothing to report — a cancel that found no session — and a
        // blank line is not a JSON document.
        if cli.output == OutputFormat::Json && !rendered.is_empty() {
            println!("{rendered}");
        }
        return Ok(());
    }
    println!(
        "{}",
        dispatch_query(cli.command, &mut client, cli.output, endpoint.as_ref()).await?
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
        Client::connect_tls(&endpoint.addr, &endpoint.node_key, &endpoint.identity).await?;
    dispatch_query(command, &mut client, output, Some(endpoint)).await
}

/// Dispatch one query `command` against an already-connected `client`, returning
/// the rendered response. Shared by the TLS path ([`run_query`]) and the
/// unauthenticated serial path (`--serial`), so every command works identically
/// over either transport.
///
/// Canonicalizes before matching. `run` has already done so for the CLI path,
/// but the public [`run_query`] has not, so removing the call here as redundant
/// would make `run_query(Command::Security, ..)` hit the compatibility arm and
/// panic. It is idempotent, which is what makes doing it twice the cheap
/// option.
async fn dispatch_query(
    command: Command,
    client: &mut Client,
    output: OutputFormat,
    endpoint: Option<&Endpoint>,
) -> anyhow::Result<String> {
    let command = command.canonical();
    Ok(match command {
        Command::NodeInfo => output::node_info(&client.node_info().await?, output)?,
        Command::Routes => output::routing_table(&client.routing_table().await?, output)?,
        Command::Keepalive => output::keepalive_table(&client.keepalive_table().await?, output)?,
        Command::Throughput => output::throughput(&client.throughput().await?, output)?,
        Command::Metrics => output::node_metrics(&client.node_metrics().await?, output)?,
        // `--follow` never reaches here: `run` intercepts it, since a stream of
        // batches cannot be returned as the one rendered response every other
        // command produces.
        Command::Logs { since, max, .. } => output::logs(&client.logs(since, max).await?, output)?,
        Command::Resolve { dest } => {
            let id = parse_id(&dest)?;
            output::resolve(&client.resolve_route(id).await?, output)?
        }
        // Runs the whole session and renders it once. `run` intercepts the CLI
        // path above to stream instead; this is the shape `run_query`'s
        // embedders need, which is one call returning one rendered answer.
        Command::Ping {
            dest,
            count,
            interval,
            timeout,
            size,
        } => {
            let destination = parse_id(&dest)?;
            let args = ping::PingArgs {
                count,
                interval_ms: interval,
                timeout_ms: timeout,
                payload_bytes: size,
            };
            ping::run(client, destination, args, output, false).await?
        }
        Command::Link(cmd) => link::run(cmd, client, output).await?,
        Command::Auth(cmd) => auth::run(cmd, client, output, endpoint).await?,
        Command::Csr(cmd) => csr::run(cmd, client).await?,
        Command::Provider(cmd) => provider::run(cmd, client, output).await?,
        // Every command that needs no node connection is dispatched by `run`
        // before a client is opened; listing them here rather than under a
        // wildcard keeps a newly added offline command from silently reaching
        // a code path that would try to connect for it.
        // `run` dispatches these before opening a client. Listing them rather
        // than using a wildcard keeps a newly added offline command from
        // silently reaching a path that would try to connect for it.
        //
        // `bail!` rather than `unreachable!`: `run_query` is public and has
        // already opened a TLS connection by the time it gets here, so an
        // embedder passing an offline command deserves an error, not a panic
        // in a library.
        Command::Cert(_) | Command::Login { .. } | Command::Logout | Command::Whoami => {
            bail!("internal: this command needs no connection and cannot be dispatched as a query")
        }
        // Rewritten by `canonical` above, so they cannot appear here.
        Command::User(_) | Command::Vpn(_) | Command::Enroll(_) | Command::Security => {
            bail!("internal: a compatibility spelling survived canonicalization")
        }
    })
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

/// Parse a duration an operator typed into a number of seconds: a count with
/// an optional unit suffix (`s`, `m`, `h`, `d`, `w`, `y`), or a bare count of
/// seconds.
///
/// A certificate lifetime is the one number in this CLI that is naturally
/// written in days or years and passed over the wire in seconds, and asking an
/// operator to convert a year by hand is asking for the wrong number of zeros.
/// Zero is refused here rather than left to the node: it is the one value whose
/// only possible effect — a certificate that expired before it was collected —
/// is never what anyone meant, and refusing locally says so without a round
/// trip.
///
/// A year is 365 days and a month is not a unit at all: a lifetime is compared
/// against a wall clock, and a unit whose length depends on which month it
/// started in cannot be checked against a cap.
pub fn parse_duration_secs(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let (count, unit_secs) = match s.strip_suffix(|c: char| c.is_ascii_alphabetic()) {
        Some(count) => {
            let unit = match s.as_bytes()[s.len() - 1] {
                b's' => 1,
                b'm' => 60,
                b'h' => 3_600,
                b'd' => 86_400,
                b'w' => 7 * 86_400,
                b'y' => 365 * 86_400,
                _ => {
                    anyhow::bail!(
                        "'{s}' has an unknown unit; use s, m, h, d, w, y, or a bare \
                         number of seconds"
                    )
                }
            };
            (count, unit)
        }
        None => (s, 1),
    };
    let count: u64 = count
        .parse()
        .with_context(|| format!("'{s}' is not a duration like 90d, 12h, or 3600"))?;
    let secs = count
        .checked_mul(unit_secs)
        .with_context(|| format!("'{s}' is too long to express in seconds"))?;
    anyhow::ensure!(
        secs > 0,
        "a lifetime of zero would issue a certificate that has already expired"
    );
    Ok(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The suffixed forms an operator reaches for, and the bare one the
    /// management API speaks.
    #[test]
    fn parse_duration_secs_accepts_each_unit() {
        assert_eq!(parse_duration_secs("3600").unwrap(), 3600);
        assert_eq!(parse_duration_secs("90s").unwrap(), 90);
        assert_eq!(parse_duration_secs("30m").unwrap(), 1_800);
        assert_eq!(parse_duration_secs("12h").unwrap(), 43_200);
        assert_eq!(parse_duration_secs("30d").unwrap(), 2_592_000);
        assert_eq!(parse_duration_secs("2w").unwrap(), 1_209_600);
        assert_eq!(parse_duration_secs("1y").unwrap(), 31_536_000);
        // Surrounding space is an artifact of shell quoting, not a mistake.
        assert_eq!(parse_duration_secs(" 7d ").unwrap(), 604_800);
    }

    /// Zero is refused here rather than at the node, because the node's answer
    /// arrives after a round trip and says the same thing.
    #[test]
    fn parse_duration_secs_rejects_zero_and_nonsense() {
        assert!(parse_duration_secs("0").is_err());
        assert!(parse_duration_secs("0d").is_err());
        assert!(parse_duration_secs("").is_err());
        assert!(parse_duration_secs("d").is_err());
        assert!(parse_duration_secs("forever").is_err());
        assert!(parse_duration_secs("-1").is_err());
        assert!(parse_duration_secs("7 days").is_err());
    }

    /// A count large enough to overflow the seconds it names is an error, not
    /// a wrapped-around lifetime.
    #[test]
    fn parse_duration_secs_rejects_an_overflowing_count() {
        assert!(parse_duration_secs("99999999999999999999y").is_err());
        assert!(parse_duration_secs(&format!("{}d", u64::MAX)).is_err());
    }

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
