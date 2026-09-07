//! This node's own membership credential: what it holds, how it got it, and
//! how it advertises it.
//!
//! One subject that used to be four unrelated top-level commands — `security`
//! read the posture, `set-auth` replaced the credential, `enroll` obtained one,
//! and `set-lazy-cert-distribution` changed how it is put on the wire. The read
//! and the writes of one thing now sit together.
//!
//! `status` keeps the name the TUI tab and the web tab both use, and `security`
//! remains a top-level spelling for it (see `Command::Security`), so the three
//! dashboards still answer to the same word.

use std::path::PathBuf;

use anyhow::Context;
use anyhow::bail;
use clap::Subcommand;
use wayfinder_auth::Keypair;
use wayfinder_client::Client;
use wayfinder_client::Endpoint;
use wayfinder_protos::wayfinder::v1alpha::CsrIssued;
use wayfinder_protos::wayfinder::v1alpha::submit_csr_response::Outcome as CsrOutcome;

use crate::cert;
use crate::output;
use crate::output::OutputFormat;
use crate::parse_mac6;
use crate::renewal::RenewalArgs;
use crate::renewal::renewal_note;
use crate::vpn;

/// The node's credential: read it, replace it, obtain one, or change how it is
/// advertised.
#[derive(Subcommand, Debug)]
pub enum AuthCommand {
    /// Mesh authentication / security posture: auth on/off, the mesh and
    /// own-cert header, and per-originator verified / expiry / revoked state.
    Status,
    /// Replace the node's identity and certificate over the management API.
    ///
    /// This *re-identifies* the node: the seed is its private key, so after this
    /// it is a different node. Certifying the identity a node already holds —
    /// the far more common operation — is `csr install`, which is the same
    /// `SetAuth` call with no seed and deliberately offers no way to supply
    /// one.
    Set {
        /// The node's new 32-byte identity seed (secret).
        #[arg(long)]
        seed: PathBuf,
        /// The node's certificate, signed by the mesh root.
        #[arg(long)]
        cert: PathBuf,
        /// The mesh trust anchor the certificate chains to.
        #[arg(long)]
        trust_anchor: PathBuf,
        /// Where the node renews this certificate. Naming none clears whatever
        /// the node had recorded — see [`RenewalArgs`].
        #[command(flatten)]
        renewal: RenewalArgs,
    },
    /// Enroll with a provider: generate a keypair, submit a CSR, and write the
    /// returned certificate and trust anchor (online enrollment).
    ///
    /// Needs the node and the provider to be mutually reachable. When they are
    /// not, the `csr` commands carry the request out-of-band instead.
    Enroll(EnrollArgs),
    /// Switch lazy cert distribution on or off at runtime: emit an 8-byte cert
    /// fingerprint on OGMs instead of the full membership cert. Applied in
    /// memory only — it does not persist across a restart. A flag-day, wire-
    /// incompatible switch with un-upgraded auth nodes: only flip this on a
    /// mesh where every node has already been upgraded.
    LazyCerts {
        /// `true` to emit the fingerprint; `false` to emit the full cert as
        /// before.
        ///
        /// Takes an explicit value rather than being a bare presence flag.
        /// As a flag there was no way to spell `false` at all, so the switch
        /// this command exists to operate could be thrown in one direction
        /// only.
        #[arg(long, action = clap::ArgAction::Set)]
        enabled: bool,
    },
}

/// The arguments to an enrollment.
///
/// A `clap::Args` struct rather than inline variant fields because `enroll` has
/// two spellings — `auth enroll` and the retained top-level `enroll` — and
/// inline fields meant writing the documentation twice. It drifted immediately:
/// the abridged copy dropped the explanation that `--mac` defaults to the MAC
/// derived from the enrolling keypair, which is the single most surprising
/// thing about the command, from the spelling most existing call sites use.
/// Flattened into both, the docs exist once and cannot disagree.
#[derive(clap::Args, Debug)]
pub struct EnrollArgs {
    /// This node's MAC, bound into the issued certificate. A certificate's MAC
    /// *is* the address its identity key derives (the same derivation
    /// `wayfinder-tap` applies at startup), so this is a cross-check on the
    /// keypair being enrolled rather than an override: naming any other address
    /// is refused, because the provider would refuse it and no node would
    /// honour the result. Leave it out unless you want the check.
    #[arg(long)]
    pub mac: Option<String>,
    /// Enrollment token, if the provider requires one.
    #[arg(long, default_value = "")]
    pub token: String,
    /// Where to write the generated 32-byte identity seed (secret).
    #[arg(long)]
    pub out_seed: PathBuf,
    /// Where to write the issued certificate.
    #[arg(long)]
    pub out_cert: PathBuf,
    /// Where to write the mesh trust anchor.
    #[arg(long)]
    pub out_anchor: PathBuf,
    /// Do not join the VPN, even if the provider offers a tunnel.
    ///
    /// Enrollment otherwise asks for a tunnel credential once the certificate
    /// is in hand and runs `tailscale up` with it. A provider with no VPN
    /// configured answers "not configured" and enrollment finishes normally
    /// either way, so this is for a host that reaches the mesh some other way
    /// rather than for talking to a CA without one.
    #[arg(long)]
    pub no_vpn: bool,
    /// Print the `tailscale up` command instead of running it.
    ///
    /// For a host where the tunnel daemon is managed elsewhere (a NixOS
    /// module, a container entrypoint). The preauth key is single-use and
    /// short-lived, so a printed command has minutes to be used, not days.
    #[arg(long)]
    pub print_vpn_command: bool,
}

/// Dispatch one `auth` subcommand against an already-connected `client`.
///
/// `endpoint` is `None` for a serial target, which has no TLS endpoint to
/// reconnect over and so cannot take enrollment's VPN step.
pub async fn run(
    cmd: AuthCommand,
    client: &mut Client,
    fmt: OutputFormat,
    endpoint: Option<&Endpoint>,
) -> anyhow::Result<String> {
    Ok(match cmd {
        AuthCommand::Status => output::security(&client.security_status().await?, fmt)?,
        AuthCommand::Set {
            seed,
            cert,
            trust_anchor,
            renewal,
        } => {
            let credential = cert::read_credential(&cert, &trust_anchor)?;
            // Length-checked like the other two inputs rather than read raw: a
            // short or truncated seed installed as an identity is a node that
            // cannot sign, and the file is the one input here whose contents
            // are otherwise unexaminable.
            let seed_bytes = cert::read_seed(&seed)?;
            // Resolved before the call, so a malformed pin is refused while
            // the node still holds the identity it had.
            let provider = renewal.provider()?;
            let renewal_note = renewal_note(provider.as_ref());
            client
                .set_auth(
                    &seed_bytes,
                    &credential.cert_bytes,
                    &credential.anchor_bytes,
                    provider,
                )
                .await
                .context("failed to set auth")?;
            format!(
                "identity replaced; installed certificate for {} (mesh {:#x}), valid until {}{renewal_note}",
                output::format_mac(&credential.cert.node_mac),
                credential.anchor.mesh_id,
                credential.cert.not_after.get(),
            )
        }
        AuthCommand::LazyCerts { enabled } => {
            client
                .set_lazy_cert_distribution(enabled)
                .await
                .context("failed to set lazy cert distribution")?;
            format!(
                "lazy cert distribution {}",
                if enabled { "enabled" } else { "disabled" }
            )
        }
        AuthCommand::Enroll(EnrollArgs {
            mac,
            token,
            out_seed,
            out_cert,
            out_anchor,
            no_vpn,
            print_vpn_command,
        }) => {
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
            // A cross-check, not an override — see the `--mac` doc. Caught here
            // rather than left to the provider so the operator is told which
            // half is wrong (usually a reused `--out-seed` from another node)
            // instead of reading a rejection about an address they did not
            // realise they had changed.
            let derived = kp.derived_mac();
            if let Some(spelled) = &mac {
                let named = parse_mac6(spelled)?;
                if named != derived.0 {
                    anyhow::bail!(
                        "--mac {} is not the address this identity derives ({}); a \
                         certificate's MAC must be the address its key derives, so \
                         either drop --mac or check --out-seed names the right identity",
                        output::format_mac(&named),
                        output::format_mac(&derived.0),
                    );
                }
            }
            let mac_bytes = derived.0;
            let issued = poll_enroll(client, &mac_bytes, &kp, &token).await?;
            // The seed is already on disk (reused from `out_seed`, or written
            // above before polling), so it needs no second write here.
            std::fs::write(&out_cert, &issued.cert)
                .with_context(|| format!("writing certificate to {}", out_cert.display()))?;
            std::fs::write(&out_anchor, &issued.trust_anchor)
                .with_context(|| format!("writing trust anchor to {}", out_anchor.display()))?;
            // Enrollment is complete and durable at this point. The VPN step
            // below is additive: it reconnects presenting the certificate just
            // issued, which earns the member tier `GetVpnEnrollment` needs —
            // the connection enrollment ran over was a stranger's and cannot
            // mint anything. Anything that goes wrong there is reported in the
            // summary rather than failing the command, since failing would
            // discard an enrollment that already succeeded.
            let vpn_note = match (no_vpn, endpoint) {
                (true, _) | (false, None) => String::new(),
                (false, Some(endpoint)) => {
                    join_vpn_as_enrolled_node(endpoint, &seed, &issued.cert, print_vpn_command)
                        .await
                        .enrollment_note()
                }
            };
            format!(
                "enrolled {}: wrote seed, certificate, and trust anchor{vpn_note}",
                output::format_mac(&mac_bytes)
            )
        }
    })
}

/// Open a second connection to `endpoint` as the freshly-enrolled node and ask
/// for a tunnel credential.
///
/// A *second* connection, not the one enrollment ran over: that one was opened
/// as a stranger (no certificate), which is the enrollment tier and cannot mint
/// a tunnel credential — deliberately, since every field of a CSR is
/// self-asserted. Presenting the issued certificate here is what proves
/// possession of the key that was certified.
///
/// Never fails the caller: it returns the outcome, whatever happened, for the
/// caller to render into the enrollment summary.
async fn join_vpn_as_enrolled_node(
    endpoint: &Endpoint,
    seed: &[u8; 32],
    cert: &[u8],
    print_only: bool,
) -> vpn::VpnJoinOutcome {
    let identity = wayfinder_client::Identity {
        seed: *seed,
        cert: cert.to_vec(),
    };
    match Client::connect_tls(&endpoint.addr, &endpoint.node_key, &identity).await {
        Ok(mut client) => vpn::join(&mut client, print_only).await,
        Err(e) => vpn::VpnJoinOutcome::NotConfigured(format!(
            "reconnecting as the enrolled node failed: {e}"
        )),
    }
}

/// Submit one CSR and interpret the outcome.
///
/// Despite the name this issues a single request and returns; the polling is
/// the operator re-running `enroll` against the same `--out-seed`. A provider
/// configured to require approval parks the CSR as pending, and re-submitting
/// the identical request is how the enrolling node collects the certificate
/// once an operator approves it — which is why the pending arm says to retry
/// rather than waiting here.
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
        // Pending (or an empty outcome, treated the same): the caller should
        // keep polling until the request is approved.
        Some(CsrOutcome::Pending(_)) | None => {
            bail!(
                "CSR still awaiting operator approval; approve it with \
                 `wayfinderctl provider requests approve --mac <mac>` and retry",
            );
        }
    }
}
