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
use wayfinder_protos::wayfinder::v1alpha::CsrIssued;
use wayfinder_protos::wayfinder::v1alpha::submit_csr_response::Outcome as CsrOutcome;

use crate::cert;
use crate::output;
use crate::output::OutputFormat;
use crate::parse_mac6;

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
    /// This node's MAC, bound into the issued certificate. Defaults to the
    /// MAC deterministically derived from the enrolling keypair (the same
    /// derivation `wayfinder-tap` applies at startup), so the enrolled
    /// cert matches the MAC the node will actually run under; pass this to
    /// override that default.
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
}

/// Dispatch one `auth` subcommand against an already-connected `client`.
///
pub async fn run(
    cmd: AuthCommand,
    client: &mut Client,
    fmt: OutputFormat,
) -> anyhow::Result<String> {
    Ok(match cmd {
        AuthCommand::Status => output::security(&client.security_status().await?, fmt)?,
        AuthCommand::Set {
            seed,
            cert,
            trust_anchor,
        } => {
            let credential = cert::read_credential(&cert, &trust_anchor)?;
            // Length-checked like the other two inputs rather than read raw: a
            // short or truncated seed installed as an identity is a node that
            // cannot sign, and the file is the one input here whose contents
            // are otherwise unexaminable.
            let seed_bytes = cert::read_seed(&seed)?;
            client
                .set_auth(
                    &seed_bytes,
                    &credential.cert_bytes,
                    &credential.anchor_bytes,
                    "",
                )
                .await
                .context("failed to set auth")?;
            format!(
                "identity replaced; installed certificate for {} (mesh {:#x}), valid until {}",
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
            // Enrollment is complete and durable at this point, and — since
            // design 18 retired the VPN control plane — that is the whole of
            // it. There is no second credential to collect: an `Iroh` mesh
            // link dials peers by the very key this certificate binds, so the
            // artifacts written above are everything the node needs.
            format!(
                "enrolled {}: wrote seed, certificate, and trust anchor",
                output::format_mac(&mac_bytes)
            )
        }
    })
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
