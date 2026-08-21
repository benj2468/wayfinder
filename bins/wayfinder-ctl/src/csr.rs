//! The certificate-signing-request workflow, from both ends.
//!
//! Online enrollment (`wayfinderctl enroll`) needs the node and the provider to
//! be mutually reachable: the node opens a connection and asks to join. These
//! commands are for the case where it cannot — a node on an isolated network,
//! behind an air gap, or simply out in the field. The request travels
//! out-of-band instead, as a file:
//!
//! ```text
//!   csr request   at the node        →  request.json  ─┐
//!                                                       │  email / USB / courier
//!   csr submit    at the provider    ←──────────────────┘
//!     (or `cert approve`, where the mesh root key lives)
//!                                    →  cert + anchor  ─┐
//!                                                       │  and back again
//!   csr install   at the node        ←──────────────────┘
//! ```
//!
//! Both node-side steps ask the *node* over the management API rather than
//! reading its seed off a filesystem, so the operator never holds the node's
//! private key — which is what makes this work for a node that minted its own
//! identity and for one whose filesystem is not reachable by path.
//!
//! `list`/`approve`/`deny` are the provider-side operator actions, the same
//! ones the web and TUI screens drive.

use std::path::PathBuf;

use anyhow::Context;
use anyhow::bail;
use clap::Subcommand;
use wayfinder_client::Client;
use wayfinder_protos::wayfinder::v1alpha::SubmitCsrRequest;
use wayfinder_protos::wayfinder::v1alpha::submit_csr_response::Outcome as CsrOutcome;

use crate::cert;
use crate::output;
use crate::output::OutputFormat;
use crate::parse_mac6;

/// The certificate-signing-request workflow: the node-side steps that carry a
/// request out and a certificate back, and the provider-side operator actions
/// on what is waiting.  See the module header for how they chain.
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

    /// Ask the node at `--connect` to describe the identity it already runs
    /// under, and write that out as a certificate signing request for an
    /// offline CA.
    ///
    /// The first step of enrolling a node that cannot reach the provider over
    /// any network. The file it writes travels out-of-band — email, a USB
    /// stick, a courier — to whoever can reach the mesh root key; `cert
    /// approve` signs it there, and the result comes back to `csr install`.
    ///
    /// This talks to the node being *enrolled*, not to a provider. Building
    /// the CSR itself never needs the node's private key: everything in it —
    /// MAC, public keys — comes from asking the node over the connection, not
    /// from signing anything, which is what makes it work against a node that
    /// minted its own identity and whose seed the operator never holds.
    ///
    /// Reaching the node in the first place is a separate question, and
    /// depends on whether it has a trust anchor loaded yet. The case this
    /// command exists for — a fresh node with none — has exactly one door
    /// open: self-key access, connecting with a copy of the node's own seed
    /// as `--identity` and its public key as `--node-key` (see
    /// `authz::decide_access`). A node that already holds a trust anchor and
    /// a certificate for it (e.g. this is a renewal, not a first enrollment)
    /// can instead be reached the ordinary way, with any `--identity`/`--cert`
    /// valid for that mesh.
    Request {
        /// Where to write the request (JSON).
        #[arg(long)]
        out_request: PathBuf,
        /// Optional shared enrollment token, if the target CA requires one.
        /// Supplied by the operator, not by the node — it is a secret the
        /// provider checks, which the node being enrolled never learns.
        #[arg(long, default_value = "")]
        token: String,
    },

    /// Upload a CSR file to the provider at `--connect`, and write back the
    /// certificate and trust anchor it issues.
    ///
    /// The middle step of the out-of-band chain, for an operator who can reach
    /// the provider but holds no mesh root key — the alternative to signing the
    /// request locally with `cert approve`.
    ///
    /// **Upload and download are the same call.** The management protocol has
    /// no separate "fetch my certificate" request: re-submitting an identical
    /// CSR is how an issued certificate is collected. So against a provider
    /// that parks requests for approval, the first run reports the request as
    /// pending and writes nothing; approve it (in the web UI, the TUI, or with
    /// `csr approve`) and re-run this against the same file to collect.
    ///
    /// Needs no membership certificate of its own: `SubmitCsr` is on the
    /// enrollment tier, so relaying someone else's request requires no
    /// credential for the provider. Any enrollment token travels inside the
    /// request file, so the relaying operator never has to learn it.
    Submit {
        /// The CSR file `csr request` produced at the node.
        #[arg(long)]
        request: PathBuf,
        /// Where to write the issued certificate.
        #[arg(long)]
        out_cert: PathBuf,
        /// Where to write the mesh trust anchor that certificate chains to.
        #[arg(long)]
        out_anchor: PathBuf,
    },

    /// Hand a signed certificate and its trust anchor back to the node at
    /// `--connect`, certifying the identity that node already holds.
    ///
    /// The last step of the out-of-band chain `csr request` begins: whoever
    /// holds the mesh root key signed the CSR with `cert approve`, and the
    /// certificate has made its way back here.
    ///
    /// The node keeps its existing identity: this sends `SetAuth` with an empty
    /// seed, so an install can certify a node but never re-identify it. On a
    /// node with `runtime_state_path` configured the result persists, so the
    /// node comes back up enrolled.
    Install {
        /// The certificate `cert approve` (or `cert issue`) produced.
        #[arg(long)]
        cert: PathBuf,
        /// The mesh trust anchor the certificate chains to.
        #[arg(long)]
        trust_anchor: PathBuf,
    },
}

/// Dispatch one `csr` subcommand against an already-connected `client`.
///
/// Which end of the workflow `client` is connected to depends on the
/// subcommand: `request` and `install` talk to the node being enrolled, while
/// `list`/`approve`/`deny`/`submit` talk to the provider.
pub async fn run(
    cmd: CsrCommand,
    client: &mut Client,
    output: OutputFormat,
) -> anyhow::Result<String> {
    Ok(match cmd {
        CsrCommand::List => output::list_pending_csrs(&client.list_pending_csrs().await?, output)?,
        CsrCommand::Approve { mac } => {
            let mac_bytes = parse_mac6(&mac)?;
            client
                .approve_csr(&mac_bytes)
                .await
                .context("approving CSR failed")?;
            format!("approved CSR for {mac}")
        }
        CsrCommand::Deny { mac } => {
            let mac_bytes = parse_mac6(&mac)?;
            client
                .deny_csr(&mac_bytes)
                .await
                .context("denying CSR failed")?;
            format!("denied CSR for {mac}")
        }
        CsrCommand::Request { out_request, token } => {
            let request = csr_for_connected_node(client, token).await?;
            let mac = output::format_mac(&request.node_mac);
            let bytes = serde_json::to_vec_pretty(&request)
                .context("serializing certificate signing request")?;
            // Written only once every field has been validated, so a node that
            // could not describe itself leaves no half-formed CSR for the
            // operator to carry to the CA.
            std::fs::write(&out_request, bytes)
                .with_context(|| format!("writing request to {}", out_request.display()))?;
            format!(
                "wrote certificate signing request for {mac} to {}",
                out_request.display()
            )
        }
        CsrCommand::Submit {
            request,
            out_cert,
            out_anchor,
        } => {
            let bytes = std::fs::read(&request)
                .with_context(|| format!("reading request {}", request.display()))?;
            let req: SubmitCsrRequest =
                serde_json::from_slice(&bytes).context("request file is not valid JSON")?;
            let mac = output::format_mac(&req.node_mac);

            let issued = client
                .submit_csr(
                    &req.node_mac,
                    &req.ed_pubkey,
                    &req.x_pubkey,
                    &req.enrollment_token,
                )
                .await
                .context("submitting the request to the provider failed")?;

            // Written only once the provider has actually issued, so a pending
            // or refused submission leaves nothing behind that could be
            // mistaken for a certificate to carry home. The two writes below
            // are not atomic as a pair — a failure between them (disk full,
            // permissions changed mid-run) can leave a cert with no matching
            // anchor — but the CSR is idempotent to re-submit, so a retry
            // after fixing the underlying I/O problem overwrites both.
            let issued = match issued.outcome {
                Some(CsrOutcome::Issued(issued)) => issued,
                Some(CsrOutcome::Rejected(r)) => bail!("the provider refused {mac}: {}", r.reason),
                // Re-submitting the identical file is what collects the
                // certificate later, so the retry instruction names the file
                // rather than describing the request abstractly.
                Some(CsrOutcome::Pending(_)) => bail!(
                    "{mac} is awaiting operator approval; approve it in the web UI, the \
                     TUI, or with `wayfinderctl csr approve --mac {mac}`, then re-run \
                     this command against {} to collect the certificate",
                    request.display()
                ),
                // A well-behaved provider always sets exactly one outcome
                // variant (see the proto comment on `SubmitCsrResponse`); an
                // unset one is a provider bug or a version mismatch, not a
                // normal pending state, so it gets its own message rather
                // than being folded into the "approve and retry" guidance
                // above — that guidance would send the operator looking for
                // a pending request that was never actually queued.
                None => bail!(
                    "the provider returned no outcome for {mac} — this indicates a \
                     provider bug or a protocol version mismatch, not a pending \
                     request; do not retry without investigating"
                ),
            };
            std::fs::write(&out_cert, &issued.cert)
                .with_context(|| format!("writing certificate to {}", out_cert.display()))?;
            std::fs::write(&out_anchor, &issued.trust_anchor)
                .with_context(|| format!("writing trust anchor to {}", out_anchor.display()))?;
            format!(
                "{mac} issued: wrote {} and {}",
                out_cert.display(),
                out_anchor.display()
            )
        }
        CsrCommand::Install { cert, trust_anchor } => {
            // Parsed and cross-checked here rather than trusted to the node:
            // the node's own validation is the backstop, but a swapped pair of
            // filenames is worth naming as such instead of surfacing as a
            // remote rejection.
            let parsed_cert = cert::read_cert(&cert)?;
            let parsed_anchor = cert::read_trust_anchor(&trust_anchor)?;
            cert::check_mesh_match(&parsed_cert, &parsed_anchor)?;

            // The bytes as read are what is sent — round-tripping them through
            // the parsed types would only add a way for the two to disagree.
            let cert_bytes = std::fs::read(&cert)
                .with_context(|| format!("re-reading cert {}", cert.display()))?;
            let anchor_bytes = std::fs::read(&trust_anchor)
                .with_context(|| format!("re-reading trust anchor {}", trust_anchor.display()))?;
            client
                .install_cert(&cert_bytes, &anchor_bytes)
                .await
                .context("installing the certificate on the node failed")?;
            format!(
                "installed certificate for {} (mesh {:#x}), valid until {}",
                output::format_mac(&parsed_cert.node_mac),
                parsed_anchor.mesh_id,
                parsed_cert.not_after.get()
            )
        }
    })
}

/// Build a [`SubmitCsrRequest`] describing the identity the connected node is
/// already running under, so a certificate can be issued for a node whose seed
/// the operator does not hold.
///
/// Every field comes from the node itself, which is the point: the MAC is the
/// one the router answers to (`GetNodeInfo`), and the public keys are the ones
/// it signs and derives with (`GetSecurityStatus`). Nothing here is the
/// operator's to choose except `token`, which is a secret the *provider*
/// checks and the enrolling node never learns.
///
/// The MAC in particular must not be guessed or overridden. A node certifying
/// the identity it already holds refuses a certificate naming any other MAC
/// (see `RouterAdapter::set_auth`), so a CSR built from anything but what the
/// node reports produces a certificate that node cannot install.
async fn csr_for_connected_node(
    client: &mut Client,
    token: String,
) -> anyhow::Result<SubmitCsrRequest> {
    let info = client
        .node_info()
        .await
        .context("asking the node for its identity")?;
    let status = client
        .security_status()
        .await
        .context("asking the node for its public keys")?;

    // `enrollment` is set only on a node running in provider mode (see the
    // proto field comment). This command is the node-enrolling half of the
    // workflow, so pointing it at the provider by mistake would silently mint
    // a CSR for the provider's own identity — a file that looks fine and
    // installs cleanly, just onto the wrong node. Caught here instead of
    // relying on the operator to notice.
    if status.enrollment.is_some() {
        bail!(
            "--connect points at a provider, not the node to enroll; `csr request` \
             asks the node being enrolled to describe itself, so run it against that \
             node instead"
        );
    }

    // An un-enrolled node still reports its keys — that is exactly what makes
    // this possible — so empty ones mean the node has no identity at all, not
    // merely that it is unenrolled. Certifying that would bind a certificate to
    // nothing.
    if status.own_ed_pubkey.is_empty() || status.own_x_pubkey.is_empty() {
        bail!(
            "the node reports no identity to certify: it has no key pair, so there is \
             nothing a certificate could be bound to"
        );
    }
    if status.own_ed_pubkey.len() != 32 || status.own_x_pubkey.len() != 32 {
        bail!(
            "the node reported malformed public keys (ed25519 {} bytes, x25519 {} bytes; \
             both must be 32)",
            status.own_ed_pubkey.len(),
            status.own_x_pubkey.len()
        );
    }
    // A `MembershipCert` binds a six-octet MAC, so a node addressed any other
    // way (a short-address mesh) cannot be certified through this path at all.
    if info.node_id.len() != 6 {
        bail!(
            "the node identifies itself with {} bytes, and a membership certificate \
             binds a 6-byte MAC",
            info.node_id.len()
        );
    }

    Ok(SubmitCsrRequest {
        node_mac: info.node_id,
        ed_pubkey: status.own_ed_pubkey,
        x_pubkey: status.own_x_pubkey,
        enrollment_token: token,
    })
}
