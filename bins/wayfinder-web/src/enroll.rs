//! Asking a provider to admit this node to its mesh.
//!
//! The dashboard's one operation that talks to a node *other* than its own: it
//! opens a second, short-lived connection to the provider, submits a
//! certificate-signing request on this node's behalf, and — if a certificate
//! comes back — installs it, together with the provider it came from, so the
//! node can renew it before it lapses. This is the only point in the system
//! where the provider's address, its pinned key and the enrollment token are all
//! in one place; a certificate names only the mesh root that signed it, so a
//! node that is not told here has no way to find its authority later.
//!
//! # Whose keys are being certified
//!
//! The node's own. The request names the identity keys the node reports, read
//! from the node itself rather than taken from the browser, and the certificate
//! that comes back is installed against the seed the node keeps
//! ([`Client::install_cert`]). Nothing about the node's identity changes; it
//! simply acquires a certificate for the one it had. The alternative — mint a
//! fresh keypair here, as the offline `wayfinderctl enroll` does — would enrol
//! a different node, and would mean this process handling a private key, which
//! it otherwise never does.
//!
//! The *address* in the request is derived from those keys rather than read
//! from `GetNodeInfo`: since design 09 §5 a certificate may name only the
//! address its key derives, so a request built from the node's reported address
//! is one no authority will sign. The two agree for any node running a build
//! that derives its own MAC. Where they disagree the node predates that rule,
//! and enrolling it would spend an address its own `SetAuth` then refuses — so
//! this refuses first, and says to update the node.
//!
//! # What this connection is
//!
//! Anonymous, and deliberately so. It presents a throwaway key and no
//! certificate, because a node with nothing to present is precisely what is
//! asking. The provider admits such a connection for enrollment alone (see
//! `wayfinder_server::authz`), so the only thing it can do is make the request
//! it came to make. Admission is the provider's decision, taken on the
//! enrollment token and the operator's approval — not on who opened the socket.
//!
//! The provider's own key is pinned by the caller. Without it a man in the
//! middle could answer instead and hand back a certificate for *its* mesh,
//! which the node would then install and believe.

use serde::Deserialize;
use serde::Serialize;

/// What became of a request to join a mesh.
///
/// The pending case is a first-class outcome rather than an error: a provider
/// that holds requests for approval is the configuration an operator is most
/// likely to be running, and "waiting for someone to approve you" is a state to
/// be shown, not a failure to be reported.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnrollmentOutcome {
    /// A certificate was issued and installed; the node is now a member of the
    /// mesh with this id.
    Enrolled {
        /// The mesh the node has joined, for the confirmation message.
        mesh_id: u32,
    },
    /// The provider parked the request for an operator to approve. Asking again
    /// later is how the certificate is collected.
    AwaitingApproval,
    /// The provider refused, with its reason.
    Rejected {
        /// Why the provider refused — its words, not this crate's.
        reason: String,
    },
}

/// Everything needed to reach one provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderTarget {
    /// The provider's management-API address (`host:port`).
    pub address: String,
    /// The provider's Ed25519 public key, 64 hex characters. Pinned, so nothing
    /// else can answer in its place.
    pub node_key: String,
    /// The shared enrollment token, if the provider requires one. Empty when it
    /// does not.
    pub token: String,
}

#[cfg(feature = "ssr")]
pub use ssr::request;

#[cfg(feature = "ssr")]
mod ssr {
    use anyhow::Context;
    use anyhow::anyhow;
    use anyhow::bail;
    use wayfinder_auth::Keypair;
    use wayfinder_client::Client;
    use wayfinder_client::Identity;
    use wayfinder_client::NodeAddr;
    use wayfinder_protos::wayfinder::v1alpha::RenewalProvider;
    use wayfinder_protos::wayfinder::v1alpha::submit_csr_response::Outcome;

    use super::EnrollmentOutcome;
    use super::ProviderTarget;
    use crate::conn::NodeConnection;

    /// Ask `provider` to admit the node behind `conn`, installing the
    /// certificate if one is issued.
    ///
    /// The node is asked who it is on every call rather than the caller being
    /// trusted to say: the CSR must name the keys the node actually holds, and
    /// a browser is not a source of truth about that.
    ///
    /// Safe to call repeatedly with the same arguments — that is how a request
    /// held for approval is collected. The provider treats a re-submission of
    /// an identical request as the same request, so retrying neither queues a
    /// second one nor changes what is pending.
    pub async fn request(
        conn: &NodeConnection,
        provider: &ProviderTarget,
    ) -> anyhow::Result<EnrollmentOutcome> {
        let node_key = parse_node_key(&provider.node_key)?;
        let address: NodeAddr = provider
            .address
            .parse()
            .with_context(|| format!("\"{}\" is not a host:port address", provider.address))?;

        // Who this node is, from the node.
        let identity = conn
            .run(async |client| {
                let security = client.security_status().await?;
                let info = client.node_info().await?;
                Ok((security.own_ed_pubkey, security.own_x_pubkey, info.node_id))
            })
            .await
            .context("asking the node for its identity")?;
        let (ed_pubkey, x_pubkey, reported_mac) = identity;
        if ed_pubkey.is_empty() || x_pubkey.is_empty() {
            bail!(
                "this node reports no identity of its own, so there is nothing to \
                 certify; it needs a management-API identity seed configured"
            );
        }
        // The subject is *derived*, not the address the node currently reports.
        // A certificate's MAC is the address its identity key derives (design
        // 09 §5) — an authority will certify no other, and no node will verify
        // one that names another. The two agree for a node that already has an
        // identity; where they differ the node is on a provisional address it
        // held before it had one, and enrolling is what moves it.
        let ed: [u8; 32] = ed_pubkey
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("this node reported a malformed ed25519 identity key"))?;
        let node_mac = wayfinder_auth::derive_mac(&ed).0.to_vec();
        if node_mac != reported_mac {
            // Refused rather than noted, for the same reason `wayfinderctl csr
            // request` refuses it: a node running this build always answers to
            // the address its key derives, so a disagreement means an older
            // build — and that node's own `set_auth` will refuse the
            // certificate this would spend at the CA. A green "Enrolled"
            // confirmation for a certificate that cannot be installed is the
            // worst outcome available here, and this crate's audience is
            // explicitly the person least equipped to debug it.
            tracing::warn!(
                reported = ?reported_mac,
                derived = ?node_mac,
                "refusing to enrol a node that is not running under the address its \
                 identity key derives"
            );
            bail!(
                "this node answers to an address its own identity key does not \
                 derive, so it is running a build from before a node's address \
                 became a function of its key. A certificate can only name the \
                 derived address, and this node would refuse one — update and \
                 restart the node first, then try again."
            );
        }

        // An anonymous connection to the provider: a throwaway key, no cert.
        let ephemeral = Identity {
            seed: Keypair::generate_seed(),
            cert: Vec::new(),
        };
        let mut provider_client = Client::connect_tls(&address, &node_key, &ephemeral)
            .await
            .with_context(|| format!("connecting to the provider at {}", provider.address))?;

        let response = provider_client
            .submit_csr(&node_mac, &ed_pubkey, &x_pubkey, &provider.token)
            .await
            .context("submitting the certificate request")?;

        match response.outcome {
            Some(Outcome::Issued(issued)) => {
                let mesh_id = mesh_id_of(&issued.trust_anchor)?;
                // The certificate is installed together with where it came
                // from, so the node can renew it before it lapses without
                // anyone coming back to this page. This is the only moment the
                // address, the pinned key and the token are all in one place —
                // the node never learns them otherwise, and a certificate names
                // only the mesh root that signed it.
                let renewal = RenewalProvider {
                    address: provider.address.clone(),
                    node_key: node_key.to_vec(),
                    enrollment_token: provider.token.clone(),
                };
                // The wall clock this server can vouch for, carried to a node
                // that may have none of its own (design 20 §4.6). Unlike
                // `wayfinderctl`, this does not *refuse* on an undisciplined
                // clock: there is no flag to offer an operator mid-enrolment,
                // and the fail-closed zero is not the disaster it would be in
                // the out-of-band flow — the certificate was minted seconds
                // ago by the provider this page just spoke to, so its
                // CA-signed `not_before` carries the anchor on its own and the
                // node comes up dated anyway.
                let (installer_unix, verdict) =
                    wayfinder_client::stamp_unix(wayfinder_client::ClockTrust::default());
                if installer_unix == 0 {
                    // Two different causes, and an operator told the wrong one
                    // fixes the wrong thing — the same split `wayfinderctl`'s
                    // `refusal` makes. A trusted verdict with a zero stamp
                    // means the reading itself was before 2025 (`date -s`); an
                    // untrusted one means nothing is disciplining the clock
                    // (NTP, or chrony's `rtcsync`).
                    if verdict.is_trusted() {
                        tracing::warn!(
                            verdict = verdict.name(),
                            "enrolling without stamping a time: this host's clock reads before \
                             2025, so there is no time to send"
                        );
                    } else {
                        tracing::warn!(
                            verdict = verdict.name(),
                            "enrolling without stamping a time: nothing vouches for this host's \
                             clock"
                        );
                    }
                }
                conn.run(async |client| {
                    client
                        .install_cert(
                            &issued.cert,
                            &issued.trust_anchor,
                            Some(renewal.clone()),
                            installer_unix,
                        )
                        .await
                })
                .await
                .context("installing the issued certificate on the node")?;
                Ok(EnrollmentOutcome::Enrolled { mesh_id })
            }
            Some(Outcome::Rejected(rejected)) => Ok(EnrollmentOutcome::Rejected {
                reason: rejected.reason,
            }),
            // An empty outcome is read as pending for the same reason the CLI
            // does: the request was accepted and no certificate came back, so
            // the only useful thing to tell the operator is to wait.
            Some(Outcome::Pending(_)) | None => Ok(EnrollmentOutcome::AwaitingApproval),
        }
    }

    /// Parse the provider's pinned Ed25519 public key from 64 hex characters.
    ///
    /// Rejected here, before anything is opened, so a mistyped key reads as a
    /// mistyped key rather than as a handshake failure against a provider that
    /// is in fact fine.
    fn parse_node_key(hex: &str) -> anyhow::Result<[u8; 32]> {
        let hex = hex.trim();
        if hex.len() != 64 {
            bail!(
                "the provider's key must be 64 hex characters (got {})",
                hex.len()
            );
        }
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| anyhow!("the provider's key is not valid hex"))?;
        }
        Ok(key)
    }

    /// The mesh id carried in the first four bytes of a serialized trust
    /// anchor, so the confirmation can name the mesh the node just joined.
    fn mesh_id_of(anchor: &[u8]) -> anyhow::Result<u32> {
        let bytes: [u8; 4] = anchor
            .get(..4)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| anyhow!("the provider returned a malformed trust anchor"))?;
        Ok(u32::from_be_bytes(bytes))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A pinned key is 64 hex characters; anything else is the operator's
        /// typo and is named as one before a connection is attempted.
        #[test]
        fn a_pinned_key_is_thirty_two_bytes_of_hex() {
            let key = "aa".repeat(32);
            assert_eq!(parse_node_key(&key).unwrap(), [0xAA; 32]);
            // Surrounding whitespace survives a copy-paste and is not an error.
            assert_eq!(parse_node_key(&format!("  {key}\n")).unwrap(), [0xAA; 32]);

            assert!(parse_node_key("aa").is_err(), "too short");
            assert!(parse_node_key(&"zz".repeat(32)).is_err(), "not hex");
        }

        /// The mesh id is the anchor's first four bytes, big-endian — the same
        /// framing `TrustAnchor::to_bytes` writes.
        #[test]
        fn mesh_id_comes_from_the_anchors_first_four_bytes() {
            let anchor = wayfinder_auth::Authority::from_seed(&[1u8; 32], 0xABCD)
                .trust_anchor()
                .to_bytes();
            assert_eq!(mesh_id_of(&anchor).unwrap(), 0xABCD);
            assert!(mesh_id_of(&[0, 1]).is_err(), "truncated anchor");
        }
    }
}
