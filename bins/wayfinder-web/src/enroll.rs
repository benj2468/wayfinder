//! Asking a provider to admit this node to its mesh.
//!
//! The dashboard's one operation that talks to a node *other* than its own: it
//! opens a second, short-lived connection to the provider, submits a
//! certificate-signing request on this node's behalf, and — if a certificate
//! comes back — installs it.
//!
//! # Whose keys are being certified
//!
//! The node's own. The request names the identity and MAC the node is already
//! running under, read from the node itself rather than taken from the browser,
//! and the certificate that comes back is installed against the seed the node
//! keeps ([`Client::install_cert`]). Nothing about the node's identity changes;
//! it simply acquires a certificate for the one it had. The alternative — mint a
//! fresh keypair here, as the offline `wayfinderctl enroll` does — would change
//! the node's MAC, which is read once at startup, leaving it signing frames
//! under a certificate its peers cannot attribute to it until someone restarts
//! it. It would also mean this process handling a private key, which it
//! otherwise never does.
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
        let address = provider
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
        let (ed_pubkey, x_pubkey, node_mac) = identity;
        if ed_pubkey.is_empty() || x_pubkey.is_empty() {
            bail!(
                "this node reports no identity of its own, so there is nothing to \
                 certify; it needs a management-API identity seed configured"
            );
        }

        // An anonymous connection to the provider: a throwaway key, no cert.
        let ephemeral = Identity {
            seed: Keypair::generate_seed(),
            cert: Vec::new(),
        };
        let mut provider_client = Client::connect_tls(address, &node_key, &ephemeral)
            .await
            .with_context(|| format!("connecting to the provider at {}", provider.address))?;

        let response = provider_client
            .submit_csr(&node_mac, &ed_pubkey, &x_pubkey, &provider.token)
            .await
            .context("submitting the certificate request")?;

        match response.outcome {
            Some(Outcome::Issued(issued)) => {
                let mesh_id = mesh_id_of(&issued.trust_anchor)?;
                conn.run(async |client| {
                    client
                        .install_cert(&issued.cert, &issued.trust_anchor)
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
