//! The renewal target an install records on the node it is installing to.
//!
//! A node holds no record of who certified it — a membership certificate names
//! the mesh root that signed it, never the address the provider answers on — so
//! unless an install says, the node cannot ask for a fresh certificate before
//! the one it holds lapses. These flags are how an operator says.
//!
//! Shared by the two commands that hand a node a credential (`auth set` and
//! `csr install`) so the spelling, the parsing and the pinning rule are the same
//! in both. Naming none of them is a supported answer, and it clears whatever
//! the node had recorded: a node handed a credential by an operator who did not
//! name an authority renews nowhere, rather than reaching back to the provider
//! behind a certificate it no longer holds.

use anyhow::Context;
use wayfinder_client::parse_key32;
use wayfinder_protos::wayfinder::v1alpha::RenewalProvider;

/// Where the node should renew the certificate being installed.
///
/// Flattened into a command's own `Args` rather than repeated, for the same
/// reason `EnrollArgs` is: three flags whose relationship (all-or-nothing, and
/// the key is not optional) has to be enforced identically wherever they appear.
#[derive(clap::Args, Debug, Default)]
pub struct RenewalArgs {
    /// The provider's management-API address (`host:port`) this node should
    /// renew its certificate against before it expires.
    ///
    /// Recorded on the node, replacing any provider a previous install left
    /// there. Leave it out and the node renews nowhere: it will still report the
    /// certificate as due and raise the `cert_expiring` alarm, but an operator
    /// has to act on it.
    #[arg(long, value_name = "HOST:PORT")]
    pub renew_from: Option<String>,

    /// The renewal provider's Ed25519 public key, hex (colon-separated or not).
    ///
    /// Required with `--renew-from`, with no trust-on-first-use fallback:
    /// nobody watches a renewal happen, so there is nobody to notice that the
    /// far end changed. It is the same key `--node-key` pins when connecting to
    /// that provider.
    #[arg(long, value_name = "HEX", requires = "renew_from")]
    pub renew_provider_key: Option<String>,

    /// The shared enrollment token the renewal provider requires, if any.
    ///
    /// Stored on the node, beside its identity seed, because a provider checks
    /// the token before it looks up the holder — an unattended renewal is gated
    /// on it exactly as a first enrollment is.
    #[arg(long, value_name = "TOKEN", requires = "renew_from")]
    pub renew_token: Option<String>,
}

impl RenewalArgs {
    /// The provider record to install, or `None` when the operator named none.
    ///
    /// The missing-key case is an error rather than an unpinned record: an
    /// address alone is not a renewal target, and accepting one would mean a
    /// node handing its keys to whatever answers.
    pub fn provider(&self) -> anyhow::Result<Option<RenewalProvider>> {
        let Some(address) = &self.renew_from else {
            return Ok(None);
        };
        let key = self.renew_provider_key.as_deref().context(
            "--renew-from needs --renew-provider-key: a renewal is unattended, so the \
             provider is pinned by key or not trusted at all",
        )?;
        Ok(Some(RenewalProvider {
            address: address.clone(),
            node_key: parse_key32(key)
                .context("parsing --renew-provider-key")?
                .to_vec(),
            enrollment_token: self.renew_token.clone().unwrap_or_default(),
        }))
    }
}

/// One sentence for the command's summary line saying what the node will now do
/// when this certificate nears expiry.
///
/// Said out loud in both directions, because both are consequences an operator
/// should not have to infer: naming a provider makes the node reach out to it
/// unattended, and naming none *turns renewal off*, silently, on a node that may
/// have been renewing itself until this command ran.
pub fn renewal_note(provider: Option<&RenewalProvider>) -> String {
    match provider {
        Some(p) => format!("; it will renew against {} before this expires", p.address),
        // Phrased as the *act*, not as a description of the resulting state.
        // This command cannot see what the node had — the install replaces the
        // record either way — so a node that was renewing itself until a moment
        // ago has just stopped, and saying only "no provider recorded" would
        // read as a remark about a fresh node rather than as what changed.
        None => "; no renewal provider was given, so any target this node had recorded is \
                 now cleared and this certificate must be renewed by hand (pass \
                 --renew-from to record one)"
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three flags become one record, with the key parsed from either
    /// spelling an operator might paste.
    #[test]
    fn the_flags_become_a_pinned_provider_record() {
        let args = RenewalArgs {
            renew_from: Some("ca.example:7700".into()),
            renew_provider_key: Some(vec!["01"; 32].join(":")),
            renew_token: Some("s3cret".into()),
        };

        let provider = args.provider().unwrap().expect("a provider was named");
        assert_eq!(provider.address, "ca.example:7700");
        assert_eq!(provider.node_key, vec![1u8; 32]);
        assert_eq!(provider.enrollment_token, "s3cret");
    }

    /// Naming nothing is the supported answer for an install that does not know
    /// the authority behind the bytes — and it is what clears a record left by
    /// an earlier enrollment, so it must not be confused with an error.
    #[test]
    fn naming_no_provider_records_none() {
        assert!(RenewalArgs::default().provider().unwrap().is_none());
    }

    /// An address with no key is refused rather than recorded unpinned. Clap
    /// enforces the same pairing at the command line; this is the guarantee for
    /// every other way the struct is built.
    #[test]
    fn an_address_without_a_key_is_refused() {
        let args = RenewalArgs {
            renew_from: Some("ca.example:7700".into()),
            ..Default::default()
        };
        assert!(args.provider().is_err());
    }

    /// The summary says what the node will do in *both* cases. An install that
    /// silently switched renewal off would leave an operator believing a node
    /// still renews itself — which they would discover when it stopped routing.
    #[test]
    fn the_summary_names_the_target_or_says_there_is_none() {
        let named = RenewalProvider {
            address: "ca.example:7700".into(),
            node_key: vec![1u8; 32],
            enrollment_token: String::new(),
        };
        assert!(renewal_note(Some(&named)).contains("ca.example:7700"));
        let cleared = renewal_note(None);
        assert!(
            cleared.contains("cleared"),
            "the note names the act: {cleared}"
        );
        assert!(cleared.contains("by hand"));
    }
}
