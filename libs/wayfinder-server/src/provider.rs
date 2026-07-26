//! The provider (certificate-authority) seam for the management API.
//!
//! A node running in *provider mode* answers enrollment requests
//! ([`GetTrustAnchorRequest`], [`SubmitCsrRequest`], [`RevokeNodeRequest`]) by
//! delegating to a [`MeshAuthority`].  The trait is deliberately byte-oriented
//! so it stays `no_std + alloc`: the concrete implementation that holds the mesh
//! root key ([`CertAuthority`](crate::CertAuthority)) lives behind the `std`
//! feature, and is injected into the [`RouterAdapter`](crate::RouterAdapter) by
//! the host driver.
//!
//! [`GetTrustAnchorRequest`]: wayfinder_protos::wayfinder_v1alpha::GetTrustAnchorRequest
//! [`SubmitCsrRequest`]: wayfinder_protos::wayfinder_v1alpha::SubmitCsrRequest
//! [`RevokeNodeRequest`]: wayfinder_protos::wayfinder_v1alpha::RevokeNodeRequest

use alloc::string::String;
use alloc::vec::Vec;

use wayfinder_protos::service::CsrOutcome;
use wayfinder_protos::service::IssuedCertData;
use wayfinder_protos::service::PendingCsrData;

/// A mesh certificate authority, as seen by the management-API layer.
///
/// All inputs and outputs are raw bytes (the same `wayfinder-auth` wire forms a
/// node loads from disk), so this trait carries no crypto types and compiles on
/// `no_std`.  Errors are human-readable strings surfaced to the client as an
/// `ErrorResponse`.
pub trait MeshAuthority {
    /// The mesh trust anchor as raw `TrustAnchor` bytes (mesh id + root public
    /// key), for an enrolling node to verify certificates against.
    fn trust_anchor_bytes(&self) -> Vec<u8>;

    /// Submit a certificate-signing request binding `node_mac` to the given
    /// Ed25519 and X25519 public keys, returning its [`CsrOutcome`].  `token` is
    /// the caller-supplied enrollment token (an empty string when none was
    /// sent).
    ///
    /// An authority that does not require operator approval issues the
    /// certificate immediately ([`CsrOutcome::Issued`]).  One that does parks the
    /// request until an operator approves it, returning [`CsrOutcome::Pending`]
    /// to a polling client until then, and [`CsrOutcome::Issued`] once approved.
    /// A bad token, or an operator denial, resolves to [`CsrOutcome::Rejected`].
    /// The `Err` variant is reserved for the request being unserviceable (clock
    /// unset, malformed input) rather than a policy rejection.
    fn submit_csr(
        &mut self,
        node_mac: &[u8],
        ed_pubkey: &[u8],
        x_pubkey: &[u8],
        token: &str,
    ) -> Result<CsrOutcome, String>;

    /// Sign a revocation for `node_mac`, returning raw `RevocationRecord` bytes
    /// for the caller to record and flood.  Returns an error string on malformed
    /// input.
    fn revoke(&mut self, node_mac: &[u8]) -> Result<Vec<u8>, String>;

    /// The certificates this authority has issued (for operator observability),
    /// in issuance order.
    fn list_certs(&self) -> Vec<IssuedCertData>;

    /// The CSRs currently awaiting operator approval, in first-seen order.
    /// Empty when the authority does not require approval or none are waiting.
    fn list_pending(&self) -> Vec<PendingCsrData>;

    /// Approve the pending CSR bound to `node_mac`: sign its certificate now so a
    /// polling client collects it on its next `submit_csr`.  Returns an error if
    /// no CSR for that MAC is pending.
    fn approve_csr(&mut self, node_mac: &[u8]) -> Result<(), String>;

    /// Deny the pending CSR bound to `node_mac`: it will not be issued and a
    /// polling client observes a [`CsrOutcome::Rejected`].  Returns an error if
    /// no CSR for that MAC is pending.
    fn deny_csr(&mut self, node_mac: &[u8]) -> Result<(), String>;
}
