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

    /// Issue a membership certificate binding `node_mac` to the given Ed25519
    /// and X25519 public keys, returning raw `MembershipCert` bytes signed by
    /// the mesh root.  `token` is the caller-supplied enrollment token (an empty
    /// string when none was sent); an implementation configured with a token
    /// must reject a request whose token does not match.  Returns an error
    /// string on a bad token or malformed input.
    fn issue_cert(
        &mut self,
        node_mac: &[u8],
        ed_pubkey: &[u8],
        x_pubkey: &[u8],
        token: &str,
    ) -> Result<Vec<u8>, String>;

    /// Sign a revocation for `node_mac`, returning raw `RevocationRecord` bytes
    /// for the caller to record and flood.  Returns an error string on malformed
    /// input.
    fn revoke(&mut self, node_mac: &[u8]) -> Result<Vec<u8>, String>;
}
