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
//! [`GetTrustAnchorRequest`]: wayfinder_protos::wayfinder::v1alpha::GetTrustAnchorRequest
//! [`SubmitCsrRequest`]: wayfinder_protos::wayfinder::v1alpha::SubmitCsrRequest
//! [`RevokeNodeRequest`]: wayfinder_protos::wayfinder::v1alpha::RevokeNodeRequest

use alloc::string::String;
use alloc::vec::Vec;

use wayfinder_protos::service::CsrOutcome;
use wayfinder_protos::service::EnrollmentAdmission;
use wayfinder_protos::service::EnrollmentPolicyData;
use wayfinder_protos::service::EnrollmentPolicyStatusData;
use wayfinder_protos::service::IssuedCertData;
use wayfinder_protos::service::PendingCsrData;
use wayfinder_protos::service::UserAccountData;
use wayfinder_protos::service::UserAuthOutcome;

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

    /// Exchange a user's credentials for a short-lived management certificate
    /// bound to the session keys they name, returning its
    /// [`UserAuthOutcome`].
    ///
    /// The `Err` variant is reserved for the request being *unserviceable* —
    /// clock unset, malformed keys — and never for the credentials being
    /// wrong, which is [`UserAuthOutcome::Rejected`]. That split is the same
    /// one [`submit_csr`](Self::submit_csr) draws, and for a sharper reason
    /// here: an implementation must never let the rejection carry, or its
    /// timing imply, which of unknown-account / wrong-password / wrong-code /
    /// locked / disabled occurred.
    fn authenticate_user(
        &mut self,
        username: &str,
        password: &str,
        totp_code: &str,
        ed_pubkey: &[u8],
        x_pubkey: &[u8],
    ) -> Result<UserAuthOutcome, String>;

    /// The user accounts on file, for an operator listing them.
    ///
    /// Carries no password hash and no TOTP secret; see [`UserAccountData`].
    fn list_users(&self) -> Vec<UserAccountData>;

    /// Create a user account, returning the `otpauth://` enrolment URI for its
    /// new second factor — or an empty string when `no_totp` was asked for.
    ///
    /// The URI is returned rather than stored because it is shown *once*: the
    /// secret inside it is not recoverable from the authority afterwards, so an
    /// implementation must hand it back here or not at all.
    ///
    /// `session_ttl_secs` of zero means "the default", so a caller with no
    /// opinion does not have to know what the default is.
    ///
    /// `Err` covers a name already taken as well as a store that cannot be made
    /// durable. Unlike [`authenticate_user`](Self::authenticate_user) there is
    /// no oracle to protect: this call needs a full management grant, and a
    /// client holding one can list the accounts outright.
    fn create_user(
        &mut self,
        username: &str,
        password: &str,
        admin: bool,
        session_ttl_secs: u64,
        no_totp: bool,
    ) -> Result<String, String>;

    /// Remove the named user account.
    ///
    /// Ends the account's ability to obtain *new* sessions. A certificate
    /// already issued to it is unaffected — that is what `revoke` and expiry
    /// are for — so cutting off a compromised account is two acts, not one.
    ///
    /// An implementation must refuse to remove the last account that can still
    /// administer the mesh. Both this and [`create_user`](Self::create_user)
    /// need a full management grant, so an authority left with no enabled
    /// administrator has a user store that can no longer be changed over the
    /// management API at all — a state reachable in one click and escapable
    /// only with a shell on the provider host.
    ///
    /// `Err` covers that refusal, a name that is not on file, and a store that
    /// cannot be made durable.
    fn remove_user(&mut self, username: &str) -> Result<(), String>;

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

    /// The enrollment policy this authority is currently applying, for the
    /// management API to report.  Says whether a token is required and never
    /// what it is: this answer rides a polled request, and a secret on it is
    /// disclosed continuously rather than when someone asks.
    fn enrollment_policy(&self) -> EnrollmentPolicyStatusData;

    /// The admission rule in force, token value included — the answer to an
    /// explicit `RevealEnrollmentToken`.
    ///
    /// The reader is already an admin or the node itself, and so is already
    /// able to replace the token outright, which is why handing it over confers
    /// nothing new.  What the separate request buys is that each disclosure is
    /// one discrete, logged event.
    fn admission(&self) -> EnrollmentAdmission;

    /// Apply a partial enrollment-policy update; fields the update does not
    /// name are left as they are.  `Err` when the change could not be made
    /// durable, which the caller must surface rather than reporting success:
    /// an operator told a security setting is in force has a right to expect
    /// it to still be in force after a restart.
    fn set_enrollment_policy(&mut self, update: &EnrollmentPolicyData) -> Result<(), String>;
}
