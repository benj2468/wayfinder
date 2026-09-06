//! The provider (certificate-authority) seam for the management API.
//!
//! A node running in *provider mode* answers enrollment requests
//! ([`GetTrustAnchorRequest`], [`SubmitCsrRequest`], [`RevokeNodeRequest`]) by
//! delegating to a [`MeshAuthority`].  The trait keeps every `wayfinder-auth`
//! value in its raw byte form (bar one — see the trait) so it carries no key
//! types and stays `no_std + alloc`: the concrete implementation that holds the
//! mesh root key ([`CertAuthority`](crate::CertAuthority)) lives behind the
//! `std` feature, and is owned outright by the certificate
//! authority's own task (`authority_task.rs`), which projects it through
//! `AuthorityAdapter`.
//!
//! [`GetTrustAnchorRequest`]: wayfinder_protos::wayfinder::v1alpha::GetTrustAnchorRequest
//! [`SubmitCsrRequest`]: wayfinder_protos::wayfinder::v1alpha::SubmitCsrRequest
//! [`RevokeNodeRequest`]: wayfinder_protos::wayfinder::v1alpha::RevokeNodeRequest

use alloc::string::String;
use alloc::vec::Vec;

use wayfinder_auth::RevocationRecord;

use crate::users::UserRole;

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
/// Every `wayfinder-auth` value crossing this trait does so as raw bytes (the
/// same wire forms a node loads from disk) — with one exception,
/// [`revoke`](MeshAuthority::revoke), whose [`RevocationRecord`] is a plain
/// `no_std` wire struct rather than a key; see that method for why it is typed.
/// Everything else returned here is a `wayfinder-protos` projection type, never
/// a `wayfinder-auth` one.  Neither pulls in a key type, so the trait compiles
/// on `no_std`.  Errors are human-readable strings surfaced to the client as an
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

    /// Remove the named user account **and** revoke every session certificate
    /// it holds, returning one [`RevocationRecord`] per revoked session for the
    /// caller to flood.
    ///
    /// Cutting off an account is one act, not two. It used to be two — this
    /// ended the ability to obtain *new* sessions and left every certificate
    /// already issued working until it expired, so deleting a compromised
    /// account left the compromise running for up to the account's session
    /// lifetime. See design 14.
    ///
    /// An implementation must delete the account and revoke its sessions as one
    /// durable unit. Splitting them leaves, in the direction that matters, an
    /// account reported gone whose sessions came back alive.
    ///
    /// It must also refuse to remove the last account that can still administer
    /// the mesh, and must evaluate that refusal *before* signing anything — a
    /// refused removal revokes nothing. Both this and
    /// [`create_user`](Self::create_user) need a full management grant, so an
    /// authority left with no enabled administrator has a user store that can no
    /// longer be changed over the management API at all — a state reachable in
    /// one click and escapable only with a shell on the provider host.
    ///
    /// `Err` covers that refusal, a name that is not on file, and a store that
    /// cannot be made durable.
    fn remove_user(&mut self, username: &str) -> Result<Vec<RevocationRecord>, String>;

    /// Revoke every session certificate the named account holds, leaving the
    /// account itself in place, and return one [`RevocationRecord`] per revoked
    /// session for the caller to flood.
    ///
    /// The difference from [`remove_user`](Self::remove_user) is the account:
    /// this ends what the account is currently holding and leaves it able to
    /// sign in again. It is the control for a lost laptop, where the person
    /// still works here.
    ///
    /// An implementation must skip sessions it has already revoked — re-sending
    /// spends mesh airtime to say what the mesh already believes — and sessions
    /// that have expired, which passive expiry already ended. So an empty vector
    /// is an ordinary success, not a failure to find the account.
    ///
    /// `Err` covers a name that is not on file and a store that cannot be made
    /// durable.
    fn revoke_user_sessions(&mut self, username: &str) -> Result<Vec<RevocationRecord>, String>;

    /// Set `username`'s role, revoking every session certificate the change
    /// invalidates, and returning one [`RevocationRecord`] per revoked session
    /// for the caller to flood.
    ///
    /// **A demotion must revoke.** The capability is stamped on the
    /// certificate, so a session minted while the account was an administrator
    /// keeps administering until it is revoked or expires; an implementation
    /// that changed only what is issued *next* would report an access as
    /// removed while its holder still had it. A promotion revokes nothing — the
    /// certificates the account holds grant less than the account now does.
    ///
    /// Restating the role an account already holds must succeed and revoke
    /// nothing: the second call is what an operator makes when unsure the first
    /// landed. The returned `bool` is whether anything actually changed —
    /// necessary because an unchanged account and a promotion both revoke
    /// nothing, so the record count alone cannot answer it, and a caller that
    /// re-derived the answer from its own roster read would be a second author
    /// of the same predicate.
    ///
    /// Like [`remove_user`](Self::remove_user), an implementation must refuse to
    /// demote the last account that can still administer the mesh, and must
    /// evaluate that refusal *before* signing anything.
    ///
    /// `Err` covers that refusal, a name that is not on file, and a store that
    /// cannot be made durable.
    fn set_user_role(
        &mut self,
        username: &str,
        role: UserRole,
    ) -> Result<(Vec<RevocationRecord>, bool), String>;

    /// Enable or disable `username`, revoking every session certificate the
    /// change invalidates, and returning one [`RevocationRecord`] per revoked
    /// session for the caller to flood.
    ///
    /// **Disabling must revoke**, for the reason a demotion must: an account
    /// that obtains no new session while every certificate it already holds
    /// keeps working is disabled only in the future tense. Enabling revokes
    /// nothing and must clear any lockout.
    ///
    /// An implementation must refuse to disable the last account that can still
    /// administer the mesh — a disabled administrator administers nothing, so
    /// this strands the mesh exactly as removing it would.
    fn set_user_enabled(
        &mut self,
        username: &str,
        enabled: bool,
    ) -> Result<(Vec<RevocationRecord>, bool), String>;

    /// Replace `username`'s password, clearing any lockout with it.
    ///
    /// The administrative reset. An implementation must leave the second factor
    /// alone: an operator able to replace both could take an account over in one
    /// act, leaving its owner no signal.
    ///
    /// Revokes nothing, deliberately — see
    /// [`revoke_user_sessions`](Self::revoke_user_sessions), which is the act
    /// for a reset that answers a compromise.
    ///
    /// `Err` covers a name that is not on file, an empty password, and a store
    /// that cannot be made durable.
    fn set_user_password(&mut self, username: &str, password: &str) -> Result<(), String>;

    /// Sign a revocation for `node_mac`, returning the [`RevocationRecord`] for
    /// the caller to record and flood.  Returns an error string on malformed
    /// input.
    ///
    /// The one output of this trait that is not raw bytes.  A revocation leaves
    /// here and travels to the router loop to be flooded, and a byte vector on
    /// that hop would make "the authority signed something the router cannot
    /// parse" a state the receiver has to handle — for a record this very
    /// process just constructed.  The typed record makes it unrepresentable.
    fn revoke(&mut self, node_mac: &[u8]) -> Result<RevocationRecord, String>;

    /// The certificates this authority has issued (for operator observability),
    /// in issuance order.
    fn list_certs(&self) -> Vec<IssuedCertData>;

    /// The CSRs currently awaiting operator approval, in first-seen order.
    /// Empty when the authority does not require approval or none are waiting.
    fn list_pending(&self) -> Vec<PendingCsrData>;

    /// Approve the pending CSR bound to `node_mac`: sign its certificate now so a
    /// polling client collects it on its next `submit_csr`.  Returns an error if
    /// no CSR for that MAC is pending.
    ///
    /// `cert_ttl_secs` is the validity window to give *this* certificate, in
    /// seconds, and `None` takes the authority's policy default — the operator
    /// admitting a device is the one who knows how long it should stay a
    /// member. A lifetime outside what the authority will issue for is refused
    /// and the request stays pending.
    fn approve_csr(&mut self, node_mac: &[u8], cert_ttl_secs: Option<u64>) -> Result<(), String>;

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
