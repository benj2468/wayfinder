//! The invitation flow's view models: what an administrator sees of the
//! invitations they have minted, and what the person redeeming one sees.
//!
//! Their own module rather than fields on [`crate::snapshot::NodeSnapshot`],
//! because they are not polled. The snapshot is what the dashboard re-reads
//! every second; an invitation listing is read when an operator opens the panel
//! and after they act on it, and a minted token is read exactly once and never
//! again. Putting them on the poll would put a bearer token on a wire that runs
//! continuously.
//!
//! Nothing here carries a stored secret out of the authority — no token hash, no
//! TOTP secret — with one deliberate exception, [`RegistrationStart`], whose
//! whole purpose is to put an account's second factor in front of its owner.

use serde::Deserialize;
use serde::Serialize;

/// A freshly minted invitation, as the operator who minted it sees it.
///
/// [`token`](Self::token) is a bearer credential and is readable here and
/// nowhere else: the authority keeps only a domain-separated hash of it. A page
/// that loses this value cannot recover it — the remedy is to revoke the
/// invitation and mint another.
///
/// It belongs in the *fragment* of the registration URL
/// (`https://…/register#<token>`). A fragment is never sent to a server, which
/// buys three things for a bearer credential: it stays out of the dashboard's
/// access logs and any reverse proxy's, it is not sent in a `Referer` header,
/// and the link unfurlers that fetch any URL pasted into a chat app never see
/// it. What the fragment does *not* fix is the URL landing in browser history,
/// a clipboard, or the messaging app that carried it — the short expiry, the
/// single use, and the operator's own listing are what bound those.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteMinted {
    /// The account name the invitation will create.
    pub username: String,
    /// The token that redeems it. Shown once.
    pub token: String,
    /// Unix seconds after which the invitation is refused.
    pub expires_unix: u64,
}

/// One outstanding invitation, as an operator triaging them sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteRow {
    /// The account name the invitation will create.
    pub username: String,
    /// Whether the created account will hold the administrator capability.
    pub admin: bool,
    /// The validity window its session certificates will carry, in seconds.
    pub session_ttl_secs: u64,
    /// Unix seconds the invitation was minted at.
    pub created_unix: u64,
    /// Unix seconds after which it is refused.
    pub expires_unix: u64,
    /// When the account's second factor was revealed, or `None` if it has not
    /// been.
    ///
    /// **The security-relevant field.** `Some(_)` on an invitation that is still
    /// listed means somebody took the second factor and did not finish
    /// registering — the account does not exist, because completing one deletes
    /// its invitation. That is either an abandoned registration or a
    /// disclosure, and the operator's response is the same either way: revoke,
    /// and invite again.
    pub started_unix: Option<u64>,
}

/// The invitations on file, and how many the authority will hold.
///
/// The capacity travels with the listing rather than as a separate metric
/// because it is what makes the listing readable: without it, a full store
/// shows up as an unexplained failure at the next mint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InviteListing {
    /// The outstanding invitations. Redeemed ones are absent — completing an
    /// invitation deletes it.
    pub invites: Vec<InviteRow>,
    /// The largest number the authority will hold at once.
    pub capacity: u32,
}

/// What starting a registration reveals to the person redeeming an invitation.
///
/// The one value in this crate that deliberately carries a secret to a browser:
/// [`totp_enrolment_uri`](Self::totp_enrolment_uri) is the account's second
/// factor, and putting it in front of its owner — and nobody else — is the
/// entire point of registering by invitation rather than being handed an
/// account someone else already knows both secrets for.
///
/// Two things follow for anything rendering it. It is shown **once**: the call
/// that produced it spent the invitation, so a page that loses it cannot ask
/// again. And only the handle may be persisted — `sessionStorage`, so a refresh
/// survives — never the URI, which has no reason to outlive the moment it is
/// scanned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationStart {
    /// The account being registered. Chosen by the administrator who minted the
    /// invitation, never by whoever is redeeming it.
    pub username: String,
    /// The `otpauth://` enrolment URI, for an authenticator app.
    pub totp_enrolment_uri: String,
    /// The handle that alone can complete this registration. Single-use.
    pub handle: String,
    /// Unix seconds after which the handle is dead and the invitation spent.
    pub handle_expires_unix: u64,
}
