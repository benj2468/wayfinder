//! The certificate authority's user store: named accounts that can be
//! exchanged for a short-lived management certificate.
//!
//! # Why this lives here and not on a node
//!
//! A node's management authorization is "a verified, non-revoked certificate
//! carrying a capability, bound to this TLS session". That model is sound,
//! tested, and identical on a Linux gateway and an nRF52840. What it lacks is
//! not a check — it is a way for a *person* to obtain something to check
//! without an operator hand-copying files.
//!
//! Passwords cannot fill that gap at the node, for four reasons that are all
//! structural rather than incidental (§4 of
//! `docs/design/06-management-api-authentication.md`): a password verifier
//! worth having is memory-hard by construction, and this crate's `embedded`
//! build targets a board whose whole heap is 32 KiB against the 64 MiB
//! [`ARGON2_MEMORY_KIB`] asks for; a password would be the only *fleet-wide*
//! bearer secret in a system where everything else is scoped, expiring and
//! revocable; it would have to be replicated to every node and kept
//! consistent; and the node's check is not the part that is wrong.
//!
//! So the credential store sits one layer up, at the certificate authority —
//! which is already the single place that decides who belongs to a mesh,
//! already persists durable state, and already has an expiry and revocation
//! story. A user proves a username, password and TOTP code here and receives a
//! certificate bound to a keypair the *client* generated; from that point it is
//! an ordinary certificate holder and every node authorizes it through the
//! unchanged `decide_access`. This module is `std`-gated and an embedded node
//! never links it — only [`UserRole`](super::types::UserRole), which the
//! management-API seam names on every target, sits outside the gate.
//!
//! # What a failed login tells the caller
//!
//! Nothing. [`AuthOutcome::Rejected`] is one variant covering unknown user,
//! wrong password, wrong code, locked account and disabled account, for the
//! same reason `MgmtDenied` never reaches the wire: an endpoint that
//! distinguishes "no such user" from "wrong password" is a user-enumeration
//! oracle reachable by anyone who can route to the provider.

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use crate::users::types::UserRole;
use argon2::Algorithm;
use argon2::Argon2;
use argon2::Params;
use argon2::PasswordHasher;
use argon2::PasswordVerifier;
use argon2::Version;
use argon2::password_hash::PasswordHash;
use argon2::password_hash::SaltString;

use hmac::Hmac;
use hmac::Mac as _;
use serde::Deserialize;
use serde::Serialize;
use sha1::Sha1;
use subtle::ConstantTimeEq;

/// Argon2id memory cost, in KiB (64 MiB).
///
/// The parameter that makes the verifier memory-*hard*, and so the one that
/// decides an offline attacker's cost per guess. It is also, directly, why
/// this module cannot exist on a node: the figure is three orders of magnitude
/// past an nRF52840 dongle's entire heap.
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;

/// Argon2id time cost (iterations).
const ARGON2_ITERATIONS: u32 = 3;

/// Argon2id parallelism (lanes). One, deliberately: a CA answers logins at
/// human rates, so there is nothing to gain from spreading a single
/// verification across cores, and a lane count is a parameter that has to match
/// between hashing and verification for a stored hash to stay usable.
const ARGON2_LANES: u32 = 1;

/// RFC 6238 time step, in seconds: the window one TOTP code is valid for.
pub(crate) const TOTP_STEP_SECS: u64 = 30;

/// How many steps either side of the current one a code is accepted from,
/// absorbing clock skew between the client's authenticator and the CA.
///
/// A window is a *replay* window unless the last accepted step is remembered,
/// which is what [`UserRecord::totp_last_step`] is for: without it, a code
/// observed in transit stays usable for up to three steps.
const TOTP_SKEW_STEPS: u64 = 1;

/// Digits in a TOTP code.
const TOTP_DIGITS: u32 = 6;

/// Bytes of TOTP shared secret. 20 is the RFC 4226 recommendation and what
/// every authenticator app expects.
const TOTP_SECRET_LEN: usize = 20;

/// Bytes of entropy in an invite token or a registration handle.
///
/// 256 bits from the OS CSPRNG, which is what lets [`UserInvite`] be looked up
/// by an unauthenticated caller's token without any of the defences a
/// low-entropy identifier needs: it is not enumerable on any timescale, so
/// there is no oracle for a timing difference to leak and no reason to spend
/// memory-hard work refusing a bad one.
const INVITE_SECRET_LEN: usize = 32;

/// Domain-separation label for an invite token's hash.
///
/// The convention is `wayfinder-auth`'s `CERT_FINGERPRINT_LABEL`. Owned here
/// rather than borrowed from that crate because the bytes being hashed are this
/// module's, and a label shared across modules is a collision waiting for the
/// day two of them hash the same string.
const INVITE_TOKEN_LABEL: &[u8] = b"wayfinder-invite-v1";

/// Domain-separation label for a registration handle's hash.
///
/// Separate from [`INVITE_TOKEN_LABEL`] so the two credentials cannot be
/// substituted for one another: both are 256-bit base32 strings in the same
/// record, and without distinct labels a handle presented as a token (or the
/// reverse) would hash to a value the other lookup recognises.
const REGISTRATION_HANDLE_LABEL: &[u8] = b"wayfinder-registration-handle-v1";

/// Consecutive failed logins before an account is locked.
///
/// The per-account half of the rate limit, and the dominant half: it is
/// recorded against the *user*, so an attacker cannot reset it by changing
/// source address the way a per-IP bucket alone would allow.
pub(crate) const LOCKOUT_THRESHOLD: u32 = 5;

/// How long an account stays locked after [`LOCKOUT_THRESHOLD`] failures.
pub(crate) const LOCKOUT_SECS: u64 = 900;

/// Default validity window for a session certificate when an admin does not
/// name one: eight hours, which matches a shift and bounds a stolen session
/// key.
///
/// Only a default. §7 decision 3 of the design is that the lifetime belongs to
/// the admin who grants the account, so it is stored per account
/// ([`UserRecord::session_ttl_secs`]) rather than being a constant the code
/// applies to everyone: an automation account may be granted minutes and a
/// field operator a shift, without either being a code change.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 8 * 3600;

/// The longest username this authority will accept, in bytes.
///
/// A username is not just a lookup key: it is persisted in the provider's state
/// snapshot, repeated in every audit line about the account, and interpolated
/// into the `otpauth://` enrolment URI an authenticator app parses. Nothing
/// bounded it, while `bins/wayfinder-web/src/bundle.rs` already bounded an
/// *uploaded* name at 128 and observed in its own doc comment that the
/// authority put no limit on one. This is the missing half of that pair. The
/// two stay separate constants — that crate does not depend on this one outside
/// its test feature — so what has to be kept in step is the *unit*: both count
/// bytes, and it is the counting rather than the number that made the older
/// pairing meaningless.
///
/// Bytes rather than characters because bytes are what the snapshot and the
/// wire actually pay for; a name of 128 multi-byte characters is not the case
/// this bound exists for.
///
/// **A bound on creation, not an invariant of stored state.** It is enforced by
/// `check_name_available`, which every path that claims a name goes through, and
/// again where an invitation is redeemed — but a `ca-state.json` written by a
/// build older than this rule is loaded as it stands. Refusing to load it would
/// turn a long username into a provider that will not start while holding the
/// mesh root of trust, which is a far worse failure than the one this prevents.
/// So `UserRecord::username` may still be longer than this; nothing downstream
/// depends on it not being.
///
/// Deliberately *only* a length bound. The charset is left open — an operator
/// may reasonably want an email address, a display name, or a non-Latin script
/// as a username, and the injection this pairs with is closed at the point of
/// use by [`percent_encode`], which is where an encoding problem belongs. A
/// charset allowlist here would be a second, weaker answer to a question already
/// answered correctly downstream.
pub const MAX_USERNAME_LEN: usize = 128;

/// How many bytes an [`AccountId`] carries.
///
/// 128 bits from the OS CSPRNG. The value is never presented to a person and
/// never travels the wire, so nothing pulls it shorter for readability; what it
/// has to be is unguessable-adjacent and, above all, non-colliding across every
/// account a mesh ever holds, including the recycled names §3.1 of design 14 is
/// about.
const ACCOUNT_ID_LEN: usize = 16;

/// The stable identity of one user account, minted once and never reused.
///
/// What links a session certificate back to the account whose sign-in produced
/// it ([`crate::authority::CertAuthority::revoke_user_sessions`] follows it).
/// Deliberately **not** the username: a name can be recycled, and a name-keyed
/// link silently hands a new account the certificates of the deleted one that
/// shared its name. An id cannot be recycled, so a session belongs to the
/// account that actually minted it or to nothing at all.
///
/// The reference points from the certificate *to* the account and never the
/// reverse — see design 14 §3.1. A list of certificates hanging off the account
/// would be destroyed by the deletion that makes revoking them urgent.
///
/// Serialized into the CA state snapshot as part of [`UserRecord`], so its shape
/// is part of the on-disk schema (see `persistence.rs`).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountId([u8; ACCOUNT_ID_LEN]);

impl AccountId {
    /// Mint a fresh id from the OS CSPRNG.
    ///
    /// Also the `serde` default, which is what gives every account in a
    /// pre-version-7 snapshot its *own* id on load rather than one shared
    /// constant — two accounts sharing an id would make each one's revocation
    /// cut the other.
    pub fn generate() -> Self {
        let mut bytes = [0u8; ACCOUNT_ID_LEN];
        argon2::password_hash::rand_core::RngCore::fill_bytes(
            &mut argon2::password_hash::rand_core::OsRng,
            &mut bytes,
        );
        Self(bytes)
    }

    /// Rebuild an id from its stored bytes.
    pub fn from_bytes(bytes: [u8; ACCOUNT_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, for stamping onto an issued-certificate record and for
    /// comparing one against an account.
    pub fn as_bytes(&self) -> &[u8; ACCOUNT_ID_LEN] {
        &self.0
    }

    /// Whether `bytes` is this id, for matching a certificate record's
    /// `account_id` (which is a `Vec<u8>`, empty for a device's certificate).
    ///
    /// A length mismatch is simply "not this account" rather than an error: the
    /// empty id every pre-version-7 record carries is a legitimate value meaning
    /// "attributed to nobody", and it reaches this comparison on every scan.
    pub fn matches(&self, bytes: &[u8]) -> bool {
        bytes == self.0
    }
}

/// One user account in the certificate authority's store.
///
/// Serialized directly into the CA state snapshot, so its shape is part of the
/// on-disk schema (see `persistence.rs`). The password is never stored, only
/// its Argon2id PHC string, which carries its own parameters and salt — so a
/// later change to [`ARGON2_MEMORY_KIB`] leaves existing hashes verifiable and
/// re-hashes only on the next password change.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserRecord {
    /// This account's stable identity, minted at creation and never reused.
    ///
    /// What a session certificate is stamped with, so that revoking "this
    /// person's access" is answerable — and stays answerable across a rename or
    /// a recycled name, neither of which [`Self::username`] survives. Defaulted
    /// by minting a fresh one, which is what gives each account in a
    /// pre-version-7 snapshot its own.
    #[serde(default = "AccountId::generate")]
    pub id: AccountId,
    /// The account name, as presented at login. Compared verbatim.
    pub username: String,
    /// Argon2id PHC string (`$argon2id$v=19$m=...`), carrying its own
    /// parameters and per-user random salt.
    pub password_hash: String,
    /// The TOTP shared secret, or `None` for an account with no second factor
    /// — an explicit per-account opt-out, not a default (see
    /// [`AuthOutcome`]'s docs and §5.3 of the design).
    pub totp_secret: Option<Vec<u8>>,
    /// The most recent TOTP step this account successfully authenticated with,
    /// so a code cannot be replayed inside the [`TOTP_SKEW_STEPS`] window.
    #[serde(default)]
    pub totp_last_step: u64,
    /// Consecutive failed logins since the last success.
    #[serde(default)]
    pub failed_attempts: u32,
    /// Unix seconds until which this account is locked out, or 0.
    #[serde(default)]
    pub locked_until: u64,
    /// Which capability this account's session certificates carry.
    #[serde(default)]
    pub role: UserRole,
    /// The validity window stamped on this account's session certificates, in
    /// seconds — chosen by the admin who granted the account.
    pub session_ttl_secs: u64,
    /// Whether the account is administratively disabled. What lets an operator
    /// cut an account off without waiting for a certificate to expire; a
    /// certificate already issued is still ended by `RevokeNode`.
    #[serde(default)]
    pub disabled: bool,
}

/// A pending invitation to register one named account.
///
/// **Deliberately not a [`UserRecord`] with a flag.** It lives in its own
/// persisted collection beside the user store, so no code path that iterates
/// accounts can ever authenticate one. A half-built account that can log in is
/// a strictly worse failure mode than an invite that cannot, and the
/// distinction should not depend on every future reader of the user store
/// remembering a flag.
///
/// Serialized into the CA state snapshot, so its shape is part of the on-disk
/// schema (see `persistence.rs`).
#[derive(Serialize, Deserialize, Clone)]
pub struct UserInvite {
    /// The account name this invite will create. Reserved from the moment it
    /// is minted, against the user store *and* against another invite.
    pub username: String,
    /// The role the created account will hold. Decided by the admin at mint
    /// and never by the redeemer: no field on either redemption request can
    /// ask for more than this.
    pub role: UserRole,
    /// Session-certificate lifetime for the created account. Refused at mint if
    /// it is past the authority's cap, and re-checked at completion — where it
    /// is *clamped* rather than refused, since the value is chosen now and
    /// applied later, under a cap that may have moved in between.
    pub session_ttl_secs: u64,
    /// `Blake2s256` of the invite token under [`INVITE_TOKEN_LABEL`]. The
    /// token itself is never stored: it is a bearer credential sitting in the
    /// provider's state file, and should be no more readable there than
    /// [`UserRecord::password_hash`] is.
    pub token_hash: [u8; 32],
    /// The account's TOTP secret, minted here and revealed exactly once, to
    /// whoever starts registration.
    ///
    /// Not an `Option`, unlike [`UserRecord::totp_secret`]. An invite with no
    /// second factor degenerates to "a bearer token in a chat message buys an
    /// account that can mint a certificate the whole mesh honours", and drops
    /// the proof-of-enrolment this path exists for. An automation account that
    /// cannot present a code has nobody to send a URL to either;
    /// `CreateUser`'s `no_totp` remains its path. The invariant lives in the
    /// type so it cannot be re-opened by accident.
    pub totp_secret: Vec<u8>,
    /// Unix seconds the invite was minted at.
    pub created_at: u64,
    /// Unix seconds after which the invite is refused.
    pub expires_at: u64,
    /// Whether registration has been started, and by whom.
    pub status: InviteStatus,
}

/// Where an invite is in its one-way lifecycle.
///
/// Redacted by hand rather than derived, because this record carries an
/// account's second factor.
///
/// [`HeldCsr`](crate::authority) omits `Debug` outright for the same reason;
/// this type keeps one because a `Vec<UserInvite>` is worth being able to print
/// while debugging the store. What it must never do is put `totp_secret` in the
/// bounded record ring that `GetLogs` serves over the management API — one
/// `?invite` in a future log line would hand an account's second factor to any
/// viewer-tier connection.
///
/// The token hash is shown as a length only: it is not a secret, but printing
/// 32 bytes of it teaches a reader nothing and buries the fields that do.
impl core::fmt::Debug for UserInvite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UserInvite")
            .field("username", &self.username)
            .field("role", &self.role)
            .field("session_ttl_secs", &self.session_ttl_secs)
            .field("token_hash", &"<32 bytes>")
            .field("totp_secret", &"<redacted>")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("status", &self.status)
            .finish()
    }
}

/// Two states and no third: an invite that has been completed does not have a
/// status, it has been deleted — atomically, with the account's creation.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum InviteStatus {
    /// Minted, and its TOTP secret not yet revealed to anyone.
    Pending,
    /// The secret has been revealed. Both the single-use interlock and the
    /// signal an admin reads: started-and-not-completed means somebody took the
    /// second factor and did not finish.
    Started {
        /// `Blake2s256` of the registration handle issued at start, under
        /// [`REGISTRATION_HANDLE_LABEL`]. Only the party holding the handle can
        /// complete.
        handle_hash: [u8; 32],
        /// Unix seconds the secret was revealed at.
        started_at: u64,
        /// Unix seconds after which the handle is dead and the invite is spent.
        handle_expires_at: u64,
    },
}

impl UserInvite {
    /// Mint an invite for `username`, with a freshly generated TOTP secret.
    ///
    /// `token_hash` rather than the token: the caller generates the token,
    /// hands it to whoever asked, and keeps only this. Passing the token in
    /// here would put it inside the type that gets serialized, which is exactly
    /// where it must not be.
    pub fn new(
        username: &str,
        role: UserRole,
        session_ttl_secs: u64,
        token_hash: [u8; 32],
        created_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            username: username.to_string(),
            role,
            session_ttl_secs,
            token_hash,
            totp_secret: generate_totp_secret(),
            created_at,
            expires_at,
            status: InviteStatus::Pending,
        }
    }

    /// The `otpauth://` enrolment URI for this invite's second factor.
    ///
    /// Unlike [`UserRecord::totp_enrolment_uri`] this is never `None`: a second
    /// factor is mandatory on this path.
    pub fn totp_enrolment_uri(&self, issuer: &str) -> String {
        totp_enrolment_uri(issuer, &self.username, &self.totp_secret)
    }

    /// Whether this invite has passed its expiry as of `now_unix`.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at
    }

    /// Whether `hash` is this invite's token hash, compared in constant time.
    ///
    /// Constant-time per comparison, though a lookup across the store is a
    /// scan, so the *work* is occupancy-dependent even though each comparison
    /// is not. That is not a leak worth closing here: the occupancy is
    /// readable by any admin and tells an anonymous caller nothing about which
    /// token would match.
    pub fn token_matches(&self, hash: &[u8; 32]) -> bool {
        self.token_hash.ct_eq(hash).into()
    }

    /// Whether `hash` is the handle hash of a *started* invite whose handle has
    /// not expired as of `now_unix`, compared in constant time.
    pub fn handle_matches(&self, hash: &[u8; 32], now_unix: u64) -> bool {
        match &self.status {
            InviteStatus::Pending => false,
            InviteStatus::Started {
                handle_hash,
                handle_expires_at,
                ..
            } => now_unix < *handle_expires_at && handle_hash.ct_eq(hash).into(),
        }
    }
}

/// What a login attempt resolved to.
///
/// Deliberately two variants and not five. Unknown user, wrong password, wrong
/// code, locked and disabled all land on [`AuthOutcome::Rejected`], because the
/// caller is unauthenticated by definition — the request is on the enrollment
/// tier — and every distinction is an oracle: "no such user" enumerates
/// accounts, and "locked" tells an attacker their guessing is working.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    /// The credentials verified. The caller mints the session certificate.
    Accepted,
    /// The credentials did not verify, for a reason the caller does not learn.
    Rejected,
}

impl UserRecord {
    /// Create an account with `password`, a freshly generated TOTP secret, and
    /// the given role and session lifetime.
    ///
    /// TOTP is enrolled by default and opted *out* of explicitly
    /// ([`Self::without_totp`]) rather than opted into: any account here can
    /// mint a certificate the whole mesh honours, so a password alone would
    /// make fleet-wide administrative access a phishable secret, and the
    /// endpoint that accepts it is reachable by anyone who can route to the
    /// provider.
    pub fn new(
        username: &str,
        password: &str,
        role: UserRole,
        session_ttl_secs: u64,
    ) -> Result<Self, String> {
        check_password_present(password)?;
        Ok(Self {
            id: AccountId::generate(),
            username: username.to_string(),
            password_hash: hash_password(password)?,
            totp_secret: Some(generate_totp_secret()),
            totp_last_step: 0,
            failed_attempts: 0,
            locked_until: 0,
            role,
            session_ttl_secs,
            disabled: false,
        })
    }

    /// Create an account from a redeemed invite: an existing TOTP secret the
    /// registrant has already enrolled, and the replay guard already advanced
    /// past the code they proved it with.
    ///
    /// Separate from [`Self::new`] rather than a pair of extra arguments on it,
    /// because `new` *mints* a secret and this one must not — and because both
    /// of the differences are the security-relevant part.
    ///
    /// `totp_last_step` is the one that fails silently. The code accepted at
    /// completion sits inside the ±[`TOTP_SKEW_STEPS`] window that
    /// [`Self::authenticate`] will accept from, so an account that started at
    /// step 0 would take that same code again at its first sign-in — up to 90
    /// seconds of replay against a brand-new administrative account.
    pub fn from_registration(
        username: &str,
        password: &str,
        totp_secret: Vec<u8>,
        totp_last_step: u64,
        role: UserRole,
        session_ttl_secs: u64,
    ) -> Result<Self, String> {
        check_password_present(password)?;
        Ok(Self {
            id: AccountId::generate(),
            username: username.to_string(),
            password_hash: hash_password(password)?,
            totp_secret: Some(totp_secret),
            totp_last_step,
            failed_attempts: 0,
            locked_until: 0,
            role,
            session_ttl_secs,
            disabled: false,
        })
    }

    /// Drop this account's second factor, for an automation account that
    /// cannot present one. Such an account should hold a long-lived
    /// certificate issued offline instead of logging in at all; this exists so
    /// that choice is stated rather than reached by omission.
    pub fn without_totp(mut self) -> Self {
        self.totp_secret = None;
        self
    }

    /// The `otpauth://` enrolment URI for this account's TOTP secret, for a
    /// one-time display at account creation (or `None` when the account has no
    /// second factor).
    ///
    /// `issuer` names the mesh in the authenticator app's list. The URI carries
    /// the shared secret in the clear by construction — that is what enrolment
    /// *is* — so it belongs on a terminal the admin is sitting at and nowhere
    /// else.
    pub fn totp_enrolment_uri(&self, issuer: &str) -> Option<String> {
        let secret = self.totp_secret.as_ref()?;
        Some(totp_enrolment_uri(issuer, &self.username, secret))
    }

    /// Whether this account is locked out as of `now_unix`.
    pub fn is_locked(&self, now_unix: u64) -> bool {
        now_unix < self.locked_until
    }

    /// Verify `password` and `totp_code` against this account as of
    /// `now_unix`, updating the account's failure counter, lockout and TOTP
    /// replay guard in place.
    ///
    /// The record is mutated whatever the outcome, so the caller must persist
    /// it either way: a failed attempt that is not durably counted is a
    /// lockout that resets on restart, which is a lockout an attacker can
    /// trigger away.
    ///
    /// Order matters. The lockout is checked *first* and short-circuits before
    /// the Argon2 verification, so a locked account cannot be used to make the
    /// CA spend [`ARGON2_MEMORY_KIB`] per guess. The password is then checked
    /// before the code, and a wrong password does not reveal whether the code
    /// was right, because both failures return the same thing.
    pub fn authenticate(&mut self, password: &str, totp_code: &str, now_unix: u64) -> AuthOutcome {
        if self.disabled || self.is_locked(now_unix) {
            return AuthOutcome::Rejected;
        }
        let password_ok = verify_password(&self.password_hash, password);
        let step = match (&self.totp_secret, password_ok) {
            // An account with no second factor: the password is the whole
            // check, and there is no step to remember.
            (None, ok) => {
                if ok {
                    Some(self.totp_last_step)
                } else {
                    None
                }
            }
            // Verify the code even when the password was wrong, so the two
            // failures cost the same wall-clock time. The result is discarded
            // either way if `password_ok` is false.
            (Some(secret), ok) => {
                let accepted = verify_totp(secret, totp_code, now_unix, self.totp_last_step);
                if ok { accepted } else { None }
            }
        };
        match step {
            Some(step) => {
                self.totp_last_step = step;
                self.failed_attempts = 0;
                self.locked_until = 0;
                AuthOutcome::Accepted
            }
            None => {
                self.failed_attempts = self.failed_attempts.saturating_add(1);
                if self.failed_attempts >= LOCKOUT_THRESHOLD {
                    self.locked_until = now_unix.saturating_add(LOCKOUT_SECS);
                }
                AuthOutcome::Rejected
            }
        }
    }

    /// Replace this account's password, clearing any lockout — an admin
    /// resetting a password is also the way an operator locked out of their
    /// own account gets back in.
    pub fn set_password(&mut self, password: &str) -> Result<(), String> {
        check_password_present(password)?;
        self.password_hash = hash_password(password)?;
        self.failed_attempts = 0;
        self.locked_until = 0;
        Ok(())
    }
}

/// Spend the work a real password verification costs, for a login naming an
/// account that does not exist.
///
/// Without this, a login for an unknown account returns in microseconds while
/// one for a known account spends [`ARGON2_MEMORY_KIB`] worth of memory-hard
/// work. That difference is measurable across a network and enumerates
/// accounts — which is precisely what [`AuthOutcome`]'s single rejection
/// variant exists to prevent, and a uniform *answer* is no use if the *timing*
/// answers instead.
///
/// Hashing rather than verifying against a stored dummy: the cost is the same
/// parameters either way, and this needs no constant that has to stay a
/// well-formed PHC string as the parameters move.
pub(crate) fn spend_absent_user_work(password: &str) {
    let _ = hash_password(password);
}

/// Refuse a password that carries no knowledge at all.
///
/// Checked where an account is *built*, not inside [`hash_password`]:
/// [`spend_absent_user_work`] hashes on behalf of an account that does not
/// exist, and an early return there would answer an empty password faster for
/// an absent user than for a present one — precisely the enumeration oracle
/// that function exists to close.
///
/// Both front ends already refuse this (`wayfinder-web`'s `api.rs`,
/// `wayfinderctl`), but neither is the trust boundary:
/// `CompleteUserRegistration` is on the enrollment tier, so a wire client
/// holding an invite handle and no credential reaches the authority directly.
fn check_password_present(password: &str) -> Result<(), String> {
    if password.is_empty() {
        return Err("a password is required".to_string());
    }
    Ok(())
}

/// Hash `password` with Argon2id at this module's parameters, returning a PHC
/// string that carries those parameters and a fresh random salt.
fn hash_password(password: &str) -> Result<String, String> {
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_LANES, None)
        .map_err(|e| format!("argon2 parameters: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| format!("hashing password: {e}"))
}

/// Whether `password` matches the PHC string `hash`.
///
/// The parameters come from the stored hash rather than from this module's
/// constants, which is what lets [`ARGON2_MEMORY_KIB`] be raised later without
/// invalidating every existing account.
fn verify_password(hash: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        // A stored hash that does not parse cannot verify anything. Failing
        // closed here means a corrupted record locks its account out rather
        // than admitting whoever asks.
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// A fresh 20-byte TOTP shared secret from the OS CSPRNG.
pub(crate) fn generate_totp_secret() -> Vec<u8> {
    let mut secret = vec![0u8; TOTP_SECRET_LEN];
    argon2::password_hash::rand_core::RngCore::fill_bytes(
        &mut argon2::password_hash::rand_core::OsRng,
        &mut secret,
    );
    secret
}

/// The `otpauth://` enrolment URI for `secret`, as `issuer` will name it in an
/// authenticator app's list.
///
/// Shared by [`UserRecord::totp_enrolment_uri`] and
/// [`UserInvite::totp_enrolment_uri`], which differ in whether the secret can
/// be absent and in nothing else. The URI carries the shared secret in the
/// clear by construction — that is what enrolment *is* — so the question that
/// matters at every call site is who is about to read it.
fn totp_enrolment_uri(issuer: &str, username: &str, secret: &[u8]) -> String {
    let issuer = percent_encode(issuer);
    let username = percent_encode(username);
    format!(
        "otpauth://totp/{issuer}:{username}?secret={}&issuer={issuer}&algorithm=SHA1&digits={}&period={}",
        base32_encode(secret),
        TOTP_DIGITS,
        TOTP_STEP_SECS,
    )
}

/// Everything outside RFC 3986's *unreserved* set (`A-Za-z0-9-._~`).
///
/// The conservative direction: over-encoding a character that would have been
/// safe costs two bytes in a URI nobody reads by hand, while under-encoding one
/// is a parameter-injection bug. `:` is therefore encoded too — the one
/// structural separator between issuer and account is written by
/// [`totp_enrolment_uri`]'s own format string, outside the encoded components,
/// so a `:` *inside* either of them cannot be mistaken for it.
const URI_COMPONENT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Percent-encode `s` for use in a URI path segment or query value.
///
/// The account name is operator-chosen text that lands in the *label* (a path
/// segment) and again in the query, and the Key URI Format requires the label
/// to be percent-encoded. Without it a name carrying `?`, `&` or `=` appends
/// parameters of its own: `x?secret=…&issuer=…` produces a URI with two
/// `secret=` and two `issuer=` values, and an authenticator that takes the
/// first enrols against the attacker's secret and attributes it to the
/// attacker's issuer.
///
/// The issuer is a compile-time constant today (`TOTP_ISSUER`, the only value
/// either production call site passes) and is encoded anyway, so it stays safe
/// if it ever becomes configurable.
///
/// Unlike [`base32_encode`] beside it this is *not* hand-rolled, and the
/// difference is worth stating because the two look like the same kind of
/// problem. No base32 crate is in this build graph, whereas `percent-encoding`
/// already is — `url` and `reqwest` both pull it, and this module is
/// `std`-gated, so every target that can reach this function has already
/// compiled it. There is no dependency edge to save, and this one closes an
/// injection: an audited implementation is the conservative choice, not the
/// indulgent one.
fn percent_encode(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, URI_COMPONENT).to_string()
}

/// A fresh invite token or registration handle: [`INVITE_SECRET_LEN`] bytes
/// from the OS CSPRNG, rendered base32 without padding.
///
/// Base32 because it is the alphabet the `otpauth://` URI beside it already
/// uses, and because it is unambiguous if the value ever has to be read aloud
/// or retyped — a token travels through whatever channel the operator has to
/// hand, which is sometimes a phone call.
pub(crate) fn generate_invite_secret() -> String {
    let mut bytes = vec![0u8; INVITE_SECRET_LEN];
    argon2::password_hash::rand_core::RngCore::fill_bytes(
        &mut argon2::password_hash::rand_core::OsRng,
        &mut bytes,
    );
    base32_encode(&bytes)
}

/// `Blake2s256(INVITE_TOKEN_LABEL || token)` — what the store keeps in place of
/// the token.
pub(crate) fn invite_token_hash(token: &str) -> [u8; 32] {
    labelled_hash(INVITE_TOKEN_LABEL, token)
}

/// `Blake2s256(REGISTRATION_HANDLE_LABEL || handle)` — what a started invite
/// keeps in place of the handle.
pub(crate) fn registration_handle_hash(handle: &str) -> [u8; 32] {
    labelled_hash(REGISTRATION_HANDLE_LABEL, handle)
}

/// Hash `value` under `label`, so two credentials of the same shape in the same
/// record can never be presented as one another.
fn labelled_hash(label: &[u8], value: &str) -> [u8; 32] {
    use blake2::Digest as _;
    let mut h = blake2::Blake2s256::new();
    h.update(label);
    h.update(value.as_bytes());
    h.finalize().into()
}

/// The RFC 6238 code for `secret` at time step `step`.
fn totp_code(secret: &[u8], step: u64) -> u32 {
    // `new_from_slice` only fails for key sizes HMAC cannot take, and HMAC
    // accepts any length, so this branch is unreachable for every secret this
    // module produces — and a zero code is not accepted by anything, so an
    // impossible failure fails closed rather than panicking.
    let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(secret) else {
        return 0;
    };
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    // RFC 4226 dynamic truncation: the low nibble of the last byte selects a
    // 4-byte window, whose top bit is masked off.
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    binary % 10u32.pow(TOTP_DIGITS)
}

/// Verify `code` against `secret` as of `now_unix`, returning the accepted time
/// step, or `None`.
///
/// A step at or below `last_step` is refused even when the code is correct:
/// [`TOTP_SKEW_STEPS`] makes three codes valid at any instant, and without this
/// a code observed in transit could be spent again within that window.
pub(crate) fn verify_totp(secret: &[u8], code: &str, now_unix: u64, last_step: u64) -> Option<u64> {
    let code = code.trim();
    if code.len() != TOTP_DIGITS as usize {
        return None;
    }
    let current = now_unix / TOTP_STEP_SECS;
    let first = current.saturating_sub(TOTP_SKEW_STEPS);
    for step in first..=current.saturating_add(TOTP_SKEW_STEPS) {
        if step <= last_step {
            continue;
        }
        let expected = format!(
            "{:0width$}",
            totp_code(secret, step),
            width = TOTP_DIGITS as usize
        );
        // Constant-time: a byte-by-byte early exit would leak how much of a
        // guessed code was right, which over a six-digit space is a usable
        // signal.
        if expected.as_bytes().ct_eq(code.as_bytes()).into() {
            return Some(step);
        }
    }
    None
}

/// The TOTP code an authenticator would show for `secret` at `now_unix`, for
/// tests in sibling modules that need to present a live one.
///
/// Not a production entry point — a client computes its own code, and a server
/// verifies rather than generates — which is why it is `#[cfg(test)]` rather
/// than simply `pub(crate)`.
#[cfg(test)]
pub(crate) fn totp_code_for_tests(secret: &[u8], now_unix: u64) -> String {
    format!(
        "{:0width$}",
        totp_code(secret, now_unix / TOTP_STEP_SECS),
        width = TOTP_DIGITS as usize
    )
}

/// RFC 4648 base32 (upper-case, unpadded), for the `otpauth://` enrolment URI.
///
/// Unpadded because that is the form authenticator apps accept in a `secret=`
/// query parameter; padding is not part of what they parse.
pub(crate) fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer: u16 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPHABET[index] as char);
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[index] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A round trip through the real Argon2id parameters: the right password
    /// verifies, a wrong one does not, and the stored form is a PHC string
    /// rather than the password.
    #[test]
    fn a_password_verifies_against_its_own_hash_and_nothing_else() {
        let hash = hash_password("correct horse battery staple").unwrap();

        assert!(
            hash.starts_with("$argon2id$"),
            "stored as a PHC string: {hash}"
        );
        assert!(
            !hash.contains("correct horse"),
            "the password itself must not be recoverable from the record"
        );
        assert!(verify_password(&hash, "correct horse battery staple"));
        assert!(!verify_password(&hash, "correct horse battery stapl"));
        assert!(!verify_password(&hash, ""));
    }

    /// Two accounts with the *same* password get different hashes: the salt is
    /// per-user, so a stolen store cannot be attacked once for everyone who
    /// happened to choose the same password.
    #[test]
    fn the_same_password_hashes_differently_for_two_accounts() {
        let a = hash_password("shared").unwrap();
        let b = hash_password("shared").unwrap();
        assert_ne!(a, b);
        assert!(verify_password(&a, "shared") && verify_password(&b, "shared"));
    }

    /// A hash that does not parse verifies nothing — a corrupt record locks
    /// its account out rather than admitting whoever asks.
    #[test]
    fn an_unparseable_hash_fails_closed() {
        assert!(!verify_password("not a phc string", "anything"));
        assert!(!verify_password("", ""));
    }

    /// The RFC 6238 vector for an all-`1234567890` ASCII secret with SHA-1:
    /// at T = 59 s (step 1) the code is 287082.
    #[test]
    fn totp_matches_the_rfc_6238_test_vector() {
        let secret = b"12345678901234567890";
        assert_eq!(totp_code(secret, 59 / TOTP_STEP_SECS), 287082);
        assert_eq!(totp_code(secret, 1111111109 / TOTP_STEP_SECS), 81804);
        assert_eq!(totp_code(secret, 1111111111 / TOTP_STEP_SECS), 50471);
    }

    /// The skew window accepts the step either side of the current one, and
    /// nothing further out.
    #[test]
    fn totp_accepts_one_step_of_skew_and_no_more() {
        let secret = b"12345678901234567890";
        let now = 1_700_000_000u64;
        let current = now / TOTP_STEP_SECS;

        for offset in [-1i64, 0, 1] {
            let step = (current as i64 + offset) as u64;
            let code = format!("{:06}", totp_code(secret, step));
            assert_eq!(
                verify_totp(secret, &code, now, 0),
                Some(step),
                "step {offset:+} must be inside the skew window"
            );
        }
        for offset in [-2i64, 2] {
            let step = (current as i64 + offset) as u64;
            let code = format!("{:06}", totp_code(secret, step));
            assert_eq!(
                verify_totp(secret, &code, now, 0),
                None,
                "step {offset:+} must be outside it"
            );
        }
    }

    /// The skew window is a replay window unless the last accepted step is
    /// remembered. It is: a code accepted once is refused when presented
    /// again, even though it is still inside its own validity window.
    #[test]
    fn a_totp_code_cannot_be_spent_twice() {
        let secret = b"12345678901234567890";
        let now = 1_700_000_000u64;
        let step = now / TOTP_STEP_SECS;
        let code = format!("{:06}", totp_code(secret, step));

        assert_eq!(verify_totp(secret, &code, now, 0), Some(step));
        assert_eq!(
            verify_totp(secret, &code, now, step),
            None,
            "the same code, one instant later, inside the same step"
        );
    }

    /// A full login: the right password and a live code are accepted, and the
    /// account's replay guard advances as a result.
    #[test]
    fn a_correct_password_and_live_code_authenticate() {
        let mut user = UserRecord::new("ops", "hunter2", UserRole::Admin, 3600).unwrap();
        let secret = user.totp_secret.clone().unwrap();
        let now = 1_700_000_000u64;
        let code = format!("{:06}", totp_code(&secret, now / TOTP_STEP_SECS));

        assert_eq!(
            user.authenticate("hunter2", &code, now),
            AuthOutcome::Accepted
        );
        assert_eq!(user.totp_last_step, now / TOTP_STEP_SECS);
        assert_eq!(user.failed_attempts, 0);

        // And the same code does not work a second time.
        assert_eq!(
            user.authenticate("hunter2", &code, now),
            AuthOutcome::Rejected
        );
    }

    /// Every way of failing is the same outcome: unknown-account is the
    /// caller's problem, but wrong password, wrong code, disabled and locked
    /// must be indistinguishable here, or the endpoint is an oracle.
    #[test]
    fn every_failure_mode_is_the_same_rejection() {
        let now = 1_700_000_000u64;
        let mut user = UserRecord::new("ops", "hunter2", UserRole::Admin, 3600).unwrap();
        let secret = user.totp_secret.clone().unwrap();
        let code = format!("{:06}", totp_code(&secret, now / TOTP_STEP_SECS));

        assert_eq!(
            user.authenticate("wrong", &code, now),
            AuthOutcome::Rejected
        );
        assert_eq!(
            user.authenticate("hunter2", "000000", now),
            AuthOutcome::Rejected
        );

        let mut disabled = UserRecord::new("bot", "hunter2", UserRole::Viewer, 3600).unwrap();
        disabled.disabled = true;
        let bot_secret = disabled.totp_secret.clone().unwrap();
        let bot_code = format!("{:06}", totp_code(&bot_secret, now / TOTP_STEP_SECS));
        assert_eq!(
            disabled.authenticate("hunter2", &bot_code, now),
            AuthOutcome::Rejected,
            "a disabled account is cut off even with correct credentials"
        );
    }

    /// Consecutive failures lock the account, the lock survives a correct
    /// password (which is the point), and it lifts on its own once
    /// `LOCKOUT_SECS` have passed.
    #[test]
    fn consecutive_failures_lock_the_account_and_the_lock_expires() {
        let now = 1_700_000_000u64;
        let mut user = UserRecord::new("ops", "hunter2", UserRole::Admin, 3600).unwrap();
        let secret = user.totp_secret.clone().unwrap();

        for _ in 0..LOCKOUT_THRESHOLD {
            assert_eq!(
                user.authenticate("wrong", "000000", now),
                AuthOutcome::Rejected
            );
        }
        assert!(user.is_locked(now));

        let code = format!("{:06}", totp_code(&secret, now / TOTP_STEP_SECS));
        assert_eq!(
            user.authenticate("hunter2", &code, now),
            AuthOutcome::Rejected,
            "the lock holds against the correct credentials, or it is not a lock"
        );

        // Once it lapses, the same credentials work — at a later step, so the
        // code has to be recomputed, which is exactly what a real client does.
        let later = now + LOCKOUT_SECS;
        let code = format!("{:06}", totp_code(&secret, later / TOTP_STEP_SECS));
        assert_eq!(
            user.authenticate("hunter2", &code, later),
            AuthOutcome::Accepted
        );
        assert_eq!(user.failed_attempts, 0);
    }

    /// An account explicitly created without a second factor authenticates on
    /// the password alone, and is not accidentally reachable with an empty code
    /// when it *does* have one.
    #[test]
    fn an_account_without_totp_authenticates_on_the_password_alone() {
        let now = 1_700_000_000u64;
        let mut bot = UserRecord::new("bot", "hunter2", UserRole::Viewer, 900)
            .unwrap()
            .without_totp();
        assert_eq!(bot.authenticate("hunter2", "", now), AuthOutcome::Accepted);
        assert_eq!(bot.authenticate("wrong", "", now), AuthOutcome::Rejected);

        let mut human = UserRecord::new("ops", "hunter2", UserRole::Admin, 3600).unwrap();
        assert_eq!(
            human.authenticate("hunter2", "", now),
            AuthOutcome::Rejected,
            "an enrolled second factor must not be skippable by omitting it"
        );
    }

    /// The enrolment URI is the standard `otpauth://` form, carries the secret
    /// base32-encoded, and is absent for an account with no second factor.
    #[test]
    fn the_enrolment_uri_is_the_standard_otpauth_form() {
        let user = UserRecord::new("ops", "hunter2", UserRole::Admin, 3600).unwrap();
        let uri = user.totp_enrolment_uri("wayfinder").unwrap();

        assert!(uri.starts_with("otpauth://totp/wayfinder:ops?"), "{uri}");
        assert!(uri.contains("issuer=wayfinder"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
        let secret = base32_encode(user.totp_secret.as_ref().unwrap());
        assert!(uri.contains(&format!("secret={secret}")));

        assert_eq!(user.without_totp().totp_enrolment_uri("wayfinder"), None);
    }

    /// A username is operator-chosen text that lands in both the *label* and
    /// the *query* of an `otpauth://` URI. The Key URI Format requires the
    /// label to be percent-encoded, and the query obviously cannot carry a raw
    /// `&` or `=` — a name like `x?secret=…&issuer=…` would otherwise append
    /// duplicate parameters, and an authenticator that takes first-wins enrols
    /// against the attacker's secret and issuer rather than this node's.
    ///
    /// The assertion is on the *count* of each parameter, not on the presence
    /// of the genuine one: the injected copies are what makes the URI
    /// ambiguous, so a fix that merely appends the real values after the
    /// forged ones would still be broken.
    #[test]
    fn the_enrolment_uri_percent_encodes_a_username_that_forges_parameters() {
        let hostile = "x?secret=AAAAAAAA&issuer=Evil&";
        let user = UserRecord::new(hostile, "hunter2", UserRole::Admin, 3600).unwrap();
        let uri = user.totp_enrolment_uri("wayfinder").unwrap();

        assert_eq!(
            uri.matches("secret=").count(),
            1,
            "exactly one secret= parameter, not the injected one too: {uri}"
        );
        assert_eq!(
            uri.matches("issuer=").count(),
            1,
            "exactly one issuer= parameter: {uri}"
        );
        assert!(
            !uri.contains("issuer=Evil"),
            "the injected issuer must not survive encoding: {uri}"
        );

        // The genuine values are still the ones present, and still readable.
        let secret = base32_encode(user.totp_secret.as_ref().unwrap());
        assert!(uri.contains(&format!("secret={secret}")), "{uri}");
        assert!(uri.contains("issuer=wayfinder"), "{uri}");

        // The label keeps its one structural `:` between issuer and account,
        // and the name's own delimiters are encoded rather than dropped.
        let label = uri
            .strip_prefix("otpauth://totp/")
            .and_then(|rest| rest.split('?').next())
            .expect("a label before the query");
        assert_eq!(
            label.matches(':').count(),
            1,
            "one issuer:account separator: {label}"
        );
        assert!(label.starts_with("wayfinder:"), "{label}");
        assert_eq!(
            label, "wayfinder:x%3Fsecret%3DAAAAAAAA%26issuer%3DEvil%26",
            "the label is the encoded name, exactly — an encoder that dropped \
             the offending bytes rather than encoding them would satisfy every \
             assertion above and lose the account's name"
        );
    }

    /// The encoder itself, against the vectors its doc comment claims.
    ///
    /// Reached directly rather than only through a URI, for the reason
    /// `base32_matches_the_rfc_4648_vectors` beside it exists: the two tests
    /// above assert that forged parameters do not *survive*, which a mangling
    /// encoder also satisfies. This pins the output, so an encoder that dropped
    /// bytes or iterated `chars()` and cast to `u8` — which would garble every
    /// non-ASCII name while leaving both those tests green — fails here.
    #[test]
    fn percent_encode_matches_rfc_3986_unreserved() {
        for (input, expected) in [
            ("", ""),
            // The unreserved set passes through untouched. An over-broad
            // catch-all arm shows up here and nowhere else.
            ("plain-name_1.0~", "plain-name_1.0~"),
            ("AZaz09", "AZaz09"),
            // Bytes, not chars: é is two bytes and encodes as two triplets.
            ("rené", "ren%C3%A9"),
            ("日本", "%E6%97%A5%E6%9C%AC"),
            // The deliberate one: `:` is encoded even though the URI's own
            // separator is a colon, because that separator is written outside
            // the encoded components.
            ("a:b", "a%3Ab"),
            ("?&=/#", "%3F%26%3D%2F%23"),
            (" ", "%20"),
        ] {
            assert_eq!(percent_encode(input), expected, "encoding {input:?}");
        }
    }

    /// The issuer is encoded too, not just the account name.
    ///
    /// It is a compile-time constant at both production call sites today, but
    /// `totp_enrolment_uri` is `pub` and takes any `&str`, so the injection is
    /// one future caller away. Cheaper to pin now than to rediscover.
    #[test]
    fn the_enrolment_uri_percent_encodes_the_issuer_too() {
        let user = UserRecord::new("ops", "hunter2", UserRole::Admin, 3600).unwrap();
        let uri = user
            .totp_enrolment_uri("evil?secret=BBBBBBBB&issuer=Nope")
            .unwrap();

        assert_eq!(uri.matches("secret=").count(), 1, "{uri}");
        assert_eq!(uri.matches("issuer=").count(), 1, "{uri}");
        assert!(!uri.contains("issuer=Nope"), "{uri}");
    }

    /// The same encoding, reached through the other constructor: an invite
    /// carries a second factor before any account exists, so its URI is built
    /// from a name that has passed exactly the same (absent) validation.
    #[test]
    fn an_invite_uri_percent_encodes_its_username_too() {
        let invite = UserInvite::new(
            "a&b=c",
            UserRole::Viewer,
            3600,
            invite_token_hash(&generate_invite_secret()),
            1_700_000_000,
            1_700_086_400,
        );
        let uri = invite.totp_enrolment_uri("wayfinder");

        assert_eq!(uri.matches("issuer=").count(), 1, "{uri}");
        assert_eq!(uri.matches("secret=").count(), 1, "{uri}");
        assert!(
            !uri.contains("a&b=c"),
            "the raw name must not survive: {uri}"
        );
    }

    /// RFC 4648 base32 vectors, unpadded.
    #[test]
    fn base32_matches_the_rfc_4648_vectors() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    /// Resetting a password clears a lockout: an admin resetting a password is
    /// also how an operator locked out of their own account gets back in.
    #[test]
    fn setting_a_password_clears_a_lockout() {
        let now = 1_700_000_000u64;
        let mut user = UserRecord::new("ops", "hunter2", UserRole::Admin, 3600).unwrap();
        for _ in 0..LOCKOUT_THRESHOLD {
            user.authenticate("wrong", "000000", now);
        }
        assert!(user.is_locked(now));

        user.set_password("hunter3").unwrap();

        assert!(!user.is_locked(now));
        assert_eq!(user.failed_attempts, 0);
        let secret = user.totp_secret.clone().unwrap();
        let code = format!("{:06}", totp_code(&secret, now / TOTP_STEP_SECS));
        assert_eq!(
            user.authenticate("hunter3", &code, now),
            AuthOutcome::Accepted
        );
    }

    /// The token is a bearer credential living in the provider's state file,
    /// and it is stored there the way a password is: not at all.
    ///
    /// Only its domain-separated hash is kept, so a snapshot that leaks tells
    /// its reader nothing they could redeem. The label is what keeps that hash
    /// from colliding with the handle's over the same bytes.
    #[test]
    fn an_invite_stores_a_hash_of_its_token_and_never_the_token() {
        let token = generate_invite_secret();
        let invite = UserInvite::new(
            "rowan",
            UserRole::Viewer,
            3600,
            invite_token_hash(&token),
            1_700_000_000,
            1_700_086_400,
        );

        let stored = alloc::format!("{invite:?}");
        assert!(
            !stored.contains(&token),
            "the token itself must not be recoverable from the record"
        );
        // Asserted against the secret's own rendering, not against the word
        // "secret": a check for a substring the type could never contain
        // passes whatever the type grows later.
        let secret = base32_encode(&invite.totp_secret);
        assert!(
            !stored.contains(&secret),
            "and neither must the second factor: this record's `Debug` reaches \
             the ring `GetLogs` serves the moment anyone writes `?invite`"
        );
        assert_eq!(invite.token_hash, invite_token_hash(&token));
        assert_ne!(
            invite_token_hash(&token),
            registration_handle_hash(&token),
            "token and handle hashes are domain-separated, so one cannot be \
             presented as the other"
        );
    }

    /// A minted secret is 256 bits from the OS CSPRNG, rendered in the base32
    /// alphabet the `otpauth://` URI already uses — unambiguous if it ever has
    /// to be read aloud, and unguessable on any timescale, which is what lets
    /// an unknown token be refused without spending Argon2id on it.
    #[test]
    fn a_minted_secret_is_unguessable_and_base32() {
        let a = generate_invite_secret();
        let b = generate_invite_secret();

        assert_ne!(a, b, "two mints must not collide");
        assert_eq!(
            a.len(),
            52,
            "256 bits in unpadded base32 is 52 characters: {a}"
        );
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(&c)),
            "base32 alphabet only: {a}"
        );
    }

    /// A second factor is mandatory on this path, so the secret is not an
    /// `Option`: an invite with none would make a bearer token in a chat
    /// message the whole credential for an account that can mint a certificate
    /// the entire mesh honours.
    #[test]
    fn an_invite_always_carries_a_second_factor_to_enrol() {
        let invite = UserInvite::new(
            "rowan",
            UserRole::Admin,
            3600,
            [0u8; 32],
            1_700_000_000,
            1_700_086_400,
        );

        assert_eq!(invite.totp_secret.len(), TOTP_SECRET_LEN);
        let uri = invite.totp_enrolment_uri("wayfinder");
        assert!(uri.starts_with("otpauth://totp/wayfinder:rowan?"));
        assert!(uri.contains(&base32_encode(&invite.totp_secret)));
    }

    /// The account built at completion keeps the secret the invite enrolled —
    /// so the code the registrant just proved keeps working — *and* starts its
    /// replay guard at the step that code was accepted at.
    ///
    /// Without the second half, the code typed at registration stays valid at
    /// the next sign-in for the rest of its ±1-step window: up to 90 seconds of
    /// replay against a brand-new administrative account.
    #[test]
    fn an_account_registered_from_an_invite_inherits_the_secret_and_the_step() {
        let now = 1_700_000_000u64;
        let step = now / TOTP_STEP_SECS;
        let secret = generate_totp_secret();

        let user = UserRecord::from_registration(
            "rowan",
            "correct horse battery staple",
            secret.clone(),
            step,
            UserRole::Admin,
            3600,
        )
        .unwrap();

        assert_eq!(user.totp_secret.as_deref(), Some(secret.as_slice()));
        assert_eq!(
            user.totp_last_step, step,
            "the accepted step must be carried in, or the registration code \
             replays at the first sign-in"
        );
        assert_eq!(user.role, UserRole::Admin);
        assert_eq!(user.session_ttl_secs, 3600);
        assert!(!user.disabled);
    }

    /// The concrete replay this closes: the code accepted at completion is
    /// refused by the very next `authenticate`, while the *next* step's code is
    /// taken.
    #[test]
    fn the_code_accepted_at_registration_is_refused_at_the_next_sign_in() {
        let now = 1_700_000_000u64;
        let secret = generate_totp_secret();
        let step = verify_totp(&secret, &totp_code_for_tests(&secret, now), now, 0)
            .expect("a live code verifies");

        let mut user = UserRecord::from_registration(
            "rowan",
            "hunter2",
            secret.clone(),
            step,
            UserRole::Viewer,
            3600,
        )
        .unwrap();

        let same_code = totp_code_for_tests(&secret, now);
        assert_eq!(
            user.authenticate("hunter2", &same_code, now),
            AuthOutcome::Rejected,
            "the registration code must not be spendable again at sign-in"
        );

        let later = now + TOTP_STEP_SECS;
        let next_code = totp_code_for_tests(&secret, later);
        assert_eq!(
            user.authenticate("hunter2", &next_code, later),
            AuthOutcome::Accepted,
            "and the account must still be usable with a fresh code"
        );
    }
}
