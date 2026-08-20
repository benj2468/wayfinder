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
//! unchanged `decide_access`. The whole module is `std`-gated and an embedded
//! node never links it.
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
const TOTP_STEP_SECS: u64 = 30;

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

/// What an account's session certificates may do.
///
/// Two roles, not a bitmask, because they are the two management tiers that
/// exist: `CERT_FLAG_ADMIN` and `CERT_FLAG_VIEWER`. A third would mean a third
/// tier in `permits`, which is a decision to take there rather than here.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum UserRole {
    /// Session certificates carry `CERT_FLAG_ADMIN`: full management.
    Admin,
    /// Session certificates carry `CERT_FLAG_VIEWER`: the queries only.
    ///
    /// The default, so an account created without a role stated is the one
    /// that can do less.
    #[default]
    Viewer,
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
        Ok(Self {
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
        Some(format!(
            "otpauth://totp/{issuer}:{}?secret={}&issuer={issuer}&algorithm=SHA1&digits={}&period={}",
            self.username,
            base32_encode(secret),
            TOTP_DIGITS,
            TOTP_STEP_SECS,
        ))
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
fn generate_totp_secret() -> Vec<u8> {
    let mut secret = vec![0u8; TOTP_SECRET_LEN];
    argon2::password_hash::rand_core::RngCore::fill_bytes(
        &mut argon2::password_hash::rand_core::OsRng,
        &mut secret,
    );
    secret
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
fn verify_totp(secret: &[u8], code: &str, now_unix: u64, last_step: u64) -> Option<u64> {
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
fn base32_encode(bytes: &[u8]) -> String {
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
}
