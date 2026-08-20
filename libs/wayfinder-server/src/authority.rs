//! The concrete mesh certificate authority for a node in provider mode.
//!
//! Host-only (`std`): holds the mesh root key (via `wayfinder_auth::Authority`)
//! and issues / revokes member certificates in response to management-API
//! enrollment requests.  Embedded nodes never link this — they only verify
//! against a trust anchor.

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;
use wayfinder::config::MAX_CERT_TTL_SECS;
use wayfinder::config::ProviderConfig;
use wayfinder::interfaces::frame::Mac;
use wayfinder_auth::Authority;
use wayfinder_auth::MembershipCert;
use wayfinder_protos::service::CsrOutcome;
use wayfinder_protos::service::EnrollData;
use wayfinder_protos::service::EnrollmentAdmission;
use wayfinder_protos::service::EnrollmentPolicyData;
use wayfinder_protos::service::EnrollmentPolicyStatusData;
use wayfinder_protos::service::IssuedCertData;
use wayfinder_protos::service::PendingCsrData;
use wayfinder_protos::service::SharedSecret;
use wayfinder_protos::service::TokenUpdate;
use wayfinder_protos::service::UserAuthOutcome;
use zerocopy::IntoBytes;

use crate::persistence::CaLog;
use crate::persistence::TokenOverride;
use crate::provider::MeshAuthority;
use crate::users::AuthOutcome;
use crate::users::UserRecord;
use crate::users::UserRole;

/// A certificate-signing request the authority is holding while it awaits an
/// operator decision.  Only populated when `auto_approve` is off; keyed by
/// MAC (one held request per node at a time). `pub(crate)` (fields stay
/// private) so `persistence.rs` can name the type in `CaLog`'s signatures;
/// derives `Serialize`/`Deserialize` directly (no separate on-disk mirror
/// type) since this is plain crate-internal state with no wire-format
/// contract pulling it in a different direction from its on-disk shape.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct HeldCsr {
    /// The enrolling node's MAC (the certificate binds to this).
    node_mac: [u8; 6],
    /// The node's Ed25519 identity public key.
    ed_pubkey: [u8; 32],
    /// The node's X25519 public key.
    x_pubkey: [u8; 32],
    /// When the request last changed state (unix seconds): first seen while
    /// pending, re-stamped on approve/deny.  Drives both operator triage (for a
    /// pending entry this is the submission time) and TTL eviction.
    requested_at: u64,
    /// Where the request is in the approval lifecycle.
    status: CsrStatus,
}

/// The lifecycle state of a [`HeldCsr`]. `pub(crate)` alongside `HeldCsr` for
/// the same reason.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) enum CsrStatus {
    /// Awaiting an operator's approve/deny decision.
    Pending,
    /// Approved: the signed certificate bytes are ready for the node to collect
    /// on its next `submit_csr` poll.
    Approved(Vec<u8>),
    /// Denied by an operator; a polling node observes a rejection with this
    /// reason and stops retrying.
    Denied(String),
}

/// A running certificate authority: the mesh root key plus the issuance policy
/// (certificate lifetime, an optional shared enrollment token, and whether an
/// operator must approve each request).
pub struct CertAuthority {
    /// Custody of the mesh root key and the mesh id it signs for.
    authority: Authority,
    /// Validity window length applied to issued certificates, in seconds.  Keep
    /// it short — passive expiry is the primary revocation mechanism.
    cert_ttl_secs: u64,
    /// Whether this authority may run with a certificate lifetime past
    /// [`MAX_CERT_TTL_SECS`] — see [`ProviderConfig::allow_unbounded_cert_ttl`].
    /// Carried from the config so the same rule holds for a lifetime set later
    /// through the management API.
    allow_unbounded_cert_ttl: bool,
    /// Optional shared enrollment token.  When set, a CSR must present the
    /// matching value; when `None`, enrollment is open (TOFU).
    enrollment_token: Option<SharedSecret>,
    /// When set, a CSR is signed on submission rather than parked as pending
    /// until an operator approves it.  Off is the closed posture, and the one a
    /// `ProviderConfig` that says nothing gets.
    auto_approve: bool,
    /// How long a held CSR survives (in seconds) before it is evicted, measured
    /// from when it last changed state.  Bounds the `held` table and frees a MAC
    /// for a fresh request once a stale one times out.
    pending_ttl_secs: u64,
    /// Current wall-clock time in unix seconds, refreshed by the driver so issued
    /// validity windows track the node's auth clock.  Zero until first set.
    now_unix: u64,
    /// The durable CA state: the issued-certificate log (for `ListCerts` and
    /// the impersonation guard) and the held-CSR store (for the
    /// operator-approval flow, only used when `auto_approve` is off), both
    /// backed by one snapshot file. Every mutation goes through
    /// [`CaLog::mutate_issued`]/[`CaLog::mutate_held`]/
    /// [`CaLog::mutate_issued_and_held`], which persist the result to the
    /// configured `state_path` (if any) so it survives a restart — this
    /// crate has no other way to touch either underlying `Vec`, so a
    /// mutation can never be committed without also being persisted (and,
    /// since a failed persist rolls the mutation back, never observed as
    /// committed without actually being durable).
    log: CaLog,
}

/// Largest number of certificate-signing requests the authority will hold at
/// once, counted across every lifecycle state (pending, approved-but-not-yet
/// collected, and denial tombstones).
///
/// `SubmitCsr` is reachable on the management API's *enrollment* tier, which
/// by design admits a client holding no credential at all. Without a count
/// bound, one anonymous peer looping submissions under fabricated MACs could
/// grow this store until the node ran out of memory — and, since the store is
/// persisted, leave the growth behind across a restart. `pending_ttl_secs`
/// alone does not bound it: nothing stops submissions arriving faster than the
/// TTL retires them.
///
/// Sized for the human on the other end rather than for the memory: a queue an
/// operator is expected to read and decide row by row is unusable long before
/// 128 entries, and at a few hundred bytes apiece the whole table is tens of
/// kilobytes even when full.
pub(crate) const MAX_HELD_CSRS: usize = 128;

/// Default held-CSR lifetime when a CA is built with [`CertAuthority::new`]
/// (the config-driven constructor takes the operator's value instead): one
/// hour, long enough for an operator to approve and short enough to bound the
/// table.
const DEFAULT_PENDING_TTL_SECS: u64 = 3600;

/// Refuse a certificate lifetime past [`MAX_CERT_TTL_SECS`], unless the
/// operator took the escape.
///
/// Passive expiry is this design's primary revocation mechanism; a lifetime
/// measured in years leaves only the active flood, which needs every node to be
/// reachable.
fn check_cert_ttl(cert_ttl_secs: u64, allow_unbounded: bool) -> Result<(), String> {
    if allow_unbounded || cert_ttl_secs <= MAX_CERT_TTL_SECS {
        return Ok(());
    }
    Err(alloc::format!(
        "cert_ttl_secs is {cert_ttl_secs}s, past the {MAX_CERT_TTL_SECS}s cap: passive \
         expiry is this mesh's primary revocation mechanism, so a certificate that \
         outlives the deployment cannot be recalled without reaching every node. \
         Shorten it, or set `allow_unbounded_cert_ttl: true` to say the long lifetime \
         is deliberate"
    ))
}

impl CertAuthority {
    /// Build a CA from a 32-byte root seed and its issuance policy.  Unless
    /// `auto_approve` is set, submitted CSRs are parked as pending until an
    /// operator approves them rather than issued on submission.  Held CSRs use
    /// [`DEFAULT_PENDING_TTL_SECS`]; [`CertAuthority::from_config`] honours the
    /// operator's configured value.
    pub fn new(
        root_seed: &[u8; 32],
        mesh_id: u32,
        cert_ttl_secs: u64,
        enrollment_token: Option<String>,
        auto_approve: bool,
    ) -> Self {
        Self {
            authority: Authority::from_seed(root_seed, mesh_id),
            cert_ttl_secs,
            // Bounded unless a config says otherwise: a caller constructing an
            // authority directly (the offline `wayfinderctl cert` tooling, and
            // tests) states its lifetime per invocation rather than persisting
            // one.
            allow_unbounded_cert_ttl: false,
            enrollment_token: enrollment_token.map(SharedSecret::new),
            auto_approve,
            pending_ttl_secs: DEFAULT_PENDING_TTL_SECS,
            now_unix: 0,
            log: CaLog::empty(),
        }
    }

    /// Build a CA from a root seed and a host [`ProviderConfig`], so the call
    /// site passes one policy object rather than unpacking every field.  The
    /// seed is loaded separately (it lives in a file, not the config).
    ///
    /// When [`ProviderConfig::state_path`] is set, the issued-certificate log
    /// and held-CSR store are loaded from that snapshot so the impersonation
    /// guard, revocations, and pending approvals survive a restart; a
    /// corrupt, foreign, or newer-than-known snapshot is refused (`Err`)
    /// rather than silently treated as empty. Absent, state starts empty
    /// (in-memory only, as before).
    pub fn from_config(root_seed: &[u8; 32], cfg: &ProviderConfig) -> Result<Self, String> {
        check_cert_ttl(cfg.cert_ttl_secs, cfg.allow_unbounded_cert_ttl)?;
        let log = CaLog::load(cfg.state_path.as_ref().map(PathBuf::from))?;
        let mut ca = Self {
            pending_ttl_secs: cfg.pending_ttl_secs,
            allow_unbounded_cert_ttl: cfg.allow_unbounded_cert_ttl,
            log,
            ..Self::new(
                root_seed,
                cfg.mesh_id,
                cfg.cert_ttl_secs,
                cfg.enrollment_token.clone(),
                cfg.auto_approve,
            )
        };
        ca.apply_policy_overrides();
        Ok(ca)
    }

    /// Overlay the operator's persisted runtime policy overrides onto the
    /// fields just taken from the startup config.
    ///
    /// The overrides win, deliberately: they are the operator's most recent
    /// stated intent, and reverting to the YAML on every restart would make a
    /// setting an operator changed from the dashboard quietly undo itself. A
    /// field with no override is left following the config, so editing the
    /// YAML still moves everything the operator has not pinned — and deleting
    /// the state file returns the node wholly to its config.
    fn apply_policy_overrides(&mut self) {
        let overrides = self.log.policy().clone();
        if let Some(auto_approve) = overrides.auto_approve {
            self.auto_approve = auto_approve;
        }
        if let Some(cert_ttl_secs) = overrides.cert_ttl_secs {
            self.cert_ttl_secs = cert_ttl_secs;
        }
        match &overrides.enrollment_token {
            Some(TokenOverride::Cleared) => self.enrollment_token = None,
            Some(TokenOverride::Set(token)) => {
                self.enrollment_token = Some(SharedSecret::new(token.clone()));
            }
            None => {}
        }
        if overrides.auto_approve.is_some()
            || overrides.cert_ttl_secs.is_some()
            || overrides.enrollment_token.is_some()
        {
            tracing::info!(
                auto_approve = self.auto_approve,
                cert_ttl_secs = self.cert_ttl_secs,
                enrollment_token_set = self.enrollment_token.is_some(),
                "enrollment policy restored from persisted runtime overrides, taking \
                 precedence over the startup configuration"
            );
        }
    }

    /// The enrollment policy currently in force, for the management API to
    /// report.
    ///
    /// Says whether a token is required and never what it is. This answer rides
    /// a polled request — a dashboard asks for it once a second — so a secret
    /// on it is disclosed continuously to everything that touches the snapshot,
    /// for the sake of an operator who reads the value perhaps twice in the
    /// life of a mesh. [`admission`](Self::admission) hands the value over one
    /// request at a time instead.
    pub fn enrollment_policy(&self) -> EnrollmentPolicyStatusData {
        EnrollmentPolicyStatusData {
            auto_approve: self.auto_approve,
            cert_ttl_secs: self.cert_ttl_secs,
            enrollment_token_set: self.enrollment_token.is_some(),
        }
    }

    /// The admission rule in force, token value included — the answer to an
    /// explicit `RevealEnrollmentToken`.
    ///
    /// The operator running a provider is the one who has to hand the token to
    /// a node that is joining, and the only alternative — replacing a working
    /// token just to learn it — kicks every node still holding the old one. It
    /// travels no further than a client already authenticated as an admin or as
    /// this node, which is a client that could replace the token anyway; what
    /// the separate request buys is that each disclosure is a discrete, logged
    /// event rather than a continuous one.
    pub fn admission(&self) -> EnrollmentAdmission {
        match &self.enrollment_token {
            Some(token) => EnrollmentAdmission::Token(token.clone()),
            None => EnrollmentAdmission::Open,
        }
    }

    /// Apply a partial enrollment-policy update and record it durably.
    ///
    /// The override is persisted *before* it is applied in memory, so the two
    /// can never disagree: a failed persist leaves the authority running its
    /// previous policy and returns `Err`, rather than admitting nodes under a
    /// policy that the next restart would forget. Fields the update does not
    /// name are left alone, both in memory and on disk.
    pub fn set_enrollment_policy(&mut self, update: &EnrollmentPolicyData) -> Result<(), String> {
        // Checked before anything is written: the dashboard can set this
        // policy, so a cap enforced only on the config file would be a lock on
        // one of two doors. Refusing here leaves the previous policy running,
        // in memory and on disk both.
        if let Some(cert_ttl_secs) = update.cert_ttl_secs {
            check_cert_ttl(cert_ttl_secs, self.allow_unbounded_cert_ttl)?;
        }
        let (_, persisted) = self.log.mutate_policy(|overrides| {
            if let Some(auto_approve) = update.auto_approve {
                overrides.auto_approve = Some(auto_approve);
            }
            if let Some(cert_ttl_secs) = update.cert_ttl_secs {
                overrides.cert_ttl_secs = Some(cert_ttl_secs);
            }
            match &update.enrollment_token {
                Some(TokenUpdate::Clear) => {
                    overrides.enrollment_token = Some(TokenOverride::Cleared);
                }
                Some(TokenUpdate::Set(token)) => {
                    overrides.enrollment_token =
                        Some(TokenOverride::Set(token.expose().to_string()));
                }
                None => {}
            }
        });
        persisted?;

        // Only now that the override is durable does the live policy move. The
        // overlay is the same one a restart performs, so what runs here and
        // what runs after a restart are the same code path rather than two
        // that have to be kept in agreement.
        self.apply_policy_overrides();
        Ok(())
    }

    /// Update the current wall-clock time (unix seconds) used to stamp issued
    /// certificate / revocation validity windows.  Called by the driver before
    /// serving a request, the same way the router's auth clock is refreshed.
    pub fn set_now_unix(&mut self, now_unix: u64) {
        self.now_unix = now_unix;
    }

    /// The mesh id this authority signs for.
    pub fn mesh_id(&self) -> u32 {
        self.authority.mesh_id()
    }

    /// Sign a certificate for `(mac, ed, x)` stamped with the current clock,
    /// record it for the `ListCerts` RPC, and return the cert plus the trust
    /// anchor it chains to.  The caller must have checked the clock is set.
    /// `pub(crate)` so in-crate tests can mint a cert directly rather than
    /// round-tripping the client-facing `submit_csr` path. `Err` if the
    /// signed cert could not be durably persisted — the cert is still valid
    /// (signing is stateless local computation, not rolled back), but the
    /// *record* of it never took effect (see `CaLog::mutate_issued`'s
    /// rollback guarantee), so a caller must not tell its own caller this
    /// succeeded when the durability guarantee it implies did not hold.
    pub(crate) fn issue(
        &mut self,
        mac: Mac,
        ed: [u8; 32],
        x: [u8; 32],
    ) -> Result<EnrollData, String> {
        let (cert, record) = self.sign(mac, ed, x);

        // Record (or refresh, by MAC) the issued cert for the ListCerts RPC.
        // A re-issue clears any prior revoked flag (it is a fresh certificate).
        let (_, persisted) = self.log.mutate_issued(|issued| {
            match issued.iter_mut().find(|c| c.node_mac == record.node_mac) {
                Some(existing) => *existing = record,
                None => issued.push(record),
            }
        });
        persisted?;

        Ok(EnrollData {
            cert: cert.as_bytes().to_vec(),
            trust_anchor: self.trust_anchor_bytes(),
        })
    }

    /// Sign a certificate for `(mac, ed, x)` stamped with the current clock
    /// and build its `IssuedCertData` record, without persisting anything.
    /// Signing is stateless local computation with nothing to roll back, so
    /// it's split out from persistence deliberately: callers decide
    /// separately *how* the record gets durably written — [`Self::issue`]
    /// persists it alone (a single `mutate_issued` write), while
    /// `approve_csr` persists it together with the held-CSR status flip as
    /// one atomic write via `CaLog::mutate_issued_and_held`, so the two
    /// halves of an approval can never durably split (see that method's own
    /// doc for the impersonation-guard gap this closes).
    fn sign(&self, mac: Mac, ed: [u8; 32], x: [u8; 32]) -> (MembershipCert, IssuedCertData) {
        let not_before = self.now_unix;
        let not_after = self.now_unix.saturating_add(self.cert_ttl_secs);
        let cert = self.authority.issue_cert(mac, ed, x, not_before, not_after);
        let record = IssuedCertData {
            node_mac: mac.0.to_vec(),
            ed_pubkey: ed.to_vec(),
            not_before,
            not_after,
            revoked: false,
            user: false,
            admin: false,
            viewer: false,
        };
        (cert, record)
    }

    /// Sign a *user session* certificate for `(mac, ed, x)` with `ttl_secs` of
    /// validity and the capability `role` names, and build its record.
    ///
    /// Separate from [`Self::sign`] rather than a flags argument on it, for the
    /// same reason `issue_admin_cert` is separate from `issue_cert`: the two
    /// produce different kinds of credential, and a call site should say which
    /// it means. The lifetime is the account's, not this authority's
    /// `cert_ttl_secs` — §7 decision 3 of the design puts it with the admin who
    /// granted the account — but is still bounded by the same cap the config
    /// path applies.
    fn sign_user_session(
        &self,
        mac: Mac,
        ed: [u8; 32],
        x: [u8; 32],
        ttl_secs: u64,
        role: UserRole,
    ) -> (MembershipCert, IssuedCertData) {
        let admin = role == UserRole::Admin;
        let not_before = self.now_unix;
        let not_after = self.now_unix.saturating_add(ttl_secs);
        let cert = self
            .authority
            .issue_user_cert(mac, ed, x, not_before, not_after, admin);
        let record = IssuedCertData {
            node_mac: mac.0.to_vec(),
            ed_pubkey: ed.to_vec(),
            not_before,
            not_after,
            revoked: false,
            user: true,
            admin,
            viewer: !admin,
        };
        (cert, record)
    }

    /// Add a user account, refusing a name that already exists.
    ///
    /// Two callers, and the *first* one is the reason this is a method at all:
    /// `wayfinderctl user add`, operating directly on the state file the
    /// provider owns, because the first account cannot be created over the
    /// management API — creating it needs the very credential it creates. The
    /// second is `MeshAuthority::create_user`, which is that same act performed
    /// by an already-admitted administrator over the wire.
    pub fn add_user(&mut self, user: UserRecord) -> Result<(), String> {
        if user.username.is_empty() {
            return Err("username must not be empty".to_string());
        }
        if self.log.users().iter().any(|u| u.username == user.username) {
            return Err(alloc::format!("user {} already exists", user.username));
        }
        let (_, persisted) = self.log.mutate_users(|users| users.push(user));
        persisted
    }

    /// The user accounts on file, for an operator listing them. Never carries a
    /// password hash or a TOTP secret out of this module: the caller gets the
    /// account's name, role, lifetime and status, which is what an operator
    /// asking "who can log in?" wants and all of it.
    pub fn list_users(&self) -> Vec<UserSummary> {
        self.log
            .users()
            .iter()
            .map(|u| UserSummary {
                username: u.username.clone(),
                role: u.role,
                session_ttl_secs: u.session_ttl_secs,
                totp_enrolled: u.totp_secret.is_some(),
                disabled: u.disabled,
                locked: u.is_locked(self.now_unix),
            })
            .collect()
    }

    /// Apply `f` to the named account and persist the result, or `Err` if no
    /// such account exists.
    ///
    /// The single mutation seam for an existing account — disabling one,
    /// resetting a password, changing a role or a session lifetime — so every
    /// change goes through one persist with one rollback guarantee rather than
    /// each caller opening the store for itself.
    pub fn update_user(
        &mut self,
        username: &str,
        f: impl FnOnce(&mut UserRecord),
    ) -> Result<(), String> {
        let (found, persisted) = self.log.mutate_users(|users| {
            match users.iter_mut().find(|u| u.username == username) {
                Some(user) => {
                    f(user);
                    true
                }
                None => false,
            }
        });
        if !found {
            return Err(alloc::format!("no such user: {username}"));
        }
        persisted
    }

    /// Remove the named account. A certificate it has already been issued is
    /// unaffected — that is what `RevokeNode` and expiry are for — so this ends
    /// the ability to obtain *new* sessions, not any session in flight.
    ///
    /// The raw store operation, with no policy on top: it will remove the last
    /// administrator. That is deliberate, and it is why `wayfinderctl user
    /// remove` is the documented way out of a mesh nobody can administer.
    /// [`MeshAuthority::remove_user`] is the same act performed over the
    /// management API, and *that* one refuses to strand the mesh — the caller
    /// there is a browser one click away from it, not an operator with a shell
    /// on this host.
    pub fn remove_user(&mut self, username: &str) -> Result<(), String> {
        let (found, persisted) = self.log.mutate_users(|users| {
            let before = users.len();
            users.retain(|u| u.username != username);
            users.len() != before
        });
        if !found {
            return Err(alloc::format!("no such user: {username}"));
        }
        persisted
    }

    /// Whether a held CSR has sat in its current state past the pending TTL.
    /// Never true before the clock is set (`now_unix == 0`), so a CA that has
    /// not yet learned the time does not evict everything as "expired".
    fn is_expired(&self, held: &HeldCsr) -> bool {
        self.now_unix != 0
            && self.now_unix.saturating_sub(held.requested_at) > self.pending_ttl_secs
    }

    /// Drop held CSRs that have timed out.  Called at the start of every poll
    /// and operator mutation so a stale request — never approved, approved but
    /// never collected, or a denial tombstone — is reclaimed and the table stays
    /// bounded. A no-op (and no persist) when nothing has actually timed out,
    /// so a routine poll that evicts nothing doesn't touch disk.
    fn evict_expired(&mut self) -> Result<(), String> {
        if self.now_unix == 0 {
            return Ok(());
        }
        let now = self.now_unix;
        let ttl = self.pending_ttl_secs;
        let has_expired = self
            .log
            .held()
            .iter()
            .any(|h| now.saturating_sub(h.requested_at) > ttl);
        if has_expired {
            let (_, persisted) = self
                .log
                .mutate_held(|held| held.retain(|h| now.saturating_sub(h.requested_at) <= ttl));
            persisted?;
        }
        Ok(())
    }
}

/// Convert a byte slice to a fixed array, with a descriptive error.
fn fixed<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], String> {
    bytes
        .try_into()
        .map_err(|_| alloc::format!("{what} must be {N} bytes"))
}

/// Parse a 6-byte node MAC from a wire slice, with a descriptive error, so the
/// enrollment methods below don't each open-code the length check and label.
fn node_mac_of(bytes: &[u8]) -> Result<Mac, String> {
    Mac::try_from(bytes).map_err(|_| "node_mac must be 6 bytes".to_string())
}

/// One user account as an operator sees it.
///
/// Deliberately not [`UserRecord`]: the record carries a password hash and a
/// TOTP secret, and neither should leave the store at all — a summary type
/// makes that a property of the API rather than of every call site remembering
/// which fields not to print.
#[derive(Clone, Debug)]
pub struct UserSummary {
    /// The account name.
    pub username: String,
    /// The capability this account's session certificates carry.
    pub role: UserRole,
    /// The validity window stamped on those certificates, in seconds.
    pub session_ttl_secs: u64,
    /// Whether a second factor is enrolled.
    pub totp_enrolled: bool,
    /// Whether the account is administratively disabled.
    pub disabled: bool,
    /// Whether the account is currently locked out by failed attempts.
    pub locked: bool,
}

impl MeshAuthority for CertAuthority {
    fn trust_anchor_bytes(&self) -> Vec<u8> {
        self.authority.trust_anchor().to_bytes().to_vec()
    }

    fn authenticate_user(
        &mut self,
        username: &str,
        password: &str,
        totp_code: &str,
        ed_pubkey: &[u8],
        x_pubkey: &[u8],
    ) -> Result<UserAuthOutcome, String> {
        // Same fail-closed rule as `submit_csr`: without a clock this would
        // mint a session whose window starts at the epoch and is already over.
        if self.now_unix == 0 {
            return Err("authority clock not set; cannot issue certificates yet".to_string());
        }
        // Malformed keys are an *unserviceable request*, not a wrong password,
        // and are refused before any credential is looked at — a client that
        // sent 31 bytes has a bug, and telling it so reveals nothing about
        // whether the account exists.
        let ed = fixed::<32>(ed_pubkey, "ed_pubkey")?;
        let x = fixed::<32>(x_pubkey, "x_pubkey")?;

        let now = self.now_unix;
        let name = username.to_string();
        // The whole attempt runs inside one `mutate_users` call, so the record
        // it leaves behind — an advanced replay guard on success, an
        // incremented failure count on failure — is persisted by the same
        // write. A failed attempt that is not durably counted is a lockout an
        // attacker can reset by making the process restart.
        let (outcome, persisted) = self.log.mutate_users(|users| {
            match users.iter_mut().find(|u| u.username == name) {
                Some(user) => {
                    let outcome = user.authenticate(password, totp_code, now);
                    (outcome, user.role, user.session_ttl_secs)
                }
                None => {
                    // Spend the work a real verification would have cost, or
                    // the response time answers the question the uniform
                    // rejection refuses to.
                    crate::users::spend_absent_user_work(password);
                    (AuthOutcome::Rejected, UserRole::Viewer, 0)
                }
            }
        });
        persisted?;

        let (outcome, role, ttl_secs) = outcome;
        if outcome == AuthOutcome::Rejected {
            // No reason, here or anywhere above this: wrong password, wrong
            // code, unknown account, locked and disabled are one answer.
            tracing::warn!(%username, "drop: user authentication denied");
            return Ok(UserAuthOutcome::Rejected);
        }

        // The account's lifetime, still bounded by the cap the config path
        // applies — an admin may grant a shift or a minute, but not a decade.
        check_cert_ttl(ttl_secs, self.allow_unbounded_cert_ttl)?;
        // A user's MAC is derived from the session key it just presented, so it
        // is fresh on every login and can never contend with a device's:
        // `submit_csr`'s impersonation guard is about MACs a client *names*,
        // and this one is not named by anybody.
        let mac = wayfinder_auth::derive_mac(&ed);
        let (cert, record) = self.sign_user_session(mac, ed, x, ttl_secs, role);

        let (_, persisted) = self.log.mutate_issued(|issued| {
            // Drop session records that have expired before adding this one.
            // A device re-enrolling replaces its record in place (the MAC is
            // stable), but a login mints a new MAC every time, so without this
            // the log would grow by one entry per login forever. Only expired
            // *user* records go: a device's history is not this path's to
            // discard, and a live session's record is what `RevokeNode` and
            // `ListCerts` are reading.
            issued.retain(|c| !(c.user && c.not_after <= now));
            match issued.iter_mut().find(|c| c.node_mac == record.node_mac) {
                Some(existing) => *existing = record,
                None => issued.push(record),
            }
        });
        persisted?;

        tracing::info!(%username, ?role, ttl_secs, "issued a user session certificate");
        Ok(UserAuthOutcome::Issued(EnrollData {
            cert: cert.as_bytes().to_vec(),
            trust_anchor: self.trust_anchor_bytes(),
        }))
    }

    fn submit_csr(
        &mut self,
        node_mac: &[u8],
        ed_pubkey: &[u8],
        x_pubkey: &[u8],
        token: &str,
    ) -> Result<CsrOutcome, String> {
        // The clock must have been set (via `set_now_unix`), or we'd issue a cert
        // whose validity window starts at the unix epoch and is already expired
        // against any real wall clock.  Fail closed.
        if self.now_unix == 0 {
            return Err("authority clock not set; cannot issue certificates yet".to_string());
        }
        // Reclaim any timed-out held requests before consulting the store, so a
        // stale entry frees the MAC for this poll (the escape hatch for a
        // genuine re-key: wait out the TTL, then re-submit).
        self.evict_expired()?;
        // A plain `!=` is sufficient: the enrollment token is a *shared* secret
        // over a network management API, not a per-user credential, so a
        // byte-compare timing side-channel is not a realistic threat (network
        // jitter dwarfs it) and a constant-time compare would add no security.
        // A bad token is a policy *rejection* of a well-formed CSR, and must not
        // touch the held-CSR store (so it can't clobber a legitimate pending
        // request for the same MAC).
        if let Some(expected) = &self.enrollment_token
            && token != expected.expose()
        {
            return Ok(CsrOutcome::Rejected(
                "invalid or missing enrollment token".to_string(),
            ));
        }
        let mac = node_mac_of(node_mac)?;
        let ed = fixed::<32>(ed_pubkey, "ed_pubkey")?;
        let x = fixed::<32>(x_pubkey, "x_pubkey")?;

        // A MAC that already holds a still-valid, non-revoked certificate is handled off
        // `issued` (not `held`, which is evicted at pending_ttl) so protection outlives the
        // held entry: the holder's own re-enrolment under the same ed key is re-issued
        // immediately (never re-parked for approval again — a duplicate MAC must not create
        // another held entry), while a *different* key claiming that MAC is rejected (a
        // second live cert for one MAC would let a new key impersonate the holder). The MAC
        // stays protected until its cert passively expires, the point at which re-keying is safe.
        if let Some(same_key) = self
            .log
            .issued()
            .iter()
            .find(|c| c.node_mac == mac.0 && !c.revoked && self.now_unix <= c.not_after)
            .map(|c| c.ed_pubkey == ed)
        {
            return Ok(if same_key {
                CsrOutcome::Issued(self.issue(mac, ed, x)?)
            } else {
                CsrOutcome::Rejected(
                    "this MAC already has a valid certificate under a different key".to_string(),
                )
            });
        }

        // Approval is automatic: sign immediately.
        if self.auto_approve {
            return Ok(CsrOutcome::Issued(self.issue(mac, ed, x)?));
        }

        // Approval required: consult the held-CSR store, keyed by MAC.  The
        // first identity to submit for a MAC owns the slot until it is decided
        // and collected or evicted.
        if let Some(idx) = self.log.held().iter().position(|h| h.node_mac == mac.0) {
            // Same identity re-polling: report the request's current disposition.
            if self.log.held()[idx].ed_pubkey == ed && self.log.held()[idx].x_pubkey == x {
                return Ok(match &self.log.held()[idx].status {
                    CsrStatus::Pending => CsrOutcome::Pending,
                    CsrStatus::Approved(cert) => CsrOutcome::Issued(EnrollData {
                        cert: cert.clone(),
                        trust_anchor: self.trust_anchor_bytes(),
                    }),
                    CsrStatus::Denied(reason) => CsrOutcome::Rejected(reason.clone()),
                });
            }
            // A *different* identity is claiming a MAC that is already held
            // (pending review, issued, or a denial tombstone).  Reject rather
            // than supersede: this keeps the key material an operator reviews
            // immutable through approval (no swap-after-review race) and stops a
            // new key from re-opening a MAC that already has an issued cert.  A
            // legitimate re-key waits out the pending TTL, which frees the slot.
            return Ok(CsrOutcome::Rejected(
                "a certificate-signing request for this MAC is already held under a different key"
                    .to_string(),
            ));
        }

        // First time we've seen this MAC — but only if there is room. Refusing
        // rather than evicting to make room is the point: an eviction policy
        // hands an attacker exactly the primitive they want, since submitting
        // enough requests would displace a legitimate pending one. Refusing
        // degrades instead to "the queue is full, an operator must drain it",
        // which is visible in `list_pending` and recoverable. Only *new*
        // entries are gated; every path above — an existing holder re-polling,
        // or collecting an approved cert — has already returned.
        if self.log.held().len() >= MAX_HELD_CSRS {
            // A capacity drop that is security-relevant and reachable by a peer
            // presenting no credential, so the operator whose enrollment queue
            // has just stopped accepting anyone hears about it. The MAC is not
            // a secret (every OGM carries one), and it is what an operator
            // needs to tell a stuck node from a flood.
            tracing::warn!(
                held = self.log.held().len(),
                capacity = MAX_HELD_CSRS,
                node_mac = ?mac,
                "drop: held-CSR store full; refusing a new enrollment request"
            );
            return Ok(CsrOutcome::Rejected(
                "the provider's certificate-signing queue is full; an operator must \
                 approve or deny the requests already held before new ones are accepted"
                    .to_string(),
            ));
        }
        let requested_at = self.now_unix;
        let (_, persisted) = self.log.mutate_held(|held| {
            held.push(HeldCsr {
                node_mac: mac.0,
                ed_pubkey: ed,
                x_pubkey: x,
                requested_at,
                status: CsrStatus::Pending,
            });
        });
        persisted?;
        Ok(CsrOutcome::Pending)
    }

    fn list_pending(&self) -> Vec<PendingCsrData> {
        self.log
            .held()
            .iter()
            .filter(|h| matches!(h.status, CsrStatus::Pending) && !self.is_expired(h))
            .map(|h| PendingCsrData {
                node_mac: h.node_mac.to_vec(),
                ed_pubkey: h.ed_pubkey.to_vec(),
                x_pubkey: h.x_pubkey.to_vec(),
                requested_at: h.requested_at,
            })
            .collect()
    }

    fn approve_csr(&mut self, node_mac: &[u8]) -> Result<(), String> {
        if self.now_unix == 0 {
            return Err("authority clock not set; cannot issue certificates yet".to_string());
        }
        let mac = node_mac_of(node_mac)?;
        self.evict_expired()?;
        let idx = self
            .log
            .held()
            .iter()
            .position(|h| h.node_mac == mac.0 && matches!(h.status, CsrStatus::Pending))
            .ok_or_else(|| alloc::format!("no pending CSR for {:02x?}", mac.0))?;
        let (ed, x) = (
            self.log.held()[idx].ed_pubkey,
            self.log.held()[idx].x_pubkey,
        );
        // Sign now (stamping the current clock) and stash the bytes; the node
        // collects them on its next poll.  Restart the entry's TTL clock so the
        // node gets a full pending-TTL window to collect from the approval.
        let (cert, record) = self.sign(mac, ed, x);
        let cert_bytes = cert.as_bytes().to_vec();
        let now = self.now_unix;
        // Record the issued cert *and* flip the held entry to Approved as one
        // write: doing these as two separate `mutate_issued`/`mutate_held`
        // calls (as this used to) left a real gap under `Persisted`'s
        // rollback — if only the second write failed, the held entry would
        // roll back to `Pending` while the cert stayed durably `issued`. An
        // operator seeing "approve failed" who then called `deny_csr` would
        // find a `Pending` entry and "successfully" deny it, but `deny_csr`
        // only ever touches `held`, so the already-issued, still-valid
        // certificate would never be revoked. Combining them means either
        // both land durably or neither does.
        let (_, persisted) = self.log.mutate_issued_and_held(|issued, held| {
            match issued.iter_mut().find(|c| c.node_mac == record.node_mac) {
                Some(existing) => *existing = record,
                None => issued.push(record),
            }
            held[idx].status = CsrStatus::Approved(cert_bytes);
            held[idx].requested_at = now;
        });
        persisted?;
        Ok(())
    }

    fn deny_csr(&mut self, node_mac: &[u8]) -> Result<(), String> {
        let mac = node_mac_of(node_mac)?;
        self.evict_expired()?;
        let idx = self
            .log
            .held()
            .iter()
            .position(|h| h.node_mac == mac.0 && matches!(h.status, CsrStatus::Pending))
            .ok_or_else(|| alloc::format!("no pending CSR for {:02x?}", mac.0))?;
        let now = self.now_unix;
        let (_, persisted) = self.log.mutate_held(|held| {
            held[idx].status = CsrStatus::Denied("denied by operator".to_string());
            // Restart the TTL clock so the denial tombstone lives a full
            // pending-TTL window (letting a polling node observe the
            // rejection before eviction).
            held[idx].requested_at = now;
        });
        persisted?;
        Ok(())
    }

    fn list_users(&self) -> Vec<wayfinder_protos::service::UserAccountData> {
        self.list_users()
            .into_iter()
            .map(|u| wayfinder_protos::service::UserAccountData {
                username: u.username,
                admin: u.role == UserRole::Admin,
                session_ttl_secs: u.session_ttl_secs,
                totp_enrolled: u.totp_enrolled,
                disabled: u.disabled,
                locked: u.locked,
            })
            .collect()
    }

    fn create_user(
        &mut self,
        username: &str,
        password: &str,
        admin: bool,
        session_ttl_secs: u64,
        no_totp: bool,
    ) -> Result<String, String> {
        let role = if admin {
            UserRole::Admin
        } else {
            UserRole::Viewer
        };
        let ttl = if session_ttl_secs == 0 {
            crate::users::DEFAULT_SESSION_TTL_SECS
        } else {
            session_ttl_secs
        };
        // Refused here rather than at the first login it makes impossible: an
        // account whose sessions the provider will not sign is an account that
        // looks created and is not usable, and the operator finds out from
        // somebody else's failed sign-in.
        check_cert_ttl(ttl, self.allow_unbounded_cert_ttl)?;

        let mut user = UserRecord::new(username, password, role, ttl)?;
        if no_totp {
            user = user.without_totp();
        }
        // Read out before the record moves into the store: this is the only
        // moment the secret is available, here or anywhere else.
        let uri = user.totp_enrolment_uri("wayfinder").unwrap_or_default();
        self.add_user(user)?;
        Ok(uri)
    }

    fn remove_user(&mut self, username: &str) -> Result<(), String> {
        // Counted before the removal rather than after, so the check reads as
        // the question being asked: would this leave the mesh with nobody who
        // can administer it? A disabled account is not an answer to that — it
        // obtains no session and so administers nothing.
        let last_admin = self
            .log
            .users()
            .iter()
            .filter(|u| u.role == UserRole::Admin && !u.disabled)
            .all(|u| u.username == username);
        let is_enabled_admin = self
            .log
            .users()
            .iter()
            .any(|u| u.username == username && u.role == UserRole::Admin && !u.disabled);
        if is_enabled_admin && last_admin {
            return Err(
                "refusing to remove the last administrator: no account would be left that can \
                 administer this mesh over the management API. Create another administrator \
                 first, or remove this one with `wayfinderctl user remove` on the provider host."
                    .to_string(),
            );
        }
        CertAuthority::remove_user(self, username)
    }

    fn revoke(&mut self, node_mac: &[u8]) -> Result<Vec<u8>, String> {
        if self.now_unix == 0 {
            return Err("authority clock not set; cannot sign revocations yet".to_string());
        }
        let mac = node_mac_of(node_mac)?;
        // The revocation must outlive any cert we issued for the node, so reuse
        // the same ttl window from now; passive expiry then takes over.
        let not_after = self.now_unix.saturating_add(self.cert_ttl_secs);
        let record = self.authority.revoke(mac, self.now_unix, not_after);

        // Mark the issued entry revoked (retained for ListCerts observability).
        let (_, persisted) = self.log.mutate_issued(|issued| {
            if let Some(entry) = issued.iter_mut().find(|c| c.node_mac == mac.0) {
                entry.revoked = true;
            }
        });
        persisted?;

        Ok(record.as_bytes().to_vec())
    }

    fn list_certs(&self) -> Vec<IssuedCertData> {
        self.log.issued().to_vec()
    }

    fn enrollment_policy(&self) -> EnrollmentPolicyStatusData {
        CertAuthority::enrollment_policy(self)
    }

    fn admission(&self) -> EnrollmentAdmission {
        CertAuthority::admission(self)
    }

    fn set_enrollment_policy(&mut self, update: &EnrollmentPolicyData) -> Result<(), String> {
        CertAuthority::set_enrollment_policy(self, update)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wayfinder_auth::Keypair;
    use wayfinder_auth::MembershipCert;
    use wayfinder_auth::RevocationRecord;
    use wayfinder_auth::TrustAnchor;
    use zerocopy::FromBytes;

    fn node_keys(seed: u8) -> ([u8; 32], [u8; 32]) {
        let kp = Keypair::from_seed(&[seed; 32]);
        (kp.ed_pubkey(), kp.x_pubkey())
    }

    /// A CA with an already-set clock and no approval gate (the common setup).
    fn open_ca() -> CertAuthority {
        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None, true);
        ca.set_now_unix(100);
        ca
    }

    /// Submit a CSR and require it to have issued, returning the cert bytes.
    fn issued_cert(
        ca: &mut CertAuthority,
        mac: &[u8],
        ed: &[u8],
        x: &[u8],
        token: &str,
    ) -> Vec<u8> {
        match ca.submit_csr(mac, ed, x, token).unwrap() {
            CsrOutcome::Issued(data) => data.cert,
            other => panic!("expected Issued, got {other:?}"),
        }
    }

    /// Build a CA with one account, returning the CA and the account's TOTP
    /// secret so a test can compute a live code.
    fn ca_with_user(role: UserRole, ttl_secs: u64) -> (CertAuthority, Vec<u8>) {
        let mut ca = open_ca();
        let user = UserRecord::new("ops", "hunter2", role, ttl_secs).unwrap();
        let secret = user.totp_secret.clone().unwrap();
        ca.add_user(user).unwrap();
        (ca, secret)
    }

    /// The current TOTP code for `secret` at the CA's clock.
    fn live_code(secret: &[u8], now: u64) -> String {
        crate::users::totp_code_for_tests(secret, now)
    }

    /// The whole login: correct credentials yield a certificate that verifies
    /// against this CA's own anchor, carries the account's capability and the
    /// user bit, and is bound to the session key the client named.
    #[test]
    fn a_valid_login_issues_a_session_certificate() {
        let (mut ca, secret) = ca_with_user(UserRole::Admin, 900);
        let (ed, x) = node_keys(2);
        let code = live_code(&secret, 100);

        let data = match ca
            .authenticate_user("ops", "hunter2", &code, &ed, &x)
            .unwrap()
        {
            UserAuthOutcome::Issued(data) => data,
            other => panic!("expected Issued, got {other:?}"),
        };

        let anchor = TrustAnchor::from_bytes(&data.trust_anchor).unwrap();
        let cert = MembershipCert::from_bytes(&data.cert).unwrap();
        let verified = anchor.verify_cert(&cert, 500).expect("verifies in window");

        assert!(verified.user, "a session certificate carries the user bit");
        assert!(
            verified.admin,
            "an Admin account mints an admin certificate"
        );
        assert!(
            !verified.viewer,
            "admin subsumes viewer rather than joining it"
        );
        assert_eq!(verified.ed_pubkey, ed, "bound to the key the client named");
        assert_eq!(
            verified.not_after,
            100 + 900,
            "the account's own lifetime, not the authority's cert_ttl_secs"
        );
        // The MAC is derived from the session key, so it is the CA's to compute
        // and never contends with a device MAC a client could name.
        assert_eq!(verified.mac, wayfinder_auth::derive_mac(&ed));
    }

    /// A Viewer account mints a read-only certificate. §7 decision 3: the role
    /// is the account's, so this is the same code path with one field changed
    /// rather than a different request.
    #[test]
    fn a_viewer_account_mints_a_viewer_certificate() {
        let (mut ca, secret) = ca_with_user(UserRole::Viewer, 900);
        let (ed, x) = node_keys(2);
        let code = live_code(&secret, 100);

        let data = match ca
            .authenticate_user("ops", "hunter2", &code, &ed, &x)
            .unwrap()
        {
            UserAuthOutcome::Issued(data) => data,
            other => panic!("expected Issued, got {other:?}"),
        };
        let anchor = TrustAnchor::from_bytes(&data.trust_anchor).unwrap();
        let verified = anchor
            .verify_cert(&MembershipCert::from_bytes(&data.cert).unwrap(), 500)
            .unwrap();
        assert!(verified.viewer && !verified.admin && verified.user);
    }

    /// Every wrong-credential path is `Ok(Rejected)`, never `Err`: `Err` is for
    /// an unserviceable request and carries a message, which is exactly what a
    /// guessing client must not get.
    #[test]
    fn wrong_credentials_are_a_rejection_not_an_error() {
        let (mut ca, secret) = ca_with_user(UserRole::Admin, 900);
        let (ed, x) = node_keys(2);
        let code = live_code(&secret, 100);

        for (label, user, password, totp) in [
            ("wrong password", "ops", "wrong", code.as_str()),
            ("wrong code", "ops", "hunter2", "000000"),
            ("unknown account", "nobody", "hunter2", code.as_str()),
        ] {
            assert!(
                matches!(
                    ca.authenticate_user(user, password, totp, &ed, &x).unwrap(),
                    UserAuthOutcome::Rejected
                ),
                "{label} must be a rejection"
            );
        }
    }

    /// A code is spent once. The skew window makes three codes live at any
    /// instant, so without the replay guard a code seen in transit would stay
    /// usable — and here that would mean a second session certificate.
    #[test]
    fn a_login_code_cannot_be_replayed() {
        let (mut ca, secret) = ca_with_user(UserRole::Admin, 900);
        let (ed, x) = node_keys(2);
        let code = live_code(&secret, 100);

        assert!(matches!(
            ca.authenticate_user("ops", "hunter2", &code, &ed, &x)
                .unwrap(),
            UserAuthOutcome::Issued(_)
        ));
        assert!(matches!(
            ca.authenticate_user("ops", "hunter2", &code, &ed, &x)
                .unwrap(),
            UserAuthOutcome::Rejected
        ));
    }

    /// A disabled account cannot log in even with correct credentials — which
    /// is the point of the flag: an operator cuts an account off now, rather
    /// than waiting for a certificate to expire.
    #[test]
    fn a_disabled_account_cannot_log_in() {
        let (mut ca, secret) = ca_with_user(UserRole::Admin, 900);
        let (ed, x) = node_keys(2);
        ca.update_user("ops", |u| u.disabled = true).unwrap();
        let code = live_code(&secret, 100);

        assert!(matches!(
            ca.authenticate_user("ops", "hunter2", &code, &ed, &x)
                .unwrap(),
            UserAuthOutcome::Rejected
        ));
    }

    /// A session certificate is recorded for `ListCerts` and flagged as a
    /// user's, and expired session records are reclaimed rather than
    /// accumulating one per login forever — a user's MAC is fresh every time,
    /// so nothing else would ever replace them.
    #[test]
    fn session_records_are_listed_and_expired_ones_reclaimed() {
        let (mut ca, secret) = ca_with_user(UserRole::Admin, 900);
        let (ed, x) = node_keys(2);

        let code = live_code(&secret, 100);
        ca.authenticate_user("ops", "hunter2", &code, &ed, &x)
            .unwrap();
        let listed = ca.list_certs();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].user && listed[0].admin);

        // Well past the first session's expiry, with a different session key:
        // the stale record goes and the new one takes its place.
        ca.set_now_unix(10_000);
        let (ed2, x2) = node_keys(3);
        let code = live_code(&secret, 10_000);
        ca.authenticate_user("ops", "hunter2", &code, &ed2, &x2)
            .unwrap();
        let listed = ca.list_certs();
        assert_eq!(listed.len(), 1, "the expired session record was reclaimed");
        assert_eq!(listed[0].ed_pubkey, ed2.to_vec());
    }

    /// A device's issued record is *not* reclaimed by a login, however stale:
    /// a device's history — and its revocation flag — is not this path's to
    /// discard.
    #[test]
    fn a_login_does_not_reclaim_a_device_record() {
        let (mut ca, secret) = ca_with_user(UserRole::Admin, 900);
        let (dev_ed, dev_x) = node_keys(4);
        issued_cert(&mut ca, &[0, 0, 0, 0, 0, 9], &dev_ed, &dev_x, "");

        ca.set_now_unix(10_000_000);
        let (ed, x) = node_keys(2);
        let code = live_code(&secret, 10_000_000);
        ca.authenticate_user("ops", "hunter2", &code, &ed, &x)
            .unwrap();

        assert_eq!(
            ca.list_certs().iter().filter(|c| !c.user).count(),
            1,
            "the long-expired device record is still on file"
        );
    }

    /// Adding a duplicate account name is refused, and the summary an operator
    /// reads carries no password hash or TOTP secret.
    #[test]
    fn user_administration_refuses_duplicates_and_leaks_no_secrets() {
        let (mut ca, _) = ca_with_user(UserRole::Admin, 900);
        assert!(
            ca.add_user(UserRecord::new("ops", "other", UserRole::Viewer, 60).unwrap())
                .is_err()
        );

        let summaries = ca.list_users();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].username, "ops");
        assert_eq!(summaries[0].role, UserRole::Admin);
        assert!(summaries[0].totp_enrolled);
        assert!(!summaries[0].disabled && !summaries[0].locked);

        ca.remove_user("ops").unwrap();
        assert!(ca.list_users().is_empty());
        assert!(ca.remove_user("ops").is_err());
    }

    /// Removing an account over the management API is refused when it is the
    /// last one that can still administer the mesh.
    ///
    /// `RemoveUser` needs a full management grant, and in login mode only an
    /// admin account's session can obtain one — so an authority left with no
    /// enabled administrator is one whose user store cannot be changed over the
    /// network at all, in either direction. The way back is `wayfinderctl user
    /// add` on the provider host, which needs a shell there and a maintenance
    /// window. One unconfirmed click should not cost that.
    ///
    /// The guard is on this path and deliberately not on the inherent
    /// [`CertAuthority::remove_user`], which is the offline tool's raw store
    /// operation and the recovery path this refusal points at.
    #[test]
    fn removing_the_last_administrator_is_refused_over_the_api() {
        let (mut ca, _) = ca_with_user(UserRole::Admin, 900);
        ca.add_user(UserRecord::new("watcher", "other-password", UserRole::Viewer, 900).unwrap())
            .unwrap();

        // A viewer goes freely: the mesh is still administrable without it.
        MeshAuthority::remove_user(&mut ca, "watcher").unwrap();

        let err = MeshAuthority::remove_user(&mut ca, "ops").unwrap_err();
        assert!(
            err.contains("administrator"),
            "the refusal says what it is protecting, so an operator can act on \
             it rather than retry it: {err}"
        );
        assert_eq!(ca.list_users().len(), 1, "and the account is still there");
    }

    /// A second administrator makes the first removable — but only while it can
    /// actually sign in. A disabled account obtains no session and so
    /// administers nothing, which makes "there are two admins on file" the
    /// wrong question to ask.
    #[test]
    fn a_disabled_administrator_is_not_the_one_left_standing() {
        let (mut ca, _) = ca_with_user(UserRole::Admin, 900);
        ca.add_user(UserRecord::new("second", "other-password", UserRole::Admin, 900).unwrap())
            .unwrap();
        ca.update_user("second", |user| user.disabled = true)
            .unwrap();

        assert!(
            MeshAuthority::remove_user(&mut ca, "ops").is_err(),
            "the only account that can still administer the mesh is not removable"
        );

        ca.update_user("second", |user| user.disabled = false)
            .unwrap();
        MeshAuthority::remove_user(&mut ca, "ops").unwrap();
        assert_eq!(ca.list_users().len(), 1);
    }

    /// An unknown name is an error rather than a silent success: whoever typed
    /// it has a wrong idea about the roster, and reporting nothing leaves them
    /// with it.
    #[test]
    fn removing_an_unknown_account_is_refused() {
        let (mut ca, _) = ca_with_user(UserRole::Admin, 900);
        assert!(MeshAuthority::remove_user(&mut ca, "nobody").is_err());
    }

    /// A login is refused before the clock is set, for the same reason a CSR
    /// is: the certificate's window would start at the epoch and be over
    /// already.
    #[test]
    fn a_login_is_refused_before_the_clock_is_set() {
        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None, true);
        ca.add_user(UserRecord::new("ops", "hunter2", UserRole::Admin, 900).unwrap())
            .unwrap();
        let (ed, x) = node_keys(2);
        assert!(
            ca.authenticate_user("ops", "hunter2", "000000", &ed, &x)
                .is_err()
        );
    }

    #[test]
    fn issued_cert_verifies_against_the_anchor() {
        let mut ca = open_ca();
        let (ed, x) = node_keys(2);
        let cert_bytes = issued_cert(&mut ca, &[0, 0, 0, 0, 0, 9], &ed, &x, "");

        let anchor = TrustAnchor::from_bytes(&ca.trust_anchor_bytes()).unwrap();
        let cert = MembershipCert::from_bytes(&cert_bytes).unwrap();
        let verified = anchor.verify_cert(&cert, 500).expect("verifies in window");
        assert_eq!(verified.mac.0, [0, 0, 0, 0, 0, 9]);
        assert_eq!(verified.ed_pubkey, ed);
    }

    #[test]
    fn bad_token_is_a_rejected_outcome_not_an_error() {
        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, Some("s3cret".to_string()), true);
        ca.set_now_unix(100);
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];
        // A well-formed CSR with a bad/missing token is *rejected* (a CSR-domain
        // outcome), not an `Err` (which is for unserviceable requests).
        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "wrong").unwrap(),
            CsrOutcome::Rejected(_)
        ));
        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Rejected(_)
        ));
        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "s3cret").unwrap(),
            CsrOutcome::Issued(_)
        ));
    }

    #[test]
    fn malformed_inputs_are_errors() {
        let mut ca = open_ca(); // past the clock guard, so we test input validation
        let (ed, x) = node_keys(2);
        assert!(ca.submit_csr(&[0, 0, 0], &ed, &x, "").is_err()); // short MAC
        assert!(ca.submit_csr(&[0; 6], &ed[..16], &x, "").is_err()); // short ed key
    }

    #[test]
    fn issuance_rejected_before_clock_is_set() {
        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None, true);
        let (ed, x) = node_keys(2);
        let err = ca.submit_csr(&[0; 6], &ed, &x, "").unwrap_err();
        assert!(err.contains("clock not set"), "got: {err}");
    }

    #[test]
    fn list_certs_records_issued_and_dedups_by_mac() {
        let mut ca = open_ca();
        let (ed, x) = node_keys(2);
        assert!(ca.list_certs().is_empty());

        issued_cert(&mut ca, &[0, 0, 0, 0, 0, 9], &ed, &x, "");
        issued_cert(&mut ca, &[0, 0, 0, 0, 0, 7], &ed, &x, "");
        assert_eq!(ca.list_certs().len(), 2);

        // Re-issuing for an existing MAC updates in place (no duplicate).
        ca.set_now_unix(200);
        issued_cert(&mut ca, &[0, 0, 0, 0, 0, 9], &ed, &x, "");
        let certs = ca.list_certs();
        assert_eq!(certs.len(), 2);
        let nine = certs.iter().find(|c| c.node_mac[5] == 9).unwrap();
        assert_eq!(nine.not_before, 200, "re-issue updated the window");
    }

    #[test]
    fn revoke_marks_the_issued_cert_revoked_but_keeps_it_listed() {
        let mut ca = open_ca();
        let (ed, x) = node_keys(2);
        issued_cert(&mut ca, &[0, 0, 0, 0, 0, 9], &ed, &x, "");
        assert!(!ca.list_certs()[0].revoked);

        ca.revoke(&[0, 0, 0, 0, 0, 9]).unwrap();
        let certs = ca.list_certs();
        assert_eq!(certs.len(), 1, "the entry is retained after revoke");
        assert!(certs[0].revoked, "and marked revoked");
    }

    #[test]
    fn revoke_produces_a_verifiable_record() {
        let mut ca = open_ca();
        let record_bytes = ca.revoke(&[0, 0, 0, 0, 0, 9]).unwrap();
        let (record, _) = RevocationRecord::ref_from_prefix(&record_bytes).unwrap();
        let anchor = TrustAnchor::from_bytes(&ca.trust_anchor_bytes()).unwrap();
        assert_eq!(
            anchor.verify_revocation(record, 0).unwrap().0,
            [0, 0, 0, 0, 0, 9]
        );
    }

    // ── Enrollment posture at construction ─────────────────────────────────────

    /// A provider config naming its mesh, its seed and a TTL, and nothing about
    /// who may join.
    fn minimal_provider_config() -> ProviderConfig {
        ProviderConfig {
            root_seed_path: String::new(),
            mesh_id: 0xABCD,
            cert_ttl_secs: 3600,
            enrollment_token: None,
            auto_approve: false,
            allow_unbounded_cert_ttl: false,
            pending_ttl_secs: 3600,
            state_path: None,
        }
    }

    /// Submit a CSR from a fresh identity and report what the authority did
    /// with it, for the posture tests below.
    fn submit(ca: &mut CertAuthority, token: &str) -> CsrOutcome {
        let (ed, x) = node_keys(2);
        ca.submit_csr(&[0, 0, 0, 0, 0, 9], &ed, &x, token).unwrap()
    }

    /// A config that says nothing about who may join gets the closed posture.
    ///
    /// This is the whole point of spelling the field the way round it is spelled:
    /// a provider signs with the mesh root key, and a certificate lets its holder
    /// sign OGMs the mesh accepts, derive pairwise keys with any neighbour, and
    /// route — so what an unattended provider would be handing out is mesh
    /// membership itself. An operator who leaves the question out of a YAML file
    /// gets a queue to review, not a signature for whoever asks.
    #[test]
    fn a_config_silent_about_admission_holds_csrs_for_approval() {
        let mut ca = CertAuthority::from_config(&[1; 32], &minimal_provider_config())
            .expect("silence about admission is a posture, not a configuration error");
        ca.set_now_unix(100);

        assert!(
            matches!(submit(&mut ca, ""), CsrOutcome::Pending),
            "an unstated posture holds the request for an operator"
        );
        assert!(
            !ca.enrollment_policy().auto_approve,
            "and reports itself closed"
        );
    }

    /// Asking for it is what gets it: an operator who wants trust-on-first-use
    /// for a closed lab or a simulation says so, and gets signatures on
    /// submission.
    #[test]
    fn auto_approve_signs_on_submission() {
        let cfg = ProviderConfig {
            auto_approve: true,
            ..minimal_provider_config()
        };
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(100);

        assert!(matches!(submit(&mut ca, ""), CsrOutcome::Issued(_)));
        assert!(ca.enrollment_policy().auto_approve);
    }

    /// A token is a *separate* gate, not a way to lift this one.
    ///
    /// The two compose: a token says who may ask, `auto_approve` says
    /// whether asking is enough. A config that names a token and stays silent
    /// about the posture therefore still parks the request — which is the
    /// direction an omission should fail in.
    #[test]
    fn a_token_alone_still_holds_the_csr_for_approval() {
        let cfg = ProviderConfig {
            enrollment_token: Some("shibboleth".into()),
            ..minimal_provider_config()
        };
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(100);

        assert!(
            matches!(submit(&mut ca, "shibboleth"), CsrOutcome::Pending),
            "the right token buys a place in the queue, not a certificate"
        );
        assert!(
            matches!(submit(&mut ca, "wrong"), CsrOutcome::Rejected(_)),
            "and the wrong one buys nothing"
        );
    }

    /// A certificate lifetime past the cap is refused.
    ///
    /// Passive expiry is this design's *primary* revocation mechanism, so a
    /// certificate lifetime measured in centuries is a mesh with no revocation
    /// at all. The simulation's ~3000-year value is fine there and one
    /// copy-paste away from a real deployment.
    #[test]
    fn an_extravagant_certificate_lifetime_is_refused() {
        let cfg = ProviderConfig {
            cert_ttl_secs: 100_000_000_000,
            enrollment_token: Some("shibboleth".into()),
            ..minimal_provider_config()
        };

        let err = CertAuthority::from_config(&[1; 32], &cfg)
            .map(|_| ())
            .expect_err("a certificate lifetime past the cap is refused");
        assert!(
            err.contains("cert_ttl_secs") && err.contains("allow_unbounded_cert_ttl"),
            "the error names the field and the way out: {err}"
        );
    }

    /// The cap has an escape, because a simulation legitimately wants a
    /// certificate that outlives it — but taking it is a sentence in the
    /// config, not an accident.
    #[test]
    fn the_escape_hatch_admits_a_long_certificate_lifetime() {
        let cfg = ProviderConfig {
            cert_ttl_secs: 100_000_000_000,
            enrollment_token: Some("shibboleth".into()),
            allow_unbounded_cert_ttl: true,
            ..minimal_provider_config()
        };

        assert!(CertAuthority::from_config(&[1; 32], &cfg).is_ok());
    }

    /// The cap holds on the runtime path too: the dashboard can set this
    /// policy, and a config-only check would be a lock on the front door
    /// alone.
    #[test]
    fn a_runtime_policy_update_cannot_exceed_the_certificate_lifetime_cap() {
        let cfg = ProviderConfig {
            enrollment_token: Some("shibboleth".into()),
            ..minimal_provider_config()
        };
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();

        let err = ca
            .set_enrollment_policy(&EnrollmentPolicyData {
                cert_ttl_secs: Some(100_000_000_000),
                ..Default::default()
            })
            .expect_err("a policy update past the cap is refused");
        assert!(err.contains("cert_ttl_secs"), "{err}");
        assert_eq!(
            ca.enrollment_policy().cert_ttl_secs,
            3600,
            "and the live policy is untouched by the refusal"
        );
    }

    /// A provider that took the escape hatch keeps it at runtime: the operator
    /// who said so in the config does not have to say so again per request.
    #[test]
    fn the_escape_hatch_carries_to_the_runtime_path() {
        let cfg = ProviderConfig {
            enrollment_token: Some("shibboleth".into()),
            allow_unbounded_cert_ttl: true,
            ..minimal_provider_config()
        };
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();

        assert!(
            ca.set_enrollment_policy(&EnrollmentPolicyData {
                cert_ttl_secs: Some(100_000_000_000),
                ..Default::default()
            })
            .is_ok()
        );
    }

    // ── Operator-approval flow (auto_approve = false) ───────────────────────

    /// A CA that parks CSRs for approval, clock set.
    fn approval_ca() -> CertAuthority {
        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None, false);
        ca.set_now_unix(100);
        ca
    }

    #[test]
    fn csr_is_pending_until_approved_then_issues_the_same_cert() {
        let mut ca = approval_ca();
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];

        // First submit parks the CSR: pending, and visible to the operator.
        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Pending
        ));
        assert!(ca.list_certs().is_empty(), "nothing issued while pending");
        let pending = ca.list_pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].node_mac, mac);
        assert_eq!(pending[0].ed_pubkey, ed);

        // Re-polling before approval stays pending (idempotent).
        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Pending
        ));

        // Operator approves; the next poll collects the cert, and the request
        // leaves the pending list.
        ca.approve_csr(&mac).expect("approve succeeds");
        assert!(ca.list_pending().is_empty(), "no longer awaiting approval");
        let first = match ca.submit_csr(&mac, &ed, &x, "").unwrap() {
            CsrOutcome::Issued(d) => d.cert,
            other => panic!("expected Issued, got {other:?}"),
        };
        // The issued cert verifies and is recorded for ListCerts.
        let anchor = TrustAnchor::from_bytes(&ca.trust_anchor_bytes()).unwrap();
        let cert = MembershipCert::from_bytes(&first).unwrap();
        assert_eq!(anchor.verify_cert(&cert, 500).unwrap().mac.0, mac);
        assert_eq!(ca.list_certs().len(), 1);

        // A later poll returns the *same* bytes (stable collection).
        let second = match ca.submit_csr(&mac, &ed, &x, "").unwrap() {
            CsrOutcome::Issued(d) => d.cert,
            other => panic!("expected Issued, got {other:?}"),
        };
        assert_eq!(first, second, "collection is idempotent");
    }

    #[test]
    fn denied_csr_reports_rejected_to_a_polling_node() {
        let mut ca = approval_ca();
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];

        ca.submit_csr(&mac, &ed, &x, "").unwrap();
        ca.deny_csr(&mac).expect("deny succeeds");
        assert!(
            ca.list_pending().is_empty(),
            "denied leaves the pending list"
        );
        assert!(
            matches!(
                ca.submit_csr(&mac, &ed, &x, "").unwrap(),
                CsrOutcome::Rejected(_)
            ),
            "a polling node learns it was denied"
        );
        assert!(ca.list_certs().is_empty(), "nothing was issued");
    }

    #[test]
    fn approve_or_deny_unknown_mac_errors() {
        let mut ca = approval_ca();
        assert!(ca.approve_csr(&[0, 0, 0, 0, 0, 9]).is_err());
        assert!(ca.deny_csr(&[0, 0, 0, 0, 0, 9]).is_err());
    }

    #[test]
    fn a_different_identity_claiming_a_held_mac_is_rejected() {
        let mut ca = approval_ca();
        let (ed1, x1) = node_keys(2);
        let (ed2, x2) = node_keys(3);
        let mac = [0, 0, 0, 0, 0, 9];

        assert!(matches!(
            ca.submit_csr(&mac, &ed1, &x1, "").unwrap(),
            CsrOutcome::Pending
        ));
        // A second identity claiming the same still-pending MAC is rejected, not
        // superseded — so the key material an operator reviews cannot be swapped
        // out from under an approval.
        assert!(matches!(
            ca.submit_csr(&mac, &ed2, &x2, "").unwrap(),
            CsrOutcome::Rejected(_)
        ));
        let pending = ca.list_pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].ed_pubkey, ed1,
            "the original request is untouched"
        );
    }

    #[test]
    fn a_different_key_cannot_reclaim_an_already_issued_mac() {
        let mut ca = approval_ca();
        let (ed1, x1) = node_keys(2);
        let (ed2, x2) = node_keys(3);
        let mac = [0, 0, 0, 0, 0, 9];

        ca.submit_csr(&mac, &ed1, &x1, "").unwrap();
        ca.approve_csr(&mac).unwrap();
        // The MAC now has an issued certificate.  A different identity claiming
        // it is rejected rather than re-opening enrollment for that MAC.
        assert!(matches!(
            ca.submit_csr(&mac, &ed2, &x2, "").unwrap(),
            CsrOutcome::Rejected(_)
        ));
        // The original identity still collects its issued cert on the next poll.
        assert!(matches!(
            ca.submit_csr(&mac, &ed1, &x1, "").unwrap(),
            CsrOutcome::Issued(_)
        ));
    }

    #[test]
    fn an_issued_mac_stays_protected_after_its_held_entry_is_evicted() {
        // pending TTL (10s) shorter than the cert TTL (100_000s), so the held
        // Approved entry ages out while the issued certificate is still valid —
        // the window in which a stale `held` alone would drop the guarantee.
        let cfg = ProviderConfig {
            root_seed_path: String::new(),
            mesh_id: 0xABCD,
            cert_ttl_secs: 100_000,
            enrollment_token: None,
            auto_approve: false,
            allow_unbounded_cert_ttl: false,
            pending_ttl_secs: 10,
            state_path: None,
        };
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(100);
        let (ed1, x1) = node_keys(2);
        let (ed2, x2) = node_keys(3);
        let mac = [0, 0, 0, 0, 0, 9];

        ca.submit_csr(&mac, &ed1, &x1, "").unwrap();
        ca.approve_csr(&mac).unwrap();

        // Age past the pending TTL: the held Approved entry is gone, but the
        // certificate it issued is still valid.
        ca.set_now_unix(100 + 20);
        // A different identity reclaiming the MAC is still rejected — the guard
        // now reads `issued`, not just `held`.
        assert!(matches!(
            ca.submit_csr(&mac, &ed2, &x2, "").unwrap(),
            CsrOutcome::Rejected(_)
        ));
        assert!(ca.log.held().is_empty(), "no new pending entry was parked");

        // Once the certificate passively expires, the MAC is free to re-key.
        ca.set_now_unix(100 + 100_001);
        assert!(matches!(
            ca.submit_csr(&mac, &ed2, &x2, "").unwrap(),
            CsrOutcome::Pending
        ));
    }

    #[test]
    fn same_key_resubmit_after_held_entry_eviction_reissues_without_reparking() {
        // Mirrors `an_issued_mac_stays_protected_after_its_held_entry_is_evicted`
        // but the *same* identity re-submits after its held (Approved) entry ages
        // out.  This is the legitimate case: the holder should be handed a fresh
        // certificate immediately, not parked as Pending a second time (which
        // would force it through operator approval again for a MAC it already
        // holds).
        let cfg = ProviderConfig {
            root_seed_path: String::new(),
            mesh_id: 0xABCD,
            cert_ttl_secs: 100_000,
            enrollment_token: None,
            auto_approve: false,
            allow_unbounded_cert_ttl: false,
            pending_ttl_secs: 10,
            state_path: None,
        };
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(100);
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];

        ca.submit_csr(&mac, &ed, &x, "").unwrap();
        ca.approve_csr(&mac).unwrap();

        // Age past the pending TTL: the held Approved entry is now stale (it is
        // physically evicted on the next call that touches the store, below).
        ca.set_now_unix(100 + 20);

        // The holder re-submits with its own (unchanged) key: it must be
        // reissued immediately, and must NOT create a new held/Pending entry.
        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Issued(_)
        ));
        assert!(
            ca.log.held().is_empty(),
            "a same-key re-submit must not re-park a held entry"
        );
        assert!(ca.list_pending().is_empty());
    }

    #[test]
    fn revoked_same_key_resubmit_is_not_reissued() {
        // Proves the `!c.revoked` term in the same-key shortcut is load-bearing:
        // a revoked holder must go back through approval, not be silently
        // re-issued a fresh certificate on the same key.
        //
        // A short `pending_ttl_secs` (with a long `cert_ttl_secs`) is used so the
        // held (Approved) entry ages out of `held` before we revoke — otherwise
        // the still-live held entry would short-circuit the request on its own
        // cached `Approved` status, without ever consulting `issued`/`revoked`
        // at all, and the test wouldn't isolate the term under test.
        let cfg = ProviderConfig {
            root_seed_path: String::new(),
            mesh_id: 0xABCD,
            cert_ttl_secs: 100_000,
            enrollment_token: None,
            auto_approve: false,
            allow_unbounded_cert_ttl: false,
            pending_ttl_secs: 10,
            state_path: None,
        };
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(100);
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];

        ca.submit_csr(&mac, &ed, &x, "").unwrap();
        ca.approve_csr(&mac).unwrap();

        // Age past the pending TTL: the held Approved entry ages out, leaving
        // the still-valid `issued` record as the only thing protecting the MAC.
        ca.set_now_unix(100 + 20);
        ca.revoke(&mac).unwrap();

        // The same identity resubmitting after revocation must be re-parked for
        // approval, not silently re-issued.
        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Pending
        ));
    }

    #[test]
    fn expired_same_key_resubmit_is_not_reissued() {
        // Proves the `now_unix <= c.not_after` term in the same-key shortcut is
        // load-bearing: once the previously-issued cert has passively expired
        // (and its held entry has aged out), a same-key resubmit must go back
        // through approval rather than being silently re-issued.
        let cfg = ProviderConfig {
            root_seed_path: String::new(),
            mesh_id: 0xABCD,
            cert_ttl_secs: 10,
            enrollment_token: None,
            auto_approve: false,
            allow_unbounded_cert_ttl: false,
            pending_ttl_secs: 10,
            state_path: None,
        };
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(100);
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];

        ca.submit_csr(&mac, &ed, &x, "").unwrap();
        ca.approve_csr(&mac).unwrap();
        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Issued(_)
        ));

        // Advance past both the cert TTL and the pending TTL, so the issued
        // cert has expired and the held entry has been evicted.
        ca.set_now_unix(100 + 20);

        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Pending
        ));
    }

    #[test]
    fn same_key_resubmit_while_still_pending_stays_pending() {
        // Regression guard for the shortcut above: a still-Pending held entry
        // (not yet approved, so not yet in `issued`) must keep reporting Pending
        // on a same-key re-poll — the issued-guard shortcut must not fire before
        // approval.
        let mut ca = approval_ca();
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];

        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Pending
        ));
        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Pending
        ));
        assert_eq!(ca.log.held().len(), 1, "still exactly one held entry");
    }

    /// The held-CSR store is bounded by count, not only by TTL, and a full
    /// queue **refuses the newcomer rather than evicting an incumbent**.
    ///
    /// Both halves are the security property. The bound is what stops an
    /// anonymous client — `SubmitCsr` is reachable on the enrollment tier with
    /// no credential at all — from growing the store until the node runs out
    /// of memory, a growth that would otherwise also be persisted and so
    /// outlive a restart. Refusing rather than evicting is what stops the
    /// *cure* from being the disease: an eviction policy hands an attacker
    /// exactly the primitive they want, the ability to displace a legitimate
    /// pending request by submitting enough of their own.
    ///
    /// A full queue therefore degrades to "an operator must drain this",
    /// which is visible in `list_pending` and recoverable, and every request
    /// already held stays held and stays collectable.
    #[test]
    fn a_full_held_csr_queue_refuses_new_requests_rather_than_evicting() {
        let mut ca = approval_ca();
        let held_mac = |n: usize| [0, 0, 0, 0, (n >> 8) as u8, n as u8];

        for n in 0..MAX_HELD_CSRS {
            let (ed, x) = node_keys(n as u8);
            assert!(
                matches!(
                    ca.submit_csr(&held_mac(n), &ed, &x, "").unwrap(),
                    CsrOutcome::Pending
                ),
                "parking request {n} of {MAX_HELD_CSRS}"
            );
        }
        assert_eq!(ca.log.held().len(), MAX_HELD_CSRS, "the queue is full");

        // One more, from a MAC and key the store has never seen: refused, with
        // a reason that names the queue rather than blaming the requester.
        let (ed, x) = node_keys(200);
        let outcome = ca
            .submit_csr(&held_mac(MAX_HELD_CSRS), &ed, &x, "")
            .unwrap();
        match outcome {
            CsrOutcome::Rejected(reason) => {
                assert!(reason.contains("full"), "got: {reason}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }

        // Nothing was displaced to make room, and every incumbent is still
        // awaiting the operator.
        assert_eq!(ca.log.held().len(), MAX_HELD_CSRS, "no incumbent evicted");
        assert_eq!(ca.list_pending().len(), MAX_HELD_CSRS);

        // And an incumbent re-polling is still answered — the cap gates *new*
        // entries, never the collection path a legitimate node is waiting on.
        let (ed0, x0) = node_keys(0);
        assert!(matches!(
            ca.submit_csr(&held_mac(0), &ed0, &x0, "").unwrap(),
            CsrOutcome::Pending
        ));
        ca.approve_csr(&held_mac(0)).expect("approve succeeds");
        assert!(matches!(
            ca.submit_csr(&held_mac(0), &ed0, &x0, "").unwrap(),
            CsrOutcome::Issued(_)
        ));
    }

    #[test]
    fn a_held_csr_is_evicted_after_the_pending_ttl() {
        let mut ca = approval_ca(); // pending TTL = DEFAULT_PENDING_TTL_SECS, clock = 100
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];

        ca.submit_csr(&mac, &ed, &x, "").unwrap();
        assert_eq!(ca.list_pending().len(), 1);

        // Advance past the TTL: the stale request drops out of the pending view
        // and is physically evicted (freeing the MAC) on the next poll.
        ca.set_now_unix(100 + DEFAULT_PENDING_TTL_SECS + 1);
        assert!(ca.list_pending().is_empty(), "expired request is hidden");

        // A fresh identity can now claim the freed MAC.
        let (ed2, x2) = node_keys(3);
        assert!(matches!(
            ca.submit_csr(&mac, &ed2, &x2, "").unwrap(),
            CsrOutcome::Pending
        ));
        assert_eq!(ca.log.held().len(), 1, "the timed-out entry was evicted");
        assert_eq!(ca.list_pending()[0].ed_pubkey, ed2);
    }

    #[test]
    fn bad_token_does_not_clobber_a_pending_request() {
        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, Some("s3cret".to_string()), false);
        ca.set_now_unix(100);
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];

        // Legitimate node parks a pending CSR.
        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "s3cret").unwrap(),
            CsrOutcome::Pending
        ));
        // An attacker submitting for the same MAC with a bad token is rejected
        // and must not disturb the held request.
        let (ed_atk, x_atk) = node_keys(9);
        assert!(matches!(
            ca.submit_csr(&mac, &ed_atk, &x_atk, "wrong").unwrap(),
            CsrOutcome::Rejected(_)
        ));
        let pending = ca.list_pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].ed_pubkey, ed, "original request untouched");
    }

    // ── State persistence (`ProviderConfig::state_path`) ────────────────────────

    /// A unique per-call state-file path under the OS temp dir, so parallel
    /// test runs (and repeated calls within one test) never collide.
    fn unique_state_path(label: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "wayfinder-server-test-{}-{label}-{n}.json",
            std::process::id()
        ))
    }

    /// An auto-approving `ProviderConfig` snapshotting to `state_path`.
    fn persisted_cfg(state_path: &std::path::Path) -> ProviderConfig {
        ProviderConfig {
            root_seed_path: String::new(),
            mesh_id: 0xABCD,
            cert_ttl_secs: 100_000,
            enrollment_token: None,
            auto_approve: true,
            allow_unbounded_cert_ttl: false,
            pending_ttl_secs: 3600,
            state_path: Some(state_path.to_string_lossy().into_owned()),
        }
    }

    /// An operator-approval `ProviderConfig` snapshotting to `state_path`.
    fn approval_persisted_cfg(state_path: &std::path::Path) -> ProviderConfig {
        ProviderConfig {
            auto_approve: false,
            allow_unbounded_cert_ttl: false,
            ..persisted_cfg(state_path)
        }
    }

    #[test]
    fn issued_certs_persist_across_a_restart() {
        let path = unique_state_path("restart");
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];

        {
            let cfg = persisted_cfg(&path);
            let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
            ca.set_now_unix(100);
            issued_cert(&mut ca, &mac, &ed, &x, "");
            ca.revoke(&mac).unwrap();
        } // Dropped here, simulating a process restart.

        let cfg = persisted_cfg(&path);
        let ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        let certs = ca.list_certs();
        assert_eq!(certs.len(), 1, "the issued cert survives the restart");
        assert_eq!(certs[0].node_mac, mac);
        assert!(certs[0].revoked, "the revocation survives the restart too");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn corrupt_state_file_fails_closed() {
        let path = unique_state_path("corrupt");
        std::fs::write(&path, b"not json").unwrap();

        let cfg = persisted_cfg(&path);
        let err = match CertAuthority::from_config(&[1; 32], &cfg) {
            Ok(_) => panic!("a corrupt state file must not be silently treated as empty"),
            Err(e) => e,
        };
        assert!(
            err.to_lowercase().contains("state"),
            "error should mention the state file, got: {err}"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn newer_state_version_fails_closed() {
        let path = unique_state_path("newer-version");
        std::fs::write(&path, r#"{"version": 999999, "issued": []}"#).unwrap();

        let cfg = persisted_cfg(&path);
        let err = match CertAuthority::from_config(&[1; 32], &cfg) {
            Ok(_) => panic!("a state file from a newer, unknown version must be refused"),
            Err(e) => e,
        };
        assert!(
            err.contains("999999"),
            "error should name the offending version, got: {err}"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn held_csrs_persist_across_a_restart() {
        let path = unique_state_path("held-restart");
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];

        {
            let cfg = approval_persisted_cfg(&path);
            let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
            ca.set_now_unix(100);
            assert!(matches!(
                ca.submit_csr(&mac, &ed, &x, "").unwrap(),
                CsrOutcome::Pending
            ));
        } // Dropped here, simulating a process restart.

        let cfg = approval_persisted_cfg(&path);
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(100);
        let pending = ca.list_pending();
        assert_eq!(pending.len(), 1, "the pending CSR survives the restart");
        assert_eq!(pending[0].node_mac, mac);
        assert_eq!(pending[0].ed_pubkey, ed);

        // The operator can act on the reloaded request as if nothing happened.
        ca.approve_csr(&mac)
            .expect("approve succeeds on the reloaded entry");
        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Issued(_)
        ));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn denied_csr_tombstone_persists_across_a_restart() {
        let path = unique_state_path("held-denied-restart");
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];

        {
            let cfg = approval_persisted_cfg(&path);
            let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
            ca.set_now_unix(100);
            ca.submit_csr(&mac, &ed, &x, "").unwrap();
            ca.deny_csr(&mac).expect("deny succeeds");
        } // Dropped here, simulating a process restart.

        let cfg = approval_persisted_cfg(&path);
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(100);
        assert!(
            matches!(
                ca.submit_csr(&mac, &ed, &x, "").unwrap(),
                CsrOutcome::Rejected(_)
            ),
            "the denial tombstone survives the restart"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn v1_state_file_migrates_forward_with_empty_held() {
        let path = unique_state_path("v1-migration");
        let (ed, _x) = node_keys(2);
        let mac = [0u8, 0, 0, 0, 0, 9];

        // The version-1 on-disk shape: issued log only, no `held` section
        // at all.
        let v1 = serde_json::json!({
            "version": 1,
            "issued": [{
                "node_mac": mac,
                "ed_pubkey": ed,
                "not_before": 50,
                "not_after": 999_999,
                "revoked": false,
            }],
        });
        std::fs::write(&path, v1.to_string()).unwrap();

        let cfg = persisted_cfg(&path);
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(100);

        // The pre-existing issued cert survived the migration...
        let certs = ca.list_certs();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].node_mac, mac);
        // ...and the held-CSR store (absent in the v1 file) defaulted to
        // empty rather than erroring.
        assert!(ca.list_pending().is_empty());

        // A subsequent mutation rewrites the file under the current version,
        // with a `held` section now present.
        let (ed2, x2) = node_keys(3);
        ca.submit_csr(&[0, 0, 0, 0, 0, 10], &ed2, &x2, "").unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        let on_disk: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            on_disk["version"],
            crate::persistence::CURRENT_STATE_VERSION
        );
        assert!(on_disk["held"].is_array());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn approved_csr_persists_across_a_restart_before_collection() {
        // Unlike `held_csrs_persist_across_a_restart` (which restarts while
        // still Pending, then approves after reload), this covers the actual
        // crash window the feature protects: an operator approves, the node
        // hasn't collected its cert yet, and the process restarts in between.
        let path = unique_state_path("approved-restart");
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];

        {
            let cfg = approval_persisted_cfg(&path);
            let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
            ca.set_now_unix(100);
            ca.submit_csr(&mac, &ed, &x, "").unwrap();
            ca.approve_csr(&mac).expect("approve succeeds");
            // No collection poll here — the node hasn't picked up its cert
            // when the process "restarts" below.
        }

        let cfg = approval_persisted_cfg(&path);
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(100);
        // The reloaded held entry is still Approved, so a poll collects the
        // cert immediately with no second approval needed.
        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Issued(_)
        ));
        assert_eq!(ca.list_certs().len(), 1, "the issued cert also survived");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn evicted_held_csr_stays_evicted_after_a_restart() {
        let path = unique_state_path("evicted-restart");
        let (ed, x) = node_keys(2);
        let (ed2, x2) = node_keys(3);
        let mac = [0, 0, 0, 0, 0, 9];

        {
            let cfg = ProviderConfig {
                pending_ttl_secs: 10,
                ..approval_persisted_cfg(&path)
            };
            let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
            ca.set_now_unix(100);
            ca.submit_csr(&mac, &ed, &x, "").unwrap();

            // Age past the pending TTL, then touch the store again so
            // eviction actually runs (and persists the now-empty held
            // table) rather than merely hiding the expired entry from
            // `list_pending`.
            ca.set_now_unix(100 + 20);
            assert!(ca.list_pending().is_empty());
            assert!(matches!(
                ca.submit_csr(&mac, &ed2, &x2, "").unwrap(),
                CsrOutcome::Pending
            ));
        } // Dropped here, simulating a restart.

        let cfg = ProviderConfig {
            pending_ttl_secs: 10,
            ..approval_persisted_cfg(&path)
        };
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(100 + 20);
        let pending = ca.list_pending();
        assert_eq!(
            pending.len(),
            1,
            "only the post-eviction entry survived the restart"
        );
        assert_eq!(
            pending[0].ed_pubkey, ed2,
            "the evicted (ed/x) entry did not resurrect after the restart"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn failed_persist_rolls_back_the_in_memory_mutation_but_caller_is_told() {
        // state_path under a directory that doesn't exist, so every write
        // attempt fails; a missing *file* is a normal fresh-install case
        // (`Ok(None)`), but a missing *directory* dooms every persist.
        let path = std::env::temp_dir()
            .join(format!(
                "wayfinder-server-test-{}-nonexistent-dir",
                std::process::id()
            ))
            .join("state.json");

        let cfg = persisted_cfg(&path);
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(100);
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];

        // The doomed write surfaces as an error to the caller — an operator
        // must not be told an action durably succeeded when it didn't.
        let err = ca.submit_csr(&mac, &ed, &x, "").unwrap_err();
        assert!(
            err.contains("persist"),
            "error should mention persistence, got: {err}"
        );

        // The in-memory mutation is rolled back to what it was before `f`
        // ran (`CaLog`'s `Persisted`-backed rollback guarantee): in-memory
        // state must never diverge from what's durably stored, so a
        // mutation that couldn't be persisted did not, as far as any later
        // caller can tell, happen at all.
        assert_eq!(
            ca.list_certs().len(),
            0,
            "the in-memory mutation was rolled back since it never durably persisted"
        );

        // The authority itself stays serviceable (doesn't panic or corrupt
        // its state) even though every persist against this path keeps
        // failing — a second, independent submission still gets exactly the
        // same fail-closed treatment as the first.
        let (ed2, x2) = node_keys(3);
        let mac2 = [0, 0, 0, 0, 0, 10];
        let err2 = ca.submit_csr(&mac2, &ed2, &x2, "").unwrap_err();
        assert!(
            err2.contains("persist"),
            "error should mention persistence, got: {err2}"
        );
        assert_eq!(
            ca.list_certs().len(),
            0,
            "the second doomed mutation was rolled back too"
        );
    }

    #[test]
    fn approve_csr_rolls_back_issued_and_held_together_on_persist_failure() {
        // A real directory, so the initial `submit_csr` (parking the CSR)
        // persists successfully — unlike the other persist-failure tests,
        // this one needs the *first* write to land so `approve_csr`'s own
        // combined write is what's actually under test.
        let dir = std::env::temp_dir().join(format!(
            "wayfinder-server-test-{}-approve-atomic",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");

        let cfg = approval_persisted_cfg(&path);
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(100);
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];

        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Pending
        ));

        // Now doom every subsequent write.
        std::fs::remove_dir_all(&dir).ok();

        let err = ca.approve_csr(&mac).unwrap_err();
        assert!(
            err.contains("persist"),
            "error should mention persistence, got: {err}"
        );

        // End-to-end confirmation that `approve_csr` never leaves an
        // orphaned issued cert when its persist fails. This doesn't by
        // itself distinguish the combined write from two separate ones —
        // deleting the whole directory before calling `approve_csr` dooms
        // every write inside that call uniformly, so a first-write-succeeds,
        // second-write-fails split can't be reproduced from outside a single
        // function call. `persistence.rs`'s own
        // `separate_mutate_issued_and_mutate_held_calls_can_durably_split`
        // (which *can* control that timing) is what actually reproduces the
        // split-durability hazard `mutate_issued_and_held` closes; this test
        // is the user-visible guarantee that falls out of it.
        assert_eq!(
            ca.list_certs().len(),
            0,
            "no certificate should be left issued when the combined approve write fails"
        );
        assert_eq!(
            ca.list_pending().len(),
            1,
            "the held entry rolls back to Pending, not silently lost or left Approved"
        );

        // No orphaned, un-revocable certificate: once storage is available
        // again, a subsequent deny succeeds against the (correctly
        // still-Pending) entry, and there is no already-issued certificate
        // left behind for it to have failed to revoke.
        std::fs::create_dir_all(&dir).unwrap();
        ca.deny_csr(&mac)
            .expect("deny succeeds against the rolled-back entry");
        assert_eq!(ca.list_certs().len(), 0);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// `deny_csr` goes through a standalone `mutate_held` call (unlike
    /// `approve_csr`, which needed the combined `mutate_issued_and_held`
    /// fix above) — this covers that call site under the same
    /// rollback-on-persist-failure semantics, since it's the other
    /// operator-facing security action against the held-CSR store (a
    /// denial that silently didn't durably take effect would be just as
    /// misleading to an operator as an approval that didn't).
    #[test]
    fn deny_csr_rolls_back_to_pending_when_persist_fails() {
        let dir = std::env::temp_dir().join(format!(
            "wayfinder-server-test-{}-deny-rollback",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");

        let cfg = approval_persisted_cfg(&path);
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(100);
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];

        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Pending
        ));

        // Now doom the deny's write.
        std::fs::remove_dir_all(&dir).ok();

        let err = ca.deny_csr(&mac).unwrap_err();
        assert!(
            err.contains("persist"),
            "error should mention persistence, got: {err}"
        );

        // The status flip to Denied rolled back — the entry is still
        // Pending, not silently left Denied in memory while never durably
        // recorded as such.
        assert_eq!(
            ca.list_pending().len(),
            1,
            "the held entry rolls back to Pending, not silently left Denied"
        );

        // Once storage is available again, denying still works normally
        // against the rolled-back (still-Pending) entry.
        std::fs::create_dir_all(&dir).unwrap();
        ca.deny_csr(&mac)
            .expect("deny succeeds once storage recovers");
        assert!(ca.list_pending().is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    // ── Runtime enrollment policy (SetConfig's EnrollmentPolicy) ────────────────

    /// The policy an authority reports is the one it was configured with, so
    /// the dashboard renders the real state before an operator edits it.
    #[test]
    fn enrollment_policy_reports_the_configured_policy() {
        let ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, Some("hunter2".into()), false);

        let policy = ca.enrollment_policy();
        assert!(!policy.auto_approve);
        assert_eq!(policy.cert_ttl_secs, 1000);
        assert!(policy.enrollment_token_set);
    }

    /// The token is handed over by its own request, so the operator running a
    /// provider can pass it to a joining node without replacing a working token
    /// just to learn what it is — and so each disclosure is one event.
    ///
    /// It reaches only a client already authenticated as an admin or as this
    /// node — one that may replace or clear the token anyway — so the report
    /// grants nothing it did not already have.
    #[test]
    fn the_token_is_revealed_by_its_own_request() {
        let ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, Some("hunter2".into()), false);

        assert_eq!(
            ca.admission(),
            EnrollmentAdmission::Token(SharedSecret::new("hunter2"))
        );
    }

    /// With no token set the flag says so and the reveal answers `Open` — not
    /// an empty token, which reads as "a token nobody can present".
    #[test]
    fn an_absent_token_reports_as_open_rather_than_empty() {
        let ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None, true);

        assert!(!ca.enrollment_policy().enrollment_token_set);
        assert_eq!(ca.admission(), EnrollmentAdmission::Open);
    }

    /// A token installed at runtime is reported back, not just recorded: this
    /// is the path the dashboard's "Set token" takes, and an operator who sets
    /// one there must be able to copy it afterwards.
    #[test]
    fn a_runtime_token_is_reported_back() {
        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None, true);

        ca.set_enrollment_policy(&EnrollmentPolicyData {
            enrollment_token: Some(TokenUpdate::Set(SharedSecret::new("let-me-in"))),
            ..Default::default()
        })
        .unwrap();

        assert!(ca.enrollment_policy().enrollment_token_set);
        assert_eq!(
            ca.admission(),
            EnrollmentAdmission::Token(SharedSecret::new("let-me-in"))
        );
    }

    /// An update names only what it changes; everything else stays as it was.
    #[test]
    fn set_enrollment_policy_leaves_unnamed_fields_alone() {
        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, Some("hunter2".into()), true);

        ca.set_enrollment_policy(&EnrollmentPolicyData {
            auto_approve: Some(false),
            ..Default::default()
        })
        .unwrap();

        let policy = ca.enrollment_policy();
        assert!(!policy.auto_approve, "the named field changed");
        assert_eq!(policy.cert_ttl_secs, 1000, "the lifetime is untouched");
        assert!(policy.enrollment_token_set, "the token is untouched");
    }

    /// Turning approval on parks the next CSR rather than signing it — the
    /// policy change has to reach the issuance path, not just the report.
    #[test]
    fn enabling_approval_parks_the_next_csr() {
        let mut ca = open_ca();
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];

        ca.set_enrollment_policy(&EnrollmentPolicyData {
            auto_approve: Some(false),
            ..Default::default()
        })
        .unwrap();

        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Pending
        ));
    }

    /// Setting a token starts gating enrollment on it immediately: a CSR
    /// presenting nothing is rejected, and the same CSR presenting the token
    /// is issued.
    #[test]
    fn setting_a_token_gates_the_next_csr() {
        let mut ca = open_ca();
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];

        ca.set_enrollment_policy(&EnrollmentPolicyData {
            enrollment_token: Some(TokenUpdate::Set(SharedSecret::new("hunter2"))),
            ..Default::default()
        })
        .unwrap();

        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Rejected(_)
        ));
        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "hunter2").unwrap(),
            CsrOutcome::Issued(_)
        ));
    }

    /// Clearing the token opens enrollment: the CSR that was being rejected
    /// for presenting nothing now issues.
    #[test]
    fn clearing_the_token_opens_enrollment() {
        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, Some("hunter2".into()), true);
        ca.set_now_unix(100);
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];
        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Rejected(_)
        ));

        ca.set_enrollment_policy(&EnrollmentPolicyData {
            enrollment_token: Some(TokenUpdate::Clear),
            ..Default::default()
        })
        .unwrap();

        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Issued(_)
        ));
        assert!(!ca.enrollment_policy().enrollment_token_set);
    }

    /// A new certificate lifetime applies to certificates issued after it, so
    /// the change is observable in the validity window rather than only in the
    /// reported policy.
    #[test]
    fn a_new_cert_ttl_applies_to_the_next_issued_cert() {
        let mut ca = open_ca();
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];

        ca.set_enrollment_policy(&EnrollmentPolicyData {
            cert_ttl_secs: Some(50_000),
            ..Default::default()
        })
        .unwrap();
        issued_cert(&mut ca, &mac, &ed, &x, "");

        let certs = ca.list_certs();
        assert_eq!(
            certs[0].not_after - certs[0].not_before,
            50_000,
            "the newly issued cert carries the new lifetime"
        );
    }

    /// The whole point of the feature: an operator's policy edit is still in
    /// force after the node restarts, rather than reverting to the YAML the
    /// operator has since moved past.
    #[test]
    fn enrollment_policy_survives_a_restart() {
        let path = unique_state_path("policy-restart");

        {
            let cfg = persisted_cfg(&path);
            let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
            ca.set_enrollment_policy(&EnrollmentPolicyData {
                auto_approve: Some(false),
                cert_ttl_secs: Some(4242),
                enrollment_token: Some(TokenUpdate::Set(SharedSecret::new("hunter2"))),
            })
            .unwrap();
        } // Dropped here, simulating a process restart.

        // `persisted_cfg` auto-approves with a 100_000s lifetime, so
        // every assertion below is a value the startup config would not have
        // produced on its own.
        let cfg = persisted_cfg(&path);
        let ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        let policy = ca.enrollment_policy();
        assert!(!policy.auto_approve);
        assert_eq!(policy.cert_ttl_secs, 4242);
        assert!(policy.enrollment_token_set);

        std::fs::remove_file(&path).ok();
    }

    /// A cleared token has to survive a restart *as cleared*: reverting to the
    /// configured token would silently re-close an enrollment the operator
    /// deliberately opened.
    #[test]
    fn a_cleared_token_stays_cleared_across_a_restart() {
        let path = unique_state_path("policy-cleared-restart");
        let cfg = ProviderConfig {
            enrollment_token: Some("from-yaml".into()),
            ..persisted_cfg(&path)
        };

        {
            let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
            assert!(ca.enrollment_policy().enrollment_token_set);
            ca.set_enrollment_policy(&EnrollmentPolicyData {
                enrollment_token: Some(TokenUpdate::Clear),
                ..Default::default()
            })
            .unwrap();
        } // Dropped here, simulating a process restart.

        let ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        assert!(
            !ca.enrollment_policy().enrollment_token_set,
            "the cleared token must not revert to the configured one"
        );

        std::fs::remove_file(&path).ok();
    }

    /// A field the operator never overrode still tracks the startup config, so
    /// editing the YAML remains meaningful for everything not pinned by a
    /// runtime override.
    #[test]
    fn an_unset_policy_field_still_follows_the_startup_config() {
        let path = unique_state_path("policy-partial-restart");

        {
            let mut ca = CertAuthority::from_config(&[1; 32], &persisted_cfg(&path)).unwrap();
            ca.set_enrollment_policy(&EnrollmentPolicyData {
                auto_approve: Some(false),
                ..Default::default()
            })
            .unwrap();
        } // Dropped here, simulating a process restart.

        // Same state file, but the operator has since edited the YAML lifetime.
        let cfg = ProviderConfig {
            cert_ttl_secs: 777,
            ..persisted_cfg(&path)
        };
        let ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        assert!(!ca.enrollment_policy().auto_approve, "the override holds");
        assert_eq!(
            ca.enrollment_policy().cert_ttl_secs,
            777,
            "the never-overridden field follows the edited config"
        );

        std::fs::remove_file(&path).ok();
    }

    /// A policy change that cannot be made durable is reported as a failure:
    /// answering `Ok` would tell the operator a security setting is in force
    /// that the next restart quietly discards.
    #[test]
    fn a_policy_change_that_cannot_persist_is_an_error() {
        let dir = std::env::temp_dir().join(format!(
            "wayfinder-server-test-{}-policy-nodir",
            std::process::id()
        ));
        std::fs::remove_dir_all(&dir).ok();
        let cfg = persisted_cfg(&dir.join("state.json"));
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();

        let result = ca.set_enrollment_policy(&EnrollmentPolicyData {
            auto_approve: Some(false),
            ..Default::default()
        });

        assert!(result.is_err(), "an unpersistable policy change must fail");
        assert!(
            ca.enrollment_policy().auto_approve,
            "and must not be left applied in memory"
        );
    }

    /// A version-2 snapshot (issued + held, no policy section) migrates
    /// forward with no overrides at all, so the authority keeps following its
    /// startup config exactly as a version-2 node did.
    #[test]
    fn v2_state_file_migrates_forward_with_no_policy_overrides() {
        let path = unique_state_path("v2-migrate");
        let v2 = serde_json::json!({
            "version": 2,
            "issued": [],
            "held": [],
        });
        std::fs::write(&path, v2.to_string()).unwrap();

        // A config whose policy differs from every default, so "followed the
        // config" is distinguishable from "fell back to something else".
        let cfg = ProviderConfig {
            cert_ttl_secs: 4321,
            auto_approve: false,
            allow_unbounded_cert_ttl: false,
            enrollment_token: Some("from-yaml".into()),
            ..persisted_cfg(&path)
        };
        let ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();

        let policy = ca.enrollment_policy();
        assert!(!policy.auto_approve);
        assert_eq!(policy.cert_ttl_secs, 4321);
        assert!(policy.enrollment_token_set);

        std::fs::remove_file(&path).ok();
    }
    /// A version-3 snapshot recorded the posture as `require_approval`, the
    /// field this schema replaced with its inverse. The override has to survive
    /// the rename inverted, not be dropped: an operator who pinned "hold every
    /// request" from the dashboard must not come back from an upgrade to a
    /// provider that signs on submission.
    #[test]
    fn v3_state_file_migrates_a_require_approval_override_to_its_inverse() {
        let path = unique_state_path("v3-migrate-posture");
        let v3 = serde_json::json!({
            "version": 3,
            "issued": [],
            "held": [],
            "policy": { "require_approval": true },
        });
        std::fs::write(&path, v3.to_string()).unwrap();

        // A config that says the opposite, so "the override held" is
        // distinguishable from "it fell back to the config".
        let cfg = ProviderConfig {
            auto_approve: true,
            ..persisted_cfg(&path)
        };
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(100);

        assert!(
            !ca.enrollment_policy().auto_approve,
            "the pinned approval requirement carried across the rename"
        );
        assert!(
            matches!(submit(&mut ca, ""), CsrOutcome::Pending),
            "and still governs an incoming request"
        );

        std::fs::remove_file(&path).ok();
    }
}
