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
use wayfinder::config::MAX_SESSION_TTL_SECS;
use wayfinder::config::ProviderConfig;
use wayfinder::interfaces::frame::Mac;
use wayfinder_auth::Authority;
use wayfinder_auth::MembershipCert;
use wayfinder_auth::RevocationRecord;
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
use crate::users::AccountId;
use crate::users::AuthOutcome;
use crate::users::DEFAULT_SESSION_TTL_SECS;
use crate::users::InviteStatus;
use crate::users::MAX_USERNAME_LEN;
use crate::users::UserInvite;
use crate::users::UserRecord;
use crate::users::UserRole;
// The earliest unix second this build will believe from a host clock, hoisted
// into `wayfinder-auth` (design 20 §4.2) so the authority stamping a validity
// window and every verifier judging one share *one* definition of "plausible".
// Two components reading the host clock with different floors is how they end
// up disagreeing about whether a certificate is inside its window. A reading
// below it is mapped onto zero here, which is the value every issuing path in
// this module already refuses.
use wayfinder::wayfinder_auth::MIN_PLAUSIBLE_UNIX;
use wayfinder_clock_trust::ClockSync;
use wayfinder_clock_trust::ClockTrust;

/// How this mesh names itself in an authenticator app's account list.
///
/// One constant rather than a literal at each call site: the string is part of
/// what a person sees when they enrol, so two paths spelling it differently
/// would put an account under two names in the same app.
const TOTP_ISSUER: &str = "wayfinder";

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
    /// Where this authority reads wall-clock time from.
    ///
    /// Was a `now_unix: u64` that something outside had to keep refreshed, and
    /// that shape was a bug: the refresher was the router loop, which on a
    /// provider with no mesh interfaces wakes once an hour, so the authority's
    /// idea of "now" froze between wakeups and every expiry check froze with it.
    /// A clock it reads *itself*, at the moment it needs the answer, cannot go
    /// stale.
    clock: Clock,
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

/// Largest number of pending invitations the authority will hold at once.
///
/// Mirrors [`MAX_HELD_CSRS`], and for one of the same two reasons: the store is
/// persisted, so unbounded growth is growth that survives a restart. The other
/// reason does *not* apply — only a full management grant can add an invite, so
/// this bounds operator error rather than an anonymous flood, which is why it
/// refuses a new mint rather than evicting an incumbent. Evicting would mean an
/// admin's earlier invitation silently stopping working because a later one was
/// issued.
///
/// Sized for the human on the other end, like the held-CSR queue beside it: a
/// list an admin is expected to read row by row and act on is unusable long
/// before 128 entries.
pub(crate) const MAX_PENDING_INVITES: usize = 128;

/// How long an invitation may go unredeemed when the admin does not say: 24
/// hours.
///
/// The bound on how long a bearer token sitting in somebody's chat history is
/// worth anything. Long enough to survive a time zone and a night's sleep,
/// short enough that a token found later is already dead — and the cost of
/// guessing short is one more mint, which is cheap.
pub const DEFAULT_INVITE_TTL_SECS: u64 = 24 * 3600;

/// What a refused registration start is told, whatever the reason.
///
/// One message for an unknown token, an expired one and a spent one. Not to
/// protect an oracle — a 256-bit `OsRng` token is not enumerable, so there is
/// nothing to protect — but because the three are indistinguishable to the
/// person reading it, whose next act is the same in all three cases: ask the
/// admin for a new invitation.
const REGISTRATION_START_REFUSED: &str = "this invitation is not valid: it may have expired, already been used, or been revoked. Ask \
     for a new one.";

/// The longest invitation lifetime an admin may ask for: 7 days.
///
/// [`DEFAULT_INVITE_TTL_SECS`] describes itself as the bound on how long a
/// bearer token sitting in somebody's chat history is worth anything — which it
/// was only while the admin said nothing, since `invite_ttl_secs` was otherwise
/// taken verbatim. This is that bound made real.
///
/// Refused rather than clamped, matching [`check_cert_ttl`] and for the same
/// reason: the admin is standing in front of the error and can fix it, which is
/// not true of the registrant at the other end.
pub const MAX_INVITE_TTL_SECS: u64 = 7 * 24 * 3600;

/// How long a started registration may be resumed for: 15 minutes.
///
/// Much shorter than the invite's own lifetime, and bounding a different thing.
/// The invite's expiry bounds "nobody has started yet"; this bounds "somebody
/// took the second factor and has not finished", which is the window in which a
/// disclosure is still convertible into an account. A registration is a page,
/// a QR code and a six-digit code — fifteen minutes is generous for that and
/// stingy for anything else.
pub(crate) const REGISTRATION_HANDLE_TTL_SECS: u64 = 15 * 60;

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

/// Refuse an account's session lifetime past [`MAX_SESSION_TTL_SECS`], unless
/// the operator took the escape.
///
/// Separate from [`check_cert_ttl`] because a session and a device certificate
/// are bounded by different arguments — see [`MAX_SESSION_TTL_SECS`] — and
/// collapsing them back into one check is how raising a device's lifetime
/// quietly grants a decade-long administrator credential.
fn check_session_ttl(session_ttl_secs: u64, allow_unbounded: bool) -> Result<(), String> {
    if allow_unbounded || session_ttl_secs <= MAX_SESSION_TTL_SECS {
        return Ok(());
    }
    Err(alloc::format!(
        "session_ttl_secs is {session_ttl_secs}s, past the {MAX_SESSION_TTL_SECS}s cap \
         on how long an account's sign-in may last: a session is a person at a \
         keyboard, and a credential that outlives the reason it was granted is what \
         revocation exists to avoid. Shorten it, or set `allow_unbounded_cert_ttl: \
         true` to say the long lifetime is deliberate"
    ))
}

/// Refuse a per-approval certificate lifetime no certificate could usefully
/// carry.
///
/// Zero is its own rejection rather than a case of the cap: a zero-second
/// lifetime issues a certificate that expired before the enrolling node could
/// collect it, taking the node off the mesh on arrival — the opposite of what
/// approving its request meant. Past that it is the same [`check_cert_ttl`]
/// the policy value answers to, since an operator picking a lifetime per
/// device is not a way around passive expiry.
fn check_approval_ttl(cert_ttl_secs: u64, allow_unbounded: bool) -> Result<(), String> {
    if cert_ttl_secs == 0 {
        return Err(
            "cert_ttl_secs must be greater than zero: a zero-second certificate \
             lifetime issues certificates that are already expired"
                .to_string(),
        );
    }
    check_cert_ttl(cert_ttl_secs, allow_unbounded)
}

/// Where a [`CertAuthority`] reads wall-clock time from.
///
/// Time is a trust input here: it decides a certificate's validity window, when
/// an invitation stops being redeemable, when a lockout lifts and how long a
/// revocation is enforced. A wrong clock is not a cosmetic fault — it is an
/// expired bearer token that still works.
///
/// This is an abstraction rather than a bare `SystemTime::now()` for one reason:
/// the properties worth testing here are *all* time-dependent, and a clock that
/// cannot be pinned cannot be tested. [`Clock::Fixed`] is what makes an expiry
/// test deterministic; [`Clock::System`] is what makes production correct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Clock {
    /// The host's system clock, read afresh at every use, gated on the host's
    /// own NTP verdict.
    ///
    /// What a real provider runs on, and the only variant that cannot go stale:
    /// it is read at the moment it is needed rather than pushed in beforehand by
    /// something whose own schedule decides how often it bothers.
    ///
    /// Two independent checks, catching two different wrong clocks. The
    /// [`ClockTrust`] policy asks whether anything is *disciplining* this clock
    /// — the case of a node that booted before NTP reached it, whose reading is
    /// plausible and hours out. `MIN_PLAUSIBLE_UNIX` then catches a clock that
    /// was never set at all, which reads as 1970.
    ///
    /// The floor is not redundant with the gate: it is what still holds on the
    /// paths where the gate passes *by construction* — an operator who set
    /// `require_time_sync = false`, and a platform that exposes no NTP status
    /// at all. Either failing yields the same zero, because to every caller
    /// they are the same fact: there is no usable time here.
    System(ClockTrust),
    /// A fixed instant, in unix seconds.
    ///
    /// For tests, and for a caller that owns its own clock. `Fixed(0)` is the
    /// "no clock yet" state that every issuing path refuses, and is what a
    /// [`CertAuthority::new`] starts in.
    ///
    /// **Not** subject to [`MIN_PLAUSIBLE_UNIX`], deliberately: a fixed time is
    /// a value the caller chose, and flooring it would make a test asking about
    /// second 100 silently ask about something else. The floor exists for the
    /// reading nobody chose.
    Fixed(u64),
}

impl Clock {
    /// The current time in unix seconds, or zero when there is no usable clock.
    fn now_unix(self) -> u64 {
        match self {
            Clock::Fixed(secs) => secs,
            // Nothing vouches for this reading, so it is worth exactly as much
            // as no reading at all. Checked before the clock is read at all: an
            // untrusted reading is not wanted even to log.
            Clock::System(trust) if !wayfinder_clock_trust::read(trust).is_trusted() => 0,
            Clock::System(_) => plausible_or_zero(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|since| since.as_secs())
                    // A system clock before the unix epoch is as unusable as one
                    // that was never set, and lands in the same place.
                    .unwrap_or(0),
            ),
        }
    }

    /// What the host says about this clock's discipline, for the operator-facing
    /// projection and the alarm.
    ///
    /// A [`Clock::Fixed`] is a value its caller chose, so there is nothing to
    /// ask the host about and it reports [`ClockSync::Unsupported`] — "no
    /// verdict is being enforced here", which is exactly true of a pinned clock.
    fn sync(self) -> ClockSync {
        match self {
            Clock::Fixed(_) => ClockSync::Unsupported,
            Clock::System(trust) => wayfinder_clock_trust::read(trust),
        }
    }
}

/// Map a host-clock reading below [`MIN_PLAUSIBLE_UNIX`] onto the fail-closed
/// zero, passing a plausible one through.
///
/// Split out so the boundary is testable without a machine whose clock is
/// actually wrong, and `pub(crate)` so the driver's own host-clock read applies
/// the *same* floor this one does — two components reading the host clock with
/// different notions of "plausible" is how they end up disagreeing about
/// whether a certificate is inside its window.
pub(crate) fn plausible_or_zero(secs: u64) -> u64 {
    if secs < MIN_PLAUSIBLE_UNIX { 0 } else { secs }
}

/// Whether an invitation is still capable of producing an account.
///
/// The two states expire on different clocks: a `Pending` invitation dies at
/// its own expiry, while a `Started` one dies when its handle window closes —
/// its original expiry is superseded the moment the secret is revealed.
///
/// Shared by [`CertAuthority::evict_expired_invites`] and
/// [`CertAuthority::list_user_invites`] so the sweep and the admin's listing
/// cannot drift apart about what counts as an invitation.
fn invite_is_live(invite: &UserInvite, now_unix: u64) -> bool {
    match invite.status {
        InviteStatus::Pending => !invite.is_expired(now_unix),
        InviteStatus::Started {
            handle_expires_at, ..
        } => now_unix < handle_expires_at,
    }
}
/// What an authority did with a renewal that arrived over the mesh.
///
/// Two outcomes, not three, and the missing one is the point: there is no
/// `Pending`. A request this authority cannot answer is refused rather than
/// queued for an operator — see
/// [`renew_holder`](CertAuthority::renew_holder) for why a held row is
/// something an unattended board must not be able to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewalOutcome {
    /// Re-issued: the raw `MembershipCert` bytes to send back.
    ///
    /// No trust anchor travels with it, unlike `EnrollData`. The node asking
    /// already holds the anchor — it is what it verified the certificate it is
    /// *currently* running under against, and what it will verify this one
    /// against before installing it — so sending a second copy would be bytes
    /// on a radio that change nothing.
    Issued(Vec<u8>),
    /// Refused, with a reason for the authority's operator.
    ///
    /// Not sent back to the asker. A `RenewReply` carries a certificate or
    /// nothing at all, so a refusal reaches the board as silence and then as
    /// the gap between its own sent/accepted counters — which is the honest
    /// channel, since a node that cannot be renewed needs an operator either
    /// way and a message it could not act on would only be one more thing to
    /// spoof.
    Refused(String),
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
            // No clock until one is set. `from_config` — the production path —
            // immediately replaces this with `Clock::System`; a test that never
            // sets one is exercising the fail-closed state on purpose.
            clock: Clock::Fixed(0),
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
    ///
    /// **This is the production path, and it is what puts the authority on
    /// [`Clock::System`].** Every real provider — `wayfinder-tap`'s node and
    /// `wayfinderctl`'s offline commands — arrives here, so a provider reads the
    /// host clock and needs nobody to refresh it. [`Self::new`] deliberately
    /// does not: it is the constructor tests and mocks use, and starting it at
    /// `Clock::Fixed(0)` is what lets a test choose its own time — or assert the
    /// fail-closed behaviour of an authority that has none.
    pub fn from_config(root_seed: &[u8; 32], cfg: &ProviderConfig) -> Result<Self, String> {
        check_cert_ttl(cfg.cert_ttl_secs, cfg.allow_unbounded_cert_ttl)?;
        let log = CaLog::load(cfg.state_path.as_ref().map(PathBuf::from))?;
        let mut ca = Self {
            pending_ttl_secs: cfg.pending_ttl_secs,
            allow_unbounded_cert_ttl: cfg.allow_unbounded_cert_ttl,
            log,
            clock: Clock::System(ClockTrust::default()),
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

    /// Pin this authority to a fixed instant (unix seconds).
    ///
    /// Equivalent to `set_clock(Clock::Fixed(now_unix))`, and kept under its
    /// original name because that is what nearly every test in this workspace
    /// means by it: "the time is now this". A provider does **not** call it —
    /// `from_config` gives it [`Clock::System`], which needs no refreshing.
    pub fn set_now_unix(&mut self, now_unix: u64) {
        self.set_clock(Clock::Fixed(now_unix));
    }

    /// Choose where this authority reads time from.
    pub fn set_clock(&mut self, clock: Clock) {
        self.clock = clock;
    }

    /// The current time in unix seconds, or zero when there is no usable clock
    /// — which every issuing path in this module refuses to act on.
    ///
    /// A method rather than a field because [`Clock::System`] has to be read at
    /// the moment of use. The whole point is that there is no stored "now" to go
    /// stale between one request and the next.
    pub fn now_unix(&self) -> u64 {
        self.clock.now_unix()
    }

    /// What the host says about this clock's discipline.
    ///
    /// Exists so a refusal can be *explained*. Every issuing path here fails on
    /// `now_unix() == 0`, which is the same sentinel for "never set" and "not
    /// trusted"; without this an operator would see a node refusing to sign and
    /// have nothing to distinguish a clock nobody ever set from one NTP has not
    /// reached yet.
    #[must_use]
    pub fn clock_sync(&self) -> ClockSync {
        self.clock.sync()
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
    ///
    /// `ttl_secs` is the validity window to sign for; `None` takes the
    /// authority's policy default. A renewal passes the lifetime the holder's
    /// existing record carries, so a device an operator admitted for its own
    /// length keeps that length instead of quietly reverting to the default on
    /// its next poll.
    pub(crate) fn issue(
        &mut self,
        mac: Mac,
        ed: [u8; 32],
        x: [u8; 32],
        ttl_secs: Option<u64>,
    ) -> Result<EnrollData, String> {
        let ttl_secs = ttl_secs.unwrap_or(self.cert_ttl_secs);
        let (cert, record) = self.sign(mac, ed, x, ttl_secs);

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
    fn sign(
        &self,
        mac: Mac,
        ed: [u8; 32],
        x: [u8; 32],
        ttl_secs: u64,
    ) -> (MembershipCert, IssuedCertData) {
        let not_before = self.now_unix();
        let not_after = self.now_unix().saturating_add(ttl_secs);
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
            // A device's certificate belongs to no account: nobody signed in
            // to obtain it, so there is nothing for a per-account revocation
            // to match it against.
            account_id: Vec::new(),
        };
        (cert, record)
    }

    /// Sign a *user session* certificate for `(mac, ed, x)` with `ttl_secs` of
    /// validity and the capability `role` names, and build its record.
    ///
    /// Separate from [`Self::sign`] rather than a flags argument on it, for the
    /// same reason `issue_user_cert` is separate from `issue_cert`: the two
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
        account: AccountId,
    ) -> (MembershipCert, IssuedCertData) {
        let admin = role == UserRole::Admin;
        let not_before = self.now_unix();
        let not_after = self.now_unix().saturating_add(ttl_secs);
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
            // The whole point of the record: without this the log knows a
            // person's session exists and not whose, which makes "end this
            // account's access" unanswerable.
            account_id: account.as_bytes().to_vec(),
        };
        (cert, record)
    }
    /// What this authority's issued log says about `mac` as of now: whether the
    /// live certificate it holds was issued to `ed`, whether it is revoked, and
    /// the window it was approved for.
    ///
    /// `None` when the address holds no certificate inside its validity window
    /// — never certified here, or certified and lapsed.
    ///
    /// **Shared by both doors into re-issue** — `submit_csr` over the management
    /// API and `renew_holder` over the mesh — because "is this a live holder"
    /// is a security question the two must answer identically. They had this
    /// expression byte-for-byte twice, which is exactly the shape that drifts:
    /// a later change tightening one door and not the other would leave the
    /// looser one as the way in.
    fn live_holder(&self, mac: Mac, ed: &[u8; 32]) -> Option<(bool, bool, u64)> {
        self.log
            .issued()
            .iter()
            .find(|c| c.node_mac == mac.0 && self.now_unix() <= c.not_after)
            .map(|c| {
                (
                    c.ed_pubkey == *ed,
                    c.revoked,
                    c.not_after.saturating_sub(c.not_before),
                )
            })
    }

    /// Re-issue for a holder that asked **over the mesh** (design 24).
    ///
    /// The holder match and nothing else: a node whose certificate is still
    /// inside its validity window, under the key that record names and not
    /// revoked, is re-issued on the spot for the window its own record carries
    /// — the lifetime an operator approved this device for, not this
    /// authority's current default.
    ///
    /// # Why this is not `submit_csr`
    ///
    /// The two agree exactly on the case that succeeds, and differ on every
    /// case that does not, which is the whole reason this is a second entry
    /// point rather than a second caller.
    ///
    /// `submit_csr` **parks** a request it cannot answer, so an operator can
    /// approve it. That is right for a request arriving over authenticated TLS,
    /// where somebody is standing at a terminal. It is wrong for one arriving
    /// over the mesh: a held row is credential-bearing state, and a lapsed
    /// board would create one unattended, once per rate-limit interval, for as
    /// long as it stayed lapsed. So this refuses instead, and queues nothing.
    ///
    /// It also takes no enrollment token, because the request carries none: the
    /// `RenewReq` body is a certificate this authority signed plus a proof of
    /// possession, which the router has already verified. A token would add a
    /// second secret for a board to hold and nothing to what is proved.
    ///
    /// # What a refusal means
    ///
    /// That this node cannot be renewed over the mesh at all — lapsed, revoked,
    /// never certified here, or naming an address its key does not derive — and
    /// that the remedy is an operator's, over the serial port. Renewal cannot
    /// rescue it, and pretending otherwise would convert a certificate's
    /// lifetime from a revocation bound into a formality (design 24 §5.2).
    ///
    /// `Err` is reserved for the request being *unserviceable* — this
    /// authority has no usable clock — exactly as it is on
    /// [`submit_csr`](MeshAuthority::submit_csr).
    pub fn renew_holder(
        &mut self,
        node_mac: &[u8],
        ed_pubkey: &[u8],
        x_pubkey: &[u8],
    ) -> Result<RenewalOutcome, String> {
        // Fail closed on an unset clock, for `submit_csr`'s reason: a
        // certificate issued against the epoch is already expired against any
        // real clock, and here it would also fail the board's
        // must-move-forward rule and be discarded after a full round trip.
        if self.now_unix() == 0 {
            return Err(
                "the authority has no usable clock (never set, a host clock reading \
                 before 2025, or a clock no time daemon is disciplining — check \
                 chronyd and the hardware clock); cannot issue certificates yet"
                    .to_string(),
            );
        }
        let mac = node_mac_of(node_mac)?;
        let ed = fixed::<32>(ed_pubkey, "ed_pubkey")?;
        let x = fixed::<32>(x_pubkey, "x_pubkey")?;
        // The address must be the one this key derives. Checked here as well as
        // at `submit_csr` because this is a second door into the same act, and
        // a binding enforced at one door is not enforced.
        if let Err(why) = check_mac_derives_from(mac, &ed, false) {
            return Ok(RenewalOutcome::Refused(why));
        }

        let holder = self.live_holder(mac, &ed);

        let Some((same_key, revoked, held_ttl_secs)) = holder else {
            // Either never certified here, or certified and lapsed. Told apart
            // in the log — the two have different remedies — but not in the
            // refusal, which is answered to a node that already knows which it
            // is and would learn nothing from being told.
            tracing::debug!(
                node_mac = ?mac,
                "refused a mesh renewal: no live certificate on file for this address"
            );
            return Ok(RenewalOutcome::Refused(
                "this address holds no live certificate from this authority; it must be \
                 enrolled and approved before it can renew"
                    .to_string(),
            ));
        };

        if !same_key {
            // Reachable only through a legacy `issued` row: the binding above
            // already refused any key that does not derive this address. Logged
            // as a `warn!` for the reason `submit_csr`'s sibling is — an
            // operator watching a MAC collision needs to tell it from a node
            // that is merely stuck.
            tracing::warn!(
                node_mac = ?mac,
                "drop: mesh renewal for a MAC already certified under a different key"
            );
            return Ok(RenewalOutcome::Refused(
                "this MAC already has a certificate under a different key".to_string(),
            ));
        }
        if revoked {
            // Never re-issued, which would clear the `revoked` flag the record
            // stands on. Revocation ejects a node that still holds its own key,
            // so the key is exactly what the ejected party has.
            tracing::warn!(
                node_mac = ?mac,
                "drop: mesh renewal from a revoked holder"
            );
            return Ok(RenewalOutcome::Refused(
                "this node has been revoked from the mesh".to_string(),
            ));
        }

        let issued = self.issue(mac, ed, x, Some(held_ttl_secs))?;
        tracing::info!(
            node_mac = ?mac,
            ttl_secs = held_ttl_secs,
            "re-issued a membership certificate to a holder renewing over the mesh"
        );
        Ok(RenewalOutcome::Issued(issued.cert))
    }

    /// Add a user account, refusing a name that already exists.
    ///
    /// Two callers. `MeshAuthority::create_user` is this act performed by an
    /// already-admitted administrator over the wire, and the bootstrap path is
    /// the same request made by an operator on the provider host presenting the
    /// node's own identity seed — which authenticates at the self-key tier and
    /// so needs no account to exist yet. (Before design 15 the second caller
    /// was `wayfinderctl user add` writing the state file directly, which raced
    /// the provider's own writes.)
    pub fn add_user(&mut self, user: UserRecord) -> Result<(), String> {
        self.evict_expired_invites()?;
        self.check_name_available(&user.username)?;
        let (_, persisted) = self.log.mutate_users(|users| users.push(user));
        persisted
    }

    /// Refuse `username` if it is empty, longer than [`MAX_USERNAME_LEN`],
    /// already an account, or already invited.
    ///
    /// The invite half is the one that is easy to leave out, and leaving it out
    /// is not merely untidy: an admin creating an account for a name that has a
    /// pending invite would silently strand that invite until it expired, and
    /// the invitee's registration would fail with nothing to point at. Every
    /// path that claims a name goes through here, in both directions.
    fn check_name_available(&self, username: &str) -> Result<(), String> {
        if username.is_empty() {
            return Err("username must not be empty".to_string());
        }
        // Bounded because the name is persisted in the state snapshot, repeated
        // in every audit record about the account, and carried in the
        // `otpauth://` enrolment URI — see `MAX_USERNAME_LEN`. Checked here, in
        // the one predicate every creating path already consults, rather than
        // in each of `add_user`/`create_user`/`create_user_invite`.
        if username.len() > MAX_USERNAME_LEN {
            return Err(alloc::format!(
                "username must be at most {MAX_USERNAME_LEN} bytes"
            ));
        }
        if self.log.users().iter().any(|u| u.username == username) {
            return Err(alloc::format!("user {username} already exists"));
        }
        if self.log.invites().iter().any(|i| i.username == username) {
            return Err(alloc::format!(
                "user {username} has already been invited; revoke that invitation first, or \
                 wait for it to expire"
            ));
        }
        Ok(())
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
                locked: u.is_locked(self.now_unix()),
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

    /// Revoke every session certificate `username` currently holds, signing one
    /// [`RevocationRecord`] per certificate for the caller to flood.
    ///
    /// The control an administrator reaches for when somebody's laptop is lost
    /// and they still work here: the account keeps its credentials and can sign
    /// in again, but nothing it was already holding is honoured. That is the
    /// whole difference from [`Self::remove_user_revoking_sessions`].
    ///
    /// The returned records are *already durably marked* revoked here and are
    /// not yet announced to the mesh. A caller that drops them leaves the
    /// authority believing something the mesh was never told — which is why the
    /// adapter's `finish` is `#[must_use]`.
    pub fn revoke_user_sessions(
        &mut self,
        username: &str,
    ) -> Result<Vec<RevocationRecord>, String> {
        let account = self.account_id_of(username)?;
        let sessions = self.live_sessions_of(account);
        self.revoke_sessions(username, &sessions, |log, revoked| {
            let (_, persisted) = log.mutate_issued(|issued| mark_revoked(issued, revoked));
            persisted
        })
    }

    /// Delete `username` **and** revoke every session certificate it holds, as
    /// one durable write.
    ///
    /// The raw [`Self::remove_user`] above ends the account's ability to obtain
    /// *new* sessions and nothing more, which is what made deleting a
    /// compromised account leave the compromise running. This is that act done
    /// completely.
    ///
    /// Deletion and revocation share one [`crate::persistence::CaLog::
    /// mutate_users_and_issued`] call rather than two, so they cannot durably
    /// split: either the account is gone and its sessions are revoked, or
    /// neither happened. The direction that matters is the first one — an
    /// account deleted whose sessions came back un-revoked is this method's own
    /// bug, reintroduced in the window where nobody would look for it.
    ///
    /// Carries no last-administrator guard: like [`Self::remove_user`], this is
    /// the raw act, and [`MeshAuthority::remove_user`] is where the policy that
    /// refuses to strand the mesh lives.
    pub fn remove_user_revoking_sessions(
        &mut self,
        username: &str,
    ) -> Result<Vec<RevocationRecord>, String> {
        let account = self.account_id_of(username)?;
        let sessions = self.live_sessions_of(account);
        let name = username.to_string();
        self.revoke_sessions(username, &sessions, move |log, revoked| {
            let (_, persisted) = log.mutate_users_and_issued(|users, issued| {
                users.retain(|u| u.username != name);
                mark_revoked(issued, revoked);
            });
            persisted
        })
    }

    /// Set `username`'s role, revoking every session certificate the change
    /// invalidates, as one durable write.
    ///
    /// **A demotion revokes.** The capability is stamped on the certificate,
    /// not read from the account at each request, so a session minted while the
    /// account was an administrator goes on administering until it is revoked
    /// or expires. Changing only what the account is issued *next* would report
    /// an access as removed while its holder still had it — the gap design 14
    /// closed for `RemoveUser`.
    ///
    /// **A promotion does not.** The certificates the account holds now grant
    /// less than the account does, which costs its holder one sign-in and
    /// nobody any access; revoking them would spend mesh airtime for nothing.
    ///
    /// Restating the role an account already holds is a success that writes and
    /// revokes nothing — the call an operator makes when unsure the first one
    /// landed must not cut off a session on its way through. That case is
    /// reported as `false` in the returned pair rather than being
    /// indistinguishable from a change that revoked nothing: a promotion also
    /// returns no records, so the vector alone cannot tell an operator whether
    /// anything happened. Reporting it here is what lets the layers above stop
    /// re-deriving the same answer from a second roster read.
    ///
    /// The role change and the revocations share one
    /// [`CaLog::mutate_users_and_issued`] call, for the reason
    /// [`Self::remove_user_revoking_sessions`] gives: they must not durably
    /// split, and the direction that matters is a demotion recorded whose
    /// admin sessions came back un-revoked.
    ///
    /// Carries no last-administrator guard — like the raw removal above, this
    /// is the act, and [`MeshAuthority::set_user_role`] is where the policy
    /// that refuses to strand the mesh lives.
    pub fn set_user_role_revoking_sessions(
        &mut self,
        username: &str,
        role: UserRole,
    ) -> Result<(Vec<RevocationRecord>, bool), String> {
        let account = self.account_id_of(username)?;
        if self.user_record(username)?.role == role {
            return Ok((Vec::new(), false));
        }
        let sessions = match role {
            UserRole::Viewer => self.live_sessions_of(account),
            UserRole::Admin => Vec::new(),
        };
        let name = username.to_string();
        self.revoke_sessions(username, &sessions, move |log, revoked| {
            let (_, persisted) = log.mutate_users_and_issued(|users, issued| {
                if let Some(user) = users.iter_mut().find(|u| u.username == name) {
                    user.role = role;
                }
                mark_revoked(issued, revoked);
            });
            persisted
        })
        .map(|records| {
            tracing::info!(%username, ?role, "changed an account's role");
            (records, true)
        })
    }

    /// Enable or disable `username`, revoking every session certificate the
    /// change invalidates, as one durable write.
    ///
    /// **Disabling revokes**, for the reason a demotion does above: an account
    /// that obtains no *new* session while every certificate it already holds
    /// keeps working is disabled only in the future tense, and an operator
    /// disabling an account believes access stopped now.
    ///
    /// **Enabling revokes nothing and clears the lockout** — an operator
    /// turning an account back on means it should work, not that it should work
    /// in fifteen minutes.
    ///
    /// Restating the state an account is already in writes nothing, and is
    /// reported as `false` in the returned pair — see
    /// [`Self::set_user_role_revoking_sessions`] for why the vector alone
    /// cannot carry that.
    ///
    /// Carries no last-administrator guard; see
    /// [`Self::set_user_role_revoking_sessions`].
    pub fn set_user_enabled_revoking_sessions(
        &mut self,
        username: &str,
        enabled: bool,
    ) -> Result<(Vec<RevocationRecord>, bool), String> {
        let account = self.account_id_of(username)?;
        // A lockout counts as something to change, not just the `disabled`
        // flag. The two are independent — five failed sign-ins lock an account
        // that was never disabled — and that is the state an operator reaches
        // for `enable` to clear. Keyed on `disabled` alone, this answered
        // "already enabled" and left the lockout standing, in the case the
        // command is most often typed for.
        let record = self.user_record(username)?;
        let already_enabled = record.disabled != enabled;
        let nothing_to_clear = !enabled || !record.is_locked(self.now_unix());
        if already_enabled && nothing_to_clear {
            return Ok((Vec::new(), false));
        }
        let sessions = if enabled {
            Vec::new()
        } else {
            self.live_sessions_of(account)
        };
        let name = username.to_string();
        self.revoke_sessions(username, &sessions, move |log, revoked| {
            let (_, persisted) = log.mutate_users_and_issued(|users, issued| {
                if let Some(user) = users.iter_mut().find(|u| u.username == name) {
                    user.disabled = !enabled;
                    if enabled {
                        user.failed_attempts = 0;
                        user.locked_until = 0;
                    }
                }
                mark_revoked(issued, revoked);
            });
            persisted
        })
        .map(|records| {
            tracing::info!(%username, enabled, "changed an account's enabled state");
            (records, true)
        })
    }

    /// Replace `username`'s password, clearing any lockout with it.
    ///
    /// The administrative reset, for somebody who has lost their password. It
    /// leaves the second factor alone: an operator able to replace both could
    /// take an account over in one act and leave its owner no signal, and
    /// whoever needs a fresh factor gets a fresh invite.
    ///
    /// Revokes nothing, deliberately. A forgotten password is the common case,
    /// and ending every device its owner is signed in on is a larger act than
    /// was asked for; when the reset answers a compromise,
    /// [`Self::revoke_user_sessions`] is the act that says so.
    pub fn set_user_password(&mut self, username: &str, password: &str) -> Result<(), String> {
        let mut failed = None;
        self.update_user(username, |user| {
            // `set_password` can fail (an empty password, Argon2 parameters)
            // and the callback returns nothing, so the failure is carried out
            // rather than swallowed: a "changed" password that did not change
            // is the worst outcome available here.
            if let Err(e) = user.set_password(password) {
                failed = Some(e);
            }
        })?;
        match failed {
            Some(e) => Err(e),
            None => {
                // Named here and never in the audit record, which carries the
                // request kind and no fields — so this is the only place the
                // question "whose password was reset, and when?" is answerable
                // on a node whose log ring is its audit trail. The password
                // itself is not logged, here or anywhere.
                tracing::info!(%username, "reset an account's password");
                Ok(())
            }
        }
    }

    /// Refuse `act` when it would leave the mesh with nobody who can administer
    /// it over the management API.
    ///
    /// Three acts reach here — removing, demoting and disabling — and they
    /// leave the same mesh: one whose user store no ordinary session can change
    /// in either direction, because every request that could change it needs a
    /// full management grant and only an administrator's session carries one.
    /// A guard on removal alone would be a locked front door beside an open
    /// window.
    ///
    /// Counted before the act rather than after, so the check reads as the
    /// question being asked. A disabled account is not an answer to it — it
    /// obtains no session and so administers nothing — which is also why
    /// disabling is one of the three acts guarded.
    ///
    /// Every caller evaluates this *before* signing anything, so a refusal has
    /// revoked nothing: the account it declined to touch keeps the sessions it
    /// holds.
    fn refuse_to_strand_the_mesh(&self, username: &str, act: &str) -> Result<(), String> {
        let enabled_admins = || {
            self.log
                .users()
                .iter()
                .filter(|u| u.role == UserRole::Admin && !u.disabled)
        };
        let is_enabled_admin = enabled_admins().any(|u| u.username == username);
        let is_the_last = enabled_admins().all(|u| u.username == username);
        if is_enabled_admin && is_the_last {
            return Err(alloc::format!(
                "refusing to {act} the last administrator: no account would be left that can \
                 administer this mesh over the management API. Create another administrator \
                 first — an operator on the provider host can do that against the running \
                 provider with `wayfinderctl user add --identity <node identity seed>`, which \
                 authenticates as the node itself."
            ));
        }
        Ok(())
    }

    /// The stored record for `username`, or an error naming what is missing.
    fn user_record(&self, username: &str) -> Result<&UserRecord, String> {
        self.log
            .users()
            .iter()
            .find(|u| u.username == username)
            .ok_or_else(|| alloc::format!("no such user: {username}"))
    }

    /// Sign a revocation for each of `sessions`, apply `commit` to record them,
    /// and return the signed records.
    ///
    /// The shared middle of the two paths above. Signing happens *before* the
    /// commit and outside it, because signing is stateless local computation
    /// with nothing to roll back — so a failed persist rolls the store back and
    /// the records are dropped without ever having been announced, which is the
    /// truthful outcome to report.
    fn revoke_sessions(
        &mut self,
        username: &str,
        sessions: &[(Mac, u64)],
        commit: impl FnOnce(&mut CaLog, &[Mac]) -> Result<(), String>,
    ) -> Result<Vec<RevocationRecord>, String> {
        // Only when there is something to sign. An account with no live
        // sessions is removable on a node whose clock was never set, exactly as
        // it is today; what must not happen is signing a window that starts at
        // the epoch and is already over.
        if !sessions.is_empty() && self.now_unix() == 0 {
            return Err("authority clock not set; cannot sign revocations yet".to_string());
        }
        let records: Vec<RevocationRecord> = sessions
            .iter()
            // The certificate's *own* expiry, not this authority's
            // `cert_ttl_secs`. A session's lifetime belongs to the account that
            // holds it and may be longer than the authority's, in which case
            // the conservative guess `Self::revoke` makes for a device would
            // stop being enforced while the certificate it cancels still
            // verified — a revocation with a hole at the end of it.
            .map(|(mac, not_after)| self.authority.revoke(*mac, self.now_unix(), *not_after))
            .collect();
        let macs: Vec<Mac> = sessions.iter().map(|(mac, _)| *mac).collect();
        commit(&mut self.log, &macs)?;
        // Logged even at zero: "revoked nothing" is the answer to a question an
        // operator asked, and its absence reads as a failure.
        tracing::info!(
            %username,
            count = records.len(),
            "revoked an account's session certificates"
        );
        Ok(records)
    }

    /// Whether `username` holds at least one session certificate that revoking
    /// would actually end.
    ///
    /// The question a caller asks *before* signing anything, so that a gate on
    /// "can this node flood a revocation?" applies to acts that revoke and not
    /// to acts that merely turn out to have nothing to revoke — see
    /// `AuthorityAdapter::gated_session_revocation`. An unknown account holds
    /// nothing, which lets the "no such user" error come from the act itself
    /// rather than from a gate that would have masked it.
    pub fn has_live_sessions(&self, username: &str) -> bool {
        !self.live_session_macs(username).is_empty()
    }

    /// The MACs of the session certificates `username` currently holds.
    ///
    /// Public because the question "what would revoking this account end?" is
    /// worth asking without answering it — [`Self::has_live_sessions`] is the
    /// gate `AuthorityAdapter` applies before signing anything, and it is built
    /// from this. It was once public for `wayfinderctl user remove`, which
    /// operated on the state file with no router beside it and so could only
    /// *name* the certificates it was leaving live; that path is gone, and the
    /// act it could not perform is now an ordinary request.
    pub fn live_session_macs(&self, username: &str) -> Vec<Mac> {
        self.account_id_of(username)
            .map(|account| {
                self.live_sessions_of(account)
                    .into_iter()
                    .map(|(mac, _)| mac)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The stable id of `username`, or an error naming what is missing.
    fn account_id_of(&self, username: &str) -> Result<AccountId, String> {
        self.log
            .users()
            .iter()
            .find(|u| u.username == username)
            .map(|u| u.id)
            .ok_or_else(|| alloc::format!("no such user: {username}"))
    }

    /// The MAC and expiry of every session certificate `account` currently
    /// holds and that is worth revoking.
    ///
    /// Two exclusions, both deliberate. An **already-revoked** entry is skipped
    /// because re-sending costs mesh airtime to say something the mesh already
    /// believes — the same rule the dashboard's Members tab applies to a node
    /// that is already revoked. An **expired** one is skipped because passive
    /// expiry has already ended it, and a record enforcing a window that is
    /// over ends nothing.
    fn live_sessions_of(&self, account: AccountId) -> Vec<(Mac, u64)> {
        self.log
            .issued()
            .iter()
            .filter(|c| c.user && !c.revoked && c.not_after > self.now_unix())
            .filter(|c| account.matches(&c.account_id))
            .filter_map(|c| Some((Mac(c.node_mac.as_slice().try_into().ok()?), c.not_after)))
            .collect()
    }

    /// Mint a one-time invitation for `username`, returning the token that
    /// redeems it — the one moment that token is readable anywhere.
    ///
    /// The admin decides *who* gets an account and *what role it has*, here and
    /// once. What they do not decide, and never see, is the account's password
    /// or its second factor: the TOTP secret is minted with the invite and
    /// revealed only to whoever redeems it.
    ///
    /// A zero `session_ttl_secs` takes [`DEFAULT_SESSION_TTL_SECS`]; a zero
    /// `invite_ttl_secs` takes [`DEFAULT_INVITE_TTL_SECS`].
    ///
    /// The lifetime is refused here rather than clamped — the admin is standing
    /// in front of the error and can fix it, which is not true of the registrant
    /// at the other end (see [`Self::complete_user_registration`]).
    pub fn create_user_invite(
        &mut self,
        username: &str,
        role: UserRole,
        session_ttl_secs: u64,
        invite_ttl_secs: u64,
    ) -> Result<MintedInvite, String> {
        // Same fail-closed rule as `submit_csr`: without a clock this would
        // mint an invitation whose window starts at the epoch and is over.
        if self.now_unix() == 0 {
            return Err(
                "the authority has no usable clock (never set, a host clock reading \
                 before 2025, or a clock no time daemon is disciplining — check \
                 chronyd and the hardware clock); cannot mint an invitation yet"
                    .to_string(),
            );
        }
        self.evict_expired_invites()?;
        self.check_name_available(username)?;
        if self.log.invites().len() >= MAX_PENDING_INVITES {
            return Err(alloc::format!(
                "the invitation store is full ({MAX_PENDING_INVITES} pending): revoke an \
                 outstanding invitation, or wait for one to expire"
            ));
        }
        let ttl = if session_ttl_secs == 0 {
            DEFAULT_SESSION_TTL_SECS
        } else {
            session_ttl_secs
        };
        // Refused at mint rather than at the completion it would make
        // impossible: an invitation whose account the provider will not sign
        // sessions for is one that looks issued and is not usable, and the
        // admin finds out from the person they invited.
        check_session_ttl(ttl, self.allow_unbounded_cert_ttl)?;
        // The same rule for the *invitation's* own lifetime, which was
        // previously taken verbatim however long the caller asked for.
        if invite_ttl_secs > MAX_INVITE_TTL_SECS {
            return Err(alloc::format!(
                "invite_ttl_secs is {invite_ttl_secs}s, past the {MAX_INVITE_TTL_SECS}s cap: an \
                 invitation is a bearer token sitting in somebody's chat history, and one that \
                 outlives the conversation cannot be recalled. Shorten it, or mint again when it \
                 expires"
            ));
        }

        let token = crate::users::generate_invite_secret();
        let expires_at = self.now_unix().saturating_add(if invite_ttl_secs == 0 {
            DEFAULT_INVITE_TTL_SECS
        } else {
            invite_ttl_secs
        });
        let invite = UserInvite::new(
            username,
            role,
            ttl,
            crate::users::invite_token_hash(&token),
            self.now_unix(),
            expires_at,
        );
        let (_, persisted) = self.log.mutate_invites(|invites| invites.push(invite));
        persisted?;

        // The name and the role, never the token and never the secret.
        tracing::info!(%username, ?role, expires_at, "minted a user invitation");
        Ok(MintedInvite {
            username: username.to_string(),
            token,
            expires_at,
        })
    }

    /// The invitations on file, for an admin triaging them.
    ///
    /// Never carries a token hash or a TOTP secret out of this module, for the
    /// same reason [`Self::list_users`] carries no password hash: a summary type
    /// makes that a property of the API rather than of every call site
    /// remembering which fields not to print.
    ///
    /// **Dead invitations are filtered, not swept.** This is a read — the
    /// provider trait behind it takes `&self` — so an entry past its expiry or
    /// its handle window is omitted here and removed by the next mutating call.
    /// Without the filter, an admin triaging a quiet provider would be shown
    /// rows that can never produce an account, including ones carrying the
    /// `started_at` this panel documents as meaning *act now*: a resolved
    /// disclosure presented as a live one.
    pub fn list_user_invites(&self) -> Vec<InviteSummary> {
        let now = self.now_unix();
        self.log
            .invites()
            .iter()
            .filter(|i| invite_is_live(i, now))
            .map(|i| {
                let (started_at, handle_expires_at) = match &i.status {
                    InviteStatus::Pending => (None, None),
                    InviteStatus::Started {
                        started_at,
                        handle_expires_at,
                        ..
                    } => (Some(*started_at), Some(*handle_expires_at)),
                };
                InviteSummary {
                    username: i.username.clone(),
                    role: i.role,
                    session_ttl_secs: i.session_ttl_secs,
                    created_at: i.created_at,
                    expires_at: i.expires_at,
                    started_at,
                    handle_expires_at,
                }
            })
            .collect()
    }

    /// Delete the invitation minted for `username`, whatever its status.
    ///
    /// The started case is the one this exists for: a start the admin did not
    /// expect means the token reached somebody it should not have, and
    /// revoke-then-re-mint is the whole response.
    pub fn revoke_user_invite(&mut self, username: &str) -> Result<(), String> {
        let (found, persisted) = self.log.mutate_invites(|invites| {
            let before = invites.len();
            invites.retain(|i| i.username != username);
            invites.len() != before
        });
        // Before the not-found answer, deliberately: `Persisted::mutate`
        // attempts a write whatever the closure did, so `persisted` carries a
        // real verdict on this path too. An admin who typo'd a username and an
        // admin whose node cannot write its state file need different answers,
        // and the second is the more important one.
        persisted?;
        if !found {
            return Err(alloc::format!("no invitation on file for {username}"));
        }
        tracing::info!(%username, "revoked a user invitation");
        Ok(())
    }

    /// Redeem `token`: reveal the account's second factor and issue the handle
    /// that alone can finish the registration.
    ///
    /// **This consumes the invitation**, and that is the design's load-bearing
    /// decision rather than an implementation detail. A start that could be
    /// repeated would let anyone who read the invitation URL out of a chat log,
    /// a clipboard or a browser history take the account's TOTP secret, while
    /// the legitimate registration still completed normally and nothing
    /// anywhere recorded that a second party holds it — which is today's
    /// property with detectability removed. Spending the invitation converts a
    /// silent disclosure into a burnt invitation and a failed registration the
    /// invitee reports.
    ///
    /// The cost is that a mid-registration page refresh has to carry the
    /// handle. A genuinely abandoned registration is re-minted by the admin,
    /// which is cheap and is also the correct response to "something odd
    /// happened".
    ///
    /// No password hashing happens on this path at all, including for an
    /// unknown token — see [`Self::complete_user_registration`] for why that is
    /// deliberate rather than an oversight.
    pub fn begin_user_registration(&mut self, token: &str) -> Result<StartedRegistration, String> {
        if self.now_unix() == 0 {
            return Err(
                "the authority has no usable clock (never set, a host clock reading \
                 before 2025, or a clock no time daemon is disciplining — check \
                 chronyd and the hardware clock); cannot start a registration yet"
                    .to_string(),
            );
        }
        self.evict_expired_invites()?;
        let now = self.now_unix();
        let hash = crate::users::invite_token_hash(token);
        let handle = crate::users::generate_invite_secret();
        let handle_hash = crate::users::registration_handle_hash(&handle);
        let handle_expires_at = now.saturating_add(REGISTRATION_HANDLE_TTL_SECS);

        // A token matching nothing must not cost a write. `Persisted::mutate`
        // persists whatever the closure did — so entering it unconditionally
        // made every garbage token from an anonymous caller a full CA-state
        // serialize and atomic file write, on the one tier that needs no
        // credential. `submit_csr` checks its token before touching the
        // held-CSR store for the same reason.
        //
        // The re-check inside the mutation below is what keeps this safe: this
        // read decides only whether a write is worth attempting, never that it
        // will succeed.
        if !self
            .log
            .invites()
            .iter()
            .any(|i| i.token_matches(&hash) && matches!(i.status, InviteStatus::Pending))
        {
            tracing::trace!("drop: registration start refused (unknown, expired or spent token)");
            return Err(REGISTRATION_START_REFUSED.to_string());
        }

        // The lookup and the state change happen inside one `mutate_invites`,
        // so two concurrent starts cannot both find the invitation `Pending`:
        // one wins and the other sees it already `Started`.
        let (found, persisted) = self.log.mutate_invites(|invites| {
            let invite = invites.iter_mut().find(|i| i.token_matches(&hash))?;
            if !matches!(invite.status, InviteStatus::Pending) {
                return None;
            }
            invite.status = InviteStatus::Started {
                handle_hash,
                started_at: now,
                handle_expires_at,
            };
            Some((
                invite.username.clone(),
                invite.totp_enrolment_uri(TOTP_ISSUER),
            ))
        });
        persisted?;

        // Reachable only by losing a race with another start between the
        // read above and this write.
        let Some((username, totp_enrolment_uri)) = found else {
            tracing::trace!("drop: registration start refused (lost the race to another start)");
            return Err(REGISTRATION_START_REFUSED.to_string());
        };

        tracing::info!(%username, "user registration started; second factor revealed");
        Ok(StartedRegistration {
            username,
            totp_enrolment_uri,
            handle,
            handle_expires_at,
        })
    }

    /// Finish a registration: verify the handle and the TOTP code, then create
    /// the account and delete the invitation as one durable act.
    ///
    /// The code is what makes this more than a password form. It proves the
    /// authenticator actually holds the secret *before* an account depends on
    /// it — the failure `create_user` has today, where a URI is printed and
    /// nobody checks it was ever scanned. The step it is accepted at is carried
    /// into the new account, so the same code cannot be spent again at sign-in.
    ///
    /// **An unknown handle costs no Argon2id.** That is the opposite of
    /// `spend_absent_user_work`'s rule for an unknown username, and deliberately
    /// so: a username is low-entropy and guessable, so timing there would
    /// enumerate accounts, whereas a handle is 256 bits from `OsRng` and is not
    /// enumerable on any timescale. There is no oracle left for timing to leak,
    /// and spending 64 MiB of memory-hard work per bad handle would hand any
    /// anonymous party a denial-of-service amplifier against the authority.
    /// Everything cheap is therefore checked first, and the password is hashed
    /// last.
    ///
    /// **A wrong code does not spend the handle.** Whoever holds the handle was
    /// handed the TOTP secret by the same call that issued it, so they can
    /// compute a correct code at will and guessing buys them nothing — while
    /// burning the handle on a typo would strand a legitimate registration with
    /// no way back.
    pub fn complete_user_registration(
        &mut self,
        handle: &str,
        password: &str,
        totp_code: &str,
    ) -> Result<(), String> {
        if self.now_unix() == 0 {
            return Err(
                "the authority has no usable clock (never set, a host clock reading \
                 before 2025, or a clock no time daemon is disciplining — check \
                 chronyd and the hardware clock); cannot create an account yet"
                    .to_string(),
            );
        }
        self.evict_expired_invites()?;
        let now = self.now_unix();
        let handle_hash = crate::users::registration_handle_hash(handle);

        // Everything cheap, and nothing that touches the store, before the
        // password is hashed.
        let Some(invite) = self
            .log
            .invites()
            .iter()
            .find(|i| i.handle_matches(&handle_hash, now))
        else {
            tracing::trace!("drop: registration completion refused (unknown or expired handle)");
            return Err(
                "this registration is no longer valid: it may have expired or been revoked. Ask \
                 for a new invitation."
                    .to_string(),
            );
        };
        let Some(step) = crate::users::verify_totp(&invite.totp_secret, totp_code, now, 0) else {
            // Left un-spent on purpose — see this method's own doc.
            tracing::debug!(username = %invite.username, "drop: registration code rejected");
            return Err("that code is not correct. Check your authenticator and try again.".into());
        };

        let username = invite.username.clone();
        let role = invite.role;
        // Re-clamped rather than re-refused. The value was chosen up to a week
        // ago under a policy that may since have changed (`from_config`'s
        // `allow_unbounded_cert_ttl` is the reachable way), and the person on
        // this end of the call can do nothing about it — refusing them would
        // burn their invitation for somebody else's decision.
        let ttl =
            if check_session_ttl(invite.session_ttl_secs, self.allow_unbounded_cert_ttl).is_ok() {
                invite.session_ttl_secs
            } else {
                MAX_SESSION_TTL_SECS
            };
        // Re-checked here, not only where the invitation was minted. The
        // invite store is durable, so a row may have been parked by a build
        // that predates `MAX_USERNAME_LEN` — the same reason
        // `check_mac_derives_from` runs again in `approve_csr` rather than
        // trusting `submit_csr` to have run it. Refused rather than truncated:
        // a name is an identifier, and half of one belongs to nobody.
        if username.len() > MAX_USERNAME_LEN {
            return Err(alloc::format!(
                "this invitation names a username longer than the {MAX_USERNAME_LEN}-byte limit                  and can no longer be redeemed; ask an administrator for a new one"
            ));
        }
        let secret = invite.totp_secret.clone();
        let user = UserRecord::from_registration(&username, password, secret, step, role, ttl)?;

        // The account and the invitation's deletion are one write. Two would
        // leave a crash window with a burnt invitation and no account, which
        // the person holding the handle cannot recover from and cannot see.
        let (created, persisted) = self.log.mutate_users_and_invites(|users, invites| {
            // Re-checked inside the mutation, against the state the write will
            // actually commit: between the read above and here nothing else
            // runs today, but "the name is free" is the invariant this store
            // exists to hold and it should be asserted where it is committed.
            if users.iter().any(|u| u.username == user.username) {
                return false;
            }
            users.push(user);
            invites.retain(|i| i.username != username);
            true
        });
        persisted?;
        if !created {
            return Err(alloc::format!(
                "user {username} already exists; this invitation can no longer be redeemed"
            ));
        }

        tracing::info!(%username, ?role, ttl_secs = ttl, "user registration completed");
        Ok(())
    }

    /// Drop invitations that have passed their expiry, and started ones whose
    /// handle window has closed.
    ///
    /// Called at the head of every invite operation that *mutates* the store,
    /// mirroring
    /// [`Self::evict_expired`]: a persisted store nobody tends would otherwise
    /// fill with records that can never be redeemed, and — worse — keep
    /// reserving the names they carry. A no-op (and no persist) when nothing
    /// has actually expired.
    ///
    /// A started invitation is dropped when its *handle* expires, not when the
    /// invitation would have: once the secret has been revealed and the handle
    /// window has closed, there is nothing left the record can be used for, and
    /// leaving it to sit out the remaining hours would hold its name reserved
    /// against the re-mint that is the correct response.
    ///
    /// **Each eviction is logged, and the started case is why.** An invitation
    /// record is the shorter-lived of the two accounts of a disclosure: the log
    /// line survives a restart in the host CA's journal, while `started_at`
    /// leaves the admin's listing here, fifteen minutes after the secret was
    /// revealed. Without a line at this moment, "somebody took a second factor
    /// and never finished" would be visible for a quarter of an hour and then
    /// simply absent, with the name freed and nothing recording that it had
    /// ever happened.
    fn evict_expired_invites(&mut self) -> Result<(), String> {
        if self.now_unix() == 0 {
            return Ok(());
        }
        let now = self.now_unix();
        let live = |i: &UserInvite| invite_is_live(i, now);
        if self.log.invites().iter().all(live) {
            return Ok(());
        }

        // Named one at a time rather than counted: the subject is the whole
        // value of the record, and an operator asking after the fact needs the
        // account name, not how many went at once. Bounded by
        // `MAX_PENDING_INVITES`, and reached only when something has actually
        // expired, so this cannot become a flood.
        for invite in self.log.invites().iter().filter(|i| !live(i)) {
            match invite.status {
                InviteStatus::Pending => tracing::info!(
                    username = %invite.username,
                    expired_at = invite.expires_at,
                    "invitation expired unredeemed; its name is free again"
                ),
                // The security-relevant one. This is the last moment the
                // provider says anything about a second factor that was handed
                // out and never turned into an account.
                InviteStatus::Started {
                    started_at,
                    handle_expires_at,
                    ..
                } => tracing::info!(
                    username = %invite.username,
                    started_at,
                    handle_expires_at,
                    "registration abandoned after the second factor was revealed; \
                     invitation dropped and its name freed — re-mint, and treat an \
                     unexpected start as a disclosure"
                ),
            }
        }

        let (_, persisted) = self.log.mutate_invites(|invites| invites.retain(live));
        persisted
    }

    /// Whether a held CSR has sat in its current state past the pending TTL.
    /// Never true before the clock is set (`now_unix == 0`), so a CA that has
    /// not yet learned the time does not evict everything as "expired".
    fn is_expired(&self, held: &HeldCsr) -> bool {
        self.now_unix() != 0
            && self.now_unix().saturating_sub(held.requested_at) > self.pending_ttl_secs
    }

    /// Drop held CSRs that have timed out.  Called at the start of every poll
    /// and operator mutation so a stale request — never approved, approved but
    /// never collected, or a denial tombstone — is reclaimed and the table stays
    /// bounded. A no-op (and no persist) when nothing has actually timed out,
    /// so a routine poll that evicts nothing doesn't touch disk.
    fn evict_expired(&mut self) -> Result<(), String> {
        if self.now_unix() == 0 {
            return Ok(());
        }
        let now = self.now_unix();
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

/// Refuse a subject address that is not the one `ed_pubkey` derives.
///
/// The issuance-side half of the key↔address binding `TrustAnchor::verify_cert`
/// enforces (design 09 §5). Verification is the half that holds even against a
/// compromised authority; this half exists so an honest one reports the mistake
/// at the point it is made, and so no certificate this CA has issued is one no
/// node will honour.
///
/// The message names the derived address rather than only the rejected one: an
/// operator who reaches for `--mac` needs to be told what to use instead, and
/// the derived MAC is public (it is on every OGM) so naming it leaks nothing.
///
/// `operator_initiated` picks the log level, and the two callers genuinely
/// differ. `approve_csr` is an authenticated operator being refused against
/// durable state — something they must see, so `warn!`. `submit_csr` is
/// admitted at the *anonymous* enrollment tier, so any client that can reach
/// the port drives this line; the root `CLAUDE.md` puts a drop reachable by
/// arbitrary remote input at `trace!`, and the rate-limit bucket bounds it per
/// source rather than making it free. Logging both at `warn!` also made the two
/// indistinguishable in the record: "somebody probed the enrollment endpoint"
/// and "an operator's approval hit a corrupt row" read identically.
fn check_mac_derives_from(
    mac: Mac,
    ed_pubkey: &[u8; 32],
    operator_initiated: bool,
) -> Result<(), String> {
    let derived = wayfinder_auth::derive_mac(ed_pubkey);
    if derived == mac {
        return Ok(());
    }
    if operator_initiated {
        tracing::warn!(
            named = ?mac,
            ?derived,
            "refusing to approve a held CSR whose MAC its identity key does not derive"
        );
    } else {
        tracing::trace!(
            named = ?mac,
            ?derived,
            "drop: CSR names a MAC its identity key does not derive"
        );
    }
    Err(alloc::format!(
        "a certificate's MAC must be the address its identity key derives: this \
         request names {:02x?} but the key derives {:02x?}",
        mac.0,
        derived.0,
    ))
}

/// A freshly minted invitation, as its caller sees it once.
///
/// [`token`](Self::token) is the whole reason this type is returned rather than
/// the invitation being minted silently: the store keeps only a hash of it, so
/// a caller that drops this value has to revoke and mint again.
#[derive(Clone)]
pub struct MintedInvite {
    /// The account name the invitation will create.
    pub username: String,
    /// The token that redeems it. A bearer credential, readable here and
    /// nowhere else.
    pub token: String,
    /// Unix seconds after which the invitation is refused.
    pub expires_at: u64,
}

/// What a started registration hands back to the person redeeming it.
///
/// Produced by the call that *spends* the invitation, so there is no second
/// chance to read it — which is why the handle is here rather than being
/// re-derivable from the token.
#[derive(Clone)]
pub struct StartedRegistration {
    /// The account name being registered. Not the redeemer's to choose.
    pub username: String,
    /// The `otpauth://` enrolment URI for the account's second factor.
    pub totp_enrolment_uri: String,
    /// The handle that alone can complete this registration.
    pub handle: String,
    /// Unix seconds after which the handle is dead and the invitation spent.
    pub handle_expires_at: u64,
}

/// One pending invitation as an admin sees it.
///
/// Deliberately not [`UserInvite`]: the record carries a token hash and a TOTP
/// secret, and neither should leave the store — a summary type makes that a
/// property of the API rather than of every call site remembering which fields
/// not to print.
#[derive(Clone, Debug)]
pub struct InviteSummary {
    /// The account name the invitation will create.
    pub username: String,
    /// The role the created account will hold.
    pub role: UserRole,
    /// The validity window its session certificates will carry, in seconds.
    pub session_ttl_secs: u64,
    /// Unix seconds the invitation was minted at.
    pub created_at: u64,
    /// Unix seconds after which it is refused.
    pub expires_at: u64,
    /// When the second factor was revealed, or `None` if it has not been.
    ///
    /// The field an admin is actually reading for. `Some(_)` with the account
    /// still absent means somebody took the second factor and did not finish:
    /// either an abandoned registration or a disclosure, and the response to
    /// both is the same.
    pub started_at: Option<u64>,
    /// When the handle issued at start dies, or `None` if unstarted.
    pub handle_expires_at: Option<u64>,
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

/// Mark every issued entry whose MAC is in `macs` revoked.
///
/// A free function rather than a closure at each call site so the two paths
/// that revoke sessions cannot drift: what "revoked" means to the store is one
/// piece of code, run inside whichever `mutate_*` the caller needs.
fn mark_revoked(issued: &mut [IssuedCertData], macs: &[Mac]) {
    for entry in issued.iter_mut() {
        if macs.iter().any(|m| m.0 == entry.node_mac.as_slice()) {
            entry.revoked = true;
        }
    }
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
        if self.now_unix() == 0 {
            return Err(
                "the authority has no usable clock (never set, a host clock reading \
                 before 2025, or a clock no time daemon is disciplining — check \
                 chronyd and the hardware clock); cannot issue certificates yet"
                    .to_string(),
            );
        }
        // Malformed keys are an *unserviceable request*, not a wrong password,
        // and are refused before any credential is looked at — a client that
        // sent 31 bytes has a bug, and telling it so reveals nothing about
        // whether the account exists.
        let ed = fixed::<32>(ed_pubkey, "ed_pubkey")?;
        let x = fixed::<32>(x_pubkey, "x_pubkey")?;

        let now = self.now_unix();
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
                    (outcome, user.role, user.session_ttl_secs, user.id)
                }
                None => {
                    // Spend the work a real verification would have cost, or
                    // the response time answers the question the uniform
                    // rejection refuses to.
                    crate::users::spend_absent_user_work(password);
                    (
                        AuthOutcome::Rejected,
                        UserRole::Viewer,
                        0,
                        AccountId::generate(),
                    )
                }
            }
        });
        persisted?;

        let (outcome, role, ttl_secs, account) = outcome;
        if outcome == AuthOutcome::Rejected {
            // No reason, here or anywhere above this: wrong password, wrong
            // code, unknown account, locked and disabled are one answer.
            tracing::warn!(%username, "drop: user authentication denied");
            return Ok(UserAuthOutcome::Rejected);
        }

        // The account's lifetime, still bounded by the session cap — an admin
        // may grant a shift or a minute, but not a decade, whatever lifetime
        // the mesh's *devices* are admitted for.
        check_session_ttl(ttl_secs, self.allow_unbounded_cert_ttl)?;
        // A user's MAC is derived from the session key it just presented, so it
        // is fresh on every login and can never contend with a device's:
        // `submit_csr`'s impersonation guard is about MACs a client *names*,
        // and this one is not named by anybody.
        let mac = wayfinder_auth::derive_mac(&ed);
        // The account id read above is durable by now: the `mutate_users` this
        // path already performs persists the whole state, ids included, before
        // the `mutate_issued` below records the certificate. That ordering is
        // what keeps a session minted just after a version-6 migration
        // attributable across the next restart — see design 14 §4.
        let (cert, record) = self.sign_user_session(mac, ed, x, ttl_secs, role, account);

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
        if self.now_unix() == 0 {
            return Err(
                "the authority has no usable clock (never set, a host clock reading \
                 before 2025, or a clock no time daemon is disciplining — check \
                 chronyd and the hardware clock); cannot issue certificates yet"
                    .to_string(),
            );
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
        // The address must be the one this key derives. Checked here as well as
        // in `verify_cert` so the failure surfaces where the mistake is made,
        // rather than as a certificate that issues cleanly and is then refused
        // by every node on the mesh.
        //
        // This — not the live-cert lock below — is what now stops
        // impersonation. The lock was first-come, so it only ever protected an
        // address that already held a certificate; an attacker could still
        // claim any address whose cert had lapsed or never existed. Naming an
        // address is no longer something a client can do at all: the address is
        // a function of the key it is presenting.
        //
        // A *rejection*, not an `Err`: the CSR is well formed and the caller is
        // answered, exactly as it is for a bad token or for the sibling
        // impersonation refusal below. It must also not touch the held store,
        // for the same reason a bad token must not — a rejected request cannot
        // be allowed to clobber a legitimate pending one for that MAC.
        if let Err(why) = check_mac_derives_from(mac, &ed, false) {
            return Ok(CsrOutcome::Rejected(why));
        }

        // A MAC that already holds a certificate inside its validity window is handled off
        // `issued` (not `held`, which is evicted at pending_ttl) so protection outlives the
        // held entry: the holder's own re-enrolment under the same ed key is re-issued
        // immediately (never re-parked for approval again — a duplicate MAC must not create
        // another held entry), while a *different* key claiming that MAC is rejected (a
        // second live cert for one MAC would let a new key impersonate the holder). The MAC
        // stays protected until its cert passively expires, the point at which re-keying is safe.
        //
        // Revocation does **not** lift that protection, and this is the subtle
        // half. The record is matched on its validity window, not on its
        // revocation status, so a revoked MAC is still MAC-locked; the
        // `revoked` flag only decides what the *holder* gets, never whether
        // anyone else may take the address. Reading the flag in the `find`
        // predicate instead — which is what this did — made a revoked record
        // invisible here, so revoking a node handed its MAC to whoever asked
        // next, under a key of their choosing. Since a revocation is judged by
        // date, the certificate that yielded post-dated the record and was
        // honoured mesh-wide: revocation defeated by the act of revoking.
        //
        // This lock used to be only as long-lived as the *issued record*, which
        // is a narrower thing than the revocation: `revoke` stamps its
        // `RevocationRecord` `not_after` at `now + cert_ttl_secs`, so it
        // outlives the certificate it cancels, and this log row does not.
        // Between the row expiring and the revocation expiring the MAC was free
        // again — issue #39, and a stranger issued in that window got a
        // certificate post-dating the revocation and honoured mesh-wide.
        //
        // **Closed**, and closed more completely than #39's planned fix
        // (consulting persisted revocations): since design 09 §5's key↔address
        // binding, `check_mac_derives_from` above has already refused any key
        // but the one that derives this address, at any time, expired record or
        // not. There is no window left to be inside. Pinned by
        // `a_different_key_cannot_reclaim_a_revoked_mac`, which absorbed the
        // test that used to hold the window open.
        //
        // Read the two facts out rather than keeping the record borrowed:
        // `issue` below takes `&mut self`.
        let holder = self.live_holder(mac, &ed);
        // Named here because the case it describes is the one that *falls
        // through* the block below, and so is read again past it.
        let revoked_holder = matches!(holder, Some((_, true, _)));

        if let Some((same_key, revoked, held_ttl_secs)) = holder {
            if !same_key {
                // Someone else's address. The wording does not distinguish a
                // revoked record from a live one: the caller holds no
                // credential for this MAC either way, and which it is, is the
                // authority's business.
                //
                // Logged because this is the impersonation attempt the lock
                // exists for, and an operator watching a MAC collision needs
                // to tell it from a node that is merely stuck. The MAC is not
                // a secret — every OGM carries one — and the keys are not
                // logged.
                //
                // Reachable only through the durable `issued` log now:
                // `check_mac_derives_from` above refuses any request whose key
                // does not derive `mac`, so for a request that reaches here the
                // key *does* derive it — and a row holding that address under a
                // different key can only have been written by a build that
                // predates the binding, or restored from a snapshot one wrote.
                // That is exactly why this is not dead code, and why
                // `a_legacy_issued_row_still_locks_its_mac` builds that row by
                // hand to keep it covered.
                tracing::warn!(
                    node_mac = ?mac,
                    "drop: CSR for a MAC already certified under a different key"
                );
                return Ok(CsrOutcome::Rejected(
                    "this MAC already has a certificate under a different key".to_string(),
                ));
            }
            if !revoked {
                // The holder, still in good standing: re-issue on the spot —
                // for the window this holder's record already carries, not the
                // authority's current default.
                //
                // This is the path an approved node collects its certificate
                // through (the row is written by the approval, and the poll
                // that follows lands here), so taking the default would throw
                // away the lifetime the operator picked for this device
                // between approving it and the node hearing about it. It is
                // also the renewal path for a node whose certificate is still
                // valid, and the same argument holds there: a device admitted
                // for its own length keeps it until an operator decides
                // otherwise, rather than drifting back to the default on a
                // poll nobody watched.
                return Ok(CsrOutcome::Issued(self.issue(
                    mac,
                    ed,
                    x,
                    Some(held_ttl_secs),
                )?));
            }
            // The holder, revoked: fall through to the approval path below —
            // never to `issue`, which would clear the `revoked` flag it is
            // standing on. Revocation ejects a node that still holds its own
            // key, so the key is exactly what the ejected party has.
            //
            // Worth a line of its own: under `auto_approve` this request used
            // to be answered with a certificate, and now silently joins a
            // queue nobody is necessarily watching.
            tracing::warn!(
                node_mac = ?mac,
                "enrollment request from a revoked holder parked for operator approval"
            );
        }

        // Approval is automatic: sign immediately — unless the record this MAC
        // holds is flagged revoked. An operator revoking a node and a config
        // saying "sign for whoever asks" are both deliberate, and where they
        // collide the specific, later act wins: re-admission is parked for
        // approval rather than granted on the spot. Without this, `auto_approve`
        // let a revoked node re-enroll itself the moment it was ejected.
        if self.auto_approve && !revoked_holder {
            return Ok(CsrOutcome::Issued(self.issue(mac, ed, x, None)?));
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
        let requested_at = self.now_unix();
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

    fn approve_csr(&mut self, node_mac: &[u8], cert_ttl_secs: Option<u64>) -> Result<(), String> {
        // Validated before anything is looked up, so a lifetime this authority
        // will not issue for leaves the request exactly where the operator
        // found it: still pending, still approvable with a lifetime that fits.
        let cert_ttl_secs = match cert_ttl_secs {
            Some(ttl) => {
                check_approval_ttl(ttl, self.allow_unbounded_cert_ttl)?;
                ttl
            }
            None => self.cert_ttl_secs,
        };
        if self.now_unix() == 0 {
            return Err(
                "the authority has no usable clock (never set, a host clock reading \
                 before 2025, or a clock no time daemon is disciplining — check \
                 chronyd and the hardware clock); cannot issue certificates yet"
                    .to_string(),
            );
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
        // Re-check the binding at approval, not only at submission. The held
        // store is durable and predates this rule, so a row parked by an
        // earlier build — or restored from a snapshot written by one — would
        // otherwise be signed on an operator's say-so without ever passing the
        // guard `submit_csr` applies.
        check_mac_derives_from(mac, &ed, true)?;
        // Sign now (stamping the current clock) and stash the bytes; the node
        // collects them on its next poll.  Restart the entry's TTL clock so the
        // node gets a full pending-TTL window to collect from the approval.
        let (cert, record) = self.sign(mac, ed, x, cert_ttl_secs);
        let cert_bytes = cert.as_bytes().to_vec();
        let now = self.now_unix();
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
        let now = self.now_unix();
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
        check_session_ttl(ttl, self.allow_unbounded_cert_ttl)?;

        let mut user = UserRecord::new(username, password, role, ttl)?;
        if no_totp {
            user = user.without_totp();
        }
        // Read out before the record moves into the store: this is the only
        // moment the secret is available, here or anywhere else.
        let uri = user.totp_enrolment_uri(TOTP_ISSUER).unwrap_or_default();
        self.add_user(user)?;
        Ok(uri)
    }

    fn set_user_role(
        &mut self,
        username: &str,
        role: UserRole,
    ) -> Result<(Vec<RevocationRecord>, bool), String> {
        if role == UserRole::Viewer {
            self.refuse_to_strand_the_mesh(username, "demote")?;
        }
        self.set_user_role_revoking_sessions(username, role)
    }

    fn set_user_enabled(
        &mut self,
        username: &str,
        enabled: bool,
    ) -> Result<(Vec<RevocationRecord>, bool), String> {
        if !enabled {
            self.refuse_to_strand_the_mesh(username, "disable")?;
        }
        self.set_user_enabled_revoking_sessions(username, enabled)
    }

    fn set_user_password(&mut self, username: &str, password: &str) -> Result<(), String> {
        CertAuthority::set_user_password(self, username, password)
    }

    fn remove_user(&mut self, username: &str) -> Result<Vec<RevocationRecord>, String> {
        self.refuse_to_strand_the_mesh(username, "remove")?;
        // The guard is evaluated before anything is signed, so a refused
        // removal has revoked nothing — the account it declined to delete keeps
        // the sessions it holds.
        //
        // And it is `remove_user_revoking_sessions`, not the raw
        // `CertAuthority::remove_user`: this is the path a dashboard's Remove
        // button reaches, and an administrator pressing it because an account is
        // compromised must not be handed an account that is gone and a
        // compromise that is still running.
        self.remove_user_revoking_sessions(username)
    }

    fn revoke_user_sessions(&mut self, username: &str) -> Result<Vec<RevocationRecord>, String> {
        CertAuthority::revoke_user_sessions(self, username)
    }

    fn revoke(&mut self, node_mac: &[u8]) -> Result<RevocationRecord, String> {
        if self.now_unix() == 0 {
            return Err(
                "the authority has no usable clock (never set, a host clock reading \
                 before 2025, or a clock no time daemon is disciplining — check \
                 chronyd and the hardware clock); cannot sign revocations yet"
                    .to_string(),
            );
        }
        let mac = node_mac_of(node_mac)?;
        // The revocation must outlive any cert we issued for the node, so reuse
        // the same ttl window from now; passive expiry then takes over.
        let not_after = self.now_unix().saturating_add(self.cert_ttl_secs);
        let record = self.authority.revoke(mac, self.now_unix(), not_after);

        // Mark the issued entry revoked (retained for ListCerts observability).
        let (_, persisted) = self.log.mutate_issued(|issued| {
            if let Some(entry) = issued.iter_mut().find(|c| c.node_mac == mac.0) {
                entry.revoked = true;
            }
        });
        persisted?;

        Ok(record)
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

/// Redacted by hand: this value exists to carry a bearer token to exactly one
/// caller, and a derived `Debug` would carry it to the log ring as well.
impl core::fmt::Debug for MintedInvite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MintedInvite")
            .field("username", &self.username)
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Redacted by hand: this carries both the `otpauth://` URI (and so the raw
/// TOTP secret) and the handle that finishes the registration.
impl core::fmt::Debug for StartedRegistration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StartedRegistration")
            .field("username", &self.username)
            .field("totp_enrolment_uri", &"<redacted>")
            .field("handle", &"<redacted>")
            .field("handle_expires_at", &self.handle_expires_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wayfinder_auth::Keypair;
    use wayfinder_auth::MembershipCert;
    use wayfinder_auth::TrustAnchor;

    fn node_keys(seed: u8) -> ([u8; 32], [u8; 32]) {
        let kp = Keypair::from_seed(&[seed; 32]);
        (kp.ed_pubkey(), kp.x_pubkey())
    }

    /// The MAC that `node_keys(seed)` derives — the only address a CSR under
    /// those keys may name, since the key↔address binding landed.
    ///
    /// Paired with `node_keys` on purpose: a test that invents an address
    /// independently of the key it presents is testing a request no honest
    /// client can build and no authority will answer.
    fn node_mac(seed: u8) -> [u8; 6] {
        Keypair::from_seed(&[seed; 32]).derived_mac().0
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

    /// The TOTP secret an invite carries, read straight out of the store.
    ///
    /// A real registrant reads it out of the `otpauth://` URI in an
    /// authenticator app; a test needs the raw bytes to compute a live code,
    /// and reaching into the store is less machinery than a base32 decoder that
    /// exists for tests alone.
    fn invite_secret(ca: &CertAuthority, username: &str) -> Vec<u8> {
        ca.log
            .invites()
            .iter()
            .find(|i| i.username == username)
            .unwrap_or_else(|| panic!("no invite on file for {username}"))
            .totp_secret
            .clone()
    }

    /// Mint an invite and start redeeming it, for the tests whose subject is
    /// what happens after that.
    fn start_registration(
        ca: &mut CertAuthority,
        username: &str,
        role: UserRole,
        ttl_secs: u64,
    ) -> StartedRegistration {
        let minted = ca
            .create_user_invite(username, role, ttl_secs, 0)
            .expect("minting an invite");
        ca.begin_user_registration(&minted.token)
            .expect("starting the registration")
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
        let verified = anchor
            .verify_cert(&cert, wayfinder::wayfinder_auth::Clocked::At(500))
            .expect("verifies in window");

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
            .verify_cert(
                &MembershipCert::from_bytes(&data.cert).unwrap(),
                wayfinder::wayfinder_auth::Clocked::At(500),
            )
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
        issued_cert(&mut ca, &node_mac(4), &dev_ed, &dev_x, "");

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

    /// A host clock too early to believe reads as *no* clock, not as a valid
    /// instant in 1970.
    ///
    /// The failure this closes is quiet and total. A node whose RTC has died, or
    /// which issued before NTP answered, reports a time near the epoch — and
    /// unlike an unset clock, that reading looks perfectly valid. Certificates
    /// would be stamped decades in the past, and every expiry check in this
    /// module would read "not yet expired" forever, which is an invitation that
    /// never dies and a lockout that never lifts.
    ///
    /// Mapping it onto zero costs nothing to write and reuses the refusal every
    /// issuing path here already performs.
    #[test]
    fn a_host_clock_from_before_2025_reads_as_no_clock_at_all() {
        assert_eq!(plausible_or_zero(0), 0, "an unset clock");
        assert_eq!(plausible_or_zero(1), 0, "one second after the epoch");
        assert_eq!(
            plausible_or_zero(1_700_000_000),
            0,
            "2023 — a plausible-looking instant, and still before this build \
             could have been deployed"
        );
        assert_eq!(
            plausible_or_zero(MIN_PLAUSIBLE_UNIX - 1),
            0,
            "the floor is exclusive below"
        );
        assert_eq!(
            plausible_or_zero(MIN_PLAUSIBLE_UNIX),
            MIN_PLAUSIBLE_UNIX,
            "and inclusive at it"
        );
        assert_eq!(
            plausible_or_zero(2_000_000_000),
            2_000_000_000,
            "a working clock passes through untouched"
        );
    }

    /// A fixed clock is **not** floored, and that asymmetry is deliberate.
    ///
    /// Nearly every test in this workspace pins the authority to a small number
    /// — second 100, second 1000 — and flooring those would silently turn a test
    /// asking about second 100 into one asking about nothing. The floor exists
    /// for the reading nobody chose; a fixed time is a value the caller chose.
    #[test]
    fn a_fixed_clock_is_taken_at_its_word() {
        let mut ca = open_ca();
        ca.set_now_unix(100);
        assert_eq!(ca.now_unix(), 100, "well below the plausibility floor");
        ca.set_now_unix(0);
        assert_eq!(ca.now_unix(), 0, "and zero stays the fail-closed sentinel");
    }

    /// An undisciplined host clock reads as the fail-closed sentinel, not as
    /// whatever the hardware happens to say.
    ///
    /// This is the gate itself. `MIN_PLAUSIBLE_UNIX` already catches a clock
    /// that was never set; it cannot catch one that is plausible and wrong,
    /// which is what a node that booted before NTP reached it has.
    #[test]
    fn an_untrusted_host_clock_reads_as_zero() {
        assert_eq!(
            Clock::System(ClockTrust::Never).now_unix(),
            0,
            "an untrusted clock is indistinguishable from no clock at all"
        );
    }

    /// The opt-out reads the host clock unconditionally, so a node whose
    /// operator has accepted the risk — or a platform with no NTP status to
    /// consult — is not bricked by the gate.
    #[test]
    fn an_assumed_host_clock_still_reads_the_host() {
        let host_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the test host's clock is after the epoch")
            .as_secs();
        assert!(
            Clock::System(ClockTrust::Assume)
                .now_unix()
                .abs_diff(host_now)
                <= 5
        );
    }

    /// A credential decision is refused outright while the clock is untrusted.
    ///
    /// Minting an invitation is the representative case — it stamps a window
    /// that a wrong clock makes either already-expired or valid far longer than
    /// intended. The refusal rides the existing `now_unix() == 0` guard, so
    /// gating the clock gates every path that already had one.
    #[test]
    fn an_untrusted_clock_refuses_to_mint_an_invitation() {
        let (mut ca, _) = ca_with_user(UserRole::Admin, 900);
        ca.set_clock(Clock::System(ClockTrust::Never));

        let err = ca
            .create_user_invite("newcomer", UserRole::Viewer, 900, 3600)
            .expect_err("an untrusted clock must not mint a dated credential");
        assert!(
            err.contains("clock"),
            "the refusal has to name the clock, or the operator debugs the wrong thing: {err}"
        );
    }

    /// An untrusted clock is *reported*, not merely acted on, so a refusal can
    /// be explained.
    ///
    /// Every issuing path here fails on the same `now_unix() == 0` sentinel,
    /// which is also what a never-set clock produces — without this an operator
    /// could not tell a clock nobody set from one NTP has not reached.
    ///
    /// This test says nothing about routing: `CertAuthority` has none. The
    /// scope boundary is pinned where routing actually exists, by
    /// `an_untrusted_clock_does_not_gate_the_routers_view_of_time` in
    /// `wayfinder-driver`.
    #[test]
    fn an_untrusted_clock_is_reported_rather_than_hidden() {
        let (mut ca, _) = ca_with_user(UserRole::Admin, 900);
        ca.set_clock(Clock::System(ClockTrust::Never));
        assert!(
            !ca.clock_sync().is_trusted(),
            "the authority can say why it is refusing"
        );
        assert_eq!(ca.clock_sync().name(), "unsynchronized");
    }

    /// The production constructor puts the authority on the host clock, so a
    /// provider needs nobody to refresh it.
    ///
    /// The whole of the fix: a `now_unix` something outside had to push in went
    /// stale whenever that something stopped pushing, and the router — which was
    /// doing the pushing — wakes once an hour on a provider with no mesh
    /// interfaces.
    ///
    /// Put on `ClockTrust::Assume`, so the property under test is the clock
    /// being *read live* rather than the build machine's NTP state — CI
    /// containers routinely report `STA_UNSYNC`, and so does this repo's own
    /// dev shell. The gate itself is covered by
    /// `an_untrusted_host_clock_reads_as_zero`.
    #[test]
    fn a_provider_built_from_config_reads_the_host_clock() {
        let path = unique_state_path("system-clock");
        let mut ca = CertAuthority::from_config(&[1; 32], &persisted_cfg(&path)).unwrap();
        // Pinned before the override, or this test would pass with
        // `from_config` returning any clock at all.
        assert_eq!(
            ca.clock,
            Clock::System(ClockTrust::default()),
            "the production constructor enforces by default"
        );
        ca.set_clock(Clock::System(ClockTrust::Assume));

        let host_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the test host's clock is after the epoch")
            .as_secs();
        assert!(
            ca.now_unix().abs_diff(host_now) <= 5,
            "a provider reads the host clock without being told the time: got {}, \
             host says {host_now}",
            ca.now_unix()
        );

        std::fs::remove_file(&path).ok();
    }

    /// An unknown name is an error rather than a silent success: whoever typed
    /// it has a wrong idea about the roster, and reporting nothing leaves them
    /// with it.
    #[test]
    fn removing_an_unknown_account_is_refused() {
        let (mut ca, _) = ca_with_user(UserRole::Admin, 900);
        assert!(MeshAuthority::remove_user(&mut ca, "nobody").is_err());
    }

    /// The account id of `username`, read straight out of the store.
    ///
    /// Reaching in rather than through `list_users`: the id is deliberately not
    /// on the wire (design 14 §3.1 keeps it a CA-side fact), so there is no
    /// projection to read it from and a test that wants it has to go here.
    fn account_id(ca: &CertAuthority, username: &str) -> AccountId {
        ca.log
            .users()
            .iter()
            .find(|u| u.username == username)
            .unwrap_or_else(|| panic!("no account on file for {username}"))
            .id
    }

    /// Sign `username` in with `seed`'s keypair, returning the MAC of the
    /// session certificate it was issued.
    ///
    /// Each seed is a different session key, so each call mints a different MAC
    /// — which is what makes "an account with several live sessions" expressible
    /// at all.
    fn sign_in(ca: &mut CertAuthority, username: &str, secret: &[u8], seed: u8) -> Vec<u8> {
        let (ed, x) = node_keys(seed);
        let code = live_code(secret, ca.now_unix());
        match ca
            .authenticate_user(username, "hunter2", &code, &ed, &x)
            .expect("the login is serviceable")
        {
            UserAuthOutcome::Issued(data) => {
                let cert = MembershipCert::from_bytes(&data.cert).expect("a parseable certificate");
                cert.node_mac.to_vec()
            }
            UserAuthOutcome::Rejected => panic!("correct credentials were rejected"),
        }
    }

    /// Advance the clock past one TOTP step, so the next sign-in presents a
    /// different code.
    ///
    /// Two sign-ins by one account are separated in time in reality and have to
    /// be here too: `authenticate` advances the replay guard past the step it
    /// accepted, so the same code a moment later is refused. That is the guard
    /// working, not an obstacle to route around.
    fn next_totp_step(ca: &mut CertAuthority) {
        ca.set_now_unix(ca.now_unix() + crate::users::TOTP_STEP_SECS);
    }

    /// The issued-log entry for `mac`.
    fn entry(ca: &CertAuthority, mac: &[u8]) -> IssuedCertData {
        ca.list_certs()
            .into_iter()
            .find(|c| c.node_mac == mac)
            .expect("the certificate is on file")
    }

    /// A session certificate records which account's sign-in produced it.
    ///
    /// The whole of what design 14 adds to the store, and the thing whose
    /// absence made "revoke this person's access" unanswerable: the issued log
    /// knew a user certificate existed and not whose it was.
    #[test]
    fn a_session_certificate_records_the_account_that_minted_it() {
        let (mut ca, secret) = ca_with_user(UserRole::Admin, 900);
        let mac = sign_in(&mut ca, "ops", &secret, 2);

        assert_eq!(
            entry(&ca, &mac).account_id,
            account_id(&ca, "ops").as_bytes().to_vec(),
            "the session is attributed to the account that signed in"
        );
    }

    /// A device's membership certificate is attributed to no account: it was
    /// not minted by a sign-in, and an empty id is how that is said.
    #[test]
    fn a_device_certificate_names_no_account() {
        let mut ca = open_ca();
        let (ed, x) = node_keys(2);
        issued_cert(&mut ca, &node_mac(2), &ed, &x, "");

        assert!(
            entry(&ca, &node_mac(2)).account_id.is_empty(),
            "an enrolled device belongs to no user account"
        );
    }

    /// Revoking an account's sessions ends *every* certificate it currently
    /// holds — one signed record per session, and each entry marked.
    ///
    /// Two sessions rather than one on purpose: a person signs in from a laptop
    /// and a phone, and a revocation that ended only the most recent would leave
    /// the other one running while telling the operator access was cut.
    #[test]
    fn revoking_an_accounts_sessions_ends_every_live_one() {
        let (mut ca, secret) = ca_with_user(UserRole::Admin, 900);
        let laptop = sign_in(&mut ca, "ops", &secret, 2);
        next_totp_step(&mut ca);
        let phone = sign_in(&mut ca, "ops", &secret, 3);
        assert_ne!(laptop, phone, "each sign-in mints its own session MAC");

        let records = ca.revoke_user_sessions("ops").expect("revoking succeeds");

        assert_eq!(records.len(), 2, "one signed revocation per live session");
        assert!(entry(&ca, &laptop).revoked);
        assert!(entry(&ca, &phone).revoked);
        assert_eq!(
            ca.list_users().len(),
            1,
            "revoking sessions is not removing the account"
        );
    }

    /// The signed records name the sessions, and verify against this CA's own
    /// anchor — a revocation the mesh will not accept is one that ends nothing.
    #[test]
    fn the_signed_revocations_name_the_sessions_and_verify() {
        let (mut ca, secret) = ca_with_user(UserRole::Admin, 900);
        let mac = sign_in(&mut ca, "ops", &secret, 2);

        let records = ca.revoke_user_sessions("ops").expect("revoking succeeds");

        let anchor = TrustAnchor::from_bytes(&ca.trust_anchor_bytes()).unwrap();
        assert_eq!(records[0].node_mac.to_vec(), mac);
        assert_eq!(
            anchor
                .verify_revocation(&records[0], ca.now_unix())
                .expect("the mesh can act on what was signed")
                .0
                .to_vec(),
            mac,
        );
    }

    /// Revoking leaves the account able to sign in again, and the new session is
    /// not born revoked.
    ///
    /// This is the whole difference from Remove, and the reason both controls
    /// exist: the laptop is lost, the person still works here.
    #[test]
    fn revoking_sessions_leaves_the_account_able_to_sign_in_again() {
        let (mut ca, secret) = ca_with_user(UserRole::Admin, 900);
        let lost = sign_in(&mut ca, "ops", &secret, 2);
        ca.revoke_user_sessions("ops").expect("revoking succeeds");

        next_totp_step(&mut ca);
        let replacement = sign_in(&mut ca, "ops", &secret, 3);

        assert!(entry(&ca, &lost).revoked, "the lost session stays revoked");
        assert!(
            !entry(&ca, &replacement).revoked,
            "the new one is not born revoked"
        );
    }

    /// Removing an account revokes its sessions in the same act.
    ///
    /// The gap design 14 exists to close: Remove was the only control a
    /// dashboard offered for cutting somebody off, and it left every
    /// certificate they held working until it expired.
    #[test]
    fn removing_an_account_revokes_its_sessions_and_deletes_it() {
        let (mut ca, secret) = ca_with_user(UserRole::Admin, 900);
        ca.add_user(UserRecord::new("second", "hunter2", UserRole::Admin, 900).unwrap())
            .unwrap();
        let mac = sign_in(&mut ca, "ops", &secret, 2);

        let records = MeshAuthority::remove_user(&mut ca, "ops").expect("removing succeeds");

        assert_eq!(records.len(), 1, "the session was revoked on the way out");
        assert!(entry(&ca, &mac).revoked);
        assert!(
            !ca.list_users().iter().any(|u| u.username == "ops"),
            "and the account is gone"
        );
    }

    /// The last-administrator guard runs before anything is signed: a refused
    /// removal must not have revoked the sessions of the account it refused to
    /// remove.
    #[test]
    fn a_refused_removal_revokes_nothing() {
        let (mut ca, secret) = ca_with_user(UserRole::Admin, 900);
        let mac = sign_in(&mut ca, "ops", &secret, 2);

        MeshAuthority::remove_user(&mut ca, "ops").expect_err("the last administrator stays");

        assert!(
            !entry(&ca, &mac).revoked,
            "the session of an account that was not removed is untouched"
        );
    }

    /// Revoking again signs nothing. Re-sending costs mesh airtime to say what
    /// the mesh already believes — the same rule the Members tab applies to a
    /// node that is already revoked.
    #[test]
    fn revoking_an_already_revoked_session_signs_nothing() {
        let (mut ca, secret) = ca_with_user(UserRole::Admin, 900);
        sign_in(&mut ca, "ops", &secret, 2);
        assert_eq!(ca.revoke_user_sessions("ops").unwrap().len(), 1);

        assert!(
            ca.revoke_user_sessions("ops").unwrap().is_empty(),
            "the second revocation has nothing left to say"
        );
    }

    /// An expired session is not revoked either: passive expiry already ended
    /// it, and a revocation record would be enforcement for a window that is
    /// over.
    #[test]
    fn an_expired_session_is_not_revoked() {
        let (mut ca, secret) = ca_with_user(UserRole::Admin, 900);
        sign_in(&mut ca, "ops", &secret, 2);
        ca.set_now_unix(100 + 901);

        assert!(
            ca.revoke_user_sessions("ops").unwrap().is_empty(),
            "an expired certificate needs no revoking"
        );
    }

    /// An account with no sessions is not an error — it is the ordinary answer
    /// for somebody who has not signed in.
    #[test]
    fn revoking_an_account_with_no_sessions_succeeds_with_nothing() {
        let (mut ca, _) = ca_with_user(UserRole::Admin, 900);
        assert!(ca.revoke_user_sessions("ops").unwrap().is_empty());
    }

    /// An unknown name is an error rather than a silent success, for the same
    /// reason removing one is: whoever sent it has a wrong idea about the
    /// roster, and answering "revoked nothing" leaves them with it.
    #[test]
    fn revoking_an_unknown_accounts_sessions_is_refused() {
        let (mut ca, _) = ca_with_user(UserRole::Admin, 900);
        assert!(ca.revoke_user_sessions("nobody").is_err());
    }

    /// A recycled name does not inherit the previous account's sessions.
    ///
    /// The reason the link is an id and not a username. `CertAuthority::
    /// remove_user` is the *raw* store operation the offline tool uses, which
    /// does not revoke — so this is exactly the state a name-keyed link would
    /// mis-attribute: a live certificate belonging to a deleted `ops`, and a
    /// new `ops` standing in its place.
    #[test]
    fn a_recycled_username_does_not_inherit_the_previous_accounts_sessions() {
        let (mut ca, secret) = ca_with_user(UserRole::Admin, 900);
        let stale = sign_in(&mut ca, "ops", &secret, 2);
        ca.remove_user("ops")
            .expect("the raw removal leaves it live");
        ca.add_user(UserRecord::new("ops", "hunter2", UserRole::Admin, 900).unwrap())
            .unwrap();

        assert!(
            ca.revoke_user_sessions("ops").unwrap().is_empty(),
            "the new account holds none of the old one's sessions"
        );
        assert!(
            !entry(&ca, &stale).revoked,
            "and the orphan is not silently re-parented"
        );
    }

    /// Two accounts' sessions do not revoke each other.
    #[test]
    fn revoking_one_account_leaves_anothers_sessions_alone() {
        let (mut ca, secret) = ca_with_user(UserRole::Admin, 900);
        let other = UserRecord::new("second", "hunter2", UserRole::Admin, 900).unwrap();
        let other_secret = other.totp_secret.clone().unwrap();
        ca.add_user(other).unwrap();
        let theirs = sign_in(&mut ca, "ops", &secret, 2);
        let mine = sign_in(&mut ca, "second", &other_secret, 3);

        ca.revoke_user_sessions("ops").expect("revoking succeeds");

        assert!(entry(&ca, &theirs).revoked);
        assert!(
            !entry(&ca, &mine).revoked,
            "a different account is untouched"
        );
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
        let cert_bytes = issued_cert(&mut ca, &node_mac(2), &ed, &x, "");

        let anchor = TrustAnchor::from_bytes(&ca.trust_anchor_bytes()).unwrap();
        let cert = MembershipCert::from_bytes(&cert_bytes).unwrap();
        let verified = anchor
            .verify_cert(&cert, wayfinder::wayfinder_auth::Clocked::At(500))
            .expect("verifies in window");
        assert_eq!(verified.mac.0, node_mac(2));
        assert_eq!(verified.ed_pubkey, ed);
    }

    #[test]
    fn bad_token_is_a_rejected_outcome_not_an_error() {
        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, Some("s3cret".to_string()), true);
        ca.set_now_unix(100);
        let (ed, x) = node_keys(2);
        let mac = node_mac(2);
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

    /// Nothing is issued without a usable clock, and the refusal says what an
    /// operator should go and look at.
    ///
    /// The message names both causes on purpose — a clock never set, and a host
    /// clock reading before the plausibility floor — because from the outside
    /// they are the same refusal and only one of them is fixed by restarting.
    #[test]
    fn issuance_rejected_before_clock_is_set() {
        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None, true);
        let (ed, x) = node_keys(2);
        let err = ca.submit_csr(&[0; 6], &ed, &x, "").unwrap_err();
        assert!(err.contains("no usable clock"), "got: {err}");
        assert!(
            err.contains("NTP") || err.contains("hardware clock"),
            "the refusal points at what to fix, not just at itself: {err}"
        );
    }

    /// An issued certificate's `not_before` is the issuing clock — so in any
    /// real deployment it is a Unix timestamp, never zero.
    ///
    /// The other half of the pair with
    /// `an_unclocked_verifier_checks_everything_except_the_window` in
    /// `wayfinder-auth`: that one shows a verifier with no clock admitting a
    /// certificate whose `not_before` it cannot judge, and this one shows that
    /// a real `not_before` is the only kind an authority produces — so the
    /// window being skipped is the *common* case on a board, not a corner.
    /// Before design 20 this pair read the opposite way, and was the reason a
    /// bare-metal node could not hold a membership credential at all.
    #[test]
    fn an_issued_certificates_not_before_is_the_issuing_clock() {
        const ISSUED_AT: u64 = 1_700_000_000;

        let mut ca = open_ca();
        let (ed, x) = node_keys(2);
        ca.set_now_unix(ISSUED_AT);
        issued_cert(&mut ca, &node_mac(2), &ed, &x, "");

        let certs = ca.list_certs();
        let issued = certs
            .iter()
            .find(|c| c.node_mac == node_mac(2))
            .expect("issued");
        assert_eq!(
            issued.not_before, ISSUED_AT,
            "the window opens at the moment of issuance, not at zero"
        );
        assert_ne!(
            issued.not_before, 0,
            "a zero `not_before` is a test-fixture shape, not one an authority mints"
        );
    }

    #[test]
    fn list_certs_records_issued_and_dedups_by_mac() {
        let mut ca = open_ca();
        let (ed, x) = node_keys(2);
        assert!(ca.list_certs().is_empty());

        // Two rows means two *identities*: one MAC per key is now the whole
        // point, so a second row needs a second key rather than a second
        // address invented for the same one.
        let (ed_b, x_b) = node_keys(7);
        issued_cert(&mut ca, &node_mac(2), &ed, &x, "");
        issued_cert(&mut ca, &node_mac(7), &ed_b, &x_b, "");
        assert_eq!(ca.list_certs().len(), 2);

        // Re-issuing for an existing MAC updates in place (no duplicate).
        ca.set_now_unix(200);
        issued_cert(&mut ca, &node_mac(2), &ed, &x, "");
        let certs = ca.list_certs();
        assert_eq!(certs.len(), 2);
        let reissued = certs.iter().find(|c| c.node_mac == node_mac(2)).unwrap();
        assert_eq!(reissued.not_before, 200, "re-issue updated the window");
    }

    #[test]
    fn revoke_marks_the_issued_cert_revoked_but_keeps_it_listed() {
        let mut ca = open_ca();
        let (ed, x) = node_keys(2);
        issued_cert(&mut ca, &node_mac(2), &ed, &x, "");
        assert!(!ca.list_certs()[0].revoked);

        ca.revoke(&node_mac(2)).unwrap();
        let certs = ca.list_certs();
        assert_eq!(certs.len(), 1, "the entry is retained after revoke");
        assert!(certs[0].revoked, "and marked revoked");
    }

    #[test]
    fn revoke_produces_a_verifiable_record() {
        let mut ca = open_ca();
        let record = ca.revoke(&node_mac(2)).unwrap();
        let anchor = TrustAnchor::from_bytes(&ca.trust_anchor_bytes()).unwrap();
        assert_eq!(anchor.verify_revocation(&record, 0).unwrap().0, node_mac(2));
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
            headscale: None,
        }
    }

    /// Submit a CSR from a fresh identity and report what the authority did
    /// with it, for the posture tests below.
    fn submit(ca: &mut CertAuthority, token: &str) -> CsrOutcome {
        let (ed, x) = node_keys(2);
        ca.submit_csr(&node_mac(2), &ed, &x, token).unwrap()
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

    /// A *person's* session is capped where a *device's* certificate is not.
    ///
    /// The two lifetimes are the same field on the same certificate and answer
    /// to different caps on purpose. A device certificate may run for years
    /// because the alternative is re-enrolling hardware nobody can reach; a
    /// session is somebody signed in at a keyboard, and a decade-long admin
    /// credential is the thing revocation exists to avoid. An operator raising
    /// one must not silently raise the other.
    #[test]
    fn a_session_lifetime_is_capped_where_a_device_lifetime_is_not() {
        let mut ca = approval_ca();
        let (ed, x) = node_keys(2);
        let mac = node_mac(2);
        let long = MAX_SESSION_TTL_SECS + 86_400;

        // Fine for a device: this is the lifetime an operator picks for a
        // sensor they are not going to visit again.
        ca.submit_csr(&mac, &ed, &x, "").unwrap();
        ca.approve_csr(&mac, Some(long))
            .expect("a device may outlive a session");

        // Refused for an account, at every door that grants one.
        let err = ca
            .create_user("rowan", "hunter2", false, long, false)
            .expect_err("an account's sessions are capped");
        assert!(err.contains("session_ttl_secs"), "{err}");
        assert!(
            ca.create_user_invite("wren", UserRole::Viewer, long, 0)
                .is_err(),
            "an invitation cannot grant what creating the account could not"
        );
    }

    /// An approval may name the lifetime for *this* device's certificate,
    /// rather than every device taking the authority's policy default.
    ///
    /// The policy value is the fallback, not the rule: a fixed installation and
    /// a contractor's laptop come through the same queue in front of the same
    /// operator, and the lifetime is the only thing that separates them.
    #[test]
    fn approval_may_name_this_certificates_lifetime() {
        let mut ca = approval_ca();
        let (ed, x) = node_keys(2);
        let mac = node_mac(2);

        ca.submit_csr(&mac, &ed, &x, "").unwrap();
        ca.approve_csr(&mac, Some(50_000))
            .expect("approve succeeds");

        let issued = ca.list_certs();
        assert_eq!(issued.len(), 1);
        assert_eq!(
            issued[0].not_after - issued[0].not_before,
            50_000,
            "the lifetime the approval named, not the authority's 1000s default"
        );

        // The collected certificate carries it too — the log and the signed
        // bytes must not disagree about when this node stops being a member.
        let cert = match ca.submit_csr(&mac, &ed, &x, "").unwrap() {
            CsrOutcome::Issued(d) => d.cert,
            other => panic!("expected Issued, got {other:?}"),
        };
        let anchor = TrustAnchor::from_bytes(&ca.trust_anchor_bytes()).unwrap();
        let cert = MembershipCert::from_bytes(&cert).unwrap();
        let verified = anchor
            .verify_cert(&cert, wayfinder::wayfinder_auth::Clocked::At(500))
            .unwrap();
        assert_eq!(verified.not_after, 100 + 50_000);
    }

    /// A node re-polling once its certificate is in hand renews at *its own*
    /// length, not the authority's default.
    ///
    /// The same code path serves the collection right after an approval and a
    /// renewal weeks later, and both used to re-issue at whatever the policy
    /// said at that moment — which would hand the operator's per-device
    /// decision a lifetime measured in however long the node took to poll.
    #[test]
    fn a_renewal_keeps_the_lifetime_the_device_was_admitted_for() {
        let mut ca = approval_ca();
        let (ed, x) = node_keys(2);
        let mac = node_mac(2);

        ca.submit_csr(&mac, &ed, &x, "").unwrap();
        ca.approve_csr(&mac, Some(50_000))
            .expect("approve succeeds");
        ca.submit_csr(&mac, &ed, &x, "").unwrap();

        // Later, still inside the window: the node asks again, as a node whose
        // certificate is approaching expiry does.
        ca.set_now_unix(40_000);
        let cert = match ca.submit_csr(&mac, &ed, &x, "").unwrap() {
            CsrOutcome::Issued(d) => d.cert,
            other => panic!("expected Issued, got {other:?}"),
        };
        let anchor = TrustAnchor::from_bytes(&ca.trust_anchor_bytes()).unwrap();
        let cert = MembershipCert::from_bytes(&cert).unwrap();
        let verified = anchor
            .verify_cert(&cert, wayfinder::wayfinder_auth::Clocked::At(40_000))
            .unwrap();
        assert_eq!(
            verified.not_after, 90_000,
            "renewed for the 50000s this device was admitted for, from now"
        );
    }

    /// An approval that names no lifetime still gets the policy default, so an
    /// operator who never picks one sees exactly the behaviour that predates
    /// the choice.
    #[test]
    fn approval_without_a_lifetime_uses_the_policy_default() {
        let mut ca = approval_ca();
        let (ed, x) = node_keys(2);
        let mac = node_mac(2);

        ca.submit_csr(&mac, &ed, &x, "").unwrap();
        ca.approve_csr(&mac, None).expect("approve succeeds");

        let issued = ca.list_certs();
        assert_eq!(issued[0].not_after - issued[0].not_before, 1000);
    }

    /// A per-approval lifetime is held to the same cap the policy value is:
    /// choosing it per device is not a way around passive expiry.
    ///
    /// And a refused approval must issue *nothing* — the request stays in the
    /// queue, so the operator can approve it again with a lifetime that fits
    /// rather than finding it silently gone.
    #[test]
    fn approval_lifetime_is_held_to_the_cap() {
        let mut ca = approval_ca();
        let (ed, x) = node_keys(2);
        let mac = node_mac(2);

        ca.submit_csr(&mac, &ed, &x, "").unwrap();
        let err = ca
            .approve_csr(&mac, Some(MAX_CERT_TTL_SECS + 1))
            .expect_err("a lifetime past the cap is refused");
        assert!(err.contains("cert_ttl_secs"), "{err}");

        assert!(ca.list_certs().is_empty(), "nothing was issued");
        assert_eq!(ca.list_pending().len(), 1, "the request is still waiting");
    }

    /// Zero is refused for the same reason the policy value refuses it: it
    /// issues a certificate that expired before the node could collect it.
    #[test]
    fn approval_lifetime_of_zero_is_refused() {
        let mut ca = approval_ca();
        let (ed, x) = node_keys(2);
        let mac = node_mac(2);

        ca.submit_csr(&mac, &ed, &x, "").unwrap();
        let err = ca
            .approve_csr(&mac, Some(0))
            .expect_err("a zero-second lifetime is refused");
        assert!(err.contains("greater than zero"), "{err}");
        assert!(ca.list_certs().is_empty(), "nothing was issued");
        assert_eq!(ca.list_pending().len(), 1, "the request is still waiting");
    }

    /// An authority that took the `allow_unbounded_cert_ttl` escape takes it
    /// for a per-approval lifetime too, rather than the escape covering only
    /// the value in the config file.
    #[test]
    fn an_unbounded_authority_accepts_an_unbounded_approval() {
        let mut ca = approval_ca();
        ca.allow_unbounded_cert_ttl = true;
        let (ed, x) = node_keys(2);
        let mac = node_mac(2);

        ca.submit_csr(&mac, &ed, &x, "").unwrap();
        ca.approve_csr(&mac, Some(MAX_CERT_TTL_SECS + 1))
            .expect("the escape covers a per-approval lifetime");
        assert_eq!(
            ca.list_certs()[0].not_after - ca.list_certs()[0].not_before,
            MAX_CERT_TTL_SECS + 1
        );
    }

    /// The live-cert lock still fires for a row a *pre-binding* build wrote.
    ///
    /// `check_mac_derives_from` refuses any request whose key does not derive
    /// the address it names, which makes the `!same_key` branch below it
    /// unreachable for every well-formed request — so the three tests that used
    /// to cover it now short-circuit at the guard, and deleting the branch
    /// would leave them all green.
    ///
    /// It is not dead code. `issued` is a durable JSON log restored across
    /// restarts, and a row written before the binding can hold `node_mac !=
    /// derive_mac(row.ed_pubkey)`. The *legitimate* holder of that address then
    /// passes the guard and lands on the branch. Built by hand here for the
    /// same reason `approving_a_held_csr_still_enforces_the_binding` builds its
    /// row by hand: this state can no longer be reached by asking.
    #[test]
    fn a_legacy_issued_row_still_locks_its_mac() {
        let mut ca = open_ca();
        let (ed, x) = node_keys(2);

        // A row a pre-binding build could have written: seed 2's address, held
        // under seed 3's key.
        let (other_ed, _) = node_keys(3);
        let (_, persisted) = ca.log.mutate_issued(|issued| {
            issued.push(IssuedCertData {
                node_mac: node_mac(2).to_vec(),
                ed_pubkey: other_ed.to_vec(),
                not_before: 0,
                not_after: 10_000,
                revoked: false,
                user: false,
                admin: false,
                viewer: false,
                account_id: Vec::new(),
            });
        });
        persisted.unwrap();

        // Seed 2 legitimately owns that address — it derives it — so the
        // derivation guard admits the request and the lock is what answers.
        let outcome = ca.submit_csr(&node_mac(2), &ed, &x, "").unwrap();
        let CsrOutcome::Rejected(why) = outcome else {
            panic!("a legacy row must still lock its MAC, got {outcome:?}");
        };
        assert!(
            why.contains("already has a certificate under a different key"),
            "the lock must be what refused this, not the derivation guard: {why}"
        );
        // The lock is not a revocation oracle either — the branch deliberately
        // does not distinguish a revoked holder from a live one, and this is the
        // only path left that reaches its wording.
        assert!(
            !why.to_lowercase().contains("revok"),
            "the lock's refusal disclosed revocation status: {why}"
        );
    }

    /// A CSR must name the address its own identity key derives.
    ///
    /// `node_mac` arrives from the client, so before the binding this was the
    /// whole of gap 4's issuance half: passing the enrollment-token check let a
    /// caller claim any address not currently covered by a live certificate.
    /// Rejected rather than silently corrected, so the mistake surfaces where
    /// it is made.
    #[test]
    fn a_csr_naming_an_address_its_key_does_not_derive_is_rejected() {
        let mut ca = open_ca();
        let (ed, x) = node_keys(2);

        // The victim's address, claimed under the attacker's keys.
        let outcome = ca.submit_csr(&node_mac(3), &ed, &x, "").unwrap();
        assert!(
            matches!(outcome, CsrOutcome::Rejected(_)),
            "expected a rejection, got {outcome:?}"
        );
        assert!(ca.list_certs().is_empty(), "nothing may be issued");
        assert!(ca.list_pending().is_empty(), "and nothing may be parked");

        // An address belonging to nobody is refused by the same rule.
        assert!(matches!(
            ca.submit_csr(&[0, 0, 0, 0, 0, 9], &ed, &x, "").unwrap(),
            CsrOutcome::Rejected(_)
        ));

        // The address the key does derive is issued.
        assert!(matches!(
            ca.submit_csr(&node_mac(2), &ed, &x, "").unwrap(),
            CsrOutcome::Issued(_)
        ));
    }

    /// The derivation guard sits *behind* the enrollment token: a caller
    /// without the token learns nothing about which addresses are claimable.
    #[test]
    fn a_bad_token_outranks_the_derivation_guard() {
        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, Some("s3cret".into()), true);
        ca.set_now_unix(100);
        let (ed, x) = node_keys(2);

        let outcome = ca.submit_csr(&node_mac(3), &ed, &x, "wrong").unwrap();
        match outcome {
            CsrOutcome::Rejected(why) => assert!(
                why.contains("token"),
                "a tokenless caller must be told about the token, got: {why}"
            ),
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    /// A CSR parked for approval is re-checked against the binding when it is
    /// approved, not only when it is submitted.
    ///
    /// The held store is written before an operator ever sees the row, so a
    /// guard that only ran on the way in would leave `approve` signing whatever
    /// a client had queued under an earlier build.
    #[test]
    fn approving_a_held_csr_still_enforces_the_binding() {
        let mut ca = approval_ca();
        let (ed, x) = node_keys(2);

        // Park a legitimate request, then corrupt the held row the way a
        // pre-binding build could have written it.
        assert!(matches!(
            ca.submit_csr(&node_mac(2), &ed, &x, "").unwrap(),
            CsrOutcome::Pending
        ));
        let (_, persisted) = ca.log.mutate_held(|held| {
            for row in held.iter_mut() {
                row.node_mac = node_mac(3);
            }
        });
        persisted.unwrap();

        assert!(
            ca.approve_csr(&node_mac(3), None).is_err(),
            "approval must refuse a held row whose MAC its key does not derive"
        );
    }

    #[test]
    fn csr_is_pending_until_approved_then_issues_the_same_cert() {
        let mut ca = approval_ca();
        let (ed, x) = node_keys(2);
        let mac = node_mac(2);

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
        ca.approve_csr(&mac, None).expect("approve succeeds");
        assert!(ca.list_pending().is_empty(), "no longer awaiting approval");
        let first = match ca.submit_csr(&mac, &ed, &x, "").unwrap() {
            CsrOutcome::Issued(d) => d.cert,
            other => panic!("expected Issued, got {other:?}"),
        };
        // The issued cert verifies and is recorded for ListCerts.
        let anchor = TrustAnchor::from_bytes(&ca.trust_anchor_bytes()).unwrap();
        let cert = MembershipCert::from_bytes(&first).unwrap();
        assert_eq!(
            anchor
                .verify_cert(&cert, wayfinder::wayfinder_auth::Clocked::At(500))
                .unwrap()
                .mac
                .0,
            mac
        );
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
        let mac = node_mac(2);

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
        assert!(ca.approve_csr(&[0, 0, 0, 0, 0, 9], None).is_err());
        assert!(ca.deny_csr(&[0, 0, 0, 0, 0, 9]).is_err());
    }

    #[test]
    fn a_different_identity_claiming_a_held_mac_is_rejected() {
        let mut ca = approval_ca();
        let (ed1, x1) = node_keys(2);
        let (ed2, x2) = node_keys(3);
        let mac = node_mac(2);

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
        let mac = node_mac(2);

        ca.submit_csr(&mac, &ed1, &x1, "").unwrap();
        ca.approve_csr(&mac, None).unwrap();
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
            headscale: None,
        };
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(100);
        let (ed1, x1) = node_keys(2);
        let (ed2, x2) = node_keys(3);
        let mac = node_mac(2);

        ca.submit_csr(&mac, &ed1, &x1, "").unwrap();
        ca.approve_csr(&mac, None).unwrap();

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

        // ...and it stays rejected once the certificate passively expires,
        // which is what the key↔address binding changed here. This used to be
        // the point at which "the MAC is free to re-key": the lock was read off
        // the *issued record*, so an address freed itself when its certificate
        // lapsed. Now the address is a function of the key, so a different key
        // has no claim on it at any time, expired record or not.
        ca.set_now_unix(100 + 100_001);
        assert!(matches!(
            ca.submit_csr(&mac, &ed2, &x2, "").unwrap(),
            CsrOutcome::Rejected(_)
        ));

        // The holder itself still re-enrols freely — renewal (same key, new
        // window) is what survives the binding, and is the only shape of
        // "re-keying" left.
        assert!(matches!(
            ca.submit_csr(&mac, &ed1, &x1, "").unwrap(),
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
            headscale: None,
        };
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(100);
        let (ed, x) = node_keys(2);
        let mac = node_mac(2);

        ca.submit_csr(&mac, &ed, &x, "").unwrap();
        ca.approve_csr(&mac, None).unwrap();

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
        // Proves the revoked-holder branch of the MAC-lock is load-bearing: a
        // revoked holder must go back through approval, not be silently
        // re-issued a fresh certificate on the same key. (This used to name the
        // `!c.revoked` term in the `find` predicate, which no longer exists —
        // the flag now selects a branch rather than filtering the record out.)
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
            headscale: None,
        };
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(100);
        let (ed, x) = node_keys(2);
        let mac = node_mac(2);

        ca.submit_csr(&mac, &ed, &x, "").unwrap();
        ca.approve_csr(&mac, None).unwrap();

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

    /// Revoking a MAC must not hand it to the next caller that asks for it.
    ///
    /// The MAC-lock's `find` used to carry `!c.revoked`, so a revoked record
    /// matched nothing and the request fell straight through to the issuing
    /// paths below — under `auto_approve`, to a root-signed certificate binding
    /// the just-revoked MAC to the *caller's* key. A revocation is judged by
    /// date, so once a second has passed that fresh certificate post-dates the
    /// record and is honoured mesh-wide: revocation defeated by the act of
    /// revoking. (`RevocationRecord::cancels` resolves an exact tie toward
    /// revoked, which is why the clock moves below — otherwise the scenario
    /// this describes would not be the one the test runs.)
    ///
    /// `auto_approve` is the sharp case — no operator ever sees the request —
    /// so it is what this pins.
    #[test]
    fn a_different_key_cannot_reclaim_a_revoked_mac() {
        let mut ca = open_ca();
        let (ed1, x1) = node_keys(2);
        let (ed2, x2) = node_keys(3);
        let mac = node_mac(2);

        assert!(matches!(
            ca.submit_csr(&mac, &ed1, &x1, "").unwrap(),
            CsrOutcome::Issued(_)
        ));
        ca.revoke(&mac).unwrap();
        // Past the revocation's instant, so a certificate minted now would
        // out-date it. Still well inside the issued record's window.
        ca.set_now_unix(101);

        // The MAC stays bound to the key that derives it, revoked or not — a
        // different key has no claim on it at any time.
        let outcome = ca.submit_csr(&mac, &ed2, &x2, "").unwrap();
        let CsrOutcome::Rejected(why) = outcome else {
            panic!("a revoked MAC was claimable by a key that never held it: {outcome:?}");
        };
        // The refusal must not be a revocation oracle. An anonymous caller
        // learns that the address is not its key's to claim — which it could
        // compute for itself — and not that this node was ejected from the mesh.
        //
        // Note which message this now checks: since the key↔address binding it
        // is `check_mac_derives_from`'s, not the live-cert lock's, because the
        // guard answers first. That makes the assertion *weaker* than it looks
        // — the derivation message could never contain "revok" — so the lock's
        // own wording is pinned separately, on the path that still reaches it.
        assert!(
            !why.to_lowercase().contains("revok"),
            "the refusal told a stranger this MAC was revoked: {why}"
        );
        assert!(
            why.contains("derives"),
            "the derivation guard is what answers a stranger now: {why}"
        );
        assert_eq!(ca.list_certs().len(), 1, "no second cert for the MAC");
        assert!(
            ca.list_certs()[0].revoked,
            "and the revocation still stands"
        );
        // A rejected claim must not occupy the MAC's approval slot either: an
        // operator reading `list_pending` sees bare MACs, and could not tell a
        // squatted entry from the legitimate node's.
        assert!(
            ca.log.held().is_empty(),
            "a rejected claim parked a held entry for the MAC"
        );

        // Issue #39's window, folded in from the test that used to pin it open.
        //
        // The lock read off the issued record was strictly shorter than the
        // revocation that made it matter: `revoke` stamps the record's
        // `not_after` at `now + cert_ttl_secs`, outliving the certificate it
        // cancels, while the issued row keeps the original one. Between the two
        // the MAC was unlocked while still revoked, so a stranger could be
        // issued a certificate that post-dated the revocation and was honoured
        // mesh-wide.
        //
        // The key↔address binding closes it, and closes it more completely than
        // the fix #39 anticipated (consulting persisted revocations): the
        // address is not this key's to claim at *any* time, so there is no
        // window to be inside.
        ca.set_now_unix(1101); // past the issued row's `not_after` of 1100
        let outcome = ca.submit_csr(&mac, &ed2, &x2, "").unwrap();
        assert!(
            matches!(outcome, CsrOutcome::Rejected(_)),
            "a stranger claimed a revoked MAC once its issued row expired, got: {outcome:?}"
        );
    }

    /// The revoked holder cannot re-admit *itself* either, which is the point:
    /// revocation ejects a node that still holds its own key, so that key is
    /// precisely what the party being ejected has.
    ///
    /// `revoked_same_key_resubmit_is_not_reissued` pins this for an authority
    /// that parks requests for approval. This is the same rule for one that
    /// approves automatically: a live revocation suspends `auto_approve` for
    /// that MAC rather than being overridden by it, so re-admission is an
    /// operator's decision under both postures.
    #[test]
    fn auto_approve_does_not_re_admit_a_revoked_holder() {
        let mut ca = open_ca();
        let (ed, x) = node_keys(2);
        let mac = node_mac(2);

        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Issued(_)
        ));
        ca.revoke(&mac).unwrap();

        assert!(
            matches!(
                ca.submit_csr(&mac, &ed, &x, "").unwrap(),
                CsrOutcome::Pending
            ),
            "a revoked node re-enrolled itself under auto_approve"
        );
        assert_eq!(ca.list_certs().len(), 1, "no second cert for the MAC");
        assert!(
            ca.list_certs()[0].revoked,
            "the revocation stands until an operator approves the re-admission"
        );
        assert_eq!(
            ca.list_pending().len(),
            1,
            "and the operator can see the request waiting"
        );
    }

    /// Approving that parked request is the way back, and it is the *only* way
    /// back — so it needs pinning. Re-admission clears the revocation, because
    /// an operator approving a CSR for a MAC they revoked is deciding exactly
    /// that; what must not happen is the node arriving there without them.
    #[test]
    fn an_operator_can_re_admit_a_revoked_holder_by_approving_its_parked_csr() {
        let mut ca = open_ca();
        let (ed, x) = node_keys(2);
        let mac = node_mac(2);

        ca.submit_csr(&mac, &ed, &x, "").unwrap();
        ca.revoke(&mac).unwrap();
        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Pending
        ));

        ca.approve_csr(&mac, None)
            .expect("the parked request is approvable");
        assert!(
            matches!(
                ca.submit_csr(&mac, &ed, &x, "").unwrap(),
                CsrOutcome::Issued(_)
            ),
            "an approved re-admission never yielded a certificate"
        );
        assert!(
            !ca.list_certs()[0].revoked,
            "re-admission left the node marked revoked"
        );
    }

    /// And denying it leaves the ejection standing, rather than quietly
    /// reopening the MAC.
    #[test]
    fn denying_a_revoked_holders_csr_leaves_the_revocation_standing() {
        let mut ca = open_ca();
        let (ed, x) = node_keys(2);
        let mac = node_mac(2);

        ca.submit_csr(&mac, &ed, &x, "").unwrap();
        ca.revoke(&mac).unwrap();
        ca.submit_csr(&mac, &ed, &x, "").unwrap();

        ca.deny_csr(&mac).expect("the parked request is deniable");
        assert!(
            matches!(
                ca.submit_csr(&mac, &ed, &x, "").unwrap(),
                CsrOutcome::Rejected(_)
            ),
            "a denied re-admission did not report the denial"
        );
        assert!(
            ca.list_certs()[0].revoked,
            "denial left the node un-revoked"
        );
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
            headscale: None,
        };
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(100);
        let (ed, x) = node_keys(2);
        let mac = node_mac(2);

        ca.submit_csr(&mac, &ed, &x, "").unwrap();
        ca.approve_csr(&mac, None).unwrap();
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
        let mac = node_mac(2);

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
        // One address per key: the queue is filled by distinct identities,
        // which is what it is bounded against.
        let held_mac = |n: usize| node_mac(n as u8);

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
        let outcome = ca.submit_csr(&node_mac(200), &ed, &x, "").unwrap();
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
        ca.approve_csr(&held_mac(0), None)
            .expect("approve succeeds");
        assert!(matches!(
            ca.submit_csr(&held_mac(0), &ed0, &x0, "").unwrap(),
            CsrOutcome::Issued(_)
        ));
    }

    #[test]
    fn a_held_csr_is_evicted_after_the_pending_ttl() {
        let mut ca = approval_ca(); // pending TTL = DEFAULT_PENDING_TTL_SECS, clock = 100
        let (ed, x) = node_keys(2);
        let mac = node_mac(2);

        ca.submit_csr(&mac, &ed, &x, "").unwrap();
        assert_eq!(ca.list_pending().len(), 1);

        // Advance past the TTL: the stale request drops out of the pending view
        // and is physically evicted (freeing the MAC) on the next poll.
        ca.set_now_unix(100 + DEFAULT_PENDING_TTL_SECS + 1);
        assert!(ca.list_pending().is_empty(), "expired request is hidden");

        // A fresh identity can now claim the freed MAC.
        let (ed2, x2) = node_keys(3);
        assert!(matches!(
            ca.submit_csr(&node_mac(3), &ed2, &x2, "").unwrap(),
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
        let mac = node_mac(2);

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
            headscale: None,
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

    /// A token matching nothing must not cost a durable write.
    ///
    /// `Persisted::mutate` persists whatever its closure did — so entering it
    /// unconditionally made every garbage token a full CA-state serialize and
    /// atomic file write, from a caller holding no credential, on the one
    /// request tier that admits one.
    ///
    /// Observed by dooming the store and reading *which* refusal comes back: a
    /// pre-check that has been removed reaches `mutate_invites` and answers
    /// with the persist failure, while the read-only check answers with the
    /// invitation refusal and never touches disk.
    #[test]
    fn an_unknown_token_is_refused_without_touching_the_store() {
        let path = unique_state_path("unknown-token-no-write");
        let mut ca = CertAuthority::from_config(&[1; 32], &persisted_cfg(&path)).unwrap();
        ca.set_now_unix(100);
        ca.create_user_invite("rowan", UserRole::Viewer, 900, 0)
            .unwrap();

        // Doom every subsequent write: the parent is now a file, so creating
        // the temporary alongside it cannot succeed.
        std::fs::remove_file(&path).ok();
        std::fs::create_dir_all(&path).unwrap();

        let err = ca
            .begin_user_registration("NOTATOKEN")
            .expect_err("an unknown token is refused");
        assert!(
            err.contains("this invitation is not valid"),
            "the refusal must come from the read-only check, not from a failed \
             write the token should never have caused: {err}"
        );

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn issued_certs_persist_across_a_restart() {
        let path = unique_state_path("restart");
        let (ed, x) = node_keys(2);
        let mac = node_mac(2);

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

    /// A session signed after loading a snapshot from before account ids
    /// existed is still attributed to its account after a restart.
    ///
    /// The one ordering property design 14 §4 leans on, tested end to end
    /// rather than asserted in a comment. Ids minted during a migration live in
    /// memory until something writes, so a certificate stamped with an id that
    /// never reached disk would be orphaned by the next restart — silently, and
    /// only discovered when a revocation found nothing to revoke. It cannot
    /// happen because `authenticate_user` persists the user store (ids and all)
    /// before it records the certificate, and this is what says so.
    #[test]
    fn a_session_signed_after_a_migration_survives_a_restart_attributed() {
        let path = unique_state_path("pre-id-snapshot");

        // Build a real v7 snapshot through the ordinary path, then age it back
        // to v6 by hand. Hand-writing the v6 file directly would mean
        // hand-writing an Argon2id hash and a TOTP secret to sign in against.
        let secret = {
            let mut ca = CertAuthority::from_config(&[1; 32], &persisted_cfg(&path)).unwrap();
            ca.set_now_unix(100);
            let user = UserRecord::new("ops", "hunter2", UserRole::Admin, 900).unwrap();
            let secret = user.totp_secret.clone().unwrap();
            ca.add_user(user).unwrap();
            secret
        };
        let mut snapshot: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        snapshot["version"] = serde_json::json!(6);
        for user in snapshot["users"].as_array_mut().unwrap() {
            user.as_object_mut().unwrap().remove("id");
        }
        std::fs::write(&path, snapshot.to_string()).unwrap();

        // Load the aged snapshot — which mints an id — and sign in against it.
        let mac = {
            let mut ca = CertAuthority::from_config(&[1; 32], &persisted_cfg(&path)).unwrap();
            ca.set_now_unix(100);
            sign_in(&mut ca, "ops", &secret, 2)
        }; // Dropped here, simulating a process restart.

        let ca = CertAuthority::from_config(&[1; 32], &persisted_cfg(&path)).unwrap();
        assert_eq!(
            entry(&ca, &mac).account_id,
            account_id(&ca, "ops").as_bytes().to_vec(),
            "the session is still attributed to the account that minted it, so \
             it is still revocable",
        );

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
        let mac = node_mac(2);

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
        ca.approve_csr(&mac, None)
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
        let mac = node_mac(2);

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
        let mac = node_mac(2);

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
        ca.submit_csr(&node_mac(3), &ed2, &x2, "").unwrap();
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
        let mac = node_mac(2);

        {
            let cfg = approval_persisted_cfg(&path);
            let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
            ca.set_now_unix(100);
            ca.submit_csr(&mac, &ed, &x, "").unwrap();
            ca.approve_csr(&mac, None).expect("approve succeeds");
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
        let mac = node_mac(2);

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
                ca.submit_csr(&node_mac(3), &ed2, &x2, "").unwrap(),
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
        let mac = node_mac(2);

        // The doomed write surfaces as an error to the caller — an operator
        // must not be told an action durably succeeded when it didn't.
        let err = ca.submit_csr(&mac, &ed, &x, "").unwrap_err();
        assert!(
            err.contains("could not record"),
            "the caller must be told the write did not land, got: {err}"
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
        let mac2 = node_mac(3);
        let err2 = ca.submit_csr(&mac2, &ed2, &x2, "").unwrap_err();
        assert!(
            err2.contains("could not record"),
            "the caller must be told the write did not land, got: {err2}"
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
        let mac = node_mac(2);

        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Pending
        ));

        // Now doom every subsequent write.
        std::fs::remove_dir_all(&dir).ok();

        let err = ca.approve_csr(&mac, None).unwrap_err();
        assert!(
            err.contains("could not record"),
            "the caller must be told the write did not land, got: {err}"
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
        let mac = node_mac(2);

        assert!(matches!(
            ca.submit_csr(&mac, &ed, &x, "").unwrap(),
            CsrOutcome::Pending
        ));

        // Now doom the deny's write.
        std::fs::remove_dir_all(&dir).ok();

        let err = ca.deny_csr(&mac).unwrap_err();
        assert!(
            err.contains("could not record"),
            "the caller must be told the write did not land, got: {err}"
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
        let mac = node_mac(2);

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
        let mac = node_mac(2);

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
        let mac = node_mac(2);
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
        let mac = node_mac(2);

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

    /// The whole self-service flow, once: an admin mints an invite for a named
    /// account, the invitee redeems it, and the account they end up with is the
    /// one the admin decided on — with a second factor the admin never saw.
    ///
    /// The mint returns the token *once*; the store keeps only its hash, so
    /// this is the single moment it is readable anywhere.
    #[test]
    fn an_invite_is_minted_redeemed_and_becomes_the_account_the_admin_specified() {
        let mut ca = open_ca();

        let minted = ca
            .create_user_invite("rowan", UserRole::Admin, 900, 0)
            .unwrap();
        assert_eq!(minted.username, "rowan");
        assert!(!minted.token.is_empty());
        assert_eq!(
            minted.expires_at,
            100 + DEFAULT_INVITE_TTL_SECS,
            "an unstated lifetime takes the default"
        );
        assert!(
            ca.list_users().is_empty(),
            "an invite is not an account: nothing that iterates the user store \
             may ever see one"
        );

        let started = ca.begin_user_registration(&minted.token).unwrap();
        assert_eq!(started.username, "rowan");
        assert!(started.totp_enrolment_uri.starts_with("otpauth://totp/"));
        assert_eq!(
            started.handle_expires_at,
            100 + REGISTRATION_HANDLE_TTL_SECS
        );

        let secret = invite_secret(&ca, "rowan");
        ca.complete_user_registration(
            &started.handle,
            "correct horse battery staple",
            &live_code(&secret, 100),
        )
        .unwrap();

        let users = ca.list_users();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "rowan");
        assert_eq!(
            users[0].role,
            UserRole::Admin,
            "the role is the admin's decision at mint, never the redeemer's"
        );
        assert_eq!(users[0].session_ttl_secs, 900);
        assert!(users[0].totp_enrolled);
        assert!(
            ca.list_user_invites().is_empty(),
            "completion deletes the invite"
        );
    }

    /// The account the flow produces actually works: the credentials chosen at
    /// registration sign in and mint a session certificate.
    ///
    /// Proving enrolment before the account exists is the property `user add`
    /// does not have — there, a URI is printed and nobody checks it was ever
    /// scanned.
    #[test]
    fn the_registered_account_can_sign_in() {
        let mut ca = open_ca();
        let (ed, x) = node_keys(2);
        let started = start_registration(&mut ca, "rowan", UserRole::Viewer, 900);
        let secret = invite_secret(&ca, "rowan");
        ca.complete_user_registration(&started.handle, "hunter2", &live_code(&secret, 100))
            .unwrap();

        // A step on, so the code accepted at completion is not the one offered
        // here — see `the_code_accepted_at_registration_is_refused_at_the_next_sign_in`.
        let later = 130;
        ca.set_now_unix(later);
        let outcome = ca
            .authenticate_user("rowan", "hunter2", &live_code(&secret, later), &ed, &x)
            .unwrap();

        assert!(
            matches!(outcome, UserAuthOutcome::Issued(_)),
            "the account registered by its own owner must be an ordinary account"
        );
    }

    /// **The design's load-bearing interlock.** Starting a registration
    /// consumes the token, so a second start with the same token is refused.
    ///
    /// A non-consuming start would let anyone who read the URL out of a chat
    /// log take the account's second factor while the legitimate registration
    /// completed normally afterwards, recording nothing anywhere. Consuming it
    /// converts a silent disclosure into a burnt invite and a failed
    /// registration the invitee reports.
    #[test]
    fn a_started_invite_refuses_a_second_begin() {
        let mut ca = open_ca();
        let minted = ca
            .create_user_invite("rowan", UserRole::Viewer, 900, 0)
            .unwrap();

        ca.begin_user_registration(&minted.token)
            .expect("the first start is served");

        assert!(
            ca.begin_user_registration(&minted.token).is_err(),
            "the token is spent: a second start must not reveal the secret again"
        );
    }

    /// And once the account exists, the token is not merely spent but unknown —
    /// the invite is gone, so a replayed redemption has nothing to match.
    #[test]
    fn a_consumed_token_is_unknown_on_replay() {
        let mut ca = open_ca();
        let minted = ca
            .create_user_invite("rowan", UserRole::Viewer, 900, 0)
            .unwrap();
        let started = ca.begin_user_registration(&minted.token).unwrap();
        let secret = invite_secret(&ca, "rowan");
        ca.complete_user_registration(&started.handle, "hunter2", &live_code(&secret, 100))
            .unwrap();

        assert!(ca.begin_user_registration(&minted.token).is_err());
        assert!(
            ca.complete_user_registration(&started.handle, "other", &live_code(&secret, 160))
                .is_err(),
            "the handle is single-use too"
        );
        assert_eq!(ca.list_users().len(), 1, "and no second account appeared");
    }

    /// The state an admin actually reads: started, and not completed.
    ///
    /// It means somebody took the second factor and did not finish — either an
    /// abandoned registration or a disclosure, and either way the response is
    /// the same: revoke and re-mint. Everything else in the listing is context
    /// for that one field.
    #[test]
    fn a_started_but_unfinished_invite_is_visible_to_the_admin() {
        let mut ca = open_ca();
        ca.create_user_invite("rowan", UserRole::Admin, 900, 0)
            .unwrap();
        ca.create_user_invite("wren", UserRole::Viewer, 900, 0)
            .unwrap();
        let taken = ca
            .create_user_invite("linnet", UserRole::Viewer, 900, 0)
            .unwrap();
        ca.begin_user_registration(&taken.token).unwrap();

        let listed = ca.list_user_invites();

        let linnet = listed
            .iter()
            .find(|i| i.username == "linnet")
            .expect("the started invite is still listed");
        assert_eq!(
            linnet.started_at,
            Some(100),
            "the moment the secret was revealed is the answer an admin needs"
        );
        assert_eq!(
            linnet.handle_expires_at,
            Some(100 + REGISTRATION_HANDLE_TTL_SECS)
        );
        assert!(
            listed
                .iter()
                .filter(|i| i.username != "linnet")
                .all(|i| i.started_at.is_none()),
            "an untouched invite must not report a start it never had"
        );
        // Asserted against the secrets' own renderings, not against the word
        // "secret": `InviteSummary` has no field that could ever contain that
        // substring, so the old check passed by construction and would have
        // gone on passing if the type grew a `totp: Vec<u8>`.
        let rendered = alloc::format!("{listed:?}");
        assert!(
            !rendered.contains(&taken.token),
            "the listing must not carry the invitation token: {rendered}"
        );
        let secret = crate::users::base32_encode(&invite_secret(&ca, "linnet"));
        assert!(
            !rendered.contains(&secret),
            "nor the second factor, which is the thing this design exists to \
             keep out of an admin's hands: {rendered}"
        );
    }

    /// A wrong code creates nothing — and does not spend the handle either, so
    /// somebody who mistyped can simply try again.
    ///
    /// Not spending it is safe rather than lax: whoever holds the handle was
    /// handed the TOTP secret by the same call, so they can compute a correct
    /// code at will. Guessing buys an attacker nothing that holding the handle
    /// did not already give them, while burning the handle on a typo would
    /// strand a legitimate registration.
    #[test]
    fn a_wrong_totp_code_at_completion_creates_no_account() {
        let mut ca = open_ca();
        let started = start_registration(&mut ca, "rowan", UserRole::Admin, 900);

        assert!(
            ca.complete_user_registration(&started.handle, "hunter2", "000000")
                .is_err(),
            "an unproven second factor must not become an account"
        );
        assert!(ca.list_users().is_empty());

        let secret = invite_secret(&ca, "rowan");
        ca.complete_user_registration(&started.handle, "hunter2", &live_code(&secret, 100))
            .expect("a mistyped code must not cost the registration");
        assert_eq!(ca.list_users().len(), 1);
    }

    /// An empty password is refused where the account is built, not only by
    /// whichever front end happened to ask for it.
    ///
    /// `CompleteUserRegistration` is on the **enrollment tier** — a wire client
    /// holding an invite handle and no credential at all reaches it directly.
    /// The `is_empty` checks in `wayfinder-web`'s `api.rs` and `wayfinderctl`
    /// are the two front ends being polite; neither is the trust boundary, and
    /// an account whose only knowledge factor is `""` is one whose second
    /// factor was already handed to whoever is asking.
    #[test]
    fn an_empty_password_is_refused_at_completion() {
        let mut ca = open_ca();
        let started = start_registration(&mut ca, "rowan", UserRole::Admin, 900);
        let secret = invite_secret(&ca, "rowan");

        assert!(
            ca.complete_user_registration(&started.handle, "", &live_code(&secret, 100))
                .is_err(),
            "an account must not be created with no password"
        );
        assert!(
            ca.list_users().is_empty(),
            "and nothing is left behind by the refusal"
        );

        // The handle survives, for the same reason a mistyped code does not
        // spend it: the person can fix this and try again.
        ca.complete_user_registration(&started.handle, "hunter2", &live_code(&secret, 100))
            .expect("a refused password must not cost the registration");
        assert_eq!(ca.list_users().len(), 1);
    }

    /// An over-long invitation lifetime is refused at mint, the way an
    /// over-long session lifetime three lines above it already is.
    ///
    /// `DEFAULT_INVITE_TTL_SECS`' own doc calls itself "the bound on how long a
    /// bearer token sitting in somebody's chat history is worth anything" — a
    /// bound that only applied when the admin said nothing. Refused rather than
    /// clamped, matching `check_cert_ttl`: the admin is standing in front of
    /// the error and can fix it.
    #[test]
    fn an_over_long_invite_lifetime_is_refused_at_mint() {
        let mut ca = open_ca();

        assert!(
            ca.create_user_invite("rowan", UserRole::Viewer, 900, MAX_INVITE_TTL_SECS + 1)
                .is_err(),
            "a ten-year bearer token is not an invitation"
        );
        assert!(
            ca.list_user_invites().is_empty(),
            "and the refusal reserves no name"
        );

        ca.create_user_invite("rowan", UserRole::Viewer, 900, MAX_INVITE_TTL_SECS)
            .expect("the cap itself is allowed");
    }

    /// An invite past its expiry is refused at the start, and one whose handle
    /// has expired is refused at the finish. Both leave nothing behind.
    #[test]
    fn an_expired_invite_and_an_expired_handle_are_each_refused() {
        let mut ca = open_ca();
        let stale = ca
            .create_user_invite("rowan", UserRole::Viewer, 900, 60)
            .unwrap();
        ca.set_now_unix(100 + 61);
        assert!(
            ca.begin_user_registration(&stale.token).is_err(),
            "an expired invite is not redeemable"
        );

        ca.set_now_unix(200);
        let started = start_registration(&mut ca, "wren", UserRole::Viewer, 900);
        let secret = invite_secret(&ca, "wren");
        ca.set_now_unix(200 + REGISTRATION_HANDLE_TTL_SECS + 1);
        assert!(
            ca.complete_user_registration(
                &started.handle,
                "hunter2",
                &live_code(&secret, 200 + REGISTRATION_HANDLE_TTL_SECS + 1)
            )
            .is_err(),
            "a handle past its window is dead, and the invite with it"
        );
        assert!(ca.list_users().is_empty());
    }

    /// An unknown handle costs no password hashing.
    ///
    /// The opposite of `spend_absent_user_work`'s rule, and deliberately so:
    /// that exists because usernames are low-entropy and guessable, so timing
    /// would enumerate accounts. A handle is 256 bits from `OsRng` and is not
    /// enumerable on any timescale, so there is no oracle left for timing to
    /// leak — while spending `ARGON2_MEMORY_KIB` per bad handle would hand any
    /// anonymous party a denial-of-service amplifier against the authority.
    ///
    /// Measured as a ratio rather than an absolute, so it is the *presence* of
    /// a memory-hard hash being asserted, not a wall-clock budget.
    #[test]
    fn an_unknown_handle_is_refused_without_spending_argon2id() {
        let mut ca = open_ca();

        let one_hash = std::time::Instant::now();
        UserRecord::new("cost", "hunter2", UserRole::Viewer, 900).unwrap();
        let one_hash = one_hash.elapsed();

        let refusals = std::time::Instant::now();
        for n in 0..20 {
            assert!(
                ca.complete_user_registration(
                    &alloc::format!("no-such-handle-{n}"),
                    "guess",
                    "000000"
                )
                .is_err()
            );
        }
        let refusals = refusals.elapsed();

        assert!(
            refusals < one_hash,
            "twenty unknown handles took {refusals:?}, which is not less than the \
             {one_hash:?} a single Argon2id costs — the refusal is hashing when it \
             must not"
        );
    }

    /// A name is reserved from the moment it is invited, in both directions.
    ///
    /// Without this an admin creating an account directly would silently strand
    /// the pending invite until it expired, and the invitee's registration
    /// would fail with nothing to point at.
    #[test]
    fn a_name_is_reserved_by_its_invite_against_every_other_path() {
        let mut ca = open_ca();
        ca.create_user_invite("rowan", UserRole::Viewer, 900, 0)
            .unwrap();

        assert!(
            ca.add_user(UserRecord::new("rowan", "hunter2", UserRole::Viewer, 900).unwrap())
                .is_err(),
            "the offline path must see the reservation too"
        );
        assert!(
            MeshAuthority::create_user(&mut ca, "rowan", "hunter2", false, 900, false).is_err(),
            "and so must the management API"
        );
        assert!(
            ca.create_user_invite("rowan", UserRole::Admin, 900, 0)
                .is_err(),
            "a second invite for the same name would strand the first"
        );
    }

    /// A username is bounded on the way in, and the bound has to hold on every
    /// path that claims a name — it is carried in the provider's state file, in
    /// every audit line, and in an `otpauth://` URI.
    ///
    /// In bytes rather than characters, because bytes are what the state file
    /// and the wire pay for. `bins/wayfinder-web/src/bundle.rs` keeps its own
    /// constant of the same value against an *uploaded* name — that crate does
    /// not depend on this one outside its test feature — and now counts the same
    /// units, where it previously counted characters beside a note that the
    /// authority bounded nothing at all.
    #[test]
    fn a_username_is_bounded_in_length_on_every_path_that_creates_one() {
        let mut ca = open_ca();
        let too_long = "r".repeat(MAX_USERNAME_LEN + 1);
        let longest = "r".repeat(MAX_USERNAME_LEN);

        assert!(
            ca.add_user(UserRecord::new(&too_long, "hunter2", UserRole::Viewer, 900).unwrap())
                .is_err(),
            "the offline path must bound the name"
        );
        assert!(
            MeshAuthority::create_user(&mut ca, &too_long, "hunter2", false, 900, false).is_err(),
            "and so must the management API"
        );
        assert!(
            ca.create_user_invite(&too_long, UserRole::Viewer, 900, 0)
                .is_err(),
            "and so must an invitation, which reserves the name before any \
             account exists to be bounded"
        );

        // The boundary itself is admitted, so the limit is off-by-one-proof and
        // is a refusal of the excessive rather than of the merely long.
        assert!(
            ca.add_user(UserRecord::new(&longest, "hunter2", UserRole::Viewer, 900).unwrap())
                .is_ok(),
            "a name of exactly the maximum length is accepted"
        );

        // Bytes, not characters — the half of the rule that an ASCII-only test
        // cannot see, and the half `bins/wayfinder-web/src/bundle.rs` counted
        // differently until it took this same constant. 65 two-byte characters
        // is 130 bytes and is over the line.
        let multibyte = "é".repeat(MAX_USERNAME_LEN / 2 + 1);
        assert!(multibyte.chars().count() < MAX_USERNAME_LEN, "setup");
        assert!(multibyte.len() > MAX_USERNAME_LEN, "setup");
        assert!(
            ca.add_user(UserRecord::new(&multibyte, "hunter2", UserRole::Viewer, 900).unwrap())
                .is_err(),
            "the bound counts bytes, so a short-but-wide name is still refused"
        );
    }

    /// And the reservation runs the other way: a name with an account cannot be
    /// invited, because completion would have nowhere to put the result.
    #[test]
    fn minting_refuses_a_name_that_already_has_an_account() {
        let (mut ca, _secret) = ca_with_user(UserRole::Admin, 900);

        assert!(
            ca.create_user_invite("ops", UserRole::Viewer, 900, 0)
                .is_err()
        );
    }

    /// Removing an account frees its name for a fresh invite.
    ///
    /// The two stores are reserved against each other in both directions, so
    /// "remove the account, then invite the name again" is the whole lifecycle
    /// — there is no third state where an account and an invite for one name
    /// coexist and have to be reconciled.
    #[test]
    fn removing_an_account_frees_its_name_to_be_invited_again() {
        let (mut ca, _secret) = ca_with_user(UserRole::Admin, 900);
        assert!(
            ca.create_user_invite("ops", UserRole::Viewer, 900, 0)
                .is_err()
        );

        ca.remove_user("ops").unwrap();

        assert!(
            ca.create_user_invite("ops", UserRole::Viewer, 900, 0)
                .is_ok()
        );
    }

    /// Revocation works at any status, and the started case is the one it
    /// exists for: a start the admin did not expect is the signal that the
    /// token leaked, and revoke-and-re-mint is the response.
    #[test]
    fn revoking_an_invite_deletes_it_at_any_status() {
        let mut ca = open_ca();
        let pending = ca
            .create_user_invite("rowan", UserRole::Viewer, 900, 0)
            .unwrap();
        let taken = ca
            .create_user_invite("wren", UserRole::Viewer, 900, 0)
            .unwrap();
        let started = ca.begin_user_registration(&taken.token).unwrap();

        ca.revoke_user_invite("rowan").unwrap();
        ca.revoke_user_invite("wren").unwrap();

        assert!(ca.list_user_invites().is_empty());
        assert!(ca.begin_user_registration(&pending.token).is_err());
        assert!(
            ca.complete_user_registration(&started.handle, "hunter2", "000000")
                .is_err(),
            "a revoked invite's registration cannot be finished"
        );
        assert!(
            ca.revoke_user_invite("rowan").is_err(),
            "a name with no invite on file is an error, not a silent success"
        );
    }

    /// A persisted store that grows without bound leaves the growth behind
    /// across a restart. Unlike held CSRs only a full grant can add one, so the
    /// cap guards against operator error rather than a remote party — but it is
    /// still a cap, and it refuses rather than evicting an incumbent.
    #[test]
    fn a_full_invite_store_refuses_a_new_mint_rather_than_evicting() {
        let mut ca = open_ca();
        for n in 0..MAX_PENDING_INVITES {
            ca.create_user_invite(&alloc::format!("user{n}"), UserRole::Viewer, 900, 0)
                .unwrap_or_else(|e| panic!("minting invite {n} of {MAX_PENDING_INVITES}: {e}"));
        }

        assert!(
            ca.create_user_invite("overflow", UserRole::Viewer, 900, 0)
                .is_err()
        );
        assert_eq!(
            ca.list_user_invites().len(),
            MAX_PENDING_INVITES,
            "no incumbent evicted"
        );
    }

    /// An expired invite is swept lazily, the way a stale held CSR is, so a
    /// store nobody tends does not fill with records that can never be
    /// redeemed.
    #[test]
    fn an_expired_invite_is_evicted_lazily() {
        let mut ca = open_ca();
        ca.create_user_invite("rowan", UserRole::Viewer, 900, 60)
            .unwrap();
        assert_eq!(ca.list_user_invites().len(), 1);

        ca.set_now_unix(100 + 61);
        ca.create_user_invite("wren", UserRole::Viewer, 900, 0)
            .unwrap();

        let listed = ca.list_user_invites();
        assert_eq!(listed.len(), 1, "the expired invite is gone");
        assert_eq!(listed[0].username, "wren");
    }

    /// A started registration whose handle window closed frees its name.
    ///
    /// The `Started` arm of the sweep is the one that matters and the one a
    /// test can miss: the refusal a caller sees on an expired handle comes from
    /// `handle_matches`' own clock check, so changing that arm to
    /// `!i.is_expired(now)` leaves every other test green while the record sits
    /// there holding its name reserved for the rest of the invitation's life —
    /// against the re-mint that is the documented response to a disclosure.
    #[test]
    fn a_started_registration_past_its_handle_window_frees_its_name() {
        let mut ca = open_ca();
        start_registration(&mut ca, "rowan", UserRole::Admin, 900);
        assert_eq!(ca.list_user_invites().len(), 1);

        ca.set_now_unix(100 + REGISTRATION_HANDLE_TTL_SECS + 1);
        assert!(
            ca.list_user_invites().is_empty(),
            "a registration nobody can finish is not an invitation"
        );

        ca.create_user_invite("rowan", UserRole::Admin, 900, 0)
            .expect("re-minting for the same name is the documented response");
    }

    /// A store full of dead invitations still admits a new mint.
    ///
    /// `create_user_invite` sweeps *before* it checks capacity, and that
    /// ordering is the whole behaviour: reverse the two lines and an operator
    /// whose store is full of yesterday's expired invitations is refused every
    /// mint until something else happens to sweep — with every other test still
    /// green, because they fill the store with live invitations only.
    #[test]
    fn a_store_full_of_expired_invites_still_admits_a_mint() {
        let mut ca = open_ca();
        for n in 0..MAX_PENDING_INVITES {
            ca.create_user_invite(&alloc::format!("user{n}"), UserRole::Viewer, 900, 60)
                .unwrap_or_else(|e| panic!("minting invite {n}: {e}"));
        }

        ca.set_now_unix(100 + 61);
        ca.create_user_invite("wren", UserRole::Viewer, 900, 0)
            .expect("a full store of dead invitations is not a full store");
        assert_eq!(
            ca.list_user_invites().len(),
            1,
            "and the dead ones went with the sweep"
        );
    }

    /// Role and lifetime are frozen at mint but applied up to a week later, so
    /// completion re-checks the lifetime against the cap in force *then*.
    ///
    /// The reachable version of that: an invite minted while the operator had
    /// taken `allow_unbounded_cert_ttl`, redeemed after they gave it back. The
    /// value passed at mint and the rule applied at completion genuinely differ.
    ///
    /// Completion **clamps** where mint **refuses**, which looks inconsistent
    /// and is not. The admin can fix an over-long lifetime and is standing
    /// there at mint, so a refusal reaches somebody who can act on it. The
    /// registrant can fix nothing, so refusing them would burn their invite for
    /// a policy decision they had no part in.
    #[test]
    fn completion_clamps_a_lifetime_the_policy_no_longer_allows() {
        let path = unique_state_path("invite-ttl-clamp");
        let overlong = MAX_SESSION_TTL_SECS + 86_400;

        let (handle, secret) = {
            let cfg = ProviderConfig {
                allow_unbounded_cert_ttl: true,
                ..persisted_cfg(&path)
            };
            let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
            ca.set_now_unix(100);
            let minted = ca
                .create_user_invite("rowan", UserRole::Viewer, overlong, 0)
                .expect("the escape hatch admits it at mint");
            let started = ca.begin_user_registration(&minted.token).unwrap();
            (started.handle, invite_secret(&ca, "rowan"))
        };

        // Restarted with the escape hatch given back.
        let mut ca = CertAuthority::from_config(&[1; 32], &persisted_cfg(&path)).unwrap();
        ca.set_now_unix(100);
        ca.complete_user_registration(&handle, "hunter2", &live_code(&secret, 100))
            .expect("a policy that moved must not burn the invitee's registration");

        assert_eq!(
            ca.list_users()[0].session_ttl_secs,
            MAX_SESSION_TTL_SECS,
            "the created account's lifetime is clamped to the cap now in force, \
             not the one the invite was minted under"
        );

        std::fs::remove_file(&path).ok();
    }

    /// Fail-closed before the clock is set, the same rule `submit_csr` and
    /// `authenticate_user` apply: without a clock this would mint an invite
    /// whose window starts at the epoch and is already over.
    #[test]
    fn invites_are_refused_before_the_clock_is_set() {
        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None, true);

        assert!(
            ca.create_user_invite("rowan", UserRole::Viewer, 900, 0)
                .is_err()
        );
        assert!(ca.begin_user_registration("anything").is_err());
        assert!(
            ca.complete_user_registration("anything", "hunter2", "000000")
                .is_err()
        );
    }

    /// An invite is durable state: a provider restarted mid-registration must
    /// still honour the handle it issued, or every restart silently burns every
    /// registration in flight.
    #[test]
    fn a_started_invite_survives_a_restart() {
        let path = unique_state_path("invite-restart");
        let cfg = persisted_cfg(&path);

        let (handle, secret) = {
            let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
            ca.set_now_unix(100);
            let minted = ca
                .create_user_invite("rowan", UserRole::Admin, 900, 0)
                .unwrap();
            let started = ca.begin_user_registration(&minted.token).unwrap();
            (started.handle, invite_secret(&ca, "rowan"))
        };

        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(130);
        let listed = ca.list_user_invites();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].started_at, Some(100));

        ca.complete_user_registration(&handle, "hunter2", &live_code(&secret, 130))
            .expect("the handle issued before the restart still completes");
        assert_eq!(ca.list_users().len(), 1);
        assert!(ca.list_user_invites().is_empty());

        std::fs::remove_file(&path).ok();
    }

    /// **Demoting an administrator ends the admin certificates it is already
    /// holding**, in the same act.
    ///
    /// The capability lives on the certificate, not on the account. A session
    /// minted while the account was an administrator carries `CERT_FLAG_ADMIN`
    /// and goes on carrying it until it is revoked or expires — so a demotion
    /// that changed only what the account is issued *next* would report an
    /// access as removed while its holder was still exercising it. That is the
    /// gap design 14 closed for `RemoveUser`, reopened one request along.
    ///
    /// Two sessions rather than one, for the reason
    /// [`revoking_an_accounts_sessions_ends_every_live_one`] uses two: a person
    /// signs in from a laptop and a phone, and ending only the most recent
    /// leaves the other one administering the mesh.
    #[test]
    fn demoting_an_administrator_revokes_the_admin_sessions_it_holds() {
        let (mut ca, secret) = ca_with_user(UserRole::Admin, 900);
        ca.add_user(UserRecord::new("second", "hunter2", UserRole::Admin, 900).unwrap())
            .unwrap();
        let laptop = sign_in(&mut ca, "ops", &secret, 2);
        next_totp_step(&mut ca);
        let phone = sign_in(&mut ca, "ops", &secret, 3);

        let (records, changed) = ca
            .set_user_role_revoking_sessions("ops", UserRole::Viewer)
            .expect("the demotion succeeds");

        assert!(changed, "the account was an administrator a moment ago");
        assert_eq!(records.len(), 2, "one signed revocation per live session");
        assert!(entry(&ca, &laptop).revoked);
        assert!(entry(&ca, &phone).revoked);

        let ops = ca
            .list_users()
            .into_iter()
            .find(|u| u.username == "ops")
            .unwrap();
        assert_eq!(ops.role, UserRole::Viewer, "and the account is demoted");
    }

    /// A promotion revokes nothing.
    ///
    /// The asymmetry is the point: the certificates the account already holds
    /// now grant *less* than the account does, which costs its holder one
    /// sign-in and nobody any access. Revoking them anyway would sign the mesh
    /// a record to flood in exchange for nothing.
    #[test]
    fn promoting_an_account_revokes_nothing() {
        let (mut ca, secret) = ca_with_user(UserRole::Viewer, 900);
        let laptop = sign_in(&mut ca, "ops", &secret, 2);

        let (records, changed) = ca
            .set_user_role_revoking_sessions("ops", UserRole::Admin)
            .expect("the promotion succeeds");

        assert!(changed);
        assert!(records.is_empty(), "nothing to cut off");
        assert!(!entry(&ca, &laptop).revoked, "the session keeps working");
        assert_eq!(
            ca.list_users()[0].role,
            UserRole::Admin,
            "and the account is promoted"
        );
    }

    /// Stating the role an account already holds is a success that revokes
    /// nothing — not an error, and not a re-issue.
    ///
    /// A caller that states a role got the account it asked for. What must not
    /// happen is that saying "this account is a viewer" twice revokes a session
    /// the first call already accounted for, since the second call is exactly
    /// what an operator does when they are unsure whether the first landed.
    #[test]
    fn restating_the_role_an_account_already_holds_revokes_nothing() {
        let (mut ca, secret) = ca_with_user(UserRole::Viewer, 900);
        let laptop = sign_in(&mut ca, "ops", &secret, 2);

        let (records, changed) = ca
            .set_user_role_revoking_sessions("ops", UserRole::Viewer)
            .expect("restating a role is not an error");

        assert!(!changed, "and it says so, rather than reporting a change");
        assert!(records.is_empty());
        assert!(!entry(&ca, &laptop).revoked);
    }

    /// **Disabling an account ends the sessions it is already holding.**
    ///
    /// Without that, "disabled" is a statement about the future only: the
    /// account obtains no *new* session while every certificate it already has
    /// keeps working, for up to its whole session lifetime. An operator
    /// disabling an account believes access stopped now.
    #[test]
    fn disabling_an_account_revokes_the_sessions_it_holds() {
        let (mut ca, secret) = ca_with_user(UserRole::Admin, 900);
        let laptop = sign_in(&mut ca, "ops", &secret, 2);

        let (records, changed) = ca
            .set_user_enabled_revoking_sessions("ops", false)
            .expect("disabling succeeds");

        assert!(changed);
        assert_eq!(records.len(), 1);
        assert!(entry(&ca, &laptop).revoked);
        assert!(ca.list_users()[0].disabled);
    }

    /// Re-enabling clears the lockout with it, and revokes nothing: an operator
    /// turning an account back on means it should work, not that it should work
    /// in fifteen minutes.
    #[test]
    fn enabling_an_account_clears_its_lockout_and_revokes_nothing() {
        let (mut ca, _) = ca_with_user(UserRole::Admin, 900);
        ca.update_user("ops", |user| {
            user.disabled = true;
            user.failed_attempts = 5;
            user.locked_until = ca_locked_until();
        })
        .unwrap();

        let (records, changed) = ca
            .set_user_enabled_revoking_sessions("ops", true)
            .expect("enabling succeeds");

        assert!(changed);
        assert!(records.is_empty());
        let ops = &ca.list_users()[0];
        assert!(!ops.disabled);
        assert!(!ops.locked, "the lockout went with it");
    }

    /// Enabling clears a lockout on an account that was **never disabled**.
    ///
    /// `disabled` and `locked_until` are independent: five failed sign-ins lock
    /// an account that is otherwise perfectly enabled, and that is the state an
    /// operator actually reaches for `enable` to fix. A fast path keyed on
    /// `disabled` alone answers "already enabled; nothing changed" and leaves
    /// the lockout standing — which makes the command's own promise false in
    /// the only case it is usually typed for. There is no `unlock` command, so
    /// the alternatives are waiting out the window or resetting the password.
    #[test]
    fn enabling_a_locked_but_never_disabled_account_clears_the_lockout() {
        let (mut ca, _) = ca_with_user(UserRole::Admin, 900);
        ca.set_now_unix(1_000);
        ca.update_user("ops", |user| {
            user.failed_attempts = 5;
            user.locked_until = ca_locked_until();
        })
        .unwrap();
        assert!(ca.list_users()[0].locked, "locked, and never disabled");
        assert!(!ca.list_users()[0].disabled);

        ca.set_user_enabled_revoking_sessions("ops", true)
            .expect("enabling succeeds");

        assert!(
            !ca.list_users()[0].locked,
            "the lockout is cleared even though `disabled` never changed"
        );
    }

    /// A demotion that cannot be made durable changes nothing and says so.
    ///
    /// Both halves are absent afterwards — the role is unchanged *and* the
    /// session is un-revoked — and the caller is told, rather than being handed
    /// a success for a write that never landed.
    ///
    /// What this deliberately does **not** prove is that the two halves share
    /// one write. Under a doomed store two separate writes both fail and both
    /// roll back, so the end state is identical; the split is only observable
    /// when the first write succeeds and the second does not, which cannot be
    /// arranged from out here — there is no way to intervene between two writes
    /// internal to the method. That property is pinned one layer down, in
    /// `persistence.rs`'s
    /// `mutate_users_and_issued_rolls_back_both_collections_together_on_persist_failure`,
    /// where the directory can be removed *between* the halves. Left explicit
    /// because a reader could reasonably assume this test covers it, and act on
    /// that assumption when changing the method.
    #[test]
    fn a_demotion_that_cannot_be_persisted_changes_nothing_and_reports_it() {
        // Set up against a store that *works*, so the account and its session
        // are durably there — then take the directory away, which dooms every
        // later write. Dooming it up front instead would roll back the setup
        // itself and leave nothing to demote.
        let dir = std::env::temp_dir().join(format!(
            "wayfinder-server-test-{}-demotion-atomicity",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let cfg = persisted_cfg(&path);
        let mut ca = CertAuthority::from_config(&[1; 32], &cfg).unwrap();
        ca.set_now_unix(1_700_000_000);

        let user = UserRecord::new("ops", "hunter2", UserRole::Admin, 900)
            .unwrap()
            .without_totp();
        ca.add_user(user).unwrap();
        let session = Keypair::from_seed(&[5u8; 32]);
        MeshAuthority::authenticate_user(
            &mut ca,
            "ops",
            "hunter2",
            "",
            &session.ed_pubkey(),
            &session.x_pubkey(),
        )
        .expect("the login is serviceable");
        let live = ca.live_session_macs("ops");
        assert_eq!(live.len(), 1, "the account holds one session to revoke");

        std::fs::remove_dir_all(&dir).unwrap();

        let err = ca
            .set_user_role_revoking_sessions("ops", UserRole::Viewer)
            .expect_err("a write that cannot be made durable is an error");
        assert!(err.contains("could not record"), "got: {err}");

        // Both halves rolled back, together.
        assert_eq!(
            ca.list_users()[0].role,
            UserRole::Admin,
            "the role change did not land"
        );
        assert!(
            !entry(&ca, &live[0].0).revoked,
            "and neither did the revocation"
        );
    }

    /// An administrative password reset replaces the password, clears any
    /// lockout, and leaves the second factor alone.
    ///
    /// The last clause is the security-relevant one. An operator who could
    /// replace the second factor too could take an account over with one
    /// request and leave its owner no signal; whoever needs a fresh factor gets
    /// a fresh invite.
    #[test]
    fn resetting_a_password_keeps_the_second_factor() {
        let (mut ca, secret) = ca_with_user(UserRole::Admin, 900);
        ca.update_user("ops", |user| {
            user.failed_attempts = 5;
            user.locked_until = ca_locked_until();
        })
        .unwrap();

        ca.set_user_password("ops", "correct horse battery staple")
            .expect("the reset succeeds");

        assert!(!ca.list_users()[0].locked, "the lockout is cleared");

        // The new password signs in, with the *same* authenticator code.
        let (ed, x) = node_keys(2);
        let code = live_code(&secret, ca.now_unix());
        let outcome = ca
            .authenticate_user("ops", "correct horse battery staple", &code, &ed, &x)
            .expect("the login is serviceable");
        assert!(
            matches!(outcome, UserAuthOutcome::Issued(_)),
            "the new password works and the old second factor still does"
        );
    }

    /// An empty password is refused rather than stored: an account whose
    /// password is the empty string is not a credential.
    #[test]
    fn resetting_a_password_to_nothing_is_refused() {
        let (mut ca, _) = ca_with_user(UserRole::Admin, 900);
        assert!(ca.set_user_password("ops", "").is_err());
    }

    /// Every one of the three refuses an unknown name rather than reporting a
    /// silent success — whoever typed it has a wrong idea about the roster.
    #[test]
    fn changing_an_unknown_account_is_refused() {
        let (mut ca, _) = ca_with_user(UserRole::Admin, 900);
        assert!(
            ca.set_user_role_revoking_sessions("nobody", UserRole::Viewer)
                .is_err()
        );
        assert!(
            ca.set_user_enabled_revoking_sessions("nobody", false)
                .is_err()
        );
        assert!(ca.set_user_password("nobody", "hunter2").is_err());
    }

    /// Demoting or disabling the last account that can still administer the
    /// mesh is refused over the management API, exactly as removing it is.
    ///
    /// All three leave the same mesh: one with no enabled administrator, whose
    /// user store no ordinary session can change in either direction. The guard
    /// belongs to all three or to none — a refusal on `RemoveUser` alone is a
    /// locked front door beside an open window.
    ///
    /// Refused *before* anything is signed, so a declined demotion has revoked
    /// nothing: the account it would not demote keeps the sessions it holds.
    #[test]
    fn stranding_the_mesh_by_demoting_or_disabling_the_last_admin_is_refused() {
        let (mut ca, secret) = ca_with_user(UserRole::Admin, 900);
        let laptop = sign_in(&mut ca, "ops", &secret, 2);

        let err = MeshAuthority::set_user_role(&mut ca, "ops", UserRole::Viewer).unwrap_err();
        assert!(
            err.contains("administrator"),
            "the refusal says what it is protecting: {err}"
        );
        let err = MeshAuthority::set_user_enabled(&mut ca, "ops", false).unwrap_err();
        assert!(err.contains("administrator"), "{err}");

        assert_eq!(ca.list_users()[0].role, UserRole::Admin);
        assert!(!ca.list_users()[0].disabled);
        assert!(
            !entry(&ca, &laptop).revoked,
            "a refused act signs nothing: the session is untouched"
        );

        // A second enabled administrator makes both go through.
        ca.add_user(UserRecord::new("second", "hunter2", UserRole::Admin, 900).unwrap())
            .unwrap();
        MeshAuthority::set_user_role(&mut ca, "ops", UserRole::Viewer).unwrap();
        MeshAuthority::set_user_enabled(&mut ca, "ops", false).unwrap();
    }

    /// A lockout instant far enough ahead of the test clock to be in force.
    fn ca_locked_until() -> u64 {
        u64::MAX
    }

    // ── renewal over the mesh (design 24) ─────────────────────────────────────

    /// A live holder asking over the mesh is re-issued on the spot, for the
    /// window its own record carries rather than the authority's current
    /// default — the same rule `SubmitCsr` applies to a holder re-enrolling,
    /// because it is the same act reached by a different road.
    #[test]
    fn a_live_holder_is_re_issued_over_the_mesh() {
        let mut ca = open_ca();
        let (ed, x) = node_keys(2);
        let first = issued_cert(&mut ca, &node_mac(2), &ed, &x, "");

        ca.set_now_unix(900);
        let outcome = ca
            .renew_holder(&node_mac(2), &ed, &x)
            .expect("a serviceable request");
        let RenewalOutcome::Issued(bytes) = outcome else {
            panic!("expected a re-issue, got {outcome:?}");
        };

        let renewed = MembershipCert::from_bytes(&bytes).expect("a well-formed certificate");
        let previous = MembershipCert::from_bytes(&first).unwrap();
        assert_eq!(renewed.node_mac, node_mac(2));
        assert_eq!(renewed.ed_pubkey, ed);
        assert!(
            renewed.not_after.get() > previous.not_after.get(),
            "a renewal has to move the credential forward, or the board refuses it"
        );
        assert_eq!(
            renewed.not_after.get() - renewed.not_before.get(),
            previous.not_after.get() - previous.not_before.get(),
            "for the lifetime an operator approved this device for, not the default"
        );
    }

    /// **A lapsed holder is refused, and never parked** (design 24 §5.2).
    ///
    /// One second past `not_after` a node is a stranger, not a renewing holder.
    /// Over the management API that request joins the approval queue, which is
    /// right: an operator is standing there. Over the mesh it must not, and the
    /// difference is the whole reason this is its own entry point rather than a
    /// second caller of `submit_csr`. A queue entry nobody asked for is a
    /// credential-bearing row an unattended board can create, once per
    /// rate-limit interval, for as long as it stays lapsed.
    ///
    /// It is also the deliberate outcome rather than a limitation to engineer
    /// away: a certificate's lifetime is the only revocation bound that reaches
    /// a member which was offline when the revocation flooded, and a mechanism
    /// that let an expired credential bootstrap a fresh one would make that
    /// bound a formality.
    #[test]
    fn a_renewal_request_from_a_lapsed_holder_is_refused() {
        let mut ca = open_ca();
        let (ed, x) = node_keys(2);
        issued_cert(&mut ca, &node_mac(2), &ed, &x, "");

        // Past the certificate's own `not_after` (issued at 100 for 1000s).
        ca.set_now_unix(2_000);
        let held_before = ca.list_pending().len();

        let outcome = ca.renew_holder(&node_mac(2), &ed, &x).unwrap();
        assert!(
            matches!(outcome, RenewalOutcome::Refused(_)),
            "expected a refusal, got {outcome:?}"
        );
        assert_eq!(
            ca.list_pending().len(),
            held_before,
            "and nothing was queued for an operator: recovery is the serial-port ritual"
        );
    }

    /// A node this authority has never certified is refused, and likewise
    /// queues nothing. Enrollment over the mesh is a non-goal — a node with no
    /// credential cannot route authenticated, so it could not reach here in the
    /// first place, and an authority that answered as if it could would be one
    /// an attacker could fill a queue through.
    #[test]
    fn a_stranger_renewing_over_the_mesh_is_refused_and_never_parked() {
        let mut ca = open_ca();
        let (ed, x) = node_keys(7);

        let outcome = ca.renew_holder(&node_mac(7), &ed, &x).unwrap();
        assert!(
            matches!(outcome, RenewalOutcome::Refused(_)),
            "expected a refusal, got {outcome:?}"
        );
        assert!(ca.list_pending().is_empty());
    }

    /// A revoked holder is refused. Revocation ejects a node that still holds
    /// its own key, so the key is exactly what the ejected party has — and
    /// re-issuing here would clear the `revoked` flag the record stands on.
    #[test]
    fn a_revoked_holder_renewing_over_the_mesh_is_refused() {
        let mut ca = open_ca();
        let (ed, x) = node_keys(2);
        issued_cert(&mut ca, &node_mac(2), &ed, &x, "");
        ca.revoke(&node_mac(2)).expect("the holder is on file");

        let outcome = ca.renew_holder(&node_mac(2), &ed, &x).unwrap();
        assert!(
            matches!(outcome, RenewalOutcome::Refused(_)),
            "expected a refusal, got {outcome:?}"
        );
        assert!(ca.list_pending().is_empty());
    }

    /// A key that does not derive the address it names is refused before
    /// anything is looked up — the key↔address binding (design 09 §5), applied
    /// at this entry point too rather than only at `SubmitCsr`.
    #[test]
    fn a_renewal_naming_an_address_its_key_does_not_derive_is_refused() {
        let mut ca = open_ca();
        let (ed, x) = node_keys(2);
        issued_cert(&mut ca, &node_mac(2), &ed, &x, "");

        let outcome = ca.renew_holder(&node_mac(3), &ed, &x).unwrap();
        assert!(
            matches!(outcome, RenewalOutcome::Refused(_)),
            "expected a refusal, got {outcome:?}"
        );
    }

    /// An authority with no usable clock services nothing. It would otherwise
    /// issue a certificate whose window starts at the unix epoch and is already
    /// expired against any real clock — the same fail-closed rule `submit_csr`
    /// keeps, and an `Err` rather than a refusal because the request is not
    /// wrong, this node is.
    #[test]
    fn an_unclocked_authority_cannot_renew_over_the_mesh() {
        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None, true);
        let (ed, x) = node_keys(2);
        assert!(ca.renew_holder(&node_mac(2), &ed, &x).is_err());
    }
}
