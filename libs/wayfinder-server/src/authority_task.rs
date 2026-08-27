//! The certificate authority's own executor, and the adapter it serves through.
//!
//! # Why the authority is not on the router loop
//!
//! Every authority request used to run as one arm of the driver's `select!`,
//! against an adapter that borrowed the router and the authority together. That
//! is affordable for a projection of router state and ruinous for the authority:
//! `AuthenticateUser` spends Argon2id at `ARGON2_MEMORY_KIB` and then performs a
//! durable write, so for 50-150 ms no link `recv` is serviced and the OGM timer
//! does not fire. On a node that both routes and provides — which nothing but
//! convention prevents, since `provider` is optional in a node's configuration
//! whether or not that node also owns interfaces — that is a data-plane outage
//! caused by a stranger's failed login.
//!
//! See `docs/design/implemented/13-certificate-authority-off-the-router-loop.md`.
//!
//! # The invariant
//!
//! **The router loop never awaits this task.** The authority may be mid-Argon2id
//! whenever the loop wants something from it, so everything the loop needs from
//! the authority arrives as a published value it can read without waiting — the
//! enrollment policy, via [`EnrollmentPolicyRx`]. Traffic in the other direction
//! (this task awaiting the loop, to flood a revocation) is safe, and is the only
//! edge on which either side ever waits.

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::watch;
use wayfinder_protos::service::AuthorityDataProvider;
use wayfinder_protos::service::CsrOutcome;
use wayfinder_protos::service::EnrollmentAdmission;
use wayfinder_protos::service::EnrollmentPolicyData;
use wayfinder_protos::service::EnrollmentPolicyStatusData;
use wayfinder_protos::service::IssuedCertData;
use wayfinder_protos::service::PendingCsrData;
use wayfinder_protos::service::RegistrationStartedData;
use wayfinder_protos::service::UserAccountData;
use wayfinder_protos::service::UserAuthOutcome;
use wayfinder_protos::service::UserInviteData;
use wayfinder_protos::service::UserInviteMintedData;
use wayfinder_protos::service::handle_authority;
use wayfinder_protos::wayfinder::v1alpha::ErrorResponse;
use wayfinder_protos::wayfinder::v1alpha::WayfinderRequest;
use wayfinder_protos::wayfinder::v1alpha::WayfinderResponse;
use wayfinder_protos::wayfinder::v1alpha::wayfinder_response::Response as RespKind;

use wayfinder_auth::RevocationRecord;

use crate::CertAuthority;
use crate::MeshAuthority;
use crate::authority::MAX_PENDING_INVITES;
use crate::users::UserRole;

/// Re-exported so a caller of this module does not have to reach into
/// `wayfinder-protos` for the string the trait defaults already produce.
pub use wayfinder_protos::service::NOT_A_PROVIDER;
pub use wayfinder_protos::service::not_a_provider_response;

/// What the router loop publishes for the authority to read without waiting.
///
/// One value rather than two channels because the two are published at the same
/// instant, by the same line, and read at the same instant by the same reader —
/// and because a single value cannot be observed torn: an authority can never
/// see a fresh clock beside a stale auth flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouterFacts {
    /// Unix seconds the router is verifying certificates against, so issued
    /// validity windows track the instant the mesh will judge them by.
    ///
    /// Never seeded to zero: every issuing path treats `now_unix == 0` as
    /// fail-closed, so an authority that read this before the router loop's
    /// first iteration would silently refuse everything.
    pub unix_secs: u64,
    /// Whether this node's mesh authentication is enabled.
    ///
    /// For `RevokeNode` alone: flooding a revocation needs this node to be an
    /// authenticated member, because the record rides its own OGMs. A provider
    /// that signs and persists a revocation it cannot flood leaves the operator
    /// believing a node was revoked when nothing was announced — so it is read
    /// at the instant of signing, never captured when the request arrived.
    pub auth_present: bool,
}

/// The router's published facts, as the authority reads them.
pub type RouterFactsRx = watch::Receiver<RouterFacts>;

/// The enrollment policy the authority publishes for the router loop to read.
///
/// `None` until the authority publishes, and on a node with no authority at
/// all — which is what `GetSecurityStatus` must keep reporting rather than a
/// default-valued policy that would read as a real one.
pub type EnrollmentPolicyRx = watch::Receiver<Option<EnrollmentPolicyStatusData>>;

/// Publishing half of [`EnrollmentPolicyRx`].
pub type EnrollmentPolicyTx = watch::Sender<Option<EnrollmentPolicyStatusData>>;

/// A signed revocation on its way to the router loop to be flooded, with the
/// channel the loop reports back on.
///
/// The parsed [`RevocationRecord`], not its bytes.  This process signed it a
/// moment ago, so "the authority produced something the router cannot parse" is
/// not a real condition — carrying bytes would only oblige the router loop to
/// invent an answer for it.  The record is a 92-byte `Copy` POD, so sending it
/// by value costs nothing a `Vec` would not.
pub type RevocationTx = mpsc::Sender<(RevocationRecord, oneshot::Sender<Result<(), String>>)>;

/// Receiving half of [`RevocationTx`], serviced by the router loop.
pub type RevocationRx = mpsc::Receiver<(RevocationRecord, oneshot::Sender<Result<(), String>>)>;

/// What may be asked of the authority task.
///
/// A command rather than a bare request because one thing the authority does is
/// not a request kind of its own: `SetConfig` carries an enrollment policy
/// alongside router settings, and the connection task splits it so each half
/// reaches its owner. Modelling that as a command keeps `request_facet`'s
/// one-owner-per-kind rule intact instead of putting `SetConfig` in both halves.
pub enum AuthorityCommand {
    /// Serve one management request from authority state.
    Request(WayfinderRequest, oneshot::Sender<WayfinderResponse>),
    /// Apply the enrollment half of a `SetConfig`.
    SetEnrollmentPolicy(EnrollmentPolicyData, oneshot::Sender<Result<(), String>>),
}

/// Sending half of the authority task's command channel.
pub type AuthorityTx = mpsc::Sender<AuthorityCommand>;

/// Receiving half of [`AuthorityTx`].
pub type AuthorityRx = mpsc::Receiver<AuthorityCommand>;

/// Everything the router loop exchanges with the certificate-authority task.
///
/// One struct because the channels are one relationship, and because wiring
/// them one at a time is how the clock gets forgotten: an authority whose
/// `now_unix` stays 0 refuses to issue anything, silently, with every
/// router-side test still green.  [`attach`](Self::attach) mints every half at
/// once, so `serve_authority` cannot be called with one of them missing.
pub struct AuthorityComms {
    /// What this router publishes for the authority: the certificate-validity
    /// clock and whether a revocation can be flooded at all.
    ///
    /// Not an `Option`, and seeded at construction.  It has to be live *before*
    /// any authority attaches, or an authority wired up later reads the zero
    /// that every issuing path treats as fail-closed.  A `watch::Sender` with
    /// no receivers costs one atomic store and cannot fail, so a node that
    /// never runs an authority pays nothing for holding it.
    facts: watch::Sender<RouterFacts>,
    /// The authority's last-published enrollment policy.
    ///
    /// `None` until it publishes, and forever on a node with no authority —
    /// which is what `GetSecurityStatus` must keep reporting, rather than a
    /// default-valued policy that would read as a real one.
    policy: Option<EnrollmentPolicyRx>,
    /// Signed revocations awaiting ingestion.  `None` keeps the router loop's
    /// corresponding `select!` arm dormant without a separate enable flag.
    revocations: Option<RevocationRx>,
}

/// The certificate-authority task's half of [`AuthorityComms`], handed over
/// whole so the task cannot be started with a channel missing.
pub struct AuthorityPorts {
    /// The command queue the connection tasks fill.
    pub commands: AuthorityRx,
    /// What the router publishes about itself, read and never awaited.
    pub facts: RouterFactsRx,
    /// Where this authority publishes its enrollment policy.
    pub policy: EnrollmentPolicyTx,
    /// Where a signed revocation goes to be flooded.
    pub revocations: RevocationTx,
}

impl AuthorityComms {
    /// Open the publishing half, seeded with a real time.
    ///
    /// `unix_secs` is seeded rather than zeroed for the reason `RouterFacts`
    /// gives: a reader that got here before the router loop's first iteration
    /// would otherwise see an authority that refuses everything, silently.
    pub fn new(unix_secs: u64) -> Self {
        let (facts, _) = watch::channel(RouterFacts {
            unix_secs,
            auth_present: false,
        });
        Self {
            facts,
            policy: None,
            revocations: None,
        }
    }

    /// Publish what the router now knows about itself.
    ///
    /// Infallible by construction (`send_replace`): an authority task that has
    /// already shut down must not make the router loop's clock tick an error.
    pub fn publish(&self, facts: RouterFacts) {
        self.facts.send_replace(facts);
    }

    /// Re-publish with a new clock, leaving `auth_present` as it stands.
    pub fn set_clock(&self, unix_secs: u64) {
        let auth_present = self.facts.borrow().auth_present;
        self.publish(RouterFacts {
            unix_secs,
            auth_present,
        });
    }

    /// Open the return channels and hand the authority task its half.
    ///
    /// Every direction is wired here, in one call, so provider mode cannot be
    /// half-enabled.
    pub fn attach(&mut self, commands: AuthorityRx) -> AuthorityPorts {
        // A router serves at most one authority. A second `attach` would
        // overwrite the first's receivers, and the orphaned task would then
        // report "the router is no longer accepting revocations" about a router
        // that is running perfectly — a lie this cannot be allowed to produce.
        assert!(
            self.revocations.is_none(),
            "attach called twice: a router serves at most one certificate authority, and a \
             second silently orphans the first's revocation path"
        );
        let (policy, policy_rx) = watch::channel(None);
        let (revocations, revocations_rx) = mpsc::channel(REVOCATION_QUEUE_DEPTH);
        self.policy = Some(policy_rx);
        self.revocations = Some(revocations_rx);
        AuthorityPorts {
            commands,
            facts: self.facts.subscribe(),
            policy,
            revocations,
        }
    }

    /// Borrow the two inbound halves at once.
    ///
    /// One call handing out two disjoint field borrows, because `select!`
    /// constructs every branch's future before polling any: the arm awaiting a
    /// revocation (`&mut`) and the arm reading the policy (`&`) are live at the
    /// same moment, so two accessor methods on `&mut self`/`&self` would not
    /// compile.
    pub fn split(&mut self) -> (&mut Option<RevocationRx>, &Option<EnrollmentPolicyRx>) {
        (&mut self.revocations, &self.policy)
    }
}

/// How many signed revocations may be in flight to the router loop at once.
///
/// One would do — `flood_revocation` sends one and awaits the router's verdict
/// before the authority serves anything else — but a little slack costs nothing
/// and keeps a shutdown race from dropping a revocation that was already
/// signed.
const REVOCATION_QUEUE_DEPTH: usize = 4;

/// Projects a [`CertAuthority`] as the management API's authority half.
///
/// The counterpart to `RouterAdapter`, and deliberately a separate type rather
/// than a second borrow inside it: the two are owned by different executors now,
/// so a single adapter holding both would be exactly the coupling this design
/// removes.
pub struct AuthorityAdapter<'a> {
    ca: &'a mut CertAuthority,
    /// What the router beside this authority currently publishes about itself.
    ///
    /// The live receiver, not a snapshot taken when the request arrived. A
    /// request can wait in the queue and then spend ~100 ms on the blocking
    /// pool before it signs anything, and a `SetAuth` can disable
    /// authentication in that window — so a value read at the top of the
    /// request is exactly the value that must not be trusted here.
    facts: RouterFactsRx,
    /// The revocations signed while serving this request, for the caller to
    /// hand to the router loop.
    ///
    /// Stashed rather than flooded here because the trait method is
    /// synchronous and the router hop is not. The task takes them immediately
    /// after the request returns, so the two stay adjacent (§4.3: the window
    /// between signing and flooding is one this design widens, and a crash
    /// inside it leaves nothing to re-derive the records from).
    ///
    /// A vector rather than the single slot this once held: `RemoveUser` and
    /// `RevokeUserSessions` each end *every* session an account holds, and an
    /// account holds one per sign-in inside its lifetime. See design 14 §3.3,
    /// which also has the airtime that costs.
    signed_revocations: Vec<RevocationRecord>,
}

impl<'a> AuthorityAdapter<'a> {
    /// Wrap `ca`, reading whether the neighbouring router can flood a
    /// revocation from `facts` at the moment one is signed.
    pub fn new(ca: &'a mut CertAuthority, facts: RouterFactsRx) -> Self {
        Self {
            ca,
            facts,
            signed_revocations: Vec::new(),
        }
    }

    /// Refuse to sign unless the neighbouring router could actually flood the
    /// result.
    ///
    /// Checked at the instant of signing rather than when the request arrived —
    /// see [`Self::facts`] — and before signing rather than after, because every
    /// path here persists: a provider that signs a revocation it cannot flood
    /// leaves the operator believing access ended when nothing was ever
    /// announced, and refusing afterwards would not undo it.
    fn can_flood(&self, act: &str) -> Result<(), String> {
        if self.facts.borrow().auth_present {
            return Ok(());
        }
        Err(alloc::format!(
            "cannot {act}: this provider node has mesh authentication disabled, so the \
             revocation cannot be flooded"
        ))
    }

    /// Run a session-revoking act, gating it on the router's ability to flood
    /// and keeping whatever it signed.
    ///
    /// The gate is applied **only when the act actually revokes something**, and
    /// that ordering is why this is one helper rather than a check in each
    /// caller. `RemoveUser` against an account with no live sessions signs
    /// nothing, so on a node with mesh authentication disabled it must keep
    /// working exactly as it does today; refusing it would be a regression
    /// dressed as a safety check. Running the act first and rejecting after is
    /// not an option either — every path here persists — so the account is asked
    /// what it holds *before* anything is signed, and the gate applies to the
    /// answer.
    ///
    /// See design 14 §5.2 and §5.3.
    fn gated_session_revocation(
        &mut self,
        username: &str,
        act: &str,
        f: impl FnOnce(&mut CertAuthority, &str) -> Result<Vec<RevocationRecord>, String>,
    ) -> Result<u32, String> {
        if self.ca.has_live_sessions(username) {
            self.can_flood(act)?;
        }
        let records = f(self.ca, username)?;
        let count = records.len() as u32;
        self.signed_revocations.extend(records);
        Ok(count)
    }

    /// Consume the adapter, yielding the revocations it signed.
    ///
    /// Consuming rather than a `take(&mut self)`: the records are already signed
    /// and durably recorded, so dropping them would leave certificates revoked
    /// in the authority's own log and never announced to the mesh. Taking `self`
    /// means a caller cannot keep using the adapter and forget them, and
    /// `must_use` means it cannot discard the result silently.
    #[must_use = "a signed revocation is already persisted; dropping it leaves the \
                  certificate revoked in the authority's records but never announced to \
                  the mesh"]
    pub fn finish(self) -> Vec<RevocationRecord> {
        self.signed_revocations
    }
}

impl AuthorityDataProvider for AuthorityAdapter<'_> {
    fn get_trust_anchor(&self) -> Result<Vec<u8>, String> {
        Ok(self.ca.trust_anchor_bytes())
    }

    fn reveal_enrollment_token(&self) -> Result<EnrollmentAdmission, String> {
        Ok(self.ca.admission())
    }

    fn submit_csr(
        &mut self,
        node_mac: &[u8],
        ed_pubkey: &[u8],
        x_pubkey: &[u8],
        enrollment_token: &str,
    ) -> Result<CsrOutcome, String> {
        self.ca
            .submit_csr(node_mac, ed_pubkey, x_pubkey, enrollment_token)
    }

    fn authenticate_user(
        &mut self,
        username: &str,
        password: &str,
        totp_code: &str,
        ed_pubkey: &[u8],
        x_pubkey: &[u8],
    ) -> Result<UserAuthOutcome, String> {
        self.ca
            .authenticate_user(username, password, totp_code, ed_pubkey, x_pubkey)
    }

    fn list_users(&self) -> Result<Vec<UserAccountData>, String> {
        // Through the trait: `CertAuthority` also has an inherent `list_users`
        // returning its own `UserSummary`, and the management API wants the
        // projected form.
        Ok(MeshAuthority::list_users(self.ca))
    }

    fn create_user(
        &mut self,
        username: &str,
        password: &str,
        admin: bool,
        session_ttl_secs: u64,
        no_totp: bool,
    ) -> Result<String, String> {
        self.ca
            .create_user(username, password, admin, session_ttl_secs, no_totp)
    }

    fn remove_user(&mut self, username: &str) -> Result<(), String> {
        // `MeshAuthority::remove_user`, named explicitly, and that is not
        // stylistic. `CertAuthority` has an *inherent* `remove_user` — the
        // offline tool's raw store operation — and an inherent method wins
        // method resolution over a trait one, so `self.ca.remove_user(..)` here
        // silently reached the raw version: no last-administrator guard, and now
        // no revocation either. The guard was written, tested, and never on this
        // path.
        self.gated_session_revocation(username, "remove this account", |ca, name| {
            MeshAuthority::remove_user(ca, name)
        })
        .map(|_| ())
    }

    fn create_user_invite(
        &mut self,
        username: &str,
        admin: bool,
        session_ttl_secs: u64,
        invite_ttl_secs: u64,
    ) -> Result<UserInviteMintedData, String> {
        let role = if admin {
            UserRole::Admin
        } else {
            UserRole::Viewer
        };
        let minted =
            self.ca
                .create_user_invite(username, role, session_ttl_secs, invite_ttl_secs)?;
        Ok(UserInviteMintedData {
            username: minted.username,
            token: minted.token,
            expires_at: minted.expires_at,
        })
    }

    fn list_user_invites(&self) -> Result<(Vec<UserInviteData>, u32), String> {
        let invites = self
            .ca
            .list_user_invites()
            .into_iter()
            .map(|i| UserInviteData {
                username: i.username,
                admin: i.role == UserRole::Admin,
                session_ttl_secs: i.session_ttl_secs,
                created_at: i.created_at,
                expires_at: i.expires_at,
                // Zero for "not started" on the wire, `None` in the summary.
                // The projection is the only place the two spellings meet, and
                // the wire one is proto3's — a message has no absent scalar.
                started_at: i.started_at.unwrap_or(0),
                handle_expires_at: i.handle_expires_at.unwrap_or(0),
            })
            .collect();
        Ok((invites, MAX_PENDING_INVITES as u32))
    }

    fn revoke_user_invite(&mut self, username: &str) -> Result<(), String> {
        self.ca.revoke_user_invite(username)
    }

    fn begin_user_registration(&mut self, token: &str) -> Result<RegistrationStartedData, String> {
        let started = self.ca.begin_user_registration(token)?;
        Ok(RegistrationStartedData {
            username: started.username,
            totp_enrolment_uri: started.totp_enrolment_uri,
            handle: started.handle,
            handle_expires_at: started.handle_expires_at,
        })
    }

    fn complete_user_registration(
        &mut self,
        handle: &str,
        password: &str,
        totp_code: &str,
    ) -> Result<(), String> {
        self.ca
            .complete_user_registration(handle, password, totp_code)
    }

    fn list_pending_csrs(&self) -> Result<Vec<PendingCsrData>, String> {
        Ok(self.ca.list_pending())
    }

    fn approve_csr(&mut self, node_mac: &[u8]) -> Result<(), String> {
        self.ca.approve_csr(node_mac)
    }

    fn deny_csr(&mut self, node_mac: &[u8]) -> Result<(), String> {
        self.ca.deny_csr(node_mac)
    }

    fn revoke_node(&mut self, node_mac: &[u8]) -> Result<(), String> {
        self.can_flood("revoke")?;
        self.signed_revocations.push(self.ca.revoke(node_mac)?);
        Ok(())
    }

    fn revoke_user_sessions(&mut self, username: &str) -> Result<u32, String> {
        self.gated_session_revocation(username, "revoke this account's sessions", |ca, name| {
            MeshAuthority::revoke_user_sessions(ca, name)
        })
    }

    fn list_certs(&self) -> Result<Vec<IssuedCertData>, String> {
        Ok(self.ca.list_certs())
    }
}

/// Run the certificate authority's event loop until its command channel closes.
///
/// Owns `ca` outright. Single ownership is what `CaLog`'s mutate-and-persist
/// contract assumes, and moving the authority to its own executor is meant to
/// change *where* it runs, not how many writers it has.
///
/// `ports.facts` carries the router loop's certificate-validity clock, applied
/// before every command so issued validity windows track the same instant the
/// router verifies against. Without it `now_unix` stays 0, which every issuing
/// path treats as fail-closed — silently, and with every router-side test still
/// green. That is why [`AuthorityPorts`] is taken whole rather than as loose
/// arguments a caller can leave out one of.
pub async fn serve_authority(mut ca: CertAuthority, ports: AuthorityPorts) {
    let AuthorityPorts {
        mut commands,
        facts,
        policy,
        revocations,
    } = ports;
    // Publish the policy the authority actually loaded before serving anything.
    // `apply_policy_overrides` runs at construction, so a persisted runtime
    // override wins over the configured value — a first `GetSecurityStatus`
    // that raced this would report the config's policy, not the one in force.
    if policy.send(Some(ca.enrollment_policy())).is_err() {
        // No receiver means the router loop that reports `GetSecurityStatus`
        // has already ended. Not fatal to the authority, but it means the
        // reported policy can never track the real one — the same permanent
        // divergence the mid-run publication failure below reports, so the same
        // level.
        tracing::error!(
            "no reader for the enrollment policy; GetSecurityStatus will not report it"
        );
    }
    tracing::info!("certificate-authority task started");

    // No clock is pushed in here, and that absence is the fix rather than an
    // omission. This line used to be `ca.set_now_unix(facts.borrow().unix_secs)`
    // — the authority borrowing the router's notion of now — and the router
    // publishes only when its loop wakes, which on a provider with no mesh
    // interfaces is once an hour. An authority request never wakes it either:
    // the connection task routes an `Authority` facet straight to this channel,
    // past the router loop entirely. So "now" froze between wakeups, and with it
    // every expiry this authority enforces — including an invitation's, which is
    // a bearer token that outlived its stated life and still redeemed.
    //
    // A provider is built by `CertAuthority::from_config`, which puts it on
    // `Clock::System`: it reads the host clock at the moment it needs an answer,
    // so there is no stored instant left to go stale.
    while let Some(command) = commands.recv().await {
        match command {
            AuthorityCommand::Request(request, reply) => {
                let (returned_ca, response, signed) =
                    serve_one_request(ca, request, facts.clone()).await;
                ca = returned_ca;

                let response = flood_revocations(&revocations, signed, response).await;
                // The client hanging up between asking and being answered is
                // ordinary, not an error: the work is already done and durable.
                let _ = reply.send(response);
            }
            AuthorityCommand::SetEnrollmentPolicy(update, reply) => {
                let outcome = ca.set_enrollment_policy(&update);
                if outcome.is_ok() && policy.send(Some(ca.enrollment_policy())).is_err() {
                    // Published before the reply, so a client that sets a policy
                    // and immediately reads it back cannot observe the old one.
                    // A failure here means the change is live and durable but
                    // `GetSecurityStatus` will keep reporting the previous value
                    // for the life of the process — silent divergence, so it is
                    // logged rather than discarded.
                    tracing::error!(
                        "enrollment policy applied but could not be published; \
                         GetSecurityStatus will report a stale policy"
                    );
                }
                let _ = reply.send(outcome);
            }
        }
    }

    // `info!` on the way out: on the certificate-authority node this task *is*
    // what the node exists to be, so its lifecycle is something an observer
    // wants. The channel closing is the ordinary shutdown path; a panic inside
    // a request does not come through here at all (see `serve_one_request`).
    tracing::info!("certificate-authority task stopping: command channel closed");
}

/// Serve one request against `ca`, returning it alongside the response.
///
/// `ca` is moved in and back out rather than borrowed because *every* request
/// runs on the blocking pool — the password paths make that necessary and
/// nothing distinguishes them cheaply enough to be worth two code paths: `spawn_blocking` needs `FnOnce + Send +
/// 'static`, and `AuthorityDataProvider::authenticate_user` takes `&mut self`,
/// so nothing short of ownership crosses that boundary. Argon2id at 64 MiB for
/// ~100 ms would otherwise park a whole tokio worker — off the router loop, but
/// still in front of every other task on that thread.
async fn serve_one_request(
    mut ca: CertAuthority,
    request: WayfinderRequest,
    facts: RouterFactsRx,
) -> (CertAuthority, WayfinderResponse, Vec<RevocationRecord>) {
    let handle = move || {
        let mut adapter = AuthorityAdapter::new(&mut ca, facts);
        let response = handle_authority(&mut adapter, request).unwrap_or_else(|returned| {
            // Unreachable via the connection task, which routes by
            // `request_facet` and so never sends a non-authority kind here.
            // Answered rather than panicked — a request kind added later without
            // an owner must not take the authority down — but logged loudly,
            // because this is the one-owner-per-kind invariant failing and
            // nothing else would show it.
            tracing::error!(
                kind = returned
                    .request
                    .as_ref()
                    .map(wayfinder_protos::service::request_kind_name)
                    .unwrap_or("none"),
                "management request reached the authority task but is not an authority request"
            );
            not_a_provider_response()
        });
        let signed = adapter.finish();
        (ca, response, signed)
    };

    match tokio::task::spawn_blocking(handle).await {
        Ok(result) => result,
        // Either way the authority this task owned went with the blocking
        // job, so there is nothing to return and nothing to serve from — fatal
        // to the task rather than to one request. But the two causes must not
        // read the same: "authority state lost" is a data-loss claim, and
        // printing it during an orderly `systemctl stop` sends an operator
        // looking for a fault that never happened.
        Err(e) if e.is_panic() => {
            panic!("certificate-authority request panicked, authority state lost: {e}");
        }
        Err(_) => {
            tracing::info!("certificate-authority request abandoned: the runtime is shutting down");
            panic!("certificate-authority task stopped with the runtime");
        }
    }
}

/// Hand every signed revocation to the router loop and fold their verdicts into
/// the response.
///
/// Signing and flooding are adjacent by construction — no other command is
/// served in between — because a crash after signing and before flooding leaves,
/// in general, nothing to re-derive the records from: the authority persists
/// only a `revoked` flag on the matching issued entries, never the signed
/// records, and nothing reloads or re-floods revocations at startup.
///
/// Every record is offered even after one fails, and the *first* failure is what
/// the caller is told. Stopping at the first would leave the remaining sessions
/// revoked in the authority's log and unannounced with nothing left to retry
/// from, which is the state this whole path exists to avoid; and reporting the
/// last failure would let a later, more ordinary one hide the first.
///
/// The router's verdict is awaited per record, so a large batch paces itself
/// against the bounded channel rather than buffering — design 14 §3.3.
async fn flood_revocations(
    revocations: &RevocationTx,
    records: Vec<RevocationRecord>,
    response: WayfinderResponse,
) -> WayfinderResponse {
    let mut failure = None;
    for record in records {
        if let Err(reason) = flood_one(revocations, record).await {
            failure.get_or_insert(reason);
        }
    }
    match failure {
        Some(reason) => signed_but_not_flooded(&reason),
        None => response,
    }
}

/// Offer one signed revocation to the router loop, reporting why it did not
/// reach the mesh.
async fn flood_one(revocations: &RevocationTx, record: RevocationRecord) -> Result<(), String> {
    let (tx, rx) = oneshot::channel();
    if revocations.send((record, tx)).await.is_err() {
        return Err("the router is no longer accepting revocations".to_string());
    }
    match rx.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(message)) => Err(message),
        Err(_) => Err("the router did not report whether it was flooded".to_string()),
    }
}

/// Report a revocation that was signed and durably recorded but never reached
/// the mesh.
///
/// Logged as well as answered, and that is the load-bearing half: the client may
/// have hung up in the window between the revoke and the flood — which is
/// exactly when something is going wrong on this node — and if the only record
/// of the divergence went down that connection, nothing anywhere would show that
/// the authority's log and the mesh now disagree.
fn signed_but_not_flooded(reason: &str) -> WayfinderResponse {
    tracing::error!(
        reason,
        "revocation signed and durably recorded but not flooded to the mesh"
    );
    error_response(&alloc::format!(
        "the revocation was signed and recorded, but was not flooded to the mesh: {reason}"
    ))
}

/// A management error response carrying `message`.
fn error_response(message: &str) -> WayfinderResponse {
    WayfinderResponse {
        response: Some(RespKind::Error(ErrorResponse {
            message: message.to_string(),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::UserRecord;
    use wayfinder_protos::service::CsrOutcome;
    use wayfinder_protos::wayfinder::v1alpha::SubmitCsrRequest;
    use wayfinder_protos::wayfinder::v1alpha::wayfinder_request::Request as ReqKind;

    fn mac(n: u8) -> [u8; 6] {
        [0, 0, 0, 0, 0, n]
    }

    /// An authority with **no clock**, for a test whose subject is the
    /// fail-closed state.
    ///
    /// `CertAuthority::new` starts at `Clock::Fixed(0)`; only `from_config` —
    /// the production path — takes `Clock::System`. Most tests here want
    /// [`clocked_authority`] instead.
    fn authority() -> CertAuthority {
        CertAuthority::new(&[9u8; 32], 0xABCD, 10_000, None, true)
    }

    /// An authority pinned to [`NOW_UNIX`], which is what a test driving
    /// `serve_authority` needs.
    ///
    /// The task does not push a clock in — a provider reads the host clock
    /// itself — so a test that wants issuing to work sets one here rather than
    /// publishing it on `facts`. Pinned rather than `Clock::System` because
    /// every window these tests assert on is measured from `NOW_UNIX`.
    fn clocked_authority() -> CertAuthority {
        let mut ca = authority();
        ca.set_now_unix(NOW_UNIX);
        ca
    }

    /// The instant every test in this module runs at.
    const NOW_UNIX: u64 = 1_700_000_000;

    /// A standing publication of the router's facts, for a test driving
    /// `AuthorityAdapter` directly rather than through the task.
    fn facts(auth_present: bool) -> RouterFactsRx {
        watch::channel(RouterFacts {
            unix_secs: NOW_UNIX,
            auth_present,
        })
        .1
    }

    /// An authority task wired exactly as `Driver::attach_authority` wires one,
    /// with the router's halves kept so a test can play the router.
    ///
    /// Shared rather than repeated per test because the wiring *is* the subject
    /// here: a test that hand-built its channels could publish a clock the
    /// production path would not, and pass while the real wiring was broken.
    struct TestAuthority {
        /// The router's side, as `Driver` holds it.
        comms: AuthorityComms,
        /// Where a connection task posts commands.
        commands: AuthorityTx,
        /// A policy receiver taken before the task started, so `changed()` sees
        /// the publication `serve_authority` makes on startup.
        policy: EnrollmentPolicyRx,
    }

    impl TestAuthority {
        /// Start a task over `ca`, with mesh authentication reported as on.
        fn start(ca: CertAuthority) -> Self {
            let mut comms = AuthorityComms::new(NOW_UNIX);
            comms.publish(RouterFacts {
                unix_secs: NOW_UNIX,
                auth_present: true,
            });
            let (commands, commands_rx) = mpsc::channel(4);
            let ports = comms.attach(commands_rx);
            let policy = comms
                .split()
                .1
                .as_ref()
                .expect("attach wires the policy half")
                .clone();
            tokio::spawn(serve_authority(ca, ports));
            Self {
                comms,
                commands,
                policy,
            }
        }

        /// Play the router loop: take the next signed revocation awaiting a flood.
        async fn next_revocation(
            &mut self,
        ) -> (RevocationRecord, oneshot::Sender<Result<(), String>>) {
            self.comms
                .split()
                .0
                .as_mut()
                .expect("attach wires the revocation half")
                .recv()
                .await
                .expect("a signed revocation reaches the router")
        }

        /// Send one command and await its response.
        async fn request(&self, request: WayfinderRequest) -> WayfinderResponse {
            let (reply_tx, reply_rx) = oneshot::channel();
            self.commands
                .send(AuthorityCommand::Request(request, reply_tx))
                .await
                .expect("the authority task is running");
            reply_rx.await.expect("the authority answers")
        }
    }

    fn submit_csr(mac: [u8; 6]) -> WayfinderRequest {
        WayfinderRequest {
            request: Some(ReqKind::SubmitCsr(SubmitCsrRequest {
                node_mac: mac.to_vec(),
                ed_pubkey: [1u8; 32].to_vec(),
                x_pubkey: [2u8; 32].to_vec(),
                enrollment_token: String::new(),
            })),
        }
    }

    fn revoke_node(mac: [u8; 6]) -> WayfinderRequest {
        WayfinderRequest {
            request: Some(ReqKind::RevokeNode(
                wayfinder_protos::wayfinder::v1alpha::RevokeNodeRequest {
                    node_mac: mac.to_vec(),
                },
            )),
        }
    }

    /// The regression this whole design most needs pinned: an authority that
    /// has no usable clock refuses to issue anything.
    ///
    /// `now_unix == 0` is fail-closed in `submit_csr`, `authenticate_user` and
    /// `revoke`, so a task wired up without the clock would answer every
    /// request with an error — and it would do it silently, with every
    /// router-side test still green. Asserting the failure *and* the fix in one
    /// test is what makes a future refactor that drops the clock go red here
    /// rather than in production.
    #[tokio::test]
    async fn an_authority_with_no_usable_clock_refuses_to_issue() {
        let mut ca = authority();

        // Clock never set: this is the shape of the bug.
        let mut adapter = AuthorityAdapter::new(&mut ca, facts(true));
        assert!(
            adapter
                .submit_csr(&mac(2), &[1u8; 32], &[2u8; 32], "")
                .is_err(),
            "an authority with no clock must refuse to issue, not issue badly"
        );

        // A clock — any clock — is what makes it work. Which one is the
        // authority's own business now: a provider is built by `from_config`
        // and reads the host's, and a test says so explicitly.
        ca.set_now_unix(NOW_UNIX);
        let mut adapter = AuthorityAdapter::new(&mut ca, facts(true));
        let outcome = adapter
            .submit_csr(&mac(2), &[1u8; 32], &[2u8; 32], "")
            .expect("a clocked authority issues");
        assert!(matches!(outcome, CsrOutcome::Issued(_)));
    }

    /// The authority stamps a certificate from **its own** clock, and the
    /// router's published time has no say in it.
    ///
    /// This test used to assert the opposite — that `serve_authority` applied
    /// the value on `facts` — and that coupling was the bug. The router
    /// publishes only when its loop wakes, once an hour on a provider with no
    /// mesh interfaces, and an authority request never wakes it; so the
    /// authority's "now" froze between wakeups and every expiry froze with it.
    ///
    /// The facts channel here publishes a *deliberately absurd* time, and the
    /// certificate must be stamped from the authority's clock regardless. What
    /// that pins is the absence of the old path: if anything ever starts pushing
    /// `facts.unix_secs` into the authority again, this goes red.
    ///
    /// It still asserts the window's exact *value* rather than merely that a
    /// certificate came back, which is what catches the drift the module header
    /// warns about — milliseconds where seconds were meant, an epoch without the
    /// elapsed time. Every one of those still issues, and still issues a
    /// certificate the mesh will reject.
    #[tokio::test]
    async fn the_authority_stamps_from_its_own_clock_not_the_routers() {
        use wayfinder_auth::MembershipCert;
        use wayfinder_protos::wayfinder::v1alpha::submit_csr_response::Outcome as CsrOutcomeKind;

        let authority = TestAuthority::start(clocked_authority());
        // A time the router has no business imposing, and which no assertion
        // below will tolerate.
        authority.comms.set_clock(NOW_UNIX + 999_999);

        let response = authority.request(submit_csr(mac(3))).await;

        let Some(RespKind::SubmitCsr(csr)) = &response.response else {
            panic!(
                "expected an issued certificate, got {:?}",
                response.response
            );
        };
        let Some(CsrOutcomeKind::Issued(issued)) = &csr.outcome else {
            panic!("expected an issued certificate, got {:?}", csr.outcome);
        };
        let cert =
            MembershipCert::from_bytes(&issued.cert).expect("the authority issues a real cert");

        assert_eq!(
            cert.not_before.get(),
            NOW_UNIX,
            "the certificate is stamped from the authority's own clock, not from \
             whatever the router last published"
        );
        assert_eq!(
            cert.not_after.get(),
            NOW_UNIX + 10_000,
            "and expire one configured TTL after it"
        );
    }

    /// The authority publishes the policy it actually loaded before it serves
    /// anything, so a `GetSecurityStatus` that races start-up reports the
    /// policy in force rather than nothing.
    #[tokio::test]
    async fn the_policy_is_published_before_the_first_command_is_served() {
        let mut authority = TestAuthority::start(clocked_authority());

        authority.policy.changed().await.unwrap();
        assert!(
            authority.policy.borrow().is_some(),
            "the authority publishes its policy on start-up"
        );
    }

    /// A revocation the router cannot flood is refused *before* it is signed.
    ///
    /// `CertAuthority::revoke` persists, so refusing afterwards would not undo
    /// it — the operator would be told the node was revoked while nothing was
    /// ever announced. This is the precondition `adapter.rs` used to check up
    /// front, kept adjacent to the signing now that the two live apart.
    #[test]
    fn revoke_is_refused_without_signing_when_the_router_cannot_flood() {
        let mut ca = authority();
        ca.set_now_unix(NOW_UNIX);

        let mut adapter = AuthorityAdapter::new(&mut ca, facts(false));
        let err = adapter.revoke_node(&mac(9)).unwrap_err();

        assert!(err.contains("authentication disabled"), "got: {err}");
        assert!(
            adapter.finish().is_empty(),
            "nothing may be signed when it could never be flooded"
        );
    }

    /// Removing an account through the adapter reaches the *trait* method — the
    /// one with the last-administrator guard and the session revocation — and
    /// not `CertAuthority`'s inherent `remove_user` beside it.
    ///
    /// A regression test for a bug that was invisible for exactly the reason it
    /// was dangerous. `CertAuthority` has both an inherent `remove_user` (the
    /// offline tool's raw store operation, no guard and no revocation) and a
    /// `MeshAuthority::remove_user` (which has both), and Rust resolves
    /// `self.ca.remove_user(..)` to the inherent one. So the guard was written,
    /// unit-tested against the trait directly, and never on the path a
    /// dashboard's Remove button actually took.
    ///
    /// It asserts the guard rather than the revocation because the guard is the
    /// half that was silently missing before design 14 existed; the two now
    /// arrive together, so either one proves the right method was called.
    #[test]
    fn removing_an_account_through_the_adapter_applies_the_last_admin_guard() {
        let mut ca = authority();
        ca.set_now_unix(NOW_UNIX);
        ca.add_user(UserRecord::new("ops", "hunter2", UserRole::Admin, 900).unwrap())
            .unwrap();

        let mut adapter = AuthorityAdapter::new(&mut ca, facts(true));
        let err = AuthorityDataProvider::remove_user(&mut adapter, "ops")
            .expect_err("the last administrator must not be removable over the API");

        assert!(err.contains("administrator"), "got: {err}");
        assert!(adapter.finish().is_empty(), "and nothing was signed");
        assert_eq!(ca.list_users().len(), 1, "the account is still there");
    }

    /// A successful revocation leaves the router a record to flood — the other
    /// half of the act, which the task hands over immediately.
    #[test]
    fn a_successful_revoke_hands_over_a_record_for_the_router() {
        let mut ca = authority();
        ca.set_now_unix(NOW_UNIX);

        let mut adapter = AuthorityAdapter::new(&mut ca, facts(true));
        adapter.revoke_node(&mac(9)).expect("revoke succeeds");

        assert_eq!(
            adapter.finish().len(),
            1,
            "the signed record must reach the router, or the revocation is recorded but silent"
        );
    }

    /// A policy is readable on the watch the moment its reply lands, so a
    /// client that saves one and immediately reads it back cannot see the old
    /// value.
    ///
    /// **This does not pin the source order**, and an earlier version of this
    /// comment claimed it did. `oneshot::send` does not yield, so
    /// `serve_authority` completes both the publish and the reply within one
    /// poll and a single-threaded test can never observe them apart —
    /// swapping the two lines leaves this green. The read-your-write guarantee
    /// a client depends on comes from that same fact (neither send can be
    /// interleaved with the caller), not from the order they are written in,
    /// which is what this asserts.
    #[tokio::test]
    async fn a_policy_change_is_readable_as_soon_as_its_reply_lands() {
        let authority = TestAuthority::start(clocked_authority());

        let (reply_tx, reply_rx) = oneshot::channel();
        authority
            .commands
            .send(AuthorityCommand::SetEnrollmentPolicy(
                EnrollmentPolicyData {
                    auto_approve: Some(false),
                    cert_ttl_secs: Some(4242),
                    ..Default::default()
                },
                reply_tx,
            ))
            .await
            .unwrap();
        reply_rx.await.unwrap().expect("the policy is accepted");

        // Read at the instant the reply lands, with no further await: if the
        // publish happened after the reply this is still the old value.
        let published = authority
            .policy
            .borrow()
            .clone()
            .expect("a policy is published");
        assert_eq!(published.cert_ttl_secs, 4242);
        assert!(!published.auto_approve);
    }

    /// A revocation crosses the channel to the router, and the router's verdict
    /// comes back to the client.
    ///
    /// This is the seam the old single-owner `revoke_node` test could not have:
    /// the authority signs and persists on one task, the router floods on
    /// another. Everything between — the record surviving the channel, the
    /// acknowledgement returning — is only exercised here.
    #[tokio::test]
    async fn a_signed_revocation_crosses_to_the_router_and_its_verdict_returns() {
        let mut authority = TestAuthority::start(clocked_authority());

        // Sent, not awaited: the authority blocks on the router's verdict
        // below, so awaiting the reply here would deadlock the test.
        let (reply_tx, reply_rx) = oneshot::channel();
        authority
            .commands
            .send(AuthorityCommand::Request(revoke_node(mac(9)), reply_tx))
            .await
            .unwrap();

        // Stand in for the router loop: take the record and report success.
        let (record, ack) = authority.next_revocation().await;
        assert_eq!(
            record.node_mac,
            mac(9),
            "the router is handed the record for the node the request named"
        );
        ack.send(Ok(())).unwrap();

        let response = reply_rx.await.unwrap();
        assert!(
            !matches!(&response.response, Some(RespKind::Error(_))),
            "a flooded revocation reports success, got {:?}",
            response.response
        );
    }

    /// When the router cannot flood it, the client is told the revocation was
    /// recorded but not announced — never that it succeeded.
    ///
    /// The authority has already persisted by this point, so silence here is
    /// how an operator ends up believing a node is off the mesh when it is not.
    #[tokio::test]
    async fn a_revocation_the_router_refuses_is_reported_as_not_flooded() {
        let mut authority = TestAuthority::start(clocked_authority());

        let (reply_tx, reply_rx) = oneshot::channel();
        authority
            .commands
            .send(AuthorityCommand::Request(revoke_node(mac(9)), reply_tx))
            .await
            .unwrap();

        let (_record, ack) = authority.next_revocation().await;
        ack.send(Err("mesh authentication is disabled".into()))
            .unwrap();

        match reply_rx.await.unwrap().response {
            Some(RespKind::Error(e)) => assert!(
                e.message.contains("not flooded"),
                "the operator must be told it was not announced, got: {}",
                e.message
            ),
            other => panic!("expected an error reporting the failed flood, got {other:?}"),
        }
    }

    /// A provider on the production clock stamps from real wall time, with the
    /// router's published time playing no part.
    ///
    /// This replaces a regression test for the coupling bug — an invitation that
    /// outlived its expiry and still redeemed, because `serve_authority` pushed
    /// `facts.unix_secs` into the authority and the router publishes that only
    /// when its loop wakes, once an hour on a provider with no mesh interfaces.
    /// That test drove a virtual clock through the workaround. The coupling is
    /// gone rather than mitigated now, so what is worth asserting is the
    /// arrangement that replaced it, end to end through the task.
    ///
    /// The expiry property itself did not move: it is covered deterministically
    /// by `an_expired_invite_and_an_expired_handle_are_each_refused` in
    /// `authority.rs`, on a fixed clock, where it belongs.
    ///
    /// `Clock::System` is otherwise exercised only in production — `from_config`
    /// is the sole path that selects it — so without this nothing would notice
    /// it being mis-wired.
    #[tokio::test]
    async fn a_provider_on_the_system_clock_stamps_from_real_time() {
        use wayfinder_auth::MembershipCert;
        use wayfinder_protos::wayfinder::v1alpha::submit_csr_response::Outcome as CsrOutcomeKind;

        let mut ca = authority();
        // What `CertAuthority::from_config` gives every real provider.
        ca.set_clock(crate::Clock::System);
        let authority = TestAuthority::start(ca);
        // A time from the router that no assertion below will tolerate.
        authority.comms.set_clock(NOW_UNIX);

        let response = authority.request(submit_csr(mac(4))).await;

        let Some(RespKind::SubmitCsr(csr)) = &response.response else {
            panic!(
                "expected an issued certificate, got {:?}",
                response.response
            );
        };
        let Some(CsrOutcomeKind::Issued(issued)) = &csr.outcome else {
            panic!("expected an issued certificate, got {:?}", csr.outcome);
        };
        let cert = MembershipCert::from_bytes(&issued.cert).expect("a real certificate");

        let host_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the test host's clock is after the epoch")
            .as_secs();
        let stamped = cert.not_before.get();
        assert_ne!(
            stamped, NOW_UNIX,
            "the router's published time must not reach the authority at all"
        );
        assert!(
            stamped.abs_diff(host_now) <= 5,
            "a provider stamps from the host clock: got {stamped}, host says {host_now}"
        );
    }

    /// The fail-closed zero does not age into a valid time.
    ///
    /// `Clock::Fixed(0)` is the "no clock yet" sentinel every issuing path
    /// refuses, and the thing to pin is that elapsed time alone never resolves
    /// it. An hour of the task running must not turn an authority that was
    /// never given a clock into one happily issuing certificates dated a few
    /// seconds past the epoch — which the mesh would reject while the operator
    /// saw success.
    ///
    /// Distinct from `an_authority_with_no_usable_clock_refuses_to_issue`, which
    /// asks the same question of `CertAuthority` directly at a single instant.
    /// This one asks it of the running task, across time.
    #[tokio::test(start_paused = true)]
    async fn a_clock_that_was_never_set_stays_the_fail_closed_zero() {
        let mut comms = AuthorityComms::new(0);
        let (commands, commands_rx) = mpsc::channel(4);
        let ports = comms.attach(commands_rx);
        // `authority()` is the no-clock constructor: `Clock::Fixed(0)`.
        tokio::spawn(serve_authority(authority(), ports));

        // An hour passes and nothing gives this authority a clock.
        tokio::time::advance(core::time::Duration::from_secs(3600)).await;

        let (reply_tx, reply_rx) = oneshot::channel();
        commands
            .send(AuthorityCommand::Request(submit_csr(mac(4)), reply_tx))
            .await
            .expect("the authority task is running");

        match reply_rx.await.expect("the authority answers").response {
            Some(RespKind::Error(_)) => {}
            other => panic!("an authority with no clock must refuse to issue, got {other:?}"),
        }
    }
}
