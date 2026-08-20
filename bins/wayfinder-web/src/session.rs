//! Who is looking at the dashboard, and what credential that gets them.
//!
//! # The two modes, and why there are two
//!
//! A dashboard reaches a node with *some* management credential. Until this
//! module there was exactly one, held by the process: whatever `--identity` and
//! `--cert` named, handed to every request that arrived on the port. That is
//! what made a non-loopback bind so dangerous — anyone who could reach the port
//! inherited the whole of that credential's access, with nothing to log in to
//! and nothing to expire.
//!
//! So [`Access::Login`] adds the other mode: a person logs in, the *provider*
//! issues a short-lived session certificate bound to a keypair this process
//! generates for them, and that session — not the process — is what reaches the
//! node. No session, no node access.
//!
//! [`Access::Static`] does not go away, and §8.3 of
//! `docs/design/06-management-api-authentication.md` is why. Dropping it is
//! cleaner on paper and costs two deployments their dashboard entirely, both of
//! them ones where a dashboard is the *only* way in:
//!
//! * **An un-enrolled node.** It has no user store, so there is nobody to log
//!   in to; proving the node's own key is the only credential that exists, and
//!   `MgmtAccess::GrantedSelfKey` exists precisely for it.
//! * **A serial-attached embedded node**, which has no authentication at all
//!   and no provider behind it.
//!
//! Static mode is therefore kept, stated explicitly by the operator, and
//! announced at startup as what it is: a shared credential that closes none of
//! this.
//!
//! # What a session is
//!
//! A random id in an `HttpOnly; SameSite=Strict` cookie, naming an entry in a
//! [`SessionStore`] that holds the seed and certificate the login produced.
//! The browser never holds a key — the same rule that governs the rest of this
//! crate — and the id is never rendered into a page, so a cross-site request
//! cannot carry one and script on the page cannot read one.
//!
//! # The second way to obtain one
//!
//! [`SessionStore::login`] needs the provider, because only the provider holds
//! the password verifier. [`SessionStore::login_with_bundle`] does not: it takes
//! a credential the provider already signed — downloaded earlier as a
//! [`crate::bundle::AuthBundle`] — and builds a session directly out of it.
//!
//! That is the whole of the offline story, and it is not a weakening. The
//! bundle is a certificate this dashboard cannot forge and does not verify; the
//! *node* verifies it against the trust anchor it already holds, exactly as it
//! verifies one that came from a password sign-in a moment earlier. So the only
//! party a bundle sign-in consults is the node the dashboard is pointed at
//! anyway, and a fabricated file buys a session that cannot read a single
//! table.
//!
//! What it does change is that a session credential now exists as a *file*.
//! [`SessionStore::export`] is what produces one, and it hands out only the
//! credential belonging to the session asking for it.

use serde::Deserialize;
use serde::Serialize;

/// The cookie a session id travels in.
pub const SESSION_COOKIE: &str = "wf_session";

/// What a server function answers with when login mode has no session behind
/// the request.
///
/// A sentinel the browser recognises, because "log in" and "the node is
/// unreachable" are different states with different remedies and the dashboard
/// must not render one as the other.
pub const NEEDS_LOGIN: &str = "not logged in to this dashboard";

/// Who the dashboard is serving, as the browser needs to know it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Viewer {
    /// Static-credential mode: there is no login, and every viewer shares the
    /// credential the process was started with.
    Static,
    /// Login mode, with no session on this browser. Nothing but the login page
    /// is reachable.
    LoggedOut,
    /// Login mode, with a live session.
    LoggedIn(SessionInfo),
}

/// What a live session is, for the parts of the UI that name it.
///
/// Never the session id, and never the key or certificate behind it: this is
/// what gets rendered onto a page, and a page is read over shoulders and
/// screenshotted into chats.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    /// The account that logged in.
    pub username: String,
    /// The signed capability the session certificate carries, in words.
    pub capability: String,
    /// Whether that capability is the administrator one.
    ///
    /// The same bit [`SessionInfo::capability`] is spelled from, kept as a
    /// `bool` because the browser branches on it: every control that changes
    /// the node is drawn only for a session that carries it. Rendering it as a
    /// string and comparing the words would put the dashboard's whole
    /// read-only posture on a spelling.
    pub admin: bool,
    /// Unix seconds at which the session certificate stops being valid, after
    /// which the session is pruned and the viewer is logged out.
    pub expires_unix: u64,
}

impl Viewer {
    /// Whether this viewer may *change* the node, rather than only read it.
    ///
    /// What the dashboard hangs every mutating control on. It is not the access
    /// control — the node's own `permits` allowlist is, and it refuses a
    /// read-only session's call whatever this says. It is what keeps the
    /// dashboard honest about that refusal: a button that is drawn, pressed and
    /// then fails is a promise the page had no business making.
    ///
    /// [`Viewer::Static`] is `true`, and that follows from what static mode is:
    /// one credential for the whole process, stated by the operator who started
    /// it, and the mode an un-enrolled node or a serial-attached board is
    /// reached in — where there is no user store, no roles, and full access to
    /// whoever can reach the port. A static credential that happens to be
    /// read-only is the one case this over-promises, and the node still refuses.
    #[must_use]
    pub fn can_administer(&self) -> bool {
        match self {
            Viewer::Static => true,
            Viewer::LoggedOut => false,
            Viewer::LoggedIn(info) => info.admin,
        }
    }
}

/// The reactive handle to [`Viewer`] the whole page hangs on.
///
/// One resource, provided in context, so the header, the login form and the
/// polling loop all read — and can all re-ask — the same question. A second
/// copy would let two parts of the page disagree about whether anyone is
/// logged in.
pub type ViewerResource = leptos::prelude::Resource<Result<Viewer, leptos::prelude::ServerFnError>>;

/// What became of a login attempt.
///
/// A refusal is a value rather than an error for the same reason
/// [`crate::enroll::EnrollmentOutcome`]'s is: a wrong password is an ordinary
/// answer to be rendered, not a failure of the request. It carries no detail,
/// because the provider deliberately gives none — unknown account, wrong
/// password, wrong code, locked and disabled are one answer there and stay one
/// answer here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoginResult {
    /// The credentials verified and a session was created.
    LoggedIn(SessionInfo),
    /// The provider refused, for a reason nobody is told.
    Denied,
}

#[cfg(feature = "ssr")]
pub use ssr::Access;
#[cfg(feature = "ssr")]
pub use ssr::LoginOutcome;
#[cfg(feature = "ssr")]
pub use ssr::PinnedNode;
#[cfg(feature = "ssr")]
pub use ssr::SessionStore;
#[cfg(feature = "ssr")]
pub use ssr::cleared_cookie;
#[cfg(feature = "ssr")]
pub use ssr::id_from_cookie_header;
#[cfg(feature = "ssr")]
pub use ssr::request_is_secure;
#[cfg(feature = "ssr")]
pub use ssr::session_cookie;

#[cfg(feature = "ssr")]
mod ssr {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::Mutex;

    use anyhow::Context;
    use axum::http::HeaderMap;
    use tracing::info;
    use tracing::warn;
    use wayfinder_auth::Keypair;
    use wayfinder_auth::MembershipCert;
    use wayfinder_client::Client;
    use wayfinder_client::Endpoint;
    use wayfinder_client::Identity;
    use wayfinder_protos::wayfinder::v1alpha::authenticate_user_response::Outcome;

    use super::SESSION_COOKIE;
    use super::SessionInfo;
    use super::Viewer;
    use crate::bundle::AuthBundle;
    use crate::bundle::capability;
    use crate::bundle::is_admin;
    use crate::conn::NodeConnection;
    use crate::conn::Target;

    /// One management endpoint this dashboard reaches, and the key that pins
    /// it.
    ///
    /// The key is not optional and has no default. Static mode can derive one
    /// from the identity it holds; a login has no identity to derive it from,
    /// so the operator states it — and without it there is nothing stopping
    /// another host answering in the node's place and collecting a password.
    #[derive(Clone, Copy, Debug)]
    pub struct PinnedNode {
        /// The management API's TLS address.
        pub addr: SocketAddr,
        /// The Ed25519 public key the endpoint must present.
        pub key: [u8; 32],
    }

    /// What a login produced, server-side.
    ///
    /// Separate from [`super::LoginResult`] so the session id has no path to
    /// the browser's *body*: it is deliberately unrepresentable in the type
    /// that crosses the wire, and travels only in the cookie.
    pub enum LoginOutcome {
        /// A session was created; the id belongs in a cookie and nowhere else.
        LoggedIn {
            /// The session id.
            id: String,
            /// What the browser may be told about it.
            info: SessionInfo,
        },
        /// The provider refused the credentials.
        Denied,
    }

    /// One live session: the connection its certificate authenticates, the
    /// credential behind that connection, and what may be said about it.
    struct StoredSession {
        /// The node connection built from this session's own credential.
        conn: Arc<NodeConnection>,
        /// Who logged in, and until when. The only part of this the browser
        /// ever sees.
        info: SessionInfo,
        /// The session keypair's seed, and the certificate the provider signed
        /// for it.
        ///
        /// Held rather than moved into the connection because a session must
        /// be able to hand its own credential back as a file — see
        /// [`SessionStore::export`]. It never leaves this struct by any other
        /// route: [`SessionInfo`] is what crosses the wire, and it has no
        /// field for either.
        seed: [u8; 32],
        /// The certificate matching [`StoredSession::seed`].
        cert: Vec<u8>,
    }

    /// The live sessions, and how to make another.
    ///
    /// One [`NodeConnection`] per session rather than one per process: the
    /// connection *is* the credential, since the management API authenticates
    /// at the TLS handshake, so sharing one would hand every viewer the first
    /// viewer's access.
    pub struct SessionStore {
        /// The node every session connects to.
        node: PinnedNode,
        /// The provider a login is performed against. Usually the same host as
        /// [`SessionStore::node`] only in a single-node deployment; in a mesh
        /// the certificate authority is one node and the dashboard may be
        /// pointed at any of them.
        provider: PinnedNode,
        /// Live sessions by id.
        ///
        /// A plain `std` mutex: nothing here is held across an await — a login
        /// does its I/O first and takes the lock only to insert — so an async
        /// mutex would buy nothing but a harder invariant to keep.
        sessions: Mutex<HashMap<String, StoredSession>>,
    }

    impl SessionStore {
        /// Build an empty store for a dashboard pointed at `node`, logging in
        /// against `provider`.
        pub fn new(node: PinnedNode, provider: PinnedNode) -> Self {
            Self {
                node,
                provider,
                sessions: Mutex::new(HashMap::new()),
            }
        }

        /// The node this dashboard is pointed at, for the header.
        pub fn label(&self) -> String {
            self.node.addr.to_string()
        }

        /// The provider a login goes to, for the login page and the startup log.
        pub fn provider(&self) -> SocketAddr {
            self.provider.addr
        }

        /// Exchange credentials at the provider for a session.
        ///
        /// The keypair is generated here and never leaves this process, so what
        /// the provider signs is bound to a key only this dashboard holds — a
        /// captured transcript of the exchange is useless without it. The
        /// password and code are held for the length of the call and stored
        /// nowhere, on either side.
        ///
        /// The connection to the provider is anonymous: a throwaway key and no
        /// certificate, which is exactly what somebody who has not logged in
        /// yet is. The provider admits it for the enrollment tier alone, where
        /// `AuthenticateUser` lives.
        pub async fn login(
            &self,
            username: &str,
            password: &str,
            totp_code: &str,
            now_unix: u64,
        ) -> anyhow::Result<LoginOutcome> {
            let seed = Keypair::generate_seed();
            let keypair = Keypair::from_seed(&seed);

            let anonymous = Identity {
                seed,
                cert: Vec::new(),
            };
            let mut client =
                Client::connect_tls(self.provider.addr, &self.provider.key, &anonymous)
                    .await
                    .with_context(|| {
                        format!("connecting to the provider at {}", self.provider.addr)
                    })?;
            let response = client
                .authenticate_user(
                    username,
                    password,
                    totp_code,
                    &keypair.ed_pubkey(),
                    &keypair.x_pubkey(),
                )
                .await
                .context("asking the provider to authenticate this login")?;

            let issued = match response.outcome {
                Some(Outcome::Issued(issued)) => issued,
                Some(Outcome::Rejected(_)) | None => {
                    // Logged here and not returned to the browser: the provider
                    // says only "no", and an operator reading the dashboard's
                    // log is entitled to know a login was attempted.
                    warn!(%username, provider = %self.provider.addr, "login refused by the provider");
                    return Ok(LoginOutcome::Denied);
                }
            };

            let cert = MembershipCert::from_bytes(&issued.cert)
                .context("the provider returned a certificate this build cannot parse")?;
            let info = SessionInfo {
                username: username.to_string(),
                capability: capability(cert.flags).to_string(),
                admin: is_admin(cert.flags),
                expires_unix: cert.not_after.get(),
            };

            // The session's own connection is built inside `admit`, from the
            // credential the login just produced. Nothing is opened yet: the
            // first poll connects, the same way static mode does.
            let conn = self.credentialed(seed, issued.cert.clone());
            let id = self.admit(conn, seed, issued.cert, info.clone(), now_unix);
            info!(
                %username,
                capability = %info.capability,
                expires_unix = info.expires_unix,
                "dashboard session opened"
            );
            Ok(LoginOutcome::LoggedIn { id, info })
        }

        /// Build a session out of a `.wfauth` credential file, with no contact
        /// with the provider at all.
        ///
        /// This is the offline path, and the reason it is sound is that it
        /// consults the one party that can actually decide: the **node**. The
        /// bundle is checked over locally first — well-formed, the certificate
        /// belongs to the key beside it, the validity window contains `now` —
        /// and then *used*, against the node, before any session exists. A
        /// certificate this process could not have verified anyway (it holds no
        /// trust anchor; in login mode it holds no mesh identity at all) is
        /// therefore never mistaken for a working one: either the node accepted
        /// the connection or there is no session.
        ///
        /// Asking the node up front costs one round trip and buys the whole
        /// difference between a sign-in and a lie. Without it, an expired,
        /// revoked or fabricated file would produce a dashboard that looks
        /// signed in, names a capability, and fails every poll — which reads as
        /// "the node is down".
        ///
        /// Errors are returned with their reason rather than flattened into
        /// [`LoginOutcome::Denied`], because the caller is holding *their own*
        /// file: there is no account to enumerate and no oracle to protect, and
        /// "this credential expired on the 3rd" is the difference between
        /// downloading a new one and filing a bug.
        pub async fn login_with_bundle(
            &self,
            text: &str,
            now_unix: u64,
        ) -> anyhow::Result<LoginOutcome> {
            let bundle = AuthBundle::parse(text)?;
            let credential = bundle.credential(now_unix)?;

            let conn = self.credentialed(credential.seed, credential.cert.clone());
            // The credential is proved by using it. `node_info` is on the
            // read-only tier of the node's own allowlist, so this succeeds for
            // exactly the certificates that are worth a session and fails for
            // every other kind — including one whose signature does not check
            // out, which is refused at the handshake.
            conn.run(async |client| client.node_info().await)
                .await
                .with_context(|| {
                    format!(
                        "the node at {} did not accept this credential file",
                        self.node.addr
                    )
                })?;

            let info = SessionInfo {
                username: bundle.username.clone(),
                // Recomputed from the certificate's signed flags, never read
                // out of the file: the file's own `capability` field is a note
                // for whoever opens it in an editor and is not evidence of
                // anything.
                capability: capability(credential.parsed.flags).to_string(),
                admin: is_admin(credential.parsed.flags),
                expires_unix: credential.parsed.not_after.get(),
            };
            let username = info.username.clone();
            // The very connection the probe just proved, rather than a fresh
            // one: it is already open and already accepted, so the first poll
            // costs nothing and cannot fail for a reason this call did not
            // already rule out.
            let id = self.admit(
                conn,
                credential.seed,
                credential.cert,
                info.clone(),
                now_unix,
            );
            info!(
                %username,
                capability = %info.capability,
                expires_unix = info.expires_unix,
                "dashboard session opened from a credential file"
            );
            Ok(LoginOutcome::LoggedIn { id, info })
        }

        /// The credential behind session `id`, as the file it is downloaded as.
        ///
        /// `None` for an absent, unknown or expired session — the same answer
        /// [`SessionStore::resolve`] gives, and for the same reason: a
        /// credential is handed only to the session it belongs to, and an
        /// expired session has none worth handing out.
        pub fn export(&self, id: Option<&str>, now_unix: u64) -> Option<AuthBundle> {
            let id = id?;
            #[expect(
                clippy::unwrap_used,
                reason = "the lock guards a map and nothing here can panic while it is held"
            )]
            let mut sessions = self.sessions.lock().unwrap();
            sessions.retain(|_, session| session.info.expires_unix > now_unix);
            let session = sessions.get(id)?;
            match AuthBundle::issue(&session.info.username, &session.seed, &session.cert) {
                Ok(bundle) => Some(bundle),
                Err(error) => {
                    // Unreachable in practice — the certificate parsed on the
                    // way in — but a silent `None` here would read to the
                    // operator as "you are not signed in", which is the one
                    // thing it does not mean.
                    warn!(username = %session.info.username, %error, "cannot export this session's credential");
                    None
                }
            }
        }

        /// A connection to this dashboard's node, authenticated by one
        /// session's credential.
        ///
        /// One [`NodeConnection`] per session rather than one per process: the
        /// connection *is* the credential, since the management API
        /// authenticates at the TLS handshake. Nothing is opened here — the
        /// first request connects.
        fn credentialed(&self, seed: [u8; 32], cert: Vec<u8>) -> Arc<NodeConnection> {
            Arc::new(NodeConnection::new(Target::Tls(Endpoint {
                addr: self.node.addr,
                node_key: self.node.key,
                identity: Identity { seed, cert },
            })))
        }

        /// Insert a freshly built session and return its id.
        ///
        /// The tail both sign-in paths share, so a password login and a bundle
        /// login cannot drift into storing different things — the expiry sweep
        /// in particular, which is what stops a long-running dashboard
        /// accumulating one entry, and one connection, per login for its whole
        /// life.
        fn admit(
            &self,
            conn: Arc<NodeConnection>,
            seed: [u8; 32],
            cert: Vec<u8>,
            info: SessionInfo,
            now_unix: u64,
        ) -> String {
            let id = new_session_id();
            #[expect(
                clippy::unwrap_used,
                reason = "the lock guards a map and nothing here can panic while it is held"
            )]
            let mut sessions = self.sessions.lock().unwrap();
            sessions.retain(|_, session| session.info.expires_unix > now_unix);
            sessions.insert(
                id.clone(),
                StoredSession {
                    conn,
                    info,
                    seed,
                    cert,
                },
            );
            id
        }

        /// The connection belonging to `id`, or `None` when there is no live
        /// session under it.
        ///
        /// An expired session is `None` *and* is dropped, so a certificate that
        /// has run out ends the session it belongs to rather than being handed
        /// to the node for the node to refuse.
        pub fn resolve(&self, id: Option<&str>, now_unix: u64) -> Option<Arc<NodeConnection>> {
            let id = id?;
            #[expect(
                clippy::unwrap_used,
                reason = "the lock guards a map and nothing here can panic while it is held"
            )]
            let mut sessions = self.sessions.lock().unwrap();
            sessions.retain(|_, session| session.info.expires_unix > now_unix);
            sessions.get(id).map(|session| Arc::clone(&session.conn))
        }

        /// What to tell the browser about the session behind `id`.
        pub fn viewer(&self, id: Option<&str>, now_unix: u64) -> Viewer {
            let Some(id) = id else {
                return Viewer::LoggedOut;
            };
            #[expect(
                clippy::unwrap_used,
                reason = "the lock guards a map and nothing here can panic while it is held"
            )]
            let mut sessions = self.sessions.lock().unwrap();
            sessions.retain(|_, session| session.info.expires_unix > now_unix);
            match sessions.get(id) {
                Some(session) => Viewer::LoggedIn(session.info.clone()),
                None => Viewer::LoggedOut,
            }
        }

        /// End the session behind `id`, dropping its connection with it.
        ///
        /// Expiring the cookie alone would leave a live, capability-carrying
        /// connection in the store for anyone who kept a copy of the id.
        pub fn end(&self, id: Option<&str>) {
            let Some(id) = id else {
                return;
            };
            #[expect(
                clippy::unwrap_used,
                reason = "the lock guards a map and nothing here can panic while it is held"
            )]
            let removed = self.sessions.lock().unwrap().remove(id);
            if let Some(session) = removed {
                info!(username = %session.info.username, "dashboard session closed");
            }
        }

        /// How many sessions are live. For tests and for a future status panel;
        /// nothing depends on it.
        pub fn len(&self) -> usize {
            #[expect(
                clippy::unwrap_used,
                reason = "the lock guards a map and nothing here can panic while it is held"
            )]
            let sessions = self.sessions.lock().unwrap();
            sessions.len()
        }

        /// Whether no session is live.
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }
    }

    /// How this dashboard obtains a credential for the node.
    ///
    /// One of these lives in the axum state, and every `#[server]` function
    /// reaches the node through it — so which mode the process is in is a fact
    /// stated once, at startup, rather than a condition each call rediscovers.
    pub enum Access {
        /// One credential for the whole process; see this module's header for
        /// why it survives.
        Static(Arc<NodeConnection>),
        /// A credential per logged-in viewer.
        Login(Arc<SessionStore>),
    }

    impl Access {
        /// What the dashboard is pointed at, for the header.
        pub fn label(&self) -> String {
            match self {
                Access::Static(conn) => conn.label(),
                Access::Login(store) => store.label(),
            }
        }

        /// The connection for a request carrying session `id`, or `None` when
        /// login mode has no live session behind it.
        pub fn connection(&self, id: Option<&str>, now_unix: u64) -> Option<Arc<NodeConnection>> {
            match self {
                Access::Static(conn) => Some(Arc::clone(conn)),
                Access::Login(store) => store.resolve(id, now_unix),
            }
        }

        /// Who the request's viewer is.
        pub fn viewer(&self, id: Option<&str>, now_unix: u64) -> Viewer {
            match self {
                Access::Static(_) => Viewer::Static,
                Access::Login(store) => store.viewer(id, now_unix),
            }
        }

        /// The credential file for the session behind `id`, if there is one to
        /// hand out.
        ///
        /// **`None` in static mode, always**, and that is not an omission. The
        /// static credential belongs to the *process*, not to whoever is
        /// looking at it: everyone who can reach the port shares it, so serving
        /// it as a download would turn "can load this page" into "holds the
        /// mesh's admin key, portably, forever". The operator who started the
        /// process already has that file on disk, which is the only place it
        /// should exist.
        pub fn export(&self, id: Option<&str>, now_unix: u64) -> Option<AuthBundle> {
            match self {
                Access::Static(_) => None,
                Access::Login(store) => store.export(id, now_unix),
            }
        }
    }

    /// A fresh session id: 32 bytes of randomness in hex.
    ///
    /// Cryptographic randomness, from the same source the keypairs come from,
    /// because this id *is* a credential for the duration of a session — a
    /// guessable one would hand a stranger an admin-capable connection without
    /// their ever seeing the password.
    fn new_session_id() -> String {
        Keypair::generate_seed()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The session id in a `Cookie` header, if there is one.
    ///
    /// Written out rather than taken from a cookie crate: this is one name in a
    /// `; `-separated list, and a dependency that parses attributes, dates and
    /// quoting earns nothing here.
    pub fn id_from_cookie_header(header: &str) -> Option<&str> {
        header.split(';').find_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            (name.trim() == SESSION_COOKIE).then(|| value.trim())
        })
    }

    /// The `Set-Cookie` value that installs a session.
    ///
    /// * `HttpOnly` — script on the page cannot read it, so an injected script
    ///   cannot exfiltrate a live admin session.
    /// * `SameSite=Strict` — the browser does not attach it to a request another
    ///   site initiated, which is what closes cross-site forgery at the root
    ///   rather than at the `Origin` header.
    /// * `Path=/` — the dashboard's pages and its `/api` calls are one session.
    /// * `Secure`, only over HTTPS: see [`request_is_secure`].
    pub fn session_cookie(id: &str, secure: bool) -> String {
        format!(
            "{SESSION_COOKIE}={id}; Path=/; HttpOnly; SameSite=Strict{}",
            if secure { "; Secure" } else { "" }
        )
    }

    /// The `Set-Cookie` value that removes one.
    pub fn cleared_cookie(secure: bool) -> String {
        format!(
            "{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
            if secure { "; Secure" } else { "" }
        )
    }

    /// Whether the request reached the dashboard over HTTPS, and so whether the
    /// session cookie may be marked `Secure`.
    ///
    /// `Secure` is not set unconditionally, however much it deserves to be: a
    /// browser refuses to *store* a `Secure` cookie that arrived over plain
    /// HTTP, and plain HTTP is how this dashboard is normally reached — over
    /// loopback, or from behind the reverse proxy that terminates TLS. Setting
    /// it always would not harden those deployments, it would make login
    /// silently impossible on them, which is the worst of both.
    ///
    /// So it follows the request: a proxy that terminated TLS says so in
    /// `X-Forwarded-Proto`, and a direct HTTPS connection is named by the
    /// `Origin` the browser sends. Neither is trustworthy input in general —
    /// both are attacker-settable — but the only thing either can do here is
    /// add an attribute that makes the cookie *narrower*, so there is nothing
    /// to gain by lying.
    pub fn request_is_secure(headers: &HeaderMap) -> bool {
        let forwarded = headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|proto| {
                proto
                    .split(',')
                    .next()
                    .is_some_and(|first| first.trim().eq_ignore_ascii_case("https"))
            });
        let origin = headers
            .get(axum::http::header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|origin| origin.to_ascii_lowercase().starts_with("https://"));
        forwarded || origin
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The session id is picked out of a cookie header carrying whatever
        /// else the browser has for this origin, and is absent rather than
        /// guessed when it is not there.
        #[test]
        fn the_session_id_is_read_out_of_a_shared_cookie_header() {
            assert_eq!(id_from_cookie_header("wf_session=abc123"), Some("abc123"));
            assert_eq!(
                id_from_cookie_header("theme=dark; wf_session=abc123; other=1"),
                Some("abc123"),
                "the browser sends every cookie for the origin, in any order"
            );
            assert_eq!(id_from_cookie_header("theme=dark"), None);
            assert_eq!(id_from_cookie_header(""), None);
            // A prefix match would accept a cookie an unrelated page set.
            assert_eq!(id_from_cookie_header("not_wf_session=abc"), None);
        }

        /// The attributes that make the cookie a session credential rather than
        /// a value any page can borrow.
        #[test]
        fn a_session_cookie_is_http_only_and_same_site_strict() {
            let cookie = session_cookie("abc123", false);
            assert!(cookie.starts_with("wf_session=abc123;"), "{cookie}");
            assert!(cookie.contains("HttpOnly"), "{cookie}");
            assert!(cookie.contains("SameSite=Strict"), "{cookie}");
            assert!(cookie.contains("Path=/"), "{cookie}");
            assert!(
                !cookie.contains("Secure"),
                "a plain-HTTP dashboard must not set a cookie the browser will discard: {cookie}"
            );

            assert!(session_cookie("abc123", true).contains("; Secure"));
            assert!(cleared_cookie(false).contains("Max-Age=0"));
        }

        /// `Secure` follows the request: HTTPS directly, or a proxy that says it
        /// terminated TLS.
        #[test]
        fn secure_is_set_only_when_the_request_arrived_over_tls() {
            let headers = |name: &str, value: &str| {
                let mut headers = HeaderMap::new();
                headers.insert(
                    axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    value.parse().unwrap(),
                );
                headers
            };

            assert!(!request_is_secure(&HeaderMap::new()));
            assert!(!request_is_secure(&headers(
                "origin",
                "http://localhost:8080"
            )));
            assert!(request_is_secure(&headers(
                "origin",
                "https://wayfinder.example"
            )));
            assert!(request_is_secure(&headers("x-forwarded-proto", "https")));
            assert!(!request_is_secure(&headers("x-forwarded-proto", "http")));
            // A chain of proxies appends; the first entry is the client's.
            assert!(request_is_secure(&headers(
                "x-forwarded-proto",
                "https, http"
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one question every mutating control on the page asks.
    ///
    /// A read-only session is the case this exists for, and it is the one that
    /// would be missed: a viewer is signed in, holds a valid certificate and
    /// polls successfully, so every check that only asks "is anyone there?"
    /// says yes.
    #[test]
    fn only_an_administrator_may_change_the_node() {
        let info = |admin| SessionInfo {
            username: "watcher".to_string(),
            capability: if admin { "administrator" } else { "read-only" }.to_string(),
            admin,
            expires_unix: 1_800_000_000,
        };

        assert!(!Viewer::LoggedIn(info(false)).can_administer());
        assert!(Viewer::LoggedIn(info(true)).can_administer());
        assert!(!Viewer::LoggedOut.can_administer());
        // Static mode is the operator's own process credential; see the method.
        assert!(Viewer::Static.can_administer());
    }
}
