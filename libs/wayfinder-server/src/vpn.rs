//! VPN coordination: minting and revoking tunnel credentials against a
//! Headscale coordination server.
//!
//! # Why this is not in `RouterAdapter`
//!
//! Every other management request is answered by [`RouterAdapter`] inside the
//! driver's `select!` loop, synchronously. These three cannot be, for two
//! independent reasons:
//!
//! * **The router loop does not know who is asking.** `QueryTx` carries a
//!   `WayfinderRequest` and a reply channel — not the connection's peer key or
//!   certificate. `GetVpnEnrollmentRequest` has no fields precisely *because*
//!   the identity it mints for is the connection's, so an adapter handler would
//!   have nothing to mint against.
//! * **It is network I/O.** The adapter runs on the same task that emits OGMs
//!   and forwards frames; awaiting an HTTP round-trip there would stall
//!   routing for as long as the coordination server takes to answer, which for
//!   an unreachable one is the full timeout.
//!
//! So the transport handles them: it is already async, and it is the layer that
//! knows which identity the credential is scoped to — the verified certificate
//! on the connection for an enrolled device, or (for a node connecting to
//! itself with its own key) the node's own address, which reaches it through
//! `AuthSnapshot::own_mac` rather than through the request.
//!
//! # What a tunnel credential is and is not
//!
//! A preauth key grants *reachability* — the holder can open a socket to
//! another node's UDP mesh port. It grants no mesh membership: OGMs and frames
//! are still verified against the trust anchor, so a party holding only a
//! stolen key is a party that can send bytes nobody accepts. This is why the
//! mesh's own signing must never become conditional on a link being
//! VPN-backed.

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use core::future::Future;

use wayfinder::interfaces::frame::Mac;

/// What a node needs to join the VPN: where to register, and the one-time
/// credential to register with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnEnrollment {
    /// Base URL of the coordination server, passed to the tunnel daemon as
    /// `--login-server`.
    pub login_server: String,
    /// A single-use, short-TTL preauthentication key. Never persisted by this
    /// node: it exists between the coordination server minting it and the
    /// enrolling node spending it.
    pub preauth_key: String,
}

/// One peer as the coordination server reports it, joined back to the mesh
/// identity that enrolled it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnPeer {
    /// The mesh MAC, recovered from the name of the Headscale user this peer's
    /// *preauth key* was minted for ([`hostname_for`]) — the one name an ACL
    /// tag does not displace and an operator cannot rename. Falls back to the
    /// node's owning user, then to [`hostname`](Self::hostname), for a peer
    /// that joined some other way. `None` when none of the three is a name this
    /// node's convention produced. Such a peer is still listed and still
    /// revocable; it simply cannot be joined to an issued certificate.
    pub mac: Option<Mac>,
    /// The hostname as registered, verbatim.
    pub hostname: String,
    /// The tunnel address the coordination server assigned.
    pub address: String,
    /// Whether the coordination server currently considers this peer connected.
    pub online: bool,
    /// When the peer was last seen (unix seconds), or 0 if never.
    pub last_seen_unix: i64,
    /// When the peer's node key expires (unix seconds), or 0 if it does not.
    pub key_expiry_unix: i64,
}

/// The name this system gives a MAC on the coordination server: its MAC as
/// lowercase hex, unseparated.
///
/// This *is* the mapping table. The design deliberately persists no
/// MAC↔peer-id state on the CA side, so the correlation has to live somewhere
/// both sides can recompute — and this name is what the CA itself writes, as
/// the Headscale user every one of that node's preauth keys is scoped to
/// (`user_id_for`), which is why it survives everything an operator can edit.
///
/// It is *not* the hostname the node registers under: nothing in enrollment
/// sets one, so a peer's `given_name` is whatever its host happened to be
/// called. [`mac_from_hostname`] is still applied to it as a last resort, for a
/// peer registered by hand under this convention.
pub fn hostname_for(mac: Mac) -> String {
    let mut s = String::with_capacity(12);
    for byte in mac.0 {
        // `core::fmt` without `format!`'s allocation per byte.
        const HEX: &[u8; 16] = b"0123456789abcdef";
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0f) as usize] as char);
    }
    s
}

/// Recover the MAC from a hostname [`hostname_for`] produced, or `None` if it
/// is not one.
///
/// Deliberately strict — exactly 12 lowercase hex digits. A looser parse (say,
/// accepting separators, or a prefix match) would let an operator-chosen
/// hostname alias a real node's MAC, which is the one thing this correlation
/// must not permit: revoking one peer would then revoke another's tunnel.
pub fn mac_from_hostname(hostname: &str) -> Option<Mac> {
    if hostname.len() != 12 {
        return None;
    }
    let mut mac = [0u8; 6];
    let bytes = hostname.as_bytes();
    for (i, slot) in mac.iter_mut().enumerate() {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(Mac(mac))
}

/// One lowercase-hex digit as a nibble, or `None`. Uppercase is refused so the
/// encoding is canonical: two spellings of one MAC would be two peers.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Why a VPN coordination call failed.
///
/// Split from a bare string so the transport can tell an operational failure
/// (the coordination server is down) apart from a configuration one (no VPN is
/// configured at all) — the first is worth an alarm and a retry, the second is
/// the normal state of every deployment that does not use VPN links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpnError {
    /// This provider has no VPN integration configured. Not an error condition:
    /// VPN links are additive, and a CA without them answers this way forever.
    NotConfigured,
    /// The coordination server could not be reached, or answered with an error.
    Unreachable(String),
    /// The coordination server answered, but not with what this client expects
    /// (a schema change, or something else entirely behind that URL).
    Malformed(String),
}

impl core::fmt::Display for VpnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VpnError::NotConfigured => {
                write!(f, "this provider has no VPN coordination configured")
            }
            VpnError::Unreachable(e) => write!(f, "VPN coordination server unreachable: {e}"),
            VpnError::Malformed(e) => {
                write!(
                    f,
                    "VPN coordination server returned an unexpected response: {e}"
                )
            }
        }
    }
}

/// The coordination-server operations the management API needs.
///
/// A trait rather than the concrete client so the authorization and correlation
/// logic above it is testable without a live Headscale — which is most of what
/// is worth testing here, since the HTTP itself is Headscale's contract, not
/// this repo's.
///
/// The methods spell out `impl Future<..> + Send` rather than using `async fn`:
/// the transport spawns a task per connection, so these futures cross a thread
/// boundary, and a bare `async fn` in a trait promises no `Send` bound.
pub trait VpnCoordinator: Send + Sync {
    /// Mint a single-use, short-TTL credential for `mac` to register with.
    ///
    /// `mac` comes from the *verified certificate on the calling connection*,
    /// never from the request body — that is the whole security property this
    /// RPC exists to have.
    fn enroll(&self, mac: Mac) -> impl Future<Output = Result<VpnEnrollment, VpnError>> + Send;

    /// Every peer the coordination server currently knows.
    fn peers(&self) -> impl Future<Output = Result<Vec<VpnPeer>, VpnError>> + Send;

    /// Remove `mac`'s registration.
    ///
    /// **Idempotent**: a MAC with no registration is `Ok(())`, not an error.
    /// Mesh revocation calls this as its second half, and a retry after a
    /// partial failure has to be able to converge — an implementation that
    /// errored on "already gone" would make the retry path report failure
    /// forever.
    fn revoke(&self, mac: Mac) -> impl Future<Output = Result<(), VpnError>> + Send;
}

/// Re-exported so callers configure the coordinator through one path: the
/// schema lives in `wayfinder::config` alongside every other config type,
/// while the client that consumes it lives here.
pub use wayfinder::config::HeadscaleConfig;

#[cfg(feature = "std")]
mod headscale {
    use super::*;

    use alloc::format;
    use core::time::Duration;
    use std::sync::Arc;

    /// How long any single coordination-server call may take.
    ///
    /// This bounds a management request's latency, not a background task's: a
    /// node blocked in `GetVpnEnrollment` is a node waiting to finish
    /// enrolling, and an operator watching `ListVpnPeers` wants "unreachable"
    /// faster than a default TCP timeout would say it.
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

    /// Install `ring` as the process-wide rustls provider, if nothing has yet.
    ///
    /// The management-API TLS in `tls.rs` never needs this: it builds each
    /// config with `builder_with_provider`, naming the provider explicitly. But
    /// `reqwest` under `rustls-no-provider` reads the *process default*, and
    /// panics at client construction when there is none — so without this, a CA
    /// with VPN configured would come up fine and then panic the first time a
    /// node tried to enroll.
    ///
    /// The result is deliberately discarded: `install_default` fails only when
    /// a provider is already installed, which is success for this purpose.
    /// Installing `ring` matches what every other TLS path in this crate uses,
    /// so one provider serves the whole process rather than which-one-wins
    /// depending on link order.
    fn install_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    /// A [`VpnCoordinator`] backed by a Headscale server's REST API.
    ///
    /// REST rather than Headscale's gRPC API: this makes four calls, and the
    /// gRPC route would pull Headscale's own protobuf definitions into this
    /// crate's build for them.
    pub struct HeadscaleCoordinator {
        http: reqwest::Client,
        api_url: String,
        login_server: String,
        api_key: String,
        node_tag: String,
        preauth_ttl_secs: u64,
    }

    impl HeadscaleCoordinator {
        /// Build a coordinator from `config`, reading the API key off disk.
        ///
        /// Fails at construction rather than at first use: a mistyped URL or an
        /// unreadable key file is a startup error an operator sees immediately,
        /// not an enrollment that fails hours later on a node they are no
        /// longer standing next to.
        pub fn new(config: &HeadscaleConfig) -> Result<Self, String> {
            let api_url = normalize_base(&config.api_url)
                .ok_or_else(|| format!("invalid headscale api_url {:?}", config.api_url))?;
            let login_server = match &config.login_server {
                Some(url) => normalize_base(url)
                    .ok_or_else(|| format!("invalid headscale login_server {:?}", url))?,
                None => api_url.clone(),
            };
            let api_key = std::fs::read_to_string(&config.api_key_path)
                .map_err(|e| format!("reading headscale api key {}: {e}", config.api_key_path))?
                .trim()
                .to_string();
            if api_key.is_empty() {
                return Err(format!(
                    "headscale api key file {} is empty",
                    config.api_key_path
                ));
            }
            install_crypto_provider();
            let http = reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .map_err(|e| format!("building headscale http client: {e}"))?;
            Ok(Self {
                http,
                api_url,
                login_server,
                api_key,
                node_tag: config.node_tag.clone(),
                preauth_ttl_secs: config.preauth_ttl_secs,
            })
        }

        /// The `Authorization` header every call carries.
        fn authorized(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
            req.bearer_auth(&self.api_key)
        }

        /// Issue `request` and parse the JSON body, mapping transport and
        /// status failures onto [`VpnError`].
        ///
        /// Never includes the response body in the error text: a coordination
        /// server's error page can echo back the request, and the request
        /// carries the API key.
        async fn send_json<T: serde::de::DeserializeOwned>(
            &self,
            request: reqwest::RequestBuilder,
        ) -> Result<T, VpnError> {
            let response = self.authorized(request).send().await.map_err(|e| {
                VpnError::Unreachable(strip_secret(&format!("{e:?}"), &self.api_key))
            })?;
            let status = response.status();
            if !status.is_success() {
                return Err(VpnError::Unreachable(format!(
                    "coordination server answered {status}"
                )));
            }
            response
                .json::<T>()
                .await
                .map_err(|e| VpnError::Malformed(strip_secret(&e.to_string(), &self.api_key)))
        }

        /// `DELETE url`, treating "already gone" as success.
        ///
        /// A 404 is not a failure here: every caller is on the revocation path,
        /// whose idempotence is contractual — the retry after a half-completed
        /// mesh revoke runs through it and has to converge, and a node listed a
        /// moment ago may have been deleted since. `what` names the thing being
        /// removed, for the error an operator reads.
        async fn delete(&self, url: &str, what: &str) -> Result<(), VpnError> {
            let response = self
                .authorized(self.http.delete(url))
                .send()
                .await
                .map_err(|e| {
                    VpnError::Unreachable(strip_secret(&format!("{e:?}"), &self.api_key))
                })?;
            let status = response.status();
            if !status.is_success() && status != reqwest::StatusCode::NOT_FOUND {
                return Err(VpnError::Unreachable(format!(
                    "coordination server answered {status} deleting {what}"
                )));
            }
            Ok(())
        }

        /// Every node Headscale knows, as its own API reports them.
        async fn list_nodes(&self) -> Result<Vec<HeadscaleNode>, VpnError> {
            let url = format!("{}/api/v1/node", self.api_url);
            let body: NodeList = self.send_json(self.http.get(&url)).await?;
            Ok(body.nodes)
        }

        /// The id of the Headscale user named `name`, or `None`.
        async fn find_user(&self, name: &str) -> Result<Option<String>, VpnError> {
            let url = format!("{}/api/v1/user", self.api_url);
            let body: UserList = self
                .send_json(self.http.get(&url).query(&[("name", name)]))
                .await?;
            Ok(body.users.into_iter().next().map(|u| u.id))
        }

        /// The id of the Headscale user for `mac`, creating it if this is the
        /// node's first enrollment.
        ///
        /// Headscale scopes every preauth key to a user, so there has to be one
        /// — and giving each node its own, named by its MAC, is what makes the
        /// peer↔certificate correlation survive an operator renaming a device.
        /// A hostname is a display name an admin may edit; the owning user is
        /// not, and it is what a revocation targets.
        ///
        /// Find-then-create races another enrollment of the same MAC, which
        /// loses on the unique-name constraint. That loss is treated as success
        /// by re-reading: both callers wanted the user to exist, and it does.
        async fn user_id_for(&self, mac: Mac) -> Result<String, VpnError> {
            let name = hostname_for(mac);
            if let Some(id) = self.find_user(&name).await? {
                return Ok(id);
            }
            let url = format!("{}/api/v1/user", self.api_url);
            let body = serde_json::json!({ "name": name });
            match self
                .send_json::<UserEnvelope>(self.http.post(&url).json(&body))
                .await
            {
                Ok(created) => Ok(created.user.id),
                // The re-read is a best-effort recovery for exactly one cause
                // of `e` (another enrollment won the create race), so its own
                // failure must not supersede `e` — that would report an
                // unrelated `find_user` error for what was actually a create
                // failure, e.g. a bad API key or a rejected request body.
                Err(e) => match self.find_user(&name).await {
                    Ok(Some(id)) => Ok(id),
                    Ok(None) | Err(_) => Err(e),
                },
            }
        }
    }

    impl VpnCoordinator for HeadscaleCoordinator {
        async fn enroll(&self, mac: Mac) -> Result<VpnEnrollment, VpnError> {
            // Scoped to this node's own Headscale user, created on first
            // enrollment. `user` is a uint64 id in Headscale's API, not a name
            // — passing the name is rejected outright.
            let user_id = self.user_id_for(mac).await?;
            let url = format!("{}/api/v1/preauthkey", self.api_url);
            // Headscale expects an RFC3339 instant, not a duration.
            let expiration = expiry_rfc3339(self.preauth_ttl_secs)?;
            let body = serde_json::json!({
                "user": user_id,
                "reusable": false,
                "ephemeral": false,
                "aclTags": [self.node_tag],
                "expiration": expiration,
            });
            let minted: PreAuthKeyResponse =
                self.send_json(self.http.post(&url).json(&body)).await?;
            if minted.pre_auth_key.key.is_empty() {
                return Err(VpnError::Malformed(
                    "coordination server minted an empty preauth key".into(),
                ));
            }
            Ok(VpnEnrollment {
                login_server: self.login_server.clone(),
                preauth_key: minted.pre_auth_key.key,
            })
        }

        async fn peers(&self) -> Result<Vec<VpnPeer>, VpnError> {
            Ok(self
                .list_nodes()
                .await?
                .into_iter()
                .map(|n| VpnPeer {
                    // The same correlation a revocation selects by — see
                    // `node_mac`. A peer it cannot name is still listed: it has
                    // tunnel reachability with no mesh identity behind it, and
                    // an operator auditing who can reach the tunnel needs to see
                    // exactly those.
                    mac: node_mac(&n),
                    hostname: n.given_name,
                    address: n.ip_addresses.first().cloned().unwrap_or_default(),
                    online: n.online,
                    last_seen_unix: parse_rfc3339(n.last_seen.as_deref()),
                    key_expiry_unix: parse_rfc3339(n.expiry.as_deref()),
                })
                .collect())
        }

        async fn revoke(&self, mac: Mac) -> Result<(), VpnError> {
            let name = hostname_for(mac);

            // The registered nodes first. Deleting the per-MAC *user* alone
            // does not take them: `enroll` tags every key it mints, and
            // Headscale reassigns a tagged node to the synthetic
            // `tagged-devices` user — so a node this system registered is never
            // among its MAC user's nodes, and deleting that user reaps only the
            // unspent keys. That is the whole bug this ordering exists to fix:
            // Headscale answered success, the RPC logged a revocation, and the
            // node kept its tunnel.
            //
            // Selected by the same correlation `peers` lists by, so an operator
            // revokes the peer they were shown — see `node_mac`.
            for node in self.list_nodes().await? {
                if node_mac(&node) != Some(mac) {
                    continue;
                }
                // A node with no id is one this cannot address — `id` is the
                // only thing `DELETE /api/v1/node/{id}` accepts — so this is a
                // schema break, and it fails rather than skipping. Skipping
                // would return the success that this whole path exists to stop
                // lying about, and deleting `/api/v1/node/` instead would be an
                // unbounded request whose meaning is Headscale's to decide.
                if node.id.is_empty() {
                    return Err(VpnError::Malformed(format!(
                        "coordination server reported a node for {name} with no id"
                    )));
                }
                self.delete(
                    &format!("{}/api/v1/node/{}", self.api_url, node.id),
                    &format!("the node registered by {name}"),
                )
                .await?;
            }

            // Then the user, which takes any key minted but not yet spent with
            // it. Last, not first: a revocation racing an enrollment would
            // otherwise leave a usable credential behind for a node that was
            // just removed.
            //
            // Idempotent by contract: a MAC with no user is success. The retry
            // path for a partially-failed mesh revocation runs through here and
            // has to converge.
            let Some(id) = self.find_user(&name).await? else {
                return Ok(());
            };
            self.delete(
                &format!("{}/api/v1/user/{id}", self.api_url),
                &format!("the registration for {name}"),
            )
            .await
        }
    }

    /// The mesh MAC behind a node Headscale reports, or `None` for a peer this
    /// system did not enroll.
    ///
    /// Three arms, narrowest first, and the order is the whole point:
    ///
    /// 1. The user its *preauth key* was minted for. `enroll` tags every key,
    ///    and Headscale reassigns a tagged node to the synthetic
    ///    `tagged-devices` user — so this is the only arm that resolves a node
    ///    this system actually registered, which is all of them.
    /// 2. The node's own owning user, for a peer registered against a MAC-named
    ///    user without a tag.
    /// 3. The hostname, last, for a peer registered by hand under this
    ///    convention.
    ///
    /// Shared by [`peers`](VpnCoordinator::peers) and
    /// [`revoke`](VpnCoordinator::revoke) rather than written twice: an
    /// operator revokes the peer the listing named, so the two must select the
    /// same node or a revocation silently misses. The strictness of
    /// [`mac_from_hostname`] is what keeps arm 3 from letting an
    /// operator-chosen name alias a real node — revoking one peer must never
    /// take out another's tunnel.
    fn node_mac(node: &HeadscaleNode) -> Option<Mac> {
        node.pre_auth_key
            .as_ref()
            .and_then(|k| k.user.as_ref())
            .and_then(|u| mac_from_hostname(&u.name))
            .or_else(|| node.user.as_ref().and_then(|u| mac_from_hostname(&u.name)))
            .or_else(|| mac_from_hostname(&node.given_name))
    }

    /// Headscale's node representation, narrowed to the fields used here.
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct HeadscaleNode {
        /// Headscale's own id for this node, and the only thing
        /// `DELETE /api/v1/node/{id}` accepts. A JSON *string*, like every
        /// other 64-bit id in this API — echoed back verbatim rather than
        /// parsed and re-rendered.
        #[serde(default)]
        id: String,
        #[serde(default)]
        given_name: String,
        /// The Headscale user this node belongs to. **Not** the per-MAC user
        /// its credential was scoped to whenever the node carries an ACL tag:
        /// Headscale reports a tagged node as owned by the synthetic
        /// `tagged-devices` user instead. Absent for a peer registered outside
        /// this flow.
        #[serde(default)]
        user: Option<HeadscaleUser>,
        /// The preauth key this node registered with, present for any node that
        /// joined with one. Its `user` is the per-MAC user `user_id_for`
        /// created, which an ACL tag does not displace — so this, not
        /// [`user`](Self::user), is what identifies a node this system enrolled.
        #[serde(default)]
        pre_auth_key: Option<PreAuthKey>,
        #[serde(default)]
        ip_addresses: Vec<String>,
        #[serde(default)]
        online: bool,
        #[serde(default)]
        last_seen: Option<String>,
        #[serde(default)]
        expiry: Option<String>,
    }

    /// A Headscale user. One is created per wayfinder node, named by its MAC
    /// as hex, and every preauth key is scoped to it.
    #[derive(serde::Deserialize)]
    struct HeadscaleUser {
        /// Headscale serialises 64-bit ids as JSON *strings* (the protobuf JSON
        /// mapping for `uint64`) but accepts either form on input, so this is
        /// kept as a string and echoed back verbatim rather than parsed and
        /// re-rendered.
        #[serde(default)]
        id: String,
        #[serde(default)]
        name: String,
    }

    #[derive(serde::Deserialize)]
    struct UserList {
        #[serde(default)]
        users: Vec<HeadscaleUser>,
    }

    #[derive(serde::Deserialize)]
    struct UserEnvelope {
        user: HeadscaleUser,
    }

    #[derive(serde::Deserialize)]
    struct NodeList {
        #[serde(default)]
        nodes: Vec<HeadscaleNode>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct PreAuthKeyResponse {
        pre_auth_key: PreAuthKey,
    }

    /// A Headscale preauth key, as it appears both in the mint response and
    /// on a node that registered with one.
    #[derive(serde::Deserialize)]
    struct PreAuthKey {
        #[serde(default)]
        key: String,
        /// The user this key was minted for — the per-MAC one, which is how a
        /// registered node is joined back to the mesh identity that enrolled it.
        #[serde(default)]
        user: Option<HeadscaleUser>,
    }

    /// `now + ttl` as an RFC3339 instant, which is what Headscale's preauth-key
    /// API expects.
    fn expiry_rfc3339(ttl_secs: u64) -> Result<String, VpnError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| VpnError::Malformed(format!("system clock before the unix epoch: {e}")))?
            .as_secs();
        Ok(format_rfc3339(now.saturating_add(ttl_secs)))
    }

    /// Format `unix` seconds as an RFC3339 UTC instant.
    ///
    /// Hand-rolled rather than pulling `chrono`/`time` in for two conversions.
    /// Civil-date arithmetic from Howard Hinnant's `civil_from_days`.
    fn format_rfc3339(unix: u64) -> String {
        let days = (unix / 86_400) as i64;
        let secs_of_day = unix % 86_400;
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            secs_of_day / 3600,
            (secs_of_day % 3600) / 60,
            secs_of_day % 60
        )
    }

    /// Parse an RFC3339 instant to unix seconds, yielding 0 for absent or
    /// unparseable input.
    ///
    /// Lenient on purpose: these feed an operator's "last seen" column, so a
    /// timestamp shape this parser does not recognise should cost that one cell
    /// rather than failing the whole peer list.
    fn parse_rfc3339(s: Option<&str>) -> i64 {
        let Some(s) = s else { return 0 };
        let bytes = s.as_bytes();
        if bytes.len() < 19 {
            return 0;
        }
        let num = |r: core::ops::Range<usize>| -> Option<i64> { s.get(r)?.parse().ok() };
        let (Some(y), Some(m), Some(d), Some(hh), Some(mm), Some(ss)) = (
            num(0..4),
            num(5..7),
            num(8..10),
            num(11..13),
            num(14..16),
            num(17..19),
        ) else {
            return 0;
        };
        // Inverse of `format_rfc3339`'s civil-date arithmetic.
        let y = if m <= 2 { y - 1 } else { y };
        let era = y.div_euclid(400);
        let yoe = y.rem_euclid(400);
        let mp = if m > 2 { m - 3 } else { m + 9 };
        let doy = (153 * mp + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe - 719_468;
        days * 86_400 + hh * 3600 + mm * 60 + ss
    }

    /// Trim a base URL to scheme://host[:port], rejecting anything that is not
    /// an absolute http(s) URL.
    fn normalize_base(raw: &str) -> Option<String> {
        let parsed = url::Url::parse(raw.trim()).ok()?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return None;
        }
        parsed.host_str()?;
        Some(parsed.as_str().trim_end_matches('/').to_string())
    }

    /// Remove `secret` from `text` if a library's error string embedded it.
    ///
    /// `reqwest` includes the request URL in some errors, and a redirect or a
    /// misconfiguration could put the key there. This is a backstop against
    /// the API key reaching a log or an error sent over the wire, not a
    /// license to put it in one.
    fn strip_secret(text: &str, secret: &str) -> String {
        if secret.is_empty() {
            return text.to_string();
        }
        text.replace(secret, "<redacted>")
    }

    /// A shareable coordinator handle, so the transport's per-connection tasks
    /// can each reach the one client (and its connection pool).
    pub type SharedCoordinator = Arc<dyn DynVpnCoordinator>;

    /// Object-safe mirror of [`VpnCoordinator`], since the transport stores one
    /// behind a trait object and `async fn` in a trait is not object-safe.
    pub trait DynVpnCoordinator: Send + Sync {
        /// See [`VpnCoordinator::enroll`].
        fn enroll<'a>(
            &'a self,
            mac: Mac,
        ) -> core::pin::Pin<
            alloc::boxed::Box<
                dyn core::future::Future<Output = Result<VpnEnrollment, VpnError>> + Send + 'a,
            >,
        >;
        /// See [`VpnCoordinator::peers`].
        fn peers<'a>(
            &'a self,
        ) -> core::pin::Pin<
            alloc::boxed::Box<
                dyn core::future::Future<Output = Result<Vec<VpnPeer>, VpnError>> + Send + 'a,
            >,
        >;
        /// See [`VpnCoordinator::revoke`].
        fn revoke<'a>(
            &'a self,
            mac: Mac,
        ) -> core::pin::Pin<
            alloc::boxed::Box<dyn core::future::Future<Output = Result<(), VpnError>> + Send + 'a>,
        >;
    }

    impl<T: VpnCoordinator> DynVpnCoordinator for T {
        fn enroll<'a>(
            &'a self,
            mac: Mac,
        ) -> core::pin::Pin<
            alloc::boxed::Box<
                dyn core::future::Future<Output = Result<VpnEnrollment, VpnError>> + Send + 'a,
            >,
        > {
            alloc::boxed::Box::pin(VpnCoordinator::enroll(self, mac))
        }
        fn peers<'a>(
            &'a self,
        ) -> core::pin::Pin<
            alloc::boxed::Box<
                dyn core::future::Future<Output = Result<Vec<VpnPeer>, VpnError>> + Send + 'a,
            >,
        > {
            alloc::boxed::Box::pin(VpnCoordinator::peers(self))
        }
        fn revoke<'a>(
            &'a self,
            mac: Mac,
        ) -> core::pin::Pin<
            alloc::boxed::Box<dyn core::future::Future<Output = Result<(), VpnError>> + Send + 'a>,
        > {
            alloc::boxed::Box::pin(VpnCoordinator::revoke(self, mac))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;

        /// The RFC3339 formatting Headscale's preauth-key API expects, and its
        /// inverse, round-trip. Both are hand-rolled, so this is the test that
        /// keeps a "last seen" column from quietly reading the wrong year.
        #[test]
        fn rfc3339_roundtrips() {
            for (unix, text) in [
                (0u64, "1970-01-01T00:00:00Z"),
                (951_782_400, "2000-02-29T00:00:00Z"),
                (1_700_000_000, "2023-11-14T22:13:20Z"),
                (1_767_225_600, "2026-01-01T00:00:00Z"),
            ] {
                assert_eq!(format_rfc3339(unix), text);
                assert_eq!(parse_rfc3339(Some(text)), unix as i64);
            }
        }

        /// A timestamp shape this parser does not recognise costs one cell, not
        /// the whole peer list.
        #[test]
        fn an_unparseable_timestamp_is_zero_not_a_failure() {
            for bad in [None, Some(""), Some("never"), Some("2026-01")] {
                assert_eq!(parse_rfc3339(bad), 0);
            }
        }

        /// Base URLs are validated at construction and normalised to a form the
        /// call sites can concatenate paths onto without producing `//`.
        #[test]
        fn base_urls_are_validated_and_normalised() {
            assert_eq!(
                normalize_base("https://vpn.example.net/").as_deref(),
                Some("https://vpn.example.net")
            );
            assert_eq!(
                normalize_base("  http://10.0.0.1:8080  ").as_deref(),
                Some("http://10.0.0.1:8080")
            );
            for bad in ["", "vpn.example.net", "ftp://vpn.example.net", "not a url"] {
                assert_eq!(normalize_base(bad), None, "{bad:?} must be refused");
            }
        }

        /// An API key must never survive into an error string, since those are
        /// logged and some are sent to the peer.
        #[test]
        fn a_leaked_api_key_is_redacted_from_error_text() {
            let key = "hs-secret-abc123";
            let text = format!("error sending request for url (https://vpn/x?key={key})");
            let cleaned = strip_secret(&text, key);
            assert!(!cleaned.contains(key));
            assert!(cleaned.contains("<redacted>"));
        }

        /// A coordinator pointed at `api_url`, bypassing [`HeadscaleCoordinator::new`]
        /// (which reads an API key file from disk).
        fn coordinator(api_url: String) -> HeadscaleCoordinator {
            install_crypto_provider();
            HeadscaleCoordinator {
                http: reqwest::Client::builder()
                    .timeout(Duration::from_secs(2))
                    .build()
                    .unwrap(),
                login_server: api_url.clone(),
                api_url,
                api_key: "test-key".to_string(),
                node_tag: "wayfinder".to_string(),
                preauth_ttl_secs: 300,
            }
        }

        /// A request log shared between a test and the server task answering
        /// it, so the test can read what arrived *without* waiting for the
        /// server to finish. A client that issues fewer requests than were
        /// queued is exactly what a regression on this path looks like, and
        /// joining the task to get its return value would hang on that case
        /// instead of failing it.
        type RequestLog = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

        /// An empty [`RequestLog`].
        fn request_log() -> RequestLog {
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()))
        }

        /// Serve exactly `responses.len()` HTTP/1.1 requests on `listener`, one
        /// canned `(status, body)` response each, then stop accepting — so a
        /// connection attempt beyond that count fails the way an unreachable
        /// server would.
        ///
        /// Records each request's start line (`"DELETE /api/v1/node/1"`) into
        /// `log` in arrival order, before answering it — so every request the
        /// client has seen a response to is already logged by the time its call
        /// returns. For a call whose whole point is *which* endpoints it hits —
        /// `revoke` — the response bodies say nothing and the request lines say
        /// everything. Every response carries `Connection: close`, so one
        /// accept is one request and arrival order is request order.
        async fn serve_logged(
            listener: tokio::net::TcpListener,
            responses: Vec<(u16, String)>,
            log: RequestLog,
        ) {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                // Requests in this test carry no body worth reading; draining
                // headers only is enough to let the client see a response.
                let mut buf = [0u8; 4096];
                let mut head = Vec::new();
                loop {
                    let n = stream.read(&mut buf).await.unwrap();
                    head.extend_from_slice(&buf[..n]);
                    if n == 0 || head.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let line = String::from_utf8_lossy(&head)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                // "GET /path HTTP/1.1" -> "GET /path": the version is noise.
                log.lock().unwrap().push(
                    line.rsplit_once(' ')
                        .map(|(m, _)| m.to_string())
                        .unwrap_or(line),
                );
                let reason = if status == 200 { "OK" } else { "Error" };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
            // Dropping the listener here (end of scope) is what makes the next
            // connection attempt fail closed rather than hang.
        }

        /// [`serve_logged`] for a test that only needs the responses served,
        /// not the requests that fetched them.
        async fn serve_n(listener: tokio::net::TcpListener, responses: Vec<(u16, String)>) {
            serve_logged(listener, responses, request_log()).await
        }

        /// When creating a Headscale user fails for a reason that is *not* the
        /// find-then-create race (e.g. the create request itself was rejected),
        /// and the recovery re-read also fails, the error reported must be the
        /// create failure — not the unrelated recovery lookup's — so an
        /// operator debugging a broken enrollment sees the actual cause.
        ///
        /// Regression test: `user_id_for` used to propagate the retry's error
        /// with `?`, discarding the original.
        #[tokio::test]
        async fn a_failed_recovery_lookup_does_not_hide_the_original_create_error() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let api_url = format!("http://{addr}");

            let server = tokio::spawn(serve_n(
                listener,
                vec![
                    // find_user: no existing user.
                    (200, r#"{"users":[]}"#.to_string()),
                    // create: rejected for a reason that is not the race.
                    (400, r#"{"message":"invalid name"}"#.to_string()),
                    // No third response queued: the recovery find_user's
                    // connection attempt fails closed.
                ],
            ));

            let coord = coordinator(api_url);
            let result = coord.user_id_for(Mac([0, 0, 0, 0, 0, 1])).await;
            server.await.unwrap();

            match result {
                Err(VpnError::Unreachable(msg)) => {
                    assert!(
                        msg.contains("400"),
                        "expected the original create failure (400), got: {msg}"
                    );
                }
                other => panic!(
                    "expected VpnError::Unreachable naming the create failure, got {other:?}"
                ),
            }
        }

        /// A peer this node enrolled is correlated back to its mesh MAC even
        /// though Headscale reports its owner as the synthetic `tagged-devices`
        /// user.
        ///
        /// Regression test for the whole correlation being dead in practice.
        /// Every credential [`enroll`](VpnCoordinator::enroll) mints carries an
        /// ACL tag, and Headscale reassigns a *tagged* node's `user` to
        /// `tagged-devices` (id 2147455555) rather than the per-MAC user the key
        /// was scoped to — so the owning user is never the MAC on any node this
        /// system registers, which is all of them. The key's own user still is,
        /// and `givenName` is whatever hostname the client happened to have.
        #[tokio::test]
        async fn a_tagged_peer_is_correlated_through_the_key_it_registered_with() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let api_url = format!("http://{addr}");
            let enrolled = Mac([0xda, 0xd6, 0xc7, 0xe7, 0x7f, 0xba]);

            // Field names and shape copied from a live Headscale 0.29.3
            // `GET /api/v1/node`: camelCase (protojson), not the snake_case the
            // `headscale nodes list -o json` CLI prints for the same message.
            let body = format!(
                r#"{{"nodes":[{{
                    "givenName":"some-laptop",
                    "user":{{"id":"2147455555","name":"tagged-devices"}},
                    "preAuthKey":{{"user":{{"id":"1","name":"{}"}}}},
                    "ipAddresses":["100.64.0.1"],
                    "online":true
                }}]}}"#,
                hostname_for(enrolled)
            );
            let server = tokio::spawn(serve_n(listener, vec![(200, body)]));

            let coord = coordinator(api_url);
            let peers = VpnCoordinator::peers(&coord).await.unwrap();
            server.await.unwrap();

            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].mac, Some(enrolled));
            assert_eq!(peers[0].hostname, "some-laptop");
        }

        /// A peer registered by hand — no wayfinder-minted key, no MAC-named
        /// user, a hostname somebody chose — is still listed, with no MAC.
        ///
        /// That peer is the one an operator most needs to see: it has tunnel
        /// reachability with no mesh identity behind it. Correlating it to a MAC
        /// anyway would be worse than showing none, since revoking by MAC would
        /// then take out an unrelated node's tunnel.
        #[tokio::test]
        async fn a_hand_registered_peer_lists_with_no_mac() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let api_url = format!("http://{addr}");

            let body = r#"{"nodes":[{
                "givenName":"intruder",
                "user":{"id":"7","name":"alice"},
                "ipAddresses":["100.64.0.9"],
                "online":false
            }]}"#
                .to_string();
            let server = tokio::spawn(serve_n(listener, vec![(200, body)]));

            let coord = coordinator(api_url);
            let peers = VpnCoordinator::peers(&coord).await.unwrap();
            server.await.unwrap();

            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].mac, None);
            assert_eq!(peers[0].hostname, "intruder");
        }

        /// A `GET /api/v1/node` body carrying `nodes`, in the field shape a
        /// live Headscale 0.29.3 emits (camelCase protojson).
        ///
        /// Written as a helper because every revoke test below needs one and
        /// the interesting part of each is a single field.
        fn node_list(nodes: &[String]) -> String {
            format!(r#"{{"nodes":[{}]}}"#, nodes.join(","))
        }

        /// A node this system registered: tagged, so Headscale reports its
        /// owning user as the synthetic `tagged-devices` while the preauth key
        /// it spent still carries the per-MAC user.
        fn tagged_node(id: &str, mac: Mac) -> String {
            format!(
                r#"{{"id":"{id}","givenName":"some-laptop",
                    "user":{{"id":"2147455555","name":"tagged-devices"}},
                    "preAuthKey":{{"user":{{"id":"1","name":"{}"}}}},
                    "ipAddresses":["100.64.0.1"],"online":true}}"#,
                hostname_for(mac)
            )
        }

        /// Run `revoke(mac)` against a server answering `responses`, and return
        /// the outcome together with the requests it actually issued.
        ///
        /// The server task is aborted rather than joined: a `revoke` that stops
        /// early leaves responses unconsumed, and that case has to fail an
        /// assertion below rather than block the test forever.
        async fn revoke_against(
            responses: Vec<(u16, String)>,
            mac: Mac,
        ) -> (Result<(), VpnError>, Vec<String>) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let log = request_log();
            let server = tokio::spawn(serve_logged(listener, responses, log.clone()));

            let coord = coordinator(format!("http://{addr}"));
            let result = VpnCoordinator::revoke(&coord, mac).await;
            server.abort();
            let requests = log.lock().unwrap().clone();
            (result, requests)
        }

        /// Revoking a MAC deletes the *node* it registered, not only the
        /// per-MAC Headscale user.
        ///
        /// Regression test for a silent failure: `enroll` tags every key it
        /// mints, Headscale reassigns a tagged node to the synthetic
        /// `tagged-devices` user, and so the registered node is not among the
        /// MAC user's nodes. Deleting that user alone therefore reaped only
        /// unspent keys — the coordination server answered success, the RPC
        /// logged "revoked a VPN registration", and the node kept its tunnel.
        ///
        /// Ordering is asserted, not incidental: the nodes go first so a
        /// revocation racing an enrollment cannot leave a usable credential
        /// behind, which is what deleting the user last is for.
        #[tokio::test]
        async fn revoking_deletes_the_registered_node_before_its_user() {
            let revoked = Mac([0x32, 0xed, 0x2e, 0x13, 0x5d, 0xf9]);
            let (result, requests) = revoke_against(
                vec![
                    (200, node_list(&[tagged_node("7", revoked)])),
                    // DELETE /api/v1/node/7
                    (200, "{}".to_string()),
                    // find_user
                    (
                        200,
                        r#"{"users":[{"id":"9","name":"32ed2e135df9"}]}"#.to_string(),
                    ),
                    // DELETE /api/v1/user/9
                    (200, "{}".to_string()),
                ],
                revoked,
            )
            .await;
            assert_eq!(result, Ok(()));

            let node_delete = requests
                .iter()
                .position(|r| r == "DELETE /api/v1/node/7")
                .unwrap_or_else(|| panic!("the registered node was never deleted: {requests:?}"));
            let user_delete = requests
                .iter()
                .position(|r| r == "DELETE /api/v1/user/9")
                .unwrap_or_else(|| panic!("the per-MAC user was never deleted: {requests:?}"));
            assert!(
                node_delete < user_delete,
                "the node must be deleted before its user: {requests:?}"
            );
        }

        /// Revoking one MAC touches no other peer's registration.
        ///
        /// The correlation is the same three-way one `peers` lists by, and its
        /// widest arm — the hostname — is a display name an operator can edit.
        /// A looser match here would revoke somebody else's tunnel, which is
        /// strictly worse than the bug this path exists to fix.
        #[tokio::test]
        async fn revoking_leaves_every_other_peer_registered() {
            let revoked = Mac([0x32, 0xed, 0x2e, 0x13, 0x5d, 0xf9]);
            let other = Mac([0x32, 0xed, 0x2e, 0x13, 0x5d, 0xfa]);
            let (result, requests) = revoke_against(
                vec![
                    (
                        200,
                        node_list(&[
                            tagged_node("7", revoked),
                            tagged_node("8", other),
                            // Registered by hand, under no name of ours.
                            r#"{"id":"9","givenName":"intruder",
                                "user":{"id":"3","name":"alice"},
                                "ipAddresses":["100.64.0.9"],"online":false}"#
                                .to_string(),
                        ]),
                    ),
                    (200, "{}".to_string()),
                    (
                        200,
                        r#"{"users":[{"id":"5","name":"32ed2e135df9"}]}"#.to_string(),
                    ),
                    (200, "{}".to_string()),
                ],
                revoked,
            )
            .await;
            assert_eq!(result, Ok(()));

            assert!(
                requests.iter().any(|r| r == "DELETE /api/v1/node/7"),
                "the revoked node was not deleted: {requests:?}"
            );
            for spared in ["DELETE /api/v1/node/8", "DELETE /api/v1/node/9"] {
                assert!(
                    !requests.iter().any(|r| r == spared),
                    "{spared} took out an unrelated peer: {requests:?}"
                );
            }
        }

        /// A node this cannot address fails the revoke rather than being
        /// skipped.
        ///
        /// `id` is the only thing `DELETE /api/v1/node/{id}` accepts, so a node
        /// reported without one cannot be removed. Reporting success anyway
        /// would be the exact shape of the bug above — a clean `Ok(())` while
        /// the node keeps its tunnel — so this is the one place on the
        /// revocation path that is deliberately *not* forgiving.
        #[tokio::test]
        async fn a_node_with_no_id_fails_the_revoke_rather_than_being_skipped() {
            let revoked = Mac([0x32, 0xed, 0x2e, 0x13, 0x5d, 0xf9]);
            let (result, _) = revoke_against(
                vec![(
                    200,
                    node_list(&[format!(
                        r#"{{"givenName":"some-laptop",
                            "preAuthKey":{{"user":{{"id":"1","name":"{}"}}}},
                            "ipAddresses":["100.64.0.1"],"online":true}}"#,
                        hostname_for(revoked)
                    )]),
                )],
                revoked,
            )
            .await;
            assert!(
                matches!(result, Err(VpnError::Malformed(_))),
                "expected a malformed-response error, got {result:?}"
            );
        }

        /// A MAC with nothing registered is success, and a node that vanished
        /// between the listing and the delete is too.
        ///
        /// Idempotence is contractual: `revoke_vpn_alongside_mesh` retries
        /// through this path after a half-completed mesh revoke, and the
        /// operator-facing message tells them to re-run `wayfinderctl vpn
        /// revoke`. An "already gone" that errored would make that retry report
        /// failure forever.
        #[tokio::test]
        async fn revoking_an_absent_or_vanished_registration_is_success() {
            let revoked = Mac([0x32, 0xed, 0x2e, 0x13, 0x5d, 0xf9]);

            for (case, responses) in [
                (
                    "nothing registered at all",
                    vec![(200, node_list(&[])), (200, r#"{"users":[]}"#.to_string())],
                ),
                (
                    "the node was deleted between the listing and the delete",
                    vec![
                        (200, node_list(&[tagged_node("7", revoked)])),
                        (404, r#"{"message":"node not found"}"#.to_string()),
                        (200, r#"{"users":[]}"#.to_string()),
                    ],
                ),
            ] {
                let (result, requests) = revoke_against(responses, revoked).await;
                assert_eq!(result, Ok(()), "{case}: {requests:?}");
            }
        }
    }
}

#[cfg(feature = "std")]
pub use headscale::DynVpnCoordinator;
#[cfg(feature = "std")]
pub use headscale::HeadscaleCoordinator;
#[cfg(feature = "std")]
pub use headscale::SharedCoordinator;

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// A MAC round-trips through the hostname that carries it, which is the
    /// only thing making the peer↔certificate join possible without the CA
    /// persisting a mapping of its own.
    #[test]
    fn mac_roundtrips_through_its_hostname() {
        for m in [
            mac(0),
            mac(1),
            mac(255),
            Mac([0x02, 0xab, 0xcd, 0xef, 0x10, 0x9f]),
        ] {
            let hostname = hostname_for(m);
            assert_eq!(hostname.len(), 12);
            assert_eq!(mac_from_hostname(&hostname), Some(m));
        }
    }

    /// A hostname that is not one of ours yields no MAC rather than a wrong
    /// one. A peer named by hand must not alias a real node's identity: if it
    /// did, revoking that peer would revoke the aliased node's tunnel.
    #[test]
    fn a_hostname_that_is_not_a_mac_yields_none() {
        for bad in [
            "",
            "gateway",
            "02:00:00:00:00:09", // separators
            "02000000000",       // 11 digits
            "0200000000090",     // 13 digits
            "02000000000g",      // not hex
            "02000000ABCD",      // uppercase: one MAC must have one spelling
        ] {
            assert_eq!(mac_from_hostname(bad), None, "{bad:?} must not parse");
        }
    }
}
