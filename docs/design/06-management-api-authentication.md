# Design: management-API security review and user credentials

**Status:** Phases 0–2 implemented in full; **Phase 3 implemented except §6
item 4** (silent renewal — see §8.5 for why it follows rather than leads).
Every finding F1–F13 is closed or resolved; none remain open. Supersedes
nothing; extends `05-enrollment-tier-security-hardening.md`, whose §4 backlog
is folded in below as F8 (also closed — see F8's "Implemented" note).

**Scope of the review:** the management API end to end — `wayfinder-auth`
(seeds, certs, revocations, pairwise tags), `wayfinder-tls-mgmt` +
`wayfinder-server` (RFC 7250 transport, `decide_access`/`permits`, the CA),
`wayfinder-client`, `wayfinder-ctl`, `wayfinder-web`, and the container/compose
deployment. The mesh data plane is reviewed only where it bears on
management authorization.

**Scope of the proposal:** §6 adds user credentials at the *certificate
authority*, not at the node. It changes `wayfinder-server`'s provider mode,
`wayfinder-ctl`, and `wayfinder-web`. It does not change `decide_access`,
the wire format, the OGM signing path, or the `no_std` core.

---

## 1. What holds up

Stated first because the plan below leans on it. These are the parts that
should not be touched while fixing the rest.

- **`authz.rs` is a closed positive allowlist.** `permits` fails closed on an
  unknown request kind *and* on an absent oneof (what prost yields for a field
  number added after this build). `permits_confines_the_enrollment_tier_to_a_closed_allowlist`
  and `permits_confines_the_viewer_tier_to_the_queries` each sweep the same
  hand-maintained `every_request_kind()` — 27 variants as of Phase 3, up from
  22 when this test was first written in `05-...` — with a hard count
  assertion, so adding a proto request forces a decision at both tiers, not
  just one.
- **Certs are bound to the TLS session.** `decide_access` refuses a verified
  admin cert whose `ed_pubkey` is not the handshake key, so a cert lifted off
  the wire is worthless without the private half. A failed claim is a denial,
  never a demotion to the enrollment tier.
- **Denials are not an oracle.** The precise `MgmtDenied` stays in the local
  log; the wire gets a flat `"authentication denied"`.
- **The crypto is carefully composed.** Domain separation on every Blake2s use
  (`wayfinder-mac-v1`, `-pairwise-v1`, `-certfp-v1`, `wf-ogm-sig-v1`,
  `wf-keepalive-sig-v1`, `wf-certreq-sig-v1`); `verify_strict` for Ed25519;
  `subtle::ConstantTimeEq` on the frame tag; sender identity length-prefixed
  into the pairwise context so an `A→B` frame cannot be reflected; monotonic
  per-neighbor replay counters; a bounded bucket window for keep-alives.
- **Clock handling fails closed.** `transport::now_unix` errors rather than
  substituting `0`, which would be the most permissive value for a `not_after`
  comparison. `CertAuthority` refuses to issue while `now_unix == 0`.
- **Secrets are written `0o600`,** narrowly created rather than written
  world-readable and chmod'd afterwards (`wayfinder-tap/src/main.rs:158`).
- **Persistence orders correctly.** `Persisted` commits before applying and
  rolls back on failure; `mutate_issued_and_held` makes an approval's two
  halves one atomic write.
- **The anonymous tier is bounded** on both axes — `MAX_HELD_CSRS` mesh-wide
  and `SourceLimiter::for_enrollment()` per source IP (the type `05-...`
  called `EnrollmentLimiter`, since generalized — see Phase 1 item 2 below).
- **The pre-authentication surface is bounded too, since Phase 1.** Every
  connection starts uncredentialed regardless of tier, and `PreAuthLimits`
  caps that population mesh-wide and per source before any request is even
  read.

## 2. Findings

Severity is "what an attacker gets", not "how hard the fix is".

### F1 — Critical. The container publishes the loginless dashboard on every interface.

`containers/Dockerfile:345` sets `ENV WAYFINDER_WEB_LISTEN=0.0.0.0:8080`. The
`--listen` argument is declared `#[arg(long, env = "WAYFINDER_WEB_LISTEN",
default_value = "127.0.0.1:8080")]`, and clap resolves an environment variable
*above* `default_value`. The `web` service in `docker-compose.yml` runs
`network_mode: host`, passes only `--addr`, and carries a comment asserting
that `--listen` "is left at its default, 127.0.0.1:8080 — under host
networking that's the host's real loopback, so this stays host-local."

It does not. Under host networking the image's env var binds the dashboard to
`0.0.0.0:8080` in the host's own network namespace. The dashboard has no
authentication of its own and holds the node's identity seed, so this is
unauthenticated, full-privilege node administration — `SetAuth`, `SetConfig`,
`RevokeNode`, enrollment policy, the enrollment token — on every host
interface. The Dockerfile's own comment reasons correctly about the container
case and does not anticipate `network_mode: host`.

### F2 — Critical. Every mutating dashboard endpoint is cross-site forgeable.

`#[server]` in server_fn 0.8 defaults to `input = PostUrl`
(`server_fn_macro-0.8.10/src/lib.rs:211`), i.e.
`application/x-www-form-urlencoded` — a CORS *simple request*, so no preflight
and no opt-in from the target. server_fn performs no Origin, `Sec-Fetch-Site`
or token check; its only use of `Referer` is choosing a redirect target after
a form post. `build_router` adds none of its own, and checks no `Host` header.

So any page an operator visits while the dashboard is running can silently
drive: `set_link_gate`, `approve_csr`, `deny_csr`, `revoke_node`,
`set_require_auth`, `set_lazy_cert_distribution`, `set_enrollment_policy`,
`set_log_level`, and `request_enrollment`.

`request_enrollment` is the sharpest: its `ProviderTarget` — address, pinned
key, token — is entirely attacker-supplied, and a successful call performs a
`SetAuth` installing the returned certificate *and trust anchor*. A drive-by
page can therefore move the node off its mesh and onto an attacker's.

Absent F1, this needs the operator to visit a page; with F1 it is reachable
directly. The missing `Host` check independently exposes the loopback bind to
DNS rebinding.

### F3 — High. Provider-mode enrollment is open by default.

`ProviderConfig::enrollment_token` is `#[serde(default)]` → `None`, and
`require_approval` is `#[serde(default)]` → `false`. A provider configured
with the minimum fields therefore signs a membership certificate for any MAC
and keys an anonymous client names, on demand.

> **Since superseded.** Phase 2 item 1 below closed this with an explicit
> `auto_approve` acknowledgement flag *beside* `require_approval`, refused at
> startup when both were absent. That pair was two fields for one decision, and
> the guard only governed omission in YAML. It has since been collapsed: the
> posture is now the single field `auto_approve` (`#[serde(default)]` →
> `false`, the closed posture), `require_approval` is gone, and the startup
> guard with it — the default is the guard. See `libs/wayfinder-server/CLAUDE.md`.

The certificate is not an admin certificate, so this is not management
escalation — but mesh segregation is the entire purpose of the trust anchor,
and this makes it opt-in. The issued cert lets its holder sign OGMs the mesh
accepts, derive pairwise keys with any neighbor, and participate in routing.

### F4 — Medium. Authorization is snapshotted at connect and never revalidated.

`serve_tls_connection` builds one `AuthContext` — anchor, revocation list,
`now_unix` — and `serve_authenticated_stream` then loops until the peer hangs
up. The `AuthContext` doc states this plainly ("a connection's authorization
reflects the mesh state when it opened"), and `AuthSnapshot`'s doc explains
carefully that `own_key` is read fresh *per connection*. Per connection is the
granularity, and a connection has no bound.

Consequences: `RevokeNode` does not terminate a revoked admin's open session;
an admin certificate that expires mid-session stays honoured; a rotated
identity seed only stops earning `GrantedSelfKey` on the *next* connect. An
attacker who obtains an admin credential and opens one long-lived connection
keeps it after every revocation lever has been pulled.

### F5 — Medium. The TLS listener has no pre-authentication resource limits.

`serve_tls_server` accepts and `tokio::spawn`s per connection with no
concurrency cap, and `acceptor.accept(tcp).await` has no handshake timeout —
so idle half-open connections accumulate without bound.

`serve_authenticated_stream` builds its codec as
`LengthDelimitedCodec::builder().new_framed(stream)`, setting no
`max_frame_length` and inheriting tokio-util's 8 MiB default. A peer that
completes the RPK handshake — which requires no credential at all, since
authorization happens afterwards at the app layer — can make the node buffer
8 MiB before the first `Authenticate` frame is even decoded. The embedded
transport caps the same thing at 4 KiB (`framing.rs:32`); the host one should
not be looser.

### F6 — Medium. The `own_key` all-zero sentinel is a self-key grant resting on an invariant.

`build_auth_snapshot` falls back to `[0u8; 32]` when no identity seed is
configured, and `decide_access` returns `GrantedSelfKey` whenever
`handshake_key == own_key`. The fallback's comment gives two reasons it is
safe: nothing drives an auth-snapshot request without a TLS listener, and
nothing configures a listener without a seed; and the all-zero key is
"unreachable by any real Ed25519 handshake key".

The first reason is a configuration invariant, and the code already logs a
`warn!` acknowledging it might not hold. The second is weaker than it reads:
all-zeros is a valid Ed25519 point encoding of low order, and `ring` — which
verifies the TLS 1.3 `CertificateVerify` here, not `ed25519-dalek`'s
`verify_strict` — does not reject low-order public keys. Whether a
`CertificateVerify` can be forged under it is not a question worth leaving
open when the type system can close it.

### F7 — Medium. The embedded serial management port has no authentication.

`embedded.rs`'s `serve` decodes a frame and forwards it straight to the router
loop. There is no `Authenticate` first-frame requirement, no `decide_access`,
and no `permits` gate — the whole 22-request surface, including `SetAuth`
(which replaces the node's identity seed *and* trust anchor) and `SetConfig`,
is available to anything that can open the port.

This is documented as unauthenticated in several places and is a deliberate
trade for a device with no other console. It is recorded here because the
authorization model has since grown four tiers on the TLS side, and the
serial port did not move with it: a USB port on a dongle is not the same
trust boundary as a JTAG header.

> **Resolved: the port becomes opt-in, and the gap is accepted.** Not
> authenticated. The shape that would have worked — the node issues a nonce, the
> client signs it with its mesh identity key, and the existing
> `decide_access`/`permits` decide the rest — is a real protocol on a link that
> has no connection boundary to hang it off: a UART has no "client attached"
> event, so the challenge needs its own request, and a nonce that must not
> repeat needs board-supplied randomness because the counter behind it restarts
> at every reboot. That is a meaningful amount of protocol for a port whose
> threat model is *physical access to the device*, which on these boards also
> means access to a SWD header that reads flash outright.
>
> What changes instead is that the port is not live unless a board is configured
> to bring it up, so a dongle does not ship with the whole request surface
> exposed by default. The remaining exposure is stated rather than closed: **a
> node whose serial management port is enabled is a node whose `SetAuth` and
> `SetConfig` are available to anything that can open `/dev/ttyACM*`.** Enabling
> it is an act, and this is what the act means.
>
> Nothing enables it today — the nRF boards' management wiring was removed
> during BLE bring-up and has not returned — so the requirement lands on
> whoever re-wires it, and is recorded in `libs/wayfinder-server/CLAUDE.md`
> beside the transport it governs.

### F8 — Medium. The enrollment token is a bearer secret on a one-second poll.

Already the first item of `05-...`'s untouched §4, restated because F1 and F2
change its reach. `GetSecurityStatusResponse` carries `enrollment_token`, and
the whole response rides `NodeSnapshot` to the browser on every poll. The
`security_never_renders_the_enrollment_token` test asserts absence from the
*markup*, not from the payload.

Two additions to what §4 records: under F1 this is remote disclosure of a
credential that admits nodes to the mesh; and the derived `Debug` on the prost
type will print it in full through any `{:?}`, so it can reach the log ring
that `GetLogs` serves.

**Implemented.** `GetSecurityStatus`/`enrollment_policy()` now report only
`enrollment_token_set`; the value itself comes back solely from a new
`RevealEnrollmentToken` request, answered by `admission()`
(`libs/wayfinder-server/src/authority.rs`). It is a read by shape but a
disclosure by content, so `authz.rs`'s allowlists name it explicitly rather
than folding it into "everything that isn't a mutation" — `permits` refuses it
to `GrantedViewer` alongside `SetLogLevel` (§7 decision 2's tier), and it stays
admin/self-key-only otherwise. The value itself is now a `SharedSecret`
newtype (`wayfinder-protos`) whose `Debug` redacts and whose reader is named
`expose`, so every place it escapes is greppable — the `SharedSecret`/sum-type
half of §4's ask, done as part of this rather than separately. The dashboard's
Provider tab fetches it on demand (`reveal_enrollment_token`) behind a "Show
token" press rather than polling it; see §8.6.

### F9 — Low. The dashboard makes browser-directed outbound connections.

`request_enrollment` dials `ProviderTarget.address` from the SSR process.
Raw-key pinning means an attacker cannot make it speak to a non-Wayfinder
service usefully, but connect/handshake outcomes are distinguishable, which
makes it a port prober from the dashboard host's network position. Reachable
via F2.

### F10 — Low. `require_auth` defaults to `false`.

A node accepts unauthenticated OGMs unless configured otherwise. A documented
compatibility choice, correct when it was made; recorded so flipping it
becomes a scheduled decision rather than an omission.

### F11 — Low. `verify_revocation` checks no validity window.

`TrustAnchor::verify_revocation` checks version, mesh id and signature, and
returns the MAC. The `not_before`/`not_after` window is enforced separately in
`OgmAuth::is_revoked` and `prune_expired`. Correct as currently composed, but
the anchor-level API is the one a new caller reaches for, and its name implies
a completeness it does not have.

### F12 — Low. `/api/{*fn_name}` accepts GET.

No current server function uses a GET encoding, so the arm is unreachable
today. It becomes a CSRF amplifier the moment one does, since a GET endpoint
is forgeable from an `<img>` tag.

### F13 — Informational. Sim config uses a ~3000-year certificate TTL.

`containers/sim.Dockerfile:181` sets `cert_ttl_secs: 100000000000`. Fine for a
simulation; worth a guard rail, because passive expiry is this design's
*primary* revocation mechanism and the value is copy-pasteable.

---

## 3. Remediation plan

### Phase 0 — deployment, today (F1, F2, F12) — **done**

Independent of everything else, and small.

1. **Done.** `ENV WAYFINDER_WEB_LISTEN` is gone from `containers/Dockerfile`;
   the compose `web` service passes `--listen 127.0.0.1:8080` explicitly, so
   the binding is stated where the comment about it lives. The process's
   non-loopback warning is unchanged.
2. **Done.** `build_router` takes a `HostPolicy` and layers two middlewares:
   `known_host_only` (every request; loopback names plus `--listen`'s own
   address plus `--allowed-host`, matched by name with the port ignored) and
   `same_origin_only` (a `Sec-Fetch-Site` other than `same-origin`/`none`, or
   a present `Origin` whose host is not admitted, is a `403`). `--allowed-host`
   is also plumbed through `nix/modules/wayfinder.nix`.
3. **Done.** The `.get(...)` arm is off `/api/{*fn_name}`.

One correction to step 2 as written. **`leptos_routes_with_context` registers
every `#[server]` function at its own exact path and method**, and an exact
route beats the `/api/{*fn_name}` wildcard this crate declares — so a layer
attached "ahead of the server-fn route" is never invoked by a real
server-function call, and the wildcard route itself is a catch-all that no
current call reaches. Both gates are therefore router-wide layers, and
`same_origin_only` decides what to guard from the request: anything with an
unsafe method, plus anything under `/api/`. Ports are not compared, because a
published container port and a reverse proxy both change the port a browser
names while the deployment is unchanged.

Tests: `bins/wayfinder-web/tests/http.rs` gained a case per rule (cross-site,
same-site, foreign `Origin` alone, same-origin allowed, neither header allowed,
foreign `Host` on both a server function and a page route, port ignored,
`--allowed-host` honoured, `GET` refused), and `server.rs` unit-tests the
matching itself.

### Phase 1 — node hardening (F4, F5, F6) — **done**

Landed independently, on `bjc/mgmt-session-hardening`, merged to `main` before
this branch — this branch is built on top of it.

1. **Done.** `transport.rs`'s `AuthGate` re-requests the `AuthSnapshot` and
   re-runs the same `authorize` helper the connect-time decision uses, at most
   once every `REVALIDATE_AFTER` (60 s); a changed verdict closes the
   connection with the same generic `"authentication denied"`. `RevokeNode`
   now reaches an already-open session, and — because the clock is re-read
   alongside it — a certificate expiring mid-session ends that session too.
   Covered by `transport::tests::revalidation_leaves_an_unchanged_verdict_alone`
   and the paired case that closes the connection on a changed one. An
   absolute session-lifetime cap beyond the cert's own `not_after` was not
   added as a separate mechanism — the cert's own expiry, now actually
   enforced by revalidation, *is* that bound.
2. **Done.** `libs/wayfinder-server/src/transport.rs`: `max_frame_length`
   reuses `MAX_FRAME_LEN` (`lib.rs`, the same 4 KiB `framing.rs` uses) on the
   **read** half only — responses stay uncapped, since a routing-table or
   log-page reply is routinely larger than any request, and capping both
   directions with one number would trade a memory bound for a dashboard that
   cannot load. `HANDSHAKE_TIMEOUT` (10 s) wraps `acceptor.accept`.
   `PreAuthLimits` bounds the population of not-yet-authenticated connections
   both mesh-wide and per source IP, refusing rather than queuing at capacity,
   and a connection hands its slot back (`PreAuthGuard::credentialed`) the
   moment it earns a full grant — never on `GrantedEnrollment`, which is
   exactly the population being bounded. The per-IP connection cap reuses
   §3.1 of `05-...`'s bucket shape directly: that type was generalized from
   `EnrollmentLimiter` to `SourceLimiter` with two constructors
   (`for_enrollment()`, `for_connections()`), rather than duplicated — see the
   correction to `05-...`'s file map.
3. **Done.** `AuthSnapshot::own_key: Option<[u8; 32]>`; `decide_access` grants
   `GrantedSelfKey` only on `Some(k) if k == handshake_key`. The all-zero
   fallback, its `warn!`, and the invariant argument are gone — the sentinel is
   unrepresentable rather than merely unreached. Regression test: a handshake
   key of all zeros against a snapshot with no seed must not be granted.

### Phase 2 — enrollment posture (F3, F8, F11, F13) — **done**

1. **Done, in its final rather than its first shape** — see the note under F3.
   `ProviderConfig::auto_approve` (`#[serde(default)]` → `false`, the closed
   posture) replaced the two-field-plus-startup-guard design as written: one
   field spelled so silence is closed, rather than a guard that only governed
   omission in YAML.
2. **Done, and further than proposed.** See F8's "Implemented" note above.
   `RevealEnrollmentToken`, `SharedSecret`, and the sum types on both the read
   side (`RevealEnrollmentTokenResponse::admission`) and the write side
   (`SetConfigRequest`'s `TokenUpdate`, which already existed and is now
   mirrored) are in. §4's proposed fix was to rename the render test to
   describe masking rather than confidentiality; what landed instead removes
   the thing the old name overclaimed, rather than renaming around it — the
   token is no longer on the polled snapshot at all, so there is nothing left
   to mask. The replacement test asserts that directly:
   `provider_renders_no_enrollment_token_because_the_poll_carries_none`
   (`bins/wayfinder-web/tests/render.rs`).
3. **Done.** `TrustAnchor::verify_revocation` (`libs/wayfinder-auth/src/revoke.rs`)
   now takes `now_unix` and checks `not_after` itself, rather than leaving the
   window to callers; `OgmAuth::is_revoked` calls it that way.
4. **Done.** `authority.rs`'s `check_cert_ttl` refuses a `cert_ttl_secs` above
   `MAX_CERT_TTL_SECS` (90 days, `libs/wayfinder/src/config.rs`) unless
   `ProviderConfig::allow_unbounded_cert_ttl` is set — enforced both at parse
   time (`from_config`) and on the runtime `set_enrollment_policy` path, so an
   operator cannot raise it past the cap after startup either.
   `containers/sim.Dockerfile`'s ~3000-year TTL sets the escape hatch
   explicitly rather than relying on an unguarded field.

### Phase 3 — credentials (F1, F2 at the root; F7 resolved separately) — **done except §6 item 4**

§5 and §6 below. Landing in order:

1. **Done.** `CERT_FLAG_USER` and `CERT_FLAG_VIEWER`, `MgmtAccess::GrantedViewer`,
   and `permits`' read-only allowlist — §7 decisions 1 and 2, taken first
   because both live in the signed certificate body.
2. **Done.** The user store at the CA (`wayfinder-server`'s `users.rs`),
   `AuthenticateUser` on the enrollment tier, and CA state version 5 carrying
   the accounts. `wayfinderctl user` administers them offline;
   `wayfinderctl login` / `logout` / `whoami` and the `known_nodes` pin file are
   §6 items 1–3.
3. **§6 item 5 (the dashboard session layer) is done; §6 item 4 (silent
   renewal) is the one thing in this whole document still outstanding.** They
   were always separable from each other and from everything above them.

   §6 item 4 is not the small change its wording suggests. "Re-prompting for
   TOTP only if the refresh window has fully lapsed" means renewing *without*
   re-authenticating, and there is nothing for the certificate authority to
   renew against: `AuthenticateUser` takes a password, and the provider does not
   learn which account an already-issued session belongs to. Making it work
   needs the session's own key to be the proof — a renewal request carrying the
   current certificate and a signature, made with the current session key, over
   the new session public key — plus a `username` on the CA's issued record so a
   MAC maps back to an account. What has landed is the detection half:
   `SessionMeta::due_renewal`, which is what any renewal policy would be built
   on. The dashboard needs it too now, and for the reason §8.5 gives: a session
   certificate simply dies, and "sign in again" is a tolerable answer for
   `wayfinderctl` and not for a dashboard somebody is watching.

   F7 is resolved rather than outstanding — see the note under the finding.

   **§8 records what the session layer turned out to be** — the decision taken
   on the one open question, and the sim work that makes it exercisable.

### Ordering

Phase 0 is hours and removes the remote reachability that makes the rest
urgent. Phase 1 and Phase 2 are independent of each other and of Phase 3.
Phase 3 is the largest and should not block any of them.

---

## 4. Why passwords do not belong on the node

The question this document was asked is whether the management API can stop
requiring certificates by accepting a username and password instead. It can —
but not at the node, for four reasons.

1. **Embedded nodes cannot afford it.** A password verifier worth having is
   memory-hard by construction; Argon2id at any honest parameter set wants
   tens of megabytes. The nRF52840 dongle already resets when a full log ring
   is serialized into its 32 KiB heap.
2. **It would be the only fleet-wide bearer secret in the system.** A password
   that authenticates to node A authenticates to node B. Everything else here
   is scoped, expiring and revocable.
3. **It would need replication.** Credentials would have to reach every node
   and stay consistent — a distributed state problem this project has
   otherwise, deliberately, avoided.
4. **The node's model is already correct.** "A verified, non-revoked admin
   cert bound to this TLS session" is sound, tested, and identical on host and
   embedded targets. The gap is not that the node's check is wrong; it is that
   getting a credential to check is manual.

The credential system therefore belongs one layer up, at the certificate
authority — which is already the single place that decides who belongs to a
mesh, already persists durable state through `CaLog`, and already has an
expiry and revocation story.

## 5. Recommended design: log in to the CA, get a short-lived admin cert

**The shape.** A user proves a username, password and TOTP code to a
provider. The provider returns an admin membership certificate, valid for
hours, bound to a keypair the *client* generated for that session. From that
point the client is an ordinary admin-cert holder and every node authorizes it
through the existing, unchanged `decide_access`.

**What that buys:**

- `authz.rs`, the wire format and the `no_std` core are untouched. Embedded
  nodes never learn what a password is.
- The password is never a bearer token for a node. The certificate is bound to
  a key the client holds; a captured transcript is useless without it.
- Expiry and revocation already work. A session cert expires on its own; a
  compromised one is revoked through `RevokeNode` and the existing flood.
- The audit trail is one place: the CA knows who logged in and what was issued
  (`ListCerts` already exists).

### 5.1 Protocol

One new request on the enrollment tier — which already exists precisely to
admit a client holding no credential:

```proto
// Exchange user credentials for a short-lived administrative certificate.
message AuthenticateUserRequest {
  string username = 1;
  string password = 2;      // Never logged, never persisted.
  string totp_code = 3;     // Empty when the account has no TOTP enrolled.
  bytes  ed_pubkey = 4;     // Client-generated session key.
  bytes  x_pubkey = 5;
}
```

Add `AuthenticateUser` to `permits`' enrollment allowlist — and to
`every_request_kind`, whose count assertion will fail until someone decides.

The response is the existing `EnrollData` (cert + trust anchor) or a flat
rejection. `submit_csr`'s MAC-collision rules do not apply: a user cert binds
to a MAC derived from the session key, so it never contends with a device's.

### 5.2 Verification

- **Password:** Argon2id, `m=64 MiB, t=3, p=1`, per-user random salt. Host-only
  — the CA is already `std`-gated and never linked by an embedded node.
- **TOTP:** RFC 6238, 30-second step, ±1 window, constant-time comparison. The
  ±1 window is a replay window unless the last-accepted step is stored per
  user and reuse rejected — store it.
- **Rate limiting:** per-username *and* per-source, with the per-username
  bucket dominant so an attacker cannot dodge it by changing address. Reuse
  `TokenBucket`; a failed login is far more expensive than a `SubmitCsr`, so
  it wants tighter numbers (say 5 burst, 1 per 30 s) and a lockout past a
  threshold.
- **Uniform failure:** one message for unknown user, wrong password, wrong
  code, and locked account. Same discipline as `MgmtDenied` today.

### 5.3 Should TOTP be required?

Yes, for any account that can mint admin certificates — which, in this design,
is any account at all. The CA is the root of the mesh's trust; a password
alone makes fleet-wide administrative access a phishable secret, and the
enrollment endpoint is reachable by anyone who can route to the provider.

Make it required by default, with an explicit per-account opt-out for
automation accounts that should instead hold a long-lived certificate issued
offline. If a second factor is ever wanted that is stronger than TOTP, the
natural upgrade is WebAuthn at the dashboard, which does not disturb this
protocol.

### 5.4 Storage

Extend `CaLog` with a `users` section — it already provides atomic replace,
rollback on failed persist, `0o600`, and a versioned schema.

```rust
struct UserRecord {
    username: String,
    password_hash: String,     // PHC string; carries its own params + salt.
    totp_secret: Option<Vec<u8>>,
    totp_last_step: u64,       // Replay guard.
    failed_attempts: u32,
    locked_until: u64,
    admin: bool,               // Whether issued certs carry CERT_FLAG_ADMIN.
    disabled: bool,
}
```

Bootstrap is offline, mirroring `cert init-ca`: `wayfinderctl user add
--state <path> --username <name> --admin`, which prompts for a password and
prints the TOTP enrolment URI. The `disabled` flag is what lets an operator
cut off an account without waiting for a certificate to expire.

## 6. Making certificates easy for everyone else

Independent of §5 and worth doing regardless — today a client needs three
flags (`--identity`, `--cert`, `--node-key`) and a manual file-copy dance.

1. **`wayfinderctl login --provider <addr> --user <name>`** — prompts for
   password and TOTP, generates the session keypair, performs §5.1, and writes
   seed + cert to `~/.config/wayfinder/session/` at `0o600`. Every other
   subcommand then finds them with no flags. `wayfinderctl logout` deletes
   them.
2. **A `known_nodes` file.** `Endpoint::load` currently defaults `node_key` to
   the client's *own* public key — a safe default in that it fails closed, but
   it means reaching any node other than during bootstrap requires 64 hex
   characters on the command line. Record the pin per address on first
   connect, behind an explicit prompt that shows the fingerprint, and reuse it
   after. Fail loudly on a changed key.
3. **`wayfinderctl whoami`** — prints the current credential's MAC, admin bit,
   mesh id and expiry. There is currently no way to answer "what am I holding
   and when does it stop working?"
4. **Silent renewal.** The client refreshes when inside the last quarter of
   the certificate's life, re-prompting for TOTP only if the refresh window
   has fully lapsed.
5. **Dashboard session layer.** A login page that performs §5.1 server-side,
   holds the resulting key and certificate in server memory keyed by a session
   id, and issues `HttpOnly; Secure; SameSite=Strict` cookies. The
   process-wide shared identity goes away: no session, no node access. This is
   the root fix for F1 and F2 — `SameSite=Strict` plus the Phase 0 origin
   check closes CSRF, and the loopback bind stops being the only thing
   standing between a stranger and `SetAuth`.

Note this reverses a standing instruction: `bins/wayfinder-web/CLAUDE.md:181`
says a session layer is "a later, separable change — do not" build it. That
instruction is right that it is separable; the findings above are why it
should now be scheduled. Update that file in the same change.

**Implemented — see §8 for the full account of what got built and the one
decision (§8.3) that turned out not to be exactly what this item's wording
said.** In short: `--identity`/`--cert` static mode was kept rather than
deleted, because an un-enrolled node and `--serial` have no provider to log in
to; login mode is used whenever `--provider` is configured. `bins/wayfinder-web/CLAUDE.md`
was rewritten, not merely updated, to describe the security posture that
resulted.

## 7. Open decisions

1. ~~**Does a user certificate need to be distinguishable from a device
   certificate?**~~ **Resolved: yes.** `CERT_FLAG_USER` (0x02) landed
   alongside `CERT_FLAG_VIEWER` in the same change that first issued a user
   certificate, precisely because it is a signed-body change and retrofitting
   it later would mean re-issuing every certificate that predates it. It
   grants nothing on its own; it is what lets `ListCerts` and the Security tab
   tell an operator apart from a node.
2. ~~**Should read-only access be a tier?**~~ **Resolved: yes, and earned by a
   bit, never by the absence of the admin bit.** `CERT_FLAG_VIEWER` (0x04) and
   `MgmtAccess::GrantedViewer` sit between the enrollment tier and the two full
   grants; `authorize_admin` became `authorize_capability`, returning which
   tier a verified certificate earns. The design's own wording above said "a
   verified certificate that is not an admin" — that is *not* what landed,
   deliberately: every device on the mesh already holds a verified non-admin
   certificate, so a tier granted by absence would have handed every node
   read access to every other node's management API in one release, with
   nothing in any configuration changing to say so. A certificate carrying
   neither bit stays denied exactly as it does today. `RevealEnrollmentToken`
   and `SetLogLevel` are refused to a viewer even though the first reads like
   a query and the second like a debugging convenience: the first is a read by
   shape but the mesh's admission credential by content, and the second
   changes what every sink on the node emits rather than merely observing one.
   `authz.rs`'s viewer allowlist is written as an explicit refusal set over
   the admin allowlist, not as "everything that isn't a mutation", so a
   request that merely looks like a read still has to be classified on
   purpose.
3. ~~**How long is a session certificate valid?**~~ **Resolved: per account,
   not a constant.** `UserRecord::session_ttl_secs` is chosen by the admin who
   grants the account, so an automation account can be minutes and a field
   operator a shift, and neither is a code change — still bounded by
   `MAX_CERT_TTL_SECS`. Phase 1's revalidation fix (F4) is what makes a short
   TTL actually mean something: before it, expiry stopped a *new* connection
   but not one already open.
4. **Where does the CA live in a multi-provider mesh?** This design assumes
   one provider holds the user store. Two providers with different user stores
   both signing for the same mesh id is a state this document does not model.
   Still open — nothing in Phase 3 addresses it.

---

## 8. What the session layer turned out to be

Written as notes for the next pass after §5/§6.1–6.3 landed, and rewritten here
as the record of what was built. §6.5 and the sim accounts are done; §6.4 is
what remains, for the reason §8.5 already gave.

### 8.1 What `wayfinder-web` was

`main.rs` built **one** `Target::Tls(Endpoint)` from `--identity` / `--cert` /
`--node-key` (or `Target::Serial`), wrapped it in a single `NodeConnection`, and
put that in the axum state. Every `#[server]` function reached it through
`api.rs`'s `connection()`, which pulled it out of the Leptos context.

So the credential was **process-wide and singular**, which is exactly F1 and
F2's root: anyone who could reach the port had whatever access that one identity
carried, and there was no per-viewer state for a forgery to be missing.

### 8.2 What replaced it

`session.rs` holds an `Access`, and the axum state holds that instead of a
connection:

- **A `SessionStore`** keyed by a random session id, each entry holding *its
  own* `NodeConnection` built from the seed and certificate a login produced,
  plus the username, the capability and the certificate's `not_after`. One
  connection per session and not one per process, because the management API
  authenticates at the TLS handshake — a shared connection would hand every
  viewer the first viewer's access.
- **`connection()` resolves the cookie**, and its absence is a distinct sentinel
  (`session::NEEDS_LOGIN`) rather than a node failure, so a browser can render
  "sign in" instead of "the node is unreachable". The polling loop watches for
  it and re-asks who the viewer is, which is what turns an expiring session into
  a sign-in form rather than a stream of failures.
- **`login` / `logout` / `session` server functions and a sign-in page.**
  `login` performs §5.1 server-side: generate a session keypair, connect to the
  provider anonymously on the enrollment tier, `AuthenticateUser`, build the
  `NodeConnection`, store it, set the cookie.
- **Expiry pruning** on every read of the store, so a long-running dashboard
  does not accumulate an entry — and a connection — per login for its whole
  life.
- **`--provider` and `--provider-key`**, the latter defaulting to `--node-key`
  (correct when the node being viewed is itself the authority). `--provider` is
  what *selects* login mode, rather than defaulting from `--addr`: see §8.3.

One thing the notes did not anticipate. **`<Routes>` has to stay in the view
tree unconditionally.** `generate_route_list` walks the app once at startup —
with no request, and so no session — to discover the routes to register, so
`<Routes>` behind "is anyone signed in?" registers nothing and every tab but the
index answers 404, in both modes, from the first boot. The dashboard is
therefore rendered and *hidden* for a signed-out viewer, with the sign-in form
over the top. It costs nothing: no tab fetches anything of its own, and the
polling loop does not run while signed out.

### 8.3 The decision that was taken

§6 item 5 said "the process-wide shared identity goes away". Taken literally
that breaks two cases, and both are cases where a dashboard is the *only* way
in:

- **An un-enrolled node.** It has no user store, so no login is possible against
  it — and self-key bootstrap is precisely why `MgmtAccess::GrantedSelfKey`
  exists ("a dashboard that reached an un-enrolled node has no other credential
  it could hold"). `topology.py --open N` produces exactly this.
- **`--serial`**, which has no authentication at all and no provider behind it.
- **A node provisioned and then taken offline**, which is the case below.

**Resolved: `--identity` / `--cert` stay, as an explicit static-credential
mode**, warned about at startup as *not* closing F1 and F2, with login as the
path whenever a provider is configured. `--provider` is the switch, and it
conflicts with `--identity`/`--cert`/`--serial` so a process is never in two
minds about which credential it holds.

#### Signing in needs the certificate authority. Using a session does not.

A worthwhile question, because the answer is not symmetric:

- **An existing session survives a partition entirely.** The node verifies the
  session certificate against the trust anchor it already holds — no contact
  with the provider, no revocation lookup beyond the flooded records it already
  has — so a dashboard signed in before the link dropped keeps working until the
  certificate expires.
- **A new sign-in does not.** `AuthenticateUser` is answered by the provider and
  nowhere else, because the password verifier is Argon2id at 64 MiB and the user
  store is one store on purpose (§4). No provider reachable, no new session.
- **And a dashboard restart is a new sign-in.** The session store is in the
  `wayfinder-web` process's memory and is not persisted, deliberately — a
  session key written to disk is a credential outliving the process that earned
  it — so restarting the dashboard while the provider is unreachable locks
  everyone out until it comes back.

#### The credential file (`.wfauth`) — implemented

The third point above is what the credential file answers, and it answers it
without contradicting the second: the session key is still never written to
disk *by the process*. It is handed to the **person**, who decides where it
lives.

A signed-in viewer downloads `<user>-<expiry>.wfauth` — that session's seed and
the certificate the provider signed for it, as JSON — and hands it back to the
sign-in form later. The dashboard rebuilds a session out of it with no contact
with the provider whatsoever. Four things make that sound rather than a hole:

- **Nothing is asserted by the file that the node does not re-check.** The
  capability shown is recomputed from the certificate's signed flags, never read
  from the file's own note of it, and the certificate is worth exactly what the
  mesh root's signature makes it worth. The dashboard holds no trust anchor and
  does not pretend to: it proves the credential by *using* it, with one
  read-only RPC, before any session exists.
- **It expires when the session it came from does.** There is no new certificate
  and no extension of anything — which is why the expiry is in the filename. An
  operator heading into the field still wants `session_ttl_secs` set to days,
  the knob this section already describes; the file is what carries that session
  across a dashboard restart, not what lengthens it.
- **It is served only to the session it belongs to**, and never in static mode,
  where the credential belongs to the process rather than to a person.
- **It is a private key in a file, stated as such** — to the person downloading
  it, in the panel that offers it. That is the trade, and it is a smaller one
  than the alternative this section previously pointed at: provisioning a
  *shared* admin certificate into static mode, which has no per-person identity
  behind it and cannot be revoked without restarting the process.

What it does not change: a **new** sign-in, by somebody who never had a file,
still needs the provider. There is no offline password verification and this
does not invent one.


There is no step that "links a password to a certificate" ahead of time. An
admin creates the account offline against the provider's state file
(`wayfinderctl user add`), and the certificate is minted *at* sign-in, bound to
a keypair the client generates then — which is what makes a captured login
transcript worthless and a session revocable and expiring.

So for a node that is provisioned and then goes offline for good — never having
been signed in to, so with no `.wfauth` file to carry — the answer is not "log
in anyway", it is **provision the credential too**: issue a certificate offline
with `wayfinderctl cert issue --admin` (or `--viewer`) and start that node's
dashboard in static mode with it. That is a deliberate trade — one shared
credential, expiring on whatever window it was issued with, with no per-person
identity behind it — and it is the trade an air-gapped node is making anyway.

Two knobs soften the merely *intermittent* case, where the provider is reachable
sometimes:

- **Session lifetime is per account** (`UserRecord::session_ttl_secs`), so an
  operator heading into the field can hold an account granted days rather than
  the eight-hour default, and sign in before departure.
- **§6 item 4 (silent renewal)** keeps a session alive across the windows when
  the provider *is* reachable, rather than making the operator notice.

What this design does not model is a second provider holding a replica of the
user store, which is what "sign in at the edge" would really require — §7 open
decision 4.

### 8.4 Sim accounts (`scripts/topology.py`)

Done, and it needed two things beyond minting the accounts:

- **`wayfinderctl user add --password-stdin`.** The prompt reads `/dev/tty`, not
  stdin, so a script that pipes a password does not supply one — it blocks on
  whatever terminal it inherited.
- **The provider's state file is seeded on the host and bind-mounted in**, as a
  *directory* (the durable store renames a temporary file over the snapshot, and
  a single-file bind mount has no "beside it" to write into), through a
  `CA_STATE_PATH` the sim image now honours. It has to be seeded before the
  stack comes up: the provider holds that state in memory and rewrites the whole
  snapshot, so an account added to a running provider is overwritten by its next
  write.

Two accounts, `admin` and `viewer`, both `--no-totp` — a simulation has nowhere
to enrol an authenticator, and the flag exists for exactly this. A viewer
account is the only way to see `MgmtAccess::GrantedViewer` end to end, and the
tier is otherwise unreachable in the sim.

Each secured node's dashboard now runs in login mode against the provider; the
open nodes keep their static credential, which is what §8.3 is about. The
`--session` flag the notes proposed is unnecessary as a result — it was a way to
point a dashboard at a logged-in session *before* login mode existed.

### 8.5 Why §6.4 follows rather than leads

An eight-hour session certificate currently just dies, and the CLI's answer is
"log in again". That is tolerable for `wayfinderctl` and not for a dashboard
somebody is watching, so silent renewal became user-visible the moment §6.5
landed — but it could not be built first, because it needs the renewal protocol
described under Phase 3 item 3 and that is independent of either.

### 8.6 The Security tab split in two, and offline issuance caught up to it

Two more pieces landed after §8.1–§8.5 were written, both downstream of §6.5
rather than new decisions.

**The Security tab split into Security and Provider.** It had grown to answer
two different questions at once — who this node believes it is and who it
trusts, versus who else it lets in — and only nodes running as a certificate
authority need the second half at all. `components/security.rs` kept the
first: identity, neighbours, the enrollment panel a *joining* node uses to ask
a provider to certify it. `components/provider.rs` is new and holds the
second: the account roster, the enrollment policy switch, the join details
(address, pinned key, token) a joining node needs to be told, and the queue of
held CSRs waiting on approval. The whole tab is gated on one fact from the
poll — whether the node reports an enrollment policy at all — so a node that
is not a provider gets one sentence saying so, not four empty panels. The
split is documentation as much as refactor: `bins/wayfinder-web/CLAUDE.md` now
states the same two-questions framing as the reason the file boundary exists,
so it does not drift back together the next time someone reaches for "add one
more thing to the Security tab".

The Provider tab is also where §6.5's "account creation is still offline"
softened, on purpose and with a stated trade: an admin session can now call
`CreateUser`/`ListUsers`/`RemoveUser` from the browser, so `wayfinderctl user
add` on the provider host remains the only way to bootstrap the *first*
account, not every account after it. The proto comment on `CreateUserRequest`
states the trade rather than leaving it implicit: an admin can already revoke
nodes and rewrite enrollment policy, so this grants no new *class* of power,
but it does put the user store on the network for the first time. A TOTP
enrolment URI is shown once, at creation, because the CA does not retain the
secret in a recoverable form — the panel says plainly that it will not be
shown again. `MeshAuthority::remove_user` (the API-reachable path, unlike the
unguarded `CertAuthority::remove_user` that `wayfinderctl user remove` calls)
refuses to remove the last account able to administer the mesh, so the
dashboard cannot be used to strand itself; the tab surfaces that refusal as an
ordinary error rather than pre-computing the rule in the browser, per this
crate's "the node is the authority" convention.

**Offline issuance grew the same two bits.** `wayfinderctl cert issue
--viewer` (mutually exclusive with `--admin`, which subsumes it) reaches
`CERT_FLAG_VIEWER` without a login round trip at all, and `cert show` now
prints a certificate's capabilities unconditionally rather than only its admin
bit — both needed once a certificate could carry a capability a quick glance
at "is this an admin cert" would no longer answer. This is what makes §8.3's
"provision the credential too" answer for an air-gapped node complete: an
operator can now hand out a read-only credential offline exactly as easily as
an admin one.

**The sign-in form carries the `.wfauth` upload as a fourth field, not a
second form.** `components/login.rs` collects user name, password and TOTP
code plus a file picker, under one "Sign in" button live once *either* a
complete password answer or a chosen file is present — `credential_route`
decides which at submit time, and the file wins if both are filled, because a
password manager fills the first two fields unprompted while choosing a file
is a deliberate act. The two paths' failure modes are asymmetric on purpose:
the password path answers "those credentials were not accepted" for every
cause (§5.2's uniform-failure rule extends to the browser), while a rejected
file names what was wrong — expired, wrong node, malformed — because there is
no account to enumerate by being specific about someone's own key.
