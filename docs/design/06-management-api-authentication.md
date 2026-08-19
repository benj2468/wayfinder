# Design: management-API security review and user credentials

**Status:** proposed; **Phase 0 implemented** (see §3). Phases 1–3 unstarted.
Supersedes nothing; extends
`05-enrollment-tier-security-hardening.md`, whose §4 backlog is folded in
below as F8.

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
  sweeps a hand-maintained list of all 22 request kinds with a count assertion,
  so adding a proto request forces a decision here.
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
  and `EnrollmentLimiter` per source IP.

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
authorization model has since grown three tiers on the TLS side, and the
serial port did not move with it: a USB port on a dongle is not the same
trust boundary as a JTAG header.

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

### Phase 1 — node hardening (F4, F5, F6)

1. **Revalidate authorization periodically.** Re-request the `AuthSnapshot`
   and re-run `decide_access` every N requests or T seconds (T ≈ 60), and on a
   changed verdict close the connection with the same generic error. This is
   the fix that makes `RevokeNode` mean what operators think it means. Add an
   absolute session lifetime capped at the presented cert's `not_after`.
2. **Bound the pre-auth surface.** `max_frame_length(MAX_FRAME_LEN)` on the
   host codec — reuse `framing.rs`'s 4 KiB rather than inventing a second
   number; a `tokio::time::timeout` around `acceptor.accept`; a
   `tokio::sync::Semaphore` capping in-flight unauthenticated connections;
   and a per-IP connection cap reusing `EnrollmentLimiter`'s bucket shape.
3. **Make the sentinel unrepresentable.** `AuthSnapshot::own_key:
   Option<[u8; 32]>` and `decide_access(own_key: Option<&[u8; 32]>)`, granting
   `GrantedSelfKey` only on `Some(k) if k == handshake_key`. Deletes the
   fallback, the `warn!`, and the argument. Add the regression test: a
   handshake key of all zeros against a snapshot with no seed must not be
   granted.

### Phase 2 — enrollment posture (F3, F8, F11, F13)

1. Make `ProviderConfig` require an explicit admission decision: reject a
   provider config that sets neither `enrollment_token` nor
   `require_approval: true` unless it also sets `auto_approve: true`. An
   operator who wants TOFU says so; nobody gets it by omission. *(Implemented
   as written, then superseded — see the note under F3. The goal held; the
   two-field-plus-guard shape did not.)*
2. Move `enrollment_token` off `GetSecurityStatusResponse` onto its own
   `RevealEnrollmentToken` request, so disclosure is a discrete, logged,
   admin-gated act. Replace the `bool` + `Option<String>` pair with the sum
   type §4 proposes, and give it a `SharedSecret` newtype with a redacting
   `Debug`. Rename the render test as §4 says.
3. Fold the window check into `verify_revocation` (taking `now_unix`, as
   `verify_cert` already does), and have `OgmAuth` call it that way.
4. Cap `cert_ttl_secs` at parse time (say 90 days) with an
   `i_know_what_i_am_doing` escape the sim sets.

### Phase 3 — credentials (F1, F2, F7 at the root)

§6 below.

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

## 7. Open decisions

1. **Does a user certificate need to be distinguishable from a device
   certificate?** `CERT_FLAG_ADMIN` is the only capability bit today. A
   `CERT_FLAG_USER` would let `ListCerts` and the security tab tell an
   operator apart from a node — but it is a signed-body change, so it wants
   deciding before the first user cert is issued, not after.
2. **Should read-only access be a tier?** `permits` has two full grants and
   one enrollment grant. A viewer who can read the routing table but not
   `SetAuth` is an obvious want once there are named users, and it is a
   cheaper change to make while `permits` is already being edited.
3. **How long is a session certificate valid?** Eight hours matches a shift
   and bounds a stolen key. It also means the TOTP prompt recurs daily, which
   some operators will route around. F4's fix makes a shorter TTL practical by
   making expiry actually terminate a live session.
4. **Where does the CA live in a multi-provider mesh?** This design assumes
   one provider holds the user store. Two providers with different user stores
   both signing for the same mesh id is a state this document does not model.
