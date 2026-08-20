# libs/wayfinder-server

The management-API server. Three layers in one crate, split by feature so an
embedded node links only what it can run.

| Layer | Feature | Files |
|---|---|---|
| `RouterAdapter` — projects a borrowed `CentralRouter` onto `WayfinderDataProvider` | always (`no_std` + `alloc`) | `adapter.rs`, `provider.rs`, `authz.rs`, `settings.rs` (trait half) |
| host transports — authenticated TLS over TCP, plus an in-process channel | `std` (default) | `transport.rs`, `tls.rs`, `authority.rs`, `persistence.rs`, `users.rs`, `settings.rs` (`SettingsFile`) |
| embedded transport — length-delimited frames over `embedded-io-async` | `embedded` | `framing.rs`, `embedded.rs` |

`std` and `embedded` are mutually exclusive in practice — a target picks one.
The embedded node reuses the *adapter*, not the transport.

Entry points for the host transport are `bind_tcp_server` (bind the listener),
`serve_tls_server` (accept + handshake + serve), `serve_authenticated_stream`
(one already-accepted stream), and `run_channel_server` (in-process). There is
no Unix-datagram or UDP listener — earlier docs referenced `run_unix_server` /
`run_udp_server`, which no longer exist.

## The query channel, and why the router is never shared

`QueryTx`/`QueryRx` (and their `embassy-sync` twins `EmbeddedQueryTx`/`Rx`)
exist so the router is owned by exactly one task. Listener tasks accept
connections concurrently, but they do not touch `CentralRouter` — they forward a
request over the channel and await a oneshot reply. The driver's event loop
services it between frames.

This is the constraint to respect when adding anything here: **nothing outside
the driver loop may hold a `&mut CentralRouter`.** If a new feature seems to
need one, it needs a new request kind, not a lock.

## `RouterAdapter` and the eleven const generics

`RouterAdapter` is generic over `CentralRouter`'s eleven capacity parameters, so
`adapter.rs` spells them out three times (~40 lines of pure boilerplate). This
is a known wart, not a pattern to imitate — see the root `CLAUDE.md` capacity
notes. If you are adding a method, copy the existing generic header verbatim
rather than inventing a shorter one.

The adapter borrows the router (`&'a mut`) and evaluates time-varying metrics at
a caller-supplied `now`, the same monotonic instant the driver stamps on
received frames. Don't call `Instant::now()` inside it — a metric read at a
different clock than the frames it describes is how throughput graphs go
subtly wrong.

## Authentication vs. authorization

Deliberately separated, and the boundary matters:

- **Authentication** is at the transport (`tls.rs`): rustls with **raw public
  keys** (RFC 7250, no X.509) — the client proves possession of its Ed25519
  mesh identity in the handshake. The TLS verifier deliberately checks *only*
  key possession; it does not decide who you are.
- **Authorization** is `authz.rs`: a pure decision over already-verified inputs
  (`decide_access` → `MgmtAccess`), with no transport and no crypto, so the
  policy is unit-testable standalone and identical across transports.

Four grant tiers:

- `GrantedAdmin` — a verified, non-revoked admin cert bound to the handshake key.
- `GrantedSelfKey` — the client proved possession of the node's *own* key. A
  node with no identity seed has **no** own key (`own_key: Option<[u8; 32]>`),
  so the tier is simply unavailable there rather than resting on a sentinel
  value being unpresentable — the all-zero key it used to compare against is a
  valid Ed25519 encoding of a low-order point, and `ring` verifies the TLS
  `CertificateVerify` here, not dalek's `verify_strict`. How
  you configure a fresh node, and it holds **whether or not the node is
  enrolled**: whoever has that seed already is the node on the mesh, and a
  dashboard that reached an un-enrolled node has no other credential it could
  hold, so revoking this at the moment of enrollment would lock out the operator
  who just enrolled it. (An earlier rule did exactly that; the reversal is
  deliberate and documented on `decide_access`.) The comparison value
  (`own_key`) is read fresh from the driver's identity-seed slot on every
  connection (`AuthSnapshot::own_key`, `RouterAdapter::set_auth` writes through
  it) rather than cached at listener startup, so a seed a `SetAuth` rotates
  away from stops earning this grant on the very next connection.
- `GrantedViewer` — a verified, non-revoked cert carrying `CERT_FLAG_VIEWER`.
  Read-only: `permits` confines it to the queries and refuses every mutation
  plus `RevealEnrollmentToken`, which is a read by shape and the mesh's
  admission credential by content. **Earned by the bit, never by the absence of
  the admin bit** — every device on the mesh holds a verified non-admin
  certificate, so a tier granted by absence would be a tier the whole mesh
  already had. A cert with neither bit is `Denied(NoCapability)`.
- `GrantedEnrollment` — the client presented no cert at all. Admitted, but
  `permits` confines it to `SubmitCsr`, `GetTrustAnchor` and
  `AuthenticateUser`.

**Admission is per-connection; what an admitted client may invoke is
per-request.** The two full grants may invoke everything, so `permits` is really
the definition of the other two. The enrollment tier exists because enrollment
is otherwise impossible: a provider worth enrolling with is itself an enrolled
member, so a node with no cert could never open the connection carrying its CSR
— and, for the same reason, someone who has not logged in yet could never open
the connection carrying their password. Admission control for it has not moved:
the enrollment token and the operator's approval for a CSR, the password, the
second factor and the per-account lockout for a login.

**Authorization is revalidated, not snapshotted.** An authenticated connection
re-requests the `AuthSnapshot` and re-runs `decide_access` every
`AUTH_REVALIDATION_INTERVAL`; a changed verdict closes the connection with the
same flat `"authentication denied"`. That is what makes `RevokeNode` reach an
open session, and — because the clock is re-read with it — what makes a
certificate expiring mid-session end that session. Before the handshake,
`PreAuthSlots` bounds the population of not-yet-authenticated connections
mesh-wide and per source IP, and refuses rather than queues at capacity;
reads are capped at `MAX_FRAME_LEN` while responses are not, because a routing
table is not a request and is not reachable before authentication.

**Admission is decided again while the connection is open.** A connection has
no bound, so deciding once at connect made `RevokeNode` a statement about
*future* connections only, and an admin certificate that expired mid-session
stayed honoured. `AuthGate` re-reads the router's auth state and re-runs the
same `authorize` helper before serving a request, at most once every
`REVALIDATE_AFTER` (60 s); a changed verdict closes the connection. Two things
follow for anyone editing this: the connect-time decision and the revalidation
must stay *one* function (they are — `authorize`), and a failure to reach the
router loop or read the clock closes the connection rather than extending the
last decision.

**What an unauthenticated peer may consume is bounded** (`PreAuthLimits`), and
this is not the same population as "connections". Completing the handshake
proves possession of *a* key, not of an authorized one, so every connection
starts uncredentialed; the cap is on that population, and a connection hands
its slot back (`PreAuthGuard::credentialed`) the moment it earns
`GrantedAdmin`/`GrantedSelfKey` — never on `GrantedEnrollment`, which is
precisely the population being bounded. Alongside it: a per-source connection
rate limit (the same `SourceLimiter` the enrollment tier's `SubmitCsr` uses), a
handshake timeout, and `MAX_FRAME_LEN` on the **read** half only. That last
asymmetry is deliberate — a host node's routing table or log page is routinely
larger than any request, so capping both directions with one number would trade
a memory bound for a dashboard that cannot load.

Denials (a cert that failed) return a deliberately generic
`"authentication denied"` over the wire while the precise reason stays in a
local `warn!` — an unauthenticated peer must not get an oracle distinguishing
wrong-key / revoked / expired / not-admin. A *per-request* refusal on an
enrollment connection does say why: that peer is already admitted and learns
nothing it could not learn by trying, while a client that merely forgot its
certificate would otherwise see every request fail with no explanation.

## Provider mode (the CA)

A node in provider mode answers enrollment (`GetTrustAnchor`, `SubmitCsr`,
`RevokeNode`) by delegating to the `MeshAuthority` trait (`provider.rs`). The
trait is byte-oriented on purpose so it stays `no_std + alloc`; the concrete
`CertAuthority` holding the mesh root key is `std`-only (`authority.rs`) and is
injected into `RouterAdapter` by the host driver.

`persistence.rs` snapshots the issued-cert log and held CSRs so the
impersonation guard, revocations, and pending approvals survive a restart. Two
things about it:

- The on-disk schema is JSON with an explicit `CURRENT_STATE_VERSION`, kept
  **independent of the protobuf wire format** so the two evolve separately.
- Mutation goes through `wayfinder_storage::Persisted` — mutate, persist, roll
  back in memory if the persist failed. Do not add ad-hoc `persist()` calls
  alongside a direct field write; that ordering is the whole point of the type.

**A provider's enrollment posture is one field, spelled so that silence is
closed.** `ProviderConfig::auto_approve` (`#[serde(default)]` → `false`)
decides whether a submitted CSR is signed on the spot or parked as pending for
an operator; omitting it gets the queue. That direction is the whole reason it
is not spelled `require_approval`: signing a certificate for whatever MAC and
keys an anonymous client names is a legitimate configuration for a closed lab
or the simulation, and not one anybody should reach by leaving a field out of a
YAML file. There is deliberately **no** startup guard to add here — the default
*is* the guard, and a second acknowledgement flag beside it was the redundancy
this replaced. `enrollment_token` composes with the posture rather than
substituting for it: the token says who may ask, `auto_approve` says whether
asking is enough.

The posture inverts across three boundaries, each of which has a comment saying
so — do not "simplify" any of them away. On the wire, field 1 of
`EnrollmentPolicy`/`EnrollmentPolicyStatus` is `reserved` and the posture moved
to field 5, so a version-mismatched peer reads "not reported" rather than the
posture backwards. On disk, state version 4 replaced version 3's
`require_approval` override, and `migrate_v3_to_v4` inverts it rather than
dropping it (an operator who pinned "hold every request" must not come back
from an upgrade signing for whoever asks). The dashboard inverts on purpose:
its switch is "Approve each request by hand", because a control you turn *on*
to add a check reads right.

`from_config` does refuse a `cert_ttl_secs` past `MAX_CERT_TTL_SECS` (90 days)
without `allow_unbounded_cert_ttl` — passive expiry is this design's *primary*
revocation mechanism, so a certificate that outlives the deployment cannot be
recalled without reaching every node. That cap is enforced on the runtime path
(`set_enrollment_policy`) too.

**The enrollment token is handed out by request, not by poll.**
`enrollment_policy()` reports only *whether* a token is set; `admission()`
returns the value, and it is reached through `RevealEnrollmentToken` alone.
`GetSecurityStatus` rides a once-a-second dashboard poll, so a secret on it is
disclosed continuously to everything that touches the snapshot — including the
log ring, through any `{:?}`. The value is a `SharedSecret` (`wayfinder-protos`)
whose `Debug` redacts and whose reader is named `expose`, so every place it
escapes is one a search finds.

## The embedded serial port is unauthenticated, and opt-in because of it

`embedded.rs`'s `serve` decodes a frame and forwards it to the router. There is
no `Authenticate` first-frame requirement, no `decide_access` and no `permits`
gate — the whole request surface, `SetAuth` and `SetConfig` included, is
available to anything that can open the port. That is a resolved decision
(F7 in `docs/design/06-management-api-authentication.md`), not an oversight
waiting to be fixed: the port's threat model is physical access to the device,
which on these boards also means access to an SWD header that reads flash
outright, and a challenge-response would be a real protocol on a link with no
connection boundary to hang it off.

What follows is a requirement on whoever wires the port up: **bring it up only
when a board is configured to, never unconditionally.** Enabling it is an act
that means "this node's identity and configuration are available over
`/dev/ttyACM*`", and it should read that way at the call site. Nothing enables
it today — the nRF boards' management wiring was removed during BLE bring-up
and has not returned.

## The user store (`users.rs`)

Named accounts that can be exchanged for a short-lived management certificate,
at the CA and **never at a node**. The reasons are structural, not incidental:
Argon2id at any honest parameter set wants tens of megabytes against a dongle's
32 KiB heap; a password would be the only fleet-wide bearer secret in a system
where everything else is scoped, expiring and revocable; and it would have to be
replicated to every node. `AuthenticateUser` returns an ordinary membership
certificate, so `decide_access`, the wire format and the `no_std` core are
untouched and an embedded node never learns what a password is.

Four rules to keep when touching it:

- **A failed login is one answer.** Unknown account, wrong password, wrong
  code, locked and disabled are all `AuthOutcome::Rejected`, and
  `spend_absent_user_work` spends the same Argon2 work for an account that does
  not exist — a uniform answer is no use if the timing answers instead.
- **Every attempt is persisted**, success or failure. The failure counter and
  the lockout live in the record; a failed attempt that is not durably counted
  is a lockout an attacker can reset by making the process restart.
- **A TOTP code is spent once.** The ±1-step skew window makes three codes live
  at any instant, so `totp_last_step` is what stops one seen in transit from
  being reused.
- **The session lifetime is the account's**, chosen by the admin who granted it
  (`UserRecord::session_ttl_secs`), not a constant here — still bounded by
  `MAX_CERT_TTL_SECS`.

Accounts are administered offline, by `wayfinderctl user` against the state
file, for the same reason `cert init-ca` is: the first account cannot be created
over the management API, because creating it needs the credential it creates.

## Persisting a runtime security setting

Two stores, split by *what owns the thing*, not by convenience:

- **The enrollment policy** rides the CA snapshot (`persistence.rs`), next to
  the certificates it governs. `CertAuthority::set_enrollment_policy` records
  the override, then re-runs `apply_policy_overrides` — the same overlay a
  restart performs, so the live path and the restart path cannot drift apart.
- **Everything node-wide** (the fail-closed gate, lazy cert distribution, an
  identity installed by `SetAuth`) goes to `settings.rs`, injected into
  `RouterAdapter` via `.with_settings(...)` by the host driver, exactly as the
  CA is.

Both stores hold **overrides**, never values: `None` means "the operator never
changed this", so the startup config still governs it and deleting the state
file returns the node wholly to its YAML. A field that stored the effective
value instead would freeze the config out permanently after one edit.

Two rules for anything added here:

- **Persist before applying.** A change that could not be recorded must not be
  running: the request fails and the node keeps its previous state. Applying
  first would leave a setting live that the next restart silently discards,
  which is precisely the failure this exists to prevent.
- **Per-interface knobs stay in memory.** Trickle bounds and participation
  gates are keyed by an index into the startup config's link list, so a stored
  override would re-point at a different link the moment an operator reorders
  one. `set_config` deliberately does not persist them.
