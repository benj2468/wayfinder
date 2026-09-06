# libs/wayfinder-server

The management-API server. Four layers in one crate, split by feature so an
embedded node links only what it can run.

| Layer | Feature | Files |
|---|---|---|
| `RouterAdapter`/`RouterView` — project a borrowed `CentralRouter` onto `RouterWrites`/`RouterReads` | always (`no_std` + `alloc`) | `adapter.rs`, `authz.rs`, `settings.rs` (trait half) |
| `RouterHandle` — the shared read lock the management reads are served from | `std` | `router_handle.rs` |
| host transports — authenticated TLS over TCP, plus an in-process channel | `std` (default) | `transport.rs`, `tls.rs`, `authority.rs`, `persistence.rs`, `users.rs`, `settings.rs` (`SettingsFile`) |
| the certificate authority's own task — `AuthorityAdapter` onto `AuthorityDataProvider` | `std` | `authority_task.rs`, `provider.rs` (the `MeshAuthority` trait half, compiled always so it stays `no_std`) |
| embedded transport — length-delimited frames over `embedded-io-async` | `embedded` | `framing.rs`, `embedded.rs` |

`std` and `embedded` are mutually exclusive in practice — a target picks one.
The embedded node reuses the *adapter*, not the transport.

Entry points for the host transport are `bind_tcp_server` (bind the listener),
`serve_tls_server` (accept + handshake + serve), `serve_authenticated_stream`
(one already-accepted stream), and `run_channel_server` (in-process). There is
no Unix-datagram or UDP listener — earlier docs referenced `run_unix_server` /
`run_udp_server`, which no longer exist.

## Reads are shared; mutations are not

The rule here used to be *nothing outside the driver loop touches
`CentralRouter`*. It is now narrower, and the narrowing is the point:

> **Nothing outside the driver loop may hold a `&mut CentralRouter`.** A shared
> `&` is fine, and is how every management *read* is served.

Sixteen of the nineteen router-facing answers take `&self`. Serving those on the
loop meant a dashboard polling seven tables a second built seven response `Vec`s
between mesh frames, one at a time, behind a depth-16 channel. `RouterHandle`
(`router_handle.rs`) gives them a read lock instead, so they run on the
connection's own task and concurrently with each other. Its module doc has the
honest accounting — including the part that has *not* changed, which is that a
large read still contends with the loop for the lock.

The three mutations (`SetAuth`, `SetConfig`, `SetLogLevel`) still travel
`QueryTx`/`QueryRx` to the loop, and should. They are operator actions rather
than polls, so there is nothing to win; and `set_auth` writes back through the
identity-seed slot that lives beside the router under the same lock, which only
the loop's write guard reaches.

**The split is enforced by types, not by discipline.** `RouterDataProvider` is
now `RouterReads` (`&self`) + `RouterWrites` (`&mut self`), and
`handle_router_read` takes `&P`. `RouterView` — the shared-borrow projection
behind the handle — implements only `RouterReads`, so a mutation routed to the
read path is a compile error, not a runtime string. `RequestFacet` splits the
same way (`RouterRead`/`RouterWrite`) so a transport knows which borrow a
request needs before it sends anything, exactly as design 13's facet fork tells
it which *owner*.

Two rules for anything added here:

- **A new `&self` answer goes on `RouterReads`**, and is then automatically
  served off the loop. A new `&mut self` one goes on `RouterWrites` and stays on
  it. Declare which in `rpc_table!`; there is no third option.
- **Never hold a router guard across an `await` that does I/O.** The driver's
  `dispatch` is the worked example: it takes the write guard to *plan* a frame,
  drops it before the link send (a LoRa transmission is not a moment), and takes
  it again to record the bytes sent. `Driver::with_router`/`with_router_mut` are
  scoped callbacks rather than returned guards for the same reason.

The embedded transport keeps the channel unchanged (`EmbeddedQueryTx`/`Rx`).
A board's executor is cooperative and single-core and its management port is one
serial connection issuing one request at a time, so there is no concurrency for
a lock to recover — and the `no_std` half of this crate stays free of one.

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

The sixteen reads do not actually live on `RouterAdapter`: they are implemented
once on `RouterView`, which holds a shared `&CentralRouter`, and the adapter
delegates to a view it builds from its own `&mut`. That is what lets a
connection task answer them without the `&mut` the adapter requires. Add a read
to `RouterView`; the adapter's delegating impl is mechanical.

## Authentication vs. authorization

Deliberately separated, and the boundary matters:

- **Authentication** is at the transport (`tls.rs`): rustls with **raw public
  keys** (RFC 7250, no X.509) — the client proves possession of its Ed25519
  mesh identity in the handshake. The TLS verifier deliberately checks *only*
  key possession; it does not decide who you are.
- **Authorization** is `authz.rs`: a pure decision over already-verified inputs
  (`decide_access` → `MgmtAccess`), with no transport and no crypto, so the
  policy is unit-testable standalone and identical across transports.

Authorization is itself split in two, and the split is where to look when
changing it. *Which tier a connection earned* is `decide_access`, here. *Which
tiers a request admits* is declared per-request in `wayfinder-protos`'s
`rpc_table!`, beside that request's owner, audit class and rate-limit bucket.
`permits` is only the join between them.

That is deliberate: the tier lists used to live here as `matches!` arms with an
implicit catch-all, so a request kind added to the proto silently became
*permitted for admin and self-key and refused for viewer and enrollment* —
which is how `SetUserRole`, `SetUserEnabled` and `SetUserPassword` arrived. The
`every_request_kind_variants!` test macro that used to sit at the bottom of
this file existed to compensate. Now an entry with no `access` list does not
parse, so the decision is forced at the declaration and that macro is gone
(the sweeps iterate `rpc::every_request_kind()` instead, behind the protos
crate's `test-support` feature).

Five grant tiers:

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
  already had.
- `GrantedMember` — a verified, non-revoked cert carrying `CERT_FLAG_MEMBER`
  and no management capability: an enrolled *device*, which is what every node
  on the mesh holds. Exactly one request wide (`GetVpnEnrollment`), and that
  narrowness is the whole point — anything added to this tier is added to the
  entire mesh at once. Earned by the bit, never by the absence of the others,
  for the same reason the viewer tier is.
- `GrantedEnrollment` — the client presented no cert at all. Admitted, but
  `permits` confines it to `SubmitCsr`, `GetTrustAnchor`, `AuthenticateUser`,
  and the two invitation-redemption requests (`BeginUserRegistration`,
  `CompleteUserRegistration`) — somebody who does not have an account *yet*
  holds no credential of any kind, and those are the requests that give them
  one. An enrollment connection can redeem an invitation it already holds and
  can do nothing else to the account store: not mint one, list one, or revoke
  one.

A cert with *no* capability bit at all is `Denied(NoCapability)`. Since
`CERT_FLAG_MEMBER` exists that means one of two things: a certificate issued
before the bit did (which keeps the access it always had — none — until
reissued), or one whose bits this build does not recognise, since unknown flags
are masked rather than guessed at.

**Admission is per-connection; what an admitted client may invoke is
per-request.** The two full grants may invoke everything *except one request*,
so `permits` is really the definition of the three confined tiers.

That one exception is `GetVpnEnrollment`, gated on the **request** ahead of the
tier match. It is not a management capability being exercised: it mints a
tunnel credential bound to the calling *device's* identity, read from the
verified certificate on the connection. An operator's session certificate and
the node's own seed are both fully privileged and neither is a device, so for
them the request has no meaning rather than being a privilege they lack. This
is also what makes design 08's two gates independent — a party holding only the
shared enrollment token can have a certificate issued for keys it names, but
cannot separately prove possession of that key to reach this request.

The enrollment tier exists because enrollment is otherwise impossible: a
provider worth enrolling with is itself an enrolled member, so a node with no
cert could never open the connection carrying its CSR
— and, for the same reason, someone who has not logged in yet could never open
the connection carrying their password. Admission control for it has not moved:
the enrollment token and the operator's approval for a CSR, the password, the
second factor and the per-account lockout for a login, and for a redemption the
invitation token — 256 bits, single-use, expiring, and minted by an admin who
chose both the name and the role it will create.

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

A node in provider mode answers enrollment (`GetTrustAnchor`, `SubmitCsr`) by
delegating to the `MeshAuthority` trait (`provider.rs`). Every `wayfinder-auth`
value crossing that trait does so as raw bytes, with one exception (`revoke`
returns a `RevocationRecord`), so it carries no key types and stays
`no_std + alloc`; the concrete `CertAuthority` holding the mesh root key is
`std`-only (`authority.rs`).

`RevokeNode` is no longer one delegation but four hops, and that is the most
surprising thing in this crate: the connection task forwards it, the authority
signs *and durably persists*, the router ingests and floods it on its OGMs, and
the connection task then revokes the VPN peer. The middle two are owned by
different tasks, which is why a revocation can be recorded and never announced —
and why every step reports whether it actually happened.

**The authority runs on its own task, never on the router's event loop**
(`authority_task.rs`, design 13). A login spends Argon2id at 64 MiB and then
performs a durable write; on the driver's `select!` arm that meant ~100 ms with
no link `recv` serviced and no OGM emitted, reachable by anyone who could open a
connection. The connection task now classifies each request with
`request_facet` *before* sending it and forwards it to the owner that can answer
it — a second channel, so authority work and router work never queue behind each
other.

Three rules follow, and all three are load-bearing:

- **The router loop must never `await` the authority task.** The authority may
  be mid-Argon2id. Everything the loop needs from it is a *published* value it
  reads without waiting: the enrollment policy for `GetSecurityStatus`
  (`EnrollmentPolicyRx`). The only edge in the other direction is a signed
  revocation travelling to the loop to be flooded, which is safe.
- **The authority's clock comes from the router loop**, published as
  `RouterFacts` through `AuthorityComms` and handed to the task by
  `Driver::attach_authority` as `AuthorityPorts::facts`. `now_unix == 0` is
  fail-closed in `submit_csr`, `authenticate_user` and `revoke`, so an authority
  wired up without it refuses every *issuing* path — silently, with every
  router-side test still green. `attach_authority` mints every channel at once
  precisely so no caller can wire three of the four.
- **`RouterAdapter` does not implement `AuthorityDataProvider` at all.**
  Misrouting an authority request to the router half is a compile error rather
  than a runtime string. Where an answer is still owed — an embedded node, or a
  host node with no provider — it comes from the trait's own defaults
  (`NOT_A_PROVIDER`) or from the connection task finding no authority channel.

`persistence.rs` snapshots the issued-cert log and held CSRs so the
impersonation guard, revocations, and pending approvals survive a restart. Two
things about it:

- The on-disk schema is JSON with an explicit `CURRENT_STATE_VERSION`, kept
  **independent of the protobuf wire format** so the two evolve separately.
- Mutation goes through `wayfinder_storage::Persisted` — mutate, persist, roll
  back in memory if the persist failed. Do not add ad-hoc `persist()` calls
  alongside a direct field write; that ordering is the whole point of the type.

**A CSR's subject is not the client's to choose.** `check_mac_derives_from`
refuses a `node_mac` that is not the address the presented `ed_pubkey` derives,
in `submit_csr` (as a `CsrOutcome::Rejected`, since the request is well formed
and the caller is answered) and again in `approve_csr` (as an `Err`, because the
held store is durable and may hold rows parked by a build that predates the
rule). This — not the live-certificate lock beside it — is what stops
impersonation: the lock is first-come, so it only ever protected an address that
already held a certificate. Keep the lock, but do not reason about impersonation
from it. See `docs/design/implemented/09-mesh-auth-gaps.md` §5.

**A provider's enrollment posture is one field, spelled so that silence is
closed.** `ProviderConfig::auto_approve` (`#[serde(default)]` → `false`)
decides whether a submitted CSR is signed on the spot or parked as pending for
an operator; omitting it gets the queue. That direction is the whole reason it
is not spelled `require_approval`: signing a certificate for whatever keys an
anonymous client presents is a legitimate configuration for a closed lab or the
simulation, and not one anybody should reach by leaving a field out of a YAML
file. There is deliberately **no** startup guard to add here — the default
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

Accounts are administered over the management API, by `wayfinderctl provider
user` — and nothing administers them through the state file. A provider rewrites
that whole snapshot from memory on every write, so a second writer beside it
raced those writes and silently discarded one side or the other; design 15 has
the detail.

The first account is the case that looks like it needs a file: it cannot be
created *by* an account, because creating one needs the credential it creates.
It does not, because an operator on the provider host holds the node's own
identity seed, which authenticates at `MgmtAccess::GrantedSelfKey` and may
invoke every request. The same credential is the way back from a mesh whose last
administrator was removed, which is why `refuse_to_strand_the_mesh` can afford
to refuse.

## Invitations (`UserInvite`, in the same module)

`CreateUser` mints both of an account's secrets and hands the *admin* its
`otpauth://` URI, so the account's second factor is permanently known to someone
who is not its owner. An invitation is the other way round: an admin decides the
name and the role, and the person redeeming it is the first party to see the
TOTP secret. Design 12.

Four rules, and the first two are the design rather than the implementation:

- **`begin_user_registration` spends the invitation.** A start that could be
  repeated would let anyone who read the URL out of a chat log take the secret
  while the real registration still completed, recording nothing. Spending it
  turns a silent disclosure into a burnt invitation and a failed registration
  the invitee reports. Do not add a "peek" that reveals without consuming.
- **An invitation is not a `UserRecord` with a flag**, it is its own persisted
  collection. A half-built account that can log in is a strictly worse failure
  mode than an invitation that cannot, and that must not depend on every future
  reader of the user store remembering to check a field. Its `totp_secret` is
  not an `Option` for the same reason: the invariant lives in the type.
- **Completion is one durable write** (`CaLog::mutate_users_and_invites`).
  Creating the account and deleting the invitation must land together, or a
  crash leaves either an account under a name whose invitation still reads
  `Started`, or a spent invitation with nothing left to redeem — and the person
  holding the handle can see neither.
- **An unknown handle costs no Argon2id.** This *inverts* `spend_absent_user_work`'s
  rule above, deliberately: that exists because usernames are guessable and
  timing would enumerate accounts, while a handle is 256 bits from `OsRng` and
  has no oracle to protect. Charging memory-hard work per bad handle would hand
  an anonymous caller a DoS amplifier. So `complete_user_registration` checks
  everything cheap first and hashes the password last.

A name is reserved in **both** directions — an account cannot be created under
an invited name, and a name with an account cannot be invited — which is what
keeps the two stores from ever disagreeing about who exists.

## Persisting a runtime security setting

Two stores, split by *what owns the thing*, not by convenience:

- **The enrollment policy** rides the CA snapshot (`persistence.rs`), next to
  the certificates it governs. `CertAuthority::set_enrollment_policy` records
  the override, then re-runs `apply_policy_overrides` — the same overlay a
  restart performs, so the live path and the restart path cannot drift apart.
- **Everything node-wide** (the fail-closed gate, lazy cert distribution, an
  identity installed by `SetAuth`) goes to `settings.rs`, injected into
  `RouterAdapter` via `.with_settings(...)` by the host driver. The CA, by
  contrast, is no longer injected here at all — see *Provider mode (the CA)*.

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
