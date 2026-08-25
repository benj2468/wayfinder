# Design: taking the certificate authority off the router loop

**Status:** Proposed. **Implement before design 12.** Independently valuable —
it is what makes a link-carrying provider safe — and a prerequisite for anything
that raises management-request volume.

**Scope:** `libs/wayfinder-driver` (`driver.rs`: the `provider` field, the
`select!` query arm, `process_pending`, `set_provider`, `refresh_auth_clock`),
`libs/wayfinder-server` (`transport.rs`: a request fork in the connection task;
`adapter.rs`: splitting the authority half out; `authority.rs`: a clock input and
a policy watch; a new authority-task module), **`libs/wayfinder-protos`**
(`service.rs`: `WayfinderDataProvider` and `WayfinderService`'s dispatch must
split with the adapter — see §3.6), `bins/wayfinder-tap` (`main.rs:630-678`),
`bins/wayfinder-web` (`mock.rs` holds its own `CertAuthority` and drives the same
service). **No change** to the management-API wire format, to any client, to the
`no_std` core (`libs/interfaces`, `libs/batman`, `CentralRouter`), to
`MembershipCert` or OGM authentication, or to `decide_access`'s tier derivation.

## 1. Motivation

### 1.1 The coupling, in both directions

A management request and the router share one thread of execution, and the
sharing is worse than it first looks.

The connection task does its own TLS handshake, framing and socket I/O — none of
which the router loop ever waits for. But at `transport.rs:694-695` it then does:

```rust
query_tx.send((request.clone(), resp_tx)).await?;
let response = resp_rx.await?;
```

So while the router never awaits a connection, **every management request awaits
the router**, and the 16-slot `query_tx` (`main.rs:432`) is shared by every
connection, so a request can also wait behind *other* connections' queued work.
The separation is one-directional, and the direction it fails in is the one that
matters for a dashboard.

Then, at `driver.rs:420-431`, the router loop serves that request:

```rust
Some((request, resp_tx)) = query_rx.recv(), if check_server => {
    let ca = provider.as_mut().map(|c| c as &mut dyn MeshAuthority);
    let mut adapter = RouterAdapter::new(&mut *router, ca, now)
    …
    let response = WayfinderService::new(adapter).handle(request);
```

One adapter over `&mut CentralRouter` **and** the certificate authority, with the
whole synchronous handler as one arm of the `select!`. While it runs, no link
`recv` is serviced, no host frame is forwarded, and the OGM/keep-alive/challenge
timer does not fire.

So there are two problems, not one: **authority work stalls the router**, and
**router busyness stalls management**. This design fixes both, and the second is
why the fix is not simply "make the authority faster".

### 1.2 The number that matters

`AuthenticateUser` resolves to `UserRecord::authenticate`, which spends Argon2id
at **64 MiB, t=3, p=1** (`users.rs:66-75`) and then performs a durable write via
`mutate_users` to record the attempt (`authority.rs:633`) — an fsync plus an
atomic rename. Roughly 50-150 ms on a decent host CPU, materially worse on an
Ampere A1 or an Orin, plus a synchronous disk round trip, all inside the router's
`select!` arm.

Two things make it worse than a slow request:

- **It is reachable before authentication.** An unknown username deliberately
  spends the identical cost (`spend_absent_user_work`, `users.rs:329`) so timing
  does not enumerate accounts. That is correct, and it means the cost is
  available to anyone who can open a connection.
- **The existing limiter does not cover it.** `PreAuthLimits`
  (`transport.rs:327-334`) rate-limits new connections per source and
  `SubmitCsr` per source (applied at `:661-665`), and caps concurrent
  uncredentialed connections at `MAX_UNCREDENTIALED_CONNECTIONS = 64`
  (`:311`) behind a 10 s `HANDSHAKE_TIMEOUT` (`:318`). Logins get the connection
  cap and the concurrency cap but **no per-source rate limit of their own**, and
  cycling *distinct unknown* usernames also sidesteps the per-account lockout
  while spending full cost every time.

### 1.3 Why now

`nix/machines/wayfinder-ca/common.nix:4` and `:107` both assert that the CA
carries no mesh links, and `:136` leans on that to justify short certificate TTLs
as the primary revocation path. That is true of the deployment today, and it is
the reason this has been survivable so far.

Two things change it. The CA is the one box in the topology with a stable public
address, so it is where design 08's tunnel terminates and it is expected to carry
links. And — independent of any forecast — **any node can already be configured
as both a provider and a link carrier**: `provider` is an `Option` on a `Driver`
that also owns interfaces, so nothing but convention keeps these two roles on
separate boxes today. Design 12 is about to raise traffic on exactly the
`AuthenticateUser` path above.

## 2. Goals / Non-goals

**Goals**

- One node serves data-plane traffic and management traffic at high rate,
  concurrently, in both directions of §1.1.
- **No work whose cost is chosen by a remote party, and no memory-hard or
  disk-bound work, executes on the router loop.** §4.2 states the residual this
  design knowingly leaves and why.
- Authority work and router work do not share a queue.
- No wire change and no client change: `wayfinderctl`, the TUI and the dashboard
  keep working untouched.

**Non-goals**

- **Not moving the router-state queries off the loop.** They are genuine
  in-memory projections, and the arm holds `&mut CentralRouter`; moving them
  means a per-request snapshot or an `Arc<RwLock<CentralRouter>>`, which reaches
  into the `no_std` core's ownership model for little gain (§7).
- Not making `CertAuthority` shared-by-lock (§7).
- Not changing the mgmt-TLS handshake, tier derivation, or any tier's request
  set.
- **Not building graceful shutdown.** `bins/wayfinder-tap` ends at
  `driver.run().await` with the TLS servers in a detached `JoinSet`; there is no
  shutdown path to extend, and adding one is its own change (§5.4).
- Not fixing revocation durability (§4.3) — that is design 03, still `Proposed`.
  This design must not make it *worse*, which is a real constraint on §3.4.

## 3. Design

### 3.1 The authority becomes a task

`CertAuthority` moves out of `Driver` into a tokio task that owns it outright,
fed by its own channel of the same `(WayfinderRequest, oneshot::Sender<…>)`
shape as `QueryTx`. `Driver` loses `provider` (`driver.rs:144`) and
`set_provider` (`:245`), so `wayfinder-tap` wires the task alongside the driver
rather than into it.

Single ownership is retained; only the executor changes. Everything
`authority.rs` assumes about being the sole writer of its store stays true.

### 3.2 The fork happens in the connection task

The connection task chooses the channel by request kind, before sending. **This
is not a new pattern — it is the one already in the file.** `transport.rs:682-695`
answers the three VPN requests in the connection task, with a comment that makes
this design's argument outright: *"They are also network I/O, and the router loop
that would otherwise await them is the loop emitting OGMs."* This design extends
that fork rather than inventing one.

**Answered in the connection task today:** `GetVpnEnrollment`, `ListVpnPeers`,
`RevokeVpnPeer` (`serve_vpn_request`, `transport.rs:724`). `Authenticate` (proto
field 19) never reaches dispatch at all — it is the transport's own first frame.

**Moving to the authority task:** `SubmitCsr`, `ApproveCsr`, `DenyCsr`,
`ListPendingCsrs`, `GetTrustAnchor`, `AuthenticateUser`, `ListUsers`,
`CreateUser`, `RemoveUser`, `ListCerts`, `RevealEnrollmentToken`, plus design
12's five registration requests.

**Proposed to move to the connection task:** `GetLogs`, `SetLogLevel` and
`GetAlarms`. None of the three touches `CentralRouter`. `GetLogs` (`adapter.rs:752-770`) takes `max_records`
straight off the wire, acquires the process-wide log ring lock, and allocates two
`String`s per record — this is the request already known to OOM a dongle, and it
is client-sized work sitting on the router loop. `SetLogLevel` (`:777`) installs
a global filter, and `GetAlarms` projects `wayfinder-alarm`'s process-global
`SharedBoard`. All three are process-global state reachable from anywhere, so
they belong beside the VPN requests. Separable from the rest of this design if it
needs to land in two pieces.

**Staying on the router loop:** everything else — every `Get*`/`List*` over
*routing* state, `ResolveRoute`, `SetAuth`, and the router half of `SetConfig`.

### 3.3 The clock the authority cannot lose

**This is the part most easily missed, and it silently breaks certificate
issuance.**

`Driver::refresh_auth_clock` (`driver.rs:278-288`) is the only production caller
of `CertAuthority::set_now_unix`, invoked from every loop entry point (`:333`,
`:489`, `:508`, `:533`). Its comment states the invariant: *"Keep the provider
CA's issuance clock in step, so issued certificate validity windows track the
same time the router verifies against."*

A `now_unix` of 0 is a hard fail-closed in `submit_csr` (`authority.rs:701`),
`authenticate_user` (`:616`) and `revoke` (`:977`). Move the authority to its own
task with no replacement and **it never issues anything again** — no CSRs, no
logins, no revocations — while every router-side test stays green.

Resolution: the router loop publishes `epoch_unix + now` into a
`tokio::sync::watch`, and the authority task calls `set_now_unix` from it before
serving each request. It must be **seeded before the task starts**, or the first
request races the first publication and hits the zero fail-closed.

Two consequences to carry:

- The two clocks can now drift by up to one loop iteration. That is far inside
  any certificate validity window, but it should be stated rather than
  discovered.
- `RouterAdapter::with_epoch_unix` (`adapter.rs:203-217`) exists so tests can
  drive certificate-validity time deterministically through the driver's `now`.
  The authority task needs the same seam — the watch sender is the natural one —
  or the expiry tests lose their virtual clock.

### 3.4 The requests that need both

**The invariant: the router loop must never `await` the authority task.** The
authority may be mid-Argon2id, so awaiting it reintroduces the stall this design
removes, with a longer chain. Every case below is shaped around that.

An audit of all fourteen `MeshAuthority` methods (`provider.rs:36-166`) and every
`self.ca` reference in `adapter.rs` confirms the set is exactly three:
`security_status`, `revoke_node`, and `set_config`'s enrollment branch.
`get_trust_anchor` (`adapter.rs:784-789`) is genuinely authority-only;
`set_auth` (`:593-666`) is genuinely router-only; `node_metrics` (`:507-576`)
reads `router.auth()` for cert-store occupancy, not the authority.

**`GetSecurityStatus`** (`adapter.rs:434-505`; the authority touch is at `:449`)
reads router posture *and* `ca.enrollment_policy()`. Resolution: the authority
task publishes its policy into a `watch`; the router loop reads the latest value
with `Receiver::borrow()`, which is synchronous and safe inside a `select!` arm.
The publication must happen before the reply is sent, so a client that sets a
policy and immediately reads it back sees its own write. Two details: the watch
must be seeded from `apply_policy_overrides` (`authority.rs:228-255`), which also
runs at construction — otherwise the first read reports config policy instead of
the persisted override — and the router-side adapter must hold an
`Option<watch::Receiver<_>>`, not a receiver, so a non-provider keeps reporting
`enrollment: None` rather than a default-valued policy.

**`RevokeNode`** (`adapter.rs:877-902`) is the hard one, because it is already
three hops and the first of them is a deliberate precondition:

```rust
// adapter.rs:881-889 — BEFORE any signing
if self.router.auth().is_none() { return Err(…) }
```

Its comment says why: *"Reject up front rather than sign a record that would
silently never propagate, leaving the operator believing the node was revoked."*
A naive "authority signs, then hands the record to the router" **inverts this**,
producing exactly the state the existing code refuses to create. The precondition
must be evaluated before the authority signs — mirrored into the same watch that
carries the enrollment policy is the cleanest option, since the router already
publishes there.

The full chain also does not end at the router: `transport.rs:701-710` runs
`revoke_vpn_alongside_mesh` in the connection task *after* the router hop returns
`Empty`, deliberately ordered so a mesh failure leaves the tunnel alone. So the
sequence becomes: connection (precondition) → authority (sign, persist) → router
(ingest, flood) → connection (VPN). Each hop is bounded; none inverts an existing
ordering.

**`SetConfig`** (`adapter.rs:669-707`; the authority branch at `:698-707`) is a
dual-state *write*. Recommended: the connection task splits it, issues the router
half **first** — preserving today's ordering, where router fields are applied
before the enrollment branch — and issues the authority half only if the request
carries one. A `SetConfig` with no `enrollment` field then never touches the
authority and never pays its latency. Report the first error; the request is not
atomic across the two halves, which is already true today.

### 3.5 Argon2id goes to a blocking pool

Even off the router loop, 64 MiB of memory-hard work for ~100 ms parks a tokio
worker. The authority task must run the password paths via `spawn_blocking`.

`CertAuthority` is `Send` (`Authority` is `{Keypair, u32}`; the rest is POD plus
`CaLog`, and `wayfinder-storage`'s only `Rc<RefCell<_>>` is test-only), so this
works — **but it forces a shape change worth stating.** `spawn_blocking` needs
`FnOnce + Send + 'static`, and `MeshAuthority::authenticate_user` takes
`&mut self`, so the task must own the concrete `CertAuthority` and move it in and
back out across the call. It cannot hold a `&mut dyn MeshAuthority`. Since
`CertAuthority` is the trait's only impl (`authority.rs:601`) and the trait exists
to keep the `no_std` adapter off the `std` authority, the authority-side code
should simply name the concrete type; the trait's remaining job is the split in
§3.6.

Note this also means the authority task serves one request at a time and does not
service others while blocked. That is a deliberate accepted limit (§7).

### 3.6 Splitting the adapter means splitting the service

`WayfinderService<P: WayfinderDataProvider>` (`service.rs:1050-1062`) is one
dispatcher over all thirty request kinds against one provider. **You cannot hand
it half an adapter.** So "split the authority half out of `RouterAdapter`"
necessarily means splitting `WayfinderDataProvider` and its dispatch in
`libs/wayfinder-protos/src/service.rs` into a router-facing half and an
authority-facing half.

Without that split, the two owners end up as two impls stubbing each other's
methods with runtime error strings — which is the failure mode §5.1 wants a
compile error for. This is the largest single piece of work in the design and it
lives in a crate the naive scope statement would omit.

There is a second impl to carry: `bins/wayfinder-web/src/mock.rs` holds
`ca: Option<CertAuthority>` (`:115`), implements the authority half (`:522-590`),
calls `ca.set_now_unix` (`:222`, `:248`) and drives `WayfinderService::new(mock)`
(`:664`). It needs the same split and the same clock treatment as §3.3.

### 3.7 Limits and capacities

- Add a per-source limiter for `AuthenticateUser` (and design 12's registration
  requests) beside the existing enrollment limiter — §1.2's gap.
- The authority channel is bounded and separate from `query_tx`. A full authority
  channel fails fast with a busy error rather than blocking the connection task
  indefinitely.
- `query_tx`'s depth of 16 is worth revisiting once it carries only router work,
  but it is not the fix.

## 4. Correctness argument

### 4.1 No deadlock

```
connection tasks ──▶ router loop
        │                 │
        │                 └─▶ watch: clock, enrollment policy, auth-present
        └─────────▶ authority task ──▶ router loop   (revocation ingest only)
```

The authority task depends on the router loop for one thing. The router loop
depends on the authority task for nothing — the policy reaches it through a
`watch`, which reads a published value rather than asking for one. Since the
router loop never blocks on user-controlled work, no chain forms back to it.

### 4.2 What still runs on the router loop, honestly

After the split the loop still serves two things that are not free, and the goal
in §2 is worded to admit them:

- **`SetAuth` and `SetConfig`'s router half perform a synchronous durable
  write.** `adapter.rs:252-257` calls `persist_settings` →
  `SettingsStore::persist` → `settings.rs:274-280` → `wayfinder-storage`'s
  `file.rs:129-130`, which is `tmp.sync_all()` plus a rename — the same
  fsync-and-rename this design calls disqualifying for the authority. Accepted
  because both are admin-gated, rare, and bounded in size by the config, not by a
  remote party. If it ever becomes a problem the fix is the same shape: a
  settings task.
- **`security_status`'s router half is not microseconds.** It does an O(n²)
  `macs.contains` dedup plus a linear `neighbors()` scan per MAC
  (`adapter.rs:470-494`), bounded by the capacity profile. Fine on a small
  profile, worth measuring on a large one.

Everything else the loop serves is an in-memory projection, plus
`ingest_revocation` and a `watch` read.

### 4.3 Revocation durability is worse than it looks, and this design must not widen it

`CertAuthority::revoke` (`authority.rs:976-995`) signs the record and then
persists **only** a `revoked = true` flag on a matching entry in the issued log.
The signed `RevocationRecord` itself is never persisted, and when the MAC has no
issued entry (`:988`) `mutate_issued` writes nothing at all. Meanwhile nothing
loads or re-floods revocations at startup — design 03 is still `Proposed`, and
the only non-test caller of `ingest_revocation` is `adapter.rs:900`.

So a crash between signing and flooding does not merely delay the flood; **in
general there is nothing left to re-derive the record from, and it is never
announced.** That is true today, in a window of microseconds. This design widens
that window to a task hop, so it must keep the two adjacent: the authority sends
to the router immediately after persisting, with no request served in between,
and the client is told only after the router acknowledges. State the residual
rather than defer it to design 03 — the widening is this design's to justify.

### 4.4 Durability otherwise unchanged

The authority task is still the sole writer of its store, so `CaLog`'s
mutate-and-persist ordering and rollback-on-failure hold exactly as before. Its
fsyncs now serialize behind authority work only, never behind a link `recv`.

## 5. Edge cases

1. **Non-provider nodes** must still answer authority requests with the existing
   "node is not a certificate-authority provider" string — produced now by the
   connection task finding no authority channel.
2. **Head-of-line blocking within one connection remains.**
   `transport.rs:694-696` is send → await → next frame, sequentially per
   connection, so a slow authority request still delays that connection's later
   router requests. The goal in §2 holds *across* connections and tasks, not
   within one. The dashboard is one connection, so this is worth knowing; fixing
   it means pipelining the connection loop, which is a separate change.
3. **`RouterAdapter` on the router side should stop accepting an authority at
   all** rather than taking `None`, so a misrouted request is a compile error.
   Note `RouterAdapter::new`'s signature is also used by
   `libs/wayfinder-embedded-driver/src/lib.rs:491` with `None`.
4. **`AuthSnapshot` stays on the loop.** The arm is `driver.rs:432-435`; the
   builder is `driver.rs:683-702` and allocates a `Vec` of revoked MACs per
   connection (`:701`). Cheap, but the next thing to watch as dashboard sessions
   multiply. Moving it to a `watch` is an obvious follow-up, out of scope.
5. **Shutdown.** No graceful path exists today (§2, non-goals). When one is
   built, the authority task must finish its persist before exit and the router
   loop must outlive it long enough to ingest an in-flight revocation. Recorded
   here so it is not rediscovered.

## 6. Observability

The root `CLAUDE.md` requires metric state to live in `CentralRouter` so it
exists on embedded nodes. That rule does not bind for the authority queue, and it
is worth saying why rather than quietly departing: an authority queue exists only
on a provider, a provider is a host node by construction, and there is no
embedded node on which a router-owned version would mean anything.

- **Authority queue depth, current vs capacity.**
- **Authority request rate**, in the `RateEstimator` shape rather than a total.
- **Router loop iteration time**, or at minimum an alarm above a threshold. This
  is the direct measurement of the condition this design removes; without it the
  fix is unfalsifiable in production. Unlike the two above, this one *does*
  belong in the shared core — `wayfinder-embedded-driver` has the same loop shape
  and the same failure mode.
- A `wayfinder-alarm` condition for a saturated authority channel.

## 7. Alternatives considered

- **`Arc<Mutex<CertAuthority>>` in the connection tasks, no task.** Both options
  decouple the authority from the router loop, and both serialize authority work
  — a single task processes one request at a time just as a mutex does, and §3.5
  means it `await`s a blocking call while doing so. So concurrency is not the
  distinguishing argument. The real one is ownership: `spawn_blocking` needs to
  *move* the authority (§3.5), which a task owning it does naturally and a shared
  mutex makes awkward; and a task gives one obvious place to hold the clock
  subscription (§3.3) and the policy publisher (§3.4). A mutex is a defensible
  implementation of the same design, not a different design.
- **Keep the authority on the loop, just `spawn_blocking` the Argon2id.**
  Rejected: it removes the largest constant and leaves the structure — the
  durable write, every other authority request and the shared shallow channel all
  stay on the router's arm, and it does nothing for §1.1's second direction.
- **Move all management off the loop, router queries included.** Rejected as a
  non-goal: needs a per-request snapshot or an `Arc<RwLock<CentralRouter>>`, both
  reaching into the `no_std` core's ownership model, for requests that already
  cost microseconds.
- **Run the CA as a separate process.** Rejected: a larger operational change (a
  second unit, a second config, an IPC boundary) than the problem needs, and the
  provider node is deliberately one binary (design 11). Revisit only if the CA
  needs to scale independently.

## 8. Open decisions for the implementing session

- **How the `revoke_node` precondition is mirrored** (§3.4) — via the shared
  watch, or evaluated in the connection task. The watch is the recommendation.
- **Whether `GetLogs`/`SetLogLevel` move in this change or a follow-up** (§3.2).
  They are clearly misplaced today; the only question is batching.
- **Authority channel capacity and busy policy.** Fail-fast is the
  recommendation; depth is a tuning question best answered against a real login
  burst.
- **How far `WayfinderDataProvider` splits** (§3.6) — two traits with two
  dispatchers, or one trait with a dispatcher parameterised by which half is
  present. This is the design's biggest implementation fork and deserves a
  prototype before commitment.
- **Where the authority task is spawned.** `main.rs` is obvious, but
  `libs/wayfinder-server` owning a `serve_authority` entry point beside
  `serve_tls_server` keeps the wiring testable without a binary.

## 9. Key file map for the implementer

| File | What changes |
|---|---|
| `libs/wayfinder-protos/src/service.rs` | **The largest piece.** Split `WayfinderDataProvider` (`:703`) and `WayfinderService`'s dispatch (`:1050-1062`) into router-facing and authority-facing halves (§3.6). |
| `libs/wayfinder-driver/src/driver.rs` | Remove `provider` (`:144`) and `set_provider` (`:245`). **Two** adapter sites: the query arm (`:422`, in `:420-431`) and `process_pending` (`:582`, fn at `:532`). `refresh_auth_clock` (`:278-288`) loses its CA half and gains a watch publish — called from `:333`, `:489`, `:508`, `:533`. New arm to ingest a revocation. Provider-using tests live in this file's own `#[cfg(test)]` (`:964-965`). |
| `libs/wayfinder-server/src/transport.rs` | Extend the existing fork at `:682-695`; authority channel beside `QueryTx`/`QueryRx` (`:36-38`); per-source limiter for `AuthenticateUser` (`:327-334`, applied `:661-665`). Mind `revoke_vpn_alongside_mesh` at `:701-710`. |
| `libs/wayfinder-server/src/adapter.rs` | Split the authority half out. `security_status` (`:434-505`, ca touch `:449`) reads a watch; `revoke_node` (`:877-902` — **including the precondition at `:881-889`**) becomes multi-hop; `set_config`'s enrollment branch (`:698-707`) moves. Leave `persist_settings` (`:252-257`) on the router side (§4.2). |
| `libs/wayfinder-server/src/authority.rs` | Clock input replacing `set_now_unix` from the driver; publish enrollment policy on every change (`:228-255`, `:306-324`); `spawn_blocking` around the password paths (`:601` is the sole `MeshAuthority` impl). Mind the zero-clock fail-closed at `:616`, `:701`, `:977` and `revoke`'s partial persistence (`:976-995`). |
| `bins/wayfinder-tap/src/main.rs` | `:630-678` spawns the authority task instead of `driver.set_provider`; wire both channels into `serve_tls_server_with_vpn` (`:498-503`). |
| `bins/wayfinder-web/src/mock.rs` | Own `CertAuthority` (`:115`), authority impl (`:522-590`), `set_now_unix` (`:222`, `:248`), service construction (`:664`) — same split, same clock. |
| `libs/wayfinder-embedded-driver/src/lib.rs` | `:491` constructs `RouterAdapter::new(…, None, …)`; changes if the parameter is dropped. |
| `nix/machines/wayfinder-ca/common.nix` | `:4`, `:107` and `:136` all assert or rely on the CA having no links. Update when it gains them — a stale "no links here" comment is what made this issue easy to miss. |

Tests first, per the root `CLAUDE.md` and the `tdd` skill. The specifying cases:
**a certificate can still be issued after the split** (the §3.3 regression, and
the one that fails silently); a slow authority request does not delay a
concurrent router query on another connection (§1.1); an authority request does
not delay a due OGM; `RevokeNode` on a node with auth disabled is refused
*without* the authority signing anything (§3.4); a revocation signed by the
authority reaches the router and floods; a `SetConfig` carrying no `enrollment`
never reaches the authority; `GetSecurityStatus` reflects a policy set moments
earlier on the same connection; a saturated authority channel returns busy rather
than blocking; a non-provider node still answers authority requests with the
provider-mode error.
