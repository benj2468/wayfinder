# Design: hardening the enrollment access tier

**Status:** Proposed — the findings below came out of the `mr-review` pass on
`bjc/unauthenticated-bug-wasm` (online enrollment via the web dashboard). That
branch's own review fixes have landed; everything in this doc was deliberately
deferred to a follow-up. Approved for implementation in a later session.

**Scope:** `libs/wayfinder-server` (`authz.rs`, `authority.rs`,
`persistence.rs`, `adapter.rs`, `transport.rs`) and the enrollment panel in
`bins/wayfinder-web`. No change to the routing core, to `LinkT`/`FrameIo`, or
to the `no_std` `CentralRouter`. No wire-format change is required by §1–§4;
§5 is test-only.

---

## 1. Motivation

`bjc/unauthenticated-bug-wasm` opened a third management-API access tier so a
node with no certificate can ask a provider to certify it. In `authz.rs`:

```rust
// libs/wayfinder-server/src/authz.rs:104
if handshake_key == own_key {
    return MgmtAccess::GrantedSelfKey;
}
let Some(anchor) = anchor else {
    return MgmtAccess::GrantedEnrollment;   // :111
};
let Some(cert) = cert else {
    return MgmtAccess::GrantedEnrollment;   // :115
};
```

`permits` (`authz.rs:156`) then confines that tier to `SubmitCsr` and
`GetTrustAnchor`. The tiering itself is the right shape, and the reasoning in
the module header is sound: admission control belongs in the enrollment policy
(token + operator approval), not in the decision to let someone *ask*.

What the branch did not account for is that **`SubmitCsr` now has a side effect
reachable with no credential at all.** Every prior caller of `SubmitCsr` had to
present either an admin certificate or the node's own key. That is no longer
true, and the code behind it was written when it was.

This doc records the four security items and the test gap that follow from
that, so they can be addressed as one coherent change rather than rediscovered.

## 2. Goals / Non-goals

**Goals**

- Bound the resources an anonymous client can consume through the enrollment
  tier.
- Make the enrollment tier's *actual* guarantees match what its documentation
  claims.
- Verify the certificate a node installs before it starts signing with it.
- Close the untested half of the authorization matrix.

**Non-goals**

- Reverting the enrollment tier. It is needed: a provider worth enrolling with
  is itself an enrolled member, so without this tier online enrollment is
  impossible.
- Reverting the self-key grant (§3 asks for a decision, not a rollback).
- Encrypting management payloads. Out of scope, as everywhere else in this
  project.
- Rate-limiting the management API in general. §1's limiter is scoped to the
  enrollment tier only.

---

## 3. The issues

### 3.1 Unbounded held-CSR growth, reachable anonymously — **highest priority**

The held-CSR store is a plain unbounded `Vec`:

```rust
// libs/wayfinder-server/src/persistence.rs:125
held: Vec<HeldCsr>,
```

with a plain `push` on the park-for-approval path:

```rust
// libs/wayfinder-server/src/authority.rs:467
held.push(HeldCsr { … });
```

Eviction is TTL-only (`pending_ttl_secs`, `authority.rs:327`) — there is no
count-based bound anywhere, and `transport.rs` applies no per-connection or
per-source rate limit. The key is `node_mac`, which is attacker-supplied.

Two consequences, both new:

- **Memory exhaustion.** A provider running `require_approval: true` with no
  enrollment token — the configuration the dashboard describes as *"anyone in
  range may join"* — can be driven to OOM by one anonymous TCP client looping
  `SubmitCsr` with a fresh fabricated MAC each time. The store is also
  persisted, so the growth outlives a restart.
- **MAC squatting.** A MAC already held under a different key is refused
  (`authority.rs:459`). MACs are not secret — every OGM carries one. So an
  anonymous client can park a CSR under a *real* node's MAC and block that
  node's genuine enrollment until the TTL expires.

Neither was reachable before: opening the connection required a trusted
credential.

**Proposed fix.**

1. Cap `held` at a compile-time maximum (`MAX_HELD_CSRS`). On overflow, refuse
   the new entry rather than evicting an existing one — evicting is exactly the
   squatting primitive an attacker wants, and refusing degrades to "the queue is
   full, an operator must drain it", which is visible and recoverable.
2. Emit a `warn!` when the cap is hit. Per the root `CLAUDE.md` this is a
   capacity eviction and a security-relevant drop, so it is `warn!`, not
   `debug!`.
3. Add a lightweight per-source submission limiter on the enrollment tier in
   `transport.rs` — a token bucket keyed by peer address, sized so a legitimate
   node enrolling (a handful of submissions, then polling) is unaffected.
4. Consider requiring proof-of-possession: make `SubmitCsr` on an
   enrollment-tier connection require that the CSR's `ed_pubkey` equal the
   connection's handshake key. This is the structural fix — it makes squatting
   another node's MAC impossible rather than merely expensive, and it costs
   nothing legitimate, because a node enrolling *itself* already holds that key.
   It does forbid enrolling a node on behalf of another, which `authz.rs:150`
   currently documents as deliberately allowed; see §6.

### 3.2 The self-key grant now survives enrollment — **needs a threat-model decision**

`decide_access` checks self-key first and unconditionally (`authz.rs:104`), so
the node's own seed grants full management forever. This reverses a rule whose
test was named `self_key_bootstrap_refused_once_enrolled` and commented
"Security-critical: … so a leaked device key cannot manage a provisioned node."

The justification given is that "whoever holds that seed *is* this node on the
mesh — it signs the node's OGMs and terminates the node's own TLS." That is
true in the online-enrollment case. It is **not** unconditionally true:

```rust
// libs/wayfinder-server/src/transport.rs:312
let own_key = Keypair::from_seed(&own_seed).ed_pubkey();
```

`own_key` is computed once when the listener starts and captured into every
spawned connection. A `SetAuth` carrying a *different* seed replaces the node's
mesh identity but not this value. Until the process restarts, the old
management-only seed still yields `GrantedSelfKey` — full management — while
signing nothing on the mesh. The premise of the doc comment does not hold in
that window.

Compounding it: the same branch began reporting the shared `enrollment_token`
through `GetSecurityStatus`. Its safety argument is "whoever can read it could
already replace it via `SetConfig`" — sound for an admin certificate, but the
self-key holder is now in that set too. So compromise of one node's seed file
yields full management of that node **plus** the secret that admits new nodes
to the whole mesh.

**This is a threat-model call, not a defect.** Either outcome is defensible:

- *Keep it.* Then say so explicitly in `authz.rs` — that this trades a
  defence-in-depth layer for dashboard continuity across enrollment — and fix
  the doc comment's overclaim, and recompute `own_key` when `SetAuth` installs a
  new seed so the stale-key window closes.
- *Narrow it.* Scope the post-enrollment grant to the connection that performed
  the install (a short-lived grace credential), restoring the old fail-closed
  rule for every other connection.

The second is more work and closes the window properly. The first is honest and
cheap. What must not happen is leaving the current comment standing, because it
argues the change is a wash when it is not.

### 3.3 `permits`' documentation overclaims

```rust
/// libs/wayfinder-server/src/authz.rs:147
/// `SubmitCsr` names its own subject, so an enrollment connection cannot reach
/// past the request it came to make.
```

The next paragraph of the same doc comment concedes the opposite — that a
client may submit a CSR for keys it does not hold. `node_mac`, `ed_pubkey` and
`x_pubkey` are entirely client-supplied and bound to nothing about the
connection. The MAC squatting in §3.1 *is* the reach-past.

This matters beyond tidiness: whoever widens `permits` next will read that
sentence as the reason it is safe to do so.

**Fix.** State what actually confines the tier — the request *set*, not the
request *contents* — and name the residual reach honestly. If §3.1's
proof-of-possession option is taken, the sentence becomes true and should be
rewritten to say why (the CSR key must equal the handshake key), not left as
an unsupported assertion.

### 3.4 `set_auth` installs a certificate it never verifies

```rust
// libs/wayfinder-server/src/adapter.rs:529
let key_pair = Keypair::from_seed(&seed);
let parsed_cert = MembershipCert::from_bytes(cert).ok_or(…)?;
let anchor = TrustAnchor::from_bytes(trust_anchor).ok_or(…)?;
self.persist_settings(…)?;                       // persisted first
let auth = OgmAuth::with_capacities(key_pair, parsed_cert, anchor);
self.router.set_auth(auth);
```

Nothing checks that `anchor.verify_cert(&parsed_cert, now)` succeeds, that the
cert's key equals `key_pair.ed_pubkey()`, or that its `node_mac` is the MAC the
router runs under. `OgmAuth::with_capacities` is a plain struct literal and
validates nothing either.

**This gap is pre-existing on `main`** — it is not introduced here. What is new
is that a remote provider's response is now fed straight into it by the web
enrollment flow. If a provider returns a certificate for the wrong key (an
operator approving the wrong row, a MAC collision in the pending queue, a
provider bug), the node persists it, reports `auth_enabled: true`, and signs
every OGM under a certificate that does not name its key. Every peer rejects
it. The node is off the mesh, believes it is on, and comes back the same way
after a restart — and since `wayfinder-tap` now takes its MAC from that
certificate, it also renames itself on the next boot.

**Fix.** Verify before persisting: `anchor.verify_cert`, then the cert key
against the keypair. Both are cheap and both are already available at that
point. Persisting only after verification also restores the property the
existing comment there claims ("a malformed request cannot leave unusable
identity material behind").

### 3.5 Test gap: half the authorization matrix is unexercised

The anchor-present column is well covered. The **anchor-absent column is not**:
six of ten credential rows have no test, and every one of them currently
returns `GrantedEnrollment` — a *grant* — for a client whose certificate claim
failed. That contradicts the rule the module documents ("a cert that fails any
of those checks is `Denied` — a failed claim, not a fallback to a lesser tier"),
which is asserted only in the anchor-present column.

Also missing:

- **A certificate signed by a different trust anchor.** The only `CertInvalid`
  case exercised anywhere is `Expired`. This is the cell where a cross-mesh
  authorization bug would live, and `decide_access` is the only gate in front of
  it.
- **A closed-set test for `permits`.** Five of ~23 request kinds are asserted.
  `permits` does fail closed on a new proto variant (it is a positive
  allowlist), but nothing forces a reviewer to notice a privileged kind being
  *moved into* the allowlist. A test that enumerates every variant and asserts
  the expected verdict — including a count assertion, so a new proto variant
  fails the test rather than passing by omission — is what makes that
  deliberate.
- **The web rejection path.** `EnrollmentOutcome::Rejected` is never produced by
  any test in `bins/wayfinder-web`; `Mock::authority` cannot even construct a
  token-requiring provider. The bad-token path is the primary admission control
  for the whole feature. A test should also assert that the *same* request with
  the *right* token succeeds — no current test proves the token is carried at
  all, so a `request` that dropped it on the floor would pass everything.

---

## 4. Secondary items (same area, lower severity)

- **The enrollment token crosses to the browser on every poll.** `NodeSnapshot`
  carries the whole `GetSecurityStatusResponse` and is serialized to the client
  every second (`components/dashboard.rs:37`). The test named
  `security_never_renders_the_enrollment_token`
  (`bins/wayfinder-web/tests/render.rs:804`) asserts the token is absent from
  the *markup* — true and worth having, but the name claims a confidentiality
  property the architecture does not provide. Rename it to
  `security_masks_the_enrollment_token_in_the_markup`, and consider moving the
  token off the polled snapshot onto an explicit on-demand reveal call so its
  disclosure is auditable rather than continuous.
- **The approval-polling loop is unbounded and uncancelled.** `ask_to_join`
  (`bins/wayfinder-web/src/components/security.rs:150`) re-arms itself via
  `set_timeout` with no retry cap, no backoff, and no `on_cleanup`. The button
  is disabled only during `Asking` (`security.rs:726`), not during `Waiting`, so
  re-clicking while waiting starts a second self-perpetuating chain. Navigating
  away leaves a timer that fires against a disposed reactive owner.
- **`EnrollmentPolicyStatusData` can represent contradictory states.**
  `enrollment_token_set: bool` plus `enrollment_token: Option<String>` admits
  `(true, None)` and `(false, Some(_))`, and proto3's non-optional `string`
  collapses `None` and `Some("")` on the wire. The review pass already fixed the
  one consumer that read the token instead of the flag; a sum type
  (`Open | Token(SharedSecret)`, mirroring the existing `TokenUpdate` on the
  write path) would make the disagreement unrepresentable. A `SharedSecret`
  newtype with a redacting `Debug` would also close the `{:?}` leak through the
  derived `Debug` on the prost types.

---

## 5. Security considerations

The change in §3.1 is the one with a trust-boundary effect: it converts an
unbounded anonymous write into a bounded one. Option 4 (proof-of-possession)
additionally removes the ability to enroll a node on another node's behalf.
That is currently a documented feature of the design, so taking option 4 is a
deliberate narrowing, not a bug fix — see §6.

§3.4 tightens what a node will accept from a provider it has pinned. It does
not change who may call `SetAuth`.

Nothing here alters the mesh wire format, the OGM signing path, or the
`no_std` core.

## 6. Open decisions for the implementing session

1. **§3.2 — keep the broad self-key grant, or narrow it to the enrolling
   connection?** This is the one item that needs a human threat-model call
   before any code is written. Everything else in this doc is implementable
   as-is.
2. **§3.1 option 4 — require the CSR's key to be the handshake key?** It makes
   MAC squatting structurally impossible, but forbids enrolling a node on behalf
   of another, which `authz.rs:150` currently documents as intentionally
   permitted. Decide whether that capability has a real use case before removing
   it. If it does, keep it and rely on the cap + rate limit instead.
3. **`MAX_HELD_CSRS` value**, and whether the limiter is per-IP or global. A
   per-IP bucket is trivially evaded on an open network; a global one is a
   self-inflicted denial of service. A hybrid (global cap + per-IP bucket) is
   probably right.
4. **Whether §4's `SharedSecret`/sum-type refactor lands here or separately.**
   It touches the proto and both clients, so it may deserve its own change.

## 7. Key file map for the implementer

| File | What changes |
|---|---|
| `libs/wayfinder-server/src/persistence.rs:125` | Cap `held`; `MAX_HELD_CSRS` const |
| `libs/wayfinder-server/src/authority.rs:459,467` | Refuse-on-full, `warn!` on cap, squatting note |
| `libs/wayfinder-server/src/transport.rs` | Per-source limiter on the enrollment tier |
| `libs/wayfinder-server/src/transport.rs:312` | Recompute `own_key` after a seed-changing `SetAuth` (if §3.2 keeps the grant) |
| `libs/wayfinder-server/src/authz.rs:104,147,150` | §3.2 decision; rewrite the `permits` doc |
| `libs/wayfinder-server/src/adapter.rs:529` | Verify cert against anchor + keypair before `persist_settings` |
| `libs/wayfinder-server/src/authz.rs` (tests) | Anchor-absent column; cross-anchor cert; `permits` closed set |
| `bins/wayfinder-web/src/mock.rs` | Token-requiring `Mock::authority` |
| `bins/wayfinder-web/tests/enroll.rs` | Rejection path; token-is-carried test |
| `bins/wayfinder-web/src/components/security.rs:150,726` | Retry cap/backoff, `on_cleanup`, disable during `Waiting` |
| `bins/wayfinder-web/tests/render.rs:804` | Rename to describe masking, not confidentiality |

## 8. Alternatives considered

- **Revert the enrollment tier and require a credential for `SubmitCsr`.**
  Rejected: it closes the door online enrollment exists to open. A provider
  worth enrolling with is an enrolled member, so there is no credential the
  joining node could hold.
- **Put enrollment on a separate listener/port.** Rejected: it moves the
  problem rather than solving it (the same unbounded `push` sits behind it) and
  doubles the configuration surface an operator must get right.
- **Evict the oldest held CSR when full.** Rejected in favour of refusing:
  eviction hands an attacker exactly the primitive needed to displace a
  legitimate pending request.
