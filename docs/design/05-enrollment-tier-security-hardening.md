# Design: hardening the enrollment access tier

**Status:** §§3.1–3.5 implemented, on `bjc/harden-enrollment-tier`. The
findings below came out of the `mr-review` pass on `bjc/unauthenticated-bug-wasm`
(online enrollment via the web dashboard); that branch's own review fixes have
landed, and everything in this doc was deliberately deferred to this follow-up.
Each section's own "Implemented" note has the detail; in short — §3.1's
proof-of-possession option (item 4) was deliberately **not** taken, a
resolved threat-model decision (enrolling a node on another's behalf stays
supported), not a gap; everything else in §§3.1–3.5 is done. **§4 (secondary
items) is untouched** — out of scope for this pass.

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

**Implemented: items 1–3.** `MAX_HELD_CSRS = 128` bounds `held` by count
(`libs/wayfinder-server/src/authority.rs`), and a full queue refuses the new
entry with a `warn!` naming the offending MAC rather than evicting an
incumbent — closing the memory-exhaustion consequence. Covered by
`authority::tests::a_full_held_csr_queue_refuses_new_requests_rather_than_evicting`
(fills the queue, confirms the newcomer is refused and nothing evicted, and
that an incumbent's own re-poll/collect path still works through a full
queue).

Item 3 (the per-source limiter) is also in: `EnrollmentLimiter`
(`libs/wayfinder-server/src/transport.rs`) is a token bucket per source IP —
5-token burst, refilling one token per 5 seconds (matching `APPROVAL_POLL` in
the web dashboard's enrollment panel, so a legitimate node polling
indefinitely is never throttled at steady state), gating `SubmitCsr`
specifically on `GrantedEnrollment` connections. The map backing it is itself
bounded (`MAX_TRACKED_SOURCES = 1024`, evicting the least-recently-touched
bucket past that — safe, since an evicted source just starts over at full
burst capacity), so it does not reproduce the unbounded-growth problem it
exists to bound. Covered by
`submit_csr_on_the_enrollment_tier_is_rate_limited_per_source` (through the
real `serve_authenticated_stream` gate: the burst succeeds, one more is
refused, a non-`SubmitCsr` request on the same connection is unaffected),
plus two synchronous unit tests for the bucket and map-eviction logic.

**Item 4 (proof-of-possession) was deliberately not taken** — a resolved
threat-model decision, not an oversight: `authz.rs`'s `permits` doc comment
(rewritten for §3.3) now says explicitly, and honestly, that a submitted
CSR's key need not match the handshake key, because removing that would also
remove the ability to enroll a node on another's behalf, which nothing else
in this design offers a substitute for (§6 item 2). **The MAC-squatting
consequence above is therefore bounded, not closed**: an anonymous client can
still park a CSR under a real node's MAC in a single submission, but cannot
do so past 128 outstanding entries mesh-wide, and cannot repeat it faster
than roughly once per 5 seconds from one source — whereas before this fix it
could do both without bound.

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

**Implemented: option 1 (keep it), with the recompute.** `own_key` no longer
lives in a variable closed over at listener startup. It travels in
`AuthSnapshot` (`libs/wayfinder-server/src/transport.rs`) and is requested
fresh from the driver's live identity on *every* connection, the same
round-trip `anchor`/`revoked` already made — `serve_tls_server` no longer
computes it at all. `RouterAdapter::set_auth` (`libs/wayfinder-server/src/adapter.rs`)
now holds `identity_seed` as a mutable reference into the driver's own storage
rather than an owned copy, and writes the seed it actually installs back
through that reference the moment installation succeeds (both the wholesale
re-key case and the certify-in-place case). `wayfinder-driver`'s
`build_auth_snapshot` reads that same slot to compute `own_key` per
connection. Net effect: a `SetAuth` that rotates the seed closes the window on
the *very next connection*, not only at the next restart — which is what
"recompute `own_key`" above was asking for, just resolved as a live read
rather than a one-time recomputation.

This does **not** revoke an already-open connection mid-flight (authorization
is still decided once, at connect time, per the existing `AuthContext`
contract) and it is not a substitute for narrowing (option 2) if the actual
goal is ever "shut out a specific live self-key holder immediately" rather
than "a rotated-away-from seed stops working going forward." The doc comments
on `decide_access` (self-key bullet) and this crate's `CLAUDE.md` were
rewritten to state this guarantee rather than the prior overclaim.

Covered by `transport::tests::a_rotated_identity_seed_stops_granting_self_key_on_the_next_connection`
(real TLS end to end: the old seed grants full access, is rotated out, no
longer grants — falls to the same enrollment-only tier a stranger gets — and
the new seed grants immediately), `adapter::tests::set_auth_writes_the_installed_seed_back_to_the_caller`,
and three `driver::tests::build_auth_snapshot_*` unit tests (including one
proving the function caches nothing and tracks a changed seed call to call).

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

**Implemented.** The overclaiming sentence is gone. `permits`' doc comment now
states what actually confines the tier (the request *set* `permits` allows,
not anything about a `SubmitCsr`'s contents), names the residual reach
honestly (a client can name a MAC and keys it does not hold — the MAC
squatting §3.1 describes), says why that reach is deliberate rather than an
oversight (it is what lets one node enroll another on its behalf), and points
at the two things that now bound its cost without eliminating it
(`MAX_HELD_CSRS` and `EnrollmentLimiter`, both landed for §3.1). The
`SECURITY ALERT` banner an earlier commit added stays, unchanged.

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

**Implemented: all three checks, plus the ordering.** `set_auth`
(`libs/wayfinder-server/src/adapter.rs`) now:

1. Calls `anchor.verify_cert(&parsed_cert, now)` and persists only after it
   succeeds — covered by four tests (`set_auth_rejects_a_cert_with_a_bad_signature`,
   `_for_the_wrong_mesh`, `_an_expired_cert`, `_a_not_yet_valid_cert`), each
   asserting both the error and that nothing was installed or persisted.
2. Checks the cert's key against `key_pair.ed_pubkey()` — the identity being
   installed, whether that is the existing seed (certify-in-place) or a fresh
   one (wholesale replacement) — covered by `set_auth_rejects_a_cert_for_the_wrong_key`.
3. Checks `node_mac` against the MAC the router runs under, **scoped to the
   certify-in-place path only** (empty seed): that is the path's whole
   promise — the identity, and so the MAC, does not change — so a cert for a
   different MAC there is a provider-side mismatch. A wholesale identity
   install is exempt on purpose: naming a new MAC is exactly what that path
   is for, and `wayfinder-tap` re-derives the router's MAC from the installed
   certificate on the next boot. Covered by
   `set_auth_rejects_a_cert_for_the_wrong_mac_when_certifying_in_place` and
   `set_auth_with_a_seed_allows_a_new_mac` (the exemption, asserted
   positively so a future change to the scoping shows up as a failure here
   rather than by omission).

The failure mode this section opens with — a provider returns a well-formed,
validly-signed certificate for the *wrong* key — is closed: `verify_cert`
alone only proved the certificate was signed by the anchor's root, not that
it was *this node's*; checks 2 and 3 are what tie it to the identity actually
being installed.

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

**Implemented.** All four gaps are closed:

- **Anchor-absent column:** `authz::tests::without_an_anchor_no_certificate_grants_more_than_enrollment`
  sweeps five credential shapes against an anchorless node — no cert, an admin
  cert, an expired admin cert, a plain member cert, and a cert issued to a
  different key — asserting every one lands on `GrantedEnrollment` rather than
  a demoted grant, and that the node's own key still outranks all of them.
- **Cross-mesh certificate:** `authz::tests::a_certificate_from_a_foreign_root_is_denied`
  covers both shapes a forged cert can take — a foreign mesh id (caught by the
  id check) and a foreign root reusing *this* mesh's id (caught only by the
  signature, the cell that actually matters).
- **Closed-set `permits`:** `authz::tests::permits_confines_the_enrollment_tier_to_a_closed_allowlist`
  enumerates all 22 request kinds this build knows (`every_request_kind`) with
  a hard count assertion, so a request kind added to the proto and forgotten
  here fails the test rather than passing by omission.
- **The web rejection path:** `Mock::authority` (`bins/wayfinder-web/src/mock.rs`)
  now takes an `Option<&str>` token, wiring it into the real `CertAuthority` it
  wraps. `bins/wayfinder-web/tests/enroll.rs` adds
  `a_wrong_enrollment_token_is_rejected` (asserts `EnrollmentOutcome::Rejected`
  and that nothing installs) and `the_right_enrollment_token_is_admitted`
  (proves the token is actually carried to the provider rather than dropped —
  the property no prior test could see, since none of them configured a
  provider that checked it).

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
unbounded anonymous write into a bounded one — capped at 128 mesh-wide
(`MAX_HELD_CSRS`) *and* rate-limited per source (`EnrollmentLimiter`, ~1
`SubmitCsr` per 5 seconds after a small burst). Option 4
(proof-of-possession) was deliberately not taken: it would additionally
remove the ability to enroll a node on another node's behalf, which is a
documented feature of the design, so taking it would be a deliberate
narrowing, not a bug fix — see §6. The MAC-squatting consequence §3.1 opens
with is therefore bounded, not eliminated: a single submission can still
squat a real node's MAC, but not fast, and not past the shared cap.

§3.4 now tightens what a node will accept from a provider it has pinned on
all three axes named in that section: the certificate must verify against
the anchor, must name the key being installed, and — when certifying the
identity already held — must name the MAC that identity already runs under.
It does not change who may call `SetAuth`.

Nothing here alters the mesh wire format, the OGM signing path, or the
`no_std` core.

## 6. Open decisions for the implementing session

1. ~~**§3.2 — keep the broad self-key grant, or narrow it to the enrolling
   connection?**~~ **Resolved: kept, with the recompute.** See §3.2's
   "Implemented" note — `own_key` is now read live per connection, so a
   rotated-away-from seed stops granting access on the next connection rather
   than staying valid until a restart. Narrowing to a short-lived
   grace-connection credential remains on the table if the actual requirement
   ever becomes "revoke a specific live connection immediately," which this
   fix does not do.
2. ~~**§3.1 option 4 — require the CSR's key to be the handshake key?**~~
   **Resolved: not taken.** Enrolling a node on another's behalf has a real
   use case (a fleet operator provisioning nodes from one console) and
   nothing else in this design substitutes for it, so the capability stays.
   MAC squatting is bounded instead, by the cap + rate limit (§3.1 items 1–3).
3. ~~**`MAX_HELD_CSRS` value, and whether the limiter is per-IP or global.**~~
   **Resolved: 128 (global cap) + per-IP token bucket, the hybrid this item
   suggested.** The count-based cap bounds the store no matter how many
   sources contribute; the per-IP bucket (`EnrollmentLimiter`) bounds how
   fast any one of them can. The bucket map itself is bounded too
   (`MAX_TRACKED_SOURCES = 1024`, LRU-evicted), so a source-address flood
   cannot reproduce the unbounded-growth problem at one remove.
4. **Whether §4's `SharedSecret`/sum-type refactor lands here or separately.**
   It touches the proto and both clients, so it may deserve its own change.

## 7. Key file map for the implementer

| File | What changes |
|---|---|
| `libs/wayfinder-server/src/persistence.rs:125` | **Done.** `held: Vec<HeldCsr>` unchanged in shape; bounded via the count check in `authority.rs` below |
| `libs/wayfinder-server/src/authority.rs` | **Done.** `MAX_HELD_CSRS = 128`, refuse-on-full, `warn!` on cap |
| `libs/wayfinder-server/src/transport.rs` | **Done.** `EnrollmentLimiter` — per-IP token bucket gating `SubmitCsr` on the enrollment tier, bounded map, LRU eviction |
| `libs/wayfinder-server/src/transport.rs` | **Done.** `own_key` moved into `AuthSnapshot`, read fresh per connection instead of computed once in `serve_tls_server` |
| `libs/wayfinder-server/src/adapter.rs` | **Done.** `RouterAdapter::set_auth` holds `identity_seed` as `&mut Option<[u8;32]>` and writes the installed seed back through it |
| `libs/wayfinder-driver/src/driver.rs` | **Done.** `build_auth_snapshot` reads the live identity slot to compute `own_key`; both call sites thread it through as a mutable reference instead of a copy |
| `libs/wayfinder-server/src/authz.rs:104,147,150` | **Done.** `decide_access`'s self-key comment (§3.2) and `permits`' rewritten doc comment (§3.3) both state their actual guarantee |
| `libs/wayfinder-server/src/adapter.rs:529` | **Done.** `anchor.verify_cert`, cert-key-vs-keypair, and (certify-in-place only) cert-MAC-vs-router-MAC, all before `persist_settings` |
| `libs/wayfinder-server/src/authz.rs` (tests) | **Done.** Anchor-absent column; cross-anchor cert; `permits` closed set |
| `bins/wayfinder-web/src/mock.rs` | **Done.** Token-requiring `Mock::authority` |
| `bins/wayfinder-web/tests/enroll.rs` | **Done.** Rejection path; token-is-carried test |
| `bins/wayfinder-web/src/components/security.rs:150,726` | Retry cap/backoff, `on_cleanup`, disable during `Waiting` — **not done, §4, out of scope for this pass** |
| `bins/wayfinder-web/tests/render.rs:804` | Rename to describe masking, not confidentiality — **not done, §4, out of scope for this pass** |

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
