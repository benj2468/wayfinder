# Design: node self-revocation, and revocation by invalidity date

**Status:** Part A implemented (§3); Part B proposed (§4).  The two ship as
**sequenced MRs**, and Part A is a prerequisite for Part B rather than a
follow-up — §5.1 records why the reverse order is unsafe.  §11 records what
Part A's implementation found that this design did not anticipate.

**Scope:** `libs/wayfinder-auth` (`RevocationRecord`'s `not_before` gains a
second meaning and a version bump — the layout is unchanged;
`Authority::revoke`; `TrustAnchor::verify_revocation`),
`libs/wayfinder` (`OgmAuth::is_revoked` and its three call sites,
`ingest_revocation`, a new self-revocation latch; `CentralRouter::auth_locked`
and the latch drain), `libs/wayfinder-server` (`NodeSettings` gains one field;
`RouterAdapter` persistence; `authz.rs`'s revocation predicate; `AuthSnapshot`),
`libs/wayfinder-driver` (`ingest_signed_revocation`, `build_auth_snapshot`),
`libs/wayfinder-alarm` (one `AlarmKind` variant), `bins/wayfinder-tap` (a
boot-time revocation check), plus the client/TUI/web/dissector projections of
the changed wire field.

**No change** to `MembershipCert`'s layout, to the OGM signature construction,
to `LinkT`/`FrameIo`, to the OGM-tail flood mechanism, to `decide_access`'s tier
derivation, or to the `no_std` core's heap-free property. Embedded targets are
explicitly out of scope (§2, non-goals) — no board installs auth today.

---

## 1. Motivation

### 1.1 A node that is told it is revoked does nothing about it

`OgmAuth::ingest_revocation` (`libs/wayfinder/src/auth.rs:517`) verifies a
flooded record against the trust anchor and then, if the record names *this*
node, discards it:

```rust
// A revocation of *this* node is a no-op here: peers enforce it against
// us, and storing/flooding our own death warrant would only waste a
// flood slot and budget.
if mac.0 == self.cert.node_mac {
    tracing::warn!("auth: received a revocation naming this node");
    return false;
}
```

One `warn!` line, and nothing else. The node keeps signing OGMs under the
cancelled certificate, keeps its cached neighbour pairwise keys and replay
counters, keeps routing, and keeps serving its management API. The behaviour is
pinned as intended by `self_revocation_is_a_noop` (`auth.rs:2149`), and the
operator-facing path says the same thing from the other side:
`ingest_signed_revocation` returns `Err("it names this node, which never floods
its own revocation")` (`libs/wayfinder-driver/src/driver.rs:881`).

"Peers enforce it against us" is true only of peers that *hold* the record.
Propagation is a one-shot burst — `REVOKE_FLOOD_BUDGET` = 6 emissions
(`auth.rs:170`) — so a peer that rebooted, or joined after the burst, has no
record and re-trusts the revoked node until its certificate passively expires.
That gap is `docs/design/03-revocation-durability.md`'s subject and is still
open. The revoked node is the one party guaranteed to know, and it is the party
currently doing nothing.

### 1.2 Revocation is MAC-keyed, so a revoked node can never come back

`RevocationRecord.node_mac` is what `OgmAuth::is_revoked` (`auth.rs:578`)
matches on. A node that is re-admitted — a new certificate issued through the
normal admin-gated enrollment flow — comes back under the same MAC, so every
peer still holding the record drops its OGMs until `not_after`.

This is not a corner case. Revocation is meant to be a *low-regret* action, and
the reasons an operator revokes are mostly not compromise:

- **Mesh switching** — a node moves from mesh A to mesh B.
- **Suspected but unconfirmed compromise** — revoke now, investigate, re-admit
  if cleared. Cheap to do only if re-admission is cheap.
- **Operator error** — the wrong MAC was revoked; there is currently no undo.
- **Decommission and later redeploy**, **lease or role expiry** — hardware
  still trusted, key never exposed.

And the escape hatch of "get a new MAC" does not exist everywhere: on nRF
boards the MAC is derived from the chip's factory FICR device id
(`libs/wayfinder-nrf/src/identity.rs:23`) and is re-derived identically if
storage is wiped. **A board cannot change its MAC** — not by re-flashing, not
by factory reset. Under MAC keying, revoking an nRF node excludes it until
`not_after` with no recovery at all.

---

## 2. Goals / Non-goals

**Goals**

1. A node that hears a revocation naming itself **stops participating** — no
   OGM emission, no frame handling, no local egress — and stays stopped across
   a restart.
2. The steps to bring it back are **clear and reachable over the wire**, for
   both re-admission to the same mesh and enrollment into a different one.
3. Neither property may be achievable by an attacker who holds no key
   material (§5.1).

**Non-goals**

- **Persisting the peer-enforcement revocation set.** `OgmAuth.revocations`
  stays RAM-only; design 03 owns that problem. This design persists exactly one
  record — the node's own — and for boot-time policy, not for enforcement.
- **Embedded self-revocation.** No board calls `set_auth` today, and the
  embedded adapter is built without an epoch clock. The `no_std` core changes
  here are written so a board inherits the behaviour when auth arrives, but no
  board-side work is in scope.
- **Wiping the node's identity seed or MAC.** §7.4 records the trade-off.
- **Re-flooding a self-naming record.** Peer-side flooding is already bounded
  and deduped; echoing our own record adds nothing.
- **Certificate-granular revocation.** §7.1 records why invalidity-by-date is
  preferred over keying on a certificate fingerprint.

---

## 3. Part A — revocation by invalidity date (MR 1)

### 3.1 The wire — no new field

**`RevocationRecord`'s layout does not change.** The existing `not_before`
carries the new meaning: it is the revocation instant, and it divides
cancelled certificates from valid ones. `REVOKE_VERSION` goes from 1 to 2
because the *semantics* change incompatibly, not the bytes.

Its doc comment becomes:

```rust
    /// Unix-seconds instant this revocation takes effect, and the line
    /// dividing cancelled certificates from valid ones: a certificate for
    /// `node_mac` is cancelled by this record only if its own `not_before` is
    /// at or before it.  A certificate issued *after* this instant — a
    /// re-admission by the authority, which by definition knew it had revoked
    /// — is unaffected, so a re-approved node rejoins under its own MAC
    /// rather than waiting out `not_after`.  Must be non-zero.  Network byte
    /// order.
    pub not_before: U64,
```

One field rather than two is the better design, not merely the cheaper one. A
separate `certs_before` would have no legitimate value other than
`not_before`: "cancel everything issued before now but do not enforce for a
week" is not a posture anyone wants, and "remove this node next Friday" should
cancel a Thursday renewal too — which is what the collapsed reading gives. A
second field whose only correct value equals the first is a field that will
eventually be set inconsistently.

Cost avoided: the record stays at **92 bytes**, so the OGM tail does not grow
and the `MAX_REVOKE_TVLVS` budget on duty-cycle-limited links is untouched.

**The one trap, and the guard for it.** Under the old semantics `not_before =
0` meant "effective immediately", and it is what every existing caller passes —
`Authority::revoke(mac, 0, 1000)` throughout the test suite. Under the new
semantics `cert.not_before < 0` is never true, so such a record verifies, is
stored, floods the mesh, and **cancels nothing**: a security control that
silently no-ops, which is the worst failure available here.

Two changes make that impossible rather than merely documented:

- `Authority::revoke` stamps the CA's `now` and its `not_before` parameter is
  removed, so a caller cannot pass 0. Scheduling a future revocation, if it is
  ever wanted, becomes an explicit second constructor.
- `TrustAnchor::verify_revocation` rejects `not_before == 0` as malformed
  (a new `AuthError` variant, or `BadVersion` reused — implementer's call),
  so a v1-shaped record can never be mistaken for a v2 one that cancels
  nothing.

Every existing `revoke(mac, 0, …)` call site in the test suites must be
updated to a real instant; this is the bulk of Part A's diff.

### 3.2 Enforcement

`OgmAuth::is_revoked` currently takes a MAC. It must take the **certificate
being judged**, because the decision now reads a field of that certificate:

```rust
fn is_revoked(&self, cert: &MembershipCert) -> bool {
    let now = self.now_unix;
    self.revocations.iter().any(|r| {
        r.record.node_mac == cert.node_mac
            && cert.not_before.get() <= r.record.not_before.get()
            && r.record.not_before.get() <= now
            && now < r.record.not_after.get()
    })
}
```

Note `not_before` now appears twice with two different jobs — as the
enforcement-window start and as the issuance cut-off. That is the collapse
working as intended, and the comparison is safe because both instants are
stamped by the same authority off the same clock: `MembershipCert.not_before`
is supplied by the CA at issuance, never by the node.

Three call sites in `libs/wayfinder/src/auth.rs` — `1067` (OGM verification),
`1191` (directed-frame verification) and `1347` (`CertReq` responder) — each
already has the peer's certificate in hand or can reach it through the
neighbour cache. The implementing session should confirm this per site rather
than assume it; where a site genuinely has only a MAC, the conservative
reading is "revoked" and that must be a deliberate, commented choice.

The management-API predicate is the fourth site. `authorize_capability`
(`libs/wayfinder-server/src/authz.rs:299`) calls `is_revoked(cert.mac)` with
the certificate right there, so it becomes `is_revoked(&cert)`. Its supplier
is `AuthSnapshot.revoked: Vec<Mac>` (`transport.rs`), populated from
`auth.revoked_macs()` in `build_auth_snapshot`
(`libs/wayfinder-driver/src/driver.rs:989-999`). A `Vec<Mac>` can no longer
answer the question — the snapshot must carry the records themselves, or a
closure the router builds. Prefer carrying `Vec<RevocationRecord>`: it keeps
the accept loop free of router borrows, which is the property `AuthSnapshot`
exists to preserve.

### 3.3 Version handling

`verify_revocation` rejects any `version != REVOKE_VERSION`
(`revoke.rs:90-92`), so v1 and v2 records do not interoperate in either
direction: a v1 node drops v2 records and vice versa. Given no deployment is
running an authenticated mesh in anger yet, **a hard cutover is the right
call**. It is also the only safe one: a v1 record's `not_before` means
"enforce from here", and reading it as v2 would cancel nothing (§3.1's trap),
while a v2 record read as v1 would cancel every certificate for the MAC
including a legitimate re-admission. The two readings fail in opposite
directions, so there is no shim that is right for both. State this in the MR
description; do not add one.

The Wireshark dissector (`libs/wayfinder-shark`) decodes revocation TVLVs.
Because the layout is unchanged it needs only the accepted version and the
field's description updated, not a new field — a smaller change than a
layout-altering design would have required.

---

## 4. Part B — self-revocation (MR 2)

### 4.1 What happens on receipt

In `OgmAuth::ingest_revocation`, replace the current early-return with a latch.
The record must clear **four** gates before the latch is set — the first is
existing behaviour, the other three are new and each closes a specific failure
in §5:

1. `verify_revocation` succeeds (anchor signature, mesh id, not already
   expired). Existing.
2. `self.now_unix != 0`. A node with no clock cannot judge a record's window
   and must not act on one (§5.4).
3. `record.not_before <= self.now_unix`. A not-yet-effective record is a
   statement about the future; acting on it early makes the node a black hole
   (§5.3).
4. `cert.not_before <= record.not_before` — Part A's clause. Without it, a
   replayed old record kills a freshly re-issued certificate (§5.1).

A record that names this node and clears all four sets
`self_revoked: Option<RevocationRecord>` and returns `false` (it was not
recorded in the enforcement set, which remains true and keeps
`ingest_revocation`'s contract intact). A record failing gate 2 or 3 is
**latched for re-evaluation in `set_time`**, not discarded — a clockless node
that later learns the time, or a future-dated record whose instant arrives,
must still act.

`OgmAuth` cannot remove itself from `CentralRouter` — it is borrowed as
`self.auth.as_mut()` — so this is a latch the router drains, exactly like the
existing `trickle_reset_hint` / `take_trickle_reset_hint` pair.

### 4.2 What the router does when it drains the latch

`CentralRouter`:

1. Sets `self.auth = None`, dropping the certificate, the trust anchor, the
   cached neighbour keys and the replay counters.
2. Calls `self.batman.reset()` — the same thing `set_auth` already does
   (`lib.rs:788-800`), and correct here for the same reason: the pairwise key
   material backing every learned route is gone.
3. Clears `ident_table` and `link_quality`, mirroring `set_auth`.
4. Reports the latched record upward so the host layer can persist and alarm
   (§4.4). The core does no I/O.

**Three call sites must drain the latch**, and missing one silently restores
today's no-op:

- `libs/wayfinder/src/lib.rs:1055` — the OGM-tail path. **This one must return
  early** after draining. Otherwise the frame falls through to
  `batman.handle_rx` (`lib.rs:1230`) and the node installs routes from, and may
  re-flood, one more OGM after it is supposedly inert.
- `libs/wayfinder/src/lib.rs:905-923` — `CentralRouter::ingest_revocation`, the
  management-API and local-CA path.
- `libs/wayfinder-py/src/driver.rs:232-235` — the simulator binding.

### 4.3 What makes the node inert

`auth_locked()` (`lib.rs:896`) is currently `require_auth && auth.is_none()`.
It becomes:

```rust
pub fn auth_locked(&self) -> bool {
    self.self_revoked || (self.require_auth && self.auth.is_none())
}
```

The `self_revoked` disjunct **must not** depend on `require_auth`. A node
configured `require_auth: false` that merely cleared its auth would fall back
to open, unauthenticated routing: with `auth == None` the OGM verification gate
at `lib.rs:1052` is skipped entirely rather than failing closed, so the node
would accept and flood OGMs from anyone holding no certificate — strictly more
permissive than before it was revoked.

`auth_locked` already gates `handle_frame_with_metrics` (`lib.rs:978`),
`handle_local_mcast` (`1569`), `poll` (`1611`), `poll_keepalive` (`1677`) and
`poll_challenge` (`1734`), so inertness falls out of the existing predicate.

**Do not reuse `require_auth = true` as the latch.** It was the first design
considered and it is wrong: `SetConfig`'s access list is `[Admin, SelfKey]`
(`libs/wayfinder-protos/src/rpc.rs:323-327`), it persists
(`adapter.rs:1144-1152`), and the persisted value overrides the YAML at boot
(`main.rs:578-580`). One self-key request would clear the lock, and an
operator "fixing" the config file would not re-secure the node.

### 4.4 Durability

Both halves of the in-RAM change are lost on restart, and the identity is
persisted, so without this section a power cycle brings the node back armed
under the revoked certificate. Note that boot's `set_auth` does **not** call
`anchor.verify_cert` — it does `from_bytes` plus a MAC-binding check only
(`bins/wayfinder-tap/src/main.rs:653-679`) — so the boot-time check has to be
written explicitly; it does not fall out of existing validation.

`NodeSettings` (`libs/wayfinder-server/src/settings.rs:59`) gains one field:

```rust
    /// The signed revocation naming this node, if it has heard one.  Raw
    /// `RevocationRecord` bytes, re-verified against the trust anchor on every
    /// boot rather than trusted as a flag.
    pub self_revocation: Option<Vec<u8>>,
```

with the matching `merge` arm and `is_empty` clause.

On self-revocation the host layer persists **two** things in one write:
`self_revocation: Some(bytes)` and `identity: None`. The second handles the
runtime-installed case — with no `settings.identity`, `identity_material`
(`main.rs:629-651`) falls through and the node comes up un-enrolled.

Storing the **record** rather than a bare `revoked: bool` earns its 100 bytes
three ways:

- **It is self-authenticating.** A hand-edited state file cannot forge one
  without the mesh root key.
- **It handles the config-file case**, which clearing `settings.identity`
  cannot. When the identity comes from a YAML `auth:` block
  (`seed_path`/`cert_path`/`trust_anchor_path`), the node must not rewrite the
  operator's config or delete their files — design 15's "a file with one owning
  process has one writer" cuts the same way. So startup, before `set_auth`,
  re-verifies the stored record against the anchor it is about to install: if
  it verifies, names this node's MAC, is unexpired, and cancels this
  certificate (`cert.not_before <= record.not_before`), the node refuses to
  arm, latches `self_revoked`, and re-raises the alarm.
- **It self-expires.** Past `not_after` the anchor rejects it
  (`AuthError::Expired`) and the node may legitimately arm again — by which
  point the certificate it cancelled has expired too, since `not_after` is
  documented as at least the cancelled certificate's own `not_after`
  (`revoke.rs:36-42`). The bound stays consistent without inventing a policy.

Clearing `self_revocation` is a side effect of a successful `SetAuth` — see
§4.6. **No RPC clears it directly.**

### 4.5 The alarm

A new `AlarmKind::SelfRevoked`, code `8`, string `"self_revoked"`
(`libs/wayfinder-alarm/src/lib.rs:154-205`), subject = this node's MAC. It
carries the operator-facing remedy, which is the whole point of requirement 2:
this node's membership was revoked; it is inert until re-enrolled.

Two mechanical notes:

- `libs/wayfinder` does not currently depend on `wayfinder-alarm`. Rather than
  add that edge to the `no_std` heap-free core, raise the alarm in the **host
  layer** off the drained latch — `wayfinder-driver` already depends on both.
  Startup's boot-time refusal (§4.4) raises the same alarm.
- Nothing in production calls `with_board`; the only callers are tests. A raise
  from a shared process therefore lands on `PROCESS_BOARD`, and in the
  multi-node simulator every node's alarm merges into one board. Not a blocker
  for this design, but it means the simulator cannot assert per-node
  attribution — worth a note where the test would otherwise be written.

The projections need the new variant: `libs/wayfinder-protos/src/service.rs`,
`libs/wayfinder-server/src/adapter.rs:308`, `bins/wayfinder-tui/src/ui.rs:505`,
`bins/wayfinder-web/src/format.rs:291,314`.

### 4.6 Recovery — the two paths

Both start from the same place: the node is inert and un-enrolled, but keeps
its seed and MAC, so it still earns `MgmtAccess::GrantedSelfKey` — granted on
the handshake key alone, before the anchor is consulted (`authz.rs:182`), from
the driver's `identity_seed` slot (`driver.rs:979`) rather than from
`router.auth()`. Clearing `auth` does not touch it.

**Same mesh.** Operator connects at the self-key tier, node enrolls through the
normal admin-gated queue, `SetAuth` installs the new certificate. Because Part
A landed first, the re-issued certificate's `not_before` is at or after the
record's, so peers accept it immediately and no waiting on `not_after` is
involved.

**Different mesh.** Same reachability, then `SetAuth` with the new mesh's
trust anchor and certificate. `verify_revocation` checks `mesh_id`
(`revoke.rs:94-96`), so mesh A's record is inert in mesh B regardless. Clearing
the anchor on self-revocation is a *prerequisite* for this path, not an
obstacle.

`SetAuth` must therefore clear `self_revocation` and the `self_revoked` latch
**as part of the same durable write** that installs the new identity, and only
when the installed certificate is not itself cancelled by the stored record.
That last clause is what prevents an unlock by re-installing the revoked
certificate.

### 4.7 The certificate authority must refuse to revoke itself

`ingest_signed_revocation` (`libs/wayfinder-driver/src/driver.rs:842-882`) runs
*after* the authority has signed and durably recorded the revocation — its own
docstring says so. So `wayfinderctl provider revoke <ca-mac>` against
`nix/machines/wayfinder-ca` would be a one-request, irreversible self-destruct:
the CA goes inert and partitions the hub it routes for, and clearing `auth`
empties `anchor` in `build_auth_snapshot`, dropping every admin connection to
`GrantedEnrollment` (`authz.rs:188`) — no `ApproveCsr`, no `RevokeNode`, no
account administration, and the mesh can enroll nobody.

**The authority must refuse a self-naming `RevokeNode` before it signs.** Do
this in MR 2 alongside the rest; it is a few lines and the failure mode is
unrecoverable without the CA's own seed.

The trailing `Err("it names this node, which never floods its own
revocation")` at `driver.rs:881` also becomes a false explanation and must be
rewritten to describe what actually happened.

---

## 5. Correctness and edge cases

### 5.1 The OGM tail is not covered by the OGM signature

**This is the finding that sets the MR order.** `signed_message`
(`auth.rs:784`) signs `SIG_DOMAIN || orig || seqno || cert_bytes` and nothing
else — deliberately, so the signature survives forwarding (`auth.rs:773-777`).
`ingest_revocations_from_tail` (`auth.rs:1465`) then runs on that unsigned
tail from `verify_ogm` (`auth.rs:1109`).

So anyone who captures one valid OGM and one root-signed revocation record —
both of which travel in the clear, and the latter is dissected by
`wayfinder-shark` — can splice the record into the tail and replay. The
originator's signature still verifies, because none of the bytes it covers
changed.

Today this is harmless: each record is independently root-signed, ingestion is
MAC-deduped (`auth.rs:536-543`) and idempotent. **Part B without Part A removes
that harmlessness.** The self-naming branch becomes destructive and does not
dedupe, and because the MAC survives re-enrollment, the loop is:

> operator re-enrolls → attacker replays the spliced frame → node self-revokes
> → repeat, indefinitely, with no key material required.

Part A's gate 4 closes it: a replayed old record's `not_before` is earlier
than the re-issued certificate's, so it no longer cancels it. In
the *other* direction the record is genuinely current and the node genuinely
should stop — which is the intended behaviour, not an attack.

Note the loop only bites at re-enrollment: while the node is locked,
`handle_frame_with_metrics` returns at `lib.rs:978` before `verify_ogm` runs,
so replays during lockout do nothing and there is no log or alarm flood.

### 5.2 Clearing auth must not widen anything

Audited: with `auth == None` and `self_revoked` latched, every `auth_locked`
gate in §4.3 fires, so no frame is processed at all. The management API
narrows rather than widens — every non-self-key client short-circuits to
`GrantedEnrollment` (`authz.rs:188`), a closed five-request allowlist, each
rate-limited through `rpc_table!`. The one widening is that a certificate that
would have been `Denied` becomes `GrantedEnrollment`, which is not an
escalation.

The dangerous case is the one §4.3 forbids: `auth == None` *without* the latch
on a `require_auth: false` node.

### 5.3 A future-dated `not_before` must not be acted on early

`verify_revocation` deliberately returns `Ok` for a not-yet-effective record
(`revoke.rs:70-79`) — it is a valid statement about the future, and
`is_revoked` applies the window. If the node went inert immediately while peers
kept `not_before <= now` false, peers would keep advertising and using routes
through a node that drops everything: a silent black hole with no route
withdrawal, which is worse than the purge it was trying to perform. Hence
gate 3, with the record latched and armed when the instant arrives.

### 5.4 `now_unix == 0` must not self-revoke

`verify_revocation`'s expiry test is `not_after <= now_unix` (`revoke.rs:97`),
which passes everything at zero, and `prune_expired` no-ops at zero
(`auth.rs:481`). A node whose clock has never been set could therefore be
bricked by a long-dead record that no live peer still holds and that it could
never garbage-collect. Hence gate 2. This is latent rather than live today (no
embedded target installs auth), but a clockless board is exactly the eventual
audience.

### 5.5 Ordering inside `verify_ogm`

The latch is set from `&mut self` on `OgmAuth` inside `verify_ogm`, while
`CentralRouter` holds it as `self.auth.as_mut()`. Borrowck forbids clearing it
there, which is why §4.1 uses a latch rather than a direct mutation. The
router's drain must precede any use of the frame — see the early-return
requirement in §4.2.

`libs/wayfinder/fuzz/fuzz_targets/verify_ogm.rs:21-22` documents that
`verify_ogm` "only ever reads `self.anchor`/`self.now_unix`/…". That comment
becomes wrong and must be corrected; the harness itself still holds, since the
fuzzer cannot forge a root signature.

---

## 6. Security considerations

**The retained seed is a stated trade-off, not an oversight.** If the
revocation was issued *because* the seed was stolen, the thief keeps everything
this node can do: `MgmtAccess::GrantedSelfKey` permits **every** request kind
with no exception — asserted deliberately at `authz.rs:898-902` — which on a
provider node includes `RevokeNode`, `ApproveCsr`, `RevealEnrollmentToken` and
the whole account-administration surface.

The design keeps the seed anyway, because:

- Wiping it removes the operator's only remote recovery path and, on a node
  reached out-of-band, makes it unrecoverable without physical access.
- The thief's real prize is mesh membership, and that is gone the moment the
  certificate is cleared and peers hold the record. They cannot obtain a new
  one: enrollment is admin-gated at the provider.
- The remedy is available and is what the alarm should say: rotate the identity
  via `SetAuth` **with** a new seed, which is a wholesale identity install and
  changes the MAC (`set_auth_with_a_seed_allows_a_new_mac`,
  `adapter.rs:2678`).

**Re-issuing to the same key re-blesses the revoked key material.** After Part
A, a re-issued certificate with the same seed differs from the old one only in
`not_before`/`not_after` (and therefore its signature and fingerprint) — it
binds the same key to the same MAC. That is correct for the §1.2 reasons an
operator revokes, and wrong for genuine compromise. `RevocationRecord.flags` is
reserved and sent as 0; a `KEY_COMPROMISED` bit that the CA refuses to re-issue
against is the natural home for that distinction. **Not in scope here** — noted
so it is not re-derived later.

---

## 7. Alternatives considered

### 7.1 Keying revocation on a certificate fingerprint instead of a date

Rejected. `MembershipCert::fingerprint()` is 8 bytes and its own documentation
is explicit that it is *not* a trust boundary — only collision-resistant among
legitimate certificates, because a fetched certificate is always re-verified
against the anchor (`cert.rs:145-155`). Keying revocation on it would make it
one, requiring a widening to 16+ bytes, and would change the CA's job: "revoke
node X" would expand to one record per unexpired certificate ever issued to X —
N floods against a bounded `MAX_REVOKED` (32) and a bounded per-OGM
attachment budget, where today it is one.

Fingerprint keying buys exactly one thing an invalidity date cannot: revoking
one live credential while leaving another live credential for the same MAC
valid. That case does not arise here — `SetAuth` installs one certificate per
device, and user session certificates derive their MAC from the session key so
they never share one (`authority.rs:87`), which is also why design 14's
account-scoped revocation does not need it either.

### 7.2 A separate `certs_before` field alongside `not_before`

Rejected — see §3.1. The two would never legitimately differ, and the second
field's failure mode (set inconsistently, or left at 0) is silent. Collapsing
them keeps the record at 92 bytes and leaves the dissector a one-line change.

### 7.3 Reusing `require_auth` as the latch

Rejected — see §4.3. Remotely clearable over the self-key tier, persisted, and
its "off" position is more open than the pre-revocation state.

### 7.4 Wiping the seed and MAC on self-revocation

Rejected — see §6. Considered seriously: it is the only option that locks a
seed thief out of the node, and because `load_or_generate_seed`
(`main.rs:146`) and `load_or_generate_mac` (`main.rs:103`) mint fresh values
when their files are absent, a wiped node would self-heal into the normal
first-boot enrollment queue. It loses to the recovery argument, and it does
nothing for nRF boards, whose MAC is FICR-derived and cannot change.

### 7.5 Storing the record in the peer-enforcement set

Rejected. There is no third party to keep dropping frames from, so the record
has no enforcement job. It is stored in `NodeSettings` as boot-time policy
instead (§4.4), which is a different purpose and a different owner.

---

## 8. Observability

- **Alarm** — `AlarmKind::SelfRevoked` (§4.5), latched and coalesced, carrying
  the remedy.
- **Security view** — self-revocation must be distinguishable from "never
  enrolled". Without it, `NodeInfo.auth_locked` (`adapter.rs:514`) and
  `SecurityStatus.require_auth` (`adapter.rs:635`) report the bootstrap
  posture, which reads as "provision me". Add a `self_revoked` bool and the
  record's `not_after` to the security-state response so the operator can see
  *when* enforcement lapses. Use the `add-metric` skill for the wire-to-TUI
  path.
- **Logs** — the state transition is `error!` (an operator must act, and it
  originates here). The per-record `warn!` at `auth.rs:534` goes away; repeats
  are absorbed by the alarm's coalescing and, after lockout, never reach the
  ingest at all (§5.1).

---

## 9. Open decisions for the implementing session

1. **Whether `is_revoked`'s three core call sites all have the certificate.**
   §3.2 asserts they do or can reach it; confirm per site. A site with only a
   MAC must fail conservative *and* say so in a comment.
2. **`AuthSnapshot.revoked`'s new shape** — `Vec<RevocationRecord>` is
   recommended (§3.2), but a router-built closure is viable if it does not
   reintroduce a router borrow on the accept loop.
3. **Where the boot-time check lives** — `bins/wayfinder-tap/src/main.rs`
   before `set_auth` is the obvious spot, but `RouterAdapter` may be the better
   home if the embedded `mgmt` path is ever to inherit it.
4. ~~**The tie at `cert.not_before == record.not_before`.**~~ **Decided:**
   `<=`, so a certificate issued in the *same second* as the revocation is
   cancelled. A revocation is a security control and the tie resolves toward
   revoking; re-admission is a deliberate act the authority can trivially
   stamp one second later, so the cost is nil and the alternative leaves a
   same-second hole. §3.2's predicate and the doc comment both read `<=`.
5. **Which error `verify_revocation` returns for `not_before == 0`** (§3.1) —
   a new `AuthError` variant is clearer than reusing `BadVersion`, at the cost
   of a variant every matcher must handle.

---

## 10. Key file map for the implementer

**Part A**

- `libs/wayfinder-auth/src/revoke.rs` — `not_before`'s doc comment,
  `REVOKE_VERSION` 1→2, `verify_revocation`'s non-zero check.
- `libs/wayfinder-auth/src/authority.rs:152` — `revoke` drops its `not_before`
  parameter and stamps `now`; every `revoke(mac, 0, …)` call site across the
  test suites follows.
- `libs/wayfinder/src/auth.rs:578` — `is_revoked` takes a cert; call sites at
  `1067`, `1191`, `1347`.
- `libs/wayfinder-server/src/authz.rs:180,297,299` — the predicate's signature.
- `libs/wayfinder-driver/src/driver.rs:989-999` — `build_auth_snapshot`.
- `libs/wayfinder-shark/` — dissector + pytest fixtures.
- `libs/wayfinder-auth/fuzz/fuzz_targets/verify_revocation.rs` — corpus.

**Part B**

- `libs/wayfinder/src/auth.rs:517` — the four gates and the latch; delete
  `self_revocation_is_a_noop` (`2149`) and replace it.
- `libs/wayfinder/src/lib.rs:896` — `auth_locked`; `905-923` and `1055` — the
  drains; `1230` — the early return.
- `libs/wayfinder-py/src/driver.rs:232-235` — the third drain.
- `libs/wayfinder-server/src/settings.rs:59` — the `NodeSettings` field,
  `merge`, `is_empty`.
- `libs/wayfinder-server/src/adapter.rs:1052` — `SetAuth` clears the latch;
  `514`/`635` — the security-view fields.
- `libs/wayfinder-driver/src/driver.rs:842-882` — the authority's self-revoke
  refusal and the corrected error string.
- `bins/wayfinder-tap/src/main.rs:629-679` — the boot-time check.
- `libs/wayfinder-alarm/src/lib.rs:154-205` — the variant; projections in
  `libs/wayfinder-protos/src/service.rs`,
  `libs/wayfinder-server/src/adapter.rs:308`, `bins/wayfinder-tui/src/ui.rs:505`,
  `bins/wayfinder-web/src/format.rs:291,314`.
- `libs/wayfinder/fuzz/fuzz_targets/verify_ogm.rs:21-22` — correct the comment.

---

## 11. What Part A's implementation found

Three deviations from §3 as written, all discovered while building it.

**`Authority::revoke` keeps its `not_before` parameter.** §3.1 proposed
removing it so a caller could not pass zero.  Unnecessary: the production CA
already passes its own clock (`libs/wayfinder-server/src/authority.rs:1054`
and `:2115`), so only test code ever passed zero.  `verify_revocation`'s
non-zero check is what actually enforces the invariant, and dropping the
parameter would have cost the Python binding its ability to date a record
(`libs/wayfinder-py/src/auth.rs:406`) for no gain.  Every
`revoke(mac, 0, …)` in the test suites moved to a real instant, which was the
bulk of the diff as predicted.

**`VerifiedCert` gained a `not_before` field.** Not anticipated at all.  §3.2
assumed the three enforcement call sites could reach the certificate they were
judging, and they can — but what they hold is a `VerifiedCert`, which carried
`not_after` and *not* `not_before`.  Without it every revocation check would
have had to re-parse the raw certificate, so the issuance instant is now
carried through verification alongside the expiry.

**The predicate lives in `wayfinder-auth`, not duplicated at each caller.**
§3.2 spelled the four-clause condition out inside `OgmAuth::is_revoked` and
left the management-API path to build its own.  Two copies of a
security-critical condition in two crates is how they drift, so it is
`RevocationRecord::cancels(&self, cert, now_unix)` in
`libs/wayfinder-auth/src/revoke.rs`, and both the router and
`authorize_capability` call it.  `AuthSnapshot.revoked` became
`Vec<RevocationRecord>` as §3.2 recommended, which is what lets the accept
loop evaluate it without a router borrow.

**Not verified locally:** the Wireshark dissector change.  Its pytest suite
does not run in this environment — 44 failures and 13 collection errors on a
clean tree, unrelated to this work — so the version bump in
`libs/wayfinder-shark/tests/test_ogm_dissector.py` and the field relabel in
`wayfinder.lua` are unexercised.  CI's `test:run:python` job covers them.
