# Design: Four gaps in mesh authentication, found by adversarial simulation

**Status:** Proposed. Each gap is a separate, independently landable change;
this document exists so they can be taken one at a time without re-deriving the
analysis. Gap 3 is fixed in its own MR alongside this doc; gaps 1, 2 and 4
remain open. The instrument that found them shipped in MR !113
(`sim/scenarios/red_team.py`).

**Scope:** `libs/wayfinder/src/auth.rs` (`OgmAuth`: OGM verification, the
neighbor-key cache, the directed-frame tag path), `libs/wayfinder-auth`
(`verify_cert`, `AuthError`), `libs/wayfinder-server/src/authority.rs`
(`submit_csr`), `bins/wayfinder-ctl/src/cert.rs` (offline `issue`/`approve`),
and — for gap 2 only — `libs/batman/src/wire.rs` (`TvlvType`) plus every
driver shell that supplies a clock. No change to `LinkT`/`FrameIo`, to the
routing engine's path selection, or to `MembershipCert`'s layout.

**Threat model, restated up front.** Wayfinder buys *authenticity* and *mesh
segregation*. It never buys confidentiality — payloads are not encrypted, and a
listener in radio range reads them whether or not the mesh is authenticated.
None of the gaps below are about secrecy; they are about an outsider affecting
routing, or a member outliving its credential.

---

## 1. Motivation

`sim/scenarios/red_team.py` runs ten attacks against a real authenticated mesh
and classifies each from measured router state. Five held; one succeeded by
design (passive eavesdropping); four are gaps.

| # | Gap | Impact | Severity |
|---|-----|--------|----------|
| 2 | OGM replay against a receiver with no prior state | **Interception** + blackhole | **Critical** |
| 1 | Unauthenticated OGM relay poisons the route table | Silent blackhole (availability) | High |
| 4 | Certificate MAC is not bound to its key | Impersonation, reachable via the shipped CSR path | High |
| 3 | Certificate expiry does not evict a cached neighbor | Lapsed member keeps link-local data plane | Medium |

They are not independent: **gap 2's fix (freshness) also substantially
mitigates gap 1**, and the natural mechanism for gap 1 (a per-hop forwarder
signature) reuses gap 2's freshness field. Fixing them in the order 2 → 1 → 4
avoids building a mechanism twice. Gap 3 is orthogonal and cheap.

Every claim below was verified empirically against the real router, not
inferred from reading the code. The reproducing test is named for each.

---

## 2. Gap 2 — OGM replay (critical)

### What happens

`OgmAuth::signed_message` covers `SIG_DOMAIN ‖ orig ‖ seqno ‖ cert_bytes`. It
binds **no freshness** — no timestamp, no nonce. Replay protection is the
receiver's per-originator sequence-number state, so it protects only a receiver
that *has* such state.

Against a receiver that does not — a node that just booted, or one out of the
real originator's radio range — a single captured OGM, replayed verbatim, is
accepted. The victim then:

1. installs a route to the absent originator,
2. **admits it as a verified neighbor**, caching the cert the replay carried,
3. derives a pairwise key from that cert, and
4. **emits real application payloads onto the attacker's link**, tagged for an
   originator that is not there.

Step 4 is what makes this critical rather than merely a phantom route. The
attacker cannot forge the tag, but payloads are not encrypted, so it reads
them — and the real originator never sees the traffic. Interception *and*
blackhole, from one captured broadcast and no credential whatsoever.

Reproduced by `test_a_captured_signed_ogm_replays_against_a_node_with_no_prior_state`
(`sim/tests/test_adversary.py`).

Also confirmed: `ttl` and `tq` are outside the signature (deliberately — they
are per-hop mutable) and can be rewritten freely on a replay. This is a
*documented* exclusion and is mitigated by the engine's TQ clamp against
locally-measured link quality (`auth.rs`, `signed_message`'s doc); it is noted
here only so it is not re-discovered as a separate finding.
`test_tq_and_ttl_are_mutable_but_the_signed_identity_fields_are_not` pins both
halves.

The lazy-cert design doc (`implemented/01-lazy-cert-distribution.md` §"Rotation/replay")
states that replaying an old `(fingerprint, OGM, sig)` triple is "bounded by
existing OGM seqno replay protection and by cert validity windows". That is
true only for a receiver that already holds newer seqno state. The bound that
actually applies to a fresh receiver is the **certificate lifetime** — 24 h in
the simulator's default, and whatever `cert_ttl_secs` the provider is
configured with in a deployment.

### Proposed fix — bind a coarse time bucket into the OGM signature

Mirrors the mechanism `augment_keepalive`/`verify_keepalive` already use in
this same file, which exists for exactly this reason ("bounds how long a
captured, genuinely signed heartbeat can be replayed").

Extend the `TvlvType::OgmSig` (`0x81`) value from `[sig:64]` to
`[bucket:8][sig:64]`, and change the signed message to:

```
SIG_DOMAIN ‖ orig ‖ seqno ‖ bucket ‖ cert_bytes
```

where `bucket = now_unix / OGM_BUCKET_SECS`, big-endian. A receiver rejects an
OGM whose bucket is outside `[current - OGM_TOLERANCE_BUCKETS, current]`.
Replay is then bounded to `(OGM_TOLERANCE_BUCKETS + 1) * OGM_BUCKET_SECS`
instead of the certificate lifetime.

The length change is self-enforcing as a flag day: the existing
`if sig_bytes.len() != SIG_LEN` check rejects the old 64-byte form, and an old
node rejects the new 72-byte form the same way. No version negotiation is
needed, but every node on a mesh must cut over together.

### The open question this is blocked on

**Where does a node get wall-clock time?**

Freshness binding makes OGM *acceptance* depend on cross-node clock agreement.
Today the wall clock is used only for certificate-window checks, so a node with
a bad clock fails a narrower set of cases.

- **Host** — fine. `wayfinder-driver`'s `refresh_auth_clock`
  (`driver.rs:277`) feeds `epoch_unix + now` from the system clock.
- **Tick/simulation** — fine. `Driver::set_epoch_unix`.
- **Embedded — there is no wall clock at all.** `wayfinder-embedded-driver`
  never calls `auth.set_time()`; its `Clock` is monotonic only, and the code
  says so explicitly at `libs/wayfinder-embedded-driver/src/lib.rs:467`: *"No
  `.with_epoch_unix(...)`: `Clock` (above) is monotonic only, with no
  wall-clock source to supply one from."* An nRF52840 has no RTC battery and
  no NTP.

So the question to settle before implementing gap 2 is: **how does an embedded
node learn unix time, and what does it do before it has?** Options, none yet
chosen:

1. **A `SetTime` management RPC** (or fold it into `SetAuth`), with the node
   holding monotonic offset from the last set. Requires a management
   connection at boot; a node that boots unattended has no time until one
   arrives.
2. **Timestamp distribution over the mesh itself** — e.g. the bucket in a
   verified OGM *is* a time source. Circular for the first OGM, and trusting
   peers for time is a trust-boundary decision of its own (a lying member can
   shift a victim's clock and thereby its replay window).
3. **Accept a monotonic-only fallback for embedded**: skip the freshness check
   when `now_unix == 0` ("clock never set"), preserving today's behavior on
   embedded and hardening only nodes that have a clock. Simple, but leaves
   exactly the constrained nodes least able to notice an attack unprotected,
   and gives an attacker a reason to *prevent* clock sync.
4. **Persist a monotonically-advancing "highest time seen"** in
   `wayfinder-storage`, so a node at least never goes backwards across a
   reboot. Bounds replay to "since the node last had a good clock" rather than
   absolutely.

This is a genuine trust/deployment decision, not a coding one, which is why it
is called out rather than settled here.

---

## 3. Gap 1 — unauthenticated OGM relay (high)

### What happens

An OGM's link-layer sender becomes the **next hop** for that OGM's originator.
Nothing in the OGM attests to the sender: the signature covers the originator,
and BATMAN's forwarding model has every relay re-flood a member's OGM under its
own source address.

So an outsider holding no credential at all can capture a member's genuine,
correctly-signed OGM and re-flood it under its own MAC. Victims install a route
to that member **with the outsider as next hop**.

It is *not* interception, and the reason matters: the victim has no verified
cert for the outsider, therefore no pairwise key, so `plan_dispatch` drops the
frame rather than emitting it unauthenticated. Traffic is discarded at the
source. The result is a **silent blackhole** — `has_route` reports success, and
sends vanish with no counter anywhere recording it.

Reproduced by `test_an_outsider_can_relay_a_members_ogm_but_cannot_carry_its_traffic`
(`sim/tests/test_adversary.py`).

### What does *not* fix it

A first attempt gated `verify_ogm` on the sender being a cached, unexpired
member (`src == orig || live_neighbor(src).is_some()`). **This is
insufficient**: the check is a lookup keyed on a MAC the attacker writes into
the frame header, with nothing binding the header to key possession. The
attacker spoofs any member's MAC the victim has already cached and is admitted.
Verified — the bypass reproduced as a passing test before that work was
reverted. Recorded here so it is not re-attempted.

It is a cheap *necessary* condition, and worth keeping as part of a real fix,
but it must not ship as the fix.

### Proposed fix — a per-hop sender attestation

A per-frame proof from the forwarder. It has to be a signature: an OGM is
broadcast one-to-many, so a pairwise tag (which is how the directed data plane
solves the same problem) cannot cover it.

New `TvlvType::SenderSig` (`0x84`), value `[sig:64]`, written by the
*transmitting* node and **rewritten at each hop**:

```
FWD_SIG_DOMAIN ‖ sender_mac ‖ orig ‖ seqno ‖ bucket
```

reusing gap 2's `bucket` from the `OgmSig` TVLV — one freshness clock per
frame, two signatures over it. Without the bucket the forwarder signature is
itself replayable and the attack returns.

Verification rule:

- `src == orig` → no `SenderSig` required; the originator's own signature
  already attests the sender. This is also the bootstrap case, so a node can
  still learn a first neighbor.
- `src != orig` → require a `SenderSig` verifying against the cached cert for
  `src`, which must be unexpired and not revoked.

Costs, stated plainly:

- **+68 bytes on relayed OGMs only** (64-byte value + 4-byte TVLV header).
  First-hop OGMs pay only gap 2's +8.
- **One Ed25519 signature per forwarded OGM per node.** On a Cortex-M4 that is
  order 1–2 ms; on a node relaying for several neighbors this is a real load
  and should be measured before committing.
- **LoRa/802.15.4 payload budget.** An 802.15.4 frame is 127 bytes total and a
  RYLR998 fragment carries 164 usable bytes; OGMs already fragment. With lazy
  cert distribution (fingerprint rather than full cert) a relayed OGM goes from
  roughly 112 to roughly 196 bytes. Without it, from roughly 260 to 344. This
  makes lazy cert distribution close to a prerequisite on constrained links.

**Explicitly rejected:** having a relay *replace* the originator's signature
with its own. That collapses the model from originator-authenticated to a
transitively-trusted chain — a single compromised member could then invent
originators. The forwarder's credential must be additive.

### What this does not fix, and cannot

A **compromised member** — one holding a valid certificate — can do all of this
legitimately: relay OGMs, win the next-hop contest with a genuinely strong
link, and then silently discard everything. No signature scheme prevents that,
because every step is something a well-behaved relay also does. Detecting it
needs forwarding verification (a watchdog, or end-to-end delivery feedback),
which this codebase has deliberately kept out of the link abstraction
(`LinkT` is fire-and-forget; see the "minimal link abstraction" decision).
Worth stating so the ceiling of gaps 1 and 2 is not overestimated: they raise
the bar from *no credential* to *a valid credential*, which is exactly what
revocation is then for.

---

## 4. Gap 4 — certificate MAC is not bound to its key (high)

### What happens

`TrustAnchor::verify_cert` checks the version, the mesh id, the root signature
and the validity window. It does **not** check that `node_mac` is the address
`ed_pubkey` derives. A certificate binding a key to somebody else's address
therefore verifies perfectly.

This is worse than "a misissuing CA could hand out impersonation", because the
shipped CA *will*: `CertAuthority::submit_csr`
(`libs/wayfinder-server/src/authority.rs:722`) takes `node_mac` **from the
client**. Its only guard is that the MAC does not already hold a valid,
non-revoked certificate under a different key — which is first-come, not
proof-of-ownership. An attacker that passes the enrollment-token check can
claim any address not currently covered by a live cert, including one whose
cert has lapsed.

`wayfinderctl cert issue --mac` and `cert approve` have the same shape offline.
(`issue_user_cert`'s callers already derive the MAC — `authority.rs:665` — so
user session certs are unaffected.)

Reproduced by `test_a_certificate_may_name_a_mac_its_key_does_not_derive`
(`sim/tests/test_security.py`).

### Proposed fix

Two layers:

1. **Verification side** — `verify_cert` rejects
   `derive_mac(&cert.ed_pubkey) != Mac(cert.node_mac)` with a new
   `AuthError::MacKeyMismatch`. This is the valuable half: it means even a
   *compromised CA* cannot mint an impersonation credential, because it would
   need a hash preimage. It turns the key↔address binding from a policy one
   node cannot audit into an invariant every node enforces for itself.
2. **Issuance side** — reject the mismatch in `submit_csr`, `cert issue`
   (validate an explicit `--mac` rather than silently honoring it) and
   `cert approve`, so the failure surfaces where the mistake is made rather
   than as "issued fine, rejected by every node".

### Consequences to accept before implementing

- **Key rotation at a fixed MAC becomes impossible.** If the address is derived
  from the key, re-keying necessarily changes the address; a re-keyed node is a
  new originator. Certificate *renewal* (same key, new window) still works, and
  still changes the fingerprint, so the existing `CertFp` → `NeedCert` refetch
  path is still needed and still exercised. Two existing tests assert rotation
  at a fixed MAC and must be converted to renewal.
- **Test churn is wide but mechanical.** Enforcing this broke 67 tests across
  `wayfinder-server`, `wayfinder-test` and `wayfinder-ctl` — every fixture that
  mints a cert for an invented MAC. The fix is for test helpers to derive MACs
  rather than invent them; where a module's `mac(n)` helper is paired
  consistently with seed `n`, redefining that one helper fixes the whole
  module at once. `wayfinder-test` is the awkward one: node identity there comes
  from the switch *topology*, so making it derive touches all 63 routing tests,
  not only the auth ones, and MAC ordering changes (worth watching for
  tie-break-sensitive assertions).

---

## 5. Gap 3 — certificate expiry does not evict a cached neighbor (medium)

### What happens

Verifying an OGM caches the peer's `VerifiedCert` *and* the pairwise key
derived from it. `cache_neighbor` only ever overwrites an entry; nothing prunes
one whose certificate has expired. `tag_directed` and `verify_directed` look
the pairwise key up by MAC without consulting `not_after`.

So when a member's enrollment lapses: its OGMs stop verifying and its route
correctly ages out, but **the link-local data plane between it and any neighbor
that already admitted it keeps working**, indefinitely. Certificate expiry is
documented as the mesh's *passive* revocation mechanism — "what bounds the
damage from a leaked key with no network" — and it does not, for an adjacent
peer. Only an active revocation does.

Reproduced by `test_expiry_does_not_cut_off_an_already_cached_neighbor`
(`sim/tests/test_security.py`).

### Fix

A `live_neighbor(mac)` accessor that treats an expired certificate as absent,
with every neighbor lookup (`neighbor_x_pubkey`, `neighbor_cert`,
`tag_directed`, `verify_directed`) routed through it, plus an
`evict_expired_neighbors()` sweep in `set_time` so the bounded table cannot
fill with lapsed members and start evicting live ones. Both guard on
`now_unix == 0` ("clock never set"), matching `prune_expired`'s existing
behavior — otherwise an unset clock evicts everything.

One behavior change falls out: an expired cached cert previously produced
`OgmVerdict::Rejected` on the fingerprint path; with the entry evicted, the
fingerprint no longer resolves and the verdict is `NeedCert`. Both drop the
OGM, which is the security property. `NeedCert` additionally attempts a fetch,
which is what recovers the link if the peer has since renewed.

No wire change, no new dependency, no clock requirement beyond what cert
validity already needs.

---

## 6. Observability (applies to gaps 1 and 2)

Per the root `CLAUDE.md`'s "metrics are first-class": the blackhole in gaps 1
and 2 is currently **silent**. `tag_directed_into`
(`libs/wayfinder-driver-core/src/lib.rs:215`) drops an untaggable directed
frame with a bare `warn!` and no counter, so a poisoned route is
indistinguishable from a healthy one to an operator, and to an application
sitting on top of the mesh.

Two things to fix together, in one small MR that does not depend on any of the
above:

1. **A bounded counter or rate on `CentralRouter`** for directed frames dropped
   for want of a pairwise key with the next hop, surfaced over the management
   API and on the TUI Metrics tab (use the `add-metric` skill). Prefer a
   `RateEstimator` over a monotonic total, per the same rule.
2. **Demote the `warn!` to `trace!`.** It is reachable by arbitrary remote
   input on a hot path, which `CLAUDE.md`'s logging rules forbid at `warn!` —
   an attacker can drive it as a log flood today.

State lives in `CentralRouter`, not the driver, so an embedded node has it too.

---

## 7. Sequencing

1. **Gap 3** — self-contained, no wire change, no open questions. Landing
   alongside this doc.
2. **Observability (§6)** — small, independent, and makes the remaining gaps
   visible while they are still open. Worth doing before the hard ones.
3. **Gap 2** — highest severity, but blocked on the wall-clock question (§2).
   Settle that first.
4. **Gap 1** — reuses gap 2's `bucket`, so it must follow it. Measure the
   per-hop signing cost on real hardware before committing.
5. **Gap 4** — independent of 1–3, but the widest test churn; best done when
   nothing else is in flight to avoid conflicts.

## 8. Key file map for the implementer

| File | Gaps | What changes |
|------|------|--------------|
| `libs/wayfinder/src/auth.rs` | 1, 2, 3 | `signed_message`, `augment_ogm`, `verify_ogm`, `cache_neighbor`, `live_neighbor`/`evict_expired_neighbors`, `set_time`, `tag_directed`, `verify_directed`, `neighbor_cert`, `neighbor_x_pubkey` |
| `libs/batman/src/wire.rs` | 1 | `TvlvType::SenderSig = 0x84` |
| `libs/wayfinder/src/lib.rs` | 1 | `verify_ogm` call site gains `frame.src` |
| `libs/wayfinder-auth/src/cert.rs` | 4 | `verify_cert` MAC/key check |
| `libs/wayfinder-auth/src/error.rs` | 4 | `AuthError::MacKeyMismatch` |
| `libs/wayfinder-server/src/authority.rs` | 4 | `submit_csr` derivation guard (~line 722) |
| `bins/wayfinder-ctl/src/cert.rs` | 4 | `issue` (`--mac` validation), `approve` (CSR MAC check) |
| `libs/wayfinder-driver-core/src/lib.rs` | §6 | `tag_directed_into` counter + `warn!` → `trace!` (line ~215) |
| `libs/wayfinder-embedded-driver/src/lib.rs` | 2 | wall-clock source, once §2's question is settled (see line 467) |
| `sim/tests/test_security.py`, `sim/tests/test_adversary.py` | all | the gap tests flip from asserting the gap to asserting the fix |
| `sim/scenarios/red_team.py` | all | verdicts flip `GAP` → `HELD` |
