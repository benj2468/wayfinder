# Design: Four gaps in mesh authentication, found by adversarial simulation

**Status:** Implemented — every gap this document tracks has shipped. Each was
a separate, independently landable change; the document exists so they could be
taken one at a time without re-deriving the analysis, and it is kept as the
record of *why* each was fixed the way it was. Gaps 1, 2, 3 and **4** shipped,
as did §7's observability, the three later findings logged in §8.7–§8.9, and
both findings from the 2026-08 sweep (§8.10, §8.11). The instrument that found
them all shipped in MR !113 (`sim/scenarios/red_team.py`).

Read the per-section notes before changing any of this code: several of the
fixes have an obvious-looking simplification that was measured and rejected, and
each says which.

> **§4 supersedes part of §2 and §3.** A second round of measurement showed
> gaps 1 and 2 to be one bug, and neither section's proposed fix closes it.
> Read §4 before implementing either.
>
> **§4's fix has since shipped**, closing gaps 1 and 2 together. §4's
> "Implementation notes" record four things the build surfaced that the design
> did not predict; the fourth is the proof-starvation scare, which was a
> mismeasurement rather than a gap.

**Where the red team stands.** It runs 46 attacks and reports **43 held, 3 by
design, 0 gaps**. The three "by design" verdicts are not gaps in waiting: they
are properties this mesh deliberately does not claim (no confidentiality, a
revocation stamped in the same second as the certificate it cancels resolving
toward revoked, and an unbounded certificate lifetime being accepted while
active revocation remains the backstop). Each is argued where it is reported.

`sim/tests/test_red_team.py`'s `BASELINE` is the authority on that count. A
regression flips a verdict in `red_team.py` and fails `BASELINE`; a new finding
is added to both and gets a section here.

**Scope:** `libs/wayfinder/src/auth.rs` (`OgmAuth`: OGM verification, the
neighbor-key cache, the directed-frame tag path), `libs/wayfinder-auth`
(`verify_cert`, `AuthError`), `libs/wayfinder-server/src/authority.rs`
(`submit_csr`), `bins/wayfinder-ctl/src/cert.rs` (offline `issue`/`approve`),
and — for gap 2 only — `libs/batman/src/wire.rs` (`TvlvType`) plus every
driver shell that supplies a clock, plus — for §4 — `libs/batman/src/engine.rs`
and `libs/wayfinder-driver-core`. No change to `LinkT`/`FrameIo` or to
`MembershipCert`'s layout. (§4 *did* change the routing engine's path
selection, which the original scope ruled out; see §9's file map.)

**Threat model, restated up front.** Wayfinder buys *authenticity* and *mesh
segregation*. It never buys confidentiality — payloads are not encrypted, and a
listener in radio range reads them whether or not the mesh is authenticated.
None of the gaps below are about secrecy; they are about an outsider affecting
routing, or a member outliving its credential.

---

## 1. Motivation

`sim/scenarios/red_team.py` classifies each attack from measured router state.
At the time of writing it ran ten: five held, one succeeded by design (passive
eavesdropping), four were gaps. It now runs 14 — see the status note above.

| # | Gap | Impact | Severity |
|---|-----|--------|----------|
| 2 | OGM replay against a receiver with no prior state | **Interception** + blackhole | **Critical** |
| 1 | Unauthenticated OGM relay poisons the route table | Silent blackhole (availability) | High |
| 4 | Certificate MAC is not bound to its key | Impersonation, reachable via the shipped CSR path | High |
| 3 | Certificate expiry does not evict a cached neighbor | Lapsed member keeps link-local data plane | Medium |

They are not independent — and they are less independent than first written.
§2 and §3 originally proposed freshness (a time bucket) for gap 2 and a per-hop
forwarder signature reusing it for gap 1. **§4 shows gaps 1 and 2 to be a
single bug that neither mechanism closes**, and replaces both with one fix.
Gaps 3 and 4 are orthogonal; gap 3 is done.

Every claim below was verified empirically against the real router, not
inferred from reading the code. The reproducing test is named for each.

---

## 2. Gap 2 — OGM replay (critical)

> **Partly superseded by §4.** The mechanism below is real, but the scope
> ("a receiver with no prior state") is too narrow and the proposed fix (a time
> bucket) does not close the attack. §4 has the measurement and the replacement.

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

> **Partly superseded by §4.** The `SenderSig` fix below exempts `src == orig`,
> which is precisely the attacker's case in §4. Its "what does *not* fix it"
> subsection still stands, and generalises.

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

## 4. Gaps 1 and 2 are one bug — and neither proposed fix closes it

Added after §2 and §3 were written, from a second round of adversarial
measurement. It supersedes part of both. Read it before implementing either.

### The measurement

`test_a_replayed_ogm_cannot_take_an_established_route` (renamed from
`test_a_replayed_ogm_hijacks_an_established_route_and_blackholes_it` when the
verdict flipped)
(`sim/tests/test_adversary.py`, parametrised `verbatim` / `tq_maxed`) runs
`hq — relay — {victim, eve}`, where the victim's only real path to hq is
through the relay. Eve holds no credential. She re-emits the freshest OGM she
has heard under **hq's spoofed link-layer source**, four times a second.

Measured, deterministically, on a victim whose route is live and converged:

| | before | after 30 s of replay |
|---|---|---|
| `best_next_hop` for hq | relay | **hq's own MAC** |
| traffic to hq reaching the hq–relay link | — | **none** |

Three consequences that contradict what §2 and §3 assume:

1. **Replay is not confined to a receiver with no prior state.** The engine
   accepts a same-seqno copy as well as a newer one
   (`libs/batman/src/engine.rs`, `handle_ogm`'s seqno banding — equal, not just
   greater, so a same-seqno copy via a second neighbour registers as an
   alternate path; that is how a redundant mesh learns its backup route). An attacker therefore never needs to advance the seqno she
   cannot sign — she replays the *current* one, heard for free off the same
   flood.
2. **She needs no field manipulation at all.** The `verbatim` parametrisation
   alters not one byte — not the unsigned TTL, not the unsigned TQ — and still
   takes the next hop, because every accepted copy refreshes `last_heard` while
   the incumbent is refreshed only on real OGMs. Maxing TQ (`tq_maxed`) merely
   makes it immediate rather than eventual.
3. **This one is *not* the "silent blackhole" of §3.** Spoofing the
   originator's MAC rather than her own means the next hop is a verified member
   whose pairwise key the victim holds — so the `plan_dispatch` gate that saves
   §3 from being interception *passes*, and the victim really transmits. The
   same probe with Eve's own source confirms the contrast: next hop stolen in
   both cases, frame emitted only when the source is spoofed.

### Why §2's time bucket does not fix it

Binding `bucket` into the OGM signature bounds how *old* a replayed OGM may be.
Eve replays the **current** OGM, so she is always inside the freshness window,
whatever its width. The bucket closes the stale-OGM-at-a-fresh-receiver case §2
describes and nothing more. It remains worth doing; it is not a fix for this.

### Why §3's `SenderSig` does not fix it either

§3's verification rule carves out exactly the attacker's case:

> `src == orig` → no `SenderSig` required; the originator's own signature
> already attests the sender.

Eve's whole move is to set `src == orig`. She drives straight through the
carve-out. The carve-out cannot simply be deleted, because it is also the
bootstrap case — a node with no neighbours must be able to learn a first one.

**So gaps 1 and 2 are not two bugs with two fixes. They are one bug**: the
signature authenticates the *originator's identity*, but the routing table
stores a claim about a *link* ("`orig` is reachable via `frame.src`"), and
nothing about the forwarder is ever checked. Spoof `src = orig` and the claim
is "hq is reachable via hq"; use `src = self` and it is "hq is reachable via
eve". Neither is verified, because no claim about the forwarder ever is.

Cryptographically: the OGM authenticator is publicly verifiable — it must be,
for one-to-many flooding — over static content. **A public authenticator over
static content is inherently replayable**, so possession of it proves nothing
whatsoever about the possessor.

### Three fixes ruled out by measurement

Recorded so none is re-attempted. §3 already records a fourth (the
`live_neighbor(src)` lookup), and it failed for the same reason as (c): a
lookup on an attacker-written MAC is not proof of possession.

- **(a) `>` instead of `>=` for installing a new path.** A speed bump, not a
  fix: Eve replays seqno N+1 on hearing it, before the legitimate copy arrives.
  Hers is then the strictly-newer one and the legitimate copy lands as `==` and
  merely refreshes. She is one hop closer to the victim than the relay is, so
  it is a race she is favoured to win.
- **(b) A timestamp in the OGM signature.** See above — always in-window.
- **(c) Gating route selection on keepalive-proven liveness.** The keepalive
  has the *same* defect: `augment_keepalive` signs
  `KEEPALIVE_SIG_DOMAIN ‖ src_mac ‖ bucket` — public, static — so it proves
  "Alice existed recently, somewhere", never "Alice is at the other end of this
  link, now, talking to me". It cannot fix a flaw it shares. Its documented 60 s
  bound (`(KEEPALIVE_TOLERANCE_BUCKETS + 1) * KEEPALIVE_BUCKET_SECS`) does not
  even bite against an attacker adjacent to a *live* originator: in
  `Alice — Eve — Bob` with Alice out of Bob's range, Eve receives a fresh
  keepalive every interval and sustains the spoof indefinitely.

### What the data plane already got right

`verify_directed` (`auth.rs:651`) has both properties the control plane lacks:

- a **receiver-bound** authenticator — a pairwise X25519 key, so a tag for Bob
  is meaningless to Carol, and Eve, holding no key, cannot produce one at all;
- **receiver-controlled freshness** — a per-neighbour strictly-monotonic
  receive counter (`accept_recv_counter`), with `next_send_counter` failing
  closed rather than reusing a value, "since a `(key, counter)` reuse with the
  static pairwise key would make tags replayable".

That is IPsec's SA model, implemented correctly, already in this tree. The
control plane never got it because an OGM is broadcast one-to-many and a
pairwise tag does not broadcast.

The IPsec comparison is worth stating precisely, because the OGM seqno *looks*
like an anti-replay counter and is not one. IPsec's per-SA sequence number
(RFC 4303 §3.4.3) works because the integrity key is pairwise-secret, so a
counter value is unforgeable, **and** because the window is initialised by a
live IKE handshake with nonces and DH, which proves the peer is present *now*.
The counter maintains freshness; it never creates it. Wayfinder has the counter
with no handshake underneath it — hence a receiver with state is protected and
a receiver without has nothing.

### The fix: split the two claims

The OGM currently conflates two claims that have different audiences.

- **"`orig` is a member, and this is its seqno N"** — genuinely one-to-many.
  Keep the public signature exactly as it is. No wire change, no extra bytes on
  a 164-byte LoRa fragment.
- **"`orig` is reachable through me"** — only ever acted on for the *chosen*
  next hop, and next-hop changes are rare. Verify it **pairwise, on demand**:
  before promoting a new `best_next_hop`, challenge the proposed neighbour with
  a fresh nonce and require a `frame_tag` response under the pairwise key.

Eve cannot answer (no key), cannot replay an old answer (the nonce is fresh and
receiver-chosen), and cannot reuse another node's answer (the key is pairwise).
In the dead-originator case there is nothing to answer at all, so the route
drops.

Two design notes that follow from the costs in §3:

- **Tag, do not sign.** A signed nonce costs an Ed25519 sign per challenge per
  neighbour per interval (order 1–2 ms each on a Cortex-M4, per §3's own
  estimate) plus a verify. `frame_tag` is 16 bytes, symmetric, microseconds,
  and already in the tree.
- **Do not run it at keep-alive rate.** It is load-bearing at exactly one
  moment: promoting a new next hop. Block *that*, then refresh the incumbent
  slowly. A continuous per-neighbour challenge is O(neighbours) of extra
  traffic on every link every interval, which runs straight into LoRa
  duty-cycle limits — the same budget pressure that makes §3's +68 bytes per
  relayed OGM painful.

### Residual: wormhole

Challenge-response proves "the holder of `orig`'s key is reachable from me
*somehow*", not "is one hop away". Eve can relay the challenge to a live hq and
pass the answer back, and the victim will believe hq is adjacent.

Accept it, for a reason worth stating: she must then relay continuously and in
both directions, and **if she relays honestly she is a working route** —
traffic flows, which is not the attack. The moment she stops relaying in order
to blackhole, the next challenge fails and the route drops. Eliminating
wormhole needs distance bounding, which is RTT-based and hopeless on LoRa,
where modulation latency dwarfs propagation. This is the right stopping point:
it converts a free, silent, permanent blackhole into an attack that requires
sustained active relaying and delivers traffic while it runs.

### The MACsec relationship

This is MACsec-shaped, and the resemblance is exact rather than loose. IEEE
802.1AE is hop-by-hop link-layer integrity with a SecTAG carrying a
receiver-tracked Packet Number and a replay window per secure association —
that is "authenticate the forwarder", which is precisely the missing X above.
The challenge-response above is a narrow, routing-layer instance of what
MACsec provides generally at the link layer.

**What per-link authentication would subsume.** All of the above, plus
something challenge-response structurally cannot reach: `tag_directed_into`
(`libs/wayfinder-driver-core/src/lib.rs:196`) skips any multicast destination —
"Broadcasts/OGMs (a multicast dst) are signed instead" — but only OGMs actually
carry a signature, so **flooded `Bcast` frames are authenticated by nothing
today** (the scope note at the head of `auth.rs` says as much). Pairwise tags
cannot cover broadcast; a per-link group key can. That is the strongest
argument for going there eventually.

**Two reasons it is not simply "MACsec will solve this later".**

1. *It only helps on links that have it.* Landing it on TAP/Ethernet and not on
   LoRa, 802.15.4 and BLE leaves the gap exactly where a physically present
   attacker is most plausible. So it belongs at the router's frame
   ingress/egress or a shared link layer — not per-driver. Literal 802.1AE does
   not port regardless: MKA is 802.1X/EAP-based, while this tree already has
   Ed25519 identity and X25519 pairwise keys. What is buildable is
   MACsec-*shaped* framing over existing key material — SecTAG-equivalent
   framing, per-link group keys, rekeying, and a replay window per secure
   channel, across four heterogeneous link types. That is a project, not a
   change.
2. *A group key authenticates against outsiders, not insiders.* Every wayfinder
   link is multi-access — LoRa and BLE advertising are shared broadcast media —
   so a per-link connectivity association means a shared key, and any member
   holding it can forge frames as any other member. Eve holds no credential, so
   it stops Eve cold; a compromised node, or a revoked one before the purge
   propagates, could still spoof a peer. On that axis the pairwise
   challenge-response is *stronger*, being per-sender rather than per-group.

So the two are complementary, not redundant, and the ordering is: do the narrow
routing-layer fix now, because the gap is live, it reuses machinery that
already exists, and it needs no wire change. Keep it behind a tight boundary —
one module, one gate on next-hop promotion — so that if link-layer
authentication later makes `frame.src` trustworthy, removing this is a deletion
rather than an excavation.

### Implementation notes — four things the design did not predict

Recorded because each is a defect the design would have shipped with, and each
was found only by running the attack against the built fix.

**1. Gating route *selection* is not enough; there are two selection paths.**
`lookup_route` reads the cached `OriginatorRecord::best_next_hop`, but the
forwarding hot path uses `next_hop`, which recomputes from `paths` and never
consults the cache. Gating only the cache would have left forwarding open to
precisely the next hop the cache had refused. Both are gated; an engine test
asserts both, because the gap between them is invisible from either one alone.

`best_next_hop` also became `Option<Mac>`. It had been initialised to
`frame.src` at record insertion — before any gate could run — so a
first-contact attacker installed itself by construction. There is no honest
`Mac` for "no usable path yet".

**2. A proof must be renewed before it lapses, not after.** The first cut
challenged only neighbours whose proof was already gone, which meant every
proof cycle dropped the route for as long as the round trip took, and a
steady-state mesh flapped its next hop. `proof_needs_refresh` fires after one
expected interval against `proof_current`'s `MAX_MISSED_PROOFS`; the gap
between the two thresholds is the margin the exchange gets to complete in.

**3. The attacker can misdirect the challenge itself — and that was the sharp
one.** `get_egress_interface` resolves through the link-quality table, which is
written on frame *receipt*, before any authentication verdict. An attacker
spoofing a member's source address at a few frames a second makes its own link
look like the way to reach that member, and collects the challenge. It cannot
answer — but it does not need to. The proof never renews and the victim loses a
route it should have kept: the hijack degrades into a denial of service, which
is better but still a regression the fix itself introduced.

Two changes close it, and both are worth keeping in mind for anything else that
reasons about *where* a peer is:

- A challenge is emitted on **every** interface rather than the metric-chosen
  one. It is a couple of dozen bytes and rare, which is what makes the fan-out
  affordable, and it means the attacker no longer chooses where the challenge
  goes.
- Egress pins to the interface a challenge was actually **answered** on
  (`proven_interface`), in preference to the link-quality table. An answered
  challenge is attacker-proof by construction: only the key holder could have
  produced it. Without this the *data* still followed the poisoned egress even
  once the route was correct — the attacker collected the traffic without ever
  owning the route.

**4. The proof table looked starvable, and was not — the instrument was
wrong.** `attack_proof_starvation_by_neighbour_count` reported a gap: on a
20-neighbour mesh, twelve fully credentialed neighbours never became usable
next hops, which read as `MAX_IN_PROGRESS_PROOF` (then 16) evicting in-flight
challenges before their answers arrived. It was not. The scenario built its
density as a **star of 20 point-to-point links**, and in the simulator every
link an endpoint touches is one router interface — so the hub was configured
with 20 interfaces against a `MAX_INTERFACES` of 8. The router ignores an index
past that bound, silently, so spokes 8..19 had no OGM timer and no
participation gate. The starved set was exactly the interfaces that did not
exist, and the boundary sat at 8 whatever `MAX_IN_PROGRESS_PROOF` was set to.

Three things follow, and the second is the one worth carrying forward:

- **The scenario now uses one shared segment**, sized from
  `MAX_NEIGHBOR_KEYS` — the most neighbours a node can hold verified keys for,
  and so the most proofs it can ever legitimately owe at once. All 64 prove and
  route, and the verdict is `HELD`.
- **The table is not what makes it hold; the retry is.** `MAX_IN_PROGRESS_PROOF`
  stays at 16, a quarter of the key cache, so this density evicts. An evicted
  challenge is simply one that is never answered, and an unanswered challenge is
  already retried on `BatmanEngine`'s backoff — so eviction costs a round trip,
  not a route. The table bounds concurrent proof *throughput*, and the only
  requirement is that throughput exceed the rate at which proofs come due for
  renewal. Measured at full density: 4, 8, 16 and 64 slots all converge
  identically (every neighbour proven ~11 s in, no route lost over the following
  two minutes), while 1 slot never converges — it settles at 42 of 64 proven,
  the equilibrium where proof completions match expiries. The cliff is between 1
  and 4, so 16 carries at least fourfold margin.
- **Read the scenario's pass accordingly.** It fails only for a table small
  enough to fall under the renewal rate, which makes it a guard against gross
  mis-sizing, not a tight bound on the constant. Nothing currently pins the
  finer property it rests on — that a challenge lost to *eviction specifically*
  is retried and eventually proves. `an_unanswered_challenge_is_retried_on_an_
  exponential_backoff` (`libs/batman`) covers the retry and
  `the_in_progress_table_evicts_least_recently_issued_when_full`
  (`libs/wayfinder/src/auth.rs`) covers the eviction, but the two live in
  different crates and neither knows about the other.
- **Silent capacity truncation is the failure mode to design against.** Three
  of the four shells had already met this: the tokio driver `warn!`s on
  over-capacity wiring and the embedded driver made it a compile-time assert,
  its doc comment noting that the `debug_assert!` it replaced "compiled out of
  the `--release` images boards actually flash". `wayfinder-tick-driver` still
  carried that same `debug_assert!` — and the Python extension the simulator
  runs is a release build, so it compiled out there too. It now `warn!`s and
  holds its own interface count to the router's, and `Simulation` refuses a
  topology that gives any node more links than `wf.MAX_INTERFACES` outright,
  rather than measuring a mesh that is quietly not the one described.
- **A red-team verdict is a measurement, and measurements need controls.** The
  gap stood for as long as it did because the verdict was plausible. What
  settled it in minutes was running the same topology *unauthenticated* (all 20
  routed — so not a trust problem) and the same neighbour count on *one
  interface* (all 20 proved — so not a proof problem). Neither control existed
  in the suite.

**A bootstrap deadlock, avoided deliberately.** Proving a neighbour needs its
pairwise key, which needs its certificate, which under lazy cert distribution
may itself have to be fetched over the mesh. Gating that fetch on proof
deadlocks: nobody can prove anything because nobody can obtain the keys to
prove with. The cert-control plane therefore routes through
`next_hop_unproven_ok`, a deliberate hole. It is safe because of what travels
it — a certificate is public data and a `CertReq` carries the requester's own
signed cert — so an attacker attracting it learns nothing it could not read off
the air and can at worst blackhole cert distribution, which jamming already
achieves. **The data plane must never use it.**

**What shipped, by crate:** `MAX_MISSED_PROOFS`, the `proven`/`challenged`
tables, `challenge_candidates`, `note_proven`/`note_challenged`,
`proof_current`, `proven_interface` and the gate in `recompute_best`/`next_hop`
(`libs/batman`); `CHALLENGE_NONCE_LEN`, `MAX_IN_PROGRESS_PROOF`,
`issue_challenge`/`answer_challenge`/`verify_challenge_response` over
`frame_tag` and the pairwise-key cache (`libs/wayfinder/src/auth.rs`);
`poll_challenge` plus the two receive arms (`libs/wayfinder/src/lib.rs`);
`NextHopChallenge`/`NextHopResponse` and their headers (`libs/batman/src/wire.rs`);
`poll_due_challenges` (`libs/wayfinder-driver-core`), wired into all three
shells.

**The nonce needs no entropy.** `getrandom` is a `std`-only dependency of
`wayfinder-auth`, so there is none in `no_std`. The nonce is a PRF over a
monotonic counter keyed by this node's pairwise key *with itself* — a
Diffie-Hellman against its own public key, which only the holder of its secret
can compute. No RNG to plumb through every board.

**Domain separation is load-bearing.** A challenge response is a `frame_tag`
under the same pairwise key `tag_directed` uses, so the two could collide. The
response's `context` is `CHALLENGE_RESP_DOMAIN ‖ responder_mac` while
`tag_directed` passes a bare 6-byte MAC; a domain-then-MAC string can never
equal a bare MAC, whatever counter or payload an attacker picks. Relying on
counter values never colliding would have been fragile.

---

---

## 5. Gap 4 — certificate MAC is not bound to its key (high)

### What happens

`TrustAnchor::verify_cert` checks the version, the mesh id, the root signature
and the validity window. It does **not** check that `node_mac` is the address
`ed_pubkey` derives. A certificate binding a key to somebody else's address
therefore verifies perfectly.

This is worse than "a misissuing CA could hand out impersonation", because the
shipped CA *will*: `CertAuthority::submit_csr`
(`libs/wayfinder-server/src/authority.rs`, `submit_csr`) takes `node_mac` **from the
client**. Its only guard is that the MAC does not already hold a valid,
non-revoked certificate under a different key — which is first-come, not
proof-of-ownership. An attacker that passes the enrollment-token check can
claim any address not currently covered by a live cert, including one whose
cert has lapsed.

`wayfinderctl cert issue --mac` and `cert approve` have the same shape offline.
(`issue_user_cert`'s callers already derive the MAC — `authenticate_user` — so
user session certs are unaffected.)

Reproduced by
`test_a_certificate_naming_a_mac_its_key_does_not_derive_is_refused`
(`sim/tests/test_security.py`) and `red_team.py::attack_ca_misissuance`, both
now asserting the fix. Two red-team attacks were added alongside them for
surface this change created rather than closed —
`attack_compromised_root_takes_a_live_members_address` (what the binding is
worth when the attacker *is* the authority, and what it still does not buy) and
`attack_agreement_key_theft_via_address_binding` (what the deliberate narrowness
of binding `ed_pubkey` alone costs) — plus
`attack_squat_a_lapsed_members_address` for issue #37's closed window.

Both of the older fixtures had to be rebuilt before they measured anything: each
ran the victim node alongside the imposter, so the victim's address was in the
observer's neighbour cache legitimately and the assertion read the same either
way. The victim is now absent from the partition, which is both the honest
measurement and the case where impersonating it is worth doing.

### The fix — shipped 2026-09-05

**The key↔address binding is adopted, and the fixed-MAC re-key it forecloses is
accepted as the price.** That was the open question this section left standing;
it is now answered, and built. See "Accepted consequences" below for what
changed as a result, and "Implementation notes" for the four things the build
surfaced that this design did not predict.

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

Verify it *everywhere* a certificate's subject is chosen or trusted, not only
at the two ends: `verify_cert` is the invariant, the three issuance paths are
where the mistake is caught early, and §8.9's `cache_neighbor` identity lock
becomes defense in depth over the binding rather than the only thing holding
the address.

### Implementation notes — what the build surfaced

Four things, none of them predicted by the design above, and the first is the
one that would have shipped a broken product.

1. **Enrollment had to start renumbering the node, and the whole flow moved with
   it.** `wayfinder-tap` derived a node's MAC from its identity key *only* when
   an `auth:` block was configured; an un-enrolled node ran under a MAC
   generated once from a discarded throwaway key and persisted to
   `mac_state_path`. Enrollment then bound the certificate to *that* address —
   deliberately, so joining a mesh did not move a node, and the comment in
   `main.rs` argued for it at length.

   That is no longer expressible: an authority will certify only the address the
   presented key derives. So the identity seed is now resolved **once** at the
   top of startup and both the MAC and the management-TLS server identity are
   derived from it, which collapses two parallel three-way matches into one and
   makes "a node routes under the address its identity key derives" structural
   rather than conditional. The persisted-MAC fallback survives for the one node
   that has no identity key at all — no `auth:` block, no runtime identity, and
   no management server to have generated a seed for — which cannot be enrolled
   over the wire anyway.

   The consequence to state plainly: **an existing unauthenticated node
   renumbers on upgrade**, once. It is a one-time move for a node holding no
   certificate, against a permanent alternative — every online enrollment
   leaving the node signing OGMs under a certificate naming an address it does
   not answer to until someone restarts it.

2. **Three CSR builders were naming the wrong field.** `csr request`
   (`wayfinder-ctl`) and the web dashboard's `enroll::request` both built the
   request from `GetNodeInfo`'s `node_id` — the address the node *currently*
   answers to. Both now derive it from the `own_ed_pubkey` the node reports, and
   both say so out loud when the two differ, because a silent renumber
   discovered when peers stop answering is the worst way to learn about one.
   `auth enroll`'s `--mac` and `cert issue`'s `--mac` became *cross-checks*
   rather than overrides: an operator who passes the right one is confirming
   which seed they meant, and one who passes the wrong one is told which half is
   wrong.

3. **`submit_csr`'s live-cert lock stopped being load-bearing, and issue #37
   closed with it.** The lock was read off the *issued record*, whose window is
   strictly shorter than the revocation that makes it matter — so between a
   record expiring and its revocation expiring, a stranger could be issued a
   certificate for a departed member's address and have it honoured mesh-wide.
   The binding closes that more completely than #37's own planned fix
   (consulting persisted revocations): the address is not another key's to claim
   at *any* time, so there is no window to be inside. The test that pinned the
   window open said in its own assertion message what to do when it started
   failing, and that is what was done — folded into
   `a_different_key_cannot_reclaim_a_revoked_mac`.

4. **§8.9's identity lock became unreachable through a certificate, and its
   tests had to be rebuilt on what it can still reach.** `cache_neighbor`
   refuses to replace a live member's `ed_pubkey`; with the binding, two
   different keys cannot both derive one address, so `verify_cert` refuses the
   second certificate long before the cache sees it. The rule is kept — §8.9
   already called it defense in depth — but what it now guards is a `derive_mac`
   collision: 46 bits, negligible by accident and days of GPU time on purpose.
   Its seven tests could no longer *mint* the state they were testing, so they
   now build it directly (a genuine verified certificate with its subject
   rewritten, which is what a collision would produce) and drive
   `cache_neighbor` rather than `verify_ogm`. A new test pins the outer refusal
   that displaced them.

Two notes on the test churn, for anyone repeating this shape of change. It came
to **~130 tests**, not the 67 this section estimated — the codebase grew. But
the prescription held exactly: in `libs/wayfinder/src/auth.rs`, 223 of 225
fixture sites already paired seed *n* with `mac(n)`, so redefining that single
helper to `Keypair::from_seed(&[n; 32]).derived_mac()` fixed 328 of the crate's 347 tests in
one edit. The residue was worth reading rather than mechanising — every one of
those sites was a fixture asserting something the binding has since made
impossible.

`wayfinder-test` was the exception this section predicted, and it was *smaller*
than feared: machine identities now come from `machine_keypair(index)` rather
than a topology counter, and only the five auth-using suites cared. The 63
routing tests were indifferent to the MAC values changing under them.

### Accepted consequences

- **Key rotation at a fixed MAC becomes impossible — accepted.** If the address
  is derived from the key, re-keying necessarily changes the address; a re-keyed
  node is a new originator, and callers that assumed an address survives a
  re-key must be changed to expect a new one. This is the trade the decision
  above makes deliberately: an address that cannot outlive its key is what makes
  the binding an invariant a node can check for itself, and a mesh that needs a
  node back under its old address re-keys to the old key or renumbers.
  Certificate *renewal* (same key, new window) still works, and still changes
  the fingerprint, so the existing `CertFp` → `NeedCert` refetch path is still
  needed and still exercised. Two existing tests assert rotation at a fixed MAC
  and must be converted to renewal.
- **`submit_csr`'s live-cert lock stops being the load-bearing guard.** It was
  first-come proof-of-nothing; once the MAC is derived, a different key claiming
  a live member's address is refused because the address is not that key's to
  claim. Keep the lock — it is still what refuses a second *live* certificate
  for one key — but it is no longer the thing preventing impersonation, and the
  comment at `authority.rs` that says so should be corrected rather than left to
  mislead the next reader.
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

## 6. Gap 3 — certificate expiry does not evict a cached neighbor (medium)

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

## 7. Observability (applies to gaps 1 and 2)

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

## 8. Sequencing

Revised by §4. The original order (2 → 1) assumed two bugs sharing a freshness
field; they are one bug with one fix, and it is no longer blocked on the
wall-clock question.

1. ~~**Gap 3**~~ — done.
2. ~~**Observability (§7)**~~ — done: `untaggable_drop_rate` on
   `CentralRouter`, surfaced through `NodeMetrics` to `wayfinderctl`, the TUI
   and the web UI, and the remote-drivable `warn!` demoted to `trace!`.
3. ~~**Gaps 1 + 2, via §4's next-hop challenge**~~ — done. One change closed
   both. No wire-format change to the OGM, no per-hop signature, and it did not
   need §2's wall clock, because the freshness is a receiver-chosen nonce
   rather than a shared clock.
4. ~~**Gap 4**~~ — done (2026-09-05). The widest test churn of any change in
   this document (~130 tests), and it moved the enrollment flow with it: see
   §5's "Implementation notes". §8.10 and §8.11 do not depend on it and are what
   is left.
5. **§2's time bucket** — still worth landing on its own merits (it bounds
   replay of a *stale* OGM at a fresh receiver, which the challenge does not
   address), but it is no longer on the critical path and it still owns the
   embedded wall-clock question. Sequence it after the above, or drop it if the
   clock question stays unsettled.
6. **Per-link (MACsec-shaped) authentication** — the eventual general answer,
   and the only one that also covers unauthenticated flooded `Bcast`. A
   project, not a change; see §4's closing subsection for what it does and does
   not subsume.

   One consequence of that `Bcast` exemption was closed separately, because it
   did not need authentication to fix and was far worse than the injection
   nuisance this document had conceded (issue #29). A `Bcast`'s `orig` and
   `seqno` are read from inside the payload, so the receiver's dedup table is
   state an outsider writes to directly — and it neither evicted nor bounded a
   seqno jump. One frame naming a member with `seqno = u32::MAX` silenced that
   member's broadcasts *permanently* and mesh-wide; about `MAX_ORIGINATORS`
   ghost origs did the same to every originator not already in the table. ARP
   rides broadcast, so this was address-resolution denial, not just payload
   loss.

   The fix is worth stating as a property rather than as a list of checks,
   because the first attempt at it was a list of checks and was still
   exploitable. **No check on the frame can help**: a keyless attacker passes
   every check available, since every field it is judged on is one the attacker
   wrote. What the receiver can do instead is refuse to hold a wrong high-water
   for long — `BroadcastSeqnoEntry::admit` treats a run of sequence numbers
   that do not advance the high-water as evidence against the *high-water*
   rather than against the frames, and resynchronises after
   `BROADCAST_SEQNO_RESET_PROTECTION`. Whatever put a wrong value there — a
   forgery, a re-seed after eviction, or the originator rebooting, which the
   code cannot tell apart and does not have to — the originator's own traffic
   corrects it within that bound.

   Two details in that are load-bearing, and both are places the first attempt
   went wrong:

   - The band treated as an ordinary duplicate must be **narrow**. A forgery
     needs no implausible leap; one *inside* the acceptance window is taken as
     a genuine advance, and the victim's own broadcasts then sit behind it. A
     wide "behind" band swallows exactly those, and the victim stays silent
     until its counter climbs past the forged value — measured at 98.5%
     suppression from 0.1 packets per second of injection.
   - The resync must restore **the sequence number that opened the run**, not
     whichever frame trips the deadline. Otherwise a third party waits out a
     run an honest, rebooting originator earned and substitutes its own number,
     reconstructing the original attack from two frames thirty seconds apart.

   What this does *not* do is make a `Bcast` authentic, which is still this
   item's job. The residual it leaves is a sustained one: an attacker injecting
   continuously, faster than the victim broadcasts, keeps advancing the
   high-water and so keeps clearing the correction. That is a flood, which an
   outsider can mount against this protocol regardless; the change is that it
   can no longer be a one-shot with permanent effect.

   Note what is **not** the fix, since it has now been proposed twice: dropping
   data-plane frames whose `frame.src` has no originator entry. §3's "What does
   *not* fix it" already rejected the equivalent `live_neighbor(src)` lookup
   because a member MAC is copied off the air; it is dead code for
   `Unicast`/`Mcast` (which `strip_directed` pairwise-authenticates); and it
   does not touch `orig`, which is the field the damage is keyed on.

## 8.7 The pairwise trailer was required by link dst, not by sub-type — **fixed**

Found by the 2026-08 directed-data-plane sweep, not by the original four-gap
analysis. Shipped fixed; recorded here because the wrong design is the one a
reader is most likely to re-derive as an optimization.

### What happened

`strip_directed` decided whether a frame had to carry a pairwise trailer from
`frame.dst.is_multicast()` — the **link-layer** destination. The exemption was
meant for floods (a pairwise key cannot cover a one-to-many send), and on
honest traffic it was accidentally correct: a `Unicast` always *did* wear a
unicast link dst.

But the link dst and the inner `dest` are unrelated fields, and both are
attacker-chosen on an injected frame. `handle_unicast`/`handle_mcast` decide
local delivery and forwarding from the **inner** `dest`. So an outsider holding
no credential could set the link dst to a group MAC (skipping the tag check)
and the inner dest to a member (winning delivery) — an unauthenticated
injection primitive into the directed data plane, exactly what the tag exists
to prevent.

The relay case is worse than the delivery case. `plan_dispatch` re-tags every
directed frame it forwards, so a relay that accepted the injection stamped its
own *genuine* pairwise tag onto content it had never authenticated. A node two
hops from the attacker, sharing no medium with it, then accepted those bytes as
authenticated member traffic. The forgery was laundered into legitimacy by an
honest node.

### The fix

Decide the requirement from the BATMAN sub-type alone
(`wayfinder_driver_core::requires_pairwise_tag`, since renamed to
`required_proof` and widened by design 17 to return a `RequiredProof` rather
than a bool — the reasoning below is unchanged), and apply the same predicate
on ingress (`strip_directed`) and egress (`tag_directed_into`) so the two halves
cannot drift. Exempt exactly the packets for which a pairwise tag is impossible
or redundant — `Ogm`, `Bcast`, `Keepalive` (one-to-many) and `CertReq`,
`CertReply` (self-authenticating, and requiring a tag would stop lazy cert
distribution bootstrapping the very keys the tag needs). Everything else
requires one, **including an unrecognised sub-type**: the engine falls back to
`route_by_dest`, so it is directed in every way that matters. The match is
exhaustive over `BatmanPacketType`, so a new variant cannot be added without
classifying it.

Note the deliberate asymmetry: ingress stays *dst-blind*. A genuinely tagged
frame is accepted under a group link dst, because `verify_directed` binds the
tag to `(pairwise key, counter, src, frame)` and the key is per-(sender,
receiver) — only the intended peer can verify it, so shouting buys the sender
nothing. Re-adding a dst check on ingress would reintroduce a decision keyed on
the attacker's own field.

### Reproduced by

`red_team.py::attack_multicast_addressed_directed_delivery` (delivery) and
`::attack_injected_directed_laundered_by_relay` (relay laundering), both now
`HELD`. Unit coverage in `libs/wayfinder-driver-core`:
`strip_directed_drops_a_group_addressed_unicast_without_a_tag`,
`a_group_addressed_unicast_is_never_laundered_by_a_relay` (with a live
tagged-frame control, so an empty sink means *refused* rather than
*unroutable*), and `a_tagged_unicast_is_accepted_even_under_a_group_link_dst`
pinning the asymmetry above.

### Residual

`BatmanPacketType::from_u8` ends in a `_ => None` wildcard over `u8`, so adding
an enum variant forces a classification in `required_proof` (a compile error)
but **not** its byte mapping in `from_u8`. A variant added to the enum and
forgotten in `from_u8` decodes as `None`, fails closed, and is dropped on every
node — visible only as `untaggable_drop_rate`. Deriving both from one macro list
would close it; out of scope for the fix itself. Still open as of 2026-09-05:
`from_u8` is eleven hand-written arms ending in `_ => None`.

---

## 8.8 A certificate could bind a member at a reserved address — **fixed**

Found by the 2026-08 certificate-issuance sweep as one of two *measured*
consequences of gap 4 (§5). Unlike gap 4 itself, this one is not blocked on the
key↔address binding: it is a property of the address alone, so it shipped ahead
of §5 and holds whichever path §5 eventually takes.

### What happened

`verify_cert` never inspected the subject MAC's bits. Since `submit_csr` takes
`node_mac` from the client (§5), a misissuance could bind a key to
`ff:ff:ff:ff:ff:ff`, to `00:00:00:00:00:00`, or to any multicast (group-bit)
address — and the certificate verified perfectly. A victim then cached a
pairwise key against that address and listed it as an admitted member.

Admission was the whole of it: a route additionally needs a next-hop proof a
bare injector cannot answer (§4). But admission is not nothing, because the
pairwise key is what `verify_directed` consults — so a directed frame
purporting to originate from "every node", or from the null address, would have
passed. It is also an address-type confusion the routing and flooding logic was
never written to expect as an *originator*.

### The fix

`verify_cert` rejects a reserved `node_mac` with `AuthError::ReservedAddress`:
the group bit set on the first octet (which subsumes broadcast), or all-zeros.
The check sits deliberately *after* the signature check — it rejects a cert the
mesh root genuinely signed, so it is a misissuance rather than a forgery, and
the error says so.

It is deliberately narrower than the convention `derive_mac` stamps
(`force_locally_administered_unicast`): it does **not** require the
locally-administered bit, because a node may legitimately route under a
globally-administered address its hardware came with. Only addresses that mean
"not one node" are refused.

Nothing is checked on the issuance side. A CA that signs such a cert now mints
one no node will honour, which is the fail-closed direction; surfacing it at
`submit_csr` as well is a small follow-up, not a correctness requirement.

### Reproduced by

`red_team.py::attack_reserved_address_originator`, now `HELD`. Unit coverage in
`libs/wayfinder-auth/src/cert.rs`: `reserved_node_mac_rejected` over all four
shapes, and `ordinary_unicast_node_mac_still_verifies` pinning the narrowness
above (a derived MAC, a compact test MAC, and a globally-administered one).

### Fallout worth recording

`wayfinder-test`'s harness numbered machine identities from zero, so
`machine1` held `00:00:00:00:00:00` — the null address — and every authed
fixture was quietly certifying a node at it. Identities are now one-based. The
symptom was the useful part: the fixture did not error, it simply failed to
converge, which is the same shape as the benchmark hazard recorded in the root
`CLAUDE.md`.

---

## 8.9 A second certificate could displace a live member's cached key — **fixed**

The other of the two *measured* consequences of gap 4 (§5) found by the 2026-08
sweep, and like §8.8 it is not blocked on the key↔address binding — so it too
shipped ahead of §5 and holds whichever path §5 eventually takes. Unlike §8.8
it is an **availability** attack, which §4's next-hop proof does not touch.

### What happened

`cache_neighbor` found a neighbour entry by `cert.mac` and overwrote it
unconditionally. A second CA-signed certificate for a live member's MAC, under
an attacker's key, therefore replaced the victim's cached entry on the next
accepted OGM — and with it the pairwise key derived from that certificate.

The pairwise key is symmetric ECDH, so the damage runs **both ways at once**:
once the victim's cache holds the attacker's key, a directed frame the real
member tagged fails `verify_directed`, and so does one the victim tags back.
Measured at **0/6 delivery** against a delivered baseline — a total, sustained
denial of one named member's authenticated data plane from a single misissued
certificate. Nothing here lets the attacker *read* that traffic; it needs to
win the route and answer a proof for that. It only has to make the address
contested.

This supersedes §6's remark that "`cache_neighbor` only ever overwrites an
entry", which was true when that section was written.

### The fix

`cache_neighbor` refuses to replace a **live** member's `ed_pubkey` with a
different one; a same-key renewal still caches. That makes a receiver no more
permissive than its own authority, which enforces exactly this at issuance
(`libs/wayfinder-server/src/authority.rs`): same identity key + new window is
re-issued, a different key while the held certificate is inside its window is
rejected, and revocation deliberately does not lift the lock.

No new flow was needed — three mechanisms that already existed compose into
one:

- ingesting a revocation calls `evict_neighbor`, so a revoked member leaves no
  entry for the rule to collide with;
- a lapsed certificate is dropped by `evict_expired_neighbors` and read as
  absent by `live_neighbor` (§6's fix), so the address frees itself once the
  window is out;
- re-admission is already modelled by `RevocationRecord::cancels`.

Two edges are decided rather than inherited:

- **An unset clock admits the new key.** `live_neighbor` calls everything live
  when `now_unix == 0`, so mirroring it would make an unclocked node — an
  embedded one has no wall clock today — refuse a legitimate re-key forever.
  Such a node cannot judge certificate validity at all, and the authority
  itself fails closed on a zero clock rather than locking addresses on one.

  This leaves the rule inert on a board, which is latent rather than
  exploitable: no board constructs an `OgmAuth` at all today, and at
  `now_unix == 0` `verify_cert` would refuse every certificate a real authority
  issues anyway. It is a blocker to *enabling* embedded auth, not a hole in a
  shipped one — tracked by the "Auth on Embedded" epic.
- **The comparison is on `ed_pubkey` alone**, matching the authority's lock. An
  agreement-key-only rotation is something the CA will sign for a live member,
  so a wider rule would reject a certificate this mesh's own authority had just
  issued.

The OGM's verdict is deliberately untouched. The certificate really is
CA-signed and its signature really does check out, so this stays a decision
about what the node *caches*; binding the address to the key at verification
time is §5's job.

### Observability

Paired with a new `AlarmKind::IdentityConflict`, raised against the contested
address. Nothing is broken by the time the refusal fires, which is precisely
why it has to be reported: a silently dropped loser presents to an operator as
unexplained route flapping, with the real cause — an authority that issued
twice for one address, or an anchor no longer under sole control — nowhere in
view. `derive_mac` yields 46 bits, so an accidental collision is negligible
(7.1e-9 at 1,000 nodes) and a deliberate one is days of GPU time; this is a
credential-issuance condition far more often than an address-space one.

### Reproduced by

`red_team.py::attack_misissued_cert_overwrites_live_member`, now `HELD` (key
never flips; 6/6 delivery under a 40 Hz flood of the second certificate). Unit
coverage in `libs/wayfinder/src/auth.rs`, covering both the refusal and the
four edges it must not swallow.

### What §5 changed here

Nothing is still open. §5 shipped on 2026-09-05, and this rule became defense in
depth over it rather than the thing holding the address: the binding removed the
precondition, so a second *certified* key for one address can no longer exist.
What the rule now guards is a `derive_mac` collision, which at 46 bits still
earns its few lines.

Two things moved with it, both recorded in §5's implementation notes. The
`IdentityConflict` alarm is raised from `verify_ogm`'s refusal now rather than
from `cache_neighbor`'s, because that is where the condition is caught — leaving
it where it was would have made the mesh's most serious credential fault silent
while the same attacker's directed frames raised `UnauthenticatedTraffic`
against the *victim*. And the rule's tests build their colliding entry by hand,
because it can no longer be minted.

The "unset clock admits the new key" edge survives, and is now the only place
where an unclocked node is *more* capable than before: it still cannot judge
validity, but it *can* check the binding, which is the first thing in this area
that works without a wall clock.

---

## 8.10 A proof outlives the key it needs — **fixed**

Found by the 2026-08 next-hop-proof sweep. Not a consequence of gap 4, and not
closed by anything above: it is an interaction *between* §6's fix and §4's, each
of which is correct alone.

### What happens

§6's `evict_expired_neighbors` drops a lapsed member's pairwise key from
`OgmAuth` at `set_time`. §4's next-hop `proven` table lives in the routing
engine and is **not** swept when that happens, so `proof_current(mac)` keeps
reading true for up to `MAX_MISSED_PROOFS` intervals afterwards.

The two halves then disagree. Path selection gates on `proof_current`, so the
engine goes on choosing the lapsed neighbor as a next hop; the data plane
resolves its key through `live_neighbor`, gets `None`, and drops the frame at
dispatch. **The route reports healthy and every directed frame over it
vanishes.** Renewal cannot rescue it from inside the window either —
`issue_challenge` fails closed for a neighbor with no key, so the proof cannot
be refreshed, only allowed to lapse.

Measured directly: after the peer's certificate expires there is a run of
sampled instants where the victim reports a route to it *and* reads its proof as
current *and* has already evicted its key; a real payload queued in that window
was dropped at dispatch while `has_route` stayed true.

### Why it is bounded, and why it still matters

It is transient (the route purges once the proof itself lapses), confined to one
neighbor, and the drop is metered — §7's `untaggable_drop_rate` is exactly the
counter that fires. What is not acceptable is that the route table *lies* for
the width of the window: an application on top of the mesh is told it has a
usable path, which is the thing §7 was added because operators could not
otherwise see.

### The fix — shipped 2026-09-05

Key eviction and proof invalidation are now one event, driven from the only
place that can see both: `CentralRouter::set_auth_time`, which advances the
certificate-validity clock and then reconciles the engine's `proven` table
against what key material survived. Both driver shells that set that clock go
through it; reaching past it to `auth_mut().set_time(..)` advances one half and
not the other, which is precisely how the defect arose, and the method's doc
says so.

**Written as a reconciliation, not as an eviction handler.** The first cut of
this design proposed passing the MACs `evict_expired_neighbors` dropped, on the
grounds that it already knows exactly which ones it dropped. Sweeping instead on the *predicate* —
`BatmanEngine::retain_proven(now, |mac| auth.has_live_key(mac))` — is both
simpler and strictly stronger, because expiry turns out not to be the only way
a key can go. A neighbour evicted from a full key cache loses its pairwise key
with no expiry involved and produces the identical blackhole; an event-shaped
fix would have closed the measured path and left that one open.
`a_key_evicted_by_cache_pressure_takes_its_proof_too` pins that case, and fails
if only expiry drives the sweep. It also needs no bounded buffer of pending
evictions (which could overflow and lose one), and it is idempotent.

Its cost is not free, though, and the first draft understated it: the outer pass
is over `proven` (bounded by `MAX_ORIGINATORS`), but each entry costs a scan of
`neighbors` (`MAX_NEIGHBOR_KEYS`), and on the tokio shell this runs per *frame*
rather than per timer tick. So the sweep is gated on `OgmAuth::key_generation`,
a counter bumped wherever a cached key stops being reachable — expiry,
revocation, or the full-table overwrite. Steady state is one integer comparison;
the scan happens only when something actually went. Note which paths bump it:
gating on "did `set_time` evict anything" instead would have reopened the
capacity-eviction hole this design exists to cover, since that eviction never
runs through the clock at all.

One limit on "strictly stronger", since it is easy to over-read: the
reconciliation covers every way a key can go, but its only *trigger* is
`set_auth_time`. A shell that never advances the auth clock never sweeps.
`wayfinder-embedded-driver` is such a shell today — it wires no auth clock at
all — so a board that enabled auth through `Driver::router_mut` would still hold
the stale proof. No board wires mesh auth yet, so this does not bite; wiring the
clock is what closes it, and is the same call the two host shells make.

Two smaller decisions, both places the obvious move is wrong:

- **The path survives; only the proof goes.** Unlike `revoke_originators`, this
  does not delete the originator record. A lapsed member is not a shunned one —
  it may renew — and keeping the path means renewal is one challenge away rather
  than a rediscovery. What it must not keep is the *cached* `best_next_hop`, so
  the sweep recomputes selection in the same call: that cache is what the
  management API and the forwarding fast path read, and leaving it to the next
  OGM or periodic sweep is the whole of the defect.
- **`challenged` is deliberately left alone.** `revoke_originators` clears it,
  but it can afford to — it deletes the record, so the MAC stops being a
  challenge candidate at all. Here the neighbour stays a candidate, and
  `challenged` is the retry *backoff*; a keyless neighbour is exactly one whose
  challenges keep failing closed, so clearing it would un-throttle the retries
  rather than tidy anything up. It clears itself the moment the neighbour proves
  itself again.

**The reverse direction needs nothing.** A proof lapsing while the key is still
live does not blackhole: selection simply stops
choosing the hop, the data plane never gets a frame to drop, and the next
challenge renews it.

### Reproduced by

`red_team.py::attack_proof_survives_key_eviction_window`, which flips `GAP` →
`HELD` (the route to the lapsed peer now clears within a second of its
certificate expiring, and no sampled instant shows a current proof over an
evicted key), with its `BASELINE` entry in `sim/tests/test_red_team.py`.

Unit coverage holds both halves, as the interaction demands:
`an_expired_neighbours_key_takes_its_next_hop_proof_with_it`
(`libs/wayfinder/src/lib.rs`) drives a real certificate to expiry through
`set_auth_time` and asserts the key, the proof and the cached next hop all go
together. Three engine-level tests (`libs/batman/src/engine.rs`) pin the sweep
itself: that it recomputes selection in the same call, that it falls back to a
path whose key is still live rather than dropping the destination, and that it
leaves the challenge backoff standing.

---

## 8.11 A replayed OGM pins an originator's seqno high-water — **fixed**

Found by the 2026-08 OGM-semantics sweep. The OGM-path twin of §8.6's `Bcast`
high-water blackhole, which was fixed first; this path now shares its
machinery.

### What happens

The attacker captures a **genuine, correctly signed** OGM from a member at a
high sequence number and replays it under its *own* link-layer source. Two
things follow, and only the first is intended:

- The forged path "hq via eve" never becomes a usable route. Eve holds no
  credential and cannot answer a next-hop challenge, so §4's fix holds exactly
  as designed.
- The victim's `OriginatorRecord` for **hq** — keyed on the originator inside the OGM,
  not on the forwarder — takes the replayed sequence number as its high-water
  anyway. Every genuine OGM hq subsequently emits sits *below* it and is
  discarded as stale, so the victim never acquires a route to a genuinely
  adjacent hq at all. A control run without the attacker acquires one.

Refreshing the replay (measured at 5 Hz) keeps `last_heard` live so the record
never ages out, holding the pin for as long as the attacker keeps transmitting.

Note what this is *not*: nothing here is forged, so nothing on the verification
path is wrong. The OGM really is hq's and really does verify against hq's key.
§4 deliberately separated "this OGM originated with hq" (which is true) from
"hq is reachable via this sender" (which the proof refuses), and the seqno
bookkeeping runs on the first claim — correctly, since that is the claim the
originator actually signed. The attack spends a true statement, replayed.

### Why refusing the frame outright was not the fix

The first instinct here is to admit nothing at all from a neighbour that has not
proven itself. It does not survive contact with §4's own measurement.

`verify_ogm` (`libs/wayfinder/src/auth.rs`) takes the payload and nothing else;
the signature covers `orig ‖ seqno ‖ cert`. **`frame.src` is not an input to any
check**, which is exactly what §4 established, and the attack it measured is
Eve replaying *under hq's spoofed link-layer source*. In §8.11's scenario hq is
genuinely adjacent and proven — the control run acquires a route through it —
so `proof_current(frame.src)` reads true for a replay carrying `src = hq`. The
gate costs one challenge round-trip at cold start and the attacker's answer is a
one-line change to the injection.

The reason recorded above ("a legitimate neighbour is unproven during ordinary
acquisition") is the weaker of the two objections and was not quite right:
recording a path and advancing a high-water are separable, so the bootstrap
deadlock is avoidable. The spoofing bypass is the one that rules the gate out,
and it is §8.6's lesson again — no check on a frame field helps when the
attacker writes that field.

What the instinct *is* right about is the shape of the defect: a value any
frame can write was deciding whether a **proven** neighbour's path got learned
at all. The fix follows from taking that seriously — narrow what the value
governs, rather than trying to trust who wrote it.

### The fix — shipped 2026-09-05

Two changes. The first closes the measured attack; the second bounds what it
could still do to nodes behind the victim.

**1. The high-water governs re-flooding and content freshness — not path
learning.** `handle_ogm` used two comparisons against one field —
`incoming_seqno > record.last_seqno` for re-flooding and `>=` for everything
else — to answer three unrelated questions: may this OGM be re-flooded, may this
node learn the path it arrived on, and may its advertised multicast memberships
be believed. Only the first two are the high-water's business. Loop protection needs a per-originator high-water;
*path learning* needs nothing of the sort, because a path's own freshness
already lives in `NeighborStats::last_seqno`, and its liveness is the next-hop
challenge's job — which §4 settled, and which the seqno never could do
("possession of a public authenticator over static content proves nothing about
the possessor"). Membership stays gated on freshness, because that is content
the originator asserts rather than an observation this node made: a replayed old
OGM must not be able to revert a live member's groups.

So a jammed high-water now costs re-flooding, plus the memberships that
originator's OGMs assert — content it claims, rather than anything this node
observed. The victim learns the path, challenges the neighbour, and routes.

**2. An `admit`-shaped resync, shared with the broadcast table.** The
three-arm decision §8's sequencing item 6 arrived at is now one implementation
— `SeqnoBands` + `admit_seqno` in `libs/batman/src/lib.rs` — parameterised by
band widths, with `BroadcastSeqnoEntry::admit` delegating to it and
`OriginatorRecord` carrying its own `resync_watch`. Both of that item's
load-bearing details carry over untouched: the run must *persist* before it is
believed, and the high-water resynchronises to the number that **opened** the
run rather than to whichever frame trips the deadline. Writing it twice was the
obvious way for the two copies to drift, and the second copy is the one nobody
would have re-derived the reasoning for.

**Why this half is load-bearing, and why the obvious argument for it is wrong.**
The tempting justification — "it bounds how long an attacker can suppress
re-flooding" — is weak on its own, and the red-team scenario does not support
it: that run is 25 s against a 30 s reset protection, so the correction never
comes due and `HELD` there measures the decoupling alone. (Nor can a fast
attacker hold the correction off; her refreshes carry the number she already
pinned, so they read as duplicates and never touch the watch, whose `since` is
deliberately not refreshed by a continuing run.)

The real argument is a **regression the decoupling would otherwise introduce**,
with no attacker in it at all. Before it, an originator that restarted its
counter — a reboot, or a `u32` wrap — had its OGMs refused outright, so
`NeighborStats::last_heard` was never refreshed, its paths aged out, and
`purge_stale` dropped the record; the next OGM then re-seeded a correct
high-water. **Eviction was the self-healing path.** Decoupling deliberately
refreshes those paths, which removes it: without the resync a restarted
originator's high-water would stand forever, and every relay in the mesh would
stop forwarding that member's OGMs permanently while the route to it looked
healthy one hop away. The two halves are not independent — the first needs the
second to stay safe.

Pinned by `a_restarted_originator_is_reflooded_again_within_the_reset_protection`,
which asserts the record survives `purge_stale` precisely to show the old
recovery is gone.

### Implementation notes — what the build surfaced

**1. The broadcast reorder tolerance could not be inherited.** At
`BROADCAST_SEQNO_REORDER_TOLERANCE = 64`, a rebooted hq re-emitting from 1
against a high-water pinned at 56 sits *inside* the band — every one of its OGMs
would read as an ordinary duplicate, no run would ever be watched, and the
correction would never fire. The band is the line between disbelieving the
*frame* and disbelieving the *high-water*, so it has to be sized to the space it
judges: OGM reordering is bounded by hop-by-hop re-flooding under a draining
TTL, which spreads a flood's copies across a few sequence numbers rather than
tens. `OGM_SEQNO_REORDER_TOLERANCE` is 16.

**2. A first sighting has to seed the high-water, not be judged against zero.**
With `OGM_SEQNO_WINDOW` narrower than the broadcast one (256), any originator
already past that when first heard would read as out of band *on contact* — no
re-flood for a reset-protection interval, on every cold join to a running mesh.
`BroadcastSeqnoEntry::seeded` had already met this and answered it; the OGM path
now seeds identically, and is safe for the same reason rather than in spite of
it — a wrong seed is corrected by the originator's own next OGMs.

**3. The narrow window is the first line, not a redundant one.** It is tempting
to widen it on the grounds that the resync corrects a wrong high-water anyway.
It should not be: a far-ahead replay landing *outside* the window is refused
outright and never pins anything, where one inside the window is accepted and
costs a reset-protection interval to undo. The resync is the fallback for the
case the window cannot see — a replay close enough to be plausible, or a
first sighting that had nothing to judge against.

**4. The record's eviction stamp had to keep the rule its broadcast twin
states.** `BroadcastSeqnoEntry::last_updated` is documented as deliberately not
refreshed by a non-advancing frame, "so an attacker's stream of non-advancing
frames must not be able to pin a poisoned entry at the top of the eviction
order". The first cut of the decoupling refreshed `OriginatorRecord::last_heard`
on every frame it learned from, quietly dropping that rule for the originator
table. It is restored — and it is the *useful* direction as well as the safe
one, because a jammed record that sorts old and gets evicted has its high-water
reseeded, which cures the jam outright. Path liveness is unaffected: routing
reads `NeighborStats::last_heard`, which is refreshed regardless.

**5. Two integration tests were injecting sequence numbers no live originator
could have emitted.** `cert_fetch_round_trip_resolves_via_seeded_first_hop` and
`cert_fetch_round_trip_with_real_responder` (`libs/wayfinder-test`) hand-built
OGMs at seqno 1000/2000 as a shorthand for "unambiguously the newest", against
a relay whose high-water for that node was in single digits. They now derive the
number from the relay's own table. Worth recording because the failure is the
honest kind: the tests were relying on a leap being accepted, which is precisely
what stopped being true.

### Deliberately not done here

- ~~**No counter for a resync firing, or for re-flood suppressed under a
  correction.**~~ **Shipped since**, as `seqno_resyncs` and
  `ogm_refloods_suppressed` on `NodeMetrics` — see §10.
- **`SeqnoBands` and `admit_seqno` are crate-private rather than wrapped in a
  per-space gate type.** A `OgmSeqnoGate`/`BroadcastSeqnoEntry` pair owning the
  `(high-water, watch)` couple would make "judged by the wrong bands" a compile
  error instead of a convention. Keeping the two callers in one crate and the
  machinery private buys most of that for none of the churn across the
  management-API projection and the Python bindings; the wrapper is the right
  move if a third space ever appears.

### Reproduced by

`red_team.py::attack_ogm_seqno_highwater_jam`, which flips `GAP` → `HELD`, with
its `BASELINE` entry in `sim/tests/test_red_team.py`. Unit-level coverage in
`libs/batman/src/engine.rs`:
`a_replayed_high_seqno_does_not_deny_a_live_originator_a_route` pins the
decoupling and `a_pinned_ogm_high_water_resynchronises_to_the_run_that_opened`
pins the correction, alongside the band edges, the `u32` wrap, a third party
attempting to cash in an honest run, the membership freshness gate, the eviction
stamp, and the restart recovery above. Note which of those the simulator can and
cannot reach: the scenario runs shorter than `OGM_SEQNO_RESET_PROTECTION`, so it
measures the decoupling only, and it now refuses to report `HELD` unless the pin
it depends on actually landed. The correction is pinned on a virtual clock
instead, where it is deterministic. The measurement runs with and without the attacker, so an
empty route table reads as *denied* rather than *never-converged* — the same
control the §8.7 unit tests use and the same hazard the root `CLAUDE.md` records
for benchmark fixtures.


---

## 9. Key file map for the implementer

| File | Gaps | What changes |
|------|------|--------------|
| `libs/wayfinder/src/auth.rs` | 3 | `cache_neighbor`, `live_neighbor`/`evict_expired_neighbors`, `set_time`, `tag_directed`, `verify_directed`, `neighbor_cert`, `neighbor_x_pubkey` |
| `libs/wayfinder-auth/src/cert.rs` | 4 | `verify_cert` MAC/key check — done |
| `libs/wayfinder-auth/src/error.rs` | 4 | `AuthError::MacKeyMismatch` — done |
| `libs/wayfinder-server/src/authority.rs` | 4 | `check_mac_derives_from`, applied by `submit_csr` (a `Rejected` outcome) and `approve_csr` (an `Err`) — done |
| `bins/wayfinder-ctl/src/cert.rs` | 4 | `issue` (`--mac` cross-check), `approve` (CSR MAC check) — done |
| `bins/wayfinder-ctl/src/auth.rs` | 4 | `auth enroll`'s `--mac` becomes a cross-check — done |
| `bins/wayfinder-ctl/src/csr.rs` | 4 | `csr request` derives the subject instead of reading `node_id` — done |
| `bins/wayfinder-web/src/enroll.rs` | 4 | the same derivation, for the dashboard's enrollment — done |
| `bins/wayfinder-tap/src/main.rs` | 4 | one up-front identity-seed resolution; the MAC and the mgmt-TLS identity both derive from it — done |
| `libs/wayfinder-server/src/adapter.rs` | 4 | `set_auth`'s in-place MAC check is now subsumed by the binding; kept as the guard against a cert for another key — done |
| `libs/wayfinder-driver-core/src/lib.rs` | §7 | `tag_directed_into` counter + `warn!` → `trace!` (line ~215) |
| `libs/wayfinder-embedded-driver/src/lib.rs` | 2 | wall-clock source, once §2's question is settled (see line 467) — **not** needed for §4's fix |
| `libs/wayfinder/src/auth.rs` | §4 | the challenge/response pair over `frame_tag` + the pairwise-key cache |
| `libs/batman/src/engine.rs` | §8.6 | `handle_broadcast`'s dedup step — done (issue #29) |
| `libs/batman/src/lib.rs` | §8.6 | `BroadcastSeqnoEntry::admit` and its three constants — done (issue #29) |
| `libs/batman/src/engine.rs` | §4 | gate `best_next_hop` promotion (`handle_rx`'s incumbent/challenger comparison) and both selection paths (`next_hop`, `lookup_route`) on a proven next hop |
| `libs/batman/src/wire.rs` | §4 | `BatmanPacketType` variants for the challenge and its response |
| `sim/tests/test_security.py`, `sim/tests/test_adversary.py` | all | the gap tests flip from asserting the gap to asserting the fix |
| `sim/scenarios/red_team.py` | all | verdicts flip `GAP` → `HELD` |
| `sim/tests/test_red_team.py` | all | `BASELINE` flips with the verdicts it pins |
| `libs/wayfinder-driver-core/src/lib.rs` | §8.7 | `required_proof` (named `requires_pairwise_tag` when §8.7 was written; replaced `is_cert_control`), applied by both `strip_directed` and `tag_directed_into` — done |
| `libs/wayfinder/src/auth.rs` | §8.10 | `has_live_key` — the predicate the engine reconciles proofs against — done |
| `libs/batman/src/engine.rs` | §8.10 | `retain_proven`: drop proofs whose key is gone and recompute selection in the same call — done |
| `libs/wayfinder/src/lib.rs` | §8.10 | `set_auth_time` — the seam holding both halves, and the only correct way for a shell to set the auth clock — done |
| `libs/wayfinder-driver/src/driver.rs`, `libs/wayfinder-tick-driver/src/lib.rs` | §8.10 | both shells that set the clock go through the router (the embedded shell sets none); each also records the local-send failure the sweep made reachable — done |
| `libs/batman/src/lib.rs` | §8.11 | `SeqnoBands`/`admit_seqno` (the shared three-arm decision, `BroadcastSeqnoEntry::admit` delegating to it), the `OGM_SEQNO_*` bands, `OriginatorRecord::resync_watch` — done |
| `libs/batman/src/engine.rs` | §8.11 | `handle_ogm`: the high-water gates re-flooding and membership freshness; path learning and selection are judged separately; a first sighting seeds — done |
| `libs/wayfinder-test/src/integration_tests.rs` | §8.11 | the two `cert_fetch_round_trip_*` tests derive their injected seqno from the relay's high-water — done |
| `libs/batman/src/lib.rs`, `libs/batman/src/engine.rs` | §10 | the three counters, their accessors, and the recording sites; `BroadcastSeqnoEntry::admit` returns its admission so both seqno spaces count alike — done |
| `libs/wayfinder-protos` | §10 | `NodeMetrics` fields 20–22 and the `NodeMetricsData` dispatch — done |
| `libs/wayfinder-server/src/adapter.rs` | §10 | the projection, and the test for it — the smoke test answers from a `Mock`, so it cannot reach this layer — done |
| `bins/wayfinder-ctl/src/output.rs`, `bins/wayfinder-tui/src/ui.rs` | §10 | CLI and TUI rendering — done |

---

## 10. Observability for the three residuals

Added after §8.10 and §8.11 shipped, because both closed their gap while leaving
a *residual* an operator could not see — and each review of those changes asked
for the same thing independently, which is usually the signal that the answer is
one piece of work rather than three afterthoughts.

Three counters on `NodeMetrics`, all fed from state in the `no_std` core so an
embedded node reports them with no host-side tally:

| Field | What it names | Whose problem it is |
|---|---|---|
| `seqno_resyncs` | this node concluded its *own* record was wrong and threw it away | its own — usually benign (a member rebooted), fast-growing only under a sustained replay |
| `ogm_refloods_suppressed` | OGMs it declined to pass on while a high-water was under correction | **everyone behind it** — they lose the route with nothing on their side to explain it |
| `proofs_swept` | proofs dropped because the key behind them went | its own — lapsing certificates, or a key cache churning under pressure |

`seqno_resyncs` counts **both** sequence-number spaces. The broadcast one has
been equally silent since §8's item 6, and since both are judged by one
`admit_seqno` there is no honest way to instrument one and not the other. That
is what made `BroadcastSeqnoEntry::admit` return its `SeqnoAdmission` instead of
a bare "flood it": the resync fact was being discarded at the one place the two
spaces can be counted alike.

**Counts, not rates, against this repo's default.** `RateEstimator`'s memory is
five seconds (`RATE_TAU_SECS`), and these events are bounded by a thirty-second
protection window or by key evictions minutes apart — a smoothed rate would read
zero at nearly every poll, so an operator would see nothing at all unless they
sampled within a few seconds of the event. The existing `oversize_drops`
counters already make this distinction: rates for traffic, counts for rare
faults. The reasoning is repeated at the accessor, the proto field and the TUI
row, because it reads as an oversight otherwise.

**What is still not covered.** The two eviction paths that *cause* a swept proof
— `evict_expired_neighbors` and `cache_neighbor`'s full-table overwrite — are
reported at their branch point only as a `debug!` and, for the saturation case,
not at all. `AlarmKind::TableSaturation` exists and is the right instrument for
the second, since the alarm board coalesces where a log line floods; that is a
change to `auth.rs`'s eviction policy reporting rather than to this metric path,
and it is not done here.

Not surfaced on the web dashboard's metrics tab, which shows a curated subset
that already excludes the sibling drop counters (`untaggable_drop_rate`,
`oversize_drops`) — three fault counters do not belong on the view built for
non-technical users while their siblings are absent from it.
