# Design: Four gaps in mesh authentication, found by adversarial simulation

**Status:** Proposed. Each gap is a separate, independently landable change;
this document exists so they can be taken one at a time without re-deriving the
analysis. Gaps 1, 2 and 3 have since shipped — 1 and 2 together, via §4. Gap 4
remains open. The instrument that found them shipped in MR !113
(`sim/scenarios/red_team.py`).

> **§4 supersedes part of §2 and §3.** A second round of measurement showed
> gaps 1 and 2 to be one bug, and neither section's proposed fix closes it.
> Read §4 before implementing either.
>
> **§4's fix has since shipped**, closing gaps 1 and 2 together. The red team
> now runs 15 attacks and reports 13 held, 1 by design, 1 gap — §5 (CA
> misissuance). §4's "Implementation notes" record four things the build
> surfaced that the design did not predict; the fourth is the proof-starvation
> scare, which was a mismeasurement rather than a gap.

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
   accepts `incoming_seqno >= record.last_seqno` (`libs/batman/src/engine.rs:925`
   — equal, not just greater, so a same-seqno copy via a second neighbour
   registers as an alternate path; that is how a redundant mesh learns its
   backup route). An attacker therefore never needs to advance the seqno she
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
4. **Gap 4** — the only gap still open. Independent of the rest, but the widest
   test churn; best done when nothing else is in flight to avoid conflicts.
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

## 9. Key file map for the implementer

| File | Gaps | What changes |
|------|------|--------------|
| `libs/wayfinder/src/auth.rs` | 3 | `cache_neighbor`, `live_neighbor`/`evict_expired_neighbors`, `set_time`, `tag_directed`, `verify_directed`, `neighbor_cert`, `neighbor_x_pubkey` |
| `libs/wayfinder-auth/src/cert.rs` | 4 | `verify_cert` MAC/key check |
| `libs/wayfinder-auth/src/error.rs` | 4 | `AuthError::MacKeyMismatch` |
| `libs/wayfinder-server/src/authority.rs` | 4 | `submit_csr` derivation guard (~line 722) |
| `bins/wayfinder-ctl/src/cert.rs` | 4 | `issue` (`--mac` validation), `approve` (CSR MAC check) |
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
