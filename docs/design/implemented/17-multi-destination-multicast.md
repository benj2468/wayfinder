# Design: multi-destination multicast

**Status:** Implemented. This doc is kept as the record of *why*, with the
places implementing it proved it wrong corrected in place rather than
retconned. Two pieces are deliberately **not** in the implementing branch and
are called out where they belong: the carrier `fan_out()` declarations (§4.5)
and the §7a observability path.

Multicast is delivered as routed unicast to an explicit destination list, batched
so that destinations sharing a next hop travel in one frame and next hops sharing
a broadcast medium cost one transmission. It is today's `Mcast` semantics with
the per-listener duplication removed — not a flood, and not a new addressing
mode.

**Scope:** `libs/batman/src/wire.rs` (`BatmanMcastPacket` changes shape),
`libs/batman/src/engine.rs` (`handle_mcast` is rewritten),
`libs/interfaces/src/engine.rs` and the three driver shells (multi-frame
emission, §4.5), `libs/wayfinder/src/auth.rs` (fan-out signature, unified send
counter),
`libs/wayfinder-driver-core/src/lib.rs` (`requires_pairwise_tag`),
`libs/wayfinder/src/lib.rs` (`handle_local_mcast`), `libs/wayfinder-shark`.

**Not touched:** `MCAST_FANOUT` and the flood-vs-unicast rule; IGMP snooping;
the broadcast dedup table; every other packet type.

---

## 1. Motivation

A multicast frame for a group with known listeners is sent as one `Mcast`
packet **per listener**, each routed independently and each carrying its own
24-byte pairwise tag. Every hop those copies share is paid for once per
listener.

```
   a ──eth── b ──radio──┬── c        group members: a, d, e, f
                        ├── d        (b and c are not members)
                        ├── e
                        └── f
```

| | Ethernet | Radio | Total |
|---|---|---|---|
| Today | 3 | **3** | 6 |
| This design | 1 | **1** | 2 |

`a` sends one frame to `b` listing `[d, e, f]`. `b` finds all three behind one
radio interface and transmits **once**; all three hear it, find themselves in
the list, and deliver. `c` hears it too, is not in the list, and ignores it —
it was never a next hop for anyone, so it does not forward either.

The radio column is what matters: it is the duty-cycle-limited medium. Neither
number grows with the listener count.

### Why not a flood

Three earlier revisions of this design flooded a group-addressed frame and
pruned the flood back toward members. §8.1 records why that was abandoned: every
mechanism it needed — a TTL sized to the furthest member, interface pruning by
membership, a fail-open rule when membership is unknown — was an *approximation*
of routing information the node already holds exactly. Each approximation had
its own staleness window and its own silent failure, and they compounded across
hops. Deterministic routing needs none of them.

### A second, independent motivation

`Bcast` carries **no** authentication — the documented scope limit in
`wayfinder::auth` — so multicast that exceeds `MCAST_FANOUT` is flooded in the
clear today. This design does not fix that (a flood is still a flood); it does
mean the *common* case stops being a flood at all.

Pinned by `one_multicast_frame_crosses_the_wire_and_the_radio_once_each`
(`libs/wayfinder-test`), `#[ignore]`d until this lands.

---

## 2. Goals

- One frame per (hop, next hop), and one transmission per (hop, broadcast
  medium), regardless of listener count.
- **Never more transmissions than today's per-listener plan**, in any topology.
  §8.1's design violated this; it is an invariant to assert, not to trust.
- Delivery decided by explicit routing, not by heuristics with staleness
  windows.
- One code path, not two: the single-destination case is `n_dests = 1`, not a
  fallback.

## 3. Non-goals

- **Changing the flood-vs-unicast rule.** `MCAST_FANOUT` still decides when a
  group is flooded instead, and that flood is unchanged.
- **Wire compatibility with the current shape.** This is a flag day (§4.1).
- **End-to-end payload authenticity.** Authentication is hop-by-hop, exactly as
  it is for directed frames today. §8.4 sketches the two-layer alternative.
- **Reaching listeners the sender has not learned.** A joiner absent from
  `mcast_members` is missed, precisely as `McastPlan::Unicast` misses it today.
- **IPv6 MLD snooping**, and **confidentiality**.

---

## 4. Design

### 4.1 Wire format

**`Mcast` (`0x04`) itself changes shape** — not a new sub-type. `BatmanMcastPacket`
gains a destination count and carries that many addresses where it carried one:

```
 0       1       2       3         4       5              5+6N
 +-------+-------+-------+---------+-------+--------------+---------+----------+
 | type  | vers  | ttl   | n_dests | form  | dest[..]     | payload | auth     |
 +-------+-------+-------+---------+-------+--------------+---------+----------+
  0x04      6      50      1..=255   1 | 2   6N bytes       MTU-bnd   24 or 72
```

A new sub-type would have bought a mixed-version mesh, at the price of a
capability handshake to discover who speaks it, a fallback path to maintain, and
two multicast handlers living side by side forever. The project is in beta, so
none of that is worth carrying: **this is a flag day**, and the old shape is
gone.

The single-destination case is not special — it is `n_dests = 1`, an 11-byte
header against today's 9. Two bytes, on a packet that already dwarfs them. So
there is **no fallback path at all**: every multicast frame has this shape, and
the routing logic has one case rather than two.

`form` selects which proof the auth trailer carries, and is the subject of
§4.4. It never selects *whether* the frame is authenticated: `1` is the pairwise
tag, `2` the fan-out signature, and every other value is a drop.

`ttl` is a loop backstop, not a routing input — the same 50 today's
`BatmanUnicastPacket` carries, for the same reason. Routing follows next hops,
so a loop needs a transient inconsistency during reconvergence; the TTL bounds
it. **Nothing sizes it to the topology**, which is the trap §8.1 fell into.

`n_dests` MUST be ≥ 1. The list shrinks as the frame is routed: each hop removes
destinations it delivers locally and splits the rest by next hop, so a frame
never carries a destination it is not on the path to.

The auth trailer is 24 bytes (counter + pairwise tag) or 72 (counter +
signature) — see §4.4.

#### Make `version` mean something first

`version` is written as `5` on every packet this codebase emits and **checked on
none of them** — a grep finds it only in constructors and test assertions. It is
currently decoration.

That matters here because it is the field that should make this flag day clean.
Bump it to `6` *and add the check*, so a node meeting the other shape rejects it
on the version rather than misparsing:

* An old node reading a new frame takes `n_dests` as the first byte of `dest`
  and the rest from the first address, yielding a garbage MAC. It almost
  certainly has no route and drops it — but "almost certainly" is doing real
  work in that sentence, and a fluke collision with its own ident would deliver
  garbage to the host.
* A new node reading an old frame takes a MAC's first byte as `n_dests` and
  reads that many addresses out of a payload that has none, which the bounds
  check catches.

Both mostly fail safe. A validated version makes both fail *deterministically*,
costs three lines, and pays for itself at the next wire change.

### 4.2 Building the frame

`handle_local_mcast` takes the destination *set* rather than one destination:

```rust
pub fn handle_local_mcast<'a>(
    &mut self,
    now: Duration,
    dests: &[Mac],          // was: dest: Mac
    payload: &[u8],
    tx_buf: &'a mut [u8],
) -> Result<impl Iterator<Item = LinkFrameData<'a>>, LocalSendError>
```

The sender resolves each of `mcast_targets(group)` to a next hop, groups by it,
and emits one frame per group. **The sender excludes itself**: a member that is
also the originator already has the frame, so it never appears in a list — which
is why nothing is ever sent back toward the originator, and why §8.1's
"relay echoes at its sender" problem does not exist here.

A destination with no route is dropped from the list with a `trace!`, exactly as
an unroutable `Mcast` is dropped today. A frame whose list empties this way is
never emitted.

### 4.3 Forwarding

`handle_mcast_multi`, at every hop:

1. **Authenticate** (§4.4). Reject before anything else is read.
2. **Refuse the whole frame** if the list is longer than `MAX_MCAST_DESTS` —
   only a member forging one gets there, and processing an attacker-chosen
   prefix would be worse than dropping.
3. **Deliver** if `self_ident` is in `dests`, and remove it from the list. If
   the frame carries `McastAuthForm::Signature`, stop here: it is never
   forwarded (§4.5).
4. **Drop** if the list is now empty, or if `ttl <= 1`. (The code emits nothing
   rather than testing emptiness, which is the same thing.)
5. **Group** the remaining destinations by this node's next hop for each.
6. **Emit one frame per group**, `ttl - 1`, carrying only that group's
   destinations.
7. **Collapse** (§4.5): *terminal* groups whose next hops sit on one broadcast
   medium become a single transmission.

Every step reads state the node owns. There is no membership table consulted, no
TTL heuristic, and no dedup — a destination appears in exactly one group at each
hop, so it traverses exactly one path and arrives once.

A node that is not a destination and is not a next hop for any destination
receives nothing addressed to it and does nothing. On a shared medium it may
*hear* a frame (as `c` does in §1); it finds itself in neither role and ignores
it.

### 4.4 Authentication

**One next hop → the pairwise tag, unchanged.** This is a directed frame like
any other; `requires_pairwise_tag` keeps `Mcast` in the *requires a tag*
bucket, `plan_dispatch` tags it on egress and `strip_directed` verifies it on
ingress, exactly as for `Unicast` today. The tag covers the whole frame
including the destination list, so a hop cannot rewrite the list without its
successor noticing.

**Several next hops on one medium → the forwarding node's signature.** A single
transmission reaching three neighbours cannot carry three pairwise tags, each
derived from a different key. So a fan-out hop signs the frame with its own key
and each receiver verifies *that hop's* signature against the cert it already
holds.

This is the same trust model, not a weaker one: `plan_dispatch` already re-tags
every directed frame it forwards, so directed traffic is already vouched for
hop by hop rather than end to end. The signature replaces the tag as the vouching
mechanism when one tag cannot cover the audience.

Two rules keep this from reopening design 09 §8.7, where a frame skipped
authentication entirely because an attacker-chosen field said it could:

* **Both forms are mandatory.** The sub-type requires *authentication*; the
  `form` byte says only which of the two proofs to demand, and a frame carrying
  neither is dropped. There is no path on which the check is skipped — which is
  the property `8ab9285` established and the one that must not regress.
* **A fan-out frame is signed by the forwarder, never by the originator.** An
  originator signature would have to survive the list being rewritten at every
  hop, and a signature that excludes the list lets an attacker rewrite the
  routing (§8.2).

**How the receiver knows which form to expect.** An earlier revision of this
section said the form follows from the link-layer destination the sender used —
one neighbour versus the medium's broadcast address — "which the receiver
observes rather than parses". That is wrong, and the codebase says so in as many
words. `requires_pairwise_tag`'s doc comment
(`libs/wayfinder-driver-core/src/lib.rs`) records the rule `8ab9285`
established:

> **This is decided by the sub-type, never by the link-layer destination.** The
> two are unrelated fields, both attacker-chosen on an injected frame […]

`frame.dst` is stamped by whoever sent the frame. It is not an observation, it
is a field of the attacker's choosing, and a discriminator built on it is the
construction that hardening removed wearing different clothes.

The resolution is to stop looking for a trustworthy selector, because the
property that mattered was never "the selector is honest". It was that **no
value of the selector reaches an unauthenticated path.** `8ab9285`'s bug was
that one branch of the choice was *no check at all* — an attacker did not have
to forge anything, only to pick that branch. Here both branches are proofs, so
the selector chooses which proof a frame is judged against, and an attacker who
flips it has only chosen the check they fail.

So: **an explicit `form` byte in the `Mcast` header** (§4.1), under three rules.

* **Every value maps to a mandatory proof.** `Tag` and `Signature` are the two
  defined values; **every other value fails closed**, exactly as
  `requires_pairwise_tag` fails closed on a sub-type it does not recognise.
  There is no value, defined or not, that means "unauthenticated".
* **The proof covers the `form` byte**, as it covers the rest of the frame.
  Flipping it invalidates whichever proof the frame carries, so the field cannot
  downgrade a signed fan-out frame into a tag-form frame to be judged against a
  pairwise key the attacker does not hold.
* **The form is not the trailer's length and cannot be inferred from it.** An
  `Mcast` payload runs to the end of the frame, so without `form` there is no
  way to say where the payload stops and a 24- or 72-byte trailer begins. Trying
  both is not a fallback, it is an oracle.

The cost is one byte, and moving `requires_pairwise_tag` from a bool to a
three-way classification for `Mcast`: `strip_directed` reads one further header
byte, at a fixed offset and bounds-checked, before choosing a verifier.

**Replay.** `Mcast` is already in the *requires a tag* bucket, so today's
multicast frame carries the 8-byte monotonic counter `verify_directed` checks.
The fan-out form must not lose it — hence a `[counter:u64 BE][sig:64]` trailer,
72 bytes.

The counter needs one change to work. `next_send_counter` allocates **per
destination**, which is fine while every directed frame has exactly one; a
fan-out frame has none. Drawing its counter from any single recipient's space
would hand the other recipients a value below their own high-water mark, and get
a legitimate frame dropped as a replay.

The fix is to allocate from **one per-sender sequence** instead of one per
destination. Receivers need no change at all: `accept_recv_counter` already keys
its high-water mark on `src` alone, and any subsequence of a strictly increasing
sequence is strictly increasing — so each neighbour still sees monotonic
counters whether it received every frame or one in ten. It also removes state,
since `evict_neighbor` then has no send-side counter to reset. What it gives up
is that a neighbour can infer this node's total directed-frame volume rather
than only its own share, which is already visible to anyone on the medium.

**Checked against `red_team.py`** (§9.1) — not for the discriminator, which is
settled above, but because the shape it legitimises is the shape two existing
attacks forge. Doing so found that the suite's forge stamped a stale protocol
version, so every forged frame was dropped at the version check and every
attack reported HELD without reaching the control it tested; the forge now
reads the version from the router itself.

**Trailer sizing.** A driver reserves space for the trailer *before* the frame's
sub-type and form have been classified, so it must reserve `MAX_TRAILER_LEN` —
the larger of the two — not the pairwise length. Reserving the smaller leaves a
fan-out signature writing 48 bytes past the end of the staged buffer. All three
shells reserved `DIRECTED_TRAILER_LEN`; each now reserves the maximum, and
`tag_directed_into` refuses a short buffer rather than indexing past it.

**Cost.** One Ed25519 sign per *fan-out hop*, not per hop: a linear path pays
only pairwise tags. On the topology in §1 that is one signature per frame, at
`b`. Signing on the data plane is new for embedded nodes and §9.3 is a
measurement, not an assumption.

### 4.5 Collapsing onto a shared medium

Two next hops behind the same interface do not need two transmissions if that
interface reaches both in one — which is what `LinkT::fan_out()` declares
(landed in !156, implemented by `UdpMultiLink`). The engine groups by next hop;
the *driver* then merges groups whose next hops share a fan-out interface into
a single transmission. It does **not** use `send_all`: the merged frame is one
frame addressed to the medium's broadcast address and pinned to the interface,
not the same payload sent to several destinations. `send_all` therefore still
has no production caller.

`fan_out()` is a **threshold**, not a flag: the destination count at which one
send beats one directed copy each. Below it the directed copies are both
cheaper and more precise. It is `None` for every point-to-point carrier, so
nothing merges there
and the per-next-hop frames go out individually. The remaining carriers (LoRa,
BLE, 802.15.4, `RawL2Link`) declare it as part of this work — **with** the
consumer, so a carrier still answering `None` when the merge lands cannot
silently disable the optimisation.

Over-claiming is a correctness bug here, not a missed optimisation: a link that
says one send reaches every neighbour when it does not will drop every
destination but one.

#### Only terminal groups merge, and a merged frame is never forwarded

Merging discards the per-next-hop grouping: several groups become **one**
destination list for the whole audience. A receiver that then needed to forward
could not tell which of the remaining destinations were its to carry and which
had already been delivered to a neighbour beside it — so it would forward all of
them, and so would every other receiver. Measured, before the rule existed:
**2293 radio transmissions where one was wanted.**

Two restrictions together close it, and both are load-bearing:

* **Only groups whose destination *is* their next hop merge.** A destination
  sitting behind its next hop keeps its own directed frame, where the next hop
  is unambiguous. This is what makes the merged audience exactly "the direct
  neighbours on this medium".
* **A frame carrying [`McastAuthForm::Signature`] is delivered and never
  forwarded.** Given the first restriction nothing in such a frame needs onward
  routing, so this costs no delivery. It is enforced at the receiver rather than
  trusted, because the rule must hold against a frame some *other* node built —
  and a forwarding storm is a far worse failure than a dropped multicast.

The single-transmission win in §1 depends on both. Neither is optional, and the
first is easy to lose while "improving" the merge to cover more cases.

### 4.6 The engine must emit more than one frame

This is the largest single piece of work, and it is what §8.1 was contorting
itself to avoid.

`MeshRoutingEngine::handle_rx` returns one `RoutingAction` and writes into one
`reply: &mut LinkFrameDataMut`. Step 5 of §4.3 needs N. The shells are already
ready — `MeshSink::emit` takes frames one at a time and driver-core loops — so
only the engine boundary changes.

Recommended shape: pass a bounded emitter into `handle_rx` rather than adding a
`RoutingAction` variant, so a handler that produces several frames does not
have to encode that in its return value.

**The bound is not the interface count.** Groups are bounded by *distinct next
hops*, and five neighbours behind one radio are five groups before the driver
collapses them (§4.5) — `MAX_INTERFACES` is 8 and `n_dests` reaches 255 on a
frame a member forged. `MCAST_FANOUT` (16) is the natural bound, being the cap
the sender already applies; §9.4 is where that is settled. Whatever it is,
account for a frame whose groups exceed it — dropping the overflow silently is
the failure this design exists to avoid, so it must be `warn!`-visible and
counted.

---

## 5. Correctness

**No misdelivery.** A destination is only ever placed in a frame addressed to
the next hop this node resolved *for that destination*, and each hop repeats the
rule against its own table. Every destination follows exactly the path its own
`Mcast` would have followed today; batching changes the packing, never the route.

**No duplicate delivery.** The grouping at each hop is a partition, so a
destination appears in exactly one outgoing frame. A node delivers only when it
finds its own ident, and removes itself before forwarding.

**Termination.** The list strictly shrinks along any path (step 2), and `ttl`
decrements per hop as a backstop against a transient routing loop. Both bounds
are the ones `Mcast` already relies on.

**No amplification.** The total number of frames a hop emits is bounded by the
number of distinct next hops among its destinations, which is bounded by the
list length, which strictly shrinks. A forged frame cannot expand.

**Cost invariant.** For any topology this must not spend more transmissions than
`McastPlan::Unicast` does. Batching only ever merges frames, so this holds by
construction — but §8.1 held it by construction too, right up until the flood's
re-broadcasts were counted. Assert it in the test.

**Edge cases to test.** `n_dests: 0` and a list overrunning the payload
(malformed — drop); a list naming only this node; a list where every destination
resolves to a different next hop (full split, no merging); a destination with no
route (dropped from the list, the rest still forwarded); a frame heard on a
shared medium naming neither this node nor anything it routes for (silent
`trace!`, never a warning — this is the common case on a radio); a fan-out frame
with a bad signature; a single-next-hop frame with a bad pairwise tag; groups
exceeding the §4.6 emitter bound.

And the `form` byte specifically: an unrecognised value (drop — never a fallback
to trying the other verifier); a fan-out frame whose `form` has been flipped to
`Tag` (the signature no longer covers the header, so the tag check fails rather
than the frame being admitted on the weaker of the two); a fan-out frame
carrying a stale counter (replayed, dropped); and a fan-out frame signed by a
non-member, which is the case §9.1 asks the red-team suite to start making.

---

## 6. Security

The threat model is unchanged: authenticity and mesh segregation, never
confidentiality.

**Hop-by-hop, as today.** Directed frames are already vouched for by each
forwarder rather than end to end — `plan_dispatch` re-tags on every forward. A
member can therefore inject into a multicast stream it forwards, which is true
of `Unicast` today and is not a new exposure. Outsiders cannot, because every
hop is authenticated.

**The list is covered.** Both the pairwise tag and the fan-out signature cover
the whole frame, so a hop cannot rewrite the destination list without its
immediate successor rejecting the frame. This is what makes routing on an
in-band list safe, and it is the property an originator-signed design could not
have (§8.2).

**Revocation** goes through the same key lookup as `verify_ogm`, so a revoked
forwarder's signature is rejected on the existing path.

**Replay** is already guarded, and must stay that way. `Mcast` sits in
`requires_pairwise_tag`'s *requires a tag* bucket, so a multicast frame today
carries the same 8-byte monotonic counter as a `Unicast` and `verify_directed`
rejects a stale one. The fan-out form keeps the counter and changes only where
it is allocated from (§4.4); dropping it because the frame is now one-to-many
would regress a guard this packet type already has.

---

## 7. Migration

A flag day (§4.1). Every node in a mesh must be updated together; a mixed mesh
does not interoperate for multicast, and with the version check added it says so
cleanly rather than misparsing.

That is affordable *because the project is in beta* and is the whole reason a new
sub-type was rejected: a second tag would have needed a capability handshake to
discover who speaks it, a fallback path kept alive indefinitely, and two
multicast handlers side by side. None of that is worth carrying to avoid one
coordinated restart of a mesh that has no external deployments.

Unicast, broadcast, OGMs and every other packet type are unaffected, so a mesh
mid-upgrade still routes — only multicast is interrupted.

`libs/wayfinder-shark`'s dissector parses the *changed* `Mcast` layout rather
than gaining a new type; its pytest suite is the cheapest place to pin it.

## 7a. Observability

**Not implemented.** The counters exist on the router — destinations dropped for
want of a route (relay and origination separately), lists refused for exceeding
capacity, groups the sink would not take, groups lost rebuilding a frame — but
none of them reaches the management API, so no operator, CLI or TUI can read
one. A counter nobody can read does not fix a quiet failure, and this is the
second follow-up.

What the full path should carry, when it lands: state belongs in the `no_std`
`CentralRouter`, not the driver; prefer a bounded here-and-now signal to a
running total. Use the `add-metric` skill.

- **Frames saved** — per-listener copies replaced by batched frames, as a ratio
  rather than a count. The first question an operator will ask is whether
  batching is firing at all.
- **Fan-out merges** — how often several next hops collapsed onto one
  transmission. This is where the §1 win shows up, and where a carrier that
  forgot to declare `fan_out()` shows up as a sudden zero.
- **Destinations dropped for want of a route**, which is the quiet failure of
  the whole scheme.
- **Auth failures by form** (bad tag versus bad signature), separating a
  misconfigured peer from an injection attempt.

---

## 8. Alternatives considered

### 8.1 A pruned flood of a group-addressed frame — three revisions, abandoned

The frame naming the *group* rather than its listeners, flooded with a TTL,
deduplicated on `(orig, seqno)`, delivered by receivers checking their own
`local_mcast`, and pruned to interfaces with members behind them.

It was attractive because the frame is a constant 13 bytes at any listener
count, membership never goes stale on the wire (the receiver decides, so a fresh
joiner is served), and a group MAC survives forwarding so one originator
signature covers the whole path.

**Abandoned for brittleness.** Every mechanism it needed was an approximation of
routing information the node already holds exactly:

* **TTL sizing.** BATMAN IV tracks TQ, not hop count, so the sender cannot read
  a distance off its table. Counting the §1 topology properly showed the flood
  costing **seven** transmissions against today's six — five on the radio
  against three — because `c` re-broadcasts as a non-member forwarder and `d`,
  `e`, `f` re-broadcast at each other. The fix was a rule collapsing the TTL to
  1 when every member behind the pruned set is a direct neighbour, which works
  at the last hop and nowhere else. Multiple fan-out points at different depths
  have no single correct TTL.
* **Membership pruning**, which fails open when membership is unknown and
  silently drops a fresh joiner's interface when it is stale.
* **The originator echo**, where a relay transmits back at the sender because
  the sender is itself a member, needing a further rule to suppress.

Three heuristics, three staleness windows, three silent failure modes, all to
approximate the next-hop table. Routed unicast reads that table directly, and
none of the three exists here — the sender excludes itself, so there is no echo;
the TTL is a loop backstop nothing sizes; and there is no membership consulted
while forwarding at all.

Worth keeping in mind if a future case genuinely needs receiver-decided
membership — a very large group where the list dominates the frame, say. The
crossover is roughly where 6N exceeds the payload.

### 8.2 An originator signature over the destination list

Rejected: the list is rewritten at every hop, so an originator signature over it
breaks on the first forward, and one that excludes it lets an attacker rewrite
the routing — turning a 1-destination frame into a 255-destination one. Per-hop
authentication (§4.4) is what makes an in-band routing list safe.

### 8.3 Coalescing only direct neighbours

An intermediate revision partitioned listeners into direct neighbours (batched)
and everyone else (one packet each). It fails on §1's topology: none of `d`, `e`,
`f` is a neighbour of `a`, so nothing batches and `a` emits three frames.
Distance is not the axis that matters; **shared next hop** is.

### 8.4 Two-layer authentication

An originator signature over the immutable part (payload) plus per-hop
authentication over the mutable envelope (the list). Preserves end-to-end
payload authenticity while allowing fan-out. Costs a further 64 bytes on every
frame and an origin verify at every destination. Worth revisiting if end-to-end
authenticity for multicast is ever wanted; it is not a goal today, because
`Unicast` does not have it either.

### 8.5 Per-link flood threshold (`LinkFeatures::min_fan_out`) — built, reverted

Flooding earlier on links that fan out natively. Rests on a flood being one
transmission, which it is not: `handle_broadcast` re-floods once per node, so a
flood costs M transmissions against Σ path lengths, and with N ≤ M−1 flooding
*earlier* makes LoRa and BLE links worse. The tests passed; they encoded the
wrong rule. Do not re-derive it.

### 8.6 Let the link read router state

Work item #11's proposal. Rejected: it inverts the layering (`LinkT` is `no_std`
and holds no router reference) and puts the same decision in every driver
instead of once in the engine. `LinkT::fan_out()` is the same information
flowing the other way — the link declares a property of its medium (§4.5) and
the router decides.

### 8.7 Do nothing

The cost is bounded by `MCAST_FANOUT` and a mesh that uses little multicast
never pays it. Rejected because the links that do pay it are the duty-cycled
radios where airtime is the binding constraint.

---

## 9. Open decisions

*Settled by the implementation, kept for the reasoning:* **2** (one per-sender
counter), **4** (`MAX_MCAST_DESTS` = 16, now pinned to `MCAST_FANOUT` by a
static assertion) and **5** (the version check landed first, then the bump to
6). **1** and **3** below are still open.

1. **What the fan-out form does to the controls covering this surface**
   (§4.4). The discriminator itself is settled — an explicit `form` byte, every
   value a mandatory proof — but the shape it legitimises is the shape the
   red-team suite forges. `red_team.py`'s
   `attack_multicast_addressed_directed_delivery` and
   `attack_injected_directed_laundered_by_relay` both inject an `Mcast` under a
   broadcast link dst, and
   `strip_directed_drops_a_group_addressed_mcast_without_a_tag` pins the same
   case. Today that shape is *structurally impossible from an honest sender*;
   after this design it is the ordinary fan-out frame. All three still pass —
   Eve carries neither a tag nor a signature — but the control protecting them
   weakens from "no such frame exists" to "the signature does not verify".
   Decide whether that is acceptable, and if it is, strengthen the three to
   assert the new reason rather than the old: a forged *signature* from a
   non-member is the case they should be making once this lands.

   *Partly done.* `attack_multicast_addressed_directed_delivery` now injects
   both auth forms. The Rust twin
   (`strip_directed_drops_a_group_addressed_mcast_without_a_tag`) still only
   exercises the tag form, and this section's claim that
   `attack_injected_directed_laundered_by_relay` injects an `Mcast` is simply
   wrong — it injects a `Unicast` under a broadcast link dst. Both remain to
   be addressed.
2. **Whether the send counter unifies for every directed frame, or only for
   fan-out** (§4.4). One per-sender sequence is the simpler of the two and needs
   no receiver change — but it changes `next_send_counter` for `Unicast` as
   well, and that function has its own tests. The alternative, a fan-out-only
   sequence beside the per-destination ones, keeps `Unicast` untouched at the
   cost of a *second* high-water mark per source on the receive side, since one
   `accept_recv_counter` mark cannot serve two counter spaces without the two
   suppressing each other. Prefer the unified counter unless the `Unicast` blast
   radius turns out to be real.
3. **Ed25519 signing cost on the data plane** for an nRF52840 at a fan-out hop.
   A measurement, not an assumption, and still the one open item that needs
   hardware. If it is prohibitive, the fallback is N
   pairwise-tagged transmissions on that hop — correct, just not collapsed.
4. **The §4.6 emitter bound.** `MCAST_FANOUT` (16) is the recommendation there,
   and the argument for why it is *not* the interface count is in §4.6. What
   remains is picking it and deciding the overflow behaviour, which must be
   `warn!`-visible and counted whatever the number turns out to be.
5. **Whether the version check lands as its own change first** (§4.1). It is
   independently useful, it is three lines, and having it in place *before* the
   layout changes is what makes the flag day diagnosable rather than mysterious.

Two decisions the flag day closes outright: there is no capability
advertisement to design, and no minimum destination count to pick — `n_dests = 1`
is the ordinary single-destination frame, not a fallback worth avoiding.

## 10. Key file map

| File | Change |
|---|---|
| `libs/batman/src/wire.rs` | `BatmanMcastPacket` gains `n_dests`, a `form` byte + an inline list; `version` bumped to 6 |
| `libs/interfaces/src/engine.rs` | `handle_rx` gains a bounded frame emitter (§4.6) |
| `libs/batman/src/engine.rs` | `handle_mcast` rewritten — deliver, remove self, group by next hop, emit per group; **validate `version`** |
| `libs/wayfinder/src/lib.rs` | `handle_local_mcast` takes `&[Mac]` and yields a frame per next-hop group |
| `libs/wayfinder/src/auth.rs` | fan-out signature: sign/verify under its own domain, a `[counter][sig]` trailer, and `next_send_counter` unified to one per-sender sequence (§4.4) |
| `libs/wayfinder-driver-core/src/lib.rs` | `requires_pairwise_tag` becomes a three-way classification for `Mcast` — tag / signature / fail closed; merge groups onto a `fan_out()` interface via `send_all` |
| `libs/wayfinder-driver/src/driver.rs`, `libs/wayfinder-embedded-driver`, `libs/wayfinder-tick-driver` | absorb multiple frames per received frame; the tick driver additionally has **no multicast plan at all** today — `queue_local_send` sends a group MAC down the unicast path and drops it |
| `libs/rylr998`, `libs/blue`, `libs/nrf-ieee802154`, `libs/at86rf233`, `raw.rs` | declare `LinkT::fan_out()` (§4.5) |
| `libs/wayfinder-test` | un-`ignore` the topology test; assert the §5 cost invariant |
| `sim/scenarios/red_team.py` | re-aim the two `Mcast`-under-broadcast attacks at a forged fan-out *signature* (§9.1) |
| `libs/wayfinder-shark/` | dissector + pytest for the changed `Mcast` layout |
