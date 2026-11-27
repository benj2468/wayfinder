# 30: An open mesh only routes over links it has seen work both ways

**Status:** Proposed. For #136. Builds on design 29 (#133, not yet merged) and
cannot ship without it.

**Scope:** `libs/batman` (selection, relay rule, one new packet type),
`libs/wayfinder` (interface bookkeeping, gates, egress choice, an accessor),
`libs/wayfinder-shark` (decode the new type). Authenticated meshes, the OGM
layout and the TQ formula do not change.

## 1. Motivation

On an open mesh, a node that hears an originator but cannot be heard back
selects that direct path and sends every frame into it. #136 measured delivery
1.00 without the one-way link and 0.00 with it. TQ measures only the receive
direction. An authenticated mesh is covered already, because the next-hop proof
is a round trip.

## 2. Goals and non-goals

Goal: on an open mesh, select a path through neighbour N only on evidence that
N hears this node, and send to N only on an interface where it does. This holds
on interfaces where this node transmits OGMs (`tx_ogm` on).

Not covered:

- **Lossy asymmetry.** The check is yes or no. A reverse direction that loses
  90% of frames passes if one in sixteen gets through. TQ is unchanged.
- **Interfaces with `tx_ogm` off.** This node sends nothing there that could be
  echoed, so requiring evidence would end the documented "ground station
  fronting a LoRa mesh" setup (`LinkFeatures`: `tx_ogm` off, `tx_data` on,
  edge nodes reachable). Such an interface keeps today's behaviour, including
  the black hole if its link is one way. Only an operator who turns the gate
  off is exposed.
- **Forgery.** An open mesh has no authentication, and anyone can send the
  evidence below. This handles radios, not attackers.
- **Authenticated meshes.** `require_proof` keeps its own gate, and everything
  below is off while it is set.

## 3. Design

### 3.1 The evidence

Node A already hears its neighbours re-flood its own OGMs, and discards them
(Rule 1). Before discarding one, record it. N has shown it hears A when A
receives from N either:

- an OGM with `orig == A` and `ttl == 49`, one below what A emits, so N
  received it straight from A; or
- an `OgmEcho` (§3.3) with `orig == A`.

`PrevSender` is not used. Under design 29 it names N's next hop, which need not
be A.

### 3.2 Which interface, and for how long

Each emission on each interface already takes its own sequence number.
`on_interface_emitted(k)` pushes that number onto `ring[k]`, a ring of the last
`MAX_MISSED_ECHOES = 16` numbers sent on interface `k`, when it has changed
since the last push (a suppressed emission pushes nothing).

An echo of seqno `s` found in `ring[k]` proves that A's transmissions on `k`
reach N, whichever interface the echo arrived on. Store
`echoed[N][k] = s`. **N is verified on `k` while `echoed[N][k]` is still in
`ring[k]`.** No timer is needed: the window follows A's own Trickle pacing.

- `select_path` skips a neighbour verified on no interface, in the same place it
  applies `proof_current`.
- Egress to N picks the best link quality **among verified interfaces**.
- A verification that turns a route on re-runs selection
  (`recompute_all_best`). It does not reset Trickle: A's advertised state has
  not changed.
- On an interface with `tx_ogm` off, an OGM heard there from N marks N *exempt*
  on it, which counts as verified (§2). The router passes the gate to the engine
  with the OGM. The mark lasts while any path through N does, and turning
  `tx_ogm` on at runtime clears that interface's exempt marks.

**Where the evidence lives.** `echoed` is its own table in the engine, keyed by
neighbour MAC, like `proven`. It is not a field of `OriginatorRecord`: it
describes a neighbour, not a destination. Evicting an originator, N included,
leaves it alone, so a re-learned originator is routable at once and a full
originator table does not reset any verification.

It holds `MAX_ORIGINATORS` entries. An entry has *lapsed* when none of its
seqnos is still in a ring and it has no exempt mark with a live path. When the
table is full, a new neighbour replaces a lapsed entry. If none has lapsed, the
new neighbour is **not admitted** and stays unverified. Evicting a live entry
instead, as `proven` does, would flap routes on every emission once neighbours
outnumber entries.

### 3.3 The relay has to echo before it has a route

Design 29 withholds a re-flood when the relay has no usable next hop. With the
filter above, two new neighbours then each wait for the other to echo first, and
the mesh never forms (§5, row 3). So a relay that hears an OGM **directly**
(`frame.src == orig`) and is not going to re-flood that copy sends an echo
instead:

```text
OgmEcho (BatmanPacketType 0x0e), 12 bytes, link dst = broadcast
  packet_type u8 | version u8 (6) | orig [u8; 6] | seqno be32
```

`orig` and `seqno` are copied from the OGM. It is never relayed, and a receiver
that is not `orig` ignores it. It teaches no path, no sequence number and no
membership, so `rx_ogm` does not gate its receipt.

**Egress.** An echo leaves on **every interface whose `tx_ogm` is on**, as a
re-flood does (`Egress::Auto` with a broadcast `dst`). The ingress interface is
not enough: if A reaches N on `k` but N reaches A only on another interface, an
echo sent back on the ingress one is lost and A never verifies a usable link.

"Not going to re-flood" covers:

| case | why there is no re-flood |
|---|---|
| no usable next hop toward `orig` | design 29 |
| a relayed copy of that seqno was flooded first | once per `(orig, seqno)` |
| the high-water refuses it (stale, or `orig` rebooted) | sequence number rules |
| ingress link has `tx_data` off | the router suppresses re-advertisement |
| ingress link has `rx_ogm` off | the engine never sees the OGM |
| the stamped re-flood does not fit the reply buffer | oversize drop |

Each record keeps the last seqno echoed, so one direct copy is answered once.
With `rx_ogm` off there is no record, and each direct OGM gets one echo, which
is one frame out per frame in.

`OgmEcho` is named under the `tx_ogm` gate in `link_may_tx`.

**Airtime.** An OGM that takes the normal re-flood sends nothing extra. In the
other cases a neighbour sends at most one 12-byte payload per `tx_ogm`
interface per direct OGM. On a shared segment of N nodes that is at most N-1
echoes per emission and N(N-1) per round, the same order as the re-floods
already cost. It reaches that bound when echoes replace re-floods (cold start)
or add to them (every relayed copy arrives first).

## 4. Compatibility and edge cases

**Wire.** One new packet type. A node without this change handles an unknown
type by its link `dst`; broadcast has no route, so it is consumed.

**Mixed versions.**

- An old neighbour's ordinary re-flood has `ttl == 49`, so new nodes verify it.
- An old neighbour sends no echo. If a relayed copy of A's OGM reaches it before
  the direct one every time, a new A **stops using that link**. This needs a
  relayed path that is consistently faster than one direct transmission, for
  example a slow LoRa link beside a two-hop Wi-Fi path.
- An old node on a one-way link keeps today's behaviour. It also still
  advertises that path, so a new neighbour with a two-way link to it can route
  through it into the black hole. The fix is complete only once the receiving
  end of each one-way link is upgraded.

**A link turning one-way** is dropped after sixteen emissions on that interface
without an echo. At the default `i_max` of 32 s that is up to about 8.5
minutes, longer than path ageing (six intervals). `main` never drops it. Not
measured.

**Loss.** Verification needs the OGM and its echo both delivered once in
sixteen tries. At 50% independent loss each way, sixteen misses in a row has
probability `0.75^16 = 0.01` per window. A window of six would give 0.18 and a
flapping link, which is why the constant is not `MAX_MISSED_OGMS`. This is
arithmetic; burst loss would be worse.

**Acceptance bar for the implementation PR.** Two open-mesh nodes, one link
losing 50% independently each way, a unicast stream, 40 seeds, `main` and the
branch on the same seeds, counted over the same window starting 120 s after
cold start. It passes if mean delivery on the branch is **at least 0.95 times**
`main`'s. If it fails, the PR does not merge: this doc is revised first, and the
implementer does not retune the constant.

**Configurations.** `tx_ogm: false` is handled in §3.2, `rx_ogm: false` and
`tx_data: false` in §3.3. With both OGM gates off no paths exist, as today.

**Reporting.** An unverified neighbour has paths but no `best_next_hop`, the
state an unproven one is in on an authenticated mesh.

**Footprint.** `echoed` is a sidecar table of at most `MAX_ORIGINATORS` entries
of `MAX_INTERFACES` sequence numbers and two interface bitmasks (held, exempt),
plus the rings. By arithmetic, not measurement: about 6 KB at 128 originators
and 8 interfaces, about 400 B at 16 and 2. The implementation PR reports `size_of::<CentralRouter>` per profile and
runs `just stack-budget` for the WL55. If it does not fit, `u16` emission
counts halve it.

## 5. Evidence

A throwaway engine-level prototype on `main` at `a4c127b7`: five engines in a
chain, `PerfectWire`-like instant delivery, `i_min` 1 s, `i_max` 16 s, 600 s of
virtual time, 40 sets of MACs (which varies Trickle jitter). "Routed" means
following `next_hop` from each end reaches the other over links that exist, at
every 10 ms sample from 120 s to 600 s. The one-way link delivers only
`hq -> field`.

| variant | symmetric chain | with one-way link |
|---|---|---|
| `main` | 40/40 | 0/40 |
| filter only, today's relay rule | 40/40 | 0/40 |
| filter + design 29 relay rule, no echo | 0/40 | 0/40 |
| filter + design 29 relay rule + echo | 40/40 | 40/40 |

**Why the filter alone fails** (read from the code and design 29 §2; the
prototype only counted the outcome). `field` hears `hq` directly and, under
today's relay rule, re-floods that copy with the direct path's TQ and
`PrevSender = hq`, although the filter stops `field` itself using that path.
`r3` has verified `field`, prefers this offer, and routes to `hq` through
`field`. `r3`'s own re-floods then carry `PrevSender = field`, which `field`
drops (Rule 1b), so `field` never gets a path through `r3` and has no route to
`hq` at all.

So this design needs a relay never to advertise a path it would not use. If
design 29 were rejected, its replacement would have to do that: withhold the
re-flood when `next_hop` is `None`, and otherwise stamp and clamp from the
selected path, not from the copy just heard.

Cold start to a two-way route: median 810 ms, max 1000 ms on `main`; median
1520 ms, max 1810 ms with the full design. Frames sent from 120 s were the same
(999 and 998-999 per seed).

The prototype differs from §3: the echo was a flagged OGM, not `OgmEcho`; a
verification expired after a fixed 60 s, not by a ring of sixteen; one interface only;
and no echo for duplicates or gated links. The sim in #136 was not re-run.

**Test cost.** With the prototype enabled, 59 of 233 `batman` library tests
failed, from a count only. Many tests feed one engine OGMs and expect a route,
so the likely fix is a helper that also feeds the echo. `libs/wayfinder` and
the bench fixtures were not tried.

## 6. Observability

`CentralRouter` gains a current count of neighbours that are heard but verified
on no interface: a one-way link, seen from the receiving end. It is derived from
the table selection reads. The management API and TUI half is #143.

## 7. Alternatives

- **Require an authenticated mesh.** It works today, but open mode is supported
  and silently loses all traffic here.
- **BATMAN IV's echo-ratio TQ.** Measures how asymmetric a link is, but changes
  the metric for every path and needs per-neighbour windows in both directions.
- **A neighbour list in each OGM.** Grows every OGM by 6 bytes per neighbour on
  the links that can least afford it.
- **Next-hop challenges without keys.** A new periodic exchange per neighbour,
  where the echo is already on the air in the common case.
- **Match on `PrevSender` instead of TTL.** Wrong under design 29 (§3.1).
- **Send `OgmEcho` for every direct OGM.** Simpler, and adds one frame per
  neighbour per OGM.
- **An off-by-default setting.** Leaves the black hole in place for anyone who
  does not know to set it. Recommended: on, with no setting.

## 8. Implementation notes

Order: design 29, then the evidence table and filter with `OgmEcho` in one PR.
The filter without the echo never converges.

Tests, each failing first:

- two engines on a one-way link never select it, and a two-way pair does;
- a cold chain converges (guards the deadlock);
- an echo of an interface-0 seqno does not verify interface 1;
- verification lapses after `MAX_MISSED_ECHOES` unechoed emissions;
- an echo goes out on every `tx_ogm` interface, not only the ingress one;
- evicting and re-learning an originator keeps its neighbour verified;
- a full evidence table replaces only a lapsed entry;
- a `tx_ogm`-off interface exempts, and turning the gate on ends that;
- each row of the §3.3 table produces one `OgmEcho`;
- an authenticated engine sends none and ignores any received.

The TTL check names the emitted TTL as a constant (`EMIT_TTL`) and compares with
`EMIT_TTL - 1`, in code and tests. The delivery measurement in §4 is part of the
implementation PR.

Files: `libs/batman/src/engine.rs` (`handle_ogm`, `select_path`,
`on_interface_emitted`), `libs/batman/src/wire.rs`, `libs/wayfinder/src/lib.rs`
(ingress gates, `link_may_tx`, egress choice), `libs/wayfinder-shark`.
