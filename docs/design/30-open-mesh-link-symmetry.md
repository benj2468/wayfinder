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
N hears this node, and send to N only on an interface where it does.

Not covered:

- **Lossy asymmetry.** The check is yes or no. A reverse direction that loses
  90% of frames passes if one in six gets through. TQ is unchanged.
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
`MAX_MISSED_ECHOES = 6` numbers sent on interface `k`, when it has changed
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
- On an interface with `tx_ogm` off, A sends nothing to be echoed. An OGM heard
  there from N marks N verified on it, which is today's behaviour. Those marks
  last as long as the path does.

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

`orig` and `seqno` are copied from the OGM. It is never relayed, and a receiver that is not `orig` ignores it. It
teaches no path, no sequence number and no membership.

"Not going to re-flood" covers:

| case | why there is no re-flood |
|---|---|
| no usable next hop toward `orig` | design 29 |
| a relayed copy of that seqno was flooded first | once per `(orig, seqno)` |
| the high-water refuses it (stale, or `orig` rebooted) | sequence number rules |
| ingress link has `tx_data` off | the router suppresses re-advertisement |
| ingress link has `rx_ogm` off | the engine never sees the OGM |

Each record keeps the last seqno echoed, so one direct copy is answered once.
With `rx_ogm` off there is no record, and each direct OGM gets one echo, which
is one frame out per frame in.

`OgmEcho` transmits under the `tx_ogm` gate, named in `link_may_tx`. An OGM
that takes the normal re-flood sends nothing extra.

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

**A link turning one-way** is dropped after six emissions on that interface
without an echo. At `i_max` that is up to `6 × i_max`, the same order as path
ageing today. Not measured.

**Loss.** Verification needs the OGM and its echo both delivered once in six
tries. At 50% loss each way, six misses in a row has probability
`0.75^6 = 0.18` per window, so such a link flaps. Today it is selected steadily
at a TQ that does not reflect the loss. The implementation PR measures delivery
over a 50% link before and after, and `MAX_MISSED_ECHOES` is the constant to
raise if it is worse.

**Configurations.** `tx_ogm: false` is handled in §3.2, `rx_ogm: false` and
`tx_data: false` in §3.3. With both OGM gates off no paths exist, as today.

**Reporting.** An unverified neighbour has paths but no `best_next_hop`, the
state an unproven one is in on an authenticated mesh.

**Footprint.** `echoed` is a sidecar table of at most `MAX_ORIGINATORS` entries
of `MAX_INTERFACES` sequence numbers, plus the rings. By arithmetic, not
measurement: about 5 KB at 128 originators and 8 interfaces, about 300 B at 16
and 2. The implementation PR reports `size_of::<CentralRouter>` per profile and
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

Cold start to a two-way route: median 810 ms, max 1000 ms on `main`; median
1520 ms, max 1810 ms with the full design. Frames sent from 120 s were the same
(999 and 998-999 per seed).

The prototype differs from §3: the echo was a flagged OGM, not `OgmEcho`; a
verification expired after a fixed 60 s, not by the ring; one interface only;
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
- verification lapses after six unechoed emissions;
- each row of the §3.3 table produces one `OgmEcho`;
- an authenticated engine sends none and ignores any received.

Files: `libs/batman/src/engine.rs` (`handle_ogm`, `select_path`,
`on_interface_emitted`), `libs/batman/src/wire.rs`, `libs/wayfinder/src/lib.rs`
(ingress gates, `link_may_tx`, egress choice), `libs/wayfinder-shark`.
