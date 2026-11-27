# Design: a relay advertises the path it would use

**Status:** Proposed. Fixes #120. Not implemented; the measurements below come
from a throwaway prototype that is not on any branch.

**Scope:** the OGM re-flood in `libs/batman` (`BatmanEngine::handle_ogm`), plus
the documentation of TVLV `PrevSender` (0x84) in `libs/batman/src/wire.rs`. No
layout, type or version number changes. No new state. No change to path
learning, next-hop selection, next-hop proof or Trickle.

## 1. Motivation

A node re-floods the first copy of each new OGM sequence number. The re-flood
describes the path **that copy arrived on**: its TQ, and `PrevSender` set to the
neighbour it came from. It does not describe the path the node would forward
on. The two differ when the copy came from a neighbour the node will not
select, which on an authenticated mesh means any neighbour without a current
next-hop proof (design 09 §4). Design 09 gates *selection* on that proof and
says nothing about re-flooding.

In the chain `hq - r1 - r2 - r3 - field`, where `field` also hears `hq`
directly but `hq` cannot hear `field`:

1. `field`'s proof of `hq` can never complete, so `field` forwards through `r3`.
2. `hq` stamps a separate sequence number on each interface's OGM. The number
   sent on the direct path never travels down the chain, so the direct copy is
   `field`'s first sight of it, and `field` re-floods it.
3. The re-flood says TQ 245 and `PrevSender = hq`. `field`'s real path is TQ 215
   through `r3`.
4. `r3` does not recognise itself in `PrevSender`, and 235 beats its TQ 225
   through `r2`. It selects `field`.
5. `field -> r3 -> field`, until TTL runs out, for every packet.

#120 reached this with two keyless radios repeating frames about 1 s late. The
wiretap there shows the same re-flood (`tq=245`, `prev=hq`, first at t=45.97 s).
**No attacker is needed**: one one-way link does it.

Measured in the sim on `main` at `ea96355b` (`PerfectWire`, default Trickle,
stream `field -> hq` at 10 packets/s over 120-180 s, seeds 0-4):

| mesh | extra one-way link `hq -> field` | delivery | `(field, r3)` next hop |
|---|---|---|---|
| authenticated | no | 1.00 | `(r3, r2)` |
| authenticated | **yes** | **0.00** | `(r3, field)`: loop |
| open | no | 1.00 | `(r3, r2)` |
| open | yes | 0.00 | `(hq, field)`: see §3 |

The one-way link is a `Channel` that delivers only what `hq` transmits:

```python
@dataclasses.dataclass(frozen=True)
class OneWay:
    src_pos: Vec3
    def evaluate(self, tx, rx, t_s, rng):
        s = PerfectWire().evaluate(tx, rx, t_s, rng)
        return dataclasses.replace(s, delivery_probability=float(tx == self.src_pos))
```

Radio links with unequal transmit power or a noisy receiver at one end are
one-way in this sense. That such a link occurs on this project's radios is an
inference; none has been measured.

## 2. Design

At the re-flood, ask `next_hop(now, orig)`, the function forwarding itself
uses. Call the answer `via`.

| field of the re-flood | today | proposed, `via` is `Some` | `via` is `None` |
|---|---|---|---|
| `PrevSender` | `frame.src` | `via` | `frame.src` |
| `tq` | `computed_tq` | `min(computed_tq, effective_tq of the via path)` | `computed_tq` |

Which copies are re-flooded, and when, does not change. In the common case the
first copy comes from the selected next hop, so `via == frame.src` and, unless
that neighbour has missed its keep-alive budget, the frame is byte-for-byte what
is sent today.

**The clamp is `effective_tq`, not `last_tq`.** `next_hop` ranks paths by
`effective_tq`, which is zero for a neighbour that has missed its keep-alive
budget. When every proven, unexpired path has missed it, `next_hop` still
returns one of them. Its `last_tq` would advertise a better path than the one
the relay ranks it as.

**A resulting `tq = 0` is sent, not suppressed.** This holds for
`via == frame.src` too.

- A receiver that hears it stores 0 for the path through this relay, so any
  alternative with a non-zero TQ wins at once. Suppression would leave the old,
  higher TQ in place until the path aged out.
- A receiver with no alternative keeps the route, as the relay itself does.
  A missed keep-alive deprioritises a path and does not evict it; suppression
  would let it expire downstream.
- Suppression would also withhold the rest of the originator's OGM, such as its
  multicast groups, from every node behind the relay.

`tq = 0` needs no special case: attenuation already saturates to it, and the
receive path treats it as any other value.

`PrevSender` then means "the neighbour the forwarder's path to `orig` runs
through", which is what Rule 1b (drop an OGM that names me) was reaching for:
its comment already notes that naming the copy's sender "does not prove the
sender's *route* to `orig` runs through us".

## 3. Goals and non-goals

Goal: a relay that has a usable route (`via` is `Some`) never offers a neighbour
a better path than that route, and never hides from a neighbour that the route
runs back through it.

Not covered:

- **Open meshes with a one-way link.** With no proof there is no bidirectional
  check, so `field` selects the direct path and black-holes. The prototype does
  not change this (0.00 before and after). It needs a link-symmetry term in the
  metric, which is a separate design.
- **Loops of three or more nodes.** One `PrevSender` names one hop.
- **The wormhole itself** (#121). Below about 800 ms the tunnelled neighbour
  passes the proof and is a genuine selection.

## 4. Correctness and edge cases

- **Two-node loop.** If B's next hop to `orig` is A, every re-flood B sends
  names A, so A learns no path through B from it. A switch of B's next hop is
  covered from B's next re-flood; until then A may hold a path learned earlier,
  which ages out as it does today.
- **The copy's sender X is no longer named when `via` is Y.** X may now learn a
  path through this node. That path is real (it runs through Y), and its TQ is
  at most one hop below what X itself advertised. If Y's path runs through X,
  that is a loop of three or more, listed above.
- **A stub neighbour.** Its only path is the copy's sender, so `via ==
  frame.src` and today's echo drop is unchanged.
- **No usable route (`via` is `None`).** Today's behaviour is kept, so a cold
  mesh still floods before the first proof completes. A neighbour can then learn
  a path through a node that will drop data for want of a proven hop. That is a
  temporary black hole, not a loop.
- **Hysteresis (#117).** The reported `best_next_hop` and `next_hop` can differ.
  This uses `next_hop`, so it stays correct however #117 is resolved.
- **Cost.** One extra scan of at most four paths per re-flood. No RAM.

## 5. Mixed versions

Same bytes, same layout. An old receiver drops a re-flood that names it, which
is right for either meaning. An old relay keeps stamping `frame.src` and keeps
today's behaviour, including this bug; the fix takes effect relay by relay. In
the scenario above, upgrading `field` is enough. Boards that cannot be upgraded
with the hosts keep interoperating.

`PrevSender` is cooperative and unsigned, as before. It is not a defence
against an insider.

## 6. Prototype results

Same setup as §1. The prototype clamped with `last_tq`, not `effective_tq`. The
two are equal unless a keep-alive has been missed, and no keep-alives are
configured in these runs, but the `effective_tq` form itself has not been run.

- One-way link, authenticated: delivery 0.00 -> 1.00 (seeds 0-1).
- Either half alone (only the TQ clamp, or only the stamp) also gives 1.00 here
  and in #120's scenario at 1000 ms. Both are proposed: the stamp protects the
  next hop itself, and the clamp stops an inflated TQ reaching every other
  neighbour.
- `cargo test -p batman -p wayfinder-test`: 231 and 90 passed, none changed.
- #120's wormhole at other latencies (seeds 0-1, stream 120-180 s):

| latency (ms) | `main` | prototype |
|---|---|---|
| 500 | 1.00, through the tunnel | 1.00, through the tunnel |
| 800 | **1.00**, through the tunnel | **0.90, 0.91** |
| 1000, 1200, 1500 | 0.00, loop | 1.00 |
| 2000 | 1.00 | 1.00 |

The 800 ms row is worse. At that latency the proof through the tunnel sits at
the edge of succeeding. Why delivery falls there has not been traced (§9).

Not measured: the other prototype seeds, convergence time, OGM airtime, the
red-team battery and the benchmarks.

## 7. Observability

None proposed. The loop was visible in `GetRoutingTable` only by reading two
nodes at once; this removes the cause. A counter of re-floods where `via !=
frame.src` would be cheap if an operator wants to find one-way links, but a
node cannot tell one from an ordinary second path.

## 8. Alternatives considered

- **Do not re-flood copies from unproven neighbours.** The unproven copy has
  already advanced the high-water, so a later proven copy of the same number is
  not re-flooded either: whoever delivers first suppresses the flood. Fixing
  that needs a second per-originator sequence field.
- **Re-flood only copies from the selected next hop** (batman-adv's rule). Also
  needs that second field, and during failover the relay stays silent until it
  switches, while its downstream neighbours age the route out.
- **A second `PrevSender` record naming `via`.** Keeps X protected as today, at
  10 more bytes on every such OGM, and old receivers read only the first.
- **Per-originator instead of per-interface sequence numbers.** Would remove the
  trigger in §1 step 2 but not the cause: a lost or delayed chain copy reaches
  the same state.

## 9. Acceptance bar and open decision

The change affects every re-flood, on open and authenticated meshes, whose first
copy did not come from the best path. That is common wherever paths are
redundant, and §1 and §6 cover only one chain. The implementing PR merges only
when all of these hold, with the numbers in its description. "`main`" means the
commit the PR branches from, measured in the same way.

1. **§1 and §6, seeds 0-4**, both columns of the latency table:
   - authenticated, with and without the one-way link: delivery 1.00;
   - open: 1.00 without the link. With it, 0.00 is expected (§3);
   - latencies 500, 1000, 1200, 1500 and 2000 ms: delivery 1.00;
   - latency 800 ms: item 3.
2. **Red team:** `sim/tests/test_red_team.py` passes with no new `GAP`. The
   baseline is not all clear today: `attack_wormhole_blackhole` is a recorded
   `GAP` (#121). If its verdict flips, the PR says why and updates the baseline.
3. **800 ms:** the cause of the lower delivery is traced. It is either fixed
   (no seed below `main`) or explained in this document, and accepting a
   remaining loss is Ben's decision.
4. **Convergence on redundant meshes** (both scenarios are open meshes), median over seeds 0-4 no higher than on
   `main`: `converged_s` from `sim/scenarios/scale.py` `run_size(49)`, and
   `recovered_s` and `rejoin_s` from `sim/scenarios/failover.py`
   `run_failover`, both without keep-alives and with `keepalive_ms=250`. A run
   that never converges or recovers fails the bar.

Open for the implementing session: whether `via == None` on an authenticated
mesh should suppress the re-flood once any neighbour has been proven.

## 10. Key file map

- `libs/batman/src/engine.rs`: `handle_ogm`, the `is_new_seqno && ogm.ttl > 1`
  block; Rule 1b's comment.
- `libs/batman/src/wire.rs`: `TvlvType::PrevSender`, `stamp_prev_sender` docs.
- Tests first: an engine test (proof required, selected next hop Y, newer
  sequence number from unproven X: the re-flood names Y and carries Y's TQ); a
  second where Y has missed its keep-alive budget and is still the only usable
  path (the re-flood is sent, names Y, and carries `tq = 0`); and
  a `wayfinder-test` scenario with a one-way link on an authenticated mesh.
  `TestSwitchConfig` has no one-way fabric yet.
