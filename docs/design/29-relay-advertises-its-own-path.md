# Design: a relay advertises the path it would use

**Status:** Proposed. Fixes #120. Not implemented; the measurements below come
from throwaway prototypes that are not on any branch.

**Scope:** the OGM re-flood in `libs/batman` (`BatmanEngine::handle_ogm`), plus
the documentation of TVLV `PrevSender` (0x84) in `libs/batman/src/wire.rs`. No
layout, type or version number changes. No new state. A relay with no usable
route stops re-flooding that originator. No change to path
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

| field of the re-flood | today | proposed |
|---|---|---|
| sent at all | always | **only if `via` is `Some`** |
| `PrevSender` | `frame.src` | `via` |
| `tq` | `computed_tq` | `min(computed_tq, effective_tq of the via path)` |

Which copy is considered for re-flooding does not change: the first copy of each
sequence number, while TTL remains. In the common case that copy comes from the
selected next hop, so `via == frame.src` and, unless that neighbour has missed
its keep-alive budget, the frame is byte-for-byte what is sent today. Everything
else the OGM does on receipt (path learning, memberships, Trickle) still
happens when the re-flood is withheld.

**No usable route, no re-flood.** On an authenticated mesh this is a node none
of whose paths to `orig` runs through a proven neighbour. Keeping today's
behaviour in that case (`PrevSender = frame.src`, `computed_tq`) does not work.
It lets two nodes settle into a stable black hole:

1. `field` has no path to `hq` through `r3`, so `via` is `None`. It re-floods
   the direct copy with TQ 245 and `PrevSender = hq`.
2. `r3` prefers that (235) to its path through `r2` (225) and selects `field`.
3. `r3` now stamps `PrevSender = field` on what it relays. `field` drops those
   (Rule 1b), so it never learns the path through `r3`, and `via` stays `None`.

Whether a cold mesh lands there depends on which of the two proofs completes
first. In the prototype it did so on 17 of 40 seeds (§6). With the re-flood
withheld, step 1 never happens.

The rule is not conditional on `require_proof`. On an open mesh the copy just
heard is itself a usable path, so `via` is `None` only if the originator's four
path slots are all stale and the sender could not be added.

**The clamp is `effective_tq`, not `last_tq`.** `next_hop` ranks paths by
`effective_tq`, which is zero for a neighbour that has missed its keep-alive
budget. When every proven, unexpired path has missed it, `next_hop` still
returns one of them. Its `last_tq` would advertise a better path than the one
the relay ranks it as.

**A resulting `tq = 0` is sent, not suppressed.** This holds for
`via == frame.src` too. It differs from the case above because the relay does
have a next hop and will forward on it.

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

Goal: a relay never offers a neighbour a path it does not have or a better one
than it has, and never hides from a neighbour that its route runs back through
it.

Not covered:

- **Open meshes with a one-way link.** With no proof there is no bidirectional
  check, so `field` selects the direct path and black-holes. The prototype does
  not change this (0.00 before and after). It needs a link-symmetry term in the
  metric, which is a separate design.
- **Loops of three or more nodes.** One `PrevSender` names one hop.
- **The wormhole itself** (#121). Below about 800 ms the tunnelled neighbour
  passes the proof and is a genuine selection.

## 4. Correctness and edge cases

- **Two-node loop.** If node Q's next hop to `orig` is P, every re-flood Q
  sends names P, so P learns no path through Q from it. A switch of Q's next hop
  is covered from Q's next re-flood; until then P may hold a path learned
  earlier, which ages out as it does today. §6 measures this after P loses its
  own upstream.
- **The copy's sender X is no longer named when `via` is Y.** X may now learn a
  path through this node. That path is real (it runs through Y), and its TQ is
  at most one hop below what X itself advertised. If Y's path runs through X,
  that is a loop of three or more, listed above.
- **A stub neighbour.** Its only path is the copy's sender, so `via ==
  frame.src` and today's echo drop is unchanged.
- **Cold start.** A relay withholds an originator until it has proven a
  neighbour on a path to it, so the first flood stops early and a later one
  carries further. This cannot deadlock: a proof involves only direct
  neighbours, which are learned from their own OGMs, and originating is not
  re-flooding. The cost is measured in §6.
- **Revocations and other TVLVs** carried on a withheld copy do not pass this
  relay until it has a route. A node still processes them on receipt.
- **Path slots.** A record holds four paths. If four unproven neighbours fill
  them, `via` is `None` and stays so. The node cannot forward to `orig` in that
  state today either; it now also stops advertising it. The slot policy is not
  changed here.
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

Authenticated meshes unless stated. **A** keeps today's behaviour when `via` is
`None` (an earlier draft of this design). **B** is the design in §2. **C**
withholds only once the node has proven at least one neighbour (§8). All three
use the `effective_tq` clamp.

One-way link of §1, seeds 0-39, delivery over 120-180 s:

| | `main` | A | B | C |
|---|---|---|---|---|
| without the link | 1.00 | 1.00 | 1.00 | 1.00 |
| with the link | 0.00 on all | 0.00 on 17 seeds | 1.00 | 1.00 |

In A's failing seeds `field` has no next hop to `hq` and `r3` points at
`field`, the state of §2. The open mesh with the link stays at 0.00 under all
of them (§3).

#120's wormhole (the tunnel carries all frames), seeds 0-4:

| latency (ms) | `main` | B |
|---|---|---|
| 500 | 1.00 | 1.00 |
| 800 | **1.00** | **0.90-0.91** |
| 1000, 1200, 1500 | 0.00, loop | 1.00 |
| 2000 | 1.00 | 1.00 |

The 800 ms row is worse. At that latency the proof through the tunnel sits at
the edge of succeeding. Why delivery falls there has not been traced (§9).

Cold start, seconds until the routes exist (median; chains over seeds 0-19,
grid over seeds 0-4):

| mesh | `main` | B | C |
|---|---|---|---|
| chain of 5, end to end | 0.4 | 0.7 | 0.6 |
| chain of 9, end to end | 0.5 | 0.9 | 0.7 |
| 3x4 grid, all pairs | 0.4 | 0.5 | 0.5 |

Failover on the grid of `sim/scenarios/failover.py`, made authenticated, seeds
0-19, `recovered_s` mean / max:

| | `main` | A | B | C |
|---|---|---|---|---|
| no keep-alives | 2.85 / 5.3 | 4.25 / 5.2 | 3.54 / 5.2 | 3.57 / 5.2 |
| `keepalive_ms=250` | 0.54 / 0.8 | 0.44 / 0.8 | 0.46 / 0.9 | 0.48 / 0.8 |

**Without keep-alives the mean is worse.** Recovery is bimodal (about 0.4 s, or
about 5 s when it waits for the dead path to age out), and the slow mode is more
common. A shows it too, so it comes from the stamp and clamp rather than from
withholding. The likely reason is that fewer alternate paths are learned before
the failure; this has not been traced. The worst case is no higher. `rejoin_s`
is bimodal on `main` as well (0.35 s or 3.1 s) and showed no clear difference.

Losing an upstream, authenticated, seeds 0-9, `main` at `ea96355b`. A link is
cut at 60 s and the following 40 s are watched. A *bounced* frame is a stream packet the neighbour
`P` sends back to the relay that was forwarding through it. Two meshes:

- **chain:** the §1 chain, `r1 - r2` cut, so `(relay, P) = (field, r3)`. It is
  run without and with the one-way link. Without that link the chain has no
  second path, so no relay can hear a copy from anyone but its next hop, and the
  rules cannot differ.
- **redundant:** two-way links only, `hq - a - y - r - field` plus
  `hq - b1 - b2 - x - r`. `r` forwards through `y`; `a - y` is cut, so
  `(relay, P) = (r, y)`. `hq` has two interfaces here, so every sequence number
  from the `x` side reaches `r` first from `x`.

| measurement (median; max in brackets) | `main` | B | D (§8) |
|---|---|---|---|
| chain: bounced frames | 0 | 0 | 0 |
| chain + one-way: bounced frames | 3260 (3512), permanent loop | 0 | 13 (13) |
| chain + one-way: `r3` names `field` for (s) | the whole 40 | never | 20.1 (22.6) |
| redundant: seeds with bounced frames | 10 of 10 | **0 of 10** | 10 of 10 |
| redundant: bounced frames | 816 (1536) | 0 | 924 (1104) |
| redundant: `r` and `y` name each other for (s) | 4.1 (6.8) | 0 (0.15) | 4.4 (5.2) |
| redundant: delivery over the 38 s of traffic | 0.79 | 0.81 | 0.78 |
| redundant: delivery restored after (s) | 7.9 (10.8) | 7.1 (11.3) | 8.3 (9.1) |

On the chain, delivery after the cut is zero under every rule, because the cut
partitions it. The redundant row is a loop `main` has today: `r` re-floods the
`x`-side copies naming `x`, so `y` records a path back through `r`, and falls
back to it while `r` still points at `y`. B removes it. The median restore time
improves by under a second and the worst seed is 0.5 s slower than on `main`, so
the gain to claim is the loop, not the outage length.

Tests: under B, `sim/tests/test_red_team.py` and `test_wormhole.py` pass
unchanged (64 tests). Of 742 `batman`, `wayfinder` and `wayfinder-test` tests,
736 pass, including the lazy-certificate-distribution ones. The six failures
assume the old behaviour:

- five engine tests about sequence numbers assert a re-flood on an engine that
  requires proof and has proven nobody. Their fixture needs a proven neighbour;
- `test_revocation_floods_and_shuns_node` expects an authenticated line of three
  to converge in one OGM round. It needs a second.

Not measured: lazy distribution in the sim and the benchmarks.

### Over-the-air cost

**B sends more on redundant meshes.** The frame layout and size do not change,
and each node still re-floods an OGM at most once. What rises is how often
nodes originate: re-floods per originated OGM are the same as on `main` (11.0
on the 3x4 grid, about 48 on the 7x7).

Measured on `main` at `d86abd6f`. The grids are those of `failover.py` (3x4,
200/2000 ms Trickle, seeds 0-9) and `scale.py` (7x7, 1/10 s, seeds 0-2), with
no data traffic. Figures are everything the nodes transmit, per node per second,
as frames / frame bytes (no PHY overhead).

Long steady window (3x4: 60-600 s; 7x7: 60-300 s):

| mesh | `main` | B |
|---|---|---|
| 3x4 open | 7.91 / 326 | 8.08 / 333 (+2%) |
| 3x4 authenticated | 12.48 / 2379 | 12.71 / 2439 (+3%) |
| 7x7 open | 6.64 / 277 | 7.29 / 305 (+10%) |
| 7x7 authenticated | 7.83 / 1851 | 8.70 / 2086 (+13%) |

B, change in bytes against `main` around start-up and a failure (3x4: seeds
0-9; 7x7: seeds 0-2; one relay off at 60 s, back at 120 s):

| mesh | 0-20 s | 20-60 s | 60-180 s |
|---|---|---|---|
| 3x4 open | +24% | +5% | +12% |
| 3x4 authenticated | +19% | +4% | +7% |
| 7x7 open | +43% | +28% | +12% |
| 7x7 authenticated | +49% | +41% | +18% |

**What resets Trickle.** On the 7x7 grids, 60-300 s, seeds 0-2, every reset
latch in that window came from `purge_stale` dropping a single path while the
originator stayed routable. None came from a new or evicted originator.

| 7x7, latches across 49 nodes, per seed | `main` | B |
|---|---|---|
| open | 29, 19, 16 | 96, 87, 90 |
| authenticated | 19, 33, 17 | 97, 102, 105 |

The likely mechanism, inferred rather than traced: B no longer names the copy's
sender, so that neighbour sometimes records a path through the relay, is not
refreshed on it, and later prunes it. Whether pruning an alternate path should
reset Trickle at all is a separate question (#145); this design does not
change it.

Where the loop of §1 exists, B saves far more than it costs. On the
authenticated one-way chain, with `field -> hq` at 10 packets/s, each node
sends 110.7 frames / 8444 bytes per second on `main` (and delivers nothing),
against 18.1 / 2648 under B (delivering everything).

## 7. Observability

None proposed. A withheld originator already shows as one with no best next hop
in `GetRoutingTable`. The loop was visible in `GetRoutingTable` only by reading two
nodes at once; this removes the cause. A counter of re-floods where `via !=
frame.src` would be cheap if an operator wants to find one-way links, but a
node cannot tell one from an ordinary second path.

## 8. Alternatives considered

- **Keep today's re-flood when `via` is `None`.** The stable black hole of §2.
- **Withhold only once some neighbour is proven** (C). It also fixes the one-way
  case and saves 0.1-0.2 s of cold start, and five fewer existing tests change.
  Rejected: it adds a node-wide condition, and until the first proof the node
  still advertises routes it will not forward on.
- **Do not re-flood copies from unproven neighbours.** Unlike §2, this tests the
  copy's sender even when the node has a proven path. The unproven copy has
  already advanced the high-water, so a later proven copy of the same number is
  not re-flooded either: whoever delivers first suppresses the flood. Fixing
  that needs a second per-originator sequence field.
- **Re-flood only copies from the selected next hop** (batman-adv's rule). Also
  needs that second field, and during failover the relay stays silent until it
  switches, while its downstream neighbours age the route out.
- **D: keep `PrevSender = frame.src`; add only the withholding and the clamp.**
  Rejected: the `via` neighbour is not told that the relay's route runs through
  it, so it records a path back and falls back to it when its own upstream dies.
  On the redundant mesh of §6 that loops on 10 of 10 seeds, as `main` does.
  D is cheaper and avoids B's 800 ms loss:

  | authenticated | `main` | B | D |
  |---|---|---|---|
  | §1 one-way link, seeds 0-39, lowest delivery | 0.00 | 1.00 | 1.00 |
  | wormhole 500 ms and 2000 ms, seeds 0-4 | 1.00 | 1.00 | 1.00 |
  | wormhole 800 ms | 1.00 | 0.90-0.91 | 1.00 |
  | wormhole 1000-1500 ms | 0.00 | 1.00 | 1.00 |
  | failover, no keep-alives, mean / max (s) | 2.85 / 5.3 | 3.54 / 5.2 | 3.57 / 5.2 |
  | failover, `keepalive_ms=250`, mean / max (s) | 0.54 / 0.8 | 0.51 / 0.7 | 0.49 / 0.8 |
  | steady airtime, 7x7 open, bytes | 277 | 305 | 277 |
  | steady airtime, 7x7 authenticated, bytes | 1851 | 2086 | 1960 |

  (The `keepalive_ms=250` B figure is from the later of two prototype runs; the
  first, in §6, gave 0.46 / 0.9.) The red-team and wormhole suites pass under D,
  with the same six old tests failing as under B. Cold start and the start-up
  airtime windows were not measured for D.
- **Name `via` only when `frame.src` is unproven.** Measured the same as D on
  the one-way link, the wormhole latencies and the authenticated grids. It adds
  a condition for no measured gain over D.
- **A second `PrevSender` record naming `via`.** Keeps X protected as today, at
  10 more bytes on every such OGM, and old receivers read only the first.
- **Per-originator instead of per-interface sequence numbers.** Would remove the
  trigger in §1 step 2 but not the cause: a lost or delayed chain copy reaches
  the same state.

## 9. Acceptance bar

The change affects every re-flood, on open and authenticated meshes, whose first
copy did not come from the best path. That is common wherever paths are
redundant. The implementing PR merges only when all of these hold, with the
numbers in its description. "`main`" means the commit the PR branches from,
measured in the same way.

1. **§1 and §6:**
   - authenticated, with and without the one-way link, seeds 0-39: delivery
     1.00 (seeds 0-4 do not catch A's failure reliably);
   - open, seeds 0-4: 1.00 without the link. With it, 0.00 is expected (§3);
   - latencies 500, 1000, 1200, 1500 and 2000 ms, seeds 0-4: delivery 1.00;
   - latency 800 ms: item 3.
2. **Red team:** `sim/tests/test_red_team.py` passes with no new `GAP`. The
   baseline is not all clear today: `attack_wormhole_blackhole` is a recorded
   `GAP` (#121). If its verdict flips, the PR says why and updates the baseline.
3. **800 ms:** the cause of the lower delivery is traced. It is either fixed
   (no seed below `main`) or explained in this document, and accepting a
   remaining loss is Ben's decision.
4. **Convergence on open redundant meshes**, median over seeds 0-4 no higher
   than on `main`: `converged_s` from `sim/scenarios/scale.py` `run_size(49)`,
   and `recovered_s` and `rejoin_s` from `sim/scenarios/failover.py`
   `run_failover`, both without keep-alives and with `keepalive_ms=250`. A run
   that never converges or recovers fails the bar.
5. **Authenticated redundant mesh** (the grid of §6, seeds 0-19): every run
   recovers, and with and without keep-alives the worst `recovered_s` is no
   more than 0.2 s above `main`'s. The PR reports the mean and the cold-start
   table beside `main`'s.
6. **Airtime**, the long steady windows of §6: no row's frames or bytes exceed
   B's column by more than 2% of `main`'s.
7. **Lost upstream**, the redundant mesh of §6, seeds 0-9: no bounced frames.

Accepting this design accepts the costs measured in §6: a few hundred
milliseconds of cold start, and a slower *mean* failover on an authenticated
mesh without keep-alives (3.5 s against 2.9 s; the worst case is no higher),
and the airtime of §6 (up to 13% more bytes in steady state, up to 49% around
start-up). The recommendation is to accept all three: they are bounded, and what
they buy is a mesh that a single one-way link otherwise cuts permanently, and no
fallback loop after a lost upstream. The alternative is to hold the design until
the failover cost is traced.

## 10. Decision for Ben

**Accept B, the design of §2?** Recommended: yes. Its price is the three costs
at the end of §9 and the 800 ms loss, which item 3 brings back to you once
traced.

The one real alternative is D (§8). It costs less airtime (nothing extra on an
open mesh) and has no 800 ms loss, but keeps the two-node fallback loop of §6.
An earlier revision recommended D because no measurement had shown that loop.
The redundant mesh of §6 now does.

## 11. Key file map

- `libs/batman/src/engine.rs`: `handle_ogm`, the `is_new_seqno && ogm.ttl > 1`
  block; Rule 1b's comment.
- `libs/batman/src/wire.rs`: `TvlvType::PrevSender`, `stamp_prev_sender` docs.
- Tests first, three engine tests on an engine that requires proof:
  - next hop Y, a newer sequence number from unproven X: the re-flood names Y
    and carries Y's TQ;
  - no proven path: nothing is sent;
  - Y has missed its keep-alive budget and is the only usable path: the re-flood
    is sent, names Y and carries `tq = 0`.
- Then a `wayfinder-test` scenario with a one-way link on an authenticated mesh.
  `TestSwitchConfig` has no one-way fabric yet.
- And one for the lost upstream of §6: after `y` loses `a`, `y` never names `r`
  while `r` names `y`.
