# Design: Peered unicast for `libs/blue`

**Status:** Proposed, and **deliberately not recommended for implementation
yet** — §9 records the specific conditions that would change that. Written to
settle whether `libs/blue` should stop being 100% broadcast and open BLE
connections to discovered peers for directed traffic, so the question isn't
re-derived from scratch later. The conclusion is that most of the benefit
motivating it is bought far more cheaply by design 07 (extended advertising),
and that the remaining benefit is gated on nRF-side blockers that are real,
structural, and shared with [design-in-memory] management-API-over-BLE work.

**Scope if built:** `libs/blue` (`src/generic_link.rs`, `src/nrf_link.rs`,
`src/std_link.rs`, plus a new peer/connection module and a new connectable
advertising role), `libs/blue/Cargo.toml` (`bluer`'s `l2cap` feature,
`nrf-softdevice`'s `ble-l2cap`), and `bins/wayfinder-nrf52840`'s SoftDevice
config and `memory.x`. **No change to `LinkT`** — see §3.1, which is the one
genuinely reassuring part of this design. No change to `libs/batman`,
`wayfinder-driver-core`, or the routing metric's *code* — but see §4.3 for a
change to what that metric *means*, which is this design's most serious
consequence and is not fixable inside `libs/blue`.

## 1. Motivation

Every frame `libs/blue` puts on the air is a non-connectable broadcast
advertisement, regardless of whether it is an OGM bound for every neighbor or
a unicast data frame bound for exactly one. That is the correct default —
`LinkT` is a fire-and-forget trait and the other radios here behave the same
way ([[feedback-minimal-link-abstraction]]) — but on BLE specifically it is
leaving a lot on the table for the directed half of the traffic.

The router already knows which half a frame is in. `wayfinder_driver_core::
Egress::Auto` resolves a unicast to a single interface via
`get_egress_interface`, and the frame reaches `LinkT::send` as a
`LinkFrameData` whose `dst` is a concrete next-hop neighbor `Mac`, not
`Mac::BROADCAST`. So a BLE link is handed, on every send, exactly the
information it would need to route the frame down a per-peer channel instead
of onto the air. It just has nowhere to put it.

What a connection would buy, against what broadcast advertising gives today:

| | advertising (today) | L2CAP CoC connection |
|---|---|---|
| delivery | unacknowledged, no retransmit | LL ACK + retransmit |
| goodput | ~19 B per 150 ms dwell ≈ **127 B/s** (BlueZ) | tens of KB/s at a 7.5–30 ms connection interval on 1M PHY |
| per-frame latency | `dwell × fragment_count` (up to 2.1 s) | one or two connection intervals |
| fragmentation | this crate's, capped at `MAX_FRAGMENTS = 15` | L2CAP CoC's own SDU segmentation; `MAX_REASSEMBLED_LEN` stops binding |
| receivers woken | every peer in range | one |

The reliability line is the one that matters most, because it compounds. A
frame arrives only if *every* fragment does, so whole-frame success is
roughly `p^n` for `n` fragments at per-fragment success `p`. At an assumed
`p = 0.9`, a 14-fragment full-cert OGM completes **23%** of the time. That is
not a latency problem, it is a "this link does not work for large frames"
problem, and it is the strongest argument for wanting something better than
broadcast.

## 2. Goals / Non-goals

**Goals** (of the mechanism, if built)
- Carry a frame whose `dst` is a specific neighbor over a per-peer BLE
  connection when one exists, falling back to today's broadcast advertising
  when it doesn't — so a peering failure degrades to current behavior rather
  than to a black hole.
- Keep OGMs and every other `Mac::BROADCAST` frame on advertising. A
  connection is inherently one-to-one; a flood over N connections is N
  transmissions of the same bytes, strictly worse than one advertisement.
- Discover and connect to peers automatically from what the mesh already
  observes, with no operator-supplied peer list.
- Preserve the `LinkT` surface exactly (§3.1).

**Non-goals**
- **Not replacing advertising.** Broadcast remains the substrate: it carries
  OGMs, it carries everything before a connection is up, and it is the
  fallback whenever one drops.
- **Not adding ACK/retry/TX-metric surface to `LinkT`.**
  [[feedback-minimal-link-abstraction]] is explicit that the shared trait
  stays fire-and-forget and that protocol-specific transmit feedback does not
  belong in it. A connection's link-layer reliability is an internal
  property of this one link, invisible to the trait.
- **Not BLE pairing/bonding.** That is a second, weaker trust model beside
  the mesh identity one — the same call the management-API-over-BLE analysis
  made. Mesh membership is established by `wayfinder-auth`, and a peered
  connection carries the same authenticated frames the air does; it is a
  faster pipe, not a trust boundary (§6).
- **Not a mesh-wide topology change.** Peering is per-radio-neighborhood and
  opportunistic. Nothing about the routing engine learns that two nodes are
  peered.

## 3. Design

### 3.1 The `LinkT` surface does not change

`send(&mut self, origin: Mac, data: &LinkFrameData<'_>)` already carries
everything needed:

```rust
async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
    if data.dst != Mac::BROADCAST
        && let Some(peer) = self.peers.connected_mut(data.dst)
    {
        return peer.send_frame(origin, data).await;   // no fragmentation at all
    }
    self.advertise_fragments(origin, data).await      // today's path, unchanged
}
```

This is the part of the design that holds up cleanly. The transport choice is
private to the link, the router never learns a peer is connected, and a
connection that is missing, saturated, or torn down simply isn't found in the
table and the frame goes out the existing path. There is no new trait method
and no new `Result` variant.

Everything difficult in this document is behind `self.peers`.

### 3.2 Peer discovery needs a second, connectable advertising role

**You cannot connect to what you cannot address, and today's advertisements
are not addressable.** `libs/blue/CLAUDE.md` records the `btmon` finding that
BlueZ draws a fresh random address on *every* advertising-set registration —
which is why `frame::ORIGIN_LEN` embeds the sender's `Mac` in each fragment
and reassembly stopped trusting the medium's address at all. That fix made
reassembly correct; it also means the address in a scan report is a
per-fragment ephemeron with no connectable peer behind it.

So peering needs something the current design deliberately does not have: a
**peering beacon** — a separate, long-lived, *connectable* advertising set
carrying the node's mesh `Mac` under an address stable enough to be the
target of a connection request. A peer's flow is then: see the beacon, read
the `Mac` out of it, decide whether to connect (§3.4), connect to the address
the beacon arrived under, open an L2CAP CoC channel on a fixed LE PSM, and
record `Mac → channel` in the peer table.

That beacon is new on-air surface with its own format, its own interval, and
its own security story (§6) — this design's largest single addition, and it
exists purely to undo the addressing property the crate currently relies on.

### 3.3 Two backends, two very different difficulties

**BlueZ host (`std_link.rs`) — tractable.** `bluer` supports multiple
advertising instances (`Adapter::supported_advertising_instances`), so the
peering beacon coexists with mesh-fragment advertising without contention.
`bluer`'s `l2cap` feature (not currently enabled in `libs/blue/Cargo.toml`,
which takes only `bluetoothd`) provides `Socket`/`Stream`/`StreamListener`
over LE PSMs in the `PSM_LE_DYN_START..=PSM_LE_MAX` (`0x80..=0xff`) range,
with `Stream` implementing tokio `AsyncRead`/`AsyncWrite`. This is the same
API the management-API-over-BLE analysis already costed out and found
straightforward.

**nRF52840 (`nrf_link.rs`) — structurally blocked, three ways.** Each of
these was verified against the pinned `nrf-softdevice` rev (`b0ac850`) and
its `s140` bindings, not assumed:

1. **There is exactly one advertising set.**
   `BLE_GAP_ADV_SET_COUNT_MAX = 1`. Mesh-fragment broadcast advertising and
   a connectable peering beacon cannot both be live; the beacon has to
   time-slice the single set with every mesh `send`. Worse,
   `nrf-softdevice` holds one global `ADV_HANDLE` and one `ADV_PORTAL`
   (`ble/peripheral.rs`), and `Portal::wait_once` **panics** with
   `"Multiple tasks waiting on same portal"` (`util/portal.rs:172`) if two
   tasks advertise concurrently. So this is not a degradation, it is a
   firmware panic unless an arbiter serializes them — and an arbiter trades
   mesh TX latency against peering discoverability, on a link whose TX
   latency is already the complaint. **This is the same blocker, with the
   same fix, that the management-API-over-BLE work is parked on**; whoever
   builds either should build the arbiter once.
2. **The radio schedule is already at its limit.** `libs/blue/CLAUDE.md`
   documents that a scan window filling its interval starved the advertiser
   into `AdvertiseError::Raw(RawError::Resources)` — perfect RX, zero TX —
   and that the current ~90% duty cycle (`SCAN_INTERVAL_625US = 180`,
   `SCAN_WINDOW_625US = 160`) is "a first guess, not a validated tuning".
   Connections add a *third* recurring, non-deferrable radio obligation: the
   SoftDevice must honor a connection event per connection per connection
   interval. N connections plus scanning plus advertising on one radio is a
   materially harder scheduling problem than the one that already broke
   once here, and it will break in the same silent, one-directional way.
3. **Role counts and RAM both need config work that has never run.** S140
   allows 20 combined connections (`BLE_GAP_ROLE_COUNT_COMBINED_MAX`), but
   defaults to 1 peripheral / 3 central
   (`BLE_GAP_ROLE_COUNT_PERIPH_DEFAULT`, `..._CENTRAL_DEFAULT`), and raising
   them costs SoftDevice RAM — as does each L2CAP channel's buffers
   (`ble-l2cap`, plus possibly `ble-l2cap-credit-workaround`).
   `NrfBleLink::new` currently takes `Config::default()` with every field
   `None`, and `bins/wayfinder-nrf52840/memory.x` still declares
   `FLASH : ORIGIN = 0x00000000` with the comment "no SoftDevice reserved".
   Peering cannot be configured onto a board whose memory map does not yet
   acknowledge the SoftDevice at all.

The asymmetry is what decides this: the *easy* backend is host↔host, and
host↔host is the case that matters least — two `wayfinder-tap` hosts in BLE
range of each other almost always have a better carrier available (UDP, or
the design 08 VPN). The cases worth peering — host↔nRF and nRF↔nRF — are
exactly the ones behind all three blockers.

### 3.4 Which peers to connect to, and when to give up

Left sketched rather than specified, since §9 does not recommend building
this yet. The shape it would need:

- **A bounded peer table.** Connections are a scarce, RAM-costed resource
  (§3.3.3) — far scarcer than the neighbor table. So the policy is a
  *selection* problem, not a "connect to everyone" one: pick the top-K
  neighbors by some criterion, and K is small (single digits on nRF).
- **A criterion.** Traffic volume to that next-hop is the honest one — peer
  where the directed traffic actually is — but it is also self-reinforcing
  and needs a decay term so a peer that goes quiet is eventually replaced.
- **A teardown and backoff policy**, so a peer that repeatedly fails to
  connect doesn't consume a slot or spin on reconnection.
- **Hysteresis**, because a connection that churns is worse than no
  connection: each attempt costs radio time on a schedule that has none
  spare (§3.3.2).

None of this is exotic, but it is a real control loop with real failure
modes, in a crate whose current state machine is "fragment, advertise,
forget".

## 4. Correctness / edge cases

### 4.1 Fallback must be total, and must not reorder

Any frame that cannot go down a connection goes out the air. That covers a
missing peer, a torn-down channel, a full transmit queue, and every
broadcast. The risk is that the *same* neighbor's frames alternate between
two paths with very different latencies (one connection interval vs. a
multi-fragment dwell), reordering them. The mesh above tolerates reordering,
but pairwise replay counters are the thing to check specifically — see
[[project-pairwise-replay-counter-reboot]] for how sensitive that machinery
already proved to be.

### 4.2 A peered link that silently stops delivering is worse than no peering

The failure mode to design against is a connection that stays *open* while
delivering nothing — the BLE analogue of every bug in
`libs/blue/CLAUDE.md`'s history, all of which presented as a link that
looked alive and moved no traffic. A connection needs a liveness signal of
its own, and the honest one is not "the socket is open" but "frames sent down
it are still being acknowledged by the mesh above".

### 4.3 The routing metric would stop describing the path the data takes

**This is the consequence that is not fixable inside `libs/blue`, and the
strongest single argument for not doing this.**

BATMAN's TQ is learned from OGM loss. OGMs are broadcast, so TQ measures the
*advertising* channel to a neighbor. If directed traffic then rides an
acknowledged, retransmitting connection, the metric is measuring a channel
the data no longer uses, and it is wrong in both directions:

- A neighbor whose advertising is 40% lossy but whose connection delivers
  effectively everything is **underrated**, and the router steers directed
  traffic away from the best path it has.
- A neighbor whose connection has silently degraded (§4.2) keeps a healthy
  TQ from OGMs it still hears, and the router keeps steering traffic into a
  hole.

Introducing a second transport with materially different loss characteristics
under a metric derived from the first is a routing-correctness problem, not a
`libs/blue` problem. Closing it properly means either feeding connection
health back into the link metric — which is exactly the TX-side feedback
[[feedback-minimal-link-abstraction]] rules out of the shared trait — or
accepting a knowingly mis-calibrated metric on this one carrier. Neither is
attractive, and neither should be decided as a side effect of a `libs/blue`
change.

## 5. Migration / versioning

The peering beacon (§3.2) is new on-air surface, but it is **purely
additive**: a node that does not understand it simply never connects, and
every node keeps broadcasting exactly as it does today. Unlike design 07's
mode tag, there is no coordinated update — a peered pair is an optimization
between two consenting nodes, invisible to everyone else. If this is ever
built, that additive property is worth preserving deliberately rather than
by accident.

## 6. Security considerations

- **The connection is not a trust boundary and must not be treated as one.**
  Frames carried over a peered channel get exactly the same `wayfinder-auth`
  verification as frames off the air — same signature checks, same pairwise
  tags, same replay counters. A connection is a faster pipe, nothing more.
  The temptation to skip verification "because it came from a peer we
  connected to" is the failure to design against: whoever we connected to is
  whoever answered a beacon, which is not an identity claim.
- **The peering beacon broadcasts the node's mesh `Mac` continuously under a
  stable address**, which is a real linkability increase over today's
  behavior. Today the mesh `Mac` is already in every fragment
  (`frame::ORIGIN_LEN`), so the `Mac` itself is not new — but pairing it with
  an address stable enough to connect to is. Payloads on this medium are
  never encrypted anyway (`wayfinder-auth` is authenticity + segregation
  only), so this changes tracking exposure, not confidentiality.
- **Connections are a bounded resource, so accepting them is a DoS surface**
  that advertising does not have. An unauthenticated peer can occupy a
  connection slot on a device that has three. Slot admission needs to be
  driven by mesh membership, not by who asked first.

## 7. Observability

Per the root `CLAUDE.md`, this state belongs in `CentralRouter`, not only in
the link — an embedded node has no driver loop, and a driver-only counter
would not exist on the hardware this is for. If built, use the `add-metric`
skill for: peered-vs-broadcast frame counts per neighbor (a
`RateEstimator`-style bounded rate, not a monotonic total), peer-table
occupancy against capacity (`TableOccupancy`), and connection
establishment/teardown as `wayfinder-alarm` conditions rather than log lines
— a peer that keeps reconnecting is a latched condition, which is exactly
what that crate exists for.

## 8. Alternatives considered

- **Directed advertising instead of connections.**
  `NonconnectableAdvertisement::ExtendedNonscannableDirected { peer, .. }`
  exists on the nRF side, so a fragment could in principle be addressed to
  one peer. **Rejected on three independent grounds**, any one sufficient:
  (a) it saves no airtime at all — a directed advertisement occupies the
  medium exactly as long as an undirected one, so it buys nothing on the
  metric that matters; (b) it needs a stable peer address, which is the
  problem §3.2 exists to solve, so it carries the cost of peering with none
  of the benefit; (c) `bluer`'s `Advertisement` has **no** peer/target
  field at all — BlueZ's `LEAdvertisingManager1` does not expose directed
  advertising — so the host backend could not do it, breaking the two
  backends' on-air interop, which is the whole point of this crate.
- **Design 07 (extended advertising) instead.** Not really an alternative
  so much as the thing that makes this one unnecessary for now — see §9.
- **Peering for the management API rather than for mesh data.** *Not*
  rejected: this is the better first customer for every piece of connection
  machinery in §3.3, and it already has an analysis. A management session is
  point-to-point, operator-initiated, short-lived, and — crucially — carries
  no routing metric that a second transport could distort (§4.3). If the
  L2CAP CoC plumbing, the SoftDevice config, and the advertising arbiter
  ever get built, they should be built for that, and mesh-data peering
  should be evaluated afterward *on top of working, hardware-validated
  connection support* rather than as the thing that has to bring it up.
- **Doing nothing.** The recommendation for now, but on the strength of
  design 07 rather than on the strength of the status quo — 23% whole-frame
  delivery for a full-cert OGM (§1) is not an acceptable resting place.

## 9. Recommendation and the conditions that would change it

**Do design 07 first, and re-evaluate this afterward against measurements
rather than against today's numbers.**

Extended advertising takes a full-cert OGM from 14 fragments to 2 and a
lazy-auth OGM from 6 to 1. Because whole-frame delivery goes as `p^n`, that
is a superlinear reliability win, not a proportional one — at an assumed
`p = 0.9` per fragment:

| frame | fragments today → with design 07 | whole-frame delivery |
|---|---|---|
| lazy-auth OGM | 6 → 1 | 53% → **90%** |
| full-cert OGM | 14 → 2 | 23% → **81%** |

That captures most of what §1's table wanted from connections, for a change
confined to constants, a one-byte mode tag, and a second `Reassembler`
instance — with **no** new radio role, **no** connection state machine, **no**
advertising-set arbiter, **no** SoftDevice config or `memory.x` work, and
**no** metric distortion (§4.3), since it does not introduce a second
transport at all. It is strictly the better first move, and the two are not
in tension: peering, if ever built, sits on top of it unchanged.

This design becomes worth revisiting when **all** of the following hold:

1. Design 07 has shipped and been measured on real hardware, and the
   residual reliability or latency on directed traffic is still a problem
   worth solving. If it isn't, this document's motivation is gone.
   **Status as of 2026-09-06: half met.** Design 07 is implemented
   (`docs/design/implemented/07-ble-extended-advertising.md`) but entirely
   unmeasured — its timing constants are still legacy-tuned. The *config*
   default is `BleSendMode::Legacy`, but both nRF firmwares
   (`wayfinder_nrf::node::run`) and the BLE bring-up rig
   (`containers/node-ble.yml`) run `Both`, so extended fragments are on the
   air; nothing has yet confirmed a peer reassembling them. The measurement,
   not the merge, is what this condition wants.
2. `bins/wayfinder-nrf52840` boots with a tuned, non-default
   `Softdevice::Config`. (Its `memory.x` is already SoftDevice-aware — it
   reserves `0x27000` of flash and a measured 13,112-byte
   `wanted_app_ram_base` — so only the `Config` half is outstanding.) The
   prerequisite
   for §3.3.3 and, independently, for the existing BLE link being trusted at
   all.
3. The single-advertising-set arbiter (§3.3.1) exists and is
   hardware-validated, most likely because the management-API-over-BLE work
   built it first.
4. There is an answer to §4.3 — either a decision to accept a knowingly
   mis-calibrated TQ on this carrier, with that written down, or a way to
   feed connection health into the metric that doesn't push TX-side
   feedback into the shared `LinkT` trait.

Until (2) and (3) are true, this is not a design that can be implemented at
all on the backend that would benefit from it. Until (4) has an answer, it
should not be implemented on the backend that could.

## 10. Key file map

Listed for completeness, should §9's conditions ever be met:

- `libs/blue/src/generic_link.rs` — `BleLink::send`'s transport dispatch
  (§3.1); the peer table lives here, alongside the existing `Reassembler`,
  so it is testable against a fake the way `BleAdvertiser` already is.
- `libs/blue/src/peer.rs` (new) — peer table, selection policy, backoff
  (§3.4). Pure logic, no radio I/O, per the crate's existing "anything that
  can be pulled into `frame.rs`/`ad.rs` should be" discipline.
- `libs/blue/src/beacon.rs` (new) — the connectable peering beacon's format
  (§3.2), built and parsed here so both backends share it, same as `ad.rs`.
- `libs/blue/src/std_link.rs` — a second advertising instance for the
  beacon, an L2CAP `StreamListener`, and outbound `Stream::connect`.
- `libs/blue/src/nrf_link.rs` — the advertising arbiter (§3.3.1),
  `Softdevice::Config` taken rather than defaulted, `central::connect`, and
  L2CAP channel setup.
- `libs/blue/Cargo.toml` — `bluer`'s `l2cap` feature; `nrf-softdevice`'s
  `ble-l2cap` (and see `ble-l2cap-credit-workaround`'s upstream note).
- `bins/wayfinder-nrf52840/memory.x` and its `Softdevice::Config` — §3.3.3.
- `libs/blue/CLAUDE.md` — would need a section on the peered path and,
  above all, on §4.3, which a future reader must not rediscover from a
  routing bug.
