# Design: IEEE 802.15.4 as the nRF52840's built-in radio link

**Status:** Implemented, and **brought up on hardware** — §3.3, §3.4, §3.5,
§3.6 as designed; §3.2 and §3.7 deliberately not, because the decision to
remove the SoftDevice outright left one board configuration instead of two
(§11.2). §12 records the bring-up on a DK and a dongle, including the one bug
only real hardware could have found.

"Brought up", not "verified": two boards route over 802.15.4 and fragmentation
works on air, but **§3.3's central claim — that the task is what prevents frame
loss — is argued from `embassy-nrf`'s source, not measured.** The A/B this doc
proposes in §7.3 was never run. §12.5 is the standing list.

> Numbering note: written against the `bjc/ble-extended-advertising` branch,
> where design 07 is `implemented/` and design 18 (BLE peered unicast) is
> `Proposed`. This doc is 19.

## 1. Scope

**In play:**

- `libs/ieee802154` — the hardware-agnostic framing crate. Gains a source
  address and fragmentation; its wire format changes.
- `libs/nrf-ieee802154` — the `LinkT` adapter for the nRF52840's built-in
  radio. Gains a continuous receive task, a reassembler, and radio
  configuration.
- `libs/wayfinder-nrf` — `MeshLink` gains a variant; the built-in-radio slot
  becomes a build-time choice between BLE and 802.15.4; `memory.x` and
  `RAM_ORIGIN` become generated rather than hand-maintained.
- `bins/wayfinder-nrf52840`, `bins/wayfinder-nrf52840-dongle` — a `build.rs`
  each, and the feature they pass down.

**Explicitly not touched:**

- **The `LinkT` / `FrameIo` surface.** No trait signature changes.
- **`libs/blue`.** BLE stays exactly as it is, including design 07's extended
  advertising. This is a second built-in-radio option, not a replacement —
  see §8.1.
- **The host side. There is nothing to build there** — §3.1.
- **`libs/wayfinder`'s capacity profile.** The link count stays 3, because
  BLE and 802.15.4 are mutually exclusive on this silicon (§3.2), so the new
  link occupies the slot the old one vacates.
- **`libs/at86rf233`.** It shares `libs/ieee802154` and therefore inherits
  §3.4's framing changes for free, but wiring it into a board is out of
  scope (§9.5).

## 2. Motivation

### 2.1 The airtime cost of using a discovery protocol as a data link

`libs/blue` carries the mesh over connectionless BLE advertising. That works,
and design 07 improved it by an order of magnitude, but the residual cost is
structural rather than tunable: an advertisement has no acknowledgement and
no rendezvous with the scanner, so `advertise_dwell` (150 ms/fragment on
BlueZ, ~80 ms on the nRF) exists to give a receiver several chances to be
listening. `LinkT::send` blocks the driver's event loop for
`dwell × fragment_count`.

802.15.4 is a data link. A mains-powered mesh node keeps its receiver on, so
one transmission is one transmission. For design 07's own reference frames:

| frame | BLE legacy | BLE extended (design 07) | 802.15.4 (this design) |
|---|---|---|---|
| lazy-auth OGM (~100 B) | 6 frags, 900 ms | 1 frag, 150 ms | 1 frame, **~4.3 ms** |
| full-cert OGM (~250 B) | 14 frags, 2.1 s | 2 frags, 300 ms | 3 frames, **~13 ms** |

The 4.3 ms is a full 127-byte PHY frame at 802.15.4's 250 kbps O-QPSK
(4 B preamble + 1 B SFD + 1 B PHR + 127 B PSDU = 133 B × 8 / 250 kbps),
before CSMA backoff. BLE 1M is four times faster on the wire; the gap above
is entirely dwell, not throughput.

### 2.2 The SoftDevice is the expensive dependency, not BLE

`libs/blue/CLAUDE.md` records why this firmware links `nrf-softdevice`: the
nRF52840's BLE link layer has no open register-level implementation, and
`nrf-sdc`/`nrf-mpsl` 0.3.0 hard-pin `embassy-nrf 0.7` against this
firmware's 0.10. There is no third option.

802.15.4 has no such problem — `embassy-nrf` drives the radio directly
(`embassy_nrf::radio::ieee802154`). Building the built-in-radio slot on
802.15.4 instead of BLE retires, in one move:

- **13,112 bytes of RAM.** Both boards' `memory.x` sets
  `RAM : ORIGIN = 0x20000000 + 13112` — the S140's measured
  `wanted_app_ram_base`. This firmware has already had a stack overflow into
  exactly that region (`node::run`'s doc comment: a ~62 KB future `memcpy`'d
  through a stack temporary, trapped as `NRF_FAULT_ID_APP_MEMACC`).
- **156 KB of flash.** `FLASH : ORIGIN = 0x00027000` is the S140 binary.
- **NVIC priorities P0 and P1**, which `init_platform` currently has to
  vacate for four peripherals (`GPIOTE`, `RTC1`, `UARTE0`, `USBD` all forced
  to `P2`), and **`TIMER0`**, which is why the dongle's `BufferedUarte` runs
  on `TIMER1`.
- The `nrf-softdevice` git dependency, its `critical-section-impl`, the
  probe-detach SD assert, and `memory.x`'s dependence on a SoftDevice
  configuration that changes if BLE roles or connection counts ever change.

That last group is not hypothetical: four separate memory entries in this
project are SoftDevice bring-up pain, and the "mgmt API over BLE" plan is
parked partly on `memory.x` not being SoftDevice-aware.

### 2.3 802.15.4 already exists here and has never been wired

`libs/ieee802154` (270 lines), `libs/nrf-ieee802154` (196 lines) and
`libs/at86rf233` (593 lines) are all in the workspace, all tested, and **none
are reachable from a running node**. `wayfinder-nrf`'s `MeshLink` is
`Rylr | Ble | Usb | Absent`; `nrf-ieee802154` is linked by the board only to
keep it compiling for the real target. The work below is closer to finishing
a started thing than starting a new one — but §3.3 and §3.4 are the two
places where what exists is not yet correct for a live driver loop.

## 3. Design

### 3.1 The host needs no new code, and no bridge firmware

The obvious-looking plan — a dongle firmware that bridges 802.15.4 to the
host over USB CDC, plus a host-side carrier to speak to it — is unnecessary,
because `wayfinder-nrf`'s CDC-NCM mesh link already solved a strictly harder
version of the problem.

`libs/wayfinder-nrf/src/usb_link.rs` makes the board enumerate as an ordinary
Ethernet interface and carries `LinkFrame`s over it natively (a `LinkFrame`
*is* an Ethernet frame — `[dst][src][ethertype][payload]`). Its module docs
already state the consequence:

```yaml
- transport: !RawL2
    interface: wf-usb0
    ethertype: 0xfafa
```

So the dongle is **a full mesh node** that happens to be plugged into a host,
not a radio peripheral the host drives. The host is another full mesh node
whose interfaces are `RawL2` → dongle and, typically, `UdpMulti` over
Tailscale (design 08). The host runs no 802.15.4, no BLE, and no radio code
of any kind; the two nodes route to each other over the USB wire like any
other pair of neighbours.

This is why `LinkTransport` gains no variant and `wayfinder-tap` is
untouched. **Do not add a host-side 802.15.4 carrier.** If a future
deployment needs one, it is a separate design.

### 3.2 One built-in radio, chosen at build time

`nrf-softdevice` claims the `RADIO` peripheral and its interrupt;
`embassy_nrf::radio::ieee802154::Radio::new` claims `p.RADIO` too. **A board
can run one or the other, never both.**

This is not caught by the type system today: `embassy_nrf::init` hands out
`p.RADIO` whether or not the SoftDevice is enabled, so wiring both compiles
cleanly and fails at runtime, in the SoftDevice's protected-peripheral trap —
i.e. as a fault, in the same family as the failures §2.2 lists. Make it a
compile error instead.

Add two mutually exclusive features to `libs/wayfinder-nrf`:

```toml
[features]
default = ["ble"]
ble = ["dep:blue", "dep:nrf-softdevice"]
ieee802154 = ["dep:nrf-ieee802154"]
```

with a guard in `lib.rs`:

```rust
#[cfg(all(feature = "ble", feature = "ieee802154"))]
compile_error!(
    "`ble` and `ieee802154` both claim the nRF52840 RADIO peripheral \
     (nrf-softdevice vs embassy-nrf) and cannot be enabled together — \
     see docs/design/19-ieee802154-nrf-link.md §3.2"
);
#[cfg(not(any(feature = "ble", feature = "ieee802154")))]
compile_error!("enable exactly one of `ble` or `ieee802154`");
```

`default = ["ble"]` means **this design changes no board's behaviour until
someone opts in**, matching design 07 §9.6's posture for the same reason.

#### The link array does not grow

`node.rs`'s `LORA`/`BLE`/`USB` indices become `LORA`/`RADIO`/`USB`, where
`RADIO` holds whichever built-in radio was compiled in. `Links` stays
`[MeshLink<Serial>; 3]`, `TRICKLE`/`NAMES`/`features()` stay 3 wide, and the
`nrf52840` capacity profile's `interfaces: 3` is unchanged. `NAMES[RADIO]`
becomes `"ble"` or `"dot15d4"` under `cfg`, so the management API still names
the interface truthfully.

#### `MeshLink` gains a variant, `cfg`-gated

```rust
pub enum MeshLink<S> {
    Rylr(RylrClient<S>),
    #[cfg(feature = "ble")]
    Ble(NrfBleLink),
    #[cfg(feature = "ieee802154")]
    Dot15d4(Ieee802154Link),
    Usb(UsbNcmLink),
    Absent,
}
```

`#[cfg]` rather than both-always-present: `NrfBleLink` cannot exist without
`nrf-softdevice` linked, which is the whole point of the feature split.

### 3.3 The receive path must be a task and a queue

**This is the load-bearing correctness change, and today's
`Ieee802154Link::recv` gets it wrong.**

`wayfinder_embedded_driver` builds one `recv` future per link, races them
against the OGM timer with `select_array`, and **drops every loser** — on
each timer tick and on each frame from any other link. `usb_link.rs` and
`blue`'s `ReportQueue` both exist to survive that; their module docs spell it
out.

`nrf-ieee802154`'s `recv` awaits `Radio::receive` directly. Reading
`embassy-nrf 0.10.0`'s implementation, `receive` installs
`OnDrop::new(|| Self::receive_cancel())`, and `receive_cancel` writes
`tasks_stop`, spins until the radio reaches `DISABLED`/`RX_IDLE`, and issues
a DMA fence. So cancelling is **memory-safe** — no DMA into a dead buffer —
but it is emphatically **not lossless**:

- Any frame mid-reception when the future drops is lost.
- Between drops the radio is *off*. The receiver exists only while the driver
  happens to be inside `recv`, so the link is duty-cycled by unrelated
  events, and each re-entry pays RX ramp-up before it can hear anything.

The result is the exact failure class `libs/blue/CLAUDE.md` catalogues: a
link that comes up, reports metrics, moves *some* traffic, and silently drops
frames in a pattern that looks like poor RF.

**Fix: the radio never leaves a spawned task.** The task owns `Radio` and is
never cancelled; `LinkT::recv` only awaits a channel, which is cancel-safe.

```text
                 ┌──────────────────── radio_task (never cancelled) ───────┐
                 │  loop {                                                  │
   Ieee802154Link│    select(radio.receive(&mut pkt), tx_req.receive()) {   │
     .recv() ────┼──← rx_queue.send(RawFrame { bytes, lqi })                │
     .send() ────┼──→ tx_req  ──→ radio.try_send(&mut pkt) ──→ tx_res ──────┼──→
                 │  }                                                       │
                 └──────────────────────────────────────────────────────────┘
```

- `rx_queue`: `Channel<CriticalSectionRawMutex, RawFrame, RX_QUEUE_DEPTH>`,
  `RX_QUEUE_DEPTH = 4` (matching `usb_link.rs`'s). A `RawFrame` is
  `{ bytes: [u8; MAX_FRAME_LEN], len: u8, lqi: u8 }` — 127 B, so the queue is
  ~508 B.
- `tx_req` / `tx_res`: depth-1 channels. `LinkT::send` takes `&mut self`, so
  at most one send is ever in flight and no request/response correlation is
  needed. `send` pushes the encoded packet and awaits the
  `Result<(), RadioError>` back.
- The task's `select` **deliberately** drops the in-flight `receive` to
  service a transmit. That is the one place cancelling is correct: the loss
  window is bounded by this node's own transmits (which would collide with a
  simultaneous reception on a half-duplex radio regardless), rather than by
  every timer tick on every other link.

Mirror `usb_link.rs`'s spawn-and-static-cell shape for the queues, and its
module-doc treatment of *why* — a future reader will otherwise "simplify"
this back into a direct await.

### 3.4 Wire format: a real source address, and fragmentation

`libs/ieee802154`'s current frame is a 7-byte header — FCF, seq, dest PAN,
dest addr — with **source addressing omitted entirely** and no fragmentation.
`MAX_PAYLOAD_LEN` is `125 − 7 − 14 = 104` bytes.

104 bytes cannot carry a full-cert OGM (~250 B), and the `nrf52840` profile's
`max_frame_len` is 512. So fragmentation is required, and fragmentation needs
a per-sender reassembly key.

`libs/blue` solved this by embedding a 6-byte `Mac` in every fragment,
because the BLE advertiser address rotates per registration. **802.15.4 has
no such problem** — it has a source address field, and nothing rotates it. Use
it, at 2 bytes instead of 6.

#### New header

```text
FCF (2) | seq (1) | dest PAN (2) | dest addr (2) | src addr (2)  =  9 bytes
```

Frame control gains `SRC_ADDR_MODE_SHORT` (`0b10 << 14`) and
`PAN_ID_COMPRESSION` (bit 6), so the source PAN is omitted — both nodes share
the broadcast PAN. Destination stays `0xffff`/`0xffff`: the medium is a
shared broadcast channel like LoRa, and mesh addressing is the `Mac` inside
the `LinkFrame`.

The source short address is `u16::from_be_bytes([mac.0[4], mac.0[5]])` —
**the same derivation `node::run` already uses for `lora_address`**, so a
board's two radios agree on its short identity. Extract it as
`wayfinder_nrf::short_address(mac)` rather than writing it twice.

#### Fragmentation

Reuse `wayfinder-link-utils`, as `rylr998` and `blue` do:

```rust
/// 9-byte MAC header, 2-byte fragment header.
pub const FRAG_PAYLOAD: usize = MAX_FRAME_LEN - HEADER_LEN - FRAG_HDR_LEN; // 114
```

| | value | note |
|---|---|---|
| `FRAG_PAYLOAD` | 114 | vs `blue`'s 18 (legacy) / 231 (extended) |
| `MAX_FRAGMENTS` | 15 | from `wayfinder-link-utils`, 4-bit count field |
| `MAX_REASSEMBLED_LEN` | 512 | the `nrf52840` profile's `max_frame_len`; `5 × 114 = 570 ≥ 512` ✓ |
| `MAX_REASSEMBLIES` | 4 | matching `blue` |

The reassembler is `Reassembler<u16, 4, 114, 512>` — keyed on the 16-bit
source short address, exactly the `FragKey<A>` shape `rylr998` uses for its
`AT+ADDRESS`. Add a `const _: () = assert!(MAX_REASSEMBLED_LEN <= MAX_FRAGMENTS * FRAG_PAYLOAD)`
alongside `blue`'s equivalent.

Because both `nrf-ieee802154` and `at86rf233` sit on `libs/ieee802154`, the
fragment build/parse helpers belong **in `libs/ieee802154`** (mirroring
`blue::frame`'s `build_fragment`/`parse_fragment_with_origin`), and each
adapter owns its own `Reassembler` instance and receive loop. That is the
one structural difference from `blue`, which has a single `generic_link.rs`
because both its backends share a platform-independent core.

#### Uniqueness requirement

Two nodes whose MACs share their low 16 bits will cross-contaminate
reassembly. This is not new — `wayfinder-link-utils`' `FragKey` docs already
name it as "a deployment requirement the driver must document", and
`rylr998` carries the identical constraint. Document it on
`ieee802154::encode`, and see §5.3 for why it degrades to dropped frames
rather than misdelivery.

### 3.5 Radio configuration

`Radio::new` leaves the caller to set channel, CCA mode and TX power.
`Ieee802154Link::new` currently takes an already-configured `Radio` and sets
nothing — fine for a type that was never instantiated, wrong for one a board
relies on. Configure explicitly at construction:

| setting | value | why |
|---|---|---|
| channel | `DOT15D4_CHANNEL: u8 = 15` | Channels 15/20/25/26 avoid the common 2.4 GHz Wi-Fi centres. Sits beside `LORA_NETWORK_ID` in `node.rs` as deployment policy. |
| PAN ID | broadcast `0xffff` | Unchanged; addressing is the mesh `Mac`. |
| CCA | `Cca::CarrierSense` | `try_send` already reports a busy channel as `ChannelInUse`. |
| TX power | `0` dBm | Explicit rather than reset-default. |

`set_sfd` stays at `DEFAULT_SFD`.

### 3.6 Trickle and link features

`node.rs`'s per-link tables are positional. Give the `RADIO` slot the same
values BLE has today:

```rust
t[RADIO] = TrickleParams { i_min: 1s, i_max: 20s };
f[RADIO] = LinkFeatures { tx_keepalive: Some(KeepAliveConfig { interval_ms: 5000 }), .. };
```

**Deliberately unchanged from BLE's**, even though §2.1 shows two orders of
magnitude more airtime headroom. Flipping the radio and retuning convergence
in one change makes a regression in either indistinguishable from the other.
Tuning is §9.3.

### 3.7 `memory.x` and `RAM_ORIGIN` become generated

Under `ieee802154` there is no SoftDevice, so both boards' flash and RAM
origins move:

| | `ble` (today) | `ieee802154` |
|---|---|---|
| `FLASH ORIGIN` | `0x00027000` | `0x00000000` |
| `FLASH LENGTH` (DK) | 860K | 1016K |
| `FLASH LENGTH` (dongle) | 732K | 884K (0x1000..0xDE000; see §11.2) |
| `RAM ORIGIN` | `0x20000000 + 13112` | `0x20000000` |
| `RAM LENGTH` | `256K - 13112` | `256K` |

Each board's `main.rs` also carries `const RAM_ORIGIN`, duplicating
`memory.x` with a "**Must stay consistent with `memory.x`**" comment on both
sides — `stack::paint` needs it and cannot read it from a linker symbol,
because `flip-link` rewrites the `MEMORY` block.

Doubling that hazard across two layouts is not acceptable. Give each board a
`build.rs` that:

1. writes `memory.x` into `OUT_DIR` from the feature-selected layout, and
2. emits `cargo::rustc-env=WAYFINDER_RAM_ORIGIN=<origin>`,

so `main.rs` becomes:

```rust
const RAM_ORIGIN: usize = const_str_parse!(env!("WAYFINDER_RAM_ORIGIN"));
```

One source of truth, and the existing hand-sync hazard is deleted rather than
duplicated. `DURABLE_STORE_BASE` is derived from the flash layout the same
way. The `build-stack-budget` CI job (`just stack-budget`) reads each board's
ELF against `memory.x`, so it validates the generated layout with no change —
and its budget rises by the 13,112 bytes the SoftDevice no longer reserves.

## 4. Testing

Test-first, per the root `CLAUDE.md`. Most of this is host-testable in the
root workspace, because `libs/ieee802154` is a plain workspace member with no
hardware dependency and `libs/nrf-ieee802154` builds on Linux (it is dropped
from root-workspace commands only on macOS, per `host_workspace_excludes`).

**`libs/ieee802154` — pure, fully covered on the host:**

- `encode` sets `SRC_ADDR_MODE_SHORT` and PAN-ID compression, and writes the
  short address the caller passed.
- Header is 9 bytes; `FRAG_PAYLOAD == 114`; the `MAX_REASSEMBLED_LEN` static
  assertion holds.
- A frame of exactly `FRAG_PAYLOAD` bytes is one fragment; one byte more is
  two.
- A 512-byte frame round-trips through fragment → `Reassembler` → frame,
  fragments delivered **out of order** and with a **duplicate**.
- Two senders with distinct short addresses interleave fragments without
  cross-contamination; two with the *same* short address are shown to corrupt
  each other (pin §3.4's documented constraint, and §5.3's claim that the
  result is a dropped frame).
- Fail-closed: a fragment whose header parses but whose body is short, an
  unknown `count`, `index >= count`.
- `MAX_REASSEMBLIES + 1` concurrent senders evicts rather than overflows.

**`libs/nrf-ieee802154` — the parts not needing a radio:**

- `map_err` (exists).
- Round-trip through `Packet::copy_from_slice`/`Deref` (exists; extend to a
  fragmented frame).
- A max-size fragment exactly fills `Packet::CAPACITY` (exists).
- The receive *loop body* — "raw frame in, complete frame or nothing out" —
  should be a free function over `&mut Reassembler` so it is testable without
  a `Radio`. Feed it a hand-built fragment sequence.

**`libs/wayfinder-nrf`:**

- `short_address(mac)` agrees with `node::run`'s existing `lora_address`
  derivation (pin them together, since §3.4 makes them one function).
- Feature-guard `compile_error!`s fire — a `trybuild` case, or just a CI
  invocation asserting the both-features build fails.

**Not host-testable, and honest about it:** §3.3's task/queue behaviour under
real cancellation, §3.5's radio configuration, and anything about actual RF.
Those are §7.

## 5. Correctness argument and edge cases

### 5.1 Cancellation

The only future the driver cancels is `Channel::receive`, which is
cancel-safe. The `Radio` is owned by a task the driver cannot see and never
cancels. The one deliberate cancellation — the task dropping `receive` to
service a transmit — is memory-safe by `embassy-nrf`'s `OnDrop` guard (§3.3),
and its loss window is a self-transmit on a half-duplex radio, which was
never receivable anyway.

### 5.2 Queue overflow

`rx_queue` full means the driver is not draining. Dropping the newest raw
frame is correct and matches `usb_link.rs`: it is a lossy medium, the
reassembler is already built for gaps, and blocking the task would stop the
receiver entirely. Log at `trace!` with a `"drop: rx queue full"` message per
the logging rules — this is reachable from arbitrary peer input and must not
be `warn!`.

### 5.3 A hostile or colliding source address

The 16-bit source address is **unauthenticated medium metadata** and is used
for exactly one thing: as a reassembly key. It is never a routing input and
never reaches the router. What the router trusts is the `Mac` inside the
reassembled `LinkFrame`, checked by `OgmAuth` as on every other link.

So the worst a spoofed or colliding address achieves is corrupting a
reassembly, which fails one of: the completeness bitmask, the `LinkFrame`
parse, or the signature check. The frame is dropped. That is a denial of
service against a shared broadcast radio by a party who is already
transmitting on it — i.e. strictly weaker than jamming, which needs no
protocol knowledge at all. Bounded reassembly capacity (`MAX_REASSEMBLIES =
4`, capacity-evicting) keeps it from growing into memory pressure.

This is the same posture `rylr998` takes toward `AT+ADDRESS` and `blue` takes
toward its embedded origin.

### 5.4 Flipping the radio partitions the mesh at that radio

A board built with `ieee802154` cannot hear a board built with `ble`. Nodes
still reach each other over LoRa and over the USB link, so a mixed deployment
degrades to whatever the *other* links provide rather than splitting the mesh
outright — but the 802.15.4 nodes and the BLE nodes are not neighbours.

There is no negotiation available and none is proposed: `blue`'s `BleSendMode`
could run both formats concurrently because they share one radio, and this
cannot. **Flip both boards together.** `default = ["ble"]` (§3.2) means no
board flips by accident.

### 5.5 CCA busy

`try_send` returns `ChannelInUse` when carrier sense finds the channel busy;
`map_err` already maps it to `LinkError::TransmitFailed`, which the driver
treats as a failed send. No retry is added here — the shared `LinkT` contract
is fire-and-forget by design (see the "minimal link abstraction" rule), and
Trickle re-emission is the recovery path. §6 makes the rate observable so a
congested channel is diagnosable rather than invisible.

## 6. Observability

Per the root `CLAUDE.md`, state belongs in `CentralRouter`, and bounded
here-and-now signals beat monotonic totals.

Already covered: `Packet::lqi()` maps to `LinkMetrics::quality`, so the
existing link-quality table works with no change. `rssi_dbm` and `snr_db`
stay `None` — `embassy-nrf`'s `Packet` exposes no RSSI.

Worth adding, both via the `add-metric` skill:

- **CCA-busy rate** — a `RateEstimator` on `TransmitFailed`-from-`ChannelInUse`
  per link. This is the direct read on 2.4 GHz congestion, which is the main
  thing that degrades this link and is otherwise invisible. Deliberately a
  decayed rate, not a counter.
- **Reassembly failure rate** — fragments dropped for a full table or an
  incomplete message evicted. Distinguishes "poor RF" from "too many
  concurrent senders for `MAX_REASSEMBLIES`", which look identical from the
  outside and have different fixes.

Both are per-link and belong on the router so they exist on a board, which
runs no `wayfinder-driver`.

## 7. What still needs hardware

An API-level pass against `embassy-nrf 0.10.0` confirmed: `Radio::new`'s
signature and its `RADIO` + interrupt-binding requirement; `Packet::CAPACITY
== 125 == ieee802154::MAX_FRAME_LEN` (already a `const` assertion);
`receive`'s `OnDrop`/`receive_cancel` semantics (§3.3); `try_send`'s CCA
shortcut chain and `ChannelInUse` result; `set_channel`/`set_cca`/`set_sfd`/
`set_transmission_power` existing as configuration entry points.

Unverified until a board runs it:

1. **The SoftDevice-free `memory.x` actually links and boots.** §3.7's
   numbers are arithmetic on the S140 reservation, not a measurement.
2. **Two boards exchange a fragmented frame.** The whole §3.4 wire format is
   untested on air.
3. **The §3.3 task genuinely stops the frame loss.** The prediction is that a
   direct-await build drops frames in proportion to other links' activity and
   the task build does not. Worth building both and comparing, because it is
   the design's central claim.
4. **Range and LQI behaviour** relative to BLE, which the mesh's link-quality
   metric feeds on.
5. **Whether dropping the SoftDevice resolves the open nRF faults** — the
   HardFault on mgmt-port attach and the GetLogs OOM reset. Plausibly
   unrelated; do not assume. Both have their own memory entries and their own
   reproductions.

## 8. Alternatives considered

### 8.1 Replace BLE entirely, delete `libs/blue`

Rejected. BLE is the only link that reaches hardware nobody controls — a
phone, a stock laptop, any host with a Bluetooth controller and no free SPI
bus or spare USB port. 802.15.4 is the better radio; BLE is the better reach.
The `LinkT` seam exists so this is not a choice, and design 07's extended
advertising work stays valuable for exactly the deployments 802.15.4 cannot
serve.

### 8.2 Run BLE and 802.15.4 concurrently via the SoftDevice timeslot API

Rejected. Nordic's timeslot API is the sanctioned multiprotocol path, but
`embassy-nrf`'s `Radio` drives `RADIO` directly with no timeslot awareness,
so this means reimplementing the 802.15.4 driver against `nrf-softdevice`'s
raw timeslot interface — and keeping the SoftDevice, which §2.2 shows is the
dependency actually worth removing. It buys concurrency this design does not
need: §5.4's partition is managed by flipping both boards together.

### 8.3 Bind Nordic's `nrf-802154` C driver

Rejected. It would restore hardware auto-ACK and full CSMA-CA retries, which
`embassy-nrf`'s driver lacks — but at the cost of reintroducing a
closed-source blob and a C build, which is the specific thing §2.2 is trying
to be rid of. `embassy-nrf`'s CCA-before-transmit is sufficient for a
broadcast, fire-and-forget link whose recovery path is Trickle.

### 8.4 A dedicated 802.15.4-to-USB bridge firmware

Rejected, and this is worth recording because it is the obvious plan. It is
strictly more work than §3.1: it needs a new firmware, a new host-side
carrier in `LinkTransport`, and a new framing protocol, in order to produce
something *less* capable than what CDC-NCM already gives — a bridge is not a
mesh node, so it cannot relay, hold a route, or answer the management API.
The dongle is already a full node with an Ethernet link to its host.

### 8.5 Embed the 6-byte `Mac` in every fragment, as `blue` does

Rejected. `blue` does that because BLE draws a fresh random advertiser
address per advertising-set registration, so no two fragments of a message
share an address (confirmed by `btmon`). 802.15.4 has a stable source address
field that this design controls. Paying 6 bytes per fragment to solve a
problem this medium does not have would cost ~5% of `FRAG_PAYLOAD` for
nothing.

### 8.6 Keep the SoftDevice's memory layout and simply not enable it

Rejected. Simpler — no `build.rs`, no second layout — but it forfeits the
13,112 bytes of RAM and 156 KB of flash that §2.2 identifies as the main
prize, on a firmware that has already overflowed its stack into precisely
that region.

## 9. Open decisions for the implementing session

1. **Channel and PAN ID** (§3.5). 15 is a placeholder chosen to dodge Wi-Fi
   1/6/11. If any deployment site has a known spectrum picture, use it. Both
   are deployment policy and belong beside `LORA_NETWORK_ID`.
2. **Does the DK default flip too, or only the dongle?** §5.4 argues both
   together; the counter-argument is keeping one DK on BLE as a live peer for
   `libs/blue` regression testing. If so, that DK cannot be a mesh neighbour
   of the 802.15.4 nodes except over LoRa/USB — decide deliberately.
3. **Trickle tuning** (§3.6). Held at BLE's values on purpose. Retune only
   after §7.3 is measured, and as its own change.
4. **`RX_QUEUE_DEPTH`** (§3.3). 4 mirrors `usb_link.rs`, whose medium is a
   wire. A radio that bursts fragments may want more; each slot is 127 bytes,
   and the SoftDevice's 13 KB is now available to spend.
5. **Whether to wire `at86rf233` as well.** It inherits §3.4 for free and
   would give a Linux host a native 802.15.4 link over SPI — but §3.1 means
   no host actually needs one. Out of scope here; do not let it expand the
   change.
6. **Whether to fold `Ieee802154Link`'s task into `wayfinder-nrf`.** §3.3
   puts it in `nrf-ieee802154`, which keeps the adapter self-contained but
   makes that crate depend on `embassy-executor`. The alternative — the board
   spawns the task and passes queue handles in, as `NrfBleLink::new` takes a
   `Spawner` — may be the better seam. Decide when writing it.

## 10. Key file map

| file | change |
|---|---|
| `libs/ieee802154/src/lib.rs` | §3.4: `src_addr` in `Ieee802154Header` (`HEADER_LEN` 7→9), FCF gains `SRC_ADDR_MODE_SHORT` + PAN-ID compression, `encode` takes a short address, new `FRAG_PAYLOAD`/`build_fragment`/`parse_fragment`, static assertions |
| `libs/ieee802154/Cargo.toml` | add `wayfinder-link-utils` |
| `libs/nrf-ieee802154/src/lib.rs` | §3.3 task + queues, §3.4 `Reassembler<u16, 4, 114, 512>`, §3.5 radio config in `new`. `map_err` and the three existing tests stay |
| `libs/wayfinder-nrf/Cargo.toml` | §3.2 `ble`/`ieee802154` features; `blue` + `nrf-softdevice` become optional |
| `libs/wayfinder-nrf/src/lib.rs` | §3.2 `compile_error!` guards; §3.4 `short_address(mac)`; `init_platform`'s P0/P1 vacating becomes `#[cfg(feature = "ble")]` |
| `libs/wayfinder-nrf/src/link.rs` | §3.2 `cfg`-gated `Ble`/`Dot15d4` variants and their `LinkT` arms |
| `libs/wayfinder-nrf/src/node.rs` | `BLE` const → `RADIO`; `cfg`-gated bring-up replacing the `Softdevice::enable` + `NrfBleLink::new` block (~lines 232–260); `NAMES`/`TRICKLE`/`features()` slot; `lora_address` uses `short_address` |
| `libs/wayfinder-nrf/CLAUDE.md` | the two radios, the exclusivity, the generated layout |
| `bins/wayfinder-nrf52840/build.rs` | **new** — §3.7 |
| `bins/wayfinder-nrf52840-dongle/build.rs` | **new** — §3.7 |
| `bins/*/memory.x` | become templates consumed by `build.rs` |
| `bins/*/src/main.rs` | `RAM_ORIGIN`/`DURABLE_STORE_BASE` from `env!` (DK ~lines 28–34, dongle ~lines 30–34) |
| `libs/blue/CLAUDE.md` | the RADIO-exclusivity section gains a pointer here |

Untouched, and worth stating so nobody goes looking: `bins/wayfinder-tap`,
`libs/wayfinder/src/config.rs`, `libs/wayfinder-driver*`, `libs/blue/src/*`.

> **§3.7 was not built, and that decision cost something.** The `build.rs`
> below exists to delete the hand-sync between `memory.x` and `RAM_ORIGIN`.
> §11.2 explains why it was dropped once there was one layout instead of two —
> but the hazard it was designed to remove then bit twice inside this very
> branch: once as the MBR RAM bug (§12.1), and once as
> `libs/wayfinder-nrf/CLAUDE.md` continuing to claim both boards share a RAM
> origin after `memory.x` and `main.rs` had been corrected. Both were caught,
> neither by a test. Reconsider §3.7 before a third board is added.

## 11. Deviations taken during implementation

Recorded as the design is built, per `docs/design/README.md`. §3.4 (the wire
format) is implemented; §3.2, §3.3, §3.5, §3.6 and §3.7 are not yet.

- **`short_address_of` lives in `libs/ieee802154`, not `wayfinder-nrf`.**
  §3.4 and §10 put it in the board-support crate. Both `LinkT` adapters need
  it — `at86rf233` is not an nRF part — so it belongs beside the header that
  carries its output. `wayfinder-nrf`'s `lora_address` derivation will call
  it rather than define it.
- **No local `MAX_REASSEMBLED_LEN <= MAX_FRAGMENTS * FRAG_PAYLOAD`
  assertion.** §3.4 asked for one alongside `blue`'s. It turned out
  `Reassembler::new` already carries exactly that as a `const {}` assert,
  inside the generic constructor every consumer calls, so a local copy would
  be dead weight. `blue`'s standalone assertion predates that and is now
  redundant too, though removing it is out of scope here.
- **`MAX_PAYLOAD_LEN` is now `MAX_REASSEMBLED_LEN - LINK_HEADER_LEN` (498),**
  not the old single-frame 104. It is the ceiling `assemble_frame` enforces,
  which is what a caller actually needs to know. `LINK_HEADER_LEN` became
  `pub` so that relationship is checkable from outside.
- **`fragment_count` clamps to a minimum of 1.** A zero-length frame is not
  something `assemble_frame` can produce, but `pack_header` debug-asserts
  `count >= 1`, and a debug panic is a worse failure than a valid empty
  fragment.
- **The fuzz target was rewritten, not just renamed.** `decode` no longer
  exists; `fuzz_targets/accept_fragment.rs` covers the whole boundary (MAC
  header, fragment header, reassembly, and the frame parse a completed
  reassembly feeds). Its reassembler is **persistent across inputs** — a
  fresh table per call would never reach eviction, duplicate indices, or a
  mid-message count change, which is most of what is worth fuzzing about
  reassembly. This was not anticipated by the design at all.
- **`at86rf233` was updated in the same change.** §1 scoped it out, meaning
  *board wiring*; its call sites had to move with the wire format regardless,
  since it shares `libs/ieee802154`. Its `FakeChip` now records every
  transmitted fragment rather than only the most recent, which is what makes
  the multi-fragment send path assertable without hardware.
- **`nrf-ieee802154` ships §3.4 with §3.3 still outstanding.** Its `recv`
  still awaits `Radio::receive` directly and is therefore not cancel-safe in
  the lossless sense. The crate docs and `libs/ieee802154/CLAUDE.md` both say
  so in as many words, and the link must not be wired into a board until
  §3.3 lands.

### 11.1 §3.3, the radio task

- **§9.6 resolved: the task lives in `nrf-ieee802154`, with the `Spawner`
  passed in** — `Ieee802154Link::new(spawner, radio, channel)`, mirroring
  `blue`'s `NrfBleLink::new(spawner, sd, mode)`. The worry that this would
  cost the crate its host-testability was unfounded: `embassy-executor`
  builds for the host without an arch feature, so `cargo nextest run
  --workspace` still compiles and runs this crate's tests.
- **`Ieee802154Link` lost its lifetime parameter.** The `Radio<'d>` moved
  into the task, so the link holds only framing state and channel handles.
  `MeshLink` (§3.2) therefore gets a plain `Dot15d4(Ieee802154Link)` variant
  with no lifetime to thread through the board's link array.
- **The transmit path is a request/result channel pair, not a mutex.** A
  `Mutex<Radio>` would either starve `send` (the task holds it while
  receiving) or need the same select, so it buys nothing. Depth 1 each, with
  no request id: `LinkT::send` takes `&mut self`, so one transmit is in
  flight at a time and the next result is always this request's. `send`
  drains any stale result first, which nothing produces today but would
  silently desynchronise the pairing if the driver ever raced `send`.
- **`Radio::set_channel` panics outside 11..=26**, which a config-driven
  channel could reach. `new` validates first and returns
  `BringUpError::InvalidChannel` — a mistyped channel should be a reported
  bring-up failure, not a panicking board. This was not anticipated by §3.5,
  which treated the setters as infallible.
- **`BringUpError` derives neither `PartialEq` nor `Eq`**, because
  `embassy_executor::SpawnError` implements neither.
- **`RX_QUEUE`/`TX_REQUEST`/`TX_RESULT` are plain `static`s**, as
  `usb_link.rs` does, not `StaticCell`s. There is one `RADIO` peripheral, so
  `new` is documented as once-per-boot: a second link would be a second
  consumer of one radio's frames, splitting them silently.
- **`at86rf233` was left with the same latent cancel-safety problem** — its
  `recv` awaits the chip's IRQ line directly. It is unwired and out of
  scope (§1), but `libs/ieee802154/CLAUDE.md` now names it so the next person
  to wire it does not rediscover this from the symptom.

### 11.2 §3.2/§3.6/§3.7, the boards

The user's decision to drop the SoftDevice outright, rather than keep BLE as
a build-time alternative, changed the shape of three sections.

- **§3.2's mutually exclusive `ble`/`ieee802154` features were not built.**
  With the SoftDevice gone from both nRF boards there is one configuration,
  not two, so there is nothing to select between: `MeshLink::Ble` became
  `MeshLink::Dot15d4` outright and `wayfinder-nrf` dropped its `blue` and
  `nrf-softdevice` dependencies. The `compile_error!` guards §3.2 specified
  guard a choice that no longer exists.
- **§3.7's `build.rs` codegen was not built either, for the same reason.** It
  existed to generate one of *two* `memory.x` layouts and derive `RAM_ORIGIN`
  from whichever was selected. With a single layout the linker scripts are
  just edited, and the pre-existing `RAM_ORIGIN`-mirrors-`memory.x` hazard is
  left as it was — unchanged, not worsened, and cheaper than getting untestable
  build-script codegen wrong on the one part of this change no host test can
  reach.
- **The dongle's flash origin moved to 0x1000, not 0x0**, and this is the
  sharpest edge in the whole change. Its Open Bootloader depends on the MBR in
  the bottom 4 KiB and, finding no SoftDevice, places an application directly
  above it. `runner.sh`'s `--sd-req` had to move from `0x123` to `0x00` in the
  same breath: the two are a pair, and mixing them places the image at the
  wrong address. The DK, flashed over SWD, links from 0 — so **the two boards'
  flash origins now differ, where they used to match**.
- **`blue`'s nRF backend lost its only consumer**, so
  `just build-loose-drivers`/`clippy-loose-drivers` were repointed from
  `nrf-ieee802154` (now wired into both boards) to
  `blue --no-default-features --features hardware,softdevice-log`. A
  straight swap of which driver is the unwired one. `blue`'s host/BlueZ half
  is untouched and still carries `wayfinder-tap`'s BLE links, per §8.1.
- **VBUS detection moved from `SoftwareVbusDetect` to `HardwareVbusDetect`.**
  The software detector existed only because the SoftDevice reserved `POWER`
  and delivered VBUS as SoC events, which in turn is why `usb_mgmt` had an
  event-pump callback and a `USBREGSTATUS` seeding read for the
  already-plugged-in case. A register read has no missed-event problem, so all
  of that is gone. The board's `bind_interrupts!` gains `CLOCK_POWER`
  (**not** `POWER_CLOCK` — `embassy-nrf` names it the other way round).
- **`init_platform` must now select `HfclkSource::ExternalXtal` explicitly.**
  `embassy-nrf` defaults to the internal RC because a board may not have a
  crystal. The `RADIO` peripheral is only specified running from the HFXO and
  USBD cannot clock the bus without it, so this is a hard requirement that the
  SoftDevice used to satisfy invisibly. LFCLK stays on `InternalRC`: the
  dongle has no 32.768 kHz crystal and would hang at boot waiting for one.
- **`critical-section-single-core` went from forbidden to required.** It was
  banned because a bare `cpsid i` starved the SoftDevice's reserved
  RADIO/RTC0/TIMER0. There are no reserved interrupts now, and it is the only
  `critical_section::set_impl!` left in the graph.
- **The unexplained 1s sleep before radio bring-up is deleted.** It was an
  unconfirmed workaround suspected of papering over a `Softdevice::enable`
  race; there is no enable to race. Recorded here because if bring-up turns
  out to be flaky without it, that is a real bug to find rather than a delay
  to restore.
- **The `__INTERRUPTS` link conflict is resolved as a side effect.** Both
  board images link cleanly; `nrf-softdevice` bundling its own PAC alongside
  `embassy-nrf`'s was the cause.

Verified: both boards cross-compile and pass clippy for
`thumbv7em-none-eabihf`, and `just stack-budget` passes on all three boards
(the nRF stack region grew from ~112,600 to 124,680 bytes, the SoftDevice's
13,112 back minus the reassembler's statics). Not verified: anything requiring
hardware, and in particular **the dongle's 0x1000/`--sd-req 0x00` pairing has
never been flashed** at the time this was written — §12.2 settles it.

## 12. Hardware bring-up

Run on an nRF52840-DK (`da:18:2c:33:4b:c4`) and an nRF52840 dongle
(`be:64:73:47:3c:f1`), both on the 802.15.4 build, channel 15.

### 12.1 The bug hardware found: the MBR's 8 RAM bytes

**`bins/wayfinder-nrf52840-dongle/memory.x` needs
`RAM : ORIGIN = 0x20000008`, not `0x20000000`.** The MBR keeps its
interrupt-forwarding address in the first 8 bytes of RAM, and that is the
mechanism by which an application above the MBR receives interrupts at all
with no SoftDevice: the bootloader issues
`SD_MBR_COMMAND_IRQ_FORWARD_ADDRESS_SET` before jumping, and the MBR's vector
table at 0 trampolines every IRQ through it. `flip-link` puts the *stack* at
the bottom of RAM, so an origin of `0x20000000` had `stack::paint` overwrite
that address during boot; the board then took a HardFault on its first
interrupt, rebooted, and halted after `MAX_CONSECUTIVE_FAULTS` with LD1 dark
and no USB.

**Neither the DK nor any host test can reproduce it.** The DK's app is at 0
with no MBR to forward anything, and the pre-802.15.4 dongle firmware could
not hit it either, because the S140's 13,112-byte reservation put RAM origin
far above these 8 bytes. It is invisible to `cargo nextest`, to clippy, to
the cross-compile, and to `just stack-budget`, which checks that the stack
*fits* rather than what lives under it.

### 12.2 The addressing pairing, settled empirically

`--sd-req 0x123` was rejected with `SdVersionFailure` after the first DFU,
which is only possible if no S140 is present. So `--sd-req 0x00` does make
the bootloader erase the SoftDevice and place the application at `MBR_SIZE`,
confirming §11.2's `0x1000` / `--sd-req 0x00` pairing against the real
bootloader rather than from the SDK sources. `libs/wayfinder-nrf/CLAUDE.md`'s
older note — that omitting `sd_req` "corrupts the SoftDevice and misplaces
the app" — described the same mechanism seen through an image still *linked*
for `0x27000`.

### 12.3 What the two boards did

- Both boot clean from the SoftDevice-free layout; `wayfinder started` in
  ~3 s, the delay being the RYLR998 detection timeout.
- `802.15.4 radio task started channel=15` — §3.3's task and §3.5's
  configuration on real silicon.
- Interface reports as `dot15d4`, Trickle `1000`/`20000` ms, keepalive
  5000 ms, exactly as §3.6 specifies.
- **Bidirectional mesh**: each node lists the other as a neighbour on
  `dot15d4` with a route. The dongle discovered the DK 168 ms after reaching
  its run loop.
- `HardwareVbusDetect` enumerates on both, and the CDC-NCM mesh interface
  appears host-side (`enp10s0u3u2i2`, MAC = node MAC + 1) — §3.1's host story
  at the interface level.
- **Probe detach no longer crashes the board.** A reset following a
  `probe-rs` detach with the radio live produced no retained fault record.
  That failure was a SoftDevice property, as §11.2 predicted.
- Stack: `used=66424 free=58288 total=124712`, stable. The region grew from
  the old ~112,600 bytes with the SoftDevice's 13,112 returned.
- The `__INTERRUPTS` duplicate-symbol link conflict is gone.

### 12.4 Fragmentation on air, and what it costs

Forced with an oversized `ping` payload (a temporary local raise of
`MAX_PING_PAYLOAD`, reverted — the shipped cap of 64 bytes is below one
fragment, so nothing this deployment normally generates fragments at all:
OGMs are unsigned because no board wires mesh auth).

| ping payload | fragments | RTT | loss (20 probes) |
|---|---|---|---|
| 16 B | 1 | 2.8 ms | 5% |
| 64 B | 1 | 4.4 ms | — |
| 200 B | 2–3 | 10.8 ms | — |
| 400 B | 4 | 18.3 ms | **35%** |

A reply at all proves the far side reassembled every fragment, so §7.2 is
closed. The RTT tracks ~4.26 ms of airtime per full PHY frame, as §2.1
predicts.

**The loss column is the finding.** With no ARQ — the `LinkT` contract is
fire-and-forget and recovery is Trickle re-emission — a frame survives only
if *every* fragment does, so per-fragment loss compounds: ~10% per fragment
gives `1 - 0.9^4 = 34%` against the 35% measured, from a 5% single-fragment
baseline.

Two consequences worth carrying forward:

- **Fragment count is a reliability parameter, not just an airtime one.**
  §2.1 argued extended BLE vs 802.15.4 on airtime alone; on this link a
  3-fragment full-cert OGM is materially less likely to land than a
  1-fragment lazy-auth OGM. That is an argument *for* design 01's lazy
  certificate distribution on this radio, independent of its airtime case.
- **A retransmission or per-fragment-ack scheme would change the numbers a
  lot**, and remains deliberately out of scope — see the "minimal link
  abstraction" rule. Worth revisiting only with this measurement in hand.

### 12.5 Still unverified

- §7.3's A/B comparison — that the §3.3 task *is* what prevents frame loss.
  The task build works; a direct-await build was never flashed to measure
  against. The 5% single-fragment baseline is the number to beat.
- §7.4 range behaviour. The scale half is closed (§12.7) and has a hardware
  check — `interop.rs`'s `assert_scaled_lqi` — but **that check has not been
  run**: it needs two boards and is `#[ignore]`d like the rest of the HIL
  tier. The TQ numbers in §12.7 remain predicted, not measured, and nothing
  has been walked out of range to confirm the value falls rather than sitting
  at 255.
- The nRF fault reports (mgmt-port HardFault, GetLogs OOM) — not
  re-tested, and §7.5 already said not to assume the SoftDevice's removal
  addresses them.

### 12.6 Carried forward from review

Raised by the `mr-review` pass and deliberately **not** fixed in this change,
each for a stated reason:

- **Fragment-reassembly loss has no metric.** Every discard in
  `Reassembler` — malformed header, capacity eviction, mismatched count — is
  `trace!`-only and stateless, and `CentralRouter` carries no reassembly
  counter. The root `CLAUDE.md` is explicit that metrics are first-class and
  belong in the `no_std` router, and `untaggable_drop_rate` is the exact
  precedent. It matters more here than on other links, because §12.4 measures
  partial-frame loss as the *expected* condition at range, and its signature
  is identical to "nobody is transmitting". Deferred because it is a full
  `add-metric` path (proto → service → `RouterAdapter` → client → TUI) and a
  wire-format change should not carry one; it wants its own MR.
- **Both radio adapters now carry the same six fields and near-identical
  `send`/`recv` bodies**, differing only in their hardware I/O — and
  `libs/ieee802154/CLAUDE.md` tells the next driver author to copy that shape.
  A `FragmentCutter` owning `index`/`count`, or a `FragmentingLink` owning the
  state, would delete the duplication *and* make a transposed index/count
  unrepresentable rather than merely rejected. Worth doing; too large to ride
  along here.
- **This driver's `LinkMetrics::quality` was unscaled.** Fixed since — §12.7
  records the mechanism and the conversion. Was issue #56.
- **Bring-up degradation is logged, not latched.** A node running on one of
  three interfaces says so once, into a bounded ring that per-frame traffic
  evicts. `wayfinder-alarm` exists for exactly that, and neither
  `wayfinder-nrf` nor `nrf-ieee802154` raises a single alarm. The startup line
  now names which links came up, which is the cheap half; the alarm is the
  right fix.

### 12.7 The LQI scale (issue #56)

`Packet::lqi()` was handed to `LinkMetrics::quality` raw, and it is not an
LQI. It returns the correlator indicator the hardware appends after the
payload, whose useful domain is **`0..=63`** — where the field is defined on
`0..=255`, and `wayfinder::link_quality::normalize_quality` returns a `Some`
verbatim on the grounds that the driver has already done the mapping.

**It was not cosmetic, because the smoothed quality clamps an OGM's advertised
TQ** (`batman::engine`: `computed_tq = (ogm.tq - 10).min(local_quality)`). A
perfect one-hop OGM arriving over `dot15d4` was recorded at `min(245, 49) =
49` — every path through the radio capped at 19% of the TQ scale. Bring-up read 49 on
`dot15d4` against BLE's 255 on the same desk and put it down to "different
scales"; the mechanism is narrower. BLE's 255 is simply where
`normalize_quality`'s RSSI curve saturates (-50 dBm), and the 802.15.4 number
never entered that curve at all.

**The factor comes from the Product Specification, not from a guess.** The
RADIO chapter gives the conversion literally:

```
LQI_IEEE = (uint8_t)(val > 63 ? 255 : val * ED_RSSISCALE)     // ED_RSSISCALE = 4
```

Nordic's own driver agrees — `nrf_802154_core.c`'s `lqi_get()` is
`lqi * LQI_VALUE_FACTOR` clamped to `LQI_MAX 0xff`, with `LQI_VALUE_FACTOR`
defined as `ED_RSSISCALE`. Its extra temperature correction is nRF53-only; on
this part `nrf_802154_rssi_lqi_corrected_get` is a pass-through. The constant
is **4 on the nRF52840** and 5 on the nRF52833/nRF5340. Nothing enforces that
— `embassy-nrf`'s chip-feature guard fires only when *no* part is selected,
and Cargo features are additive — so what protects it is that a port means
editing the `nrf52840` feature in `Cargo.toml`, with
`ed_rssiscale_is_the_nrf52840_value` to make that edit fail loudly.

Two things that argument settles, which §12.6 had left open:

- **The "is it really saturated?" question needs no range test.** The domain
  is `0..=63`, and one of the readings was **67** — already past the ceiling,
  reported as 26% quality. Walking the boards apart is still worth doing as a
  check on the *scaled* value (§12.5), but it was not needed to decide whether
  to scale.
- **Scaling does not erase the honest part of the reading.** §12.4 measures 5%
  single-fragment loss at desk range, and 49 maps to 196, not 255 — a link
  that still reads as imperfect. The conversion moves the number onto the axis
  the router believes it is reading; it does not invent a perfect link.

Expected effect at desk range: `dot15d4` advertises TQ ~196-245 against BLE's
245, where it advertised 49.

**The fix removes the evidence that would confirm it**, which is the part
worth carrying forward. The management API's link-quality column *was* the raw
correlator value, smoothed — that is how bring-up measured 49 and 67 at all.
After the conversion every hardware reading of 64 or more reads 255, so that
column can no longer separate "correctly saturated" from "wrong scale factor"
or "reading a stale byte", and the discriminator §12.5 proposes (walk the
boards apart, watch the value fall) starts from a number already pinned at its
ceiling. Worse, the saturation branch moves an out-of-spec reading from
*conspicuously bad* — 67 shown as 26%, which is what got this investigated —
to *ideal*. Two things answer it: a per-frame `trace!` in `capture` carries
**both** numbers, which is now the only place in the receive path the raw
value survives; and `interop.rs`'s `assert_scaled_lqi` is the on-hardware
check, asserting the best `dot15d4` row clears 128 — a floor an unscaled build
is structurally incapable of reaching, since the correlator tops out at 63.

**Other drivers set the field too**, contrary to how #56 was filed. Two, in
fact: `at86rf233` passes its chip's appended byte, which is correct because
the AT86RF23x appends a conformant IEEE `0..=255` LQI; and `PyLinkMetrics` in
`wayfinder-py` exposes it to a Python simulation author as a settable field,
where it had been documented as "carrier-defined" — the one framing this whole
entry exists to retire. So the contract had a correct user and an
undocumented third surface, and was worth sharpening rather than replacing.

**What made it easy to get wrong** is that nothing distinguishes a correct LQI
from an unscaled one by inspection: 67 is plausible on either scale, so no
assertion in the router can catch it. A newtype does not help either — the
upstream method is *named* `lqi()` and its docs assert it is one, so
`Lqi::from_ieee(packet.lqi())` would have read as correct to author and
reviewer alike. The false belief was injected between a datasheet and the
first line of Rust, which is outside what any type can reach.

The mapping therefore stays in the driver — a correlator indicator is neither
RSSI nor SNR, and centralizing it would put a per-chip hardware constant in
the `no_std` router — and enforcement is four things instead:
`LinkMetrics::quality`'s docs state the scale and the datasheet-pinned-test
obligation, `libs/interfaces/CLAUDE.md` repeats it where a driver author
actually looks, `ieee_lqi` carries that test, and `capture_reports_a_scaled_lqi`
pins the *wiring* — because every other test here passes against a `capture`
that never calls `ieee_lqi` at all, which is one token away from silently
un-shipping the fix.

One thing that is **not** enforceable and should not be attempted: a lower
length bound in `capture`. `Packet::lqi` is documented to return garbage below
3 bytes, and a runt can reach it — but `decode_fragment` rejects anything
under 11 bytes before `recv` returns, so those metrics never reach the router.
A bound here would only duplicate that one.
