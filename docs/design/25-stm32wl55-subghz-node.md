# Design: a wayfinder node on the STM32WL55, with the radio on the die

**Status:** Partly implemented. `libs/lora-link`, `bins/wayfinder-wl55jc`,
`libs/wayfinder-log`'s per-board ring and `libs/wayfinder-hil`'s `BoardKind`
are built; the board **links, fits, and passes `just stack-budget-wl55jc`** as
a LoRa relay, and §4.1's table carries figures measured from the real image.

**The management port is built but does not fit**: 36,872 bytes over flash on
current `main`, and 13,960 (13.6 KiB) over once the float-formatting and
compact-SHA-512 changes land — see §4.1's re-measurement, and branch
`bjc/wl55jc-mgmt-port`, which carries the working port. Closing that gap is §9's first open question and the
thing blocking `libs/wayfinder-hil`, enrolment, and observability without a
debug probe. The durable store (§4.9) and the `fuzz/` target (§10) are also
unbuilt.

**Nothing here is hardware-verified and cannot be**: the board on the bench
does not answer on SWD (§2.3), so every claim rests on the static gates this
repo already trusts for board work. §11 records what deviated during
implementation, including the one gate that needed a per-board threshold.

## 1. Scope

**New:**

- **`libs/lora-link`** — hardware-agnostic raw-LoRa framing and fragmentation,
  `no_std`, a root workspace member. Owns the §4.4 wire format (this is the
  first radio here whose hardware supplies no addressing of its own) and reuses
  `wayfinder-link-utils`. **Pure framing helpers, no `LinkT` impl and no radio
  dependency** — exactly `libs/ieee802154`'s shape, whose `LinkT` lives in its
  `at86rf233`/`nrf-ieee802154` adapters instead. §4.3 explains why that seam is
  load-bearing rather than tidiness.
- **`bins/wayfinder-wl55jc`** — the NUCLEO-WL55JC1 firmware: its own
  `[workspace]`, `memory.x`, clocks, RF front-end control, capacity profile,
  durable store, the `lora-phy`-backed `LinkT`, and the management
  arm that makes it reachable from `libs/wayfinder-hil`.
- **`libs/wayfinder-log`** — `RING_CAPACITY` becomes per-board rather than
  per-`target_os`. §4.7.
- **`libs/wayfinder-hil`** — a `BoardKind` for this part, and the first board
  whose probe and management port share one USB serial. §4.9.

**Changed:**

- **`justfile` / `.github/workflows/ci.yml`** — `build-wl55jc`, `clippy-wl55jc`,
  `stack-budget-wl55jc`, and the new crate in `build-embedded`.

**Explicitly not touched:**

- **`bins/wayfinder-stm32f411`.** It stays as the non-Nordic HAL-portability
  proof and keeps its external-module LoRa path. Its three never-flashed bugs
  are fixed separately (§2.2) and are not this design's business.
- **Any wire format already on air.** §4.4's format is new and rides inside a
  link; nothing above `LinkT` observes it.
- **The routing core, `batman`, `wayfinder-driver-core`.** A new board and a new
  link, nothing else. If this design needs a core change, that change is its
  own MR with its own argument.

## 2. Motivation

### 2.1 The board on the bench is not the board the tree has firmware for

`bins/wayfinder-stm32f411` targets a NUCLEO-F411RE. The part actually attached
is a **NUCLEO-WL55JC1** (STM32WL55JC). They share a vendor and almost nothing
else:

| | STM32F411RE | STM32WL55JC |
|---|---|---|
| cores | 1 × Cortex-M4F | 2 × (M4 + M0+) |
| flash | 512 KiB | **256 KiB** |
| RAM | 128 KiB | **64 KiB** (32K + 32K, contiguous) |
| LoRa | external RYLR998, AT commands over UART | **on the die**, SX126x-class over `SUBGHZSPI` |

The last row is the one that makes this a design rather than a port. Every LoRa
path in this repo goes through `rylr998`, which is an AT-command driver for a
module that does its own addressing, its own network-id filtering, and reports
the sender's address on every `+RCV` line. None of that exists on a raw SX126x:
it hands over a LoRa PHY payload and nothing else. So the radio needs a new
`LinkT`, and that `LinkT` needs a wire format.

It is also a better fit for what this project is. One part, one antenna, no
UART between the router and its radio, and no second vendor's firmware in the
path.

### 2.2 What was wrong with the F411 firmware, and why it matters here

The F411 firmware had never been flashed, and three bugs had accumulated behind
that fact. They are fixed on `main` in `a01cfc7` (MR !192), separately from
this design — but two of them are the reason it leads with a measured memory
budget:

- **`memory.x` was the nRF52840's map** — `FLASH : ORIGIN = 0x00000000` (the
  read-only boot alias, which `probe-rs` refuses because no NVM region covers
  it) and `RAM … 256K` on a 128 KiB part, putting `_stack_start` past the end
  of real RAM.
- **It built at the `host` capacity profile** — 128 originators, 8 interfaces,
  2048-byte frames, a Linux gateway's sizing. With the memory map corrected,
  `.bss` overflows RAM by 9,268 bytes. That image could never have run, and
  nothing said so, because the link succeeded against RAM the part does not
  have.
- **No `[profile]` section at all**, so no `panic = "abort"` — unlike both nRF
  boards.

The lesson this design takes from that: **on this family the memory budget is
the design, and it has to be measured rather than assumed.** A 64 KiB part is
half of what already did not fit at default capacities.

### 2.3 The board cannot currently be flashed

Nothing here is hardware-verified, and that is recorded rather than glossed.
The onboard STLINK-V3E enumerates (four interfaces: debug, mass storage, and
the VCP at `/dev/ttyACM0`; the drag-and-drop volume is labelled `NOD_WL55JC`),
and its own firmware answers — but no target responds on SWD:

```
probe-rs:      JtagGetIdcodeError (SWD), JtagNoDeviceConnected (JTAG), SwdDpError (under reset)
stlink 1.8.0:  Failed to enter SWD mode; chipid 0x000; sram 0
```

Two independent tools agreeing makes this the probe's view of the target, not a
tooling fault. Everything below is therefore gated on the static checks the
repo already trusts for board work — it links, it fits, `stack-budget.py`
passes — with the on-silicon claims explicitly deferred to §9.

## 3. Goals and non-goals

**Goals**

1. A NUCLEO-WL55JC1 runs the same `wayfinder_embedded_driver::Driver` the nRF
   boards run, over its on-die radio, with no external radio module.
2. It is reachable by `libs/wayfinder-hil` over its management port, closing
   the gap design 21 §1 recorded as the reason the STM32 was out of HIL scope.
3. The image fits with headroom that is *measured and gated*, not asserted.
4. The radio driver is reusable for any SX126x, not welded to this board.

**Non-goals**

1. **The CM0+ core stays parked.** §4.8.
2. **No LoRaWAN.** `lora-phy`'s `lorawan-radio` feature stays off; this is a
   mesh PHY, not a WAN stack.
3. **No duty-cycle or LBT regulatory logic in this MR.** §6.3 states the
   obligation and why it is deferred rather than faked.
4. **No replacement of `rylr998`.** Two LoRa links with different wire formats
   coexist; they are not interoperable and §4.4 says so plainly.

## 4. Design

### 4.1 The memory budget, measured

The F411 image is the only thing available to measure against, so it is what
the numbers come from — same routing core, same driver, same crypto, same
`tracing` stack. Flash, at the corrected `memory.x` and a one-interface
capacity profile:

| release profile | flash | vs 256 KiB |
|---|---|---|
| as committed (no `[profile]`) | 333 KiB | **over by 77 KiB** |
| `panic="abort"`, `lto="fat"`, `opt-level="s"` | 233 KiB | fits, 23 KiB spare |
| `panic="abort"`, `lto="fat"`, `opt-level="z"` | 197 KiB | fits, 58 KiB spare |

**So flash is not the constraint *for the relay*, provided this board is built
at `opt-level="z"` with fat LTO.** That is a required setting here, not a
preference, and it is why the table is in the design rather than in a commit
message.

> **Correction, measured after the fact.** That conclusion does not extend to
> the finished node, and the reason is a flaw in how it was measured: the F411
> image these figures come from **never linked the management path**. That
> board calls `run()`, not `run_with_mgmt`, so LTO stripped the whole protobuf
> dispatch — the table above describes a strictly smaller program than the one
> it was reasoning about.
>
> Linking the management port on this board costs **+75,480 bytes of flash**
> and takes the image to 290,916 against 262,144 available — **over by
> 28.1 KiB** — while leaving only 18.1 KiB of stack. So flash *is* the binding
> constraint for a node with a management port, and §4.10's budget is wrong in
> the same way. The port itself is built and measured on branch
> `bjc/wl55jc-mgmt-port`; §9 carries what closing the gap would take. Per-crate attribution of the 268 KiB `.text` at default settings, for
whoever next wonders where it goes: `core` 52.5 KiB (a third of it float
formatting — `flt2dec`'s `dragon`/`grisu`, ~15 KiB, which nothing on a router
should need and which is worth chasing separately), `wayfinder` 46.5, `batman`
34.4, `curve25519-dalek` 33.0, `sha2` 27.1 (almost all of it one unrolled
`compress512`), `heapless` 12.3.

RAM is the constraint, and the figures below are now **measured from the real
image** rather than extrapolated. The relay as built (one radio, no management
port, a 2 KiB heap) comes to:

| | bytes | of 64 KiB |
|---|---|---|
| flash (`.vector_table`+`.text`+`.rodata`+`.data`) | 215,436 | 210.4 KiB of 256 |
| statics (`.data` + `.bss`) | 34,744 | 33.9 KiB |
| stack region left by `flip-link` | 30,784 | 30.1 KiB |

which is comfortable — but it is the relay, not the finished node. The
management port is what consumes the remaining headroom (§4.10 budgets 12 KiB
of heap against the 2 KiB here), so the numbers to re-check are these, after
that lands.

> **Re-measured on 2026-09-26, after rebasing onto `main`.** Ten commits of
> `main` landed while this board sat on a branch, including the footprint work
> in `67682b1` and certificate renewal over the mesh. Same board, same
> `opt-level="z"` + fat LTO; flash is `.text` + `.data` (so `.rodata`
> included), statics are `.data` + `.bss`:
>
> | image | flash of 262,144 | statics of 65,536 |
> |---|---|---|
> | relay, before the rebase | 215,436 | 34,744 |
> | relay, rebased | 219,532 | 31,692 |
> | relay, rebased, `ring` off (§4.7) | 219,036 — **43,108 spare** | 27,564 |
> | + management port, on `main` | 299,016 — **over by 36,872** | 43,984 |
> | + float fields kept out of `core::fmt` (#71) and rolled SHA-512 (#73) | 276,104 — **over by 13,960** | 43,984 |
>
> So `main` made the relay 4 KB larger in flash and 3 KB smaller in RAM, and
> the port's shortfall *grew* before the size work began to close it. With the
> port, 21,552 bytes are left for stack. The two changes in the last row cut
> 22,912 bytes here; the remaining 13.6 KiB is #72's and #74's to find. The
> largest single consumers of that image by `cargo bloat --crates`:
> `embassy_executor` 23.9 KiB (really this board's own task bodies inlined into
> their polls, #74), `wayfinder_protos` 23.2, `curve25519_dalek` 15.0, `batman`
> 12.9, `prost` 11.9, `wayfinder_driver_core` 10.0.

For reference, the F411 image the design was planned against had statics of
~52 KiB, which on a 64 KiB part would have left ~12 KiB of stack. Two statics
dominated it, and both were addressed:

- **`___embassy_main POOL`, 27,976 bytes** — the main task's future, which
  holds the `Driver` and therefore the router. Shrank with the capacity
  profile (§4.2).
- **`wayfinder_log::ring::RING`, 16,416 bytes** — the `GetLogs` record ring,
  whose size was a constant chosen for a 256 KiB part. Now per-board and set to
  16 records (~4 KiB) here. §4.7.

The budget this design commits to, and gates:

| | bytes | note |
|---|---|---|
| log ring (16 records) | ~4,100 | §4.7 |
| heap | 12 KiB | §4.10 — mgmt framing is the floor |
| task pool (router + mgmt task) | ~20 KiB | capacity profile, §4.2 |
| UART/radio buffers, misc statics | ~3 KiB | |
| **statics total** | **~39 KiB** | |
| **stack** | **~25 KiB** | against a ~20 KiB measured chain |

Each row is a knob, and `just stack-budget-wl55jc` is what stops the sum
drifting past 64 KiB unnoticed. Note what the existing gate would *not* have
caught: it validates a task-poll frame against a share of the stack region, and
on the broken F411 image it passed while reporting a stack top of `0x20040000`
— past the end of real RAM. **`stack-budget.py` should also assert that
`memory.x`'s regions match the chip's** (§9).

### 4.2 Capacity profile

One radio, a handful of neighbours, and a ~5 kbps medium:

```
originators: 16, interfaces: 1, mcast_members: 8, local_mcast: 4,
ident_table: 16, ident_live: 12, link_quality: 16, neighbor_keys: 8,
revoked: 4, in_flight_cert_requests: 2, pending_replies: 2,
max_frame_len: 512,
```

`max_frame_len: 512` is not headroom and must not be trimmed to save RAM. It
has to equal the link's `MAX_REASSEMBLED_LEN` (§4.4): below it the router
silently drops frames the radio was willing to carry, which is the failure
`wayfinder-nrf`'s `assert!(ieee802154::MAX_REASSEMBLED_LEN ==
nrf52840::MAX_FRAME_LEN)` exists to make loud. 512 is what `rylr998` and the
nRF profile both use, and it is sized for a ~260-byte authenticated OGM plus
revocation TVLVs — so a smaller value does not cost throughput, it costs
authenticated OGMs. The RAM comes from §4.7 instead.

This crate gets the same static assertion, pinning its profile to the link's
reassembly ceiling.

### 4.3 The radio: `lora-phy`, plus the glue only this part needs

`embassy-stm32` 0.6 has **no `subghz` module** — the driver it used to carry is
gone, and the one thing it retains is the transport:
`Spi::new_subghz(p.SUBGHZSPI, tx_dma, rx_dma, Irqs)`, which configures the
hardwired SPI at `min(PCLK3/2, 16 MHz)` per RM0453 §7.2.13. The SX126x command
set itself comes from **`lora-phy` 3.0.1** (embassy-rs's own crate, same org as
`embassy-stm32`), which already has what this part needs:

- `sx126x::variant::Stm32wl { use_high_power_pa }` — selects the PA and, more
  importantly, reports `use_dio2_as_rfswitch() == false`, because on this part
  the antenna switch is board GPIO rather than the chip's DIO2.
- A 6-method `InterfaceVariant` trait — `reset`, `wait_on_busy`, `await_irq`,
  `enable_rf_switch_rx`/`_tx`, `disable_rf_switch` — which is precisely the
  board-specific seam.

**Where the seam goes, and why it is not just tidiness.** `libs/lora-link`
carries only the framing — `assemble_frame`, `fragment_count`,
`build_fragment`, `decode_fragment`, `accept_fragment`, `decode_frame` and the
constants tying them together — and depends on no radio crate. The `LinkT`
implementation, and with it `lora-phy`, live in the board crate. Three reasons,
in order of weight:

1. **`defmt` never enters the root workspace.** `lora-phy`'s `defmt` dependency
   is non-optional (§4.6), so a root member depending on it would put `defmt`
   in the host graph — where a `cargo nextest run --workspace` test binary has
   no `global_logger` to link against. Confining it to the board's own
   `[workspace]`, which needs the no-op logger anyway, sidesteps the question
   rather than answering it.
2. **The link's logic becomes host-testable against a mock radio**, which is
   where all of §10's tests live. Nothing in the wire format or the reassembly
   needs silicon.
3. **It is the shape this repo already uses** for exactly this split:
   `libs/ieee802154` is framing-only and neither of its two radio adapters is
   in its dependency graph. Following it means a second raw-LoRa radio costs a
   thin adapter rather than a refactor — and it is why there is deliberately
   *no* `LoraRadio` trait here. An abstraction over one implementation would be
   a guess at where the next radio differs.

The STM32WL implementation starts in the board crate rather than in a
`libs/stm32wl-radio` of its own. It is genuinely board-specific — `SUBGHZSPI`,
`PWR`/`RCC` registers, and *this* Nucleo's front-end pins — and extracting it
before a second STM32WL board exists would be guessing at the seam.
`wayfinder-nrf` was extracted when the second nRF board arrived, and that is
the right trigger here too.

`lora-phy` ships `GenericSx126xInterfaceVariant`, and it is **not usable here**:
it takes GPIO pins, and on the STM32WL none of those three signals is a pin.
Reset is `RCC.CSR.RFRST`, busy is `PWR.SR2.RFBUSYS`, the chip-select is
`PWR.SUBGHZSPICR.NSS`, and the IRQ is the `RADIO_IRQ_BUSY` interrupt line. So
this design writes an `Stm32wlInterfaceVariant` — six small methods over those
registers plus the front-end GPIOs. That is the whole vendor-specific surface,
and keeping it behind `InterfaceVariant` is what stops the STM32WL's registers
leaking into anything reusable.

**The RF front-end must be verified against the schematic, not assumed.** The
NUCLEO-WL55JC1 routes the antenna through a switch driven by three `FE_CTRL`
GPIOs with distinct RX / TX-low-power / TX-high-power states, and the JC1 is
the high-band (868/915 MHz) build. The exact pin assignment and polarity are to
be read out of UM2592 and the board schematic during implementation; they are
deliberately not written down here from memory, because a wrong antenna-switch
state is the failure that looks like a working radio with no range, and it
would be indistinguishable from a routing bug from anywhere above `LinkT`.

### 4.4 The wire format

`rylr998` gets three things from its module that a raw SX126x does not supply:
a sender address on every receive, network-id filtering, and an addressed send.
The reassembler keys on that address, so the format has to carry it. One on-air
LoRa payload is therefore:

```
[net_id: 1][src_id: 2][frag_hdr: 2][content chunk …]
```

- **`net_id`** replaces `AT+NETWORKID`: a one-byte mesh discriminator, checked
  on receive and dropped on mismatch. Not a security boundary — that is
  `wayfinder-auth`'s job (§6.1) — just the cheap filter that keeps two
  co-located meshes out of each other's reassembly tables.
- **`src_id`** is the low 16 bits of the sender's `Mac`, exactly the derivation
  `rylr998` uses for `AT+ADDRESS`, and it carries the same deployment
  requirement: **distinct nodes must differ in the low two bytes of their
  `Mac`**, or their fragments cross-contaminate. It cannot be read out of the
  reassembled content instead, even though the content's Ethernet-shaped header
  already holds the full source `Mac` at bytes 6..12 — that is only available
  *after* reassembly, and the key is needed per fragment.
- **`frag_hdr`** is `wayfinder_link_utils::pack_header` / `parse_fragment`
  unchanged, `FRAG_HDR_LEN = 2`, `MAX_FRAGMENTS = 15`.
- **`content`** is the same Ethernet-shaped
  `[dst:6][src:6][protocol:2][payload]` blob every other link carries, so
  nothing above `LinkT` can tell.

An SX126x LoRa payload caps at 255 bytes, giving `FRAG_PAYLOAD = 255 - 5 = 250`,
and `15 × 250 = 3750` comfortably covers `MAX_REASSEMBLED_LEN = 512` (the
relationship is checked inside `Reassembler::new` already).
`MAX_REASSEMBLIES = 4`, matching `rylr998` — each slot costs a full 512-byte
buffer, so this is 2 KiB of the §4.1 budget.

**This is not interoperable with `rylr998`**, and should not be made so. The
RYLR module imposes base64 and a 180-byte AT-line budget that a raw PHY has no
reason to inherit. Two LoRa links, two formats, no shared air.

`fan_out()` is **not** overridden, matching every other radio driver here
(`rylr998`, `blue`, `ieee802154` all take the default `None`). A broadcast LoRa
send arguably fits the `Some(1)` case its docs describe, but that method is a
design-17 seam nothing currently reads, and diverging from the other radios
unilaterally would be a silent change to egress behaviour for no present
benefit. Recorded as an open question in §9, for all four drivers at once.

### 4.5 `recv` must be cancel-safe, and awaiting `lora-phy` directly is not

`libs/ieee802154/CLAUDE.md` records this as the trap that has already caught
one driver in this repo, and it applies to this radio verbatim.
`wayfinder_embedded_driver` races **every link's `recv` against the OGM
timer** and drops every loser, so a `recv` holding a half-received frame in a
local is torn down routinely — on every timer tick, and on every frame from
any other link.

Awaiting `lora_phy::LoRa::rx` inside `recv` *looks* fine and is memory-safe.
What it does instead is lose the frame in flight and leave the radio out of
receive until the next `recv` — so a radio duty-cycled by an unrelated timer
reads as **poor RF, not as a bug**, which is the worst available failure shape
on a mesh whose whole job is judging link quality. `at86rf233` has this latent
problem today and has never been exercised because it is unwired; this board
would exercise it immediately, since the OGM timer fires continuously.

**So the radio is owned by a never-cancelled task, and `recv` awaits only a
channel.** That is the shape `nrf-ieee802154`'s `radio_task`,
`wayfinder_nrf::usb_link` and `blue`'s `ReportQueue` all already take, for
this same reason. Concretely: the board spawns a task holding the
`lora_phy::LoRa`, which loops receiving and pushes each
`(bytes, rssi, snr)` into an `embassy_sync` channel; the `LinkT::recv`
implementation awaits that channel and is therefore trivially cancel-safe.

Note where this leaves §4.3's split: cancellation is a property of the
`LinkT::recv` implementation, which lives in the board crate — so
`libs/lora-link` is not involved in it at all, and none of its framing
functions need to be cancel-safe. The one test that covers cancellation
(test 9) therefore has to live with the `LinkT` impl.

The transmit side has no such constraint — `LinkT::send` is awaited to
completion by `plan_dispatch`'s caller and is not raced — so it may drive the
radio directly. It does need the channel task to yield the radio, which is
what makes the owning task a `Mutex<LoRa>` holder rather than a pure loop; the
implementing session should expect that to be the fiddly part, and design 4.5's
claim is only that the *receive* path must not be cancellable.

### 4.6 `lora-phy` drags in `defmt`, and this project decided against `defmt`

`lora-phy` 3.0.1 depends on `defmt` **non-optionally**, and calls its log
macros (6 sites: `debug`, `trace`, `warn`). `defmt` will not link without a
`#[defmt::global_logger]`.

This repo has already settled the question in the other direction.
`libs/wayfinder-log/Cargo.toml:57` and `libs/blue/Cargo.toml:37-43` record it:
`log` rather than `defmt`, because `wayfinder-log` installs a `log` sink on
**the RTT channel it already owns**, whereas `defmt` needs a host decoder.
Linking `defmt-rtt` here would put two RTT implementations in one image, both
claiming the control block — so that is out.

**Decision: the board crate provides a no-op `#[defmt::global_logger]`.** It
discards records, `defmt` links, `rtt-target` keeps the channel, and the cost
is `lora-phy`'s six records. Bridging is not a real option: `defmt`'s whole
premise is deferred formatting, so the logger receives an interned frame, not a
string, and rendering it on-target would mean shipping the decoder and the
image's own symbol table. If those six records are ever wanted, the honest
route is a `defmt` feature upstream or a second RTT channel — not a bridge.

Two mechanical consequences to get right, both silent when wrong: `defmt` needs
`-Tdefmt.x` on the link line alongside `-Tlink.x`, and the no-op logger must
still implement the full `Logger` contract
(`acquire`/`release`/`write`/`flush`) or the link error names an undefined
`_defmt_*` symbol rather than the cause.

### 4.7 The log ring is sized for a part four times this size

`wayfinder_log::ring::RING_CAPACITY` is a `cfg(target_os = "none")` constant of
64 records, ~240 bytes each, ~16 KiB — and its own doc comment reasons about
"256 KiB of RAM". That was right for the nRF and is a **quarter of all RAM** on
this part.

`target_os` is the wrong axis: it distinguishes bare metal from a host, and the
distinction that matters now is between two bare-metal boards that differ by 4×
in RAM. The ring is a `static` inside the crate, so the board cannot simply
instantiate a smaller one.

**Decision: a `build.rs` in `wayfinder-log` reads an environment variable
(`WAYFINDER_LOG_RING_CAPACITY`), defaulting to today's per-`target_os`
values.** A Cargo feature is the obvious alternative and is worse: features are
additive and unify across a dependency graph, so `ring-16` and `ring-64` in one
graph would silently resolve to whichever is a superset, and the axis is a
*quantity*, which features model badly. Each board being its own `[workspace]`
hides that hazard today rather than removing it. The variable is set in this
board's `.cargo/config.toml`, next to the other facts about how it is built,
and 16 records at 160-byte messages remain enough to carry a bring-up sequence.

The ring's own invariants and `GetLogs`'s batch-byte budget are unaffected —
only the capacity changes, and both are already written against the constant.

**Since then, `main` made the ring itself optional** (the `ring` feature), for
a board with no management API to serve `GetLogs` from. The two compose rather
than compete: the feature decides *whether* there is a ring, the variable *how
big* it is, and with the feature off the variable is inert. The relay takes
the ring off entirely — nothing on it can read one — which frees the 4,128
bytes this section budgeted; the management-port build turns it back on at 16
records.

### 4.8 Dual core: CM4 only, and the CM0+ is never released

`STM32WL55JC` has a Cortex-M4 and a Cortex-M0+. This firmware is **CM4 only**
(`embassy-stm32`'s `stm32wl55jc-cm4`, and `probe-rs`'s `cm4` core), and it
never sets `C2BOOT`. That is what makes §4.1's arithmetic legitimate: with the
CM0+ parked, the CM4 owns all 64 KiB rather than the 32 KiB SRAM1 it would keep
if the second core were brought up with SRAM2 assigned to it. The two banks are
contiguous (`0x20000000..0x20008000` and `0x20008000..0x20010000`), so
`memory.x` declares one `RAM : ORIGIN = 0x20000000, LENGTH = 64K`.

Writing this down because the failure mode is nasty: releasing the CM0+ later
for anything — even as an experiment — silently takes RAM this design has
already spent, and the symptom is a stack that overflows into statics on a part
whose `memory.x` still claims 64 KiB.

`flip-link` applies here for the same reason it does on the nRF (no MPU guard
region, so an overflow that reaches `.bss` corrupts it silently instead of
faulting), and it matters more: the stack margin in §4.1 is ~5 KiB, not tens.

### 4.9 The management port, and what it unlocks

Design 21 §1 kept the STM32 out of HIL scope for two reasons: no `probe-rs`
runner, and no management port. The runner is trivial
(`probe-rs run --chip STM32WL55JCIx`). The port is the real work, and on this
board it is unusually cheap: the onboard STLINK-V3E already presents a VCP at
`/dev/ttyACM0`, wired to a board UART. `wayfinder_server::serve` frames
requests over any `embedded_io_async` byte stream, so a plain `BufferedUart` is
a management port — **no USB device stack, unlike the nRF's `usb_mgmt`**, which
is a meaningful saving on both flash and RAM here.

Which UART the VCP lands on is **LPUART1, on PA2 (TX) / PA3 (RX) at 115200**.
Confirmed, not assumed: Zephyr's `boards/st/nucleo_wl55jc/nucleo_wl55jc.dts`
makes `&lpuart1` both `zephyr,console` and `zephyr,shell-uart` with
`pinctrl-0 = <&lpuart1_tx_pa2 &lpuart1_rx_pa3>`. The part also has `USART1`
and `USART2`, which reach the Arduino/Morpho headers rather than the ST-LINK.

**And the part has no USB at all** — no `USB` or `OTG` peripheral exists in
`stm32-metapac`'s `stm32wl55jc-cm4` PAC, so the nRF's CDC-ACM approach is not
merely unnecessary here, it is unavailable. That is a simplification rather
than a limitation: `wayfinder_client::Client::connect_serial` already speaks
the management protocol over a serial port, so a `BufferedUart` on LPUART1 is
a complete management port with no device stack, no descriptors, and no VBUS
handling.

`wayfinder-hil` then needs a `BoardKind::Stm32wl55Nucleo`, with
`chip() == "STM32WL55JCIx"` and `has_probe() == true`. One thing about this
board breaks an assumption the inventory currently encodes: **its probe and its
management port are the same USB device**, so `probe` and `usb` carry the
*same* serial (`003900314142500E20353451` on the bench part). The nRF DK's
`hil.toml` comment says the opposite for its own hardware — "the J-Link's two
CDC-ACM interfaces share one serial between them and are not the mgmt port" —
so that comment is about the DK, not a rule, and `example.hil.toml` should say
so. Nothing in `usb::match_device` needs to change: the STLINK-V3E presents
exactly one `ttyACM`, so the serial is unambiguous. It is the *documentation*
that would mislead the next person.

Design 21's `ProbeRequired` check still applies, and `usb` stays required —
this board has a management port, so it has no reason to relax that.

### 4.10 Identity, and the heap floor

The F411 has a compile-time `Mac` constant and no durable store (design 22
§6.3). This board should not repeat that: a node that cannot persist its
identity seed, its membership certificate and its clock checkpoint cannot
enroll, cannot renew (design 24), and re-derives a new identity on every reset.

`wayfinder-storage`'s `FlashStore` is the A/B two-page ping-pong, and
`embassy-stm32`'s `flash` module covers this family. STM32WL flash pages are
2 KiB, so the store costs two pages at the top of the 256 KiB region, and
`wayfinder_embedded_driver::identity` supplies the rest unchanged.

**Corrected by measurement:** the arithmetic below is sound but moot, because
the management path does not fit in this part's flash at all (§4.1's
correction). The 12 KiB figure was reached and the port built against it; the
image then overflowed flash by 28.1 KiB, with the heap accounting for 10 KiB of
a 12.2 KiB rise in statics. Treat the number as the *starting point for a
retry*, not a settled budget.

The heap floor follows from the management port rather than from choice:
`wayfinder_server::framing::MAX_FRAME_LEN` is 4 KiB and `serve` holds one
buffer per direction, so 8 KiB is pinned by a single session before any
response `Vec`. `wayfinder-nrf` allows 32 KiB for this; a 64 KiB part cannot,
and §4.1 budgets **12 KiB**. That is a deliberate squeeze on the same
allocator, and it is the row of the budget most likely to be wrong — which is
why `GetLogs`'s existing batch-byte budget matters here: the nRF's full-ring
`GetLogs` OOM is the exact shape of failure a smaller heap invites, and a
16-record ring (§4.7) cuts the response's worst case by 4× at the same time.

## 5. Correctness argument and edge cases

### 5.1 Nothing above `LinkT` can observe the new format

The load-bearing claim of §4.4 is that this link is substitutable for any
other. It holds because the bytes handed up are the same Ethernet-shaped
`[dst][src][protocol][payload]` content every carrier produces: `net_id`,
`src_id` and the fragment header are stripped on receive and never reach
`Received::frame`, and a frame is delivered only once fully reassembled.
`recv` therefore has the same contract as `rylr998`'s — it loops consuming
physical packets until *some* message completes, so a lone fragment buffers and
the loop continues rather than returning early or fabricating a short frame.
That loop is the one place a fragmenting link most easily goes wrong, and it is
tested by item 2 and item 4 of the test list.

### 5.2 The failure modes are bounded, and each degrades rather than corrupts

- **Reassembly table full** — oldest-first eviction. Costs completion rate,
  never correctness, and costs no memory because the table is fixed.
- **A fragment lost on air** — the message never completes and its slot is
  eventually evicted. LoRa has no retransmission here and `LinkT` is
  deliberately fire-and-forget (no TX-side ACK/retry in the trait), so a lost
  fragment is a lost frame, which is exactly what the routing layer above
  already tolerates from a lossy radio.
- **A duplicate fragment** — idempotent: it overwrites the same offset with
  the same bytes. `wayfinder-link-utils` already owns this.
- **`src_id` collision between two nodes** — interleaves two senders' bytes
  into one reassembly buffer. It cannot be detected from the air, so it is
  prevented by deployment rule rather than defended at runtime. **It costs
  dropped frames, never misattributed ones**, and that is the load-bearing
  part: the authenticated `Mac` travels *inside* the reassembled content, so a
  corrupted reassembly fails the `LinkFrame` parse or the signature check
  rather than arriving under the wrong sender. `libs/ieee802154` pins exactly
  this with `colliding_source_addresses_corrupt_rather_than_misattribute`, and
  this crate wants the same test under the same name (test 1).
- **A frame too large to fragment** — refused at `send` with `BufferFull`
  (test 5), never truncated. Truncation here would hand the router a frame that
  parses and lies.

### 5.3 The two silent-failure traps this board sets

Both are cases where a wrong value produces a *plausible-looking* node rather
than an error, which is why each gets a compile-time or gated check instead of
a comment:

- **`max_frame_len` below the link's reassembly ceiling** silently drops
  oversized frames — principally authenticated OGMs, so the node would look
  healthy and route nothing. A `const` assertion pins the two (§4.2), copying
  `wayfinder-nrf`'s.
- **A `memory.x` that does not match the part** links happily and faults at
  first use, or overflows into statics with no fault at all. This is precisely
  what happened to the F411 (§2.2) and what `stack-budget.py` failed to catch
  (§4.1). `flip-link` converts the overflow half into a deterministic fault;
  the region-vs-chip half wants the new gate in §9.

## 6. Security considerations

### 6.1 `net_id` is a filter, not a boundary

§4.4's one-byte `net_id` is trivially forgeable and is not defended. Mesh
membership is `wayfinder-auth`'s `MembershipCert` under a per-mesh trust
anchor, verified above `LinkT`, and nothing about this link changes that.
`net_id` exists so two co-located meshes do not fill each other's reassembly
tables; it must never be described as segregation.

### 6.2 Reassembly is attacker-reachable

`src_id`, `msg_id`, the fragment index and the count all arrive from the air
unauthenticated, and `MAX_REASSEMBLIES` is 4. An attacker within radio range
can open four bogus messages and hold every slot. That is the same exposure
`rylr998` and `ieee802154` already carry, mitigated the same way: oldest-first
eviction, so pressure costs completion rate rather than correctness, and a
fixed table so it costs no memory. Parse failures of air-supplied fragments are
`trace!`, never `warn!` — a malformed packet must not flood the ring, and on
this part the ring is 16 records.

### 6.3 Transmit is regulated, and this MR does not regulate it

868/915 MHz is duty-cycle limited (EU) or dwell-time limited (US), and nothing
in this design enforces either. The `Trickle` timer bounds OGM cadence for
routing's sake, not for compliance, and it is not a substitute. This is called
out rather than quietly inherited from `rylr998` (whose module did not enforce
it either): a bench node at low duty is fine, and anything deployed needs a
real airtime governor. A `LinkT` cannot be the place it lives — the trait is
deliberately fire-and-forget with no TX-side feedback — so it belongs beside
the Trickle schedule, as its own design.

### 6.4 The management port is unauthenticated

Unchanged and not made worse: the embedded serve path dispatches to
`handle_router` with no tier check (#59), so anyone with the cable can
`SetAuth`. This board adds one more part with that property, which is an
argument for #59 and not a new hole. The HIL harness drives it through
`wayfinder_client::Client`, so closing #59 stays a harness change rather than a
test rewrite.

## 7. Observability

RTT over the probe, as on the nRF, plus `GetLogs` over the management port —
which on this board is the more important of the two, since §2.3's SWD problem
shows how easily the probe path disappears. The `info!("build")` record
(design 23) is emitted before anything can fail, so a board that then halts
still says which firmware it is running.

Per CLAUDE.md's metrics rule, the radio's per-frame RSSI/SNR go into
`LinkMetrics` and therefore into the router's link-quality table, and are
readable through the existing `GetLinkQualityTable`. `lora-phy` reports both
for a received packet, so `quality` is left `None` and the engine derives the
score — deliberately, since a hand-rolled LQI mapping is exactly the
"normalized score, not a hardware reading" hazard `LinkMetrics::quality`
documents, and there is no datasheet-pinned mapping to justify one yet.

## 8. Alternatives considered

- **Hand-roll the SX126x command set.** Rejected. It is a large, well-trodden
  register surface, `lora-phy` is maintained by the same org as
  `embassy-stm32`, and the only genuinely board-specific part is the 6-method
  `InterfaceVariant` — which we write anyway. The `defmt` tax (§4.6) is a
  smaller cost than owning the command set.
- **An older `embassy-stm32` that still has `subghz`.** Rejected: it would pin
  this board to a version the other boards are moving off, to get a driver
  upstream deliberately dropped.
- **Put the WL55 radio behind the `rylr998` wire format** so the two LoRa links
  interoperate. Rejected in §4.4: it would inherit base64 and a 180-byte
  AT-line budget for no reason, and halve usable payload.
- **Retarget `bins/wayfinder-stm32f411` at the WL55.** Rejected. Different core
  count, memory map, radio and HAL config; the only shared line would be the
  `EmbassyClock`. The F411 crate earns its place as the external-module LoRa
  path and the non-Nordic proof.
- **A Cargo feature for the log ring size.** Rejected in §4.7 — features are
  additive, and this is a quantity.
- **Skip the management port, ship a radio-only relay** like the F411.
  Rejected: it is what keeps the STM32 out of HIL, it is cheap on this board
  (§4.9), and without a durable store and a management port the node cannot
  enroll or renew.

## 9. Decisions taken at proposal time

- **`opt-level="z"` + fat LTO is mandatory on this board**, not a tuning
  preference (§4.1). At default settings the image is 333 KiB against 256 KiB
  of flash.
- **`max_frame_len` stays 512** and is statically pinned to the link's
  reassembly ceiling (§4.2). RAM is found in the log ring instead.
- **The CM0+ is never released** (§4.8), because the RAM budget spends its bank.
- **A no-op `defmt` logger**, rather than `defmt-rtt` or a bridge (§4.6).
- **`fan_out` is not overridden**, matching all three existing radio drivers
  (§4.4).

### Genuinely open

- **The SWD failure (§2.3).** Everything on-silicon is blocked on it. Unknown
  whether it is the VMware USB passthrough this host runs behind (control
  transfers work — the probe's own version and serial read fine — while the
  bulk SWD path fails), the Anker hub in between, the STLINK-V3E's old **V3J7**
  firmware, or the board. The drag-and-drop volume is a flashing fallback but
  not an observability one, so it does not substitute.
- **`fan_out` across all four radio drivers.** A broadcast radio send looks
  like the `Some(1)` case, none of them declares it, and the method's own docs
  say it is dead weight until design 17 lands. Worth settling once, for all of
  them, rather than per driver.
- **How to fit the management port in 256 KB of flash — #75**, with
  #71 (the `flt2dec` waste below), #72 (routing core), #73 (crypto) and #74
  (async platform) under it. The single largest open question, since without
  the port this board cannot be reached by `libs/wayfinder-hil`, cannot be
  enrolled, cannot renew (design 24), and has no observability at all once SWD
  is unavailable — its state on the bench today.

  The gap is 28.8 KiB and splits into a bounded half and a decision:

  - **~13 KiB is recoverable waste** with a known cause and fix (#71).
    Necessary, and on its own not sufficient.
  - **The remaining ~16 KiB is a decision.** The cost is the protobuf
    dispatch — `handle_router` 13.3 KiB, `wayfinder_protos` 22.6 KiB, `prost`
    11.9 KiB — and trimming which request kinds a constrained board answers
    cuts against `rpc_table!`'s declare-once contract, where a kind missing
    from the table does not compile *deliberately*, so that a request cannot
    become silently unanswerable. Changing that is a change to a shipped
    crate's central invariant and **wants its own design doc**; #75 records it
    as unfiled.

- **What the durable store costs.** Design 22's flash A/B store plus identity
  persistence is the other thing this board needs to be a real mesh member
  (§4.10), and its footprint is **not measured**. Given the budget above, it
  should be measured before it is promised.

- **`flt2dec` in a router image** (~11 KiB of visible `.text`, plus more in the
  tail, plus 1.7 KiB of `<u128>::_fmt_inner`). **Cause now known**, and it is
  not a stray call site: `tracing_core::field::Visit` is used as `dyn Visit`,
  so the trait's *default* `record_f64`/`record_i128`/`record_u128` — which
  format via `Debug` — are in the vtable and cannot be stripped even though
  nothing in this firmware logs a float. `wayfinder-log` implements only
  `record_debug` and relies on those defaults (its `rtt.rs:172` comment says
  exactly that). Overriding the three on bare metal with integer-only
  rendering should reclaim it, and would shrink both nRF images too. Its own
  small MR, since it touches a crate every target links. **#71.**
- **Whether `stack-budget.py` should validate `memory.x` against the chip**
  (§4.1). It passed on an image whose stack top was past the end of RAM. This
  design wants that gate, and it is arguably its own small MR.

## 10. File map

| File | Change |
|---|---|
| `libs/lora-link/` | **new**, root member — the §4.4 wire format and fragmentation helpers. No `LinkT`, no radio dependency (§4.3) |
| `libs/lora-link/CLAUDE.md` | **new** — the driver-authoring guide, mirroring `libs/ieee802154/CLAUDE.md`, carrying §4.5's cancel-safety rule |
| `libs/lora-link/fuzz/` | **new** — `accept_fragment` over the air-facing boundary, mirroring `libs/ieee802154/fuzz` |
| `bins/wayfinder-wl55jc/` | **new workspace** — `memory.x`, `.cargo/config.toml`, profile, RF front-end, the `LinkT` over `lora-phy` + `Stm32wlInterfaceVariant`, the no-op `defmt` logger, the receive task (§4.5), mgmt arm, `FlashStore` |
| `libs/wayfinder-log/build.rs` | **new** — `WAYFINDER_LOG_RING_CAPACITY` (§4.7) |
| `libs/wayfinder-log/src/ring.rs` | `RING_CAPACITY` from the build script |
| `libs/wayfinder-hil/src/inventory.rs` | `BoardKind::Stm32wl55Nucleo`, `chip()`, `has_probe()` |
| `example.hil.toml` | a WL55 entry; correct the shared-serial comment (§4.9) |
| `justfile` | `build-wl55jc`, `clippy-wl55jc`, `stack-budget-wl55jc`, wired into `build-embedded` / `clippy-embedded` / `stack-budget` / `clean-embedded` |
| `.github/workflows/ci.yml` | the new crate in `build-embedded` and `build-stack-budget` |
| `CLAUDE.md` | the new crate and board in the architecture map |

### Failing tests to write first

Per CLAUDE.md this is test-first, and the board binary itself cannot be
host-tested (`test = false`, no linkable harness) — so the tests live in
`libs/lora-link`, which is where all the logic that can be wrong actually is.
Tests 1-8 are framing and need nothing but byte slices; test 9 belongs with the
`LinkT` impl in the board crate:

1. **`colliding_source_addresses_corrupt_rather_than_misattribute`** — same
   name as `libs/ieee802154`'s, because it is the same property: two `Mac`s
   sharing their low two bytes spoil each other's reassembly, and the result is
   a dropped frame rather than one attributed to the wrong sender (§5.2). The
   derivation itself matches `ieee802154::short_address_of`, so a node's radios
   agree on its short identity.
2. **A frame larger than one LoRa payload splits, and reassembles
   byte-identical** through the `wayfinder-link-utils` adapter.
3. **A fragment with a foreign `net_id` is dropped** and does not enter the
   reassembly table.
4. **Interleaved fragments from two `src_id`s reassemble independently**, the
   property the key exists for.
5. **A `MAX_REASSEMBLED_LEN + 1` frame is refused at `send`** with
   `BufferFull`, not truncated.
6. **Reassembly slot exhaustion evicts oldest-first** and keeps serving the
   newest sender (§6.2).
7. **`MAX_REASSEMBLED_LEN == profile::MAX_FRAME_LEN`** as a `const` assertion
   in the board crate, mirroring `wayfinder-nrf`'s (§4.2).
8. **RSSI/SNR reach `LinkMetrics` unscaled, with `quality: None`** (§7).
9. **`recv` resolves from the channel, not from the radio** — drop a `recv`
   future mid-frame and the next `recv` still yields that frame (§4.5). The one
   test here that is about *cancellation* rather than framing, and the one whose
   absence would let the trap in §4.5 back in silently.

None of these need hardware. What does is §9's open list, and it is
`libs/wayfinder-hil` that will ask for it.

## 11. Deviations taken during implementation

Recorded as the design is built, per `docs/design/README.md`.

- **`libs/sx126x-link` became `libs/lora-link`, and carries no `LinkT`.** §1
  first described a crate wrapping `lora-phy` behind a local `LoraRadio` trait.
  Reading `libs/ieee802154` settled it differently: that crate is framing-only
  and neither of its two radio adapters is in its dependency graph, and
  following that shape gets three things the original would not — `defmt` never
  enters the root workspace, the framing is host-testable against byte slices
  with no mock at all, and a second raw-LoRa radio costs an adapter rather than
  a refactor. The `LoraRadio` trait is gone with it: an abstraction over one
  implementation is a guess at where the next radio differs.

- **`src_id` is passed in, not derived.** §4.4 says the derivation matches
  `ieee802154::short_address_of`, and the first instinct was to call it. Design
  19 §11 had already settled where that function lives and why, and the
  STM32F411 already derives its RYLR998 address inline — so the board
  computes it and `lora-link` takes a `u16`, rather than a LoRa crate depending
  on an 802.15.4 crate for two lines of arithmetic.

- **Four hardware facts were wrong in the proposal and are corrected in the
  code.** Each is the kind that links cleanly and fails at runtime, which is
  why they are listed rather than quietly fixed:
  - **The target is `thumbv7em-none-eabi`.** This part's Cortex-M4 has no FPU.
    Both `embassy-stm32` and `stm32-metapac` map `stm32wl.*` to the soft-float
    triple; the proposal assumed the `eabihf` the other two boards use, which
    would HardFault on the first float. `flake.nix` and
    `containers/testenv.Dockerfile` gained the target.
  - **HSE is `Bypass`, not `Oscillator`,** and sysclk comes from the PLL
    (32/2×6/2 = 48 MHz) rather than straight off HSE. On this board HSE is fed
    by the radio's TCXO output, so driving it as a crystal oscillator leaves the
    clock dead — which looks like a board that hung in `init`.
  - **The board has a TCXO** (`tcxo_ctrl: Some(Ctrl1V7)`). The proposal guessed
    `None`, which leaves the radio with no reference.
  - **LD2 is PB9, not PB15.** This board has three user LEDs — LD1 blue on
    PB15, LD2 green on PB9, LD3 red on PB11 — so the first draft lit the blue
    one while its comment said green. The worst shape of wrong: the board
    looks like it booted, and a bench test passes.

  All four were settled against machine-readable sources rather than recall —
  `stm32-metapac`/`embassy-stm32`'s own target mapping for the FPU question,
  the `lora-rs` STM32WL example for the clocks and TCXO, and Zephyr's
  `boards/st/nucleo_wl55jc/nucleo_wl55jc.dts` for the LEDs and the console
  UART. Worth doing the same for anything else this board needs from UM2592.

- **`init_primary`, not `init`.** `embassy-stm32` has no single-core `init` for
  a dual-core part, so the CM4-only decision (§4.8) is not just a claim in a
  comment — it is in the API. The `SharedData` static it requires is a plain
  `.bss` static here, since nothing else ever reads it; that stops being true
  the day the CM0+ is released, and so does `memory.x`.

- **`lora-phy` needs a `SpiDevice`, and `new_subghz` gives a `SpiBus`.** §4.3
  named the `InterfaceVariant` as the glue and missed this second piece. On a
  discrete SX126x an `ExclusiveDevice` over an NSS pin fills the gap; here the
  chip-select is `PWR.SUBGHZSPICR.NSS`, so `src/spi_device.rs` is a small
  hand-written wrapper. Its error path is the load-bearing part — NSS must be
  deasserted even when an operation fails, or the next transaction runs as a
  continuation of the abandoned one and the radio reads the first byte as an
  opcode.

- **`stack-budget-wl55jc` ran at `--task-poll-pct 30`, not the 8% default; it
  now runs at 12%.** After the rebase onto `main` the `main` task's poll
  measures 2,788 bytes, not 6,820, and the stack region 37,968, so the justfile
  recipe carries the current numbers and a tighter share. The poll is reserved
  with Thumb-2 `subw`, which `stack-budget.py` reads as a zero-byte frame until
  MR !199 teaches it the encoding; before that lands, this board's gate
  measures only the radio task.
  What follows is the original reasoning, kept for the record.

- **Transmit goes through a queue to the radio task, not a `Mutex<LoRa>`** as
  §4.5 anticipated. A half-duplex radio parked inside `rx()` holds the radio,
  so a mutexed `send` would wait for a frame to arrive; the task instead races
  `rx()` against a depth-1 transmit queue (`radio.rs`'s module docs).

  This is the one gate that needed relaxing, so the reasoning is in the
  justfile recipe rather than only here. In short: the default is a *fraction*,
  and this board's stack region is ~30 KB against the nRF52840's ~122 KB — 8%
  is ~9.8 KB of absolute room there and ~2.5 KB here, so the same `main` task
  that passes comfortably on the nRF cannot fit on a part with a quarter of the
  SRAM. The frame did not grow; the denominator shrank.

  The body chain was checked, as `scripts/stack-budget.py` requires before
  raising the number: the two task polls reserve 6,820 + 980 = 7,800 bytes for
  the node's life, and the deepest transient chain above them is ~10.3 KB, for
  a peak near 18.1 KB of the 30,784-byte region — roughly 40% margin.

  **The real fix is not taken here.** `wayfinder-nrf` gets it for free: a
  `#[task]` in a *library* crate has its body outlined into
  `___run_task_inner_function0`, leaving the poll a trampoline of a few hundred
  bytes. Moving this board's mesh loop into its own task *inside the binary*
  was tried and made it worse — ~9.9 KB, plus the extra task pool cost region —
  because the outlining is a crate-boundary effect. It therefore waits
  for a board-support crate, which §4.3 argues should wait for a second STM32WL
  board.

- **Test 9 (cancel-safety) is not written.** §10 puts it with the `LinkT` impl,
  which lives in the board crate — and that crate cannot be host-tested
  (`test = false`, no linkable harness). So the property §4.5 exists to protect
  is currently held by construction and by documentation, not by a test. That
  is a real gap: it is the one defect in this board that would present as poor
  RF rather than as a failure. The honest options are an `embedded-test` target
  (design 21's Tier A, unbuilt) or moving the `LinkT` into a library crate —
  the same extraction the stack-budget deviation above wants.
