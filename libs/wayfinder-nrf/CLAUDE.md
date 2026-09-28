# CLAUDE.md — nRF52840 board support

Guidance for the nRF52840 firmware: this crate plus the board binaries that
consume it, `bins/wayfinder-nrf52840` (DK, PCA10056) and
`bins/wayfinder-nrf52840-dongle` (PCA10059).

## What goes where

A board binary owns only what is genuinely board-specific:

| Board-owned | Shared here |
| --- | --- |
| `memory.x` and the two constants tracking it (`DURABLE_STORE_BASE`, `RAM_ORIGIN`) | `fault` — panic/HardFault handling, the retained fault record |
| LED pin | `stack` — high-water painting and reporting |
| `bind_interrupts!` | `identity` — the durable node record: a seed minted from the RNG, the MAC derived from it, and the FICR board id |
| `.cargo/config.toml` runner | `link` — the `MeshLink` 802.15.4/USB/absent enum |
| | `usb_mgmt` — the USB device: CDC-ACM management port + the shared `Builder` |
| | `usb_link` — the CDC-NCM mesh interface |
| | `node::run` — the whole bring-up sequence |
| | `init_platform`, the capacity profile, the heap |

**Anything a third board would also need belongs here, not in a `main.rs`.** The
two boards existing is the forcing function: a behaviour that lives in one
binary is a behaviour the other silently lacks.

## Adding a board

1. Copy `bins/wayfinder-nrf52840-dongle` — it is the smaller of the two.
2. Write `memory.x`, then set `DURABLE_STORE_BASE` and `RAM_ORIGIN` to match it.
   Both are checked only by the comments next to them; getting `RAM_ORIGIN`
   wrong silently disables stack measurement rather than failing. **`RAM_ORIGIN`
   is not automatically `0x20000000`** — a board that boots through Nordic's
   MBR must leave its first 8 bytes alone (see "Board differences"). **`RAM_ORIGIN`
   is not automatically `0x20000000`** — a board that boots through Nordic's
   MBR must leave its first 8 bytes alone (see "Board differences").
3. Fix the LED pin and the `.cargo/config.toml` runner.
4. Add the build and clippy lines to `.github/workflows/ci.yml`'s `build-embedded`.

Nothing else should need touching. If it does, that is a sign the thing you are
reaching for should move into this crate first.

## Board differences

|  | DK (PCA10056) | Dongle (PCA10059) |
| --- | --- | --- |
| Liveness LED | `P0_13`, active-low | `P0_06`, active-low (`P0_13` is not routed) |
| App flash | `0x0..0xFE000` (1016K) | `0x1000..0xDE000` (884K) |
| Identity store | `0xFE000` | `0xDE000` |
| Mesh address | the seed's `derived_mac()`, persisted since design 22 | same |
| USB serial | the FICR board id — **not** the mesh MAC | same |
| Low flash | free (app starts at 0) | MBR, `0x0..0x1000`, required by the bootloader |
| RAM origin | `0x20000000` | `0x20000008` — the MBR's IRQ-forward address sits below it |
| RAM origin | `0x20000000` | `0x20000008` — the MBR's IRQ-forward address sits below it |
| High flash | free | Open Bootloader + MBR params/settings, `0xE0000..0x100000` reserved |
| Debug probe | onboard | SWD pads only |
| Logs | RTT or USB | **USB only** |

Neither runs a SoftDevice, so nothing reserves 13112 bytes below the
application any more — that was the S140's measured `wanted_app_ram_base`.

**The RAM origins still differ between the boards, and not by much: 8 bytes.**
The dongle boots via the MBR, which keeps its interrupt-forwarding address in
the first 8 bytes of RAM; that address is how an application above the MBR
receives interrupts at all with no SoftDevice present. `flip-link` puts the
*stack* at the bottom of RAM, so a dongle built at `0x20000000` has
`stack::paint` overwrite it during boot and the board HardFaults on its first
interrupt, reboots, and halts with LD1 dark and no USB. The DK has no MBR —
its application is at `0x0` — so it is genuinely `0x20000000`.

This is not hypothetical: it is what the dongle did, and it is invisible to
every host test, to clippy, to the cross-compile and to `just stack-budget`
(which checks that the stack *fits*, not what lives underneath it). See
design 19 §12.1.

**Flash origins now differ between the boards**, which they did not before.
The DK links from 0 because `probe-rs` writes wherever the image says. The
dongle links from 0x1000 because the Open Bootloader depends on the MBR in the
bottom 4 KiB and, finding no SoftDevice, places an application directly above
it (`nrf_dfu_bank0_start_addr()` in the nRF5 SDK returns `MBR_SIZE`).
`runner.sh`'s `--sd-req 0x00` is the other half of that pairing — see
"Flashing".

The dongle's flash reservation is deliberately conservative — the Open
Bootloader is smaller than 128K, but its exact extent depends on the build the
board shipped with. Under-reserving corrupts the DFU path that is the only way
to reflash a dongle without a probe. Flashing over SWD and dropping the
bootloader frees the whole top 128K, in which case the dongle can use the DK's
layout.

The dongle has no 32.768 kHz crystal. `init_platform` therefore leaves
`lfclk_source` at `embassy-nrf`'s `InternalRC` default. **Setting
`LfclkSource::ExternalXtal` would hang the dongle at boot** waiting for a
crystal that is not fitted, while leaving the DK working — the classic
one-board-only failure here.

HFCLK is the opposite: `init_platform` explicitly selects `ExternalXtal`,
which `embassy-nrf` does *not* default to. Both boards have the 32 MHz
crystal, and both the `RADIO` peripheral and USBD require it — the radio is
only specified running from the HFXO. The SoftDevice used to start it on
demand; nothing does now unless `init_platform` says so.

## Flashing

The DK, over its onboard debugger — one command, nothing to stage first:

```bash
cd bins/wayfinder-nrf52840 && cargo run --release
```

There used to be a `probe-rs download` of `s140_nrf52_7.3.0_softdevice.hex`
before this, once per board. It is not needed and not wanted: the image links
from 0 and simply overwrites any S140 left there.

The dongle has no onboard debugger. With an SWD probe on the pads the flow is
identical. Without one, it is DFU over the Open Bootloader: hold the reset
button until LD2 pulses red, then `cargo run --release` in
`bins/wayfinder-nrf52840-dongle`, which drives `runner.sh`. Note that DFU is
what the reserved high flash exists for — see above.

`runner.sh` does three things: `rust-objcopy` the given ELF straight to
`.hex` (**not** `cargo objcopy`, which reinvokes `cargo build` under its own
default *dev* profile and objcopies that instead, silently ignoring the actual
release binary it was handed — this was the first thing that made every early
flash unbootable, well before the addressing bug below); `nrfutil
nrf5sdk-tools pkg generate` to build a signed-less DFU `.zip` with
`--sd-req 0x00` ("no SoftDevice"; it was `0x123`, S140 7.3.0's documented
firmware ID from `nrfutil nrf5sdk-tools pkg generate --help`'s
well-known-values table, while the app linked above an S140); then `nrfutil
device program --firmware *.zip --traits nordicDfu` to flash it. A raw `.hex`
can't go straight to `nrfutil device program` for a USB/`nordicDfu` device —
that path only accepts `.hex` over `jlink`/`mcuBoot` traits, neither of which
this board has; it needs the `.zip`.

**`--sd-req` must agree with `memory.x`, and the pairing inverted.** The
bootloader computes the app's placement itself at flash time
(`nrf_dfu_bank0_start_addr()` in `nRF5_SDK`) from whatever SoftDevice it
currently finds valid; `sd_req` only names the requirement, it does not
declare an address. So:

- **Now**: `--sd-req 0x00` + `FLASH : ORIGIN = 0x00001000`. The bootloader
  erases any S140 it still finds and places the app just above the MBR.
- **Before**: `--sd-req 0x123` + `ORIGIN = 0x00027000`, placing the app above
  a SoftDevice it was told to keep.

Mixing the halves is the failure this note exists for. `0x123` with the
current `memory.x` places a 0x1000-linked image at 0x27000; `0x00` with the
old one wipes the SoftDevice the image expected to sit above. Both brick the
board until the next DFU. Omitting `--sd-req` entirely (as `nrfdfu-rs` does —
tried and abandoned, see below) behaves like `0x00` on the builds tested, but
is left explicit rather than relied on.

`nrfutil-nrf5sdk-tools` (the package-generation extension) isn't published by
Nordic for `aarch64-linux` — check `pkgs/by-name/nr/nrfutil/source.nix` in
nixpkgs before assuming it's just a `withAllExtensions` wiring gap. `flake.nix`
runs the real `x86_64-linux` build under `qemu-user` for that one step
(`nrfutilNrf5sdkTools` in `perSystem`) — the same trick already used for
x86_64-only Android NDK/SDK binaries on this project's `aarch64` devShell.
Only package *generation* is emulated; `nrfutil device program` itself runs
natively, since `nrfutil-device` is published for `aarch64-linux`.

`nrfdfu-rs` (`overlay/pkgs/nrfdfu.nix`, removed) was tried first: it takes an
ELF directly with no packaging step, but always sends `FwType::Application`
with no `sd_req` at all — see the `--sd-req` note above for what that does.
Patching its `sd_size` field first seemed promising but doesn't help:
`sd_size` is only consulted for `Softdevice`/`SoftdeviceAndBootloader`
transfers, never for a plain `Application` one — `sd_req` is the field that
actually matters here. `nrfdfu --get-images` is still a handy read-only
diagnostic if `nrfdfu` ever gets reinstated for that alone.

## The USB mesh link

USB carries two independent functions on **one** device: the CDC-ACM management
port and a CDC-NCM mesh interface. That is why `usb_mgmt::init` builds both and
returns both — there is a single `embassy_usb::Builder`, and `UsbMgmt::run`
drives the device stack that the mesh link also depends on. **The link is dead
whenever `UsbMgmt::run` is not being polled**, which is not obvious from the
link's own API.

The host side needs no new code. `LinkFrame` is byte-for-byte an Ethernet frame,
so the board puts frames on the wire verbatim and `wayfinder-tap`'s existing
raw-L2 carrier binds straight to the NIC that appears:

```yaml
- transport: !RawL2
    interface: wf-usb0
    ethertype: 0xfafa
```

Three things here fail silently:

- **That `ethertype` must equal `usb_link::MESH_ETHERTYPE`.** It is a wire
  transport label, deliberately not the mesh protocol (`0x4305`), so the link can
  share a NIC with the host kernel's own IPv6 solicitations and mDNS — which do
  arrive and are dropped. Mismatch it and both ends come up healthy while no
  frame is ever accepted.
- **`UsbNcmLink::rx_buf` must stay `MAX_LINK_FRAME_LEN`.** `Receiver::read_packet`
  copies the datagram in with no length check of its own, so anything larger than
  the buffer panics inside `embassy-usb`. The host picks that length (it brings
  the interface up at MTU 1500); the only bound is the 2048-byte NTB, which is
  what `MAX_LINK_FRAME_LEN` matches. Shrinking it to the profile's smaller
  `max_frame_len` puts a full-size host frame one hop from rebooting the node.
- **Two CDC functions is exactly `embassy-usb`'s default `MAX_INTERFACE_COUNT`
  of 4.** A third function needs the `max-interface-count-6` feature. This one at
  least panics in the builder rather than truncating the descriptor.

The link is point-to-point and wired, so it gets the tighter Trickle schedule of
the two interfaces (`node::TRICKLE`) — there is no airtime budget to respect.

## The management port is unauthenticated, and that is the decision

`usb_mgmt::init` brings the CDC-ACM management port up **unconditionally**,
whenever USB init succeeds. There is no feature flag and no config gate, and
the embedded serve path dispatches straight to `handle_router` with no tier
check — so the whole request surface, `SetAuth` and `SetTime` included, is
available to anything that can open `/dev/ttyACM*`. Since design 22 a board
supplies a `SettingsStore`, so a credential written over that port is
*durable*: the cable changes the node's identity permanently, not until the
next reset.

**This is the accepted posture (GitLab #57, design 06 F7), not a gap to
re-file.** The port is USB on a board in someone's hand: whoever can reach it
is standing next to the device, and on these boards that also means an SWD
header that reads flash outright. A gate would not move that boundary, and it
would cost the two things this port is for — the dongle has no probe header, so
`GetLogs` over this port is the only way its logs are read, and
`libs/wayfinder-hil` reaches every board through it. A board also has no config
file, so "opt-in" could only mean a compile-time feature baked into the shipped
image, leaving the operator holding the cable as the one person unable to
change it.

Two consequences to keep in mind when working here:

- **Do not add a request to the embedded surface on the assumption that
  something upstream checks who is asking.** Nothing does. The tier model in
  `wayfinder-protos`'s `rpc.rs` governs the TLS transport; the serial path does
  not consult it.
- **A management transport with no physical precondition does not inherit this
  answer.** Mgmt-over-BLE (the parked plan) or a board with an IP stack must
  bring its own authentication — there the attacker need not be in the room,
  which is the entire basis of the decision above.

## A fault reboots; it does not halt

Both `#[panic_handler]` and the `HardFault` handler print, then reset. They halt
only after `MAX_CONSECUTIVE_FAULTS` (3) in a row.

**Both also retain what killed the board across the reset**, in `.uninit` — the
HardFault its registers (`FAULT_RECORD`), a panic its rendered text
(`PANIC_MSG`) — and `report_retained` re-emits either as `error!` on the next
boot, early enough that nothing pushes it out of the log ring:

```
wayfinderctl --serial /dev/serial/by-id/usb-Wayfinder_*-if00 logs | \
  grep 'previous boot ended in'
```

This is the only diagnostic path a dongle has. The `rprintln!` in each handler
reaches an RTT channel that needs an attached probe, and attaching one is itself
a documented cause of faults here (see below). Without the retained record a
panic reset the node leaving no evidence anywhere — indistinguishable, from the
host, from a power glitch or a USB teardown.

The retained panic text is capped at `PANIC_MSG_LEN` (120 bytes), sized so it
survives `wayfinder-log`'s 160-byte `MESSAGE_CAP` once the event's own text and
the `detail="…"` wrapper are accounted for. A longer panic message loses its
tail, not its location prefix.

This is deliberate and the reasoning is not obvious. A node that halts is dead —
no mesh, no RTT, no USB management port — until someone power-cycles it, which
is the worst failure mode available to hardware deployed where nobody is
holding a probe. Not every fault here is the node's own doing either (see the
next section). A reset costs a few seconds instead. The counter is the other
half: a fault that recurs every boot is a bug to read off the probe, and a board
reboot-looping through it is harder to observe than one sitting still.

Two consequences when debugging:

- If a reattach shows **no output at all**, that is a board spinning in a halted
  fault — the message was printed once and already drained. Reset it rather
  than attaching to a corpse.
- `mark_boot_healthy` is called once the run loop is reached, so everything that
  fails deterministically during bring-up (identity load, radio bring-up, USB)
  still latches the counter and eventually halts.

## Detaching a debug probe used to crash the board

**This was a SoftDevice property and should be gone with it. It is recorded
because the symptom is distinctive, and because "it stopped happening" is
worth being able to attribute.**

Disconnecting `probe-rs` while the SoftDevice's radio was live reliably tripped
a SoftDevice timing assert: `NRF_FAULT_ID_SD_ASSERT` through
`nrf-softdevice`'s `fault_handler` — the "Softdevice assertion failed … Most
common cause is disabling interrupts for too long" panic — with the faulting PC
inside the SoftDevice image (below `0x27000`), not in any code in this repo.
Tearing the debug session down clears `C_DEBUGEN`/`DEMCR`, drops the chip out of
Debug Interface Mode, and the SoftDevice noticed it had missed a radio deadline.

What was measured on a DK at the time, to save the next person the evening:

- Reset and left alone with no probe at all — ran indefinitely.
- Probe attached continuously — ran indefinitely; attaching was harmless.
- `probe-rs attach` then Ctrl+C — asserted every time, identical faulting PC.
- `--no-catch-reset --no-catch-hardfault` — no difference; probe-rs's default
  vector catch was not the cause.
- `probe-rs reset` then detach — survived, because the SoftDevice was not
  enabled until ~4s into boot and there was no live radio to disturb yet.

There is no SoftDevice and no `NRF_FAULT_ID_SD_ASSERT` now, so **a crash on
probe detach today is a new bug, not this one** — `embassy-nrf`'s radio driver
has no deadline to miss in the same way. Unverified on hardware.

**Reading logs over the USB management port is still the better habit**, and on
a dongle it is the only option:

```bash
wayfinderctl --serial /dev/ttyACMX logs --follow
```

That works while detached, and it works *after* a fault, which a probe does
not.

## Things that fail silently

Five coupled facts, each of which breaks something without a compile error:

- **`flip-link` is load-bearing, not a nicety.** It puts the stack below the
  statics. Without it the descending stack runs into `.uninit` — where the
  retained fault record lives — then `.bss`. `stack::paint` detects the layout
  at runtime and disables itself rather than corrupting memory, but the fault
  record has no such guard.
- **`RAM_ORIGIN` cannot come from a linker symbol.** `flip-link` rewrites the
  `MEMORY` block, so by the final link `ORIGIN(RAM)` equals `_stack_start`. A
  symbol defined from it collapses the measured region to nothing and painting
  silently stops. It has to be a constant next to `memory.x`.
- **`critical-section-single-core` is now the right impl, and used to be
  forbidden.** Its `acquire` is a bare `cpsid i`, masking everything. While the
  SoftDevice owned RADIO/RTC0/TIMER0 at priority 0/1 that starved the radio —
  this firmware takes a critical section on every log record and every heap
  allocation — and the SoftDevice tripped its assert intermittently once the
  run loop started logging. The compatible impl then came from
  `nrf-softdevice/critical-section-impl`, which masked only non-reserved IRQs.
  With no SoftDevice there are no reserved interrupts to starve, so the plain
  single-core impl is both correct and the only one left. If a second impl ever
  enters the graph, both call `critical_section::set_impl!` and the link fails
  rather than silently picking one.
- **A board spawns `node::run` itself; never a local `#[task]` that awaits
  it.** `.await`ing a foreign `async fn` makes its future a field of the outer
  coroutine, and rustc builds it in a stack temporary and `memcpy`s it in — a
  temporary the outer poll frame reserves for as long as the task lives, not
  just for the copy. `run`'s future is ~62 KB, and with `flip-link` the stack
  is only what `memory.x` leaves after the statics (112,600 bytes on the DK).
  That copy plus `run`'s own frame (~28 KB) plus `Driver::with_capacities`'
  (~26 KB) came to 117,376 and ran off the bottom of RAM into the SoftDevice's
  then-reserved region, which trapped as `NRF_FAULT_ID_APP_MEMACC`. What that
  looked like was a node logging a clean bring-up through the radio's
  "link brought up" line and then stopping, with the panic only readable on the
  *next* boot out of `fault::report_retained`. The 13112 bytes are back, so the
  stack region is now ~124 KB rather than 112,600 and that exact sum no longer
  overflows. Read the current figure off `just stack-budget` rather than
  trusting one written down here — it moves whenever a static does — but the
  mechanism is unchanged and `just stack-budget` is what actually holds the
  line. `run` is therefore the `#[embassy_executor::task]`,
  and since a task cannot be generic the board's `USBD` binding reaches it as
  the `fn` pointer `usb_mgmt::UsbDriverFactory`. Two rules follow: keep
  `bind_interrupts!` in the board binary (a `Binding` impl is not a symbol, so
  a handler defined in the library rlib can be dropped by the linker), and
  measure with `rust-objdump -d | grep 'sub.*sp'` rather than assuming — the
  three frames above are the whole budget and are easy to grow by accident.
- **`rtt-target` must stay on one version.** The panic handler writes to the
  channel `wayfinder_log::init()` already set up. A second version pulls in a
  second RTT control block and the panic messages go nowhere.

## Peripheral ownership

Nothing is reserved. The SoftDevice used to claim RADIO, RTC0, TIMER0, POWER,
CLOCK, RNG, ECB, CCM_AAR, TEMP and SWI5_EGU5, and most of the awkwardness in
this crate descended from that list. What is left of it:

- **UARTE0, TIMER1 and the PPI channels are free.** They carried a RYLR998
  LoRa module, which these boards no longer link: the radio was never used in
  practice, and dropping it took 17,236 bytes of flash and 16,756 of `.bss`
  (the `MeshLink` enum was sized by its RYLR variant, so the whole link array
  shrank). `libs/rylr998` is unchanged and still carries
  `bins/wayfinder-stm32f411`.
- USB VBUS state is read straight off `POWER` by `HardwareVbusDetect`, and the
  HF crystal is started once by `init_platform`. Both used to be SoftDevice
  syscalls — see `usb_mgmt`.
- `init_platform` leaves interrupt priorities at `embassy-nrf`'s defaults. It
  used to force GPIOTE, RTC1, UARTE0 and USBD to `P2`, because the SoftDevice
  reserved levels 0 and 1 and refused to enable if anything was already there.
- **`blue`'s BLE link and `nrf-ieee802154` both want RADIO and remain mutually
  exclusive.** These boards wire 802.15.4. `NrfBleLink` is not linked by any
  board any more; `just build-loose-drivers` cross-compiles it so it does not
  rot. The host (BlueZ) half of `blue` is unaffected and still carries
  `bins/wayfinder-tap`'s BLE links.

See `docs/design/19-ieee802154-nrf-link.md` for why the boards moved.
