# CLAUDE.md — nRF52840 board support

Guidance for the nRF52840 firmware: this crate plus the board binaries that
consume it, `bins/wayfinder-nrf52840` (DK, PCA10056) and
`bins/wayfinder-nrf52840-dongle` (PCA10059).

## What goes where

A board binary owns only what is genuinely board-specific:

| Board-owned | Shared here |
| --- | --- |
| `memory.x` and the two constants tracking it (`DURABLE_STORE_BASE`, `RAM_ORIGIN`) | `fault` — panic/HardFault handling, the retained fault record |
| LED and UART pins | `stack` — high-water painting and reporting |
| `bind_interrupts!` | `identity` — FICR-derived MAC + flash persistence |
| `.cargo/config.toml` runner | `link` — the `MeshLink` LoRa/BLE/absent enum |
| | `usb_mgmt` — the CDC-ACM management port |
| | `node::run` — the whole bring-up sequence |
| | `init_platform`, the capacity profile, the heap |

**Anything a third board would also need belongs here, not in a `main.rs`.** The
two boards existing is the forcing function: a behaviour that lives in one
binary is a behaviour the other silently lacks.

## Adding a board

1. Copy `bins/wayfinder-nrf52840-dongle` — it is the smaller of the two.
2. Write `memory.x`, then set `DURABLE_STORE_BASE` and `RAM_ORIGIN` to match it.
   Both are checked only by the comments next to them; getting `RAM_ORIGIN`
   wrong silently disables stack measurement rather than failing.
3. Fix the LED pin, the two UART pins and the `.cargo/config.toml` runner.
4. Add the build and clippy lines to `.gitlab-ci.yml`'s `build:embedded`.

Nothing else should need touching. If it does, that is a sign the thing you are
reaching for should move into this crate first.

## Board differences

|  | DK (PCA10056) | Dongle (PCA10059) |
| --- | --- | --- |
| Liveness LED | `P0_13`, active-low | `P0_06`, active-low (`P0_13` is not routed) |
| RYLR998 UART | `P0_02` RX / `P0_26` TX | `P0_31` RX / `P0_29` TX (castellated edge) |
| App flash | `0x27000..0xFE000` (860K) | `0x27000..0xDE000` (732K) |
| Identity store | `0xFE000` | `0xDE000` |
| High flash | free | Open Bootloader + MBR params/settings, `0xE0000..0x100000` reserved |
| Debug probe | onboard | SWD pads only |
| Logs | RTT or USB | **USB only** |

Both run S140 7.3.0 with the same `nrf_softdevice::Config::default()`, so the
RAM reservation (13112 bytes) is identical. If one moves, both move.

The dongle's flash reservation is deliberately conservative — the Open
Bootloader is smaller than 128K, but its exact extent depends on the build the
board shipped with. Under-reserving corrupts the DFU path that is the only way
to reflash a dongle without a probe. Flashing over SWD and dropping the
bootloader frees the whole top 128K, in which case the dongle can use the DK's
layout.

The dongle has no 32.768 kHz crystal. This costs nothing today because
`nrf_softdevice::Config::default()` passes a null `p_clock_lf_cfg`, which the
SoftDevice documents as "RC source with `rc_ctiv = 16`, `rc_temp_ctiv = 2`".
**Setting an explicit LFXO clock config would break the dongle** while leaving
the DK working.

## Flashing

The DK, over its onboard debugger — the SoftDevice first, once per board:

```bash
probe-rs download --chip nRF52840_xxAA --binary-format hex \
  bins/wayfinder-nrf52840/s140_nrf52_7.3.0_softdevice.hex
cd bins/wayfinder-nrf52840 && cargo run --release
```

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
`--sd-req 0x123` (S140 7.3.0's documented firmware ID, from `nrfutil
nrf5sdk-tools pkg generate --help`'s well-known-values table); then `nrfutil
device program --firmware *.zip --traits nordicDfu` to flash it. A raw `.hex`
can't go straight to `nrfutil device program` for a USB/`nordicDfu` device —
that path only accepts `.hex` over `jlink`/`mcuBoot` traits, neither of which
this board has; it needs the `.zip`.

**`--sd-req` is not optional.** Omitting it (as `nrfdfu-rs` does — tried and
abandoned, see below) makes the Nordic bootloader conclude the app doesn't
depend on a SoftDevice and **erase it** before placing the app at `0x1000`
instead of `0x27000` — corrupting the SoftDevice and misplacing the app (which
is linked, per `memory.x`, to run from `0x27000`) in one step. The bootloader
computes the app's actual placement itself at flash time
(`nrf_dfu_bank0_start_addr()` in `nRF5_SDK`), from whatever SoftDevice it
currently finds valid — `sd_req` only has to name it correctly, not declare an
address.

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

## A fault reboots; it does not halt

Both `#[panic_handler]` and the `HardFault` handler print, then reset. They halt
only after `MAX_CONSECUTIVE_FAULTS` (3) in a row.

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
  fails deterministically during bring-up (SoftDevice RAM sizing, identity load,
  USB) still latches the counter and eventually halts.

## Detaching a debug probe crashes the board, and that is expected

**Disconnecting `probe-rs` while the SoftDevice's radio is live reliably trips a
SoftDevice timing assert.** It surfaces as `NRF_FAULT_ID_SD_ASSERT` through
`nrf-softdevice`'s `fault_handler` — the "Softdevice assertion failed … Most
common cause is disabling interrupts for too long" panic — with the faulting PC
inside the SoftDevice image (below `0x27000`), not in any code in this repo.
Tearing the debug session down clears `C_DEBUGEN`/`DEMCR`, drops the chip out of
Debug Interface Mode, and the SoftDevice notices it missed a radio deadline.

This is a property of the SoftDevice, not a bug here. What was measured on a DK,
to save the next person the evening:

- Reset and left alone with no probe at all — runs indefinitely.
- Probe attached continuously — runs indefinitely; attaching is harmless.
- `probe-rs attach` then Ctrl+C — asserts every time, identical faulting PC.
- `--no-catch-reset --no-catch-hardfault` — no difference; probe-rs's default
  vector catch is not the cause.
- `probe-rs reset` then detach — survives, because the SoftDevice is not enabled
  until ~4s into boot and there is no live radio to disturb yet.

**The way to avoid the whole interaction is not to attach a probe.** Read the
log ring over the USB management port instead:

```bash
wayfinderctl --serial /dev/ttyACMX logs --follow
```

That works while detached, and it works *after* a fault, which the probe does
not. On a dongle it is the only option.

## Things that fail silently

Four coupled facts, each of which breaks something without a compile error:

- **`flip-link` is load-bearing, not a nicety.** It puts the stack below the
  statics. Without it the descending stack runs into `.uninit` — where the
  retained fault record lives — then `.bss`. `stack::paint` detects the layout
  at runtime and disables itself rather than corrupting memory, but the fault
  record has no such guard.
- **`RAM_ORIGIN` cannot come from a linker symbol.** `flip-link` rewrites the
  `MEMORY` block, so by the final link `ORIGIN(RAM)` equals `_stack_start`. A
  symbol defined from it collapses the measured region to nothing and painting
  silently stops. It has to be a constant next to `memory.x`.
- **Never enable `critical-section-single-core`.** Its `acquire` is a bare
  `cpsid i`, masking the SoftDevice's reserved RADIO/RTC0/TIMER0 interrupts.
  This firmware takes a critical section on every log record and every heap
  allocation, so the radio starves and the SoftDevice trips its assert
  intermittently once the run loop starts logging. The compatible impl is
  `nrf-softdevice/critical-section-impl`. Both call `critical_section::set_impl!`,
  so enabling the wrong one fails to link — that is the only reason this is
  recoverable.
- **`rtt-target` must stay on one version.** The panic handler writes to the
  channel `wayfinder_log::init()` already set up. A second version pulls in a
  second RTT control block and the panic messages go nowhere.

## Peripheral ownership

The SoftDevice claims RADIO, RTC0, TIMER0, POWER, CLOCK, RNG, ECB, CCM_AAR,
TEMP and SWI5_EGU5. Consequences already encoded in the code:

- `BufferedUarte` uses **TIMER1**, not TIMER0, for its RX idle-gap detection.
- USB VBUS state and the HF crystal are reached through SoftDevice syscalls
  rather than the `POWER`/`CLOCK` registers — see `usb_mgmt`.
- `init_platform` drops GPIOTE, RTC1, UARTE0 and USBD to priority `P2`. The
  SoftDevice reserves levels 0 and 1 and rejects `sd_softdevice_enable()`
  outright if anything is already enabled there.
- `blue`'s BLE link and `nrf-ieee802154` both want RADIO and are mutually
  exclusive. These boards wire BLE.
