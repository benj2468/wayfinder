# libs/blue

`LinkT` adapters carrying the mesh over Bluetooth Low Energy. Core is
`no_std`; each backend is behind its own off-by-default feature.

Connectionless BLE advertising broadcast only — no GATT, no connections —
matching the fire-and-forget `LinkT` model the other radio drivers here use.
`send` broadcasts a frame's fragments as short-lived non-connectable
advertisements; `recv` reassembles fragments observed by continuous passive
scanning. Fragmentation reuses the shared `wayfinder-link-utils` machinery
(see its `CLAUDE.md`), instantiated with the sender's own mesh `Mac` as the
reassembly key — **not** the medium-reported advertiser address, unlike
every other consumer of that crate. That's a deliberate departure: a `btmon`
capture against a real BlueZ controller showed the advertiser address
rotating on *every* advertising-set registration (new random address per
fragment, not per rotation timeout), so no multi-fragment message's
fragments ever shared one address. `frame::build_fragment` embeds the
sender's `Mac` in *every* fragment (`ORIGIN_LEN`, 6 bytes) rather than
relying on the address at all — costing some payload (`FRAG_PAYLOAD` drops
from 25 to 19 bytes) but making reassembly correct regardless of what the
medium's own address does. `BleAddr` (`addr.rs`) still exists for
diagnostics (logging, RSSI association) but is no longer load-bearing.

## Two backends, one wire format

| | `NrfBleLink` (`hardware`) | `StdBleLink` (`std`) |
|---|---|---|
| target | nRF52840, `no_std` | Linux host, tokio |
| stack | `nrf-softdevice` | BlueZ over D-Bus (`bluer`) |
| consumer | `bins/wayfinder-nrf52840` | `bins/wayfinder-tap` |
| AD framing | built here (`ad.rs`) | built by BlueZ |

They interoperate on-air, which is the point: a `wayfinder-tap` host can
front a terminal mesh of MCUs over BLE. `frame::build_fragment` produces the
`[frag_header][body]` blob both put on the air; the nRF path additionally
wraps it in this crate's own Manufacturer-Specific-Data framing
(`build_fragment_ad`), because it hands the radio a whole advertising-data
buffer, while BlueZ builds that structure itself from raw manufacturer-data
bytes. **That asymmetry is the easiest thing to get wrong here** — passing
`build_fragment_ad`'s output to BlueZ double-wraps the AD structure and the
fragment never parses on the far side. `frame.rs`'s
`build_fragment_and_build_fragment_ad_agree_on_the_wire` test pins the two
paths together.

### `BleLink` is generic, not platform-hosted, itself (`src/generic_link.rs`)

`BleLink<A: BleAdvertiser>` doesn't drive any platform BLE API itself — it
takes the platform advertise call as a type parameter (`BleAdvertiser::
advertise`), and reads scan reports off a channel fed by a cloneable
`BleReportSink`. `StdBleLink` (`std` feature) is the concrete instantiation,
wrapping it with a `BleAdvertiser` that drives BlueZ. This generic-over-
`BleAdvertiser` design is deliberate: it means `StdBleLink` — unlike
`NrfBleLink` — is fully unit-tested against a fake `BleAdvertiser`, with no
real hardware/`bluetoothd` dependency at all.

## BlueZ specifics (`src/std_link.rs`)

Non-obvious requirements, each of which silently yields a link that looks
alive but moves no traffic — or, worse, *some* traffic — if missed:

- **The advertisement handle must be held.** `bluer` unregisters an
  advertisement when its handle drops, so `send` sleeps for
  `advertise_dwell` before dropping it. Dropping it immediately (`let _ =`)
  registers and retires the advertisement without a single advertising event
  reaching the air.
- **Duplicates are filtered at two independent layers, and both must be
  disabled.** Getting one and not the other still loses every fragment after
  a peer's first.
  - *Controller layer* — needs the advertisement monitor (`mesh_monitor()`).
    The kernel runs its LE scan with the HCI `filter_duplicates` parameter
    disabled only while a monitor is active, and controllers deduplicate
    reports keyed on advertiser address without comparing the payload. Since
    a frame spans several fragments from one address, that costs whole frames
    rather than stray fragments. Confirm with `btmon`: read
    `Filter duplicates:` on the `LE Set Scan Enable` command.
  - *BlueZ layer* — needs `duplicate_data: true` on the `DiscoveryFilter`.
    This is still load-bearing and is **not** superseded by the monitor: it
    disables BlueZ's own suppression of repeated `ManufacturerData`, which is
    what makes the property change fire more than once per peer.
    `DiscoveryFilter` derives `Default`, so omitting the field leaves
    BlueZ-level filtering on.
- **Fragment bytes come from the property-change event, never a read-back.**
  `discover_devices_with_changes()` looks right and isn't: bluer discards the
  changed value and re-emits a bare `DeviceAdded`, so servicing it means
  asking BlueZ what the data is *now*. That samples current state instead of
  consuming what changed — with several fragments in flight from one peer it
  observes the latest blob repeatedly and never sees the earlier ones. Hence
  plain `discover_devices()` for the discovery signal plus a per-device
  `Device::events()` subscription for values, with a one-time read-back only
  to seed state predating the subscription.

Two host-side settings in `/etc/bluetooth/main.conf` (NixOS:
`hardware.bluetooth.settings`), neither of which this crate can supply for
itself:

- **`Experimental = true`** (or `bluetoothd --experimental`), BlueZ ≥ 5.55.
  `org.bluez.AdvertisementMonitorManager1` is gated behind it; without it
  `RegisterMonitor` fails with `org.freedesktop.DBus.Error.UnknownMethod` and
  the link runs degraded. `register_mesh_monitor` treats that as
  non-fatal-but-loud rather than tearing the link down. Note bluer issues
  `RegisterMonitor` inside `Adapter::monitor()`, *not* inside
  `MonitorManager::register()` — guarding only the latter still propagates
  the failure. Check with
  `busctl introspect org.bluez /org/bluez org.bluez.AdvertisementMonitorManager1`.
- **`Privacy = device` is no longer required for reassembly correctness**
  (though there's no reason to remove it either). It used to be: reassembly
  keyed on the advertiser address, so `Privacy = device` was needed to move
  address assignment onto the RPA path, which was expected to hold one
  address for the ~15-minute rotation timeout instead of drawing a fresh
  *non-resolvable* private address per advertising session. That expectation
  turned out to be wrong in practice — a `btmon` capture against a real
  controller, with `Privacy = device` correctly set, showed
  `BluerAdvertiser::advertise`'s one-registration-per-fragment pattern
  drawing a new random address on *every* registration anyway, not just
  every ~15 minutes. Every multi-fragment message's fragments went out under
  different addresses, 100% of the time, so reassembly could never complete.
  The fix (`frame::ORIGIN_LEN`) embeds the sender's own `Mac` in every
  fragment and keys reassembly on that instead, so the address's behavior —
  rotating per session, per registration, or not at all — no longer matters.

`advertise_dwell` (config: `advertise_dwell_ms`, default 150 ms) is the
airtime knob — how long each fragment's advertising set stays registered. It
must outlast the on-air advertising interval by enough to cover *several*
repeats, not just one. This crate explicitly requests a 20 ms interval
(`ADVERTISING_INTERVAL` in `std_link.rs`, `min_interval`/`max_interval` on
the `Advertisement`) rather than leaving it unset: left unset, BlueZ picks
its own default, measured via `btmon` against a real controller at **1280
ms** — an order of magnitude past `advertise_dwell`, which left most
fragments with exactly one on-air transmission before their advertising set
was torn down (confirmed by the `LE Advertising Set Terminated` event's
"Number of completed extended advertising events" field — 0 or 1, never
more), no redundancy against a scanner that isn't listening at that exact
moment. This was the actual cause of a real-world failure: two nRF52840
peers exchanged OGMs over BLE fine with each other, but neither ever
completed an OGM reassembly *from* a `wayfinder-tap` host on the same mesh,
while that host's own BLE receive path (decoding OGMs from the nRF peers)
worked perfectly — a one-directional TX-only defect, matching a sender that
gives the receiver a single, poorly-timed shot per fragment. Setting the
interval explicitly needs `MinInterval`/`MaxInterval` support (BlueZ ≥ 5.56
plus controller support); registration fails outright without it. The dwell
cost is paid per fragment either way: a frame takes `dwell × fragment_count`,
up to 14 fragments.

## Why `nrf-softdevice`, not `trouble-host`/`nrf-sdc`

This chip's BLE link layer (connection/advertising event timing, frequency
hopping, whitening, CRC, channel selection) has no open register-level
implementation — unlike 802.15.4 (`libs/nrf-ieee802154`), which `embassy-nrf`
implements directly, driving BLE on this chip requires one of Nordic's two
closed-source stacks: the classic monolithic "SoftDevice" (`nrf-softdevice`)
or the newer, more modular "SoftDevice Controller" + "Multiprotocol Service
Layer" (`nrf-sdc`/`nrf-mpsl`), paired with the pure-Rust `trouble-host` on
top.

`trouble-host` + `nrf-sdc` was the first choice (nicer async API, same
`embassy-rs` org as `trouble-host`), but building against it revealed a hard
blocker: `nrf-sdc`/`nrf-mpsl` 0.3.0 hard-pin `embassy-nrf 0.7` internally —
confirmed via `cargo tree -i embassy-nrf`, which showed both `0.7.0` and
`0.11.0` resolved in the same dependency graph. `embassy-nrf`'s peripheral
singleton/interrupt types are version-specific, and `embassy_nrf::init()` can
only run once per program per version, so there is no way to reconcile that
with the rest of this firmware's `embassy-nrf` version. `nrf-softdevice` has
**no `embassy-nrf` dependency at all** — it manages its own peripheral/
interrupt access directly — so it sidesteps the conflict entirely and needs
no `embassy-nrf` bump on the rest of the board's bring-up (only
`embassy-executor` needed bumping, to 0.10, matching what `blue`'s task
spawning needs).

## RADIO-peripheral exclusivity with `nrf-ieee802154`

`nrf-softdevice` claims the `RADIO` peripheral (and its interrupt) directly,
same as `libs/nrf-ieee802154`'s 802.15.4 mode. **This firmware can never run
both live at once** — not a blocker today, since `bins/wayfinder-nrf52840`
only wires up LoRa + BLE (`nrf-ieee802154` is linked purely to keep it
compiling for the real target, never instantiated) — but don't try to wire
both into `Driver::new`'s link array.

## On-air format (`src/ad.rs`)

Legacy (non-extended) BLE advertising caps total advertising data at 31
bytes — confirmed by reading `nrf-softdevice`'s own `advertise()` path, not
assumed; there was no path to extended advertising's larger per-PDU budget
without deeper, harder-to-verify-without-hardware changes, so this crate
accepts the 31-byte ceiling and fragments more aggressively than RYLR998
does (`FRAG_PAYLOAD` = 25 bytes here vs. RYLR998's 178).

Each advertisement carries one Manufacturer Specific Data AD structure
(`[len][0xFF][company_id: u16 LE][frag_header][body]`) tagged with
`ad::MESH_COMPANY_ID` (`0xFFFF` — the Bluetooth SIG's reserved
testing/no-vendor value, used here as a private marker, not a real vendor
registration) so the scan callback can cheaply discard ambient BLE traffic
before it ever reaches the reassembler.

## Building with the `hardware`/`std` features

`nrf-softdevice` (and `nrf-softdevice-s140`) link a precompiled Nordic
SoftDevice binary and only support real embedded targets — `cargo build -p
blue --features hardware` will fail on the host target; the feature is
off by default so this crate stays a normal, host-buildable/testable
workspace member (see `Cargo.toml`'s `[features]` comment). Unlike the
earlier `nrf-sdc`/`nrf-mpsl` attempt, neither crate has a `build.rs`/uses
`bindgen` — `LIBCLANG_PATH` is not needed here; `cargo build -p blue
--target thumbv7em-none-eabihf --features hardware` builds with no extra
environment setup.

`std` is the mirror image: `bluer` needs `libdbus` at build time and a live
`bluetoothd` at run time, so it too stays off by default. `cargo build -p
blue --features std` is the host build `wayfinder-driver` uses. **Keep
`anyhow` (and anything else `std`-by-default) behind this feature** — it is
an unconditional dependency here that broke the firmware build once already.

## Testability: `src/frame.rs` vs. the backends

`send`'s frame assembly, fragment-count computation, and per-fragment
AD-structure building are pure logic with no `nrf-softdevice` (or BlueZ)
dependency — split into `src/frame.rs` (not gated behind either feature,
unit-tested on host same as `ad.rs`/`addr.rs`) so they aren't stranded
untested behind a feature gate along with the actual radio I/O.
`src/nrf_link.rs` and `src/std_link.rs` are then just the async glue calling
into `frame::`.

Neither backend's I/O is unit-tested: one needs the SoftDevice on real
silicon, the other a live `bluetoothd` on the system bus. Anything that
*can* be pulled into `frame.rs`/`ad.rs` should be, rather than being written
inline in a link and going untested.

Note `ad.rs` and `frame::build_fragment_ad` carry
`#[cfg_attr(not(feature = "hardware"), allow(dead_code))]` — they are the
self-framing path, reached only by the nRF backend and by tests, so a plain
host build would otherwise warn on all of it.

## `unsafe impl Send`/`Sync` are single-core/single-executor assumptions

`src/nrf_link.rs`'s `SdHandle` (`&'static Softdevice`) and `ReportQueue`
(`NoopRawMutex`-backed `Channel`) both opt back into `Send`/`Sync` (required
by `LinkT: Send`) on the grounds that this firmware runs one embassy
executor on one Cortex-M core, so there's never a second real thread to race
against. That's true today, but the type system can't check it — if this
crate is ever ported to a multi-core target or driven by more than one
executor, both `unsafe impl`s become unsound with no compiler diagnostic.
Re-audit them specifically if that ever changes.

## Detaching a debug probe trips a SoftDevice assert

Measured on an nRF52840-DK running `bins/wayfinder-nrf52840`: **disconnecting
`probe-rs` while the SoftDevice's radio is live reliably panics the board** with
`NRF_FAULT_ID_SD_ASSERT` via `nrf-softdevice`'s `fault_handler` ("Softdevice
assertion failed … Most common cause is disabling interrupts for too long"),
faulting PC inside the SoftDevice image (below `0x27000`). Tearing the debug
session down clears `C_DEBUGEN`/`DEMCR`, dropping the chip out of Debug
Interface Mode, and the SoftDevice notices a missed radio deadline.

Attaching is fine — a probe held attached indefinitely causes no trouble, and
`probe-rs reset` followed by a detach also survives, because the SoftDevice is
not enabled until several seconds into boot. It is specifically **detaching from
a running radio** that faults. probe-rs's default reset/hardfault vector catch
is not involved (`--no-catch-reset --no-catch-hardfault` changes nothing).

Two traps this sets:

* The symptom is identical to the *other* SD_ASSERT cause — masking the
  SoftDevice's reserved interrupts, e.g. by registering
  `cortex-m/critical-section-single-core` instead of
  `nrf-softdevice/critical-section-impl` (see the note in
  `bins/wayfinder-nrf52840/Cargo.toml`). Before debugging a fault, establish
  whether the board also dies when *no probe is involved* — reset it, leave it
  alone, and read the log ring afterwards. If it only dies around probe
  detach, the code is not at fault.
* A reattach that shows *nothing at all* is a board already halted in a panic
  whose message was printed once and drained by the previous session — not a
  live-but-quiet board. Reset before concluding anything from silence.

`bins/wayfinder-nrf52840`'s `#[panic_handler]` reboots (with a reset-surviving
consecutive-panic count that halts after three) rather than halting, so this is
survivable on a deployed node. The way to sidestep it entirely is to read logs
over the USB management port — `wayfinderctl --serial /dev/ttyACMX logs
--follow` — which also works after a fault, unlike the probe.

## Hardware bring-up status

Nothing here has been validated against a real radio, on either backend —
treat every timing constant as a first guess.

**nRF (`src/nrf_link.rs`)**: exact `Softdevice::Config` role/connection-count
tuning (currently `Config::default()`), `SCAN_INTERVAL_625US`/
`SCAN_WINDOW_625US`, and whether `ADV_EVENTS_PER_FRAGMENT` (4) advertising
events at `ADV_INTERVAL_625US` (20 ms) is enough for a passive scanner to
reliably catch every advertisement. **`ADV_INTERVAL_625US` is the value to
watch first on hardware**: 20 ms is the SoftDevice's documented
`BLE_GAP_ADV_INTERVAL_MIN`, but if the stack rejects it for non-connectable
advertising the symptom is `advertise` returning an error and the link
transmitting nothing — fall back to 160 (100 ms), which is unambiguously valid
for every advertising type.

**Scanning and advertising contend for the same radio, and it's easy to starve
one of them entirely.** `ScanConfig::default()`'s `interval`/`window` (2732/500
in 625µs units) duty-cycle scanning to ~18%, which reads as "we scan for a bit
then go quiet" — not tied to `send()` at all, just the receive window closing
on its own schedule. The fix is *not* to set `window == interval` for
literally continuous scanning: that leaves the SoftDevice's radio scheduler no
gap to service any other role, and `send`'s `peripheral::advertise` starts
failing every call with `AdvertiseError::Raw(RawError::Resources)` (SoftDevice
docs on `sd_ble_gap_adv_start`: "Not enough BLE role slots available. Stop one
or more currently active roles ... and try again") — perfect RX, zero TX. This
is easy to miss on a noisy build: heavy unfiltered `log`-crate output from
`nrf-softdevice` itself (see `libs/wayfinder-embedded-log`) can slow the scan
callback's `sd_ble_gap_scan_start` resume enough to leave the SoftDevice
incidental gaps, masking the starvation until that logging is quieted down.
Current values (`SCAN_INTERVAL_625US` = 180, `SCAN_WINDOW_625US` = 160, ~90%
duty cycle) clear this on the one board tested so far, but — like every other
constant in this section — are a first guess, not a validated tuning; if
`send()` starts failing with `Resources` again, widen the gap (lower the
window relative to the interval) before anything else.

**BlueZ (`src/std_link.rs`)**: whether register/advertise/unregister per
fragment sustains a usable frame rate, or whether the D-Bus round-trips
dominate, is still unvalidated (though `btmon` captures below show fragments
routinely getting 34-42 completed advertising events within a 150 ms dwell,
so registration latency clearly isn't the bottleneck it might have been).
**Whether the two backends interoperate on the air** was chased through two
root causes before landing on the real one:

1. Two nRF52840 peers and a `wayfinder-tap` host shared one mesh; both nRF
   peers routed to each other and to the host fine, but the host never
   completed an OGM reassembly *from* either nRF peer despite decoding OGMs
   *from* both of them correctly (its scan/receive path was never the
   problem). First suspect: BlueZ was defaulting to a 1280 ms advertising
   interval (unset `MinInterval`/`MaxInterval`) against a 150 ms dwell, so
   most fragments got exactly one on-air transmission before teardown and
   some got zero — fixed by setting both to 20 ms explicitly
   (`ADVERTISING_INTERVAL`, matching `nrf_link.rs`'s own cadence).
2. That fix alone didn't resolve it. A follow-up `btmon` capture (all other
   mesh nodes powered off, to rule out cross-attribution) showed every
   fragment now getting 30-42 completed advertising events — reliable
   transmission — yet reassembly still never completed. The actual cause:
   every 2-fragment OGM's two fragments went out under two *different*
   random advertiser addresses, 100% of the time (7 of 7 OGMs captured),
   because `BluerAdvertiser`'s one-registration-per-fragment pattern draws a
   fresh RPA on every registration regardless of `Privacy = device` or the
   ~15-minute rotation timeout. Reassembly keyed on that address
   (`FragKey`), so no multi-fragment message could ever complete — see the
   `Privacy = device` bullet above for the full history.

Fixed by no longer trusting the medium's address at all: `frame::ORIGIN_LEN`
embeds the sender's own `Mac` in every fragment, and reassembly keys on that
instead (`frame::parse_fragment_with_origin`). Costs some payload
(`FRAG_PAYLOAD` 25 → 19 bytes, `MAX_REASSEMBLED_LEN` 350 → 280) but makes
reassembly correct regardless of what BlueZ's RPA does. Not yet re-confirmed
on real hardware after this fix — the next real-mesh test should watch for a
nRF peer completing a `discovered new originator` for the BlueZ host's
identity.

A `send` occupies the driver's event loop for `dwell × fragment_count` on both
backends — the same "slow link stalls the loop" property the LoRa link has —
but the two dwells differ by an order of magnitude, so quote them separately:

| backend | per-fragment dwell | full-size frame (14 fragments) |
|---|---|---|
| nRF | ~80 ms (4 events × 20 ms) | ~1.1 s |
| BlueZ | 150 ms (`advertise_dwell`) | ~2.1 s |

If that turns out to hurt in practice, the fix is in the driver's scheduling,
not here. Note the nRF figure is only this small because `max_events` is set:
leaving it unset makes the SoftDevice advertise unlimited events and the
`timeout` backstop becomes the sole bound, which at a 1 s backstop is ~14 s
per frame.
