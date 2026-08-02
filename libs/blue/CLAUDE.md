# libs/blue

`LinkT` adapters carrying the mesh over Bluetooth Low Energy. Core is
`no_std`; each backend is behind its own off-by-default feature.

Connectionless BLE advertising broadcast only — no GATT, no connections —
matching the fire-and-forget `LinkT` model the other radio drivers here use.
`send` broadcasts a frame's fragments as short-lived non-connectable
advertisements; `recv` reassembles fragments observed by continuous passive
scanning. Fragmentation reuses the shared `wayfinder-link-utils` machinery
(see its `CLAUDE.md`), instantiated with a BLE advertiser address
(`BleAddr`) as the reassembly key — unlike RYLR998's 16-bit `AT+ADDRESS`,
this needs no deployment-time configuration, since BLE addresses are already
globally distinct per physical device and reported on every scan report.

## Three backends, one wire format

| | `NrfBleLink` (`hardware`) | `StdBleLink` (`std`) | `BleLink` via `android` |
|---|---|---|---|
| target | nRF52840, `no_std` | Linux host, tokio | Android host, tokio |
| stack | `nrf-softdevice` | BlueZ over D-Bus (`bluer`) | injected `BleAdvertiser`, UniFFI-backed |
| consumer | `bins/wayfinder-nrf52840` | `bins/wayfinder-tap` | `bins/wayfinder-pixel` |
| AD framing | built here (`ad.rs`) | built by BlueZ | built by platform |

They interoperate on-air, which is the point: a `wayfinder-tap` host can
front a terminal mesh of MCUs over BLE. `frame::build_fragment` produces the
`[frag_header][body]` blob both put on the air; the nRF path additionally
wraps it in this crate's own Manufacturer-Specific-Data framing
(`build_fragment_ad`), because it hands the radio a whole advertising-data
buffer, while BlueZ (and Android) build that structure themselves from raw
manufacturer-data bytes. **That asymmetry is the easiest thing to
get wrong here** — passing `build_fragment_ad`'s output to BlueZ
double-wraps the AD structure and the fragment never parses on the far side.
`frame.rs`'s `build_fragment_and_build_fragment_ad_agree_on_the_wire` test
pins the two paths together.

### `BleLink` is generic, not platform-hosted, itself (`src/generic_link.rs`)

`BleLink<A: BleAdvertiser>` doesn't drive any platform BLE API itself — it
takes the platform advertise call as a type parameter (`BleAdvertiser::
advertise`), and reads scan reports off a channel fed by a cloneable
`BleReportSink`. `StdBleLink` (`std` feature) is one concrete instantiation,
wrapping it with a `BleAdvertiser` that drives BlueZ; `bins/wayfinder-pixel`
(`android` feature, no `bluer`/D-Bus weight) is the other, wrapping it with a
`BleAdvertiser` bridged across a UniFFI boundary to a Kotlin-implemented
`BluetoothLeAdvertiser` binding — see that crate's `src/lib.rs`
(`PixelBleAdvertiser`, `MeshNode`) for the FFI side; the actual Android
`BluetoothLeAdvertiser`/scan-callback wiring on the Kotlin side is still a
later phase, only the UniFFI plumbing exists so far. This generic-over-
`BleAdvertiser` design is deliberate: it means both backends built on
`BleLink` — unlike `NrfBleLink` — are fully unit-tested against a fake
`BleAdvertiser`, with no real hardware/`bluetoothd`/JNI dependency at all.

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
- **`Privacy = device`.** Reassembly keys on the advertiser address
  (`FragKey`), so that address has to stay put for at least the time a frame
  spends on the air. Non-connectable advertising asks the kernel for privacy,
  and with no RPA configured it answers with a fresh *non-resolvable* private
  address per advertising session — and since `BluerAdvertiser::advertise`
  registers and tears down one advertisement per fragment, every fragment
  would leave under a different address and nothing would ever reassemble.
  `Privacy = device` moves it onto the RPA path, which holds one address for
  the rotation timeout (~15 min) instead. This is a deployment dependency
  accepted deliberately: the mesh owns every device it integrates with, so
  pinning host config is cheaper than spending payload bytes on a sender tag
  in the fragment header. It does not generalise — Android's
  `BluetoothLeAdvertiser` gives an app no control over the advertising
  address at all, so the planned pixel backend will have to revisit the
  keying rather than inherit this.

`advertise_dwell` (config: `advertise_dwell_ms`, default 150 ms) is the
airtime knob. It must outlast the controller's advertising interval — BlueZ's
default is ~100 ms, and this crate deliberately doesn't override it, since
the `MinInterval`/`MaxInterval` advertisement properties need BlueZ ≥ 5.56
plus controller support and registration fails outright without it. The cost
is paid per fragment: a frame takes `dwell × fragment_count`, up to 14
fragments.

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

## Hardware bring-up status

Nothing here has been validated against a real radio, on either backend —
treat every timing constant as a first guess.

**nRF (`src/nrf_link.rs`)**: exact `Softdevice::Config` role/connection-count
tuning (currently `Config::default()`), the scan interval constants, and
whether `ADV_EVENTS_PER_FRAGMENT` (4) advertising events at
`ADV_INTERVAL_625US` (20 ms) is enough for a passive scanner to reliably catch
every advertisement. **`ADV_INTERVAL_625US` is the value to watch first on
hardware**: 20 ms is the SoftDevice's documented `BLE_GAP_ADV_INTERVAL_MIN`,
but if the stack rejects it for non-connectable advertising the symptom is
`advertise` returning an error and the link transmitting nothing — fall back to
160 (100 ms), which is unambiguously valid for every advertising type.

**BlueZ (`src/std_link.rs`)**: whether the 150 ms default dwell actually
clears the controller's advertising interval; whether register/advertise/
unregister per fragment sustains a usable frame rate, or whether the D-Bus
round-trips dominate; and, above all, **whether the two backends really do
interoperate on the air** — the shared wire format is pinned by unit test,
but no nRF node and Linux node have yet exchanged a frame.

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
