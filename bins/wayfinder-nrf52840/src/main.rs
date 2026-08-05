//! nRF52840-DK firmware: run the wayfinder mesh router on bare metal over
//! connectionless BLE advertising broadcast (the chip's built-in 2.4GHz
//! radio) and, if one happens to be wired up, a RYLR998 LoRa module on a
//! UART.
//!
//! This wires the board's concrete pieces to the HAL-agnostic
//! [`wayfinder_embedded_driver::Driver`]: [`blue::NrfBleLink`] (see
//! `libs/blue/CLAUDE.md`) adapts the SoftDevice-driven radio into the mesh
//! [`LinkT`], [`rylr998::RylrClient`] does the same for the LoRa module's
//! AT-command protocol over a [`BufferedUarte`], and an `embassy-time`-backed
//! [`Clock`] paces the OGM timer. Both interfaces are dispatched through the
//! board-local [`MeshLink`] enum, since [`Driver`] takes one concrete link
//! type. The embassy thread-mode executor drives the driver's `async` loop
//! forever.
//!
//! The management API is served over the chip's **USB device peripheral** as a
//! CDC-ACM port (see [`usb_mgmt`]), so the node is inspectable with
//! `wayfinder-tui`/`wayfinderctl --serial` over the board's own USB connector.
//! This replaces the second UART on the DK's onboard-debugger VCOM lines that
//! used to carry it: USBD needs no GPIOs and no debug probe, which is what makes
//! the same firmware serviceable on an nRF52840 dongle.
//!
//! # Detaching a debug probe crashes this board, and that is expected
//!
//! **Disconnecting `probe-rs` while the SoftDevice's radio is live reliably
//! trips a SoftDevice timing assert.** It surfaces as
//! `NRF_FAULT_ID_SD_ASSERT` through `nrf-softdevice`'s `fault_handler` — the
//! "Softdevice assertion failed … Most common cause is disabling interrupts
//! for too long" panic — with the faulting PC inside the SoftDevice image
//! (below `0x27000`), not in any code in this repo. Tearing the debug session
//! down clears `C_DEBUGEN`/`DEMCR` and drops the chip out of Debug Interface
//! Mode, and the SoftDevice notices it missed a radio deadline.
//!
//! This is a property of the SoftDevice, not a bug here. What was measured on
//! an nRF52840-DK, to save the next person the evening:
//!
//! * Reset and left alone with no probe at all — runs indefinitely.
//! * Probe attached continuously — runs indefinitely; attaching is harmless.
//! * `probe-rs attach` then Ctrl+C — asserts every time, identical faulting PC.
//! * `--no-catch-reset --no-catch-hardfault` — makes no difference; probe-rs's
//!   default vector catch is not the cause.
//! * `probe-rs reset` then detach — survives, because the SoftDevice is not
//!   enabled until ~4 s into boot and there is no live radio to disturb yet.
//!
//! Two consequences worth knowing. First, [`panic`] reboots rather than halting
//! precisely so this is survivable: a node that halted here would sit dead —
//! no mesh, no RTT, no USB management port — until power-cycled. Second, if a
//! reattach shows *no output at all*, that is a board still spinning in a
//! halted panic (the message was printed once and already drained), not a
//! silent board — reset it rather than attaching to a corpse.
//!
//! The way to avoid the whole interaction is not to attach a probe: read the
//! log ring over the USB management port instead, with `wayfinderctl --serial
//! /dev/ttyACMX logs --follow`. That path works while detached, and it works
//! *after* a fault, which the probe does not.
//!
//! [`BufferedUarte`]: embassy_nrf::buffered_uarte::BufferedUarte
//! [`LinkT`]: wayfinder::link::LinkT

#![no_std]
#![no_main]

use blue::NrfBleLink;
use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_nrf::Peri;
use embassy_nrf::bind_interrupts;
use embassy_nrf::buffered_uarte;
use embassy_nrf::buffered_uarte::BufferedUarte;
use embassy_nrf::gpio::Level;
use embassy_nrf::gpio::Output;
use embassy_nrf::gpio::OutputDrive;
use embassy_nrf::interrupt::InterruptExt;
use embassy_nrf::interrupt::Priority;
use embassy_nrf::nvmc::Nvmc;
use embassy_nrf::nvmc::{self};
use embassy_nrf::pac::Interrupt;
use embassy_nrf::peripherals;
use embassy_nrf::uarte::Baudrate;
use embassy_nrf::uarte::Config as UarteConfig;
use embassy_nrf::uarte::Parity;
use embassy_nrf::usb;
use embassy_time::Duration as EmbassyDuration;
use embassy_time::Instant;
use embassy_time::Timer;
use embedded_alloc::LlffHeap as Heap;
use embedded_io_async::Read;
use embedded_io_async::Write;
use nrf_softdevice::SocEvent;
use nrf_softdevice::Softdevice;
use rylr998::Bandwidth;
use rylr998::CodingRate;
use rylr998::LoraError;
use rylr998::RylrClient;
use rylr998::SpreadingFactory;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;
use wayfinder::config::KeepAliveConfig;
use wayfinder::config::LinkFeatures;
use wayfinder::interfaces::frame::LinkFrameData;
use wayfinder::interfaces::frame::Mac;
use wayfinder::interfaces::link::LinkError;
use wayfinder::link::LinkT;
use wayfinder::link::Received;
use wayfinder_server::EmbeddedQueryChannel;

mod usb_mgmt;

wayfinder::define_profile! {
    /// This board's capacity profile.
    ///
    /// The routing core's tables are const-generic so a node sizes them to the
    /// mesh it actually serves rather than to a Linux gateway's. Two figures
    /// here are derived from hardware and must not be raised casually:
    ///
    /// - `interfaces: 2` is exactly this board's link count (LoRa + BLE).
    /// - `max_frame_len: 512` is the largest frame either link can deliver —
    ///   `rylr998`'s reassembly caps at 512 bytes and `blue`'s at 350, so
    ///   nothing longer can arrive. Lowering it below 512 would silently drop
    ///   reassembled LoRa frames.
    ///
    /// The rest are sized for the handful-of-nodes mesh this board joins, with
    /// headroom: `originators` and `ident_table` must stay powers of two.
    pub nrf52840 {
        originators: 32,
        interfaces: 2,
        mcast_members: 16,
        local_mcast: 4,
        ident_table: 32,
        ident_live: 24,
        link_quality: 32,
        neighbor_keys: 16,
        revoked: 8,
        in_flight_cert_requests: 4,
        pending_replies: 4,
        max_frame_len: 512,
    }
}

use wayfinder_embedded_driver::Clock;
use wayfinder_embedded_driver::Driver;
use wayfinder_embedded_driver::TrickleParams;
use wayfinder_embedded_driver::identity::IDENTITY_READ_BUF_LEN;
use wayfinder_embedded_driver::identity::IdentityError;
use wayfinder_embedded_driver::identity::load_or_init_identity;
use wayfinder_storage::FlashStore;

use crate::usb_mgmt::on_soc_event;

#[global_allocator]
static HEAP: Heap = Heap::empty();

/// Consecutive panics tolerated before the handler stops rebooting and halts
/// instead. Three is enough for a transient fault to clear and few enough that
/// a deterministic one settles quickly.
const MAX_CONSECUTIVE_PANICS: u32 = 3;

/// Roughly how long the panic handler holds the CPU before resetting, so a probe
/// that is attached has time to drain the message out of the RTT buffer (which
/// does not survive the reset). Cycles rather than a `Timer`: the executor is
/// gone by now and `embassy-time` cannot be awaited from a panic handler.
const PANIC_DRAIN_CYCLES: u32 = 2 * 64_000_000;

/// Panic bookkeeping that survives a soft reset, so the handler can tell a
/// one-off fault from a fault it is about to reboot into forever.
///
/// Layout: the high 24 bits are [`PANIC_GUARD_MAGIC`], the low 8 the count.
///
/// **`.uninit` is the whole mechanism, not a detail.** A `static` anywhere else
/// — behind a lock, an atomic, anything — sits in `.bss`/`.data` and is zeroed
/// or re-initialized by `cortex-m-rt` on *every* boot, including the reset this
/// handler itself triggers; the count would never exceed 1 and a deterministic
/// panic would reboot-loop forever. `.uninit` is excluded from that startup
/// zeroing (it begins exactly at `__ebss`), and nRF52 RAM holds its contents
/// across a `SYSRESETREQ` as long as power does. The cost is that after a
/// power-on the bytes are genuinely garbage — hence the magic, without which
/// garbage resembling a large count would halt on the first panic after
/// power-up instead of recovering.
///
/// An `AtomicU32` keeps every access safe: the section makes the initializer
/// below dead (`.uninit` is `NOLOAD`), and load/store are calls the compiler
/// will not speculate, duplicate, or fold — the guarantee `read_volatile` would
/// give, without `unsafe` or pointer casts. `Relaxed` because there is no
/// concurrency to order against: one executor, one core, and the only writer
/// besides [`mark_boot_healthy`] is a panic handler that never returns. A lock
/// would be worse than useless here — `critical_section` on this board is
/// `nrf-softdevice`'s impl, so taking one inside a panic handler is the very
/// interrupt-starving path that produces these faults, and an already-borrowed
/// guard would panic *inside* `#[panic_handler]`.
///
/// Scalar rather than a two-field struct: LLVM splits struct globals into
/// per-field globals when every access is field-wise, which would move the magic
/// out into `.bss`, zero it each boot, and silently degrade the guard to "always
/// reset, never halt".
#[unsafe(link_section = ".uninit.PANIC_GUARD")]
static PANIC_GUARD: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Marks [`PANIC_GUARD`] as ours rather than post-power-on garbage. Arbitrary,
/// but not a value RAM is likely to hold by accident (`b"WAF"`).
const PANIC_GUARD_MAGIC: u32 = 0x5741_4600;

/// Selects the magic half of [`PANIC_GUARD`].
const PANIC_GUARD_MAGIC_MASK: u32 = 0xFFFF_FF00;

/// Selects the count half of [`PANIC_GUARD`], and is also the count's
/// saturation point — it only ever has to distinguish "below
/// [`MAX_CONSECUTIVE_PANICS`]" from "at or above".
const PANIC_GUARD_COUNT_MASK: u32 = 0x0000_00FF;

/// Declare this boot healthy, resetting the consecutive-panic count.
///
/// Called once the node is far enough along that a panic from here on is a
/// runtime fault worth rebooting out of, rather than a bring-up failure that
/// would recur identically on the next boot. Everything that panics
/// deterministically on this board — `sd_ble_enable` sizing against `memory.x`,
/// identity load, USB bring-up — happens before this point, so those still
/// latch the counter and halt after [`MAX_CONSECUTIVE_PANICS`].
fn mark_boot_healthy() {
    PANIC_GUARD.store(PANIC_GUARD_MAGIC, core::sync::atomic::Ordering::Relaxed);
}

/// Record one more panic and return the resulting consecutive count (1 for the
/// first panic since the last healthy boot, or since power-on).
fn bump_panic_count() -> u32 {
    let stored = PANIC_GUARD.load(core::sync::atomic::Ordering::Relaxed);
    // A mismatched magic means power-on garbage rather than a count this
    // handler wrote, so treat it as the first panic.
    let count = if stored & PANIC_GUARD_MAGIC_MASK == PANIC_GUARD_MAGIC {
        ((stored & PANIC_GUARD_COUNT_MASK) + 1).min(PANIC_GUARD_COUNT_MASK)
    } else {
        1
    };
    PANIC_GUARD.store(
        PANIC_GUARD_MAGIC | count,
        core::sync::atomic::Ordering::Relaxed,
    );
    count
}

/// Prints the panic message over RTT, then reboots the node — or halts, once
/// [`MAX_CONSECUTIVE_PANICS`] reboots in a row have failed to clear the fault.
///
/// Rebooting is the important half. A mesh node's faults are not all its own
/// fault: detaching a debug probe while the SoftDevice's radio is live trips its
/// timing assert (`NRF_FAULT_ID_SD_ASSERT`) through `nrf-softdevice`'s
/// `fault_handler`, and a node that halted there would sit dead — no mesh, no
/// RTT, no USB management port — until someone power-cycled it. That is the
/// worst failure mode available to a node deployed where nobody is holding a
/// probe. A reset costs a few seconds of downtime instead.
///
/// Halting after repeated panics is the other half: a fault that recurs every
/// boot (a mis-sized SoftDevice RAM region, say) is a bug to be read off the
/// probe, and a node reboot-looping through it is harder to observe than one
/// sitting still with its message in the RTT buffer.
///
/// Writes to the print channel `wayfinder_log::init()` already set
/// up for `tracing`'s output, rather than opening a second RTT channel — the
/// two must therefore stay on the same `rtt-target` version (see this crate's
/// `Cargo.toml`). If a panic happens before that `init()` call, the message
/// is silently dropped (per `rtt_target::rprintln!`'s documented behavior).
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let count = bump_panic_count();

    // `rprintln!` runs its format string through `concat!`, so implicitly
    // captured identifiers are not available — every value is positional.
    rtt_target::rprintln!("panic ({}/{}): {}", count, MAX_CONSECUTIVE_PANICS, info);

    if count >= MAX_CONSECUTIVE_PANICS {
        rtt_target::rprintln!(
            "panic: {} consecutive panics; halting",
            MAX_CONSECUTIVE_PANICS
        );
        loop {
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
    }

    rtt_target::rprintln!("panic: resetting");
    // Let an attached probe drain RTT — the buffer does not survive the reset.
    cortex_m::asm::delay(PANIC_DRAIN_CYCLES);
    cortex_m::peripheral::SCB::sys_reset()
}

/// Bytes reserved for `alloc`. Two users share it: `tracing-core`'s bookkeeping
/// and the USB management server's per-request buffers.
///
/// Sized against `wayfinder_server::framing::MAX_FRAME_LEN` (4 KiB): `serve`
/// holds one in-flight buffer per direction, so a single management session can
/// pin up to 8 KiB in framing buffers alone; this leaves ~24 KiB of headroom for
/// the `RouterAdapter` response `Vec`s a query itself builds plus tracing's
/// bookkeeping — tiny against the part's 256 KiB SRAM. Grow both constants
/// together if a real routing-table response ever gets close to the cap.
const HEAP_SIZE_BYTES: usize = 32 * 1024;

/// LoRa network id shared by every node in this mesh (RYLR `AT+NETWORKID`).
const LORA_NETWORK_ID: u8 = 18;

/// How many `AT` ping attempts (1s timeout each) to make before concluding no
/// RYLR998 module is wired to this UART and continuing BLE-only, rather than
/// blocking boot forever waiting for a reply that will never come. ~3s total:
/// long enough to cover the module's own boot delay, short enough not to
/// stall a BLE-only board noticeably.
const RYLR_PING_ATTEMPTS: u32 = 3;

/// Base flash offset of the durable identity store: the two 4 KiB pages at the
/// very top of flash that `memory.x` carves out of the `FLASH` region so the
/// linker leaves them free. `FlashStore` uses them as its A/B ping-pong pair.
/// **Must stay consistent with `memory.x`'s reservation** — see the comment
/// there.
const DURABLE_STORE_BASE: u32 = (1024 * 1024) - 2 * nvmc::PAGE_SIZE as u32;

/// Derive this node's mesh MAC from the nRF52840's factory-programmed FICR
/// device ID.
///
/// The device ID is a per-chip unique 64-bit value burned in at manufacture,
/// so the derived address is **stable across reboots even before it is
/// persisted** and **distinct between physical boards** with no provisioning
/// step — which is why a flash-persist failure is recoverable rather than
/// fatal (the same MAC is re-derived next boot). The top octet is forced to a
/// locally-administered unicast value: the L/A bit (`0x02`) set, the I/G
/// multicast bit (`0x01`) cleared. Each physical node therefore also gets a
/// distinct RYLR `AT+ADDRESS` (derived from the low octets), keeping the RYLR
/// reassembler from cross-contaminating fragments (see `libs/rylr998/CLAUDE.md`)
/// on boards that have a module attached.
fn ficr_derived_mac() -> Mac {
    let ficr = embassy_nrf::pac::FICR;
    let lo = ficr.deviceid(0).read().to_le_bytes();
    let hi = ficr.deviceid(1).read().to_le_bytes();
    let mut octets = [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1]];
    octets[0] = (octets[0] & 0xFE) | 0x02;
    Mac(octets)
}

// Bind the UARTE0 (RYLR998, if attached) interrupt to the buffered-UARTE
// handler so the driver's async serial reads/writes are woken by hardware
// rather than polled, and USBD's to the USB device stack that carries the
// management API (see `usb_mgmt`). UARTE1 carried the management link over the
// DK's VCOM lines until USB replaced it, and is now unbound.
bind_interrupts!(struct Irqs {
    UARTE0 => buffered_uarte::InterruptHandler<peripherals::UARTE0>;
    USBD => usb::InterruptHandler<peripherals::USBD>;
});

/// An `embassy-time`-backed [`Clock`] for the embedded driver: the monotonic
/// RTC1 tick (via the `time-driver-rtc1` feature) is the clock the router ages
/// routes and paces OGM emission against.
struct EmbassyClock;

impl Clock for EmbassyClock {
    fn now(&self) -> core::time::Duration {
        core::time::Duration::from_micros(Instant::now().as_micros())
    }

    async fn sleep(&self, duration: core::time::Duration) {
        Timer::after(EmbassyDuration::from_micros(duration.as_micros() as u64)).await;
    }
}

/// Dispatches `LinkT` across this board's mesh interfaces. `wayfinder_embedded_driver::Driver<L, C, N>`
/// takes a fixed `[L; N]` of one concrete link type; this is the
/// "board-defined `enum` dispatching across mixed media" its doc comment
/// anticipates.
#[expect(clippy::large_enum_variant, reason = "typed instead of boxed")]
enum MeshLink<S> {
    /// The RYLR998 LoRa module, over the UART carrying its AT-command
    /// protocol.
    Rylr(RylrClient<S>),
    /// Connectionless BLE advertising broadcast over the chip's built-in
    /// radio.
    Ble(NrfBleLink),
    /// No RYLR998 module was detected at boot on this slot's UART. Unlike a
    /// genuine link fault, an absent external module is an expected shape
    /// (a BLE-only deployment) — this variant keeps the link array's size
    /// fixed at compile time while contributing nothing.
    ///
    /// `send` reports [`LinkError::NotPresent`], which the driver logs at
    /// `trace!` and does *not* feed to the transmit-rate estimator. Both
    /// halves matter: a `TransmitFailed` here would `warn!` once per OGM on
    /// every BLE-only board, and an `Ok(0)` would record a transmitted frame,
    /// publishing a non-zero `tx_fps` for hardware that isn't attached. The
    /// one-time `warn!` at boot is the operator's signal that this slot is
    /// empty. `recv` never resolves, since nothing will ever arrive on a
    /// medium with nothing attached.
    Absent,
}

impl<S> LinkT for MeshLink<S>
where
    S: Read + Write + Send,
{
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        match self {
            MeshLink::Rylr(link) => link.send(origin, data).await,
            MeshLink::Ble(link) => link.send(origin, data).await,
            MeshLink::Absent => Err(LinkError::NotPresent),
        }
    }

    async fn recv<'a>(&'a mut self) -> Result<Received<'a>, LinkError> {
        match self {
            MeshLink::Rylr(link) => link.recv().await,
            MeshLink::Ble(link) => link.recv().await,
            MeshLink::Absent => core::future::pending().await,
        }
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // SAFETY: called once, before any other code can allocate, over a
    // `static mut` region sized by `HEAP_SIZE_BYTES` that nothing else
    // references.
    unsafe {
        static mut HEAP_MEM: [core::mem::MaybeUninit<u8>; HEAP_SIZE_BYTES] =
            [core::mem::MaybeUninit::uninit(); HEAP_SIZE_BYTES];
        #[allow(static_mut_refs)]
        HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE_BYTES);
    }

    // Install the RTT tracing subscriber now that the allocator is up (its
    // dispatcher allocates) and before any `tracing` event, so the mesh stack's
    // logs are visible over the debug probe.
    wayfinder_log::init();

    info!("Welcome to Wayfinder");

    // Same SoftDevice restriction as described just below, for the UARTE0
    // interrupt the RYLR998 link uses and the USBD one the management port
    // does. `embassy_nrf::config::Config` has no field for either priority —
    // unlike GPIOTE/RTC1, they stay at the hardware reset default (highest,
    // priority 0) until set explicitly — so they are dropped to `P2` straight
    // on the NVIC here rather than through the `nrf_config` built below. Order
    // only matters relative to the SoftDevice being enabled (via
    // `Softdevice::enable`, later in `wayfinder()`); nothing between here and
    // there resets NVIC priorities.
    Interrupt::UARTE0.set_priority(Priority::P2);
    Interrupt::USBD.set_priority(Priority::P2);

    // The SoftDevice (brought up later, via `Softdevice::enable`) reserves NVIC
    // priority levels 0 and 1 for itself and rejects `sd_softdevice_enable()`
    // outright (`SdmIncorrectInterruptConfiguration`) if any interrupt is
    // already enabled at those levels. `embassy_nrf::config::Config::default()`
    // enables GPIOTE and the RTC1 time driver at `Priority::P0` — the highest
    // level — so both must be dropped to `P2`, matching `nrf-softdevice`'s own
    // examples, before the SoftDevice is ever enabled.
    let mut nrf_config = embassy_nrf::config::Config::default();
    nrf_config.gpiote_interrupt_priority = embassy_nrf::interrupt::Priority::P2;
    nrf_config.time_interrupt_priority = embassy_nrf::interrupt::Priority::P2;
    let p = embassy_nrf::init(nrf_config);

    // Resolve this node's durable mesh identity before bringing up the radio:
    // load the MAC persisted in the reserved top flash pages, or — on a
    // never-provisioned board — derive it from the factory FICR device ID and
    // persist it for next boot. This is the node's first use of the
    // `DurableStore`/`Persisted` abstraction on bare metal.
    //
    // `FlashStore::new` failing means `DURABLE_STORE_BASE`/`memory.x` are
    // inconsistent (a build-time programming error, not a runtime fault) —
    // nothing to recover from, so halt loudly like the radio bring-up
    // failures below rather than run against a misaddressed flash region.
    let store = match FlashStore::new(Nvmc::new(p.NVMC), DURABLE_STORE_BASE) {
        Ok(store) => store,
        Err(e) => {
            error!(?e, "durable identity store misconfigured; halting");
            loop {
                cortex_m::asm::wfe();
            }
        }
    };
    let mut id_buf = [0u8; IDENTITY_READ_BUF_LEN];
    let node_mac = match load_or_init_identity(store, ficr_derived_mac, &mut id_buf) {
        Ok(identity) => *identity.get(),
        Err(e @ IdentityError::Decode(_)) => {
            // The persisted identity blob was unreadable (corrupt or a
            // foreign format) — a permanent condition, not a transient I/O
            // fault, so it won't resolve on its own; per CLAUDE.md's logging
            // rubric this is an operator-actionable, node-local failure, not
            // a `warn!`. `load_or_init_identity` already made a best-effort
            // attempt to re-derive and re-persist a fresh blob so a *later*
            // boot converges to a stable address; this boot falls back to
            // the same deterministic value in memory.
            error!(
                ?e,
                "persisted node identity unreadable; re-derived from FICR"
            );
            ficr_derived_mac()
        }
        Err(e) => {
            // A store I/O failure: node-local, not attacker-triggerable, and
            // not something this boot can usefully retry — per CLAUDE.md,
            // `error!`, not `warn!`. The FICR-derived MAC is deterministic,
            // so the node still boots with a correct, stable address; only
            // its *persistence* is degraded until the store recovers.
            error!(
                ?e,
                "durable identity store unavailable; using FICR-derived MAC in memory"
            );
            ficr_derived_mac()
        }
    };
    info!(?node_mac, "resolved node identity");

    // LED1 (P0.13, active-low) lit = firmware booted and reached the run loop.
    // Moved into the mesh task below, which is what actually lights it.
    let led = Output::new(p.P0_13, Level::High, OutputDrive::Standard);

    // The buffered UARTE needs `'static` scratch buffers; `rx_buffer.len()` must
    // be even.  Each `static mut` is taken by a unique `&mut` exactly once here.
    let rx_buffer: &'static mut [u8] = {
        static mut RX: [u8; 256] = [0; 256];
        // SAFETY: `main` runs once, so this is the only `&mut` ever taken to
        // `RX`; no other reference to it exists.
        unsafe { &mut *core::ptr::addr_of_mut!(RX) }
    };
    let tx_buffer: &'static mut [u8] = {
        static mut TX: [u8; 256] = [0; 256];
        // SAFETY: `main` runs once, so this is the only `&mut` ever taken to
        // `TX`; no other reference to it exists.
        unsafe { &mut *core::ptr::addr_of_mut!(TX) }
    };

    let mut uarte_config = UarteConfig::default();
    uarte_config.baudrate = Baudrate::BAUD115200; // RYLR998 default
    uarte_config.parity = Parity::EXCLUDED;

    // RYLR998 wiring (change these two GPIOs to match how you connect the
    // module): P1.01 = MCU TX → module RX, P1.02 = MCU RX ← module TX, plus the
    // DK's 3V3 and GND to the module.  Both broken out on the DK headers and
    // free of analog/QSPI conflicts.
    // `TIMER1`, not `TIMER0`: `BufferedUarte` drives a timer over PPI to detect
    // the RX idle gap, and `TIMER0` is one of the peripherals the S140
    // SoftDevice claims exclusively for radio timing (it is in
    // `nrf_softdevice`'s own `RESERVED_IRQS` list, alongside RADIO/RTC0). On a
    // board with a RYLR998 actually attached, the `BufferedUarte` outlives
    // `Softdevice::enable` and the two would then be reprogramming one timer
    // against each other. `TIMER1` is otherwise unused here — `embassy-time`
    // runs on RTC1 and the 802.15.4 adapter is never wired live.
    let uarte = buffered_uarte::BufferedUarte::new(
        p.UARTE0,
        p.TIMER1,
        p.PPI_CH0,
        p.PPI_CH1,
        p.PPI_GROUP0,
        p.P0_02, // RXD (module TX)
        p.P0_26, // TXD (module RX)
        Irqs,
        uarte_config,
        rx_buffer,
        tx_buffer,
    );

    info!("constructing wayfinder task");

    // Run the mesh loop. `led` moves into the task rather than being lit here:
    // `Output`'s `Drop` disconnects the pin, and `main` returns as soon as the
    // task is queued, so a local LED would be driven for a few microseconds and
    // then float. Lighting it inside the task also makes the documented meaning
    // ("reached the run loop") true, rather than merely "was queued".
    let Ok(task) = wayfinder(node_mac, uarte, p.USBD, spawner, led) else {
        // Halting rather than falling through: with no mesh task there is
        // nothing to run, and continuing would leave LED1 dark while the board
        // sits idle looking booted. Matches every other genuine fault here.
        error!("failed to spawn wayfinder task; halting");
        loop {
            cortex_m::asm::wfe();
        }
    };
    info!("spawning wayfinder task");
    spawner.spawn(task);
}

#[embassy_executor::task]
async fn wayfinder(
    node_mac: Mac,
    uarte: BufferedUarte<'static>,
    usbd: Peri<'static, peripherals::USBD>,
    spawner: Spawner,
    led: Output<'static>,
) {
    // Bring up the RYLR998 if one is actually wired to this UART, and
    // configure the shared LoRa settings every node in this mesh must agree
    // on. Unlike BLE (built into the chip, always present), this is an
    // external module this board may or may not have attached — so a radio
    // that never responds to `ping` is a normal, expected shape (a BLE-only
    // deployment), not a fault, and degrades to `MeshLink::Absent` rather than
    // halting boot. A module that *does* respond but then rejects
    // configuration is a different, genuine problem: it's present and
    // malfunctioning, not absent, so that case still halts with LED1 dark
    // rather than run a misconfigured relay that looks healthy.
    let lora_address = u16::from_be_bytes([node_mac.0[4], node_mac.0[5]]);
    let rylr_link = 'rylr: {
        let Ok(mut client) = RylrClient::new(uarte) else {
            warn!("RYLR998 serial init failed; continuing BLE-only");
            break 'rylr MeshLink::Absent;
        };

        let mut detected = false;
        for _ in 0..RYLR_PING_ATTEMPTS {
            if embassy_time::with_timeout(EmbassyDuration::from_secs(1), client.ping())
                .await
                .is_ok()
            {
                detected = true;
                break;
            }
            trace!("waiting for radio to boot");
        }
        if !detected {
            warn!("RYLR998 not detected; continuing BLE-only");
            break 'rylr MeshLink::Absent;
        }

        let configured = async {
            client.set_address(lora_address).await?;
            client.set_network_id(LORA_NETWORK_ID).await?;
            client
                .set_parameters(
                    SpreadingFactory::Sf7,
                    Bandwidth::Khz125,
                    CodingRate::Cr48,
                    15,
                )
                .await?;
            Ok::<(), LoraError>(())
        }
        .await;
        if let Err(e) = configured {
            error!(?e, "RYLR998 present but configuration failed; halting");
            loop {
                cortex_m::asm::wfe();
            }
        }
        MeshLink::Rylr(client)
    };

    // TODO: unconfirmed workaround, added during hardware bring-up ("add
    // wait") with no recorded root cause. Suspected to paper over a
    // SoftDevice-enable race against the RYLR998 UART bring-up just above (or
    // against the UARTE0/UARTE1 priority calls further up), but that hasn't
    // been verified against real hardware. Don't remove without confirming on
    // a board that BLE bring-up is still reliable without it.
    debug!("waiting 1s before starting Ble");
    Timer::after_secs(1).await;

    // Enables the SoftDevice and starts its single event pump, the only place
    // SoC events are ever delivered — hence the USB stack's power-event
    // handler (`on_soc_event`) riding along here rather than being installed
    // by `usb_mgmt` itself. See `usb_mgmt`'s module doc. A spawn failure here
    // is treated like every other genuine boot fault below: halt with LED1
    // dark rather than run without the event pump USB VBUS detection and BLE
    // both depend on.
    let sd = Softdevice::enable(&Default::default());
    match softdevice_task(sd, on_soc_event) {
        Ok(task) => spawner.spawn(task),
        Err(e) => {
            error!(?e, "softdevice event-pump task spawn failed; halting");
            loop {
                cortex_m::asm::wfe();
            }
        }
    }

    // Bring up this node's second mesh interface: BLE advertising broadcast
    // over the chip's built-in radio. Unlike the RYLR998 above, this radio is
    // always physically present, so a bring-up failure here is a genuine
    // fault — halt with LED1 dark rather than run a relay with only its
    // optional interface actually working.
    let ble_link = match NrfBleLink::new(spawner, sd) {
        Ok(link) => link,
        Err(e) => {
            error!(?e, "BLE bring-up failed; halting");
            loop {
                cortex_m::asm::wfe();
            }
        }
    };
    debug!("BLE link brought up");

    // The management port, now that the SoftDevice it borrows power and clock
    // state from is up. A failure here leaves the node routing but unobservable
    // — degraded, not dead — so unlike the radios it does not halt: the mesh is
    // the job, and management is how you watch it do the job.
    let usb = match usb_mgmt::init(usbd, Irqs, node_mac).await {
        Ok(usb) => Some(usb),
        Err(e) => {
            error!(?e, "USB management port unavailable; continuing without it");
            None
        }
    };

    let links = [rylr_link, MeshLink::Ble(ble_link)];

    // Per-link Trickle schedules, in the same order as the `links` array above
    // — the coupling is positional, so swapping these silently gives each radio
    // the other's cadence rather than failing to compile. LoRa's is a relaxed
    // cadence suited to its low airtime budget; BLE's tighter bounds reflect
    // its much higher duty-cycle budget, and its `i_max` is mirrored by
    // `ogm.i_max_ms` on the `Ble` link in `var/conf/install.yml` so a host node
    // and this board agree on the schedule.
    let trickle = [
        TrickleParams {
            i_min: core::time::Duration::from_secs(5),
            i_max: core::time::Duration::from_secs(128),
        },
        TrickleParams {
            i_min: core::time::Duration::from_secs(1),
            i_max: core::time::Duration::from_secs(20),
        },
    ];

    let features = [
        LinkFeatures::default(),
        LinkFeatures {
            tx_keepalive: Some(KeepAliveConfig { interval_ms: 5000 }),
            ..Default::default()
        },
    ];

    // Built at this board's capacities rather than the host defaults; the link
    // and clock types are inferred, only the profile is pinned.
    let mut driver: wayfinder_embedded_driver::driver_for!(_, _, 2, nrf52840) =
        Driver::with_capacities(node_mac, links, EmbassyClock, &trickle, &features);

    // Reached the run loop: signal liveness on LED1 (active-low). Held for the
    // lifetime of this task, so the pin stays driven — dropping it would
    // disconnect the pin and the LED would go dark.
    let mut led = led;
    led.set_low();
    // Every deterministic bring-up panic is behind us; from here a panic is a
    // runtime fault the node should reboot out of rather than latch on.
    mark_boot_healthy();
    info!("wayfinder started");

    // The query channel bridging the USB management serve loop to the router
    // loop. Both ends borrow it, and both futures are joined below, so it can
    // live on this task's stack.
    let query_channel = EmbeddedQueryChannel::new();
    let (query_tx, query_rx) = query_channel.split();

    match usb {
        // Run the mesh loop (now also servicing management queries) and the USB
        // device + serve loop concurrently on this one task; neither returns.
        Some(usb) => {
            join(driver.run_with_mgmt(&query_rx), usb.run(&query_tx))
                .await
                .0
        }
        // No management port: nothing will ever send on `query_rx`, so racing it
        // would only cost an idle future per loop iteration.
        None => driver.run().await,
    }
}

/// The SoftDevice's single event pump, forwarding SoC events to the board's
/// handler (see [`usb_mgmt::on_soc_event`]). BLE events are consumed
/// internally by `nrf-softdevice` and never reach the handler.
#[embassy_executor::task]
async fn softdevice_task(sd: &'static Softdevice, on_soc_event: fn(SocEvent)) -> ! {
    sd.run_with_callback(on_soc_event).await
}
