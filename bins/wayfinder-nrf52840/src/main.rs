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
//! This board previously also served the management API over a second UART on
//! the DK's onboard-debugger VCOM port. That wiring was deliberately removed
//! during BLE bring-up and the node is currently *not* inspectable over serial
//! — `wayfinder-embedded-driver`'s `mgmt` feature and `wayfinder-server` are
//! still depended on but unwired, so restoring it is a matter of rebuilding
//! the `UARTE1` + `EmbeddedQueryChannel` + `serve` path and swapping
//! `driver.run()` back for `driver.run_with_mgmt(&query_rx)`.
//!
//! [`BufferedUarte`]: embassy_nrf::buffered_uarte::BufferedUarte
//! [`LinkT`]: wayfinder::link::LinkT

#![no_std]
#![no_main]

use blue::NrfBleLink;
use embassy_executor::Spawner;
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
use embassy_time::Duration as EmbassyDuration;
use embassy_time::Instant;
use embassy_time::Timer;
use embedded_alloc::LlffHeap as Heap;
use embedded_io_async::Read;
use embedded_io_async::Write;
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
use wayfinder::interfaces::frame::LinkFrameData;
use wayfinder::interfaces::frame::Mac;
use wayfinder::interfaces::link::LinkError;
use wayfinder::link::LinkT;
use wayfinder::link::Received;

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

#[global_allocator]
static HEAP: Heap = Heap::empty();

/// Prints the panic message over RTT before halting, so a fatal error (e.g.
/// `nrf-softdevice`'s own `sd_ble_enable` RAM-too-small panic — see
/// `memory.x`) is visible on the debug probe instead of a silent hang.
/// Writes to the print channel `wayfinder_embedded_log::init()` already set
/// up for `tracing`'s output, rather than opening a second RTT channel — the
/// two must therefore stay on the same `rtt-target` version (see this crate's
/// `Cargo.toml`). If a panic happens before that `init()` call, the message
/// is silently dropped (per `rtt_target::rprintln!`'s documented behavior)
/// and this degrades to a plain halt.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    rtt_target::rprintln!("panic: {}", info);
    loop {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Bytes reserved for `alloc`. Its only current user is `tracing-core`'s
/// bookkeeping, which needs a small fraction of this.
///
/// Still sized for the management server that used to run here (see the module
/// doc): `wayfinder_server::framing::MAX_FRAME_LEN` is 4 KiB and `serve` holds
/// one in-flight buffer per direction, so a single connection could pin 8 KiB
/// in framing buffers alone, leaving ~24 KiB for the `RouterAdapter` response
/// `Vec`s a query builds. Left at 32 KiB rather than shrunk to fit tracing
/// alone — it is tiny against the part's 256 KiB SRAM, and re-wiring the mgmt
/// API would need it straight back.
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
// rather than polled. UARTE1 carried the management-API VCOM link until that
// was removed during BLE bring-up (see the module doc) and is currently unbound.
bind_interrupts!(struct Irqs {
    UARTE0 => buffered_uarte::InterruptHandler<peripherals::UARTE0>;
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
    wayfinder_embedded_log::init();

    info!("Welcome to Wayfinder");

    // Same SoftDevice restriction as described just below, for the UARTE0
    // interrupt the RYLR998 link uses. `embassy_nrf::config::Config` has no
    // field for UARTE priority — unlike GPIOTE/RTC1, it stays at the hardware
    // reset default (highest, priority 0) until set explicitly — so it is
    // dropped to `P2` straight on the NVIC here rather than through the
    // `nrf_config` built below. Order only matters relative to the SoftDevice
    // being enabled (in `NrfBleLink::new`, later); nothing between here and
    // there resets NVIC priorities.
    Interrupt::UARTE0.set_priority(Priority::P2);

    // The SoftDevice (brought up later, in `NrfBleLink::new`) reserves NVIC
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
    let uarte = buffered_uarte::BufferedUarte::new(
        p.UARTE0,
        p.TIMER0,
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
    let Ok(task) = wayfinder(node_mac, uarte, spawner, led) else {
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

    // Bring up this node's second mesh interface: BLE advertising broadcast
    // over the chip's built-in radio. Unlike the RYLR998 above, this radio is
    // always physically present, so a bring-up failure here is a genuine
    // fault — halt with LED1 dark rather than run a relay with only its
    // optional interface actually working.
    let ble_link = match NrfBleLink::new(spawner) {
        Ok(link) => link,
        Err(e) => {
            error!(?e, "BLE bring-up failed; halting");
            loop {
                cortex_m::asm::wfe();
            }
        }
    };
    debug!("BLE link brought up");

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

    // Built at this board's capacities rather than the host defaults; the link
    // and clock types are inferred, only the profile is pinned.
    let mut driver: wayfinder_embedded_driver::driver_for!(_, _, 2, nrf52840) =
        Driver::with_capacities(node_mac, links, EmbassyClock, &trickle, &[]);

    // Reached the run loop: signal liveness on LED1 (active-low). Held for the
    // lifetime of this task, so the pin stays driven — dropping it would
    // disconnect the pin and the LED would go dark.
    let mut led = led;
    led.set_low();
    info!("wayfinder started");

    driver.run().await
}
