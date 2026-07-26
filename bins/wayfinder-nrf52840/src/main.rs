//! nRF52840-DK firmware: run the wayfinder mesh router on bare metal over a
//! RYLR998 LoRa link attached to a UART.
//!
//! This wires the board's concrete pieces to the HAL-agnostic
//! [`wayfinder_embedded_driver::Driver`]: a [`BufferedUarte`] on two GPIOs
//! carries the RYLR998's AT-command protocol, [`rylr998::RylrClient`] adapts
//! that serial into the mesh [`LinkT`], and an `embassy-time`-backed [`Clock`]
//! paces the OGM timer.  The embassy thread-mode executor drives the driver's
//! `async` loop forever.
//!
//! Milestone 1 is a **radio relay**: one LoRa interface, OGM exchange +
//! forwarding, no host device.  A second UART exposes the management API on
//! the DK's onboard-debugger VCOM port, so the node is inspectable
//! (`wayfinder-tui`/`wayfinderctl --serial`) without a second mesh node.
//!
//! [`BufferedUarte`]: embassy_nrf::buffered_uarte::BufferedUarte
//! [`LinkT`]: wayfinder::link::LinkT

#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_nrf::bind_interrupts;
use embassy_nrf::buffered_uarte;
use embassy_nrf::gpio::Level;
use embassy_nrf::gpio::Output;
use embassy_nrf::gpio::OutputDrive;
use embassy_nrf::nvmc::Nvmc;
use embassy_nrf::nvmc::{self};
use embassy_nrf::peripherals;
use embassy_nrf::uarte::Baudrate;
use embassy_nrf::uarte::Config as UarteConfig;
use embassy_nrf::uarte::Parity;
use embassy_time::Duration as EmbassyDuration;
use embassy_time::Instant;
use embassy_time::Timer;
use embedded_alloc::LlffHeap as Heap;
use panic_halt as _;
use rylr998::Bandwidth;
use rylr998::CodingRate;
use rylr998::LoraError;
use rylr998::RylrClient;
use rylr998::SpreadingFactory;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;
use wayfinder::interfaces::frame::Mac;
use wayfinder_embedded_driver::Clock;
use wayfinder_embedded_driver::Driver;
use wayfinder_embedded_driver::TrickleParams;
use wayfinder_embedded_driver::identity::IDENTITY_READ_BUF_LEN;
use wayfinder_embedded_driver::identity::IdentityError;
use wayfinder_embedded_driver::identity::load_or_init_identity;
use wayfinder_server::EmbeddedQueryChannel;
use wayfinder_server::FrameError;
use wayfinder_server::serve;
use wayfinder_storage::FlashStore;

#[global_allocator]
static HEAP: Heap = Heap::empty();

/// Bytes reserved for `alloc`.  Two users share it: `tracing-core`'s bookkeeping
/// and the management server's per-request buffers.  Sized against
/// `wayfinder_server::framing::MAX_FRAME_LEN` (4 KiB): `serve` holds one
/// in-flight buffer per direction, so a single connection can pin up to 8 KiB
/// in framing buffers alone; this leaves ~24 KiB of headroom for the
/// `RouterAdapter` response `Vec`s a query itself builds plus tracing's
/// bookkeeping — tiny against the part's 256 KiB SRAM. Grow both constants
/// together if a real routing-table response ever gets close to the cap.
const HEAP_SIZE_BYTES: usize = 32 * 1024;

/// LoRa network id shared by every node in this mesh (RYLR `AT+NETWORKID`).
const LORA_NETWORK_ID: u8 = 18;

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
/// reassembler from cross-contaminating fragments (see `libs/rylr998/CLAUDE.md`).
fn ficr_derived_mac() -> Mac {
    let ficr = embassy_nrf::pac::FICR;
    let lo = ficr.deviceid(0).read().to_le_bytes();
    let hi = ficr.deviceid(1).read().to_le_bytes();
    let mut octets = [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1]];
    octets[0] = (octets[0] & 0xFE) | 0x02;
    Mac(octets)
}

// Bind the UARTE0 interrupt to the buffered-UARTE handler so the driver's async
// serial reads/writes are woken by hardware rather than polled.
bind_interrupts!(struct Irqs {
    UARTE0 => buffered_uarte::InterruptHandler<peripherals::UARTE0>;
    UARTE1 => buffered_uarte::InterruptHandler<peripherals::UARTE1>;
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

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
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

    let p = embassy_nrf::init(Default::default());

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

    // LED1 (P0.13, active-low) lit = firmware booted and reached the run loop.
    let mut led = Output::new(p.P0_13, Level::High, OutputDrive::Standard);

    // Bring up the RYLR998 and configure the shared LoRa settings every node in
    // this mesh must agree on.  A distinct 16-bit address per node (low bytes of
    // the mesh MAC) keeps fragment reassembly from cross-contaminating.
    let Ok(mut client) = RylrClient::new(uarte) else {
        // Serial init failed: leave LED1 off and halt.
        loop {
            cortex_m::asm::wfe();
        }
    };
    let lora_address = u16::from_be_bytes([node_mac.0[4], node_mac.0[5]]);
    // Apply the shared LoRa settings every node in this mesh must agree on. A
    // failure here (the module didn't ACK a command) would leave the node on the
    // wrong address/network — silently deaf on the mesh, or cross-contaminating
    // another node's fragment reassembly. Halt with LED1 dark rather than run a
    // misconfigured relay that looks healthy.
    let configured = async {
        // We need to wait until the module is actually awake
        while embassy_time::with_timeout(EmbassyDuration::from_secs(1), client.ping())
            .await
            .is_err()
        {
            trace!("waiting for radio to boot");
        }
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
        warn!(?e, "radio configuration failed; halting");
        loop {
            cortex_m::asm::wfe();
        }
    }

    // Reached the run loop: signal liveness on LED1.
    led.set_low();

    // A relaxed per-link Trickle schedule suited to LoRa's low airtime budget.
    let trickle = [TrickleParams {
        i_min: core::time::Duration::from_secs(5),
        i_max: core::time::Duration::from_secs(128),
    }];

    let mut driver = Driver::new(node_mac, [client], EmbassyClock, &trickle, &[]);

    // Bring up the second UART on the DK's onboard-debugger VCOM lines so the
    // management API is reachable as a USB serial device (`/dev/ttyACM*`) with no
    // extra wiring: on the PCA10056, P0.06 = nRF TX → host and P0.08 = nRF RX ←
    // host.  No hardware flow control (the RYLR link runs without it too).  The
    // scratch buffers follow the same `'static`, taken-once pattern as the RYLR
    // UART above; `rx_buffer.len()` must be even.
    let mgmt_rx_buffer: &'static mut [u8] = {
        static mut RX: [u8; 256] = [0; 256];
        // SAFETY: `main` runs once, so this is the only `&mut` ever taken to `RX`.
        unsafe { &mut *core::ptr::addr_of_mut!(RX) }
    };
    let mgmt_tx_buffer: &'static mut [u8] = {
        static mut TX: [u8; 256] = [0; 256];
        // SAFETY: `main` runs once, so this is the only `&mut` ever taken to `TX`.
        unsafe { &mut *core::ptr::addr_of_mut!(TX) }
    };
    let mut mgmt_uarte_config = UarteConfig::default();
    mgmt_uarte_config.baudrate = Baudrate::BAUD115200;
    mgmt_uarte_config.parity = Parity::EXCLUDED;
    let mut mgmt_uart = buffered_uarte::BufferedUarte::new(
        p.UARTE1,
        p.TIMER1,
        p.PPI_CH2,
        p.PPI_CH3,
        p.PPI_GROUP1,
        p.P0_08, // RXD: host TX → nRF RX
        p.P0_06, // TXD: nRF TX → host RX
        Irqs,
        mgmt_uarte_config,
        mgmt_rx_buffer,
        mgmt_tx_buffer,
    );

    // The query channel bridging the management serve loop to the router loop.
    let query_channel = EmbeddedQueryChannel::new();
    let (query_tx, query_rx) = query_channel.split();

    // The serve loop owns the VCOM UART and frames management requests against
    // the channel. It never gives up permanently: the node keeps routing
    // regardless (only the management link is affected), and `serve` returning
    // is retried rather than treated as a one-shot failure, since its most
    // common cause — an operator's serial terminal disconnecting/reconnecting —
    // is routine, not exceptional.
    let mgmt = async {
        loop {
            match serve(&mut mgmt_uart, &query_tx).await {
                // A clean disconnect, mid-frame or between frames — the ordinary
                // shape of a serial terminal reattaching. Reopen the link.
                Err(FrameError::UnexpectedEof) => {
                    trace!("management link disconnected; awaiting reconnect");
                }
                // A peer-supplied length prefix desynchronised the stream: a
                // protocol violation reachable by whatever's on the other end of
                // the wire, not a node-local fault, so this stays below error!.
                Err(e @ FrameError::Oversized(_)) => {
                    warn!(?e, "management link reset: oversized frame");
                }
                // A genuine UART fault: node-local, not attacker-triggerable, and
                // (until this loop retries) a permanently lost resource — exactly
                // what error! is for. Back off briefly so a persistently broken
                // UART can't turn this into a tight retry loop.
                Err(e @ FrameError::Io(_)) => {
                    error!(?e, "management UART I/O error; retrying");
                    Timer::after(EmbassyDuration::from_millis(100)).await;
                }
                Ok(()) => unreachable!("serve only returns via an error"),
            }
        }
    };

    // Run the mesh loop (now also servicing management queries) and the serve
    // loop concurrently on the one executor task; neither ever returns.
    join(driver.run_with_mgmt(&query_rx), mgmt).await;
}
