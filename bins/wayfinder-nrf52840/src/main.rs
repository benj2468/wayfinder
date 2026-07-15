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
//! forwarding, no host device.  A second node (a Linux box with its own
//! RYLR998) is what you inspect the mesh from.
//!
//! [`BufferedUarte`]: embassy_nrf::buffered_uarte::BufferedUarte
//! [`LinkT`]: wayfinder::link::LinkT

#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_nrf::uarte::{Baudrate, Config as UarteConfig, Parity};
use embassy_nrf::{bind_interrupts, buffered_uarte, peripherals};
use embassy_time::{Duration as EmbassyDuration, Instant, Timer};
use embedded_alloc::LlffHeap as Heap;
use panic_halt as _;
use rylr998::{Bandwidth, CodingRate, LoraError, RylrClient, SpreadingFactory};
use tracing::warn;
use wayfinder::interfaces::frame::Mac;
use wayfinder_embedded_driver::{Clock, Driver, TrickleParams};

#[global_allocator]
static HEAP: Heap = Heap::empty();

/// Bytes reserved for `alloc` — `tracing-core`'s own bookkeeping is the only
/// user today, so this is deliberately tiny; grow it if a future allocation
/// panics.
const HEAP_SIZE_BYTES: usize = 1024;

/// This node's mesh identity.  Each physical node needs a **distinct** MAC — and
/// therefore a distinct RYLR `AT+ADDRESS` (derived below), since the RYLR
/// reassembler keys in-flight fragments on the 16-bit module address (see
/// `libs/rylr998/CLAUDE.md`).  The peer Linux node must use a different one.
const NODE_MAC: Mac = Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

/// LoRa network id shared by every node in this mesh (RYLR `AT+NETWORKID`).
const LORA_NETWORK_ID: u8 = 18;

// Bind the UARTE0 interrupt to the buffered-UARTE handler so the driver's async
// serial reads/writes are woken by hardware rather than polled.
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

    let p = embassy_nrf::init(Default::default());

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
        p.P1_02, // RXD (module TX)
        p.P1_01, // TXD (module RX)
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
    let lora_address = u16::from_be_bytes([NODE_MAC.0[4], NODE_MAC.0[5]]);
    // Apply the shared LoRa settings every node in this mesh must agree on. A
    // failure here (the module didn't ACK a command) would leave the node on the
    // wrong address/network — silently deaf on the mesh, or cross-contaminating
    // another node's fragment reassembly. Halt with LED1 dark rather than run a
    // misconfigured relay that looks healthy.
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

    let mut driver = Driver::new(NODE_MAC, [client], EmbassyClock, &trickle, &[]);
    driver.run().await
}
