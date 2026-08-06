//! nRF52840 dongle (PCA10059) firmware: the wayfinder mesh router on bare metal,
//! over connectionless BLE advertising broadcast and — if one is wired to the
//! castellated edge — a RYLR998 LoRa module on UARTE0.
//!
//! Same silicon and the same [`wayfinder_nrf`] board support as the DK; this
//! file is the dongle's pin map, flash layout and interrupt bindings. The board
//! has no onboard debugger, so the USB management port is the only way into a
//! running node — see `libs/wayfinder-nrf/CLAUDE.md`.

#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_nrf::Peri;
use embassy_nrf::bind_interrupts;
use embassy_nrf::buffered_uarte;
use embassy_nrf::buffered_uarte::BufferedUarte;
use embassy_nrf::gpio::Level;
use embassy_nrf::gpio::Output;
use embassy_nrf::gpio::OutputDrive;
use embassy_nrf::nvmc;
use embassy_nrf::peripherals;
use embassy_nrf::usb;
use tracing::error;
use tracing::info;
use wayfinder::interfaces::frame::Mac;

/// Base flash offset of the durable identity store: the two 4 KiB pages
/// `memory.x` carves out just below the region reserved for the Open
/// Bootloader. Unlike the DK's, this cannot sit at the very top of flash — the
/// bootloader's own settings pages live there. **Must stay consistent with
/// `memory.x`** — see the note there.
const DURABLE_STORE_BASE: u32 = 0xE_0000 - 2 * nvmc::PAGE_SIZE as u32;

/// `ORIGIN(RAM)` from `memory.x`, and so the address the stack bottoms out at
/// under `flip-link`. **Must stay consistent with `memory.x`** — it cannot be
/// read back from a linker symbol, since `flip-link` rewrites the `MEMORY`
/// block (see `wayfinder_nrf::stack::paint`).
const RAM_ORIGIN: usize = 0x2000_0000 + 13112;

// UARTE0 for the RYLR998, if attached; USBD for the device stack carrying the
// management API — which on this board is the only interface it has.
bind_interrupts!(struct Irqs {
    UARTE0 => buffered_uarte::InterruptHandler<peripherals::UARTE0>;
    USBD => usb::InterruptHandler<peripherals::USBD>;
});

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = wayfinder_nrf::init_platform(RAM_ORIGIN);
    let node_mac = wayfinder_nrf::identity::resolve(p.NVMC, DURABLE_STORE_BASE);

    // LD1 (P0.06, active-low) lit = reached the run loop. The dongle does not
    // route the DK's P0.13. Moved into the task that actually lights it, since
    // `Output`'s `Drop` disconnects the pin.
    let led = Output::new(p.P0_06, Level::High, OutputDrive::Standard);

    // RYLR998 wiring on the castellated edge: P0.31 = MCU RX ← module TX,
    // P0.29 = MCU TX → module RX, plus VDD and GND. `TIMER1`, not `TIMER0`:
    // `BufferedUarte` drives a timer over PPI to detect the RX idle gap, and the
    // S140 SoftDevice claims `TIMER0` exclusively for radio timing.
    let (rx_buffer, tx_buffer) = wayfinder_nrf::uarte_buffers();
    let uarte = BufferedUarte::new(
        p.UARTE0,
        p.TIMER1,
        p.PPI_CH0,
        p.PPI_CH1,
        p.PPI_GROUP0,
        p.P0_31, // RXD (module TX)
        p.P0_29, // TXD (module RX)
        Irqs,
        wayfinder_nrf::uarte_config(),
        rx_buffer,
        tx_buffer,
    );

    let Ok(task) = node(node_mac, uarte, p.USBD, spawner, led) else {
        error!("failed to spawn node task; halting");
        loop {
            cortex_m::asm::wfe();
        }
    };
    info!("spawning node task");
    spawner.spawn(task);
}

/// The board's one long-lived task: bring up the radios and the management port,
/// then run the router loop forever.
#[embassy_executor::task]
async fn node(
    node_mac: Mac,
    uarte: BufferedUarte<'static>,
    usbd: Peri<'static, peripherals::USBD>,
    spawner: Spawner,
    led: Output<'static>,
) -> ! {
    wayfinder_nrf::node::run(node_mac, uarte, usbd, Irqs, spawner, led).await
}
