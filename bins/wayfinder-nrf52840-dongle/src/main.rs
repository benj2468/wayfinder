//! nRF52840 dongle (PCA10059) firmware: the wayfinder mesh router on bare metal,
//! over the chip's built-in IEEE 802.15.4 radio.
//!
//! Same silicon and the same [`wayfinder_nrf`] board support as the DK; this
//! file is the dongle's pin map, flash layout and interrupt bindings. The board
//! has no onboard debugger, so the USB management port is the only way into a
//! running node — see `libs/wayfinder-nrf/CLAUDE.md`.

#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_nrf::bind_interrupts;
use embassy_nrf::gpio::Level;
use embassy_nrf::gpio::Output;
use embassy_nrf::gpio::OutputDrive;
use embassy_nrf::nvmc;
use embassy_nrf::peripherals;
use embassy_nrf::radio;
use embassy_nrf::radio::ieee802154::Radio;
use embassy_nrf::usb;
use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
use tracing::error;
use tracing::info;

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
///
/// `+ 8`, unlike the DK's, because the MBR keeps its interrupt-forwarding
/// address in the first 8 bytes of RAM — see the note in `memory.x`.
const RAM_ORIGIN: usize = 0x2000_0008;

// RADIO for the 802.15.4 link; USBD for the device stack carrying the
// management API — which on this board is the only way in — and the CDC-NCM
// mesh interface; CLOCK_POWER for VBUS detection, which reads `POWER` directly
// now that no SoftDevice reserves it.
bind_interrupts!(struct Irqs {
    RADIO => radio::InterruptHandler<peripherals::RADIO>;
    USBD => usb::InterruptHandler<peripherals::USBD>;
    CLOCK_POWER => usb::vbus_detect::InterruptHandler;
});

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = wayfinder_nrf::init_platform(RAM_ORIGIN);
    let identity = wayfinder_nrf::identity::resolve(p.NVMC, p.RNG, DURABLE_STORE_BASE);

    // LD1 (P0.06, active-low) lit = reached the run loop. The dongle does not
    // route the DK's P0.13. Moved into the task that actually lights it, since
    // `Output`'s `Drop` disconnects the pin.
    let led = Output::new(p.P0_06, Level::High, OutputDrive::Standard);

    // `wayfinder_nrf::node::run` is spawned directly, not wrapped in a local
    // `#[task]` that awaits it: the wrapper would `memcpy` that ~62 KB future
    // through a stack buffer its poll frame then held for the life of the node,
    // which overflowed into the SoftDevice's RAM. See `run`'s docs.
    //
    // The closure is non-capturing and so coerces to the `fn` pointer
    // `UsbDriverFactory`; it exists to keep `Irqs` — and with it the linked
    // `USBD` interrupt handler — in this binary rather than in the library.
    let Ok(task) = wayfinder_nrf::node::run(
        identity,
        Radio::new(p.RADIO, Irqs),
        p.USBD,
        |usbd| usb::Driver::new(usbd, Irqs, HardwareVbusDetect::new(Irqs)),
        spawner,
        led,
    ) else {
        error!("failed to spawn node task; halting");
        loop {
            cortex_m::asm::wfe();
        }
    };
    info!("spawning node task");
    spawner.spawn(task);
}
