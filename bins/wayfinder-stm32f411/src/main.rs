//! NUCLEO-F411RE (STM32F411RE) firmware: run the wayfinder mesh router on bare
//! metal over a RYLR998 LoRa link on USART1.
//!
//! This is the second-family proof: a non-Nordic Cortex-M running the **same**
//! [`wayfinder_embedded_driver::Driver`] the nRF52840 board uses, differing only
//! in the HAL that supplies the concrete UART link and the `embassy-time`
//! [`Clock`].  Milestone 1 is a radio relay (one LoRa interface, no host device).
//!
//! [`Clock`]: wayfinder_embedded_driver::Clock

#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_stm32::bind_interrupts;
use embassy_stm32::gpio::Level;
use embassy_stm32::gpio::Output;
use embassy_stm32::gpio::Speed;
use embassy_stm32::peripherals;
use embassy_stm32::usart;
use embassy_stm32::usart::BufferedUart;
use embassy_stm32::usart::Config as UartConfig;
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
use tracing::warn;
use wayfinder::interfaces::frame::Mac;
use wayfinder_embedded_driver::Clock;
use wayfinder_embedded_driver::Driver;
use wayfinder_embedded_driver::TrickleParams;

#[global_allocator]
static HEAP: Heap = Heap::empty();

/// Bytes reserved for `alloc` — `tracing-core`'s bookkeeping is the only user
/// today; grow it if a future allocation panics.
const HEAP_SIZE_BYTES: usize = 1024;

/// This node's mesh identity.  Distinct per physical node (drives a distinct
/// RYLR `AT+ADDRESS`, since the reassembler keys on the 16-bit module address).
const NODE_MAC: Mac = Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);

/// LoRa network id shared by every node in this mesh (RYLR `AT+NETWORKID`).
const LORA_NETWORK_ID: u8 = 18;

bind_interrupts!(struct Irqs {
    USART1 => usart::BufferedInterruptHandler<peripherals::USART1>;
});

/// An `embassy-time`-backed [`Clock`] for the embedded driver.
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

    let p = embassy_stm32::init(Default::default());

    // The buffered UART needs `'static` scratch buffers; each `static mut` is
    // taken by a unique `&mut` exactly once here.
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

    let mut uart_config = UartConfig::default();
    uart_config.baudrate = 115200; // RYLR998 default

    // RYLR998 wiring on USART1: PA9 = MCU TX → module RX, PA10 = MCU RX ←
    // module TX, plus the board's 3V3 and GND to the module.
    let Ok(uart) = BufferedUart::new(
        p.USART1,
        p.PA10, // RX (module TX)
        p.PA9,  // TX (module RX)
        tx_buffer,
        rx_buffer,
        Irqs,
        uart_config,
    ) else {
        loop {
            cortex_m::asm::wfe();
        }
    };

    // LD2 (PA5) lit = firmware booted and reached the run loop.
    let mut led = Output::new(p.PA5, Level::Low, Speed::Low);

    let Ok(mut client) = RylrClient::new(uart) else {
        loop {
            cortex_m::asm::wfe();
        }
    };
    let lora_address = u16::from_be_bytes([NODE_MAC.0[4], NODE_MAC.0[5]]);
    // Apply the shared LoRa settings every node in this mesh must agree on. A
    // failure here (the module didn't ACK a command) would leave the node on the
    // wrong address/network — silently deaf on the mesh, or cross-contaminating
    // another node's fragment reassembly. Halt with LD2 dark rather than run a
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

    // Reached the run loop: signal liveness on LD2.
    led.set_high();

    let trickle = [TrickleParams {
        i_min: core::time::Duration::from_secs(5),
        i_max: core::time::Duration::from_secs(128),
    }];

    let mut driver = Driver::new(NODE_MAC, [client], EmbassyClock, &trickle, &[]);
    driver.run().await
}
