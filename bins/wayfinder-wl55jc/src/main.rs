//! NUCLEO-WL55JC1 (STM32WL55JC) firmware: the wayfinder mesh router on bare
//! metal over the LoRa radio **on the same die**.
//!
//! The fourth part (and second STM32) to run the same
//! [`wayfinder_embedded_driver::Driver`] the other boards run, and the first
//! whose *LoRa* radio is not a separate part: no UART to a module, no second
//! vendor's firmware in the path, and no AT commands. What that costs is a wire format,
//! because a raw SX126x supplies none of the addressing a RYLR998 module does —
//! see `libs/lora-link`.
//!
//! # Two facts about this part that differ from every other board here
//!
//! - **Its Cortex-M4 has no FPU**, so the target is `thumbv7em-none-eabi`. The
//!   nRF52840 and STM32F411 are both `eabihf`; copying their
//!   `.cargo/config.toml` produces an image that links and then HardFaults on
//!   its first float.
//! - **It has 64 KB of SRAM**, a quarter of the nRF52840's, and this firmware
//!   gets all of it only because it never releases the Cortex-M0+. See
//!   `memory.x`, and `docs/design/25-stm32wl55-subghz-node.md` §4.1 for the
//!   budget.
//!
//! Milestone 1 is a radio relay: one LoRa interface, no host device, no
//! management port. Its identity is durable: a seed minted once from the TRNG
//! and kept in flash, with the mesh address derived from it (`identity.rs`).
//! The management port is what would make it reachable from
//! `libs/wayfinder-hil`, and is the next step.

#![no_std]
#![no_main]

mod identity;
mod radio;

use embassy_executor::Spawner;
use embassy_stm32::bind_interrupts;
use embassy_stm32::gpio::Level;
use embassy_stm32::gpio::Output;
use embassy_stm32::gpio::Speed;
use embassy_stm32::rng::Rng;
use embassy_stm32::spi::Spi;
use embassy_time::Duration as EmbassyDuration;
use embassy_time::Instant;
use embassy_time::Timer;
use embedded_alloc::LlffHeap as Heap;
use lora_phy::mod_params::Bandwidth;
use lora_phy::mod_params::CodingRate;
use lora_phy::mod_params::SpreadingFactor;
use panic_halt as _;
use tracing::error;
use tracing::info;
use wayfinder_embedded_driver::Clock;
use wayfinder_embedded_driver::Driver;
use wayfinder_embedded_driver::Restored;
use wayfinder_embedded_driver::TrickleParams;

use crate::radio::LoraLink;
use crate::radio::RadioConfig;
use wayfinder_wl55jc::RadioParts;

#[global_allocator]
static HEAP: Heap = Heap::empty();

/// Bytes reserved for `alloc`.
///
/// `tracing-core`'s bookkeeping is the only user while this board has no
/// management port. Adding one raises the floor sharply — `wayfinder_server`'s
/// framing is 4 KiB and `serve` holds one buffer per direction, so a single
/// session pins 8 KiB before any response — and design 25 §4.10 budgets 12 KiB
/// for that. Grow it when the port lands, not before: on a 64 KiB part this is
/// RAM taken from the stack.
const HEAP_SIZE_BYTES: usize = 2 * 1024;

/// The mesh discriminator carried in every fragment. A filter that keeps a
/// co-located mesh out of this one's reassembly table — **not** a security
/// boundary, which is `wayfinder-auth`'s job above `LinkT`.
const LORA_NET_ID: u8 = 18;

/// The radio settings every node on this mesh must agree on.
///
/// 868.1 MHz is in the EU ISM band this board's JC1 (high-band) front end is
/// built for; a US node wants 915 MHz. SF7/125 kHz/4-8 matches what the
/// RYLR998 nodes in this repo are configured for, so the two meshes are at
/// least comparable — they are *not* interoperable, since the wire formats
/// differ (`libs/lora-link/CLAUDE.md`).
///
/// **The duty cycle these settings imply is not enforced anywhere in this
/// firmware.** Design 25 §6.3: a deployed node needs a real airtime governor,
/// and `Trickle` bounds OGM cadence for routing's sake, not for compliance.
const RADIO: RadioConfig = RadioConfig {
    frequency_hz: 868_100_000,
    spreading_factor: SpreadingFactor::_7,
    bandwidth: Bandwidth::_125KHz,
    coding_rate: CodingRate::_4_8,
    // Conservative: well inside what the high-power PA can do, and inside EU
    // limits without relying on a governor that does not exist yet.
    output_power: 14,
};

wayfinder::define_profile! {
    /// The capacity profile this board is built at.
    ///
    /// **Not optional on this part.** `Driver::new` builds at the default
    /// `host` capacities — 128 originators, 8 interfaces, 2048-byte frames —
    /// which is a Linux gateway's sizing and does not fit 64 KB of SRAM. (The
    /// STM32F411 board shipped that way for the same reason, and `.bss`
    /// overflowed its 128 KB once its memory map was corrected.)
    ///
    /// `interfaces: 1` is the hardware: one radio, no host device, no second
    /// link.
    ///
    /// `max_frame_len` **must equal** `lora_link::MAX_REASSEMBLED_LEN`; the
    /// assertion after this macro is what makes a drift a build error rather
    /// than a silent drop of every oversized frame — principally authenticated
    /// OGMs, so the node would look healthy and route nothing.
    pub wl55jc {
        originators: 16,
        interfaces: 1,
        mcast_members: 8,
        local_mcast: 4,
        ident_table: 16,
        ident_live: 12,
        link_quality: 16,
        neighbor_keys: 8,
        revoked: 4,
        in_flight_cert_requests: 2,
        pending_replies: 2,
        max_frame_len: 512,
    }
}

/// The router must be able to hold whatever the link can reassemble. Below the
/// link's ceiling it silently refuses frames the radio was willing to carry;
/// above it costs RAM for frames that cannot arrive. `wayfinder-nrf` pins
/// itself to `ieee802154::MAX_REASSEMBLED_LEN` the same way.
const _: () = assert!(lora_link::MAX_REASSEMBLED_LEN == wl55jc::MAX_FRAME_LEN);

bind_interrupts!(struct Irqs {
    // The radio's own interrupt. `Stm32wlInterfaceVariant::await_irq` unmasks it and waits on the
    // signal this handler sets; it must not touch the SPI bus.
    SUBGHZ_RADIO => wayfinder_wl55jc::SubghzIrqHandler;
    // `SUBGHZSPI` transfers over DMA, so both channels' completion interrupts
    // have to be bound or `Spi::new_subghz` will not accept `Irqs`.
    DMA1_CHANNEL1 => embassy_stm32::dma::InterruptHandler<embassy_stm32::peripherals::DMA1_CH1>;
    DMA1_CHANNEL2 => embassy_stm32::dma::InterruptHandler<embassy_stm32::peripherals::DMA1_CH2>;
    RNG => embassy_stm32::rng::InterruptHandler<embassy_stm32::peripherals::RNG>;
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

/// Stop the node, leaving LD2 dark. For a bring-up failure that leaves nothing
/// useful to run: a relay whose only radio is misconfigured looks healthy and
/// is silently deaf on the mesh.
fn halt() -> ! {
    loop {
        cortex_m::asm::wfe();
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

    // After the allocator (the dispatcher allocates) and before any event.
    wayfinder_log::init();

    // The first record this board emits, before anything that can fail: with
    // no management port yet, this is the only way to learn which firmware is
    // running, and a board that halts during bring-up is when that matters.
    info!(
        version = wayfinder_version::VERSION,
        commit = wayfinder_version::COMMIT,
        dirty = wayfinder_version::DIRTY,
        source = ?wayfinder_version::SOURCE,
        "build",
    );

    // See `clock_config`: HSE32 off the radio's TCXO, which the radio needs.
    let p = embassy_stm32::init_primary(
        wayfinder_wl55jc::clock_config(),
        &wayfinder_wl55jc::SHARED_DATA,
    );

    // LD2, the green user LED, lit = firmware booted and reached the run loop.
    // Active high, and **PB9** — this board has three user LEDs (LD1 blue on
    // PB15, LD2 green on PB9, LD3 red on PB11), so the wrong one lights up
    // rather than nothing, which is the kind of mistake that survives a bench
    // test. Per Zephyr's `nucleo_wl55jc.dts`, whose `led0` alias is this pin.
    let mut led = Output::new(p.PB9, Level::Low, Speed::Low);

    let RadioParts {
        spi,
        interface,
        sx_config,
    } = wayfinder_wl55jc::radio_parts(
        Spi::new_subghz(p.SUBGHZSPI, p.DMA1_CH1, p.DMA1_CH2, Irqs),
        p.PC3,
        p.PC4,
        p.PC5,
    );

    // The radio's own task, which must outlive every `recv` — see `radio.rs`'s
    // module docs for why this is not a mutex. It is handed the *parts* and
    // builds the `LoRa` itself, so that value is never a temporary in this
    // function's frame: `main`'s poll frame is held for the life of the node,
    // and `scripts/stack-budget.py` gates exactly that.
    //
    // The task pool holds one, so this only fails if it were spawned twice.
    let Ok(task) = radio::radio_task(spi, interface, sx_config, RADIO) else {
        error!("could not spawn the radio task; halting");
        halt();
    };
    spawner.spawn(task);

    // Spawning only queues the task: it starts the IWDG on its first poll,
    // after `main` yields to the driver, so bring-up above can never trip it.
    let Ok(task) = wayfinder_wl55jc::watchdog_task(p.IWDG) else {
        error!("could not spawn the watchdog task; halting");
        halt();
    };
    spawner.spawn(task);

    let mut driver = build_node(p.FLASH, Rng::new(p.RNG, Irqs));
    led.set_high();

    info!(lora = true, "wayfinder started");
    driver.run().await
}

/// The driver this board runs, at its own capacity profile.
type Node = wayfinder_embedded_driver::driver_for!(LoraLink, EmbassyClock, 1, crate::wl55jc);

/// Resolve this node's identity, then build its driver and restore it from
/// the durable record.
///
/// **Out of line on purpose.** Called from `main`'s task, whose poll frame is
/// reserved for the life of the node: inlined there, the identity record and
/// its read buffer (~1.5 KiB between them) stayed reserved under the run loop
/// forever, and `just stack-budget-wl55jc` measured the poll at 4,252 bytes
/// against 2,788. Here they are a transient frame, gone before `run` starts;
/// the driver itself is returned straight into `main`'s future.
#[inline(never)]
fn build_node(
    flash: embassy_stm32::Peri<'static, embassy_stm32::peripherals::FLASH>,
    rng: Rng<'static, embassy_stm32::peripherals::RNG>,
) -> Node {
    // The mesh address the link and the router both key on comes out of this.
    // Its low two bytes are the `src_id` every fragment carries, so it must
    // differ between boards, which a seed per board (or, failing that, the
    // factory id) guarantees and a shared constant did not.
    let identity = identity::resolve(flash, rng);
    let link = radio::lora_link(LORA_NET_ID, lora_link::short_address_of(identity.mac));

    let trickle = [TrickleParams {
        i_min: core::time::Duration::from_secs(5),
        i_max: core::time::Duration::from_secs(128),
    }];

    // Built at this board's capacities rather than the host defaults.
    let mut driver: Node =
        Driver::with_capacities(identity.mac, [link], EmbassyClock, &trickle, &[], &["lora"]);

    // Before anything is emitted, so a stored credential signs this node's
    // first OGM rather than its second. Only the outcome is logged: with no
    // management port, nothing on this board can act on a refusal but an
    // operator reading the log.
    if let Some(record) = &identity.record {
        match driver.restore(record) {
            Restored::Authenticated => info!("restored membership credential from flash"),
            Restored::Unauthenticated => {}
            Restored::Refused(why) => {
                error!(?why, "stored credential refused; routing unauthenticated")
            }
        }
    }
    driver
}
