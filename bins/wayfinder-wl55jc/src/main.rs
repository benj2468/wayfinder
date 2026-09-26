//! NUCLEO-WL55JC1 (STM32WL55JC) firmware: the wayfinder mesh router on bare
//! metal over the LoRa radio **on the same die**.
//!
//! The third silicon family to run the same
//! [`wayfinder_embedded_driver::Driver`] the nRF boards run, and the first
//! whose radio is not a separate part: no UART to a module, no second vendor's
//! firmware in the path, and no AT commands. What that costs is a wire format,
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
//! management port and no durable store yet — so like `wayfinder-stm32f411`
//! this board's `Mac` is a compile-time constant. The management port is what
//! would make it reachable from `libs/wayfinder-hil`, and is the next step.

#![no_std]
#![no_main]

mod defmt_logger;
mod iv;
mod radio;
mod spi_device;

use embassy_executor::Spawner;
use embassy_stm32::Config;
use embassy_stm32::bind_interrupts;
use embassy_stm32::gpio::Level;
use embassy_stm32::gpio::Output;
use embassy_stm32::gpio::Speed;
use embassy_stm32::interrupt::InterruptExt;
use embassy_stm32::rcc::Sysclk;
use embassy_stm32::spi::Spi;
use embassy_time::Duration as EmbassyDuration;
use embassy_time::Instant;
use embassy_time::Timer;
use embedded_alloc::LlffHeap as Heap;
use lora_phy::mod_params::Bandwidth;
use lora_phy::mod_params::CodingRate;
use lora_phy::mod_params::SpreadingFactor;
use lora_phy::sx126x::Config as Sx126xConfig;
use lora_phy::sx126x::Stm32wl;
use lora_phy::sx126x::TcxoCtrlVoltage;
use panic_halt as _;
use tracing::error;
use tracing::info;
use wayfinder::interfaces::frame::Mac;
use wayfinder_embedded_driver::Clock;
use wayfinder_embedded_driver::Driver;
use wayfinder_embedded_driver::TrickleParams;

use crate::iv::Stm32wlInterfaceVariant;
use crate::radio::LoraLink;
use crate::radio::RadioConfig;
use crate::spi_device::SubghzSpiDevice;

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

/// This node's mesh identity. **Must be distinct per physical node**, and in
/// particular its low two bytes must be: that is the `src_id` every fragment
/// carries, and two nodes sharing it spoil each other's reassembly.
///
/// A compile-time constant only until this board has a durable store; see the
/// module docs.
const NODE_MAC: Mac = Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x03]);

/// The mesh discriminator carried in every fragment. A filter that keeps a
/// co-located mesh out of this one's reassembly table — **not** a security
/// boundary, which is `wayfinder-auth`'s job above `LinkT`.
const LORA_NET_ID: u8 = 18;

/// Which of the SX126x's two power amplifiers transmit uses. This board brings
/// out RFO_HP. Named once because two consumers must agree on it: `lora-phy`'s
/// `Stm32wl` variant (PA configuration) and the antenna switch, whose transmit
/// truth table inverts FE_CTRL1 by PA — a disagreement transmits into the
/// wrong path and presents as a radio with no range.
const USE_HIGH_POWER_PA: bool = true;

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
    // The radio's own interrupt. `iv::await_irq` unmasks it and waits on the
    // signal this handler sets; it must not touch the SPI bus.
    SUBGHZ_RADIO => crate::SubghzIrqHandler;
    // `SUBGHZSPI` transfers over DMA, so both channels' completion interrupts
    // have to be bound or `Spi::new_subghz` will not accept `Irqs`.
    DMA1_CHANNEL1 => embassy_stm32::dma::InterruptHandler<embassy_stm32::peripherals::DMA1_CH1>;
    DMA1_CHANNEL2 => embassy_stm32::dma::InterruptHandler<embassy_stm32::peripherals::DMA1_CH2>;
});

/// `embassy-stm32`'s cross-core handshake area.
///
/// Required by [`embassy_stm32::init_primary`] because this is a dual-core
/// part — there is no single-core `init` for it. **Where it lives does not
/// matter here**, unlike on a board that runs both cores: this firmware never
/// releases the CM0+ (it does not set `C2BOOT`), so nothing else ever reads
/// this, and a plain `static` in `.bss` is enough. Placing it in a section
/// both cores agree on becomes necessary the day that changes — and so does
/// re-doing `memory.x`'s RAM budget, which spends the CM0+'s bank.
static SHARED_DATA: core::mem::MaybeUninit<embassy_stm32::SharedData> =
    core::mem::MaybeUninit::uninit();

/// Wakes [`iv::IRQ_SIGNAL`] and nothing else.
struct SubghzIrqHandler;

impl embassy_stm32::interrupt::typelevel::Handler<embassy_stm32::interrupt::typelevel::SUBGHZ_RADIO>
    for SubghzIrqHandler
{
    unsafe fn on_interrupt() {
        // Mask the line before signalling: the radio's IRQ status is cleared
        // by `lora-phy` over SPI, which cannot happen from here, so leaving it
        // unmasked would re-enter this handler forever. `iv::await_irq`
        // unmasks it again before each wait.
        embassy_stm32::interrupt::SUBGHZ_RADIO.disable();
        iv::IRQ_SIGNAL.signal(());
    }
}

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

    // Radio bring-up, not performance tuning: HSE32 is the reference the
    // transceiver itself runs from, so the radio does not work without it.
    //
    // **`Bypass`, not `Oscillator`.** On this board HSE is fed by the radio's
    // TCXO output rather than a plain crystal across OSC_IN/OSC_OUT, so
    // driving it as an oscillator leaves the clock dead — and a board whose
    // HSE never starts looks like a board that hung in `init`.
    //
    // Sysclk then comes from the PLL (32 / 2 * 6 / 2 = 48 MHz, the part's
    // maximum) rather than straight off HSE, which would run the core at
    // 32 MHz for no reason.
    let mut config = Config::default();
    {
        use embassy_stm32::rcc::Hse;
        use embassy_stm32::rcc::HseMode;
        use embassy_stm32::rcc::HsePrescaler;
        use embassy_stm32::rcc::Pll;
        use embassy_stm32::rcc::PllMul;
        use embassy_stm32::rcc::PllPreDiv;
        use embassy_stm32::rcc::PllQDiv;
        use embassy_stm32::rcc::PllRDiv;
        use embassy_stm32::rcc::PllSource;

        config.rcc.hse = Some(Hse {
            freq: embassy_stm32::time::Hertz(32_000_000),
            mode: HseMode::Bypass,
            prescaler: HsePrescaler::DIV1,
        });
        config.rcc.sys = Sysclk::PLL1_R;
        config.rcc.pll = Some(Pll {
            source: PllSource::HSE,
            prediv: PllPreDiv::DIV2,
            mul: PllMul::MUL6,
            divp: None,
            divq: Some(PllQDiv::DIV2),
            divr: Some(PllRDiv::DIV2),
        });
    }
    let p = embassy_stm32::init_primary(config, &SHARED_DATA);

    // LD2, the green user LED, lit = firmware booted and reached the run loop.
    // Active high, and **PB9** — this board has three user LEDs (LD1 blue on
    // PB15, LD2 green on PB9, LD3 red on PB11), so the wrong one lights up
    // rather than nothing, which is the kind of mistake that survives a bench
    // test. Per Zephyr's `nucleo_wl55jc.dts`, whose `led0` alias is this pin.
    let mut led = Output::new(p.PB9, Level::Low, Speed::Low);

    // The NUCLEO-WL55JC1's antenna switch: FE_CTRL1/2/3. Getting these wrong
    // presents as a working radio with no range, which is indistinguishable
    // from a routing bug from anywhere above `LinkT`.
    let fe_ctrl1 = Output::new(p.PC4, Level::Low, Speed::High);
    let fe_ctrl2 = Output::new(p.PC5, Level::Low, Speed::High);
    // FE_CTRL3 is the switch enable and idles high on this board.
    let fe_ctrl3 = Output::new(p.PC3, Level::High, Speed::High);

    // A bare `SpiBus`; `lora-phy` wants a `SpiDevice`, and the chip-select is
    // a `PWR` register bit rather than a pin — hence the wrapper.
    let spi = SubghzSpiDevice::new(Spi::new_subghz(p.SUBGHZSPI, p.DMA1_CH1, p.DMA1_CH2, Irqs));

    let interface = Stm32wlInterfaceVariant::new(USE_HIGH_POWER_PA, fe_ctrl1, fe_ctrl2, fe_ctrl3);

    let sx_config = Sx126xConfig {
        chip: Stm32wl {
            use_high_power_pa: USE_HIGH_POWER_PA,
        },
        // This board *does* have a TCXO, on the radio's DIO3 supply. It is the
        // same 32 MHz reference `config.rcc.hse` bypasses in on, so leaving
        // this `None` gives the radio no reference at all.
        tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V7),
        use_dcdc: true,
        rx_boost: false,
    };

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

    let link = LoraLink::new(LORA_NET_ID, short_address_of(NODE_MAC));

    led.set_high();

    let trickle = [TrickleParams {
        i_min: core::time::Duration::from_secs(5),
        i_max: core::time::Duration::from_secs(128),
    }];

    // Built at this board's capacities rather than the host defaults.
    let mut driver: wayfinder_embedded_driver::driver_for!(_, _, 1, crate::wl55jc) =
        Driver::with_capacities(NODE_MAC, [link], EmbassyClock, &trickle, &[], &["lora"]);

    info!(lora = true, "wayfinder started");
    driver.run().await
}

/// The 16-bit short identity this node transmits under: the low two bytes of
/// its [`Mac`], big-endian.
///
/// The same derivation `ieee802154::short_address_of` uses, so a node's radios
/// agree — written out here rather than depending on the 802.15.4 crate for two
/// lines of arithmetic on a board that has no 802.15.4 radio.
fn short_address_of(mac: Mac) -> u16 {
    u16::from_be_bytes([mac.0[4], mac.0[5]])
}
