//! What every firmware image for the NUCLEO-WL55JC1 shares: the clock tree, the
//! on-die radio's vendor glue, and the antenna switch.
//!
//! Two images link this — the mesh node (`src/main.rs`) and the HIL echo
//! firmware (`examples/hil_reyax_echo.rs`) — and the point of the split is that
//! the details which present as "a radio with no range" when wrong (the TCXO,
//! `Bypass` HSE, the FE_CTRL truth table, which PA) exist once.
//!
//! **`bind_interrupts!` is deliberately not here**: each binary binds its own,
//! naming [`SubghzIrqHandler`]. A handler generated in a library rlib is only
//! linked if something in its object is referenced, and a `Binding` impl is not
//! a symbol — the reasoning `libs/wayfinder-nrf/src/usb_mgmt.rs` records for
//! the nRF's USB interrupt, which applies unchanged here.

#![no_std]

mod defmt_logger;
pub mod iv;
pub mod spi_device;

use embassy_stm32::Config;
use embassy_stm32::Peri;
use embassy_stm32::gpio::Level;
use embassy_stm32::gpio::Output;
use embassy_stm32::gpio::Speed;
use embassy_stm32::interrupt::InterruptExt;
use embassy_stm32::mode::Async;
use embassy_stm32::peripherals::PC3;
use embassy_stm32::peripherals::PC4;
use embassy_stm32::peripherals::PC5;
use embassy_stm32::rcc::Sysclk;
use embassy_stm32::spi::Spi;
use embassy_stm32::spi::mode::Master;
use lora_phy::sx126x::Config as Sx126xConfig;
use lora_phy::sx126x::Stm32wl;
use lora_phy::sx126x::TcxoCtrlVoltage;

use crate::iv::Stm32wlInterfaceVariant;
use crate::spi_device::SubghzSpiDevice;

/// Which of the SX126x's two power amplifiers transmit uses. This board brings
/// out RFO_HP. Named once because two consumers must agree on it: `lora-phy`'s
/// `Stm32wl` variant (PA configuration) and the antenna switch, whose transmit
/// truth table inverts FE_CTRL1 by PA — a disagreement transmits into the
/// wrong path and presents as a radio with no range.
pub const USE_HIGH_POWER_PA: bool = true;

/// Preamble length in symbols. Both ends must agree; 8 is the SX126x default
/// and what every other LoRa stack on this band uses.
pub const PREAMBLE_SYMBOLS: u16 = 8;

/// `embassy-stm32`'s cross-core handshake area.
///
/// Required by [`embassy_stm32::init_primary`] because this is a dual-core
/// part — there is no single-core `init` for it. **Where it lives does not
/// matter here**, unlike on a board that runs both cores: no image for this
/// board releases the CM0+ (none sets `C2BOOT`), so nothing else ever reads
/// this, and a plain `static` in `.bss` is enough. Placing it in a section
/// both cores agree on becomes necessary the day that changes — and so does
/// re-doing `memory.x`'s RAM budget, which spends the CM0+'s bank.
pub static SHARED_DATA: core::mem::MaybeUninit<embassy_stm32::SharedData> =
    core::mem::MaybeUninit::uninit();

/// The `SUBGHZ_RADIO` interrupt handler: wakes [`iv::IRQ_SIGNAL`] and nothing
/// else. Each binary names it in its own `bind_interrupts!` (see the module
/// docs for why the binding is not made here).
pub struct SubghzIrqHandler;

impl embassy_stm32::interrupt::typelevel::Handler<embassy_stm32::interrupt::typelevel::SUBGHZ_RADIO>
    for SubghzIrqHandler
{
    unsafe fn on_interrupt() {
        // Mask the line before signalling: the radio's IRQ status is cleared
        // by `lora-phy` over SPI, which cannot happen from here, so leaving it
        // unmasked would re-enter this handler forever.
        // `Stm32wlInterfaceVariant::await_irq` unmasks it again before each wait.
        embassy_stm32::interrupt::SUBGHZ_RADIO.disable();
        iv::IRQ_SIGNAL.signal(());
    }
}

/// The clock tree every image on this board runs: HSE32 off the radio's TCXO,
/// sysclk at 48 MHz from the PLL.
///
/// Radio bring-up, not performance tuning: HSE32 is the reference the
/// transceiver itself runs from, so the radio does not work without it.
///
/// **`Bypass`, not `Oscillator`.** On this board HSE is fed by the radio's
/// TCXO output rather than a plain crystal across OSC_IN/OSC_OUT, so driving
/// it as an oscillator leaves the clock dead — and a board whose HSE never
/// starts looks like a board that hung in `init`.
///
/// Sysclk then comes from the PLL (32 / 2 * 6 / 2 = 48 MHz, the part's
/// maximum) rather than straight off HSE, which would run the core at 32 MHz
/// for no reason.
pub fn clock_config() -> Config {
    use embassy_stm32::rcc::Hse;
    use embassy_stm32::rcc::HseMode;
    use embassy_stm32::rcc::HsePrescaler;
    use embassy_stm32::rcc::Pll;
    use embassy_stm32::rcc::PllMul;
    use embassy_stm32::rcc::PllPreDiv;
    use embassy_stm32::rcc::PllQDiv;
    use embassy_stm32::rcc::PllRDiv;
    use embassy_stm32::rcc::PllSource;

    let mut config = Config::default();
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
    config
}

/// Everything `lora_phy::sx126x::Sx126x::new` takes, assembled for this board.
pub struct RadioParts {
    /// The SUBGHZSPI bus, with the `PWR`-register chip select `lora-phy`
    /// cannot drive itself.
    pub spi: SubghzSpiDevice<'static>,
    /// Reset, busy, IRQ and the antenna switch.
    pub interface: Stm32wlInterfaceVariant<Output<'static>>,
    /// The transceiver's own configuration: PA, TCXO and DC-DC.
    pub sx_config: Sx126xConfig<Stm32wl>,
}

/// Assemble the on-die radio from the SUBGHZSPI bus and the antenna switch's
/// three pins.
///
/// The bus is built by the caller, because `Spi::new_subghz` needs the
/// binary's own `bind_interrupts!` struct.
pub fn radio_parts(
    subghz: Spi<'static, Async, Master>,
    fe_ctrl3: Peri<'static, PC3>,
    fe_ctrl1: Peri<'static, PC4>,
    fe_ctrl2: Peri<'static, PC5>,
) -> RadioParts {
    // The NUCLEO-WL55JC1's antenna switch: FE_CTRL1/2/3. Getting these wrong
    // presents as a working radio with no range, which is indistinguishable
    // from a routing bug from anywhere above `LinkT`.
    let fe_ctrl1 = Output::new(fe_ctrl1, Level::Low, Speed::High);
    let fe_ctrl2 = Output::new(fe_ctrl2, Level::Low, Speed::High);
    // FE_CTRL3 is the switch enable and idles high on this board.
    let fe_ctrl3 = Output::new(fe_ctrl3, Level::High, Speed::High);

    RadioParts {
        // A bare `SpiBus`; `lora-phy` wants a `SpiDevice`, and the chip-select
        // is a `PWR` register bit rather than a pin — hence the wrapper.
        spi: SubghzSpiDevice::new(subghz),
        interface: Stm32wlInterfaceVariant::new(USE_HIGH_POWER_PA, fe_ctrl1, fe_ctrl2, fe_ctrl3),
        sx_config: Sx126xConfig {
            chip: Stm32wl {
                use_high_power_pa: USE_HIGH_POWER_PA,
            },
            // This board *does* have a TCXO, on the radio's DIO3 supply. It is
            // the same 32 MHz reference `clock_config` bypasses in on, so
            // leaving this `None` gives the radio no reference at all.
            tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V7),
            use_dcdc: true,
            rx_boost: false,
        },
    }
}
