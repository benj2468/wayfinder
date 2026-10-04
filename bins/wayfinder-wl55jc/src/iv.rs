//! The STM32WL's `lora-phy` [`InterfaceVariant`]: the three signals that are
//! GPIO pins on a discrete SX126x and **registers** on this part, plus the
//! NUCLEO-WL55JC1's antenna switch.
//!
//! This is the whole vendor-specific surface of the radio, and it exists
//! because `lora-phy`'s own `GenericSx126xInterfaceVariant` is unusable here:
//! it takes `OutputPin`s for reset and busy, and on the STM32WL neither is a
//! pin.
//!
//! | signal | discrete SX126x | STM32WL55 |
//! |---|---|---|
//! | reset | NRESET pin | `RCC.CSR.RFRST` |
//! | busy | BUSY pin | `PWR.SR2.RFBUSYS` |
//! | chip select | NSS pin | `PWR.SUBGHZSPICR.NSS`, set by `SubghzSpiDevice` |
//! | IRQ | DIO1 pin | the `SUBGHZ_RADIO` interrupt |
//!
//! Keeping it behind `InterfaceVariant` is what stops those registers leaking
//! into anything reusable — `libs/lora-link` knows nothing about them.

use embassy_stm32::interrupt::InterruptExt;
use embassy_stm32::pac;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use embedded_hal_async::delay::DelayNs;
use lora_phy::mod_params::RadioError;
use lora_phy::mod_traits::InterfaceVariant;

/// Fired by the `SUBGHZ_RADIO` interrupt, awaited by [`InterfaceVariant::await_irq`].
///
/// A [`Signal`] rather than a channel: the handler's only job is to say *an
/// event happened*, and `lora-phy` then reads the radio's own IRQ-status
/// register to find out which. Coalescing two events into one wake is
/// therefore harmless, and the handler must not touch the SPI bus.
pub static IRQ_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// The NUCLEO-WL55JC1's antenna switch, driven by three GPIOs, plus the PA
/// selection.
///
/// The pin roles follow the board's RF front end: `rf_switch_rx` is FE_CTRL1
/// (PC4), `rf_switch_tx` is FE_CTRL2 (PC5), and `rf_switch_en` is FE_CTRL3
/// (PC3). The three states this produces — receive, transmit on the low-power
/// PA, transmit on the high-power PA — match the switch's truth table; see
/// [`Self::new`].
pub struct Stm32wlInterfaceVariant<CTRL> {
    use_high_power_pa: bool,
    rf_switch_rx: CTRL,
    rf_switch_tx: CTRL,
    rf_switch_en: CTRL,
}

impl<CTRL> Stm32wlInterfaceVariant<CTRL>
where
    CTRL: embedded_hal::digital::OutputPin,
{
    /// Wire up the antenna switch.
    ///
    /// `use_high_power_pa` selects which of the SX126x's two power amplifiers
    /// the transmit path uses, and it must match how the board routes the
    /// antenna — the NUCLEO-WL55JC1 brings out RFO_HP. **Switching at runtime
    /// is not supported** (`lora_phy::sx126x::variant::Stm32wl` says so), so
    /// this is fixed at construction.
    ///
    /// All three pins are required. `lora-phy`'s trait allows a board with no
    /// switch at all, but this board has all three, and a missing one would
    /// leave the antenna disconnected from whichever path it names — which
    /// presents as a working radio with no range. Infallible for the same
    /// reason: there is nothing left to check once the pins exist.
    pub fn new(
        use_high_power_pa: bool,
        rf_switch_rx: CTRL,
        rf_switch_tx: CTRL,
        rf_switch_en: CTRL,
    ) -> Self {
        Self {
            use_high_power_pa,
            rf_switch_rx,
            rf_switch_tx,
            rf_switch_en,
        }
    }
}

impl<CTRL> InterfaceVariant for Stm32wlInterfaceVariant<CTRL>
where
    CTRL: embedded_hal::digital::OutputPin,
{
    /// Pulse `RCC.CSR.RFRST`, the radio subsystem's reset.
    ///
    /// The delays bracket the pulse the way a discrete SX126x's NRESET line
    /// would be driven; the radio is not addressable until it has cleared, and
    /// `wait_on_busy` is what the caller uses to find out.
    async fn reset(&mut self, delay: &mut impl DelayNs) -> Result<(), RadioError> {
        pac::RCC.csr().modify(|w| w.set_rfrst(true));
        pac::RCC.csr().modify(|w| w.set_rfrst(false));
        delay.delay_ms(10).await;
        Ok(())
    }

    /// Spin until `PWR.SR2.RFBUSYS` clears.
    ///
    /// A busy-wait rather than an interrupt: the radio deasserts this within
    /// microseconds of a command, and it is read between SPI transactions
    /// rather than across an idle period, so there is nothing to sleep for.
    async fn wait_on_busy(&mut self) -> Result<(), RadioError> {
        while pac::PWR.sr2().read().rfbusys() {}
        Ok(())
    }

    /// Wait for the radio's own interrupt.
    ///
    /// The pending bit is cleared and the line unmasked *before* awaiting.
    /// Nothing is lost by the clear because the radio's IRQ line is
    /// **level**-triggered: it stays asserted until `lora-phy` clears the
    /// radio's IRQ status over SPI, so an event that already happened
    /// re-pends the moment the line is unmasked. The clear only discards a
    /// stale NVIC pending bit.
    ///
    /// `IRQ_SIGNAL` itself is never reset here, so a signal left set by an
    /// abandoned `rx` can satisfy one wait spuriously. `lora-phy` rereads the
    /// radio's IRQ status after every wake and treats "nothing set" as a
    /// spurious wake, so this costs a loop, not a wrong answer.
    async fn await_irq(&mut self) -> Result<(), RadioError> {
        // Clear then unmask, in that order: a stale pending bit left from the
        // previous operation would otherwise fire this immediately and report
        // an event that already happened.
        embassy_stm32::interrupt::SUBGHZ_RADIO.unpend();
        unsafe { embassy_stm32::interrupt::SUBGHZ_RADIO.enable() };
        IRQ_SIGNAL.wait().await;
        Ok(())
    }

    /// Receive: FE_CTRL2 low, FE_CTRL1 high, FE_CTRL3 high.
    async fn enable_rf_switch_rx(&mut self) -> Result<(), RadioError> {
        self.rf_switch_tx
            .set_low()
            .map_err(|_| RadioError::RfSwitchTx)?;
        self.rf_switch_rx
            .set_high()
            .map_err(|_| RadioError::RfSwitchRx)?;
        self.rf_switch_en
            .set_high()
            .map_err(|_| RadioError::RfSwitchRx)?;
        Ok(())
    }

    /// Transmit: FE_CTRL2 high, FE_CTRL3 high, and FE_CTRL1 **inverted from
    /// the PA selection** — low for the high-power path, high for the
    /// low-power one. That inversion is the switch's truth table, not a
    /// convenience, which is why it reads oddly.
    async fn enable_rf_switch_tx(&mut self) -> Result<(), RadioError> {
        if self.use_high_power_pa {
            self.rf_switch_rx.set_low()
        } else {
            self.rf_switch_rx.set_high()
        }
        .map_err(|_| RadioError::RfSwitchRx)?;
        self.rf_switch_tx
            .set_high()
            .map_err(|_| RadioError::RfSwitchTx)?;
        self.rf_switch_en
            .set_high()
            .map_err(|_| RadioError::RfSwitchTx)?;
        Ok(())
    }

    /// All three low, disconnecting the antenna from both paths.
    async fn disable_rf_switch(&mut self) -> Result<(), RadioError> {
        self.rf_switch_en
            .set_low()
            .map_err(|_| RadioError::RfSwitchTx)?;
        self.rf_switch_rx
            .set_low()
            .map_err(|_| RadioError::RfSwitchRx)?;
        self.rf_switch_tx
            .set_low()
            .map_err(|_| RadioError::RfSwitchTx)?;
        Ok(())
    }
}
