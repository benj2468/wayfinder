//! [`SubghzSpiDevice`]: the `SUBGHZSPI` bus presented as an
//! `embedded-hal-async` **device**.
//!
//! `lora-phy` wants a `SpiDevice` — a bus plus a chip-select it owns — while
//! `embassy_stm32::spi::Spi::new_subghz` gives a bare `SpiBus`. On a discrete
//! SX126x the gap is filled by an `ExclusiveDevice` driving an NSS pin. **There
//! is no pin here**: the sub-GHz radio's chip-select is
//! `PWR.SUBGHZSPICR.NSS`, a register bit, so the wrapper has to be written
//! rather than taken off the shelf.
//!
//! Two details in [`SpiDevice::transaction`] are load-bearing and easy to drop:
//!
//! - **NSS is asserted low and deasserted high**, so the bit is *cleared* to
//!   select the radio. It reads backwards from every GPIO chip-select.
//! - **NSS is deasserted on every way out of a transaction** — an operation
//!   failing, and the transaction future being *dropped* mid-transfer. Leaving
//!   the radio selected means the next transaction runs as a continuation of
//!   the abandoned one; the radio interprets the first byte as an opcode, so a
//!   desynchronised bus does not error, it executes something else.
//!
//!   The drop case is not hypothetical. `radio_task` races `lora-phy`'s `rx`
//!   against its transmit queue, and `rx` does SPI work of its own once the
//!   radio interrupts (IRQ status, payload, packet status). A transmit that
//!   arrives during those reads wins the race and drops `rx` inside a
//!   transaction. So the deassert lives in [`NssGuard`]'s `Drop`, not at the
//!   end of the function.

use embassy_stm32::mode::Async;
use embassy_stm32::pac;
use embassy_stm32::spi::Error as SpiError;
use embassy_stm32::spi::Spi;
use embassy_stm32::spi::mode::Master;
use embedded_hal_async::spi::ErrorType;
use embedded_hal_async::spi::Operation;
use embedded_hal_async::spi::SpiBus;
use embedded_hal_async::spi::SpiDevice;

/// The `SUBGHZSPI` bus, with the radio's register-backed chip-select.
///
/// The bus is private: the whole point of the type is that every access
/// selects and deselects the radio around it.
pub struct SubghzSpiDevice<'d>(Spi<'d, Async, Master>);

impl<'d> SubghzSpiDevice<'d> {
    /// Wrap the bus `Spi::new_subghz` returns.
    pub fn new(spi: Spi<'d, Async, Master>) -> Self {
        Self(spi)
    }
}

/// The radio selected for as long as this lives: NSS is asserted (cleared —
/// it is active low) on construction and deasserted on drop, including the
/// drop of a transaction future cancelled mid-transfer. See the module docs.
struct NssGuard;

impl NssGuard {
    /// Select the radio.
    fn assert() -> Self {
        pac::PWR.subghzspicr().modify(|w| w.set_nss(false));
        Self
    }
}

impl Drop for NssGuard {
    fn drop(&mut self) {
        pac::PWR.subghzspicr().modify(|w| w.set_nss(true));
    }
}

impl ErrorType for SubghzSpiDevice<'_> {
    type Error = SpiError;
}

impl SpiDevice<u8> for SubghzSpiDevice<'_> {
    async fn transaction(&mut self, operations: &mut [Operation<'_, u8>]) -> Result<(), SpiError> {
        let nss = NssGuard::assert();

        let mut result = Ok(());
        for op in operations {
            result = match op {
                Operation::Read(buf) => self.0.read(buf).await,
                Operation::Write(buf) => self.0.write(buf).await,
                Operation::Transfer(read, write) => self.0.transfer(read, write).await,
                Operation::TransferInPlace(buf) => self.0.transfer_in_place(buf).await,
                // A delay inside a transaction keeps NSS asserted, which is
                // what the trait specifies. `lora-phy` does not ask for one on
                // this part, so rather than pull in a timer just for it this
                // reports the operation as unsupported instead of silently
                // continuing without the wait.
                Operation::DelayNs(_) => Err(SpiError::Framing),
            };
            if result.is_err() {
                break;
            }
        }

        // Flushed on the error path too; a flush that fails does not change
        // what has to be done to NSS, which the guard does either way.
        // `SpiBus::flush` carries no buffer to infer the word type from, and
        // `Spi` implements the bus for both `u8` and `u16`, so it has to be
        // named explicitly.
        let flushed = SpiBus::<u8>::flush(&mut self.0).await;
        drop(nss);

        result.and(flushed)
    }
}
