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
//! - **The bus is flushed and NSS deasserted even when an operation fails.**
//!   Returning early on the error would leave the radio selected, and the next
//!   transaction would then run as a continuation of the abandoned one — the
//!   radio interprets the first byte as an opcode, so a desynchronised bus does
//!   not error, it executes something else.

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
pub struct SubghzSpiDevice<'d>(pub Spi<'d, Async, Master>);

impl ErrorType for SubghzSpiDevice<'_> {
    type Error = SpiError;
}

impl SpiDevice<u8> for SubghzSpiDevice<'_> {
    async fn transaction(&mut self, operations: &mut [Operation<'_, u8>]) -> Result<(), SpiError> {
        // Assert: NSS is active low, so this *clears* the bit.
        pac::PWR.subghzspicr().modify(|w| w.set_nss(false));

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

        // Both of these must happen on the error path too — see the module
        // docs. A flush that fails does not change what has to be done to NSS.
        // `SpiBus::flush` carries no buffer to infer the word type from, and
        // `Spi` implements the bus for both `u8` and `u16`, so it has to be
        // named explicitly.
        let flushed = SpiBus::<u8>::flush(&mut self.0).await;
        pac::PWR.subghzspicr().modify(|w| w.set_nss(true));

        result.and(flushed)
    }
}
