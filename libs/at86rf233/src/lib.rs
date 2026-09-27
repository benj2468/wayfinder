#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! Generic SPI driver for the Atmel/Microchip AT86RF233 IEEE 802.15.4 radio
//! transceiver, exposed as a Wayfinder [`LinkT`] mesh interface.
//!
//! Unlike the nRF52840's built-in radio, the AT86RF233 is a discrete chip
//! connected over SPI plus two GPIOs (an interrupt-request line and an
//! active-low reset), so this driver is generic over
//! [`embedded_hal_async::spi::SpiDevice`], [`embedded_hal_async::digital::Wait`],
//! and [`embedded_hal::digital::OutputPin`] — any MCU with an
//! `embedded-hal-async` implementation can drive a radio connected this way.
//!
//! The driver runs the chip in its "basic" operating mode (`RX_ON`/`PLL_ON`,
//! no hardware auto-ACK or CSMA-CA retries), matching the broadcast,
//! no-acknowledgement frames [`ieee802154::build_fragment`] produces. On-air
//! framing and fragmentation are handled by the [`ieee802154`] crate; this
//! driver speaks only the chip's SPI register and frame-buffer protocol.

use embedded_hal::digital::OutputPin;
use embedded_hal_async::digital::Wait;
use embedded_hal_async::spi::Operation;
use embedded_hal_async::spi::SpiDevice;
use ieee802154::FragmentSpec;
use ieee802154::Ieee802154Reassembler;
use ieee802154::MAX_FRAME_LEN;
use ieee802154::MAX_REASSEMBLED_LEN;
use ieee802154::accept_fragment;
use ieee802154::assemble_frame;
use ieee802154::build_fragment;
use ieee802154::decode_frame;
use ieee802154::fragment_count;
use ieee802154::short_address_of;
use interfaces::frame::LinkFrameData;
use interfaces::frame::Mac;
use interfaces::link::LinkError;
use interfaces::link::LinkMetrics;
use wayfinder::link::LinkT;
use wayfinder::link::Received;

/// AT86RF233 register address: TRX_STATUS. Bits 0-4 report the radio
/// transceiver's current state-machine state ([`STATE_TRX_OFF`],
/// [`STATE_PLL_ON`], [`STATE_RX_ON`], etc.); bits 5-7 report CCA results and
/// are ignored by this driver.
const REG_TRX_STATUS: u8 = 0x01;

/// AT86RF233 register address: TRX_STATE. Writing a state or command value
/// (e.g. [`STATE_PLL_ON`], [`CMD_TX_START`]) to bits 0-4 requests a state
/// transition or triggers an action.
const REG_TRX_STATE: u8 = 0x02;

/// AT86RF233 register address: PHY_CC_CCA. Bits 0-4 select the operating
/// channel; valid values are 11-26 for the 2.4 GHz ISM band.
const REG_PHY_CC_CCA: u8 = 0x08;

/// AT86RF233 register address: IRQ_MASK. Selects which [`REG_IRQ_STATUS`]
/// bits assert the IRQ pin.
const REG_IRQ_MASK: u8 = 0x0e;

/// AT86RF233 register address: IRQ_STATUS. Pending interrupt flags; reading
/// this register clears it.
const REG_IRQ_STATUS: u8 = 0x0f;

/// TRX_STATUS / TRX_STATE value: TRX_OFF. Oscillator running, synthesizer and
/// receiver/transmitter off — the state a hardware reset leaves the chip in.
const STATE_TRX_OFF: u8 = 0x08;

/// TRX_STATUS / TRX_STATE value: PLL_ON. Synthesizer locked and ready to
/// transmit; required before writing the frame buffer for a send.
const STATE_PLL_ON: u8 = 0x09;

/// TRX_STATUS / TRX_STATE value: RX_ON. Receiver enabled and listening for
/// incoming frames. The driver's resting state between operations.
const STATE_RX_ON: u8 = 0x06;

/// TRX_STATE command: TX_START. Begins transmitting the frame currently
/// loaded into the frame buffer. Valid only from [`STATE_PLL_ON`]; not a
/// stable [`REG_TRX_STATUS`] value, so it is never passed to
/// [`At86Rf233::wait_for_state`].
const CMD_TX_START: u8 = 0x02;

/// Mask for the state-machine bits of [`REG_TRX_STATUS`] / [`REG_TRX_STATE`]
/// (bits 0-4).
const TRX_STATUS_MASK: u8 = 0x1f;

/// Mask for the channel field of [`REG_PHY_CC_CCA`] (bits 0-4).
const CHANNEL_MASK: u8 = 0x1f;

/// [`REG_IRQ_STATUS`] / [`REG_IRQ_MASK`] bit: TRX_END. Set when a frame
/// transmission or reception completes; the only interrupt this driver
/// enables.
const IRQ_TRX_END: u8 = 0x08;

/// SPI command byte prefix for a register read: bits 7-6 = `10`, bits 5-0 =
/// the 6-bit register address.
const CMD_REG_READ: u8 = 0x80;

/// SPI command byte prefix for a register write: bits 7-6 = `11`, bits 5-0 =
/// the 6-bit register address.
const CMD_REG_WRITE: u8 = 0xc0;

/// SPI command byte for a frame buffer write (preparing a frame to
/// transmit). Followed by a PHY header length byte and that many minus
/// [`FCS_LEN`] data bytes; the hardware computes and appends the FCS.
const CMD_FRAME_WRITE: u8 = 0x60;

/// SPI command byte for a frame buffer read (reading a received frame). The
/// chip clocks out a PHY header length byte, the received PSDU (data plus
/// [`FCS_LEN`] FCS bytes), and a trailing LQI byte.
const CMD_FRAME_READ: u8 = 0x20;

/// IEEE 802.15.4 `aMaxPHYPacketSize`: the largest PSDU the frame buffer holds,
/// including the trailing FCS.
const MAX_PSDU_LEN: usize = 127;

/// Length in bytes of the FCS the hardware computes on transmit and checks
/// (but does not strip) on receive.
const FCS_LEN: usize = 2;

/// Bytes clocked during a frame buffer read, after the [`CMD_FRAME_READ`]
/// command byte: the PHY header length byte, up to [`MAX_PSDU_LEN`] PSDU
/// bytes, and a trailing LQI byte.
const FRAME_BUFFER_READ_LEN: usize = 1 + MAX_PSDU_LEN + 1;

/// Maximum number of register polls while waiting for a requested state
/// transition before giving up with [`LinkError::Io`].
const MAX_STATE_POLLS: usize = 1000;

/// A [`LinkT`] mesh interface backed by an AT86RF233 connected over SPI.
///
/// Generic over the SPI device, the chip's interrupt-request line, and its
/// active-low reset pin, so the same driver runs on any MCU with an
/// `embedded-hal-async` implementation. Construct with [`At86Rf233::new`].
pub struct At86Rf233<SPI, IRQ, RST> {
    spi: SPI,
    irq: IRQ,
    reset: RST,
    /// IEEE 802.15.4 sequence number for the next fragment [`LinkT::send`]
    /// transmits, incremented (with wraparound) after each one.
    seq: u8,
    /// Fragment-reassembly message id for the next *frame* [`LinkT::send`]
    /// transmits, incremented (with wraparound) after each one. Distinct from
    /// [`Self::seq`]: every fragment of one frame shares a `msg_id`, while
    /// each gets its own MAC sequence number.
    msg_id: u8,
    /// Assembled frame bytes being fragmented by the current [`LinkT::send`].
    tx_frame: [u8; MAX_REASSEMBLED_LEN],
    /// Scratch buffer for the most recently received fragment, filled by
    /// [`Self::read_frame_buffer`].
    rx_buf: [u8; MAX_FRAME_LEN],
    /// In-flight fragment reassemblies, keyed on peers' short addresses.
    reassembler: Ieee802154Reassembler,
    /// Landing buffer for a completed reassembly; [`LinkT::recv`] borrows its
    /// returned [`Received`] from this.
    rx_frame: [u8; MAX_REASSEMBLED_LEN],
}

impl<SPI, IRQ, RST> At86Rf233<SPI, IRQ, RST>
where
    SPI: SpiDevice,
    IRQ: Wait,
    RST: OutputPin,
{
    /// Bring up the radio: hardware-reset the chip, tune to `channel`, and
    /// leave it in [`STATE_RX_ON`] listening for frames with [`IRQ_TRX_END`]
    /// enabled.
    ///
    /// `channel` selects the IEEE 802.15.4 channel (valid range 11-26 for the
    /// 2.4 GHz band); it is masked to 5 bits and written directly to
    /// [`REG_PHY_CC_CCA`] without further validation.
    ///
    /// Returns [`LinkError::Io`] if the chip does not reach an expected state
    /// within a bounded number of register polls — e.g. it is not present,
    /// not powered, or wired incorrectly.
    pub async fn new(spi: SPI, irq: IRQ, reset: RST, channel: u8) -> Result<Self, LinkError> {
        let mut radio = Self {
            spi,
            irq,
            reset,
            seq: 0,
            msg_id: 0,
            tx_frame: [0u8; MAX_REASSEMBLED_LEN],
            rx_buf: [0u8; MAX_FRAME_LEN],
            reassembler: Ieee802154Reassembler::new(),
            rx_frame: [0u8; MAX_REASSEMBLED_LEN],
        };

        radio.reset_chip().await?;
        radio.set_state(STATE_PLL_ON).await?;
        radio.set_channel(channel).await?;
        radio.set_state(STATE_RX_ON).await?;
        radio.write_register(REG_IRQ_MASK, IRQ_TRX_END).await?;

        Ok(radio)
    }

    /// Pulse the active-low `/RST` pin and wait for the chip to settle into
    /// [`STATE_TRX_OFF`], the state a hardware reset always leaves it in.
    async fn reset_chip(&mut self) -> Result<(), LinkError> {
        self.reset.set_low().map_err(|_| LinkError::Io)?;
        self.reset.set_high().map_err(|_| LinkError::Io)?;
        self.wait_for_state(STATE_TRX_OFF).await
    }

    /// Read one register via the SPI register-read command.
    async fn read_register(&mut self, addr: u8) -> Result<u8, LinkError> {
        let mut buf = [CMD_REG_READ | (addr & 0x3f), 0u8];
        self.spi
            .transfer_in_place(&mut buf)
            .await
            .map_err(|_| LinkError::Io)?;
        Ok(buf[1])
    }

    /// Write one register via the SPI register-write command.
    async fn write_register(&mut self, addr: u8, value: u8) -> Result<(), LinkError> {
        self.spi
            .write(&[CMD_REG_WRITE | (addr & 0x3f), value])
            .await
            .map_err(|_| LinkError::Io)
    }

    /// Poll [`REG_TRX_STATUS`] until its state bits equal `state`, up to
    /// [`MAX_STATE_POLLS`] times.
    async fn wait_for_state(&mut self, state: u8) -> Result<(), LinkError> {
        for _ in 0..MAX_STATE_POLLS {
            if self.read_register(REG_TRX_STATUS).await? & TRX_STATUS_MASK == state {
                return Ok(());
            }
        }
        Err(LinkError::Io)
    }

    /// Request a state transition by writing [`REG_TRX_STATE`], then wait for
    /// [`REG_TRX_STATUS`] to confirm it.
    async fn set_state(&mut self, state: u8) -> Result<(), LinkError> {
        self.write_register(REG_TRX_STATE, state).await?;
        self.wait_for_state(state).await
    }

    /// Set the operating channel by read-modify-writing [`REG_PHY_CC_CCA`]'s
    /// channel field, preserving its other bits (CCA mode/threshold).
    async fn set_channel(&mut self, channel: u8) -> Result<(), LinkError> {
        let cca = self.read_register(REG_PHY_CC_CCA).await?;
        self.write_register(
            REG_PHY_CC_CCA,
            (cca & !CHANNEL_MASK) | (channel & CHANNEL_MASK),
        )
        .await
    }

    /// Load `data` (an encoded frame without its FCS) into the chip's frame
    /// buffer for transmission, with PHY header length `phr` (`data.len() +
    /// `[`FCS_LEN`]`).
    async fn write_frame_buffer(&mut self, phr: u8, data: &[u8]) -> Result<(), LinkError> {
        self.spi
            .transaction(&mut [
                Operation::Write(&[CMD_FRAME_WRITE, phr]),
                Operation::Write(data),
            ])
            .await
            .map_err(|_| LinkError::Io)
    }

    /// Read a received frame from the frame buffer into `self.rx_buf`,
    /// returning the PSDU length with the trailing [`FCS_LEN`]-byte FCS
    /// stripped, and the trailing LQI byte.
    ///
    /// Returns [`LinkError::MalformedFrame`] if the reported PHY header length
    /// is shorter than [`FCS_LEN`] or longer than [`MAX_PSDU_LEN`] — the PHR
    /// is the length byte the sender put on the air, so a bad one is the
    /// sender's fault (or noise), not this radio's.
    async fn read_frame_buffer(&mut self) -> Result<(usize, u8), LinkError> {
        let mut buf = [0u8; 1 + FRAME_BUFFER_READ_LEN];
        buf[0] = CMD_FRAME_READ;
        self.spi
            .transfer_in_place(&mut buf)
            .await
            .map_err(|_| LinkError::Io)?;

        let phr = buf[1] as usize;
        if !(FCS_LEN..=MAX_PSDU_LEN).contains(&phr) {
            return Err(LinkError::MalformedFrame);
        }
        let psdu_len = phr - FCS_LEN;
        self.rx_buf[..psdu_len].copy_from_slice(&buf[2..2 + psdu_len]);
        let lqi = buf[2 + phr];
        Ok((psdu_len, lqi))
    }
}

/// AT86RF233-specific notes: `send` transitions [`STATE_PLL_ON`] →
/// [`CMD_TX_START`] → [`STATE_RX_ON`], blocking on the IRQ line for
/// [`IRQ_TRX_END`] before returning. `recv` blocks on the same IRQ line for an
/// incoming frame and reports the chip's hardware LQI as
/// [`LinkMetrics::quality`] **unscaled**, which is correct here and is not an
/// oversight: the AT86RF23x appends a conformant IEEE 802.15.4 LQI already on
/// `0..=255`, the scale that field is defined on. The sibling
/// `nrf-ieee802154` must scale because the nRF52840 appends a correlator
/// indicator on `0..=63` instead. (Datasheet §14.3.8 "Link Quality
/// Indication": <https://ww1.microchip.com/downloads/en/DeviceDoc/Atmel-8351-MCU_Wireless-AT86RF233_Datasheet.pdf>.)
/// The AT86RF233 has no SNR concept, so
/// [`LinkMetrics::snr_db`] is always `None`, and `rssi_dbm` is left for a
/// future `PHY_RSSI` read.
impl<SPI, IRQ, RST> LinkT for At86Rf233<SPI, IRQ, RST>
where
    SPI: SpiDevice + Send,
    IRQ: Wait + Send,
    RST: OutputPin + Send,
{
    /// Fragment `data` and transmit every fragment, returning the total
    /// on-air bytes.
    ///
    /// A fragment that fails to transmit abandons the whole frame rather than
    /// sending the rest: the receiver cannot complete a reassembly missing a
    /// fragment, so the remaining airtime would be spent for nothing.
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        let frame_len = assemble_frame(origin, data, &mut self.tx_frame)?;
        let count = fragment_count(frame_len)?;
        let src_addr = short_address_of(origin);
        let msg_id = self.msg_id;
        self.msg_id = self.msg_id.wrapping_add(1);

        let mut sent = 0;
        for index in 0..count {
            let mut tx_buf = [0u8; MAX_FRAME_LEN];
            let n = build_fragment(
                &self.tx_frame[..frame_len],
                FragmentSpec {
                    seq: self.seq,
                    src_addr,
                    msg_id,
                    index,
                    count,
                },
                &mut tx_buf,
            )?;
            self.seq = self.seq.wrapping_add(1);

            self.set_state(STATE_PLL_ON).await?;
            self.write_frame_buffer((n + FCS_LEN) as u8, &tx_buf[..n])
                .await?;
            self.read_register(REG_IRQ_STATUS).await?; // clear any pending IRQ
            self.write_register(REG_TRX_STATE, CMD_TX_START).await?;
            self.irq.wait_for_high().await.map_err(|_| LinkError::Io)?;
            self.read_register(REG_IRQ_STATUS).await?; // ack TRX_END
            self.set_state(STATE_RX_ON).await?;
            sent += n;
        }

        Ok(sent)
    }

    /// Receive fragments until one completes a frame.
    ///
    /// A fragment that does not complete a message is not an event the driver
    /// has anything to do with, so this loops rather than returning — the
    /// driver's `recv` arm expects a whole frame or nothing.
    async fn recv<'a>(&'a mut self) -> Result<Received<'a>, LinkError> {
        let (len, metrics) = loop {
            self.irq.wait_for_high().await.map_err(|_| LinkError::Io)?;
            self.read_register(REG_IRQ_STATUS).await?; // ack TRX_END
            let (n, lqi) = self.read_frame_buffer().await?;

            let metrics = LinkMetrics {
                rssi_dbm: None,
                snr_db: None,
                quality: Some(lqi),
            };
            if let Some(complete) = accept_fragment(
                &mut self.reassembler,
                &self.rx_buf[..n],
                metrics,
                &mut self.rx_frame,
            ) {
                break complete;
            }
        };

        Ok(Received {
            frame: decode_frame(&self.rx_frame[..len])?,
            metrics,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::Mutex;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// Minimal AT86RF233 register + frame-buffer model. `registers` starts in
    /// [`STATE_TRX_OFF`] (the post-reset state); writing a "real" state value
    /// to [`REG_TRX_STATE`] instantly updates [`REG_TRX_STATUS`] to match,
    /// modeling the chip's state machine without real timing.
    struct FakeChip {
        registers: [u8; 0x40],
        /// One `[phr, ...frame buffer write data]` entry per frame-buffer
        /// write, in transmission order. A `Vec` of them rather than only the
        /// most recent because one `send` now writes one entry *per
        /// fragment*, and the per-fragment sequencing is what needs asserting.
        tx_frames: Vec<Vec<u8>>,
        /// `[phr, ...psdu (incl. FCS), lqi]` entries returned by successive
        /// frame-buffer reads, oldest first. A queue rather than one buffer
        /// because `recv` now loops until a fragment *completes* a frame, and
        /// a single-valued field could never drive that loop past its first
        /// iteration.
        rx_frames: VecDeque<Vec<u8>>,
    }

    impl FakeChip {
        fn new() -> Self {
            let mut registers = [0u8; 0x40];
            registers[REG_TRX_STATUS as usize] = STATE_TRX_OFF;
            Self {
                registers,
                tx_frames: Vec::new(),
                rx_frames: VecDeque::new(),
            }
        }
    }

    #[derive(Debug)]
    struct FakeSpiError;

    impl embedded_hal::spi::Error for FakeSpiError {
        fn kind(&self) -> embedded_hal::spi::ErrorKind {
            embedded_hal::spi::ErrorKind::Other
        }
    }

    #[derive(Clone)]
    struct FakeSpi(Arc<Mutex<FakeChip>>);

    impl embedded_hal::spi::ErrorType for FakeSpi {
        type Error = FakeSpiError;
    }

    impl SpiDevice for FakeSpi {
        async fn transaction(
            &mut self,
            operations: &mut [Operation<'_, u8>],
        ) -> Result<(), Self::Error> {
            let mut chip = self.0.lock().unwrap();
            match operations {
                [Operation::TransferInPlace(buf)] if buf[0] == CMD_FRAME_READ => {
                    // Peek: one `recv` iteration reads the PHR and then the
                    // body in two transactions, so the entry is only consumed
                    // once the body has been handed over.
                    let frame = chip.rx_frames.front().cloned().unwrap_or_default();
                    for i in 1..buf.len() {
                        buf[i] = frame.get(i - 1).copied().unwrap_or(0);
                    }
                    if buf.len() > 2 {
                        chip.rx_frames.pop_front();
                    }
                }
                [Operation::TransferInPlace(buf)] if buf[0] & 0xc0 == CMD_REG_READ => {
                    let addr = buf[0] & 0x3f;
                    buf[1] = chip.registers[addr as usize];
                }
                [Operation::Write(buf)] if buf[0] & 0xc0 == CMD_REG_WRITE => {
                    let addr = buf[0] & 0x3f;
                    let value = buf[1];
                    chip.registers[addr as usize] = value;
                    if addr == REG_TRX_STATE
                        && matches!(value, STATE_TRX_OFF | STATE_PLL_ON | STATE_RX_ON)
                    {
                        chip.registers[REG_TRX_STATUS as usize] = value;
                    }
                }
                [Operation::Write(hdr), Operation::Write(data)] if hdr[0] == CMD_FRAME_WRITE => {
                    let mut frame = Vec::with_capacity(1 + data.len());
                    frame.push(hdr[1]);
                    frame.extend_from_slice(data);
                    chip.tx_frames.push(frame);
                }
                _ => panic!("unexpected SPI transaction shape"),
            }
            Ok(())
        }
    }

    /// IRQ line that is always asserted, so `wait_for_high` always returns
    /// immediately. Sufficient for testing SPI sequencing without modeling
    /// real interrupt timing.
    struct FakeIrq;

    impl embedded_hal::digital::ErrorType for FakeIrq {
        type Error = core::convert::Infallible;
    }

    impl Wait for FakeIrq {
        async fn wait_for_high(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
        async fn wait_for_low(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
        async fn wait_for_rising_edge(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
        async fn wait_for_falling_edge(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
        async fn wait_for_any_edge(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    /// `/RST` pin that records nothing and never fails; [`FakeChip`] models
    /// the post-reset state directly.
    struct FakeReset;

    impl embedded_hal::digital::ErrorType for FakeReset {
        type Error = core::convert::Infallible;
    }

    impl OutputPin for FakeReset {
        fn set_low(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
        fn set_high(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    /// `new` resets the chip, tunes to the requested channel, leaves it in
    /// [`STATE_RX_ON`], and enables [`IRQ_TRX_END`].
    #[tokio::test]
    async fn new_brings_radio_to_rx_on_with_irq_enabled() {
        let chip = Arc::new(Mutex::new(FakeChip::new()));
        let radio = At86Rf233::new(FakeSpi(chip.clone()), FakeIrq, FakeReset, 17)
            .await
            .unwrap();
        drop(radio);

        let chip = chip.lock().unwrap();
        assert_eq!(
            chip.registers[REG_TRX_STATUS as usize] & TRX_STATUS_MASK,
            STATE_RX_ON
        );
        assert_eq!(chip.registers[REG_PHY_CC_CCA as usize] & CHANNEL_MASK, 17);
        assert_eq!(chip.registers[REG_IRQ_MASK as usize], IRQ_TRX_END);
    }

    /// If the chip never reports the expected state (e.g. not present or not
    /// wired up), `new` gives up after [`MAX_STATE_POLLS`] with
    /// [`LinkError::Io`] instead of looping forever.
    #[tokio::test]
    async fn new_returns_io_error_if_chip_never_reaches_trx_off() {
        let mut fake_chip = FakeChip::new();
        fake_chip.registers[REG_TRX_STATUS as usize] = 0x00; // P_ON; never changes in this fake
        let chip = Arc::new(Mutex::new(fake_chip));

        assert!(matches!(
            At86Rf233::new(FakeSpi(chip), FakeIrq, FakeReset, 11).await,
            Err(LinkError::Io)
        ));
    }

    /// `send` fragments the frame, writes `[phr][fragment]` to the frame
    /// buffer, triggers [`CMD_TX_START`], and leaves the chip back in
    /// [`STATE_RX_ON`]. Successive sends increment the IEEE 802.15.4 sequence
    /// number.
    #[tokio::test]
    async fn send_writes_encoded_frame_and_returns_to_rx_on() {
        let chip = Arc::new(Mutex::new(FakeChip::new()));
        let mut radio = At86Rf233::new(FakeSpi(chip.clone()), FakeIrq, FakeReset, 11)
            .await
            .unwrap();

        let payload = [0xde, 0xad, 0xbe, 0xef];
        let n = radio
            .send(
                mac(1),
                &LinkFrameData {
                    dst: mac(2),
                    protocol: 0x4305,
                    payload: &payload,
                },
            )
            .await
            .unwrap();

        {
            let chip = chip.lock().unwrap();
            assert_eq!(chip.tx_frames.len(), 1, "a small frame is one fragment");
            let sent = &chip.tx_frames[0];
            assert_eq!(sent[0], (n + FCS_LEN) as u8);

            let mut reassembler = Ieee802154Reassembler::new();
            let mut out = [0u8; MAX_REASSEMBLED_LEN];
            let (len, _) = accept_fragment(
                &mut reassembler,
                &sent[1..],
                LinkMetrics::default(),
                &mut out,
            )
            .expect("a single-fragment frame completes on its own fragment");
            let frame = decode_frame(&out[..len]).unwrap();
            assert_eq!(frame.src, mac(1));
            assert_eq!(frame.dst, mac(2));
            assert_eq!(&frame.payload, &payload);
            assert_eq!(
                chip.registers[REG_TRX_STATUS as usize] & TRX_STATUS_MASK,
                STATE_RX_ON
            );
        }

        radio
            .send(
                mac(1),
                &LinkFrameData {
                    dst: mac(2),
                    protocol: 0x4305,
                    payload: &payload,
                },
            )
            .await
            .unwrap();

        // seq is the third byte of the encoded ieee802154 header.
        assert_eq!(chip.lock().unwrap().tx_frames[1][1 + 2], 1);
    }

    /// A frame too large for one 127-byte PHY frame is transmitted as several
    /// fragments: one frame-buffer write and one `TX_START` each, the MAC
    /// sequence number advancing per *fragment*, and the chip left in
    /// [`STATE_RX_ON`] at the end. `send` reports the total on-air bytes.
    #[tokio::test]
    async fn send_transmits_every_fragment_of_an_oversized_frame() {
        let chip = Arc::new(Mutex::new(FakeChip::new()));
        let mut radio = At86Rf233::new(FakeSpi(chip.clone()), FakeIrq, FakeReset, 11)
            .await
            .unwrap();

        // Three fragments' worth, matching design 19 §2.1's full-cert OGM.
        let payload = [0x5a; 250];
        let n = radio
            .send(
                mac(1),
                &LinkFrameData {
                    dst: mac(2),
                    protocol: 0x4305,
                    payload: &payload,
                },
            )
            .await
            .unwrap();

        let chip = chip.lock().unwrap();
        assert_eq!(chip.tx_frames.len(), 3);
        assert_eq!(
            n,
            chip.tx_frames.iter().map(|f| f.len() - 1).sum::<usize>(),
            "reported bytes are the sum of the fragments actually written"
        );
        // Each fragment carries its own MAC sequence number, ascending.
        for (i, sent) in chip.tx_frames.iter().enumerate() {
            assert_eq!(sent[1 + 2], i as u8);
        }
        assert_eq!(
            chip.registers[REG_TRX_STATUS as usize] & TRX_STATUS_MASK,
            STATE_RX_ON
        );
    }

    /// `recv` waits for the IRQ line, reads `[phr][psdu incl. FCS][lqi]` from
    /// the frame buffer, strips the FCS, reassembles the embedded
    /// `LinkFrame`, and reports the chip's LQI as [`LinkMetrics::quality`].
    #[tokio::test]
    async fn recv_reads_frame_buffer_and_reports_lqi() {
        let chip = Arc::new(Mutex::new(FakeChip::new()));
        let mut radio = At86Rf233::new(FakeSpi(chip.clone()), FakeIrq, FakeReset, 11)
            .await
            .unwrap();

        let payload = [0xca, 0xfe];
        let mut frame = [0u8; MAX_REASSEMBLED_LEN];
        let frame_len = assemble_frame(
            mac(3),
            &LinkFrameData {
                dst: mac(4),
                protocol: 0x4305,
                payload: &payload,
            },
            &mut frame,
        )
        .unwrap();
        let mut encoded = [0u8; MAX_FRAME_LEN];
        let n = build_fragment(
            &frame[..frame_len],
            FragmentSpec {
                seq: 5,
                src_addr: short_address_of(mac(3)),
                msg_id: 0,
                index: 0,
                count: 1,
            },
            &mut encoded,
        )
        .unwrap();

        {
            let mut chip = chip.lock().unwrap();
            let mut rx = Vec::new();
            rx.push((n + FCS_LEN) as u8);
            rx.extend_from_slice(&encoded[..n]);
            rx.extend_from_slice(&[0, 0]); // FCS bytes; not validated here
            rx.push(200); // LQI
            chip.rx_frames.push_back(rx);
        }

        let received = radio.recv().await.unwrap();
        assert_eq!(received.frame.src, mac(3));
        assert_eq!(received.frame.dst, mac(4));
        assert_eq!(received.frame.protocol.get(), 0x4305);
        assert_eq!(&received.frame.payload, &payload);
        assert_eq!(received.metrics.quality, Some(200));
        assert_eq!(received.metrics.rssi_dbm, None);
        assert_eq!(received.metrics.snr_db, None);
    }

    /// The fragments one `send` puts on the wire reassemble, through a second
    /// radio's `recv`, into exactly the frame that went in.
    ///
    /// This is the test that pins the send/recv pair *semantically* rather
    /// than structurally, and it is the one that catches the mistake the
    /// structural assertions cannot: moving `msg_id.wrapping_add(1)` inside
    /// the fragment loop still yields three fragments with ascending MAC
    /// sequence numbers and the right byte count, but gives each a distinct
    /// `FragKey`, so no receiver could ever complete a multi-fragment
    /// reassembly. The link would silently degrade to carrying only frames
    /// under 114 bytes — excluding the full-cert OGM this radio exists for.
    ///
    /// It also drives `recv`'s loop past its first iteration, which a
    /// single-fragment test cannot.
    #[tokio::test]
    async fn fragments_from_send_reassemble_through_recv() {
        let tx_chip = Arc::new(Mutex::new(FakeChip::new()));
        let mut tx = At86Rf233::new(FakeSpi(tx_chip.clone()), FakeIrq, FakeReset, 11)
            .await
            .unwrap();

        let payload = [0x5a; 250];
        tx.send(
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0x4305,
                payload: &payload,
            },
        )
        .await
        .unwrap();

        // Replay what the transmitter actually wrote into a receiver's frame
        // buffer, in order, shaped as the chip returns them:
        // `[phr][psdu incl. FCS][lqi]`.
        let rx_chip = Arc::new(Mutex::new(FakeChip::new()));
        {
            let sent = tx_chip.lock().unwrap();
            assert_eq!(sent.tx_frames.len(), 3, "250 bytes is three fragments");
            let mut rx = rx_chip.lock().unwrap();
            for fragment in &sent.tx_frames {
                let psdu = &fragment[1..];
                let mut entry = vec![(psdu.len() + FCS_LEN) as u8];
                entry.extend_from_slice(psdu);
                entry.extend_from_slice(&[0, 0]); // FCS, not validated here
                entry.push(200); // LQI
                rx.rx_frames.push_back(entry);
            }
        }

        let mut receiver = At86Rf233::new(FakeSpi(rx_chip), FakeIrq, FakeReset, 11)
            .await
            .unwrap();
        let received = receiver.recv().await.unwrap();

        assert_eq!(received.frame.src, mac(1));
        assert_eq!(received.frame.dst, mac(2));
        assert_eq!(received.frame.protocol.get(), 0x4305);
        assert_eq!(&received.frame.payload, &payload[..]);
        // The metrics belong to the fragment that *completed* the frame.
        assert_eq!(received.metrics.quality, Some(200));
    }

    /// A frame buffer read whose reported PHY header length is shorter than
    /// the FCS is rejected rather than underflowing the PSDU length
    /// computation.
    #[tokio::test]
    async fn recv_rejects_phr_shorter_than_fcs() {
        let chip = Arc::new(Mutex::new(FakeChip::new()));
        let mut radio = At86Rf233::new(FakeSpi(chip.clone()), FakeIrq, FakeReset, 11)
            .await
            .unwrap();

        chip.lock().unwrap().rx_frames.push_back(vec![1]); // phr = 1 < FCS_LEN

        assert!(matches!(radio.recv().await, Err(LinkError::MalformedFrame)));
    }
}
