#![cfg_attr(not(test), no_std)]

//! [`LinkT`] adapter for the nRF52840's built-in IEEE 802.15.4 radio
//! (`embassy_nrf::radio::ieee802154::Radio`).
//!
//! On-air framing is handled by the hardware-agnostic [`ieee802154`] crate
//! (see the `at86rf233` crate for the SPI-radio equivalent); this crate only
//! adapts [`ieee802154::encode`]/[`ieee802154::decode`] to `embassy-nrf`'s
//! [`Packet`] buffer and [`Radio::try_send`]/[`Radio::receive`].
//!
//! [`Packet::CAPACITY`] (125) equals [`ieee802154::MAX_FRAME_LEN`] (also 125),
//! so every frame [`ieee802154::encode`] produces fits in a [`Packet`] without
//! truncation; this is checked at compile time below.
//!
//! The caller constructs the [`Radio`] — it needs the real `RADIO` peripheral
//! and an interrupt binding, which exist only on real nRF52840 hardware — and
//! hands it to [`Ieee802154Link::new`].

use embassy_nrf::radio::Error as RadioError;
use embassy_nrf::radio::ieee802154::{Packet, Radio};
use ieee802154::{MAX_FRAME_LEN, decode, encode};
use interfaces::frame::{LinkFrameData, Mac};
use interfaces::link::{LinkError, LinkMetrics};
use wayfinder::link::{LinkT, Received};

const _: () = assert!(Packet::CAPACITY as usize == MAX_FRAME_LEN);

/// A [`LinkT`] mesh interface backed by the nRF52840's built-in IEEE 802.15.4
/// radio.
///
/// On-air framing is handled by [`ieee802154::encode`]/[`ieee802154::decode`];
/// this type adapts those to `embassy-nrf`'s [`Packet`] buffer. Construct with
/// [`Ieee802154Link::new`].
pub struct Ieee802154Link<'d> {
    radio: Radio<'d>,
    /// IEEE 802.15.4 sequence number for the next frame [`LinkT::send`]
    /// transmits, incremented (with wraparound) after each send.
    seq: u8,
    /// Scratch packet for the most recently received frame. [`LinkT::recv`]
    /// receives into this buffer and borrows from it for its returned
    /// [`Received`].
    rx_packet: Packet,
}

impl<'d> Ieee802154Link<'d> {
    /// Wrap an already-configured [`Radio`] as a [`LinkT`] mesh interface.
    pub fn new(radio: Radio<'d>) -> Self {
        Self {
            radio,
            seq: 0,
            rx_packet: Packet::new(),
        }
    }
}

/// Map an `embassy-nrf` radio error to a [`LinkError`].
///
/// [`RadioError::CrcFailed`] (a corrupted received frame, from
/// [`Radio::receive`]) maps to [`LinkError::ReceiveFailed`], and
/// [`RadioError::ChannelInUse`] (clear-channel assessment found the channel
/// busy, from [`Radio::try_send`]) maps to [`LinkError::TransmitFailed`]. All
/// other variants — including any added later, since [`RadioError`] is
/// `#[non_exhaustive]` — map to [`LinkError::Io`].
fn map_err(err: RadioError) -> LinkError {
    match err {
        RadioError::CrcFailed(_) => LinkError::ReceiveFailed,
        RadioError::ChannelInUse => LinkError::TransmitFailed,
        _ => LinkError::Io,
    }
}

/// The nRF52840 radio has no software-controlled retry/ack and no SNR
/// concept: `send` performs hardware clear-channel assessment before
/// transmitting and reports a busy channel as [`LinkError::TransmitFailed`];
/// `recv` reports the hardware [`Packet::lqi`] as [`LinkMetrics::quality`],
/// leaving `rssi_dbm` and `snr_db` as `None`.
impl<'d> LinkT for Ieee802154Link<'d> {
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        let mut buf = [0u8; MAX_FRAME_LEN];
        let n = encode(self.seq, origin, data, &mut buf)?;
        self.seq = self.seq.wrapping_add(1);

        let mut packet = Packet::new();
        packet.copy_from_slice(&buf[..n]);
        self.radio.try_send(&mut packet).await.map_err(map_err)?;

        Ok(n)
    }

    async fn recv<'a>(&'a mut self) -> Result<Received<'a>, LinkError> {
        self.radio
            .receive(&mut self.rx_packet)
            .await
            .map_err(map_err)?;

        let frame = decode(&self.rx_packet)?;
        Ok(Received {
            frame,
            metrics: LinkMetrics {
                rssi_dbm: None,
                snr_db: None,
                quality: Some(self.rx_packet.lqi()),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// `map_err` distinguishes the two `RadioError` variants `recv`/`send`
    /// can actually produce (`CrcFailed` from [`Radio::receive`],
    /// `ChannelInUse` from [`Radio::try_send`]) and falls back to
    /// [`LinkError::Io`] for everything else, including future
    /// `#[non_exhaustive]` variants.
    #[test]
    fn map_err_distinguishes_known_variants() {
        assert!(matches!(
            map_err(RadioError::CrcFailed(0)),
            LinkError::ReceiveFailed
        ));
        assert!(matches!(
            map_err(RadioError::ChannelInUse),
            LinkError::TransmitFailed
        ));
        assert!(matches!(map_err(RadioError::BufferTooLong), LinkError::Io));
    }

    /// `ieee802154::encode`'s output round-trips through
    /// [`Packet::copy_from_slice`] / [`Deref`](core::ops::Deref) /
    /// `ieee802154::decode`, exactly as [`Ieee802154Link::send`]/`recv` use
    /// it (`send` via the encode + `copy_from_slice` half, `recv` via the
    /// `Deref` + `decode` half).
    #[test]
    fn encoded_frame_round_trips_through_packet() {
        let mut buf = [0u8; MAX_FRAME_LEN];
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let n = encode(
            7,
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0x4305,
                payload: &payload,
            },
            &mut buf,
        )
        .unwrap();

        let mut packet = Packet::new();
        packet.copy_from_slice(&buf[..n]);

        let frame = decode(&packet).unwrap();
        assert_eq!(frame.src, mac(1));
        assert_eq!(frame.dst, mac(2));
        assert_eq!(frame.protocol.get(), 0x4305);
        assert_eq!(&frame.payload, &payload);
    }

    /// A maximum-size encoded frame (`MAX_FRAME_LEN` bytes, the largest
    /// `encode` will ever produce) exactly fills a `Packet`'s capacity
    /// without panicking in `copy_from_slice`.
    #[test]
    fn max_size_frame_fits_in_packet() {
        let mut buf = [0u8; MAX_FRAME_LEN];
        let payload = [0u8; ieee802154::MAX_PAYLOAD_LEN];
        let n = encode(
            0,
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0,
                payload: &payload,
            },
            &mut buf,
        )
        .unwrap();
        assert_eq!(n, MAX_FRAME_LEN);

        let mut packet = Packet::new();
        packet.copy_from_slice(&buf[..n]);
        assert_eq!(packet.len(), MAX_FRAME_LEN as u8);
    }
}
