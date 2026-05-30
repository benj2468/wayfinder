use crate::frame::{LinkFrameData, MeshIdentifier};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LinkError {
    #[error("IO error")]
    Io,
    #[error("transmit failed")]
    TransmitFailed,
    #[error("receive failed")]
    ReceiveFailed,
    #[error("buffer full")]
    BufferFull,
    #[error("invalid packet")]
    InvalidPacket,
}

/// Per-frame physical-layer measurements reported by the radio.
///
/// Every field is optional because the available signal varies by hardware:
/// LoRa exposes RSSI/SNR, WiFi exposes RSSI plus MCS, a virtual/wired link
/// exposes nothing.  Consumers must tolerate any field being `None`.
///
/// Radios that natively expose a single normalized quality value may set
/// `quality` directly; the engine prefers that when present and otherwise
/// derives one from `rssi_dbm` / `snr_db`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkMetrics {
    /// Received signal strength of the frame in dBm.  Typical LoRa range is
    /// roughly `-130..=-30` and lower values indicate weaker signal.
    pub rssi_dbm: Option<i16>,
    /// Signal-to-noise ratio of the frame in dB.  Typical LoRa range is
    /// roughly `-20..=20`; higher is better.
    pub snr_db: Option<i8>,
    /// Pre-normalized link quality on a `0..=255` scale (matching BATMAN's
    /// TQ convention).  Set by drivers that know how to map their native
    /// metrics; leave `None` to let the engine apply a default curve.
    pub quality: Option<u8>,
}

/// The result of a single `EmbeddedMeshLink::receive` call: how many bytes
/// were written into the caller's buffer, paired with the radio's
/// observations of the frame.
#[derive(Debug, Clone, Copy)]
pub struct RxResult {
    /// Number of bytes written into the receive buffer.
    pub bytes: usize,
    /// Physical-layer measurements for the received frame.
    pub metrics: LinkMetrics,
}

pub trait EmbeddedMeshLink<Ident: MeshIdentifier> {
    /// Sends a raw frame out over the physical medium.
    /// If destination identifier is Broadcast, then the radio should broadcast it
    fn transmit(
        &mut self,
        data: LinkFrameData<'_, Ident>,
    ) -> impl Future<Output = Result<(), LinkError>>;

    /// Async blocking check to receive a frame from the radio.
    ///
    /// Returns the number of bytes written into `buf` along with any
    /// physical-layer metrics the radio observed for this frame (RSSI, SNR,
    /// etc.).  Radios that cannot measure a given metric leave the
    /// corresponding [`LinkMetrics`] field as `None`.
    fn receive(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<RxResult, LinkError>>;
}
