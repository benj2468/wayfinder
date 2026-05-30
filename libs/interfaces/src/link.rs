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
