use thiserror::Error;

/// An error raised by a mesh link while transmitting or receiving a frame.
#[derive(Error, Debug)]
pub enum LinkError {
    /// A lower-level I/O operation on the link failed.
    #[error("IO error")]
    Io,
    /// The frame could not be transmitted onto the medium.
    #[error("transmit failed")]
    TransmitFailed,
    /// There is no radio behind this link, so nothing was — or ever will be —
    /// transmitted.
    ///
    /// Distinct from [`Self::TransmitFailed`], which means a real radio tried
    /// and failed. A board keeping its link array a fixed size uses this for
    /// slots whose hardware isn't wired: that is not a fault to warn about once
    /// per OGM, but it must not be recorded as a transmission either, or the
    /// absent interface publishes itself as live-and-idle.
    #[error("link not present")]
    NotPresent,
    /// A frame could not be received from the medium.
    #[error("receive failed")]
    ReceiveFailed,
    /// The supplied buffer was too small to hold the frame.
    #[error("buffer full")]
    BufferFull,
    /// The received bytes did not parse as a valid frame.
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
#[repr(C)]
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
