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
/// A radio that natively produces a single normalized quality value may set
/// `quality` directly, and the engine then prefers it over `rssi_dbm` /
/// `snr_db`.  Doing so is a stronger promise than it looks — see that field's
/// docs for the scale it commits to and why nothing catches a breach.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct LinkMetrics {
    /// Received signal strength of the frame in dBm.  Typical LoRa range is
    /// roughly `-130..=-30` and lower values indicate weaker signal.
    pub rssi_dbm: Option<i16>,
    /// Signal-to-noise ratio of the frame in dB.  Typical LoRa range is
    /// roughly `-20..=20`; higher is better.
    pub snr_db: Option<i8>,
    /// Link quality as an IEEE 802.15.4-style LQI: `0..=255`, higher is
    /// better, `0` the worst compliant signal and `255` the best (which is
    /// also BATMAN's TQ convention).  Leave `None` to let the engine derive a
    /// score from `rssi_dbm`/`snr_db` instead.
    ///
    /// **This is a normalized score, not a hardware reading.** A `Some` is
    /// taken verbatim by `wayfinder::link_quality::normalize_quality`, then
    /// smoothed into the per-`(neighbor, interface)` EWMA that does two jobs:
    /// it clamps the TQ this node advertises for every path over the link,
    /// and it picks which interface a frame egresses on. So a value left on
    /// some narrower native scale silently suppresses routing through that
    /// radio — and loses it the egress race against a radio that reports on
    /// the right scale — rather than looking wrong anywhere.
    ///
    /// A driver whose hardware reports something else (a correlator
    /// indicator, an ED level, an SNR-derived index) must map it here, and
    /// pin that mapping to its datasheet with a unit test: nothing about the
    /// value itself distinguishes a correct LQI from an unscaled one.
    pub quality: Option<u8>,
}
