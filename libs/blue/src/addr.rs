//! The BLE advertiser address: this driver's fragment-reassembly key address
//! type (see `wayfinder_link_utils::FragKey`).
//!
//! Reassembly keyed on this address needs two properties, and BLE only gives
//! one of them for free:
//!
//! - **Distinctness** between senders — free. Unlike RYLR998's configured
//!   `AT+ADDRESS`, a BLE address is globally distinct per physical device and
//!   reported on every scan report, so no deployment-time configuration is
//!   needed to keep keys from colliding.
//! - **Stability** for as long as a frame is on the air — *not* free, and the
//!   trap. A frame spans several fragments, and BLE privacy is designed to
//!   rotate the advertising address. The nRF backend gets stability from the
//!   SoftDevice's static identity address; the BlueZ backend needs
//!   `Privacy = device` in the host's `main.conf` (see
//!   `crate::std_link::BluerAdvertiser`). Nothing here enforces it — see
//!   `libs/blue/CLAUDE.md`.

/// A 6-byte BLE device address (public or random; this driver doesn't
/// distinguish the two, since it only ever compares addresses for equality
/// as a reassembly key).
///
/// The byte array is private so a reassembly key can only be minted from a
/// real reported address via [`From`], not assembled ad hoc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BleAddr([u8; 6]);

impl BleAddr {
    /// The address's six bytes, most-significant first, as the reporting
    /// stack supplied them.
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl From<[u8; 6]> for BleAddr {
    fn from(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_round_trips() {
        let addr = BleAddr::from([1, 2, 3, 4, 5, 6]);
        assert_eq!(addr.as_bytes(), &[1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn equality_is_byte_equality() {
        assert_eq!(BleAddr::from([0; 6]), BleAddr::from([0; 6]));
        assert_ne!(BleAddr::from([0; 6]), BleAddr::from([1, 0, 0, 0, 0, 0]));
    }
}
