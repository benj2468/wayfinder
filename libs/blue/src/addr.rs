//! The BLE advertiser address, as reported by the scan stack.
//!
//! **No longer the fragment-reassembly key** (see `crate::frame::ORIGIN_LEN`)
//! — it was, until a `btmon` capture against a real BlueZ controller showed
//! the address rotating on *every* advertising-set registration despite
//! `Privacy = device` being set correctly, so no multi-fragment message's
//! fragments ever shared one. Kept only for diagnostics (logging, RSSI
//! association) — see `libs/blue/CLAUDE.md`.

/// A 6-byte BLE device address, public or random — this driver never
/// distinguishes the two, only compares them for equality.
///
/// The byte array is private so a value can only be minted from a real
/// reported address via [`From`], not assembled ad hoc.
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
