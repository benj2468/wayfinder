//! The BLE advertiser address: this driver's fragment-reassembly key address
//! type (see `wayfinder_link_utils::FragKey`). Unlike RYLR998's configured
//! `AT+ADDRESS`, a BLE address is already globally distinct per physical
//! device and reported on every scan report, so no deployment-time
//! configuration is needed to keep reassembly keys from colliding.

/// A 6-byte BLE device address (public or random; this driver doesn't
/// distinguish the two, since it only ever compares addresses for equality
/// as a reassembly key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BleAddr(pub [u8; 6]);

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
        assert_eq!(addr.0, [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn equality_is_byte_equality() {
        assert_eq!(BleAddr::from([0; 6]), BleAddr::from([0; 6]));
        assert_ne!(BleAddr::from([0; 6]), BleAddr::from([1, 0, 0, 0, 0, 0]));
    }
}
