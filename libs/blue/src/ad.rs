//! BLE advertising-data (AD) structure framing for tagging and finding this
//! mesh's fragments among ambient BLE advertisements.
//!
//! Advertising data (and scan-response data) is a sequence of
//! length-prefixed AD structures (Bluetooth Core Spec, Vol 3, Part C,
//! §11): `[len][type][data (len-1 bytes)]...`. We use one Manufacturer
//! Specific Data structure (`type = 0xFF`) per fragment, whose data is
//! `[company_id: u16 LE][fragment bytes]`. [`MESH_COMPANY_ID`] is a marker,
//! not a real vendor registration — `0xFFFF` is the value the Bluetooth SIG
//! reserves for testing and never assigns to a vendor, which is why it's
//! usable here without registering one.
//!
//! Only the bare-metal backend builds and parses this framing itself; the
//! BlueZ one has the host stack do it from
//! `Advertisement::manufacturer_data` (see `crate::std_link`) and never calls
//! in here except for [`MESH_COMPANY_ID`]. Hence the `dead_code` allowance
//! below — off a `hardware` build, only this module's own tests exercise the
//! rest.

#![cfg_attr(not(feature = "hardware"), allow(dead_code))]

/// AD type for Manufacturer Specific Data (Bluetooth Core Spec assigned
/// numbers).
const AD_TYPE_MANUFACTURER_SPECIFIC: u8 = 0xFF;

/// TOOD(bjc) this should be configurable like we have for ethernet
/// Marker tag (not a real Bluetooth SIG company id — see the module doc)
/// distinguishing this mesh's advertisements from ambient BLE traffic.
pub const MESH_COMPANY_ID: u16 = 0xFFFF;

/// Bytes of AD-structure framing prefixed to a fragment's bytes: 1 length
/// byte + 1 type byte + 2 company-id bytes.
const AD_HDR_LEN: usize = 4;

/// Largest fragment payload (`[frag_header][body]` from
/// `wayfinder_link_utils`) one AD structure can carry — bounded by the
/// length byte's `u8` range, which also covers the type and company-id
/// bytes. This is the wire format's own ceiling; the actual transport
/// budget on legacy BLE advertising is far smaller — see
/// [`MAX_LEGACY_FRAGMENT_LEN`].
pub const MAX_FRAGMENT_LEN: usize = u8::MAX as usize - (AD_HDR_LEN - 1);

/// Largest total advertising-data length a legacy (non-extended) BLE
/// advertisement can carry (Bluetooth Core Spec, Vol 6, Part B, §2.3.4.9) —
/// the hard cap this crate stays within by fragmenting aggressively, rather
/// than using extended advertising's much larger per-PDU budget; see
/// `libs/blue/CLAUDE.md` for why extended advertising isn't used here.
/// `nrf_softdevice::ble::peripheral::start_adv` doesn't itself truncate or
/// reject an oversized buffer (it only asserts `data.len() < u16::MAX`) —
/// the SoftDevice firmware is what would reject a legacy advertisement
/// exceeding this, so this crate must stay under the cap on its own.
pub const MAX_LEGACY_ADV_DATA_LEN: usize = 31;

/// Largest fragment payload that fits one legacy advertisement, once our AD
/// structure's own framing is subtracted.
pub const MAX_LEGACY_FRAGMENT_LEN: usize = MAX_LEGACY_ADV_DATA_LEN - AD_HDR_LEN;

/// Build one Manufacturer-Specific-Data AD structure tagging `fragment` (a
/// pre-packed `[frag_header][body]` blob, see `wayfinder_link_utils`) as
/// this mesh's traffic: `[len][0xFF][company_id LE][fragment]`. Returns the
/// number of bytes written to `out`, or `None` if `fragment` exceeds
/// [`MAX_FRAGMENT_LEN`] or `out` is too small.
pub fn build_ad_structure(fragment: &[u8], out: &mut [u8]) -> Option<usize> {
    if fragment.len() > MAX_FRAGMENT_LEN {
        return None;
    }
    let total = AD_HDR_LEN + fragment.len();
    if out.len() < total {
        return None;
    }
    out[0] = (AD_HDR_LEN - 1 + fragment.len()) as u8;
    out[1] = AD_TYPE_MANUFACTURER_SPECIFIC;
    out[2..4].copy_from_slice(&MESH_COMPANY_ID.to_le_bytes());
    out[4..total].copy_from_slice(fragment);
    Some(total)
}

/// Scan a raw advertising-data buffer (a sequence of length-prefixed AD
/// structures) for our tagged Manufacturer Specific Data structure,
/// returning its fragment bytes (`[frag_header][body]`) if found. A
/// malformed AD structure (a length byte that would run past the buffer, or
/// `len == 0`) stops the scan rather than panicking — the remaining bytes
/// are untrusted input from the air.
pub fn find_mesh_fragment(adv_data: &[u8]) -> Option<&[u8]> {
    let mut pos = 0;
    while pos < adv_data.len() {
        let len = adv_data[pos] as usize;
        if len == 0 {
            return None;
        }
        let struct_end = pos + 1 + len;
        if struct_end > adv_data.len() {
            return None;
        }

        let ad_type = adv_data[pos + 1];
        let data = &adv_data[pos + 2..struct_end];
        if ad_type == AD_TYPE_MANUFACTURER_SPECIFIC && data.len() >= 2 {
            let company_id = u16::from_le_bytes([data[0], data[1]]);
            if company_id == MESH_COMPANY_ID {
                return Some(&data[2..]);
            }
        }
        pos = struct_end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_ad_structure_frames_length_type_and_company_id() {
        let fragment = [0xAA, 0xBB, 0xCC];
        let mut out = [0u8; 16];
        let n = build_ad_structure(&fragment, &mut out).unwrap();
        // len covers type(1) + company_id(2) + fragment(3) = 6.
        assert_eq!(&out[..n], &[6, 0xFF, 0xFF, 0xFF, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn build_ad_structure_rejects_output_too_small() {
        let fragment = [0xAA, 0xBB, 0xCC];
        let mut out = [0u8; 6];
        assert!(build_ad_structure(&fragment, &mut out).is_none());
    }

    #[test]
    fn build_ad_structure_rejects_oversized_fragment() {
        let fragment = [0u8; MAX_FRAGMENT_LEN + 1];
        let mut out = [0u8; 512];
        assert!(build_ad_structure(&fragment, &mut out).is_none());
    }

    #[test]
    fn find_mesh_fragment_extracts_our_tagged_structure() {
        let fragment = [1, 2, 3, 4];
        let mut ad = [0u8; 16];
        let n = build_ad_structure(&fragment, &mut ad).unwrap();
        assert_eq!(find_mesh_fragment(&ad[..n]), Some(&fragment[..]));
    }

    #[test]
    fn find_mesh_fragment_skips_unrelated_ad_structures() {
        // A Flags AD structure (type 0x01, common in real advertisements),
        // then our tagged structure.
        let mut adv = vec![2, 0x01, 0x06];
        let fragment = [9, 9];
        let mut tagged = [0u8; 16];
        let n = build_ad_structure(&fragment, &mut tagged).unwrap();
        adv.extend_from_slice(&tagged[..n]);
        assert_eq!(find_mesh_fragment(&adv), Some(&fragment[..]));
    }

    #[test]
    fn find_mesh_fragment_ignores_other_manufacturers_data() {
        // Manufacturer Specific Data (type 0xFF) but a different company id
        // -- must not be mistaken for our marker.
        let adv = [5, 0xFF, 0x4C, 0x00, 0x02, 0x15];
        assert_eq!(find_mesh_fragment(&adv), None);
    }

    #[test]
    fn find_mesh_fragment_returns_none_for_empty_or_no_match() {
        assert_eq!(find_mesh_fragment(&[]), None);
        assert_eq!(find_mesh_fragment(&[2, 0x01, 0x06]), None);
    }

    #[test]
    fn find_mesh_fragment_stops_on_malformed_length() {
        // Declared length runs past the buffer.
        assert_eq!(find_mesh_fragment(&[10, 0xFF, 0xFF, 0xFF]), None);
        // A zero length is malformed (every AD structure has at least a type byte).
        assert_eq!(find_mesh_fragment(&[0, 1, 2, 3]), None);
    }
}
