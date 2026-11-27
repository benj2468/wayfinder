//! The byte layout of a node's **stored** revocation list (design 03 §3.1.1).
//!
//! ```text
//! version: u8 = 1 | count: u16 (big-endian) | count × RevocationRecord
//! ```
//!
//! This is a storage format, not a wire format: it never crosses the mesh.
//!
//! **Decoding is not verification.** A decoded record must still pass
//! [`TrustAnchor::verify_revocation`](crate::TrustAnchor::verify_revocation)
//! before it is enforced, which is also where a record's own
//! [`version`](RevocationRecord::version) is checked. Re-verifying on load is
//! why editing the store cannot forge a revocation (it can remove one).

use zerocopy::FromBytes;
use zerocopy::IntoBytes;

use crate::error::AuthError;
use crate::revoke::RevocationRecord;

/// Version byte of the stored list; the only version accepted.
///
/// Independent of [`REVOKE_VERSION`](crate::REVOKE_VERSION), which versions
/// the records inside it.
pub const REVOCATION_LOG_VERSION: u8 = 1;

/// Bytes ahead of the first record: the version and the big-endian count.
const HEADER_LEN: usize = 3;

/// The encoded size of a list of `count` records, for sizing a buffer.
///
/// `None` if `count` does not fit the layout's 16-bit field, or the size does
/// not fit a `usize`.
#[must_use]
pub const fn revocation_log_len(count: usize) -> Option<usize> {
    if count > u16::MAX as usize {
        return None;
    }
    match count.checked_mul(RevocationRecord::SERIALIZED_LEN) {
        Some(body) => body.checked_add(HEADER_LEN),
        None => None,
    }
}

/// Encode `records`, in order, into the front of `out`, returning the number
/// of bytes written.
///
/// `None` if `out` is too small or there are more records than the 16-bit
/// count can say. `out` then holds a partial encoding that must not be stored.
#[must_use]
pub fn encode_revocation_log<'a>(
    records: impl IntoIterator<Item = &'a RevocationRecord>,
    out: &mut [u8],
) -> Option<usize> {
    let (header, mut body) = out.split_at_mut_checked(HEADER_LEN)?;
    let mut count: u16 = 0;
    for record in records {
        count = count.checked_add(1)?;
        let (slot, rest) = body.split_at_mut_checked(RevocationRecord::SERIALIZED_LEN)?;
        slot.copy_from_slice(record.as_bytes());
        body = rest;
    }
    let [hi, lo] = count.to_be_bytes();
    header.copy_from_slice(&[REVOCATION_LOG_VERSION, hi, lo]);
    revocation_log_len(usize::from(count))
}

/// Decode a stored list, borrowing its records from `bytes` without copying.
///
/// Strict, so that a damaged blob is never read as a shorter list:
/// [`AuthError::BadVersion`] for a version other than
/// [`REVOCATION_LOG_VERSION`], and [`AuthError::Malformed`] if the header is
/// cut short or the length is not exactly what `count` says.
///
/// A missing blob is the caller's to treat as an empty list; an empty slice is
/// malformed.
pub fn decode_revocation_log(bytes: &[u8]) -> Result<&[RevocationRecord], AuthError> {
    let (&[version, hi, lo], body) = bytes
        .split_first_chunk::<HEADER_LEN>()
        .ok_or(AuthError::Malformed)?;
    if version != REVOCATION_LOG_VERSION {
        return Err(AuthError::BadVersion);
    }
    let count = usize::from(u16::from_be_bytes([hi, lo]));
    <[RevocationRecord]>::ref_from_bytes_with_elems(body, count).map_err(|_| AuthError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::Authority;
    use interfaces::frame::Mac;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    fn record(n: u8) -> RevocationRecord {
        Authority::from_seed(&[1u8; 32], 0xABCD).revoke(mac(n), 500, 1000)
    }

    /// An empty list is a header alone, and decodes back to no records.
    #[test]
    fn an_empty_list_round_trips() {
        let mut out = [0u8; 8];
        let len = encode_revocation_log(&[], &mut out).unwrap();
        assert_eq!(&out[..len], &[1, 0, 0]);
        assert!(decode_revocation_log(&out[..len]).unwrap().is_empty());
    }

    /// The stored layout is pinned byte for byte: version, big-endian count,
    /// then each record's own bytes in order. A change here orphans every
    /// list already on a disk or in flash.
    #[test]
    fn the_layout_is_pinned() {
        let records = [record(7), record(8)];
        let mut out = [0u8; 256];
        let len = encode_revocation_log(&records, &mut out).unwrap();

        assert_eq!(len, 3 + 2 * 92);
        assert_eq!(&out[..3], &[1, 0, 2]);
        assert_eq!(&out[3..95], records[0].as_bytes());
        assert_eq!(&out[95..187], records[1].as_bytes());
    }

    /// Records come back unchanged, in order, and still verify.
    #[test]
    fn records_round_trip_and_still_verify() {
        let anchor = Authority::from_seed(&[1u8; 32], 0xABCD).trust_anchor();
        let mut out = [0u8; 256];
        let len = encode_revocation_log(&[record(7), record(8)], &mut out).unwrap();

        let decoded = decode_revocation_log(&out[..len]).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(anchor.verify_revocation(&decoded[0], 0), Ok(mac(7)));
        assert_eq!(anchor.verify_revocation(&decoded[1], 0), Ok(mac(8)));
    }

    /// The encoder takes any iterator of records, so a caller whose list
    /// holds them inside larger entries need not collect them first.
    #[test]
    fn encodes_from_a_mapped_iterator() {
        let entries = [(record(7), 3u8)];
        let mut out = [0u8; 95];
        assert_eq!(
            encode_revocation_log(entries.iter().map(|(r, _)| r), &mut out),
            Some(95)
        );
    }

    /// The largest blob per capacity profile matches design 03's table.
    #[test]
    fn blob_sizes_match_the_design() {
        assert_eq!(revocation_log_len(0), Some(3));
        assert_eq!(revocation_log_len(4), Some(371));
        assert_eq!(revocation_log_len(8), Some(739));
        assert_eq!(revocation_log_len(1024), Some(94_211));
        assert_eq!(revocation_log_len(usize::from(u16::MAX) + 1), None);
    }

    /// A buffer one byte short is refused, for the header and for a record.
    #[test]
    fn a_short_buffer_is_refused() {
        assert_eq!(encode_revocation_log(&[], &mut [0u8; 2]), None);
        assert_eq!(encode_revocation_log(&[record(7)], &mut [0u8; 94]), None);
    }

    /// More records than the 16-bit count can say is refused, never wrapped.
    #[test]
    fn too_many_records_is_refused() {
        let one = record(7);
        let count = usize::from(u16::MAX) + 1;
        let mut out = std::vec![0u8; 3 + count * 92];
        assert_eq!(
            encode_revocation_log(core::iter::repeat_n(&one, count), &mut out),
            None
        );
    }

    /// A version this build does not know is an error, not an empty list.
    /// Erased flash (all ones) is one such version.
    #[test]
    fn an_unknown_version_is_refused() {
        for version in [0u8, 2, 0xFF] {
            assert_eq!(
                decode_revocation_log(&[version, 0, 0]).map(<[_]>::len),
                Err(AuthError::BadVersion),
                "version {version}"
            );
        }
    }

    /// A length that disagrees with `count` is an error in both directions:
    /// truncated, and with trailing bytes. Nothing is partially accepted.
    #[test]
    fn a_length_that_disagrees_with_the_count_is_refused() {
        let mut out = [0u8; 256];
        let len = encode_revocation_log(&[record(7), record(8)], &mut out).unwrap();

        for bad in (0..len).chain([len + 1]) {
            assert_eq!(
                decode_revocation_log(&out[..bad]).map(<[_]>::len),
                Err(AuthError::Malformed),
                "length {bad}"
            );
        }
        // The count itself damaged: claims more, then fewer, than are there.
        for count in [3u16, 1, u16::MAX] {
            out[1..3].copy_from_slice(&count.to_be_bytes());
            assert_eq!(
                decode_revocation_log(&out[..len]).map(<[_]>::len),
                Err(AuthError::Malformed),
                "count {count}"
            );
        }
    }
}
