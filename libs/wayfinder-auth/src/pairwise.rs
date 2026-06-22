//! The per-frame pairwise authentication tag for the directed data plane.
//!
//! Unicast and multicast frames travel hop-by-hop to a single next-hop
//! neighbor, so they are authenticated with a cheap symmetric tag keyed by the
//! pairwise key both ends derive with [`Keypair::pairwise_key`](crate::Keypair::pairwise_key).
//! A monotonically increasing counter is bound into the tag for replay
//! resistance.  OGMs and broadcasts are one-to-many and cannot use a pairwise
//! tag — they are authenticated by the originator's signature instead.

use blake2::{Blake2s256, Digest};
use subtle::ConstantTimeEq;

/// Length in bytes of the on-wire authentication tag.  16 bytes (128 bits) is
/// ample for per-frame authentication while staying cheap on a LoRa frame.
pub const TAG_LEN: usize = 16;

/// Compute the authentication tag for one directed frame.
///
/// Binds the pairwise `key`, a per-`(src,dst)` monotonic `counter`, and the
/// frame bytes together with a domain-separated keyed BLAKE2s hash (BLAKE2 is
/// immune to length extension, so prefixing the key is a sound MAC).  The
/// `frame` bytes should cover the link header and payload so neither addressing
/// nor content can be altered without detection.  The receiver recomputes the
/// tag with [`verify_frame_tag`].
pub fn frame_tag(key: &[u8; 32], counter: u64, frame: &[u8]) -> [u8; TAG_LEN] {
    let mut h = Blake2s256::new();
    h.update(b"wayfinder-tag-v1");
    h.update(key);
    h.update(counter.to_be_bytes());
    h.update(frame);
    let full = h.finalize();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full[..TAG_LEN]);
    tag
}

/// Verify a frame's authentication `tag` in constant time.  Returns `true` only
/// if `tag` matches the tag recomputed from `key`, `counter`, and `frame`.  The
/// caller is responsible for rejecting a `counter` that is not strictly greater
/// than the last accepted one from this neighbor (replay defense).
pub fn verify_frame_tag(key: &[u8; 32], counter: u64, frame: &[u8], tag: &[u8; TAG_LEN]) -> bool {
    let expected = frame_tag(key, counter, frame);
    expected.ct_eq(tag).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tag verifies against the exact key/counter/frame it was made with.
    #[test]
    fn tag_roundtrips() {
        let key = [7u8; 32];
        let frame = b"dst|src|proto|payload";
        let tag = frame_tag(&key, 1, frame);
        assert!(verify_frame_tag(&key, 1, frame, &tag));
    }

    /// Changing the frame bytes invalidates the tag (integrity).
    #[test]
    fn tampered_frame_fails() {
        let key = [7u8; 32];
        let tag = frame_tag(&key, 1, b"original frame");
        assert!(!verify_frame_tag(&key, 1, b"tampered frame", &tag));
    }

    /// Replaying a tag under a different counter fails (replay resistance).
    #[test]
    fn counter_bound_into_tag() {
        let key = [7u8; 32];
        let frame = b"frame";
        let tag = frame_tag(&key, 1, frame);
        assert!(!verify_frame_tag(&key, 2, frame, &tag));
    }

    /// A different (e.g. foreign-mesh) key produces a different tag.
    #[test]
    fn wrong_key_fails() {
        let frame = b"frame";
        let tag = frame_tag(&[1u8; 32], 1, frame);
        assert!(!verify_frame_tag(&[2u8; 32], 1, frame, &tag));
    }
}
