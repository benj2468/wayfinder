//! The per-frame pairwise authentication tag for the directed data plane.
//!
//! Unicast and multicast frames travel hop-by-hop to a single next-hop
//! neighbor, so they are authenticated with a cheap symmetric tag keyed by the
//! pairwise key both ends derive with [`Keypair::pairwise_key`](crate::Keypair::pairwise_key).
//! A monotonically increasing counter is bound into the tag for replay
//! resistance.  OGMs and broadcasts are one-to-many and cannot use a pairwise
//! tag — they are authenticated by the originator's signature instead.

use blake2::Blake2s256;
use blake2::Digest;
use subtle::ConstantTimeEq;

/// Length in bytes of the on-wire authentication tag.  16 bytes (128 bits) is
/// ample for per-frame authentication while staying cheap on a LoRa frame.
pub const TAG_LEN: usize = 16;

/// Compute the authentication tag for one directed frame.
///
/// Binds the pairwise `key`, a per-`(src,dst)` monotonic `counter`, a caller
/// `context`, and the `frame` bytes together with a domain-separated keyed
/// BLAKE2s hash (BLAKE2 is immune to length extension, so prefixing the key is a
/// sound MAC).  The receiver recomputes the tag with [`verify_frame_tag`].
///
/// `context` is essential when the `key` is symmetric across both directions of
/// a link (as the pairwise key is): the caller must bind the **sender's
/// identity** (e.g. its MAC) into `context` so a frame cannot be reflected back
/// to its author as if it came from the peer.  Without that, an `A→B` frame and
/// a `B→A` frame would be interchangeable under the same key.
pub fn frame_tag(key: &[u8; 32], counter: u64, context: &[u8], frame: &[u8]) -> [u8; TAG_LEN] {
    let mut h = Blake2s256::new();
    h.update(b"wayfinder-tag-v2");
    h.update(key);
    h.update(counter.to_be_bytes());
    // Length-prefix the context so it cannot be confused with the frame bytes.
    h.update((context.len() as u32).to_be_bytes());
    h.update(context);
    h.update(frame);
    let full = h.finalize();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full[..TAG_LEN]);
    tag
}

/// Verify a frame's authentication `tag` in constant time.  Returns `true` only
/// if `tag` matches the tag recomputed from `key`, `counter`, `context`, and
/// `frame`.  The caller is responsible for rejecting a `counter` that is not
/// strictly greater than the last accepted one from this neighbor (replay
/// defense) and for passing the **sender's** identity as `context` (see
/// [`frame_tag`]).
pub fn verify_frame_tag(
    key: &[u8; 32],
    counter: u64,
    context: &[u8],
    frame: &[u8],
    tag: &[u8; TAG_LEN],
) -> bool {
    let expected = frame_tag(key, counter, context, frame);
    expected.ct_eq(tag).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &[u8] = b"node-a";
    const B: &[u8] = b"node-b";

    /// A tag verifies against the exact key/counter/context/frame it was made with.
    #[test]
    fn tag_roundtrips() {
        let key = [7u8; 32];
        let frame = b"dst|src|proto|payload";
        let tag = frame_tag(&key, 1, A, frame);
        assert!(verify_frame_tag(&key, 1, A, frame, &tag));
    }

    /// Changing the frame bytes invalidates the tag (integrity).
    #[test]
    fn tampered_frame_fails() {
        let key = [7u8; 32];
        let tag = frame_tag(&key, 1, A, b"original frame");
        assert!(!verify_frame_tag(&key, 1, A, b"tampered frame", &tag));
    }

    /// Replaying a tag under a different counter fails (replay resistance).
    #[test]
    fn counter_bound_into_tag() {
        let key = [7u8; 32];
        let frame = b"frame";
        let tag = frame_tag(&key, 1, A, frame);
        assert!(!verify_frame_tag(&key, 2, A, frame, &tag));
    }

    /// A different (e.g. foreign-mesh) key produces a different tag.
    #[test]
    fn wrong_key_fails() {
        let frame = b"frame";
        let tag = frame_tag(&[1u8; 32], 1, A, frame);
        assert!(!verify_frame_tag(&[2u8; 32], 1, A, frame, &tag));
    }

    /// A tag made with sender context `A` does not verify under context `B`,
    /// even with the same (symmetric) key — so an `A→B` frame cannot be reflected
    /// back to `A` as if it came from `B`.
    #[test]
    fn context_prevents_reflection() {
        let key = [7u8; 32];
        let frame = b"frame";
        let tag = frame_tag(&key, 1, A, frame);
        assert!(!verify_frame_tag(&key, 1, B, frame, &tag));
    }
}
