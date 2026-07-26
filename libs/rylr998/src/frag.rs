//! Link-layer fragmentation wire format for on-air frames too large for one
//! `AT+SEND` packet. Entirely internal to the rylr998 driver: `LinkT` and
//! everything above it never observes a frame was split.
//!
//! Each fragment is a 2-byte header prefixed to a slice of the frame's
//! `[dst][src][protocol][payload]` bytes, before base64-encoding:
//!
//! ```text
//! byte 0: msg_id             (u8, wraps, one per `send()` call)
//! byte 1: (index << 4) | count    index in 0..count, count in 1..=MAX_FRAGMENTS
//! ```
//!
//! Non-final fragments always carry exactly [`FRAG_PAYLOAD`] frame-content
//! bytes, so a fragment's byte offset is `index * FRAG_PAYLOAD` — reassembly
//! needs no per-fragment length bookkeeping, only the last fragment is short.

use crate::link::MAX_FRAME_LEN;
use tracing::trace;
use tracing::warn;
use wayfinder::interfaces::link::LinkMetrics;

/// Bytes of fragment header prefixed to each on-air fragment's frame-content
/// bytes, before base64-encoding.
pub(crate) const FRAG_HDR_LEN: usize = 2;

/// Frame-content bytes (the `[dst][src][protocol][payload]` blob) carried by
/// one fragment.
pub(crate) const FRAG_PAYLOAD: usize = MAX_FRAME_LEN - FRAG_HDR_LEN;

/// Largest number of fragments one logical frame may be split into, bounded
/// by the 4-bit `count` field in the packed header byte.
pub(crate) const MAX_FRAGMENTS: usize = 15;

/// Largest reassembled frame `send`/reassembly will handle: comfortably above
/// a ~260-byte authenticated OGM, with headroom for revocation TVLVs.
pub(crate) const MAX_REASSEMBLED_LEN: usize = 512;

const _: () = assert!(MAX_REASSEMBLED_LEN <= MAX_FRAGMENTS * FRAG_PAYLOAD);

/// Pack a fragment header: `msg_id` plus `index`/`count` packed one nibble
/// each. `count` must be in `1..=MAX_FRAGMENTS` and `index` in `0..count`.
pub(crate) fn pack_header(msg_id: u8, index: usize, count: usize) -> [u8; FRAG_HDR_LEN] {
    debug_assert!((1..=MAX_FRAGMENTS).contains(&count));
    debug_assert!(index < count);
    [msg_id, ((index as u8) << 4) | (count as u8)]
}

/// Physical-layer reassembly key: the sending module's 16-bit RYLR address
/// plus the sender-chosen message id. Uniqueness requires distinct nodes to
/// use distinct configured `AT+ADDRESS` values (see the rylr998 CLAUDE.md
/// deployment note) — it lets fragments avoid duplicating the real 6-byte
/// mesh `Mac`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FragKey {
    pub(crate) addr: u16,
    pub(crate) msg_id: u8,
}

/// A decoded 2-byte fragment header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FragHeader {
    pub(crate) msg_id: u8,
    pub(crate) index: u8,
    pub(crate) count: u8,
}

/// Parse `[msg_id][index<<4|count]` plus body from `bytes`. `None` if `bytes`
/// is shorter than [`FRAG_HDR_LEN`], the encoded `count` is 0, or
/// `index >= count` — all of which indicate a malformed or adversarial frame
/// rather than a real gap in the sequence.
pub(crate) fn parse_fragment(bytes: &[u8]) -> Option<(FragHeader, &[u8])> {
    if bytes.len() < FRAG_HDR_LEN {
        return None;
    }
    let msg_id = bytes[0];
    let index = bytes[1] >> 4;
    let count = bytes[1] & 0x0F;
    if count == 0 || index >= count {
        return None;
    }
    Some((
        FragHeader {
            msg_id,
            index,
            count,
        },
        &bytes[FRAG_HDR_LEN..],
    ))
}

/// Largest number of concurrent in-flight (incomplete) messages the
/// reassembler tracks. Not derived from a hard protocol limit — LoRa's low
/// duty cycle and small neighbor counts mean only a handful of fragmented
/// messages are realistically in flight at once; chosen as a small,
/// deliberately modest bound (each entry costs a full `MAX_REASSEMBLED_LEN`
/// buffer) rather than an exact worst case. Capacity pressure degrades
/// gracefully via oldest-first eviction, so an undersized bound costs
/// completion rate, not correctness.
const MAX_REASSEMBLIES: usize = 4;

/// One in-flight message: fragments are copied to `index * FRAG_PAYLOAD`
/// offsets in `buf` as they arrive, until all `count` have been seen.
struct Reassembly {
    key: FragKey,
    count: u8,
    /// Bitmask of received fragment indices; bits `0..count` are meaningful.
    have: u16,
    /// One past the highest byte written so far; equals the total length
    /// once the message is complete.
    len: usize,
    buf: [u8; MAX_REASSEMBLED_LEN],
    /// Metrics from the most recently received fragment of this message.
    metrics: LinkMetrics,
}

impl Reassembly {
    fn new(key: FragKey, count: u8) -> Self {
        Self {
            key,
            count,
            have: 0,
            len: 0,
            buf: [0u8; MAX_REASSEMBLED_LEN],
            metrics: LinkMetrics::default(),
        }
    }

    fn is_complete(&self) -> bool {
        let full_mask: u16 = (1u16 << self.count) - 1;
        self.have & full_mask == full_mask
    }
}

/// Bounded reassembly table, keyed by [`FragKey`]. Evicts the oldest
/// in-flight message when a new key arrives and the table is already at
/// [`MAX_REASSEMBLIES`] — the same capacity-bound eviction
/// `OgmAuth.neighbors` uses in `wayfinder::auth`. No wall clock exists in
/// `no_std`, so stale/partial entries are reclaimed by capacity pressure
/// rather than a timer; acceptable on a fire-and-forget lossy medium.
pub(crate) struct Reassembler {
    /// Invariant: always ordered oldest-arrival-first. `accept` is the only
    /// mutator and preserves this by construction — new entries are always
    /// `push`ed at the back, eviction always `remove(0)`s the front, and an
    /// in-place mismatched-count reset (see `accept`) deliberately does *not*
    /// reorder, so a reset slot keeps its original arrival-order position for
    /// eviction purposes.
    entries: heapless::Vec<Reassembly, MAX_REASSEMBLIES>,
}

impl Reassembler {
    pub(crate) fn new() -> Self {
        Self {
            entries: heapless::Vec::new(),
        }
    }

    /// Feed one fragment. On completion, copy the assembled frame bytes into
    /// `out` and drop the entry, returning `(len, metrics)` — `metrics` from
    /// whichever fragment completed the message. Otherwise `None`.
    ///
    /// A malformed header (`count == 0`, `index >= count`, an oversized body,
    /// or an offset past the reassembly buffer) is rejected without touching
    /// the table. `index`/`count` come straight off the wire and are only
    /// bounded to `0..MAX_FRAGMENTS` by the 4-bit header field — nothing
    /// stops a crafted or corrupted fragment from declaring an `index` that
    /// is individually `< count` yet still lands `index * FRAG_PAYLOAD` past
    /// `MAX_REASSEMBLED_LEN` (only `send()`'s own fragments respect that
    /// relationship), so the offset is bounds-checked explicitly rather than
    /// trusted. A duplicate index for an already-buffered message is
    /// silently ignored — the first copy wins. A key whose declared `count`
    /// differs from what's already buffered is treated as a fresh message
    /// reusing that key (e.g. after `msg_id` wraps) and resets the slot
    /// rather than merging.
    pub(crate) fn accept(
        &mut self,
        key: FragKey,
        hdr: &FragHeader,
        body: &[u8],
        metrics: LinkMetrics,
        out: &mut [u8],
    ) -> Option<(usize, LinkMetrics)> {
        let off = hdr.index as usize * FRAG_PAYLOAD;
        if hdr.count == 0
            || hdr.index >= hdr.count
            || body.len() > FRAG_PAYLOAD
            || off + body.len() > MAX_REASSEMBLED_LEN
        {
            trace!(
                ?key,
                index = hdr.index,
                count = hdr.count,
                "drop: malformed fragment header"
            );
            return None;
        }

        let slot = match self.entries.iter().position(|e| e.key == key) {
            Some(i) if self.entries[i].count == hdr.count => i,
            Some(i) => {
                trace!(
                    ?key,
                    old_count = self.entries[i].count,
                    new_count = hdr.count,
                    "drop: mismatched fragment count, resetting reassembly slot"
                );
                self.entries[i] = Reassembly::new(key, hdr.count);
                i
            }
            None => {
                if self.entries.is_full() {
                    warn!(
                        evicted_key = ?self.entries[0].key,
                        ?key,
                        "capacity eviction: dropping incomplete fragment reassembly"
                    );
                    self.entries.remove(0);
                }
                self.entries
                    .push(Reassembly::new(key, hdr.count))
                    .unwrap_or_else(|_| unreachable!("just ensured room above"));
                self.entries.len() - 1
            }
        };

        let entry = &mut self.entries[slot];
        let bit = 1u16 << hdr.index;
        if entry.have & bit == 0 {
            entry.buf[off..off + body.len()].copy_from_slice(body);
            entry.have |= bit;
            entry.len = entry.len.max(off + body.len());
        } else {
            trace!(?key, index = hdr.index, "drop: duplicate fragment index");
        }
        entry.metrics = metrics;

        if entry.is_complete() {
            let entry = self.entries.remove(slot);
            out[..entry.len].copy_from_slice(&entry.buf[..entry.len]);
            Some((entry.len, entry.metrics))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_header_packs_nibbles() {
        assert_eq!(pack_header(7, 0, 1), [7, 0x01]);
        assert_eq!(pack_header(7, 0, 2), [7, 0x02]);
        assert_eq!(pack_header(7, 1, 2), [7, 0x12]);
        assert_eq!(pack_header(0xff, 14, 15), [0xff, 0xEF]);
    }

    // ── parse_fragment ──────────────────────────────────────────────

    #[test]
    fn parse_fragment_valid() {
        let hdr = pack_header(3, 1, 2);
        let bytes = [hdr[0], hdr[1], 0xAA, 0xBB];
        let (parsed, body) = parse_fragment(&bytes).unwrap();
        assert_eq!(
            parsed,
            FragHeader {
                msg_id: 3,
                index: 1,
                count: 2
            }
        );
        assert_eq!(body, &[0xAA, 0xBB]);
    }

    #[test]
    fn parse_fragment_rejects_short_input() {
        assert!(parse_fragment(&[]).is_none());
        assert!(parse_fragment(&[5]).is_none());
    }

    #[test]
    fn parse_fragment_rejects_zero_count() {
        // header byte 0x00: index=0, count=0.
        assert!(parse_fragment(&[5, 0x00, 1, 2]).is_none());
    }

    #[test]
    fn parse_fragment_rejects_index_ge_count() {
        // header byte 0x22: index=2, count=2 -- index must be < count.
        assert!(parse_fragment(&[5, 0x22, 1, 2]).is_none());
    }

    // ── Reassembler ──────────────────────────────────────────────────

    fn key(addr: u16, msg_id: u8) -> FragKey {
        FragKey { addr, msg_id }
    }

    fn metrics(rssi: i16) -> LinkMetrics {
        LinkMetrics {
            rssi_dbm: Some(rssi),
            snr_db: None,
            quality: None,
        }
    }

    #[test]
    fn accept_completes_single_fragment_message() {
        let mut r = Reassembler::new();
        let mut out = [0u8; 16];
        let hdr = FragHeader {
            msg_id: 0,
            index: 0,
            count: 1,
        };
        let result = r.accept(key(1, 0), &hdr, &[1, 2, 3], metrics(-40), &mut out);
        assert_eq!(result, Some((3, metrics(-40))));
        assert_eq!(&out[..3], &[1, 2, 3]);
    }

    #[test]
    fn accept_out_of_order_fragments_complete() {
        let mut r = Reassembler::new();
        let mut out = [0u8; MAX_REASSEMBLED_LEN];

        let frag0 = [0xAAu8; FRAG_PAYLOAD];
        let frag1 = [0xBBu8; 5];
        let hdr0 = FragHeader {
            msg_id: 0,
            index: 0,
            count: 2,
        };
        let hdr1 = FragHeader {
            msg_id: 0,
            index: 1,
            count: 2,
        };

        // Fragment 1 arrives first: incomplete, nothing returned yet.
        assert_eq!(
            r.accept(key(1, 0), &hdr1, &frag1, metrics(-50), &mut out),
            None
        );
        // Fragment 0 arrives second, completing the message.
        let (len, m) = r
            .accept(key(1, 0), &hdr0, &frag0, metrics(-40), &mut out)
            .expect("message should complete");
        assert_eq!(len, FRAG_PAYLOAD + 5);
        assert_eq!(&out[..FRAG_PAYLOAD], &frag0[..]);
        assert_eq!(&out[FRAG_PAYLOAD..len], &frag1[..]);
        assert_eq!(
            m,
            metrics(-40),
            "metrics from the fragment that completed it"
        );
    }

    #[test]
    fn accept_duplicate_index_is_ignored() {
        let mut r = Reassembler::new();
        let mut out = [0u8; MAX_REASSEMBLED_LEN];
        let hdr0 = FragHeader {
            msg_id: 0,
            index: 0,
            count: 2,
        };
        let hdr1 = FragHeader {
            msg_id: 0,
            index: 1,
            count: 2,
        };
        let original = [0xAAu8; FRAG_PAYLOAD];
        let duplicate = [0xCCu8; FRAG_PAYLOAD];

        assert_eq!(
            r.accept(key(1, 0), &hdr0, &original, metrics(-40), &mut out),
            None
        );
        // A second, different-content fragment 0 must not overwrite the first.
        assert_eq!(
            r.accept(key(1, 0), &hdr0, &duplicate, metrics(-40), &mut out),
            None
        );
        let (len, _) = r
            .accept(key(1, 0), &hdr1, &[4, 5], metrics(-40), &mut out)
            .unwrap();
        assert_eq!(len, FRAG_PAYLOAD + 2);
        assert_eq!(
            &out[..FRAG_PAYLOAD],
            &original[..],
            "original fragment 0 data preserved, duplicate ignored"
        );
        assert_eq!(&out[FRAG_PAYLOAD..len], &[4, 5]);
    }

    #[test]
    fn accept_rejects_oversized_body() {
        let mut r = Reassembler::new();
        let mut out = [0u8; MAX_REASSEMBLED_LEN];
        let hdr = FragHeader {
            msg_id: 0,
            index: 0,
            count: 2,
        };
        let too_big = [0u8; FRAG_PAYLOAD + 1];
        assert_eq!(
            r.accept(key(1, 0), &hdr, &too_big, metrics(0), &mut out),
            None
        );
        assert!(
            r.entries.is_empty(),
            "an oversized body must not create a table entry"
        );
    }

    /// The largest message the reassembler can actually complete: exactly
    /// `MAX_REASSEMBLED_LEN` bytes, split into the maximum number of
    /// full-size fragments plus a short final one (3 fragments at
    /// `FRAG_PAYLOAD` = 178 bytes here: 2 full + one 156-byte tail). Nothing
    /// with a higher declared `index` can ever complete regardless of `count`
    /// or body size, since a fragment's offset is always
    /// `index * FRAG_PAYLOAD` and `MAX_REASSEMBLED_LEN` bounds it — the wire
    /// format's nominal `count` ceiling of `MAX_FRAGMENTS` (15) is therefore
    /// never actually reachable in practice.
    #[test]
    fn accept_completes_largest_reassemblable_message() {
        let mut r = Reassembler::new();
        let mut out = [0u8; MAX_REASSEMBLED_LEN];
        let count = MAX_REASSEMBLED_LEN.div_ceil(FRAG_PAYLOAD) as u8;

        let mut last = None;
        for index in 0..count {
            let start = index as usize * FRAG_PAYLOAD;
            let end = core::cmp::min(start + FRAG_PAYLOAD, MAX_REASSEMBLED_LEN);
            let body = vec![index; end - start];
            let hdr = FragHeader {
                msg_id: 0,
                index,
                count,
            };
            last = r.accept(key(1, 0), &hdr, &body, metrics(0), &mut out);
        }

        let (len, _) = last.expect("final fragment should complete the message");
        assert_eq!(len, MAX_REASSEMBLED_LEN);
        for index in 0..count {
            let start = index as usize * FRAG_PAYLOAD;
            let end = core::cmp::min(start + FRAG_PAYLOAD, MAX_REASSEMBLED_LEN);
            assert!(out[start..end].iter().all(|&b| b == index));
        }
    }

    #[test]
    fn accept_rejects_malformed_header() {
        let mut r = Reassembler::new();
        let mut out = [0u8; 16];
        let bad = FragHeader {
            msg_id: 0,
            index: 2,
            count: 2,
        };
        assert_eq!(
            r.accept(key(1, 0), &bad, &[1, 2], metrics(-40), &mut out),
            None
        );
        assert!(
            r.entries.is_empty(),
            "malformed input must not create a table entry"
        );
    }

    #[test]
    fn accept_evicts_oldest_when_capacity_full() {
        let mut r = Reassembler::new();
        let mut out = [0u8; MAX_REASSEMBLED_LEN];
        let hdr0 = FragHeader {
            msg_id: 0,
            index: 0,
            count: 2,
        };
        let hdr1 = FragHeader {
            msg_id: 0,
            index: 1,
            count: 2,
        };

        // Fill the table with MAX_REASSEMBLIES (4) distinct, incomplete messages.
        for addr in 0..4u16 {
            r.accept(key(addr, 0), &hdr0, &[1], metrics(0), &mut out);
        }
        assert_eq!(r.entries.len(), 4);

        // A 5th distinct key evicts the oldest (addr 0).
        r.accept(key(4, 0), &hdr0, &[1], metrics(0), &mut out);
        assert_eq!(r.entries.len(), 4);

        // addr 0's second fragment now completes nothing: its prior state
        // was evicted, so this looks like a fresh, still-incomplete message.
        assert_eq!(r.accept(key(0, 0), &hdr1, &[2], metrics(0), &mut out), None);
        // addr 4, inserted after eviction, still completes normally (offset
        // for index 1 is FRAG_PAYLOAD, so total length is FRAG_PAYLOAD + 1).
        assert_eq!(
            r.accept(key(4, 0), &hdr1, &[2], metrics(0), &mut out),
            Some((FRAG_PAYLOAD + 1, metrics(0)))
        );
    }

    /// A header can be individually well-formed (`index < count`, body within
    /// `FRAG_PAYLOAD`) yet still declare an offset past the reassembly
    /// buffer's end (e.g. `index=10, count=15`: `10 * FRAG_PAYLOAD = 1180 >
    /// MAX_REASSEMBLED_LEN`). Nothing on the wire ties `count` to
    /// `MAX_REASSEMBLED_LEN` — only `send()`'s own emitted fragments respect
    /// that relationship — so a crafted or corrupted on-air fragment must be
    /// rejected here, not panic.
    #[test]
    fn accept_rejects_out_of_range_offset() {
        let mut r = Reassembler::new();
        let mut out = [0u8; MAX_REASSEMBLED_LEN];
        let hdr = FragHeader {
            msg_id: 0,
            index: 10,
            count: 15,
        };
        let body = [0u8; FRAG_PAYLOAD];
        assert_eq!(r.accept(key(1, 0), &hdr, &body, metrics(0), &mut out), None);
        assert!(
            r.entries.is_empty(),
            "an out-of-range fragment must not create a table entry"
        );
    }

    #[test]
    fn accept_mismatched_count_resets_slot() {
        let mut r = Reassembler::new();
        let mut out = [0u8; 16];

        // Start a 3-fragment message, only fragment 0 arrives.
        let stale_hdr = FragHeader {
            msg_id: 0,
            index: 0,
            count: 3,
        };
        assert_eq!(
            r.accept(key(1, 0), &stale_hdr, &[1, 2, 3], metrics(0), &mut out),
            None
        );

        // Same key, but a brand-new single-fragment message (e.g. msg_id
        // reused this key's slot) -- must reset, not merge, and complete
        // immediately since count == 1.
        let fresh_hdr = FragHeader {
            msg_id: 0,
            index: 0,
            count: 1,
        };
        let (len, _) = r
            .accept(key(1, 0), &fresh_hdr, &[9, 9], metrics(0), &mut out)
            .expect("fresh single-fragment message should complete immediately");
        assert_eq!(len, 2);
        assert_eq!(&out[..2], &[9, 9]);
    }
}
