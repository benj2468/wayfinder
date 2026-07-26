//! Thin adapter instantiating the shared small-MTU fragmentation/reassembly
//! machinery (see `libs/wayfinder-link-utils`) for this driver's on-air
//! budget.
//!
//! The module's AT interface caps an on-air frame at [`crate::link::MAX_FRAME_LEN`]
//! (180 bytes: 240 base64 chars, since payload is base64-encoded). Real mesh
//! frames — especially authenticated OGMs — routinely exceed that, so
//! `link.rs`'s `send`/`recv` split and reassemble transparently via
//! [`Reassembler`]; nothing above `LinkT` ever observes that a frame was
//! fragmented.
//!
//! **Reassembly key and its deployment requirement.** [`Reassembler`] keys
//! in-flight messages by `(sender's RYLR 16-bit address, msg_id)` rather than
//! the mesh `Mac`, since the module already reports the sender's address on
//! every `+RCV` line — this avoids duplicating the 6-byte `Mac` into every
//! fragment. **This means distinct physical nodes must be configured with
//! distinct `AT+ADDRESS` values** (e.g. derived from the low 16 bits of the
//! node's mesh `Mac`); nodes sharing an address would have their fragments
//! cross-contaminate in each others' reassembly slots.

use crate::link::MAX_FRAME_LEN;

pub(crate) use wayfinder_link_utils::FRAG_HDR_LEN;
pub(crate) use wayfinder_link_utils::MAX_FRAGMENTS;
pub(crate) use wayfinder_link_utils::pack_header;
pub(crate) use wayfinder_link_utils::parse_fragment;

/// Frame-content bytes (the `[dst][src][protocol][payload]` blob) carried by
/// one fragment.
pub(crate) const FRAG_PAYLOAD: usize = MAX_FRAME_LEN - FRAG_HDR_LEN;

/// Largest reassembled frame `send`/reassembly will handle: comfortably above
/// a ~260-byte authenticated OGM, with headroom for revocation TVLVs. (The
/// `MAX_REASSEMBLED_LEN <= MAX_FRAGMENTS * FRAG_PAYLOAD` relationship this
/// implies is checked inside `Reassembler::new()` itself, not re-asserted
/// here.)
pub(crate) const MAX_REASSEMBLED_LEN: usize = 512;

/// Largest number of concurrent in-flight (incomplete) messages the
/// reassembler tracks. Not derived from a hard protocol limit — LoRa's low
/// duty cycle and small neighbor counts mean only a handful of fragmented
/// messages are realistically in flight at once; chosen as a small,
/// deliberately modest bound (each entry costs a full `MAX_REASSEMBLED_LEN`
/// buffer) rather than an exact worst case. Capacity pressure degrades
/// gracefully via oldest-first eviction, so an undersized bound costs
/// completion rate, not correctness.
const MAX_REASSEMBLIES: usize = 4;

/// This driver's reassembly key: the RYLR module's 16-bit `AT+ADDRESS` plus
/// the sender-chosen message id.
pub(crate) type FragKey = wayfinder_link_utils::FragKey<u16>;

/// This driver's reassembly table, sized to its on-air budget.
pub(crate) type Reassembler =
    wayfinder_link_utils::Reassembler<u16, MAX_REASSEMBLIES, FRAG_PAYLOAD, MAX_REASSEMBLED_LEN>;
