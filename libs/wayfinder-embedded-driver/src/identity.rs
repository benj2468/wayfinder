//! What a bare-metal node keeps across a reset: one durable record holding an
//! identity **seed**, a clock checkpoint, and the runtime settings the
//! management API writes through.
//!
//! A host node is handed its identity by config; a bare-metal node has no
//! config file and no filesystem an operator can drop a file into, so it must
//! mint its own the first time it boots and remember it thereafter. This
//! module is that memory. [`load_or_init_record`] reads the record back from a
//! board-supplied [`DurableStore`] if one was ever written, and otherwise
//! mints a seed and durably saves it.
//!
//! Designed in `docs/design/22-embedded-node-record.md`.
//!
//! # Three things, one blob
//!
//! The record holds a seed, a clock checkpoint, and a credential, and they are
//! one blob rather than three stores because their **lifetimes are the same**.
//! Design 20 §4.5 is explicit that the checkpoint must be "persisted in the
//! same blob as the credential, written, loaded and erased with it": a board
//! that reloads a credential without a checkpoint boots credentialed-and-
//! `Unknown`, and any attempt to fill the gap from the certificate's own
//! `not_before` is the clock rollback design 20 §4.4 forbids in bold.
//!
//! # The seed is the identity; the MAC falls out of it
//!
//! There is no MAC in this record. Since design 09 §5 a certificate's MAC *is*
//! the address its identity key derives, so the node's address is
//! [`NodeRecord::mac`] — `Keypair::from_seed(&seed).derived_mac()` — and
//! storing it beside the seed would be storing the same fact twice, with the
//! two able to disagree. They did disagree: GitLab #58 is a board routing
//! under a FICR-derived address while holding a certificate naming another,
//! found on real hardware by `libs/wayfinder-hil`.
//!
//! The seed is a *top-level field* rather than one inside the credential, for
//! the one reason a board differs from a host here: it has a seed from its
//! very first boot and only later, maybe, a credential.
//!
//! # What this does not promise
//!
//! **Confidentiality at rest.** An nRF52840's internal flash is readable over
//! SWD unless APPROTECT is engaged, and encrypting the record would need a key
//! the CPU can obtain unattended at boot — on a part with no secure element,
//! no debugger-proof key storage and no PUF, that key lives in the same flash
//! as the ciphertext. Design 22 §4.7 records the reasoning and the bound on
//! the exposure: this seed is one node's membership, never the mesh root,
//! which is minted offline and never enters a node.
//!
//! What the store *does* promise is atomicity (a reader never sees a torn
//! old/new mix) and, since design 22, erasure — [`DurableStore::scrub`] so a
//! rotated seed does not linger in a spare flash page, and
//! [`DurableStore::erase`] so an unreadable record is disposed of rather than
//! written over.

use wayfinder::interfaces::frame::Mac;
use wayfinder::wayfinder_auth::Keypair;
use wayfinder::wayfinder_auth::MembershipCert;
use wayfinder::wayfinder_auth::RevocationRecord;
use wayfinder::wayfinder_auth::TrustAnchor;
use wayfinder_storage::Codec;
use wayfinder_storage::DurableStore;
use wayfinder_storage::Persisted;

/// Encoding version for a persisted node record. Bumped only on an
/// incompatible layout change; [`RecordCodec::decode`] rejects any other value
/// so a blob written by a future format fails closed rather than having its
/// bytes read as a seed.
pub const RECORD_VERSION: u8 = 2;

/// The version byte written by this module's predecessor, whose blob was
/// `[1, mac0..mac5]` and held no key at all.
///
/// Recognised rather than left to fail as an unknown version: both paths mint
/// a fresh seed, but one logs a stated migration and the other logs corruption
/// on a board that is fine. A firmware update should not look like a fault.
/// See [`RecordCodecError::LegacyMacBlob`] and design 22 §6.1.
pub const LEGACY_MAC_VERSION: u8 = 1;

// The four blob lengths this record is laid out from are *not* named here.
// Each is a property of a `wayfinder-auth` type, and this module asks that type
// for it — `Keypair::SEED_LEN`, `MembershipCert::SERIALIZED_LEN`,
// `TrustAnchor::SERIALIZED_LEN`, `RevocationRecord::SERIALIZED_LEN`. A local
// alias would put a second public name on the same fact in a second crate, and
// a locally recomputed `size_of` would put a second *definition* on it: the
// stored layout would then be free to drift from what the parser expects, one
// crate away from the type that decides it.

/// The record's fixed prefix: a version byte, a flags byte, the seed, and the
/// clock checkpoint. Every optional blob follows it, in a fixed order.
///
/// No length prefixes: each optional field's size is a compile-time constant,
/// so the flags byte plus the total length determine the layout exactly — and
/// [`RecordCodec::decode`] checks that those two agree rather than trusting
/// either alone.
pub const RECORD_HEADER_LEN: usize = 1 + 1 + Keypair::SEED_LEN + 8;

/// The largest a record can be: everything present at once. Well under a 4 KiB
/// flash page's capacity, which is the headroom design 22 §4.1 relies on to
/// keep this encoding simple.
pub const MAX_RECORD_LEN: usize = RECORD_HEADER_LEN
    + MembershipCert::SERIALIZED_LEN
    + TrustAnchor::SERIALIZED_LEN
    + RevocationRecord::SERIALIZED_LEN;

/// Read buffer size for loading a record. `DurableStore::load`'s own contract
/// already forbids overflowing a too-small `out` buffer regardless of size (an
/// oversized stored blob comes back as a store-level error, never a
/// truncation) — this constant's one byte of slack over [`MAX_RECORD_LEN`]
/// only decides *which* error an off-by-one-too-long stored blob produces:
/// with the slack it is caught by [`RecordCodec::decode`]'s length check
/// ("bad format"), and without it the store reports an undersized buffer
/// ("caller under-sized the read"). Both fail closed; the slack picks the more
/// informative one.
pub const RECORD_READ_BUF_LEN: usize = MAX_RECORD_LEN + 1;

bitflags::bitflags! {
    /// The record's flags byte: which optional blobs follow the header, and
    /// which of the two runtime settings have been written at all.
    ///
    /// A settings bit comes in a **pair** — `_SET` says the management API has
    /// written the value, the other carries it — because `None` and
    /// `Some(false)` are different records: the first leaves the board's
    /// startup default authoritative, the second overrides it to off. One bit
    /// could not tell those apart.
    ///
    /// Unknown bits are retained rather than rejected. What guards against a
    /// foreign layout is [`RECORD_VERSION`], which is checked first and fails
    /// closed; a reserved bit set by a future writer of *this* version implies
    /// no trailing blob, so it cannot desynchronise the length check below.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct RecordFlags: u8 {
        /// A certificate follows the header.
        const CERT = 1 << 0;
        /// A trust anchor follows.
        const ANCHOR = 1 << 1;
        /// A self-revocation record follows.
        const REVOKE = 1 << 2;
        /// `require_auth` has been set at runtime (as opposed to never
        /// touched, which leaves the startup default authoritative).
        const REQUIRE_AUTH_SET = 1 << 3;
        /// The value of `require_auth`, meaningful only alongside
        /// [`REQUIRE_AUTH_SET`](Self::REQUIRE_AUTH_SET).
        const REQUIRE_AUTH = 1 << 4;
        /// `lazy_cert_distribution` has been set at runtime.
        const LAZY_SET = 1 << 5;
        /// The value of `lazy_cert_distribution`, meaningful only alongside
        /// [`LAZY_SET`](Self::LAZY_SET).
        const LAZY = 1 << 6;
    }
}

/// A record loaded from a board's durable store, sealed behind
/// [`Persisted`] so every later change is persisted with it.
///
/// An alias because the full spelling appears in a `Result` beside
/// [`Provisioned`], where it is more punctuation than information.
pub type LoadedRecord<S> = Persisted<NodeRecord, S, RecordCodec>;

/// How a board came by the record it is holding.
///
/// Returned by [`load_or_init_record`] rather than logged inside it, so the
/// board can report it through whatever it has and a test can assert it.
///
/// The distinction is the point. All three of these once produced the same
/// `info!` line, which meant a node whose mesh address had just changed
/// permanently was indistinguishable in the log from one that had simply
/// booted — leaving every peer's originator table churning for no stated
/// reason, which is the class of silence this whole design exists to remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provisioned {
    /// A record was already stored and was read back. The ordinary boot.
    Loaded,
    /// Nothing was stored, so a seed was minted and saved. A board's first
    /// boot, or its first after its flash was erased.
    Minted,
    /// A `v1` MAC-only blob was found and replaced with a fresh record.
    ///
    /// **The board's mesh address changed**, once, at this boot. Unavoidable —
    /// the old blob holds a FICR-derived address and no key, so there is
    /// nothing to carry forward — and harmless in the way that matters, since
    /// a board that could not store a credential by definition held none. But
    /// it is a change worth saying out loud rather than leaving an operator to
    /// notice their node came back under a new originator.
    MigratedFromV1,
}

/// Everything a board carries across a reset.
///
/// The three credential blobs are stored as the **raw bytes as received**,
/// never as re-encodings of parsed types: they are what the next boot will
/// parse, so round-tripping them through `MembershipCert`/`TrustAnchor` first
/// would only add a way for the stored and the intended to disagree. The
/// adapter's own `set_auth` persists them on the same terms.
///
/// [`Debug`](core::fmt::Debug) is hand-written and redacts the seed — see the
/// impl below for why that matters on this target.
#[derive(Clone, PartialEq, Eq)]
pub struct NodeRecord {
    /// The node's Ed25519 identity seed. Secret: it *is* the node's identity,
    /// and the node's mesh address is derived from it ([`NodeRecord::mac`]).
    pub seed: [u8; Keypair::SEED_LEN],
    /// The clock high-water mark, in unix seconds, or `0` for none.
    ///
    /// `WallClock::estimate`'s value, restored at boot by handing it back to
    /// `WallClock::anchor` — through that method's `max`, so a stale page read
    /// after a later correction cannot pull the estimate back. It always
    /// under-counts, because a board cannot measure how long it was powered
    /// off, and that deficit is safe precisely because the posture is a floor.
    pub checkpoint_unix: u64,
    /// The node's membership certificate, as received.
    pub cert: Option<[u8; MembershipCert::SERIALIZED_LEN]>,
    /// The mesh trust anchor the certificate chains to, as received.
    pub trust_anchor: Option<[u8; TrustAnchor::SERIALIZED_LEN]>,
    /// The root-signed revocation naming this node, if it has heard one.
    ///
    /// Self-authenticating and re-verified against the trust anchor on every
    /// boot, which is why persisting it is safe and why losing it across a
    /// reset — today's behaviour — defeats design 16 entirely.
    pub self_revocation: Option<[u8; RevocationRecord::SERIALIZED_LEN]>,
    /// Whether the node fails closed while it holds no membership cert.
    /// `None` means the operator has never set it, leaving the build's default
    /// authoritative.
    pub require_auth: Option<bool>,
    /// Whether the node's OGMs carry a cert fingerprint rather than the full
    /// certificate. `None` as for [`require_auth`](Self::require_auth).
    pub lazy_cert_distribution: Option<bool>,
}

impl NodeRecord {
    /// A record for a board that has just minted `seed` and holds nothing
    /// else: no credential, no checkpoint, no runtime settings.
    pub fn fresh(seed: [u8; Keypair::SEED_LEN]) -> NodeRecord {
        NodeRecord {
            seed,
            checkpoint_unix: 0,
            cert: None,
            trust_anchor: None,
            self_revocation: None,
            require_auth: None,
            lazy_cert_distribution: None,
        }
    }

    /// This node's keypair, derived from the seed.
    pub fn keypair(&self) -> Keypair {
        Keypair::from_seed(&self.seed)
    }

    /// This node's mesh address: the MAC its identity key derives.
    ///
    /// Derived rather than stored, so a certificate naming this MAC is by
    /// construction a certificate for the address the board routes under
    /// (design 09 §5, and GitLab #58 for what happens when the two are allowed
    /// to be separate facts).
    pub fn mac(&self) -> Mac {
        self.keypair().derived_mac()
    }
}

/// Redacts the seed, and derives nothing.
///
/// Hand-written rather than `#[derive(Debug)]` because this crate's logs are
/// **served over the management API**: `wayfinder-log`'s ring is what `GetLogs`
/// answers from, so one `?record` in a future trace line would put the node's
/// private key in front of anything that can reach the port. The MAC is shown
/// instead — it is the public half of the same fact, and it is what an operator
/// reading a log actually wants to identify the node by.
impl core::fmt::Debug for NodeRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NodeRecord")
            .field("mac", &self.mac())
            .field("seed", &"<redacted>")
            .field("checkpoint_unix", &self.checkpoint_unix)
            .field("cert", &self.cert.is_some())
            .field("trust_anchor", &self.trust_anchor.is_some())
            .field("self_revocation", &self.self_revocation.is_some())
            .field("require_auth", &self.require_auth)
            .field("lazy_cert_distribution", &self.lazy_cert_distribution)
            .finish()
    }
}

/// A record's encoded bytes: a fixed-capacity buffer plus the length actually
/// used, so [`RecordCodec`] stays allocation-free on a `no_std` target while
/// still encoding a variable-length record.
pub struct EncodedRecord {
    bytes: [u8; MAX_RECORD_LEN],
    len: usize,
}

impl AsRef<[u8]> for EncodedRecord {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// [`Codec`] for a [`NodeRecord`].
///
/// A leading version byte and a flags byte, deliberately *not* a raw zerocopy
/// dump, so the stored blob is self-describing enough to reject a stale or
/// foreign format on decode instead of accepting arbitrary bytes as a seed.
pub struct RecordCodec;

/// A [`RecordCodec`] decode failure: the stored bytes weren't a well-formed
/// node record.
#[derive(Debug, PartialEq, Eq)]
pub enum RecordCodecError {
    /// The blob's length does not match what its version and flags imply.
    WrongLength {
        /// The blob's actual length.
        len: usize,
        /// The length its flags say it should have been.
        expected: usize,
    },
    /// The leading version byte wasn't one this build understands.
    UnknownVersion(u8),
    /// The blob is this module's predecessor's: `[1, mac0..mac5]`, a
    /// FICR-derived address and no key.
    ///
    /// Not an error the caller should report as a fault.
    /// [`load_or_init_record`] treats it as a never-provisioned store and
    /// mints a fresh seed, which changes the board's mesh address once — the
    /// only outcome available, since the old blob holds nothing to carry
    /// forward. Harmless in the way that matters: a board that could not store
    /// a credential by definition holds none.
    LegacyMacBlob,
}

impl Codec<NodeRecord> for RecordCodec {
    type Error = RecordCodecError;
    type Encoded = EncodedRecord;

    fn encode(&self, value: &NodeRecord) -> Result<Self::Encoded, Self::Error> {
        let mut bytes = [0u8; MAX_RECORD_LEN];
        let mut flags = RecordFlags::empty();
        flags.set(RecordFlags::CERT, value.cert.is_some());
        flags.set(RecordFlags::ANCHOR, value.trust_anchor.is_some());
        flags.set(RecordFlags::REVOKE, value.self_revocation.is_some());
        if let Some(require_auth) = value.require_auth {
            flags.insert(RecordFlags::REQUIRE_AUTH_SET);
            flags.set(RecordFlags::REQUIRE_AUTH, require_auth);
        }
        if let Some(lazy) = value.lazy_cert_distribution {
            flags.insert(RecordFlags::LAZY_SET);
            flags.set(RecordFlags::LAZY, lazy);
        }

        bytes[0] = RECORD_VERSION;
        bytes[1] = flags.bits();
        bytes[2..2 + Keypair::SEED_LEN].copy_from_slice(&value.seed);
        bytes[2 + Keypair::SEED_LEN..RECORD_HEADER_LEN]
            .copy_from_slice(&value.checkpoint_unix.to_be_bytes());

        let mut at = RECORD_HEADER_LEN;
        for blob in [
            value.cert.as_ref().map(|b| &b[..]),
            value.trust_anchor.as_ref().map(|b| &b[..]),
            value.self_revocation.as_ref().map(|b| &b[..]),
        ]
        .into_iter()
        .flatten()
        {
            bytes[at..at + blob.len()].copy_from_slice(blob);
            at += blob.len();
        }

        Ok(EncodedRecord { bytes, len: at })
    }

    fn decode(&self, bytes: &[u8]) -> Result<NodeRecord, Self::Error> {
        match bytes.first() {
            Some(&RECORD_VERSION) => {}
            Some(&LEGACY_MAC_VERSION) => return Err(RecordCodecError::LegacyMacBlob),
            Some(&other) => return Err(RecordCodecError::UnknownVersion(other)),
            // An empty blob cannot even name a version. A store that has never
            // been written reports `None` rather than reaching here, so this
            // is a damaged record, not a fresh device.
            None => {
                return Err(RecordCodecError::WrongLength {
                    len: 0,
                    expected: RECORD_HEADER_LEN,
                });
            }
        }
        if bytes.len() < RECORD_HEADER_LEN {
            return Err(RecordCodecError::WrongLength {
                len: bytes.len(),
                expected: RECORD_HEADER_LEN,
            });
        }

        let flags = RecordFlags::from_bits_retain(bytes[1]);
        let blob_len = |flag: RecordFlags, len: usize| if flags.contains(flag) { len } else { 0 };
        let expected = RECORD_HEADER_LEN
            + blob_len(RecordFlags::CERT, MembershipCert::SERIALIZED_LEN)
            + blob_len(RecordFlags::ANCHOR, TrustAnchor::SERIALIZED_LEN)
            + blob_len(RecordFlags::REVOKE, RevocationRecord::SERIALIZED_LEN);
        // The flags byte and the total length are two independent statements
        // about the same layout, and a record is only well-formed when they
        // agree. Trusting the flags alone would hand a caller a truncated
        // certificate it would then fail to verify for the wrong reason.
        if bytes.len() != expected {
            return Err(RecordCodecError::WrongLength {
                len: bytes.len(),
                expected,
            });
        }

        let mut seed = [0u8; Keypair::SEED_LEN];
        seed.copy_from_slice(&bytes[2..2 + Keypair::SEED_LEN]);
        let mut checkpoint = [0u8; 8];
        checkpoint.copy_from_slice(&bytes[2 + Keypair::SEED_LEN..RECORD_HEADER_LEN]);

        let mut at = RECORD_HEADER_LEN;
        let mut take = |present: bool, len: usize| -> Option<usize> {
            present.then(|| {
                let start = at;
                at += len;
                start
            })
        };
        let cert_at = take(
            flags.contains(RecordFlags::CERT),
            MembershipCert::SERIALIZED_LEN,
        );
        let anchor_at = take(
            flags.contains(RecordFlags::ANCHOR),
            TrustAnchor::SERIALIZED_LEN,
        );
        let revoke_at = take(
            flags.contains(RecordFlags::REVOKE),
            RevocationRecord::SERIALIZED_LEN,
        );

        Ok(NodeRecord {
            seed,
            checkpoint_unix: u64::from_be_bytes(checkpoint),
            cert: cert_at.map(|at| {
                let mut b = [0u8; MembershipCert::SERIALIZED_LEN];
                b.copy_from_slice(&bytes[at..at + MembershipCert::SERIALIZED_LEN]);
                b
            }),
            trust_anchor: anchor_at.map(|at| {
                let mut b = [0u8; TrustAnchor::SERIALIZED_LEN];
                b.copy_from_slice(&bytes[at..at + TrustAnchor::SERIALIZED_LEN]);
                b
            }),
            self_revocation: revoke_at.map(|at| {
                let mut b = [0u8; RevocationRecord::SERIALIZED_LEN];
                b.copy_from_slice(&bytes[at..at + RevocationRecord::SERIALIZED_LEN]);
                b
            }),
            require_auth: flags
                .contains(RecordFlags::REQUIRE_AUTH_SET)
                .then_some(flags.contains(RecordFlags::REQUIRE_AUTH)),
            lazy_cert_distribution: flags
                .contains(RecordFlags::LAZY_SET)
                .then_some(flags.contains(RecordFlags::LAZY)),
        })
    }
}

/// Failure bringing up a node's durable record.
#[derive(Debug, PartialEq, Eq)]
pub enum IdentityError<SE> {
    /// The backing [`DurableStore`] failed a read, write or erase.
    Store(SE),
    /// A previously-stored record failed to decode — a corrupt or
    /// foreign-format store.
    ///
    /// A *permanent* condition, not a transient I/O fault: the bytes on the
    /// medium are intact and will fail to decode identically on every future
    /// boot until something rewrites them. [`load_or_init_record`] makes a
    /// best-effort attempt to do exactly that — erase, then persist a freshly
    /// minted seed — so the node converges on its *next* boot rather than
    /// hitting this error forever. This boot still reports it, so an operator
    /// sees that the node's identity was unreadable rather than the node
    /// quietly changing address with no trace.
    Decode {
        /// What was wrong with the stored bytes.
        error: RecordCodecError,
        /// Whether the best-effort repair actually landed.
        ///
        /// Carried rather than discarded because the two outcomes need
        /// different words from the caller, and guessing produces the worse
        /// kind of log line. `true`: the damaged record is gone and the node
        /// comes up under a new address next boot. `false`: the erase or the
        /// write also failed, so the node will hit this identical failure on
        /// every boot until its flash is erased by hand — and a message
        /// promising a fresh identity would send an operator looking in
        /// entirely the wrong place.
        repaired: bool,
    },
    /// Encoding a freshly minted record failed. Distinct from
    /// [`IdentityError::Decode`] even though both wrap a codec error: this
    /// means nothing is durably stored yet, not that a previously-good store
    /// was found corrupt.
    Encode(RecordCodecError),
}

/// Load this node's durable record from `store`, or mint a seed with
/// `mint_seed` and persist a fresh record if the store has never been written.
///
/// On a store that already holds a record, `mint_seed` is never called and no
/// write occurs, so a normal boot costs no flash wear.
///
/// The record is returned wrapped in a [`Persisted`] that owns `store` and the
/// codec, so every later change goes through [`Persisted::mutate`] (or
/// `mutate_sealed`, for one that replaces the seed) and is persisted with it.
/// Read the current record with [`Persisted::get`].
///
/// `read_buf` must be at least [`RECORD_READ_BUF_LEN`] bytes.
///
/// # `mint_seed` must produce a *random* seed
///
/// Not a value derived from the chip's factory ID. That ID is not secret — it
/// is readable by anything on the part — so a key derived from it is
/// derivable by anyone who knows it. A public *address* derived from FICR is
/// fine and is what a board with no record falls back to; a private key is
/// not. Design 22 §4.3.
///
/// # Both pages failing validation at once
///
/// A `FlashStore` whose two pages were each independently corrupted reports
/// `load` as `Ok(None)`, which is indistinguishable from "never provisioned"
/// at the [`DurableStore`] layer — so this function mints and persists a new
/// seed, exactly as on a fresh device.
///
/// **This module's predecessor called that harmless because a FICR mint is
/// idempotent. That argument does not survive.** A random seed is not
/// idempotent, so this case silently changes the board's mesh address. It is
/// accepted anyway: the alternative is a board that refuses to boot after a
/// double corruption, and a changed address on a board that has also lost its
/// credential is the lesser harm. Design 22 §5.
pub fn load_or_init_record<S, F>(
    mut store: S,
    mint_seed: F,
    read_buf: &mut [u8],
) -> Result<(LoadedRecord<S>, Provisioned), IdentityError<S::Error>>
where
    S: DurableStore,
    F: FnOnce() -> [u8; Keypair::SEED_LEN],
{
    let stored = store.load(read_buf).map_err(IdentityError::Store)?;
    let decoded = stored.map(|n| RecordCodec.decode(&read_buf[..n]));
    let was_legacy = matches!(decoded, Some(Err(RecordCodecError::LegacyMacBlob)));

    match decoded {
        Some(Ok(record)) => Ok((
            Persisted::new(record, store, RecordCodec),
            Provisioned::Loaded,
        )),
        // A stated migration, not a fault: mint as if the store were fresh.
        // *Which* of the two it was travels back in `Provisioned`, because
        // they are the same action with very different consequences — one is
        // a board's first boot, the other is a board's mesh address changing
        // under a firmware update. See `RecordCodecError::LegacyMacBlob`.
        Some(Err(RecordCodecError::LegacyMacBlob)) | None => {
            let record = NodeRecord::fresh(mint_seed());
            let encoded = RecordCodec.encode(&record).map_err(IdentityError::Encode)?;
            store.save(encoded.as_ref()).map_err(IdentityError::Store)?;
            let how = if was_legacy {
                Provisioned::MigratedFromV1
            } else {
                Provisioned::Minted
            };
            Ok((Persisted::new(record, store, RecordCodec), how))
        }
        Some(Err(error)) => {
            // Permanent, not transient (see `IdentityError::Decode`):
            // best-effort repair so a *later* boot converges instead of
            // hitting this same error forever. This boot reports `error`
            // either way — but *whether the repair landed* travels with it,
            // because a caller that assumed it had would promise an operator a
            // fresh identity that was never written, and send them looking in
            // the wrong place when the board came back identical.
            //
            // `erase` before `save`, not `save` alone: the damaged bytes may
            // be a readable old seed under a broken header, and a shorter
            // record written over a longer one would leave its tail behind.
            let repaired = store
                .erase()
                .and_then(
                    |()| match RecordCodec.encode(&NodeRecord::fresh(mint_seed())) {
                        Ok(encoded) => store.save(encoded.as_ref()),
                        // Encoding a fresh record cannot fail — every field is
                        // fixed-size and the buffer is `MAX_RECORD_LEN` — but
                        // reporting a repair that did not happen is the one
                        // thing this branch must not do.
                        Err(_) => Ok(()),
                    },
                )
                .is_ok();
            Err(IdentityError::Decode { error, repaired })
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    use std::rc::Rc;
    use wayfinder::wayfinder_auth::Keypair;

    /// A distinct 32-byte seed per test, from one byte.
    fn seed(n: u8) -> [u8; 32] {
        [n; 32]
    }

    /// Stand-in wire bytes for the three optional blobs. The codec stores them
    /// verbatim and never parses them — the adapter deliberately persists what
    /// it received rather than a re-encoding of what it parsed — so a test
    /// need only supply the right *length*.
    fn cert_bytes(n: u8) -> [u8; MembershipCert::SERIALIZED_LEN] {
        [n; MembershipCert::SERIALIZED_LEN]
    }
    fn anchor_bytes(n: u8) -> [u8; TrustAnchor::SERIALIZED_LEN] {
        [n; TrustAnchor::SERIALIZED_LEN]
    }
    fn revoke_bytes(n: u8) -> [u8; RevocationRecord::SERIALIZED_LEN] {
        [n; RevocationRecord::SERIALIZED_LEN]
    }

    /// An in-memory [`DurableStore`] whose blob is shared via `Rc<RefCell<_>>`,
    /// so a test can hand one clone to the loader and inspect (or re-load
    /// through) the other to see what was durably written — the same "simulate
    /// a restart against the same medium" trick the storage crate's own tests
    /// use.
    ///
    /// Also records every call in order, because two of the properties below
    /// are about *sequence* rather than final state: a corrupt record must be
    /// erased before a fresh seed is written over it, not merely overwritten.
    #[derive(Default, Clone)]
    struct MemStore {
        blob: Rc<RefCell<Option<Vec<u8>>>>,
        calls: Rc<RefCell<Vec<&'static str>>>,
    }

    impl MemStore {
        fn holding(bytes: Vec<u8>) -> MemStore {
            let store = MemStore::default();
            *store.blob.borrow_mut() = Some(bytes);
            store
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.borrow().clone()
        }
    }

    impl DurableStore for MemStore {
        type Error = core::convert::Infallible;

        fn load(&mut self, out: &mut [u8]) -> Result<Option<usize>, Self::Error> {
            self.calls.borrow_mut().push("load");
            Ok(self.blob.borrow().as_ref().map(|b| {
                out[..b.len()].copy_from_slice(b);
                b.len()
            }))
        }

        fn save(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            self.calls.borrow_mut().push("save");
            *self.blob.borrow_mut() = Some(data.to_vec());
            Ok(())
        }

        fn erase(&mut self) -> Result<(), Self::Error> {
            self.calls.borrow_mut().push("erase");
            *self.blob.borrow_mut() = None;
            Ok(())
        }
    }

    /// A store whose `save` always fails, mirroring `wayfinder_storage`'s own
    /// `FailingStore` test double.
    #[derive(Default)]
    struct FailingStore;

    impl DurableStore for FailingStore {
        type Error = &'static str;

        fn load(&mut self, _out: &mut [u8]) -> Result<Option<usize>, Self::Error> {
            Ok(None)
        }

        fn save(&mut self, _data: &[u8]) -> Result<(), Self::Error> {
            Err("flash write failed")
        }

        fn erase(&mut self) -> Result<(), Self::Error> {
            Err("flash write failed")
        }
    }

    /// The fixed part of the record is a version byte, a flags byte, the seed
    /// and the checkpoint — and nothing else.
    ///
    /// Pinned as a literal because it is the arithmetic in design 22 §4.1:
    /// this is the layout whose worst case has to fit a flash page with an
    /// order of magnitude of headroom, and a field appearing here silently
    /// would be exactly the kind of growth that argument stops holding for.
    #[test]
    fn the_fixed_header_is_forty_two_bytes() {
        assert_eq!(RECORD_HEADER_LEN, 1 + 1 + 32 + 8);
        assert_eq!(RECORD_HEADER_LEN, 42);
    }

    /// The flags byte's **bit positions are wire format**, not an internal
    /// enumeration: a board that reboots into new firmware parses records the
    /// old firmware wrote, and [`RECORD_VERSION`] does not move when the
    /// constants inside [`RecordFlags`] are merely reordered. So a reorder
    /// would silently reinterpret every stored record — an anchor read as a
    /// certificate, `require_auth` read as `lazy_cert_distribution` — with no
    /// version to fail closed on and no round-trip test to notice, since a
    /// round trip agrees with itself under any permutation.
    ///
    /// Pinned here as literal bit positions for that reason. Changing one is
    /// a format change and needs a `RECORD_VERSION` bump beside it.
    #[test]
    fn the_flag_bit_positions_are_wire_format() {
        assert_eq!(RecordFlags::CERT.bits(), 1 << 0);
        assert_eq!(RecordFlags::ANCHOR.bits(), 1 << 1);
        assert_eq!(RecordFlags::REVOKE.bits(), 1 << 2);
        assert_eq!(RecordFlags::REQUIRE_AUTH_SET.bits(), 1 << 3);
        assert_eq!(RecordFlags::REQUIRE_AUTH.bits(), 1 << 4);
        assert_eq!(RecordFlags::LAZY_SET.bits(), 1 << 5);
        assert_eq!(RecordFlags::LAZY.bits(), 1 << 6);

        // And the byte an encode actually writes, so the assertions above are
        // checked against the encoder rather than only against themselves.
        //
        // Deliberately a *lopsided* record — anchor but no cert, `require_auth`
        // set to false, `lazy` set to true — because a fully-populated one
        // writes `0b0111_1111` and would match under every permutation of the
        // bits, which is the one thing this test exists to catch.
        let record = NodeRecord {
            seed: seed(0x33),
            checkpoint_unix: 0,
            cert: None,
            trust_anchor: Some(anchor_bytes(0xA0)),
            self_revocation: None,
            require_auth: Some(false),
            lazy_cert_distribution: Some(true),
        };
        let encoded = RecordCodec.encode(&record).unwrap();
        // Set: ANCHOR (1), REQUIRE_AUTH_SET (3), LAZY_SET (5), LAZY (6).
        // Clear: CERT (0), REVOKE (2), REQUIRE_AUTH (4).
        assert_eq!(encoded.as_ref()[1], 0b0110_1010);
    }

    /// **There is no MAC in the record.** It is `derived_mac()` of the seed's
    /// keypair, and storing it beside the seed would be storing the same fact
    /// twice — which is exactly the defect GitLab #58 reports, in durable
    /// form.
    #[test]
    fn the_mac_is_derived_from_the_seed_and_not_stored() {
        let record = NodeRecord::fresh(seed(0x11));

        assert_eq!(record.mac(), Keypair::from_seed(&seed(0x11)).derived_mac());

        let encoded = RecordCodec.encode(&record).unwrap();
        assert_eq!(
            encoded.as_ref().len(),
            RECORD_HEADER_LEN,
            "a record with no credential is header-only; there is no room for an address"
        );
    }

    /// A seedless board is not representable: `NodeRecord` always carries one,
    /// because a board has a seed from its very first boot and only *then*
    /// maybe a credential. Design 22 §4.1 — hoisting the seed out of
    /// `NodeIdentity` is what makes that structural.
    #[test]
    fn a_bare_seed_round_trips() {
        let record = NodeRecord::fresh(seed(0x22));
        let encoded = RecordCodec.encode(&record).unwrap();
        let decoded = RecordCodec.decode(encoded.as_ref()).unwrap();

        assert_eq!(decoded.seed, seed(0x22));
        assert_eq!(decoded.checkpoint_unix, 0);
        assert_eq!(decoded.cert, None);
        assert_eq!(decoded.trust_anchor, None);
        assert_eq!(decoded.self_revocation, None);
        assert_eq!(decoded.require_auth, None);
        assert_eq!(decoded.lazy_cert_distribution, None);
    }

    /// Every field present at once round-trips, and the encoding is exactly as
    /// long as its parts.
    #[test]
    fn a_full_record_round_trips() {
        let record = NodeRecord {
            seed: seed(0x33),
            checkpoint_unix: 1_800_000_000,
            cert: Some(cert_bytes(0xA1)),
            trust_anchor: Some(anchor_bytes(0xB2)),
            self_revocation: Some(revoke_bytes(0xC3)),
            require_auth: Some(true),
            lazy_cert_distribution: Some(false),
        };

        let encoded = RecordCodec.encode(&record).unwrap();
        assert_eq!(
            encoded.as_ref().len(),
            RECORD_HEADER_LEN
                + MembershipCert::SERIALIZED_LEN
                + TrustAnchor::SERIALIZED_LEN
                + RevocationRecord::SERIALIZED_LEN
        );

        let decoded = RecordCodec.decode(encoded.as_ref()).unwrap();
        assert_eq!(decoded, record);
    }

    /// Each optional blob is independently present or absent — all eight
    /// combinations, since the flags byte and the payload's length have to
    /// agree in every one of them and a fixed-position layout is easy to get
    /// right for one case and wrong for the others.
    #[test]
    fn every_combination_of_optional_blobs_round_trips() {
        for bits in 0u8..8 {
            let record = NodeRecord {
                seed: seed(0x44),
                checkpoint_unix: 42,
                cert: (bits & 1 != 0).then(|| cert_bytes(1)),
                trust_anchor: (bits & 2 != 0).then(|| anchor_bytes(2)),
                self_revocation: (bits & 4 != 0).then(|| revoke_bytes(3)),
                require_auth: None,
                lazy_cert_distribution: None,
            };

            let encoded = RecordCodec.encode(&record).unwrap();
            let decoded = RecordCodec
                .decode(encoded.as_ref())
                .unwrap_or_else(|e| panic!("combination {bits:#05b} failed to decode: {e:?}"));
            assert_eq!(decoded, record, "combination {bits:#05b}");
        }
    }

    /// The two boolean settings are tri-state — unset, false, true — and unset
    /// is not the same as false: it means the operator has never changed it,
    /// which is what keeps a startup default authoritative.
    #[test]
    fn the_tristate_flags_round_trip_all_nine_ways() {
        for require_auth in [None, Some(false), Some(true)] {
            for lazy in [None, Some(false), Some(true)] {
                let record = NodeRecord {
                    require_auth,
                    lazy_cert_distribution: lazy,
                    ..NodeRecord::fresh(seed(0x55))
                };

                let encoded = RecordCodec.encode(&record).unwrap();
                let decoded = RecordCodec.decode(encoded.as_ref()).unwrap();
                assert_eq!(
                    decoded.require_auth, require_auth,
                    "{require_auth:?}/{lazy:?}"
                );
                assert_eq!(
                    decoded.lazy_cert_distribution, lazy,
                    "{require_auth:?}/{lazy:?}"
                );
            }
        }
    }

    /// The checkpoint survives at full width: design 22 §4.5 persists
    /// `WallClock::estimate`, a unix second, and truncating it would move the
    /// clock — in the one direction §4.6 says nothing may.
    #[test]
    fn a_large_checkpoint_round_trips_undamaged() {
        let record = NodeRecord {
            checkpoint_unix: u64::MAX - 1,
            ..NodeRecord::fresh(seed(0x66))
        };
        let encoded = RecordCodec.encode(&record).unwrap();
        assert_eq!(
            RecordCodec
                .decode(encoded.as_ref())
                .unwrap()
                .checkpoint_unix,
            u64::MAX - 1
        );
    }

    /// A blob from a format this build does not understand fails closed,
    /// rather than having its bytes read as a seed.
    #[test]
    fn decode_rejects_an_unknown_version() {
        let mut blob = vec![0u8; RECORD_HEADER_LEN];
        blob[0] = 0xFE;
        assert_eq!(
            RecordCodec.decode(&blob),
            Err(RecordCodecError::UnknownVersion(0xFE))
        );
    }

    /// A record shorter than its own fixed header is refused before anything
    /// is read out of it.
    #[test]
    fn decode_rejects_a_truncated_record() {
        let mut blob = vec![0u8; RECORD_HEADER_LEN - 1];
        blob[0] = RECORD_VERSION;
        assert!(matches!(
            RecordCodec.decode(&blob),
            Err(RecordCodecError::WrongLength { .. })
        ));
    }

    /// **The flags byte and the payload length must agree.** A record whose
    /// flags claim a certificate follows but which carries no bytes for one is
    /// refused, rather than yielding a truncated certificate the node would
    /// then fail to verify for the wrong reason.
    #[test]
    fn decode_rejects_a_length_that_disagrees_with_the_flags() {
        let full = NodeRecord {
            cert: Some(cert_bytes(0xD4)),
            ..NodeRecord::fresh(seed(0x77))
        };
        let encoded = RecordCodec.encode(&full).unwrap();

        // Drop the last byte: the flags still claim a certificate.
        let short = &encoded.as_ref()[..encoded.as_ref().len() - 1];
        assert!(matches!(
            RecordCodec.decode(short),
            Err(RecordCodecError::WrongLength { .. })
        ));

        // And a byte too many, with the flags unchanged.
        let mut long = encoded.as_ref().to_vec();
        long.push(0);
        assert!(matches!(
            RecordCodec.decode(&long),
            Err(RecordCodecError::WrongLength { .. })
        ));
    }

    /// A v1 blob — the `[version, mac0..mac5]` this module used to write — is
    /// recognised as a **migration**, not as corruption.
    ///
    /// Both paths mint the same fresh seed; the difference is what an operator
    /// reads afterwards. A firmware update should not look like a fault
    /// (design 22 §6.1). There is nothing to carry forward: the old blob holds
    /// a FICR-derived MAC and no key, and a board that could not store a
    /// credential by definition holds none.
    #[test]
    fn a_v1_mac_blob_reads_as_never_provisioned() {
        let v1 = vec![1u8, 0x02, 0, 0, 0, 0, 0x2a];
        assert_eq!(
            RecordCodec.decode(&v1),
            Err(RecordCodecError::LegacyMacBlob)
        );
    }

    /// ...and the loader treats it exactly as a fresh device: a seed is minted
    /// and persisted, and this boot reports success rather than an error.
    #[test]
    fn a_v1_mac_blob_mints_a_fresh_seed_without_reporting_an_error() {
        let store = MemStore::holding(vec![1u8, 0x02, 0, 0, 0, 0, 0x2a]);
        let mut buf = [0u8; RECORD_READ_BUF_LEN];

        let (loaded, how) = load_or_init_record(store.clone(), || seed(0x88), &mut buf)
            .expect("a v1 blob is a migration, not a failure");

        assert_eq!(loaded.get().seed, seed(0x88));
        assert_eq!(
            how,
            Provisioned::MigratedFromV1,
            "a migration must be distinguishable from a first boot: the board's mesh \
             address just changed permanently, and this is the only thing that says so"
        );
        let mut buf = [0u8; RECORD_READ_BUF_LEN];
        let (reloaded, how) = load_or_init_record(
            store,
            || panic!("the migrated record should already be stored"),
            &mut buf,
        )
        .unwrap();
        assert_eq!(reloaded.get().seed, seed(0x88));
        assert_eq!(how, Provisioned::Loaded, "the next boot is an ordinary one");
    }

    /// On a fresh store the seed is minted once and durably persisted: a
    /// second call against the same medium reloads it without minting again.
    #[test]
    fn a_fresh_store_mints_a_seed_and_persists_it() {
        let store = MemStore::default();
        let mut buf = [0u8; RECORD_READ_BUF_LEN];

        let (first, how) = load_or_init_record(store.clone(), || seed(0x99), &mut buf).unwrap();
        assert_eq!(first.get().seed, seed(0x99));
        assert_eq!(how, Provisioned::Minted, "a fresh store is a first boot");

        let mut buf = [0u8; RECORD_READ_BUF_LEN];
        let (second, how) = load_or_init_record(
            store,
            || panic!("mint must not run when a record is already stored"),
            &mut buf,
        )
        .unwrap();
        assert_eq!(second.get().seed, seed(0x99));
        assert_eq!(how, Provisioned::Loaded);
    }

    /// A stored record is reloaded whole — the credential comes back with the
    /// seed, which is the entire point of one blob rather than two stores
    /// (design 22 §5).
    #[test]
    fn a_stored_credential_is_reloaded_with_its_seed() {
        let store = MemStore::default();
        let mut buf = [0u8; RECORD_READ_BUF_LEN];
        let (mut loaded, _) = load_or_init_record(store.clone(), || seed(0xAA), &mut buf).unwrap();

        loaded
            .mutate(|record| {
                record.cert = Some(cert_bytes(0x01));
                record.trust_anchor = Some(anchor_bytes(0x02));
                record.checkpoint_unix = 1_800_000_000;
            })
            .1
            .expect("the store accepts writes");
        drop(loaded);

        let mut buf = [0u8; RECORD_READ_BUF_LEN];
        let (rebooted, _) =
            load_or_init_record(store, || panic!("already provisioned"), &mut buf).unwrap();
        let record = rebooted.get();
        assert_eq!(record.seed, seed(0xAA));
        assert_eq!(record.cert, Some(cert_bytes(0x01)));
        assert_eq!(record.trust_anchor, Some(anchor_bytes(0x02)));
        assert_eq!(record.checkpoint_unix, 1_800_000_000);
    }

    /// **An undecodable record is erased before anything is written over it.**
    ///
    /// The old `MacCodec` overwrote a corrupt blob in place, which was fine
    /// for six public address bytes. With a seed in it, "overwrite" is the
    /// wrong verb: the payload may be a readable old key under a damaged
    /// header, and a `save` of a shorter record would leave its tail behind.
    /// Design 22 §4.4.
    #[test]
    fn a_corrupt_record_is_erased_before_a_fresh_seed_is_minted() {
        let store = MemStore::holding(vec![0xFE; RECORD_HEADER_LEN]);
        let mut buf = [0u8; RECORD_READ_BUF_LEN];

        let _ = load_or_init_record(store.clone(), || seed(0xBB), &mut buf);

        assert_eq!(
            store.calls(),
            vec!["load", "erase", "save"],
            "the damaged bytes must be erased, not merely written over"
        );
    }

    /// A corrupt record is still an error *on this boot* — an operator must
    /// see that the node's persisted identity was unreadable, rather than the
    /// node quietly coming up under a new address with no trace.
    #[test]
    fn a_corrupt_record_fails_closed_on_this_boot() {
        let store = MemStore::holding(vec![0xFE; RECORD_HEADER_LEN]);
        let mut buf = [0u8; RECORD_READ_BUF_LEN];

        assert!(matches!(
            load_or_init_record(store, || seed(0xCC), &mut buf),
            Err(IdentityError::Decode { repaired: true, .. })
        ));
    }

    /// ...and the *next* boot succeeds against the re-minted record, rather
    /// than hitting the same decode error forever.
    #[test]
    fn a_corrupt_record_self_heals_on_the_next_boot() {
        let store = MemStore::holding(vec![0xFE; RECORD_HEADER_LEN]);
        let mut buf = [0u8; RECORD_READ_BUF_LEN];

        let first = load_or_init_record(store.clone(), || seed(0xDD), &mut buf);
        assert!(matches!(first, Err(IdentityError::Decode { .. })));

        let mut buf = [0u8; RECORD_READ_BUF_LEN];
        let (second, how) = load_or_init_record(
            store,
            || panic!("the corrupt record should already have been repaired"),
            &mut buf,
        )
        .unwrap();
        assert_eq!(second.get().seed, seed(0xDD));
        assert_eq!(how, Provisioned::Loaded);
    }

    /// A fresh mint whose persist fails surfaces as a store error, not a
    /// silently in-memory-only seed. The caller must know the identity did not
    /// durably land — on the nRF that is what selects the FICR fallback
    /// (design 22 §4.3), and a board that believes it has a durable seed when
    /// it does not would present a new address on every power cycle.
    #[test]
    fn a_mint_whose_persist_fails_surfaces_as_a_store_error() {
        let mut buf = [0u8; RECORD_READ_BUF_LEN];
        assert!(matches!(
            load_or_init_record(FailingStore, || seed(0xEE), &mut buf),
            Err(IdentityError::Store("flash write failed"))
        ));
    }

    /// The read buffer is one byte longer than the largest record, so a stored
    /// blob one byte too long is caught by the codec's own length check ("bad
    /// format") rather than by the store reporting an undersized buffer
    /// ("caller under-sized the read"). Both fail closed; the slack picks the
    /// more informative one.
    #[test]
    fn the_read_buffer_has_one_byte_of_slack_over_the_largest_record() {
        assert_eq!(RECORD_READ_BUF_LEN, MAX_RECORD_LEN + 1);

        // The behaviour, not just the arithmetic: a stored blob one byte too
        // long must come back as a decode error naming the length, which is
        // what the slack buys. Without it the store would report an undersized
        // read buffer instead — also fail-closed, but it points an operator at
        // the caller rather than at the bytes.
        let store = MemStore::holding(vec![RECORD_VERSION; MAX_RECORD_LEN + 1]);
        let mut buf = [0u8; RECORD_READ_BUF_LEN];

        assert!(
            matches!(
                load_or_init_record(store, || seed(0x5A), &mut buf),
                Err(IdentityError::Decode {
                    error: RecordCodecError::WrongLength { .. },
                    ..
                })
            ),
            "an over-long record should be reported as a bad format, not as a short buffer"
        );
    }

    /// An empty stored blob cannot even name a version, and is refused rather
    /// than read as a fresh device — a store that has never been written
    /// reports `Ok(None)` instead, so zero bytes means damage.
    #[test]
    fn decode_rejects_an_empty_blob() {
        assert!(matches!(
            RecordCodec.decode(&[]),
            Err(RecordCodecError::WrongLength { len: 0, .. })
        ));
    }

    /// A `NodeRecord`'s `Debug` must not print the seed.
    ///
    /// This crate's log records are served over the management API — the ring
    /// `GetLogs` answers from — so a `?record` in some future trace line would
    /// hand the node's private key to anything that can reach the port.
    #[test]
    fn debug_redacts_the_seed() {
        let record = NodeRecord::fresh(seed(0xAB));
        let rendered = std::format!("{record:?}");

        assert!(
            !rendered.contains("171, 171"),
            "the seed's bytes must not appear: {rendered}"
        );
        assert!(rendered.contains("redacted"), "{rendered}");
        assert!(
            rendered.contains("mac"),
            "the public half is what a reader wants: {rendered}"
        );
    }
}
