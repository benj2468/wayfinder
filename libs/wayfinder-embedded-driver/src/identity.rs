//! Durable node identity for an embedded node: the node's mesh [`Mac`],
//! generated once on first boot and persisted so it survives power cycles.
//!
//! A host node is handed its MAC by config; a bare-metal node has no config
//! file, so it must mint its own identity the first time it boots and remember
//! it thereafter — otherwise it would present a different mesh address to its
//! peers on every reset, churning their originator tables. This module is that
//! first integration of [`wayfinder_storage`]'s [`DurableStore`]/[`Persisted`]
//! onto embedded: [`load_or_init_identity`] reads the MAC back from a
//! board-supplied [`DurableStore`] if one was ever written, and otherwise runs
//! a board-supplied `init` closure (e.g. deriving the MAC from the chip's
//! factory-unique FICR on the nRF52840) and durably saves the result.
//!
//! Only the [`Mac`] is persisted today. The value is wrapped in a [`Persisted`]
//! rather than returned bare because that's this crate's established pattern
//! for "a value whose mutations should always attempt to persist" (mirrors
//! `wayfinder-server`'s `CaLog`, the abstraction's original motivating
//! caller) — not because a specific future field is already planned. Node
//! identity growing secret material (a keypair/enrolment cert) is explicitly
//! called out as its own, separate design problem in
//! `docs/design/implemented/04-generic-durable-store.md` §2's *non-goals*,
//! precisely because secret material has different handling concerns (sealed
//! storage, rotation) than this module's plain-`Mac` codec would give it for
//! free — so that door is intentionally left for a future design to open, not
//! assumed open here.

use wayfinder::interfaces::frame::Mac;
use wayfinder_storage::{Codec, DurableStore, Persisted};

/// Encoding version for a persisted identity blob. Bumped only on an
/// incompatible layout change; [`MacCodec::decode`] rejects any other value so
/// a blob written by a future format fails closed rather than being
/// misinterpreted as a MAC.
const IDENTITY_VERSION: u8 = 1;

/// Length of the encoded identity blob: a version byte followed by the six MAC
/// octets.
const IDENTITY_BLOB_LEN: usize = 1 + 6;

/// Read buffer size for loading the identity blob. `DurableStore::load`'s own
/// contract already forbids overflowing a too-small `out` buffer regardless
/// of size (an oversized stored blob comes back as a store-level error, never
/// a truncation) — this constant's one byte of slack over [`IDENTITY_BLOB_LEN`]
/// only decides *which* error an off-by-one-too-long stored blob produces: with
/// the slack, it's caught by [`MacCodec::decode`]'s length check
/// (`IdentityError::Decode`, "bad format"); without it, the store would report
/// it as an undersized buffer (`IdentityError::Store`, "caller under-sized the
/// read"). Both fail closed; the slack byte picks the more informative one.
pub const IDENTITY_READ_BUF_LEN: usize = IDENTITY_BLOB_LEN + 1;

/// [`Codec`] for a node's [`Mac`]: `[IDENTITY_VERSION, mac.0[0..6]]`. A tiny
/// fixed layout with a leading version byte — deliberately *not* raw
/// zerocopy bytes, so the stored blob is self-describing enough to reject a
/// stale or foreign format on decode instead of silently accepting six
/// arbitrary bytes as an address.
pub struct MacCodec;

/// A [`MacCodec`] decode failure: the stored bytes weren't a well-formed
/// identity blob.
#[derive(Debug, PartialEq, Eq)]
pub enum MacCodecError {
    /// The blob wasn't exactly [`IDENTITY_BLOB_LEN`] bytes.
    WrongLength(usize),
    /// The leading version byte wasn't one this build understands.
    UnknownVersion(u8),
}

impl Codec<Mac> for MacCodec {
    type Error = MacCodecError;
    type Encoded = [u8; IDENTITY_BLOB_LEN];

    fn encode(&self, value: &Mac) -> Result<Self::Encoded, Self::Error> {
        let mut out = [0u8; IDENTITY_BLOB_LEN];
        out[0] = IDENTITY_VERSION;
        out[1..].copy_from_slice(&value.0);
        Ok(out)
    }

    fn decode(&self, bytes: &[u8]) -> Result<Mac, Self::Error> {
        if bytes.len() != IDENTITY_BLOB_LEN {
            return Err(MacCodecError::WrongLength(bytes.len()));
        }
        if bytes[0] != IDENTITY_VERSION {
            return Err(MacCodecError::UnknownVersion(bytes[0]));
        }
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&bytes[1..]);
        Ok(Mac(mac))
    }
}

/// Failure bringing up a node's durable identity.
#[derive(Debug, PartialEq, Eq)]
pub enum IdentityError<SE> {
    /// The backing [`DurableStore`] failed a read or write.
    Store(SE),
    /// A previously-stored identity blob failed to decode — a corrupt or
    /// foreign-format store. This is a *permanent* condition, not a
    /// transient I/O fault: the bytes on the medium are intact and will fail
    /// to decode identically on every future boot until something rewrites
    /// them. [`load_or_init_identity`] makes a best-effort attempt to do
    /// exactly that (re-mint via `init` and overwrite the bad blob) before
    /// returning this error, so the node converges to a stable address on
    /// its *next* boot rather than hitting this same error forever — but
    /// this boot still reports the error, so an operator sees that the
    /// node's identity was corrupt rather than the node quietly changing
    /// address with no trace.
    Decode(MacCodecError),
    /// [`MacCodec::encode`]ing a freshly-minted `Mac` failed. Distinct from
    /// [`IdentityError::Decode`] even though both wrap a [`MacCodecError`]:
    /// this means nothing is durably stored yet (an in-memory value just
    /// couldn't be serialized), not that a previously-good store was found
    /// corrupt.
    Encode(MacCodecError),
}

/// Load this node's durable [`Mac`] from `store`, or mint one with `init` and
/// persist it if the store has never been written.
///
/// On a store that already holds an identity, `init` is never called and no
/// write occurs (so a normal boot costs no flash wear). On a fresh store,
/// `init` supplies the new MAC — a board derives this from a stable,
/// per-device source (the nRF52840 uses its factory FICR device ID) so the
/// address is reproducible even if the very first persist were lost — and the
/// result is durably saved before returning.
///
/// The identity is returned wrapped in a [`Persisted`] that owns `store` and
/// the codec, so later evolution of the node identity persists through
/// [`Persisted::mutate`]. Read the current MAC with [`Persisted::get`].
///
/// `read_buf` must be at least [`IDENTITY_READ_BUF_LEN`] bytes.
///
/// **Both pages of a [`DurableStore`] failing validation simultaneously**
/// (e.g. a `FlashStore` whose two pages were each independently corrupted by
/// separate power-loss events over the device's lifetime) is indistinguishable
/// from "never provisioned" at the `DurableStore` layer — both report
/// `load` as `Ok(None)`. That means this function silently mints and persists
/// a *new* MAC in that scenario rather than surfacing an error, the same as on
/// a genuinely fresh device. Accepted for this caller specifically because a
/// fresh mint is idempotent and harmless (the FICR-derived MAC on the
/// nRF52840 is deterministic, so even a "new" mint reproduces the same
/// address) — a future caller whose `init` is *not* idempotent would need a
/// different contract.
pub fn load_or_init_identity<S, F>(
    mut store: S,
    init: F,
    read_buf: &mut [u8],
) -> Result<Persisted<Mac, S, MacCodec>, IdentityError<S::Error>>
where
    S: DurableStore,
    F: FnOnce() -> Mac,
{
    match store.load(read_buf).map_err(IdentityError::Store)? {
        Some(n) => match MacCodec.decode(&read_buf[..n]) {
            Ok(mac) => Ok(Persisted::new(mac, store, MacCodec)),
            Err(decode_err) => {
                // Permanent, not transient (see IdentityError::Decode's doc):
                // best-effort re-mint and overwrite the bad blob so a *later*
                // boot converges to a stable address instead of hitting this
                // same error forever. Best-effort because this boot reports
                // `decode_err` regardless — a failed overwrite here just means
                // the next boot retries this same recovery, not a worse
                // outcome than not trying.
                if let Ok(encoded) = MacCodec.encode(&init()) {
                    let _ = store.save(encoded.as_ref());
                }
                Err(IdentityError::Decode(decode_err))
            }
        },
        None => {
            let mac = init();
            let encoded = MacCodec.encode(&mac).map_err(IdentityError::Encode)?;
            store.save(encoded.as_ref()).map_err(IdentityError::Store)?;
            Ok(Persisted::new(mac, store, MacCodec))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    use std::rc::Rc;

    fn mac(n: u8) -> Mac {
        Mac([0x02, 0, 0, 0, 0, n])
    }

    /// An in-memory [`DurableStore`] whose blob is shared via `Rc<RefCell<_>>`,
    /// so a test can hand one clone to `load_or_init_identity` and inspect (or
    /// re-load through) the other to see what was durably written — the same
    /// "simulate a restart against the same medium" trick the storage crate's
    /// own tests use.
    #[derive(Default, Clone)]
    struct MemStore {
        blob: Rc<RefCell<Option<Vec<u8>>>>,
    }

    impl DurableStore for MemStore {
        type Error = core::convert::Infallible;

        fn load(&mut self, out: &mut [u8]) -> Result<Option<usize>, Self::Error> {
            Ok(self.blob.borrow().as_ref().map(|b| {
                out[..b.len()].copy_from_slice(b);
                b.len()
            }))
        }

        fn save(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            *self.blob.borrow_mut() = Some(data.to_vec());
            Ok(())
        }
    }

    /// The `MacCodec` round-trips a MAC through its byte form.
    #[test]
    fn codec_round_trips() {
        let m = mac(0x2a);
        let encoded = MacCodec.encode(&m).unwrap();
        assert_eq!(encoded.len(), IDENTITY_BLOB_LEN);
        assert_eq!(MacCodec.decode(&encoded).unwrap(), m);
    }

    /// Decode rejects a wrong-length blob rather than reading past/short of the
    /// six address bytes.
    #[test]
    fn codec_rejects_wrong_length() {
        assert_eq!(
            MacCodec.decode(&[IDENTITY_VERSION, 1, 2, 3]),
            Err(MacCodecError::WrongLength(4))
        );
    }

    /// Decode rejects an unknown version byte, failing closed on a
    /// foreign/future format instead of treating its bytes as an address.
    #[test]
    fn codec_rejects_unknown_version() {
        let mut blob = [0u8; IDENTITY_BLOB_LEN];
        blob[0] = 0xFF;
        assert_eq!(
            MacCodec.decode(&blob),
            Err(MacCodecError::UnknownVersion(0xFF))
        );
    }

    /// Decode also rejects a blob one byte too *long* — the specific boundary
    /// `IDENTITY_READ_BUF_LEN`'s one byte of slack exists to route through
    /// this check rather than an undersized-buffer error.
    #[test]
    fn codec_rejects_one_byte_too_long() {
        let mut blob = [0u8; IDENTITY_BLOB_LEN + 1];
        blob[0] = IDENTITY_VERSION;
        assert_eq!(
            MacCodec.decode(&blob),
            Err(MacCodecError::WrongLength(IDENTITY_BLOB_LEN + 1))
        );
    }

    /// On a fresh store, `init` mints the MAC and it is durably persisted: a
    /// second call against the same underlying store reloads that MAC without
    /// calling `init` again.
    #[test]
    fn fresh_store_mints_and_persists_then_reloads() {
        let store = MemStore::default();
        let mut buf = [0u8; IDENTITY_READ_BUF_LEN];

        let first = load_or_init_identity(store.clone(), || mac(0x11), &mut buf).unwrap();
        assert_eq!(*first.get(), mac(0x11));

        // A "reboot": init must NOT run (it would panic if it did), and the
        // reloaded MAC is the one first minted, proving it was persisted.
        let second = load_or_init_identity(
            store,
            || panic!("init must not run when an identity is already stored"),
            &mut buf,
        )
        .unwrap();
        assert_eq!(*second.get(), mac(0x11));
    }

    /// A corrupt/undecodable stored blob surfaces as `IdentityError::Decode`,
    /// not a silent re-mint — an operator must see that a node's persisted
    /// identity was unreadable.
    #[test]
    fn corrupt_store_fails_closed() {
        let store = MemStore::default();
        *store.blob.borrow_mut() = Some(vec![0xFF, 0xFF]); // bad version + short
        let mut buf = [0u8; IDENTITY_READ_BUF_LEN];

        let result = load_or_init_identity(store, || mac(0x22), &mut buf);
        assert!(matches!(result, Err(IdentityError::Decode(_))));
    }

    /// A corrupt stored blob is still reported as `Err` on this boot (per
    /// `corrupt_store_fails_closed` above), but `load_or_init_identity`
    /// makes a best-effort attempt to overwrite it with a freshly-minted MAC
    /// before returning — so a *second* call against the same underlying
    /// store (simulating the next boot) succeeds with the re-minted address
    /// instead of hitting the same decode error forever.
    #[test]
    fn corrupt_store_self_heals_on_next_boot() {
        let store = MemStore::default();
        *store.blob.borrow_mut() = Some(vec![0xFF, 0xFF]); // undecodable
        let mut buf = [0u8; IDENTITY_READ_BUF_LEN];

        let first = load_or_init_identity(store.clone(), || mac(0x44), &mut buf);
        assert!(matches!(first, Err(IdentityError::Decode(_))));

        let second = load_or_init_identity(
            store,
            || panic!("init must not run again — the corrupt blob should already be repaired"),
            &mut buf,
        )
        .unwrap();
        assert_eq!(*second.get(), mac(0x44));
    }

    /// A store whose `save` always fails, mirroring `wayfinder_storage`'s own
    /// `FailingStore` test double — exercises the fresh-mint path's error
    /// propagation, which no other test in this module reaches.
    #[derive(Default)]
    struct FailingStore;

    impl DurableStore for FailingStore {
        type Error = &'static str;

        fn load(&mut self, _out: &mut [u8]) -> Result<Option<usize>, Self::Error> {
            Ok(None)
        }

        fn save(&mut self, _data: &[u8]) -> Result<(), Self::Error> {
            Err("disk full")
        }
    }

    /// On a fresh store whose `save` fails, the mint-and-persist path surfaces
    /// `IdentityError::Store`, not a silently-succeeding in-memory-only MAC —
    /// the caller must know the identity didn't durably land.
    #[test]
    fn fresh_store_mint_persist_failure_surfaces_as_store_error() {
        let mut buf = [0u8; IDENTITY_READ_BUF_LEN];
        let result = load_or_init_identity(FailingStore, || mac(0x33), &mut buf);
        assert!(matches!(result, Err(IdentityError::Store("disk full"))));
    }
}
