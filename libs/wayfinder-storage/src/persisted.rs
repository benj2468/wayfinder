//! [`Persisted`]: seal a value's mutations behind a callback that also
//! durably persists the result, on top of a [`DurableStore`].
//!
//! `CaLog` (`wayfinder-server`) had this exact shape hand-rolled —
//! `mutate_issued`/`mutate_held` ran a closure against its in-memory state
//! and then always attempted a persist — before it was generalized here.
//! Nothing about that orchestration (run `f`, then persist, return both
//! outcomes) is specific to CA state; only *what's inside* the value and how
//! it's encoded is caller-specific, via [`Codec`].

use crate::DurableStore;

/// Translate a value to/from the raw bytes a [`DurableStore`] persists,
/// independent of the store's own medium (file vs. flash). Fully
/// caller-defined: JSON-for-auditability, a raw POD dump, anything —
/// [`Persisted`] never inspects the bytes itself.
pub trait Codec<T> {
    /// Encoding/decoding failure (a serialization error, malformed bytes on
    /// decode, an unrecognized schema version — whatever a given codec needs).
    type Error;
    /// The encoded bytes' owning container: `Vec<u8>` for a `std`/`alloc`
    /// codec (e.g. JSON), or a fixed-capacity buffer type for a `no_std`,
    /// allocation-free one. Only needs to deref to the encoded bytes.
    type Encoded: AsRef<[u8]>;

    /// Encode `value` into its durable byte representation.
    fn encode(&self, value: &T) -> Result<Self::Encoded, Self::Error>;

    /// Decode a durable byte representation back into `T`.
    fn decode(&self, bytes: &[u8]) -> Result<T, Self::Error>;
}

/// Failure loading a [`Persisted`]: either the store itself failed (I/O), or
/// the bytes it returned didn't decode.
#[derive(Debug)]
pub enum LoadError<SE, CE> {
    /// The underlying [`DurableStore::load`] returned an error.
    Store(SE),
    /// The store's bytes didn't decode via the [`Codec`].
    Decode(CE),
}

/// Failure persisting a mutation: either encoding the new value failed, or
/// the store's write did.
#[derive(Debug)]
pub enum PersistError<SE, CE> {
    /// The [`Codec`] failed to encode the value.
    Encode(CE),
    /// The underlying [`DurableStore::save`] returned an error.
    Store(SE),
}

/// The outcome of a single persist attempt: a named alias for
/// `Result<(), PersistError<SE, CE>>` so callers (and this module's own
/// signatures) don't spell out the nested generic inline.
pub type PersistOutcome<SE, CE> = Result<(), PersistError<SE, CE>>;

/// An in-memory value of `T` whose mutations are sealed behind
/// [`Persisted::mutate`]: the only way to change the value is to hand this
/// type a closure, which it runs and then durably persists the result,
/// returning both outcomes. This is what makes "every mutation is followed
/// by a persist attempt" a property of the type rather than a convention
/// call sites must remember — the same guarantee `CaLog` documented as its
/// own invariant before this was generalized.
///
/// `S` is typically `Option<ConcreteStore>` when persistence is itself
/// optional (no configured path/flash region ⇒ in-memory only) — see the
/// blanket `DurableStore for Option<S>` impl, which makes `None` behave as
/// an always-empty, always-successfully-no-op store with no special-casing
/// needed here.
pub struct Persisted<T, S, C> {
    value: T,
    store: S,
    codec: C,
}

impl<T, S, C> Persisted<T, S, C> {
    /// Wrap an already-known `value` with `store`/`codec` directly, without
    /// reading anything back first — for a caller that has no snapshot to
    /// load yet (a fresh, in-memory-only instance) and so has nothing to
    /// gain from [`Self::load`]'s round trip through the store.
    /// Unconstrained (no `DurableStore`/`Codec` bounds): building this value
    /// is plain field assignment, whatever `S`/`C` end up being.
    pub fn new(value: T, store: S, codec: C) -> Self {
        Self {
            value,
            store,
            codec,
        }
    }
}

impl<T, S: DurableStore, C: Codec<T>> Persisted<T, S, C> {
    /// Load `T` from `store` via `codec`, or start from `default` if the
    /// store is empty (a legitimately fresh store, not an error) — `store`
    /// itself decides what "empty" means (a missing file, an unwritten flash
    /// region, or `None` under the `Option<S>` blanket impl).
    ///
    /// `read_buf` bounds the largest encoded blob this call can read; a
    /// larger one is a [`LoadError::Store`] (surfaced via the store's own
    /// oversized-blob error), never a silent truncation.
    pub fn load(
        mut store: S,
        codec: C,
        default: T,
        read_buf: &mut [u8],
    ) -> Result<Self, LoadError<S::Error, C::Error>> {
        let value = match store.load(read_buf).map_err(LoadError::Store)? {
            Some(n) => codec.decode(&read_buf[..n]).map_err(LoadError::Decode)?,
            None => default,
        };
        Ok(Self {
            value,
            store,
            codec,
        })
    }

    /// Read-only view of the current in-memory value.
    pub fn get(&self) -> &T {
        &self.value
    }

    fn persist(&mut self) -> PersistOutcome<S::Error, C::Error> {
        let encoded = self
            .codec
            .encode(&self.value)
            .map_err(PersistError::Encode)?;
        self.store
            .save(encoded.as_ref())
            .map_err(PersistError::Store)?;
        Ok(())
    }
}

impl<T: Clone, S: DurableStore, C: Codec<T>> Persisted<T, S, C> {
    /// Run `f` against the value, then attempt to durably persist the
    /// result, returning both `f`'s result and the persist outcome so the
    /// caller can decide how to react to a durability failure.
    ///
    /// A failed persist **rolls the value back** to what it was before `f`
    /// ran: the in-memory value must never diverge from what's durably
    /// stored, so a mutation that couldn't be persisted did not, as far as
    /// any later [`Self::get`]/`mutate` call can tell, happen at all. `f`'s
    /// own return value is still handed back regardless — it's the caller's
    /// business, not tied to whether the mutation stuck — but the caller
    /// must treat a `Err` persist outcome as "this did not take effect",
    /// not just "this isn't durable yet".
    ///
    /// Requires `T: Clone` to snapshot the pre-mutation value; cheap at the
    /// scale this is meant for (see the design doc's own "tens of KB"
    /// framing for `CaLog`'s state) — a value large enough for a full clone
    /// per mutation to matter is a sign `mutate` needs a different shape for
    /// that caller, not that this bound is wrong in general.
    ///
    /// **Caveat: the rollback guarantee assumes `f` does not panic.** The
    /// snapshot is a local restored after `f` returns; if `f` unwinds, this
    /// function never gets the chance to restore it, and `self.value` is
    /// left however far `f` got before panicking — no persist is attempted
    /// either. In practice every closure passed to `mutate` in this
    /// workspace is a simple, infallible field mutation (a `Vec::push`, an
    /// index assignment already guarded by a prior lookup) that isn't
    /// expected to panic, so this is a real but low-probability gap, not a
    /// hardened one — `no_std`'s `catch_unwind` unavailability (many
    /// embedded targets build with `panic = "abort"`, where there's nothing
    /// to catch) also rules out closing it portably at this layer.
    pub fn mutate<R>(
        &mut self,
        f: impl FnOnce(&mut T) -> R,
    ) -> (R, PersistOutcome<S::Error, C::Error>) {
        let snapshot = self.value.clone();
        let result = f(&mut self.value);
        let persisted = self.persist();
        if persisted.is_err() {
            self.value = snapshot;
        }
        (result, persisted)
    }
}

/// Makes persistence itself optional: `None` behaves as an always-empty
/// store whose writes always trivially succeed, so a caller with an optional
/// backing store (no configured path, no flash region assigned) can use
/// `Persisted<T, Option<ConcreteStore>, C>` and get "in-memory only, mutate
/// still runs, persist is just always a no-op" for free — no special-casing
/// needed in [`Persisted`] itself. Mirrors the optionality `CaLog` handled by
/// hand before this was generalized.
impl<S: DurableStore> DurableStore for Option<S> {
    type Error = S::Error;

    fn load(&mut self, out: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        match self {
            Some(store) => store.load(out),
            None => Ok(None),
        }
    }

    fn save(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        match self {
            Some(store) => store.save(data),
            None => Ok(()),
        }
    }
}

// `std`-only: the test double below shares state via `Rc<RefCell<_>>`, a
// `std` convenience. `Persisted` itself stays `no_std`-clean (see the crate
// doc); this module just isn't the place that proves it — `cargo test -p
// wayfinder-storage --no-default-features` would otherwise fail to even
// compile, since `#[cfg(test)]` alone doesn't imply `std` is available.
#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use core::convert::Infallible;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// An in-memory [`DurableStore`] for tests: no real I/O, so `Persisted`'s
    /// orchestration can be exercised without a filesystem. Backed by a
    /// shared `Rc<RefCell<_>>` so a test can clone the handle *before*
    /// handing one clone's ownership to `Persisted::load`, then build a
    /// second `Persisted` from the other clone to observe what actually got
    /// durably written — a real store would use a real file path the same way.
    #[derive(Default, Clone)]
    struct MemStore {
        blob: Rc<RefCell<Option<heapless::Vec<u8, 256>>>>,
    }

    impl DurableStore for MemStore {
        type Error = Infallible;

        fn load(&mut self, out: &mut [u8]) -> Result<Option<usize>, Self::Error> {
            Ok(self.blob.borrow().as_ref().map(|b| {
                out[..b.len()].copy_from_slice(b);
                b.len()
            }))
        }

        fn save(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            let mut v = heapless::Vec::new();
            v.extend_from_slice(data).unwrap();
            *self.blob.borrow_mut() = Some(v);
            Ok(())
        }
    }

    /// A store whose `save` always fails, to exercise the
    /// rollback-on-persist-failure guarantee.
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

    /// Trivial codec for a `u32` counter: 4 bytes, big-endian. Enough to
    /// exercise `Persisted`'s orchestration without pulling serde into this
    /// crate's own tests.
    struct CounterCodec;

    impl Codec<u32> for CounterCodec {
        type Error = &'static str;
        type Encoded = [u8; 4];

        fn encode(&self, value: &u32) -> Result<Self::Encoded, Self::Error> {
            Ok(value.to_be_bytes())
        }

        fn decode(&self, bytes: &[u8]) -> Result<u32, Self::Error> {
            let arr: [u8; 4] = bytes.try_into().map_err(|_| "counter must be 4 bytes")?;
            Ok(u32::from_be_bytes(arr))
        }
    }

    /// `Persisted::new` wraps a value directly, with no store round trip —
    /// the shape `CaLog::empty()` needs (a fresh, in-memory-only instance).
    /// `mutate` still works normally afterward.
    #[test]
    fn new_wraps_a_value_without_loading() {
        let mut p = Persisted::new(7u32, None::<MemStore>, CounterCodec);
        assert_eq!(*p.get(), 7);

        let (_, persisted) = p.mutate(|v| *v += 1);
        assert!(persisted.is_ok());
        assert_eq!(*p.get(), 8);
    }

    /// A fresh store (nothing ever saved) loads as the caller-supplied
    /// default, not an error.
    #[test]
    fn load_from_empty_store_uses_default() {
        let mut buf = [0u8; 64];
        let p = Persisted::load(MemStore::default(), CounterCodec, 0, &mut buf).unwrap();
        assert_eq!(*p.get(), 0);
    }

    /// `mutate` applies the closure and durably persists the result: a
    /// second `Persisted` built from a clone of the same underlying store
    /// (simulating a restart) reloads the mutated value, not the default.
    #[test]
    fn mutate_persists_and_reloads() {
        let store = MemStore::default();
        let mut buf = [0u8; 64];
        let mut p = Persisted::load(store.clone(), CounterCodec, 0, &mut buf).unwrap();

        let (old, persisted) = p.mutate(|v| {
            let old = *v;
            *v += 1;
            old
        });
        assert_eq!(old, 0);
        assert!(persisted.is_ok());
        assert_eq!(*p.get(), 1);

        let reloaded = Persisted::load(store, CounterCodec, 0, &mut buf).unwrap();
        assert_eq!(
            *reloaded.get(),
            1,
            "the mutation was durably persisted, not just applied in memory"
        );
    }

    /// `mutate`'s closure result and the persist outcome are both returned,
    /// independently — `f`'s return value is not swallowed by a persist
    /// failure.
    #[test]
    fn mutate_returns_closure_result_and_persist_outcome_independently() {
        let mut buf = [0u8; 64];
        let mut p = Persisted::load(MemStore::default(), CounterCodec, 5, &mut buf).unwrap();

        let (doubled, persisted) = p.mutate(|v| *v * 2);
        assert_eq!(doubled, 10, "closure's own return value is preserved");
        assert!(persisted.is_ok());
    }

    /// A failing store rolls the in-memory value back to what it was before
    /// `f` ran: memory must never diverge from what's durably stored, so a
    /// mutation that couldn't be persisted did not, as far as any later
    /// `get()`/`mutate()` can tell, happen at all. The persist outcome still
    /// surfaces as `Err` so the caller can propagate/retry it, and `f`'s own
    /// return value is still handed back (it's the caller's business, not
    /// tied to whether the mutation stuck).
    #[test]
    fn failed_persist_rolls_back_the_in_memory_mutation() {
        let mut buf = [0u8; 64];
        let mut p = Persisted::load(FailingStore, CounterCodec, 0, &mut buf).unwrap();

        let (old, persisted) = p.mutate(|v| {
            let old = *v;
            *v += 1;
            old
        });
        assert!(matches!(persisted, Err(PersistError::Store("disk full"))));
        assert_eq!(
            old, 0,
            "the closure's own return value is still handed back"
        );
        assert_eq!(
            *p.get(),
            0,
            "the in-memory value was rolled back since it never durably persisted"
        );
    }

    /// `None: DurableStore` (the optional-persistence blanket impl) always
    /// reports empty on load and trivially succeeds on save — `Persisted`
    /// needs no special-casing to support "in-memory only, no backing store
    /// configured".
    #[test]
    fn optional_store_none_is_in_memory_only() {
        let mut buf = [0u8; 64];
        let none_store: Option<MemStore> = None;
        let mut p = Persisted::load(none_store, CounterCodec, 0, &mut buf).unwrap();

        let (_, persisted) = p.mutate(|v| *v += 1);
        assert!(persisted.is_ok(), "a None store's save is a no-op success");
        assert_eq!(*p.get(), 1, "the mutation still applies in memory");
    }

    /// Corrupt/undecodable bytes on load surface as `LoadError::Decode`, not
    /// a silent fallback to the default — mirroring `CaLog`'s existing
    /// fail-closed posture for a corrupt state file.
    #[test]
    fn undecodable_bytes_fail_closed_on_load() {
        let store = MemStore::default();
        *store.blob.borrow_mut() = Some(heapless::Vec::from_slice(b"not four bytes").unwrap());
        let mut buf = [0u8; 64];

        let result = Persisted::load(store, CounterCodec, 0, &mut buf);
        assert!(matches!(result, Err(LoadError::Decode(_))));
    }

    /// A codec whose `encode` fails for one sentinel value (`u32::MAX`) and
    /// succeeds otherwise — `CounterCodec`'s `encode` is infallible, so
    /// every other test in this module only ever exercises `persist()`'s
    /// *store*-failure path (`PersistError::Store`); this is the only way to
    /// reach its *encode*-failure path (`PersistError::Encode`) instead.
    struct FailsToEncodeSentinel;

    impl Codec<u32> for FailsToEncodeSentinel {
        type Error = &'static str;
        type Encoded = [u8; 4];

        fn encode(&self, value: &u32) -> Result<Self::Encoded, Self::Error> {
            if *value == u32::MAX {
                Err("refusing to encode the sentinel value")
            } else {
                Ok(value.to_be_bytes())
            }
        }

        fn decode(&self, bytes: &[u8]) -> Result<u32, Self::Error> {
            let arr: [u8; 4] = bytes.try_into().map_err(|_| "counter must be 4 bytes")?;
            Ok(u32::from_be_bytes(arr))
        }
    }

    /// The rollback guarantee holds for an *encode* failure too, not just a
    /// *store* failure: `persist()` has two fallible steps
    /// (`codec.encode` then `store.save`), and `mutate` must roll back on
    /// either — even with a perfectly healthy store (`MemStore`, not
    /// `FailingStore`) behind it, so the encode failure alone is what's
    /// under test here.
    #[test]
    fn failed_encode_rolls_back_the_in_memory_mutation_even_with_a_healthy_store() {
        let mut buf = [0u8; 64];
        let mut p =
            Persisted::load(MemStore::default(), FailsToEncodeSentinel, 0, &mut buf).unwrap();

        let (old, persisted) = p.mutate(|v| {
            let old = *v;
            *v = u32::MAX;
            old
        });
        assert!(matches!(persisted, Err(PersistError::Encode(_))));
        assert_eq!(
            old, 0,
            "the closure's own return value is still handed back"
        );
        assert_eq!(
            *p.get(),
            0,
            "the in-memory value was rolled back since encoding it for persistence failed"
        );
    }
}
