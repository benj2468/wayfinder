#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! A generic durable-blob-store abstraction.
//!
//! [`DurableStore`] is one guarantee — durably replace a blob such that a
//! reader never observes a torn mix of old and new, even across a crash
//! mid-write — over media with wildly different atomicity primitives (a POSIX
//! file has atomic `rename`; raw flash has neither atomic rename nor atomic
//! byte-level overwrite). It is `no_std`-clean so it runs on bare-metal flash
//! as readily as a `std` file. What is *inside* the blob (encoding,
//! versioning, migration) stays the caller's concern.
//!
//! See `docs/design/implemented/04-generic-durable-store.md` for the design
//! this implements.

#[cfg(feature = "std")]
mod file;

#[cfg(feature = "std")]
pub use file::FileStore;

#[cfg(feature = "flash")]
mod flash;

#[cfg(feature = "flash")]
pub use flash::FlashError;
#[cfg(feature = "flash")]
pub use flash::FlashStore;

mod persisted;

pub use persisted::Codec;
pub use persisted::LoadError;
pub use persisted::PersistError;
pub use persisted::PersistOutcome;
pub use persisted::Persisted;

/// Durable, atomic single-blob storage.
///
/// One instance owns exactly one blob. A caller persisting several things
/// independently (as `CaLog` does) holds one instance per thing; there is no
/// multi-blob transaction support, deliberately — see the design doc's
/// non-goals.
///
/// Blocking by design, and since design 22 that is a live trade rather than a
/// deferred one: a board's clock checkpoint and its `SetAuth` both write from
/// inside `run_with_mgmt`, which is exactly the "revisit if" this paragraph
/// used to name as hypothetical.
///
/// It stays blocking. A checkpoint is one erase every six hours and a `SetAuth`
/// is an operator action, so the loop stalls for tens of milliseconds on a
/// cadence nothing on the mesh can notice — against `dynosaur`
/// dyn-compatibility ceremony through every backend and every caller. Revisit
/// if a *frequent* writer is ever added.
pub trait DurableStore {
    /// The error type this store's medium can produce.
    type Error;

    /// Load the most recently durably saved blob into `out`, returning its
    /// length.
    ///
    /// `Ok(None)` means nothing has ever been saved — a legitimately fresh
    /// store, not an error. A blob larger than `out` is an error (via
    /// `Self::Error`), not a silent truncation.
    fn load(&mut self, out: &mut [u8]) -> Result<Option<usize>, Self::Error>;

    /// Durably replace the saved blob with `data`, atomically: a `load`
    /// after a crash or power loss during this call must return either the
    /// previous blob or `data` in full, never a mix, and never a torn
    /// partial write.
    fn save(&mut self, data: &[u8]) -> Result<(), Self::Error>;

    /// Erase every copy of the blob other than the current one.
    ///
    /// Only meaningful on a medium that keeps a previous copy in order to
    /// provide `save`'s atomicity — `FlashStore`'s A/B ping-pong does exactly
    /// that, and for a blob carrying a secret it is the wrong default: a
    /// rotated identity seed lingers in the spare page, in the clear, until
    /// some later save happens to land on it.
    ///
    /// Call it *after* a `save` that replaced a secret, never before:
    /// `save(new)` then `scrub()` leaves a valid page at every instant a power
    /// cut can occur, where the reverse order has a window with nothing
    /// durable at all. What it gives up is the fallback for a *later* torn
    /// write — but a `save` already begins by erasing the sibling, so that
    /// fallback only ever spanned the gap between two saves. See
    /// `docs/design/22-embedded-node-record.md` §4.4.
    ///
    /// The default is a no-op, which is correct for a medium that keeps no
    /// second copy in the first place (a `rename`-based `FileStore`). An
    /// implementor whose `save` *does* leave one must override it.
    ///
    /// Costs no erase when there is nothing stale to erase, so a caller may
    /// invoke it unconditionally without spending flash wear.
    fn scrub(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Return the store to never-written: a subsequent `load` reports
    /// `Ok(None)`, and no copy of the blob remains on the medium.
    ///
    /// Distinct from saving an empty blob, which is a *record* holding
    /// nothing and which a caller cannot tell from a fresh device. This is
    /// what a caller wants when the stored bytes may be a secret it can no
    /// longer read — an undecodable identity record, say, whose payload might
    /// still be an old seed under a damaged header.
    ///
    /// Erasing a store that was never written is `Ok(())`, not an error: the
    /// desired end state already holds, so a caller erasing before minting a
    /// fresh identity need not special-case a fresh device.
    ///
    /// Deliberately **not** defaulted, where [`scrub`](Self::scrub) is. A
    /// no-op `scrub` is the honest answer on a medium that keeps no second
    /// copy; a no-op `erase` is never the honest answer, and a caller reaching
    /// for it is disposing of something it believes is a secret. Silently
    /// doing nothing there is the failure this method exists to prevent, so
    /// every store is made to answer for it.
    fn erase(&mut self) -> Result<(), Self::Error>;
}
