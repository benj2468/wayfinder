#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! A generic durable-blob-store abstraction.
//!
//! `CaLog` (`wayfinder-server`) and the mesh's local revocation cache both
//! need the same underlying guarantee — durably replace one blob with
//! another such that a reader never observes a torn mix of old and new, even
//! across a crash or power loss mid-write — on media with wildly different
//! atomicity primitives (a POSIX file has atomic `rename`; raw flash has
//! neither atomic rename nor atomic byte-level overwrite). [`DurableStore`]
//! is that one shared guarantee, `no_std`-clean so it can eventually run on
//! bare-metal flash as readily as a `std` file; everything about *what's
//! inside* the blob (encoding, versioning, migration) stays the caller's
//! concern.
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
/// A `DurableStore` instance owns exactly one blob's worth of state — a
/// caller with several independently-persisted things (as `CaLog` already
/// has: an issued-certificate log and a held-CSR store, each persisted by
/// its own call) holds one instance per thing, not one instance managing
/// several. There is no multi-blob transaction support, deliberately (see
/// the design doc's non-goals).
///
/// Synchronous (blocking) by design, not async. The obvious argument for
/// async — a flash erase/write cycle can take tens of milliseconds, and
/// shouldn't block a shared executor — only pays for itself when something
/// *else* could usefully run during that block, i.e. multiple concurrent
/// tasks. An embedded node using this trait may now also run a management-API
/// serve loop concurrently on the same executor (`wayfinder-embedded-driver`'s
/// `run_with_mgmt`), so the "nothing else to starve" premise no longer holds
/// unconditionally — but every `DurableStore` call in this workspace today
/// (the nRF52840 binary's identity load/mint) happens once at boot, before
/// that concurrent loop starts, so nothing is actually starved yet. This
/// stays sync rather than paying `dynosaur`/dyn-compatibility ceremony for a
/// benefit no current call site needs; revisit if a `DurableStore` call is
/// ever added on a hot path that runs *after* a second concurrent task is
/// live. On `std`, `FileStore` blocks the calling thread for the duration of
/// the write, exactly as direct `std::fs` calls already do everywhere else in
/// this workspace.
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
}
