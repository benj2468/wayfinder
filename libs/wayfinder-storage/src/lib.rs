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
/// Blocking by design. A flash erase/write can take tens of milliseconds, but
/// every call site in this workspace today (the nRF's identity load/mint) runs
/// once at boot, before any concurrent task exists to starve. Revisit if a
/// call is ever added on a path that runs alongside a live `run_with_mgmt`
/// loop — until then, async would buy `dynosaur` dyn-compatibility ceremony
/// for nothing.
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
