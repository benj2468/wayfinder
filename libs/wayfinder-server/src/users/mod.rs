//! The certificate authority's user accounts, in two halves.
//!
//! [`types`] is the `no_std` half: the role an account holds, which the
//! management-API seam ([`MeshAuthority`](crate::MeshAuthority)) names and
//! every target therefore compiles. [`store`] is the accounts themselves —
//! password hashing, TOTP, the roster the CA persists — and is `std`-gated,
//! because a board has neither the heap for Argon2id nor any business holding
//! a password. Its module doc carries the argument for that split of duties.

pub mod types;

#[cfg(feature = "std")]
mod store;

pub use types::UserRole;

// Glob, so every account type keeps the `crate::users::…` path it had when the
// store was one file: the split is where the code lives, not what the rest of
// the crate calls it.
#[cfg(feature = "std")]
pub use store::*;
