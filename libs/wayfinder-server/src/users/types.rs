//! The user store's vocabulary types, on `no_std`.
//!
//! [`store`](super::store) is `std`-gated — it hashes passwords with Argon2id
//! and checks TOTP codes, neither of which an embedded node links (see that
//! module for why the credential store sits at the certificate authority at
//! all). What crosses the management-API seam is not a credential, though: it
//! is which of the two management tiers an account holds, and
//! [`MeshAuthority`](crate::MeshAuthority) is compiled on both targets. So the
//! role lives here, where a `no_std` build can name it and a board pays a
//! discriminant for it.

/// What an account's session certificates may do.
///
/// Two roles, not a bitmask, because they are the two management tiers that
/// exist: `CERT_FLAG_ADMIN` and `CERT_FLAG_VIEWER`. A third would mean a third
/// tier in `permits`, which is a decision to take there rather than here.
///
/// The serde derives are `std`-only because serde itself is: the only thing
/// that serializes a role is the CA state snapshot (`persistence.rs`), which
/// exists on no other target.
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum UserRole {
    /// Session certificates carry `CERT_FLAG_ADMIN`: full management.
    Admin,
    /// Session certificates carry `CERT_FLAG_VIEWER`: the queries, less the
    /// few that are an administrator's read (the log ring, the account
    /// roster).
    ///
    /// The default, so an account created without a role stated is the one
    /// that can do less.
    #[default]
    Viewer,
}
