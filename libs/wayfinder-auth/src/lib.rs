#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! Cryptographic identity and mesh membership for Wayfinder.
//!
//! Wayfinder meshes are optionally segregated by a per-mesh trust anchor: a
//! node belongs to a mesh only if it holds a [`MembershipCert`] signed by that
//! mesh's root key (the trust anchor).  This crate provides the primitives that
//! make that work, with a `no_std` core (verification + key agreement, used by
//! the router even on embedded nodes) and a `std`-gated [`Authority`] (the
//! certificate authority run by the enrollment portal).
//!
//! Identity is **key-bound to a MAC**: a cert attests `Ed25519 pubkey ↔ node
//! MAC ↔ mesh`, so the existing device-derived [`Mac`](interfaces::frame::Mac)
//! addressing is preserved and authentication is purely additive.
//!
//! Two authentication mechanisms ride on top:
//! - **Control plane (OGMs, one-to-many):** the originator signs the immutable
//!   header ([`Keypair::sign`] / [`verify_signature`]) and embeds its cert, so
//!   every member can verify it against the trust anchor.  This is what rejects
//!   spurious or forged OGMs.
//! - **Directed data plane (unicast/mcast, hop-by-hop):** a cheap pairwise
//!   symmetric tag ([`pairwise_tag`]) keyed by an X25519 shared secret derived
//!   from the neighbor's cert pubkey ([`Keypair::pairwise_key`]).
//!
//! Payloads are never encrypted — wayfinder provides authenticity and
//! segregation only; confidentiality is left to L3.

mod cert;
mod error;
mod key;
mod mac;
mod pairwise;
mod revoke;

#[cfg(feature = "std")]
mod authority;

pub use cert::CERT_FLAG_ADMIN;
pub use cert::CERT_FLAG_USER;
pub use cert::CERT_FLAG_VIEWER;
pub use cert::CERT_VERSION;
pub use cert::MembershipCert;
pub use cert::TrustAnchor;
pub use cert::VerifiedCert;
pub use error::AuthError;
pub use key::Keypair;
pub use key::verify_signature;
pub use mac::derive_mac;
pub use mac::force_locally_administered_unicast;
pub use pairwise::TAG_LEN;
pub use pairwise::frame_tag;
pub use pairwise::verify_frame_tag;
pub use revoke::REVOKE_VERSION;
pub use revoke::RevocationRecord;

#[cfg(feature = "std")]
pub use authority::Authority;
