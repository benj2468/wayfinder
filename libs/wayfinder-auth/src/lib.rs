#![cfg_attr(not(feature = "std"), no_std)]

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
mod pairwise;
mod revoke;

#[cfg(feature = "std")]
mod authority;

pub use cert::{CERT_VERSION, MembershipCert, TrustAnchor, VerifiedCert};
pub use error::AuthError;
pub use key::{Keypair, verify_signature};
pub use pairwise::{TAG_LEN, frame_tag, verify_frame_tag};
pub use revoke::{REVOKE_VERSION, RevocationRecord};

#[cfg(feature = "std")]
pub use authority::Authority;
