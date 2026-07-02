//! The wayfinder management-API wire protocol.
//!
//! [`wayfinder_v1alpha`] holds the `prost`-generated request/response types for
//! the `wayfinder.v1alpha` protobuf package (node info, routing/link-quality
//! tables, metrics, security status, and the certificate-authority flow), and
//! [`service`] defines the [`WayfinderDataProvider`](service::WayfinderDataProvider)
//! trait and request dispatch built on top of them. The crate is `no_std` +
//! `alloc`; the `serde` feature adds JSON serialization for the CLI.
#![no_std]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

extern crate alloc;

/// The `prost`-generated types for the `wayfinder.v1alpha` protobuf package.
/// Every message/field/enum is documented from its `//` comment in
/// `protos/wayfinder/v1alpha/wayfinder.proto` (enforced by `buf lint`).
pub mod wayfinder_v1alpha {
    #[expect(unused_imports)]
    use alloc::vec::Vec;

    include!(concat!(env!("OUT_DIR"), "/wayfinder.v1alpha.rs"));
}

/// The [`WayfinderDataProvider`](service::WayfinderDataProvider) trait and the
/// request/response dispatch that projects a data source onto the wire types.
pub mod service;
