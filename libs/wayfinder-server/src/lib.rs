//! The Wayfinder management-API server.
//!
//! The crate splits into three layers:
//!
//! * [`RouterAdapter`] — a `no_std` + `alloc` adapter that exposes a borrowed
//!   [`wayfinder::CentralRouter`] through the management-API
//!   [`WayfinderDataProvider`](wayfinder_protos::service::WayfinderDataProvider)
//!   trait. This is the part embedded callers can reuse without a runtime.
//! * the `std` transport layer (gated behind the `std` feature) — the
//!   authenticated TLS-over-TCP listener loop ([`bind_tcp_server`] /
//!   [`serve_tls_server`]), the in-process [`run_channel_server`], and the
//!   [`QueryTx`]/[`QueryRx`] channel they use to forward queries to a
//!   single-threaded router loop so the router is never shared across tasks.
//! * the embedded transport layer (gated behind the `embedded` feature,
//!   `no_std` + `alloc`) — length-delimited framing over an
//!   `embedded-io-async` byte stream (e.g. a UART), and the
//!   [`EmbeddedQueryTx`]/[`EmbeddedQueryRx`] `embassy-sync` channel + [`serve`]
//!   loop that play the same role as the `std` layer's listeners/channel.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

extern crate alloc;

mod adapter;
pub use adapter::RouterAdapter;
pub use adapter::RouterView;

/// Shared read access to the router, so a management read runs on the
/// connection's own task rather than on the driver's event loop.
#[cfg(feature = "std")]
mod router_handle;
#[cfg(feature = "std")]
pub use router_handle::RouterHandle;
#[cfg(feature = "std")]
pub use router_handle::SharedRouter;

/// The certificate authority's own executor: the task that owns a
/// [`CertAuthority`] so no management request runs on the router's event loop.
#[cfg(feature = "std")]
mod authority_task;
#[cfg(feature = "std")]
pub use authority_task::AuthorityAdapter;
#[cfg(feature = "std")]
pub use authority_task::AuthorityCommand;
#[cfg(feature = "std")]
pub use authority_task::AuthorityComms;
#[cfg(feature = "std")]
pub use authority_task::AuthorityPorts;
#[cfg(feature = "std")]
pub use authority_task::AuthorityRx;
#[cfg(feature = "std")]
pub use authority_task::AuthorityTx;
#[cfg(feature = "std")]
pub use authority_task::EnrollmentPolicyRx;
#[cfg(feature = "std")]
pub use authority_task::EnrollmentPolicyTx;
#[cfg(feature = "std")]
pub use authority_task::NOT_A_PROVIDER;
#[cfg(feature = "std")]
pub use authority_task::RevocationRx;
#[cfg(feature = "std")]
pub use authority_task::RevocationTx;
#[cfg(feature = "std")]
pub use authority_task::RouterFacts;
#[cfg(feature = "std")]
pub use authority_task::RouterFactsRx;
#[cfg(feature = "std")]
pub use authority_task::serve_authority;
pub use wayfinder_protos::service::not_a_provider_response;

/// VPN coordination against a Headscale server: the credential an enrolled
/// device is handed to join the tunnel, and the peer list/revocation an
/// operator manages it through.  `std` only — a tunnel daemon needs a real OS
/// network stack, so an embedded node never links this.
#[cfg(feature = "std")]
pub mod vpn;

mod authz;
pub use authz::MgmtAccess;
pub use authz::MgmtDenied;
pub use authz::authorize_capability;
pub use authz::decide_access;

#[cfg(feature = "embedded")]
mod framing;
#[cfg(feature = "embedded")]
pub use framing::FrameError;

/// The largest management *request* frame this node will read from a peer.
///
/// A remote peer supplies the 4-byte length prefix, so an unbounded value lets
/// it demand an arbitrarily large allocation — on the embedded transport from a
/// fixed heap, and on the host TLS transport from a process that is also
/// routing the mesh, before it has presented any credential at all (the
/// handshake authenticates a key, not an authorization).
///
/// 4 KiB comfortably covers every request: the largest is a `SetAuth` carrying
/// a seed, a certificate and a trust anchor. It also covers a routing-table
/// *response* on the node counts an embedded relay actually sees (dozens of
/// originators, a couple of paths each — a few hundred entries at ~20-50
/// encoded bytes apiece), which is why the embedded transport applies it in
/// both directions. The host transport does not: a host node's log page or
/// routing table runs well past this, and it is the peer's input, not the
/// node's own answer, that this bound exists to limit.
///
/// A caller sizing an embedded node's heap around this cap should budget for
/// **two** buffers at this size (`serve` keeps one in each direction) plus the
/// response `Vec`s a query itself builds — see `HEAP_SIZE_BYTES` in
/// `bins/wayfinder-nrf52840`.
pub const MAX_FRAME_LEN: usize = 4 * 1024;
#[cfg(feature = "embedded")]
pub use framing::read_frame;
#[cfg(feature = "embedded")]
pub use framing::write_frame;

#[cfg(feature = "embedded")]
mod embedded;
#[cfg(feature = "embedded")]
pub use embedded::EmbeddedQueryChannel;
#[cfg(feature = "embedded")]
pub use embedded::EmbeddedQueryRx;
#[cfg(feature = "embedded")]
pub use embedded::EmbeddedQueryTx;
#[cfg(feature = "embedded")]
pub use embedded::serve;

// Ungated: the account *store* inside is `std`-only, but the role it hands the
// `MeshAuthority` seam (`users::types`) has to compile wherever that trait does.
mod users;
#[cfg(feature = "std")]
pub use users::AuthOutcome;
#[cfg(feature = "std")]
pub use users::DEFAULT_SESSION_TTL_SECS;
#[cfg(feature = "std")]
pub use users::MAX_USERNAME_LEN;
#[cfg(feature = "std")]
pub use users::UserRecord;
pub use users::UserRole;

#[cfg(feature = "std")]
mod tls;
#[cfg(feature = "std")]
pub use tls::server_config;

mod provider;
pub use provider::MeshAuthority;

mod settings;
pub use settings::NodeIdentity;
pub use settings::NodeSettings;
#[cfg(feature = "std")]
pub use settings::SettingsFile;
pub use settings::SettingsStore;

#[cfg(feature = "std")]
mod persistence;

/// Whether the host's system clock is disciplined enough to make credential
/// decisions with — the gate that keeps a plausible-but-wrong clock from
/// minting or accepting dated credentials.
///
/// Lives in `wayfinder-clock-trust` so `wayfinder-client` can reach the *same*
/// verdict without depending on this crate (design 20 §4.6); re-exported here
/// so existing callers keep their path.
#[cfg(feature = "std")]
pub use wayfinder_clock_trust::ClockSync;
#[cfg(feature = "std")]
pub use wayfinder_clock_trust::ClockTrust;
#[cfg(feature = "std")]
pub use wayfinder_clock_trust::DEFAULT_MAX_CLOCK_ERROR_US;
/// Ask the host what it thinks of its own clock, under the given policy.
///
/// Re-exported under a qualified name because `read` alone says nothing at a
/// call site in another crate.
#[cfg(feature = "std")]
pub use wayfinder_clock_trust::read as clock_sync;
/// The host's wall clock in unix seconds, or zero if it reads before 2025.
///
/// The plausibility floor on its own, without the NTP trust gate — for the
/// router's certificate-validity clock, which must stay best-effort rather than
/// fail closed (see `Driver::refresh_auth_clock`). Exported so there is exactly
/// one definition of "plausible" across the crates that read the host clock.
#[cfg(feature = "std")]
pub fn host_unix_now() -> u64 {
    authority::plausible_or_zero(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_secs())
            .unwrap_or(0),
    )
}

#[cfg(feature = "std")]
mod authority;
#[cfg(feature = "std")]
pub use authority::CertAuthority;
#[cfg(feature = "std")]
pub use authority::Clock;
#[cfg(feature = "std")]
pub use authority::DEFAULT_INVITE_TTL_SECS;
#[cfg(feature = "std")]
pub use authority::InviteSummary;
#[cfg(feature = "std")]
pub use authority::MintedInvite;
#[cfg(feature = "std")]
pub use authority::StartedRegistration;

/// A mesh address, re-exported because this crate's public API is stated in
/// terms of it — [`decide_access`] takes one, [`AuthSnapshot`] carries one —
/// and a caller should not have to depend on `wayfinder` to name a type it is
/// handed here.
pub use wayfinder::interfaces::frame::Mac;

#[cfg(feature = "std")]
mod transport;
#[cfg(feature = "std")]
pub use transport::AuthContext;
#[cfg(feature = "std")]
pub use transport::AuthSnapshot;
#[cfg(feature = "std")]
pub use transport::AuthSnapshotRx;
#[cfg(feature = "std")]
pub use transport::AuthSnapshotTx;
#[cfg(feature = "std")]
pub use transport::ChannelRequest;
#[cfg(feature = "std")]
pub use transport::ChannelServerRx;
#[cfg(feature = "std")]
pub use transport::ChannelServerTx;
#[cfg(feature = "std")]
pub use transport::QueryRx;
#[cfg(feature = "std")]
pub use transport::QueryTx;
#[cfg(feature = "std")]
pub use transport::ServerServices;
#[cfg(feature = "std")]
pub use transport::bind_tcp_server;
#[cfg(feature = "std")]
pub use transport::run_channel_server;
#[cfg(feature = "std")]
pub use transport::serve_tls_server;
#[cfg(feature = "std")]
pub use transport::serve_tls_server_with_vpn;
