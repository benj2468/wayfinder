//! Central router orchestration for the wayfinder mesh.
//!
//! [`CentralRouter`] wraps the [`batman`] routing engine with an ident table, a
//! per-(neighbor, interface) link-quality table, opt-in OGM authentication
//! ([`auth`]), and the observability counters and estimators surfaced through
//! the management API. It is the single object driven by both an embedded node
//! and the host driver: it demuxes received frames by protocol, paces periodic
//! OGM emission, and plans unicast, multicast, and broadcast egress. The mesh
//! interface it speaks to is the [`link::LinkT`] trait. The crate is `no_std`
//! (host-only helpers are gated behind the `std`/`alloc` features).
#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

#[cfg(feature = "alloc")]
extern crate alloc;

pub use batman;
pub use interfaces;
pub use wayfinder_auth;

use batman::{
    BatmanEngine,
    wire::{
        BATADV_BCAST, BATADV_CERT_REPLY, BATADV_CERT_REQ, BATADV_IV_OGM, BATADV_KEEPALIVE,
        BATADV_MCAST, BATADV_UNICAST, BatmanBroadcastPacket, BatmanCertReplyPacket,
        BatmanCertReqPacket, BatmanMcastPacket, BatmanUnicastPacket, ETH_P_BATMAN,
    },
};
use core::time::Duration;
use interfaces::{
    engine::{MeshRoutingEngine, RoutingAction},
    frame::{LinkFrame, LinkFrameData, LinkFrameDataMut, Mac},
    link::LinkMetrics,
};
use tracing::{debug, info, trace, warn};
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    auth::OgmAuth,
    link_quality::{LinkQualityTable, normalize_quality},
    routing_table::IdentTable,
};

pub use crate::link_quality::LinkQualityRecord;

/// Per-link Trickle configuration ([`config::LinkConfig`]) so links with
/// different speeds back off OGM emission on independent schedules.
#[cfg(feature = "alloc")]
pub mod config;

pub mod auth;
/// Per-link participation features ([`features::LinkFeatures`]), in the
/// allocation-free core so the router can gate traffic on every deployment.
pub mod features;
pub mod link;

mod link_quality;
mod routing_table;

/// EtherType demuxed to the BATMAN engine by
/// [`handle_frame_with_metrics`](CentralRouter::handle_frame_with_metrics).
pub const DEFAULT_BATMAN_ETHER_TYPE: u16 = 0x4305;

/// Maximum number of interested listeners for which a multicast frame is sent
/// as individual unicasts before falling back to flooding, matching the spirit
/// of batman-adv's multicast fanout limit.  Beyond this count, flooding is
/// cheaper than many point-to-point copies.
pub const MCAST_FANOUT: usize = 16;

/// Error returned by [`CentralRouter::handle_local`] and
/// [`CentralRouter::handle_local_mcast`] when the frame cannot be sent onto the
/// mesh.  No bytes are written to the caller's `tx_buf` when either variant is
/// returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalSendError {
    /// The packet header plus the caller's payload do not fit in the supplied
    /// transmit buffer. The caller should retry with a larger `tx_buf` (or
    /// drop the frame).
    BufferTooSmall,
    /// The router is [`auth_locked`](CentralRouter::auth_locked): `require_auth`
    /// is set and no valid membership cert is installed yet, so the router
    /// must not originate any mesh traffic. The frame is dropped; install a
    /// valid cert via [`set_auth`](CentralRouter::set_auth) to unlock.
    AuthLocked,
}

/// Maximum number of mesh interfaces for which the router keeps independent
/// throughput estimates.  Interfaces are addressed by their registration index
/// (the same `iface_idx` used by the link-quality and OGM-schedule tables);
/// frames on an index at or beyond this bound are still routed correctly but
/// are not measured.  Sized generously for the small radio meshes this targets.
///
/// Defined as [`batman::MAX_INTERFACES`] rather than a separate literal so the
/// throughput-tracking bound cannot silently drift away from the bound the
/// BATMAN engine uses to pace OGM emission: an interface index the engine
/// schedules an OGM for must be one this router also measures, and vice versa.
pub const MAX_INTERFACES: usize = batman::MAX_INTERFACES;

/// Floor a configured keep-alive interval is clamped to
/// ([`CentralRouter::configure_interface_keepalive`]) rather than left
/// arbitrarily close to zero. Chosen well below any realistic operator-chosen
/// cadence (the default is 5s) so it only bites a degenerate/typo'd config
/// value, not a legitimately fast one.
pub const MIN_KEEPALIVE_INTERVAL: core::time::Duration = core::time::Duration::from_millis(100);

/// Capacity of the BATMAN originator (routing) table.  Must be a power of two
/// (a `heapless` map requirement) and is also the bound on the broadcast-dedup
/// table; 128 leaves headroom over a typical mesh.  Exposed so the management
/// API can report how close the table is to saturation.
pub const ORIGINATOR_CAPACITY: usize = 128;

/// Time constant of the throughput EWMA, in seconds.  An idle interface's
/// estimated rate decays to ~37% of its prior value over this window, so it is
/// the rough "memory" of the smoothed rate: long enough to ride out the gaps
/// between bursty mesh frames, short enough to track real changes within a few
/// seconds.
const RATE_TAU_SECS: f64 = 5.0;

/// A time-decayed (EWMA) estimate of one interface/direction's throughput,
/// rather than a cumulative counter: a node that runs for weeks reports a
/// bounded, here-and-now rate with no ever-growing total to age out.
///
/// Updates are event-driven — one [`observe`](RateEstimator::observe) per frame,
/// stamped with the loop's monotonic `now` — and the smoothed value also decays
/// toward zero as that `now` advances without traffic, so [`rate`](
/// RateEstimator::rate) reads a *current* estimate even while idle.  All state
/// lives in the `no_std` routing core so an embedded node that drives the
/// [`CentralRouter`] directly produces the same statistics with no host-side
/// tally to keep.
#[derive(Debug, Clone, Copy, Default)]
struct RateEstimator {
    /// Smoothed rate in bytes/sec, as of `last`.
    bps: f64,
    /// Smoothed rate in frames/sec, as of `last`.
    fps: f64,
    /// Bytes observed at the `last` instant but not yet folded into the EWMA
    /// (multiple frames can share one loop `now`); folded once time advances.
    pending_bytes: u64,
    /// Frames observed at the `last` instant, awaiting the same fold.
    pending_frames: u64,
    /// Instant of the current pending bucket, or `None` before the first frame.
    last: Option<Duration>,
}

impl RateEstimator {
    /// Fold `bytes` of one frame observed at `now` into the estimate.
    ///
    /// Frames sharing a single `now` (e.g. a flood fanned out in one loop pass)
    /// accumulate into a pending bucket; the bucket is converted to an
    /// instantaneous rate and blended in only once `now` advances, so a
    /// zero-length interval never divides by zero.
    fn observe(&mut self, now: Duration, bytes: usize) {
        match self.last {
            None => {
                self.last = Some(now);
                self.pending_bytes = bytes as u64;
                self.pending_frames = 1;
            }
            // Same (or, defensively, earlier) instant: keep accumulating.
            Some(prev) if now <= prev => {
                self.pending_bytes = self.pending_bytes.saturating_add(bytes as u64);
                self.pending_frames = self.pending_frames.saturating_add(1);
            }
            Some(prev) => {
                let dt = (now - prev).as_secs_f64();
                self.blend(dt);
                self.last = Some(now);
                self.pending_bytes = bytes as u64;
                self.pending_frames = 1;
            }
        }
    }

    /// Blend the pending bucket, spread over a `dt`-second interval, into the
    /// EWMA using the time-aware weight `alpha = dt / (tau + dt)`.
    fn blend(&mut self, dt: f64) {
        if dt <= 0.0 {
            return;
        }
        let alpha = dt / (RATE_TAU_SECS + dt);
        let inst_bps = self.pending_bytes as f64 / dt;
        let inst_fps = self.pending_frames as f64 / dt;
        self.bps = self.bps * (1.0 - alpha) + inst_bps * alpha;
        self.fps = self.fps * (1.0 - alpha) + inst_fps * alpha;
    }

    /// The smoothed `(bytes/sec, frames/sec)` as of `now`, without mutating the
    /// estimator: the pending bucket is folded over the elapsed interval so an
    /// interface that has gone quiet reads as a decaying — eventually
    /// near-zero — rate rather than a stale one.
    fn rate(&self, now: Duration) -> (f64, f64) {
        match self.last {
            None => (0.0, 0.0),
            Some(prev) => {
                let dt = now.saturating_sub(prev).as_secs_f64();
                if dt <= 0.0 {
                    return (self.bps, self.fps);
                }
                let alpha = dt / (RATE_TAU_SECS + dt);
                let inst_bps = self.pending_bytes as f64 / dt;
                let inst_fps = self.pending_frames as f64 / dt;
                (
                    self.bps * (1.0 - alpha) + inst_bps * alpha,
                    self.fps * (1.0 - alpha) + inst_fps * alpha,
                )
            }
        }
    }
}

/// A snapshot of one interface's smoothed throughput, evaluated at a caller-
/// supplied instant.  Rates rather than totals: bounded for an arbitrarily
/// long-lived node and directly displayable.  Produced by
/// [`CentralRouter::interface_throughput`].
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct InterfaceThroughput {
    /// Smoothed receive rate in bytes per second.
    pub rx_bps: f64,
    /// Smoothed receive rate in frames per second.
    pub rx_fps: f64,
    /// Smoothed transmit rate in bytes per second.
    pub tx_bps: f64,
    /// Smoothed transmit rate in frames per second.
    pub tx_fps: f64,
}

/// Wire length of a link frame carrying a `payload_len`-byte payload: the
/// Ethernet-shaped header `[dst: Mac][src: Mac][protocol: u16]` plus the
/// payload.  The receive path measures throughput in these whole-frame bytes so
/// it matches what the transmit side (which counts the bytes the link adapter
/// puts on the wire) reports.
fn link_frame_wire_len(payload_len: usize) -> usize {
    2 * core::mem::size_of::<Mac>() + core::mem::size_of::<u16>() + payload_len
}

/// How the router intends to deliver a multicast frame for a given group,
/// returned by [`CentralRouter::mcast_plan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McastPlan {
    /// Send an individual [`BATADV_MCAST`] packet to each interested
    /// originator — the set returned by [`CentralRouter::mcast_targets`].
    /// Chosen when at least one and at most [`MCAST_FANOUT`] listeners are
    /// known.
    Unicast,
    /// Flood the frame as a broadcast across the whole mesh.  Chosen when no
    /// listeners are known (membership may simply be unlearned) or when more
    /// than [`MCAST_FANOUT`] listeners make flooding cheaper than unicasting.
    Flood,
}

/// One neighbor's keep-alive liveness as of a caller-supplied instant,
/// returned by [`CentralRouter::keepalive_table`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepAliveEntry {
    /// The neighbor this entry describes.
    pub neighbor: Mac,
    /// Milliseconds elapsed since this neighbor's last heard heartbeat, as of
    /// the instant the table was read.
    pub ms_since_last_heard: u64,
    /// The learned heartbeat cadence, in milliseconds — zero until a second
    /// heartbeat has provided a real gap to measure (see
    /// `batman::KeepAliveStats::interval_estimate`).
    pub interval_estimate_ms: u64,
    /// Whether this neighbor has missed its keep-alive budget
    /// ([`BatmanEngine::keepalive_missed`](batman::BatmanEngine::keepalive_missed))
    /// — the signal [`next_hop`](batman::BatmanEngine::next_hop) deprioritizes
    /// a path relayed through this neighbor on, surfaced here so a degraded-
    /// but-not-yet-OGM-stale link is directly observable rather than only
    /// inferable from a route switching away.
    pub missed: bool,
}

/// The egress decision returned by [`CentralRouter::get_egress_interface`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressInterface {
    /// Send out every interface — used for broadcast destinations and for
    /// any destination the router has not yet observed.
    All,
    /// Send out a specific physical interface by its index.
    Interface(usize),
}

/// The two independent outputs produced by processing one received frame.
///
/// The split lifetimes are deliberate and are what let the router avoid
/// copying on the no-alloc path: a forwarded/re-flooded frame is built in the
/// caller's transmit scratchpad (`'tx`), while a locally-delivered frame is
/// borrowed straight out of the received frame (`'rx`).  Both, either, or
/// neither may be present for a given frame.
#[derive(Debug)]
pub struct RxOutcome<'rx, 'tx> {
    /// A frame to (re)transmit onto the mesh — a forwarded unicast, a
    /// re-flooded broadcast, or an OGM reply.  Dispatch it via
    /// [`CentralRouter::get_egress_interface`].  Borrows the transmit buffer.
    pub forward: Option<LinkFrameData<'tx>>,
    /// The inner payload to hand up to the local host (write it to the TAP),
    /// present when a packet reached its final local destination.  Borrows
    /// the received frame.
    pub deliver_local: Option<&'rx [u8]>,
}

impl RxOutcome<'_, '_> {
    /// An outcome that neither forwards nor delivers anything — the result of
    /// a consumed control packet or a dropped frame.
    fn empty() -> Self {
        Self {
            forward: None,
            deliver_local: None,
        }
    }
}

/// The central mesh router: it wraps the [`BatmanEngine`] with an ident table,
/// a per-(neighbor, interface) link-quality table, opt-in OGM authentication,
/// and the observability counters/estimators. It demuxes received frames by
/// protocol, drives periodic OGM emission, and plans unicast/multicast/broadcast
/// egress — the single object both the embedded node and the host driver own.
pub struct CentralRouter {
    /// The Batman routing engine for this router.  Its originator capacity is
    /// [`ORIGINATOR_CAPACITY`] — a power of two, as the `heapless` map requires.
    batman: BatmanEngine<ORIGINATOR_CAPACITY>,
    ident_table: IdentTable<Mac>,
    link_quality: LinkQualityTable<Mac>,
    /// Per-interface receive-rate estimators, indexed by interface registration
    /// order (`iface_idx`).  See [`RateEstimator`].
    rx_rates: [RateEstimator; MAX_INTERFACES],
    /// Per-interface transmit-rate estimators, indexed by interface
    /// registration order (`iface_idx`).
    tx_rates: [RateEstimator; MAX_INTERFACES],
    /// Number of interfaces actually in use — the count of distinct indices the
    /// router has seen configured or carrying traffic, capped at
    /// [`MAX_INTERFACES`].  Bounds the slice [`interface_throughput`] reports so
    /// consumers don't see a tail of never-touched interfaces.
    ///
    /// [`interface_throughput`]: CentralRouter::interface_throughput
    iface_count: usize,
    /// Opt-in OGM authentication state.  `None` (the default) leaves the router
    /// in its open, pre-auth behavior.  When `Some`, the router signs the OGMs
    /// it emits and drops incoming OGMs that do not verify against the mesh
    /// trust anchor — segregating this mesh from others sharing the medium.
    auth: Option<OgmAuth>,
    /// Fail-closed policy: when `true`, this node must not act as a mesh router
    /// (process, forward, deliver, or originate any mesh traffic) until a valid
    /// membership cert is installed via [`set_auth`](CentralRouter::set_auth).
    /// `false` (the default) preserves the historical behavior where a node
    /// with no cert yet still routes in the open, unauthenticated mode. See
    /// [`auth_locked`](CentralRouter::auth_locked).
    require_auth: bool,
    /// Lazy cert distribution: when `true`, [`poll`](CentralRouter::poll)
    /// emits an OGM cert fingerprint instead of the full cert (see
    /// [`OgmAuth::augment_ogm_lazy`]). `false` (the default) preserves
    /// today's behavior. Set from
    /// [`Config::lazy_cert_distribution`](crate::config::Config::lazy_cert_distribution)
    /// via [`set_lazy_cert_distribution`](CentralRouter::set_lazy_cert_distribution).
    /// Receiving already tolerates both wire forms unconditionally (see
    /// [`OgmAuth::verify_ogm`]); only what this node *emits* is gated.
    lazy_cert_distribution: bool,
    /// Count of locally originated host frames dropped because they did not fit
    /// in the transmit buffer once wrapped in mesh encapsulation — i.e. the host
    /// sent a frame larger than the mesh can carry (a misconfigured MTU).  A
    /// bounded, here-and-now signal an operator can query; the first such drop
    /// also logs a single `warn!` so it is not entirely silent.
    oversize_drops: u32,
    /// Whether this node currently has a runtime configuration override
    /// successfully applied (via [`apply_runtime_trickle_config`](CentralRouter::apply_runtime_trickle_config)
    /// or any future method that installs one), as opposed to running purely
    /// off its startup configuration. Only ever set on a successful
    /// application, never on a rejected one. Sticky: once set, stays set for
    /// the life of the process. See [`runtime_config_active`](CentralRouter::runtime_config_active).
    runtime_config_active: bool,
    /// Smoothed rate at which this node sends `CertReq` (lazy-cert-
    /// distribution fetches, as a requester with an unresolved fingerprint).
    /// Frames-per-second only (no byte size to a control packet is tracked
    /// here); see [`RateEstimator`].
    cert_req_tx_rate: RateEstimator,
    /// Smoothed rate at which this node sends `CertReply` (answering a
    /// `CertReq`, as the originator whose cert was asked for) — either
    /// immediately or via the opportunistic parked-reply flush.
    cert_reply_tx_rate: RateEstimator,
    /// Per-interface participation features, indexed by interface registration
    /// order (`iface_idx`).  Gates which traffic classes this node sends and
    /// receives on each link: an OGM/broadcast/unicast is dropped on ingress or
    /// suppressed on egress when the corresponding [`LinkFeatures`] flag is off.
    /// Defaults to full participation ([`LinkFeatures::default`]) for every
    /// interface, so an unconfigured link behaves exactly as before.
    ///
    /// [`LinkFeatures`]: crate::features::LinkFeatures
    link_features: [crate::features::LinkFeatures; MAX_INTERFACES],
}

impl CentralRouter {
    /// Create a router for the node with address `self_ident`, with an empty
    /// routing engine, link-quality table, rate estimators, and authentication
    /// disabled.
    pub fn new(self_ident: Mac) -> Self {
        Self {
            batman: BatmanEngine::new(self_ident),
            ident_table: IdentTable::new(),
            link_quality: LinkQualityTable::new(),
            rx_rates: [RateEstimator::default(); MAX_INTERFACES],
            tx_rates: [RateEstimator::default(); MAX_INTERFACES],
            iface_count: 0,
            auth: None,
            require_auth: false,
            lazy_cert_distribution: false,
            oversize_drops: 0,
            runtime_config_active: false,
            cert_req_tx_rate: RateEstimator::default(),
            cert_reply_tx_rate: RateEstimator::default(),
            link_features: [crate::features::LinkFeatures::default(); MAX_INTERFACES],
        }
    }

    /// Set the per-link participation [`features`](crate::features::LinkFeatures)
    /// for interface `idx` (from that link's `features:` config), and register
    /// the interface so its throughput is reported from startup.  Out-of-range
    /// indices (`>= `[`MAX_INTERFACES`]) are ignored.  Call once per interface
    /// at driver wiring time; the default for an unconfigured interface is full
    /// participation, so a link that never calls this behaves exactly as before.
    pub fn set_link_features(&mut self, idx: usize, features: crate::features::LinkFeatures) {
        if idx < MAX_INTERFACES {
            self.link_features[idx] = features;
            self.touch_iface(idx);
        }
    }

    /// The participation features configured for interface `idx` — full
    /// participation ([`LinkFeatures::default`](crate::features::LinkFeatures)) for
    /// an unconfigured or out-of-range index.
    pub fn link_features(&self, idx: usize) -> crate::features::LinkFeatures {
        self.link_features.get(idx).copied().unwrap_or_default()
    }

    /// Whether interface `idx`'s features permit **transmitting** an outgoing
    /// BATMAN frame whose sub-type is `packet_type` (its leading payload byte)
    /// onto it.  OGM re-floods require [`tx_ogm`]; data-plane frames (flooded
    /// broadcasts and directed unicast/multicast) require [`tx_data`]; any other
    /// sub-type (notably the lazy-cert control packets, which carry their own
    /// signature) is always permitted.  The driver's egress fan-out consults
    /// this per candidate interface so a partially participating link never puts
    /// a suppressed class on the wire.
    ///
    /// [`tx_ogm`]: crate::features::LinkFeatures::tx_ogm
    /// [`tx_data`]: crate::features::LinkFeatures::tx_data
    pub fn link_may_tx(&self, idx: usize, packet_type: Option<u8>) -> bool {
        let f = self.link_features(idx);
        match packet_type {
            Some(BATADV_IV_OGM) => f.tx_ogm,
            Some(BATADV_BCAST) | Some(BATADV_UNICAST) | Some(BATADV_MCAST) => f.tx_data,
            _ => true,
        }
    }

    /// Smoothed frames/sec at which this node sends `CertReq` (lazy-cert-
    /// distribution fetches), evaluated as of `now`. A rising rate signals
    /// growing cert-cache churn or a misresolving fingerprint.
    pub fn cert_req_tx_rate(&self, now: Duration) -> f64 {
        self.cert_req_tx_rate.rate(now).1
    }

    /// Smoothed frames/sec at which this node sends `CertReply` (answering
    /// `CertReq`s as the requested originator), evaluated as of `now`. A
    /// rising rate signals this node is serving cert lookups for many peers.
    pub fn cert_reply_tx_rate(&self, now: Duration) -> f64 {
        self.cert_reply_tx_rate.rate(now).1
    }

    /// Number of locally originated host frames dropped because they exceeded
    /// the mesh's carrying capacity once encapsulated.  A non-zero value means
    /// the host MTU is set too high for the mesh links (see
    /// [`TapConfig::DEFAULT_MTU`](crate::config::TapConfig::DEFAULT_MTU)).
    pub fn oversize_drops(&self) -> u32 {
        self.oversize_drops
    }

    /// Number of relayed frames (OGM re-floods, broadcast re-floods, unicast/
    /// multicast relays) dropped because they didn't fit an egress link's
    /// buffer — i.e. this node received a frame on a link whose MTU is larger
    /// than another of its links.  Distinct from [`oversize_drops`], which
    /// only counts locally originated frames.
    ///
    /// [`oversize_drops`]: CentralRouter::oversize_drops
    pub fn relay_oversize_drops(&self) -> u32 {
        self.batman.relay_oversize_drops()
    }

    /// Record one oversize-drop of a local host frame.  Emits a single `warn!`
    /// on the first occurrence — enough for an operator to notice a bad MTU —
    /// then only bumps the counter, so a host looping oversize frames cannot
    /// flood the logs on this hot path.
    fn note_oversize_drop(&mut self) {
        if self.oversize_drops == 0 {
            warn!("dropping host frame too large to carry over the mesh; lower the TAP MTU");
        }
        self.oversize_drops = self.oversize_drops.saturating_add(1);
    }

    /// Enable opt-in mesh authentication with the given [`OgmAuth`] state: the
    /// router will sign its emitted OGMs and reject incoming OGMs that do not
    /// verify against the mesh trust anchor.  Without this the router stays in
    /// its open, unauthenticated mode.
    pub fn set_auth(&mut self, auth: OgmAuth) {
        debug!("updating auth state; resetting learned routing state");
        self.auth = Some(auth);
        // Routes, link-quality, ident mappings, and broadcast-dedup state were
        // all learned under the previous (or no) auth regime and are stale the
        // instant this node's identity/anchor changes — drop them so the node
        // re-converges cleanly under the new auth.  The engine reset also latches
        // a topology change, so the node re-announces promptly.
        self.batman.reset();
        self.ident_table.clear();
        self.link_quality.clear();
    }

    /// Borrow the OGM authentication state, if enabled — for the security view
    /// and for driver-side upkeep (refreshing the clock, recording revocations).
    pub fn auth(&self) -> Option<&OgmAuth> {
        self.auth.as_ref()
    }

    /// Mutably borrow the OGM authentication state, if enabled.
    pub fn auth_mut(&mut self) -> Option<&mut OgmAuth> {
        self.auth.as_mut()
    }

    /// Set the fail-closed policy: when `require` is `true` and no
    /// membership cert is installed yet, the router goes [`auth_locked`]
    /// (inert on the mesh) until [`set_auth`] installs one. Typically set once
    /// at startup from [`Config::require_auth`](crate::config::Config); calling
    /// it again with `false` un-gates a node that has no cert, restoring the
    /// open (pre-auth) behavior.
    ///
    /// [`auth_locked`]: CentralRouter::auth_locked
    /// [`set_auth`]: CentralRouter::set_auth
    pub fn set_require_auth(&mut self, require: bool) {
        self.require_auth = require;
    }

    /// Set the lazy-cert-distribution policy: when `true`,
    /// [`poll`](CentralRouter::poll) emits a cert fingerprint on this node's
    /// OGMs instead of the full cert. Typically set once at startup from
    /// [`Config::lazy_cert_distribution`](crate::config::Config::lazy_cert_distribution).
    /// A flag-day cutover — every node on the mesh must be upgraded (able to
    /// resolve fingerprints via fetch) before any node flips this to `true`.
    pub fn set_lazy_cert_distribution(&mut self, lazy: bool) {
        self.lazy_cert_distribution = lazy;
    }

    /// The [`set_lazy_cert_distribution`](Self::set_lazy_cert_distribution)
    /// counterpart for a *runtime* override (the management API's
    /// `SetConfig`), rather than startup wiring: applies the new policy and
    /// additionally marks [`runtime_config_active`](Self::runtime_config_active),
    /// mirroring [`apply_runtime_trickle_config`](Self::apply_runtime_trickle_config).
    /// Kept distinct from the plain setter so startup wiring (from
    /// [`Config::lazy_cert_distribution`](crate::config::Config::lazy_cert_distribution))
    /// never spuriously marks the node as running a runtime override.
    pub fn apply_runtime_lazy_cert_distribution(&mut self, lazy: bool) {
        self.lazy_cert_distribution = lazy;
        self.runtime_config_active = true;
    }

    /// Whether this node is required to authenticate but has no membership
    /// cert installed yet — the "inert until authorized" state. This is a
    /// presence/bootstrap gate only: `require_auth && self.auth.is_none()`.
    /// Once any cert is installed via [`set_auth`], the router stays unlocked
    /// for good — even once that cert later passively expires. Re-locking on
    /// cert expiry is a deliberate deferred follow-up, not implemented here.
    /// While locked, the router must not process, forward, deliver, or
    /// originate any mesh traffic (see [`handle_frame_with_metrics`],
    /// [`poll`], [`handle_local`], [`handle_local_mcast`]); provisioning still
    /// works out-of-band over the management API. Surfaced to operators as
    /// `NodeInfo.auth_locked` over the management API and shown on the TUI
    /// overview pane.
    ///
    /// [`set_auth`]: CentralRouter::set_auth
    /// [`handle_frame_with_metrics`]: CentralRouter::handle_frame_with_metrics
    /// [`poll`]: CentralRouter::poll
    /// [`handle_local`]: CentralRouter::handle_local
    /// [`handle_local_mcast`]: CentralRouter::handle_local_mcast
    pub fn auth_locked(&self) -> bool {
        self.require_auth && self.auth.is_none()
    }

    /// Ingest a signed revocation (the operator/management-API entry point for
    /// an emergency purge), returning whether it was newly recorded.  On a new
    /// record the engine's Trickle timers are reset so the carrying OGM floods
    /// promptly at `i_min` instead of waiting out the backed-off emission
    /// interval.  A no-op returning `false` when auth is disabled.
    pub fn ingest_revocation(
        &mut self,
        record: &wayfinder_auth::RevocationRecord,
        now: core::time::Duration,
    ) -> bool {
        let Some(auth) = self.auth.as_mut() else {
            return false;
        };
        let newly = auth.ingest_revocation(record);
        if auth.take_trickle_reset_hint() {
            info!(
                "ingested revocation; resetting timers, revoking originators, and purging stale OGMs"
            );
            self.batman.reset_ogm_timers(now);
            self.batman.revoke_originators(auth.revoked_macs());
            self.batman.purge_stale(now);
        }
        newly
    }
    /// Process a received link-layer frame without any physical-layer
    /// metrics — equivalent to calling [`handle_frame_with_metrics`] with
    /// [`LinkMetrics::default`].  Useful for tests and for links that
    /// cannot report per-frame signal information.
    ///
    /// [`handle_frame_with_metrics`]: CentralRouter::handle_frame_with_metrics
    pub fn handle_frame<'rx, 'tx>(
        &mut self,
        now: Duration,
        iface_idx: usize,
        frame: &'rx LinkFrame,
        tx_buf: &'tx mut [u8],
    ) -> RxOutcome<'rx, 'tx> {
        self.handle_frame_with_metrics(now, iface_idx, frame, LinkMetrics::default(), tx_buf)
    }

    /// Process a received link-layer frame, folding the radio's
    /// physical-layer metrics for `frame.src` into the per-(neighbor,
    /// interface) link-quality table.  The egress decision for that
    /// neighbor will be biased toward whichever interface accumulates the
    /// highest smoothed quality.
    ///
    /// Returns an [`RxOutcome`]: any frame to (re)transmit onto the mesh and
    /// any inner payload to deliver to the local host. Returns an empty
    /// `RxOutcome` immediately — before any link-quality/throughput
    /// accounting or protocol demux — when [`auth_locked`].
    ///
    /// [`auth_locked`]: CentralRouter::auth_locked
    pub fn handle_frame_with_metrics<'rx, 'tx>(
        &mut self,
        now: Duration,
        iface_idx: usize,
        frame: &'rx LinkFrame,
        metrics: LinkMetrics,
        tx_buf: &'tx mut [u8],
    ) -> RxOutcome<'rx, 'tx> {
        let src = frame.src;
        let dst = frame.dst;
        let protocol = frame.protocol.get();
        let span = tracing::trace_span!(
            "handle_frame",
            iface_idx,
            ?src,
            ?dst,
            protocol = %format_args!("0x{protocol:04x}"),
        );
        let _enter = span.enter();
        trace!(payload_len = frame.payload.len(), "rx frame");

        // Fail closed: `require_auth` is set and no valid membership cert is
        // installed yet, so this node must be fully inert on the mesh — drop
        // before any demux, routing-table update, or local delivery.
        // Provisioning (enroll/set-auth) happens out-of-band over the
        // management API and is unaffected.
        if self.auth_locked() {
            trace!("drop: auth locked (no membership cert)");
            return RxOutcome::empty();
        }

        tx_buf.fill(0);
        // 0. Update the link-quality table for the sender, keyed on the
        //    interface this frame arrived on.  Done before any further
        //    processing so even frames that the upper layers drop still
        //    contribute their signal information. (This no longer holds when
        //    `auth_locked()`: the fail-closed gate above already returned
        //    before this step runs.)
        let quality = normalize_quality(&metrics);
        self.link_quality.update(frame.src, iface_idx, quality);
        // The smoothed link quality to this neighbor, used to clamp any OGM's
        // advertised TQ so a node can't claim a path better than the link we
        // measure to it.  Only meaningful when the frame carried a real
        // physical measurement: metric-less transports (UDP/Unix/raw L2) report
        // `LinkMetrics::default`, which normalizes to 0 — clamping by that would
        // wrongly zero every TQ — so they apply no clamp at all.
        let measured =
            metrics.rssi_dbm.is_some() || metrics.snr_db.is_some() || metrics.quality.is_some();
        let local_quality = if measured {
            self.link_quality.quality_for(frame.src, iface_idx)
        } else {
            None
        };

        // 0b. Account the frame against this interface's ingress rate before any
        //     demux, so even frames the upper layers drop still register as
        //     received throughput on the wire. (Again, this no longer holds
        //     when `auth_locked()`: such frames never reach this point.)
        self.record_rx(iface_idx, link_frame_wire_len(frame.payload.len()), now);

        // 1. Add a record to the identifier table
        self.ident_table.add_record(iface_idx, frame.dst);
        // 2. Demux by Protocol ID
        match frame.protocol.get() {
            DEFAULT_BATMAN_ETHER_TYPE => {
                // Per-link receive gating: drop a traffic class this link is
                // configured not to accept before it can touch the routing
                // tables, be delivered, or generate a re-flood.  The rx-rate
                // and link-quality above already counted the frame as observed
                // on the wire, matching how other upper-layer drops behave.
                // Cert-control packets (CertReq/CertReply) fall through the
                // arms below and are never gated here — the auth control plane
                // must keep flowing regardless of data/routing gates.
                let features = self.link_features(iface_idx);
                match frame.payload.first() {
                    Some(&BATADV_IV_OGM) if !features.rx_ogm => {
                        trace!("drop: rx_ogm disabled on this link");
                        return RxOutcome::empty();
                    }
                    Some(&BATADV_BCAST) | Some(&BATADV_UNICAST) | Some(&BATADV_MCAST)
                        if !features.rx_data =>
                    {
                        trace!("drop: rx_data disabled on this link");
                        return RxOutcome::empty();
                    }
                    _ => {}
                }

                // Opt-in control-plane segregation: when auth is enabled, an OGM
                // that does not verify against our trust anchor is dropped before
                // it can touch the routing table.  Only OGMs are gated here (the
                // one-to-many control plane).  Data-plane frames (BCAST/UNICAST/
                // MCAST) are NOT authenticated yet — an outsider can still inject
                // them until the pairwise data-plane tag lands; see auth.rs scope.
                if frame.payload.first() == Some(&BATADV_IV_OGM)
                    && let Some(auth) = self.auth.as_mut()
                {
                    match auth.verify_ogm(&frame.payload) {
                        auth::OgmVerdict::Verified => {}
                        auth::OgmVerdict::Rejected => {
                            return RxOutcome {
                                forward: None,
                                deliver_local: None,
                            };
                        }
                        auth::OgmVerdict::NeedCert { orig, fp } => {
                            // We have no route to `orig` yet — `verify_ogm`
                            // gates before the engine sees this OGM, so
                            // nothing installed one. Seed the first hop with
                            // the OGM's actual link source (`frame.src`),
                            // which by construction has a route to `orig`
                            // (it just relayed/originated this OGM). This
                            // copy is dropped either way; the next emission
                            // after the fetch resolves verifies normally.
                            let hdr_len = core::mem::size_of::<BatmanCertReqPacket>();
                            let forward = if hdr_len <= tx_buf.len()
                                && let Some(body_len) = auth.build_cert_request(
                                    orig,
                                    fp,
                                    frame.src,
                                    &mut tx_buf[hdr_len..],
                                ) {
                                let req_hdr = BatmanCertReqPacket {
                                    packet_type: BATADV_CERT_REQ,
                                    version: 5,
                                    ttl: 50,
                                    dest: orig,
                                };
                                tx_buf[..hdr_len].copy_from_slice(req_hdr.as_bytes());
                                self.cert_req_tx_rate.observe(now, 0);
                                Some(LinkFrameData {
                                    dst: frame.src,
                                    protocol: ETH_P_BATMAN,
                                    payload: &tx_buf[..hdr_len + body_len],
                                })
                            } else {
                                None
                            };
                            return RxOutcome {
                                forward,
                                deliver_local: None,
                            };
                        }
                    }
                }

                // Opt-in control-plane segregation for keep-alives too: when
                // auth is enabled, a keep-alive whose signature does not
                // verify against the sender's cached cert (from a previously
                // verified OGM) is dropped before it can touch the engine's
                // liveness table. Without this, an unauthenticated keep-alive
                // let any on-link party bias route selection away from a
                // spoofed victim neighbor without holding a membership cert —
                // the same segregation guarantee OGMs already get.
                if frame.payload.first() == Some(&BATADV_KEEPALIVE)
                    && let Some(auth) = self.auth.as_mut()
                    && !auth.verify_keepalive(frame.src, &frame.payload)
                {
                    return RxOutcome {
                        forward: None,
                        deliver_local: None,
                    };
                }

                // If verifying that OGM folded in a *new* revocation, snap the
                // Trickle timers to i_min so this node re-floods the purge
                // promptly rather than at its backed-off emission interval.
                if let Some(auth) = self.auth.as_mut()
                    && auth.take_trickle_reset_hint()
                {
                    self.batman.reset_ogm_timers(now);
                    self.batman.revoke_originators(auth.revoked_macs());
                    self.batman.purge_stale(now);
                }

                let mut reply: LinkFrameDataMut<'_> = tx_buf.into();

                // BATMAN-adv Protocol ID
                let action = self.batman.handle_rx(now, frame, local_quality, &mut reply);
                trace!(
                    reply_dst = ?reply.dst,
                    reply_protocol = %format_args!("0x{:04x}", reply.protocol),
                    "post-action reply"
                );
                match action {
                    RoutingAction::Consumed => {
                        // Trim the payload to the incoming frame size so that
                        // trailing zeros from the scratchpad buffer are not
                        // forwarded on the wire.
                        let forward = if reply.protocol != 0 {
                            // A re-flood of an OGM *is* advertising its originator
                            // as reachable through us. Suppress it when the OGM
                            // arrived on a link we can't send data onto
                            // (`tx_data` off): we could never deliver to that
                            // originator, so advertising a route to it would
                            // black-hole any peer that then routed through us.
                            // The engine has already learned it into our local
                            // table (surfaced via the management API); we simply
                            // don't propagate it. See
                            // [`LinkFeatures::tx_data`](crate::features::LinkFeatures::tx_data).
                            if frame.payload.first() == Some(&BATADV_IV_OGM)
                                && !self.link_features(iface_idx).tx_data
                            {
                                trace!(
                                    "drop: not re-advertising an OGM learned on a tx_data-off link"
                                );
                                None
                            } else {
                                let len = frame.payload.len().min(reply.payload.len());
                                Some(LinkFrameData {
                                    dst: reply.dst,
                                    protocol: reply.protocol,
                                    payload: &reply.payload[..len],
                                })
                            }
                        } else if frame.payload.first() == Some(&BATADV_IV_OGM)
                            && let Ok((ogm, _)) =
                                batman::wire::BatmanOgmPacket::ref_from_prefix(&frame.payload)
                            && let Some(auth) = self.auth.as_mut()
                        {
                            // This OGM itself needed no re-flood (the common
                            // case), leaving the forward slot free.
                            // Opportunistically flush a pending `CertReply`
                            // for its originator, now that verifying it
                            // (re)confirms a route back to them (design doc
                            // §3.3/§5.4). A genuine re-flood always wins the
                            // slot; a skipped flush here is not a
                            // correctness issue — the requester's own retry
                            // (`OgmAuth::build_cert_request`) is the
                            // backstop.
                            let flushed = Self::try_flush_pending_cert_reply(
                                auth,
                                &self.batman,
                                now,
                                ogm.orig,
                                &mut reply,
                            );
                            if flushed.is_some() {
                                self.cert_reply_tx_rate.observe(now, 0);
                            }
                            flushed.map(|(next, total)| LinkFrameData {
                                dst: next,
                                protocol: ETH_P_BATMAN,
                                payload: &reply.payload[..total],
                            })
                        } else {
                            None
                        };
                        RxOutcome {
                            forward,
                            deliver_local: None,
                        }
                    }
                    RoutingAction::ForwardTo(next_hop) => {
                        // BATMAN told us this packet needs to keep moving.
                        // Re-transmit it out to the designated next-hop neighbor.
                        let len = frame.payload.len().min(reply.payload.len());
                        reply.payload[..len].copy_from_slice(&frame.payload[..len]);
                        RxOutcome {
                            forward: Some(LinkFrameData {
                                dst: next_hop,
                                protocol: DEFAULT_BATMAN_ETHER_TYPE,
                                payload: &reply.payload[..len],
                            }),
                            deliver_local: None,
                        }
                    }
                    RoutingAction::DeliverLocal => match frame.payload.first() {
                        Some(&BATADV_CERT_REPLY) => {
                            // Terminates in our own auth state, never the
                            // host TAP: verify against the trust anchor,
                            // confirm it answers an outstanding request, and
                            // cache it.
                            if let Some(auth) = self.auth.as_mut() {
                                let body = frame
                                    .payload
                                    .get(Self::inner_offset(&frame.payload)..)
                                    .unwrap_or(&[]);
                                auth.ingest_cert_reply(body);
                            }
                            RxOutcome::empty()
                        }
                        Some(&BATADV_CERT_REQ) => {
                            // Terminates here: this node is the originator
                            // whose cert was requested (the terminal-only
                            // responder — an intermediate holder answering
                            // early is a deferred optimization). Verify the
                            // requester's self-authenticating body, then
                            // either answer immediately (a route exists) or
                            // park it for the opportunistic flush above.
                            let body = frame
                                .payload
                                .get(Self::inner_offset(&frame.payload)..)
                                .unwrap_or(&[]);
                            let requester = self
                                .auth
                                .as_mut()
                                .and_then(|auth| auth.verify_cert_request(body));
                            let Some(requester) = requester else {
                                return RxOutcome::empty();
                            };

                            let hdr_len = core::mem::size_of::<BatmanCertReplyPacket>();
                            #[expect(
                                clippy::expect_used,
                                reason = "requester came from self.auth.verify_cert_request, so auth must still be Some"
                            )]
                            let own_cert = *self
                                .auth
                                .as_ref()
                                .expect("auth present: requester was just verified through it")
                                .own_cert();
                            let cert_bytes = own_cert.as_bytes();
                            let total = hdr_len + cert_bytes.len();

                            match self.batman.next_hop(now, requester) {
                                Some(next) if total <= reply.payload.len() => {
                                    let reply_hdr = BatmanCertReplyPacket {
                                        packet_type: BATADV_CERT_REPLY,
                                        version: 5,
                                        ttl: 50,
                                        dest: requester,
                                    };
                                    reply.payload[..hdr_len].copy_from_slice(reply_hdr.as_bytes());
                                    reply.payload[hdr_len..total].copy_from_slice(cert_bytes);
                                    self.cert_reply_tx_rate.observe(now, 0);
                                    return RxOutcome {
                                        forward: Some(LinkFrameData {
                                            dst: next,
                                            protocol: ETH_P_BATMAN,
                                            payload: &reply.payload[..total],
                                        }),
                                        deliver_local: None,
                                    };
                                }
                                Some(_) => {
                                    // A route exists, but the reply doesn't
                                    // fit the transmit buffer — a local MTU
                                    // misconfiguration (own cert + header is
                                    // a fixed ~165 bytes), not "no route
                                    // yet". Parking it wouldn't help (the
                                    // opportunistic flush hits the same
                                    // buffer), but the requester's own retry
                                    // is a harmless no-op backstop either
                                    // way, so park it anyway rather than add
                                    // a second silent-drop path.
                                    debug!(
                                        total,
                                        buf_len = reply.payload.len(),
                                        "auth: cert reply does not fit the transmit buffer"
                                    );
                                }
                                None => {
                                    trace!(?requester, "auth: no route to cert requester yet");
                                }
                            }
                            // Park it for the opportunistic flush once
                            // verifying one of the requester's OGMs confirms
                            // a route back.
                            if let Some(auth) = self.auth.as_mut() {
                                auth.park_pending_reply(requester);
                            }
                            RxOutcome::empty()
                        }
                        _ => {
                            // Hand the inner frame up to the local host, stripping
                            // the BATMAN header that carried it here.
                            RxOutcome {
                                forward: None,
                                deliver_local: frame
                                    .payload
                                    .get(Self::inner_offset(&frame.payload)..),
                            }
                        }
                    },
                    RoutingAction::DeliverLocalAndForward(_next) => {
                        // A fresh broadcast: deliver the inner frame locally
                        // *and* propagate the re-flood the engine wrote into
                        // `reply` (TTL decremented, addressed to BROADCAST).
                        let forward = if reply.protocol != 0 {
                            let len = frame.payload.len().min(reply.payload.len());
                            Some(LinkFrameData {
                                dst: reply.dst,
                                protocol: reply.protocol,
                                payload: &reply.payload[..len],
                            })
                        } else {
                            None
                        };
                        RxOutcome {
                            forward,
                            deliver_local: frame.payload.get(Self::inner_offset(&frame.payload)..),
                        }
                    }
                }
            }
            0x88B5 => {
                trace!("rx experimental protocol frame");
                // Dynamically route to a completely separate experimental protocol context
                RxOutcome::empty()
            }
            _ => {
                trace!(protocol = %format_args!("0x{protocol:04x}"), "drop: unknown protocol");
                RxOutcome::empty()
            }
        }
    }

    /// Byte offset of the inner (host) payload within a BATMAN packet payload,
    /// i.e. the size of the BATMAN header that must be stripped before local
    /// delivery.  Determined from the packet sub-type byte; unknown types are
    /// delivered whole (offset 0).
    fn inner_offset(payload: &[u8]) -> usize {
        match payload.first() {
            Some(&BATADV_UNICAST) => core::mem::size_of::<BatmanUnicastPacket>(),
            Some(&BATADV_MCAST) => core::mem::size_of::<BatmanMcastPacket>(),
            Some(&BATADV_BCAST) => core::mem::size_of::<BatmanBroadcastPacket>(),
            Some(&BATADV_CERT_REQ) => core::mem::size_of::<BatmanCertReqPacket>(),
            Some(&BATADV_CERT_REPLY) => core::mem::size_of::<BatmanCertReplyPacket>(),
            _ => 0,
        }
    }

    /// After an OGM that itself needed no re-flood, opportunistically flush
    /// a parked pending `CertReply` for that OGM's originator (`orig`), now
    /// that verifying it (re)confirms a route back to them (design doc
    /// §3.3/§5.4). Builds the reply — this node's own cert, since a pending
    /// reply is only ever parked for *this* node's own cert request (the
    /// terminal-only responder; see [`OgmAuth::verify_cert_request`]) —
    /// into `reply`'s scratch buffer and clears the pending entry only on
    /// full success (route resolved and the buffer had room), so a failed
    /// attempt leaves the entry parked for the next opportunity. Returns the
    /// next hop and the written length; the caller (which owns `reply`
    /// directly) builds the final borrowed [`LinkFrameData`] from it, since
    /// that borrow cannot outlive this function's own `&mut` parameter.
    fn try_flush_pending_cert_reply(
        auth: &mut auth::OgmAuth,
        batman: &BatmanEngine<ORIGINATOR_CAPACITY>,
        now: Duration,
        orig: Mac,
        reply: &mut LinkFrameDataMut<'_>,
    ) -> Option<(Mac, usize)> {
        if !auth.has_pending_reply(orig) {
            return None;
        }
        let next = batman.next_hop(now, orig)?;
        let cert = *auth.own_cert();
        let cert_bytes = cert.as_bytes();
        let hdr_len = core::mem::size_of::<BatmanCertReplyPacket>();
        let total = hdr_len + cert_bytes.len();
        if total > reply.payload.len() {
            return None;
        }
        let hdr = BatmanCertReplyPacket {
            packet_type: BATADV_CERT_REPLY,
            version: 5,
            ttl: 50,
            dest: orig,
        };
        reply.payload[..hdr_len].copy_from_slice(hdr.as_bytes());
        reply.payload[hdr_len..total].copy_from_slice(cert_bytes);
        reply.dst = next;
        reply.protocol = ETH_P_BATMAN;
        auth.clear_pending_reply(orig);
        Some((next, total))
    }

    /// Decide how to deliver a multicast frame for `group`: as individual
    /// unicasts to each known listener (when 1..=[`MCAST_FANOUT`] are known)
    /// or by flooding (no listeners known, or too many to be worth it).
    pub fn mcast_plan(&self, group: Mac) -> McastPlan {
        let count = self.batman.mcast_listeners(group).count();
        if (1..=MCAST_FANOUT).contains(&count) {
            McastPlan::Unicast
        } else {
            McastPlan::Flood
        }
    }

    /// The originators that have announced interest in `group` — the targets
    /// for [`McastPlan::Unicast`].  Borrows `self`; allocates nothing.
    pub fn mcast_targets(&self, group: Mac) -> impl Iterator<Item = Mac> + '_ {
        self.batman.mcast_listeners(group)
    }

    /// Set the multicast groups the local host listens to (typically from IGMP
    /// snooping).  They are announced to the mesh in this node's OGMs so other
    /// routers forward the corresponding multicast traffic toward us.
    pub fn set_local_mcast_groups(&mut self, groups: &[Mac]) {
        self.batman.set_local_mcast_groups(groups);
    }

    /// Wrap host data destined for the multicast listener `dest` in a
    /// [`BATADV_MCAST`] packet routed toward its best-known next hop.  Called
    /// once per target of a [`McastPlan::Unicast`].  Returns
    /// [`LocalSendError::BufferTooSmall`] if the header plus `payload` would
    /// not fit in `tx_buf`, or [`LocalSendError::AuthLocked`] while
    /// [`auth_locked`](CentralRouter::auth_locked).
    pub fn handle_local_mcast<'a>(
        &mut self,
        now: core::time::Duration,
        dest: Mac,
        payload: &[u8],
        tx_buf: &'a mut [u8],
    ) -> Result<LinkFrameData<'a>, LocalSendError> {
        if self.auth_locked() {
            trace!("drop: auth locked, suppressing local multicast egress");
            return Err(LocalSendError::AuthLocked);
        }
        let next_hop = self.batman.next_hop(now, dest).unwrap_or(dest);

        let header = BatmanMcastPacket {
            packet_type: BATADV_MCAST,
            version: 5,
            ttl: 50,
            dest,
        };
        let header_size = core::mem::size_of::<BatmanMcastPacket>();
        let total_size = header_size + payload.len();
        if total_size > tx_buf.len() {
            self.note_oversize_drop();
            return Err(LocalSendError::BufferTooSmall);
        }
        tx_buf[..header_size].copy_from_slice(header.as_bytes());
        tx_buf[header_size..total_size].copy_from_slice(payload);

        Ok(LinkFrameData {
            dst: next_hop,
            protocol: ETH_P_BATMAN,
            payload: &tx_buf[..total_size],
        })
    }

    /// Drive periodic router maintenance at time `now`, returning a
    /// Trickle-paced OGM broadcast to emit (built into `tx_buf`) when one is
    /// due, or `None` otherwise.  Called each tick of the executor loop.
    #[tracing::instrument(skip_all, level = "info")]
    pub fn poll<'tx>(
        &mut self,
        now: core::time::Duration,
        tx_buf: &'tx mut [u8],
    ) -> Option<LinkFrameData<'tx>> {
        // Fail closed: locked nodes originate nothing (total mesh silence)
        // until a valid membership cert is installed.
        if self.auth_locked() {
            trace!("drop: auth locked, suppressing OGM emission");
            return None;
        }
        // 3. Handle BATMAN outgoing maintenance ticks
        let broadcast = Mac::BROADCAST;
        // Take only the produced length so the borrow of `tx_buf` ends and we can
        // re-borrow it mutably to append the auth TVLVs below.
        let produced = self
            .batman
            .produce_periodic_broadcast(now, tx_buf)
            .map(|p| p.len());
        // The engine may just have purged neighbors that stopped refreshing
        // their routes; drop their link-quality rows too so an inspection API
        // (e.g. the management API's link-quality RPC) can never keep
        // reporting a neighbor the routing table has already forgotten.
        let batman = &self.batman;
        self.link_quality
            .retain_live(|neighbor| batman.originator_table.contains_key(&neighbor));
        if let Some(len) = produced {
            // When auth is enabled, append our cert (or, under lazy cert
            // distribution, just its fingerprint) + OGM signature so peers
            // can verify this OGM; the engine already wrote the base OGM
            // into tx_buf.
            let final_len = match self.auth.as_mut() {
                Some(auth) if self.lazy_cert_distribution => auth.augment_ogm_lazy(tx_buf, len),
                Some(auth) => auth.augment_ogm(tx_buf, len),
                None => Some(len),
            };
            let Some(final_len) = final_len else {
                // Augmentation failed (buffer too small for the cert/
                // fingerprint + signature, or `tvlv_len` would overflow).
                // Never fall back to broadcasting the un-augmented,
                // unsigned OGM the engine already wrote into `tx_buf`: an
                // auth-enabled peer would reject it, but an open node on a
                // mixed mesh would install a route to this node with zero
                // cryptographic backing — fail-open on exactly the guarantee
                // this feature exists to provide. Suppress this emission
                // instead; the next Trickle round retries.
                warn!(
                    "auth: dropping OGM emission — augmentation failed (buffer too small for the mesh MTU?)"
                );
                return None;
            };
            // Flood the OGM out of every radio interface to map the surrounding topology
            return Some(LinkFrameData {
                dst: broadcast,
                protocol: DEFAULT_BATMAN_ETHER_TYPE,
                payload: &tx_buf[..final_len],
            });
        }
        None
    }

    /// Build a keep-alive heartbeat to emit into `tx_buf`, or `None` if
    /// suppressed. No `now` needed to build the base heartbeat — a keep-alive
    /// carries no sequence number on the wire — but when auth is enabled the
    /// signed trailer's time bucket is drawn from the auth clock
    /// ([`OgmAuth::set_time`](auth::OgmAuth::set_time)), refreshed
    /// separately. Like [`poll`](Self::poll), a keep-alive is signed
    /// ([`OgmAuth::augment_keepalive`](auth::OgmAuth::augment_keepalive))
    /// when auth is on, verified by peers against the sender's cert cached
    /// from a prior OGM rather than a cert/fingerprint resent on every
    /// heartbeat.
    pub fn poll_keepalive<'tx>(&mut self, tx_buf: &'tx mut [u8]) -> Option<LinkFrameData<'tx>> {
        // Fail closed, same as `poll`: a locked node originates nothing.
        if self.auth_locked() {
            trace!("drop: auth locked, suppressing keep-alive emission");
            return None;
        }
        let Some(len) = self.batman.produce_keepalive(tx_buf).map(|p| p.len()) else {
            trace!("drop: tx buffer too small for keepalive header");
            return None;
        };
        let final_len = match self.auth.as_mut() {
            Some(auth) => {
                let Some(final_len) = auth.augment_keepalive(tx_buf, len) else {
                    // Never fall back to broadcasting the unsigned keep-alive:
                    // an auth-enabled peer would reject it, but a node that
                    // hasn't yet enabled auth would accept it as-is — the same
                    // fail-open risk `poll` avoids for OGMs.
                    warn!(
                        "auth: dropping keep-alive emission — signature augmentation failed (buffer too small?)"
                    );
                    return None;
                };
                final_len
            }
            None => len,
        };
        Some(LinkFrameData {
            dst: Mac::BROADCAST,
            protocol: DEFAULT_BATMAN_ETHER_TYPE,
            payload: &tx_buf[..final_len],
        })
    }

    /// Install (or replace) the adaptive OGM schedule for mesh interface `idx`,
    /// supplying that link's `i_min`/`i_max` at runtime.  Call once per interface
    /// when wiring up the driver; see
    /// [`BatmanEngine::configure_interface_ogm`](batman::BatmanEngine::configure_interface_ogm).
    pub fn configure_interface_ogm(
        &mut self,
        idx: usize,
        i_min: core::time::Duration,
        i_max: core::time::Duration,
        now: core::time::Duration,
    ) {
        self.batman.configure_interface_ogm(idx, i_min, i_max, now);
        // Register the interface so its throughput is reported from startup,
        // even before it has carried any traffic.
        self.touch_iface(idx);
    }

    /// Apply a runtime override of interface `idx`'s Trickle/OGM bounds,
    /// received over the management API (`SetConfig`) rather than at startup
    /// wiring. Unlike [`configure_interface_ogm`](CentralRouter::configure_interface_ogm),
    /// which is also used to *provision* new interfaces at startup, this only
    /// overrides an interface already registered by startup wiring: `idx` must
    /// be below [`num_interfaces`](CentralRouter::num_interfaces), else this
    /// returns `false` and leaves the router untouched — in particular it does
    /// *not* mark [`runtime_config_active`](CentralRouter::runtime_config_active),
    /// so that flag never lies about an override having taken effect. On
    /// success, like `configure_interface_ogm`, this replaces the interface's
    /// Trickle timer outright: any backoff already grown toward the old
    /// `i_max` is discarded and the interface resets to firing within
    /// `[i_min/2, i_min)` of `now` — expect a burst of OGMs shortly after
    /// calling this on a live interface.
    pub fn apply_runtime_trickle_config(
        &mut self,
        idx: usize,
        i_min: core::time::Duration,
        i_max: core::time::Duration,
        now: core::time::Duration,
    ) -> bool {
        if idx >= self.num_interfaces() {
            return false;
        }
        self.configure_interface_ogm(idx, i_min, i_max, now);
        self.runtime_config_active = true;
        true
    }

    /// Apply a runtime override of interface `idx`'s participation
    /// [`features`](crate::features::LinkFeatures), received over the management
    /// API (`SetConfig`) rather than at startup wiring.  Like
    /// [`apply_runtime_trickle_config`](Self::apply_runtime_trickle_config),
    /// this only overrides an interface already registered by startup wiring:
    /// `idx` must be below [`num_interfaces`](Self::num_interfaces), else it
    /// returns `false` and leaves the router untouched (in particular it does
    /// *not* mark [`runtime_config_active`](Self::runtime_config_active), so
    /// that flag never lies about an override having taken effect).  The new
    /// features take effect on the very next frame: the receive gates are read
    /// per-frame in [`handle_frame_with_metrics`](Self::handle_frame_with_metrics)
    /// and the transmit gates via [`link_may_tx`](Self::link_may_tx) on each
    /// dispatch, and OGM emission is governed by the always-armed timer plus the
    /// live `tx_ogm` check — so no timer needs re-arming when that flag flips.
    /// `tx_keepalive` is the one exception: it *is* re-armed/disarmed here
    /// against `now`, since (unlike `tx_ogm`) its timer only exists at all
    /// while a schedule is configured.
    ///
    /// `features` is a full replacement; a caller wanting to flip a single flag
    /// merges its change onto [`link_features(idx)`](Self::link_features) first.
    pub fn apply_runtime_link_features(
        &mut self,
        idx: usize,
        features: crate::features::LinkFeatures,
        now: core::time::Duration,
    ) -> bool {
        if idx >= self.num_interfaces() {
            return false;
        }
        self.set_link_features(idx, features);
        // Keep the keep-alive timer bank in sync with the new features: a
        // `tx_keepalive` that changed from `None` to `Some` (or vice versa,
        // or to a different interval) must re-arm/disarm the timer here, not
        // just update the stored flag — this is the one piece of a link's
        // features with its own independent scheduling state to keep current.
        self.configure_interface_keepalive(idx, features.tx_keepalive.map(|c| c.interval()), now);
        self.runtime_config_active = true;
        true
    }

    /// Whether this node currently has a runtime configuration override
    /// applied, as opposed to running purely off its startup configuration.
    pub fn runtime_config_active(&self) -> bool {
        self.runtime_config_active
    }

    /// Time until the soonest interface is next due to emit an OGM, as of `now`.
    /// The driver sleeps for this long before its next periodic emission.
    pub fn next_broadcast_after(&self, now: core::time::Duration) -> core::time::Duration {
        self.batman.next_broadcast_after(now)
    }

    /// The index of the interface most overdue to emit an OGM as of `now`, or
    /// `None` when none is yet due.
    pub fn due_interface(&self, now: core::time::Duration) -> Option<usize> {
        self.batman.due_interface(now)
    }

    /// Record that interface `idx` just emitted an OGM at `now`, advancing its
    /// Trickle schedule (doubling the interval toward `i_max`).
    pub fn on_interface_emitted(&mut self, idx: usize, now: core::time::Duration) {
        self.batman.on_interface_emitted(idx, now);
    }

    /// Install (or replace) mesh interface `idx`'s keep-alive transmit
    /// schedule. `interval` of `None` disarms it (that interface never
    /// transmits keep-alives); `Some` arms a fixed-cadence heartbeat at that
    /// period, floored to [`MIN_KEEPALIVE_INTERVAL`] — a degenerate
    /// near-zero config value (e.g. an `interval_ms: 0` typo) would otherwise
    /// arm a `TrickleTimer` that fires on effectively every tick, flooding
    /// the link with heartbeats instead of failing loudly.
    pub fn configure_interface_keepalive(
        &mut self,
        idx: usize,
        interval: Option<core::time::Duration>,
        now: core::time::Duration,
    ) {
        let interval = interval.map(|iv| {
            if iv < MIN_KEEPALIVE_INTERVAL {
                warn!(
                    ?iv,
                    floor = ?MIN_KEEPALIVE_INTERVAL,
                    "keep-alive interval below floor, clamping"
                );
                MIN_KEEPALIVE_INTERVAL
            } else {
                iv
            }
        });
        self.batman
            .configure_interface_keepalive(idx, interval, now);
    }

    /// Time until the soonest interface is next due to emit a keep-alive, as
    /// of `now`.
    pub fn next_keepalive_after(&self, now: core::time::Duration) -> core::time::Duration {
        self.batman.next_keepalive_after(now)
    }

    /// The index of the interface most overdue to emit a keep-alive as of
    /// `now`, or `None` when none is configured or due.
    pub fn due_keepalive_interface(&self, now: core::time::Duration) -> Option<usize> {
        self.batman.due_keepalive_interface(now)
    }

    /// Record that interface `idx` just emitted a keep-alive at `now`,
    /// advancing its fixed-cadence schedule.
    pub fn on_keepalive_emitted(&mut self, idx: usize, now: core::time::Duration) {
        self.batman.on_keepalive_emitted(idx, now);
    }

    /// Wrap host data destined for `dest` in the appropriate BATMAN packet,
    /// ready to hand to a link.  A `dest` of [`MeshIdentifier::BROADCAST`]
    /// produces a flooded [`BatmanBroadcastPacket`] (e.g. for a host ARP);
    /// any other destination produces a [`BatmanUnicastPacket`] routed toward
    /// the best-known next hop.  Returns [`LocalSendError::BufferTooSmall`] if
    /// `payload` plus the header would not fit in `tx_buf`, or
    /// [`LocalSendError::AuthLocked`] while
    /// [`auth_locked`](CentralRouter::auth_locked).
    ///
    /// [`MeshIdentifier::BROADCAST`]: interfaces::frame::MeshIdentifier::BROADCAST
    pub fn handle_local<'a>(
        &mut self,
        now: core::time::Duration,
        dest: Mac,
        payload: &[u8],
        tx_buf: &'a mut [u8],
    ) -> Result<LinkFrameData<'a>, LocalSendError> {
        if self.auth_locked() {
            trace!("drop: auth locked, suppressing local egress");
            return Err(LocalSendError::AuthLocked);
        }
        // Broadcast destinations are flooded, not routed to a next hop.
        if dest == Mac::BROADCAST {
            let header = BatmanBroadcastPacket {
                packet_type: BATADV_BCAST,
                version: 5,
                ttl: 50,
                seqno: self.batman.next_broadcast_seqno().to_be(),
                orig: self.batman.self_ident,
            };
            let header_size = core::mem::size_of::<BatmanBroadcastPacket>();
            let total_size = header_size + payload.len();
            if total_size > tx_buf.len() {
                self.note_oversize_drop();
                return Err(LocalSendError::BufferTooSmall);
            }
            tx_buf[..header_size].copy_from_slice(header.as_bytes());
            tx_buf[header_size..total_size].copy_from_slice(payload);
            return Ok(LinkFrameData {
                dst: Mac::BROADCAST,
                protocol: ETH_P_BATMAN,
                payload: &tx_buf[..total_size],
            });
        }

        // 1. Query BATMAN for the next-hop physical address
        let next_hop = if let Some(next_hop) = self.batman.next_hop(now, dest) {
            next_hop
        } else {
            dest
        };
        // 2. Build the Unicast Header
        let header = BatmanUnicastPacket {
            packet_type: BATADV_UNICAST,
            version: 5,
            ttl: 50,
            dest,
        };

        // 3. Allocate a deterministic transmission workspace on the stack
        let header_size = core::mem::size_of::<BatmanUnicastPacket>();
        let total_size = header_size + payload.len();

        if total_size > tx_buf.len() {
            self.note_oversize_drop();
            return Err(LocalSendError::BufferTooSmall);
        }

        // Pack the header and data sequentially into the scratchpad
        tx_buf[..header_size].copy_from_slice(header.as_bytes());
        tx_buf[header_size..total_size].copy_from_slice(payload);

        Ok(LinkFrameData {
            dst: next_hop,
            protocol: ETH_P_BATMAN,
            payload: &tx_buf[..total_size],
        })
    }

    /// Choose the egress interface for a frame destined to `dest`.
    ///
    /// Resolution order:
    /// 1. `BROADCAST` always returns [`EgressInterface::All`].
    /// 2. If BATMAN has chosen a next-hop neighbor for `dest`, use the
    ///    interface with the best EWMA link quality observed for *that
    ///    neighbor*.  This is what makes the choice metric-driven.
    /// 3. Otherwise (no BATMAN route — `dest` is presumed to be a direct
    ///    neighbor or unknown), fall back to the best-quality interface
    ///    observed for `dest` itself.
    /// 4. If no quality data exists yet, fall back to the legacy
    ///    last-seen [`IdentTable`] entry.
    #[tracing::instrument(skip(self))]
    pub fn get_egress_interface(
        &mut self,
        now: core::time::Duration,
        dest: Mac,
    ) -> Option<EgressInterface> {
        if dest == Mac::BROADCAST {
            return Some(EgressInterface::All);
        }

        let next_hop = self.batman.next_hop(now, dest).unwrap_or(dest);

        if let Some(iface) = self.link_quality.best_interface_for(next_hop) {
            return Some(EgressInterface::Interface(iface));
        }

        self.ident_table
            .get_egress_interface(dest)
            .map(EgressInterface::Interface)
    }

    /// This node's own mesh address.
    pub fn self_ident(&self) -> Mac {
        self.batman.self_ident
    }

    /// Iterate every known originator record.  The originator table is keyed by
    /// MAC for O(1) lookup, so this yields the records in no particular order;
    /// use [`originator_count`](Self::originator_count) for the count.
    pub fn originator_table(&self) -> impl Iterator<Item = &batman::OriginatorRecord> + '_ {
        self.batman.originator_table.values()
    }

    /// The number of originators currently known — O(1).
    pub fn originator_count(&self) -> usize {
        self.batman.originator_table.len()
    }

    /// `(used, capacity)` of the originator (routing) table — how full the
    /// fixed-capacity routing table is.  At capacity the least-recently-heard
    /// originator is evicted to admit a new one.
    pub fn originator_occupancy(&self) -> (usize, usize) {
        (self.batman.originator_table.len(), ORIGINATOR_CAPACITY)
    }

    /// `(used, capacity)` of the broadcast-deduplication table (one entry per
    /// originator whose flooded broadcasts we've seen).  Bounded by
    /// [`ORIGINATOR_CAPACITY`]; further originators are dropped once full.
    pub fn broadcast_dedup_occupancy(&self) -> (usize, usize) {
        (self.batman.broadcast_seqno.len(), ORIGINATOR_CAPACITY)
    }

    /// `(used, capacity)` of the locally-joined multicast group table — groups
    /// this node announces in its OGMs.
    pub fn local_mcast_occupancy(&self) -> (usize, usize) {
        (self.batman.local_mcast.len(), batman::MAX_LOCAL_MCAST)
    }

    /// `(used, capacity)` of the learned multicast-membership table —
    /// `(group, remote listener)` pairs learned from other nodes' OGMs.
    pub fn mcast_member_occupancy(&self) -> (usize, usize) {
        (self.batman.mcast_members.len(), batman::MAX_MCAST_MEMBERS)
    }

    /// The number of distinct directly-reachable (one-hop) neighbours: known
    /// originators whose best path is the originator itself (next hop equals the
    /// destination).  A subset of [`originator_count`](Self::originator_count)
    /// that excludes nodes only reachable through a relay.
    pub fn neighbor_count(&self) -> usize {
        self.batman
            .originator_table
            .values()
            .filter(|r| r.best_next_hop == r.neighbor_ident)
            .count()
    }

    /// Borrow the link-quality table for inspection.  Read-only mirror of
    /// the structure the data plane mutates on every received frame.
    pub fn link_quality_records(&self) -> &[LinkQualityRecord<Mac>] {
        self.link_quality.records()
    }

    /// Snapshot of every neighbor this router has heard at least one
    /// keep-alive from, evaluated as of `now`. No particular order.
    pub fn keepalive_table(
        &self,
        now: core::time::Duration,
    ) -> impl Iterator<Item = KeepAliveEntry> + '_ {
        self.batman.keepalive.iter().map(move |(neighbor, stats)| {
            let neighbor = *neighbor;
            KeepAliveEntry {
                neighbor,
                ms_since_last_heard: now
                    .saturating_sub(stats.last_heard)
                    .as_millis()
                    .min(u64::MAX as u128) as u64,
                interval_estimate_ms: stats.interval_estimate.as_millis().min(u64::MAX as u128)
                    as u64,
                missed: self.batman.keepalive_missed(now, neighbor),
            }
        })
    }

    /// Fold `bytes` of one received link frame, observed at `now`, into
    /// interface `idx`'s receive-rate estimate.
    ///
    /// Called automatically from [`handle_frame_with_metrics`] for every frame
    /// that arrives, so the normal receive path needs no extra wiring.  It is
    /// `pub` so an embedded loop that ingests frames through some other path can
    /// still keep the ingress rate truthful.  A no-op for `idx >=
    /// `[`MAX_INTERFACES`].
    ///
    /// [`handle_frame_with_metrics`]: CentralRouter::handle_frame_with_metrics
    pub fn record_rx(&mut self, idx: usize, bytes: usize, now: Duration) {
        if let Some(e) = self.rx_rates.get_mut(idx) {
            e.observe(now, bytes);
            self.touch_iface(idx);
        }
    }

    /// Fold `bytes` of one transmitted link frame, sent at `now`, into interface
    /// `idx`'s transmit-rate estimate.
    ///
    /// Unlike the receive path, the router does not perform the transmit itself
    /// — the host or embedded I/O layer does, after the router has chosen the
    /// egress via [`get_egress_interface`].  That layer calls this once per
    /// physical send (a broadcast that floods N interfaces counts on each),
    /// keeping the rate estimate inside the routing core where the management
    /// API can read it.  A no-op for `idx >= `[`MAX_INTERFACES`].
    ///
    /// [`get_egress_interface`]: CentralRouter::get_egress_interface
    pub fn record_tx(&mut self, idx: usize, bytes: usize, now: Duration) {
        if let Some(e) = self.tx_rates.get_mut(idx) {
            e.observe(now, bytes);
            self.touch_iface(idx);
        }
    }

    /// Number of interfaces the router is tracking throughput for — those
    /// configured for OGM emission or having carried traffic.  Indices `0..`
    /// this value are valid arguments to [`interface_throughput`].
    ///
    /// [`interface_throughput`]: CentralRouter::interface_throughput
    pub fn num_interfaces(&self) -> usize {
        self.iface_count
    }

    /// The smoothed throughput of interface `idx`, evaluated as of `now` so an
    /// idle interface reads as a decaying rather than stale rate.  Returns
    /// `None` for `idx >= `[`num_interfaces`].  Indices line up with the
    /// OGM-schedule and link-quality views; sum across all interfaces for the
    /// node-wide rate.
    ///
    /// [`num_interfaces`]: CentralRouter::num_interfaces
    pub fn interface_throughput(&self, idx: usize, now: Duration) -> Option<InterfaceThroughput> {
        if idx >= self.iface_count {
            return None;
        }
        let (rx_bps, rx_fps) = self.rx_rates[idx].rate(now);
        let (tx_bps, tx_fps) = self.tx_rates[idx].rate(now);
        Some(InterfaceThroughput {
            rx_bps,
            rx_fps,
            tx_bps,
            tx_fps,
        })
    }

    /// Note that interface `idx` exists, widening the range
    /// [`interface_throughput`] reports over.  Saturates at [`MAX_INTERFACES`].
    ///
    /// [`interface_throughput`]: CentralRouter::interface_throughput
    fn touch_iface(&mut self, idx: usize) {
        if idx < MAX_INTERFACES {
            self.iface_count = self.iface_count.max(idx + 1);
        }
    }

    /// Snapshot the per-interface adaptive OGM emission schedule: each
    /// interface's current publish interval and the `i_min`/`i_max` bounds it
    /// backs off between.  Yields one entry per configured interface in
    /// registration order; backs the management-API `GetOgmSchedule` request.
    pub fn ogm_schedule(&self) -> impl Iterator<Item = batman::OgmScheduleEntry> + '_ {
        self.batman.ogm_schedule()
    }

    /// Read-only equivalent of [`handle_local`] + [`get_egress_interface`]:
    /// returns the next-hop neighbor and the egress decision that *would*
    /// be made for a packet to `dest` right now, without mutating any
    /// router state.  Used to back the management-API `ResolveRoute`
    /// request.
    ///
    /// `next_hop` mirrors the `next_hop(now, dest).unwrap_or(dest)`
    /// fallback used inside [`handle_local`] — when no live BATMAN route is
    /// known the router will try to reach `dest` directly.
    ///
    /// The egress value is `None` when no link-quality or last-seen
    /// information exists for the destination; in that state the data
    /// plane has nothing to transmit on either.
    ///
    /// [`handle_local`]: CentralRouter::handle_local
    /// [`get_egress_interface`]: CentralRouter::get_egress_interface
    pub fn resolve_route(
        &self,
        now: core::time::Duration,
        dest: Mac,
    ) -> (Mac, Option<EgressInterface>) {
        if dest == Mac::BROADCAST {
            return (Mac::BROADCAST, Some(EgressInterface::All));
        }

        let next_hop = self.batman.next_hop(now, dest).unwrap_or(dest);

        let egress = if let Some(iface) = self.link_quality.best_interface_for(next_hop) {
            Some(EgressInterface::Interface(iface))
        } else {
            self.ident_table
                .peek_egress_interface(dest)
                .map(EgressInterface::Interface)
        };

        (next_hop, egress)
    }
}

#[cfg(test)]
mod cp2_local_delivery {
    use super::*;
    use batman::wire::{BATADV_BCAST, BATADV_UNICAST, BatmanBroadcastPacket, BatmanUnicastPacket};
    use interfaces::frame::{LinkFrame, Mac};
    use zerocopy::{FromBytes, IntoBytes};

    // Stand-in for an inner host frame (e.g. an IP packet inside an Ethernet
    // frame) that rides across the mesh and must be delivered to the TAP.
    const INNER: &[u8] = &[0x45, 0x00, 0x00, 0x1c, 0xde, 0xad];

    /// Map a compact `u8` test identifier to a full MAC address.
    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// Serialise a `LinkFrame`, Ethernet-shaped: `[dst][src][proto BE][payload]`.
    fn link_frame_bytes(src: u8, dst: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(mac(dst).as_bytes());
        v.extend_from_slice(mac(src).as_bytes());
        v.extend_from_slice(&ETH_P_BATMAN.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    /// A unicast packet addressed to us must surface its inner payload for
    /// local delivery (to the TAP) and produce no mesh forward.
    #[test]
    fn unicast_for_self_delivers_locally() {
        let mut router: CentralRouter = CentralRouter::new(mac(1));

        let mut payload = Vec::new();
        let hdr = BatmanUnicastPacket {
            packet_type: BATADV_UNICAST,
            version: 5,
            ttl: 50,
            dest: mac(1),
        };
        payload.extend_from_slice(hdr.as_bytes());
        payload.extend_from_slice(INNER);

        let bytes = link_frame_bytes(2, 1, &payload);
        let frame = LinkFrame::ref_from_bytes(&bytes).unwrap();

        let mut tx = [0u8; 256];
        let outcome = router.handle_frame(core::time::Duration::ZERO, 0, frame, &mut tx);

        assert_eq!(outcome.deliver_local, Some(INNER));
        assert!(outcome.forward.is_none());
    }

    /// A fresh broadcast must be both delivered to the local TAP and
    /// re-flooded (with a decremented TTL) onto the mesh.
    #[test]
    fn broadcast_delivers_locally_and_refloods() {
        let mut router: CentralRouter = CentralRouter::new(mac(1));

        let mut payload = Vec::new();
        let hdr = BatmanBroadcastPacket {
            packet_type: BATADV_BCAST,
            version: 5,
            ttl: 50,
            seqno: 7u32.to_be(),
            orig: mac(2),
        };
        payload.extend_from_slice(hdr.as_bytes());
        payload.extend_from_slice(INNER);

        let bytes = link_frame_bytes(2, 0xff, &payload);
        let frame = LinkFrame::ref_from_bytes(&bytes).unwrap();

        let mut tx = [0u8; 256];
        let outcome = router.handle_frame(core::time::Duration::ZERO, 0, frame, &mut tx);

        // Delivered to the local TAP ...
        assert_eq!(outcome.deliver_local, Some(INNER));
        // ... and re-flooded to neighbours.
        let fwd = outcome.forward.expect("expected a re-flood frame");
        assert_eq!(fwd.dst, Mac::BROADCAST);
        assert_eq!(fwd.protocol, ETH_P_BATMAN);
        let (out, rest) = BatmanBroadcastPacket::ref_from_prefix(fwd.payload).unwrap();
        assert_eq!(out.ttl, 49);
        assert_eq!(&rest[..INNER.len()], INNER);
    }

    /// A broadcast that needs re-flooding, but whose re-flood doesn't fit the
    /// egress `tx` buffer (e.g. arrived on a large-MTU link, being relayed out
    /// a smaller one), must still deliver locally, must not forward anything,
    /// and must not panic — and the drop must be counted so an operator can
    /// see the MTU mismatch, distinct from `oversize_drops` (which only counts
    /// locally originated frames).
    #[test]
    fn broadcast_reflood_oversize_is_counted_not_panicked() {
        let mut router: CentralRouter = CentralRouter::new(mac(1));

        let mut payload = Vec::new();
        let hdr = BatmanBroadcastPacket {
            packet_type: BATADV_BCAST,
            version: 5,
            ttl: 50,
            seqno: 7u32.to_be(),
            orig: mac(2),
        };
        payload.extend_from_slice(hdr.as_bytes());
        payload.extend_from_slice(INNER);

        let bytes = link_frame_bytes(2, 0xff, &payload);
        let frame = LinkFrame::ref_from_bytes(&bytes).unwrap();

        // Room for the fixed broadcast header only; no room for INNER.
        let header_size = core::mem::size_of::<BatmanBroadcastPacket>();
        let mut tx = vec![0u8; header_size];
        let outcome = router.handle_frame(core::time::Duration::ZERO, 0, frame, &mut tx);

        assert_eq!(outcome.deliver_local, Some(INNER)); // still delivered locally
        assert!(outcome.forward.is_none()); // but not re-flooded
        assert_eq!(router.relay_oversize_drops(), 1);
        assert_eq!(router.oversize_drops(), 0); // distinct counter, untouched
    }

    /// Local egress: a host frame addressed to the broadcast Ident must be
    /// wrapped in a BatmanBroadcastPacket (not a unicast) so it floods.
    #[test]
    fn local_broadcast_frame_is_wrapped_as_broadcast() {
        let mut router: CentralRouter = CentralRouter::new(mac(1));

        let mut tx = [0u8; 256];
        let out = router
            .handle_local(Duration::ZERO, Mac::BROADCAST, INNER, &mut tx)
            .expect("broadcast packet should build");

        assert_eq!(out.dst, Mac::BROADCAST);
        assert_eq!(out.protocol, ETH_P_BATMAN);
        let (hdr, rest) = BatmanBroadcastPacket::ref_from_prefix(out.payload).unwrap();
        assert_eq!(hdr.packet_type, BATADV_BCAST);
        assert_eq!(hdr.orig, mac(1)); // our own ident
        assert!(hdr.ttl > 1);
        assert_eq!(&rest[..INNER.len()], INNER);
    }
}

#[cfg(test)]
mod cert_control_delivery {
    //! Lazy-cert-distribution control packets (`BATADV_CERT_REQ` /
    //! `BATADV_CERT_REPLY`) are routed like a unicast, but must never leak to
    //! the local host/TAP the way an ordinary unicast's inner payload does —
    //! they are consumed internally by the router's auth state
    //! (`ingest_cert_reply`/`verify_cert_request`, exercised for real in
    //! `mod cert_responder` below). This module only checks the routing/
    //! non-leak contract in isolation.

    use super::*;
    use batman::wire::{
        BATADV_CERT_REPLY, BATADV_CERT_REQ, BatmanCertReplyPacket, BatmanCertReqPacket,
    };
    use interfaces::frame::{LinkFrame, Mac};
    use zerocopy::{FromBytes, IntoBytes};

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    fn link_frame_bytes(src: u8, dst: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(mac(dst).as_bytes());
        v.extend_from_slice(mac(src).as_bytes());
        v.extend_from_slice(&ETH_P_BATMAN.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    /// A `CertReq` addressed to us reaches local delivery at the engine layer
    /// (`RoutingAction::DeliverLocal`) but must not be surfaced to the host —
    /// unlike a unicast, `deliver_local` must stay `None`.
    #[test]
    fn cert_req_for_self_is_not_delivered_to_host() {
        let mut router: CentralRouter = CentralRouter::new(mac(1));

        let mut payload = Vec::new();
        let hdr = BatmanCertReqPacket {
            packet_type: BATADV_CERT_REQ,
            version: 5,
            ttl: 50,
            dest: mac(1),
        };
        payload.extend_from_slice(hdr.as_bytes());
        payload.extend_from_slice(b"requester cert + sig");

        let bytes = link_frame_bytes(2, 1, &payload);
        let frame = LinkFrame::ref_from_bytes(&bytes).unwrap();

        let mut tx = [0u8; 256];
        let outcome = router.handle_frame(core::time::Duration::ZERO, 0, frame, &mut tx);

        assert!(
            outcome.deliver_local.is_none(),
            "cert-control payloads must never reach the host TAP"
        );
        assert!(outcome.forward.is_none());
    }

    /// A `CertReply` addressed to us is likewise not surfaced to the host.
    #[test]
    fn cert_reply_for_self_is_not_delivered_to_host() {
        let mut router: CentralRouter = CentralRouter::new(mac(1));

        let mut payload = Vec::new();
        let hdr = BatmanCertReplyPacket {
            packet_type: BATADV_CERT_REPLY,
            version: 5,
            ttl: 50,
            dest: mac(1),
        };
        payload.extend_from_slice(hdr.as_bytes());
        payload.extend_from_slice(b"the requested cert");

        let bytes = link_frame_bytes(2, 1, &payload);
        let frame = LinkFrame::ref_from_bytes(&bytes).unwrap();

        let mut tx = [0u8; 256];
        let outcome = router.handle_frame(core::time::Duration::ZERO, 0, frame, &mut tx);

        assert!(outcome.deliver_local.is_none());
        assert!(outcome.forward.is_none());
    }

    /// A `CertReq` not addressed to us is still relayed toward the next hop,
    /// exactly like an ordinary unicast — only local delivery is special-cased.
    #[test]
    fn cert_req_for_other_node_is_still_forwarded() {
        let mut router: CentralRouter = CentralRouter::new(mac(1));

        // Learn a route to node 5 via node 2 (a bare OGM is enough with auth
        // disabled).
        let ogm_hdr_len = core::mem::size_of::<batman::wire::BatmanOgmPacket>();
        let mut ogm_payload = vec![0u8; ogm_hdr_len];
        let ogm = batman::wire::BatmanOgmPacket {
            packet_type: batman::wire::BATADV_IV_OGM,
            version: 5,
            ttl: 50,
            flags: 0,
            seqno: 1u32.to_be(),
            orig: mac(5),
            reserved: 0,
            tq: 255,
            tvlv_len: 0,
        };
        ogm_payload.copy_from_slice(ogm.as_bytes());
        let ogm_bytes = link_frame_bytes(2, 0xff, &ogm_payload);
        let ogm_frame = LinkFrame::ref_from_bytes(&ogm_bytes).unwrap();
        let mut tx = [0u8; 256];
        router.handle_frame(core::time::Duration::ZERO, 0, ogm_frame, &mut tx);

        let mut payload = Vec::new();
        let hdr = BatmanCertReqPacket {
            packet_type: BATADV_CERT_REQ,
            version: 5,
            ttl: 10,
            dest: mac(5),
        };
        payload.extend_from_slice(hdr.as_bytes());
        payload.extend_from_slice(b"cert body");

        let bytes = link_frame_bytes(3, 1, &payload);
        let frame = LinkFrame::ref_from_bytes(&bytes).unwrap();

        let mut tx = [0u8; 256];
        let outcome = router.handle_frame(core::time::Duration::ZERO, 0, frame, &mut tx);

        let fwd = outcome.forward.expect("expected a relay toward node 5");
        assert_eq!(fwd.dst, mac(2)); // next hop toward node 5
        let (fwd_hdr, rest) = BatmanCertReqPacket::ref_from_prefix(fwd.payload).unwrap();
        assert_eq!(fwd_hdr.ttl, 9);
        assert_eq!(&rest[..b"cert body".len()], b"cert body");
        assert!(outcome.deliver_local.is_none());
    }
}

#[cfg(test)]
mod cert_responder {
    //! The responder half of lazy cert distribution: a locally-delivered
    //! `CertReq` (this node is the terminal originator whose cert was
    //! asked for) is answered immediately when a route to the requester
    //! exists, or parked and flushed opportunistically once one appears.

    use super::*;
    use batman::wire::{
        BATADV_CERT_REPLY, BATADV_IV_OGM, BatmanCertReplyPacket, BatmanCertReqPacket,
        BatmanOgmPacket,
    };
    use interfaces::frame::{LinkFrame, Mac};
    use zerocopy::{FromBytes, IntoBytes};

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    fn link_frame_bytes(src: u8, dst: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(mac(dst).as_bytes());
        v.extend_from_slice(mac(src).as_bytes());
        v.extend_from_slice(&ETH_P_BATMAN.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    /// A signed OGM from `orig` (via `orig_auth`), to prime the responder's
    /// route table and cert cache — a 1-hop OGM, so the neighbor discovered
    /// is `orig` itself.
    fn signed_ogm(orig_auth: &mut auth::OgmAuth, orig: Mac, seqno: u32, ttl: u8) -> Vec<u8> {
        let ogm_hdr_len = core::mem::size_of::<BatmanOgmPacket>();
        let mut buf = vec![0u8; 512];
        let ogm = BatmanOgmPacket {
            packet_type: BATADV_IV_OGM,
            version: 5,
            ttl,
            flags: 0,
            seqno: seqno.to_be(),
            orig,
            reserved: 0,
            tq: 255,
            tvlv_len: 0,
        };
        buf[..ogm_hdr_len].copy_from_slice(ogm.as_bytes());
        let len = orig_auth.augment_ogm(&mut buf, ogm_hdr_len).unwrap();
        buf.truncate(len);
        buf
    }

    /// A `CertReq` from a requester we already have a route to is answered
    /// immediately with this node's own cert, addressed back toward the
    /// requester's next hop.
    #[test]
    fn cert_req_answered_immediately_when_route_exists() {
        let authority = wayfinder_auth::Authority::from_seed(&[1; 32], 0xABCD);
        let responder_kp = wayfinder_auth::Keypair::from_seed(&[1; 32]);
        let responder_cert = authority.issue_cert(
            mac(1),
            responder_kp.ed_pubkey(),
            responder_kp.x_pubkey(),
            0,
            1000,
        );
        let mut router: CentralRouter = CentralRouter::new(mac(1));
        router.set_auth(auth::OgmAuth::new(
            responder_kp,
            responder_cert,
            authority.trust_anchor(),
        ));
        router.auth_mut().unwrap().set_time(100);

        let requester_kp = wayfinder_auth::Keypair::from_seed(&[3; 32]);
        let requester_cert = authority.issue_cert(
            mac(3),
            requester_kp.ed_pubkey(),
            requester_kp.x_pubkey(),
            0,
            1000,
        );
        let mut requester_auth =
            auth::OgmAuth::new(requester_kp, requester_cert, authority.trust_anchor());
        requester_auth.set_time(100);

        // Prime a direct route + cert cache from the requester (mac(3)).
        let ogm_bytes = signed_ogm(&mut requester_auth, mac(3), 1, 50);
        let ogm_frame_bytes = link_frame_bytes(3, 0xff, &ogm_bytes);
        let ogm_frame = LinkFrame::ref_from_bytes(&ogm_frame_bytes).unwrap();
        let mut tx = [0u8; 512];
        router.handle_frame(core::time::Duration::ZERO, 0, ogm_frame, &mut tx);
        assert_eq!(router.originator_table().count(), 1);

        // The requester asks for our (mac(1)'s) cert.
        let mut req_buf = [0u8; 512];
        let req_len = requester_auth
            .build_cert_request(mac(1), [0; 8], mac(3), &mut req_buf)
            .unwrap();
        let mut payload = Vec::new();
        let hdr = BatmanCertReqPacket {
            packet_type: batman::wire::BATADV_CERT_REQ,
            version: 5,
            ttl: 50,
            dest: mac(1),
        };
        payload.extend_from_slice(hdr.as_bytes());
        payload.extend_from_slice(&req_buf[..req_len]);
        let req_frame_bytes = link_frame_bytes(3, 1, &payload);
        let req_frame = LinkFrame::ref_from_bytes(&req_frame_bytes).unwrap();

        let mut tx = [0u8; 512];
        let outcome = router.handle_frame(core::time::Duration::ZERO, 0, req_frame, &mut tx);

        let fwd = outcome
            .forward
            .expect("must answer immediately: a route exists");
        assert_eq!(fwd.dst, mac(3));
        let (reply_hdr, cert_bytes) = BatmanCertReplyPacket::ref_from_prefix(fwd.payload).unwrap();
        assert_eq!(reply_hdr.packet_type, BATADV_CERT_REPLY);
        assert_eq!(reply_hdr.dest, mac(3));
        assert_eq!(
            &cert_bytes[..core::mem::size_of::<wayfinder_auth::MembershipCert>()],
            router.auth().unwrap().own_cert().as_bytes()
        );
        assert!(outcome.deliver_local.is_none());
    }

    /// A `CertReq` from a requester we have no route to yet is parked, not
    /// answered — and later flushed once an OGM from that requester (that
    /// itself needs no re-flood) confirms a route back.
    #[test]
    fn cert_req_parked_then_flushed_by_later_ogm() {
        let authority = wayfinder_auth::Authority::from_seed(&[1; 32], 0xABCD);
        let responder_kp = wayfinder_auth::Keypair::from_seed(&[1; 32]);
        let responder_cert = authority.issue_cert(
            mac(1),
            responder_kp.ed_pubkey(),
            responder_kp.x_pubkey(),
            0,
            1000,
        );
        let mut router: CentralRouter = CentralRouter::new(mac(1));
        router.set_auth(auth::OgmAuth::new(
            responder_kp,
            responder_cert,
            authority.trust_anchor(),
        ));
        router.auth_mut().unwrap().set_time(100);

        let requester_kp = wayfinder_auth::Keypair::from_seed(&[3; 32]);
        let requester_cert = authority.issue_cert(
            mac(3),
            requester_kp.ed_pubkey(),
            requester_kp.x_pubkey(),
            0,
            1000,
        );
        let mut requester_auth =
            auth::OgmAuth::new(requester_kp, requester_cert, authority.trust_anchor());
        requester_auth.set_time(100);

        // No prior OGM from the requester: no route yet.
        let mut req_buf = [0u8; 512];
        let req_len = requester_auth
            .build_cert_request(mac(1), [0; 8], mac(3), &mut req_buf)
            .unwrap();
        let mut payload = Vec::new();
        let hdr = BatmanCertReqPacket {
            packet_type: batman::wire::BATADV_CERT_REQ,
            version: 5,
            ttl: 50,
            dest: mac(1),
        };
        payload.extend_from_slice(hdr.as_bytes());
        payload.extend_from_slice(&req_buf[..req_len]);
        let req_frame_bytes = link_frame_bytes(3, 1, &payload);
        let req_frame = LinkFrame::ref_from_bytes(&req_frame_bytes).unwrap();

        let mut tx = [0u8; 512];
        let outcome = router.handle_frame(core::time::Duration::ZERO, 0, req_frame, &mut tx);
        assert!(outcome.forward.is_none(), "no route yet: must not answer");
        assert!(
            router.auth().unwrap().has_pending_reply(mac(3)),
            "the request must be parked"
        );

        // An OGM from the requester arrives with ttl=1 so it needs no
        // re-flood, leaving the forward slot free for the opportunistic
        // flush.
        let ogm_bytes = signed_ogm(&mut requester_auth, mac(3), 1, 1);
        let ogm_frame_bytes = link_frame_bytes(3, 0xff, &ogm_bytes);
        let ogm_frame = LinkFrame::ref_from_bytes(&ogm_frame_bytes).unwrap();
        let mut tx = [0u8; 512];
        let outcome = router.handle_frame(core::time::Duration::ZERO, 0, ogm_frame, &mut tx);

        let fwd = outcome
            .forward
            .expect("the parked reply must be flushed once a route appears");
        assert_eq!(fwd.dst, mac(3));
        let (reply_hdr, _) = BatmanCertReplyPacket::ref_from_prefix(fwd.payload).unwrap();
        assert_eq!(reply_hdr.packet_type, BATADV_CERT_REPLY);
        assert!(!router.auth().unwrap().has_pending_reply(mac(3)));
    }

    /// A signed *lazy* OGM (`CertFp`, not `Cert`) from `orig_auth`, mirroring
    /// [`signed_ogm`] but for triggering an unresolved-fingerprint fetch.
    fn lazy_signed_ogm(orig_auth: &mut auth::OgmAuth, orig: Mac, seqno: u32, ttl: u8) -> Vec<u8> {
        let ogm_hdr_len = core::mem::size_of::<BatmanOgmPacket>();
        let mut buf = vec![0u8; 512];
        let ogm = BatmanOgmPacket {
            packet_type: BATADV_IV_OGM,
            version: 5,
            ttl,
            flags: 0,
            seqno: seqno.to_be(),
            orig,
            reserved: 0,
            tq: 255,
            tvlv_len: 0,
        };
        buf[..ogm_hdr_len].copy_from_slice(ogm.as_bytes());
        let len = orig_auth.augment_ogm_lazy(&mut buf, ogm_hdr_len).unwrap();
        buf.truncate(len);
        buf
    }

    /// Receiving a `CertFp` OGM from a never-seen originator triggers a
    /// `CertReq` fetch, which must register on the cert-request send-rate
    /// metric — an operator-visible signal for how often this node is
    /// fetching certs.
    #[test]
    fn fetching_an_unresolved_fingerprint_grows_the_cert_req_tx_rate() {
        let authority = wayfinder_auth::Authority::from_seed(&[1; 32], 0xABCD);
        let receiver_kp = wayfinder_auth::Keypair::from_seed(&[1; 32]);
        let receiver_cert = authority.issue_cert(
            mac(1),
            receiver_kp.ed_pubkey(),
            receiver_kp.x_pubkey(),
            0,
            1000,
        );
        let mut router: CentralRouter = CentralRouter::new(mac(1));
        router.set_auth(auth::OgmAuth::new(
            receiver_kp,
            receiver_cert,
            authority.trust_anchor(),
        ));
        router.auth_mut().unwrap().set_time(100);
        assert_eq!(
            router.cert_req_tx_rate(core::time::Duration::from_secs(1)),
            0.0
        );

        let sender_kp = wayfinder_auth::Keypair::from_seed(&[2; 32]);
        let sender_cert =
            authority.issue_cert(mac(2), sender_kp.ed_pubkey(), sender_kp.x_pubkey(), 0, 1000);
        let mut sender_auth = auth::OgmAuth::new(sender_kp, sender_cert, authority.trust_anchor());
        sender_auth.set_time(100);

        let ogm_bytes = lazy_signed_ogm(&mut sender_auth, mac(2), 1, 50);
        let ogm_frame_bytes = link_frame_bytes(2, 0xff, &ogm_bytes);
        let ogm_frame = LinkFrame::ref_from_bytes(&ogm_frame_bytes).unwrap();
        let mut tx = [0u8; 512];
        let outcome = router.handle_frame(core::time::Duration::ZERO, 0, ogm_frame, &mut tx);
        assert!(
            outcome.forward.is_some(),
            "an unresolved fingerprint must trigger a CertReq fetch"
        );

        assert!(
            router.cert_req_tx_rate(core::time::Duration::from_secs(1)) > 0.0,
            "fetching an unresolved cert must register on the cert-request send-rate metric"
        );
    }

    /// Answering a `CertReq` — immediately, since a route to the requester
    /// already exists — must register on the cert-reply send-rate metric.
    #[test]
    fn answering_a_cert_req_grows_the_cert_reply_tx_rate() {
        let authority = wayfinder_auth::Authority::from_seed(&[1; 32], 0xABCD);
        let responder_kp = wayfinder_auth::Keypair::from_seed(&[1; 32]);
        let responder_cert = authority.issue_cert(
            mac(1),
            responder_kp.ed_pubkey(),
            responder_kp.x_pubkey(),
            0,
            1000,
        );
        let mut router: CentralRouter = CentralRouter::new(mac(1));
        router.set_auth(auth::OgmAuth::new(
            responder_kp,
            responder_cert,
            authority.trust_anchor(),
        ));
        router.auth_mut().unwrap().set_time(100);
        assert_eq!(
            router.cert_reply_tx_rate(core::time::Duration::from_secs(1)),
            0.0
        );

        let requester_kp = wayfinder_auth::Keypair::from_seed(&[3; 32]);
        let requester_cert = authority.issue_cert(
            mac(3),
            requester_kp.ed_pubkey(),
            requester_kp.x_pubkey(),
            0,
            1000,
        );
        let mut requester_auth =
            auth::OgmAuth::new(requester_kp, requester_cert, authority.trust_anchor());
        requester_auth.set_time(100);

        // Prime a direct route back to the requester (mac(3)).
        let ogm_bytes = signed_ogm(&mut requester_auth, mac(3), 1, 50);
        let ogm_frame_bytes = link_frame_bytes(3, 0xff, &ogm_bytes);
        let ogm_frame = LinkFrame::ref_from_bytes(&ogm_frame_bytes).unwrap();
        let mut tx = [0u8; 512];
        router.handle_frame(core::time::Duration::ZERO, 0, ogm_frame, &mut tx);

        let mut req_buf = [0u8; 512];
        let req_len = requester_auth
            .build_cert_request(mac(1), [0; 8], mac(3), &mut req_buf)
            .unwrap();
        let mut payload = Vec::new();
        let hdr = BatmanCertReqPacket {
            packet_type: batman::wire::BATADV_CERT_REQ,
            version: 5,
            ttl: 50,
            dest: mac(1),
        };
        payload.extend_from_slice(hdr.as_bytes());
        payload.extend_from_slice(&req_buf[..req_len]);
        let req_frame_bytes = link_frame_bytes(3, 1, &payload);
        let req_frame = LinkFrame::ref_from_bytes(&req_frame_bytes).unwrap();
        let mut tx = [0u8; 512];
        let outcome = router.handle_frame(core::time::Duration::ZERO, 0, req_frame, &mut tx);
        assert!(outcome.forward.is_some(), "must answer immediately");

        assert!(
            router.cert_reply_tx_rate(core::time::Duration::from_secs(1)) > 0.0,
            "answering a CertReq must register on the cert-reply send-rate metric"
        );
    }
}

#[cfg(test)]
mod mcast_forwarding {
    //! Selective multicast forwarding: a multicast frame is sent as an
    //! individual [`BATADV_MCAST`] packet to each interested originator when
    //! the listener count is within [`MCAST_FANOUT`], else flooded.

    use super::*;
    use batman::wire::{
        BATADV_IV_OGM, BATADV_MCAST, BatmanMcastPacket, BatmanOgmPacket, BatmanTvlvHdr, TvlvType,
    };
    use interfaces::frame::{LinkFrame, Mac};
    use zerocopy::{FromBytes, IntoBytes};

    const INNER: &[u8] = &[0x45, 0x00, 0x00, 0x10, 0x99];

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// A multicast group MAC (`01:00:5e:00:00:NN`).
    fn group(n: u8) -> Mac {
        Mac([0x01, 0x00, 0x5e, 0x00, 0x00, n])
    }

    /// Serialise a `LinkFrame`, Ethernet-shaped: `[dst][src][proto BE][payload]`.
    fn link_frame_bytes(src: Mac, dst: Mac, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(dst.as_bytes());
        v.extend_from_slice(src.as_bytes());
        v.extend_from_slice(&ETH_P_BATMAN.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    /// Feed `router` an OGM from `orig` announcing interest in `groups`, so the
    /// router learns `orig` as a listener for them.
    fn learn_listener(router: &mut CentralRouter, orig: Mac, seqno: u32, groups: &[Mac]) {
        let mut value = Vec::new();
        for g in groups {
            value.extend_from_slice(g.as_bytes());
        }
        let tvlv_hdr = BatmanTvlvHdr {
            tvlv_type: TvlvType::Mcast.as_u8(),
            version: 1,
            len: (value.len() as u16).to_be(),
        };
        let tvlv_total = core::mem::size_of::<BatmanTvlvHdr>() + value.len();
        let ogm = BatmanOgmPacket {
            packet_type: BATADV_IV_OGM,
            version: 5,
            ttl: 50,
            flags: 0,
            seqno: seqno.to_be(),
            orig,
            reserved: 0,
            tq: 255,
            tvlv_len: (tvlv_total as u16).to_be(),
        };
        let mut payload = ogm.as_bytes().to_vec();
        payload.extend_from_slice(tvlv_hdr.as_bytes());
        payload.extend_from_slice(&value);

        let bytes = link_frame_bytes(orig, Mac::BROADCAST, &payload);
        let frame = LinkFrame::ref_from_bytes(&bytes).unwrap();
        let mut tx = [0u8; 256];
        router.handle_frame(core::time::Duration::ZERO, 0, frame, &mut tx);
    }

    /// With no known listeners for a group, the plan is to flood.
    #[test]
    fn no_listeners_plans_flood() {
        let router = CentralRouter::new(mac(1));
        assert_eq!(router.mcast_plan(group(5)), McastPlan::Flood);
    }

    /// A handful of known listeners (within fanout) plans selective unicast,
    /// and `mcast_targets` lists exactly those originators.
    #[test]
    fn known_listeners_plan_unicast_and_list_targets() {
        let mut router = CentralRouter::new(mac(1));
        learn_listener(&mut router, mac(2), 1, &[group(5)]);
        learn_listener(&mut router, mac(3), 1, &[group(5)]);

        assert_eq!(router.mcast_plan(group(5)), McastPlan::Unicast);
        let mut targets: Vec<Mac> = router.mcast_targets(group(5)).collect();
        targets.sort_by_key(|m| m.0);
        assert_eq!(targets, vec![mac(2), mac(3)]);
    }

    /// More listeners than the fanout threshold falls back to flooding.
    #[test]
    fn over_fanout_plans_flood() {
        let mut router = CentralRouter::new(mac(1));
        for n in 0..=(MCAST_FANOUT as u8) {
            learn_listener(&mut router, mac(10 + n), 1, &[group(5)]);
        }
        assert_eq!(router.mcast_plan(group(5)), McastPlan::Flood);
    }

    /// `handle_local_mcast` wraps the frame in a BATADV_MCAST packet addressed
    /// to the given listener, preserving the inner payload.
    #[test]
    fn handle_local_mcast_wraps_in_mcast_packet() {
        let mut router = CentralRouter::new(mac(1));
        let mut tx = [0u8; 256];
        let out = router
            .handle_local_mcast(Duration::ZERO, mac(7), INNER, &mut tx)
            .expect("mcast packet should build");

        assert_eq!(out.protocol, ETH_P_BATMAN);
        let (hdr, rest) = BatmanMcastPacket::ref_from_prefix(out.payload).unwrap();
        assert_eq!(hdr.packet_type, BATADV_MCAST);
        assert_eq!(hdr.dest, mac(7));
        assert!(hdr.ttl > 1);
        assert_eq!(&rest[..INNER.len()], INNER);
    }

    /// A host frame that does not fit the transmit buffer once wrapped is
    /// dropped gracefully (no panic) and counted; a frame that fits is not.
    #[test]
    fn oversize_local_frame_is_counted_not_panicked() {
        let mut router = CentralRouter::new(mac(1));

        // A tiny buffer that cannot hold even the unicast header + payload.
        let mut tiny = [0u8; 4];
        assert!(
            router
                .handle_local(Duration::ZERO, mac(2), INNER, &mut tiny)
                .is_err()
        );
        assert_eq!(router.oversize_drops(), 1);

        // A second oversize drop bumps the counter without a second warn.
        assert!(
            router
                .handle_local(Duration::ZERO, mac(2), INNER, &mut tiny)
                .is_err()
        );
        assert_eq!(router.oversize_drops(), 2);

        // A frame that fits does not touch the counter.
        let mut ok = [0u8; 256];
        assert!(
            router
                .handle_local(Duration::ZERO, mac(2), INNER, &mut ok)
                .is_ok()
        );
        assert_eq!(router.oversize_drops(), 2);
    }

    /// A full 1500-byte host frame fits, fully wrapped, in a
    /// [`MAX_LINK_FRAME_LEN`](interfaces::frame::MAX_LINK_FRAME_LEN) buffer — the
    /// size the data path actually uses — so it is never an oversize drop.
    #[test]
    fn full_mtu_host_frame_fits_max_link_frame_buffer() {
        use interfaces::frame::MAX_LINK_FRAME_LEN;

        let mut router = CentralRouter::new(mac(1));
        let host_frame = [0u8; 1514]; // 1500 MTU + 14-byte Ethernet header
        let mut tx = [0u8; MAX_LINK_FRAME_LEN];
        assert!(
            router
                .handle_local(Duration::ZERO, mac(2), &host_frame, &mut tx)
                .is_ok()
        );
        assert_eq!(router.oversize_drops(), 0);
    }
}

#[cfg(test)]
mod throughput {
    use super::*;
    use core::time::Duration;
    use interfaces::frame::{LinkFrame, Mac};
    use zerocopy::{FromBytes, IntoBytes};

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// A fresh router reports no interfaces and no throughput.
    #[test]
    fn no_interfaces_until_touched() {
        let router = CentralRouter::new(mac(1));
        assert_eq!(router.num_interfaces(), 0);
        assert_eq!(router.interface_throughput(0, Duration::ZERO), None);
    }

    /// Configuring an interface's OGM schedule registers it for throughput
    /// reporting at a zero rate, before any traffic.
    #[test]
    fn configuring_interface_registers_zero_rate() {
        let mut router = CentralRouter::new(mac(1));
        router.configure_interface_ogm(
            2,
            Duration::from_secs(1),
            Duration::from_secs(8),
            Duration::ZERO,
        );
        // iface_count widens to cover the highest configured index.
        assert_eq!(router.num_interfaces(), 3);
        let tp = router
            .interface_throughput(2, Duration::from_secs(1))
            .unwrap();
        assert_eq!(tp, InterfaceThroughput::default());
    }

    /// `apply_runtime_trickle_config` installs the new Trickle bounds (like
    /// `configure_interface_ogm`) and additionally marks the router's runtime
    /// config as active, distinguishing a live override from startup wiring.
    /// Matches real deployment flow: startup wiring registers the interface via
    /// `configure_interface_ogm` first, and only afterward could a runtime
    /// override arrive.
    #[test]
    fn apply_runtime_trickle_config_marks_active_and_installs_bounds() {
        let mut router = CentralRouter::new(mac(1));
        router.configure_interface_ogm(
            0,
            Duration::from_secs(1),
            Duration::from_secs(8),
            Duration::ZERO,
        );
        assert!(!router.runtime_config_active());

        let applied = router.apply_runtime_trickle_config(
            0,
            Duration::from_millis(500),
            Duration::from_millis(4000),
            Duration::ZERO,
        );

        assert!(applied);
        assert!(router.runtime_config_active());
        let entry = router.ogm_schedule().find(|e| e.iface_idx == 0).unwrap();
        assert_eq!(entry.min_interval, Duration::from_millis(500));
        assert_eq!(entry.max_interval, Duration::from_millis(4000));
    }

    /// An index that doesn't correspond to any interface registered at startup
    /// is rejected rather than silently marking the router as having an active
    /// runtime override that didn't actually apply anything.
    #[test]
    fn apply_runtime_trickle_config_rejects_unregistered_interface() {
        let mut router = CentralRouter::new(mac(1));

        let applied = router.apply_runtime_trickle_config(
            0,
            Duration::from_millis(500),
            Duration::from_millis(4000),
            Duration::ZERO,
        );

        assert!(!applied);
        assert!(!router.runtime_config_active());
    }

    /// A steady stream of equal-sized frames at a fixed cadence converges on the
    /// true byte/frame rate.
    #[test]
    fn steady_stream_converges_on_true_rate() {
        let mut e = RateEstimator::default();
        // 100 bytes every 0.1s == 1000 B/s and 10 frames/s.
        let mut t = Duration::ZERO;
        for _ in 0..400 {
            e.observe(t, 100);
            t += Duration::from_millis(100);
        }
        let (bps, fps) = e.rate(t);
        assert!((bps - 1000.0).abs() < 50.0, "bps={bps}");
        assert!((fps - 10.0).abs() < 0.5, "fps={fps}");
    }

    /// Several frames sharing one instant accumulate into the same bucket and
    /// are folded together once time advances, rather than dividing by a zero
    /// interval.  Three 50-byte frames at one instant must read identically to a
    /// single 150-byte frame at that instant — the burst is not lost, and there
    /// is no division by a zero interval.
    #[test]
    fn simultaneous_frames_accumulate() {
        let mut split = RateEstimator::default();
        split.observe(Duration::ZERO, 50);
        split.observe(Duration::ZERO, 50);
        split.observe(Duration::ZERO, 50);

        let mut combined = RateEstimator::default();
        combined.observe(Duration::ZERO, 150);

        let (split_bps, _) = split.rate(Duration::from_secs(1));
        let (combined_bps, _) = combined.rate(Duration::from_secs(1));
        assert!(split_bps.is_finite());
        assert!(
            (split_bps - combined_bps).abs() < 1e-9,
            "{split_bps} vs {combined_bps}"
        );
        // But the per-frame counts differ: the split bucket saw three frames.
        assert_eq!(split.pending_frames, 3);
        assert_eq!(combined.pending_frames, 1);
    }

    /// An interface that goes quiet decays toward zero as the read instant
    /// advances, rather than reporting a stale rate forever.
    #[test]
    fn idle_interface_decays_toward_zero() {
        let mut e = RateEstimator::default();
        let mut t = Duration::ZERO;
        for _ in 0..100 {
            e.observe(t, 1000);
            t += Duration::from_millis(100);
        }
        let (busy, _) = e.rate(t);
        assert!(busy > 1000.0, "should be carrying traffic: {busy}");
        // Now read far in the future with no further frames: rate collapses.
        let (idle, _) = e.rate(t + Duration::from_secs(60));
        assert!(
            idle < busy / 10.0,
            "idle rate {idle} should be far below {busy}"
        );
    }

    /// Receiving a frame through the normal path advances the interface's
    /// receive rate; the transmit rate stays zero until something is sent.
    #[test]
    fn handle_frame_drives_rx_rate_only() {
        let mut router = CentralRouter::new(mac(1));
        let frame_bytes = {
            // A minimal non-BATMAN frame is fine: rx is counted before demux.
            let mut raw = Vec::new();
            raw.extend_from_slice(mac(1).as_bytes()); // dst = self
            raw.extend_from_slice(mac(2).as_bytes()); // src
            raw.extend_from_slice(&0x88B5u16.to_be_bytes()); // experimental proto, dropped
            raw.extend_from_slice(&[0u8; 100]);
            raw
        };
        let mut tx = [0u8; 1500];
        let mut t = Duration::ZERO;
        for _ in 0..50 {
            let frame = LinkFrame::ref_from_bytes(&frame_bytes).unwrap();
            router.handle_frame(t, 0, frame, &mut tx);
            t += Duration::from_millis(100);
        }
        let tp = router.interface_throughput(0, t).unwrap();
        assert!(tp.rx_bps > 0.0, "rx_bps={}", tp.rx_bps);
        assert!(tp.rx_fps > 0.0, "rx_fps={}", tp.rx_fps);
        assert_eq!(tp.tx_bps, 0.0);
        assert_eq!(tp.tx_fps, 0.0);
    }

    /// `record_tx` drives the transmit rate independently per interface.
    #[test]
    fn record_tx_drives_tx_rate_per_interface() {
        let mut router = CentralRouter::new(mac(1));
        let mut t = Duration::ZERO;
        for _ in 0..50 {
            router.record_tx(1, 200, t);
            t += Duration::from_millis(100);
        }
        let tp = router.interface_throughput(1, t).unwrap();
        assert!(tp.tx_bps > 0.0, "tx_bps={}", tp.tx_bps);
        assert_eq!(tp.rx_bps, 0.0);
        // Interface 0 was never touched by traffic but index 1 widened the count.
        let tp0 = router.interface_throughput(0, t).unwrap();
        assert_eq!(tp0, InterfaceThroughput::default());
    }

    /// Out-of-range indices are ignored, not panics.
    #[test]
    fn out_of_range_interface_is_noop() {
        let mut router = CentralRouter::new(mac(1));
        router.record_tx(MAX_INTERFACES + 4, 100, Duration::ZERO);
        assert_eq!(router.num_interfaces(), 0);
    }
}

#[cfg(test)]
mod node_metrics {
    use super::*;
    use batman::wire::{BATADV_IV_OGM, BatmanOgmPacket};
    use core::time::Duration;
    use interfaces::frame::{LinkFrame, Mac};
    use zerocopy::{FromBytes, IntoBytes};

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    fn link_frame_bytes(src: Mac, dst: Mac, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(dst.as_bytes());
        out.extend_from_slice(src.as_bytes());
        out.extend_from_slice(&DEFAULT_BATMAN_ETHER_TYPE.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Feed one OGM so the router learns `orig` as a direct neighbour with the
    /// given transmission quality.  A full TTL makes it a one-hop path.
    fn feed_direct_ogm(router: &mut CentralRouter, orig: Mac, seqno: u32, tq: u8) {
        let ogm = BatmanOgmPacket {
            packet_type: BATADV_IV_OGM,
            version: 5,
            ttl: 50,
            flags: 0,
            seqno: seqno.to_be(),
            orig,
            reserved: 0,
            tq,
            tvlv_len: 0,
        };
        let bytes = link_frame_bytes(orig, Mac::BROADCAST, ogm.as_bytes());
        let frame = LinkFrame::ref_from_bytes(&bytes).unwrap();
        let mut tx = [0u8; 256];
        router.handle_frame(Duration::ZERO, 0, frame, &mut tx);
    }

    /// A fresh router reports empty, non-zero-capacity tables and no neighbours.
    #[test]
    fn fresh_router_reports_empty_tables() {
        let router = CentralRouter::new(mac(1));
        assert_eq!(router.originator_occupancy(), (0, ORIGINATOR_CAPACITY));
        assert_eq!(router.broadcast_dedup_occupancy(), (0, ORIGINATOR_CAPACITY));
        assert_eq!(router.local_mcast_occupancy().0, 0);
        assert_eq!(router.mcast_member_occupancy().0, 0);
        assert_eq!(router.neighbor_count(), 0);
    }

    /// Joining local multicast groups fills the local-mcast table.
    #[test]
    fn local_mcast_groups_fill_table() {
        let mut router = CentralRouter::new(mac(1));
        let groups = [Mac::from_ipv4_multicast("224.0.0.1".parse().unwrap())];
        router.set_local_mcast_groups(&groups);
        assert_eq!(router.local_mcast_occupancy().0, 1);
    }

    /// A direct OGM registers the originator as a one-hop neighbour and fills the
    /// originator table.
    #[test]
    fn direct_ogm_counts_as_neighbor() {
        let mut router = CentralRouter::new(mac(1));
        feed_direct_ogm(&mut router, mac(2), 1, 255);
        assert_eq!(router.originator_count(), 1);
        assert_eq!(router.originator_occupancy().0, 1);
        assert_eq!(router.neighbor_count(), 1);
    }
}

#[cfg(test)]
mod keepalive_route_selection {
    use batman::wire::{BATADV_IV_OGM, BATADV_KEEPALIVE, BatmanKeepAlivePacket, BatmanOgmPacket};
    use core::time::Duration;
    use interfaces::frame::{LinkFrame, Mac};
    use zerocopy::{FromBytes, IntoBytes};

    use super::*;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    fn link_frame_bytes(src: Mac, dst: Mac, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(dst.as_bytes());
        out.extend_from_slice(src.as_bytes());
        out.extend_from_slice(&DEFAULT_BATMAN_ETHER_TYPE.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Feed one OGM for `orig`, relayed by immediate neighbor `via` on
    /// interface `iface_idx`, at instant `now`.
    fn feed_ogm_via(
        router: &mut CentralRouter,
        orig: Mac,
        via: Mac,
        iface_idx: usize,
        seqno: u32,
        tq: u8,
        now: Duration,
    ) {
        let ogm = BatmanOgmPacket {
            packet_type: BATADV_IV_OGM,
            version: 5,
            ttl: 50,
            flags: 0,
            seqno: seqno.to_be(),
            orig,
            reserved: 0,
            tq,
            tvlv_len: 0,
        };
        let bytes = link_frame_bytes(via, Mac::BROADCAST, ogm.as_bytes());
        let frame = LinkFrame::ref_from_bytes(&bytes).unwrap();
        let mut tx = [0u8; 256];
        router.handle_frame(now, iface_idx, frame, &mut tx);
    }

    /// Feed one keep-alive heartbeat from immediate neighbor `via` on
    /// interface `iface_idx`, at instant `now`.
    fn feed_keepalive_via(router: &mut CentralRouter, via: Mac, iface_idx: usize, now: Duration) {
        let pkt = BatmanKeepAlivePacket {
            packet_type: BATADV_KEEPALIVE,
            version: 5,
        };
        let bytes = link_frame_bytes(via, Mac::BROADCAST, pkt.as_bytes());
        let frame = LinkFrame::ref_from_bytes(&bytes).unwrap();
        let mut tx = [0u8; 256];
        router.handle_frame(now, iface_idx, frame, &mut tx);
    }

    /// Set up two alternate paths to `dest`: a high-TQ path via neighbor 2 on
    /// interface 0 (keep-alive armed with a 1s learned cadence), and a
    /// lower-TQ path via neighbor 3 on interface 1 (no keep-alives at all —
    /// opt-in by observation). Returns the router positioned at t=1s, right
    /// after the second keep-alive teaches the 1s cadence.
    fn build_two_paths(router: &mut CentralRouter, dest: Mac) {
        feed_ogm_via(router, dest, mac(2), 0, 1, 255, Duration::ZERO);
        feed_ogm_via(router, dest, mac(3), 1, 1, 100, Duration::ZERO);
        feed_keepalive_via(router, mac(2), 0, Duration::ZERO);
        feed_keepalive_via(router, mac(2), 0, Duration::from_secs(1));
    }

    /// `handle_local` — the primary locally-originated-traffic path — routes
    /// via the healthy alternate once the incumbent's keep-alive is missed,
    /// even though its raw OGM TQ was higher. This is the fix for the
    /// critical finding: `handle_local` used to call the cached, non-time-
    /// aware `lookup_route`, which never saw keep-alive (or even OGM)
    /// staleness until this node's own next OGM tick.
    #[test]
    fn handle_local_switches_to_live_alternate_after_keepalive_miss() {
        let mut router = CentralRouter::new(mac(1));
        let dest = mac(9);
        build_two_paths(&mut router, dest);

        let mut tx = [0u8; 256];
        let before = router
            .handle_local(Duration::from_secs(1), dest, b"hi", &mut tx)
            .unwrap();
        assert_eq!(before.dst, mac(2), "before any miss, higher TQ wins");

        let mut tx2 = [0u8; 256];
        let after = router
            .handle_local(Duration::from_secs(5), dest, b"hi", &mut tx2)
            .unwrap();
        assert_eq!(
            after.dst,
            mac(3),
            "after a missed keep-alive, the live alternate must win"
        );
    }

    /// `get_egress_interface` follows the same switch: the interface with the
    /// best link quality for the *chosen* next hop changes once the
    /// incumbent's keep-alive is missed.
    #[test]
    fn get_egress_interface_switches_after_keepalive_miss() {
        let mut router = CentralRouter::new(mac(1));
        let dest = mac(9);
        build_two_paths(&mut router, dest);

        assert_eq!(
            router.get_egress_interface(Duration::from_secs(1), dest),
            Some(EgressInterface::Interface(0)),
            "before any miss, neighbor 2's interface wins"
        );
        assert_eq!(
            router.get_egress_interface(Duration::from_secs(5), dest),
            Some(EgressInterface::Interface(1)),
            "after a missed keep-alive, neighbor 3's interface must win"
        );
    }

    /// `resolve_route` (the read-only management-API path) follows the same
    /// switch as `handle_local`/`get_egress_interface`.
    #[test]
    fn resolve_route_switches_after_keepalive_miss() {
        let mut router = CentralRouter::new(mac(1));
        let dest = mac(9);
        build_two_paths(&mut router, dest);

        let (next_hop, _) = router.resolve_route(Duration::from_secs(1), dest);
        assert_eq!(next_hop, mac(2));

        let (next_hop, _) = router.resolve_route(Duration::from_secs(5), dest);
        assert_eq!(next_hop, mac(3));
    }

    /// A router that has never heard a keep-alive reports an empty table.
    #[test]
    fn keepalive_table_empty_when_nothing_heard() {
        let router = CentralRouter::new(mac(1));
        assert_eq!(router.keepalive_table(Duration::ZERO).count(), 0);
    }

    /// `keepalive_table` reports the learned cadence and elapsed time
    /// correctly, and its `missed` flag matches the same miss/no-miss
    /// transition the route-selection tests above observe indirectly.
    #[test]
    fn keepalive_table_reports_entry_and_missed_flag() {
        let mut router = CentralRouter::new(mac(1));
        let dest = mac(9);
        build_two_paths(&mut router, dest);

        let entries: Vec<_> = router.keepalive_table(Duration::from_secs(1)).collect();
        assert_eq!(
            entries.len(),
            1,
            "only neighbor 2 has ever sent a keep-alive"
        );
        let e = entries[0];
        assert_eq!(e.neighbor, mac(2));
        assert_eq!(e.ms_since_last_heard, 0, "just heard at t=1s");
        assert_eq!(
            e.interval_estimate_ms, 1000,
            "learned from the 1s gap between the two heartbeats"
        );
        assert!(!e.missed, "within budget just after the second heartbeat");

        let entries: Vec<_> = router.keepalive_table(Duration::from_secs(5)).collect();
        let e = entries[0];
        assert_eq!(e.ms_since_last_heard, 4000);
        assert!(e.missed, "past the 3 * 1s budget since last heard at t=1s");
    }
}

#[cfg(test)]
mod tq_clamp_integration {
    //! The local-TQ clamp wired through [`CentralRouter`]: a measured poor link
    //! caps an OGM's advertised TQ, but metric-less transports (which report
    //! [`LinkMetrics::default`]) must apply no clamp — otherwise their
    //! normalized quality of 0 would wrongly zero every route.
    use super::*;
    use batman::wire::{BATADV_IV_OGM, BatmanOgmPacket};
    use core::time::Duration;
    use interfaces::frame::{LinkFrame, Mac};
    use interfaces::link::LinkMetrics;
    use zerocopy::{FromBytes, IntoBytes};

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// One direct OGM from `orig` advertising transmission quality `tq`.
    fn ogm_frame_bytes(orig: Mac, tq: u8) -> Vec<u8> {
        let ogm = BatmanOgmPacket {
            packet_type: BATADV_IV_OGM,
            version: 5,
            ttl: 50,
            flags: 0,
            seqno: 1u32.to_be(),
            orig,
            reserved: 0,
            tq,
            tvlv_len: 0,
        };
        let mut out = Vec::new();
        out.extend_from_slice(Mac::BROADCAST.as_bytes());
        out.extend_from_slice(orig.as_bytes());
        out.extend_from_slice(&DEFAULT_BATMAN_ETHER_TYPE.to_be_bytes());
        out.extend_from_slice(ogm.as_bytes());
        out
    }

    /// Metric-less transports report [`LinkMetrics::default`]; the router must
    /// not clamp, so the only reduction is the normal one-hop attenuation
    /// (255 - 10 = 245).  Guards the regression where a normalized-to-0 quality
    /// zeroed every TQ.
    #[test]
    fn metricless_frame_does_not_clamp() {
        let mut router = CentralRouter::new(mac(1));
        let bytes = ogm_frame_bytes(mac(2), 255);
        let frame = LinkFrame::ref_from_bytes(&bytes).unwrap();
        let mut tx = [0u8; 256];
        router.handle_frame(Duration::ZERO, 0, frame, &mut tx);
        assert_eq!(router.batman.originator_table[&mac(2)].max_tq, 245);
    }

    /// A real, poor measured link caps the advertised TQ at that link quality.
    #[test]
    fn measured_poor_link_clamps_tq() {
        let mut router = CentralRouter::new(mac(1));
        let bytes = ogm_frame_bytes(mac(2), 255);
        let frame = LinkFrame::ref_from_bytes(&bytes).unwrap();
        let mut tx = [0u8; 256];
        let metrics = LinkMetrics {
            rssi_dbm: None,
            snr_db: None,
            quality: Some(40),
        };
        router.handle_frame_with_metrics(Duration::ZERO, 0, frame, metrics, &mut tx);
        assert_eq!(router.batman.originator_table[&mac(2)].max_tq, 40);
    }
}

#[cfg(test)]
mod keepalive_config_validation {
    use core::time::Duration;
    use interfaces::frame::Mac;

    use super::*;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// A degenerate (zero) configured interval is floored to
    /// [`MIN_KEEPALIVE_INTERVAL`] rather than left near-zero, which would
    /// otherwise arm a `TrickleTimer` that fires on effectively every tick —
    /// a config typo turning into a self-inflicted heartbeat flood.
    #[test]
    fn configure_interface_keepalive_clamps_a_degenerate_interval() {
        let mut router = CentralRouter::new(mac(1));
        router.configure_interface_keepalive(0, Some(Duration::ZERO), Duration::ZERO);
        let armed = router.batman.keepalive_timers[0]
            .as_ref()
            .expect("interface armed");
        assert!(
            armed.i_min() >= MIN_KEEPALIVE_INTERVAL,
            "a zero interval must be floored to a sane minimum, not left at ~0"
        );
    }

    /// A sane, already-reasonable interval passes through unclamped.
    #[test]
    fn configure_interface_keepalive_leaves_a_sane_interval_unclamped() {
        let mut router = CentralRouter::new(mac(1));
        router.configure_interface_keepalive(0, Some(Duration::from_secs(5)), Duration::ZERO);
        let armed = router.batman.keepalive_timers[0]
            .as_ref()
            .expect("interface armed");
        assert_eq!(armed.i_min(), Duration::from_secs(5));
    }
}

#[cfg(test)]
mod ogm_auth_integration {
    //! End-to-end opt-in OGM auth through `CentralRouter`: a signed OGM is
    //! accepted by a same-mesh peer, an unsigned or foreign-mesh OGM is dropped
    //! when auth is on, and the unauthenticated mode is unchanged.
    use super::*;
    use core::time::Duration;
    use interfaces::frame::{LinkFrame, Mac};
    use wayfinder_auth::{Authority, Keypair};
    use zerocopy::FromBytes;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// A router for node `m` with auth enabled against `authority`'s mesh.
    fn router_with_auth(authority: &Authority, m: Mac, seed: u8) -> CentralRouter {
        let kp = Keypair::from_seed(&[seed; 32]);
        let cert = authority.issue_cert(m, kp.ed_pubkey(), kp.x_pubkey(), 0, 1000);
        let mut r = CentralRouter::new(m);
        let mut auth = crate::auth::OgmAuth::new(kp, cert, authority.trust_anchor());
        auth.set_time(100);
        r.set_auth(auth);
        r
    }

    /// Drive one OGM out of `r` and return its serialized payload.
    fn poll_ogm_bytes(r: &mut CentralRouter) -> Vec<u8> {
        let mut tx = [0u8; 1500];
        let out = r.poll(Duration::ZERO, &mut tx).expect("ogm produced");
        out.payload.to_vec()
    }

    /// Wrap an OGM payload in a broadcast LinkFrame from `src`.
    fn link_frame(src: Mac, ogm: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(Mac::BROADCAST.as_bytes());
        v.extend_from_slice(src.as_bytes());
        v.extend_from_slice(&DEFAULT_BATMAN_ETHER_TYPE.to_be_bytes());
        v.extend_from_slice(ogm);
        v
    }

    /// Feed `ogm` (from `src`) into `b` and report how many originators it learned.
    fn feed(b: &mut CentralRouter, src: Mac, ogm: &[u8]) -> usize {
        let bytes = link_frame(src, ogm);
        let frame = LinkFrame::ref_from_bytes(&bytes).unwrap();
        let mut tx = [0u8; 1500];
        b.handle_frame(Duration::ZERO, 0, frame, &mut tx);
        b.originator_count()
    }

    /// A signed OGM is accepted by a peer on the same mesh.
    #[test]
    fn signed_ogm_accepted_by_same_mesh() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = router_with_auth(&authority, mac(1), 2);
        let ogm = poll_ogm_bytes(&mut a);
        let mut b = router_with_auth(&authority, mac(2), 3);
        assert_eq!(feed(&mut b, mac(1), &ogm), 1);
    }

    /// An unsigned OGM (from a node not running auth) is dropped under auth.
    #[test]
    fn unsigned_ogm_dropped_when_auth_enabled() {
        let mut plain = CentralRouter::new(mac(1));
        let ogm = poll_ogm_bytes(&mut plain);
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = router_with_auth(&authority, mac(2), 3);
        assert_eq!(
            feed(&mut b, mac(1), &ogm),
            0,
            "unsigned OGM must be dropped under auth"
        );
    }

    /// Enabling auth at runtime resets learned routing state: a route learned
    /// while the node was open (under no auth) is dropped, so the node
    /// re-converges cleanly under the new identity/anchor.
    #[test]
    fn set_auth_resets_learned_routing_state() {
        // While open, the node learns a neighbour from an unsigned OGM.
        let mut peer = CentralRouter::new(mac(1));
        let ogm = poll_ogm_bytes(&mut peer);
        let mut node = CentralRouter::new(mac(2)); // auth off
        assert_eq!(
            feed(&mut node, mac(1), &ogm),
            1,
            "learns the neighbour while open"
        );

        // Enabling auth drops the pre-auth route.
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let kp = Keypair::from_seed(&[3; 32]);
        let cert = authority.issue_cert(mac(2), kp.ed_pubkey(), kp.x_pubkey(), 0, 1000);
        let mut auth = crate::auth::OgmAuth::new(kp, cert, authority.trust_anchor());
        auth.set_time(100);
        node.set_auth(auth);
        assert_eq!(
            node.originator_count(),
            0,
            "set_auth must reset learned routing state"
        );
    }

    /// An OGM signed for another mesh (different trust anchor) is dropped — the
    /// segregation property end to end.
    #[test]
    fn foreign_mesh_ogm_dropped() {
        let theirs = Authority::from_seed(&[9; 32], 0xABCD);
        let mut foreign = router_with_auth(&theirs, mac(1), 2);
        let ogm = poll_ogm_bytes(&mut foreign);
        let ours = Authority::from_seed(&[1; 32], 0xABCD);
        let mut b = router_with_auth(&ours, mac(2), 3);
        assert_eq!(
            feed(&mut b, mac(1), &ogm),
            0,
            "foreign-mesh OGM must be dropped"
        );
    }

    /// With auth disabled the router accepts unsigned OGMs exactly as before.
    #[test]
    fn auth_disabled_accepts_unsigned() {
        let mut plain_a = CentralRouter::new(mac(1));
        let ogm = poll_ogm_bytes(&mut plain_a);
        let mut b = CentralRouter::new(mac(2));
        assert_eq!(
            feed(&mut b, mac(1), &ogm),
            1,
            "unauthenticated mode must be unchanged"
        );
    }

    // ── `require_auth`: fail-closed until a valid cert is installed ────────────

    /// `handle_frame_with_metrics` on a `require_auth` node with no cert yet
    /// returns an empty [`RxOutcome`] (no forward, no local delivery) — the
    /// frame is dropped outright rather than merely failing an auth check.
    #[test]
    fn locked_router_returns_empty_rx_outcome() {
        let mut peer = CentralRouter::new(mac(1));
        let ogm = poll_ogm_bytes(&mut peer);
        let bytes = link_frame(mac(1), &ogm);
        let frame = LinkFrame::ref_from_bytes(&bytes).unwrap();

        let mut node = CentralRouter::new(mac(2));
        node.set_require_auth(true);
        assert!(node.auth_locked());

        let mut tx = [0u8; 1500];
        let outcome = node.handle_frame(Duration::ZERO, 0, frame, &mut tx);
        assert!(outcome.forward.is_none(), "a locked node forwards nothing");
        assert!(
            outcome.deliver_local.is_none(),
            "a locked node delivers nothing locally"
        );
    }

    /// `poll_keepalive`, like `poll`, fails closed: a `require_auth` node with
    /// no cert yet emits no keep-alive heartbeat either.
    #[test]
    fn poll_keepalive_emits_nothing_while_auth_locked() {
        let mut node = CentralRouter::new(mac(2));
        node.set_require_auth(true);
        assert!(node.auth_locked());

        let mut tx = [0u8; 64];
        assert!(node.poll_keepalive(&mut tx).is_none());
    }

    /// A `require_auth` node with no cert is inert end to end: it neither
    /// learns from nor emits any mesh traffic, and installing a valid cert via
    /// `set_auth` unlocks it so the same traffic is processed normally.
    #[test]
    fn require_auth_locks_the_router_until_a_cert_is_installed() {
        let mut peer = CentralRouter::new(mac(1));
        let ogm = poll_ogm_bytes(&mut peer);

        let mut node = CentralRouter::new(mac(2));
        node.set_require_auth(true);
        assert!(node.auth_locked(), "no cert yet: node must be locked");

        // Locked: an incoming OGM teaches it nothing.
        assert_eq!(
            feed(&mut node, mac(1), &ogm),
            0,
            "locked node must not process any frame"
        );

        // Locked: the router emits nothing on poll (total mesh silence).
        let mut tx = [0u8; 1500];
        assert!(
            node.poll(Duration::ZERO, &mut tx).is_none(),
            "locked node must not emit OGMs"
        );

        // Installing a valid cert unlocks the router.
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let kp = Keypair::from_seed(&[3; 32]);
        let cert = authority.issue_cert(mac(2), kp.ed_pubkey(), kp.x_pubkey(), 0, 1000);
        let mut auth = crate::auth::OgmAuth::new(kp, cert, authority.trust_anchor());
        auth.set_time(100);
        node.set_auth(auth);
        assert!(!node.auth_locked(), "a valid cert unlocks the router");

        // A signed OGM from a same-mesh peer is now processed normally.
        let mut authed_peer = router_with_auth(&authority, mac(1), 2);
        let signed_ogm = poll_ogm_bytes(&mut authed_peer);
        assert_eq!(
            feed(&mut node, mac(1), &signed_ogm),
            1,
            "unlocked node processes frames normally"
        );
    }

    /// The default (`require_auth = false`) is unchanged: a node with no cert
    /// still routes exactly as before — a regression guard ensuring the new
    /// fail-closed gate does not affect the open, unauthenticated mode.
    #[test]
    fn require_auth_false_is_unchanged_open_behavior() {
        let mut peer = CentralRouter::new(mac(1));
        let ogm = poll_ogm_bytes(&mut peer);
        let mut node = CentralRouter::new(mac(2)); // require_auth defaults to false
        assert!(!node.auth_locked());
        assert_eq!(
            feed(&mut node, mac(1), &ogm),
            1,
            "open mode is unchanged by the require_auth gate"
        );
    }

    /// A locked node must refuse to originate local unicast/broadcast traffic
    /// (not just refuse to process received frames) — `handle_local` is the
    /// host-egress path, exercised independently of `handle_frame`.
    #[test]
    fn locked_router_rejects_local_egress() {
        let mut node = CentralRouter::new(mac(2));
        node.set_require_auth(true);
        assert!(node.auth_locked());

        let mut tx = [0u8; 256];
        assert!(matches!(
            node.handle_local(Duration::ZERO, mac(9), b"payload", &mut tx),
            Err(LocalSendError::AuthLocked)
        ));

        // Installing a valid cert unlocks local egress too.
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let kp = Keypair::from_seed(&[3; 32]);
        let cert = authority.issue_cert(mac(2), kp.ed_pubkey(), kp.x_pubkey(), 0, 1000);
        let mut auth = crate::auth::OgmAuth::new(kp, cert, authority.trust_anchor());
        auth.set_time(100);
        node.set_auth(auth);
        assert!(!node.auth_locked());
        assert!(
            node.handle_local(Duration::ZERO, mac(9), b"payload", &mut tx)
                .is_ok()
        );
    }

    /// The same fail-closed gate applies to local multicast egress
    /// (`handle_local_mcast`), which wraps host data in a `BATADV_MCAST`
    /// packet rather than a unicast/broadcast one.
    #[test]
    fn locked_router_rejects_local_mcast_egress() {
        let mut node = CentralRouter::new(mac(2));
        node.set_require_auth(true);
        assert!(node.auth_locked());

        let mut tx = [0u8; 256];
        assert!(matches!(
            node.handle_local_mcast(Duration::ZERO, mac(9), b"payload", &mut tx),
            Err(LocalSendError::AuthLocked)
        ));

        // Installing a valid cert unlocks local multicast egress too.
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let kp = Keypair::from_seed(&[3; 32]);
        let cert = authority.issue_cert(mac(2), kp.ed_pubkey(), kp.x_pubkey(), 0, 1000);
        let mut auth = crate::auth::OgmAuth::new(kp, cert, authority.trust_anchor());
        auth.set_time(100);
        node.set_auth(auth);
        assert!(!node.auth_locked());
        assert!(
            node.handle_local_mcast(Duration::ZERO, mac(9), b"payload", &mut tx)
                .is_ok()
        );
    }

    /// The fail-closed gate must cover the data plane, not just OGMs: a
    /// well-formed `BATADV_BCAST` frame fed to a locked router must produce a
    /// wholly empty `RxOutcome` — no forward, no local delivery — guarding
    /// against a future refactor that only gates the OGM demux arm.
    #[test]
    fn locked_router_drops_a_forwarded_data_frame() {
        const INNER: &[u8] = &[0x45, 0x00, 0x00, 0x1c, 0xde, 0xad];

        let mut payload = Vec::new();
        let hdr = BatmanBroadcastPacket {
            packet_type: BATADV_BCAST,
            version: 5,
            ttl: 50,
            seqno: 7u32.to_be(),
            orig: mac(1),
        };
        payload.extend_from_slice(hdr.as_bytes());
        payload.extend_from_slice(INNER);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(Mac::BROADCAST.as_bytes());
        bytes.extend_from_slice(mac(1).as_bytes());
        bytes.extend_from_slice(&ETH_P_BATMAN.to_be_bytes());
        bytes.extend_from_slice(&payload);
        let frame = LinkFrame::ref_from_bytes(&bytes).unwrap();

        let mut node = CentralRouter::new(mac(2));
        node.set_require_auth(true);
        assert!(node.auth_locked());

        let mut tx = [0u8; 256];
        let outcome = node.handle_frame(Duration::ZERO, 0, frame, &mut tx);
        assert!(
            outcome.forward.is_none(),
            "a locked node must not forward a data-plane frame"
        );
        assert!(
            outcome.deliver_local.is_none(),
            "a locked node must not locally deliver a data-plane frame"
        );
    }

    // ── Keep-alive auth: end-to-end signing/verification through `CentralRouter` ──

    /// Feed `payload` into `b` as if received directly from `src` on
    /// `iface_idx` at `now`.
    fn feed_at(b: &mut CentralRouter, src: Mac, iface_idx: usize, payload: &[u8], now: Duration) {
        let bytes = link_frame(src, payload);
        let frame = LinkFrame::ref_from_bytes(&bytes).unwrap();
        let mut tx = [0u8; 512];
        b.handle_frame(now, iface_idx, frame, &mut tx);
    }

    /// A single spoofed keep-alive can no longer resurrect a genuinely dead
    /// neighbor's route once auth is enabled — the end-to-end regression
    /// test for the vulnerability the auth gate closes. Two alternate paths
    /// to `dest` exist: a high-TQ one via `neighbor_a`, which keep-alives,
    /// and a lower-TQ one via a second relay that never does. Once
    /// `neighbor_a`'s real keep-alives stop and its budget elapses, routing
    /// switches to the alternate (exactly like the unauthenticated case in
    /// `keepalive_route_selection`, proving legitimate keep-alives are still
    /// recorded correctly under auth) — and a forged "resurrection"
    /// keep-alive afterward, claiming to be `neighbor_a`, must not switch it
    /// back.
    #[test]
    fn forged_keepalive_cannot_resurrect_a_dead_route() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut dest = router_with_auth(&authority, mac(9), 9);
        let mut neighbor_a = router_with_auth(&authority, mac(2), 2);
        let mut router = router_with_auth(&authority, mac(1), 1);

        // `dest` originates one signed OGM; the same signed bytes are
        // relayed to `router` via two different neighbors with different
        // advertised TQ. `tq` is a mutable, unsigned-covered field (see
        // `signed_message`'s doc), safe to vary post-signing — mirroring how
        // a real relay's engine attenuates it per hop.
        let ogm_high = poll_ogm_bytes(&mut dest);
        let mut ogm_low = ogm_high.clone();
        ogm_low[15] = 100; // `tq` byte offset within `BatmanOgmPacket`
        feed_at(&mut router, mac(2), 0, &ogm_high, Duration::ZERO);
        feed_at(&mut router, mac(3), 1, &ogm_low, Duration::ZERO);

        // `neighbor_a`'s own OGM, so `router` caches its cert — a
        // precondition for keep-alive verification.
        let ogm_a = poll_ogm_bytes(&mut neighbor_a);
        feed_at(&mut router, mac(2), 0, &ogm_a, Duration::ZERO);

        // Two real, signed keep-alives from `neighbor_a` teach a ~1s cadence.
        let mut tx = [0u8; 128];
        let ka0 = neighbor_a.poll_keepalive(&mut tx).unwrap().payload.to_vec();
        feed_at(&mut router, mac(2), 0, &ka0, Duration::ZERO);
        let mut tx = [0u8; 128];
        let ka1 = neighbor_a.poll_keepalive(&mut tx).unwrap().payload.to_vec();
        feed_at(&mut router, mac(2), 0, &ka1, Duration::from_secs(1));

        let mut tx = [0u8; 256];
        let before = router
            .handle_local(Duration::from_secs(1), mac(9), b"hi", &mut tx)
            .unwrap();
        assert_eq!(before.dst, mac(2), "before any miss, higher TQ wins");

        let mut tx2 = [0u8; 256];
        let after = router
            .handle_local(Duration::from_secs(5), mac(9), b"hi", &mut tx2)
            .unwrap();
        assert_eq!(
            after.dst,
            mac(3),
            "after a missed keep-alive, the live alternate must win"
        );

        // An attacker forges a "resurrection" keep-alive claiming to be
        // `neighbor_a`, tampering a captured signature rather than holding
        // its key. It must not verify, so it must not revive the dead route.
        let mut forged = ka1.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0xff;
        feed_at(&mut router, mac(2), 0, &forged, Duration::from_secs(6));

        let mut tx3 = [0u8; 256];
        let still_after = router
            .handle_local(Duration::from_secs(6), mac(9), b"hi", &mut tx3)
            .unwrap();
        assert_eq!(
            still_after.dst,
            mac(3),
            "a forged keep-alive must not resurrect the dead route"
        );
    }
}

#[cfg(test)]
mod lazy_cert_distribution_switchover {
    //! `Config::lazy_cert_distribution` / `CentralRouter::set_lazy_cert_distribution`
    //! switch what a node *emits* on its OGMs (full cert vs. fingerprint);
    //! receiving already tolerates both unconditionally (Phase 3).

    use super::*;
    use batman::wire::{TvlvType, find_tvlv};
    use interfaces::frame::Mac;
    use wayfinder_auth::{Authority, Keypair};

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    fn router_with_auth(authority: &Authority, m: Mac, seed: u8) -> CentralRouter {
        let kp = Keypair::from_seed(&[seed; 32]);
        let cert = authority.issue_cert(m, kp.ed_pubkey(), kp.x_pubkey(), 0, 1000);
        let mut r = CentralRouter::new(m);
        let mut auth = crate::auth::OgmAuth::new(kp, cert, authority.trust_anchor());
        auth.set_time(100);
        r.set_auth(auth);
        r
    }

    /// With the flag off (the default), a router's OGMs still carry the full
    /// cert, exactly as before this feature existed.
    #[test]
    fn flag_off_emits_full_cert() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = router_with_auth(&authority, mac(1), 2);
        let mut tx = [0u8; 1500];
        let ogm = a.poll(core::time::Duration::ZERO, &mut tx).unwrap().payload;
        let hdr_len = core::mem::size_of::<batman::wire::BatmanOgmPacket>();
        assert!(find_tvlv(&ogm[hdr_len..], TvlvType::Cert).is_some());
        assert!(find_tvlv(&ogm[hdr_len..], TvlvType::CertFp).is_none());
    }

    /// With the flag on, a router's OGMs carry only the 8-byte fingerprint —
    /// zero cert bytes on the wire.
    #[test]
    fn flag_on_emits_fingerprint_only() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = router_with_auth(&authority, mac(1), 2);
        a.set_lazy_cert_distribution(true);
        let mut tx = [0u8; 1500];
        let ogm = a.poll(core::time::Duration::ZERO, &mut tx).unwrap().payload;
        let hdr_len = core::mem::size_of::<batman::wire::BatmanOgmPacket>();
        assert!(find_tvlv(&ogm[hdr_len..], TvlvType::Cert).is_none());
        assert!(find_tvlv(&ogm[hdr_len..], TvlvType::CertFp).is_some());
    }

    /// `apply_runtime_lazy_cert_distribution` has the same wire effect as the
    /// startup setter, but additionally marks `runtime_config_active` —
    /// distinguishing a live management-API override from startup wiring,
    /// which `set_lazy_cert_distribution` alone does not.
    #[test]
    fn apply_runtime_lazy_cert_distribution_marks_active_and_switches_emission() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = router_with_auth(&authority, mac(1), 2);
        assert!(!a.runtime_config_active());

        a.apply_runtime_lazy_cert_distribution(true);
        assert!(a.runtime_config_active());

        let mut tx = [0u8; 1500];
        let ogm = a.poll(core::time::Duration::ZERO, &mut tx).unwrap().payload;
        let hdr_len = core::mem::size_of::<batman::wire::BatmanOgmPacket>();
        assert!(find_tvlv(&ogm[hdr_len..], TvlvType::Cert).is_none());
        assert!(find_tvlv(&ogm[hdr_len..], TvlvType::CertFp).is_some());
    }

    /// If the transmit buffer is too small to append the cert/fingerprint +
    /// signature, `poll` must suppress the emission entirely — never fall
    /// back to broadcasting the un-augmented, unsigned OGM the engine wrote.
    /// Fail closed on the exact guarantee auth exists to provide, not open.
    #[test]
    fn augmentation_failure_suppresses_emission_rather_than_broadcasting_unsigned() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut a = router_with_auth(&authority, mac(1), 2);
        let hdr_len = core::mem::size_of::<batman::wire::BatmanOgmPacket>();
        // Room for the bare OGM header only — nowhere near enough for a
        // cert/fingerprint plus a 64-byte signature.
        let mut tx = vec![0u8; hdr_len + 8];
        assert!(
            a.poll(core::time::Duration::ZERO, &mut tx).is_none(),
            "must suppress emission rather than broadcast an unsigned OGM"
        );

        // Same for the lazy path.
        a.set_lazy_cert_distribution(true);
        assert!(a.poll(core::time::Duration::ZERO, &mut tx).is_none());
    }
}

#[cfg(test)]
mod link_features_tests {
    //! Per-link participation gating (`LinkFeatures`): receive gates drop a
    //! traffic class on ingress, and `link_may_tx` reports the transmit gates
    //! the driver fan-out consults.
    use super::*;
    use crate::features::LinkFeatures;
    use core::time::Duration;
    use interfaces::frame::{LinkFrame, Mac};
    use zerocopy::{FromBytes, IntoBytes};

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// Build the raw bytes of a link frame `[dst][src][protocol be][payload]`.
    fn link_frame(dst: Mac, src: Mac, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(dst.as_bytes());
        v.extend_from_slice(src.as_bytes());
        v.extend_from_slice(&DEFAULT_BATMAN_ETHER_TYPE.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    /// A bare 1-hop OGM payload from `orig` (header only, no TVLVs).
    fn ogm_payload(orig: Mac) -> Vec<u8> {
        batman::wire::BatmanOgmPacket {
            packet_type: BATADV_IV_OGM,
            version: 5,
            ttl: 50,
            flags: 0,
            seqno: 1u32.to_be(),
            orig,
            reserved: 0,
            tq: 255,
            tvlv_len: 0,
        }
        .as_bytes()
        .to_vec()
    }

    /// A flooded broadcast payload from `orig` carrying `inner`.
    fn bcast_payload(orig: Mac, inner: &[u8]) -> Vec<u8> {
        let mut v = BatmanBroadcastPacket {
            packet_type: BATADV_BCAST,
            version: 5,
            ttl: 50,
            seqno: 1u32.to_be(),
            orig,
        }
        .as_bytes()
        .to_vec();
        v.extend_from_slice(inner);
        v
    }

    /// A unicast payload addressed to `dest` carrying `inner`.
    fn unicast_payload(dest: Mac, inner: &[u8]) -> Vec<u8> {
        let mut v = BatmanUnicastPacket {
            packet_type: BATADV_UNICAST,
            version: 5,
            ttl: 50,
            dest,
        }
        .as_bytes()
        .to_vec();
        v.extend_from_slice(inner);
        v
    }

    /// Feed a raw link frame arriving on `iface` into `r`, returning the
    /// outcome (which borrows `raw` and `tx`).
    fn feed<'r>(
        r: &mut CentralRouter,
        iface: usize,
        raw: &'r [u8],
        tx: &'r mut [u8],
    ) -> RxOutcome<'r, 'r> {
        let frame = LinkFrame::ref_from_bytes(raw).unwrap();
        r.handle_frame(Duration::ZERO, iface, frame, tx)
    }

    /// An unconfigured interface reports full participation; every flag is set.
    #[test]
    fn unconfigured_interface_is_full_participation() {
        let r = CentralRouter::new(mac(1));
        let f = r.link_features(0);
        assert!(f.tx_ogm && f.rx_ogm && f.tx_data && f.rx_data);
        // Out-of-range index also defaults to full, never panics.
        let f = r.link_features(MAX_INTERFACES + 5);
        assert!(f.tx_ogm && f.rx_data);
    }

    /// `set_link_features` stores the features and widens the interface count so
    /// the interface is reported from registration.
    #[test]
    fn set_link_features_stores_and_registers() {
        let mut r = CentralRouter::new(mac(1));
        assert_eq!(r.num_interfaces(), 0);
        let f = LinkFeatures {
            tx_ogm: false,
            ..Default::default()
        };
        r.set_link_features(2, f);
        assert!(!r.link_features(2).tx_ogm);
        assert!(r.link_features(2).rx_ogm, "unset flags stay on");
        assert_eq!(
            r.num_interfaces(),
            3,
            "iface_count widened to cover index 2"
        );
    }

    /// `link_may_tx` maps each BATMAN sub-type to its transmit gate; cert-control
    /// and unknown sub-types are always permitted.
    #[test]
    fn link_may_tx_maps_subtype_to_gate() {
        let mut r = CentralRouter::new(mac(1));
        let f = LinkFeatures {
            tx_ogm: false,
            rx_ogm: true,
            tx_data: false,
            rx_data: true,
            ..Default::default()
        };
        r.set_link_features(0, f);
        assert!(!r.link_may_tx(0, Some(BATADV_IV_OGM)), "tx_ogm gates OGM");
        assert!(!r.link_may_tx(0, Some(BATADV_BCAST)), "tx_data gates BCAST");
        assert!(
            !r.link_may_tx(0, Some(BATADV_UNICAST)),
            "tx_data gates UNICAST"
        );
        assert!(!r.link_may_tx(0, Some(BATADV_MCAST)), "tx_data gates MCAST");
        assert!(
            r.link_may_tx(0, Some(BATADV_CERT_REQ)),
            "cert-control always allowed"
        );
        assert!(r.link_may_tx(0, None), "unknown sub-type allowed");
        // A full (unconfigured) interface permits every class.
        assert!(r.link_may_tx(1, Some(BATADV_IV_OGM)));
        assert!(r.link_may_tx(1, Some(BATADV_BCAST)));
        assert!(r.link_may_tx(1, Some(BATADV_UNICAST)));
    }

    /// `apply_runtime_link_features` overrides a registered interface, marks the
    /// router as running a runtime override, and takes effect immediately; an
    /// out-of-range index is rejected without marking the override active.
    #[test]
    fn apply_runtime_link_features_gates_on_registration() {
        let mut r = CentralRouter::new(mac(1));
        // Register interface 0 (via its OGM schedule), like startup wiring.
        r.configure_interface_ogm(
            0,
            Duration::from_secs(1),
            Duration::from_secs(8),
            Duration::ZERO,
        );
        assert_eq!(r.num_interfaces(), 1);
        assert!(!r.runtime_config_active());

        let f = LinkFeatures {
            tx_ogm: false,
            ..Default::default()
        };
        assert!(
            r.apply_runtime_link_features(0, f, Duration::ZERO),
            "registered iface accepted"
        );
        assert!(!r.link_features(0).tx_ogm, "override took effect");
        assert!(
            r.runtime_config_active(),
            "marked as running a runtime override"
        );

        // An unregistered index is rejected and does not further mutate state.
        assert!(!r.apply_runtime_link_features(9, LinkFeatures::default(), Duration::ZERO));
    }

    /// An OGM arriving on a link with `rx_ogm` disabled is dropped before the
    /// engine sees it — no originator is learned, so the link can never become a
    /// transit next hop. With `rx_ogm` on (the default), the same OGM is learned.
    #[test]
    fn rx_ogm_gate_drops_incoming_ogm() {
        let payload = ogm_payload(mac(2));
        let raw = link_frame(Mac::BROADCAST, mac(2), &payload);

        // Default (rx_ogm on): the OGM is learned.
        let mut on = CentralRouter::new(mac(1));
        let mut tx = [0u8; 1500];
        feed(&mut on, 0, &raw, &mut tx);
        assert_eq!(on.originator_count(), 1, "rx_ogm on: OGM learned");

        // rx_ogm off on iface 0: dropped, nothing learned.
        let mut off = CentralRouter::new(mac(1));
        let f = LinkFeatures {
            rx_ogm: false,
            ..Default::default()
        };
        off.set_link_features(0, f);
        let mut tx = [0u8; 1500];
        let out = feed(&mut off, 0, &raw, &mut tx);
        assert_eq!(off.originator_count(), 0, "rx_ogm off: OGM dropped");
        assert!(out.forward.is_none() && out.deliver_local.is_none());
    }

    /// Data-plane frames (broadcast and directed unicast) arriving on a link
    /// with `rx_data` disabled are dropped — not delivered, not re-flooded. With
    /// the default they are delivered.
    #[test]
    fn rx_data_gate_drops_incoming_data() {
        let bcast = link_frame(
            Mac::BROADCAST,
            mac(2),
            &bcast_payload(mac(2), &[0xDE, 0xAD, 0xBE, 0xEF]),
        );
        // A unicast addressed to this node (mac 1).
        let unicast = link_frame(
            mac(1),
            mac(2),
            &unicast_payload(mac(1), &[0x01, 0x02, 0x03]),
        );

        // Default (rx_data on): both are delivered locally.
        for raw in [&bcast, &unicast] {
            let mut on = CentralRouter::new(mac(1));
            let mut tx = [0u8; 1500];
            let out = feed(&mut on, 0, raw, &mut tx);
            assert!(out.deliver_local.is_some(), "rx_data on: delivered");
        }

        // rx_data off on iface 0: both classes dropped before the engine.
        for raw in [&bcast, &unicast] {
            let mut off = CentralRouter::new(mac(1));
            off.set_link_features(
                0,
                LinkFeatures {
                    rx_data: false,
                    ..Default::default()
                },
            );
            let mut tx = [0u8; 1500];
            let out = feed(&mut off, 0, raw, &mut tx);
            assert!(
                out.forward.is_none() && out.deliver_local.is_none(),
                "rx_data off: data frame dropped"
            );
        }
    }

    /// An OGM heard on a `tx_data`-off link is *learned* (so it is visible
    /// locally) but *not re-flooded* — the node never advertises a route to
    /// nodes it could not deliver to. With `tx_data` on, the same OGM is
    /// re-flooded (advertised). This is the anti-black-hole rule for a read-only
    /// front.
    #[test]
    fn tx_data_off_link_learns_but_does_not_readvertise_ogm() {
        let raw = link_frame(Mac::BROADCAST, mac(2), &ogm_payload(mac(2)));

        // tx_data on (default): the OGM is learned and re-flooded (advertised).
        let mut advertises = CentralRouter::new(mac(1));
        let mut tx = [0u8; 1500];
        let out = feed(&mut advertises, 0, &raw, &mut tx);
        assert_eq!(advertises.originator_count(), 1, "originator learned");
        assert!(
            out.forward.is_some(),
            "tx_data on: OGM re-flooded (advertised)"
        );

        // tx_data off: still learned (local visibility), but not re-flooded.
        let mut readonly = CentralRouter::new(mac(1));
        readonly.set_link_features(
            0,
            LinkFeatures {
                tx_data: false,
                ..Default::default()
            },
        );
        let mut tx = [0u8; 1500];
        let out = feed(&mut readonly, 0, &raw, &mut tx);
        assert_eq!(
            readonly.originator_count(),
            1,
            "tx_data off: originator still learned for local visibility"
        );
        assert!(
            out.forward.is_none(),
            "tx_data off: OGM not re-advertised, so no peer black-holes"
        );
    }
}
