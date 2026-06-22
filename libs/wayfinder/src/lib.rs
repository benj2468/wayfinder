#![cfg_attr(not(any(test, feature = "std")), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub use batman;
pub use interfaces;

use batman::{
    BatmanEngine,
    wire::{
        BATADV_BCAST, BATADV_MCAST, BATADV_UNICAST, BatmanBroadcastPacket, BatmanMcastPacket,
        BatmanUnicastPacket, ETH_P_BATMAN,
    },
};
use core::time::Duration;
use interfaces::{
    engine::{MeshRoutingEngine, RoutingAction},
    frame::{LinkFrame, LinkFrameData, LinkFrameDataMut, Mac},
    link::LinkMetrics,
};
use pretty_hex::pretty_hex;
use tracing::warn;
use zerocopy::IntoBytes;

use crate::{
    link_quality::{LinkQualityTable, normalize_quality},
    routing_table::IdentTable,
};

pub use crate::link_quality::LinkQualityRecord;

#[cfg(feature = "alloc")]
pub mod config;

pub mod link;

mod link_quality;
mod routing_table;

pub const DEFAULT_BATMAN_ETHER_TYPE: u16 = 0x4305;

/// Maximum number of interested listeners for which a multicast frame is sent
/// as individual unicasts before falling back to flooding, matching the spirit
/// of batman-adv's multicast fanout limit.  Beyond this count, flooding is
/// cheaper than many point-to-point copies.
pub const MCAST_FANOUT: usize = 16;

/// Error returned by [`CentralRouter::handle_local`] and
/// [`CentralRouter::handle_local_mcast`] when the packet header plus the
/// caller's payload do not fit in the supplied transmit buffer.  The caller
/// should retry with a larger `tx_buf` (or drop the frame); no bytes are
/// written to the buffer when this is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferTooSmall;

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
}

impl CentralRouter {
    pub fn new(self_ident: Mac) -> Self {
        Self {
            batman: BatmanEngine::new(self_ident),
            ident_table: IdentTable::new(),
            link_quality: LinkQualityTable::new(),
            rx_rates: [RateEstimator::default(); MAX_INTERFACES],
            tx_rates: [RateEstimator::default(); MAX_INTERFACES],
            iface_count: 0,
        }
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
    /// any inner payload to deliver to the local host.
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
        let span = tracing::trace_span!("handle_frame", iface_idx, ?src, ?dst, ?protocol);
        let _enter = span.enter();
        tracing::trace!("{}", pretty_hex(&&frame.payload));

        tx_buf.fill(0);
        // 0. Update the link-quality table for the sender, keyed on the
        //    interface this frame arrived on.  Done before any further
        //    processing so even frames that the upper layers drop still
        //    contribute their signal information.
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
        //     received throughput on the wire.
        self.record_rx(iface_idx, link_frame_wire_len(frame.payload.len()), now);

        // 1. Add a record to the identifier table
        self.ident_table.add_record(iface_idx, frame.dst);
        // 2. Demux by Protocol ID
        match frame.protocol.get() {
            DEFAULT_BATMAN_ETHER_TYPE => {
                let mut reply: LinkFrameDataMut<'_> = tx_buf.into();

                // BATMAN-adv Protocol ID
                let action = self.batman.handle_rx(now, frame, local_quality, &mut reply);
                tracing::debug!(
                    "Post-action reply: dst={:?}, protocol={:?}",
                    reply.dst,
                    reply.protocol
                );
                match action {
                    RoutingAction::Consumed => {
                        // Trim the payload to the incoming frame size so that
                        // trailing zeros from the scratchpad buffer are not
                        // forwarded on the wire.
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
                    RoutingAction::DeliverLocal => {
                        // Hand the inner frame up to the local host, stripping
                        // the BATMAN header that carried it here.
                        RxOutcome {
                            forward: None,
                            deliver_local: frame.payload.get(Self::inner_offset(&frame.payload)..),
                        }
                    }
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
                tracing::debug!("received experimental protocol frame");
                // Dynamically route to a completely separate experimental protocol context
                RxOutcome::empty()
            }
            _ => {
                warn!("Dropped unknown protocol frame");
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
            _ => 0,
        }
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
    /// [`BufferTooSmall`] if the header plus `payload` would not fit in
    /// `tx_buf`.
    pub fn handle_local_mcast<'a>(
        &mut self,
        dest: Mac,
        payload: &[u8],
        tx_buf: &'a mut [u8],
    ) -> Result<LinkFrameData<'a>, BufferTooSmall> {
        let next_hop = self.batman.lookup_route(dest).unwrap_or(dest);

        let header = BatmanMcastPacket {
            packet_type: BATADV_MCAST,
            version: 5,
            ttl: 50,
            dest,
        };
        let header_size = core::mem::size_of::<BatmanMcastPacket>();
        let total_size = header_size + payload.len();
        if total_size > tx_buf.len() {
            return Err(BufferTooSmall);
        }
        tx_buf[..header_size].copy_from_slice(header.as_bytes());
        tx_buf[header_size..total_size].copy_from_slice(payload);

        Ok(LinkFrameData {
            dst: next_hop,
            protocol: ETH_P_BATMAN,
            payload: &tx_buf[..total_size],
        })
    }

    #[tracing::instrument(skip_all, level = "info")]
    pub fn poll<'tx>(
        &mut self,
        now: core::time::Duration,
        tx_buf: &'tx mut [u8],
    ) -> Option<LinkFrameData<'tx>> {
        // 3. Handle BATMAN outgoing maintenance ticks
        let broadcast = Mac::BROADCAST;
        if let Some(ogm_payload) = self.batman.produce_periodic_broadcast(now, tx_buf) {
            let ogm = LinkFrameData {
                dst: broadcast,
                protocol: DEFAULT_BATMAN_ETHER_TYPE,
                payload: ogm_payload,
            };
            // Flood the OGM out of every radio interface to map the surrounding topology
            return Some(ogm);
        }
        None
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

    /// Wrap host data destined for `dest` in the appropriate BATMAN packet,
    /// ready to hand to a link.  A `dest` of [`MeshIdentifier::BROADCAST`]
    /// produces a flooded [`BatmanBroadcastPacket`] (e.g. for a host ARP);
    /// any other destination produces a [`BatmanUnicastPacket`] routed toward
    /// the best-known next hop.  Returns [`BufferTooSmall`] if `payload` plus
    /// the header would not fit in `tx_buf`.
    ///
    /// [`MeshIdentifier::BROADCAST`]: interfaces::frame::MeshIdentifier::BROADCAST
    pub fn handle_local<'a>(
        &mut self,
        dest: Mac,
        payload: &[u8],
        tx_buf: &'a mut [u8],
    ) -> Result<LinkFrameData<'a>, BufferTooSmall> {
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
                return Err(BufferTooSmall);
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
        let next_hop = if let Some(next_hop) = self.batman.lookup_route(dest) {
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
            return Err(BufferTooSmall);
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
    pub fn get_egress_interface(&mut self, dest: Mac) -> Option<EgressInterface> {
        if dest == Mac::BROADCAST {
            return Some(EgressInterface::All);
        }

        let next_hop = self.batman.lookup_route(dest).unwrap_or(dest);

        if let Some(iface) = self.link_quality.best_interface_for(next_hop) {
            return Some(EgressInterface::Interface(iface));
        }

        self.ident_table
            .get_egress_interface(dest)
            .map(EgressInterface::Interface)
    }

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
    /// `next_hop` mirrors the `lookup_route(dest).unwrap_or(dest)`
    /// fallback used inside [`handle_local`] — when no BATMAN route is
    /// known the router will try to reach `dest` directly.
    ///
    /// The egress value is `None` when no link-quality or last-seen
    /// information exists for the destination; in that state the data
    /// plane has nothing to transmit on either.
    ///
    /// [`handle_local`]: CentralRouter::handle_local
    /// [`get_egress_interface`]: CentralRouter::get_egress_interface
    pub fn resolve_route(&self, dest: Mac) -> (Mac, Option<EgressInterface>) {
        if dest == Mac::BROADCAST {
            return (Mac::BROADCAST, Some(EgressInterface::All));
        }

        let next_hop = self.batman.lookup_route(dest).unwrap_or(dest);

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

    /// Local egress: a host frame addressed to the broadcast Ident must be
    /// wrapped in a BatmanBroadcastPacket (not a unicast) so it floods.
    #[test]
    fn local_broadcast_frame_is_wrapped_as_broadcast() {
        let mut router: CentralRouter = CentralRouter::new(mac(1));

        let mut tx = [0u8; 256];
        let out = router
            .handle_local(Mac::BROADCAST, INNER, &mut tx)
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
mod mcast_forwarding {
    //! Selective multicast forwarding: a multicast frame is sent as an
    //! individual [`BATADV_MCAST`] packet to each interested originator when
    //! the listener count is within [`MCAST_FANOUT`], else flooded.

    use super::*;
    use batman::wire::{
        BATADV_IV_OGM, BATADV_MCAST, BATADV_TVLV_MCAST, BatmanMcastPacket, BatmanOgmPacket,
        BatmanTvlvHdr,
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
            tvlv_type: BATADV_TVLV_MCAST,
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
            prev_sender: orig,
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
            .handle_local_mcast(mac(7), INNER, &mut tx)
            .expect("mcast packet should build");

        assert_eq!(out.protocol, ETH_P_BATMAN);
        let (hdr, rest) = BatmanMcastPacket::ref_from_prefix(out.payload).unwrap();
        assert_eq!(hdr.packet_type, BATADV_MCAST);
        assert_eq!(hdr.dest, mac(7));
        assert!(hdr.ttl > 1);
        assert_eq!(&rest[..INNER.len()], INNER);
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
    /// given transmission quality.  `prev_sender == orig` and full TTL make it a
    /// one-hop path.
    fn feed_direct_ogm(router: &mut CentralRouter, orig: Mac, seqno: u32, tq: u8) {
        let ogm = BatmanOgmPacket {
            packet_type: BATADV_IV_OGM,
            version: 5,
            ttl: 50,
            flags: 0,
            seqno: seqno.to_be(),
            orig,
            prev_sender: orig,
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
            prev_sender: orig,
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
