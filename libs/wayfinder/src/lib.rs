#![cfg_attr(not(test), no_std)]

pub use batman;
pub use interfaces;

use batman::{
    BatmanEngine,
    wire::{
        BATADV_BCAST, BATADV_MCAST, BATADV_UNICAST, BatmanBroadcastPacket, BatmanMcastPacket,
        BatmanUnicastPacket, ETH_P_BATMAN,
    },
};
use interfaces::{
    engine::{MeshRoutingEngine, RoutingAction},
    frame::{LinkFrame, LinkFrameData, LinkFrameDataMut, Mac},
    link::LinkMetrics,
};
use pretty_hex::pretty_hex;
use tracing::{trace, warn};
use zerocopy::IntoBytes;

use crate::{
    link_quality::{LinkQualityTable, normalize_quality},
    routing_table::IdentTable,
};

pub use crate::link_quality::LinkQualityRecord;

#[cfg(feature = "alloc")]
pub mod config;

mod link_quality;
mod routing_table;

pub const DEFAULT_BATMAN_ETHER_TYPE: u16 = 0x4305;

/// Maximum number of interested listeners for which a multicast frame is sent
/// as individual unicasts before falling back to flooding, matching the spirit
/// of batman-adv's multicast fanout limit.  Beyond this count, flooding is
/// cheaper than many point-to-point copies.
pub const MCAST_FANOUT: usize = 16;

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
    /// The Batman routing engine for this router
    batman: BatmanEngine<100>,
    ident_table: IdentTable<Mac>,
    link_quality: LinkQualityTable<Mac>,
}

impl CentralRouter {
    pub fn new(self_ident: Mac) -> Self {
        Self {
            batman: BatmanEngine::new(self_ident),
            ident_table: IdentTable::new(),
            link_quality: LinkQualityTable::new(),
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
        iface_idx: usize,
        frame: &'rx LinkFrame,
        tx_buf: &'tx mut [u8],
    ) -> RxOutcome<'rx, 'tx> {
        self.handle_frame_with_metrics(iface_idx, frame, LinkMetrics::default(), tx_buf)
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
        iface_idx: usize,
        frame: &'rx LinkFrame,
        metrics: LinkMetrics,
        tx_buf: &'tx mut [u8],
    ) -> RxOutcome<'rx, 'tx> {
        let src = frame.src;
        let dst = frame.dst;
        let protocol = frame.protocol;
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

        // 1. Add a record to the identifier table
        self.ident_table.add_record(iface_idx, frame.dst);
        // 2. Demux by Protocol ID
        match frame.protocol {
            DEFAULT_BATMAN_ETHER_TYPE => {
                let mut reply: LinkFrameDataMut<'_> = tx_buf.into();

                // BATMAN-adv Protocol ID
                let action = self.batman.handle_rx(frame, &mut reply);
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
    /// once per target of a [`McastPlan::Unicast`].  Returns `Err(())` if the
    /// header plus `payload` would not fit in `tx_buf`.
    pub fn handle_local_mcast<'a>(
        &mut self,
        dest: Mac,
        payload: &[u8],
        tx_buf: &'a mut [u8],
    ) -> Result<LinkFrameData<'a>, ()> {
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
            return Err(());
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

    /// Wrap host data destined for `dest` in the appropriate BATMAN packet,
    /// ready to hand to a link.  A `dest` of [`MeshIdentifier::BROADCAST`]
    /// produces a flooded [`BatmanBroadcastPacket`] (e.g. for a host ARP);
    /// any other destination produces a [`BatmanUnicastPacket`] routed toward
    /// the best-known next hop.  Returns `Err(())` if `payload` plus the
    /// header would not fit in `tx_buf`.
    ///
    /// [`MeshIdentifier::BROADCAST`]: interfaces::frame::MeshIdentifier::BROADCAST
    pub fn handle_local<'a>(
        &mut self,
        dest: Mac,
        payload: &[u8],
        tx_buf: &'a mut [u8],
    ) -> Result<LinkFrameData<'a>, ()> {
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
                return Err(());
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
            return Err(());
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

    pub fn originator_table(&self) -> &[batman::OriginatorRecord] {
        &self.batman.originator_table
    }

    /// Borrow the link-quality table for inspection.  Read-only mirror of
    /// the structure the data plane mutates on every received frame.
    pub fn link_quality_records(&self) -> &[LinkQualityRecord<Mac>] {
        self.link_quality.records()
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

    /// Serialise a `LinkFrame` ([src][dst][proto NE][payload]).
    fn link_frame_bytes(src: u8, dst: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(mac(src).as_bytes());
        v.extend_from_slice(mac(dst).as_bytes());
        v.extend_from_slice(&ETH_P_BATMAN.to_ne_bytes());
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
        let outcome = router.handle_frame(0, frame, &mut tx);

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
        let outcome = router.handle_frame(0, frame, &mut tx);

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

    /// Serialise a `LinkFrame` ([src][dst][proto NE][payload]).
    fn link_frame_bytes(src: Mac, dst: Mac, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(src.as_bytes());
        v.extend_from_slice(dst.as_bytes());
        v.extend_from_slice(&ETH_P_BATMAN.to_ne_bytes());
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
        router.handle_frame(0, frame, &mut tx);
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
