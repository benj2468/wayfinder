#![cfg_attr(not(test), no_std)]

pub use batman;
pub use interfaces;

use core::marker::PhantomData;

use batman::{
    BatmanEngine,
    wire::{BATADV_UNICAST, BatmanUnicastPacket, ETH_P_BATMAN},
};
use interfaces::{
    engine::{MeshRoutingEngine, RoutingAction},
    frame::{LinkFrame, LinkFrameData, LinkFrameDataMut, MeshIdentifier},
    link::LinkMetrics,
};
use tracing::{trace, warn};
use zerocopy::IntoBytes;

use crate::{
    link_quality::{LinkQualityTable, normalize_quality},
    routing_table::IdentTable,
};

pub use crate::link_quality::LinkQualityRecord;

mod link_quality;
mod routing_table;

pub const DEFAULT_BATMAN_ETHER_TYPE: u16 = 0x4305;

/// The egress decision returned by [`CentralRouter::get_egress_interface`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressInterface {
    /// Send out every interface — used for broadcast destinations and for
    /// any destination the router has not yet observed.
    All,
    /// Send out a specific physical interface by its index.
    Interface(usize),
}

pub struct CentralRouter<Ident: MeshIdentifier> {
    /// The Batman routing engine for this router
    batman: BatmanEngine<100, Ident>,
    ident_table: IdentTable<Ident>,
    link_quality: LinkQualityTable<Ident>,
    phantom: PhantomData<Ident>,
}

impl<Ident: MeshIdentifier> CentralRouter<Ident> {
    pub fn new(self_ident: Ident) -> Self {
        Self {
            batman: BatmanEngine::new(self_ident),
            phantom: PhantomData,
            ident_table: IdentTable::new(),
            link_quality: LinkQualityTable::new(),
        }
    }
}

impl<Ident: MeshIdentifier + 'static> CentralRouter<Ident> {
    /// Process a received link-layer frame without any physical-layer
    /// metrics — equivalent to calling [`handle_frame_with_metrics`] with
    /// [`LinkMetrics::default`].  Useful for tests and for links that
    /// cannot report per-frame signal information.
    ///
    /// [`handle_frame_with_metrics`]: CentralRouter::handle_frame_with_metrics
    pub fn handle_frame<'tx>(
        &mut self,
        iface_idx: usize,
        frame: &LinkFrame<Ident>,
        tx_buf: &'tx mut [u8],
    ) -> Option<LinkFrameData<'tx, Ident>> {
        self.handle_frame_with_metrics(iface_idx, frame, LinkMetrics::default(), tx_buf)
    }

    /// Process a received link-layer frame, folding the radio's
    /// physical-layer metrics for `frame.src` into the per-(neighbor,
    /// interface) link-quality table.  The egress decision for that
    /// neighbor will be biased toward whichever interface accumulates the
    /// highest smoothed quality.
    pub fn handle_frame_with_metrics<'tx>(
        &mut self,
        iface_idx: usize,
        frame: &LinkFrame<Ident>,
        metrics: LinkMetrics,
        tx_buf: &'tx mut [u8],
    ) -> Option<LinkFrameData<'tx, Ident>> {
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
                let mut reply: LinkFrameDataMut<'_, Ident> = tx_buf.into();

                // BATMAN-adv Protocol ID
                match self.batman.handle_rx(frame, &mut reply) {
                    RoutingAction::Consumed => {
                        // Trim the payload to the incoming frame size so that
                        // trailing zeros from the scratchpad buffer are not
                        // forwarded on the wire.
                        if reply.protocol != 0 {
                            let len = frame.payload.len().min(reply.payload.len());
                            Some(LinkFrameData {
                                dst: reply.dst,
                                protocol: reply.protocol,
                                payload: &reply.payload[..len],
                            })
                        } else {
                            None
                        }
                    }
                    RoutingAction::ForwardTo(next_hop) => {
                        // BATMAN told us this packet needs to keep moving.
                        // Re-transmit it out to the designated next-hop neighbor.
                        let len = frame.payload.len().min(reply.payload.len());
                        reply.payload[..len].copy_from_slice(&frame.payload[..len]);
                        Some(LinkFrameData {
                            dst: next_hop,
                            protocol: DEFAULT_BATMAN_ETHER_TYPE,
                            payload: &reply.payload[..len],
                        })
                    }
                    RoutingAction::DeliverLocal => {
                        if reply.protocol != 0 {
                            Some(reply.into())
                        } else {
                            None
                        }
                    }
                }
            }
            0x88B5 => {
                // Dynamically route to a completely separate experimental protocol context
                None
            }
            _ => {
                warn!("Dropped unknown protocol frame");
                None
            }
        }
    }

    pub fn poll<'tx>(
        &mut self,
        now: core::time::Duration,
        tx_buf: &'tx mut [u8],
    ) -> Option<LinkFrameData<'tx, Ident>> {
        // 3. Handle BATMAN outgoing maintenance ticks
        let broadcast = Ident::BROADCAST;
        if let Some(ogm_payload) = self.batman.produce_periodic_broadcast(now, tx_buf) {
            trace!("transmitting OGM");
            // Flood the OGM out of every radio interface to map the surrounding topology
            return Some(LinkFrameData {
                dst: broadcast,
                protocol: DEFAULT_BATMAN_ETHER_TYPE,
                payload: ogm_payload,
            });
        }
        None
    }

    pub fn handle_local<'a>(
        &mut self,
        dest: Ident,
        payload: &[u8],
        tx_buf: &'a mut [u8],
    ) -> Result<LinkFrameData<'a, Ident>, ()> {
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
        let header_size = core::mem::size_of::<BatmanUnicastPacket<Ident>>();
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
    pub fn get_egress_interface(&mut self, dest: Ident) -> Option<EgressInterface> {
        if dest == Ident::BROADCAST {
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

    pub fn self_ident(&self) -> Ident {
        self.batman.self_ident
    }

    pub fn originator_table(&self) -> &[batman::OriginatorRecord<Ident>] {
        &self.batman.originator_table
    }

    /// Borrow the link-quality table for inspection.  Read-only mirror of
    /// the structure the data plane mutates on every received frame.
    pub fn link_quality_records(&self) -> &[LinkQualityRecord<Ident>] {
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
    pub fn resolve_route(&self, dest: Ident) -> (Ident, Option<EgressInterface>) {
        if dest == Ident::BROADCAST {
            return (Ident::BROADCAST, Some(EgressInterface::All));
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
