use interfaces::{
    engine::{MeshRoutingEngine, RoutingAction},
    frame::{LinkFrame, LinkFrameDataMut, MeshIdentifier},
};
use tracing::warn;
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    BatmanEngine, NeighborStats, OriginatorRecord,
    wire::{BATADV_IV_OGM, BATADV_UNICAST, BatmanOgmPacket, BatmanUnicastPacket, ETH_P_BATMAN},
};

impl<const MAX_ORIGINATORS: usize, Ident: MeshIdentifier> BatmanEngine<MAX_ORIGINATORS, Ident> {
    /// Actively queries the BATMAN routing table for a given destination.
    /// Returns the immediate next-hop MAC address if a route exists.
    pub fn lookup_route(&self, destination: Ident) -> Option<Ident> {
        // Look up the final target node in our calculated originator records
        self.originator_table
            .iter()
            .find(|record| record.neighbor_ident == destination)
            .map(|record| record.best_next_hop)
    }
}

impl<const MAX_ORIGINATORS: usize, Ident> MeshRoutingEngine<Ident>
    for BatmanEngine<MAX_ORIGINATORS, Ident>
where
    Ident: MeshIdentifier,
{
    fn handle_rx<'a>(
        &mut self,
        frame: &'a LinkFrame<Ident>,
        reply: &mut LinkFrameDataMut<'a, Ident>,
    ) -> RoutingAction<Ident> {
        // Core protocol routing filter
        if frame.protocol != ETH_P_BATMAN || frame.payload.is_empty() {
            return RoutingAction::Consumed;
        }

        let src = frame.src;
        let dst = frame.dst;

        // Identify packet sub-type safely via zero-copy parsing
        match frame.payload[0] {
            BATADV_IV_OGM => {
                let parsed = BatmanOgmPacket::read_from_prefix(&frame.payload);

                let Ok((ogm, _)) = parsed else {
                    warn!("Unable to parse OGM Packet");
                    return RoutingAction::Consumed;
                };

                let orig_ident = ogm.orig;

                // Rule 1: Drop our own looped back OGMs
                if orig_ident == self.self_ident {
                    return RoutingAction::Consumed;
                }

                let incoming_seqno = u32::from_be(ogm.seqno);

                // Look for or initialize the originator destination entry
                let mut record_idx = self
                    .originator_table
                    .iter()
                    .position(|r| r.neighbor_ident == orig_ident);

                if record_idx.is_none() {
                    if self.originator_table.len() >= MAX_ORIGINATORS {
                        return RoutingAction::Consumed; // Table full, drop packet
                    }
                    let new_record = OriginatorRecord {
                        neighbor_ident: ogm.orig,
                        best_next_hop: frame.src,
                        max_tq: 0,
                        last_seqno: 0,
                        paths: heapless::Vec::new(),
                    };
                    let _ = self.originator_table.push(new_record);
                    record_idx = Some(self.originator_table.len() - 1);
                }

                let record = &mut self.originator_table[record_idx.unwrap()];

                // Rule 2: Evaluate if this OGM is fresh sequence metadata
                // (Simplified sequence check for baseline demonstration)
                if incoming_seqno >= record.last_seqno {
                    record.last_seqno = incoming_seqno;

                    // Simple path metric attenuation (echoing back path quality drop)
                    let computed_tq = ogm.tq.saturating_sub(10);

                    // Track path via this specific immediate neighbor
                    if let Some(path) = record.paths.iter_mut().find(|p| p.neighbor_ident == src) {
                        path.last_tq = computed_tq;
                        path.last_seqno = incoming_seqno;
                    } else if record.paths.len() < 4 {
                        let _ = record.paths.push(NeighborStats {
                            neighbor_ident: frame.src,
                            last_tq: computed_tq,
                            last_seqno: incoming_seqno,
                        });
                    }

                    // Update routing table selection if this path has superior quality
                    if computed_tq >= record.max_tq {
                        record.max_tq = computed_tq;
                        record.best_next_hop = frame.src;
                    }

                    // --- REACTIVE STEP: Forward OGM (Flood Routing Propagation) ---
                    // Lower TTL to prevent routing infinity storms
                    if ogm.ttl > 1 {
                        let mut outbound_ogm = ogm;
                        outbound_ogm.ttl -= 1;
                        outbound_ogm.tq = computed_tq;
                        outbound_ogm.prev_sender = self.self_ident;

                        // Write bytes into the ephemeral execution buffer provided by caller
                        let size = core::mem::size_of::<BatmanOgmPacket<Ident>>();

                        reply.dst = Ident::BROADCAST;
                        reply.protocol = ETH_P_BATMAN;
                        reply
                            .payload
                            .get_mut(0..size)
                            .unwrap()
                            .copy_from_slice(&outbound_ogm.as_bytes()[..size]);

                        return RoutingAction::Consumed;
                    }
                }
                RoutingAction::Consumed
            }

            BATADV_UNICAST => {
                let parsed = BatmanUnicastPacket::read_from_prefix(&frame.payload);
                if parsed.is_err() {
                    return RoutingAction::Consumed;
                }
                let (unicast_hdr, _) = parsed.unwrap();
                let dst = unicast_hdr.dest;

                // Rule 1: Is this packet meant for US?
                if dst == self.self_ident {
                    // Yes! Return a modified action so the central router knows
                    // to strip the header and deliver just the inner application data payload.
                    return RoutingAction::DeliverLocal;
                }

                // Rule 2: Check TTL to prevent infinite routing bouncing
                if unicast_hdr.ttl <= 1 {
                    return RoutingAction::Consumed; // Drop packet, expired
                }

                // Rule 3: We are an intermediate relay node. Look up the next hop for the final destination.
                if let Some(record) = self
                    .originator_table
                    .iter()
                    .find(|r| r.neighbor_ident == dst)
                {
                    // Re-write the mutable scratchpad/response buffer with the updated header
                    let mut updated_hdr = unicast_hdr;
                    updated_hdr.ttl -= 1;

                    let size = core::mem::size_of::<BatmanUnicastPacket<Ident>>();

                    reply.dst = record.best_next_hop;
                    reply.protocol = ETH_P_BATMAN;
                    reply
                        .payload
                        .get_mut(0..size)
                        .unwrap()
                        .copy_from_slice(updated_hdr.as_bytes());
                }

                RoutingAction::Consumed // Route unknown, drop packet
            }

            // Unicast payload frames routing paths
            _ => {
                if dst == self.self_ident {
                    RoutingAction::DeliverLocal
                } else if let Some(record) = self
                    .originator_table
                    .iter()
                    .find(|r| r.neighbor_ident == dst)
                {
                    // Forwarding decision dictated dynamically by current best path lookup
                    RoutingAction::ForwardTo(record.best_next_hop)
                } else {
                    RoutingAction::Consumed // No path known, drop packet
                }
            }
        }
    }

    fn produce_periodic_broadcast(&mut self, _now: core::time::Duration) -> Option<&[u8]> {
        // Increment sequence allocation for this ticker frame
        self.sequence_number = self.sequence_number.wrapping_add(1);

        let ogm = BatmanOgmPacket {
            packet_type: BATADV_IV_OGM,
            version: 5,
            ttl: 50,
            tq: 255, // Max link capability score from original anchor source
            seqno: self.sequence_number.to_be(),
            orig: self.self_ident,
            prev_sender: self.self_ident,
        };

        let size = core::mem::size_of::<BatmanOgmPacket<Ident>>();
        self.tx_buffer[..size].copy_from_slice(ogm.as_bytes());
        Some(&self.tx_buffer[..size])
    }
}
