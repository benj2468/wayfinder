use interfaces::{
    engine::{MeshRoutingEngine, RoutingAction},
    frame::{LinkFrame, LinkFrameDataMut, Mac},
};
use tracing::trace;
use tracing::warn;
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    BatmanEngine, NeighborStats, OriginatorRecord,
    wire::{
        BATADV_BCAST, BATADV_IV_OGM, BATADV_MCAST, BATADV_TVLV_MCAST, BATADV_UNICAST,
        BatmanBroadcastPacket, BatmanMcastPacket, BatmanOgmPacket, BatmanTvlvHdr,
        BatmanUnicastPacket, ETH_P_BATMAN, find_tvlv,
    },
};

impl<const MAX_ORIGINATORS: usize> BatmanEngine<MAX_ORIGINATORS> {
    /// Actively queries the BATMAN routing table for a given destination.
    /// Returns the immediate next-hop MAC address if a route exists.
    pub fn lookup_route(&self, destination: Mac) -> Option<Mac> {
        // Look up the final target node in our calculated originator records
        self.originator_table
            .iter()
            .find(|record| record.neighbor_ident == destination)
            .map(|record| record.best_next_hop)
    }

    /// Replace the set of multicast groups the local host listens to.  These
    /// are announced to the mesh in the multicast TVLV of every OGM this node
    /// produces.  Groups beyond [`MAX_LOCAL_MCAST`] are dropped.
    ///
    /// [`MAX_LOCAL_MCAST`]: crate::MAX_LOCAL_MCAST
    pub fn set_local_mcast_groups(&mut self, groups: &[Mac]) {
        self.local_mcast.clear();
        for g in groups {
            if self.local_mcast.push(*g).is_err() {
                break; // table full; drop the rest
            }
        }
    }

    /// The multicast groups the local host currently listens to.
    pub fn local_mcast_groups(&self) -> &[Mac] {
        &self.local_mcast
    }

    /// Iterate the originators that have announced interest in `group`.
    /// Drives selective multicast forwarding.
    pub fn mcast_listeners(&self, group: Mac) -> impl Iterator<Item = Mac> + '_ {
        self.mcast_members
            .iter()
            .filter(move |(g, _)| *g == group)
            .map(|(_, m)| *m)
    }

    /// Replace `orig`'s recorded multicast memberships with the groups carried
    /// in `tail` (the TVLV region following an OGM header).  An OGM with no
    /// multicast TVLV prunes all of `orig`'s memberships.  Called when an OGM
    /// is accepted; keeps [`Self::mcast_members`] in sync with the latest
    /// announcement from each originator.
    fn update_mcast_membership(&mut self, orig: Mac, tail: &[u8]) {
        // Drop every membership currently attributed to this originator;
        // the incoming announcement is authoritative for it.
        let mut i = 0;
        while i < self.mcast_members.len() {
            if self.mcast_members[i].1 == orig {
                self.mcast_members.swap_remove(i);
            } else {
                i += 1;
            }
        }

        // Re-add the groups the originator now announces (6 bytes per MAC).
        if let Some(value) = find_tvlv(tail, BATADV_TVLV_MCAST) {
            for chunk in value.chunks_exact(6) {
                let mut bytes = [0u8; 6];
                bytes.copy_from_slice(chunk);
                if self.mcast_members.push((Mac(bytes), orig)).is_err() {
                    break; // table full; drop the rest
                }
            }
        }
    }
}

impl<const MAX_ORIGINATORS: usize> MeshRoutingEngine for BatmanEngine<MAX_ORIGINATORS> {
    #[tracing::instrument(skip(self, frame, reply), fields(self_ident = ?self.self_ident), level = "trace", ret)]
    fn handle_rx<'rx, 'tx>(
        &mut self,
        frame: &'tx LinkFrame,
        reply: &mut LinkFrameDataMut<'rx>,
    ) -> RoutingAction {
        let src = frame.src;
        let dst = frame.dst;
        let protocol = frame.protocol;

        tracing::trace!(
            "handling src = {:?}, dest = {:?}, proto = {:?}, payload_len = {:?}",
            src,
            dst,
            protocol,
            frame.payload.len()
        );

        // Core protocol routing filter
        if frame.protocol != ETH_P_BATMAN || frame.payload.is_empty() {
            return RoutingAction::Consumed;
        }

        // Identify packet sub-type safely via zero-copy parsing
        match frame.payload[0] {
            BATADV_IV_OGM => {
                let parsed = BatmanOgmPacket::read_from_prefix(&frame.payload);

                let Ok((ogm, _)) = parsed else {
                    warn!("Unable to parse OGM Packet");
                    return RoutingAction::Consumed;
                };

                trace!("parsed OGM packet: {:?}", ogm);

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

                    // Fold this originator's multicast memberships (carried in
                    // the OGM's TVLV tail) into the membership table.  The
                    // `record` borrow has ended above, so taking `&mut self`
                    // here is fine.
                    let header_size = core::mem::size_of::<BatmanOgmPacket>();
                    let tail = frame.payload.get(header_size..).unwrap_or(&[]);
                    self.update_mcast_membership(orig_ident, tail);

                    // --- REACTIVE STEP: Forward OGM (Flood Routing Propagation) ---
                    // Lower TTL to prevent routing infinity storms
                    if ogm.ttl > 1 {
                        let mut outbound_ogm = ogm;
                        outbound_ogm.ttl -= 1;
                        outbound_ogm.tq = computed_tq;
                        outbound_ogm.prev_sender = self.self_ident;

                        // Write the fixed header into the caller's scratchpad,
                        // then copy the TVLV tail (membership announcements)
                        // verbatim from the incoming frame so it propagates
                        // unchanged with the re-flooded OGM.
                        let size = core::mem::size_of::<BatmanOgmPacket>();
                        let tvlv_len = u16::from_be(ogm.tvlv_len) as usize;
                        let total = size + tvlv_len;

                        reply.dst = Mac::BROADCAST;
                        reply.protocol = ETH_P_BATMAN;
                        reply
                            .payload
                            .get_mut(0..size)
                            .unwrap()
                            .copy_from_slice(&outbound_ogm.as_bytes()[..size]);
                        if let (Some(dst), Some(src)) = (
                            reply.payload.get_mut(size..total),
                            frame.payload.get(size..total),
                        ) {
                            dst.copy_from_slice(src);
                        }

                        return RoutingAction::Consumed;
                    }
                }
                RoutingAction::Consumed
            }

            BATADV_BCAST => {
                let parsed = BatmanBroadcastPacket::read_from_prefix(&frame.payload);

                let Ok((bcast, inner)) = parsed else {
                    warn!("Unable to parse Broadcast Packet");
                    return RoutingAction::Consumed;
                };

                trace!("parsed broadcast packet: {:?}", bcast);

                let orig_ident = bcast.orig;

                // Rule 1: never act on our own broadcast looping back.
                if orig_ident == self.self_ident {
                    return RoutingAction::Consumed;
                }

                let incoming_seqno = u32::from_be(bcast.seqno);

                // Rule 2: deduplicate on (orig, seqno).  A broadcast arriving
                // via several paths must be flooded onward only once, or it
                // would circulate forever on a cyclic mesh.
                if let Some(entry) = self.broadcast_seqno.iter_mut().find(|e| e.0 == orig_ident) {
                    if incoming_seqno <= entry.1 {
                        return RoutingAction::Consumed; // duplicate or stale
                    }
                    entry.1 = incoming_seqno;
                } else if self
                    .broadcast_seqno
                    .push((orig_ident, incoming_seqno))
                    .is_err()
                {
                    return RoutingAction::Consumed; // table full, drop packet
                }

                // Rule 3: TTL exhausted — deliver to the local node but do not
                // re-flood (mirrors OGM TTL expiry).
                if bcast.ttl <= 1 {
                    return RoutingAction::DeliverLocal;
                }

                // Rule 4: re-flood with a decremented TTL.  The inner frame is
                // copied verbatim after the header so the next hop can deliver
                // it too.  The local delivery of the inner frame is the
                // caller's responsibility — it strips this header off `frame`.
                let mut outbound = bcast;
                outbound.ttl -= 1;

                let header_size = core::mem::size_of::<BatmanBroadcastPacket>();
                let total = header_size + inner.len();

                reply.dst = Mac::BROADCAST;
                reply.protocol = ETH_P_BATMAN;
                reply
                    .payload
                    .get_mut(0..header_size)
                    .unwrap()
                    .copy_from_slice(&outbound.as_bytes()[..header_size]);
                reply
                    .payload
                    .get_mut(header_size..total)
                    .unwrap_or(&mut [])
                    .copy_from_slice(inner);

                RoutingAction::DeliverLocalAndForward(Mac::BROADCAST)
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
                    // and preserve the inner application payload that follows the header.
                    let mut updated_hdr = unicast_hdr;
                    updated_hdr.ttl -= 1;

                    let size = core::mem::size_of::<BatmanUnicastPacket>();
                    let inner = frame.payload.get(size..).unwrap_or(&[]);
                    let total = size + inner.len();

                    reply.dst = record.best_next_hop;
                    reply.protocol = ETH_P_BATMAN;
                    reply
                        .payload
                        .get_mut(0..size)
                        .unwrap()
                        .copy_from_slice(updated_hdr.as_bytes());
                    reply
                        .payload
                        .get_mut(size..total)
                        .unwrap_or(&mut [])
                        .copy_from_slice(inner);
                }

                RoutingAction::Consumed // Route unknown, drop packet
            }

            BATADV_MCAST => {
                // Structurally identical to unicast routing: each multicast
                // copy is addressed to one listener node and travels toward it
                // hop by hop, delivered locally on arrival.
                let parsed = BatmanMcastPacket::read_from_prefix(&frame.payload);
                if parsed.is_err() {
                    return RoutingAction::Consumed;
                }
                let (mcast_hdr, _) = parsed.unwrap();
                let dst = mcast_hdr.dest;

                // Rule 1: this copy reached its target listener — deliver up.
                if dst == self.self_ident {
                    return RoutingAction::DeliverLocal;
                }

                // Rule 2: drop if TTL is exhausted.
                if mcast_hdr.ttl <= 1 {
                    return RoutingAction::Consumed;
                }

                // Rule 3: relay toward the next hop for the target listener.
                if let Some(record) = self
                    .originator_table
                    .iter()
                    .find(|r| r.neighbor_ident == dst)
                {
                    let mut updated_hdr = mcast_hdr;
                    updated_hdr.ttl -= 1;

                    let size = core::mem::size_of::<BatmanMcastPacket>();
                    let inner = frame.payload.get(size..).unwrap_or(&[]);
                    let total = size + inner.len();

                    reply.dst = record.best_next_hop;
                    reply.protocol = ETH_P_BATMAN;
                    reply
                        .payload
                        .get_mut(0..size)
                        .unwrap()
                        .copy_from_slice(updated_hdr.as_bytes());
                    reply
                        .payload
                        .get_mut(size..total)
                        .unwrap_or(&mut [])
                        .copy_from_slice(inner);
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

    fn produce_periodic_broadcast<'tx>(
        &mut self,
        _now: core::time::Duration,
        tx_buffer: &'tx mut [u8],
    ) -> Option<&'tx [u8]> {
        // Increment sequence allocation for this ticker frame
        self.sequence_number = self.sequence_number.wrapping_add(1);

        let header_size = core::mem::size_of::<BatmanOgmPacket>();
        let tvlv_hdr_size = core::mem::size_of::<BatmanTvlvHdr>();

        // A multicast TVLV is attached only when the local host has joined at
        // least one group; its value is those group MACs back-to-back.
        let mcast_value_len = self.local_mcast.len() * core::mem::size_of::<Mac>();
        let tvlv_len = if mcast_value_len == 0 {
            0
        } else {
            tvlv_hdr_size + mcast_value_len
        };

        let ogm = BatmanOgmPacket {
            packet_type: BATADV_IV_OGM,
            version: 5,
            ttl: 50,
            flags: 0,
            seqno: self.sequence_number.to_be(),
            orig: self.self_ident,
            prev_sender: self.self_ident,
            reserved: 0,
            tq: 255, // Max link capability score from original anchor source
            tvlv_len: (tvlv_len as u16).to_be(),
        };

        tx_buffer[..header_size].copy_from_slice(ogm.as_bytes());

        if tvlv_len > 0 {
            let hdr = BatmanTvlvHdr {
                tvlv_type: BATADV_TVLV_MCAST,
                version: 1,
                len: (mcast_value_len as u16).to_be(),
            };
            tx_buffer[header_size..header_size + tvlv_hdr_size].copy_from_slice(hdr.as_bytes());
            let mut off = header_size + tvlv_hdr_size;
            for group in &self.local_mcast {
                tx_buffer[off..off + core::mem::size_of::<Mac>()].copy_from_slice(group.as_bytes());
                off += core::mem::size_of::<Mac>();
            }
        }

        Some(&tx_buffer[..header_size + tvlv_len])
    }
}
