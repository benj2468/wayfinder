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
};
use tracing::{trace, warn};
use zerocopy::{FromBytes, IntoBytes};

pub const DEFAULT_BATMAN_ETHER_TYPE: u16 = 0x4305;

pub enum EgressInterface {
    All,
    Interface(usize),
}

struct IdentTable<Ident: MeshIdentifier> {
    // TODO: how should we store this? We cannot dynamically allocate
    phantom: PhantomData<Ident>,
}

impl<Ident: MeshIdentifier> IdentTable<Ident> {
    fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }

    fn add_record(&mut self, iface_idx: usize, dest: Ident) {
        todo!()
    }

    fn get_egress_interface(&self, dest: Ident) -> Option<usize> {
        todo!()
    }
}

pub struct CentralRouter<Ident: MeshIdentifier> {
    /// The Batman routing engine for this router
    batman: BatmanEngine<100, Ident>,
    ident_table: IdentTable<Ident>,
    phantom: PhantomData<Ident>,
}

impl<Ident: MeshIdentifier> CentralRouter<Ident> {
    pub fn new(self_ident: Ident) -> Self {
        Self {
            batman: BatmanEngine::new(self_ident),
            phantom: PhantomData,
            ident_table: IdentTable::new(),
        }
    }
}

impl<Ident: MeshIdentifier + 'static> CentralRouter<Ident> {
    pub fn handle_frame<'rx, 'tx>(
        &mut self,
        iface_idx: usize,
        frame: &'rx LinkFrame<Ident>,
        tx_buf: &'tx mut [u8],
    ) -> Option<LinkFrameData<'tx, Ident>> {
        // 1. Add a record to the identifier table
        self.ident_table.add_record(iface_idx, frame.dst);
        // 2. Demux by Protocol ID
        let result = match frame.protocol {
            DEFAULT_BATMAN_ETHER_TYPE => {
                let mut reply: LinkFrameDataMut<'_, Ident> = tx_buf.into();

                // BATMAN-adv Protocol ID
                match self.batman.handle_rx(frame, &mut reply) {
                    RoutingAction::Consumed => {
                        if reply.protocol != 0 {
                            Some(reply.into())
                        } else {
                            None
                        }
                    }
                    RoutingAction::ForwardTo(next_hop) => {
                        // BATMAN told us this packet needs to keep moving.
                        // Re-transmit it out to the designated next-hop neighbor.
                        reply.dst = next_hop;
                        reply.protocol = DEFAULT_BATMAN_ETHER_TYPE;
                        reply.payload.copy_from_slice(&frame.payload);
                        Some(reply.into())
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
        };

        result
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

    pub fn get_egress_interface(&self, dest: Ident) -> Option<EgressInterface> {
        if dest == Ident::BROADCAST {
            return Some(EgressInterface::All);
        }
        self.ident_table
            .get_egress_interface(dest)
            .map(|iface_idx| EgressInterface::Interface(iface_idx))
    }
}
