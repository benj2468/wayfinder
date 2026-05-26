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
    link::EmbeddedMeshLink,
};
use tracing::{trace, trace_span, warn};
use zerocopy::{FromBytes, IntoBytes};

pub const DEFAULT_BATMAN_ETHER_TYPE: u16 = 0x4305;

pub struct CentralRouter<Ident: MeshIdentifier> {
    /// The Batman routing engine for this router
    batman: BatmanEngine<100, Ident>,
    phantom: PhantomData<Ident>,
}

impl<Ident: MeshIdentifier> CentralRouter<Ident> {
    pub fn new(self_ident: Ident) -> Self {
        Self {
            batman: BatmanEngine::new(self_ident),
            phantom: PhantomData,
        }
    }
}

impl<Ident: MeshIdentifier> CentralRouter<Ident> {
    pub async fn poll_and_route<L: EmbeddedMeshLink<Ident>>(
        &mut self,
        interfaces: &mut [&mut L],
        now: core::time::Duration,
    ) {
        let mut tx_buf = [0u8; 1500];
        let mut rx_buf = [0u8; 1500];

        // 1. Poll every physical interface for data
        for interface_idx in 0..interfaces.len() {
            let span = trace_span!("interface_poll", interface_idx = interface_idx);
            let _enter = span.enter();

            let link = &mut interfaces[interface_idx];

            trace!("waiting for data");
            if let Ok(n) = link.receive(&mut rx_buf).await {
                if n == 0 {
                    continue;
                }
                trace!("received data");
                let frame_bytes = &rx_buf[..n];
                let frame = match LinkFrame::<Ident>::ref_from_bytes(frame_bytes) {
                    Ok(f) => f,
                    Err(_) => {
                        warn!("Failed to parse link frame");
                        continue;
                    }
                };

                let mut should_go_local = false;

                // 2. Demux by Protocol ID
                match frame.protocol {
                    DEFAULT_BATMAN_ETHER_TYPE => {
                        let mut reply: LinkFrameDataMut<'_, Ident> = tx_buf.as_mut_slice().into();

                        // BATMAN-adv Protocol ID
                        match self.batman.handle_rx(frame, &mut reply) {
                            RoutingAction::Consumed => {
                                // Handled internally by BATMAN (e.g., OGM processed)
                            }
                            RoutingAction::ForwardTo(next_hop) => {
                                // BATMAN told us this packet needs to keep moving.
                                // Re-transmit it out to the designated next-hop neighbor.
                                let _ = link
                                    .transmit(LinkFrameData {
                                        dst: next_hop,
                                        protocol: DEFAULT_BATMAN_ETHER_TYPE,
                                        payload: &frame.payload,
                                    })
                                    .await;
                            }
                            RoutingAction::DeliverLocal => {
                                // Route up to your local embedded application layer
                                // We will need to queue this up and handle it after
                                should_go_local = true;
                            }
                        }

                        if reply.protocol != 0 {
                            let _ = link.transmit(reply.into()).await;
                        }
                    }
                    0x88B5 => {
                        // Dynamically route to a completely separate experimental protocol context
                    }
                    _ => warn!("Dropped unknown protocol frame"),
                }

                if should_go_local {
                    trace!("dispatching to local app");
                    self.dispatch_to_local_app(frame);
                }
            }
        }

        // 3. Handle BATMAN outgoing maintenance ticks
        let broadcast = Ident::BROADCAST;
        if let Some(ogm_payload) = self.batman.produce_periodic_broadcast(now) {
            for link in interfaces.iter_mut() {
                trace!("transmitting OGM");
                // Flood the OGM out of every radio interface to map the surrounding topology
                let _ = link
                    .transmit(LinkFrameData {
                        dst: broadcast,
                        protocol: DEFAULT_BATMAN_ETHER_TYPE,
                        payload: ogm_payload,
                    })
                    .await;
            }
        }
    }

    pub async fn dispatch_from_local<L: EmbeddedMeshLink<Ident>>(
        &mut self,
        interfaces: &mut [&mut L],
        dest: Ident,
        payload: &[u8],
    ) -> Result<(), ()> {
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
        let mut tx_scratchpad = [0u8; 1500]; // Max MTU frame layout bounds
        let header_size = core::mem::size_of::<BatmanUnicastPacket<Ident>>();
        let total_size = header_size + payload.len();

        if total_size > tx_scratchpad.len() {
            return Err(());
        }

        // Pack the header and data sequentially into the scratchpad
        tx_scratchpad[..header_size].copy_from_slice(header.as_bytes());
        tx_scratchpad[header_size..total_size].copy_from_slice(payload);

        // 4. Fire the encapsulated packet out to the immediate neighbor
        for link in interfaces.iter_mut() {
            let _ = link
                .transmit(LinkFrameData {
                    dst: next_hop,
                    protocol: ETH_P_BATMAN,
                    payload: &tx_scratchpad[..total_size],
                })
                .await;
        }
        Ok(())
    }

    fn dispatch_to_local_app(&self, _frame: &LinkFrame<Ident>) {
        // App logic lives here
    }
}
