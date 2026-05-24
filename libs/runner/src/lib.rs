use std::marker::PhantomData;

use batman::BatmanEngine;
use interfaces::{
    engine::{MeshRoutingEngine, RoutingAction},
    frame::{LinkFrame, LinkFrameData, LinkFrameDataMut},
    link::{EmbeddedMeshLink, MeshIdentifier},
};
use tracing::{info_span, trace, trace_span};

pub const DEFAULT_BATMAN_ETHER_TYPE: u16 = 0x4305;

pub struct CentralRouter<Ident: MeshIdentifier, const N: usize> {
    /// The set of physical interfaces for this router
    interfaces: [Box<dyn EmbeddedMeshLink<Ident>>; N],
    /// The Batman routing engine for this router
    batman: BatmanEngine<100, Ident>,
    phantom: PhantomData<Ident>,
}

impl<Ident: MeshIdentifier, const N: usize> CentralRouter<Ident, N> {
    pub fn new(interfaces: [Box<dyn EmbeddedMeshLink<Ident>>; N], self_ident: Ident) -> Self {
        Self {
            interfaces,
            batman: BatmanEngine::new(self_ident),
            phantom: PhantomData,
        }
    }
}

impl<Ident: MeshIdentifier, const N: usize> CentralRouter<Ident, N> {
    pub async fn poll_and_route(&mut self, now: std::time::Instant) {
        let mut rx_buf = [0u8; 1500];

        let mut tx_buf = [0u8; 1500];
        let tx_buf = tx_buf.as_mut_slice();

        // 1. Poll every physical interface for data
        for interface_idx in 0..self.interfaces.len() {
            let span = trace_span!("interface_poll", interface_idx = interface_idx);
            let _enter = span.enter();

            let link = &mut self.interfaces[interface_idx];

            trace!("waiting for data");
            if let Ok(Some(frame)) = link.receive(&mut rx_buf).await {
                trace!("received data");
                let mut should_go_local = false;

                // 2. Demux by Protocol ID
                match frame.protocol {
                    DEFAULT_BATMAN_ETHER_TYPE => {
                        let mut reply: LinkFrameDataMut<'_, Ident> = tx_buf.into();

                        // BATMAN-adv Protocol ID
                        match self.batman.handle_rx(&frame, &mut reply) {
                            RoutingAction::Consumed => {
                                // Handled internally by BATMAN (e.g., OGM processed)
                            }
                            RoutingAction::ForwardTo(next_hop) => {
                                // BATMAN told us this packet needs to keep moving.
                                // Re-transmit it out to the designated next-hop neighbor.
                                let _ = link.transmit(LinkFrameData {
                                    dst: next_hop,
                                    protocol: DEFAULT_BATMAN_ETHER_TYPE,
                                    payload: &frame.payload,
                                });
                            }
                            RoutingAction::DeliverLocal => {
                                // Route up to your local embedded application layer
                                // We will need to queue this up and handle it after
                                should_go_local = true;
                            }
                        }

                        if reply.protocol != 0 {
                            let _ = link.transmit(reply.into());
                        }
                    }
                    0x88B5 => {
                        // Dynamically route to a completely separate experimental protocol context
                    }
                    _ => println!("Dropped unknown protocol frame"),
                }

                if should_go_local {
                    trace!("dispatching to local app");
                    self.dispatch_to_local_app(&frame);
                }
            }
        }

        // 3. Handle BATMAN outgoing maintenance ticks
        let broadcast = Ident::BROADCAST;
        if let Some(ogm_payload) = self.batman.produce_periodic_broadcast(now) {
            for link in self.interfaces.iter_mut() {
                println!("transmitting OGM");
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

    fn dispatch_to_local_app(&self, _frame: &LinkFrame<Ident>) {
        // App logic lives here
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use interfaces::link::IdentifiableLink;
    use pretty_hex::PrettyHex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::CentralRouter;

    #[tokio::test]
    async fn test_constructor() {
        let _ = CentralRouter::new([], 0_u8);
    }

    #[tokio::test]
    async fn test_constructor_with_duplex() {
        let mut buf = [0; 1500];
        let (a, mut b) = tokio::io::duplex(3000);
        b.write(&buf).await.unwrap();

        let mut router = CentralRouter::new(
            [Box::new(IdentifiableLink {
                identifier: 0,
                link: a,
            })],
            0,
        );

        let now = std::time::Instant::now();
        router.poll_and_route(now).await;
        // We should have received a message.
        let read = tokio::time::timeout(Duration::from_secs(1), b.read(&mut buf))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(read, 14);
    }
}
