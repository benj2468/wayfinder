use crate::frame::{LinkFrame, LinkFrameDataMut};

pub enum RoutingAction<Ident> {
    /// The packet was a BATMAN control message (like an OGM);
    /// the engine consumed it to update its internal routing tables.
    Consumed,

    /// The packet was data destined for another node.
    /// Forward it to this next-hop MAC address on the mesh network.
    ForwardTo(Ident),

    /// The packet has reached its final destination (this node).
    /// Hand it up to the local application layer.
    DeliverLocal,
}

pub trait MeshRoutingEngine<Ident> {
    /// Ingest an incoming frame from the central router.
    /// The engine processes it, updates metrics, and returns the next logical step.
    fn handle_rx<'rx, 'tx>(
        &mut self,
        frame: &'rx LinkFrame<Ident>,
        reply: &mut LinkFrameDataMut<'tx, Ident>,
    ) -> RoutingAction<Ident>;

    /// Force the engine to generate its regular periodic routing messages (OGMs).
    /// Returns a closure or a slice instructing the manager what to broadcast.
    fn produce_periodic_broadcast<'tx>(
        &mut self,
        now: core::time::Duration,
        tx_buffer: &'tx mut [u8],
    ) -> Option<&'tx [u8]>;
}
