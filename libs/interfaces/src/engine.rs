use crate::frame::{LinkFrame, LinkFrameDataMut, Mac};

#[derive(Debug)]
pub enum RoutingAction {
    /// The packet was a BATMAN control message (like an OGM);
    /// the engine consumed it to update its internal routing tables.
    Consumed,

    /// The packet was data destined for another node.
    /// Forward it to this next-hop MAC address on the mesh network.
    ForwardTo(Mac),

    /// The packet has reached its final destination (this node).
    /// Hand it up to the local application layer.
    DeliverLocal,

    /// The packet was a mesh broadcast (e.g. a flooded ARP) that is new to
    /// this node, so it must be acted on twice: handed up to the local
    /// application layer *and* re-flooded to neighbours.  The engine has
    /// already written the re-flood frame (with a decremented TTL) into the
    /// `reply` buffer, addressed to the contained identifier — normally
    /// [`MeshIdentifier::BROADCAST`].  The caller forwards that frame and, in
    /// addition, delivers the inner payload locally as it would for
    /// [`RoutingAction::DeliverLocal`].
    ///
    /// [`MeshIdentifier::BROADCAST`]: crate::frame::MeshIdentifier::BROADCAST
    DeliverLocalAndForward(Mac),
}

pub trait MeshRoutingEngine {
    /// Ingest an incoming frame from the central router.
    /// The engine processes it, updates metrics, and returns the next logical step.
    fn handle_rx<'rx, 'tx>(
        &mut self,
        frame: &'rx LinkFrame,
        reply: &mut LinkFrameDataMut<'tx>,
    ) -> RoutingAction;

    /// Force the engine to generate its regular periodic routing messages (OGMs).
    /// Returns a closure or a slice instructing the manager what to broadcast.
    fn produce_periodic_broadcast<'tx>(
        &mut self,
        now: core::time::Duration,
        tx_buffer: &'tx mut [u8],
    ) -> Option<&'tx [u8]>;
}
