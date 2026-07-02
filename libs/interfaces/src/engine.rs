use core::time::Duration;

use crate::frame::{LinkFrame, LinkFrameDataMut, Mac};

/// The decision a [`MeshRoutingEngine`] returns after processing a received
/// frame, telling the central router what to do with it: consume it, forward it,
/// deliver it locally, or both deliver and re-flood.
#[derive(Debug)]
pub enum RoutingAction {
    /// The packet was a BATMAN control message (like an OGM), a re-flood, or
    /// a relayed unicast/multicast; the engine consumed it and updated its
    /// internal routing tables.  It may *also* have written a rebuilt packet
    /// into the `reply` buffer to send onward — the caller must check
    /// `reply.protocol != 0` to tell whether there's anything to forward,
    /// since the engine leaves `reply` untouched (protocol `0`) when it has
    /// nothing to send, including when the rebuilt packet didn't fit the
    /// caller's `reply` buffer.
    Consumed,

    /// The packet was data destined for another node.
    /// Forward it to this next-hop MAC address on the mesh network.
    ForwardTo(Mac),

    /// The packet has reached its final destination (this node).
    /// Hand it up to the local application layer.
    DeliverLocal,

    /// The packet was a mesh broadcast (e.g. a flooded ARP) that is new to
    /// this node, so it must be acted on twice: handed up to the local
    /// application layer *and*, when there's room, re-flooded to neighbours.
    /// Local delivery always happens (it reads the original frame, not
    /// `reply`), but the re-flood itself is conditional: the engine has
    /// written the re-flood frame (with a decremented TTL) into the `reply`
    /// buffer, addressed to the contained identifier — normally
    /// [`MeshIdentifier::BROADCAST`] — only when it fit; as with
    /// [`RoutingAction::Consumed`], the caller must check `reply.protocol !=
    /// 0` before forwarding, since a rebuilt packet too large for `reply`
    /// (e.g. relaying across a smaller-MTU link) leaves it untouched.
    ///
    /// [`MeshIdentifier::BROADCAST`]: crate::frame::MeshIdentifier::BROADCAST
    DeliverLocalAndForward(Mac),
}

/// A mesh routing protocol's behaviour, independent of transport and identity
/// crypto: it ingests received frames ([`handle_rx`](Self::handle_rx)) and
/// emits periodic topology broadcasts
/// ([`produce_periodic_broadcast`](Self::produce_periodic_broadcast)). The
/// central router drives one implementation (e.g. the BATMAN engine) and demuxes
/// frames to it by protocol.
pub trait MeshRoutingEngine {
    /// Ingest an incoming frame from the central router.
    /// The engine processes it, updates metrics, and returns the next logical step.
    ///
    /// `local_quality` is the caller's locally-measured link quality (0..=255) to
    /// the neighbor that relayed this frame, or `None` when unmeasured.  An
    /// engine may use it to bound a sender's advertised path metric by the link
    /// actually observed to it (see the BATMAN OGM TQ clamp); `None` applies no
    /// such bound.
    fn handle_rx<'rx, 'tx>(
        &mut self,
        now: Duration,
        frame: &'rx LinkFrame,
        local_quality: Option<u8>,
        reply: &mut LinkFrameDataMut<'tx>,
    ) -> RoutingAction;

    /// Force the engine to generate its regular periodic routing messages (OGMs).
    /// Returns a closure or a slice instructing the manager what to broadcast.
    fn produce_periodic_broadcast<'tx>(
        &mut self,
        now: Duration,
        tx_buffer: &'tx mut [u8],
    ) -> Option<&'tx [u8]>;
}
