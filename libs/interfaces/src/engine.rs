use core::time::Duration;

use crate::frame::LinkFrame;
use crate::frame::LinkFrameData;
use crate::frame::LinkFrameDataMut;
use crate::frame::Mac;

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

/// A bounded sink for frames an engine produces when one received frame yields
/// **more than one** outgoing frame.
///
/// `reply` can hold exactly one, and its forward path in the central router
/// trims the payload to the *incoming* frame's length — correct while a relay
/// only decrements a TTL, and wrong the moment an outgoing frame is a different
/// size from the one that caused it. Multi-destination multicast is exactly
/// that case: each hop removes itself from the destination list and splits the
/// rest by next hop, so every frame it emits is shorter than the one it
/// received, and there may be several. Frames pushed here carry their own
/// slice, so the length is exact and never inferred.
///
/// The sink is **bounded**, and [`push`](Self::push) says so by returning
/// `false` rather than silently taking fewer frames than it was given: dropping
/// a destination group without a trace is the failure multi-destination
/// multicast exists to remove, so a refusal must be counted and surfaced by the
/// caller.
pub trait FrameSink {
    /// Accept one outgoing frame, returning `false` if the sink is full.
    ///
    /// The implementation **must** copy `frame.payload` before returning — it
    /// borrows a scratchpad the engine reuses for the next frame.
    fn push(&mut self, frame: LinkFrameData<'_>) -> bool;
}

/// A sink with no room at all, for a caller that cannot take extra frames.
///
/// Every push is refused rather than quietly discarded, so an engine's overflow
/// accounting sees a shell that never had capacity exactly as it sees one that
/// ran out — there is no configuration in which frames vanish unrecorded.
impl FrameSink for () {
    fn push(&mut self, _frame: LinkFrameData<'_>) -> bool {
        false
    }
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
    ///
    /// `out` takes any frame beyond the single one `reply` can hold — see
    /// [`FrameSink`]. A handler that produces at most one frame ignores it
    /// entirely; a caller that cannot accept extras passes `&mut ()`.
    fn handle_rx<'rx, 'tx>(
        &mut self,
        now: Duration,
        frame: &'rx LinkFrame,
        local_quality: Option<u8>,
        reply: &mut LinkFrameDataMut<'tx>,
        out: &mut dyn FrameSink,
    ) -> RoutingAction;

    /// Force the engine to generate its regular periodic routing messages (OGMs).
    /// Returns a closure or a slice instructing the manager what to broadcast.
    fn produce_periodic_broadcast<'tx>(
        &mut self,
        now: Duration,
        tx_buffer: &'tx mut [u8],
    ) -> Option<&'tx [u8]>;
}
