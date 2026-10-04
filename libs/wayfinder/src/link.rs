//! [`LinkT`]: one mesh interface — the trait the router/driver speaks to — plus
//! the [`Received`] frame-with-metrics it yields.
//!
//! The trait is a real native `async fn` trait (no `async_trait` rewrite), so
//! it is usable verbatim in a `no_std` executor: an embedded link just
//! implements it and is driven by static dispatch.  For dynamic dispatch — the
//! `std` driver keeps a heterogeneous `Vec` of interfaces — the `dynosaur`
//! `cfg_attr` generates `DynLinkT`, a `dyn`-compatible wrapper that boxes the
//! async return values.  Because `dynosaur`'s generated constructors reference
//! `std`, `DynLinkT` is gated behind the `std` feature; the bare [`LinkT`] trait
//! is always available.

use interfaces::frame::LinkFrame;
use interfaces::frame::LinkFrameData;
use interfaces::frame::Mac;
use interfaces::link::LinkError;
use interfaces::link::LinkMetrics;

/// One frame received off a mesh interface, paired with the physical-layer
/// measurements the carrier observed for it.
///
/// The metrics let the engine bias its egress choice toward the
/// highest-quality interface (see `CentralRouter::handle_frame_with_metrics`).
/// A carrier with no signal information (a wired pipe, an in-process channel)
/// reports [`LinkMetrics::default`]; a radio fills in RSSI/SNR/quality.
#[repr(C)]
pub struct Received<'a> {
    /// The parsed link-layer frame, borrowed from the interface's receive
    /// buffer.  Valid until the next receive on the same interface.
    pub frame: &'a LinkFrame,
    /// Physical-layer measurements for this frame.
    pub metrics: LinkMetrics,
}

/// One mesh interface: it accepts whole link-layer frames addressed to a
/// destination MAC and yields received frames with their physical-layer metrics.
///
/// The driver chooses *which* interface and *which* next-hop MAC (via the
/// routing engine); a `LinkT` decides only *how* to put that frame onto its own
/// medium.  A point-to-point link ignores the destination; a multi-access or
/// self-routing link uses it.
///
/// Under the `std` feature, `dynosaur` additionally generates a `DynLinkT`
/// boxed wrapper (for the driver's heterogeneous interface list); the attribute
/// is a no-op on the trait itself, so embedded `no_std` callers see the exact
/// same trait and implement it directly by static dispatch.
// Native `async fn` in a trait is exactly what `dynosaur` consumes; the
// auto-trait-bound lint does not apply to this usage.
#[allow(async_fn_in_trait)]
#[cfg_attr(feature = "std", dynosaur::dynosaur(DynLinkTInner = dyn(box) LinkT))]
pub trait LinkT: Send {
    /// Deliver one frame originating from `origin` to `data.dst` over this
    /// medium.  `data.dst` is a next-hop (or final) node MAC, or
    /// [`Mac::BROADCAST`].  Returns the number of bytes written.
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError>;

    /// Deliver the *same* `(protocol, payload)` to each destination in `dsts`.
    ///
    /// A link with a native fan-out — one UDP-multicast datagram, one radio
    /// group transmission — overrides this to exploit it.  The default sends one
    /// frame per destination via [`send`](LinkT::send), so simple carriers need
    /// not implement it.
    async fn send_all(
        &mut self,
        origin: Mac,
        dsts: &[Mac],
        protocol: u16,
        payload: &[u8],
    ) -> Result<(), LinkError> {
        for &dst in dsts {
            self.send(
                origin,
                &LinkFrameData {
                    dst,
                    protocol,
                    payload,
                },
            )
            .await?;
        }
        Ok(())
    }

    /// This medium's **native fan-out threshold**: the number of distinct
    /// multicast targets routed out this link at which one flood becomes
    /// cheaper than one directed copy each.
    ///
    /// `None` — the default — means the link has no native fan-out to exploit:
    /// one `send` reaches one neighbor, so N copies genuinely cost N and
    /// flooding is never the cheaper option on this link's account.  Every
    /// point-to-point carrier is this, and so is a multi-access one whose
    /// "broadcast" is really a loop over known peers.
    ///
    /// `Some(n)` means one `send` already reaches every neighbor on this
    /// medium.  `Some(1)` is the strongest form — a directed copy costs
    /// exactly what a flood costs, so a single target already justifies
    /// flooding — and fits any carrier that ignores `data.dst` when it
    /// transmits: a LoRa module addressed to its broadcast address, a
    /// non-connectable BLE advertisement, an 802.15.4 frame sent to `0xffff`.
    /// A larger `n` fits a medium that fans out in one operation but where a
    /// directed copy is still meaningfully cheaper than the mesh-wide cost of
    /// a flood.
    ///
    /// This is a statement about the *medium*, which is why it belongs to the
    /// link rather than to config: the driver is what knows whether its own
    /// `send` is a broadcast.
    ///
    /// **Read by the multicast fan-out collapse** (design 17 §4.5). It is the seam design 17 (multi-destination
    /// multicast) plugs into: a forwarding node with several next hops behind
    /// one interface collapses them into a single `send_all` when, and only
    /// when, the link declares that one send reaches them all. If that design
    /// is abandoned, delete this method along with
    /// [`send_all`](LinkT::send_all) — a declaration nothing reads is exactly
    /// the dead weight `send_all` has been since it was introduced.
    fn fan_out(&self) -> Option<FanOut> {
        None
    }

    /// Await the next frame from the interface, with its physical-layer metrics.
    /// The returned [`Received`] borrows the interface's receive buffer and is
    /// invalidated by the next receive.
    async fn recv<'a>(&'a mut self) -> Result<Received<'a>, LinkError>;
}

/// A link's [`LinkT::fan_out`] declaration: when merging several directed
/// copies into one transmission pays off, and how large that one transmission
/// may be.
///
/// The two travel together because the cap only matters where a merge can
/// happen. A merged frame is larger than any one directed copy — its
/// destination list is the union (6 bytes per extra peer), and on an
/// authenticated node it carries a signature trailer where a copy carries a
/// pairwise tag (48 bytes more) — so on a small-MTU radio a multicast whose
/// copies each fit can merge into a frame the radio refuses. That loses every
/// listener at once, so the collapse checks `max_frame_len` first and keeps the
/// directed copies when the merged frame would not fit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FanOut {
    /// The number of distinct terminal destinations behind this link at which
    /// one merged transmission beats one directed copy each. See
    /// [`LinkT::fan_out`] for what `1` and larger values mean.
    pub threshold: core::num::NonZeroU8,
    /// The largest assembled link frame (`[dst][src][protocol][payload]`, the
    /// bytes `send` is handed) this link can carry. A frame past it is refused
    /// by `send`, typically with `LinkError::BufferFull`.
    pub max_frame_len: usize,
}

impl FanOut {
    /// The declaration every broadcast medium in this repo makes: a LoRa
    /// module or raw LoRa PHY, an 802.15.4 frame to `0xffff`, a BLE
    /// advertisement, and a raw L2 segment (whose merged frame goes to the
    /// broadcast MAC). One `send` reaches every neighbor on each of those.
    ///
    /// **A threshold of two, not one**, although one directed copy costs a
    /// broadcast radio exactly what a flood does. The collapse it gates
    /// (design 17 §4.5) swaps the frame's pairwise tag for a signature, since
    /// one transmission cannot carry a tag per recipient. With a single
    /// terminal destination that swap saves no transmission and only makes
    /// the frame longer, which on a duty-cycled medium is airtime spent for
    /// nothing. From two destinations up it saves a whole transmission per
    /// extra peer. The host's multicast UDP links use the same threshold.
    pub const fn broadcast(max_frame_len: usize) -> FanOut {
        FanOut {
            threshold: match core::num::NonZeroU8::new(2) {
                Some(n) => n,
                None => unreachable!(),
            },
            max_frame_len,
        }
    }
}

/// A dynamically dispatched [`LinkT`] trait object.
///
/// Gated behind the `std` feature: it aliases the `dynosaur`-generated wrapper
/// whose boxing constructors reference `std`, so it only exists when the macro
/// above runs.  Embedded `no_std` callers use [`LinkT`] directly.
#[cfg(feature = "std")]
pub type DynLinkT<'a> = DynLinkTInner<'a>;

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU8;

    /// A carrier that declares nothing about its medium — the shape of every
    /// point-to-point pipe.
    struct Plain;

    impl LinkT for Plain {
        async fn send(&mut self, _: Mac, _: &LinkFrameData<'_>) -> Result<usize, LinkError> {
            Ok(0)
        }
        async fn recv(&mut self) -> Result<Received<'_>, LinkError> {
            Err(LinkError::Io)
        }
    }

    /// A carrier whose every `send` already reaches every neighbor, so one
    /// directed copy costs what a flood costs.
    struct Broadcasting;

    impl LinkT for Broadcasting {
        fn fan_out(&self) -> Option<FanOut> {
            Some(FanOut {
                threshold: NonZeroU8::new(1).unwrap(),
                max_frame_len: 1500,
            })
        }
        async fn send(&mut self, _: Mac, _: &LinkFrameData<'_>) -> Result<usize, LinkError> {
            Ok(0)
        }
        async fn recv(&mut self) -> Result<Received<'_>, LinkError> {
            Err(LinkError::Io)
        }
    }

    /// The default is "no native fan-out": a link says nothing unless it has
    /// something to say, so adding the hint changes no existing carrier.
    #[test]
    fn a_link_declares_no_fan_out_by_default() {
        assert_eq!(Plain.fan_out(), None);
    }

    #[test]
    fn a_broadcast_medium_declares_its_threshold() {
        assert_eq!(
            Broadcasting.fan_out().map(|f| f.threshold),
            NonZeroU8::new(1)
        );
    }

    /// The declaration has to survive type erasure: the host driver holds its
    /// interfaces as `DynLinkT`, so a hint the boxed wrapper dropped would be
    /// a hint the host node never sees.
    #[cfg(feature = "std")]
    #[test]
    fn the_boxed_wrapper_forwards_the_declaration() {
        let plain = DynLinkT::new_box(Plain);
        assert_eq!(plain.fan_out(), None);
        let broadcasting = DynLinkT::new_box(Broadcasting);
        assert_eq!(broadcasting.fan_out(), Broadcasting.fan_out());
    }
}
