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

    /// Await the next frame from the interface, with its physical-layer metrics.
    /// The returned [`Received`] borrows the interface's receive buffer and is
    /// invalidated by the next receive.
    async fn recv<'a>(&'a mut self) -> Result<Received<'a>, LinkError>;
}

/// A dynamically dispatched [`LinkT`] trait object.
///
/// Gated behind the `std` feature: it aliases the `dynosaur`-generated wrapper
/// whose boxing constructors reference `std`, so it only exists when the macro
/// above runs.  Embedded `no_std` callers use [`LinkT`] directly.
#[cfg(feature = "std")]
pub type DynLinkT<'a> = DynLinkTInner<'a>;
