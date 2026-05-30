//! Test harness for [`CentralRouter`].
//!
//! [`TestRouter`] wraps a [`CentralRouter`] and pairs it with one
//! [`mpsc::Sender`] per physical interface.  Every outgoing frame — whether
//! from a periodic OGM tick, a forwarded packet, or local application data —
//! is serialised and dispatched to the right channel automatically using
//! [`CentralRouter::get_egress_interface`].
//!
//! # Multiple interfaces
//!
//! Pass one sender per interface when constructing the router:
//!
//! ```ignore
//! let router = TestRouter::new(my_ident, vec![tx_iface0, tx_iface1]);
//! ```
//!
//! For a broadcast destination (or any destination not yet in the ident table)
//! the frame is flooded to **all** interfaces.  For a known unicast destination
//! the index returned by `get_egress_interface` selects the channel.

use std::time::Duration;

use interfaces::{
    frame::{LinkFrame, MeshIdentifier},
    link::LinkMetrics,
};
use tokio::sync::mpsc;
use wayfinder::{CentralRouter, EgressInterface};
use zerocopy::FromBytes;

// ── wire-format helpers ───────────────────────────────────────────────────────

/// Serialize a `LinkFrame<Ident>` into a heap-allocated byte vector.
///
/// Wire layout (matches `#[repr(C, packed)]` of `LinkFrame<Ident>`):
/// ```text
/// [src: Ident][dst: Ident][protocol: u16 native-endian][payload ...]
/// ```
pub fn build_frame<Ident: MeshIdentifier>(
    src: Ident,
    dst: Ident,
    protocol: u16,
    payload: &[u8],
) -> Vec<u8> {
    let ident_size = core::mem::size_of::<Ident>();
    let mut bytes = Vec::with_capacity(ident_size * 2 + 2 + payload.len());
    bytes.extend_from_slice(src.as_bytes());
    bytes.extend_from_slice(dst.as_bytes());
    bytes.extend_from_slice(&protocol.to_ne_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

/// Zero-copy parse of raw bytes into a `&LinkFrame<Ident>`.
///
/// The returned reference borrows directly from `bytes` — no allocation.
pub fn parse_frame<Ident: MeshIdentifier>(bytes: &[u8]) -> &LinkFrame<Ident> {
    LinkFrame::<Ident>::ref_from_bytes(bytes).expect("failed to parse LinkFrame from bytes")
}

// ── TestRouter ────────────────────────────────────────────────────────────────

/// A [`CentralRouter`] wired up to a set of egress channels for test use.
///
/// Each call to [`poll`], [`receive`], and [`send_local`] automatically
/// serialises any outgoing frame and dispatches it to the correct interface
/// channel, determined by [`CentralRouter::get_egress_interface`].
///
/// [`poll`]: TestRouter::poll
/// [`receive`]: TestRouter::receive
/// [`send_local`]: TestRouter::send_local
pub struct TestRouter<Ident: MeshIdentifier> {
    /// The underlying router — exposed so tests can inspect routing state
    /// (e.g. originator tables) directly.
    pub router: CentralRouter<Ident>,
    ident: Ident,
    /// Egress channel for each interface, indexed by interface index.
    interfaces: Vec<mpsc::Sender<Vec<u8>>>,
    /// Inner frames the router handed up for local delivery (i.e. what would
    /// be written to the TAP), in arrival order.  Lets tests assert that a
    /// packet reached its final destination and was delivered intact.
    local_deliveries: Vec<Vec<u8>>,
}

// `CentralRouter`'s `handle_frame`, `handle_local`, and `get_egress_interface`
// are all in an `impl<Ident: MeshIdentifier + 'static>` block, so we need the
// same bound here.
impl<Ident: MeshIdentifier + 'static> TestRouter<Ident> {
    /// Create a new test router with the given node identity and one egress
    /// sender per interface.
    pub fn new(ident: Ident, interfaces: Vec<mpsc::Sender<Vec<u8>>>) -> Self {
        Self {
            router: CentralRouter::new(ident),
            ident,
            interfaces,
            local_deliveries: Vec::new(),
        }
    }

    /// The inner frames the router has delivered locally so far (what would
    /// have been written to the TAP), in arrival order.
    pub fn local_deliveries(&self) -> &[Vec<u8>] {
        &self.local_deliveries
    }

    // ── outbound ─────────────────────────────────────────────────────────────

    /// Drive one periodic-broadcast tick.
    ///
    /// Calls [`CentralRouter::poll`] and, if an OGM is produced, serialises
    /// it and floods it to all interfaces (OGMs are always broadcasts).
    pub async fn poll(&mut self, now: Duration) {
        let my_ident = self.ident;
        let mut buf = [0u8; 512];
        if let Some(frame) = self.router.poll(now, &mut buf) {
            let dst = frame.dst;
            let wire = build_frame(my_ident, dst, frame.protocol, frame.payload);
            // frame / buf borrow ends after build_frame copies the payload
            self.send_egress(dst, wire).await;
        }
    }

    /// Inject application-layer data destined for `dest` into the mesh.
    ///
    /// Calls [`CentralRouter::handle_local`] to build the BATMAN unicast
    /// packet, then dispatches it on the interface chosen by
    /// [`CentralRouter::get_egress_interface`].
    ///
    /// Returns `Err(())` if the router has no route to `dest` (propagated
    /// from `handle_local`).
    pub async fn send_local(&mut self, dest: Ident, payload: &[u8]) -> Result<(), ()> {
        let my_ident = self.ident;
        let mut buf = [0u8; 512];
        let frame = self.router.handle_local(dest, payload, &mut buf)?;
        let dst = frame.dst;
        let wire = build_frame(my_ident, dst, frame.protocol, frame.payload);
        // frame / buf borrow ends after build_frame copies the payload
        self.send_egress(dst, wire).await;
        Ok(())
    }

    // ── inbound ───────────────────────────────────────────────────────────────

    /// Process one raw wire frame received on interface `iface_idx`.
    ///
    /// Parses the bytes as a [`LinkFrame`], passes it to
    /// [`CentralRouter::handle_frame`], and — if a reply is produced —
    /// serialises it and dispatches it on the appropriate egress interface.
    pub async fn receive(&mut self, iface_idx: usize, raw: &[u8]) {
        self.receive_with_metrics(iface_idx, raw, LinkMetrics::default())
            .await;
    }

    /// Same as [`receive`], but carries explicit [`LinkMetrics`] as if the
    /// radio had reported them.  Tests use this to inject controlled
    /// RSSI/SNR values so that the metric-driven egress decision can be
    /// exercised without real hardware.
    ///
    /// [`receive`]: TestRouter::receive
    pub async fn receive_with_metrics(
        &mut self,
        iface_idx: usize,
        raw: &[u8],
        metrics: LinkMetrics,
    ) {
        let my_ident = self.ident;
        let mut buf = [0u8; 512];
        let frame = parse_frame::<Ident>(raw);
        let outcome = self
            .router
            .handle_frame_with_metrics(iface_idx, frame, metrics, &mut buf);
        // Record any inner frame delivered to the local host.
        if let Some(local) = outcome.deliver_local {
            self.local_deliveries.push(local.to_vec());
        }
        if let Some(r) = outcome.forward {
            let dst = r.dst;
            let wire = build_frame(my_ident, dst, r.protocol, r.payload);
            self.send_egress(dst, wire).await;
        }
    }

    /// Drain all pending frames from `rx` through [`receive`].
    ///
    /// Frames are collected before processing so that any replies generated
    /// during `receive` do not feed back into the same drain loop.
    ///
    /// [`receive`]: TestRouter::receive
    pub async fn drain(&mut self, iface_idx: usize, rx: &mut mpsc::Receiver<Vec<u8>>) {
        let mut pending = Vec::new();
        while let Ok(raw) = rx.try_recv() {
            pending.push(raw);
        }
        for raw in pending {
            self.receive(iface_idx, &raw).await;
        }
    }

    // ── internal ─────────────────────────────────────────────────────────────

    /// Route `wire` to the correct egress interface(s) for `dst`.
    ///
    /// | Situation | Behaviour |
    /// |-----------|-----------|
    /// | Known unicast `dst` | Single interface via `get_egress_interface` |
    /// | Broadcast `dst` | All interfaces |
    /// | Unknown `dst` (not yet in ident table) | All interfaces (flood) |
    async fn send_egress(&mut self, dst: Ident, wire: Vec<u8>) {
        // Resolve the egress decision before accessing self.interfaces so the
        // mutable borrow of self.router does not overlap with the channel sends.
        let egress = self.router.get_egress_interface(dst);
        match egress {
            Some(EgressInterface::Interface(idx)) if idx < self.interfaces.len() => {
                let _ = self.interfaces[idx].send(wire).await;
            }
            _ => {
                // Broadcast destination or destination not yet learned — flood.
                for tx in &self.interfaces {
                    let _ = tx.send(wire.clone()).await;
                }
            }
        }
    }
}
