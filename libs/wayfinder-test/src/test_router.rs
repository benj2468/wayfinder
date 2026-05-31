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
    frame::{LinkFrame, Mac},
    link::LinkMetrics,
};
use tokio::sync::mpsc;
use wayfinder::{CentralRouter, EgressInterface};
use zerocopy::{FromBytes, IntoBytes};

use crate::{driver::TestHarness, switch::PortComms};

// ── wire-format helpers ───────────────────────────────────────────────────────

/// Serialize a `LinkFrame` into a heap-allocated byte vector.
///
/// Wire layout (matches `#[repr(C, packed)]` of `LinkFrame`):
/// ```text
/// [src: Mac][dst: Mac][protocol: u16 native-endian][payload ...]
/// ```
pub fn build_frame(src: Mac, dst: Mac, protocol: u16, payload: &[u8]) -> Vec<u8> {
    let ident_size = core::mem::size_of::<Mac>();
    let mut bytes = Vec::with_capacity(ident_size * 2 + 2 + payload.len());
    bytes.extend_from_slice(src.as_bytes());
    bytes.extend_from_slice(dst.as_bytes());
    bytes.extend_from_slice(&protocol.to_ne_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

/// Zero-copy parse of raw bytes into a `&LinkFrame`.
///
/// The returned reference borrows directly from `bytes` — no allocation.
pub fn parse_frame(bytes: &[u8]) -> &LinkFrame {
    LinkFrame::ref_from_bytes(bytes).expect("failed to parse LinkFrame from bytes")
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
pub struct TestRouter {
    /// The underlying router — exposed so tests can inspect routing state
    /// (e.g. originator tables) directly.
    pub router: CentralRouter,
    pub ident: Mac,
    /// Duplex channels for each interface, indexed by interface index.
    pub interfaces: Vec<PortComms>,
    /// Inner frames the router handed up for local delivery (i.e. what would
    /// be written to the TAP), in arrival order.  Lets tests assert that a
    /// packet reached its final destination and was delivered intact.
    pub local_deliveries: Vec<Vec<u8>>,
}

impl TestRouter {
    pub fn new_from_config(
        h: &mut TestHarness,
        mac: Mac,
        config: &wayfinder::config::Config,
    ) -> Self {
        let mut interfaces = vec![];

        for link in &config.links {
            match link {
                wayfinder::config::LinkConfig::Test { switch_name } => {
                    let duplex = h.add_switch_port(switch_name);

                    interfaces.push(duplex);
                }
                _ => panic!("unsupported link type in test mode"),
            }
        }

        Self::new(mac, interfaces)
    }

    /// Create a new test router with the given node identity and one egress
    /// sender per interface.
    pub fn new(ident: Mac, interfaces: Vec<PortComms>) -> Self {
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
    pub async fn send_local(&mut self, dest: Mac, payload: &[u8]) -> Result<(), ()> {
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
        let frame = parse_frame(raw);
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

    /// Drain all pending frames from links
    pub async fn drain_all(&mut self) {
        let msgs = self
            .interfaces
            .iter_mut()
            .enumerate()
            .flat_map(|(i, iface)| {
                let mut pending = vec![];
                while let Ok(raw) = iface.ingress.try_recv() {
                    pending.push((i, raw));
                }
                pending
            })
            .collect::<Vec<_>>();

        for (i, raw) in msgs {
            self.receive(i, &raw).await;
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
    async fn send_egress(&mut self, dst: Mac, wire: Vec<u8>) {
        // Resolve the egress decision before accessing self.interfaces so the
        // mutable borrow of self.router does not overlap with the channel sends.
        let egress = self.router.get_egress_interface(dst);
        match egress {
            Some(EgressInterface::Interface(idx)) if idx < self.interfaces.len() => {
                let _ = self.interfaces[idx].egress.send(wire).await;
            }
            _ => {
                // Broadcast destination or destination not yet learned — flood.
                for tx in &self.interfaces {
                    let _ = tx.egress.send(wire.clone()).await;
                }
            }
        }
    }
}
