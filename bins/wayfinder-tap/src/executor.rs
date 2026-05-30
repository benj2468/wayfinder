//! The main executor: the router event loop bundling all long-lived state so a
//! single iteration ([`EventLoop::run_once`]) can be driven deterministically in
//! tests against a fake TAP and in-process mesh links.

use futures::{StreamExt, stream::FuturesOrdered};
use pretty_hex::pretty_hex;
use wayfinder::CentralRouter;
use wayfinder::EgressInterface;
use wayfinder::interfaces::frame::{LinkFrameData, MeshIdentifier};
use wayfinder_protos::service::WayfinderService;

use wayfinder_server::{QueryRx, RouterAdapter};

use crate::links::{AsyncIo, Link};

/// All the long-lived state the router event loop operates on, bundled so that
/// [`EventLoop::run_once`] can be driven deterministically in tests (with a
/// fake [`AsyncIo`] and in-process [`Link`]s) instead of from `main`.
pub(crate) struct EventLoop<Tap: AsyncIo> {
    /// The local host network device.
    pub(crate) tap: Tap,
    /// The mesh interfaces, indexed by interface index.
    pub(crate) interfaces: Vec<Link>,
    /// The routing engine for this node.
    pub(crate) router: CentralRouter<[u8; 6]>,
    /// Management-API queries forwarded from the server tasks.
    pub(crate) query_rx: QueryRx,
    /// This node's mesh identifier (its TAP MAC address).
    pub(crate) mac_addr: [u8; 6],
    /// Reference instant for periodic-broadcast timing.
    pub(crate) start: std::time::Instant,
    /// Receive scratchpad for frames read from the TAP.
    pub(crate) rx_buffer: [u8; 1500],
    /// Transmit scratchpad the router builds outgoing frames into.
    pub(crate) tx_buffer: [u8; 1500],
}

/// One iteration's worth of work, fully owned so that no borrow of the rx/tx
/// scratchpads or the interface set escapes the `select!`.
struct LoopOutput {
    /// `(destination ident, protocol, serialized payload)` to transmit onto
    /// the mesh, dispatched via `get_egress_interface`.
    mesh: Option<([u8; 6], u16, Vec<u8>)>,
    /// Inner frame to write back to the local TAP device.
    local: Option<Vec<u8>>,
}

impl<Tap: AsyncIo> EventLoop<Tap> {
    /// Run a single iteration: wait for whichever happens first — a frame from
    /// a mesh interface, a frame from the local TAP, a management query, or the
    /// periodic-broadcast timer — process it, then deliver any inner frame to
    /// the TAP and dispatch any outgoing frame onto the mesh.
    pub(crate) async fn run_once(&mut self) -> anyhow::Result<()> {
        // Destructure into disjoint field borrows so the `select!` can hold a
        // mutable borrow of the interfaces alongside the router and buffers.
        let EventLoop {
            tap,
            interfaces,
            router,
            query_rx,
            mac_addr,
            start,
            rx_buffer,
            tx_buffer,
        } = self;
        let mac_addr = *mac_addr;
        let start = *start;

        let output: LoopOutput = {
            let mut futures = interfaces
                .iter_mut()
                .enumerate()
                .map(|(i, iface)| async move { iface.receive().await.map(|frame| (i, frame)).ok() })
                .collect::<FuturesOrdered<_>>();

            tokio::select! {
                Some(Some((idx, frame))) = futures.next() => {
                    tracing::debug!("received frame from interface {}", idx);
                    let rx = router.handle_frame(idx, frame, tx_buffer);
                    tracing::debug!("decoded as {:?}", rx);
                    LoopOutput {
                        mesh: rx.forward.map(|f| (f.dst, f.protocol, f.payload.to_vec())),
                        local: rx.deliver_local.map(|inner| inner.to_vec()),
                    }
                },
                Ok(len) = tap.recv(rx_buffer) => {
                    tracing::debug!("tap received frame of length {}", len);
                    // The TAP hands us a full Ethernet frame:
                    // [dst MAC:6][src MAC:6][ethertype:2][payload...].  Route by
                    // the destination MAC — which *is* the mesh Ident — and
                    // carry the whole frame across the mesh untouched.
                    let eth = &rx_buffer[..len];
                    tracing::debug!("{}", pretty_hex::pretty_hex(&eth));
                    let mesh = if eth.len() >= 14 {
                        let mut dst_mac = [0u8; 6];
                        dst_mac.copy_from_slice(&eth[0..6]);
                        // The I/G bit (LSB of the first octet) marks multicast /
                        // broadcast destinations, which we flood across the mesh.
                        let dest = if dst_mac[0] & 0x01 != 0 {
                            <[u8; 6]>::BROADCAST
                        } else {
                            dst_mac
                        };
                        router
                            .handle_local(dest, eth, tx_buffer)
                            .ok()
                            .map(|f| (f.dst, f.protocol, f.payload.to_vec()))
                    } else {
                        None
                    };
                    LoopOutput { mesh, local: None }
                },
                Some((request, resp_tx)) = query_rx.recv() => {
                    let response = WayfinderService::new(RouterAdapter::new(&*router)).handle(request);
                    let _ = resp_tx.send(response);
                    LoopOutput { mesh: None, local: None }
                },
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                    LoopOutput {
                        mesh: router
                            .poll(start.elapsed(), tx_buffer)
                            .map(|f| (f.dst, f.protocol, f.payload.to_vec())),
                        local: None,
                    }
                }
            }
        };

        tracing::debug!("output: mesh={:?} local={:?}", output.mesh, output.local);

        // Hand any inner frame up to the local host by writing it to the TAP.
        if let Some(local) = output.local {
            tracing::debug!("local output: {}", pretty_hex(&local));
            tap.send(&local).await?;
        }

        // Dispatch any outgoing frame onto the mesh.
        if let Some((dst, protocol, payload)) = output.mesh {
            tracing::debug!(
                "mesh output: dst={:?} protocol={:?} payload={:?}",
                dst,
                protocol,
                payload
            );
            let data = LinkFrameData {
                dst,
                protocol,
                payload: &payload,
            };

            if let Some(egress) = router.get_egress_interface(dst) {
                tracing::debug!("egress: {:?}", egress);
                match egress {
                    EgressInterface::All => {
                        for iface in interfaces.iter_mut() {
                            iface.send(mac_addr, &data).await?;
                        }
                    }
                    EgressInterface::Interface(iface_idx) => {
                        if let Some(iface) = interfaces.get_mut(iface_idx) {
                            iface.send(mac_addr, &data).await?;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
