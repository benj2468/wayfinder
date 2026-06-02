//! The router event loop, bundling all long-lived state behind one [`Driver`].
//!
//! The driver is transport-agnostic: the local host device and every mesh
//! interface are [`FrameIo`] carriers, so the *same* loop runs against real
//! sockets in production and against in-process channels in tests.  Two ways to
//! drive it:
//!
//! * [`Driver::run`] / [`Driver::run_once`] — the free-running `select!` loop
//!   used in production: it awaits whichever event happens first (a mesh frame,
//!   a host frame, a management query, or the periodic-broadcast timer).
//! * [`Driver::poll`] + [`Driver::process_pending`] — deterministic stepping
//!   for tests: drive the periodic broadcast at a chosen instant, then drain
//!   every already-pending frame in one non-blocking sweep.

use std::time::{Duration, Instant};

use futures::{FutureExt, future::select_all};
use pretty_hex::pretty_hex;
use tokio::time::{Interval, interval};
use tracing::info;
use wayfinder::interfaces::frame::{LinkFrame, LinkFrameData, Mac};
use wayfinder::{CentralRouter, EgressInterface, McastPlan};
use wayfinder_protos::service::WayfinderService;
use wayfinder_server::{QueryRx, RouterAdapter};
use zerocopy::FromBytes;

use crate::snoop::McastSnooper;
use crate::transport::{FrameIo, Link};

/// One unit of work's outgoing frames.
struct LoopOutput {
    /// `(destination ident, protocol, serialized payload)` frames to transmit
    /// onto the mesh, each dispatched via `get_egress_interface`.  Usually one,
    /// but a selectively-forwarded multicast frame produces one per listener.
    mesh: Vec<(Mac, u16, Vec<u8>)>,
    /// Inner frame to write back to the local host device.
    local: Option<Vec<u8>>,
}

impl LoopOutput {
    /// An empty unit of work — nothing to send anywhere.
    fn none() -> Self {
        Self {
            mesh: Vec::new(),
            local: None,
        }
    }
}

/// The router event loop and all the state it operates on.
///
/// `Local` is the host-facing device (a TUN/TAP in production, an observable
/// channel in tests); the mesh interfaces are type-erased [`Link`]s.
pub struct Driver<Local: FrameIo> {
    /// The local host network device.
    local: Local,
    /// The mesh interfaces, indexed by interface index.
    interfaces: Vec<Link>,
    /// The routing engine for this node.
    router: CentralRouter,
    /// Management-API queries forwarded from the server tasks.
    query_rx: QueryRx,
    /// This node's mesh identifier (its host device's MAC address).
    mac: Mac,
    /// Snoops IGMP on the host link to learn which multicast groups the local
    /// host listens to, so they can be announced to the mesh.
    snooper: McastSnooper,
    /// Reference instant for periodic-broadcast timing.
    start: Instant,
    /// Receive scratchpad for frames read from the host device.
    rx_buffer: [u8; 1500],
    /// Transmit scratchpad the router builds outgoing frames into.
    tx_buffer: [u8; 1500],
}

impl<Local: FrameIo> Driver<Local> {
    /// Build a driver for node `mac` over the given host device, mesh
    /// interfaces, and management-query channel.
    pub fn new(mac: Mac, local: Local, interfaces: Vec<Link>, query_rx: QueryRx) -> Self {
        Self {
            local,
            interfaces,
            router: CentralRouter::new(mac),
            query_rx,
            mac,
            snooper: McastSnooper::new(),
            start: Instant::now(),
            rx_buffer: [0u8; 1500],
            tx_buffer: [0u8; 1500],
        }
    }

    /// The underlying router, for inspecting routing state (originator tables,
    /// link quality, route resolution).
    pub fn router(&self) -> &CentralRouter {
        &self.router
    }

    /// The underlying router, mutably — lets callers inject crafted frames with
    /// explicit link metrics that the message-oriented transports cannot carry.
    pub fn router_mut(&mut self) -> &mut CentralRouter {
        &mut self.router
    }

    /// Run the event loop forever.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut int = interval(Duration::from_secs(10));
        loop {
            self.run_once(&mut int, true, true, true).await?;
        }
    }

    /// Run a single iteration: wait for whichever happens first — a frame from a
    /// mesh interface, a frame from the local host device, a management query,
    /// or the periodic-broadcast timer — process it, then deliver any inner
    /// frame to the host and dispatch any outgoing frame onto the mesh.
    #[tracing::instrument(skip(self, interval, check_local, check_mesh, check_server), fields(ident = ?self.mac))]
    pub async fn run_once(
        &mut self,
        interval: &mut Interval,
        check_local: bool,
        check_mesh: bool,
        check_server: bool,
    ) -> anyhow::Result<()> {
        // Destructure into disjoint field borrows so the `select!` can hold a
        // mutable borrow of the interfaces alongside the router and buffers.
        let Driver {
            local,
            interfaces,
            router,
            query_rx,
            mac,
            snooper,
            start,
            rx_buffer,
            tx_buffer,
        } = self;
        let mac = *mac;
        let start = *start;

        let output: LoopOutput = {
            tokio::select! {
                (Some((idx, frame)), _, _) = select_all(
                    interfaces.iter_mut().enumerate().map(|(i, iface)| {
                        Box::pin(async move { iface.receive().await.map(|frame| (i, frame)).ok() })
                    })
                ), if check_mesh && !interfaces.is_empty() => {
                    tracing::debug!("received frame from interface {}", idx);
                    handle_mesh_frame(router, idx, frame, tx_buffer)
                },
                Ok(len) = local.recv(rx_buffer), if check_local => {
                    tracing::debug!("host device received frame of length {}", len);
                    let eth = &rx_buffer[..len];
                    tracing::debug!("{}", pretty_hex(&eth));
                    LoopOutput {
                        mesh: plan_host_frame(router, snooper, eth, tx_buffer),
                        local: None,
                    }
                },
                Some((request, resp_tx)) = query_rx.recv(), if check_server => {
                    let response = WayfinderService::new(RouterAdapter::new(&*router)).handle(request);
                    let _ = resp_tx.send(response);
                    LoopOutput::none()
                },
                _ = interval.tick() => {
                    tracing::info!("polling OGM");
                    LoopOutput {
                        mesh: poll_ogm(router, start.elapsed(), tx_buffer),
                        local: None,
                    }
                }
            }
        };

        dispatch(local, interfaces, router, mac, output).await
    }

    /// Inject one host Ethernet frame as if it had arrived from the local
    /// device, wrapping it for the mesh and dispatching the resulting copies
    /// immediately.  Equivalent to the host-device arm of [`run_once`], exposed
    /// so a caller can push host traffic programmatically.
    ///
    /// [`run_once`]: Driver::run_once
    pub async fn inject_host_frame(&mut self, eth: &[u8]) -> anyhow::Result<()> {
        let mesh = plan_host_frame(
            &mut self.router,
            &mut self.snooper,
            eth,
            &mut self.tx_buffer,
        );
        self.dispatch_output(LoopOutput { mesh, local: None }).await
    }

    /// Drive one periodic-broadcast tick at instant `now` (relative to the
    /// reference instant), dispatching any OGM produced.  Deterministic
    /// counterpart to the `select!` timer arm, for tests that control time.
    pub async fn poll(&mut self, now: Duration) -> anyhow::Result<()> {
        let mesh = poll_ogm(&mut self.router, now, &mut self.tx_buffer);
        let output = LoopOutput { mesh, local: None };
        dispatch(
            &self.local,
            &mut self.interfaces,
            &mut self.router,
            self.mac,
            output,
        )
        .await
    }

    /// Drain every already-pending event — host frames, mesh frames, and
    /// management queries — in non-blocking sweeps until nothing remains.
    ///
    /// This is the deterministic counterpart to [`run_once`]: where `run_once`
    /// awaits the next single event, `process_pending` consumes the current
    /// backlog and returns.  Replies generated while draining are dispatched
    /// onto the egress channels, not fed back into this sweep, so the loop
    /// terminates.
    ///
    /// [`run_once`]: Driver::run_once
    pub async fn process_pending(&mut self) -> anyhow::Result<()> {
        loop {
            let mut progressed = false;

            // Host device: a frame the local host wants to put on the mesh.
            let polled = self.local.recv(&mut self.rx_buffer).now_or_never();
            if let Some(result) = polled {
                let len = result?;
                progressed = true;
                let eth = self.rx_buffer[..len].to_vec();
                let mesh = plan_host_frame(
                    &mut self.router,
                    &mut self.snooper,
                    &eth,
                    &mut self.tx_buffer,
                );
                self.dispatch_output(LoopOutput { mesh, local: None })
                    .await?;
            }

            // Mesh interfaces: forwarded/delivered frames.
            for idx in 0..self.interfaces.len() {
                if let Some(result) = self.interfaces[idx].try_recv_raw() {
                    progressed = true;
                    let raw = result?;
                    let output = {
                        let frame = LinkFrame::ref_from_bytes(&raw)
                            .map_err(|_| anyhow::anyhow!("malformed link frame"))?;
                        handle_mesh_frame(&mut self.router, idx, frame, &mut self.tx_buffer)
                    };
                    self.dispatch_output(output).await?;
                }
            }

            // Management queries from the in-process server.
            if let Ok((request, resp_tx)) = self.query_rx.try_recv() {
                progressed = true;
                let response =
                    WayfinderService::new(RouterAdapter::new(&self.router)).handle(request);
                let _ = resp_tx.send(response);
            }

            if !progressed {
                break;
            }
        }
        Ok(())
    }

    /// Deliver one unit of work via the borrowed `self` fields.
    async fn dispatch_output(&mut self, output: LoopOutput) -> anyhow::Result<()> {
        dispatch(
            &self.local,
            &mut self.interfaces,
            &mut self.router,
            self.mac,
            output,
        )
        .await
    }
}

/// Produce this node's periodic OGM (if one is due) as a mesh frame.
fn poll_ogm(
    router: &mut CentralRouter,
    now: Duration,
    tx_buffer: &mut [u8],
) -> Vec<(Mac, u16, Vec<u8>)> {
    router
        .poll(now, tx_buffer)
        .map(|f| (f.dst, f.protocol, f.payload.to_vec()))
        .into_iter()
        .collect()
}

/// Process one received link-layer frame into a unit of work.
fn handle_mesh_frame(
    router: &mut CentralRouter,
    idx: usize,
    frame: &LinkFrame,
    tx_buffer: &mut [u8],
) -> LoopOutput {
    let rx = router.handle_frame(idx, frame, tx_buffer);
    tracing::debug!("decoded as {:?}", rx);
    LoopOutput {
        mesh: rx
            .forward
            .map(|f| (f.dst, f.protocol, f.payload.to_vec()))
            .into_iter()
            .collect(),
        local: rx.deliver_local.map(|inner| inner.to_vec()),
    }
}

/// Turn one host Ethernet frame into the mesh frames that carry it.
///
/// The host hands us a full Ethernet frame `[dst MAC][src MAC][ethertype][..]`.
/// We route by the destination MAC — which *is* the mesh ident — and carry the
/// whole frame across the mesh untouched: a normal unicast for a single host, a
/// flooded broadcast for the all-ones address (or as multicast fallback), or —
/// for a multicast group with a known, bounded listener set — an individual
/// `BATADV_MCAST` copy per interested node.  IGMP is snooped first so the
/// groups the host joins/leaves are announced on the next OGM.
fn plan_host_frame(
    router: &mut CentralRouter,
    snooper: &mut McastSnooper,
    eth: &[u8],
    tx_buffer: &mut [u8],
) -> Vec<(Mac, u16, Vec<u8>)> {
    if snooper.observe(eth) {
        router.set_local_mcast_groups(&snooper.groups());
    }

    let mut mesh: Vec<(Mac, u16, Vec<u8>)> = Vec::new();
    if eth.len() < 14 {
        return mesh;
    }

    let mut dst_mac = [0u8; 6];
    dst_mac.copy_from_slice(&eth[0..6]);
    let dst = Mac(dst_mac);

    let flood =
        |router: &mut CentralRouter, mesh: &mut Vec<(Mac, u16, Vec<u8>)>, buf: &mut [u8]| {
            if let Ok(f) = router.handle_local(Mac::BROADCAST, eth, buf) {
                mesh.push((f.dst, f.protocol, f.payload.to_vec()));
            }
        };

    if dst.is_broadcast() {
        flood(router, &mut mesh, tx_buffer);
    } else if dst.is_multicast() {
        match router.mcast_plan(dst) {
            McastPlan::Unicast => {
                let targets: Vec<Mac> = router.mcast_targets(dst).collect();
                for target in targets {
                    if let Ok(f) = router.handle_local_mcast(target, eth, tx_buffer) {
                        mesh.push((f.dst, f.protocol, f.payload.to_vec()));
                    }
                }
            }
            McastPlan::Flood => flood(router, &mut mesh, tx_buffer),
        }
    } else if let Ok(f) = router.handle_local(dst, eth, tx_buffer) {
        mesh.push((f.dst, f.protocol, f.payload.to_vec()));
    }

    mesh
}

/// Deliver one unit of work: write any inner frame to the host device and
/// dispatch each outgoing frame onto the mesh via `get_egress_interface`.
async fn dispatch<Local: FrameIo>(
    local: &Local,
    interfaces: &mut [Link],
    router: &mut CentralRouter,
    mac: Mac,
    output: LoopOutput,
) -> anyhow::Result<()> {
    if let Some(inner) = output.local {
        tracing::debug!("local output: {}", pretty_hex(&inner));
        local.send(&inner).await?;
    }

    for (dst, protocol, payload) in output.mesh {
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

        match router.get_egress_interface(dst) {
            Some(EgressInterface::All) => {
                for iface in interfaces.iter_mut() {
                    iface.send(mac, &data).await?;
                }
            }
            Some(EgressInterface::Interface(iface_idx)) => {
                if let Some(iface) = interfaces.get_mut(iface_idx) {
                    iface.send(mac, &data).await?;
                }
            }
            None => {}
        }
    }

    Ok(())
}
