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

use anyhow::bail;
use futures::{FutureExt, future::select_all};
use interfaces::link::LinkMetrics;
use pretty_hex::pretty_hex;
use tokio::time::sleep;
use wayfinder::auth::DIRECTED_TRAILER_LEN;
use wayfinder::config::TrickleConfig;
use wayfinder::interfaces::frame::{LinkFrame, LinkFrameData, Mac};
use wayfinder::{CentralRouter, DEFAULT_BATMAN_ETHER_TYPE, EgressInterface, McastPlan};
use wayfinder_protos::service::WayfinderService;
use wayfinder_server::{CertAuthority, MeshAuthority, QueryRx, RouterAdapter};
use zerocopy::{FromBytes, IntoBytes};

use wayfinder::link::{DynLinkT, LinkT};

use crate::snoop::McastSnooper;
use crate::transport::FrameIo;

/// How an [`OutgoingFrame`] is fanned out onto the mesh.
enum Egress {
    /// Let the router pick the egress (`get_egress_interface`): a metric-driven
    /// single interface for a unicast, or every interface for a broadcast/flood.
    /// `exclude` is the interface index a re-flood arrived on — split-horizon,
    /// so a re-flood never goes back toward the neighbor it came from (which
    /// would otherwise circulate OGMs/broadcasts until their TTL drains).
    /// `None` for locally originated frames, which go out every interface.
    Auto { exclude: Option<usize> },
    /// Send out exactly one interface by index, bypassing the router's egress
    /// choice.  Used for per-link OGM emission, where each interface fires on
    /// its own adaptive (Trickle) schedule rather than flooding all at once.
    Iface(usize),
}

/// One frame to put on the mesh, plus how to fan it out.
struct OutgoingFrame {
    /// Destination ident (a next-hop neighbor, or `BROADCAST` for a flood).
    dst: Mac,
    /// EtherType-style protocol identifier stamped on the link frame.
    protocol: u16,
    /// Serialized payload to transmit.
    payload: Vec<u8>,
    /// How to dispatch this frame onto the mesh interfaces.
    egress: Egress,
}

/// One unit of work's outgoing frames.
struct LoopOutput {
    /// Frames to transmit onto the mesh, each dispatched via
    /// `get_egress_interface`.  Usually one, but a selectively-forwarded
    /// multicast frame produces one per listener.
    mesh: Vec<OutgoingFrame>,
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
/// channel in tests); the mesh interfaces are type-erased [`LinkT`]s, so simple
/// point-to-point carriers and self-routing multi-access links can be mixed.
pub struct Driver<Local: FrameIo> {
    /// The local host network device.
    local: Local,
    /// The mesh interfaces, indexed by interface index.
    interfaces: Vec<Box<DynLinkT<'static>>>,
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
    /// Wall-clock unix time (seconds) corresponding to `now == 0` (the `start`
    /// instant).  The auth clock is then `auth_epoch_unix + now`, so it advances
    /// with the loop's `now` rather than reading the wall clock each tick — which
    /// lets a test drive certificate-validity time forward (faster than real
    /// time) via the `now` it already controls.  Defaults to the wall clock at
    /// construction; override with [`set_auth_epoch_unix`](Self::set_auth_epoch_unix).
    auth_epoch_unix: u64,
    /// Receive scratchpad for frames read from the host device.
    rx_buffer: [u8; 1500],
    /// Transmit scratchpad the router builds outgoing frames into.
    tx_buffer: [u8; 1500],
    /// The mesh certificate authority, present only when this node runs in
    /// provider mode (set via [`set_provider`](Self::set_provider)).  Serves the
    /// enrollment management-API requests; absent ⇒ those return an error.
    provider: Option<CertAuthority>,
}

impl<Local: FrameIo> Driver<Local> {
    /// Build a driver for node `mac` over the given host device, mesh
    /// interfaces, and management-query channel.  `trickle` supplies each
    /// interface's per-link adaptive OGM bounds (`i_min`/`i_max`), in interface
    /// order; interfaces without an entry fall back to [`TrickleConfig::default`].
    pub fn new(
        mac: Mac,
        local: Local,
        interfaces: Vec<Box<DynLinkT<'static>>>,
        trickle: Vec<TrickleConfig>,
        query_rx: QueryRx,
    ) -> Self {
        let mut router = CentralRouter::new(mac);
        // Install each interface's adaptive OGM schedule up front so the
        // periodic loop has a per-interface timer to consult from the start.
        for idx in 0..interfaces.len() {
            let cfg = trickle.get(idx).copied().unwrap_or_default();
            router.configure_interface_ogm(idx, cfg.i_min(), cfg.i_max(), Duration::ZERO);
        }
        Self {
            local,
            interfaces,
            router,
            query_rx,
            mac,
            snooper: McastSnooper::new(),
            start: Instant::now(),
            auth_epoch_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            rx_buffer: [0u8; 1500],
            tx_buffer: [0u8; 1500],
            provider: None,
        }
    }

    /// Enable provider (certificate-authority) mode: the node serves enrollment
    /// requests (`GetTrustAnchor`/`SubmitCsr`/`RevokeNode`) from this `ca`.
    pub fn set_provider(&mut self, ca: CertAuthority) {
        self.provider = Some(ca);
    }

    /// Set the wall-clock unix time (seconds) that corresponds to the driver's
    /// `now == 0`.  The auth clock used for certificate-validity checks is then
    /// `epoch + now`.  Tests set this to a fixed value and drive `now` forward to
    /// exercise expiry deterministically, faster than real time.
    pub fn set_auth_epoch_unix(&mut self, epoch_unix: u64) {
        self.auth_epoch_unix = epoch_unix;
    }

    /// Advance the auth state's certificate-validity clock to `auth_epoch_unix +
    /// now`.  A no-op when auth is disabled.  Called from every entry point that
    /// processes frames so cert expiry tracks the loop's `now` consistently.
    fn refresh_auth_clock(&mut self, now: Duration) {
        let epoch = self.auth_epoch_unix;
        let unix = epoch.saturating_add(now.as_secs());
        if let Some(auth) = self.router.auth_mut() {
            auth.set_time(unix);
        }
        // Keep the provider CA's issuance clock in step, so issued certificate
        // validity windows track the same time the router verifies against.
        if let Some(ca) = self.provider.as_mut() {
            ca.set_now_unix(unix);
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
        loop {
            let now = self.start.elapsed();
            self.run_once(now, true, true, true, true).await?;
        }
    }

    /// Run a single iteration: wait for whichever happens first — a frame from a
    /// mesh interface, a frame from the local host device, a management query,
    /// or the periodic-broadcast timer — process it, then deliver any inner
    /// frame to the host and dispatch any outgoing frame onto the mesh.
    ///
    /// `now` is the current instant (relative to the driver's reference instant)
    /// stamped on received originator records and on any OGM produced, so a
    /// caller that controls time — e.g. a deterministic test — controls route
    /// ageing.  Production passes `self.start.elapsed()`.
    #[tracing::instrument(
        skip(self, check_local, check_mesh, check_server, check_periodic),
        fields(ident = ?self.mac)
    )]
    pub async fn run_once(
        &mut self,
        now: Duration,
        check_local: bool,
        check_mesh: bool,
        check_server: bool,
        check_periodic: bool,
    ) -> anyhow::Result<()> {
        // Advance the auth clock from the loop's `now` (see `refresh_auth_clock`).
        self.refresh_auth_clock(now);

        // When the soonest interface is next due to emit an OGM, on the tokio
        // clock.  Each interface backs off (Trickle) on its own schedule, so the
        // periodic arm sleeps until whichever fires first.  Recomputed every
        // iteration, so a timer reset by the frame just processed (an
        // inconsistency) shortens the next sleep automatically.
        let next_due = self.router.next_broadcast_after(now);

        // Destructure into disjoint field borrows so the `select!` can hold a
        // mutable borrow of the interfaces alongside the router and buffers.
        let Driver {
            local,
            interfaces,
            router,
            query_rx,
            mac,
            snooper,
            start: _,
            auth_epoch_unix: _,
            rx_buffer,
            tx_buffer,
            provider,
        } = self;
        let mac = *mac;

        let output: LoopOutput = {
            tokio::select! {
                (Some((idx, received)), _, _) = select_all(
                    interfaces.iter_mut().enumerate().map(|(i, iface)| {
                        Box::pin(async move { iface.recv().await.map(|received| (i, received)).ok() })
                    })
                ), if check_mesh && !interfaces.is_empty() => {
                    tracing::debug!("received frame from interface {}", idx);
                    handle_mesh_frame(now, router, idx, received.frame, received.metrics, tx_buffer)
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
                    let ca = provider.as_mut().map(|c| c as &mut dyn MeshAuthority);
                    let response = WayfinderService::new(RouterAdapter::new(&mut *router, ca, now)).handle(request);
                    let _ = resp_tx.send(response);
                    LoopOutput::none()
                },
                _ = sleep(next_due), if check_periodic => {
                    tracing::info!("polling OGM");
                    LoopOutput {
                        mesh: poll_due_ogms(router, now, tx_buffer),
                        local: None,
                    }
                }
            }
        };

        dispatch(local, interfaces, router, mac, now, output).await
    }

    /// Inject one host Ethernet frame as if it had arrived from the local
    /// device, wrapping it for the mesh and dispatching the resulting copies
    /// immediately.  Equivalent to the host-device arm of [`run_once`], exposed
    /// so a caller can push host traffic programmatically.
    ///
    /// [`run_once`]: Driver::run_once
    pub async fn inject_host_frame(&mut self, eth: &[u8]) -> anyhow::Result<()> {
        let now = self.start.elapsed();
        let mesh = plan_host_frame(
            &mut self.router,
            &mut self.snooper,
            eth,
            &mut self.tx_buffer,
        );
        self.dispatch_output(now, LoopOutput { mesh, local: None })
            .await
    }

    /// Drive one *per-interface* periodic tick at instant `now`: emit an OGM for
    /// each interface whose Trickle timer is due (advancing that timer), exactly
    /// as the production periodic arm does via [`poll_due_ogms`].  This is the
    /// deterministic, sleep-free counterpart to the `check_periodic` arm of
    /// [`run_once`] — where that arm `sleep`s until the soonest timer fires on the
    /// real tokio clock, this emits whatever is already due at the caller-supplied
    /// `now`, so a test controlling the clock exercises the true per-interface
    /// Trickle emission path (distinct seqno per interface) rather than the
    /// all-interface [`poll`](Self::poll) flood.
    ///
    /// [`run_once`]: Driver::run_once
    pub async fn poll_due(&mut self, now: Duration) -> anyhow::Result<()> {
        self.refresh_auth_clock(now);
        let mesh = poll_due_ogms(&mut self.router, now, &mut self.tx_buffer);
        let output = LoopOutput { mesh, local: None };
        dispatch(
            &self.local,
            &mut self.interfaces,
            &mut self.router,
            self.mac,
            now,
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
        self.refresh_auth_clock(self.start.elapsed());
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
                self.dispatch_output(self.start.elapsed(), LoopOutput { mesh, local: None })
                    .await?;
            }

            // Mesh interfaces: forwarded/delivered frames.
            for idx in 0..self.interfaces.len() {
                let output = match self.interfaces[idx].recv().now_or_never() {
                    None => continue,
                    Some(Err(e)) => bail!("link recv failed: {e:?}"),
                    Some(Ok(received)) => {
                        progressed = true;
                        handle_mesh_frame(
                            self.start.elapsed(),
                            &mut self.router,
                            idx,
                            received.frame,
                            received.metrics,
                            &mut self.tx_buffer,
                        )
                    }
                };
                self.dispatch_output(self.start.elapsed(), output).await?;
            }

            // Management queries from the in-process server.
            if let Ok((request, resp_tx)) = self.query_rx.try_recv() {
                progressed = true;
                let now = self.start.elapsed();
                let ca = self.provider.as_mut().map(|c| c as &mut dyn MeshAuthority);
                let response = WayfinderService::new(RouterAdapter::new(&mut self.router, ca, now))
                    .handle(request);
                let _ = resp_tx.send(response);
            }

            if !progressed {
                break;
            }
        }
        Ok(())
    }

    /// Deliver one unit of work via the borrowed `self` fields, stamping any
    /// transmit-rate accounting with `now`.
    async fn dispatch_output(&mut self, now: Duration, output: LoopOutput) -> anyhow::Result<()> {
        dispatch(
            &self.local,
            &mut self.interfaces,
            &mut self.router,
            self.mac,
            now,
            output,
        )
        .await
    }
}

/// Produce an OGM for each interface that is due to emit as of `now`, addressed
/// to that one interface.  Every link backs off (Trickle) independently, so on
/// a given wake-up only the interface(s) whose timer has fired emit; each is
/// then advanced toward its `i_max`.
fn poll_due_ogms(
    router: &mut CentralRouter,
    now: Duration,
    tx_buffer: &mut [u8],
) -> Vec<OutgoingFrame> {
    let mut out = Vec::new();
    // Each emission advances exactly one interface's timer, so the set of due
    // interfaces shrinks every pass and the loop terminates.
    while let Some(idx) = router.due_interface(now) {
        if let Some(f) = router.poll(now, tx_buffer) {
            out.push(OutgoingFrame {
                dst: f.dst,
                protocol: f.protocol,
                payload: f.payload.to_vec(),
                egress: Egress::Iface(idx),
            });
        }
        router.on_interface_emitted(idx, now);
    }
    out
}

/// Verify and strip the pairwise tag trailer from a directed data-plane frame
/// when auth is enabled, returning the frame to route on: the original frame
/// (auth off, or a broadcast/OGM), a shorter *view* over the same bytes with the
/// trailer dropped, or `None` if the frame must be dropped (bad/missing tag from
/// an unverified or foreign neighbor).
fn strip_directed<'a>(router: &mut CentralRouter, frame: &'a LinkFrame) -> Option<&'a LinkFrame> {
    // Only directed (unicast/mcast) frames carry a tag; broadcasts/OGMs (a
    // multicast dst) are signed, and with auth off nothing is tagged.
    let Some(auth) = router.auth_mut() else {
        return Some(frame);
    };
    if frame.protocol.get() != DEFAULT_BATMAN_ETHER_TYPE || frame.dst.is_multicast() {
        return Some(frame);
    }

    let body_len = frame.payload.len().checked_sub(DIRECTED_TRAILER_LEN)?;
    let (inner, trailer) = frame.payload.split_at(body_len);
    if !auth.verify_directed(frame.src, inner, trailer) {
        return None; // unverified/foreign neighbor or replay — drop
    }

    // Reinterpret the frame's own bytes minus the trailer — a shorter view over
    // the same buffer (no copy) — so the engine sees only the real payload and
    // never forwards or delivers the tag bytes.
    let full = frame.as_bytes();
    let strip_len = full.len() - DIRECTED_TRAILER_LEN;
    LinkFrame::ref_from_bytes(full.get(..strip_len)?).ok()
}

/// Process one received link-layer frame into a unit of work, folding the
/// carrier's physical-layer `metrics` into the engine's link-quality table.
fn handle_mesh_frame(
    now: Duration,
    router: &mut CentralRouter,
    idx: usize,
    frame: &LinkFrame,
    metrics: LinkMetrics,
    tx_buffer: &mut [u8],
) -> LoopOutput {
    let Some(frame) = strip_directed(router, frame) else {
        return LoopOutput::none(); // directed frame failed authentication
    };
    let rx = router.handle_frame_with_metrics(now, idx, frame, metrics, tx_buffer);
    tracing::debug!("decoded as {:?}", rx);
    LoopOutput {
        mesh: rx
            .forward
            .map(|f| OutgoingFrame {
                dst: f.dst,
                protocol: f.protocol,
                payload: f.payload.to_vec(),
                // A re-flood must not go back out the interface it arrived on.
                egress: Egress::Auto { exclude: Some(idx) },
            })
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
) -> Vec<OutgoingFrame> {
    if snooper.observe(eth) {
        router.set_local_mcast_groups(&snooper.groups());
    }

    let mut mesh: Vec<OutgoingFrame> = Vec::new();
    if eth.len() < 14 {
        return mesh;
    }

    let mut dst_mac = [0u8; 6];
    dst_mac.copy_from_slice(&eth[0..6]);
    let dst = Mac(dst_mac);

    // Locally originated frames flood out every interface (no ingress to omit).
    let flood = |router: &mut CentralRouter, mesh: &mut Vec<OutgoingFrame>, buf: &mut [u8]| {
        if let Ok(f) = router.handle_local(Mac::BROADCAST, eth, buf) {
            mesh.push(OutgoingFrame {
                dst: f.dst,
                protocol: f.protocol,
                payload: f.payload.to_vec(),
                egress: Egress::Auto { exclude: None },
            });
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
                        mesh.push(OutgoingFrame {
                            dst: f.dst,
                            protocol: f.protocol,
                            payload: f.payload.to_vec(),
                            egress: Egress::Auto { exclude: None },
                        });
                    }
                }
            }
            McastPlan::Flood => flood(router, &mut mesh, tx_buffer),
        }
    } else if let Ok(f) = router.handle_local(dst, eth, tx_buffer) {
        mesh.push(OutgoingFrame {
            dst: f.dst,
            protocol: f.protocol,
            payload: f.payload.to_vec(),
            egress: Egress::Auto { exclude: None },
        });
    }

    mesh
}

/// Deliver one unit of work: write any inner frame to the host device and
/// dispatch each outgoing frame onto the mesh via `get_egress_interface`.
async fn dispatch<Local: FrameIo>(
    local: &Local,
    interfaces: &mut [Box<DynLinkT<'static>>],
    router: &mut CentralRouter,
    mac: Mac,
    now: Duration,
    output: LoopOutput,
) -> anyhow::Result<()> {
    if let Some(inner) = output.local {
        tracing::debug!("local output: {}", pretty_hex(&inner));
        local.send(&inner).await?;
    }

    for OutgoingFrame {
        dst,
        protocol,
        mut payload,
        egress,
    } in output.mesh
    {
        tracing::debug!(
            "mesh output: dst={:?} protocol={:?} payload={:?}",
            dst,
            protocol,
            payload
        );

        // Authenticate directed data-plane frames (unicast/mcast to a specific
        // next hop) with a pairwise tag when auth is enabled.  Broadcasts/OGMs
        // (a multicast dst) are signed instead, so they are skipped here.
        if protocol == DEFAULT_BATMAN_ETHER_TYPE
            && !dst.is_multicast()
            && let Some(auth) = router.auth_mut()
        {
            // Grow the payload by the trailer and let `tag_directed` write the
            // tag straight into the appended bytes (no separate scratch buffer).
            let body_len = payload.len();
            payload.resize(body_len + DIRECTED_TRAILER_LEN, 0);
            let (frame, trailer) = payload.split_at_mut(body_len);
            if auth.tag_directed(dst, frame, trailer).is_none() {
                // Auth on but we can't tag this directed frame (no verified key
                // for dst yet, or counter exhausted): drop it rather than emit it
                // in the clear.
                tracing::debug!("auth: dropping untaggable directed frame to {dst:?}");
                continue;
            }
        }

        let data = LinkFrameData {
            dst,
            protocol,
            payload: &payload,
        };

        match egress {
            // A per-link OGM goes out exactly one interface, on that link's own
            // adaptive schedule.
            Egress::Iface(iface_idx) => {
                if let Some(iface) = interfaces.get_mut(iface_idx) {
                    let sent = iface.send(mac, &data).await?;
                    router.record_tx(iface_idx, sent, now);
                }
            }
            // Otherwise let the router's metric-driven egress choice decide.
            Egress::Auto { exclude } => match router.get_egress_interface(dst) {
                Some(EgressInterface::All) => {
                    for (idx, iface) in interfaces.iter_mut().enumerate() {
                        // Split-horizon: skip the interface a re-flood arrived on.
                        if Some(idx) == exclude {
                            continue;
                        }
                        let sent = iface.send(mac, &data).await?;
                        router.record_tx(idx, sent, now);
                    }
                }
                Some(EgressInterface::Interface(iface_idx)) => {
                    if let Some(iface) = interfaces.get_mut(iface_idx) {
                        let sent = iface.send(mac, &data).await?;
                        router.record_tx(iface_idx, sent, now);
                    }
                }
                None => {}
            },
        }
    }

    Ok(())
}
