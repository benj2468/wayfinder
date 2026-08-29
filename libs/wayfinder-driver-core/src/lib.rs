//! Shared, `no_std` router-orchestration logic for the wayfinder drivers.
//!
//! All three driver shells — the `std`/tokio [`wayfinder-driver`], the
//! `no_std` [`wayfinder-embedded-driver`], and the synchronous
//! [`wayfinder-tick-driver`] — turn the same three inputs into the same
//! outgoing frames: a received mesh frame, a due periodic OGM, and (later) a
//! host frame.  That translation is the logic here.  It is deliberately
//! **synchronous and allocation-free**: it plans each outgoing frame into an
//! [`OutgoingFrame`] borrowing the caller's transmit scratchpad and hands it to
//! a [`MeshSink`], which copies it into whatever staging the driver uses
//! (`Vec` on the host, `heapless::Vec` on embedded) before the scratchpad is
//! reused.
//!
//! The transmit side is shared the same way: [`plan_dispatch`] makes the whole
//! outgoing decision — authenticate the frame, resolve its egress, apply
//! the per-link transmit gate — and returns *how much to
//! send* and *which interfaces* to send it on.  What stays in each driver is
//! only the async event loop, the interface set, and the actual I/O for the
//! interfaces in that plan: "one behavior, three loops".
//!
//! # The whole surface
//!
//! A shell's event loop has three arms, and each maps to one call here:
//!
//! | event-loop arm | call |
//! |---|---|
//! | a link produced a `recv` result | [`handle_link_result`] |
//! | the periodic timer fired | [`poll_due_all`] |
//! | a staged frame is ready to go out | [`plan_dispatch`] |
//!
//! The first two hand their results to a [`MeshSink`]; the third returns a
//! [`DispatchPlan`]. [`handle_mesh_frame`], [`poll_due_ogms`] and
//! [`poll_due_keepalives`] sit underneath and are exposed for callers that need
//! one step in isolation — deterministic stepping in tests, mostly.
//!
//! Everything else — authenticating a directed frame on the way in or out,
//! resolving egress, gating each link — is internal, deliberately: a shell that
//! reached past these could apply half the policy.
//!
//! [`wayfinder-tick-driver`]: https://docs.rs/wayfinder-tick-driver
//! [`wayfinder-driver`]: https://docs.rs/wayfinder-driver
//! [`wayfinder-embedded-driver`]: https://docs.rs/wayfinder-embedded-driver
#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use core::time::Duration;

use interfaces::link::LinkError;
use interfaces::link::LinkMetrics;
use tracing::trace;
use wayfinder::DEFAULT_BATMAN_ETHER_TYPE;
use wayfinder::EgressInterface;
use wayfinder::auth::DIRECTED_TRAILER_LEN;
use wayfinder::batman::wire::BatmanPacketType;
use wayfinder::interfaces::frame::LinkFrame;
use wayfinder::interfaces::frame::Mac;
use wayfinder::link::Received;
use wayfinder::router_ops::OgmAuthOps;
use wayfinder::router_ops::RouterOps;
use wayfinder_alarm::AlarmKind;
use wayfinder_alarm::NodeId;
use wayfinder_alarm::Severity;
use wayfinder_alarm::Subject;
use wayfinder_alarm::alarm;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

/// How an [`OutgoingFrame`] is fanned out onto the mesh interfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Egress {
    /// Let the router pick the egress (`get_egress_interface`): a metric-driven
    /// single interface for a unicast, or every interface for a
    /// broadcast/flood.
    ///
    /// **A flood goes out every interface, including the one a re-flood arrived
    /// on** — there is deliberately no interface-level split-horizon, because
    /// one interface is not one neighbor. On a radio whose peers are out of
    /// range of each other, or a `UdpMulti` link with one tunnel per peer, the
    /// ingress interface is the only path to whoever missed the original.
    /// This is the canonical statement of that rule; elsewhere points here.
    ///
    /// Loop protection lives in the engine: a node drops the copy that comes
    /// back to it as its own originator, and every other copy is stopped by a
    /// per-originator seqno **high-water mark** (separate ones for OGMs and
    /// broadcasts). That is a watermark, not set membership — it resets when an
    /// originator record is evicted or purged, and is not wraparound-aware.
    /// The exclusion this replaced masked neither: it never bounded a loop
    /// across a cyclic mesh, only the immediate one-hop echo.
    ///
    /// Costs N² OGM frames per Trickle round on a shared segment of N nodes,
    /// where it cost N; see `flooding_every_interface_costs_a_quadratic_number_of_ogms`.
    Auto,
    /// Send out exactly one interface by index, bypassing the router's egress
    /// choice — used for per-link OGM emission on each link's own Trickle
    /// schedule.
    ///
    /// Also bypasses the per-link **transmit gate**, deliberately: the emitter
    /// (`poll_due_ogms`) has already consulted that link's `tx_ogm`, and
    /// gating again here would be both redundant and wrong.
    Iface(usize),
}

/// One frame to put on the mesh, plus how to fan it out.
///
/// `payload` borrows the caller's transmit scratchpad, which is reused on the
/// next planning call, so a [`MeshSink`] must copy it before returning from
/// [`emit`](MeshSink::emit).
pub struct OutgoingFrame<'a> {
    /// Destination ident (a next-hop neighbor, or [`Mac::BROADCAST`] for a
    /// flood).
    pub dst: Mac,
    /// EtherType-style protocol identifier stamped on the link frame.
    pub protocol: u16,
    /// Serialized payload to transmit, borrowed from the transmit scratchpad.
    pub payload: &'a [u8],
    /// How to dispatch this frame onto the mesh interfaces.
    pub egress: Egress,
}

/// Where a driver receives the frames the shared planning logic produces.
///
/// The planning functions call [`emit`](Self::emit) once per outgoing mesh
/// frame and [`deliver_local`](Self::deliver_local) for any payload bound for
/// the local host device.  A router-only node (no host device) leaves
/// `deliver_local` at its default no-op.
pub trait MeshSink {
    /// Accept one frame bound for the mesh.  The implementation **must** copy
    /// `frame.payload` before returning — it borrows a scratchpad reused on the
    /// next planning call.
    fn emit(&mut self, frame: OutgoingFrame<'_>);

    /// Accept one inner payload bound for the local host device.  Defaults to a
    /// no-op for nodes that route only and have no host device to deliver to.
    fn deliver_local(&mut self, inner: &[u8]) {
        let _ = inner;
    }
}

/// Whether `payload`'s BATMAN sub-type must carry the pairwise trailer when
/// auth is on.
///
/// **This is decided by the sub-type, never by the link-layer destination.**
/// The two are unrelated fields, both attacker-chosen on an injected frame, and
/// keying the requirement on the link dst is what let a `Unicast`/`Mcast` wear
/// a group MAC to skip the tag check while still being delivered or relayed by
/// its *inner* `dest` — an unauthenticated injection primitive into the
/// directed data plane, and (via a relay's own re-tagging on the forward) a way
/// to launder outsider bytes onto a node that never shared a medium with the
/// attacker.
///
/// The exemptions are the packets for which a pairwise tag is either impossible
/// or redundant, and nothing else:
///
/// * [`Ogm`](BatmanPacketType::Ogm), [`Bcast`](BatmanPacketType::Bcast) and
///   [`Keepalive`](BatmanPacketType::Keepalive) are one-to-many — a per-neighbor
///   key cannot cover a flood. An OGM and a keep-alive carry the originator's
///   own signature instead; a `Bcast` carries nothing, which is the documented
///   scope limit in [`wayfinder::auth`].
/// * [`CertReq`](BatmanPacketType::CertReq) and
///   [`CertReply`](BatmanPacketType::CertReply) are addressed like directed
///   frames but self-authenticating: each carries its own signature, and
///   requiring a pairwise tag would make lazy cert distribution unable to
///   bootstrap the very keys that tag needs.
///
/// Everything else requires one, including a sub-type this build does not
/// recognise. `BatmanEngine::handle_rx` hands an unknown type to
/// `route_by_dest`, which will deliver or forward it, so it is directed in
/// every way that matters here — and a future sub-type this build has never
/// seen may well be routed by an inner `dest` of its own. Failing closed costs
/// nothing: no honest peer emits a sub-type we cannot classify.
fn requires_pairwise_tag(payload: &[u8]) -> bool {
    match payload.first().copied().and_then(BatmanPacketType::from_u8) {
        Some(
            BatmanPacketType::Ogm
            | BatmanPacketType::Bcast
            | BatmanPacketType::Keepalive
            | BatmanPacketType::CertReq
            | BatmanPacketType::CertReply,
        ) => false,
        Some(
            BatmanPacketType::Unicast
            | BatmanPacketType::Mcast
            | BatmanPacketType::EchoRequest
            | BatmanPacketType::EchoReply
            | BatmanPacketType::NextHopChallenge
            | BatmanPacketType::NextHopResponse,
        ) => true,
        // Unrecognised sub-type, or an empty payload: fail closed.
        None => true,
    }
}

/// Verify and strip the pairwise-tag trailer from a directed data-plane frame
/// when auth is enabled, returning the frame to route on: the original frame
/// (auth off, or a sub-type that carries no pairwise tag), a shorter *view*
/// over the same bytes with the trailer dropped, or `None` if the frame must be
/// dropped (bad/missing tag from an unverified or foreign neighbor).
fn strip_directed<'a, R: RouterOps>(router: &mut R, frame: &'a LinkFrame) -> Option<&'a LinkFrame> {
    // Tagged-or-not is `requires_pairwise_tag`'s call, from the sub-type alone
    // and never from `frame.dst` — see its doc for why. With auth off nothing
    // is tagged at all.
    let Some(auth) = router.auth_mut() else {
        return Some(frame);
    };
    if frame.protocol.get() != DEFAULT_BATMAN_ETHER_TYPE || !requires_pairwise_tag(&frame.payload) {
        return Some(frame);
    }

    let Some(body_len) = frame.payload.len().checked_sub(DIRECTED_TRAILER_LEN) else {
        // Too short to even hold a tag trailer — a malformed/foreign frame.
        trace!(src = ?frame.src, len = frame.payload.len(), "drop: directed frame too short for auth trailer");
        return None;
    };
    let (inner, trailer) = frame.payload.split_at(body_len);
    if !auth.verify_directed(frame.src, inner, trailer) {
        // Unverified/foreign neighbor or a replayed counter — drop rather than
        // route an unauthenticated directed frame.
        //
        // `dst` and the sub-type are both recorded because together they are
        // what distinguishes the two causes. A directed sub-type under a *group*
        // link dst is structurally impossible from an honest sender — it is the
        // group-MAC bypass being attempted — while the same record with a
        // unicast dst is the far commoner "peer has not finished enrolling".
        // Without these fields the two are byte-identical, and a node under
        // attack reads as a node with a slow enrollment.
        trace!(
            src = ?frame.src,
            dst = ?frame.dst,
            sub_type = ?frame.payload.first().copied().and_then(BatmanPacketType::from_u8),
            group_dst = frame.dst.is_multicast(),
            "drop: directed frame failed pairwise auth"
        );
        // And flag it, once per source however long the stream runs. Raised on
        // every frame on purpose: the board coalesces by `(kind, subject)`, so
        // a flood of these is one row with a count rather than one row each —
        // which is exactly why the detector needs no rate limiter of its own.
        //
        // `Info`, not `Warning`: a single frame from a peer that has not
        // finished enrolling looks identical to one from a peer that never
        // will, and the first is the commoner explanation. What separates them
        // is the row's count, which an operator reads.
        alarm!(
            Severity::Info,
            AlarmKind::UnauthenticatedTraffic,
            Subject::Node(NodeId::new(&frame.src.0)),
            "body_len={}",
            body_len
        );
        return None;
    }

    // Reinterpret the frame's own bytes minus the trailer — a shorter view over
    // the same buffer (no copy) — so the engine sees only the real payload and
    // never forwards or delivers the tag bytes.
    //
    // Neither failure below uses `?`/`.ok()`: this frame *authenticated*, and
    // `verify_directed` has already spent its replay counter, so a
    // retransmission would be refused as a replay. Losing it here is
    // unrecoverable and must never be silent. Both arms are this node's own
    // invariant breaking rather than a peer's malformed input — but a member's
    // tag had to verify first, which bounds the rate, so they stay `trace!`
    // alongside every other drop on this path.
    let full = frame.as_bytes();
    let strip_len = full.len() - DIRECTED_TRAILER_LEN;
    let Some(bytes) = full.get(..strip_len) else {
        trace!(
            src = ?frame.src,
            full_len = full.len(),
            "drop: authenticated frame too short to re-view without its trailer"
        );
        return None;
    };
    match LinkFrame::ref_from_bytes(bytes) {
        Ok(stripped) => Some(stripped),
        Err(_) => {
            trace!(
                src = ?frame.src,
                len = bytes.len(),
                "drop: authenticated frame failed to re-parse after stripping its trailer"
            );
            None
        }
    }
}

/// Finalize a directed data-plane frame for transmit, appending a pairwise auth
/// tag when one is required, and return **how many bytes to actually send**.
///
/// `buf` holds the frame body in `buf[..body_len]` and must reserve at least
/// [`DIRECTED_TRAILER_LEN`] spare bytes after it (`buf.len() >= body_len +
/// DIRECTED_TRAILER_LEN`) for the tag to be written into; the caller owns the
/// buffer, so reserving that space is its concern.  Returns:
///
/// * `Some(body_len)` — send the body untagged: auth is disabled, or
///   [`requires_pairwise_tag`] exempts this sub-type (see its doc for which
///   ones, and why each either cannot carry a pairwise tag or need not).
/// * `Some(body_len + DIRECTED_TRAILER_LEN)` — the tag was written; send the
///   body plus trailer.
/// * `None` — auth is on but the frame can't be tagged (no verified key for
///   `dst` yet, or the pairwise counter is exhausted); the caller must **drop**
///   it rather than emit it in the clear.
///
/// [`DIRECTED_TRAILER_LEN`]: wayfinder::auth::DIRECTED_TRAILER_LEN
fn tag_directed_into<R: RouterOps>(
    router: &mut R,
    now: Duration,
    dst: Mac,
    protocol: u16,
    body_len: usize,
    buf: &mut [u8],
) -> Option<usize> {
    // The same rule the receiver applies, read off the same field, so the two
    // halves cannot drift: a sub-type `requires_pairwise_tag` would refuse
    // untagged on ingress is never emitted untagged either.
    let needs_tag =
        protocol == DEFAULT_BATMAN_ETHER_TYPE && requires_pairwise_tag(&buf[..body_len]);

    let Some(auth) = router.auth_mut() else {
        // Auth disabled: send the body untagged.
        return Some(body_len);
    };
    if !needs_tag {
        return Some(body_len);
    }

    // Write the tag straight into the reserved trailer bytes (no scratch buffer).
    let (frame, trailer) = buf[..body_len + DIRECTED_TRAILER_LEN].split_at_mut(body_len);
    if auth.tag_directed(dst, frame, trailer).is_some() {
        Some(body_len + DIRECTED_TRAILER_LEN)
    } else {
        // Auth on but we can't tag this directed frame (no verified key for dst
        // yet, or counter exhausted): the caller drops it rather than emit it in
        // the clear.
        //
        // `trace!`, not `warn!`: `dst` comes from routing state a remote peer
        // can influence, so a peer could otherwise drive this at frame rate and
        // flood the bounded log ring a probe-less board depends on
        // (CLAUDE.md's logging rules). The counter below is what makes the drop
        // visible instead — a `warn!` nobody can afford to leave on is not
        // observability.
        // The sub-type and `group_dst` separate the two causes this one counter
        // now absorbs: no verified key for `dst` yet (transient, an enrolling
        // peer) versus a directed sub-type staged against a group dst (a bug
        // here, never transient). `untaggable_drop_rate` alone cannot tell them
        // apart.
        trace!(
            ?dst,
            sub_type = ?buf.get(..body_len)
                .and_then(<[u8]>::first)
                .copied()
                .and_then(BatmanPacketType::from_u8),
            group_dst = dst.is_multicast(),
            "drop: untaggable directed frame"
        );
        router.record_untaggable_drop(now);
        None
    }
}

/// Process one received link-layer frame, folding the carrier's physical-layer
/// `metrics` into the engine's link-quality table and planning any resulting
/// re-flood/forward (to `sink.emit`) and local delivery (to
/// `sink.deliver_local`).
pub fn handle_mesh_frame<R: RouterOps>(
    now: Duration,
    router: &mut R,
    idx: usize,
    frame: &LinkFrame,
    metrics: LinkMetrics,
    tx_buffer: &mut [u8],
    sink: &mut impl MeshSink,
) {
    let Some(frame) = strip_directed(router, frame) else {
        return; // directed frame failed authentication
    };
    let rx = router.handle_frame_with_metrics(now, idx, frame, metrics, tx_buffer);
    trace!(
        forward = rx.forward.is_some(),
        deliver_local = rx.deliver_local.is_some(),
        "frame decoded"
    );
    if let Some(f) = rx.forward {
        sink.emit(OutgoingFrame {
            dst: f.dst,
            protocol: f.protocol,
            payload: f.payload,
            egress: match rx.pin_egress_iface {
                // A next-hop proof response: link-local by construction, so it
                // must return out exactly the interface its challenge arrived
                // on rather than through routing state (see `RxOutcome`'s
                // `pin_egress_iface` doc).
                Some(pinned) => Egress::Iface(pinned),
                // Everything else — a re-flood included, which goes back out
                // the interface it arrived on too; see [`Egress::Auto`] for why
                // there is no split-horizon here.
                None => Egress::Auto,
            },
        });
    }
    if let Some(inner) = rx.deliver_local {
        sink.deliver_local(inner);
    }
}

/// Emit an OGM for each interface whose Trickle timer is due as of `now`
/// (advancing that timer), each addressed to its one interface via
/// [`Egress::Iface`].
pub fn poll_due_ogms<R: RouterOps>(
    router: &mut R,
    now: Duration,
    tx_buffer: &mut [u8],
    sink: &mut impl MeshSink,
) {
    // Each emission advances exactly one interface's timer, so the set of due
    // interfaces shrinks every pass and the loop terminates.
    while let Some(idx) = router.due_interface(now) {
        // Own-OGM transmit gate: a link with `tx_ogm` off never emits this
        // node's OGMs.  Both drivers arm the Trickle timer on every interface
        // regardless of `tx_ogm` (so the features stay runtime-toggleable
        // without re-arming a timer), so this poll-time check is the actual
        // suppression: it skips the emission while `on_interface_emitted` below
        // still advances the timer unconditionally, so the due-set shrinks and
        // the loop terminates.
        if router.link_features(idx).tx_ogm
            && let Some(f) = router.poll(now, tx_buffer)
        {
            sink.emit(OutgoingFrame {
                dst: f.dst,
                protocol: f.protocol,
                payload: f.payload,
                egress: Egress::Iface(idx),
            });
        }
        router.on_interface_emitted(idx, now);
    }
}

/// Emit a keep-alive heartbeat for each interface whose fixed-cadence timer
/// is due as of `now` (advancing that timer), each addressed to its one
/// interface via [`Egress::Iface`]. Unlike [`poll_due_ogms`] there is no
/// poll-time feature check to make: an interface's keep-alive timer only
/// exists (is `Some`) once `configure_interface_keepalive` armed it from that
/// link's `tx_keepalive` config, so "due" already implies "opted in."
pub fn poll_due_keepalives<R: RouterOps>(
    router: &mut R,
    now: Duration,
    tx_buffer: &mut [u8],
    sink: &mut impl MeshSink,
) {
    // Each emission advances exactly one interface's timer, so the set of due
    // interfaces shrinks every pass and the loop terminates.
    while let Some(idx) = router.due_keepalive_interface(now) {
        if let Some(f) = router.poll_keepalive(tx_buffer) {
            sink.emit(OutgoingFrame {
                dst: f.dst,
                protocol: f.protocol,
                payload: f.payload,
                egress: Egress::Iface(idx),
            });
        }
        router.on_keepalive_emitted(idx, now);
    }
}

/// Emit a next-hop proof challenge to each neighbor still awaiting one,
/// addressed to that neighbor.
///
/// A challenge goes out only for a candidate whose proof is missing, lapsed or
/// due for renewal, and the router spaces retries per neighbor, so an
/// unanswered candidate costs one frame per backoff step rather than one per
/// tick.
///
/// **This is not silent in the steady state.** Renewal falls due after one
/// `seed_interval()` while a proof only lapses after `MAX_MISSED_PROOFS` of
/// them — the gap is the margin the round trip gets — so a fully proven mesh
/// still re-challenges every path neighbor about once per interval, times the
/// interface count below. Budget duty cycle against that, not against zero.
///
/// A candidate that is *not* answering is louder than that at first and no
/// louder in the end: the retry starts at `i_min` and doubles, capping at
/// `seed_interval()`. That shape is deliberate. A node's first challenge to a
/// neighbor races the lazy certificate exchange and is routinely dropped by a
/// peer that does not hold this node's certificate yet, and charging a full
/// `i_max` for that lost frame left a settled mesh unable to route for over
/// two minutes. The handful of extra frames a doubling retry spends are
/// bounded by the cap, which is the rate the duty-cycle budget in
/// `docs/design/09-mesh-auth-gaps.md` was written against.
///
/// Emitted on **every** interface rather than the router's metric-chosen one,
/// which is the security-relevant part. `get_egress_interface` resolves through
/// the link-quality table, and that table is written on frame *receipt* —
/// before any authentication verdict — so an attacker spoofing a member's
/// source address can make its own link look like the way to reach that member
/// and collect the challenge itself. It could not answer, but it would not need
/// to: the proof would simply never renew and the victim would lose a route it
/// should have kept. Letting the attacker choose where the challenge goes hands
/// it a denial of service, so the challenge does not ask. A challenge is a
/// couple of dozen bytes and rare, which is what makes the fan-out affordable.
pub fn poll_due_challenges<R: RouterOps>(
    router: &mut R,
    now: Duration,
    tx_buffer: &mut [u8],
    sink: &mut impl MeshSink,
) {
    let ifaces = router.num_interfaces();
    // Each call marks its target challenged, so the candidate set shrinks every
    // pass and the loop terminates.
    while let Some((dst, f)) = router.poll_challenge(now, tx_buffer) {
        trace!(
            ?dst,
            ifaces, "emitting next-hop challenge on every interface"
        );
        for idx in 0..ifaces {
            // `Egress::Iface` is not re-gated by `plan_dispatch` (the OGM path
            // already consulted `tx_ogm` before staging), so the per-link
            // transmit gate has to be consulted here or not at all.
            if !router.link_may_tx(idx, Some(BatmanPacketType::NextHopChallenge)) {
                trace!(iface_idx = idx, "drop: tx gate disabled on this link");
                continue;
            }
            sink.emit(OutgoingFrame {
                dst: f.dst,
                protocol: f.protocol,
                payload: f.payload,
                egress: Egress::Iface(idx),
            });
        }
    }
}

/// Emit the reachability probe the running ping session has due at `now`, if
/// any, letting the router resolve its egress ([`Egress::Auto`]).
///
/// **One probe per call, not a loop.** The other `poll_due_*` functions here
/// loop until their router runs out of work; this one deliberately does not.
/// A probe's cadence *is* the measurement — a shell that slept through three
/// intervals and then emitted three back-to-back probes would be timing its own
/// burst rather than the path, and on a duty-cycle-limited radio it would spend
/// the airtime budget the session exists to measure. The router paces from
/// `now` for the same reason; see
/// [`CentralRouter::poll_ping`](wayfinder::CentralRouter::poll_ping).
///
/// [`Egress::Auto`] rather than the per-interface fan-out
/// [`poll_due_challenges`] uses: a probe is addressed to one next hop and
/// exists to measure the path the router would actually pick, so asking the
/// router to pick it is the point. That also means `plan_dispatch` applies the
/// `tx_data` gate on the way out, which is where a probe's transmit gate is
/// consulted.
pub fn poll_due_pings<R: RouterOps>(
    router: &mut R,
    now: Duration,
    tx_buffer: &mut [u8],
    sink: &mut impl MeshSink,
) {
    if let Some(f) = router.poll_ping(now, tx_buffer) {
        trace!(dst = ?f.dst, "emitting reachability probe");
        sink.emit(OutgoingFrame {
            dst: f.dst,
            protocol: f.protocol,
            payload: f.payload,
            egress: Egress::Auto,
        });
    }
}

/// Plan one mesh link's `recv` outcome into `sink`: a received frame, or a drop
/// on error.
///
/// The receive arm of every shell's event loop. A link error is **transient by
/// contract** — a reconnecting transport surfaces `Io` until a later call
/// succeeds — so it costs this iteration nothing but a log line, never the
/// loop.
///
/// That log is `trace!`, not `warn!`: a noisy or jammed radio can fail every
/// `recv`, and this is a per-frame path reachable by ambient conditions. On a
/// board with no debug probe the bounded `GetLogs` ring is the only way to see
/// anything at all, and a `warn!` here would evict everything else in it.
pub fn handle_link_result<R: RouterOps>(
    now: Duration,
    router: &mut R,
    idx: usize,
    result: Result<Received<'_>, LinkError>,
    tx_buffer: &mut [u8],
    sink: &mut impl MeshSink,
) {
    match result {
        Ok(received) => {
            trace!(iface = idx, "rx frame from interface");
            handle_mesh_frame(
                now,
                router,
                idx,
                received.frame,
                received.metrics,
                tx_buffer,
                sink,
            );
        }
        Err(e) => {
            trace!(iface = idx, error = ?e, "drop: link recv error");
            // One row per interface, however many errors it produces. `Info`
            // rather than `Warning` because a single failed receive is usually
            // transient — an ICMP unreachable behind a UDP carrier, a radio
            // mid-reset — and the row's `count` is what distinguishes that from
            // a link that has genuinely stopped working.
            //
            // Escalating on persistence would be better still, and needs a
            // per-interface consecutive-error counter this function has nowhere
            // to keep: it is deliberately stateless, and the router is the only
            // state a shell hands it. Left as the natural follow-up rather than
            // smuggled in as a `static`.
            alarm!(
                Severity::Info,
                AlarmKind::LinkErrors,
                Subject::Interface(idx as u8),
                "{:?}",
                e
            );
        }
    }
}

/// Plan the periodic work into `sink` — OGMs and keep-alives on their
/// independent schedules, plus any next-hop proof or reachability probe that
/// has fallen due.
///
/// The timer arm of every shell's event loop, which sleeps until whichever
/// schedule fires first and so must service them all on waking. The third
/// keeps no timer of its own — [`poll_due_challenges`] re-derives its candidate
/// set from current routing and proof state on every call — but it does have a
/// *deadline*, and a shell that sleeps must fold
/// [`RouterOps::next_challenge_after`] into the same `min` as the OGM and
/// keep-alive ones. Leaving it out is what welds proof to the OGM schedule: a
/// newly discovered originator then waits for the next Trickle deadline, up to
/// a full `i_max` on a settled mesh, carrying no traffic until it arrives.
/// Callers that need to drive one in isolation (deterministic stepping in
/// tests) call [`poll_due_ogms`], [`poll_due_keepalives`] and
/// [`poll_due_challenges`] directly.
///
/// A running ping session is a fourth deadline with the same requirement:
/// [`RouterOps::next_ping_after`] must be in that `min` too, or probes go out
/// on whatever cadence the mesh's other traffic happens to wake the loop at —
/// which on a settled mesh is minutes, so every probe would time out and a
/// working path would read as totally lossy.
///
/// [`RouterOps::next_challenge_after`]: wayfinder::router_ops::RouterOps::next_challenge_after
/// [`RouterOps::next_ping_after`]: wayfinder::router_ops::RouterOps::next_ping_after
pub fn poll_due_all<R: RouterOps>(
    router: &mut R,
    now: Duration,
    tx_buffer: &mut [u8],
    sink: &mut impl MeshSink,
) {
    trace!("polling OGMs, keep-alives, next-hop challenges and probes");
    poll_due_ogms(router, now, tx_buffer, sink);
    poll_due_keepalives(router, now, tx_buffer, sink);
    poll_due_challenges(router, now, tx_buffer, sink);
    poll_due_pings(router, now, tx_buffer, sink);
}

/// A set of mesh-interface indices, as a bitmask.
///
/// A bitmask rather than a collection because this is `no_std` and
/// allocation-free, and the answer must outlive the `&mut` borrow of the router
/// that produced it — a borrowing iterator would keep the router locked exactly
/// while the caller needs it to record the transmit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InterfaceSet(u32);

impl InterfaceSet {
    /// The number of interfaces this set can represent.
    ///
    /// Named `CAPACITY` rather than `MAX_INTERFACES` on purpose: `wayfinder`
    /// already exports a `MAX_INTERFACES` (the router's default interface-table
    /// size, 8), and two same-named constants a factor of four apart is a trap.
    /// This one is a property of the bitmask, not of any capacity profile.
    pub const CAPACITY: usize = u32::BITS as usize;

    /// Add `idx` to the set. Indices `>= CAPACITY` are ignored rather than
    /// aliasing onto a low bit — unreachable, per `INTERFACE_SET_FITS_ROUTER`.
    fn insert(&mut self, idx: usize) {
        if idx < Self::CAPACITY {
            self.0 |= 1 << idx;
        }
    }

    /// Whether interface `idx` is in the set.
    pub fn contains(self, idx: usize) -> bool {
        idx < Self::CAPACITY && self.0 & (1 << idx) != 0
    }

    /// Whether the set is empty — nothing to transmit (no route, or every
    /// candidate link gated off).
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The interface indices in the set, ascending.
    pub fn iter(self) -> impl Iterator<Item = usize> {
        let mut bits = self.0;
        core::iter::from_fn(move || {
            if bits == 0 {
                return None;
            }
            let idx = bits.trailing_zeros() as usize;
            bits &= bits - 1; // clear the lowest set bit
            Some(idx)
        })
    }
}

/// A capacity profile must never track more interfaces than an [`InterfaceSet`]
/// can represent, or the high interfaces would be planned and then silently
/// dropped from every fan-out — a node mute on a link it believes is up.
///
/// Checked at compile time against the default profile, in the same spirit as
/// `wayfinder-embedded-driver`'s `N <= R::INTERFACES`. A profile is free to
/// shrink; this catches a future one that grows past the bitmask.
const INTERFACE_SET_FITS_ROUTER: () = assert!(
    wayfinder::MAX_INTERFACES <= InterfaceSet::CAPACITY,
    "InterfaceSet cannot represent every interface the router tracks"
);

/// One planned frame's transmit decision: the bytes to put on the wire, and the
/// interfaces to put them on.
///
/// Constructed only by [`plan_dispatch`] — the fields are private because every
/// invariant here is something that function establishes: the payload is
/// authenticated (or legitimately needs no tag); every target is an interface
/// the driver actually holds (`< num_interfaces`), which is what lets a caller
/// index its own link array with one; and any target the *router* chose has
/// passed that link's transmit gate. An explicit [`Egress::Iface`] is passed
/// through ungated by design — see [`plan_dispatch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchPlan<'a> {
    payload: &'a [u8],
    targets: InterfaceSet,
}

impl<'a> DispatchPlan<'a> {
    /// The exact bytes to transmit: the frame body, plus the pairwise auth
    /// trailer when one was written into it.
    ///
    /// A borrowed slice rather than a length, so a caller cannot pair it with
    /// the wrong buffer or forget to apply it.
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// The interfaces to transmit on. Empty means "nothing to send" (no route,
    /// or every candidate link gated off) — as opposed to a `None` plan, which
    /// means "drop this frame".
    pub fn targets(&self) -> InterfaceSet {
        self.targets
    }
}

/// Decide how to put one planned frame on the wire: authenticate it, then
/// resolve which interfaces carry it.
///
/// This is the whole transmit-side decision every driver shell shares — the
/// tokio host loop, the embedded loop, and the synchronous tick loop. Only the
/// I/O differs between them, so they each drive this and then transmit
/// [`payload`](DispatchPlan::payload) on every interface in
/// [`targets`](DispatchPlan::targets).
///
/// `buf` holds the frame body in `buf[..body_len]` and **must** reserve at
/// least [`DIRECTED_TRAILER_LEN`] spare bytes after it for a tag to be written
/// into; the caller owns the buffer, so making that room is its concern.
/// `num_interfaces` is how many mesh interfaces the *driver* actually holds,
/// which bounds the fan-out independently of the router's capacity.
///
/// Returns `None` when the frame must be **dropped**: auth is on but this
/// directed frame cannot be tagged, and emitting it in the clear would leak an
/// unauthenticated frame onto the mesh.
///
/// [`DIRECTED_TRAILER_LEN`]: wayfinder::auth::DIRECTED_TRAILER_LEN
#[allow(clippy::too_many_arguments)]
pub fn plan_dispatch<'a, R: RouterOps>(
    router: &mut R,
    now: Duration,
    dst: Mac,
    protocol: u16,
    egress: Egress,
    body_len: usize,
    buf: &'a mut [u8],
    num_interfaces: usize,
) -> Option<DispatchPlan<'a>> {
    let () = INTERFACE_SET_FITS_ROUTER;
    let send_len = tag_directed_into(router, now, dst, protocol, body_len, buf)?;

    // The BATMAN sub-type of this outgoing frame (its leading payload byte),
    // used to consult each candidate interface's per-link transmit gates
    // (`link_may_tx`). Only meaningful for BATMAN frames; other protocols are
    // never gated (`None` ⇒ always permitted).  Read from the *body*, not the
    // whole buffer: `buf` still carries the reserved trailer past `body_len`.
    let pkt_type = (protocol == DEFAULT_BATMAN_ETHER_TYPE)
        .then(|| buf.get(..body_len).and_then(<[u8]>::first).copied())
        .flatten()
        .and_then(BatmanPacketType::from_u8);

    let mut targets = InterfaceSet::default();
    match egress {
        // A per-link OGM goes out exactly one interface, on that link's own
        // adaptive schedule. Deliberately *not* re-gated: `poll_due_ogms`
        // already consulted this link's `tx_ogm` before emitting.  Still bounded
        // by the driver's link count, so a plan never names an interface the
        // caller doesn't have.
        Egress::Iface(idx) if idx < num_interfaces => targets.insert(idx),
        Egress::Iface(idx) => {
            trace!(
                iface_idx = idx,
                num_interfaces, "drop: egress interface beyond the driver's links"
            );
        }
        // Otherwise let the router's metric-driven egress choice decide.
        Egress::Auto => match router.get_egress_interface(now, dst) {
            Some(EgressInterface::All) => {
                for idx in 0..num_interfaces {
                    // Per-link transmit gate: skip a link that does not send
                    // this traffic class (an OGM re-flood onto a `tx_ogm`-off
                    // link, or any broadcast onto a listen-only link).
                    if !router.link_may_tx(idx, pkt_type) {
                        trace!(iface_idx = idx, "drop: tx gate disabled on this link");
                        continue;
                    }
                    targets.insert(idx);
                }
            }
            Some(EgressInterface::Interface(idx)) if idx < num_interfaces => {
                // Per-link transmit gate: a unicast/mcast toward a route out a
                // `tx_data`-off link is dropped rather than forwarded.
                if router.link_may_tx(idx, pkt_type) {
                    targets.insert(idx);
                } else {
                    trace!(iface_idx = idx, "drop: tx gate disabled on egress link");
                }
            }
            Some(EgressInterface::Interface(idx)) => {
                trace!(
                    iface_idx = idx,
                    num_interfaces, "drop: egress interface beyond the driver's links"
                );
            }
            // No route to `dst`. Traced because otherwise a unicast to an
            // unknown destination vanishes with no record anywhere on the path —
            // the frame is planned, then simply never sent.
            None => trace!(?dst, "drop: no route to destination"),
        },
    }

    Some(DispatchPlan {
        payload: &buf[..send_len],
        targets,
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;

    use super::*;
    // The planning functions are generic over `RouterOps` now; the tests still
    // instantiate a concrete host-profile router to drive them.
    use wayfinder::CentralRouter;
    use wayfinder::auth::DIRECTED_TRAILER_LEN;
    use wayfinder::auth::OgmAuth;
    use wayfinder::auth::OgmVerdict;
    use wayfinder::batman::wire::BatmanOgmPacket;
    use wayfinder::features::LinkFeatures;
    use wayfinder::interfaces::frame::LinkFrame;
    use wayfinder_auth::Authority;
    use wayfinder_auth::Keypair;
    use zerocopy::FromBytes;
    use zerocopy::IntoBytes;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// An `OgmAuth` for member `m`, seeded deterministically under `authority`,
    /// with its clock set inside the cert's validity window.
    fn member_auth(authority: &Authority, seed: u8, m: Mac) -> OgmAuth {
        let kp = Keypair::from_seed(&[seed; 32]);
        let cert = authority.issue_cert(m, kp.ed_pubkey(), kp.x_pubkey(), 0, 1000);
        let mut auth = OgmAuth::new(kp, cert, authority.trust_anchor());
        auth.set_time(100);
        auth
    }

    /// The bytes of a bare 1-hop OGM from `orig` — BATMAN header only, no TVLVs.
    fn bare_ogm_bytes(orig: Mac, seqno: u32, ttl: u8) -> Vec<u8> {
        let ogm = BatmanOgmPacket {
            packet_type: BatmanPacketType::Ogm.as_u8(),
            version: 5,
            ttl,
            flags: 0,
            seqno: seqno.to_be(),
            orig,
            reserved: 0,
            tq: 255,
            tvlv_len: 0,
        };
        ogm.as_bytes().to_vec()
    }

    /// A signed 1-hop OGM payload from `orig` via `orig_auth` (header + cert/sig
    /// TVLVs) — enough for a peer's `verify_ogm` to learn `orig`'s keys.
    fn signed_ogm_bytes(orig_auth: &mut OgmAuth, orig: Mac, seqno: u32) -> Vec<u8> {
        let mut buf = bare_ogm_bytes(orig, seqno, 50);
        let hdr = buf.len();
        buf.resize(512, 0);
        let len = orig_auth.augment_ogm(&mut buf, hdr).expect("augment OGM");
        buf.truncate(len);
        buf
    }

    /// One captured mesh output: dst, protocol, an owned copy of the payload,
    /// and how it was to be fanned out.
    #[derive(Debug, PartialEq, Eq)]
    struct Captured {
        dst: Mac,
        protocol: u16,
        payload: Vec<u8>,
        egress: Egress,
    }

    /// A [`MeshSink`] that records every emitted frame and local delivery so a
    /// test can assert on them.
    #[derive(Default)]
    struct CaptureSink {
        mesh: Vec<Captured>,
        local: Vec<Vec<u8>>,
    }

    impl MeshSink for CaptureSink {
        fn emit(&mut self, frame: OutgoingFrame<'_>) {
            self.mesh.push(Captured {
                dst: frame.dst,
                protocol: frame.protocol,
                payload: frame.payload.to_vec(),
                egress: frame.egress,
            });
        }
        fn deliver_local(&mut self, inner: &[u8]) {
            self.local.push(inner.to_vec());
        }
    }

    /// Build the raw bytes of a link frame: `[dst][src][protocol be][payload]`.
    fn frame_bytes(dst: Mac, src: Mac, protocol: u16, payload: &[u8]) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(dst.as_bytes());
        raw.extend_from_slice(src.as_bytes());
        raw.extend_from_slice(&protocol.to_be_bytes());
        raw.extend_from_slice(payload);
        raw
    }

    /// With auth disabled (the default), `strip_directed` passes a directed
    /// unicast frame through unchanged — same bytes, nothing stripped.
    #[test]
    fn strip_directed_passes_through_when_auth_disabled() {
        let mut router = CentralRouter::new(mac(1));
        let raw = frame_bytes(mac(2), mac(3), DEFAULT_BATMAN_ETHER_TYPE, &[0xaa, 0xbb]);
        let frame = LinkFrame::ref_from_bytes(&raw).unwrap();

        let out = strip_directed(&mut router, frame).expect("auth-off frame is kept");
        assert_eq!(out.as_bytes(), frame.as_bytes());
    }

    /// A due interface produces exactly one OGM per `poll_due_ogms`, addressed
    /// to that interface (`Egress::Iface`) as a BATMAN broadcast.
    #[test]
    fn poll_due_ogms_emits_one_broadcast_per_due_interface() {
        let mut router = CentralRouter::new(mac(1));
        router.configure_interface_ogm(
            0,
            Duration::from_secs(1),
            Duration::from_secs(8),
            Duration::ZERO,
        );

        // Advance to whenever interface 0 first becomes due (Trickle chooses the
        // exact instant), so the test doesn't hard-code the schedule.
        let mut now = Duration::ZERO;
        while router.due_interface(now).is_none() && now < Duration::from_secs(60) {
            now += Duration::from_millis(100);
        }
        assert!(
            router.due_interface(now).is_some(),
            "interface never came due"
        );

        let mut tx = [0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
        let mut sink = CaptureSink::default();
        poll_due_ogms(&mut router, now, &mut tx, &mut sink);

        assert_eq!(sink.mesh.len(), 1, "one due interface => one OGM");
        let ogm = &sink.mesh[0];
        assert_eq!(ogm.dst, Mac::BROADCAST);
        assert_eq!(ogm.protocol, DEFAULT_BATMAN_ETHER_TYPE);
        assert_eq!(ogm.egress, Egress::Iface(0));
        assert!(sink.local.is_empty());
    }

    /// An interface whose Trickle timer is armed but whose `tx_ogm` feature is
    /// off emits no OGM: `poll_due_ogms` skips the emission yet still advances
    /// the timer, so the loop makes progress and terminates.
    #[test]
    fn poll_due_ogms_skips_tx_ogm_disabled_interface() {
        use wayfinder::features::LinkFeatures;

        let mut router = CentralRouter::new(mac(1));
        router.configure_interface_ogm(
            0,
            Duration::from_secs(1),
            Duration::from_secs(8),
            Duration::ZERO,
        );
        // Arm the timer, then disable OGM tx on that same interface.
        let f = LinkFeatures {
            tx_ogm: false,
            ..Default::default()
        };
        router.set_link_features(0, f);

        let mut now = Duration::ZERO;
        while router.due_interface(now).is_none() && now < Duration::from_secs(60) {
            now += Duration::from_millis(100);
        }
        assert!(
            router.due_interface(now).is_some(),
            "interface never came due"
        );

        let mut tx = [0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
        let mut sink = CaptureSink::default();
        poll_due_ogms(&mut router, now, &mut tx, &mut sink);

        assert!(sink.mesh.is_empty(), "tx_ogm off ⇒ no OGM emitted");
        assert!(
            router.due_interface(now).is_none(),
            "timer still advanced so the poll loop terminates"
        );
    }

    /// A due interface produces exactly one keep-alive per
    /// `poll_due_keepalives`, addressed to that interface (`Egress::Iface`).
    #[test]
    fn poll_due_keepalives_emits_one_heartbeat_per_due_interface() {
        let mut router = CentralRouter::new(mac(1));
        router.configure_interface_keepalive(0, Some(Duration::from_secs(1)), Duration::ZERO);

        let mut now = Duration::ZERO;
        while router.due_keepalive_interface(now).is_none() && now < Duration::from_secs(60) {
            now += Duration::from_millis(100);
        }
        assert!(
            router.due_keepalive_interface(now).is_some(),
            "interface never came due"
        );

        let mut tx = [0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
        let mut sink = CaptureSink::default();
        poll_due_keepalives(&mut router, now, &mut tx, &mut sink);

        assert_eq!(sink.mesh.len(), 1, "one due interface => one heartbeat");
        let hb = &sink.mesh[0];
        assert_eq!(hb.dst, Mac::BROADCAST);
        assert_eq!(hb.protocol, DEFAULT_BATMAN_ETHER_TYPE);
        assert_eq!(hb.egress, Egress::Iface(0));
        assert!(sink.local.is_empty());
    }

    /// An interface with no keep-alive configured never appears from
    /// `due_keepalive_interface`, so `poll_due_keepalives` emits nothing for
    /// it — opt-in, unlike the always-armed OGM Trickle timer.
    #[test]
    fn poll_due_keepalives_is_noop_when_no_interface_configured() {
        let mut router = CentralRouter::new(mac(1));
        // No `configure_interface_keepalive` call at all.

        let mut tx = [0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
        let mut sink = CaptureSink::default();
        poll_due_keepalives(
            &mut router,
            Duration::from_secs(1_000_000),
            &mut tx,
            &mut sink,
        );

        assert!(sink.mesh.is_empty());
        assert!(sink.local.is_empty());
    }

    /// A frame with an unknown protocol is dropped by the engine, so
    /// `handle_mesh_frame` plans nothing — no mesh emit, no local delivery.
    #[test]
    fn handle_mesh_frame_on_unknown_protocol_emits_nothing() {
        let mut router = CentralRouter::new(mac(1));
        // 0x9999 is neither BATMAN (0x4305) nor the reserved 0x88B5.
        let raw = frame_bytes(mac(1), mac(2), 0x9999, &[0xde, 0xad]);
        let frame = LinkFrame::ref_from_bytes(&raw).unwrap();

        let mut tx = [0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
        let mut sink = CaptureSink::default();
        handle_mesh_frame(
            Duration::ZERO,
            &mut router,
            0,
            frame,
            LinkMetrics::default(),
            &mut tx,
            &mut sink,
        );

        assert!(sink.mesh.is_empty());
        assert!(sink.local.is_empty());
    }

    /// A received OGM is re-flooded onto **every** interface, the one it
    /// arrived on included — see [`Egress::Auto`].
    #[test]
    fn handle_mesh_frame_reforwards_ogm_onto_every_interface() {
        let mut router = CentralRouter::new(mac(1)); // auth off
        let ogm = bare_ogm_bytes(mac(2), 1, 50);
        let link = frame_bytes(Mac::BROADCAST, mac(2), DEFAULT_BATMAN_ETHER_TYPE, &ogm);
        let frame = LinkFrame::ref_from_bytes(&link).unwrap();

        let mut tx = [0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
        let mut sink = CaptureSink::default();
        handle_mesh_frame(
            Duration::ZERO,
            &mut router,
            2,
            frame,
            LinkMetrics::default(),
            &mut tx,
            &mut sink,
        );

        assert_eq!(sink.mesh.len(), 1, "the OGM is re-flooded once");
        assert_eq!(
            sink.mesh[0].egress,
            Egress::Auto,
            "the ingress interface is not excluded"
        );
    }

    /// With auth on, a directed unicast to a neighbor that was never verified has
    /// no pairwise key, so `tag_directed_into` returns `None` — the caller drops
    /// it rather than emit an untagged directed frame in the clear.
    #[test]
    fn tag_directed_into_drops_untaggable_directed_frame() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut router = CentralRouter::new(mac(1));
        router.set_auth(member_auth(&authority, 1, mac(1)));

        let body = [0xAAu8, 0xBB, 0xCC];
        let mut buf = body.to_vec();
        buf.resize(body.len() + DIRECTED_TRAILER_LEN, 0);
        let out = tag_directed_into(
            &mut router,
            Duration::ZERO,
            mac(2), // never verified => no pairwise key
            DEFAULT_BATMAN_ETHER_TYPE,
            body.len(),
            &mut buf,
        );
        assert_eq!(out, None, "untaggable directed frame is dropped");
    }

    /// With auth on, a cert-control packet (CertReq/CertReply) carries its own
    /// self-authenticating signature, so `tag_directed_into` leaves it untagged —
    /// returning exactly `body_len`, no trailer — even to an unverified node.
    #[test]
    fn tag_directed_into_leaves_cert_control_untagged() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut router = CentralRouter::new(mac(1));
        router.set_auth(member_auth(&authority, 1, mac(1)));

        let body = [BatmanPacketType::CertReq.as_u8(), 0x11, 0x22];
        let mut buf = body.to_vec();
        buf.resize(body.len() + DIRECTED_TRAILER_LEN, 0);
        let out = tag_directed_into(
            &mut router,
            Duration::ZERO,
            mac(2),
            DEFAULT_BATMAN_ETHER_TYPE,
            body.len(),
            &mut buf,
        );
        assert_eq!(out, Some(body.len()), "cert-control frame sent untagged");
    }

    /// The full auth round-trip through the shared core: once two nodes have
    /// exchanged signed OGMs (each holding the other's pairwise key),
    /// `tag_directed_into` on the sender writes a valid tag and `strip_directed`
    /// on the receiver verifies it and returns the inner frame, trailer removed.
    #[test]
    fn tag_then_strip_directed_round_trips_for_verified_neighbor() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        // Receiver A = mac(1) (the router); sender B = mac(2) (a peer auth).
        let mut router = CentralRouter::new(mac(1));
        router.set_auth(member_auth(&authority, 1, mac(1)));
        let mut peer = member_auth(&authority, 2, mac(2));

        // Mutual OGM verification agrees the pairwise key both ways: the router
        // learns B, and B learns A.
        let ogm_from_peer = signed_ogm_bytes(&mut peer, mac(2), 1);
        assert_eq!(
            router.auth_mut().unwrap().verify_ogm(&ogm_from_peer),
            OgmVerdict::Verified
        );
        let ogm_from_router = signed_ogm_bytes(router.auth_mut().unwrap(), mac(1), 1);
        assert_eq!(peer.verify_ogm(&ogm_from_router), OgmVerdict::Verified);

        // B tags a directed frame addressed to A.
        let inner = [0xDEu8, 0xAD, 0xBE, 0xEF];
        let mut tagged = inner.to_vec();
        tagged.resize(inner.len() + DIRECTED_TRAILER_LEN, 0);
        let (frame, trailer) = tagged.split_at_mut(inner.len());
        peer.tag_directed(mac(1), frame, trailer)
            .expect("peer tags to a verified neighbor");

        // A strips + verifies it, recovering exactly the inner frame.
        let link = frame_bytes(mac(1), mac(2), DEFAULT_BATMAN_ETHER_TYPE, &tagged);
        let stripped = strip_directed(&mut router, LinkFrame::ref_from_bytes(&link).unwrap())
            .expect("verified directed frame is kept");
        assert_eq!(
            &stripped.payload[..],
            &inner[..],
            "trailer stripped, inner intact"
        );
    }

    /// A next-hop proof *response* must go back out exactly the interface its
    /// challenge arrived on — never resolved through routing state.
    ///
    /// Unlike the challenge itself (fanned out to every interface for this
    /// exact reason, see `poll_due_challenges`), the response is a reply
    /// planned by `handle_frame_with_metrics` and returned through the generic
    /// `RxOutcome::forward` path, which `handle_mesh_frame` dispatches with
    /// `Egress::Auto` — resolved via `CentralRouter::get_egress_interface`.
    /// That function falls back to the link-quality table whenever the
    /// responder has not *itself* independently proven the challenger yet
    /// (proof is asymmetric and this is a real, if narrow, window: a
    /// responder answering the very first challenge it ever receives from a
    /// newly-discovered neighbor has typically not yet completed its own
    /// reciprocal challenge of that neighbor). The link-quality table is
    /// written from any broadcast frame's `frame.src` on receipt, before any
    /// authentication verdict — so an attacker spoofing the challenger's MAC
    /// on a *different* interface (e.g. replaying one of its genuine OGMs,
    /// gap 1/2's own attack) can steer the response away from the real
    /// challenger, denying exactly the proof exchange this feature exists to
    /// secure. The link-quality poisoning is reproduced inline below, via a
    /// spoofed broadcast on a second interface.
    #[test]
    fn next_hop_response_is_pinned_to_the_arrival_interface() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut router = CentralRouter::new(mac(1));
        router.set_auth(member_auth(&authority, 1, mac(1)));
        let mut challenger = member_auth(&authority, 2, mac(2));

        // The router verifies mac(2) over the genuine link, interface 0.
        let ogm = signed_ogm_bytes(&mut challenger, mac(2), 1);
        let link = frame_bytes(Mac::BROADCAST, mac(2), DEFAULT_BATMAN_ETHER_TYPE, &ogm);
        let mut tx = [0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
        let mut sink = CaptureSink::default();
        handle_mesh_frame(
            Duration::ZERO,
            &mut router,
            0,
            LinkFrame::ref_from_bytes(&link).unwrap(),
            LinkMetrics::default(),
            &mut tx,
            &mut sink,
        );
        // mac(2) verifies the router right back, so it can tag a directed
        // challenge to it below — the precondition `tag_directed` checks.
        let router_ogm = signed_ogm_bytes(router.auth_mut().unwrap(), mac(1), 1);
        assert_eq!(challenger.verify_ogm(&router_ogm), OgmVerdict::Verified);

        // An attacker elsewhere replays mac(2)'s own (genuinely signed)
        // broadcast OGM on interface 1 with a strong measured signal —
        // exactly gap 1/2's attack — poisoning the link-quality table's
        // opinion of where mac(2) lives, before the router's own reciprocal
        // challenge of mac(2) has had a chance to complete.
        let metrics = LinkMetrics {
            quality: Some(200),
            ..Default::default()
        };
        let mut poison_sink = CaptureSink::default();
        handle_mesh_frame(
            Duration::ZERO,
            &mut router,
            1,
            LinkFrame::ref_from_bytes(&link).unwrap(),
            metrics,
            &mut tx,
            &mut poison_sink,
        );

        // mac(2) genuinely (and correctly, pairwise-tagged like any other
        // directed frame) challenges the router over the real link,
        // interface 0.
        let hdr = wayfinder::batman::wire::BatmanNextHopChallengePacket {
            packet_type: BatmanPacketType::NextHopChallenge.as_u8(),
            version: 5,
        };
        let mut inner = hdr.as_bytes().to_vec();
        inner.extend_from_slice(&[0xAB; wayfinder::auth::CHALLENGE_NONCE_LEN]);
        let mut body = inner.clone();
        body.resize(inner.len() + DIRECTED_TRAILER_LEN, 0);
        let (frame, trailer) = body.split_at_mut(inner.len());
        challenger
            .tag_directed(mac(1), frame, trailer)
            .expect("challenger tags to a verified neighbor");
        let challenge = frame_bytes(mac(1), mac(2), DEFAULT_BATMAN_ETHER_TYPE, &body);

        let mut sink = CaptureSink::default();
        handle_mesh_frame(
            Duration::ZERO,
            &mut router,
            0,
            LinkFrame::ref_from_bytes(&challenge).unwrap(),
            LinkMetrics::default(),
            &mut tx,
            &mut sink,
        );

        assert_eq!(sink.mesh.len(), 1, "the challenge is answered");
        assert_eq!(
            sink.mesh[0].egress,
            Egress::Iface(0),
            "the response must return out the interface the challenge arrived \
             on, not wherever routing state (poisonable from another \
             interface) would otherwise send it"
        );
    }

    /// With auth on, a directed frame from a neighbor the router has never
    /// verified fails the pairwise check, so `strip_directed` drops it (returns
    /// `None`) rather than route an unauthenticated frame.
    #[test]
    fn strip_directed_drops_frame_from_unverified_neighbor() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut router = CentralRouter::new(mac(1));
        router.set_auth(member_auth(&authority, 1, mac(1)));

        let inner = [BatmanPacketType::Unicast.as_u8(), 0x02, 0x03];
        let mut payload = inner.to_vec();
        payload.resize(inner.len() + DIRECTED_TRAILER_LEN, 0); // bogus zero trailer
        let link = frame_bytes(mac(1), mac(9), DEFAULT_BATMAN_ETHER_TYPE, &payload);
        let frame = LinkFrame::ref_from_bytes(&link).unwrap();

        assert!(
            strip_directed(&mut router, frame).is_none(),
            "directed frame from an unverified neighbor is dropped"
        );
    }

    /// Dropping a directed frame that failed its pairwise check also *flags* it:
    /// the drop is a `trace!` nobody is watching, and this is the record that
    /// outlives it.
    ///
    /// Raised onto a scoped board rather than the process-global one: these
    /// tests share a process, and writing the global would leak into every
    /// other test that reads it.
    #[test]
    fn a_frame_failing_pairwise_auth_raises_an_alarm_against_its_source() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut router = CentralRouter::new(mac(1));
        router.set_auth(member_auth(&authority, 1, mac(1)));

        let mut payload = [BatmanPacketType::Unicast.as_u8(), 0x02, 0x03].to_vec();
        payload.resize(3 + DIRECTED_TRAILER_LEN, 0); // bogus zero trailer
        let link = frame_bytes(mac(1), mac(9), DEFAULT_BATMAN_ETHER_TYPE, &payload);
        let frame = LinkFrame::ref_from_bytes(&link).unwrap();

        let board = std::sync::Arc::new(wayfinder_alarm::SharedBoard::new());
        wayfinder_alarm::with_board(&board, || {
            assert!(strip_directed(&mut router, frame).is_none());
        });

        let snapshot = board.snapshot();
        assert_eq!(snapshot.alarms.len(), 1);
        let raised = &snapshot.alarms[0];
        assert_eq!(raised.kind, AlarmKind::UnauthenticatedTraffic);
        assert_eq!(raised.severity, Severity::Info);
        assert_eq!(
            raised.subject,
            Subject::Node(NodeId::new(&mac(9).0)),
            "attributed to the frame's source, not to the node itself"
        );
    }

    /// A stream of unauthenticated frames from one source is one row with a
    /// count, not one row per frame.
    ///
    /// This is the property that lets the detector above be as naive as it is —
    /// it raises on every frame, from inside the very flood it reports, and
    /// carries no rate limiter of its own. If coalescing ever stopped working
    /// the alarm board would become the flood.
    #[test]
    fn a_flood_of_unauthenticated_frames_coalesces_into_one_row() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut router = CentralRouter::new(mac(1));
        router.set_auth(member_auth(&authority, 1, mac(1)));

        let mut payload = [BatmanPacketType::Unicast.as_u8(), 0x02, 0x03].to_vec();
        payload.resize(3 + DIRECTED_TRAILER_LEN, 0);
        let link = frame_bytes(mac(1), mac(9), DEFAULT_BATMAN_ETHER_TYPE, &payload);
        let frame = LinkFrame::ref_from_bytes(&link).unwrap();

        let board = std::sync::Arc::new(wayfinder_alarm::SharedBoard::new());
        wayfinder_alarm::with_board(&board, || {
            for _ in 0..500 {
                assert!(strip_directed(&mut router, frame).is_none());
            }
        });

        let snapshot = board.snapshot();
        assert_eq!(snapshot.alarms.len(), 1, "500 frames, one row");
        assert_eq!(
            snapshot.alarms[0].count, 500,
            "and the magnitude is the count"
        );
        assert_eq!(snapshot.dropped, 0, "nothing was refused for want of room");
    }

    /// Two misbehaving sources are two rows, so neither can hide behind the
    /// other: the dedup key is `(kind, subject)`, not `kind` alone.
    #[test]
    fn two_unauthenticated_sources_get_a_row_each() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut router = CentralRouter::new(mac(1));
        router.set_auth(member_auth(&authority, 1, mac(1)));

        let mut payload = [BatmanPacketType::Unicast.as_u8(), 0x02, 0x03].to_vec();
        payload.resize(3 + DIRECTED_TRAILER_LEN, 0);

        let board = std::sync::Arc::new(wayfinder_alarm::SharedBoard::new());
        wayfinder_alarm::with_board(&board, || {
            for src in [mac(8), mac(9)] {
                let link = frame_bytes(mac(1), src, DEFAULT_BATMAN_ETHER_TYPE, &payload);
                let frame = LinkFrame::ref_from_bytes(&link).unwrap();
                assert!(strip_directed(&mut router, frame).is_none());
            }
        });

        assert_eq!(board.snapshot().alarms.len(), 2);
    }

    // ---- plan_dispatch ----------------------------------------------------
    //
    // Egress resolution and the per-link transmit gate were written out in all
    // three driver shells once. That made a correctness invariant a thing you
    // could fix in one shell and silently leave broken in two. These pin the
    // shared decision so the shells can be reduced to "do the I/O for each
    // interface in the plan".

    // ---- event-loop handlers ----------------------------------------------
    //
    // The two arms every shell's event loop drives — "a link produced a recv
    // result" and "the periodic timer fired" — are the same logic in each, so
    // they belong beside the rest of the planning core rather than in one
    // shell. The `Err` arm in particular disagreed between shells (`warn!` on
    // the host, `trace!` on embedded); these pin the settled behaviour.

    /// A received OGM planned through `handle_link_result` reaches the engine
    /// and produces the same re-flood `handle_mesh_frame` would.
    #[test]
    fn handle_link_result_plans_a_received_frame() {
        let mut router = router_with_interfaces(2);
        let ogm = bare_ogm_bytes(mac(2), 7, 50);
        let bytes = frame_bytes(Mac::BROADCAST, mac(2), DEFAULT_BATMAN_ETHER_TYPE, &ogm);
        let frame = LinkFrame::ref_from_bytes(&bytes).unwrap();

        let mut tx = [0u8; 256];
        let mut sink = CaptureSink::default();
        handle_link_result(
            Duration::from_secs(1),
            &mut router,
            0,
            Ok(wayfinder::link::Received {
                frame,
                metrics: LinkMetrics::default(),
            }),
            &mut tx,
            &mut sink,
        );

        assert_eq!(router.originator_count(), 1, "the OGM reached the engine");
        assert_eq!(sink.mesh.len(), 1, "and was planned for re-flood");
    }

    /// A link `recv` error costs the iteration nothing but a log line: no
    /// frames planned, no panic. Transient by contract — a reconnecting
    /// transport returns `Io` until a later call succeeds — so it must never
    /// take down the loop.
    #[test]
    fn handle_link_result_drops_a_recv_error() {
        let mut router = router_with_interfaces(2);
        let mut tx = [0u8; 256];
        let mut sink = CaptureSink::default();

        handle_link_result(
            Duration::from_secs(1),
            &mut router,
            0,
            Err(interfaces::link::LinkError::Io),
            &mut tx,
            &mut sink,
        );

        assert!(sink.mesh.is_empty(), "a recv error plans nothing");
        assert!(sink.local.is_empty());
    }

    /// …and raises an alarm against the interface that produced it, so a link
    /// that has quietly stopped receiving is visible without anyone watching
    /// `trace!` at the moment it happened.
    ///
    /// Attributed to the interface rather than the node: one dead radio on a
    /// multi-link node is a different condition from the node being unwell, and
    /// folding them together would let a working link's silence be explained by
    /// a broken one's noise.
    #[test]
    fn a_link_recv_error_raises_an_alarm_against_that_interface() {
        let mut router = router_with_interfaces(2);
        let mut tx = [0u8; 256];
        let mut sink = CaptureSink::default();

        let board = std::sync::Arc::new(wayfinder_alarm::SharedBoard::new());
        wayfinder_alarm::with_board(&board, || {
            for _ in 0..3 {
                handle_link_result(
                    Duration::from_secs(1),
                    &mut router,
                    1,
                    Err(interfaces::link::LinkError::Io),
                    &mut tx,
                    &mut sink,
                );
            }
        });

        let snapshot = board.snapshot();
        assert_eq!(snapshot.alarms.len(), 1, "three errors, one row");
        let raised = &snapshot.alarms[0];
        assert_eq!(raised.kind, AlarmKind::LinkErrors);
        assert_eq!(raised.subject, Subject::Interface(1));
        assert_eq!(raised.count, 3);
    }

    /// The periodic arm drives both schedules in one call: an interface due an
    /// OGM and an interface due a keep-alive both emit.
    #[test]
    fn poll_due_all_drives_ogms_and_keepalives_together() {
        let mut router = router_with_interfaces(1);
        router.configure_interface_keepalive(0, Some(Duration::from_secs(1)), Duration::ZERO);

        // Advance to where both schedules have fired.
        let mut now = Duration::ZERO;
        while router.due_interface(now).is_none() && now < Duration::from_secs(60) {
            now += Duration::from_millis(100);
        }
        now += Duration::from_secs(2);

        let mut tx = [0u8; 256];
        let mut sink = CaptureSink::default();
        poll_due_all(&mut router, now, &mut tx, &mut sink);

        let types: Vec<u8> = sink
            .mesh
            .iter()
            .filter_map(|f| f.payload.first().copied())
            .collect();
        assert!(
            types.contains(&BatmanPacketType::Ogm.as_u8()),
            "the OGM schedule fired: {types:?}"
        );
        assert!(
            types.contains(&BatmanPacketType::Keepalive.as_u8()),
            "the keep-alive schedule fired in the same call: {types:?}"
        );
    }

    /// An empty set yields nothing and claims nothing.
    #[test]
    fn interface_set_empty() {
        let set = InterfaceSet::default();
        assert!(set.is_empty());
        assert_eq!(set.iter().count(), 0);
        assert!(!set.contains(0));
    }

    /// Membership round-trips, and `iter` yields ascending indices.
    #[test]
    fn interface_set_holds_and_orders_its_members() {
        let mut set = InterfaceSet::default();
        for idx in [3, 0, 7] {
            set.insert(idx);
        }
        assert!(!set.is_empty());
        assert_eq!(set.iter().collect::<Vec<_>>(), std::vec![0, 3, 7]);
        assert!(set.contains(3));
        assert!(!set.contains(1));
    }

    /// At capacity: the last representable index is index 31, and every index
    /// below it is held simultaneously.
    #[test]
    fn interface_set_at_capacity() {
        let mut set = InterfaceSet::default();
        for idx in 0..InterfaceSet::CAPACITY {
            set.insert(idx);
        }
        assert_eq!(set.iter().count(), InterfaceSet::CAPACITY);
        assert!(set.contains(InterfaceSet::CAPACITY - 1));
    }

    /// Past capacity: ignored, not aliased onto a low bit — the failure mode
    /// that would silently transmit on the wrong interface. `contains` must not
    /// panic on a wild index either (`1 << 64` would be UB-adjacent).
    #[test]
    fn interface_set_ignores_indices_past_capacity() {
        let mut set = InterfaceSet::default();
        set.insert(InterfaceSet::CAPACITY);
        set.insert(InterfaceSet::CAPACITY + 1);
        set.insert(usize::MAX);

        assert!(
            set.is_empty(),
            "an out-of-range index must not alias onto a low interface"
        );
        assert!(!set.contains(InterfaceSet::CAPACITY));
        assert!(!set.contains(usize::MAX));
    }

    /// A router with `n` interfaces configured, each on a fast Trickle schedule
    /// so egress resolution has real interfaces to choose between.
    fn router_with_interfaces(n: usize) -> CentralRouter {
        let mut router = CentralRouter::new(mac(1));
        for idx in 0..n {
            router.configure_interface_ogm(
                idx,
                Duration::from_secs(1),
                Duration::from_secs(8),
                Duration::ZERO,
            );
        }
        router
    }

    /// Plan a broadcast (the flood path) of `payload` and collect the target
    /// interface indices, or `None` if the frame is to be dropped outright.
    ///
    /// Collects inside the helper because a [`DispatchPlan`] borrows the buffer
    /// it was planned against, which is local to this function.
    fn plan_broadcast(
        router: &mut CentralRouter,
        payload: &[u8],
        num_interfaces: usize,
    ) -> Option<Vec<usize>> {
        let mut buf = payload.to_vec();
        buf.resize(payload.len() + DIRECTED_TRAILER_LEN, 0);
        plan_dispatch(
            router,
            Duration::from_secs(1),
            Mac::BROADCAST,
            DEFAULT_BATMAN_ETHER_TYPE,
            Egress::Auto,
            payload.len(),
            &mut buf,
            num_interfaces,
        )
        .map(|plan| plan.targets().iter().collect())
    }

    /// A per-link OGM names its interface directly and is **not** re-gated
    /// here: `poll_due_ogms` already consulted that link's `tx_ogm` before
    /// emitting, so gating twice would be both redundant and wrong.
    #[test]
    fn explicit_interface_egress_targets_exactly_that_interface() {
        let mut router = router_with_interfaces(4);
        let payload = [BatmanPacketType::Ogm.as_u8(), 0x02, 0x03];
        let mut buf = payload.to_vec();
        buf.resize(payload.len() + DIRECTED_TRAILER_LEN, 0);

        let plan = plan_dispatch(
            &mut router,
            Duration::from_secs(1),
            Mac::BROADCAST,
            DEFAULT_BATMAN_ETHER_TYPE,
            Egress::Iface(2),
            payload.len(),
            &mut buf,
            4,
        )
        .expect("a per-link OGM is always dispatchable");

        assert_eq!(plan.targets().iter().collect::<Vec<_>>(), std::vec![2]);
        assert_eq!(plan.payload(), payload, "auth off ⇒ body only, no trailer");
    }

    /// A broadcast with no ingress interface floods every interface.
    #[test]
    fn broadcast_floods_every_interface() {
        let mut router = router_with_interfaces(4);
        let targets = plan_broadcast(&mut router, &[BatmanPacketType::Ogm.as_u8(), 0x02], 4)
            .expect("a broadcast is dispatchable");

        assert_eq!(targets, std::vec![0, 1, 2, 3]);
    }

    /// The per-link transmit gate suppresses a traffic class on a link
    /// configured not to carry it, without touching the other links.
    #[test]
    fn transmit_gate_removes_a_link_from_the_flood() {
        let mut router = router_with_interfaces(4);
        let off = LinkFeatures {
            tx_ogm: false,
            ..Default::default()
        };
        router.set_link_features(2, off);

        let targets = plan_broadcast(&mut router, &[BatmanPacketType::Ogm.as_u8(), 0x02], 4)
            .expect("a broadcast is dispatchable");

        assert_eq!(
            targets,
            std::vec![0, 1, 3],
            "the `tx_ogm`-off link is dropped from the fan-out"
        );
    }

    /// The fan-out is bounded by the driver's actual interface count, not the
    /// router's capacity — a shell with two links must not be told to transmit
    /// on eight.
    #[test]
    fn fanout_is_bounded_by_the_drivers_interface_count() {
        let mut router = router_with_interfaces(8);
        let targets = plan_broadcast(&mut router, &[BatmanPacketType::Ogm.as_u8(), 0x02], 2)
            .expect("a broadcast is dispatchable");

        assert_eq!(targets, std::vec![0, 1]);
    }

    /// A directed frame that cannot be authenticated is **dropped**, never
    /// emitted in the clear: no plan at all, rather than an empty target set.
    #[test]
    fn untaggable_directed_frame_yields_no_plan() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut router = router_with_interfaces(2);
        router.set_auth(member_auth(&authority, 1, mac(1)));

        // mac(9) is an unverified neighbour: no pairwise key, so no tag.
        let payload = [BatmanPacketType::Unicast.as_u8(), 0x02, 0x03];
        let mut buf = payload.to_vec();
        buf.resize(payload.len() + DIRECTED_TRAILER_LEN, 0);

        assert!(
            plan_dispatch(
                &mut router,
                Duration::from_secs(1),
                mac(9),
                DEFAULT_BATMAN_ETHER_TYPE,
                Egress::Auto,
                payload.len(),
                &mut buf,
                2,
            )
            .is_none(),
            "an untaggable directed frame is dropped, not emitted untagged"
        );
    }

    /// No known route and nothing to flood ⇒ a plan with no targets. Distinct
    /// from `None`, which means "drop this frame".
    #[test]
    fn unroutable_unicast_plans_no_targets() {
        let mut router = router_with_interfaces(2);
        let payload = [BatmanPacketType::Unicast.as_u8(), 0x02];
        let mut buf = payload.to_vec();
        buf.resize(payload.len() + DIRECTED_TRAILER_LEN, 0);

        let plan = plan_dispatch(
            &mut router,
            Duration::from_secs(1),
            mac(200),
            DEFAULT_BATMAN_ETHER_TYPE,
            Egress::Auto,
            payload.len(),
            &mut buf,
            2,
        )
        .expect("auth off ⇒ always dispatchable");

        assert!(
            plan.targets().is_empty(),
            "no route to an unknown destination ⇒ nothing to transmit"
        );
    }

    /// A next-hop proof frame must be addressed to *this node*. Both proof
    /// types are point-to-point by construction — a challenger unicasts to the
    /// candidate, and the candidate unicasts the answer back — so a multicast
    /// destination is malformed, never something a legitimate peer emits.
    ///
    /// The *second* line of the defense, and deliberately kept as one.
    /// `requires_pairwise_tag` refuses this frame a step earlier — a proof
    /// sub-type is directed, so it needs a valid trailer whatever link dst it
    /// wears — but that check and this one key on different fields, so a
    /// regression in the sub-type table cannot reopen the reflection primitive
    /// on its own. This test runs with auth **on**, which is the case where
    /// both checks are live; it is asserting the second one still holds even
    /// though the first would have caught the same frame.
    #[test]
    fn a_broadcast_addressed_challenge_is_never_answered() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut router = CentralRouter::new(mac(1));
        router.set_auth(member_auth(&authority, 1, mac(1)));
        let mut member = member_auth(&authority, 2, mac(2));

        // The router learns mac(2) as a verified, live neighbor on interface 0,
        // so `answer_challenge` would otherwise find a pairwise key for it.
        let ogm = signed_ogm_bytes(&mut member, mac(2), 1);
        let link = frame_bytes(Mac::BROADCAST, mac(2), DEFAULT_BATMAN_ETHER_TYPE, &ogm);
        let mut tx = [0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
        let mut sink = CaptureSink::default();
        handle_mesh_frame(
            Duration::ZERO,
            &mut router,
            0,
            LinkFrame::ref_from_bytes(&link).unwrap(),
            LinkMetrics::default(),
            &mut tx,
            &mut sink,
        );

        // An attacker with no credential, on a different interface: broadcast
        // destination, mac(2)'s address spoofed as the source, and no directed
        // trailer whatsoever.
        let hdr = wayfinder::batman::wire::BatmanNextHopChallengePacket {
            packet_type: BatmanPacketType::NextHopChallenge.as_u8(),
            version: 5,
        };
        let mut body = hdr.as_bytes().to_vec();
        body.extend_from_slice(&[0xCD; wayfinder::auth::CHALLENGE_NONCE_LEN]);
        let forged = frame_bytes(Mac::BROADCAST, mac(2), DEFAULT_BATMAN_ETHER_TYPE, &body);

        let mut sink = CaptureSink::default();
        handle_mesh_frame(
            Duration::ZERO,
            &mut router,
            1,
            LinkFrame::ref_from_bytes(&forged).unwrap(),
            LinkMetrics::default(),
            &mut tx,
            &mut sink,
        );
        assert!(
            sink.mesh.is_empty(),
            "an unauthenticated broadcast-addressed challenge must not be answered"
        );
    }

    /// The response arm carries the same guard, and there it protects the
    /// proof itself rather than just cost.
    ///
    /// A response's freshness rests on two things: the nonce inside it, and the
    /// pairwise trailer `strip_directed` checks on the way in — the trailer's
    /// replay counter is what stops a captured response being re-credited
    /// later, the replay `red_team.py::attack_challenge_response_replay` covers
    /// on the directed path. `requires_pairwise_tag` now demands that trailer
    /// by sub-type, so a group link dst no longer skips the check; this guard
    /// is the independent second check keyed on the address instead, so
    /// crediting a proof takes *both* to regress.
    #[test]
    fn a_broadcast_addressed_response_cannot_credit_a_proof() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut router = CentralRouter::new(mac(1));
        router.set_auth(member_auth(&authority, 1, mac(1)));
        let mut member = member_auth(&authority, 2, mac(2));

        // Mutual verification, so each side holds the other's pairwise key.
        let ogm = signed_ogm_bytes(&mut member, mac(2), 1);
        let link = frame_bytes(Mac::BROADCAST, mac(2), DEFAULT_BATMAN_ETHER_TYPE, &ogm);
        let mut tx = [0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
        let mut sink = CaptureSink::default();
        handle_mesh_frame(
            Duration::ZERO,
            &mut router,
            0,
            LinkFrame::ref_from_bytes(&link).unwrap(),
            LinkMetrics::default(),
            &mut tx,
            &mut sink,
        );
        let router_ogm = signed_ogm_bytes(router.auth_mut().unwrap(), mac(1), 1);
        assert_eq!(member.verify_ogm(&router_ogm), OgmVerdict::Verified);

        // The router challenges mac(2) for real, and mac(2) answers for real.
        let mut chal_buf = [0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
        let (_, challenge) = router
            .poll_challenge(Duration::ZERO, &mut chal_buf)
            .expect("mac(2) is a live candidate next hop");
        let hdr_len = core::mem::size_of::<wayfinder::batman::wire::BatmanNextHopChallengePacket>();
        let nonce = challenge.payload[hdr_len..].to_vec();
        let tag = member
            .answer_challenge(mac(1), &nonce)
            .expect("the router is a live neighbor of mac(2)");

        // An attacker with no key relays those genuine response bytes with a
        // broadcast destination, so no pairwise trailer is ever demanded.
        let rsp_hdr = wayfinder::batman::wire::BatmanNextHopResponsePacket {
            packet_type: BatmanPacketType::NextHopResponse.as_u8(),
            version: 5,
        };
        let mut body = rsp_hdr.as_bytes().to_vec();
        body.extend_from_slice(&tag);
        let forged = frame_bytes(Mac::BROADCAST, mac(2), DEFAULT_BATMAN_ETHER_TYPE, &body);

        let mut sink = CaptureSink::default();
        handle_mesh_frame(
            Duration::ZERO,
            &mut router,
            1,
            LinkFrame::ref_from_bytes(&forged).unwrap(),
            LinkMetrics::default(),
            &mut tx,
            &mut sink,
        );
        assert!(
            !router.proof_current(Duration::ZERO, mac(2)),
            "a proof must never be credited from a frame that was never \
             pairwise-authenticated"
        );
    }

    /// A challenge must not go out a link whose data gate is closed.
    ///
    /// `poll_due_challenges` emits with `Egress::Iface`, and `plan_dispatch`
    /// deliberately does not re-gate that variant (the OGM path already
    /// consulted `tx_ogm` before staging). So unless this loop consults the
    /// gate itself, nothing does — and a link configured `tx_data: false`
    /// transmits a challenge per unproven neighbor per refresh interval, which
    /// on a duty-cycle-limited LoRa link is exactly the airtime the operator
    /// turned the gate off to reclaim.
    #[test]
    fn a_challenge_skips_a_link_whose_data_gate_is_closed() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut router = CentralRouter::new(mac(1));
        router.set_auth(member_auth(&authority, 1, mac(1)));
        let mut member = member_auth(&authority, 2, mac(2));

        // Two interfaces; interface 1 carries OGMs but never data.
        router.set_link_features(0, wayfinder::features::LinkFeatures::default());
        router.set_link_features(
            1,
            wayfinder::features::LinkFeatures {
                tx_data: false,
                ..Default::default()
            },
        );

        // mac(2) becomes a known, verified candidate next hop on interface 0.
        let ogm = signed_ogm_bytes(&mut member, mac(2), 1);
        let link = frame_bytes(Mac::BROADCAST, mac(2), DEFAULT_BATMAN_ETHER_TYPE, &ogm);
        let mut tx = [0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
        let mut sink = CaptureSink::default();
        handle_mesh_frame(
            Duration::ZERO,
            &mut router,
            0,
            LinkFrame::ref_from_bytes(&link).unwrap(),
            LinkMetrics::default(),
            &mut tx,
            &mut sink,
        );

        let mut sink = CaptureSink::default();
        poll_due_challenges(&mut router, Duration::ZERO, &mut tx, &mut sink);

        assert!(
            !sink.mesh.is_empty(),
            "the candidate is challenged on the link that may carry data"
        );
        assert!(
            sink.mesh.iter().all(|f| f.egress == Egress::Iface(0)),
            "no challenge may go out interface 1, whose data gate is closed"
        );
    }

    // ── the pairwise trailer is required by sub-type, not by link dst ──────

    /// A non-broadcast group MAC (I/G bit set), an IPv4-multicast-derived
    /// address. Distinct from [`Mac::BROADCAST`] so a test can show the rule
    /// turns on the *multicast bit*, not on the all-ones address specifically.
    fn group_mac() -> Mac {
        Mac([0x01, 0x00, 0x5E, 0x00, 0x00, 0x2A])
    }

    /// The bytes of a `Unicast` packet routed toward `dest`, carrying `body`.
    fn unicast_bytes(dest: Mac, body: &[u8]) -> Vec<u8> {
        let hdr = wayfinder::batman::wire::BatmanUnicastPacket {
            packet_type: BatmanPacketType::Unicast.as_u8(),
            version: 5,
            ttl: 50,
            dest,
        };
        let mut out = hdr.as_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    /// The bytes of an `Mcast` packet addressed to listener `dest`, carrying
    /// `body`.
    fn mcast_bytes(dest: Mac, body: &[u8]) -> Vec<u8> {
        let hdr = wayfinder::batman::wire::BatmanMcastPacket {
            packet_type: BatmanPacketType::Mcast.as_u8(),
            version: 5,
            ttl: 50,
            dest,
        };
        let mut out = hdr.as_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    /// A router at `mac(1)` with auth on that has verified `mac(2)` as a live
    /// neighbor, plus that peer's own `OgmAuth`. Mutual, so either side can tag
    /// a directed frame to the other — which is what makes an untagged frame in
    /// these tests refused for want of a *tag* rather than for want of a key.
    fn router_with_verified_peer(authority: &Authority) -> (CentralRouter, OgmAuth) {
        let mut router = CentralRouter::new(mac(1));
        router.set_auth(member_auth(authority, 1, mac(1)));
        let mut peer = member_auth(authority, 2, mac(2));

        // Through `handle_mesh_frame`, not straight into `verify_ogm`: the
        // engine has to learn `mac(2)` as an originator too, or it is never a
        // candidate next hop for the tests that go on to route through it.
        let ogm = signed_ogm_bytes(&mut peer, mac(2), 1);
        let link = frame_bytes(Mac::BROADCAST, mac(2), DEFAULT_BATMAN_ETHER_TYPE, &ogm);
        let mut tx = [0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
        let mut sink = CaptureSink::default();
        handle_mesh_frame(
            Duration::ZERO,
            &mut router,
            0,
            LinkFrame::ref_from_bytes(&link).unwrap(),
            LinkMetrics::default(),
            &mut tx,
            &mut sink,
        );
        assert!(
            router.auth_mut().unwrap().neighbor_cert(mac(2)).is_some(),
            "the peer's OGM verified, so its pairwise key is cached"
        );

        let router_ogm = signed_ogm_bytes(router.auth_mut().unwrap(), mac(1), 1);
        assert_eq!(peer.verify_ogm(&router_ogm), OgmVerdict::Verified);
        (router, peer)
    }

    /// Walk `peer` through a real next-hop challenge/response so the router
    /// will actually *route* through it: with auth on, `next_hop` skips any
    /// relay that has not proven itself, so a test about forwarding has to
    /// clear that gate first.
    ///
    /// Driven end to end (rather than poked into the engine, which is private
    /// to `wayfinder` anyway) because the response is itself one of the
    /// directed sub-types this change now demands a trailer on — so this
    /// doubles as coverage that an honest proof exchange still completes.
    fn prove_peer(router: &mut CentralRouter, peer: &mut OgmAuth) {
        use wayfinder::batman::wire::BatmanNextHopChallengePacket;
        use wayfinder::batman::wire::BatmanNextHopResponsePacket;

        let mut chal = [0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
        let (target, challenge) = router
            .poll_challenge(Duration::ZERO, &mut chal)
            .expect("mac(2) is a live candidate next hop");
        assert_eq!(target, mac(2));
        let hdr_len = core::mem::size_of::<BatmanNextHopChallengePacket>();
        let nonce = challenge.payload[hdr_len..].to_vec();
        let tag = peer
            .answer_challenge(mac(1), &nonce)
            .expect("the router is a live neighbor of mac(2)");

        let rsp = BatmanNextHopResponsePacket {
            packet_type: BatmanPacketType::NextHopResponse.as_u8(),
            version: 5,
        };
        let mut inner = rsp.as_bytes().to_vec();
        inner.extend_from_slice(&tag);
        let mut body = inner.clone();
        body.resize(inner.len() + DIRECTED_TRAILER_LEN, 0);
        let (f, trailer) = body.split_at_mut(inner.len());
        peer.tag_directed(mac(1), f, trailer).expect("peer tags");

        let link = frame_bytes(mac(1), mac(2), DEFAULT_BATMAN_ETHER_TYPE, &body);
        let mut tx = [0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
        let mut sink = CaptureSink::default();
        handle_mesh_frame(
            Duration::ZERO,
            router,
            0,
            LinkFrame::ref_from_bytes(&link).unwrap(),
            LinkMetrics::default(),
            &mut tx,
            &mut sink,
        );
        assert!(
            router.proof_current(Duration::ZERO, mac(2)),
            "a genuine, pairwise-tagged proof response must still be credited"
        );
    }

    /// The trailer requirement is a property of the BATMAN sub-type: every
    /// packet routed toward an inner `dest` needs one; every one-to-many or
    /// self-authenticating packet cannot have one.
    #[test]
    fn requires_pairwise_tag_is_decided_by_sub_type() {
        for t in [
            BatmanPacketType::Unicast,
            BatmanPacketType::Mcast,
            BatmanPacketType::EchoRequest,
            BatmanPacketType::EchoReply,
            BatmanPacketType::NextHopChallenge,
            BatmanPacketType::NextHopResponse,
        ] {
            assert!(
                requires_pairwise_tag(&[t.as_u8(), 0xff]),
                "{t:?} is point-to-point and must carry a pairwise trailer"
            );
        }
        for t in [
            BatmanPacketType::Ogm,
            BatmanPacketType::Bcast,
            BatmanPacketType::Keepalive,
            BatmanPacketType::CertReq,
            BatmanPacketType::CertReply,
        ] {
            assert!(
                !requires_pairwise_tag(&[t.as_u8(), 0xff]),
                "{t:?} carries its own signature, or none at all"
            );
        }
        // Fail closed on what this build cannot classify: an unrecognised
        // sub-type is routed by destination like a directed frame, and an empty
        // payload is malformed either way.
        assert!(requires_pairwise_tag(&[0xEE]));
        assert!(requires_pairwise_tag(&[]));
    }

    /// A `Unicast` carried under a *group* link-layer dst still has to prove
    /// itself.
    ///
    /// This is the ingress half of the group-link-dst bypass. `handle_unicast`
    /// decides local delivery from the *inner* `BatmanUnicastPacket.dest`,
    /// while the trailer check used to key on `frame.dst.is_multicast()` — so
    /// an outsider could aim the inner dest at a member, wear a group MAC on
    /// the link, and skip authentication entirely.
    #[test]
    fn strip_directed_drops_a_group_addressed_unicast_without_a_tag() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let (mut router, _peer) = router_with_verified_peer(&authority);

        // Eve — `mac(9)`, no credential — aims the inner dest at the router.
        let payload = unicast_bytes(mac(1), b"UNI-VIA-MCAST-DST");
        for dst in [group_mac(), Mac::BROADCAST] {
            let link = frame_bytes(dst, mac(9), DEFAULT_BATMAN_ETHER_TYPE, &payload);
            assert!(
                strip_directed(&mut router, LinkFrame::ref_from_bytes(&link).unwrap()).is_none(),
                "an untagged unicast under link dst {dst:?} must be dropped"
            );
        }
    }

    /// The same for `Mcast`, which `handle_mcast` routes by its inner `dest`
    /// exactly the way a unicast is routed.
    #[test]
    fn strip_directed_drops_a_group_addressed_mcast_without_a_tag() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let (mut router, _peer) = router_with_verified_peer(&authority);

        let payload = mcast_bytes(mac(1), b"MCAST-VIA-BCAST-DST");
        let link = frame_bytes(Mac::BROADCAST, mac(9), DEFAULT_BATMAN_ETHER_TYPE, &payload);
        assert!(
            strip_directed(&mut router, LinkFrame::ref_from_bytes(&link).unwrap()).is_none(),
            "an untagged mcast under a broadcast link dst must be dropped"
        );
    }

    /// The other half of the rule, and the one an over-eager fix would break: a
    /// genuinely flooded `Bcast` *cannot* carry a pairwise tag — the key is
    /// per-neighbor and the send is one-to-many — so it must still pass through
    /// untouched, with nothing stripped off its tail.
    #[test]
    fn strip_directed_still_passes_a_flooded_broadcast() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let (mut router, _peer) = router_with_verified_peer(&authority);

        let payload = [BatmanPacketType::Bcast.as_u8(), 5, 50, 0, 1, 2, 3];
        let link = frame_bytes(Mac::BROADCAST, mac(2), DEFAULT_BATMAN_ETHER_TYPE, &payload);
        let frame = LinkFrame::ref_from_bytes(&link).unwrap();
        let out = strip_directed(&mut router, frame).expect("a flood is not pairwise-tagged");
        assert_eq!(out.as_bytes(), frame.as_bytes(), "nothing stripped");
    }

    /// End to end through `handle_mesh_frame`: the injected unicast never
    /// reaches the host device under *any* link dst, where before it did under
    /// a group one and did not under an honest one. That contrast is the whole
    /// finding — `red_team.py::attack_multicast_addressed_directed_delivery`
    /// makes the same measurement against a live node.
    #[test]
    fn a_group_addressed_unicast_is_never_delivered_locally() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let (mut router, _peer) = router_with_verified_peer(&authority);

        let payload = unicast_bytes(mac(1), b"INJECTED");
        let mut tx = [0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
        let mut sink = CaptureSink::default();
        for dst in [group_mac(), Mac::BROADCAST, mac(1)] {
            let link = frame_bytes(dst, mac(9), DEFAULT_BATMAN_ETHER_TYPE, &payload);
            handle_mesh_frame(
                Duration::ZERO,
                &mut router,
                0,
                LinkFrame::ref_from_bytes(&link).unwrap(),
                LinkMetrics::default(),
                &mut tx,
                &mut sink,
            );
        }
        assert!(
            sink.local.is_empty(),
            "an outsider's untagged unicast must not reach the host device, \
             whatever link dst it wears"
        );
        assert!(sink.mesh.is_empty(), "and nothing is relayed on its behalf");
    }

    /// The relay-laundering half, which is the worse one: a group-addressed
    /// unicast whose inner dest is a *third* node must not be forwarded,
    /// because forwarding is where this node stamps its own genuine pairwise
    /// tag onto content it never authenticated (`plan_dispatch` re-tags every
    /// directed frame it sends). A peer two hops from the attacker would
    /// otherwise accept the injection as authenticated member traffic.
    ///
    /// The tagged frame relayed first is the control: it proves the route and
    /// the forwarding path are live, so the attack's empty sink means *refused*
    /// rather than *unroutable*. Mirrors
    /// `red_team.py::attack_injected_directed_laundered_by_relay`.
    #[test]
    fn a_group_addressed_unicast_is_never_laundered_by_a_relay() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let (mut router, mut peer) = router_with_verified_peer(&authority);
        let mut third = member_auth(&authority, 3, mac(3));
        prove_peer(&mut router, &mut peer);

        // `mac(3)`'s own signed OGM reaches the router over `mac(2)`, so the
        // router holds a route to `mac(3)` whose next hop is `mac(2)`.
        let ogm = signed_ogm_bytes(&mut third, mac(3), 7);
        let relayed = frame_bytes(Mac::BROADCAST, mac(2), DEFAULT_BATMAN_ETHER_TYPE, &ogm);
        let mut tx = [0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
        let mut sink = CaptureSink::default();
        handle_mesh_frame(
            Duration::ZERO,
            &mut router,
            0,
            LinkFrame::ref_from_bytes(&relayed).unwrap(),
            LinkMetrics::default(),
            &mut tx,
            &mut sink,
        );

        // Control: the same packet, honestly addressed and genuinely tagged by
        // `mac(2)`, *is* relayed toward `mac(3)`.
        let inner = unicast_bytes(mac(3), b"HONEST");
        let mut body = inner.clone();
        body.resize(inner.len() + DIRECTED_TRAILER_LEN, 0);
        let (f, trailer) = body.split_at_mut(inner.len());
        peer.tag_directed(mac(1), f, trailer).expect("peer tags");
        let honest = frame_bytes(mac(1), mac(2), DEFAULT_BATMAN_ETHER_TYPE, &body);
        let mut sink = CaptureSink::default();
        handle_mesh_frame(
            Duration::ZERO,
            &mut router,
            0,
            LinkFrame::ref_from_bytes(&honest).unwrap(),
            LinkMetrics::default(),
            &mut tx,
            &mut sink,
        );
        assert_eq!(
            sink.mesh.len(),
            1,
            "control: a tagged unicast toward mac(3) is relayed"
        );

        // The attack: Eve's untagged copy, aimed at `mac(3)`, under a broadcast
        // link dst.
        let payload = unicast_bytes(mac(3), b"LAUNDERED");
        let link = frame_bytes(Mac::BROADCAST, mac(9), DEFAULT_BATMAN_ETHER_TYPE, &payload);
        let mut sink = CaptureSink::default();
        handle_mesh_frame(
            Duration::ZERO,
            &mut router,
            0,
            LinkFrame::ref_from_bytes(&link).unwrap(),
            LinkMetrics::default(),
            &mut tx,
            &mut sink,
        );
        assert!(
            sink.mesh.is_empty(),
            "a relay must not re-tag content it never authenticated on ingress"
        );
    }

    /// The transmit side reads the same rule, so the two halves cannot drift: a
    /// `Unicast` staged against a group dst is *dropped* rather than emitted
    /// untagged. No honest path stages one — the point is that "directed" means
    /// the same thing on both sides, so a frame that would be refused on
    /// ingress is never produced on egress either.
    #[test]
    fn tag_directed_into_refuses_a_group_addressed_unicast() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let (mut router, _peer) = router_with_verified_peer(&authority);

        let body = unicast_bytes(mac(3), b"payload");
        let mut buf = body.clone();
        buf.resize(body.len() + DIRECTED_TRAILER_LEN, 0);
        assert!(
            tag_directed_into(
                &mut router,
                Duration::ZERO,
                Mac::BROADCAST,
                DEFAULT_BATMAN_ETHER_TYPE,
                body.len(),
                &mut buf,
            )
            .is_none(),
            "a directed sub-type with no taggable next hop is dropped, not sent \
             in the clear"
        );
    }

    /// And the converse on transmit, which is what keeps the honest broadcast
    /// paths working: a keep-alive addressed to the broadcast MAC goes out
    /// as-is, with no trailer appended.
    #[test]
    fn tag_directed_into_leaves_a_keepalive_untagged() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let (mut router, _peer) = router_with_verified_peer(&authority);

        let body = [BatmanPacketType::Keepalive.as_u8(), 5];
        let mut buf = body.to_vec();
        buf.resize(body.len() + DIRECTED_TRAILER_LEN, 0);
        assert_eq!(
            tag_directed_into(
                &mut router,
                Duration::ZERO,
                Mac::BROADCAST,
                DEFAULT_BATMAN_ETHER_TYPE,
                body.len(),
                &mut buf,
            ),
            Some(body.len()),
            "a keep-alive carries its own signature, not a pairwise tag"
        );
    }

    /// The bytes of an `EchoRequest` probe routed toward `dest`.
    fn echo_request_bytes(dest: Mac, orig: Mac) -> Vec<u8> {
        wayfinder::batman::wire::BatmanEchoPacket {
            packet_type: BatmanPacketType::EchoRequest.as_u8(),
            version: 5,
            ttl: 50,
            dest,
            orig,
            seqno: 1u16.to_be(),
            req_hops: 0,
            hops: 0,
        }
        .as_bytes()
        .to_vec()
    }

    /// An untagged `EchoRequest` under a group link dst is refused, so the ping
    /// data plane cannot be used as an unauthenticated reflection primitive.
    ///
    /// The ping suite in `wayfinder-test` runs entirely with auth *off*, where
    /// `strip_directed` short-circuits before the sub-type is ever consulted —
    /// so without this test the only thing standing behind
    /// `requires_pairwise_tag`'s claim about `EchoRequest`/`EchoReply` is the
    /// table test, and moving the pair to the exempt arm breaks nothing else in
    /// the workspace. An outsider that could get an echo answered would have a
    /// reflection primitive off any member MAC it has read off the air, which is
    /// exactly what the `NextHopChallenge` address guard exists to deny on the
    /// proof path.
    #[test]
    fn an_untagged_echo_request_is_never_answered() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let (mut router, _peer) = router_with_verified_peer(&authority);

        let payload = echo_request_bytes(mac(1), mac(9));
        let mut tx = [0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
        let mut sink = CaptureSink::default();
        for dst in [group_mac(), Mac::BROADCAST, mac(1)] {
            let link = frame_bytes(dst, mac(9), DEFAULT_BATMAN_ETHER_TYPE, &payload);
            handle_mesh_frame(
                Duration::ZERO,
                &mut router,
                0,
                LinkFrame::ref_from_bytes(&link).unwrap(),
                LinkMetrics::default(),
                &mut tx,
                &mut sink,
            );
        }
        assert!(
            sink.mesh.is_empty(),
            "an outsider's untagged echo request must not be answered, \
             whatever link dst it wears"
        );
        assert!(sink.local.is_empty(), "and nothing is delivered locally");
    }

    /// A sub-type this build does not recognise is refused when untagged.
    ///
    /// Named for the behavior on purpose. The `None => true` fail-closed arm is
    /// otherwise covered only by accident, through two tests that use
    /// `[0xAA, ..]`/`[0xDE, ..]` as opaque filler and say nothing about
    /// sub-types — and this very change shows how that coverage evaporates: the
    /// four `[0x01, 0x02, 0x03]` payloads elsewhere in this file had to become
    /// real `Unicast` bytes, because `0x01` is `Ogm` and silently became exempt.
    /// The same tidying applied to `0xAA` would delete the fail-closed arm's
    /// only behavioral coverage without failing a thing.
    #[test]
    fn an_unrecognised_sub_type_is_refused_when_untagged() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let (mut router, _peer) = router_with_verified_peer(&authority);

        // 0xEE is not a `BatmanPacketType` this build knows.
        let payload = [0xEEu8, 0x01, 0x02, 0x03];
        assert!(
            BatmanPacketType::from_u8(payload[0]).is_none(),
            "this test is meaningless if 0xEE ever becomes a known sub-type"
        );

        let mut tx = [0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
        let mut sink = CaptureSink::default();
        for dst in [group_mac(), Mac::BROADCAST, mac(1)] {
            let link = frame_bytes(dst, mac(9), DEFAULT_BATMAN_ETHER_TYPE, &payload);
            assert!(
                strip_directed(&mut router, LinkFrame::ref_from_bytes(&link).unwrap()).is_none(),
                "an unrecognised sub-type must fail closed under link dst {dst:?}"
            );
            handle_mesh_frame(
                Duration::ZERO,
                &mut router,
                0,
                LinkFrame::ref_from_bytes(&link).unwrap(),
                LinkMetrics::default(),
                &mut tx,
                &mut sink,
            );
        }
        assert!(sink.local.is_empty(), "nothing delivered locally");
        assert!(sink.mesh.is_empty(), "and nothing relayed on its behalf");
    }

    /// The positive control for [`a_group_addressed_unicast_is_never_delivered_locally`]:
    /// a genuinely tagged unicast from a verified peer, aimed at this node, *is*
    /// delivered to the host device.
    ///
    /// Without it every `sink.local` assertion in this file is `is_empty()`, so
    /// a change that broke local delivery outright would leave the whole suite
    /// green while the negative tests went on "passing" for the wrong reason.
    #[test]
    fn a_tagged_unicast_from_a_verified_peer_is_delivered_locally() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let (mut router, mut peer) = router_with_verified_peer(&authority);

        let inner = unicast_bytes(mac(1), b"HONEST-PAYLOAD");
        let mut body = inner.clone();
        body.resize(inner.len() + DIRECTED_TRAILER_LEN, 0);
        let (f, trailer) = body.split_at_mut(inner.len());
        peer.tag_directed(mac(1), f, trailer).expect("peer tags");

        let link = frame_bytes(mac(1), mac(2), DEFAULT_BATMAN_ETHER_TYPE, &body);
        let mut tx = [0u8; wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN];
        let mut sink = CaptureSink::default();
        handle_mesh_frame(
            Duration::ZERO,
            &mut router,
            0,
            LinkFrame::ref_from_bytes(&link).unwrap(),
            LinkMetrics::default(),
            &mut tx,
            &mut sink,
        );
        assert_eq!(sink.local.len(), 1, "the honest unicast is delivered");
        assert!(
            sink.local[0].ends_with(b"HONEST-PAYLOAD"),
            "and the trailer was stripped before delivery, not passed through"
        );
    }

    /// A *genuinely tagged* unicast is accepted even under a group link dst —
    /// the deliberate asymmetry with
    /// [`tag_directed_into_refuses_a_group_addressed_unicast`], recorded here so
    /// nobody "fixes" it.
    ///
    /// `strip_directed` is dst-blind by design, and `verify_directed` binds the
    /// tag to `(pairwise key, counter, src, frame)` — the link dst is *not* in
    /// the bound context. That is safe because the pairwise key is per-(sender,
    /// receiver): only the intended peer can verify the tag, so the other N-1
    /// nodes on the segment drop it and the sender gains nothing by shouting.
    ///
    /// The two obvious "fixes" are both worse. Rejecting on a group dst at
    /// ingress re-introduces a decision keyed on the attacker-chosen field this
    /// whole change exists to stop trusting; binding the dst into the tag is a
    /// wire-format change that buys nothing. Egress refuses to *produce* one
    /// only because no honest path stages one — that is a tightness check on
    /// ourselves, not a claim about what a peer may send.
    #[test]
    fn a_tagged_unicast_is_accepted_even_under_a_group_link_dst() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let (mut router, mut peer) = router_with_verified_peer(&authority);

        let inner = unicast_bytes(mac(1), b"TAGGED-UNDER-GROUP");
        let mut body = inner.clone();
        body.resize(inner.len() + DIRECTED_TRAILER_LEN, 0);
        let (f, trailer) = body.split_at_mut(inner.len());
        peer.tag_directed(mac(1), f, trailer).expect("peer tags");

        let link = frame_bytes(Mac::BROADCAST, mac(2), DEFAULT_BATMAN_ETHER_TYPE, &body);
        let out = strip_directed(&mut router, LinkFrame::ref_from_bytes(&link).unwrap());
        assert!(
            out.is_some(),
            "the tag authenticates the frame; the link dst is not part of what it binds"
        );
        assert_eq!(
            out.unwrap().payload.len(),
            inner.len(),
            "and the trailer is stripped exactly as under a unicast dst"
        );
    }
}
