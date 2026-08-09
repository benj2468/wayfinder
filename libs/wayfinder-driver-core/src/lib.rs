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
//! split-horizon and the per-link transmit gate — and returns *how much to
//! send* and *which interfaces* to send it on.  What stays in each driver is
//! only the async event loop, the interface set, and the actual I/O for the
//! interfaces in that plan: "one behavior, three loops".
//!
//! # The whole surface
//!
//! Four entry points, and a shell calls all four:
//!
//! | | |
//! |---|---|
//! | [`handle_mesh_frame`] | a frame arrived on interface `idx` |
//! | [`poll_due_ogms`] | the periodic timer fired |
//! | [`poll_due_keepalives`] | likewise, for keep-alives |
//! | [`plan_dispatch`] | a staged frame is ready to go out |
//!
//! The first three hand their results to a [`MeshSink`]; the fourth returns a
//! [`DispatchPlan`]. Everything else — authenticating a directed frame on the
//! way in or out, resolving egress, split-horizon — is internal to those four,
//! deliberately: a shell that reached past them could apply half the policy.
//!
//! [`wayfinder-tick-driver`]: https://docs.rs/wayfinder-tick-driver
//! [`wayfinder-driver`]: https://docs.rs/wayfinder-driver
//! [`wayfinder-embedded-driver`]: https://docs.rs/wayfinder-embedded-driver
#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use core::time::Duration;

use interfaces::link::LinkMetrics;
use tracing::trace;
use tracing::warn;
use wayfinder::DEFAULT_BATMAN_ETHER_TYPE;
use wayfinder::EgressInterface;
use wayfinder::auth::DIRECTED_TRAILER_LEN;
use wayfinder::batman::wire::BATADV_CERT_REPLY;
use wayfinder::batman::wire::BATADV_CERT_REQ;
use wayfinder::interfaces::frame::LinkFrame;
use wayfinder::interfaces::frame::Mac;
use wayfinder::router_ops::OgmAuthOps;
use wayfinder::router_ops::RouterOps;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

/// How an [`OutgoingFrame`] is fanned out onto the mesh interfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Egress {
    /// Let the router pick the egress (`get_egress_interface`): a metric-driven
    /// single interface for a unicast, or every interface for a
    /// broadcast/flood.  `exclude` is the interface index a re-flood arrived on
    /// (split-horizon), so a re-flood never goes back toward the neighbor it
    /// came from; `None` for locally originated frames.
    Auto {
        /// The interface index to omit from an `All` fan-out, or `None`.
        exclude: Option<usize>,
    },
    /// Send out exactly one interface by index, bypassing the router's egress
    /// choice — used for per-link OGM emission on each link's own Trickle
    /// schedule.
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

/// Whether `payload`'s BATMAN sub-type is a lazy-cert-distribution control
/// packet (`BATADV_CERT_REQ`/`BATADV_CERT_REPLY`) — addressed to a specific
/// node like a directed data-plane frame, but self-authenticating (its own
/// signature) rather than pairwise-tagged.
fn is_cert_control(payload: &[u8]) -> bool {
    matches!(
        payload.first(),
        Some(&BATADV_CERT_REQ) | Some(&BATADV_CERT_REPLY)
    )
}

/// Verify and strip the pairwise-tag trailer from a directed data-plane frame
/// when auth is enabled, returning the frame to route on: the original frame
/// (auth off, a broadcast/OGM, or a cert-control packet), a shorter *view* over
/// the same bytes with the trailer dropped, or `None` if the frame must be
/// dropped (bad/missing tag from an unverified or foreign neighbor).
fn strip_directed<'a, R: RouterOps>(router: &mut R, frame: &'a LinkFrame) -> Option<&'a LinkFrame> {
    // Only directed (unicast/mcast) frames carry a tag; broadcasts/OGMs (a
    // multicast dst) are signed, and with auth off nothing is tagged.
    let Some(auth) = router.auth_mut() else {
        return Some(frame);
    };
    if frame.protocol.get() != DEFAULT_BATMAN_ETHER_TYPE
        || frame.dst.is_multicast()
        || is_cert_control(&frame.payload)
    {
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
        trace!(src = ?frame.src, "drop: directed frame failed pairwise auth");
        return None;
    }

    // Reinterpret the frame's own bytes minus the trailer — a shorter view over
    // the same buffer (no copy) — so the engine sees only the real payload and
    // never forwards or delivers the tag bytes.
    let full = frame.as_bytes();
    let strip_len = full.len() - DIRECTED_TRAILER_LEN;
    LinkFrame::ref_from_bytes(full.get(..strip_len)?).ok()
}

/// Finalize a directed data-plane frame for transmit, appending a pairwise auth
/// tag when one is required, and return **how many bytes to actually send**.
///
/// `buf` holds the frame body in `buf[..body_len]` and must reserve at least
/// [`DIRECTED_TRAILER_LEN`] spare bytes after it (`buf.len() >= body_len +
/// DIRECTED_TRAILER_LEN`) for the tag to be written into; the caller owns the
/// buffer, so reserving that space is its concern.  Returns:
///
/// * `Some(body_len)` — send the body untagged: auth is disabled, or this is a
///   broadcast/OGM/cert-control packet that carries its own signature instead.
/// * `Some(body_len + DIRECTED_TRAILER_LEN)` — the tag was written; send the
///   body plus trailer.
/// * `None` — auth is on but the frame can't be tagged (no verified key for
///   `dst` yet, or the pairwise counter is exhausted); the caller must **drop**
///   it rather than emit it in the clear.
///
/// [`DIRECTED_TRAILER_LEN`]: wayfinder::auth::DIRECTED_TRAILER_LEN
fn tag_directed_into<R: RouterOps>(
    router: &mut R,
    dst: Mac,
    protocol: u16,
    body_len: usize,
    buf: &mut [u8],
) -> Option<usize> {
    // Broadcasts/OGMs (a multicast dst) are signed instead, and cert-control
    // packets (CertReq/CertReply) carry their own self-authenticating signature
    // rather than a neighbor pairwise tag, so both send their body as-is.
    let needs_tag = protocol == DEFAULT_BATMAN_ETHER_TYPE
        && !dst.is_multicast()
        && !is_cert_control(&buf[..body_len]);

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
        warn!(?dst, "auth: dropping untaggable directed frame");
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
    if let Some(f) = rx.forward {
        sink.emit(OutgoingFrame {
            dst: f.dst,
            protocol: f.protocol,
            payload: f.payload,
            // A re-flood must not go back out the interface it arrived on.
            egress: Egress::Auto { exclude: Some(idx) },
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
/// authenticated (or legitimately needs no tag), and the targets have already
/// been split-horizon filtered and transmit-gated.
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
    let send_len = tag_directed_into(router, dst, protocol, body_len, buf)?;

    // The BATMAN sub-type of this outgoing frame (its leading payload byte),
    // used to consult each candidate interface's per-link transmit gates
    // (`link_may_tx`). Only meaningful for BATMAN frames; other protocols are
    // never gated (`None` ⇒ always permitted).  Read from the *body*, not the
    // whole buffer: `buf` still carries the reserved trailer past `body_len`.
    let pkt_type = (protocol == DEFAULT_BATMAN_ETHER_TYPE)
        .then(|| buf.get(..body_len).and_then(<[u8]>::first).copied())
        .flatten();

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
        Egress::Auto { exclude } => match router.get_egress_interface(now, dst) {
            Some(EgressInterface::All) => {
                for idx in 0..num_interfaces {
                    // Split-horizon: never re-flood back out the interface a
                    // re-flood arrived on.
                    if Some(idx) == exclude {
                        continue;
                    }
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
    use wayfinder::batman::wire::BATADV_CERT_REPLY;
    use wayfinder::batman::wire::BATADV_CERT_REQ;
    use wayfinder::batman::wire::BATADV_IV_OGM;
    use wayfinder::batman::wire::BATADV_UNICAST;
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
            packet_type: BATADV_IV_OGM,
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

    /// `is_cert_control` flags exactly the two lazy-cert control sub-types by
    /// their leading byte, and nothing else (including the empty payload).
    #[test]
    fn is_cert_control_flags_cert_packets() {
        assert!(is_cert_control(&[BATADV_CERT_REQ]));
        assert!(is_cert_control(&[BATADV_CERT_REPLY, 0xff]));
        assert!(!is_cert_control(&[0x01]));
        assert!(!is_cert_control(&[]));
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

    /// A received OGM from a neighbor is re-flooded, tagged with
    /// `Egress::Auto { exclude: Some(idx) }` so split-horizon keeps it off the
    /// interface it arrived on (the loop-prevention invariant behind the
    /// broadcast-flood fix).
    #[test]
    fn handle_mesh_frame_reforwards_ogm_with_split_horizon_exclude() {
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
            Egress::Auto { exclude: Some(2) },
            "split-horizon excludes the ingress interface"
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

        let body = [BATADV_CERT_REQ, 0x11, 0x22];
        let mut buf = body.to_vec();
        buf.resize(body.len() + DIRECTED_TRAILER_LEN, 0);
        let out = tag_directed_into(
            &mut router,
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

    /// With auth on, a directed frame from a neighbor the router has never
    /// verified fails the pairwise check, so `strip_directed` drops it (returns
    /// `None`) rather than route an unauthenticated frame.
    #[test]
    fn strip_directed_drops_frame_from_unverified_neighbor() {
        let authority = Authority::from_seed(&[1; 32], 0xABCD);
        let mut router = CentralRouter::new(mac(1));
        router.set_auth(member_auth(&authority, 1, mac(1)));

        let inner = [0x01u8, 0x02, 0x03];
        let mut payload = inner.to_vec();
        payload.resize(inner.len() + DIRECTED_TRAILER_LEN, 0); // bogus zero trailer
        let link = frame_bytes(mac(1), mac(9), DEFAULT_BATMAN_ETHER_TYPE, &payload);
        let frame = LinkFrame::ref_from_bytes(&link).unwrap();

        assert!(
            strip_directed(&mut router, frame).is_none(),
            "directed frame from an unverified neighbor is dropped"
        );
    }

    // ---- plan_dispatch ----------------------------------------------------
    //
    // Egress resolution, split-horizon and the per-link transmit gate are
    // written out in all three driver shells today. That makes split-horizon —
    // a correctness invariant — a thing you can fix in one shell and silently
    // leave broken in two. These pin the shared decision so the shells can be
    // reduced to "do the I/O for each interface in the plan".

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
        exclude: Option<usize>,
        num_interfaces: usize,
    ) -> Option<Vec<usize>> {
        let mut buf = payload.to_vec();
        buf.resize(payload.len() + DIRECTED_TRAILER_LEN, 0);
        plan_dispatch(
            router,
            Duration::from_secs(1),
            Mac::BROADCAST,
            DEFAULT_BATMAN_ETHER_TYPE,
            Egress::Auto { exclude },
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
        let payload = [BATADV_IV_OGM, 0x02, 0x03];
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
        let targets = plan_broadcast(&mut router, &[BATADV_IV_OGM, 0x02], None, 4)
            .expect("a broadcast is dispatchable");

        assert_eq!(targets, std::vec![0, 1, 2, 3]);
    }

    /// **Split-horizon.** A re-flood must never go back out the interface it
    /// arrived on, or two nodes ping-pong the same broadcast between them.
    #[test]
    fn reflood_never_returns_out_the_ingress_interface() {
        let mut router = router_with_interfaces(4);
        let targets = plan_broadcast(&mut router, &[BATADV_IV_OGM, 0x02], Some(1), 4)
            .expect("a re-flood is dispatchable");

        assert_eq!(targets, std::vec![0, 2, 3]);
        assert!(
            !targets.contains(&1),
            "split-horizon: the ingress interface must be excluded"
        );
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

        let targets = plan_broadcast(&mut router, &[BATADV_IV_OGM, 0x02], None, 4)
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
        let targets = plan_broadcast(&mut router, &[BATADV_IV_OGM, 0x02], None, 2)
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
        let payload = [BATADV_UNICAST, 0x02, 0x03];
        let mut buf = payload.to_vec();
        buf.resize(payload.len() + DIRECTED_TRAILER_LEN, 0);

        assert!(
            plan_dispatch(
                &mut router,
                Duration::from_secs(1),
                mac(9),
                DEFAULT_BATMAN_ETHER_TYPE,
                Egress::Auto { exclude: None },
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
        let payload = [BATADV_UNICAST, 0x02];
        let mut buf = payload.to_vec();
        buf.resize(payload.len() + DIRECTED_TRAILER_LEN, 0);

        let plan = plan_dispatch(
            &mut router,
            Duration::from_secs(1),
            mac(200),
            DEFAULT_BATMAN_ETHER_TYPE,
            Egress::Auto { exclude: None },
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
}
