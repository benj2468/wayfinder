//! Shared, `no_std` router-orchestration logic for the wayfinder drivers.
//!
//! Both drivers — the `std`/tokio [`wayfinder-driver`] and the `no_std`
//! [`wayfinder-embedded-driver`] — turn the same three inputs into the same
//! outgoing frames: a received mesh frame, a due periodic OGM, and (later) a
//! host frame.  That translation is the logic here.  It is deliberately
//! **synchronous and allocation-free**: it plans each outgoing frame into an
//! [`OutgoingFrame`] borrowing the caller's transmit scratchpad and hands it to
//! a [`MeshSink`], which copies it into whatever staging the driver uses
//! (`Vec` on the host, `heapless::Vec` on embedded) before the scratchpad is
//! reused.  The async event loop, the interface set, and the dispatch of staged
//! frames stay in each driver — "one behavior, two loops".
//!
//! [`wayfinder-driver`]: https://docs.rs/wayfinder-driver
//! [`wayfinder-embedded-driver`]: https://docs.rs/wayfinder-embedded-driver
#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use core::time::Duration;

use interfaces::link::LinkMetrics;
use tracing::{trace, warn};
use wayfinder::auth::DIRECTED_TRAILER_LEN;
use wayfinder::batman::wire::{BATADV_CERT_REPLY, BATADV_CERT_REQ};
use wayfinder::interfaces::frame::{LinkFrame, Mac};
use wayfinder::{CentralRouter, DEFAULT_BATMAN_ETHER_TYPE};
use zerocopy::{FromBytes, IntoBytes};

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
pub fn is_cert_control(payload: &[u8]) -> bool {
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
pub fn strip_directed<'a>(
    router: &mut CentralRouter,
    frame: &'a LinkFrame,
) -> Option<&'a LinkFrame> {
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
pub fn tag_directed_into(
    router: &mut CentralRouter,
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
pub fn handle_mesh_frame(
    now: Duration,
    router: &mut CentralRouter,
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
pub fn poll_due_ogms(
    router: &mut CentralRouter,
    now: Duration,
    tx_buffer: &mut [u8],
    sink: &mut impl MeshSink,
) {
    // Each emission advances exactly one interface's timer, so the set of due
    // interfaces shrinks every pass and the loop terminates.
    while let Some(idx) = router.due_interface(now) {
        if let Some(f) = router.poll(now, tx_buffer) {
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

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;

    use super::*;
    use wayfinder::auth::{DIRECTED_TRAILER_LEN, OgmAuth, OgmVerdict};
    use wayfinder::batman::wire::{
        BATADV_CERT_REPLY, BATADV_CERT_REQ, BATADV_IV_OGM, BatmanOgmPacket,
    };
    use wayfinder::interfaces::frame::LinkFrame;
    use wayfinder_auth::{Authority, Keypair};
    use zerocopy::{FromBytes, IntoBytes};

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
}
