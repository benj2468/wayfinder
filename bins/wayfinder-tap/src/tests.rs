//! Integration tests for the driver, driving [`Driver::run_once`] against a
//! fake TAP and an in-process mesh interface — the real production wiring with
//! only the kernel devices swapped for channels.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::mpsc;
use wayfinder::batman::wire::{
    BATADV_BCAST, BATADV_IV_OGM, BATADV_MCAST, BATADV_TVLV_MCAST, BATADV_UNICAST, BatmanOgmPacket,
    BatmanTvlvHdr, BatmanUnicastPacket, ETH_P_BATMAN,
};
use wayfinder::interfaces::frame::Mac;
use wayfinder_driver::{Driver, FrameIo, Link, QueryRx, QueryTx};
use zerocopy::IntoBytes;

// ── fake TAP ───────────────────────────────────────────────────────────────

/// A [`FrameIo`] backed by channels so tests can inject frames "from the host"
/// and inspect frames the driver writes "to the host".  The outbound log is
/// shared via [`Arc`] so the test can observe it after the device is moved into
/// the [`Driver`].
struct FakeTap {
    inbound: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    outbound: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl FakeTap {
    fn new() -> (Self, mpsc::Sender<Vec<u8>>, Arc<Mutex<Vec<Vec<u8>>>>) {
        let (tx, rx) = mpsc::channel(16);
        let outbound = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                inbound: tokio::sync::Mutex::new(rx),
                outbound: outbound.clone(),
            },
            tx,
            outbound,
        )
    }
}

#[async_trait]
impl FrameIo for FakeTap {
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let frame = self.inbound.lock().await.recv().await;
        match frame {
            Some(f) => {
                let n = f.len().min(buf.len());
                buf[..n].copy_from_slice(&f[..n]);
                Ok(n)
            }
            // Channel exhausted: stay pending so this select branch never
            // wins (the test always injects before driving run_once).
            None => std::future::pending().await,
        }
    }

    async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.outbound.lock().unwrap().push(buf.to_vec());
        Ok(buf.len())
    }
}

// ── wire helpers ─────────────────────────────────────────────────────────

/// Serialize a `LinkFrame`: `[src][dst][proto native][payload]`.  Protocol is
/// written native-endian to match how the link layer encodes it.
fn link_wire(src: [u8; 6], dst: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&src);
    v.extend_from_slice(&dst);
    v.extend_from_slice(&ETH_P_BATMAN.to_ne_bytes());
    v.extend_from_slice(payload);
    v
}

/// Build a raw Ethernet frame: `[dst MAC][src MAC][ethertype][payload]`.
fn eth_frame(dst: [u8; 6], src: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&dst);
    v.extend_from_slice(&src);
    v.extend_from_slice(&[0x08, 0x00]); // IPv4 ethertype, arbitrary here
    v.extend_from_slice(payload);
    v
}

/// Boilerplate for a single-interface node under test: the [`Driver`] plus the
/// test-side handles for injecting/observing host and mesh frames.
struct Harness {
    driver: Driver<FakeTap>,
    /// Inject frames as if they arrived from the host on the TAP.
    tap_in: mpsc::Sender<Vec<u8>>,
    /// What the driver has written back to the host TAP.
    tap_out: Arc<Mutex<Vec<Vec<u8>>>>,
    /// The far end of the single mesh interface's duplex.
    far: tokio::net::UnixDatagram,
    /// Kept alive so the management-query channel stays open (its select
    /// branch must remain pending, not resolve to `None`).
    _qtx: QueryTx,
}

fn harness(mac: [u8; 6]) -> Harness {
    let (tap, tap_in, tap_out) = FakeTap::new();
    let (near, far) = tokio::net::UnixDatagram::pair().unwrap();
    let (qtx, qrx): (QueryTx, QueryRx) = mpsc::channel(1);
    Harness {
        driver: Driver::new(Mac(mac), tap, vec![Link::new(near)], qrx),
        tap_in,
        tap_out,
        far,
        _qtx: qtx,
    }
}

impl Harness {
    async fn step(&mut self) {
        self.driver.run_once().await.unwrap();
    }

    /// Frames the driver has written to the host TAP so far.
    fn tap_sent(&self) -> Vec<Vec<u8>> {
        self.tap_out.lock().unwrap().clone()
    }
}

// ── tests ──────────────────────────────────────────────────────────────────

/// A broadcast/multicast Ethernet frame from the host is wrapped as a
/// BATMAN broadcast and flooded onto the mesh.
#[tokio::test]
async fn tap_broadcast_frame_floods_to_mesh() {
    let mac = [0xaa, 0, 0, 0, 0, 1];
    let mut h = harness(mac);

    h.tap_in
        .send(eth_frame([0xff; 6], mac, b"arp who-has"))
        .await
        .unwrap();
    h.step().await;

    // Read the frame that landed on the (single) mesh interface.
    let mut buf = [0u8; 1500];
    let n = h.far.recv(&mut buf).await.unwrap();
    assert!(n >= 15);
    // wire: [src:6][dst:6][proto:2][batman payload...]
    assert_eq!(&buf[6..12], &[0xff; 6], "link dst should be broadcast");
    assert_eq!(buf[14], BATADV_BCAST, "should be a BATMAN broadcast");
}

/// After learning a peer via its OGM, a unicast Ethernet frame to that
/// peer's MAC is wrapped as a BATMAN unicast and routed to it.
#[tokio::test]
async fn tap_unicast_frame_routes_to_learned_peer() {
    let mac = [0xaa, 0, 0, 0, 0, 1];
    let peer = [0xbc, 0, 0, 0, 0, 2];
    let mut h = harness(mac);

    // 1) Peer announces itself via an OGM (delivered on the interface).
    let ogm = BatmanOgmPacket {
        packet_type: BATADV_IV_OGM,
        version: 5,
        ttl: 50,
        flags: 0,
        seqno: 1u32.to_be(),
        orig: Mac(peer),
        prev_sender: Mac(peer),
        reserved: 0,
        tq: 255,
        tvlv_len: 0,
    };
    h.far
        .send(&link_wire(peer, [0xff; 6], ogm.as_bytes()))
        .await
        .unwrap();
    h.step().await;
    // Drain the re-flooded OGM that run_once just put back on the wire.
    let mut scratch = [0u8; 1500];
    let _ = h.far.recv(&mut scratch).await.unwrap();

    // 2) Host sends a unicast frame to the peer's MAC.
    h.tap_in
        .send(eth_frame(peer, mac, b"hello peer"))
        .await
        .unwrap();
    h.step().await;

    let mut buf = [0u8; 1500];
    let n = h.far.recv(&mut buf).await.unwrap();
    assert!(n >= 23);
    assert_eq!(&buf[6..12], &peer, "link dst should be the (direct) peer");
    assert_eq!(buf[14], BATADV_UNICAST, "should be a BATMAN unicast");
    // BatmanUnicastPacket = [type:1][version:1][ttl:1][dest:6]; dest follows
    // the 14-byte link header + 3 header bytes => buf[17..23].
    assert_eq!(&buf[17..23], &peer, "unicast dest should be the peer");
}

/// A BATMAN unicast addressed to us is unwrapped and the inner frame is
/// written to the local TAP.
#[tokio::test]
async fn mesh_unicast_for_self_is_written_to_tap() {
    let mac = [0xaa, 0, 0, 0, 0, 1];
    let peer = [0xbc, 0, 0, 0, 0, 2];
    let mut h = harness(mac);

    let inner = b"INNER ETHERNET FRAME FOR THE HOST";
    let hdr = BatmanUnicastPacket {
        packet_type: BATADV_UNICAST,
        version: 5,
        ttl: 50,
        dest: Mac(mac),
    };
    let mut batman = hdr.as_bytes().to_vec();
    batman.extend_from_slice(inner);
    h.far.send(&link_wire(peer, mac, &batman)).await.unwrap();

    h.step().await;

    let sent = h.tap_sent();
    assert_eq!(sent.len(), 1, "exactly one frame delivered to the TAP");
    assert_eq!(sent[0], inner, "inner frame delivered to the host verbatim");
}

/// Two datagrams arriving back-to-back on one interface must be processed
/// as two distinct frames. Regression test for `Link::receive` accumulating
/// into its buffer across calls and concatenating frames.
#[tokio::test]
async fn two_frames_on_one_interface_stay_distinct() {
    let mac = [0xaa, 0, 0, 0, 0, 1];
    let peer = [0xbc, 0, 0, 0, 0, 2];
    let mut h = harness(mac);

    let inners: [&[u8]; 2] = [b"first frame!!", b"second frame!"];
    for inner in inners {
        let hdr = BatmanUnicastPacket {
            packet_type: BATADV_UNICAST,
            version: 5,
            ttl: 50,
            dest: Mac(mac),
        };
        let mut batman = hdr.as_bytes().to_vec();
        batman.extend_from_slice(inner);
        h.far.send(&link_wire(peer, mac, &batman)).await.unwrap();
    }

    h.step().await;
    h.step().await;

    let sent = h.tap_sent();
    assert_eq!(
        sent,
        vec![inners[0].to_vec(), inners[1].to_vec()],
        "each frame must be delivered intact, not concatenated"
    );
}

/// After learning (via an OGM multicast TVLV) that a peer listens to a group,
/// a multicast Ethernet frame from the host to that group is sent as a single
/// BATADV_MCAST packet addressed to the peer — not flooded as a broadcast.
#[tokio::test]
async fn tap_multicast_frame_unicasts_to_known_listener() {
    let mac = [0xaa, 0, 0, 0, 0, 1];
    let peer = [0xbc, 0, 0, 0, 0, 2];
    let group = [0x01, 0x00, 0x5e, 0x00, 0x00, 0x2a];
    let mut h = harness(mac);

    // 1) Peer announces itself and its interest in `group` via an OGM carrying
    //    a multicast TVLV (value = the single group MAC).
    let value = group.to_vec();
    let tvlv_hdr = BatmanTvlvHdr {
        tvlv_type: BATADV_TVLV_MCAST,
        version: 1,
        len: (value.len() as u16).to_be(),
    };
    let tvlv_total = std::mem::size_of::<BatmanTvlvHdr>() + value.len();
    let ogm = BatmanOgmPacket {
        packet_type: BATADV_IV_OGM,
        version: 5,
        ttl: 50,
        flags: 0,
        seqno: 1u32.to_be(),
        orig: Mac(peer),
        prev_sender: Mac(peer),
        reserved: 0,
        tq: 255,
        tvlv_len: (tvlv_total as u16).to_be(),
    };
    let mut payload = ogm.as_bytes().to_vec();
    payload.extend_from_slice(tvlv_hdr.as_bytes());
    payload.extend_from_slice(&value);
    h.far
        .send(&link_wire(peer, [0xff; 6], &payload))
        .await
        .unwrap();
    h.step().await;
    // Drain the re-flooded OGM that run_once put back on the wire.
    let mut scratch = [0u8; 1500];
    let _ = h.far.recv(&mut scratch).await.unwrap();

    // 2) Host sends a multicast Ethernet frame to the group.
    h.tap_in
        .send(eth_frame(group, mac, b"mcast hello"))
        .await
        .unwrap();
    h.step().await;

    // 3) A single BATADV_MCAST copy addressed to the peer lands on the mesh.
    let mut buf = [0u8; 1500];
    let n = h.far.recv(&mut buf).await.unwrap();
    assert!(n >= 23, "frame too short to be a BATADV_MCAST packet");
    // wire: [src:6][dst:6][proto:2][BatmanMcastPacket: type,ver,ttl,dest:6 ...]
    assert_eq!(
        &buf[6..12],
        &peer,
        "link dst should be the (direct) listener"
    );
    assert_eq!(buf[14], BATADV_MCAST, "should be a BATMAN multicast packet");
    assert_eq!(
        &buf[17..23],
        &peer,
        "mcast dest should be the listener node"
    );
}
