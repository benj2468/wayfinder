//! Integration tests for the event loop, driving [`EventLoop::run_once`] against
//! a fake TAP and an in-process mesh interface.

use async_trait::async_trait;
use tokio::sync::mpsc;
use wayfinder::CentralRouter;
use wayfinder::batman::wire::{
    BATADV_BCAST, BATADV_IV_OGM, BATADV_UNICAST, BatmanOgmPacket, BatmanUnicastPacket, ETH_P_BATMAN,
};
use wayfinder::interfaces::frame::Mac;
use zerocopy::IntoBytes;

use wayfinder_server::QueryTx;

use crate::executor::EventLoop;
use crate::links::{AsyncIo, Link};

// ── fake TAP ───────────────────────────────────────────────────────────────

/// A [`AsyncIo`] backed by channels so tests can inject frames "from the host"
/// and inspect frames the router writes "to the host".
struct FakeTap {
    inbound: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    outbound: tokio::sync::Mutex<Vec<Vec<u8>>>,
}

impl FakeTap {
    fn new() -> (Self, mpsc::Sender<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(16);
        (
            Self {
                inbound: tokio::sync::Mutex::new(rx),
                outbound: tokio::sync::Mutex::new(Vec::new()),
            },
            tx,
        )
    }

    /// Frames the router has written to the TAP so far.
    async fn sent(&self) -> Vec<Vec<u8>> {
        self.outbound.lock().await.clone()
    }
}

#[async_trait]
impl AsyncIo for FakeTap {
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
        self.outbound.lock().await.push(buf.to_vec());
        Ok(buf.len())
    }
}

// ── wire helpers ─────────────────────────────────────────────────────────

/// Serialize a `LinkFrame<[u8;6]>`: `[src][dst][proto native][payload]`.
/// Protocol is written native-endian to match how the link layer (and
/// `build_frame` in the test harness) encodes it.
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

/// Boilerplate for a single-interface router under test: the `EventLoop`
/// plus the test-side handles for injecting/observing host and mesh frames.
struct Harness {
    ev: EventLoop<FakeTap>,
    /// Inject frames as if they arrived from the host on the TAP.
    tap_in: mpsc::Sender<Vec<u8>>,
    /// The far end of the single mesh interface's duplex.
    far: tokio::net::UnixDatagram,
    /// Kept alive so the management-query channel stays open (its select
    /// branch must remain pending, not resolve to `None`).
    _qtx: QueryTx,
}

fn harness(mac: [u8; 6]) -> Harness {
    let (tap, tap_in) = FakeTap::new();
    let (near, far) = tokio::net::UnixDatagram::pair().unwrap();
    let (qtx, qrx) = mpsc::channel(1);
    Harness {
        ev: EventLoop {
            tap,
            interfaces: vec![Link::new(near)],
            router: CentralRouter::new(Mac(mac)),
            query_rx: qrx,
            mac_addr: Mac(mac),
            start: std::time::Instant::now(),
            rx_buffer: [0u8; 1500],
            tx_buffer: [0u8; 1500],
        },
        tap_in,
        far,
        _qtx: qtx,
    }
}

impl Harness {
    async fn step(&mut self) {
        self.ev.run_once().await.unwrap();
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
        tq: 255,
        seqno: 1u32.to_be(),
        orig: Mac(peer),
        prev_sender: Mac(peer),
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

    let sent = h.ev.tap.sent().await;
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

    let sent = h.ev.tap.sent().await;
    assert_eq!(
        sent,
        vec![inners[0].to_vec(), inners[1].to_vec()],
        "each frame must be delivered intact, not concatenated"
    );
}
