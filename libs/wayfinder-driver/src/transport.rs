//! Frame transports: the [`FrameIo`] byte-pipe every simple carrier is hidden
//! behind, the [`LinkT`] mesh-interface trait the driver speaks to, and the
//! [`Link`] adapter that turns a [`FrameIo`] into a point-to-point [`LinkT`].
//!
//! Two layers, deliberately:
//!
//! * [`FrameIo`] is the dumb message-oriented byte pipe — one `recv`/`send`
//!   moves exactly one whole frame.  Both the local host device (a TUN/TAP) and
//!   each point-to-point mesh carrier (a `UnixDatagram`, `UdpSocket`, an
//!   in-process channel, …) are this shape.
//! * [`LinkT`] is one *mesh interface*.  A point-to-point carrier gets a
//!   [`LinkT`] for free via the blanket [`Link`] adapter, which ignores the
//!   destination and frames `[src][dst][protocol][payload]` onto the pipe.  A
//!   multi-access or self-routing carrier (UDP multicast, a radio whose mesh
//!   "appears as a single switch") instead implements [`LinkT`] directly and
//!   uses the destination MAC handed to [`send`](LinkT::send) to make its own
//!   delivery decision.  The driver only ever holds `Box<dyn LinkT>`, so a
//!   single interface set can mix both kinds.

use async_trait::async_trait;

use interfaces::link::LinkMetrics;
use wayfinder::interfaces::{
    frame::{LinkFrame, LinkFrameData, Mac},
    link::LinkError,
};
use zerocopy::{FromBytes, IntoBytes};

/// A message-oriented async byte pipe: read/write whole frames, one per call.
///
/// Implemented by every concrete point-to-point carrier a [`Link`] (or the
/// driver's local host device) can sit on — a kernel TUN/TAP device, a
/// `UnixDatagram`, a `UdpSocket`, an in-process channel — and by test fakes, so
/// the driver can be exercised without real hardware.
#[async_trait]
pub trait FrameIo: Send + Sync {
    /// Receive one frame from the transport into `buf`, returning its length.
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    /// Write one whole frame to the transport, returning the number of bytes
    /// written.
    async fn send(&self, buf: &[u8]) -> std::io::Result<usize>;
}

#[cfg(feature = "tokio")]
#[async_trait]
impl FrameIo for tokio::net::UnixDatagram {
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        tokio::net::UnixDatagram::recv(self, buf).await
    }
    async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        tokio::net::UnixDatagram::send(self, buf).await
    }
}

#[cfg(feature = "tokio")]
#[async_trait]
impl FrameIo for tokio::net::UdpSocket {
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        tokio::net::UdpSocket::recv(self, buf).await
    }
    async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        tokio::net::UdpSocket::send(self, buf).await
    }
}

/// One frame received off a mesh interface, paired with the physical-layer
/// measurements the carrier observed for it.
///
/// The metrics let the engine bias its egress choice toward the
/// highest-quality interface (see `CentralRouter::handle_frame_with_metrics`).
/// A carrier with no signal information (a wired pipe, an in-process channel)
/// reports [`LinkMetrics::default`]; a radio fills in RSSI/SNR/quality.
pub struct Received<'a> {
    /// The parsed link-layer frame, borrowed from the interface's receive
    /// buffer.  Valid until the next receive on the same interface.
    pub frame: &'a LinkFrame,
    /// Physical-layer measurements for this frame.
    pub metrics: LinkMetrics,
}

/// One mesh interface: it accepts whole link-layer frames addressed to a
/// destination MAC and yields received frames with their physical-layer
/// metrics.
///
/// The driver chooses *which* interface and *which* next-hop MAC (via the
/// routing engine); a `LinkT` decides only *how* to put that frame onto its own
/// medium.  A point-to-point link ignores the destination; a multi-access or
/// self-routing link uses it.
#[async_trait]
pub trait LinkT: Send {
    /// Deliver one frame originating from `origin` to `data.dst` over this
    /// medium.  `data.dst` is a next-hop (or final) node MAC, or
    /// [`Mac::BROADCAST`].  Returns the number of bytes written.
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError>;

    /// Deliver the *same* `(protocol, payload)` to each destination in `dsts`.
    ///
    /// A link with a native fan-out — one UDP-multicast datagram, one radio
    /// group transmission — overrides this to exploit it.  The default sends
    /// one frame per destination via [`send`](LinkT::send), so simple carriers
    /// need not implement it.
    async fn send_all(
        &mut self,
        origin: Mac,
        dsts: &[Mac],
        protocol: u16,
        payload: &[u8],
    ) -> Result<(), LinkError> {
        for &dst in dsts {
            self.send(
                origin,
                &LinkFrameData {
                    dst,
                    protocol,
                    payload,
                },
            )
            .await?;
        }
        Ok(())
    }

    /// Await the next frame from the interface, with its physical-layer
    /// metrics.  The returned [`Received`] borrows the interface's receive
    /// buffer and is invalidated by the next receive.
    async fn recv(&mut self) -> Result<Received<'_>, LinkError>;

    /// Poll for an already-pending frame without awaiting.
    ///
    /// Returns `None` when nothing is immediately available.  Cancel-safe
    /// carriers (mpsc channels, datagram sockets) do not lose a frame when the
    /// poll comes up empty.  This is the non-blocking primitive the
    /// deterministic test stepping (`Driver::process_pending`) is built on.
    fn try_recv(&mut self) -> Option<Result<Received<'_>, LinkError>>;
}

/// Point-to-point [`LinkT`] adapter over any [`FrameIo`] byte pipe.
///
/// The carrier has exactly one peer, so the destination MAC is irrelevant to
/// delivery: every frame goes to the one peer.  This adapter just frames
/// `[src][dst][protocol][payload]` onto the pipe and parses it back, and so
/// inherits the default [`LinkT::send_all`] (a loop over [`send`](LinkT::send))
/// — there is no fan-out to exploit on a single peer.
///
/// [`send`]: LinkT::send
pub struct Link<Io: FrameIo> {
    socket: Io,
    buffer: [u8; 1500],
}

impl<Io: FrameIo> Link<Io> {
    /// Wrap any message-oriented async byte pipe as a point-to-point mesh
    /// interface.
    pub fn new(socket: Io) -> Self {
        Self {
            socket,
            buffer: [0u8; 1500],
        }
    }

    /// Serialize `origin` + `data` into `self.buffer`, returning the framed
    /// length.  Wire layout: `[src: Mac][dst: Mac][protocol: u16
    /// native-endian][payload]`.
    fn frame_into_buffer(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> usize {
        let mut idx = 0;
        self.buffer[0..size_of::<Mac>()].copy_from_slice(origin.as_bytes());
        idx += size_of::<Mac>();

        self.buffer[idx..(idx + size_of::<Mac>())].copy_from_slice(data.dst.as_bytes());
        idx += size_of::<Mac>();

        // Protocol is stored and compared native-endian throughout (matching
        // `LinkFrame`'s zerocopy reads and the engine's EtherType constants),
        // so write the native bytes — not big-endian.
        self.buffer[idx..(idx + size_of::<u16>())].copy_from_slice(data.protocol.as_bytes());
        idx += size_of::<u16>();

        self.buffer[idx..(idx + data.payload.len())].copy_from_slice(data.payload);
        idx += data.payload.len();
        idx
    }
}

#[async_trait]
impl<Io: FrameIo> LinkT for Link<Io> {
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        let idx = self.frame_into_buffer(origin, data);
        self.socket.send(&self.buffer[..idx]).await.map_err(|e| {
            tracing::error!("Error sending to socket: {:?}", e);
            LinkError::Io
        })?;
        Ok(idx)
    }

    async fn recv(&mut self) -> Result<Received<'_>, LinkError> {
        // The socket is message-oriented (a datagram per frame), so a single
        // recv yields exactly one whole frame — no buffering or reassembly.
        let n = self.socket.recv(&mut self.buffer).await.map_err(|e| {
            tracing::error!("Error reading from socket: {:?}", e);
            LinkError::Io
        })?;
        let frame = LinkFrame::ref_from_bytes(&self.buffer[..n]).map_err(|_| LinkError::Io)?;
        // A bare byte pipe carries no signal information.
        Ok(Received {
            frame,
            metrics: LinkMetrics::default(),
        })
    }

    #[cfg(feature = "tokio")]
    fn try_recv(&mut self) -> Option<Result<Received<'_>, LinkError>> {
        use futures::FutureExt;
        let n = match self.socket.recv(&mut self.buffer).now_or_never()? {
            Ok(n) => n,
            Err(e) => {
                tracing::error!("Error reading from socket: {:?}", e);
                return Some(Err(LinkError::Io));
            }
        };
        Some(
            LinkFrame::ref_from_bytes(&self.buffer[..n])
                .map_err(|_| LinkError::Io)
                .map(|frame| Received {
                    frame,
                    metrics: LinkMetrics::default(),
                }),
        )
    }

    #[cfg(not(feature = "tokio"))]
    fn try_recv(&mut self) -> Option<Result<Received<'_>, LinkError>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// In-memory [`FrameIo`]: `recv` drains a preloaded inbound queue (and
    /// parks forever once empty, so `now_or_never` reports "nothing pending"),
    /// while `send` records every datagram into a shared buffer.  `sent` is an
    /// `Arc` so a test can keep a handle to inspect outbound frames after the
    /// `FakeIo` has been moved into a `Link`.
    #[derive(Default, Clone)]
    struct FakeIo {
        inbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    #[async_trait]
    impl FrameIo for FakeIo {
        async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            loop {
                if let Some(frame) = self.inbound.lock().unwrap().pop_front() {
                    buf[..frame.len()].copy_from_slice(&frame);
                    return Ok(frame.len());
                }
                // Nothing queued: park so `now_or_never` resolves to `None`.
                std::future::pending::<()>().await;
            }
        }
        async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
            self.sent.lock().unwrap().push(buf.to_vec());
            Ok(buf.len())
        }
    }

    /// The blanket [`Link`] adapter frames a [`LinkFrameData`] onto the pipe so
    /// it parses back as the same `[src][dst][protocol][payload]` frame.
    #[tokio::test]
    async fn link_send_round_trips_a_frame() {
        let io = FakeIo::default();
        let sent = io.sent.clone();
        let mut link = Link::new(io);

        let payload = [0xde, 0xad, 0xbe, 0xef];
        link.send(
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0x4305,
                payload: &payload,
            },
        )
        .await
        .unwrap();

        let datagrams = sent.lock().unwrap();
        assert_eq!(datagrams.len(), 1);
        let frame = LinkFrame::ref_from_bytes(&datagrams[0]).unwrap();
        assert_eq!(frame.src, mac(1));
        assert_eq!(frame.dst, mac(2));
        assert_eq!({ frame.protocol }, 0x4305);
        assert_eq!(&frame.payload, &payload);
    }

    /// `recv` on the blanket adapter yields the parsed frame and — because a
    /// bare byte pipe carries no signal information — default metrics.
    #[tokio::test]
    async fn link_recv_yields_frame_with_default_metrics() {
        let io = FakeIo::default();
        // Preload one frame: src=3, dst=4, proto=0x4305, payload=[1,2,3].
        let mut raw = Vec::new();
        raw.extend_from_slice(mac(3).as_bytes());
        raw.extend_from_slice(mac(4).as_bytes());
        raw.extend_from_slice(&0x4305u16.to_ne_bytes());
        raw.extend_from_slice(&[1, 2, 3]);
        io.inbound.lock().unwrap().push_back(raw);

        let mut link = Link::new(io);
        let received = link.recv().await.unwrap();
        assert_eq!(received.frame.src, mac(3));
        assert_eq!(received.frame.dst, mac(4));
        assert_eq!(&received.frame.payload, &[1, 2, 3]);
        assert_eq!(received.metrics, LinkMetrics::default());
    }

    /// The default `send_all` fans a single payload out to each destination by
    /// looping `send` — one datagram per destination, in order.
    #[tokio::test]
    async fn default_send_all_loops_send_per_destination() {
        let io = FakeIo::default();
        let sent = io.sent.clone();
        let mut link = Link::new(io);

        let dsts = [mac(10), mac(11), mac(12)];
        link.send_all(mac(1), &dsts, 0x4305, &[0x42]).await.unwrap();

        let datagrams = sent.lock().unwrap();
        assert_eq!(datagrams.len(), 3);
        for (datagram, expected_dst) in datagrams.iter().zip(dsts) {
            let frame = LinkFrame::ref_from_bytes(datagram).unwrap();
            assert_eq!(frame.dst, expected_dst);
            assert_eq!(&frame.payload, &[0x42]);
        }
    }

    /// A `LinkT` with a native bulk path, proving an implementer can override
    /// `send_all` to send once instead of N times.
    #[derive(Default)]
    struct BulkLink {
        /// Number of times the bulk `send_all` path ran.
        bulk_calls: usize,
        /// Number of individual `send` calls.
        unit_sends: usize,
        /// Metrics to report from the next `recv`.
        next_metrics: LinkMetrics,
        last_frame: Vec<u8>,
    }

    #[async_trait]
    impl LinkT for BulkLink {
        async fn send(
            &mut self,
            _origin: Mac,
            _data: &LinkFrameData<'_>,
        ) -> Result<usize, LinkError> {
            self.unit_sends += 1;
            Ok(0)
        }

        async fn send_all(
            &mut self,
            _origin: Mac,
            _dsts: &[Mac],
            _protocol: u16,
            _payload: &[u8],
        ) -> Result<(), LinkError> {
            // One medium operation regardless of how many destinations.
            self.bulk_calls += 1;
            Ok(())
        }

        async fn recv(&mut self) -> Result<Received<'_>, LinkError> {
            self.last_frame = {
                let mut raw = Vec::new();
                raw.extend_from_slice(mac(7).as_bytes());
                raw.extend_from_slice(mac(8).as_bytes());
                raw.extend_from_slice(&0x4305u16.to_ne_bytes());
                raw
            };
            let frame = LinkFrame::ref_from_bytes(&self.last_frame).map_err(|_| LinkError::Io)?;
            Ok(Received {
                frame,
                metrics: self.next_metrics,
            })
        }

        fn try_recv(&mut self) -> Option<Result<Received<'_>, LinkError>> {
            None
        }
    }

    /// An overriding implementer takes its single bulk path and never falls
    /// back to per-destination `send`.
    #[tokio::test]
    async fn overridden_send_all_uses_bulk_path() {
        let mut link = BulkLink::default();
        link.send_all(mac(1), &[mac(2), mac(3), mac(4)], 0x4305, &[0])
            .await
            .unwrap();
        assert_eq!(link.bulk_calls, 1);
        assert_eq!(link.unit_sends, 0);
    }

    /// A radio-style link surfaces its per-frame physical metrics through
    /// `recv`, so the driver can fold them into the engine.
    #[tokio::test]
    async fn recv_surfaces_link_metrics() {
        let mut link = BulkLink {
            next_metrics: LinkMetrics {
                rssi_dbm: Some(-72),
                snr_db: Some(9),
                quality: Some(200),
            },
            ..Default::default()
        };
        let received = link.recv().await.unwrap();
        assert_eq!(received.metrics.rssi_dbm, Some(-72));
        assert_eq!(received.metrics.snr_db, Some(9));
        assert_eq!(received.metrics.quality, Some(200));
    }
}
