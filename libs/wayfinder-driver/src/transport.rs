//! Frame transports: the [`FrameIo`] trait every carrier is hidden behind, and
//! the [`Link`] adapter that turns one into a mesh interface.
//!
//! A transport is message-oriented: one `recv`/`send` moves exactly one whole
//! link-layer (or host) frame.  Both the local host device (a TUN/TAP) and each
//! mesh interface (a `UnixDatagram`, `UdpSocket`, an in-process channel, …) are
//! the same shape, so one trait serves both roles and a single `Vec<Link>` can
//! mix carriers of different concrete types.

use async_trait::async_trait;

use wayfinder::interfaces::{
    frame::{LinkFrame, LinkFrameData, Mac},
    link::LinkError,
};
use zerocopy::{FromBytes, IntoBytes};

/// A message-oriented async transport: read/write whole frames, one per call.
///
/// Implemented by every concrete carrier a [`Link`] (or the driver's local
/// host device) can sit on — a kernel TUN/TAP device, a `UnixDatagram`, a
/// `UdpSocket`, an in-process channel — and by test fakes, so the driver can be
/// exercised without real hardware.
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

/// One mesh interface: a message-oriented transport carrying one whole
/// link-layer frame per datagram.  The transport is type-erased behind
/// [`FrameIo`], so a single `Vec<Link>` can mix carriers of different concrete
/// types.
pub struct Link {
    socket: Box<dyn FrameIo>,
    buffer: [u8; 1500],
}

impl Link {
    /// Wrap any message-oriented async transport as a mesh interface.
    pub fn new<Io: FrameIo + 'static>(socket: Io) -> Self {
        Self {
            socket: Box::new(socket),
            buffer: [0u8; 1500],
        }
    }

    /// Receive one whole link-layer frame from the interface, awaiting until
    /// one arrives.
    pub async fn receive(&mut self) -> Result<&LinkFrame, LinkError> {
        // The socket is message-oriented (a datagram per frame), so a single
        // recv yields exactly one whole frame — no buffering or reassembly.
        let n = self.socket.recv(&mut self.buffer).await.map_err(|e| {
            tracing::error!("Error reading from socket: {:?}", e);
            LinkError::Io
        })?;
        LinkFrame::ref_from_bytes(&self.buffer[..n]).map_err(|_| LinkError::Io)
    }

    /// Poll the interface for an already-pending frame without awaiting.
    ///
    /// Returns `None` when nothing is immediately available, `Some(Ok(bytes))`
    /// with the raw frame otherwise.  The bytes are copied out (rather than
    /// borrowed) so the caller can process them while mutating the interface
    /// set — this is the non-blocking primitive the deterministic test stepping
    /// is built on.  Cancel-safe transports (mpsc channels, datagram sockets)
    /// do not lose a frame when the poll comes up empty.
    #[cfg(feature = "tokio")]
    pub fn try_recv_raw(&mut self) -> Option<Result<Vec<u8>, LinkError>> {
        use futures::FutureExt;
        match self.socket.recv(&mut self.buffer).now_or_never()? {
            Ok(n) => Some(Ok(self.buffer[..n].to_vec())),
            Err(e) => {
                tracing::error!("Error reading from socket: {:?}", e);
                Some(Err(LinkError::Io))
            }
        }
    }

    /// Serialize and transmit a frame originating from `origin_ident`.
    ///
    /// Wire layout: `[src: Mac][dst: Mac][protocol: u16 native-endian][payload]`.
    pub async fn send(
        &mut self,
        origin_ident: Mac,
        data: &LinkFrameData<'_>,
    ) -> Result<usize, LinkError> {
        let mut idx = 0;
        self.buffer[0..size_of::<Mac>()].copy_from_slice(origin_ident.as_bytes());
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

        self.socket.send(&self.buffer[..idx]).await.map_err(|e| {
            tracing::error!("Error sending to socket: {:?}", e);
            LinkError::Io
        })?;

        Ok(idx)
    }
}
