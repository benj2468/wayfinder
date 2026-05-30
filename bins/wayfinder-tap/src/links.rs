//! Link-layer abstractions: the host-facing TAP device behind a testable trait,
//! and the in-process [`Link`] each mesh interface is built on.
//!
//! Each mesh interface is a [`Link`] over an in-process duplex (the link-transport
//! tasks bridge the real socket to it), so interfaces need no abstraction to be
//! testable.  Only the local TAP device touches the kernel, so we hide it behind
//! a trait that a fake can implement in unit tests.

use pretty_hex::pretty_hex;
use tokio::net::UnixDatagram;
use wayfinder::interfaces::{
    frame::{LinkFrame, LinkFrameData, MeshIdentifier},
    link::LinkError,
};
use zerocopy::{FromBytes, IntoBytes};

/// The local end of the host network: read/write whole link-layer frames.
/// Abstracted so the event loop can be driven against a fake in tests instead
/// of a real kernel TUN/TAP device.
pub(crate) trait AsyncIo {
    /// Receive one frame from the device into `buf`, returning its length.
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    /// Write one frame to the device.
    async fn send(&self, buf: &[u8]) -> std::io::Result<usize>;
}

impl AsyncIo for tun_rs::AsyncDevice {
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        tun_rs::AsyncDevice::recv(self, buf).await
    }
    async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        tun_rs::AsyncDevice::send(self, buf).await
    }
}

/// One mesh interface: a message-oriented Unix datagram socket carrying one
/// whole link-layer frame per datagram.
pub struct Link {
    socket: UnixDatagram,
    buffer: [u8; 1500],
}

impl Link {
    /// Wrap a datagram socket as a mesh interface.
    pub fn new(socket: UnixDatagram) -> Self {
        Self {
            socket,
            buffer: [0u8; 1500],
        }
    }

    /// Receive one whole link-layer frame from the interface.
    pub async fn receive<Ident: MeshIdentifier + 'static>(
        &mut self,
    ) -> Result<&LinkFrame<Ident>, LinkError> {
        // The socket is message-oriented (a datagram per frame), so a single
        // recv yields exactly one whole frame — no buffering or reassembly.
        let n = self.socket.recv(&mut self.buffer).await.map_err(|e| {
            tracing::error!("Error reading from socket: {:?}", e);
            LinkError::Io
        })?;
        LinkFrame::ref_from_bytes(&self.buffer[..n]).map_err(|_| LinkError::Io)
    }

    /// Serialize and transmit a frame originating from `origin_ident`.
    pub async fn send<Ident: MeshIdentifier + 'static>(
        &mut self,
        origin_ident: Ident,
        data: &LinkFrameData<'_, Ident>,
    ) -> Result<usize, LinkError> {
        let mut idx = 0;
        self.buffer[0..size_of::<Ident>()].copy_from_slice(origin_ident.as_bytes());
        idx += size_of::<Ident>();

        self.buffer[idx..(idx + size_of::<Ident>())].copy_from_slice(data.dst.as_bytes());
        idx += size_of::<Ident>();

        // Protocol is stored and compared native-endian throughout (matching
        // `LinkFrame`'s zerocopy reads and the engine's EtherType constants),
        // so write the native bytes — not big-endian.
        self.buffer[idx..(idx + size_of::<u16>())].copy_from_slice(data.protocol.as_bytes());
        idx += size_of::<u16>();

        self.buffer[idx..(idx + data.payload.len())].copy_from_slice(data.payload);
        idx += data.payload.len();

        tracing::trace!("Publishing from {:?} to {:?}", origin_ident, data.dst);
        tracing::trace!("{}", pretty_hex(&&self.buffer[..idx]));

        self.socket.send(&self.buffer[..idx]).await.map_err(|e| {
            tracing::error!("Error sending to socket: {:?}", e);
            LinkError::Io
        })?;

        Ok(idx)
    }
}
