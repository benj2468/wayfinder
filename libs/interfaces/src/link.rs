use crate::frame::{LinkFrame, LinkFrameData, MeshIdentifier};
use embedded_io_async::{Read, Write};
use thiserror::Error;
use zerocopy::{FromBytes, IntoBytes};

#[derive(Error, Debug)]
pub enum LinkError {
    #[error("IO error")]
    Io,
    #[error("transmit failed")]
    TransmitFailed,
    #[error("receive failed")]
    ReceiveFailed,
    #[error("buffer full")]
    BufferFull,
    #[error("invalid packet")]
    InvalidPacket,
}

pub trait EmbeddedMeshLink<Ident: MeshIdentifier> {
    /// The identifier of the destination node.
    fn identifier(&self) -> Ident;

    /// Sends a raw frame out over the physical medium.
    /// If destination identifier is Broadcast, then the radio should broadcast it
    fn transmit(
        &mut self,
        data: LinkFrameData<'_, Ident>,
    ) -> impl Future<Output = Result<(), LinkError>>;

    /// Async blocking check to receive a frame from the radio.
    /// Returns Ok(size) if a packet arrived.
    fn receive(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<usize, LinkError>>;
}

pub struct IdentifiableLink<Ident: MeshIdentifier, T> {
    identifier: Ident,
    stream: T,
    buffer: [u8; 1500],
    read_offset: usize,
}

impl<Ident: MeshIdentifier, T> IdentifiableLink<Ident, T>
where
    T: Read + Write,
{
    pub fn new(identifier: Ident, stream: T) -> Self {
        Self {
            identifier,
            stream,
            buffer: [0u8; 1500],
            read_offset: 0,
        }
    }

    pub async fn receive(&mut self) -> Result<&LinkFrame<Ident>, LinkError> {
        let buf = &mut self.buffer;
        loop {
            let read = self
                .stream
                .read(&mut buf[self.read_offset..])
                .await
                .map_err(|_| LinkError::Io)?;

            self.read_offset += read;

            if etherparse::Ethernet2Slice::from_slice_without_fcs(&buf[..self.read_offset]).is_ok()
            {
                return LinkFrame::ref_from_bytes(&buf[..self.read_offset])
                    .map_err(|_| LinkError::Io);
            }
        }
    }

    pub async fn send(&mut self, data: &LinkFrameData<'_, Ident>) -> Result<usize, LinkError> {
        let mut idx = 0;
        self.buffer[0..size_of::<Ident>()].copy_from_slice(self.identifier.as_bytes());
        idx += size_of::<Ident>();

        self.buffer[idx..(idx + size_of::<Ident>())].copy_from_slice(data.dst.as_bytes());
        idx += size_of::<Ident>();

        self.buffer[idx..(idx + size_of::<u16>())]
            .copy_from_slice(data.protocol.to_be().as_bytes());
        idx += size_of::<u16>();

        self.buffer[idx..(idx + data.payload.len())].copy_from_slice(data.payload);
        idx += data.payload.len();

        self.stream
            .write_all(&self.buffer[..idx])
            .await
            .map_err(|_| LinkError::Io)?;

        Ok(idx)
    }

    pub fn read(&self, n: usize) -> &[u8] {
        &self.buffer[..n]
    }
}
