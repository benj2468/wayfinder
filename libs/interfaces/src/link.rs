use crate::frame::{LinkFrameData, MeshIdentifier};
use embedded_io_async::{Read, Write};
use thiserror::Error;

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
    async fn transmit(&mut self, data: LinkFrameData<'_, Ident>) -> Result<(), LinkError>;

    /// Async blocking check to receive a frame from the radio.
    /// Returns Ok(size) if a packet arrived.
    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize, LinkError>;
}

pub struct IdentifiableLink<Ident: MeshIdentifier, T> {
    pub identifier: Ident,
    pub stream: T,
}

impl<Ident: MeshIdentifier, T> IdentifiableLink<Ident, T>
where
    T: Read + Write,
{
    pub fn new(identifier: Ident, stream: T) -> Self {
        Self { identifier, stream }
    }
}

impl<T, Ident: MeshIdentifier> EmbeddedMeshLink<Ident> for IdentifiableLink<Ident, T>
where
    T: Read + Write,
{
    fn identifier(&self) -> Ident {
        self.identifier
    }

    async fn transmit(&mut self, data: LinkFrameData<'_, Ident>) -> Result<(), LinkError> {
        self.stream
            .write_all(self.identifier.as_bytes())
            .await
            .map_err(|_| LinkError::Io)?;
        self.stream
            .write_all(data.dst.as_bytes())
            .await
            .map_err(|_| LinkError::Io)?;
        self.stream
            .write_all(&data.protocol.to_be_bytes())
            .await
            .map_err(|_| LinkError::Io)?;
        self.stream
            .write_all(data.payload)
            .await
            .map_err(|_| LinkError::Io)?;
        Ok(())
    }

    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize, LinkError> {
        // This is a naive implementation that just reads what's available.
        // For real framing, we might need a length prefix or similar.
        // But since the original LinkCodec just returned everything, we'll do the same for now,
        // or try to read a full LinkFrame header + payload if possible.

        // HOWEVER, without a length prefix, we don't know how much to read.
        // The original used `tokio_util::codec::Framed`, which for the provided `LinkCodec`
        // would just return whatever was in the internal buffer of `Framed`.

        let n = self.stream.read(buf).await.map_err(|_| LinkError::Io)?;
        Ok(n)
    }
}
