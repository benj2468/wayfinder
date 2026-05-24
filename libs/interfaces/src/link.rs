use crate::frame::{LinkFrame, LinkFrameData};
use async_trait::async_trait;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(Error, Debug)]
pub enum LinkError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("transmit failed")]
    TransmitFailed,
    #[error("receive failed")]
    ReceiveFailed,
    #[error("buffer full")]
    BufferFull,
    #[error("invalid packet")]
    InvalidPacket,
}

pub trait MeshIdentifier:
    Copy + PartialEq + Eq + FromBytes + IntoBytes + Immutable + Default
{
    const BROADCAST: Self;
}

impl MeshIdentifier for u8 {
    const BROADCAST: Self = 0xff;
}

#[async_trait]
pub trait EmbeddedMeshLink<Ident: MeshIdentifier> {
    /// The identifier of the destination node.
    fn identifier(&self) -> Ident;

    /// Sends a raw frame out over the physical medium.
    /// If destination identifier is Broadcast, then the radio should broadcast it
    async fn transmit(&mut self, data: LinkFrameData<'_, Ident>) -> Result<(), LinkError>;

    /// Async blocking check to receive a frame from the radio.
    /// Returns Ok(Some((source_identifier, bytes_written_to_buf))) if a packet arrived.
    async fn receive<'a>(
        &mut self,
        buffer: &'a mut [u8],
    ) -> Result<Option<&'a LinkFrame<Ident>>, LinkError>;
}

pub struct IdentifiableLink<Ident: MeshIdentifier, T> {
    pub identifier: Ident,
    pub link: T,
}

#[async_trait]
impl<T, Ident: MeshIdentifier + Send> EmbeddedMeshLink<Ident> for IdentifiableLink<Ident, T>
where
    T: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin + Send,
{
    fn identifier(&self) -> Ident {
        self.identifier
    }

    async fn transmit(&mut self, data: LinkFrameData<'_, Ident>) -> Result<(), LinkError> {
        self.link.write_all(&self.identifier.as_bytes()).await?;
        self.link.write_all(&data.dst.as_bytes()).await?;
        self.link.write_all(&data.protocol.to_be_bytes()).await?;
        self.link.write_all(&data.payload).await?;
        self.link.flush().await?;

        Ok(())
    }

    async fn receive<'a>(
        &mut self,
        buffer: &'a mut [u8],
    ) -> Result<Option<&'a LinkFrame<Ident>>, LinkError> {
        let (mut reader, _) = tokio::io::split(&mut self.link);

        let bytes_read = reader
            .read(buffer)
            .await
            .map_err(|_| LinkError::ReceiveFailed)?;

        if bytes_read == 0 {
            return Ok(None);
        }

        let frame = LinkFrame::ref_from_bytes(&buffer[..bytes_read])
            .map_err(|_| LinkError::InvalidPacket)?;

        Ok(Some(frame))
    }
}
