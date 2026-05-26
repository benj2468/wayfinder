pub use crate::frame::{LinkCodec, LinkFrameData, MeshIdentifier};
use async_trait::async_trait;
use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

#[derive(Error, Debug)]
pub enum LinkError {
    #[error(transparent)]
    Io(#[from] tokio::io::Error),
    #[error("transmit failed")]
    TransmitFailed,
    #[error("receive failed")]
    ReceiveFailed,
    #[error("buffer full")]
    BufferFull,
    #[error("invalid packet")]
    InvalidPacket,
}

#[async_trait]
pub trait EmbeddedMeshLink<Ident: MeshIdentifier>: Send {
    /// The identifier of the destination node.
    fn identifier(&self) -> Ident;

    /// Sends a raw frame out over the physical medium.
    /// If destination identifier is Broadcast, then the radio should broadcast it
    async fn transmit(&mut self, data: LinkFrameData<'_, Ident>) -> Result<(), LinkError>;

    /// Async blocking check to receive a frame from the radio.
    /// Returns Ok(Some(bytes)) if a packet arrived.
    async fn receive(&mut self) -> Result<Option<BytesMut>, LinkError>;
}

pub struct IdentifiableLink<Ident: MeshIdentifier, T> {
    pub identifier: Ident,
    pub framed: Framed<T, LinkCodec<Ident>>,
}

impl<Ident: MeshIdentifier, T> IdentifiableLink<Ident, T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(identifier: Ident, link: T) -> Self {
        Self {
            identifier,
            framed: Framed::new(link, LinkCodec::new(identifier)),
        }
    }
}

#[async_trait]
impl<T, Ident: MeshIdentifier + Send> EmbeddedMeshLink<Ident> for IdentifiableLink<Ident, T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn identifier(&self) -> Ident {
        self.identifier
    }

    async fn transmit(&mut self, data: LinkFrameData<'_, Ident>) -> Result<(), LinkError> {
        self.framed.send(data).await.map_err(LinkError::Io)
    }

    async fn receive(&mut self) -> Result<Option<BytesMut>, LinkError> {
        match self.framed.next().await {
            Some(Ok(bytes)) => Ok(Some(bytes)),
            Some(Err(e)) => Err(LinkError::Io(e)),
            None => Ok(None),
        }
    }
}
