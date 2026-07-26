//! Helpers for building concrete `tokio::net` mesh links.

use std::net::SocketAddr;

use tokio::net::UdpSocket;
use tokio::net::UnixDatagram;
use tokio::task::JoinSet;

use wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN;
use wayfinder::link::DynLinkT;

use crate::transport::Link;

/// Build a mesh link carried over UDP, type-erased as a [`LinkT`].
///
/// UDP point-to-point is a plain byte pipe, so it gets its [`LinkT`] behaviour
/// from the [`Link`] adapter.  The router speaks to an in-process
/// [`UnixDatagram`] (a clean message-oriented carrier); a spawned task bridges
/// that to the real UDP socket bound to `bind_addr` and connected to
/// `remote_addr`.  The bridge task is spawned into `join_set` so its lifetime
/// is tied to the caller's.
pub async fn build_udp_link(
    bind_addr: SocketAddr,
    remote_addr: SocketAddr,
    join_set: &mut JoinSet<anyhow::Result<()>>,
) -> anyhow::Result<Box<DynLinkT<'static>>> {
    let udp_socket = UdpSocket::bind(bind_addr).await?;
    udp_socket.connect(remote_addr).await?;

    let (bridge, router_side) = UnixDatagram::pair()?;

    join_set.spawn(async move {
        let mut rx_buf = [0u8; MAX_LINK_FRAME_LEN];
        let mut tx_buf = [0u8; MAX_LINK_FRAME_LEN];
        loop {
            tokio::select! {
                Ok(bytes) = udp_socket.recv(&mut rx_buf) => {
                    if let Err(e) = bridge.send(&rx_buf[..bytes]).await {
                        tracing::warn!(error = ?e, "udp bridge to in-process socket failed");
                    }
                },
                Ok(bytes) = bridge.recv(&mut tx_buf) => {
                    if let Err(e) = udp_socket.send(&tx_buf[..bytes]).await {
                        tracing::warn!(error = ?e, "udp bridge to off-process socket failed");
                    }
                },
            }
        }
    });

    Ok(DynLinkT::new_box(Link::new(router_side)))
}
