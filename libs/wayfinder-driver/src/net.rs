//! Helpers for building concrete `tokio::net` mesh links.

use std::net::SocketAddr;

use tokio::{net::UdpSocket, net::UnixDatagram, task::JoinSet};

use crate::transport::Link;

/// Build a mesh [`Link`] carried over UDP.
///
/// The router speaks to an in-process [`UnixDatagram`] (so the [`Link`] is a
/// clean message-oriented carrier); a spawned task bridges that to the real UDP
/// socket bound to `bind_addr` and connected to `remote_addr`.  The bridge task
/// is spawned into `join_set` so its lifetime is tied to the caller's.
pub async fn build_udp_link(
    bind_addr: SocketAddr,
    remote_addr: SocketAddr,
    join_set: &mut JoinSet<anyhow::Result<()>>,
) -> anyhow::Result<Link> {
    let udp_socket = UdpSocket::bind(bind_addr).await?;
    udp_socket.connect(remote_addr).await?;

    let (bridge, router_side) = UnixDatagram::pair()?;

    join_set.spawn(async move {
        let mut rx_buf = [0u8; 1500];
        let mut tx_buf = [0u8; 1500];
        loop {
            tokio::select! {
                Ok(bytes) = udp_socket.recv(&mut rx_buf) => {
                    if let Err(e) = bridge.send(&rx_buf[..bytes]).await {
                        tracing::error!("Error bridging to in-process socket: {:?}", e);
                    }
                },
                Ok(bytes) = bridge.recv(&mut tx_buf) => {
                    if let Err(e) = udp_socket.send(&tx_buf[..bytes]).await {
                        tracing::error!("Error bridging to off-process socket: {:?}", e);
                    }
                },
            }
        }
    });

    Ok(Link::new(router_side))
}
