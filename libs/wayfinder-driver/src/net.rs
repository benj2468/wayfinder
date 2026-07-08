//! Helpers for building concrete `tokio::net` mesh links.

use std::net::SocketAddr;

use serde::Deserialize;
use tokio::{net::UdpSocket, net::UnixDatagram, task::JoinSet};

use wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN;
use wayfinder::link::DynLinkT;

use crate::registry::{LINK_BUILDERS, LinkBuilder};
use crate::transport::Link;

/// Config `params` for the in-tree `"Udp"` link type — see [`build_udp_link`].
#[derive(Deserialize, schemars::JsonSchema)]
struct UdpLinkParams {
    /// Local address the UDP socket binds to.
    bind_addr: SocketAddr,
    /// Remote peer the socket is connected to (send/recv target).
    remote_addr: SocketAddr,
}

#[linkme::distributed_slice(LINK_BUILDERS)]
static UDP_BUILDER: LinkBuilder = LinkBuilder {
    type_tag: "Udp",
    build: |params, join_set| {
        Box::pin(async move {
            let cfg: UdpLinkParams = serde_json::from_value(params.clone())?;
            build_udp_link(cfg.bind_addr, cfg.remote_addr, join_set).await
        })
    },
    schema: || schemars::schema_for!(UdpLinkParams),
};

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

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact path `wayfinder-tap`'s registry-driven link loop takes: look
    /// up `"Udp"` in `LINK_BUILDERS`, parse a JSON `params` blob (as it would
    /// arrive flattened from YAML via `LinkConfig::params`), and build a real
    /// link from it — proving the closed `match` removed from `main.rs` was
    /// faithfully replaced, not just that the registry compiles.
    #[tokio::test]
    async fn udp_link_type_is_registered_and_builds_a_real_link() {
        let builder = LINK_BUILDERS
            .iter()
            .find(|b| b.type_tag == "Udp")
            .expect("Udp builder registered in this module, above");
        let params = serde_json::json!({
            "bind_addr": "127.0.0.1:0",
            "remote_addr": "127.0.0.1:19999",
        });
        let mut join_set = JoinSet::new();
        let link = (builder.build)(&params, &mut join_set)
            .await
            .expect("Udp builder should build a real link from valid params");
        drop(link);
    }
}
