//! Helpers for building concrete `tokio::net` mesh links.

use std::collections::HashMap;
use std::net::SocketAddr;

use tokio::net::UdpSocket;
use tokio::net::UnixDatagram;
use tokio::task::JoinSet;

use wayfinder::interfaces::frame::LinkFrame;
use wayfinder::interfaces::frame::LinkFrameData;
use wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN;
use wayfinder::interfaces::frame::Mac;
use wayfinder::interfaces::link::LinkError;
use wayfinder::interfaces::link::LinkMetrics;
use wayfinder::link::DynLinkT;
use wayfinder::link::LinkT;
use wayfinder::link::Received;
use zerocopy::FromBytes;

use crate::raw::interface_index;
use crate::transport::Link;
use interfaces::wire::frame_into_buf;

/// Learned mapping of neighbor MAC to UDP transport address for
/// [`UdpMultiLink`], refreshed from the sender address of every received
/// datagram (see [`resolve_target`]).  A neighbor's address is only ever
/// learned this way — there is no static peer list — so a destination is
/// reachable by unicast only after at least one frame (in practice, an OGM)
/// has been heard from it.
#[derive(Default)]
struct UdpPeerTable {
    peers: HashMap<Mac, SocketAddr>,
}

impl UdpPeerTable {
    /// Record (or refresh, if the peer's address changed) the transport
    /// address a frame from `mac` was most recently observed at.
    fn learn(&mut self, mac: Mac, addr: SocketAddr) {
        self.peers.insert(mac, addr);
    }

    /// The most recently learned transport address for `mac`, if any.
    fn resolve(&self, mac: Mac) -> Option<SocketAddr> {
        self.peers.get(&mac).copied()
    }
}

/// Where a frame addressed to `dst` should be sent: the shared
/// `discovery_addr` (a v4 broadcast or v6 multicast group) for any
/// multicast/broadcast destination, regardless of what's been learned, or a
/// specific peer's last-known unicast address once [`UdpPeerTable`] has
/// learned it.  `None` means `dst` hasn't been heard from yet, so there is
/// nowhere to send a unicast frame — the caller drops it rather than
/// guessing.
fn resolve_target(
    dst: Mac,
    discovery_addr: SocketAddr,
    peers: &UdpPeerTable,
) -> Option<SocketAddr> {
    if dst.is_multicast() {
        Some(discovery_addr)
    } else {
        peers.resolve(dst)
    }
}

/// A native multi-access UDP mesh interface: an unconnected socket that
/// reaches every peer on a shared IP network without a static peer list, the
/// UDP analog of [`RawL2Link`](crate::RawL2Link) — except unlike raw L2, UDP
/// addressing isn't the mesh MAC, so this link (unlike `RawL2Link`) has to
/// learn each neighbor's transport address for itself, in [`UdpPeerTable`].
/// [`send`](LinkT::send) reaches [`Mac::BROADCAST`]/multicast via
/// `discovery_addr`; any other destination via its most recently learned
/// address, dropping the frame if none is known yet. [`recv`](LinkT::recv)
/// refreshes the table from every datagram's sender address. Construct with
/// [`build_udp_multi_link`].
pub struct UdpMultiLink {
    /// The unconnected socket: `send_to`/`recv_from`, never `connect`ed to a
    /// single peer.
    socket: UdpSocket,
    /// Where a [`Mac::BROADCAST`]/multicast-destined frame is sent: an IPv4
    /// broadcast address, or an IPv6 multicast group this socket has joined.
    discovery_addr: SocketAddr,
    /// Learned neighbor transport addresses, refreshed on every `recv`.
    peers: UdpPeerTable,
    /// Scratch buffer for the most recently sent or received frame, sized to
    /// [`MAX_LINK_FRAME_LEN`] like every other data-path buffer.
    wire_buf: [u8; MAX_LINK_FRAME_LEN],
}

impl LinkT for UdpMultiLink {
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        let Some(target) = resolve_target(data.dst, self.discovery_addr, &self.peers) else {
            // Not reachable by arbitrary remote input: this fires only when
            // *this* node tries to address a peer it has never heard an OGM
            // from, i.e. before the engine would ever have learned a route to
            // it. Metadata only, no payload.
            tracing::trace!(dst = ?data.dst, "drop: no known udp address for destination");
            return Ok(0);
        };
        // No wire-vs-mesh protocol split (unlike raw L2's `RawL2Link`): a UDP
        // port is already the demux, so the EtherType-shaped field written is
        // `data.protocol` itself.
        let Some(n) = frame_into_buf(origin, data.protocol, data, &mut self.wire_buf) else {
            tracing::trace!(
                payload_len = data.payload.len(),
                "drop: frame exceeds udp-multi wire buffer"
            );
            return Ok(0);
        };
        self.socket
            .send_to(&self.wire_buf[..n], target)
            .await
            .map_err(|e| {
                tracing::warn!(error = ?e, "udp-multi send failed");
                LinkError::Io
            })?;
        Ok(n)
    }

    async fn recv(&mut self) -> Result<Received<'_>, LinkError> {
        let (n, peer_addr) = self
            .socket
            .recv_from(&mut self.wire_buf)
            .await
            .map_err(|e| {
                tracing::warn!(error = ?e, "udp-multi recv failed");
                LinkError::Io
            })?;
        let frame = LinkFrame::ref_from_bytes(&self.wire_buf[..n]).map_err(|_| LinkError::Io)?;
        self.peers.learn(frame.src, peer_addr);
        // A UDP datagram carries no physical-layer signal information.
        Ok(Received {
            frame,
            metrics: LinkMetrics::default(),
        })
    }
}

/// Build a native multi-access UDP mesh link, type-erased as a [`LinkT`].
///
/// Binds an unconnected socket to `bind_addr`. `discovery_addr` is where a
/// broadcast/multicast frame goes: for an IPv4 address, the socket enables
/// `SO_BROADCAST` and sends there directly (e.g. a subnet or limited
/// broadcast address); for an IPv6 multicast address, the socket joins that
/// group on `multicast_interface` (required in that case — IPv6 multicast is
/// scoped to an interface, unlike IPv4 broadcast). Any other destination is
/// reached once [`UdpMultiLink::recv`](LinkT::recv) has learned its address
/// from a received frame — in practice, from the periodic OGM every mesh node
/// broadcasts, so there is nothing to statically configure per peer.
pub async fn build_udp_multi_link(
    bind_addr: SocketAddr,
    discovery_addr: SocketAddr,
    multicast_interface: Option<&str>,
) -> anyhow::Result<Box<DynLinkT<'static>>> {
    let socket = UdpSocket::bind(bind_addr).await?;

    match discovery_addr {
        SocketAddr::V4(_) => socket.set_broadcast(true)?,
        SocketAddr::V6(v6) if v6.ip().is_multicast() => {
            let interface = multicast_interface.ok_or_else(|| {
                anyhow::anyhow!(
                    "multicast_interface is required when discovery_addr is an IPv6 multicast address"
                )
            })?;
            socket.join_multicast_v6(v6.ip(), interface_index(interface)?)?;
        }
        SocketAddr::V6(_) => anyhow::bail!(
            "IPv6 discovery_addr must be a multicast address: IPv6 has no broadcast equivalent"
        ),
    }

    Ok(DynLinkT::new_box(UdpMultiLink {
        socket,
        discovery_addr,
        peers: UdpPeerTable::default(),
        wire_buf: [0u8; MAX_LINK_FRAME_LEN],
    }))
}

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

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    const DISCOVERY: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST), 9999);

    // ── UdpPeerTable ─────────────────────────────────────────────────────────

    #[test]
    fn peer_table_starts_with_nothing_learned() {
        let table = UdpPeerTable::default();
        assert_eq!(table.resolve(mac(1)), None);
    }

    #[test]
    fn peer_table_resolves_a_learned_peer() {
        let mut table = UdpPeerTable::default();
        table.learn(mac(1), addr(4001));
        assert_eq!(table.resolve(mac(1)), Some(addr(4001)));
    }

    #[test]
    fn peer_table_is_unaffected_by_other_macs() {
        let mut table = UdpPeerTable::default();
        table.learn(mac(1), addr(4001));
        assert_eq!(table.resolve(mac(2)), None);
    }

    /// A peer's address can change (DHCP lease renewal, roaming) — the table
    /// tracks only the most recently observed address per MAC, not history.
    #[test]
    fn peer_table_learn_again_overwrites_the_previous_address() {
        let mut table = UdpPeerTable::default();
        table.learn(mac(1), addr(4001));
        table.learn(mac(1), addr(4002));
        assert_eq!(table.resolve(mac(1)), Some(addr(4002)));
    }

    // ── resolve_target ───────────────────────────────────────────────────────

    #[test]
    fn broadcast_destination_resolves_to_discovery_addr_even_if_never_learned() {
        let table = UdpPeerTable::default();
        assert_eq!(
            resolve_target(Mac::BROADCAST, DISCOVERY, &table),
            Some(DISCOVERY)
        );
    }

    /// Any group address (not just the all-ones broadcast) goes to the shared
    /// discovery address — mirrors [`Mac::is_multicast`], not just `==
    /// Mac::BROADCAST`.
    #[test]
    fn multicast_destination_resolves_to_discovery_addr() {
        let table = UdpPeerTable::default();
        let group = Mac([0x01, 0x00, 0x5e, 0, 0, 1]);
        assert!(group.is_multicast());
        assert_eq!(resolve_target(group, DISCOVERY, &table), Some(DISCOVERY));
    }

    #[test]
    fn unicast_destination_not_yet_learned_resolves_to_nothing() {
        let table = UdpPeerTable::default();
        assert_eq!(resolve_target(mac(7), DISCOVERY, &table), None);
    }

    #[test]
    fn unicast_destination_resolves_to_its_learned_address_not_discovery_addr() {
        let mut table = UdpPeerTable::default();
        table.learn(mac(7), addr(4007));
        assert_eq!(resolve_target(mac(7), DISCOVERY, &table), Some(addr(4007)));
    }
}
