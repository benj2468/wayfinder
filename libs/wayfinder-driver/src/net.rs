//! Helpers for building concrete `tokio::net` mesh links.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;

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

/// Maximum distinct peers [`UdpPeerTable`] tracks at once, evicting the
/// least-recently-heard entry to admit a new one beyond this. A UDP-multi
/// socket accepts datagrams from arbitrary, unauthenticated senders — without
/// a cap, an attacker could grow the table without bound simply by sending
/// datagrams from spoofed source addresses. Comfortably above any real
/// deployment's spoke count while keeping the table's memory footprint (and,
/// once fan-out is in play, the cost of a learned-but-fake entry) trivial.
const MAX_TRACKED_PEERS: usize = 128;

/// How long a learned peer stays eligible for unicast resolution or broadcast
/// fan-out after it was last heard from. Bounds how long a single forged
/// datagram can buy an attacker-chosen address a seat in the fan-out set, and
/// lets a genuinely departed peer age out without needing a periodic timer —
/// expiry is checked lazily, against the caller-supplied `now`, wherever a
/// peer would otherwise be used.
const PEER_TTL: Duration = Duration::from_secs(600);

/// Learned mapping of neighbor MAC to UDP transport address for
/// [`UdpMultiLink`], refreshed from the sender address of every received
/// datagram (see [`resolve_target`]).  A neighbor's address is only ever
/// learned this way — there is no static peer list — so a destination is
/// reachable by unicast only after at least one frame (in practice, an OGM)
/// has been heard from it.  Bounded by [`MAX_TRACKED_PEERS`] and aged out by
/// [`PEER_TTL`] — see their doc comments for why both exist.
#[derive(Default)]
struct UdpPeerTable {
    peers: HashMap<Mac, (SocketAddr, Instant)>,
}

impl UdpPeerTable {
    /// Record (or refresh, if the peer's address changed) the transport
    /// address a frame from `mac` was most recently observed at, at `now`.
    ///
    /// If this is a new peer and the table is already at
    /// [`MAX_TRACKED_PEERS`], the least-recently-heard entry is evicted first
    /// — a stale/departed peer is, by construction, the most likely candidate.
    fn learn(&mut self, mac: Mac, addr: SocketAddr, now: Instant) {
        let at_capacity = !self.peers.contains_key(&mac) && self.peers.len() >= MAX_TRACKED_PEERS;
        if at_capacity
            && let Some(&oldest) = self
                .peers
                .iter()
                .min_by_key(|(_, (_, heard_at))| *heard_at)
                .map(|(mac, _)| mac)
        {
            self.peers.remove(&oldest);
        }
        self.peers.insert(mac, (addr, now));
    }

    /// The most recently learned transport address for `mac`, if it was heard
    /// from within [`PEER_TTL`] of `now`.
    fn resolve(&self, mac: Mac, now: Instant) -> Option<SocketAddr> {
        self.peers
            .get(&mac)
            .filter(|(_, heard_at)| now.saturating_duration_since(*heard_at) < PEER_TTL)
            .map(|(addr, _)| *addr)
    }

    /// Every currently live (within [`PEER_TTL`] of `now`) learned peer
    /// address, for fanning a broadcast/multicast-destined frame out to all
    /// of them. Order is unspecified.
    fn addrs(&self, now: Instant) -> impl Iterator<Item = SocketAddr> + '_ {
        self.peers
            .values()
            .filter(move |(_, heard_at)| now.saturating_duration_since(*heard_at) < PEER_TTL)
            .map(|(addr, _)| *addr)
    }
}

/// Where a frame addressed to `dst` should be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendTarget {
    /// A single known address: the configured `discovery_addr` for a
    /// multicast/broadcast destination, or a specific peer's last-known
    /// unicast address.
    Direct(SocketAddr),
    /// A multicast/broadcast destination with no configured `discovery_addr`
    /// — the hub mode, over a medium (like a Tailscale tunnel) with no real
    /// broadcast domain to send one datagram into. The caller fans the frame
    /// out to every currently learned peer instead.
    FanOut,
}

/// Where a frame addressed to `dst` should be sent: the shared
/// `discovery_addr` (a v4 broadcast or v6 multicast group) for any
/// multicast/broadcast destination if one is configured, [`SendTarget::FanOut`]
/// if not, or a specific peer's last-known unicast address once
/// [`UdpPeerTable`] has learned it.  `None` means `dst` hasn't been heard from
/// yet, so there is nowhere to send a unicast frame — the caller drops it
/// rather than guessing.
fn resolve_target(
    dst: Mac,
    discovery_addr: Option<SocketAddr>,
    peers: &UdpPeerTable,
    now: Instant,
) -> Option<SendTarget> {
    if dst.is_multicast() {
        Some(match discovery_addr {
            Some(addr) => SendTarget::Direct(addr),
            None => SendTarget::FanOut,
        })
    } else {
        peers.resolve(dst, now).map(SendTarget::Direct)
    }
}

/// A native multi-access UDP mesh interface: an unconnected socket that
/// reaches every peer on a shared IP network without a static peer list, the
/// UDP analog of `RawL2Link` (raw L2 is Linux-only, so this is deliberately
/// not a link) — except unlike raw L2, UDP
/// addressing isn't the mesh MAC, so this link (unlike `RawL2Link`) has to
/// learn each neighbor's transport address for itself, in [`UdpPeerTable`].
/// [`send`](LinkT::send) reaches [`Mac::BROADCAST`]/multicast via
/// `discovery_addr` if one is configured, or by fanning out to every learned
/// peer if not (see [`SendTarget::FanOut`] — this is the hub/star-topology
/// mode, for a medium like a Tailscale tunnel with no real broadcast domain);
/// any other destination via its most recently learned address, dropping the
/// frame if none is known yet. [`recv`](LinkT::recv) refreshes the table from
/// every datagram's sender address. Construct with [`build_udp_multi_link`].
pub struct UdpMultiLink {
    /// The unconnected socket: `send_to`/`recv_from`, never `connect`ed to a
    /// single peer.
    socket: UdpSocket,
    /// Where a [`Mac::BROADCAST`]/multicast-destined frame is sent: an IPv4
    /// broadcast address, or an IPv6 multicast group this socket has joined.
    /// `None` is the hub/fan-out mode — see the struct doc comment.
    discovery_addr: Option<SocketAddr>,
    /// Learned neighbor transport addresses, refreshed on every `recv`.
    peers: UdpPeerTable,
    /// Scratch buffer for the most recently sent or received frame, sized to
    /// [`MAX_LINK_FRAME_LEN`] like every other data-path buffer.
    wire_buf: [u8; MAX_LINK_FRAME_LEN],
}

impl LinkT for UdpMultiLink {
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        let now = Instant::now();
        let Some(target) = resolve_target(data.dst, self.discovery_addr, &self.peers, now) else {
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
        match target {
            SendTarget::Direct(addr) => {
                self.socket
                    .send_to(&self.wire_buf[..n], addr)
                    .await
                    .map_err(|e| {
                        tracing::warn!(error = ?e, "udp-multi send failed");
                        LinkError::Io
                    })?;
                Ok(n)
            }
            SendTarget::FanOut => {
                let targets: Vec<SocketAddr> = self.peers.addrs(now).collect();
                if targets.is_empty() {
                    tracing::trace!("drop: no known peers to fan broadcast out to");
                    return Ok(0);
                }
                let mut any_sent = false;
                for addr in targets {
                    match self.socket.send_to(&self.wire_buf[..n], addr).await {
                        Ok(_) => any_sent = true,
                        // One peer's send failing must not stop the frame
                        // reaching the rest — a departed spoke isn't reason to
                        // silently withhold an OGM from every other one.
                        Err(e) => {
                            tracing::warn!(error = ?e, ?addr, "udp-multi fan-out send failed")
                        }
                    }
                }
                if any_sent { Ok(n) } else { Err(LinkError::Io) }
            }
        }
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
        self.peers.learn(frame.src, peer_addr, Instant::now());
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
/// scoped to an interface, unlike IPv4 broadcast). `None` skips all of that:
/// this is the hub/star-topology mode (see [`UdpMultiLink`]'s doc comment) for
/// a medium with no real broadcast domain — a Tailscale tunnel is exactly
/// this, since it's point-to-point WireGuard links, not a shared L2/L3
/// segment. Any other destination is reached once
/// [`UdpMultiLink::recv`](LinkT::recv) has learned its address from a received
/// frame — in practice, from the periodic OGM every mesh node broadcasts, so
/// there is nothing to statically configure per peer.
pub async fn build_udp_multi_link(
    bind_addr: SocketAddr,
    discovery_addr: Option<SocketAddr>,
    multicast_interface: Option<&str>,
) -> anyhow::Result<Box<DynLinkT<'static>>> {
    let socket = UdpSocket::bind(bind_addr).await?;

    match discovery_addr {
        None => {}
        Some(SocketAddr::V4(_)) => socket.set_broadcast(true)?,
        Some(SocketAddr::V6(v6)) if v6.ip().is_multicast() => {
            let interface = multicast_interface.ok_or_else(|| {
                anyhow::anyhow!(
                    "multicast_interface is required when discovery_addr is an IPv6 multicast address"
                )
            })?;
            socket.join_multicast_v6(v6.ip(), interface_index(interface)?)?;
        }
        Some(SocketAddr::V6(_)) => anyhow::bail!(
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
    use std::time::Duration;

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
        assert_eq!(table.resolve(mac(1), Instant::now()), None);
    }

    #[test]
    fn peer_table_resolves_a_learned_peer() {
        let mut table = UdpPeerTable::default();
        let now = Instant::now();
        table.learn(mac(1), addr(4001), now);
        assert_eq!(table.resolve(mac(1), now), Some(addr(4001)));
    }

    #[test]
    fn peer_table_is_unaffected_by_other_macs() {
        let mut table = UdpPeerTable::default();
        let now = Instant::now();
        table.learn(mac(1), addr(4001), now);
        assert_eq!(table.resolve(mac(2), now), None);
    }

    /// A peer's address can change (DHCP lease renewal, roaming) — the table
    /// tracks only the most recently observed address per MAC, not history.
    #[test]
    fn peer_table_learn_again_overwrites_the_previous_address() {
        let mut table = UdpPeerTable::default();
        let now = Instant::now();
        table.learn(mac(1), addr(4001), now);
        table.learn(mac(1), addr(4002), now);
        assert_eq!(table.resolve(mac(1), now), Some(addr(4002)));
    }

    /// A peer not heard from in over [`PEER_TTL`] is treated as gone: it must
    /// neither answer a unicast resolve nor appear in the broadcast fan-out
    /// set. This is what stops one forged datagram from buying an
    /// attacker-chosen address a permanent seat in the fan-out set.
    #[test]
    fn peer_table_forgets_a_peer_past_its_ttl() {
        let mut table = UdpPeerTable::default();
        let heard_at = Instant::now();
        table.learn(mac(1), addr(4001), heard_at);

        let still_fresh = heard_at + PEER_TTL - Duration::from_secs(1);
        assert_eq!(table.resolve(mac(1), still_fresh), Some(addr(4001)));

        let expired = heard_at + PEER_TTL + Duration::from_secs(1);
        assert_eq!(table.resolve(mac(1), expired), None);
        assert_eq!(table.addrs(expired).count(), 0);
    }

    /// A socket that accepts datagrams from arbitrary unauthenticated senders
    /// must not grow the table without bound — capped, evicting the
    /// least-recently-heard entry to admit a new one once full.
    #[test]
    fn peer_table_evicts_the_oldest_entry_once_at_capacity() {
        let mut table = UdpPeerTable::default();
        let base = Instant::now();
        for i in 0..MAX_TRACKED_PEERS {
            table.learn(
                mac(i as u8),
                addr(4000 + i as u16),
                base + Duration::from_millis(i as u64),
            );
        }

        let now = base + Duration::from_millis(MAX_TRACKED_PEERS as u64);
        // A brand new peer, never seen before — MAX_TRACKED_PEERS is kept well
        // under 256 (the u8 mac space) so this mac was not already learned by
        // the loop above.
        table.learn(mac(MAX_TRACKED_PEERS as u8), addr(9000), now);

        assert_eq!(
            table.resolve(mac(0), now),
            None,
            "the oldest entry must have been evicted to admit a new one"
        );
        assert_eq!(
            table.resolve(mac(MAX_TRACKED_PEERS as u8), now),
            Some(addr(9000))
        );
        assert_eq!(
            table.peers.len(),
            MAX_TRACKED_PEERS,
            "the table must not grow past its cap"
        );
    }

    // ── resolve_target ───────────────────────────────────────────────────────

    #[test]
    fn broadcast_destination_resolves_to_discovery_addr_even_if_never_learned() {
        let table = UdpPeerTable::default();
        assert_eq!(
            resolve_target(Mac::BROADCAST, Some(DISCOVERY), &table, Instant::now()),
            Some(SendTarget::Direct(DISCOVERY))
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
        assert_eq!(
            resolve_target(group, Some(DISCOVERY), &table, Instant::now()),
            Some(SendTarget::Direct(DISCOVERY))
        );
    }

    /// With no configured `discovery_addr` — the hub/fan-out mode — a
    /// broadcast destination resolves to [`SendTarget::FanOut`] rather than
    /// nothing, even with no peers learned yet; the caller decides what an
    /// empty fan-out set means.
    #[test]
    fn broadcast_destination_with_no_discovery_addr_fans_out() {
        let table = UdpPeerTable::default();
        assert_eq!(
            resolve_target(Mac::BROADCAST, None, &table, Instant::now()),
            Some(SendTarget::FanOut)
        );
    }

    #[test]
    fn unicast_destination_not_yet_learned_resolves_to_nothing() {
        let table = UdpPeerTable::default();
        assert_eq!(
            resolve_target(mac(7), Some(DISCOVERY), &table, Instant::now()),
            None
        );
    }

    #[test]
    fn unicast_destination_resolves_to_its_learned_address_not_discovery_addr() {
        let mut table = UdpPeerTable::default();
        let now = Instant::now();
        table.learn(mac(7), addr(4007), now);
        assert_eq!(
            resolve_target(mac(7), Some(DISCOVERY), &table, now),
            Some(SendTarget::Direct(addr(4007)))
        );
    }

    /// Unicast resolution is unaffected by fan-out mode — a destination is
    /// still reached by its own learned address, never by looping the
    /// fan-out set.
    #[test]
    fn unicast_destination_resolves_the_same_way_with_no_discovery_addr() {
        let mut table = UdpPeerTable::default();
        let now = Instant::now();
        table.learn(mac(7), addr(4007), now);
        assert_eq!(
            resolve_target(mac(7), None, &table, now),
            Some(SendTarget::Direct(addr(4007)))
        );
    }

    // ── UdpMultiLink (real sockets) ──────────────────────────────────────────

    async fn hub(bind: SocketAddr) -> UdpMultiLink {
        let socket = UdpSocket::bind(bind).await.unwrap();
        UdpMultiLink {
            socket,
            discovery_addr: None,
            peers: UdpPeerTable::default(),
            wire_buf: [0u8; MAX_LINK_FRAME_LEN],
        }
    }

    /// Send one raw frame from `from` to `to`, as a spoke announcing itself —
    /// this is what [`UdpMultiLink::recv`] learns a peer's address from.
    async fn announce(from: &UdpSocket, to: SocketAddr, src: Mac) {
        let data = LinkFrameData {
            dst: Mac::BROADCAST,
            protocol: 0x1234,
            payload: b"hi",
        };
        let mut buf = [0u8; MAX_LINK_FRAME_LEN];
        let n = frame_into_buf(src, data.protocol, &data, &mut buf).unwrap();
        from.send_to(&buf[..n], to).await.unwrap();
    }

    /// A hub with no `discovery_addr` learns each spoke purely from the
    /// datagrams it receives, then fans a broadcast-destined frame out to
    /// every spoke it has learned — the behavior this file exists to add.
    #[tokio::test]
    async fn a_hub_fans_a_broadcast_out_to_every_learned_peer() {
        let mut hub_link = hub(addr(0)).await;
        let hub_addr = hub_link.socket.local_addr().unwrap();

        let mut spokes = Vec::new();
        for _ in 0..3 {
            spokes.push(UdpSocket::bind(addr(0)).await.unwrap());
        }
        for (i, spoke) in spokes.iter().enumerate() {
            announce(spoke, hub_addr, mac(i as u8 + 1)).await;
            hub_link.recv().await.unwrap();
        }

        let out = LinkFrameData {
            dst: Mac::BROADCAST,
            protocol: 0x1234,
            payload: b"ogm",
        };
        let n = hub_link.send(mac(0), &out).await.unwrap();
        assert!(n > 0);

        for spoke in &spokes {
            let mut buf = [0u8; MAX_LINK_FRAME_LEN];
            let (recvd, _) =
                tokio::time::timeout(Duration::from_secs(2), spoke.recv_from(&mut buf))
                    .await
                    .expect("spoke did not receive the fanned-out broadcast")
                    .unwrap();
            assert!(recvd > 0);
        }
    }

    #[tokio::test]
    async fn a_hub_with_no_learned_peers_drops_a_broadcast() {
        let mut hub_link = hub(addr(0)).await;
        let out = LinkFrameData {
            dst: Mac::BROADCAST,
            protocol: 0x1234,
            payload: b"ogm",
        };
        assert_eq!(hub_link.send(mac(0), &out).await.unwrap(), 0);
    }

    /// One learned peer whose send fails must not stop the broadcast reaching
    /// the rest. Port 0 is never a valid UDP send destination, so it fails
    /// deterministically at the OS level — standing in for a peer that has
    /// gone away, without depending on ICMP timing or socket-close races.
    #[tokio::test]
    async fn a_send_failure_to_one_peer_does_not_stop_the_others() {
        let mut hub_link = hub(addr(0)).await;
        let hub_addr = hub_link.socket.local_addr().unwrap();

        let alive = UdpSocket::bind(addr(0)).await.unwrap();
        announce(&alive, hub_addr, mac(1)).await;
        hub_link.recv().await.unwrap();

        hub_link.peers.learn(mac(2), addr(0), Instant::now());

        let out = LinkFrameData {
            dst: Mac::BROADCAST,
            protocol: 0x1234,
            payload: b"ogm",
        };
        let n = hub_link.send(mac(0), &out).await.unwrap();
        assert!(
            n > 0,
            "the broadcast must still be reported as sent to the reachable peer"
        );

        let mut buf = [0u8; MAX_LINK_FRAME_LEN];
        let (recvd, _) = tokio::time::timeout(Duration::from_secs(2), alive.recv_from(&mut buf))
            .await
            .expect("the alive peer did not receive the broadcast")
            .unwrap();
        assert!(recvd > 0);
    }

    #[tokio::test]
    async fn build_udp_multi_link_accepts_no_discovery_addr() {
        let link = build_udp_multi_link(addr(0), None, None).await;
        assert!(link.is_ok());
    }
}
