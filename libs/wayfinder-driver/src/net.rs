//! Helpers for building concrete `tokio::net` mesh links.

use std::collections::HashMap;
use std::net::Ipv4Addr;
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
use crate::raw::interface_ipv4;
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
/// `discovery_addr` (a v4 broadcast or peer address, or a joined v4/v6
/// multicast group) for any
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
    /// broadcast or peer address, or an IPv4/IPv6 multicast group this socket
    /// has joined. `None` is the hub/fan-out mode — see the struct doc
    /// comment.
    discovery_addr: Option<SocketAddr>,
    /// Learned neighbor transport addresses, refreshed on every `recv`.
    peers: UdpPeerTable,
    /// This medium's native fan-out, resolved once from the
    /// [`DiscoveryMode`] at construction — see
    /// [`DiscoveryMode::native_fan_out`]. Stored rather than recomputed from
    /// `discovery_addr`, because the distinction that decides it (a subnet
    /// broadcast versus a unicast peer) is not recoverable from the address
    /// alone once the classifier has been left behind.
    fan_out: Option<wayfinder::link::FanOut>,
    /// Scratch buffer for the most recently sent or received frame, sized to
    /// [`MAX_LINK_FRAME_LEN`] like every other data-path buffer.
    wire_buf: [u8; MAX_LINK_FRAME_LEN],
}

impl LinkT for UdpMultiLink {
    fn fan_out(&self) -> Option<wayfinder::link::FanOut> {
        self.fan_out
    }

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
        // A peer's bytes that are not a frame: its fault, not the socket's.
        let frame = LinkFrame::ref_from_bytes(&self.wire_buf[..n])
            .map_err(|_| LinkError::MalformedFrame)?;
        self.peers.learn(frame.src, peer_addr, Instant::now());
        // A UDP datagram carries no physical-layer signal information.
        Ok(Received {
            frame,
            metrics: LinkMetrics::default(),
        })
    }
}

/// What a configured `discovery_addr` actually asks the socket to do.
///
/// Classified up front, and separately from the socket setup that acts on it,
/// because the distinction this enum draws — an IPv4 *broadcast* address versus
/// an IPv4 *multicast group* — is exactly the one the builder used to miss.
/// Both are `SocketAddr::V4`, but they need opposite socket configuration
/// (`SO_BROADCAST` versus an `IP_ADD_MEMBERSHIP` join), and getting it wrong is
/// silent: a group address given `SO_BROADCAST` treatment transmits fine and
/// never receives, because the socket never joined the group.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DiscoveryMode {
    /// No discovery address: the hub/star mode, where a broadcast-destined
    /// frame is fanned out to every learned peer instead. See
    /// [`SendTarget::FanOut`].
    FanOut,
    /// A directly-addressed IPv4 destination: a broadcast address (subnet or
    /// limited), *or* a single peer's unicast address. The socket enables
    /// `SO_BROADCAST` and sends there directly; there is no group to join, so
    /// no interface needs naming.
    ///
    /// The unicast case is not a degenerate one — it is what the shipped
    /// hub/spoke deployments use, where a spoke's `discovery_addr` is the
    /// hub's tunnel address (see `docs/design/implemented/08-internet-links-headscale-vpn.md`
    /// and `nix/machines/wayfinder-ca/common.nix`). Naming this variant for
    /// broadcast alone would misdescribe the only IPv4 `discovery_addr` this
    /// repo actually deploys.
    Direct(SocketAddr),
    /// An IPv4 multicast group. The socket joins it on `interface` and pins
    /// its outgoing multicast to that same NIC.
    MulticastV4 {
        /// The group to join.
        group: Ipv4Addr,
        /// NIC the membership is joined on and outgoing datagrams leave by.
        interface: String,
    },
    /// An IPv6 multicast group. As `MulticastV4`, but scoped by kernel
    /// interface index rather than by interface address.
    MulticastV6 {
        /// The group to join.
        group: std::net::Ipv6Addr,
        /// NIC the membership is joined on and outgoing datagrams leave by.
        interface: String,
    },
}

impl DiscoveryMode {
    /// This mode's [`LinkT::fan_out`] declaration: the number of destinations
    /// on this link at which one send beats one directed copy each, or `None`
    /// when a send reaches one peer and N copies genuinely cost N.
    ///
    /// `Some(2)` for the modes where a single datagram reaches every peer at
    /// once — a joined multicast group, or the limited broadcast address. Two
    /// is the crossover rather than one because a directed copy here is a
    /// single unicast datagram, exactly what a group send costs; at one
    /// destination they tie, and the unicast is the more precise of the two
    /// (it does not wake every other peer on the group). At two they do not.
    ///
    /// `None` everywhere else, and the asymmetry is deliberate: over-claiming
    /// is a **correctness** bug, not a missed optimisation. A planner told that
    /// one send covers several next hops will send once and consider the rest
    /// delivered, so a mode that cannot prove it reaches everyone must say
    /// nothing. That rules out hub/fan-out mode (which loops `send_to` per
    /// learned peer) and every non-multicast [`DiscoveryMode::Direct`] address:
    /// a *subnet* broadcast would qualify, but it cannot be told apart from a
    /// plain unicast peer without the netmask — and a unicast peer is what the
    /// shipped hub/spoke deployments actually configure.
    fn native_fan_out(&self) -> Option<core::num::NonZeroU8> {
        /// One datagram reaches every peer, so the second directed copy is
        /// already the more expensive way to do it.
        const REACHES_EVERY_PEER: Option<core::num::NonZeroU8> = core::num::NonZeroU8::new(2);
        match self {
            DiscoveryMode::MulticastV4 { .. } | DiscoveryMode::MulticastV6 { .. } => {
                REACHES_EVERY_PEER
            }
            DiscoveryMode::Direct(SocketAddr::V4(v4)) if v4.ip().is_broadcast() => {
                REACHES_EVERY_PEER
            }
            DiscoveryMode::Direct(_) | DiscoveryMode::FanOut => None,
        }
    }
}

/// Classify a `(discovery_addr, multicast_interface)` config pair, rejecting
/// the combinations that cannot work.
///
/// Every multicast mode — v4 and v6 alike — requires `multicast_interface`.
/// Multicast is scoped to one NIC on both families: the membership is joined on
/// an interface and outgoing datagrams leave by an interface, and letting the
/// kernel pick either from the routing table is how a link ends up listening on
/// one NIC and transmitting out another. IPv4 used not to require it only
/// because IPv4 multicast was not handled at all.
fn discovery_mode(
    bind_addr: SocketAddr,
    discovery_addr: Option<SocketAddr>,
    multicast_interface: Option<&str>,
) -> anyhow::Result<DiscoveryMode> {
    /// Both multicast families: the socket must be able to *receive* the group
    /// it is about to join. Joining is not enough — a socket bound to a
    /// specific unicast address never sees a datagram addressed to the group,
    /// and a socket bound to a different port never sees one sent to the
    /// group's port. Either mistake yields a link that transmits perfectly and
    /// receives nothing, with no error at any layer.
    fn check_bindable(bind_addr: SocketAddr, group: SocketAddr) -> anyhow::Result<()> {
        if !bind_addr.ip().is_unspecified() && bind_addr.ip() != group.ip() {
            anyhow::bail!(
                "bind_addr {bind_addr} cannot receive multicast group {group}: bind to the \
                 wildcard address (0.0.0.0 / [::]) or to the group address itself. A socket \
                 bound to one NIC's own address joins the group but never receives it"
            );
        }
        if bind_addr.port() != group.port() {
            anyhow::bail!(
                "bind_addr port {} does not match the discovery_addr port {}: datagrams sent \
                 to the group's port would never be received",
                bind_addr.port(),
                group.port()
            );
        }
        Ok(())
    }

    /// Shared by both families: a multicast group with no NIC to scope it to.
    fn require_interface(interface: Option<&str>, family: &str) -> anyhow::Result<String> {
        interface.map(str::to_string).ok_or_else(|| {
            anyhow::anyhow!(
                "multicast_interface is required when discovery_addr is an {family} multicast \
                 address: the group is joined on one NIC and datagrams leave by one NIC, and \
                 neither may be left to the routing table"
            )
        })
    }

    match discovery_addr {
        None => {
            if multicast_interface.is_some() {
                anyhow::bail!(
                    "multicast_interface is meaningless without a discovery_addr to join a \
                     multicast group at"
                );
            }
            Ok(DiscoveryMode::FanOut)
        }
        Some(addr @ SocketAddr::V4(v4)) if v4.ip().is_multicast() => {
            check_bindable(bind_addr, addr)?;
            Ok(DiscoveryMode::MulticastV4 {
                group: *v4.ip(),
                interface: require_interface(multicast_interface, "IPv4")?,
            })
        }
        Some(addr @ SocketAddr::V4(_)) => {
            if multicast_interface.is_some() {
                anyhow::bail!(
                    "multicast_interface is meaningless for the non-multicast IPv4 \
                     discovery_addr {addr}: there is no group to join, and the route to a \
                     broadcast or peer address already determines which NIC is used. Drop the \
                     field, or point discovery_addr at a multicast group (224.0.0.0/4) if \
                     scoping this link to one NIC is what you meant"
                );
            }
            Ok(DiscoveryMode::Direct(addr))
        }
        Some(addr @ SocketAddr::V6(v6)) if v6.ip().is_multicast() => {
            check_bindable(bind_addr, addr)?;
            Ok(DiscoveryMode::MulticastV6 {
                group: *v6.ip(),
                interface: require_interface(multicast_interface, "IPv6")?,
            })
        }
        Some(SocketAddr::V6(_)) => anyhow::bail!(
            "IPv6 discovery_addr must be a multicast address: IPv6 has no broadcast equivalent"
        ),
    }
}

/// Apply one [`DiscoveryMode`] to a freshly bound socket.
///
/// Split from [`discovery_mode`] so the classification is testable without a
/// socket (and without a NIC that has to exist on the test host), leaving this
/// half as the thin syscall sequence it should be.
fn apply_discovery_mode(socket: &UdpSocket, mode: &DiscoveryMode) -> anyhow::Result<()> {
    match mode {
        DiscoveryMode::FanOut => {}
        DiscoveryMode::Direct(_) => socket.set_broadcast(true)?,
        DiscoveryMode::MulticastV4 { group, interface } => {
            let nic = interface_ipv4(interface)?;
            socket.join_multicast_v4(*group, nic)?;
            // Pin the *send* side to the same NIC the membership was joined
            // on. Without this the kernel routes 224.0.0.0/4 by the routing
            // table, which on a multi-homed node is routinely a different
            // interface than the one this link listens on — the link then
            // transmits where nobody is listening while hearing only what
            // arrives on the other NIC.
            socket2::SockRef::from(socket).set_multicast_if_v4(&nic)?;
            // Stated rather than inherited. The default IPv4 multicast TTL is
            // 1, which is right for a single-segment mesh link and is what
            // this link is for; writing it down means a future change to make
            // it configurable has an obvious place to land, and an operator
            // reading the code does not have to know the kernel default to
            // know why a second-hop node never hears this link.
            socket.set_multicast_ttl_v4(1)?;
            // Off, unlike the kernel default. With it on, this socket receives
            // every datagram it sends: the engine drops the frames (they carry
            // our own `orig`), but only *after* `UdpMultiLink::recv` has
            // learned this node's own MAC into the peer table and
            // `CentralRouter::record_rx` has counted a self-transmitted
            // broadcast as received — roughly doubling the interface's
            // reported rx rate on a multicast link, which is a number an
            // operator and an app on top of the mesh both act on.
            //
            // Safe to disable because two nodes cannot share a multicast link
            // on one host anyway: the socket sets no SO_REUSEADDR/SO_REUSEPORT,
            // so the second bind to the same port fails. If that ever changes,
            // this has to change with it — loopback is how co-located nodes
            // would hear each other.
            socket2::SockRef::from(socket).set_multicast_loop_v4(false)?;
        }
        DiscoveryMode::MulticastV6 { group, interface } => {
            let idx = interface_index(interface)?;
            socket.join_multicast_v6(group, idx)?;
            // As above, for the v6 send side: scoped by interface index rather
            // than by interface address.
            socket2::SockRef::from(socket).set_multicast_if_v6(idx)?;
            // As the v4 arm: off so this node does not receive, learn from and
            // meter its own transmissions.
            socket2::SockRef::from(socket).set_multicast_loop_v6(false)?;
        }
    }
    Ok(())
}

/// Build a native multi-access UDP mesh link, type-erased as a [`LinkT`].
///
/// Binds an unconnected socket to `bind_addr`. `discovery_addr` is where a
/// broadcast/multicast frame goes, and [`discovery_mode`] classifies which of
/// the three shapes it is: an IPv4 broadcast address (the socket enables
/// `SO_BROADCAST`), an IPv4 or IPv6 multicast group (the socket joins it on
/// `multicast_interface`, required for both families, and pins its outgoing
/// multicast to that same NIC), or `None` — the hub/star-topology mode (see
/// [`UdpMultiLink`]'s doc comment) for a medium with no real broadcast domain,
/// a Tailscale tunnel being exactly this since it's point-to-point WireGuard
/// links rather than a shared L2/L3 segment. Any other destination is reached
/// once [`UdpMultiLink::recv`](LinkT::recv) has learned its address from a
/// received frame — in practice, from the periodic OGM every mesh node
/// broadcasts, so there is nothing to statically configure per peer.
pub async fn build_udp_multi_link(
    bind_addr: SocketAddr,
    discovery_addr: Option<SocketAddr>,
    multicast_interface: Option<&str>,
) -> anyhow::Result<Box<DynLinkT<'static>>> {
    // Classified before the bind so a misconfigured link fails on the config
    // error rather than on whatever the socket does with it afterwards.
    let mode = discovery_mode(bind_addr, discovery_addr, multicast_interface)?;
    let socket = UdpSocket::bind(bind_addr).await?;
    apply_discovery_mode(&socket, &mode)?;

    Ok(DynLinkT::new_box(UdpMultiLink {
        socket,
        discovery_addr,
        // A datagram carries a whole `MAX_LINK_FRAME_LEN` frame, the same
        // bound `wire_buf` and every other data-path buffer use.
        fan_out: mode
            .native_fan_out()
            .map(|threshold| wayfinder::link::FanOut {
                threshold,
                max_frame_len: MAX_LINK_FRAME_LEN,
            }),
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
    use core::num::NonZeroU8;
    use std::time::Duration;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// A wildcard bind, the normal shape; tests that care about `bind_addr`
    /// spell out their own.
    const BIND: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 9999);

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

    // ── discovery_mode ───────────────────────────────────────────────────────

    /// An IPv4 *broadcast* address is the `SO_BROADCAST` mode: no group to
    /// join, so no NIC needs naming.
    #[test]
    fn ipv4_broadcast_discovery_addr_is_broadcast_mode() {
        assert_eq!(
            discovery_mode(BIND, Some(DISCOVERY), None).unwrap(),
            DiscoveryMode::Direct(DISCOVERY)
        );
    }

    /// An IPv4 *multicast* group is a real multicast mode — not the broadcast
    /// mode it used to silently fall into, which set `SO_BROADCAST`, never
    /// joined the group, and so produced a link that transmitted and never
    /// received.
    #[test]
    fn ipv4_multicast_discovery_addr_is_multicast_mode() {
        let group = SocketAddr::from(([239, 1, 1, 1], 9999));
        assert_eq!(
            discovery_mode(BIND, Some(group), Some("eth0")).unwrap(),
            DiscoveryMode::MulticastV4 {
                group: std::net::Ipv4Addr::new(239, 1, 1, 1),
                interface: "eth0".to_string(),
            }
        );
    }

    /// IPv4 multicast is scoped to a NIC for the same reason IPv6 is: the
    /// membership is joined on one interface and datagrams leave through one
    /// interface. Omitting it is a hard error, not a kernel-picks-one default.
    #[test]
    fn ipv4_multicast_discovery_addr_requires_a_multicast_interface() {
        let group = SocketAddr::from(([239, 1, 1, 1], 9999));
        let err = discovery_mode(BIND, Some(group), None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("multicast_interface"),
            "the error must name the missing field, got: {err}"
        );
    }

    /// The v6 arm keeps its existing contract.
    #[test]
    fn ipv6_multicast_discovery_addr_requires_a_multicast_interface() {
        let group: SocketAddr = "[ff02::1]:9999".parse().unwrap();
        let err = discovery_mode(BIND, Some(group), None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("multicast_interface"),
            "the error must name the missing field, got: {err}"
        );
    }

    /// A non-multicast IPv6 address has no broadcast equivalent to fall back
    /// on, so it stays rejected.
    #[test]
    fn ipv6_unicast_discovery_addr_is_rejected() {
        let addr: SocketAddr = "[2001:db8::1]:9999".parse().unwrap();
        assert!(discovery_mode(BIND, Some(addr), None).is_err());
    }

    /// `multicast_interface` without a `discovery_addr` names a group that
    /// does not exist — rejected here rather than in `wayfinder-tap`, so
    /// every caller of the builder gets the check.
    #[test]
    fn multicast_interface_without_a_discovery_addr_is_rejected() {
        let err = discovery_mode(BIND, None, Some("eth0"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("multicast_interface"),
            "the error must name the offending field, got: {err}"
        );
    }

    /// A multicast socket must be bound to the wildcard address or to the group
    /// itself; bound to a NIC's own unicast address it joins the group happily
    /// and then never receives a datagram addressed to that group.
    ///
    /// Rejected rather than silently accepted because it is the *natural*
    /// mistake here: the operator has just been told to name the NIC in
    /// `multicast_interface`, so writing that NIC's address in `bind_addr` too
    /// reads like the consistent thing to do — and it produces exactly the
    /// transmits-but-never-receives link this whole classifier exists to stop.
    #[test]
    fn multicast_rejects_a_bind_addr_on_a_specific_unicast_address() {
        let group: SocketAddr = "239.1.1.1:9999".parse().unwrap();
        let bind: SocketAddr = "192.168.1.5:9999".parse().unwrap();
        let err = discovery_mode(bind, Some(group), Some("eth0"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("bind_addr"),
            "the error must name the offending field, got: {err}"
        );
    }

    /// The wildcard bind is the normal case and is accepted.
    #[test]
    fn multicast_accepts_a_wildcard_bind_addr() {
        let group: SocketAddr = "239.1.1.1:9999".parse().unwrap();
        let bind: SocketAddr = "0.0.0.0:9999".parse().unwrap();
        assert!(discovery_mode(bind, Some(group), Some("eth0")).is_ok());
    }

    /// Binding to the group address itself also works on every platform this
    /// runs on, so it is accepted too.
    #[test]
    fn multicast_accepts_a_bind_addr_on_the_group_itself() {
        let group: SocketAddr = "239.1.1.1:9999".parse().unwrap();
        let bind: SocketAddr = "239.1.1.1:9999".parse().unwrap();
        assert!(discovery_mode(bind, Some(group), Some("eth0")).is_ok());
    }

    /// The same rule for IPv6.
    #[test]
    fn ipv6_multicast_rejects_a_bind_addr_on_a_specific_unicast_address() {
        let group: SocketAddr = "[ff02::1]:9999".parse().unwrap();
        let bind: SocketAddr = "[2001:db8::5]:9999".parse().unwrap();
        assert!(discovery_mode(bind, Some(group), Some("eth0")).is_err());
    }

    /// A datagram sent to the group's port is only received by a socket bound
    /// to that same port, so a mismatch is another silently one-way link.
    #[test]
    fn multicast_rejects_a_bind_port_that_differs_from_the_group_port() {
        let group: SocketAddr = "239.1.1.1:9999".parse().unwrap();
        let bind: SocketAddr = "0.0.0.0:9998".parse().unwrap();
        let err = discovery_mode(bind, Some(group), Some("eth0"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("port"),
            "the error must explain the port mismatch, got: {err}"
        );
    }

    /// Neither rule constrains the broadcast or hub modes: a broadcast
    /// destination is not a group anything joins, and a fan-out link sends
    /// only to addresses it has learned.
    #[test]
    fn broadcast_and_fan_out_modes_do_not_constrain_the_bind_addr() {
        let bind: SocketAddr = "192.168.1.5:1234".parse().unwrap();
        assert!(discovery_mode(bind, Some(DISCOVERY), None).is_ok());
        assert!(discovery_mode(bind, None, None).is_ok());
    }

    /// No discovery address at all is the hub/fan-out mode.
    #[test]
    fn no_discovery_addr_is_fan_out_mode() {
        assert_eq!(
            discovery_mode(BIND, None, None).unwrap(),
            DiscoveryMode::FanOut
        );
    }

    // ── native fan-out ───────────────────────────────────────────────────────

    /// A joined multicast group is the clear case: one datagram reaches every
    /// peer on it, so two directed copies already cost more than one group
    /// send.
    #[test]
    fn a_multicast_group_declares_native_fan_out() {
        let group: SocketAddr = "239.1.1.1:9999".parse().unwrap();
        let bind: SocketAddr = "0.0.0.0:9999".parse().unwrap();
        let mode = discovery_mode(bind, Some(group), Some("eth0")).unwrap();
        assert_eq!(mode.native_fan_out(), NonZeroU8::new(2));
    }

    #[test]
    fn an_ipv6_multicast_group_declares_native_fan_out() {
        let group: SocketAddr = "[ff02::1]:9999".parse().unwrap();
        let bind: SocketAddr = "[::]:9999".parse().unwrap();
        let mode = discovery_mode(bind, Some(group), Some("eth0")).unwrap();
        assert_eq!(mode.native_fan_out(), NonZeroU8::new(2));
    }

    /// The limited broadcast address reaches the whole segment in one
    /// datagram, so it fans out for the same reason a group does.
    #[test]
    fn the_limited_broadcast_address_declares_native_fan_out() {
        let mode = discovery_mode(BIND, Some(DISCOVERY), None).unwrap();
        assert_eq!(mode.native_fan_out(), NonZeroU8::new(2));
    }

    /// A *unicast* peer address — what the shipped hub/spoke deployments put in
    /// `discovery_addr` — reaches exactly one peer, so it declares nothing.
    ///
    /// Over-claiming here would be a correctness bug, not a missed
    /// optimisation: a planner that believed one send covered several next hops
    /// would send once to the hub and silently drop every other destination.
    /// A *subnet* broadcast address is indistinguishable from a unicast one
    /// without the netmask, so it lands here too — declaring nothing costs an
    /// optimisation, declaring wrongly costs delivery.
    #[test]
    fn a_unicast_peer_discovery_addr_declares_no_fan_out() {
        let hub: SocketAddr = "100.64.0.1:6000".parse().unwrap();
        let bind: SocketAddr = "0.0.0.0:6000".parse().unwrap();
        let mode = discovery_mode(bind, Some(hub), None).unwrap();
        assert_eq!(mode.native_fan_out(), None);
    }

    /// Hub/fan-out mode loops `send_to` once per learned peer, so a
    /// "broadcast" genuinely costs N datagrams and there is nothing to exploit.
    #[test]
    fn hub_mode_declares_no_fan_out() {
        let mode = discovery_mode(BIND, None, None).unwrap();
        assert_eq!(mode.native_fan_out(), None);
    }

    /// And the declaration survives onto the built link, which is what any
    /// consumer actually asks — `LinkT::fan_out` on a `UdpMultiLink`, not on
    /// the classifier.
    #[tokio::test]
    async fn a_built_multicast_link_declares_its_medium() {
        let group: SocketAddr = "239.77.77.79:45995".parse().unwrap();
        let bind: SocketAddr = "0.0.0.0:45995".parse().unwrap();
        let link = build_udp_multi_link(bind, Some(group), Some(loopback_nic()))
            .await
            .expect("a wildcard bind on the loopback NIC is a valid multicast config");
        assert_eq!(link.fan_out().map(|f| f.threshold), NonZeroU8::new(2));
    }

    /// The hub-mode link built the same way declares nothing.
    #[tokio::test]
    async fn a_built_hub_link_declares_no_fan_out() {
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let link = build_udp_multi_link(bind, None, None)
            .await
            .expect("hub mode is always valid");
        assert_eq!(link.fan_out(), None);
    }

    // ── apply_discovery_mode (real sockets) ──────────────────────────────────

    /// The loopback NIC, whichever it is called on this host.
    fn loopback_nic() -> &'static str {
        if cfg!(target_os = "linux") {
            "lo"
        } else {
            "lo0"
        }
    }

    /// The whole point of the change: an IPv4 multicast `discovery_addr` must
    /// actually reach the kernel as a group join plus a pinned egress
    /// interface. Nothing above this line proves the syscalls are even
    /// well-formed — the classifier tests stop at the enum.
    #[tokio::test]
    async fn ipv4_multicast_mode_configures_a_real_socket() {
        let group: SocketAddr = "239.77.77.78:45997".parse().unwrap();
        let bind: SocketAddr = "0.0.0.0:45997".parse().unwrap();
        let mode = discovery_mode(bind, Some(group), Some(loopback_nic()))
            .expect("a wildcard bind on the loopback NIC is a valid multicast config");
        let socket = UdpSocket::bind(bind).await.expect("bind");
        apply_discovery_mode(&socket, &mode).expect("join, pin and set loop/ttl must all succeed");
    }

    /// The v6 arm likewise — `set_multicast_if_v6` takes an ifindex where v4
    /// takes an address, so the two arms share no code and need separate
    /// cover.
    #[tokio::test]
    async fn ipv6_multicast_mode_configures_a_real_socket() {
        let group: SocketAddr = "[ff02::1:3]:45996".parse().unwrap();
        let bind: SocketAddr = "[::]:45996".parse().unwrap();
        let mode = discovery_mode(bind, Some(group), Some(loopback_nic()))
            .expect("a wildcard bind on the loopback NIC is a valid multicast config");
        let socket = UdpSocket::bind(bind).await.expect("bind");
        apply_discovery_mode(&socket, &mode).expect("join and pin must succeed");
    }

    /// The hub mode touches no socket option at all, so it must work against a
    /// socket with no multicast capability in play.
    #[tokio::test]
    async fn fan_out_mode_configures_a_real_socket() {
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mode = discovery_mode(bind, None, None).expect("hub mode is always valid");
        let socket = UdpSocket::bind(bind).await.expect("bind");
        apply_discovery_mode(&socket, &mode).expect("fan-out mode configures nothing");
    }

    // ── interface_ipv4 ───────────────────────────────────────────────────────

    /// The loopback NIC always carries 127.0.0.1, on every host this builds
    /// for — so the name-to-address walk has a fixed point to assert against.
    #[test]
    fn interface_ipv4_resolves_the_loopback_nic() {
        assert_eq!(
            interface_ipv4(loopback_nic()).expect("loopback always has an IPv4 address"),
            std::net::Ipv4Addr::LOCALHOST
        );
    }

    /// A name that matches no interface is reported as such, rather than as an
    /// interface that exists but lacks an address — they are different
    /// mistakes and only one of them is fixed by adding an address.
    #[test]
    fn interface_ipv4_distinguishes_an_unknown_nic_from_one_with_no_ipv4() {
        let err = interface_ipv4("wf-nope-not-a-nic0")
            .expect_err("no such interface")
            .to_string();
        assert!(
            err.contains("no such network interface"),
            "an unknown NIC must not be reported as one missing an address, got: {err}"
        );
    }

    // ── UdpMultiLink (real sockets) ──────────────────────────────────────────

    async fn hub(bind: SocketAddr) -> UdpMultiLink {
        let socket = UdpSocket::bind(bind).await.unwrap();
        UdpMultiLink {
            socket,
            fan_out: None,
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

    /// A datagram too short to be a frame is the sender's fault, and on a UDP
    /// carrier the sender is anyone who can reach the port. It must surface as
    /// [`LinkError::MalformedFrame`] — which the driver drops without raising
    /// `LinkErrors` — not as `Io`, which would let that stranger keep the
    /// interface's alarm latched (#77). Nor may it teach the hub a peer.
    #[tokio::test]
    async fn a_runt_datagram_is_a_malformed_frame() {
        let mut hub_link = hub(addr(0)).await;
        let hub_addr = hub_link.socket.local_addr().unwrap();
        let stranger = UdpSocket::bind(addr(0)).await.unwrap();

        stranger.send_to(&[0u8; 3], hub_addr).await.unwrap();

        assert!(matches!(
            hub_link.recv().await,
            Err(LinkError::MalformedFrame)
        ));
        assert!(
            hub_link.peers.peers.is_empty(),
            "a runt must not be learned"
        );
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
