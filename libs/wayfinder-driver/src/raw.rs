//! Raw-socket mesh carriers built on `socket2`.
//!
//! Two flavours, mirroring the two `LinkT` shapes described in [`transport`]:
//!
//! * **Raw IP** ([`build_raw_ip_link`]) is a point-to-point byte pipe, the exact
//!   analog of the UDP link: an `AF_INET`/`SOCK_RAW` socket bound to a local
//!   address and connected to a fixed peer over a chosen IP protocol number.  It
//!   carries our [`LinkFrame`] bytes as the IP payload, so it gets its [`LinkT`]
//!   behaviour from the [`Link`] adapter.  The kernel prepends the IPv4 header on
//!   send and (on Linux) *delivers* it on recv, so the bridge strips it back off
//!   before handing the frame up.
//! * **Raw L2** (`RawL2Link`, Linux-only — hence not a link) is a native
//!   multi-access interface: an
//!   `AF_PACKET`/`SOCK_RAW` socket bound to one NIC.  The wire frame is the
//!   Ethernet-shaped `[dst][src][ethertype][payload]`, but the **EtherType** is a
//!   configurable *transport label* (the value the socket binds/filters on, e.g.
//!   `0xfafa`), distinct from the **mesh protocol** the router demuxes on (e.g.
//!   BATMAN `0x4305`).  Send stamps the configured EtherType; recv retags that
//!   field back to the mesh protocol in place (a 2-byte rewrite, no overhead) so
//!   the bytes reinterpret as a [`LinkFrame`].  This lets a deployment pick any
//!   EtherType — to isolate co-located meshes, or to coexist with real batman-adv
//!   — without being forced onto the router's protocol number.  It implements
//!   [`LinkT`] directly and routes each frame by its destination MAC.
//! * **Raw L2 egress** ([`RawL2Egress`]) is a *host-facing* transport, not a mesh
//!   interface: an `AF_PACKET`/`SOCK_RAW` socket bound to one physical NIC with
//!   `ETH_P_ALL`, so it carries every frame on the wire rather than one transport
//!   EtherType. It is the same shape as the kernel TAP device the driver's local
//!   egress otherwise uses — a dumb whole-frame passthrough, [`FrameIo`] rather
//!   than [`LinkT`] — just backed by a real NIC someone can plug a cable into
//!   instead of a virtual device. Both raw-L2 carriers rely on the kernel's
//!   `PACKET_IGNORE_OUTGOING` option so a frame this node just transmitted (mesh
//!   traffic, or e.g. a co-located DHCP server's own broadcast replies) is never
//!   read back and re-forwarded.
//!
//! **The two raw-L2 carriers are Linux-only.** `AF_PACKET` is a Linux socket
//! family with no portable equivalent (macOS's nearest analog is BPF, a
//! different API), so on any other host they are constructor stubs that fail
//! with a clear reason instead of compiling away — a configured raw-L2
//! carrier is then a startup error, not a compile error in the node that
//! reads the config. Raw IP is `AF_INET`/`SOCK_RAW` and stays portable,
//! though the header-on-receive behaviour described above is Linux's.
//!
//! [`transport`]: crate::transport
//! [`FrameIo`]: crate::transport::FrameIo
//! [`Link`]: crate::transport::Link

// Only what the portable helpers below need. The frame-shaping imports the
// raw-L2 carriers use are scoped to them (`tokio_impl`), so a non-Linux build
// — where those carriers are `cfg`'d out — doesn't drag in a pile of unused
// imports; the tests import their own.
use interfaces::frame::Mac;

/// Offset of the payload within a raw IPv4 datagram as delivered by an
/// `AF_INET`/`SOCK_RAW` socket, i.e. the length of the IPv4 header (IHL × 4).
///
/// Linux hands raw-IP receivers the full datagram including the IP header, so
/// the bridge must skip this many bytes to recover the carried frame.  Returns
/// `None` if `datagram` is not a well-formed IPv4 header (wrong version, IHL
/// below the 20-byte minimum, or header longer than the datagram).
fn ipv4_payload_offset(datagram: &[u8]) -> Option<usize> {
    let first = *datagram.first()?;
    if first >> 4 != 4 {
        return None; // not IPv4
    }
    let ihl_words = (first & 0x0f) as usize;
    let header_len = ihl_words * 4;
    if header_len < 20 || header_len > datagram.len() {
        return None;
    }
    Some(header_len)
}

/// Extract the destination MAC — a raw-L2 frame's leading 6 bytes — from an
/// Ethernet-shaped `[dst][src][ethertype][payload]` buffer, for addressing an
/// `AF_PACKET` `sendto`. `None` if `frame` is shorter than a MAC address.
///
/// Pure logic, so it is compiled and unit-tested on every host even though its
/// only caller is the Linux-only egress carrier below.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn frame_dst_mac(frame: &[u8]) -> Option<Mac> {
    let bytes: [u8; 6] = frame.get(..6)?.try_into().ok()?;
    Some(Mac(bytes))
}

#[cfg(feature = "tokio")]
pub use tokio_impl::RawL2Egress;
// No non-Linux counterpart, unlike `RawL2Egress`: nothing outside this module
// names this type — it only ever travels as a `Box<DynLinkT>` — so there is
// nothing for a stub to keep compiling.
#[cfg(all(feature = "tokio", target_os = "linux"))]
pub use tokio_impl::RawL2Link;
#[cfg(feature = "tokio")]
pub use tokio_impl::build_raw_ip_link;
#[cfg(feature = "tokio")]
pub use tokio_impl::build_raw_l2_egress;
#[cfg(feature = "tokio")]
pub use tokio_impl::build_raw_l2_link;
// Shared with the multi-access UDP link (`net::build_udp_multi_link`), which
// needs the same NIC-name resolution to join a multicast group on a specific
// interface: by kernel index for IPv6, by interface address for IPv4 (see
// `interface_ipv4` for why the two families differ).
#[cfg(feature = "tokio")]
pub(crate) use tokio_impl::interface_index;
#[cfg(feature = "tokio")]
pub(crate) use tokio_impl::interface_ipv4;

#[cfg(feature = "tokio")]
mod tokio_impl {
    use super::*;

    use interfaces::frame::MAX_LINK_FRAME_LEN;

    // The Ethernet-frame shaping the `AF_PACKET` carriers do; raw IP hands the
    // kernel an opaque payload and needs none of it.
    #[cfg(target_os = "linux")]
    use interfaces::frame::LinkFrame;
    #[cfg(target_os = "linux")]
    use interfaces::frame::LinkFrameData;
    #[cfg(target_os = "linux")]
    use interfaces::link::LinkError;
    #[cfg(target_os = "linux")]
    use interfaces::link::LinkMetrics;
    #[cfg(target_os = "linux")]
    use interfaces::wire::ETH_HEADER_LEN;
    #[cfg(target_os = "linux")]
    use interfaces::wire::frame_into_buf;
    #[cfg(target_os = "linux")]
    use interfaces::wire::retag_ethertype;
    #[cfg(target_os = "linux")]
    use zerocopy::FromBytes;

    use std::io;
    use std::mem::MaybeUninit;
    use std::net::IpAddr;

    use socket2::Domain;
    use socket2::Protocol;
    use socket2::Socket;
    use socket2::Type;
    use tokio::io::unix::AsyncFd;
    use tokio::net::UnixDatagram;
    use tokio::task::JoinSet;

    use crate::transport::FrameIo;
    use crate::transport::Link;
    use wayfinder::link::DynLinkT;

    // Named only by the `AF_PACKET` carriers: hand-building a `sockaddr_ll`
    // (`size_of`/`socklen_t`/`SockAddr*`), reaching the fd for `setsockopt`
    // (`AsRawFd`), and the `LinkT` those carriers implement.
    #[cfg(target_os = "linux")]
    use socket2::SockAddr;
    #[cfg(target_os = "linux")]
    use socket2::SockAddrStorage;
    #[cfg(target_os = "linux")]
    use socket2::socklen_t;
    #[cfg(target_os = "linux")]
    use std::mem::size_of;
    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;
    #[cfg(target_os = "linux")]
    use wayfinder::DEFAULT_BATMAN_ETHER_TYPE;
    #[cfg(target_os = "linux")]
    use wayfinder::link::Received;

    // Kept unconditional: `build_raw_ip_link`'s documentation intra-doc-links
    // to it on every platform, and rustdoc resolves that through this import
    // while rustc doesn't count a doc link as a use.
    #[cfg_attr(not(target_os = "linux"), allow(unused_imports))]
    use wayfinder::link::LinkT;

    /// `SOL_PACKET` setsockopt level (not exported by `libc` on all targets).
    #[cfg(target_os = "linux")]
    const SOL_PACKET: libc::c_int = 263;
    /// `PACKET_IGNORE_OUTGOING`: stop the kernel looping our own transmitted
    /// frames back into our receive queue (Linux ≥ 4.20).  Best-effort.
    #[cfg(target_os = "linux")]
    const PACKET_IGNORE_OUTGOING: libc::c_int = 23;

    /// Receive into an `[u8]` buffer through `socket2`'s `MaybeUninit` API.
    ///
    /// `Socket::recv` only writes the bytes it reports and never reads from the
    /// buffer, so viewing an initialized `[u8]` as `[MaybeUninit<u8>]` for the
    /// call is sound, and the returned prefix is fully initialized.
    fn recv_into(sock: &Socket, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: `[u8]` and `[MaybeUninit<u8>]` share a layout; `recv` only
        // writes, so no uninitialized byte is ever observed as `u8`.
        let uninit = unsafe { &mut *(buf as *mut [u8] as *mut [MaybeUninit<u8>]) };
        sock.recv(uninit)
    }

    /// Await readiness, then perform one non-blocking `recv` on a `socket2`
    /// socket registered with the tokio reactor.
    async fn async_recv(fd: &AsyncFd<Socket>, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = fd.readable().await?;
            match guard.try_io(|inner| recv_into(inner.get_ref(), buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Await writability, then perform one non-blocking `send_to`.
    ///
    /// Only the `AF_PACKET` carriers address per-frame; raw IP is a connected
    /// socket and uses [`async_send`].
    #[cfg(target_os = "linux")]
    async fn async_send_to(fd: &AsyncFd<Socket>, buf: &[u8], addr: &SockAddr) -> io::Result<usize> {
        loop {
            let mut guard = fd.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send_to(buf, addr)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Await writability, then perform one non-blocking `send` on a connected
    /// socket.
    async fn async_send(fd: &AsyncFd<Socket>, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = fd.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Build an `AF_PACKET` `sockaddr_ll` for `interface`/`ethertype`, optionally
    /// targeting a specific destination MAC.
    ///
    /// Used both to `bind` the socket to a NIC (with `dst = None`) and to address
    /// each outbound frame (with `dst = Some(mac)`).  `ethertype` is stored in
    /// network byte order, as the kernel expects in `sll_protocol`.
    #[cfg(target_os = "linux")]
    fn link_sockaddr(ifindex: u32, ethertype: u16, dst: Option<Mac>) -> SockAddr {
        let mut storage = SockAddrStorage::zeroed();
        // SAFETY: `sockaddr_ll` is a valid `sockaddr_storage` view for AF_PACKET
        // and fits within the storage; we initialize only defined fields.
        let sll = unsafe { storage.view_as::<libc::sockaddr_ll>() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = ethertype.to_be();
        sll.sll_ifindex = ifindex as libc::c_int;
        if let Some(mac) = dst {
            sll.sll_halen = 6;
            sll.sll_addr[..6].copy_from_slice(&mac.0);
        }
        // SAFETY: `storage` now holds a fully-formed `sockaddr_ll` of the given
        // length.
        unsafe { SockAddr::new(storage, size_of::<libc::sockaddr_ll>() as socklen_t) }
    }

    /// Resolve a NIC name (e.g. `"eth0"`) to the IPv4 address configured on
    /// it.
    ///
    /// The IPv4 multicast socket options take an interface *address*, not the
    /// index [`interface_index`] returns: `IP_ADD_MEMBERSHIP` and
    /// `IP_MULTICAST_IF` both identify the NIC by one of its addresses on the
    /// portable (BSD-derived) `ip_mreq`/`in_addr` forms that `socket2` exposes.
    /// So a name has to be walked to an address, which is what `getifaddrs`
    /// is for.
    ///
    /// An interface with several IPv4 addresses yields the first the kernel
    /// lists; any of them identifies the same NIC to these options, so the
    /// choice does not matter. An interface with none — a v6-only or unnumbered
    /// NIC — is an error rather than a fall back to `INADDR_ANY`, because
    /// `INADDR_ANY` is precisely the "let the routing table pick" behavior the
    /// caller named an interface to avoid.
    pub(crate) fn interface_ipv4(name: &str) -> anyhow::Result<std::net::Ipv4Addr> {
        use std::net::Ipv4Addr;

        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: `head` is a valid out-pointer; on success the list it is set
        // to is freed by the `freeifaddrs` below, on every path out.
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return Err(anyhow::Error::from(std::io::Error::last_os_error())
                .context(format!("getifaddrs while resolving interface {name}")));
        }

        let mut found = None;
        // Tracked separately from `found` so a typo'd NIC name and a NIC with
        // no IPv4 address get different messages. They are different mistakes
        // with different fixes, and `interface_index` (the v6 path) already
        // distinguishes them — telling an operator to add an address to an
        // interface that does not exist sends them the wrong way entirely.
        let mut name_seen = false;
        let mut cur = head;
        // SAFETY: `cur` walks the kernel-allocated list from `head` until the
        // NUL terminator, and is only dereferenced while non-null. Every field
        // read below is initialized by `getifaddrs`; `ifa_addr` is explicitly
        // allowed to be null (an interface with no address for that family),
        // which the guard covers.
        while !cur.is_null() {
            let ifa = unsafe { &*cur };
            cur = ifa.ifa_next;

            if ifa.ifa_addr.is_null() {
                continue;
            }
            // SAFETY: `ifa_name` is a NUL-terminated C string owned by the
            // list, valid until `freeifaddrs`.
            let this = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) };
            if this.to_bytes() != name.as_bytes() {
                continue;
            }
            // Before the family test: an interface that exists but has only a
            // v6 address must still count as *seen*.
            name_seen = true;
            // SAFETY: non-null per the guard above, and `sa_family` is the
            // common prefix of every `sockaddr` variant, so reading it is
            // valid whatever the concrete family turns out to be.
            if unsafe { (*ifa.ifa_addr).sa_family } != libc::AF_INET as libc::sa_family_t {
                continue;
            }
            // SAFETY: the family check above establishes that `ifa_addr` points
            // at a `sockaddr_in`, which is what this reads.
            let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
            found = Some(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)));
            break;
        }

        // SAFETY: `head` is the list `getifaddrs` allocated above and has not
        // been freed; nothing borrows it past this point (`found` is a copied
        // address, not a pointer into the list).
        unsafe { libc::freeifaddrs(head) };

        match (found, name_seen) {
            (Some(addr), _) => Ok(addr),
            (None, true) => Err(anyhow::anyhow!(
                "network interface {name} has no IPv4 address to join a group on"
            )),
            (None, false) => Err(anyhow::anyhow!("no such network interface: {name}")),
        }
    }

    /// Resolve a NIC name (e.g. `"eth0"`) to its kernel interface index.
    pub(crate) fn interface_index(name: &str) -> anyhow::Result<u32> {
        let cstr = std::ffi::CString::new(name)?;
        // SAFETY: `cstr` is a valid NUL-terminated C string for the duration of
        // the call.
        let idx = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
        if idx == 0 {
            anyhow::bail!("no such network interface: {name}");
        }
        Ok(idx)
    }

    /// A native raw-L2 mesh interface: an `AF_PACKET`/`SOCK_RAW` socket bound to
    /// one NIC, carrying mesh frames under a configurable wire EtherType.
    ///
    /// Multi-access: [`send`](LinkT::send) addresses each frame by its
    /// destination MAC via `sendto`, so one socket reaches every peer on the
    /// segment (and `ff:ff:ff:ff:ff:ff` broadcasts).  Construct with
    /// [`build_raw_l2_link`].
    #[cfg(target_os = "linux")]
    pub struct RawL2Link {
        /// The reactor-registered packet socket.
        fd: AsyncFd<Socket>,
        /// Kernel index of the bound interface, used to address outbound frames.
        ifindex: u32,
        /// Wire EtherType this interface binds/filters on and stamps onto sent
        /// frames.  A transport label, kept independent of the mesh protocol the
        /// router demuxes on (see [`frame_into_buf`]).
        ethertype: u16,
        /// Mesh protocol this link carries — the value written into
        /// [`LinkFrame::protocol`] on receive so the router demuxes the frame
        /// (BATMAN's EtherType).  This is what decouples the wire `ethertype`
        /// from the router: the link translates between the two.
        mesh_protocol: u16,
        /// Scratch buffer holding the Ethernet bytes most recently sent or
        /// received off the wire.  On receive the EtherType is retagged in place
        /// to `mesh_protocol` (see [`retag_ethertype`]), yielding a [`LinkFrame`]
        /// with no copy, so no second buffer is needed.  Sized to
        /// [`MAX_LINK_FRAME_LEN`] like every other data-path buffer so a fully
        /// wrapped host frame is neither truncated on receive nor overruns
        /// [`frame_into_buf`] (a panic) on send.
        wire_buf: [u8; MAX_LINK_FRAME_LEN],
    }

    #[cfg(target_os = "linux")]
    impl LinkT for RawL2Link {
        /// One L2 segment: a directed copy goes to one station, but the
        /// merged frame the fan-out collapse builds is addressed to the
        /// broadcast MAC, which every station on the segment receives. So one
        /// send does reach every neighbor, the property the declaration
        /// claims, at the same threshold as the radios.
        fn fan_out(&self) -> Option<core::num::NonZeroU8> {
            wayfinder::link::BROADCAST_FAN_OUT
        }

        async fn send(
            &mut self,
            origin: Mac,
            data: &LinkFrameData<'_>,
        ) -> Result<usize, LinkError> {
            let Some(n) = frame_into_buf(origin, self.ethertype, data, &mut self.wire_buf) else {
                // The wrapped frame exceeds the wire buffer — only possible with a
                // host MTU set far above the recommended default. Drop it rather
                // than panic; the router already counts the common oversize case.
                tracing::trace!(
                    payload_len = data.payload.len(),
                    "drop: raw-l2 frame exceeds wire buffer"
                );
                return Ok(0);
            };
            let addr = link_sockaddr(self.ifindex, self.ethertype, Some(data.dst));
            async_send_to(&self.fd, &self.wire_buf[..n], &addr)
                .await
                .map_err(|e| {
                    tracing::warn!(error = ?e, "raw-l2 send failed");
                    LinkError::Io
                })?;
            Ok(n)
        }

        async fn recv(&mut self) -> Result<Received<'_>, LinkError> {
            let n = async_recv(&self.fd, &mut self.wire_buf)
                .await
                .map_err(|e| {
                    tracing::warn!(error = ?e, "raw-l2 recv failed");
                    LinkError::Io
                })?;
            if n < ETH_HEADER_LEN {
                return Err(LinkError::MalformedFrame);
            }
            // The wire EtherType is a transport label; retag it to this link's
            // mesh protocol so the bytes reinterpret as a `LinkFrame` the router
            // can demux — in place, no copy.
            retag_ethertype(&mut self.wire_buf, self.mesh_protocol);
            let frame = LinkFrame::ref_from_bytes(&self.wire_buf[..n])
                .map_err(|_| LinkError::MalformedFrame)?;
            // AF_PACKET carries no physical-layer signal information.
            Ok(Received {
                frame,
                metrics: LinkMetrics::default(),
            })
        }
    }

    /// Open, bind and configure an `AF_PACKET`/`SOCK_RAW` socket on `ifindex`
    /// for wire `ethertype`: non-blocking, and — best-effort — set to skip the
    /// kernel's loopback of this node's own transmitted frames back into its
    /// own receive queue (`PACKET_IGNORE_OUTGOING`, Linux ≥ 4.20; older kernels
    /// lack the option, so failure here is non-fatal). Shared by
    /// [`build_raw_l2_link`] and [`build_raw_l2_egress`] — both are raw-L2
    /// packet sockets differing only in what `ethertype` they bind/filter on
    /// and what they do with the bytes.
    #[cfg(target_os = "linux")]
    fn open_packet_socket(ifindex: u32, ethertype: u16) -> anyhow::Result<Socket> {
        let socket = Socket::new(
            Domain::PACKET,
            Type::RAW,
            Some(Protocol::from(i32::from(ethertype.to_be()))),
        )?;
        socket.bind(&link_sockaddr(ifindex, ethertype, None))?;
        socket.set_nonblocking(true)?;

        let on: libc::c_int = 1;
        // SAFETY: standard setsockopt with a correctly-sized `c_int` value.
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                SOL_PACKET,
                PACKET_IGNORE_OUTGOING,
                &on as *const _ as *const libc::c_void,
                size_of::<libc::c_int>() as socklen_t,
            );
        }

        Ok(socket)
    }

    /// Build a native raw-L2 mesh link bound to `interface`, filtering and
    /// stamping `ethertype`, type-erased as a [`LinkT`].
    ///
    /// `ethertype` is the wire transport label only; the link carries BATMAN and
    /// presents [`DEFAULT_BATMAN_ETHER_TYPE`] to the router on receive, so any
    /// `ethertype` works without being forced onto the router's protocol number.
    ///
    /// Requires `CAP_NET_RAW` (or root).  The socket ignores its own outgoing
    /// frames where the kernel supports it, so a frame this node transmits is not
    /// echoed back into [`recv`](LinkT::recv).
    ///
    /// Linux-only; see [the module documentation](self) for the non-Linux
    /// behaviour.
    #[cfg(target_os = "linux")]
    pub fn build_raw_l2_link(
        interface: &str,
        ethertype: u16,
    ) -> anyhow::Result<Box<DynLinkT<'static>>> {
        let ifindex = interface_index(interface)?;
        let socket = open_packet_socket(ifindex, ethertype)?;

        let link = RawL2Link {
            fd: AsyncFd::new(socket)?,
            ifindex,
            ethertype,
            mesh_protocol: DEFAULT_BATMAN_ETHER_TYPE,
            wire_buf: [0u8; MAX_LINK_FRAME_LEN],
        };
        Ok(DynLinkT::new_box(link))
    }

    /// A physical NIC presented to the driver as a host-frame transport: an
    /// `AF_PACKET`/`SOCK_RAW` socket bound to one interface with `ETH_P_ALL`, so
    /// it captures every frame on the wire rather than one transport EtherType.
    /// Plain byte-pipe passthrough — no EtherType retagging, and (unlike
    /// [`RawL2Link`]) no mesh-protocol framing on send, since the bytes handed
    /// to [`send`](FrameIo::send) are already a whole Ethernet frame, the same
    /// shape the kernel TAP device produces and consumes. Construct with
    /// [`build_raw_l2_egress`].
    #[cfg(target_os = "linux")]
    pub struct RawL2Egress {
        /// The reactor-registered packet socket.
        fd: AsyncFd<Socket>,
        /// Kernel index of the bound interface, used to address outbound frames.
        ifindex: u32,
    }

    #[cfg(target_os = "linux")]
    #[cfg_attr(feature = "std", async_trait::async_trait)]
    impl FrameIo for RawL2Egress {
        async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            async_recv(&self.fd, buf).await
        }

        async fn send(&self, buf: &[u8]) -> io::Result<usize> {
            // The frame carries its own destination MAC (it is Ethernet-shaped,
            // like everything TAP passes through) — that MAC is what a packet
            // socket's `sendto` needs to address, not anything this carrier
            // decides on its own.
            let Some(dst) = frame_dst_mac(buf) else {
                tracing::trace!(
                    len = buf.len(),
                    "drop: egress frame too short for a destination address"
                );
                return Ok(0);
            };
            let addr = link_sockaddr(self.ifindex, libc::ETH_P_ALL as u16, Some(dst));
            async_send_to(&self.fd, buf, &addr).await
        }
    }

    /// Build a raw-L2 egress carrier bound to `interface`, type-erased as
    /// [`FrameIo`].
    ///
    /// Requires `CAP_NET_RAW` (or root). Wayfinder does not create or address
    /// this interface — it must already exist and be up. The socket ignores its
    /// own outgoing frames where the kernel supports it (see
    /// [`open_packet_socket`]), so this node's own transmissions — including a
    /// co-located DHCP server's broadcast replies bound to this same interface —
    /// are never read back and forwarded into the mesh.
    ///
    /// Linux-only; see [the module documentation](self) for the non-Linux
    /// behaviour.
    #[cfg(target_os = "linux")]
    pub fn build_raw_l2_egress(interface: &str) -> anyhow::Result<RawL2Egress> {
        let ifindex = interface_index(interface)?;
        let socket = open_packet_socket(ifindex, libc::ETH_P_ALL as u16)?;
        Ok(RawL2Egress {
            fd: AsyncFd::new(socket)?,
            ifindex,
        })
    }

    /// The non-Linux stand-in for the `AF_PACKET` egress carrier.
    ///
    /// Uninhabited on purpose: there is no packet socket to hold, and making
    /// that a type-level fact means every `FrameIo` method below is discharged
    /// by an empty match rather than by a panic or a placeholder value. It
    /// exists only so [`build_raw_l2_egress`]'s signature — and therefore
    /// every caller that builds a local egress from a config — is identical on
    /// all platforms.
    #[cfg(not(target_os = "linux"))]
    pub enum RawL2Egress {}

    #[cfg(not(target_os = "linux"))]
    #[cfg_attr(feature = "std", async_trait::async_trait)]
    impl FrameIo for RawL2Egress {
        async fn recv(&self, _buf: &mut [u8]) -> io::Result<usize> {
            match *self {}
        }

        async fn send(&self, _buf: &[u8]) -> io::Result<usize> {
            match *self {}
        }
    }

    /// The non-Linux counterpart of the raw-L2 mesh link; always fails. See
    /// [the module documentation](self).
    #[cfg(not(target_os = "linux"))]
    pub fn build_raw_l2_link(
        _interface: &str,
        _ethertype: u16,
    ) -> anyhow::Result<Box<DynLinkT<'static>>> {
        anyhow::bail!(
            "raw-L2 mesh links are supported on Linux only (they need an \
             AF_PACKET socket, which this host has no equivalent of); use a \
             `udp` link instead, or run this node on Linux"
        )
    }

    /// The non-Linux counterpart of the raw-L2 egress carrier; always fails.
    /// See [the module documentation](self).
    #[cfg(not(target_os = "linux"))]
    pub fn build_raw_l2_egress(_interface: &str) -> anyhow::Result<RawL2Egress> {
        anyhow::bail!(
            "raw-L2 local egress is supported on Linux only (it needs an \
             AF_PACKET socket, which this host has no equivalent of); use a \
             `tap` egress instead, or run this node on Linux"
        )
    }

    /// Build a point-to-point mesh link carried over a raw IPv4 socket, type-
    /// erased as a [`LinkT`].
    ///
    /// The mirror image of [`build_udp_link`](crate::build_udp_link): an
    /// `AF_INET`/`SOCK_RAW` socket bound to `bind_addr` and connected to
    /// `remote_addr` over IP protocol number `protocol`, carrying our opaque
    /// framing as the IP payload.  The router speaks to an in-process
    /// [`UnixDatagram`]; a spawned bridge copies frames both ways, **stripping
    /// the IPv4 header** off each received datagram (the kernel delivers it on a
    /// raw-IP socket) before handing the frame to the [`Link`] adapter.  The
    /// bridge task is spawned into `join_set` so its lifetime is tied to the
    /// caller's.
    ///
    /// Requires `CAP_NET_RAW` (or root).
    pub async fn build_raw_ip_link(
        bind_addr: IpAddr,
        remote_addr: IpAddr,
        protocol: u8,
        join_set: &mut JoinSet<anyhow::Result<()>>,
    ) -> anyhow::Result<Box<DynLinkT<'static>>> {
        let domain = match bind_addr {
            IpAddr::V4(_) => Domain::IPV4,
            IpAddr::V6(_) => Domain::IPV6,
        };
        let socket = Socket::new(domain, Type::RAW, Some(Protocol::from(protocol as i32)))?;
        // Port 0: raw sockets are protocol-, not port-, addressed.
        socket.bind(&std::net::SocketAddr::new(bind_addr, 0).into())?;
        socket.connect(&std::net::SocketAddr::new(remote_addr, 0).into())?;
        socket.set_nonblocking(true)?;
        let raw_fd = AsyncFd::new(socket)?;

        let (bridge, router_side) = UnixDatagram::pair()?;

        join_set.spawn(async move {
            let mut rx_buf = [0u8; MAX_LINK_FRAME_LEN];
            let mut tx_buf = [0u8; MAX_LINK_FRAME_LEN];
            loop {
                tokio::select! {
                    res = async_recv(&raw_fd, &mut rx_buf) => match res {
                        Ok(n) => {
                            // Raw-IP recv includes the IPv4 header; skip it so the
                            // adapter sees only our framing.
                            if let Some(off) = ipv4_payload_offset(&rx_buf[..n])
                                && let Err(e) = bridge.send(&rx_buf[off..n]).await
                            {
                                tracing::warn!(error = ?e, "raw-ip bridge to in-process socket failed");
                            }
                        }
                        // A recv error here is usually transient (e.g. an ICMP
                        // error surfaced on a connected raw socket), so keep the
                        // bridge up and retry rather than tearing the link down.
                        Err(e) => tracing::warn!(error = ?e, "raw-ip recv failed"),
                    },
                    res = bridge.recv(&mut tx_buf) => match res {
                        // Send the framing verbatim; the kernel prepends the IP header.
                        Ok(n) => {
                            if let Err(e) = async_send(&raw_fd, &tx_buf[..n]).await {
                                tracing::warn!(error = ?e, "raw-ip bridge to off-process socket failed");
                            }
                        }
                        // The router side of the bridge is gone; nothing left to do.
                        Err(e) => {
                            tracing::warn!(error = ?e, "raw-ip bridge recv failed; closing bridge");
                            break;
                        }
                    },
                }
            }
            Ok(())
        });

        Ok(DynLinkT::new_box(Link::new(router_side)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use interfaces::frame::LinkFrame;
    use interfaces::frame::LinkFrameData;
    use interfaces::wire::ETH_HEADER_LEN;
    use interfaces::wire::frame_into_buf;
    use interfaces::wire::retag_ethertype;
    use zerocopy::FromBytes;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// A raw-L2 egress frame is Ethernet-shaped (`[dst][src][ethertype][payload]`,
    /// the same layout `frame_into_buf` writes and `TapDevice` passes through
    /// verbatim), so the destination address to `sendto` on is just its leading
    /// six bytes.
    #[test]
    fn frame_dst_mac_reads_leading_six_bytes() {
        let mut wire = [0u8; 32];
        let n = frame_into_buf(
            mac(3),
            0x0800,
            &LinkFrameData {
                dst: mac(9),
                protocol: 0x0800,
                payload: &[1, 2, 3],
            },
            &mut wire,
        )
        .expect("frame fits buffer");
        assert_eq!(frame_dst_mac(&wire[..n]), Some(mac(9)));
    }

    /// A buffer shorter than a MAC address (6 bytes) has no destination to
    /// extract, so `send` on such a frame should drop it rather than read past
    /// the end or address it with garbage.
    #[test]
    fn frame_dst_mac_rejects_short_buffer() {
        assert_eq!(frame_dst_mac(&[0, 0, 0, 0, 0]), None);
        assert_eq!(frame_dst_mac(&[]), None);
    }

    /// A frame sent under a custom wire EtherType retags on receive into a
    /// `LinkFrame` whose `protocol` is the *mesh* protocol (not the wire
    /// EtherType), so the router demuxes it correctly even though the wire
    /// carried an arbitrary EtherType — and with no length change.
    #[test]
    fn custom_ethertype_retags_to_mesh_protocol() {
        let mut wire = [0u8; 64];
        let payload = [1, 2, 3, 4, 5];
        let n = frame_into_buf(
            mac(7),
            0xfafa,
            &LinkFrameData {
                dst: mac(8),
                protocol: 0x4305,
                payload: &payload,
            },
            &mut wire,
        )
        .expect("frame fits buffer");
        // On the wire the EtherType is the configured carrier, not 0x4305.
        assert_eq!(&wire[12..14], &[0xfa, 0xfa]);

        // Receive side: retag the EtherType to the mesh protocol in place.
        retag_ethertype(&mut wire, 0x4305);
        let frame = LinkFrame::ref_from_bytes(&wire[..n]).unwrap();
        assert_eq!(frame.src, mac(7));
        assert_eq!(frame.dst, mac(8));
        assert_eq!(frame.protocol.get(), 0x4305); // mesh protocol restored for demux
        assert_eq!(&frame.payload, &payload);
    }

    /// Retagging is correct for an empty payload (the minimum-length frame),
    /// leaving just `[dst][src][protocol]`.
    #[test]
    fn retag_handles_empty_payload() {
        let mut wire = [0u8; 32];
        let n = frame_into_buf(
            mac(3),
            0x88b5,
            &LinkFrameData {
                dst: mac(4),
                protocol: 0x4305,
                payload: &[],
            },
            &mut wire,
        )
        .expect("frame fits buffer");
        assert_eq!(n, ETH_HEADER_LEN);
        retag_ethertype(&mut wire, 0x4305);
        let frame = LinkFrame::ref_from_bytes(&wire[..n]).unwrap();
        assert_eq!(frame.dst, mac(4));
        assert_eq!(frame.src, mac(3));
        assert_eq!(frame.protocol.get(), 0x4305);
        assert!(frame.payload.is_empty());
    }

    /// A minimal (no-options) IPv4 header is 20 bytes, so the payload begins at
    /// offset 20.
    #[test]
    fn ipv4_payload_offset_skips_minimal_header() {
        let mut datagram = [0u8; 24];
        datagram[0] = 0x45; // version 4, IHL 5 words = 20 bytes
        assert_eq!(ipv4_payload_offset(&datagram), Some(20));
    }

    /// The IHL field is honoured, so a header carrying options is skipped in
    /// full.
    #[test]
    fn ipv4_payload_offset_honours_ihl_with_options() {
        let mut datagram = [0u8; 40];
        datagram[0] = 0x46; // version 4, IHL 6 words = 24 bytes
        assert_eq!(ipv4_payload_offset(&datagram), Some(24));
    }

    /// Non-IPv4 first nibbles, sub-minimum IHL, and headers longer than the
    /// datagram are all rejected.
    #[test]
    fn ipv4_payload_offset_rejects_malformed() {
        assert_eq!(ipv4_payload_offset(&[]), None);
        assert_eq!(ipv4_payload_offset(&[0x60]), None); // IPv6
        assert_eq!(ipv4_payload_offset(&[0x44]), None); // IHL 4 words = 16 < 20
        assert_eq!(ipv4_payload_offset(&[0x45, 0, 0]), None); // header longer than datagram
    }
}
