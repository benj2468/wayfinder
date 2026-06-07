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
//! * **Raw L2** ([`RawL2Link`]) is a native multi-access interface: an
//!   `AF_PACKET`/`SOCK_RAW` socket bound to one NIC.  Because [`LinkFrame`] is
//!   already Ethernet-shaped (`[dst][src][ethertype][payload]`, big-endian type),
//!   our frame *is* the Ethernet frame: send serializes a `LinkFrame` straight
//!   onto the wire and recv reinterprets the received bytes as a `LinkFrame` with
//!   no conversion.  It implements [`LinkT`] directly and routes each frame by
//!   its destination MAC.
//!
//! [`transport`]: crate::transport
//! [`Link`]: crate::transport::Link

use interfaces::{
    frame::{LinkFrame, LinkFrameData, Mac},
    link::{LinkError, LinkMetrics},
};
use zerocopy::FromBytes;

/// Length of the [`LinkFrame`]/Ethernet header: `[dst: 6][src: 6][ethertype: 2]`.
const ETH_HEADER_LEN: usize = 14;

/// Serialize `origin` + `data` as a [`LinkFrame`] (i.e. an Ethernet frame) into
/// `buf`, returning its length.
///
/// Wire layout `[dst: Mac][src: Mac][ethertype: u16 big-endian][payload]`.  Since
/// [`LinkFrame`] is defined with exactly this layout, the result is both a valid
/// `LinkFrame` and a valid Ethernet frame — no separate conversion is needed on
/// the receive side, which simply reinterprets the bytes via
/// [`LinkFrame::ref_from_bytes`].
fn frame_into_buf(origin: Mac, data: &LinkFrameData<'_>, buf: &mut [u8]) -> usize {
    buf[0..6].copy_from_slice(&data.dst.0);
    buf[6..12].copy_from_slice(&origin.0);
    buf[12..14].copy_from_slice(&data.protocol.to_be_bytes());
    buf[ETH_HEADER_LEN..ETH_HEADER_LEN + data.payload.len()].copy_from_slice(data.payload);
    ETH_HEADER_LEN + data.payload.len()
}

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

#[cfg(feature = "tokio")]
pub use tokio_impl::{RawL2Link, build_raw_ip_link, build_raw_l2_link};

#[cfg(feature = "tokio")]
mod tokio_impl {
    use super::*;

    use std::io;
    use std::mem::{MaybeUninit, size_of};
    use std::net::IpAddr;
    use std::os::fd::AsRawFd;

    use socket2::{Domain, Protocol, SockAddr, SockAddrStorage, Socket, Type, socklen_t};
    use tokio::io::unix::AsyncFd;
    use tokio::net::UnixDatagram;
    use tokio::task::JoinSet;

    use crate::transport::Link;
    use wayfinder::link::{DynLinkT, LinkT, Received};

    /// `SOL_PACKET` setsockopt level (not exported by `libc` on all targets).
    const SOL_PACKET: libc::c_int = 263;
    /// `PACKET_IGNORE_OUTGOING`: stop the kernel looping our own transmitted
    /// frames back into our receive queue (Linux ≥ 4.20).  Best-effort.
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

    /// Resolve a NIC name (e.g. `"eth0"`) to its kernel interface index.
    fn interface_index(name: &str) -> anyhow::Result<u32> {
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
    /// one NIC, mapping our frames directly onto Ethernet frames.
    ///
    /// Multi-access: [`send`](LinkT::send) addresses each frame by its
    /// destination MAC via `sendto`, so one socket reaches every peer on the
    /// segment (and `ff:ff:ff:ff:ff:ff` broadcasts).  Construct with
    /// [`build_raw_l2_link`].
    pub struct RawL2Link {
        /// The reactor-registered packet socket.
        fd: AsyncFd<Socket>,
        /// Kernel index of the bound interface, used to address outbound frames.
        ifindex: u32,
        /// EtherType this interface filters on / stamps onto sent frames.
        ethertype: u16,
        /// Scratch buffer holding the Ethernet/[`LinkFrame`] bytes most recently
        /// sent or received off the wire.  Received bytes are reinterpreted in
        /// place as a [`LinkFrame`], so no second buffer is needed.
        wire_buf: [u8; 1514],
    }

    impl LinkT for RawL2Link {
        async fn send(
            &mut self,
            origin: Mac,
            data: &LinkFrameData<'_>,
        ) -> Result<usize, LinkError> {
            let n = frame_into_buf(origin, data, &mut self.wire_buf);
            let addr = link_sockaddr(self.ifindex, self.ethertype, Some(data.dst));
            async_send_to(&self.fd, &self.wire_buf[..n], &addr)
                .await
                .map_err(|e| {
                    tracing::error!("raw-l2 send failed: {e:?}");
                    LinkError::Io
                })?;
            Ok(n)
        }

        async fn recv(&mut self) -> Result<Received<'_>, LinkError> {
            let n = async_recv(&self.fd, &mut self.wire_buf)
                .await
                .map_err(|e| {
                    tracing::error!("raw-l2 recv failed: {e:?}");
                    LinkError::Io
                })?;
            // `LinkFrame` is Ethernet-shaped, so the received bytes are already a
            // valid frame — reinterpret them with no conversion.
            let frame = LinkFrame::ref_from_bytes(&self.wire_buf[..n])
                .map_err(|_| LinkError::InvalidPacket)?;
            // AF_PACKET carries no physical-layer signal information.
            Ok(Received {
                frame,
                metrics: LinkMetrics::default(),
            })
        }
    }

    /// Build a native raw-L2 mesh link bound to `interface`, filtering and
    /// stamping `ethertype`, type-erased as a [`LinkT`].
    ///
    /// Requires `CAP_NET_RAW` (or root).  The socket ignores its own outgoing
    /// frames where the kernel supports it, so a frame this node transmits is not
    /// echoed back into [`recv`](LinkT::recv).
    pub fn build_raw_l2_link(
        interface: &str,
        ethertype: u16,
    ) -> anyhow::Result<Box<DynLinkT<'static>>> {
        let ifindex = interface_index(interface)?;
        let socket = Socket::new(
            Domain::PACKET,
            Type::RAW,
            Some(Protocol::from(i32::from(ethertype.to_be()))),
        )?;
        socket.bind(&link_sockaddr(ifindex, ethertype, None))?;
        socket.set_nonblocking(true)?;

        // Best-effort: suppress kernel loopback of our own transmissions.  Older
        // kernels lack the option; a failure here is non-fatal.
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

        let link = RawL2Link {
            fd: AsyncFd::new(socket)?,
            ifindex,
            ethertype,
            wire_buf: [0u8; 1514],
        };
        Ok(DynLinkT::new_box(link))
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
            let mut rx_buf = [0u8; 1500];
            let mut tx_buf = [0u8; 1500];
            loop {
                tokio::select! {
                    res = async_recv(&raw_fd, &mut rx_buf) => match res {
                        Ok(n) => {
                            // Raw-IP recv includes the IPv4 header; skip it so the
                            // adapter sees only our framing.
                            if let Some(off) = ipv4_payload_offset(&rx_buf[..n])
                                && let Err(e) = bridge.send(&rx_buf[off..n]).await
                            {
                                tracing::error!("raw-ip bridge to in-process socket: {e:?}");
                            }
                        }
                        Err(e) => tracing::error!("raw-ip recv: {e:?}"),
                    },
                    res = bridge.recv(&mut tx_buf) => match res {
                        // Send the framing verbatim; the kernel prepends the IP header.
                        Ok(n) => {
                            if let Err(e) = async_send(&raw_fd, &tx_buf[..n]).await {
                                tracing::error!("raw-ip bridge to off-process socket: {e:?}");
                            }
                        }
                        Err(e) => tracing::error!("raw-ip bridge recv: {e:?}"),
                    },
                }
            }
        });

        Ok(DynLinkT::new_box(Link::new(router_side)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// `frame_into_buf` lays down a genuine Ethernet frame: destination first,
    /// then source, then the EtherType **big-endian**, then the payload — which
    /// is exactly the `LinkFrame` layout.
    #[test]
    fn frame_into_buf_writes_ethernet_layout() {
        let mut buf = [0u8; 64];
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let n = frame_into_buf(
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0x4305,
                payload: &payload,
            },
            &mut buf,
        );
        assert_eq!(n, ETH_HEADER_LEN + payload.len());
        assert_eq!(&buf[0..6], &mac(2).0); // Ethernet destination
        assert_eq!(&buf[6..12], &mac(1).0); // Ethernet source
        assert_eq!(&buf[12..14], &[0x43, 0x05]); // EtherType, big-endian
        assert_eq!(&buf[14..n], &payload);
    }

    /// The bytes `frame_into_buf` produces reinterpret directly as the same
    /// `LinkFrame` — the zero-copy recv path the raw-L2 link relies on, with no
    /// MAC swap or endian conversion.
    #[test]
    fn frame_into_buf_reinterprets_as_link_frame() {
        let mut wire = [0u8; 64];
        let payload = [1, 2, 3, 4, 5];
        let n = frame_into_buf(
            mac(7),
            &LinkFrameData {
                dst: mac(8),
                protocol: 0x4305,
                payload: &payload,
            },
            &mut wire,
        );

        let frame = LinkFrame::ref_from_bytes(&wire[..n]).unwrap();
        assert_eq!(frame.src, mac(7));
        assert_eq!(frame.dst, mac(8));
        assert_eq!(frame.protocol.get(), 0x4305);
        assert_eq!(&frame.payload, &payload);
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
