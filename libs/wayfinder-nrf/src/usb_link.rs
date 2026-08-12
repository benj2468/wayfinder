//! A mesh interface over the USB device peripheral, as a CDC-NCM (USB
//! Ethernet) function.
//!
//! This is the wired counterpart to the board's LoRa and BLE radios: the host
//! the dongle is plugged into becomes a mesh neighbour, so a Linux node can
//! reach the LoRa/BLE mesh through the board without a second radio.
//!
//! # Why NCM, and why there is no host-side driver
//!
//! [`LinkFrame`] *is* an Ethernet frame — `[dst][src][ethertype][payload]`, in
//! that order, with the protocol big-endian — precisely so a carrier whose
//! medium is real Ethernet needs no conversion. CDC-NCM carries whole Ethernet
//! datagrams with their own boundaries, so a frame goes out with one
//! `write_packet` and comes back with one `read_packet`: no length prefix, no
//! fragmentation.
//!
//! The consequence is that **the host side needs no new code at all**. The
//! board enumerates as an ordinary network interface, and `wayfinder-tap`'s
//! existing raw-L2 carrier binds straight to it:
//!
//! ```yaml
//! - transport: !RawL2
//!     interface: wf-usb0
//!     ethertype: 0xfafa
//! ```
//!
//! That `ethertype` **must equal [`MESH_ETHERTYPE`]**. It is the wire transport
//! label both ends filter on, deliberately distinct from the mesh protocol the
//! router demuxes (BATMAN's `0x4305`) so the link can share a NIC with
//! unrelated traffic — including the host kernel's own IPv6 solicitations and
//! mDNS, which arrive here and are dropped. A mismatch is silent: both ends
//! come up and no frame is ever accepted.
//!
//! # Why the receive side is a task and a queue
//!
//! **`LinkT::recv` must be cancel-safe here**, and the USB class's is not.
//! `wayfinder_embedded_driver` builds one `recv` future per link, races them
//! against the OGM timer with `select_array`, and **drops every loser** — so a
//! `recv` is torn down on each timer tick and each frame from any other link.
//!
//! `Receiver::read_packet` accumulates a multi-packet NTB across several
//! `read_ep.read()` awaits, holding the partial transfer in a stack local;
//! `Receiver::wait_connection` writes an 8-byte `NETWORK_CONNECTION`
//! notification to the interrupt endpoint. Cancelling either mid-flight loses
//! the partial NTB and leaves the host's stream half-consumed, which
//! desynchronises the framing and disrupts the shared device — including the
//! CDC-ACM management port on the same [`UsbDevice`](embassy_usb::UsbDevice).
//!
//! So the USB reads live in a spawned task that is never cancelled, and `recv`
//! only awaits a channel, which is cancel-safe. This mirrors `blue`'s
//! `ReportQueue`, for the same reason.
//!
//! [`LinkFrame`]: wayfinder::interfaces::frame::LinkFrame

use embassy_executor::SpawnError;
use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_usb::Builder;
use embassy_usb::class::cdc_ncm::CdcNcmClass;
use embassy_usb::class::cdc_ncm::Receiver;
use embassy_usb::class::cdc_ncm::Sender;
use embassy_usb::class::cdc_ncm::State;
use embassy_usb::driver::EndpointError;
use static_cell::StaticCell;
use tracing::debug;
use tracing::trace;
use wayfinder::DEFAULT_BATMAN_ETHER_TYPE;
use wayfinder::interfaces::frame::LinkFrame;
use wayfinder::interfaces::frame::LinkFrameData;
use wayfinder::interfaces::frame::MAX_LINK_FRAME_LEN;
use wayfinder::interfaces::frame::Mac;
use wayfinder::interfaces::link::LinkError;
use wayfinder::interfaces::link::LinkMetrics;
use wayfinder::interfaces::wire::ETH_HEADER_LEN;
use wayfinder::interfaces::wire::frame_into_buf;
use wayfinder::interfaces::wire::retag_ethertype;
use wayfinder::interfaces::wire::wire_ethertype;
use wayfinder::link::LinkT;
use wayfinder::link::Received;
use zerocopy::FromBytes;

use crate::usb_mgmt::UsbDriver;

/// Wire EtherType this link stamps on send and filters on receive.
///
/// A transport label, not the mesh protocol — see the module docs. `0xfafa` is
/// in the range no registered EtherType uses, and is the value the host's
/// `RawL2` link must be configured with.
pub const MESH_ETHERTYPE: u16 = 0xfafa;

/// Bulk endpoint packet size. 64 is the maximum a full-speed device may use,
/// which is what the nRF52840 enumerates as.
const MAX_PACKET_SIZE: u16 = 64;

/// The largest mesh frame this link carries in either direction: the largest
/// frame this board's router can stage, plus the Ethernet header wrapped around
/// it.
///
/// Note this is *not* the largest datagram the host can put on the interface —
/// it brings the link up at MTU 1500 — only the largest one worth keeping. The
/// receive task drops anything longer, because the router could not accept it
/// anyway. See [`NTB_LANDING_LEN`] for the buffer that has to absorb the rest.
const MAX_MESH_FRAME_LEN: usize = crate::nrf52840::MAX_FRAME_LEN + ETH_HEADER_LEN;

/// Size of the buffer `read_packet` copies a received datagram into.
///
/// **Load-bearing, and larger than [`MAX_MESH_FRAME_LEN`] on purpose.**
/// `Receiver::read_packet` copies the datagram in with no length check of its
/// own, so a datagram larger than this buffer panics inside `embassy-usb`. The
/// host decides that length, not us; the only bound is the 2048-byte NTB the
/// datagram was parsed out of, which is what [`MAX_LINK_FRAME_LEN`] matches.
/// Filtering happens *after* the copy, so this cannot shrink to the frame size
/// we actually accept.
const NTB_LANDING_LEN: usize = MAX_LINK_FRAME_LEN;

/// Depth of the queue between the USB receive task and `recv`'s consumer.
///
/// The producer drops rather than blocking when this fills (see
/// [`usb_ncm_rx_task`] for why blocking is not an option on USB), so this is
/// the burst the link absorbs while the driver's event loop is busy elsewhere —
/// a BLE advertising session or a LoRa `send`, either of which can stall it for
/// hundreds of milliseconds. Four frames at the router's frame capacity is
/// ~2 KB, the point where widening it costs more RAM than the extra tolerance
/// is worth on this part.
const RX_QUEUE_DEPTH: usize = 4;

/// One received mesh frame, already filtered and retagged, on its way from the
/// USB receive task to [`UsbNcmLink::recv`].
struct RxFrame {
    data: [u8; MAX_MESH_FRAME_LEN],
    len: usize,
}

/// Bridges the USB receive task to `recv`'s async consumer.
///
/// A `CriticalSectionRawMutex` rather than `blue`'s `NoopRawMutex`-plus-`unsafe
/// impl Sync`: the critical section is taken once per whole frame, not per byte,
/// and `nrf-softdevice`'s `critical-section-impl` masks only non-reserved IRQs,
/// so it cannot starve the radio the way `critical-section-single-core` would.
/// Cheap enough here to be worth not hand-writing another `Sync`.
static RX_QUEUE: Channel<CriticalSectionRawMutex, RxFrame, RX_QUEUE_DEPTH> = Channel::new();

/// Everything that can go wrong bringing the USB device up.
#[derive(Debug)]
pub enum UsbInitError {
    /// A SoftDevice syscall failed — see [`crate::usb_mgmt::init`] for which
    /// power and clock state USB needs and why it is reachable only that way.
    Softdevice(nrf_softdevice::RawError),
    /// The CDC-NCM receive task could not be spawned, so the mesh link would
    /// have no producer. See [`usb_ncm_rx_task`].
    Spawn(SpawnError),
}

impl From<nrf_softdevice::RawError> for UsbInitError {
    fn from(e: nrf_softdevice::RawError) -> Self {
        Self::Softdevice(e)
    }
}

impl From<SpawnError> for UsbInitError {
    fn from(e: SpawnError) -> Self {
        Self::Spawn(e)
    }
}

/// Drain CDC-NCM datagrams for the node's lifetime, queueing the mesh frames
/// among them.
///
/// This runs as its own task precisely so it is never cancelled — see the
/// module docs. Everything cancellation would corrupt is therefore contained
/// here: the multi-packet NTB read, and the connection notification.
#[embassy_executor::task]
async fn usb_ncm_rx_task(mut rx: Receiver<'static, UsbDriver>) -> ! {
    static LANDING: StaticCell<[u8; NTB_LANDING_LEN]> = StaticCell::new();
    let buf = LANDING.init([0; NTB_LANDING_LEN]);

    loop {
        let n = match rx.read_packet(buf).await {
            Ok(n) => n,
            Err(e) => {
                // No host has the interface enabled — an unplugged dongle, or
                // one whose host has not brought the link up. That is the
                // resting state of a deployed node, not a fault, and
                // `wait_connection` parks on `wait_enabled` rather than
                // spinning.
                debug!(?e, "usb mesh link down; waiting for host");
                if rx.wait_connection().await.is_ok() {
                    debug!("usb mesh link up");
                }
                continue;
            }
        };

        // The interface carries whatever else the host puts on it — IPv6 router
        // solicitation and duplicate-address detection, mDNS — so anything not
        // bearing our transport label is somebody else's.
        if wire_ethertype(&buf[..n]) != Some(MESH_ETHERTYPE) {
            trace!(len = n, "drop: not a mesh frame");
            continue;
        }
        if n > MAX_MESH_FRAME_LEN {
            trace!(len = n, "drop: mesh frame exceeds router frame capacity");
            continue;
        }

        // Retag the wire transport label to the mesh protocol, so what reaches
        // `recv` is already a `LinkFrame` the router can demux.
        retag_ethertype(&mut buf[..n], DEFAULT_BATMAN_ETHER_TYPE);

        let mut frame = RxFrame {
            data: [0; MAX_MESH_FRAME_LEN],
            len: n,
        };
        frame.data[..n].copy_from_slice(&buf[..n]);
        // Drops rather than blocking when the driver is behind, matching
        // `blue`'s ReportQueue.
        //
        // Blocking here would look like backpressure and isn't: with no read
        // armed, the nRF NAKs the bulk OUT endpoint for as long as the driver
        // is busy — and the driver's event loop stalls for a whole BLE
        // advertising session or a multi-hundred-millisecond LoRa `send`. The
        // host controller times a transfer out long before that, which
        // surfaces as an xHCI transaction error and a device reset, not as a
        // slowed-down sender. A mesh link is lossy by definition and OGMs
        // repeat, so shedding a frame is the cheap failure.
        if RX_QUEUE.try_send(frame).is_err() {
            trace!("drop: usb rx queue full");
        }
    }
}

/// Derive the MAC the *host's* network interface takes, from this node's mesh
/// MAC.
///
/// These must differ: they are two endpoints on one Ethernet segment, and a
/// host whose NIC carries the same address as its neighbour sees its own
/// traffic reflected. The low bit of the last octet is flipped, which always
/// changes the address; the first octet is additionally marked
/// locally-administered and unicast, since this is a synthesized address rather
/// than one from an assigned OUI.
///
/// Our own frames are unaffected either way — [`frame_into_buf`] stamps the
/// node's mesh MAC as the source, and the host's raw socket transmits that
/// verbatim — so this address only ever appears on the host's own traffic.
fn host_nic_mac(node: Mac) -> [u8; 6] {
    let mut mac = node.0;
    mac[0] = (mac[0] | 0x02) & 0xfe;
    mac[5] ^= 0x01;
    mac
}

/// A mesh interface carried over CDC-NCM.
///
/// Built by [`crate::usb_mgmt::init`], which owns the one USB device the board
/// enumerates; this is one function on it, alongside the CDC-ACM management
/// port.
pub struct UsbNcmLink {
    tx: Sender<'static, UsbDriver>,
    /// Scratch buffer for the Ethernet bytes of the frame being sent.
    ///
    /// Cancellation-safe without a task, unlike the receive side: the driver
    /// awaits `dispatch` *after* its `select` resolves, so a `send` is never
    /// raced and never dropped mid-transfer.
    tx_buf: [u8; MAX_MESH_FRAME_LEN],
    /// Holds the frame most recently taken off [`RX_QUEUE`], for `recv` to
    /// borrow out as a [`LinkFrame`].
    rx_frame: [u8; MAX_MESH_FRAME_LEN],
}

impl UsbNcmLink {
    /// Add a CDC-NCM function to `builder`, spawn its receive task, and return
    /// it as a mesh link.
    ///
    /// `node_mac` is this node's mesh identifier; the host-side interface takes
    /// a derived address (see [`host_nic_mac`]).
    pub fn new(
        builder: &mut Builder<'static, UsbDriver>,
        node_mac: Mac,
        spawner: Spawner,
    ) -> Result<Self, SpawnError> {
        static STATE: StaticCell<State<'static>> = StaticCell::new();

        let class = CdcNcmClass::new(
            builder,
            STATE.init(State::new()),
            host_nic_mac(node_mac),
            MAX_PACKET_SIZE,
        );
        let (tx, rx) = class.split();
        spawner.spawn(usb_ncm_rx_task(rx)?);

        Ok(Self {
            tx,
            tx_buf: [0; MAX_MESH_FRAME_LEN],
            rx_frame: [0; MAX_MESH_FRAME_LEN],
        })
    }
}

impl LinkT for UsbNcmLink {
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        let Some(n) = frame_into_buf(origin, MESH_ETHERTYPE, data, &mut self.tx_buf) else {
            trace!(
                payload_len = data.payload.len(),
                "drop: usb frame exceeds wire buffer"
            );
            return Ok(0);
        };
        match self.tx.write_packet(&self.tx_buf[..n]).await {
            Ok(()) => Ok(n),
            // No host has the interface enabled. `NotPresent` keeps it out of
            // the transmit-rate estimator and below `warn!`, the same treatment
            // an unwired radio slot gets.
            Err(EndpointError::Disabled) => Err(LinkError::NotPresent),
            Err(EndpointError::BufferOverflow) => Err(LinkError::BufferFull),
        }
    }

    /// Cancel-safe: the only await is [`RX_QUEUE`]'s receive, which either
    /// yields a whole frame or leaves the queue untouched. See the module docs
    /// for why that matters.
    async fn recv(&mut self) -> Result<Received<'_>, LinkError> {
        let frame = RX_QUEUE.receive().await;
        let len = frame.len;
        self.rx_frame[..len].copy_from_slice(&frame.data[..len]);

        let frame = LinkFrame::ref_from_bytes(&self.rx_frame[..len])
            .map_err(|_| LinkError::InvalidPacket)?;
        // USB carries no physical-layer signal information.
        Ok(Received {
            frame,
            metrics: LinkMetrics::default(),
        })
    }
}
