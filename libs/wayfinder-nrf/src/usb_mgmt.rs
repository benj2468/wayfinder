//! The board's USB device: the management API as a CDC-ACM (USB serial) port,
//! and a mesh interface as a CDC-NCM (USB Ethernet) function.
//!
//! A host runs `wayfinder-tui` or `wayfinderctl --serial /dev/ttyACMX` against
//! the node, since [`serve`] frames requests over any [`embedded_io_async`] byte
//! stream and CDC-ACM presents one. USBD is on the chip itself, so this needs no
//! GPIOs and no debug probe — the only way into a dongle.
//!
//! Both functions live on **one** [`UsbDevice`], which is why [`init`] builds
//! them together and hands the caller both halves: there is a single `Builder`,
//! and only whatever it produces can be run. The two are otherwise independent
//! — [`crate::usb_link`] owns the mesh side, and a host that never opens the
//! management port does not affect it, or vice versa.
//!
//! USBD depends on `POWER` and `CLOCK`, and this firmware owns both outright,
//! so both of its needs are met without ceremony:
//!
//! - **VBUS state** is read straight off `USBREGSTATUS` by
//!   [`HardwareVbusDetect`], which also covers the case a software detector
//!   had to special-case — a cable already plugged in at boot, the normal
//!   situation for a bus-powered dongle — because a register read has no
//!   notion of a missed event.
//! - **The high-frequency crystal** is started once by
//!   [`crate::init_platform`], for the radio's sake as much as USB's, and
//!   never stopped.
//!
//! Both used to be reached through SoftDevice syscalls, which reserved
//! `POWER` and started/stopped the crystal around radio activity. That is
//! also why VBUS arrived as SoC events and needed an event pump to deliver
//! them; nothing here needs one now.

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_nrf::Peri;
use embassy_nrf::peripherals::USBD;
use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
use embassy_time::Duration;
use embassy_time::Timer;
use embassy_usb::Builder;
use embassy_usb::Config;
use embassy_usb::UsbDevice;
use embassy_usb::class::cdc_acm::BufferedReceiver;
use embassy_usb::class::cdc_acm::CdcAcmClass;
use embassy_usb::class::cdc_acm::CdcAcmError;
use embassy_usb::class::cdc_acm::Sender;
use embassy_usb::class::cdc_acm::State;
use embedded_io_async::ErrorType;
use embedded_io_async::Read;
use embedded_io_async::Write;
use static_cell::StaticCell;
use tracing::debug;
use tracing::trace;
use tracing::warn;
use wayfinder::interfaces::frame::Mac;
use wayfinder_server::EmbeddedQueryTx;
use wayfinder_server::FrameError;
use wayfinder_server::serve;

use crate::usb_link::UsbInitError;
use crate::usb_link::UsbNcmLink;

/// The USB driver this board instantiates: the nRF USBD peripheral, with VBUS
/// state read directly off `POWER`.
pub type UsbDriver = embassy_nrf::usb::Driver<'static, HardwareVbusDetect>;

/// How a board hands this crate its `USBD` and `POWER_CLOCK` interrupt
/// bindings: a constructor for [`UsbDriver`], called by [`init`]. A board
/// supplies
/// `|usbd| embassy_nrf::usb::Driver::new(usbd, Irqs, HardwareVbusDetect::new(Irqs))`.
///
/// [`HardwareVbusDetect`] is built inside the closure rather than passed in
/// because it needs the board's `CLOCK_POWER` binding, which is subject to
/// the same linkage argument as `USBD` below.
///
/// A plain `fn` pointer rather than the `impl Binding<USBD, _>` parameter this
/// replaces, for two reasons that both live outside this module:
///
/// - [`crate::node::run`] is an `#[embassy_executor::task]`, and a task
///   cannot be generic. Threading the binding as a type parameter made `run`
///   generic, which forced the board to wrap it in a second `async fn` — and
///   that wrapper cost 62 KB of the node's stack for the whole run. See
///   `run`'s own comment for the failure it caused.
/// - `bind_interrupts!` stays in the board binary, where the linker is certain
///   to pull the generated `USBD` handler into the vector table. A handler
///   defined in a library rlib is only linked if something in its object is
///   referenced, and a `Binding` impl is not a symbol — so moving the binding
///   here to erase the generic would risk a device that enumerates nothing.
pub type UsbDriverFactory = fn(Peri<'static, USBD>) -> UsbDriver;

/// USB vendor id. `1209:0001` is pid.codes' *unallocated* test pair, never
/// assigned to a shipping product — right for research firmware, but it must be
/// replaced before distribution, since two test devices on one host are
/// indistinguishable by id alone.
const USB_VID: u16 = 0x1209;

/// USB product id. See [`USB_VID`].
const USB_PID: u16 = 0x0001;

/// Bulk endpoint packet size. 64 is the maximum a full-speed device may use,
/// which is what the nRF52840 enumerates as.
const MAX_PACKET_SIZE: u16 = 64;

/// Current drawn from the bus, in mA, as declared to the host. Covers a
/// bus-powered dongle running the radio; a DK is externally powered and draws
/// none of it.
const MAX_POWER_MA: u16 = 100;

/// Render `mac` as the 12 uppercase hex digits of a USB serial-number string, so
/// the host's `/dev/serial/by-id/…` symlink names the board. Without it several
/// dongles on one host are distinguishable only by enumeration order.
///
/// Fed the **board id** ([`crate::identity::from_ficr`]), not the node's mesh
/// MAC. The two used to be the same value and stopped being so in design 22,
/// when the mesh address became the one the node's identity seed derives: that
/// address changes on the next boot after every `SetAuth`, and a USB serial
/// that moved with it would rename `/dev/serial/by-id/…` under whoever was
/// holding the port — including the hardware-in-the-loop rig, whose inventory
/// pins boards by exactly this string. A serial number identifies a physical
/// part; a mesh MAC identifies a mesh node; they change on entirely different
/// schedules. Because it stays FICR-derived the value itself is unchanged, so
/// existing `hil.toml` files and `by-id` paths keep working.
fn serial_number(mac: Mac) -> &'static str {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    static SERIAL: StaticCell<[u8; 12]> = StaticCell::new();

    let mut buf = [0u8; 12];
    for (i, octet) in mac.0.into_iter().enumerate() {
        buf[i * 2] = HEX[usize::from(octet >> 4)];
        buf[i * 2 + 1] = HEX[usize::from(octet & 0x0f)];
    }

    let buf = SERIAL.init(buf);
    #[expect(
        clippy::expect_used,
        reason = "every byte written above is an ASCII hex digit"
    )]
    core::str::from_utf8(buf).expect("hex digits are valid UTF-8")
}

/// A CDC-ACM port as one bidirectional byte stream.
///
/// [`serve`] wants a single `Read + Write`, while the class splits into a
/// [`Sender`] and a [`BufferedReceiver`] — the buffered form being the one that
/// can answer a read smaller than a USB packet, which the 4-byte length prefix
/// always is.
struct CdcAcmStream {
    tx: Sender<'static, UsbDriver>,
    rx: BufferedReceiver<'static, UsbDriver>,
    /// Whether the last packet written filled the endpoint, leaving the current
    /// USB transfer unterminated. See [`flush`](Self::flush).
    last_packet_full: bool,
}

impl CdcAcmStream {
    /// Wait until the host has enumerated the port and enabled both endpoints.
    /// Reads and writes before this report [`CdcAcmError::NotConnected`].
    async fn wait_connection(&mut self) {
        join(self.tx.wait_connection(), self.rx.wait_connection()).await;
    }
}

impl ErrorType for CdcAcmStream {
    type Error = CdcAcmError;
}

impl Read for CdcAcmStream {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.rx.read(buf).await
    }
}

impl Write for CdcAcmStream {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let n = self.tx.write(buf).await?;
        self.last_packet_full = n == usize::from(MAX_PACKET_SIZE);
        Ok(n)
    }

    /// End the current USB transfer, emitting a zero-length packet if the last
    /// one written left it unterminated.
    ///
    /// A bulk transfer ends at a packet *shorter* than the endpoint maximum, so
    /// a response whose last packet came out exactly [`MAX_PACKET_SIZE`] long
    /// leaves the host entitled to keep waiting. `Sender::write` emits one
    /// packet per call, so whether that call filled the endpoint is the
    /// question — a flag, not a byte count, because `write_frame` writes the
    /// 4-byte length prefix as its own short (and therefore terminating)
    /// transfer, which a running total would miscount.
    ///
    /// Nothing above this layer knows about packet sizes, so a missing ZLP
    /// surfaces as a client hanging on one response in every sixty-four.
    async fn flush(&mut self) -> Result<(), Self::Error> {
        if self.last_packet_full {
            trace!("terminating usb transfer with a zero-length packet");
            self.tx
                .write_packet(&[])
                .await
                .map_err(|_| CdcAcmError::NotConnected)?;
            self.last_packet_full = false;
        }
        self.tx.flush().await
    }
}

/// The USB management interface: the device stack and the CDC-ACM port it
/// carries, ready to be [`run`](Self::run).
pub struct UsbMgmt {
    device: UsbDevice<'static, UsbDriver>,
    stream: CdcAcmStream,
}

/// Bring up the USB device stack, its CDC-ACM management port and its CDC-NCM
/// mesh interface.
///
/// **Must be called after [`crate::init_platform`]**, which starts the
/// high-frequency crystal USBD needs to clock the bus. `node_mac` seeds the
/// mesh interface's host-side address — that one really is the node's, since
/// the NCM interface is a mesh link and not a hardware label — while the USB
/// serial number comes from the board's FICR id (see [`serial_number`]).
/// `make_driver` builds the driver from the board's `bind_interrupts!` struct
/// — see [`UsbDriverFactory`].
///
/// Neither returned half does anything until it is polled: the [`UsbMgmt`] via
/// [`run`](UsbMgmt::run) — which is also what drives the shared device stack,
/// so the mesh link is dead until it is running — and the [`UsbNcmLink`] by the
/// driver's event loop.
pub async fn init(
    usbd: Peri<'static, USBD>,
    make_driver: UsbDriverFactory,
    node_mac: Mac,
    spawner: Spawner,
) -> Result<(UsbMgmt, UsbNcmLink), UsbInitError> {
    let driver = make_driver(usbd);

    let mut config = Config::new(USB_VID, USB_PID);
    config.manufacturer = Some("Wayfinder");
    // Deliberately unchanged now that the device carries a second function: the
    // product string is part of the host's `/dev/serial/by-id/` symlink, so
    // editing it silently breaks every script and doc naming that path.
    config.product = Some("Wayfinder mesh node management");
    config.serial_number = Some(serial_number(crate::identity::from_ficr()));
    config.max_power = MAX_POWER_MA;
    config.self_powered = false;
    // Left at its default `true`, with the matching 0xEF/0x02/0x01 device
    // class `Config::new` sets: two CDC functions on one device are only
    // separable by a host if each is introduced by an Interface Association
    // Descriptor.

    // The stack borrows all of these for the device's lifetime, which outlives
    // this function.
    //
    // The configuration descriptor holds every interface, endpoint and
    // class-specific descriptor of *both* functions concatenated — around 180
    // bytes for CDC-ACM plus CDC-NCM. 512 leaves room for a third function
    // without this becoming the thing that breaks.
    static CONFIG_DESCRIPTOR: StaticCell<[u8; 512]> = StaticCell::new();
    static BOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static CONTROL_BUF: StaticCell<[u8; 64]> = StaticCell::new();
    static STATE: StaticCell<State<'static>> = StaticCell::new();
    static RX_BUF: StaticCell<[u8; MAX_PACKET_SIZE as usize]> = StaticCell::new();

    let mut builder = Builder::new(
        driver,
        config,
        CONFIG_DESCRIPTOR.init([0; 512]),
        BOS_DESCRIPTOR.init([0; 256]),
        // No Microsoft OS descriptors: CDC-ACM and CDC-NCM both bind to in-box
        // drivers on the Linux and macOS hosts this is used from. Windows may
        // need an MS OS 2.0 descriptor to bind NCM to a composite function.
        &mut [],
        CONTROL_BUF.init([0; 64]),
    );

    let class = CdcAcmClass::new(&mut builder, STATE.init(State::new()), MAX_PACKET_SIZE);
    let (tx, rx) = class.split();

    // Two interfaces each, which is exactly `embassy-usb`'s default
    // `MAX_INTERFACE_COUNT` of 4. A third function needs the
    // `max-interface-count-6` feature; the builder panics rather than
    // truncating, so this fails loudly if it is ever forgotten.
    let link = UsbNcmLink::new(&mut builder, node_mac, spawner)?;

    Ok((
        UsbMgmt {
            device: builder.build(),
            stream: CdcAcmStream {
                tx,
                rx: rx.into_buffered(RX_BUF.init([0; MAX_PACKET_SIZE as usize])),
                last_packet_full: false,
            },
        },
        link,
    ))
}

impl UsbMgmt {
    /// Run the USB device stack and serve management requests off the CDC-ACM
    /// port, forwarding each to the router loop over `query_tx`. Never returns.
    pub async fn run(self, query_tx: &EmbeddedQueryTx<'_>) -> ! {
        let Self {
            mut device,
            mut stream,
        } = self;
        let (never, _) = join(device.run(), serve_forever(&mut stream, query_tx)).await;
        never
    }
}

/// Serve management requests off `stream` for the node's lifetime.
///
/// A session ending is routine: the port exists only while a host has the
/// device enumerated, so an unplugged cable is the normal state of a deployed
/// node, not a fault. Nothing here logs louder than that implies.
async fn serve_forever(stream: &mut CdcAcmStream, query_tx: &EmbeddedQueryTx<'_>) -> ! {
    loop {
        stream.wait_connection().await;
        debug!("management port connected");

        match serve(stream, query_tx).await {
            // The host closed the port, or the cable came out mid-frame.
            Err(FrameError::UnexpectedEof | FrameError::Io(_)) => {
                debug!("management port disconnected");
            }
            // A peer-supplied length prefix desynchronised the stream —
            // reachable by whatever is on the other end of the cable, not a
            // node-local fault, so it stays below `error!`.
            Err(e @ FrameError::Oversized(_)) => {
                warn!(?e, "management link reset: oversized frame");
            }
            Ok(()) => unreachable!("serve only returns via an error"),
        }

        // Management sessions are the deepest thing this board does — prost
        // decode, the `RouterAdapter` projection and response encoding stack on
        // top of whatever the mesh loop held — so the peak is worth sampling at
        // a session boundary too. Rare: reaching here means the *stream*
        // failed, which a host merely closing `/dev/ttyACMX` does not do.
        crate::stack::report();

        // The endpoints are disabled the instant the host goes away, so
        // `wait_connection` can return immediately after a torn-down session;
        // this keeps that from becoming a tight loop.
        Timer::after(Duration::from_millis(100)).await;
    }
}
