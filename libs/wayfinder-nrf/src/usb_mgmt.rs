//! The management API over the nRF52840's USB device peripheral, as a CDC-ACM
//! (USB serial) port.
//!
//! A host runs `wayfinder-tui` or `wayfinderctl --serial /dev/ttyACMX` against
//! the node, since [`serve`] frames requests over any [`embedded_io_async`] byte
//! stream and CDC-ACM presents one. USBD is on the chip itself, so this needs no
//! GPIOs and no debug probe — the only way into a dongle.
//!
//! The SoftDevice owns `POWER` and `CLOCK`, both of which USBD depends on, so
//! [`init`] has to ask it for what a bare-metal USB stack would do itself:
//!
//! - **VBUS state** arrives only as SoC events, hence [`SoftwareVbusDetect`] fed
//!   by [`on_soc_event`] rather than the register-polling `HardwareVbusDetect`.
//!   No event is generated for a cable that was *already* plugged in — the
//!   normal case for a bus-powered dongle — so the initial state is seeded by
//!   reading `USBREGSTATUS` through the SoftDevice.
//! - **The high-frequency crystal** must run for USBD to clock the bus at all,
//!   and the SoftDevice otherwise starts and stops it around radio activity.
//!
//! [`on_soc_event`] must be handed to the SoftDevice's single event pump, the
//! only place SoC events are delivered — see [`crate::node`].

use embassy_futures::join::join;
use embassy_nrf::Peri;
use embassy_nrf::interrupt::typelevel::Binding;
use embassy_nrf::peripherals::USBD;
use embassy_nrf::usb::InterruptHandler;
use embassy_nrf::usb::vbus_detect::SoftwareVbusDetect;
use embassy_sync::once_lock::OnceLock;
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
use nrf_softdevice::RawError;
use nrf_softdevice::SocEvent;
use nrf_softdevice::raw;
use static_cell::StaticCell;
use tracing::debug;
use tracing::trace;
use tracing::warn;
use wayfinder::interfaces::frame::Mac;
use wayfinder_server::EmbeddedQueryTx;
use wayfinder_server::FrameError;
use wayfinder_server::serve;

/// The USB driver this board instantiates: the nRF USBD peripheral, with VBUS
/// state supplied by software rather than read off the SoftDevice-reserved
/// `POWER` peripheral.
type UsbDriver = embassy_nrf::usb::Driver<'static, &'static SoftwareVbusDetect>;

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

/// How long [`init`] waits for the crystal before carrying on regardless. Its
/// datasheet startup time is well under a millisecond, so reaching this bound
/// means the clock request is wrong rather than slow.
const HFCLK_START_TIMEOUT_MS: u64 = 100;

/// Interval between [`hfclk_running`] polls while waiting for the crystal.
const HFCLK_POLL_INTERVAL_MS: u64 = 1;

/// `USBREGSTATUS.VBUSDETECT` — VBUS is present on the connector. Spelled out
/// because `sd_power_usbregstatus_get` returns the raw register and the
/// SoftDevice headers carry no field masks; bit positions from the nRF52840
/// product specification's `POWER` table.
const USBREGSTATUS_VBUSDETECT: u32 = 1 << 0;

/// `USBREGSTATUS.OUTPUTRDY` — the USB 3.3V regulator has settled, which is the
/// condition USBD's pull-up may be enabled under.
const USBREGSTATUS_OUTPUTRDY: u32 = 1 << 1;

/// The board's VBUS state. A `static` because the halves live apart:
/// [`on_soc_event`] runs on the SoftDevice event pump with no way to carry board
/// state, and the USB driver holds a `&'static` borrow for the device's
/// lifetime. Initialised exactly once, by [`init`].
static VBUS: OnceLock<SoftwareVbusDetect> = OnceLock::new();

/// Feed one SoftDevice SoC event to the USB stack's VBUS state. Pass to the
/// SoftDevice's event pump; non-power events are ignored.
///
/// Events arriving before [`init`] are dropped rather than initialising [`VBUS`]
/// with a guess: the SoftDevice generates no power events until `init` enables
/// them, so this cannot lose a transition, and `init`'s `USBREGSTATUS` read is
/// authoritative for everything beforehand.
pub fn on_soc_event(event: SocEvent) {
    let Some(vbus) = VBUS.try_get() else {
        trace!(?event, "drop: soc event before usb init");
        return;
    };
    match event {
        SocEvent::PowerUsbDetected => {
            debug!("usb power detected");
            vbus.detected(true);
        }
        SocEvent::PowerUsbRemoved => {
            debug!("usb power removed");
            vbus.detected(false);
        }
        SocEvent::PowerUsbPowerReady => {
            debug!("usb power ready");
            vbus.ready();
        }
        other => trace!(event = ?other, "ignoring non-power soc event"),
    }
}

/// Ask the SoftDevice to deliver USB power events, then seed [`VBUS`] with the
/// current state.
///
/// Enabling comes first so a transition between the two steps is reported
/// rather than lost; a redundant report is harmless. Neither step awaits, so
/// the event pump cannot observe a half-initialised state in between.
fn init_vbus() -> Result<&'static SoftwareVbusDetect, RawError> {
    // SAFETY: plain SoftDevice syscalls, valid once it is enabled (which
    // `init`'s contract requires) and borrowing no state.
    unsafe {
        RawError::convert(raw::sd_power_usbdetected_enable(1))?;
        RawError::convert(raw::sd_power_usbremoved_enable(1))?;
        RawError::convert(raw::sd_power_usbpwrrdy_enable(1))?;
    }

    let mut status = 0u32;
    // SAFETY: as above; `status` is a live, aligned, exclusively-borrowed u32.
    unsafe { RawError::convert(raw::sd_power_usbregstatus_get(&mut status))? };
    let detected = status & USBREGSTATUS_VBUSDETECT != 0;
    let ready = status & USBREGSTATUS_OUTPUTRDY != 0;
    debug!(detected, ready, "seeding usb vbus state");

    Ok(VBUS.get_or_init(|| SoftwareVbusDetect::new(detected, ready)))
}

/// Whether the SoftDevice reports the high-frequency crystal as running.
fn hfclk_running() -> Result<bool, RawError> {
    let mut running = 0u32;
    // SAFETY: a SoftDevice syscall over a live, exclusively-borrowed u32.
    unsafe { RawError::convert(raw::sd_clock_hfclk_is_running(&mut running))? };
    Ok(running != 0)
}

/// Take a standing request on the high-frequency crystal and wait briefly for it
/// to start. Without it the USB device would enumerate or not depending on what
/// BLE happened to be doing.
///
/// The request is never released, costing the crystal's run current for the
/// node's whole lifetime rather than only while a host is attached — the right
/// trade for the mains-fed boards this targets, and the first thing to revisit
/// if it ever runs on a battery.
async fn request_hfclk() -> Result<(), RawError> {
    // SAFETY: a SoftDevice syscall taking no arguments, valid once enabled.
    unsafe { RawError::convert(raw::sd_clock_hfclk_request())? };

    for _ in 0..(HFCLK_START_TIMEOUT_MS / HFCLK_POLL_INTERVAL_MS) {
        if hfclk_running()? {
            trace!("hfxo running");
            return Ok(());
        }
        Timer::after(Duration::from_millis(HFCLK_POLL_INTERVAL_MS)).await;
    }

    // Not fatal: the request stands, so the crystal may yet start and the port
    // come up late. Loud because a USB device that never enumerates is otherwise
    // indistinguishable from a bad cable.
    warn!("hfxo did not start within the timeout; usb may not enumerate");
    Ok(())
}

/// Render `mac` as the 12 uppercase hex digits of a USB serial-number string, so
/// the host's `/dev/serial/by-id/…` symlink names the node by its mesh MAC.
/// Without it several dongles on one host are distinguishable only by
/// enumeration order.
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

/// Bring up the USB device stack and its CDC-ACM management port.
///
/// **Must be called after `Softdevice::enable`**, since the power and clock
/// state it needs is reachable only through SoftDevice syscalls, which return
/// [`RawError::SoftdeviceNotEnabled`] otherwise. `node_mac` becomes the device's
/// USB serial number, and `irqs` is the board's `bind_interrupts!` struct, which
/// must bind `USBD`.
///
/// The returned [`UsbMgmt`] does nothing until [`run`](UsbMgmt::run) is polled.
pub async fn init(
    usbd: Peri<'static, USBD>,
    irqs: impl Binding<embassy_nrf::interrupt::typelevel::USBD, InterruptHandler<USBD>> + 'static,
    node_mac: Mac,
) -> Result<UsbMgmt, RawError> {
    let vbus = init_vbus()?;
    request_hfclk().await?;

    let driver = embassy_nrf::usb::Driver::new(usbd, irqs, vbus);

    let mut config = Config::new(USB_VID, USB_PID);
    config.manufacturer = Some("Wayfinder");
    config.product = Some("Wayfinder mesh node management");
    config.serial_number = Some(serial_number(node_mac));
    config.max_power = MAX_POWER_MA;
    config.self_powered = false;

    // The stack borrows all of these for the device's lifetime, which outlives
    // this function.
    static CONFIG_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static CONTROL_BUF: StaticCell<[u8; 64]> = StaticCell::new();
    static STATE: StaticCell<State<'static>> = StaticCell::new();
    static RX_BUF: StaticCell<[u8; MAX_PACKET_SIZE as usize]> = StaticCell::new();

    let mut builder = Builder::new(
        driver,
        config,
        CONFIG_DESCRIPTOR.init([0; 256]),
        BOS_DESCRIPTOR.init([0; 256]),
        // No Microsoft OS descriptors: CDC-ACM binds to the in-box driver on
        // every host this is used from.
        &mut [],
        CONTROL_BUF.init([0; 64]),
    );

    let class = CdcAcmClass::new(&mut builder, STATE.init(State::new()), MAX_PACKET_SIZE);
    let (tx, rx) = class.split();

    Ok(UsbMgmt {
        device: builder.build(),
        stream: CdcAcmStream {
            tx,
            rx: rx.into_buffered(RX_BUF.init([0; MAX_PACKET_SIZE as usize])),
            last_packet_full: false,
        },
    })
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
