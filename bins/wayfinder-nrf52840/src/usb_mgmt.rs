//! The management API over the nRF52840's USB device peripheral, as a CDC-ACM
//! (USB serial) port.
//!
//! This is the board's management transport: a host runs `wayfinder-tui` or
//! `wayfinderctl --serial /dev/ttyACMX` against the node exactly as it did over
//! the DK's onboard-debugger VCOM UART, since [`wayfinder_server::serve`] frames
//! requests over any [`embedded_io_async`] byte stream and CDC-ACM presents one.
//! What changes is what the far end needs: USBD is on the chip itself, so the
//! management port is the board's own USB connector rather than two GPIOs wired
//! to a debug probe. That is what makes this reachable on an nRF52840 **dongle**
//! (PCA10059), which has no onboard debugger and no VCOM to borrow.
//!
//! # Coexisting with the SoftDevice
//!
//! `blue`'s BLE link runs the S140 SoftDevice, which takes exclusive ownership
//! of the `POWER` and `CLOCK` peripherals — both of which USBD depends on. So
//! the two things a bare-metal USB stack normally does for itself have to be
//! asked of the SoftDevice instead, and [`init`] does both:
//!
//! - **VBUS state** reaches us only as SoC events, so the driver is built on
//!   [`SoftwareVbusDetect`] fed by [`on_soc_event`] rather than the
//!   register-polling `HardwareVbusDetect`. Those events are off until
//!   requested, and none is generated for a cable that was *already* plugged in
//!   — the normal case for a bus-powered dongle — so the initial state is
//!   seeded by reading `USBREGSTATUS` through the SoftDevice.
//! - **The high-frequency crystal** (HFXO) must be running for USBD to clock
//!   the bus at all; the SoftDevice otherwise starts and stops it around radio
//!   activity, so [`init`] takes a standing request on it.
//!
//! [`on_soc_event`] has to be handed to the SoftDevice's single event pump —
//! the only place SoC events are ever delivered — so `main.rs` passes it to
//! its own `softdevice_task` when spawning that pump, rather than `usb_mgmt`
//! installing it directly.
//!
//! # What a dongle still needs
//!
//! This removes the *management* obstacle to running on a PCA10059, not every
//! obstacle. Three board differences remain, none of them addressed here:
//!
//! - **Flash layout.** The dongle ships with Nordic's Open Bootloader occupying
//!   the top 32 KiB (`0xF8000..0x100000`), which overlaps the two pages
//!   `memory.x` reserves at `0xFE000` for the durable identity store. Flashing
//!   over SWD and dropping the bootloader avoids it; keeping DFU means moving
//!   the store and `DURABLE_STORE_BASE` down.
//! - **GPIO.** `main.rs` drives LED1 on `P0_13`, a DK pin the dongle does not
//!   route; its LEDs are on `P0_06` and `P0_08`/`P1_09`/`P0_12`.
//! - **Logging.** RTT needs a debug probe, which the dongle has only on bare
//!   SWD pads — so on that board this port is not merely the management
//!   interface, it is the *only* interface into a running node.

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
/// state supplied by software (see the module doc) rather than read off the
/// SoftDevice-reserved `POWER` peripheral.
type UsbDriver = embassy_nrf::usb::Driver<'static, &'static SoftwareVbusDetect>;

/// USB vendor and product id.
///
/// `1209:0001` is pid.codes' explicitly *unallocated* test pair: reserved for
/// prototypes and deliberately never assigned to a shipping product, so it can
/// never collide with a real device's driver bindings. It is the honest choice
/// for research firmware — but it must be replaced with an allocated pair
/// before any of this is distributed, since two different test devices on one
/// host are indistinguishable by id alone.
const USB_VID: u16 = 0x1209;
const USB_PID: u16 = 0x0001;

/// Bulk endpoint packet size, in bytes. 64 is the maximum a full-speed device
/// may use, which is what the nRF52840 enumerates as; a management response is
/// several packets either way, so the largest allowed value minimises the
/// per-frame packet count.
const MAX_PACKET_SIZE: u16 = 64;

/// Current drawn from the USB bus, in mA, as declared to the host. A bus-powered
/// dongle running the radio sits well inside this; the DK is externally powered
/// and draws none of it, but declaring the higher figure is harmless and covers
/// both boards with one descriptor.
const MAX_POWER_MA: u16 = 100;

/// How long [`init`] waits for the SoftDevice to bring the HFXO up before
/// carrying on regardless. The crystal's datasheet startup time is well under a
/// millisecond, so reaching this bound means something is wrong with the clock
/// request rather than that it needs longer — hence a short poll and a `warn!`,
/// not an open-ended wait that would strand boot.
const HFCLK_START_TIMEOUT_MS: u64 = 100;

/// Interval between [`hfclk_running`] polls while waiting for the crystal.
const HFCLK_POLL_INTERVAL_MS: u64 = 1;

/// `USBREGSTATUS.VBUSDETECT` — VBUS is present on the connector.
///
/// Spelled out here rather than imported: `sd_power_usbregstatus_get` hands back
/// the raw register value, and the SoftDevice headers carry no field masks for
/// it (they belong to the `POWER` peripheral, which those headers don't
/// describe). Bit positions are from the nRF52840 product specification's
/// `POWER` register table.
const USBREGSTATUS_VBUSDETECT: u32 = 1 << 0;

/// `USBREGSTATUS.OUTPUTRDY` — the USB 3.3V regulator's output has settled, which
/// is the condition USBD's pull-up may be enabled under.
const USBREGSTATUS_OUTPUTRDY: u32 = 1 << 1;

/// The board's VBUS state, as reported by the SoftDevice.
///
/// A `static` because the two halves live in different places: [`on_soc_event`]
/// (running on `blue`'s SoftDevice event-pump task, with no way to carry board
/// state) writes it, and the USB driver holds a `&'static` borrow of it for the
/// lifetime of the device. Initialised exactly once, by [`init`].
static VBUS: OnceLock<SoftwareVbusDetect> = OnceLock::new();

/// Feed one SoftDevice SoC event to the USB stack's VBUS state.
///
/// Pass this to `main.rs`'s `softdevice_task` when spawning the SoftDevice's
/// event pump — see the module doc for why USB power detection has to travel
/// through that single callback rather than a register poll. Non-power events
/// are ignored.
///
/// Events that arrive before [`init`] has run are dropped rather than
/// initialising [`VBUS`] with a guessed state: the SoftDevice does not generate
/// power events until `init` enables them, so this cannot lose a transition, and
/// `init`'s `USBREGSTATUS` read is authoritative for everything that happened
/// beforehand.
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

/// Ask the SoftDevice to deliver USB power events, then read the current VBUS
/// state and seed [`VBUS`] with it.
///
/// Enabling comes first so that a transition between the two steps is reported
/// rather than lost; the redundant case (an event for a state the read below
/// also observes) is harmless, since both carry the same value. Neither step
/// awaits, so the SoftDevice's event pump — a task on this same executor —
/// cannot run in between and observe a half-initialised state.
fn init_vbus() -> Result<&'static SoftwareVbusDetect, RawError> {
    // SAFETY: plain SoftDevice syscalls, valid once the SoftDevice is enabled
    // (which `init`'s contract requires) and taking no borrowed state.
    unsafe {
        RawError::convert(raw::sd_power_usbdetected_enable(1))?;
        RawError::convert(raw::sd_power_usbremoved_enable(1))?;
        RawError::convert(raw::sd_power_usbpwrrdy_enable(1))?;
    }

    let mut status = 0u32;
    // SAFETY: as above; `status` is a live, aligned, exclusively-borrowed u32
    // for the duration of the call.
    unsafe { RawError::convert(raw::sd_power_usbregstatus_get(&mut status))? };
    let detected = status & USBREGSTATUS_VBUSDETECT != 0;
    let ready = status & USBREGSTATUS_OUTPUTRDY != 0;
    debug!(detected, ready, "seeding usb vbus state");

    Ok(VBUS.get_or_init(|| SoftwareVbusDetect::new(detected, ready)))
}

/// Whether the SoftDevice reports the HFXO as running.
fn hfclk_running() -> Result<bool, RawError> {
    let mut running = 0u32;
    // SAFETY: a SoftDevice syscall over a live, exclusively-borrowed u32.
    unsafe { RawError::convert(raw::sd_clock_hfclk_is_running(&mut running))? };
    Ok(running != 0)
}

/// Take a standing request on the high-frequency crystal and wait (briefly) for
/// it to start.
///
/// USBD cannot clock the bus off the internal RC oscillator, and the SoftDevice
/// starts the crystal only around its own radio activity — so without this the
/// USB device would enumerate or not depending on what BLE happened to be doing.
///
/// The request is never released, which costs the crystal's standing run current
/// for the node's whole lifetime rather than only while a host is attached. That
/// is the right trade for the boards this firmware targets — a DK and a
/// bus-powered dongle, both mains-fed — but it is the thing to revisit first if
/// this ever runs on a battery: releasing on `PowerUsbRemoved` and re-requesting
/// on `PowerUsbDetected` would scope it to when the port is actually in use.
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

    // Not fatal on its own: the request stands, so the crystal may yet start and
    // the port come up late. Loud because a USB device that never enumerates is
    // otherwise indistinguishable from a bad cable.
    warn!("hfxo did not start within the timeout; usb may not enumerate");
    Ok(())
}

/// Render `mac` as the 12 uppercase hex digits of a USB serial-number string.
///
/// Reported in the device descriptor, so the host's
/// `/dev/serial/by-id/…` symlink names the node by its mesh MAC. That is what
/// makes several dongles on one host individually addressable — without it they
/// are distinguishable only by enumeration order.
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
/// [`Sender`] and a [`BufferedReceiver`] (the buffered form being the one that
/// can answer a read smaller than a USB packet, which the 4-byte length prefix
/// always is). This rejoins them, and takes care of the one rule bulk endpoints
/// impose that a UART does not — see [`flush`](Self::flush).
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
    /// A bulk transfer ends at a packet *shorter* than the endpoint's maximum,
    /// so a response whose last packet came out exactly [`MAX_PACKET_SIZE`]
    /// bytes long leaves the host entitled to keep waiting for more of the same
    /// transfer. `Sender`'s `write` emits exactly one packet per call, so
    /// whether that call filled the endpoint is exactly the question — and
    /// [`wayfinder_server::write_frame`] flushes once per frame, which is where
    /// the answer has to be acted on.
    ///
    /// Tracking the flag rather than a byte count matters because a frame is not
    /// one transfer: `write_frame` writes the 4-byte length prefix separately
    /// from the body, and that short prefix packet terminates a transfer of its
    /// own. A running total would call a 60-byte body "64 bytes, needs a ZLP"
    /// and emit a stray one.
    ///
    /// Nothing above this layer knows about packet sizes, so a missing ZLP would
    /// surface as a management client hanging on one response in every
    /// sixty-four — reproducible, but only for particular response sizes.
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
/// **Must be called after the SoftDevice is enabled** (i.e. after
/// `Softdevice::enable`), since the power and clock state it needs is
/// reachable only through SoftDevice syscalls; those return
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
    // Bus-powered on the dongle; the DK's USB connector is likewise the only
    // thing this descriptor speaks for.
    config.self_powered = false;

    // The stack borrows all of these for the device's lifetime, which outlives
    // this function — hence `'static` promotion rather than locals. `StaticCell`
    // rather than `main.rs`'s older `static mut` + `addr_of_mut!` idiom: it
    // enforces the take-exactly-once rule those `SAFETY` comments have to argue
    // by hand.
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
/// A management session ending is routine here in a way it never was over the
/// DK's VCOM UART: the port exists only while a host has the device enumerated,
/// so unplugging the cable — or simply never plugging one in — is the normal
/// state of a deployed node, not a fault. Each pass therefore waits for the host
/// to enable the endpoints before serving, and no failure below is louder than
/// the mesh traffic it must not drown out.
async fn serve_forever(stream: &mut CdcAcmStream, query_tx: &EmbeddedQueryTx<'_>) -> ! {
    loop {
        stream.wait_connection().await;
        debug!("management port connected");

        match serve(stream, query_tx).await {
            // The host closed the port, or the cable came out mid-frame. The
            // ordinary end of a session; wait for the next one.
            Err(FrameError::UnexpectedEof | FrameError::Io(_)) => {
                debug!("management port disconnected");
            }
            // A peer-supplied length prefix desynchronised the stream: a
            // protocol violation reachable by whatever is on the other end of
            // the cable, not a node-local fault, so this stays below `error!`.
            Err(e @ FrameError::Oversized(_)) => {
                warn!(?e, "management link reset: oversized frame");
            }
            Ok(()) => unreachable!("serve only returns via an error"),
        }

        // Management sessions are the deepest thing this board does — prost
        // decode, the `RouterAdapter` projection, and response encoding all run
        // on top of whatever the mesh loop was already holding — so the peak is
        // worth sampling against a session boundary and not only against a
        // timer.
        //
        // Note how rarely this actually runs, though: reaching it means `serve`
        // returned, and `serve` only returns when the *stream* fails. A host
        // merely closing `/dev/ttyACMX` does not do that — the device stays
        // enumerated with its endpoints live, so the read below simply blocks
        // for the next client. This fires on an unplug or a re-enumeration, not
        // on an ordinary `wayfinderctl` invocation. `crate::stack_watch` is the
        // reporting path that always runs; this one just times a sample to the
        // teardown when there is one.
        crate::stack::report();

        // The endpoints are disabled the instant the host goes away, so
        // `wait_connection` returning immediately after a torn-down session is
        // possible; this keeps that from becoming a tight loop.
        Timer::after(Duration::from_millis(100)).await;
    }
}
