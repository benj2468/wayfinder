//! Board-support code shared by every nRF52840 wayfinder firmware.
//!
//! A board binary supplies only what is genuinely board-specific — its
//! `memory.x`, the flash offset of the durable store, its LED and UART pins, and
//! its `bind_interrupts!` struct — then hands the rest to [`init_platform`] and
//! [`node::run`]. Everything else (fault handling, stack measurement, identity,
//! the link enum, the USB management port, the capacity profile) lives here so
//! the boards cannot drift apart.
//!
//! See this crate's `CLAUDE.md` for the hardware behaviour encoded here: why a
//! fault reboots rather than halts, why detaching a debug probe crashes the
//! board, and how the supported boards differ.

#![no_std]

pub mod clock;
pub mod fault;
pub mod identity;
pub mod link;
pub mod node;
pub mod stack;
pub mod usb_link;
pub mod usb_mgmt;

use embassy_nrf::config::HfclkSource;
use embedded_alloc::LlffHeap as Heap;
use tracing::debug;
use tracing::info;

wayfinder::define_profile! {
    /// The capacity profile every nRF52840 board is built at, sizing the
    /// routing core's const-generic tables to this mesh rather than a gateway's.
    ///
    /// Two figures come from hardware: `interfaces` is the board's link count
    /// (LoRa + 802.15.4 + the CDC-NCM USB link), and `max_frame_len` is the
    /// largest frame any link can deliver — `rylr998` reassembly caps at 512
    /// and `ieee802154`'s `MAX_REASSEMBLED_LEN` is pinned to this very number
    /// — so lowering it would silently drop reassembled frames from either
    /// radio. **Raising it means raising `ieee802154::MAX_REASSEMBLED_LEN`
    /// too**, or the 802.15.4 link refuses frames the router considers legal.
    /// The rest carry headroom for a handful-of-nodes mesh; `originators` and
    /// `ident_table` must stay powers of two.
    ///
    /// `max_frame_len` deliberately does *not* rise for the USB link, which
    /// could carry a full 1500-byte host MTU: it is the router's frame
    /// capacity, so raising it would cost RAM on every board to serve frames
    /// the radios can never relay onward anyway. The USB link's own receive
    /// buffer is sized separately and independently — see
    /// [`usb_link::UsbNcmLink`].
    pub nrf52840 {
        originators: 32,
        interfaces: 3,
        mcast_members: 16,
        local_mcast: 4,
        ident_table: 32,
        ident_live: 24,
        link_quality: 32,
        neighbor_keys: 16,
        revoked: 8,
        in_flight_cert_requests: 4,
        pending_replies: 4,
        max_frame_len: 512,
    }
}

/// The 802.15.4 link cannot reassemble a frame larger than this crate's
/// capacity profile allows the router to hold, and must not refuse one it
/// does. Both `CLAUDE.md` and the profile's own doc comment say to keep them
/// in sync; this is what makes forgetting a build error instead of a silent
/// drop of every oversized frame.
const _: () = assert!(ieee802154::MAX_REASSEMBLED_LEN == nrf52840::MAX_FRAME_LEN);

#[global_allocator]
static HEAP: Heap = Heap::empty();

/// Bytes reserved for `alloc`, shared by `tracing-core`'s bookkeeping and the
/// USB management server's per-request buffers.
///
/// Sized against `wayfinder_server::framing::MAX_FRAME_LEN` (4 KiB): `serve`
/// holds one in-flight buffer per direction, so one management session can pin
/// 8 KiB in framing buffers alone. The rest is headroom for a query's response
/// `Vec`s — tiny against the part's 256 KiB SRAM.
const HEAP_SIZE_BYTES: usize = 32 * 1024;

/// Bring the chip up to the point a board can start wiring peripherals:
/// stack painting, the heap, logging, any retained fault report, and the
/// clock sources its radio and USB depend on.
///
/// **Call as the first statement of `main`.** [`stack::paint`] measures only
/// what happens after it runs and must see the stack at its shallowest.
/// `ram_floor` is the board's `ORIGIN(RAM)` from its `memory.x` — see
/// [`stack::paint`] for why it cannot be read from a linker symbol.
///
/// # Clocks
///
/// **HFCLK is switched to the external crystal**, which `embassy-nrf` does not
/// do by default (it assumes a board may not have one). Both are hard
/// requirements, not accuracy preferences: the `RADIO` peripheral is only
/// specified running from the HFXO, and USBD cannot clock the bus without it.
/// Every board this crate supports has a 32 MHz crystal.
///
/// LFCLK is left on the internal RC oscillator. The DK has a 32.768 kHz
/// crystal and the dongle does not, so `InternalRC` is the only setting that
/// works on both; nothing here needs the accuracy an LFXO would add.
///
/// Interrupt priorities are left at `embassy-nrf`'s defaults. They used to be
/// forced to `P2` because the SoftDevice reserved levels 0 and 1 and refused
/// to enable if anything was already there; with it gone, nothing is
/// reserved.
pub fn init_platform(ram_floor: usize) -> embassy_nrf::Peripherals {
    stack::paint(ram_floor);

    // SAFETY: called once, before any other code can allocate, over a
    // `static mut` region sized by `HEAP_SIZE_BYTES` that nothing else
    // references.
    unsafe {
        static mut HEAP_MEM: [core::mem::MaybeUninit<u8>; HEAP_SIZE_BYTES] =
            [core::mem::MaybeUninit::uninit(); HEAP_SIZE_BYTES];
        #[allow(static_mut_refs)]
        HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE_BYTES);
    }

    // After the allocator (the dispatcher allocates) and before any event.
    wayfinder_log::init();
    info!("Welcome to Wayfinder");

    // Before anything this boot could push it out of the log ring.
    fault::report_retained();

    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = HfclkSource::ExternalXtal;

    // `embassy_nrf::init` spins on `EVENTS_HFCLKSTARTED` with no timeout, and
    // both the radio and USB are dead without the crystal — so a board whose
    // HFXO never starts hangs here, before any link or management port
    // exists, with no fault record (a hang is not a panic). Logging is
    // already up, so bracket the spin: the last line in the ring then names
    // the suspect instead of leaving a node that looks bricked.
    debug!("starting HFXO (both the radio and USB need it)");
    let peripherals = embassy_nrf::init(config);
    debug!("HFXO running");
    peripherals
}

/// `'static` scratch buffers for a board's [`BufferedUarte`], whose `rx` length
/// must be even.
///
/// [`BufferedUarte`]: embassy_nrf::buffered_uarte::BufferedUarte
pub fn uarte_buffers() -> (&'static mut [u8], &'static mut [u8]) {
    static RX: static_cell::StaticCell<[u8; 256]> = static_cell::StaticCell::new();
    static TX: static_cell::StaticCell<[u8; 256]> = static_cell::StaticCell::new();
    (RX.init([0; 256]), TX.init([0; 256]))
}

/// UART settings for a RYLR998: its factory default is 115200 8N1.
pub fn uarte_config() -> embassy_nrf::uarte::Config {
    let mut config = embassy_nrf::uarte::Config::default();
    config.baudrate = embassy_nrf::uarte::Baudrate::BAUD115200;
    config.parity = embassy_nrf::uarte::Parity::EXCLUDED;
    config
}
