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

use embassy_nrf::interrupt::InterruptExt;
use embassy_nrf::interrupt::Priority;
use embassy_nrf::pac::Interrupt;
use embedded_alloc::LlffHeap as Heap;
use tracing::info;

wayfinder::define_profile! {
    /// The capacity profile every nRF52840 board is built at, sizing the
    /// routing core's const-generic tables to this mesh rather than a gateway's.
    ///
    /// Two figures come from hardware: `interfaces` is the board's link count
    /// (LoRa + BLE + the CDC-NCM USB link), and `max_frame_len` is the largest
    /// frame any link can deliver — `rylr998` reassembly caps at 512, `blue` at
    /// 350 — so lowering it would silently drop reassembled LoRa frames. The
    /// rest carry headroom for a handful-of-nodes mesh; `originators` and
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
/// interrupt priorities the SoftDevice demands.
///
/// **Call as the first statement of `main`.** [`stack::paint`] measures only
/// what happens after it runs and must see the stack at its shallowest.
/// `ram_floor` is the board's `ORIGIN(RAM)` from its `memory.x` — see
/// [`stack::paint`] for why it cannot be read from a linker symbol.
///
/// The SoftDevice reserves NVIC priority levels 0 and 1 and rejects
/// `sd_softdevice_enable()` outright if any interrupt is already enabled there.
/// `embassy_nrf`'s defaults put GPIOTE and the RTC1 time driver at `P0`, and
/// UARTE0/USBD sit at the hardware reset default (highest) until set, so all
/// four drop to `P2` here.
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

    Interrupt::UARTE0.set_priority(Priority::P2);
    Interrupt::USBD.set_priority(Priority::P2);

    let mut config = embassy_nrf::config::Config::default();
    config.gpiote_interrupt_priority = Priority::P2;
    config.time_interrupt_priority = Priority::P2;
    embassy_nrf::init(config)
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
