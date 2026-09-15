//! ESP32 (Xtensa LX6) firmware: the wayfinder mesh router on bare metal, on a
//! third board family.
//!
//! What this board establishes that no host test can is that the toolchain
//! fork, the sysroot built from source, `linkall.x` and the ESP-IDF image
//! header line up well enough for the ROM bootloader to start what we flash —
//! and now that the same [`wayfinder_embedded_driver::Driver`] the nRF and
//! STM32 boards run also links and executes on Xtensa.
//!
//! **It has no mesh medium yet.** ESP-NOW is its own ticket; until then every
//! interface is [`MeshLink::Absent`] and the node routes over nothing. That is
//! still a running router — it paces its Trickle timers, ages its tables and
//! emits the records that show the engine turning over — which is what makes
//! the radio a separate, reviewable step rather than a big-bang bring-up.
//!
//! # This part's memory, measured
//!
//! `esp-hal`'s linker script gives the application `0x3ffb0000..0x3ffe0000` —
//! **192 KB of DRAM**, not the 320 KB the part's datasheet totals, because the
//! ROM and the Bluetooth controller reserve the rest. The hello-world image
//! that preceded this one reported ~190 KiB there, which reads alarming and is
//! not: that figure is `.stack` (194,684 bytes), a *region the linker hands
//! out*, against 1,924 bytes of actual statics. Statics and stack share the 192 KB, so the router's
//! footprint comes out of the stack rather than out of some separate budget.
//!
//! [`MeshLink::Absent`]: link::MeshLink::Absent

#![no_std]
#![no_main]

mod identity;
mod link;
mod mgmt;

use embassy_executor::Spawner;
use embassy_futures::join::join;
// The panic handler, linked for its side effect.
use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::timer::timg::TimerGroup;
use esp_hal::uart::Uart;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;
use wayfinder_embedded_driver::Clock;
use wayfinder_embedded_driver::Driver;
use wayfinder_embedded_driver::Restored;
use wayfinder_embedded_driver::TrickleParams;
use wayfinder_server::EmbeddedQueryChannel;

use crate::identity::Identity;
use crate::link::MeshLink;

// The descriptor the ESP-IDF second-stage bootloader reads out of the image
// before starting it; see this crate's `Cargo.toml`.
esp_bootloader_esp_idf::esp_app_desc!();

/// Bytes reserved for `alloc`.
///
/// Sized the way `libs/wayfinder-nrf` sizes its heap, and for the same reason:
/// `wayfinder_server::framing`'s 4 KiB frame limit means one management session
/// can pin 8 KiB in framing buffers alone (`serve` holds one in-flight buffer
/// per direction), on top of a response's own `Vec`s and `tracing-core`'s
/// dispatcher bookkeeping. Exceeding it is a `handle_alloc_error` panic, which
/// on a board is a reset.
///
/// This was 1 KiB — the STM32's figure — while the dispatcher was the only
/// user. Serving the management API is what made it the nRF's.
const HEAP_SIZE_BYTES: usize = 32 * 1024;

wayfinder::define_profile! {
    /// The capacity profile this board is built at.
    ///
    /// Sized against the 192 KB of DRAM `esp-hal` actually gives the
    /// application (see the module docs), which statics and stack share. The
    /// host defaults `Driver::new` would use are a Linux gateway's — 128
    /// originators, 8 interfaces, 2048-byte frames — and naming a profile is
    /// how the STM32F411 avoided discovering that at link time.
    ///
    /// `interfaces: 1` is the hardware: one slot, holding nothing until ESP-NOW
    /// lands. `max_frame_len: 512` anticipates it — ESP-NOW caps a payload at
    /// 250 bytes, so frames arrive fragmented and are reassembled up to this
    /// bound by `wayfinder-link-utils`, exactly as the LoRa and 802.15.4 links
    /// do. `originators` and `ident_table` must stay powers of two.
    pub esp32 {
        originators: 32,
        interfaces: 1,
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

/// The UART the management port speaks over. **UART0**, which is the one wired
/// to a dev board's USB-serial bridge; see [`mgmt`].
///
/// 115200 8N1, matching what `wayfinderctl --serial` opens by default.
const MGMT_BAUD: u32 = 115_200;

/// This board's driver, at the [`esp32`] capacities: one (absent) link driven
/// by the `embassy-time` clock.
type BoardDriver = wayfinder_embedded_driver::driver_for!(MeshLink, EspClock, 1, esp32);

/// Per-link Trickle schedule. One entry, for the one interface.
///
/// The numbers are the 802.15.4 link's rather than LoRa's: ESP-NOW rides the
/// Wi-Fi PHY at megabits, so it has airtime headroom closer to the nRF's radio
/// than to a duty-cycle-limited sub-GHz link. Retune once there is hardware to
/// measure, the way `docs/design/19` says for the nRF.
const TRICKLE: [TrickleParams; 1] = [TrickleParams {
    i_min: core::time::Duration::from_secs(1),
    i_max: core::time::Duration::from_secs(20),
}];

/// Per-link display name, so the management API reports something a reader can
/// place rather than a bare `0`.
///
/// **`(absent)` is in the name deliberately.** The slot holds
/// [`MeshLink::Absent`] until ESP-NOW lands, and a board advertising an
/// interface called `espnow` with zero neighbours is byte-for-byte what two
/// working boards out of range look like — every metric plausible, every timer
/// pacing, nothing wrong anywhere. Whoever is bringing this up would check
/// antennas, channel and power before finding the `Absent` in `link.rs`. Drop
/// the suffix in the same change that gives the slot a radio.
const NAMES: [&str; 1] = ["espnow(absent)"];

/// An `embassy-time`-backed [`Clock`] for the embedded driver.
///
/// Identical in shape to the nRF and STM32 boards': `embassy-time` is the one
/// timebase all three share, so the driver's `select!` between a link `recv`
/// and the OGM deadline behaves the same on every board. `esp-rtos` supplies
/// the time driver and the executor behind it.
struct EspClock;

impl Clock for EspClock {
    fn now(&self) -> core::time::Duration {
        core::time::Duration::from_micros(embassy_time::Instant::now().as_micros())
    }

    async fn sleep(&self, duration: core::time::Duration) {
        embassy_time::Timer::after(embassy_time::Duration::from_micros(
            duration.as_micros() as u64
        ))
        .await;
    }
}

#[esp_rtos::main]
async fn main(_spawner: Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));

    // Before the scheduler: `esp-rtos` allocates, and so does the `tracing`
    // dispatcher installed below.
    esp_alloc::heap_allocator!(size: HEAP_SIZE_BYTES);

    // The scheduler, and with it the `embassy-time` driver `EspClock` and every
    // `Timer::after` in the driver loop run on.
    //
    // TIMG0 rather than a SYSTIMER alarm: the original ESP32 has no SYSTIMER
    // (that is the C3/C6/S3). `FROM_CPU_INTR0` is the software interrupt
    // `esp-rtos` yields through.
    //
    // `esp-rtos` rather than `esp-hal-embassy`, which is the pairing the nRF
    // and STM32 boards' `embassy-executor` would suggest: `esp-hal-embassy`
    // 0.9.1 asks `esp-hal` for a `__esp_hal_embassy` feature that no released
    // `esp-hal` has, so it resolves against an unpublished HAL and cannot be
    // built here at all. `esp-rtos` is the supported path on esp-hal 1.x, and
    // its `embassy` feature gives the same executor and `embassy-time` queue,
    // so the driver loop is unchanged.
    esp_rtos::start(
        TimerGroup::new(peripherals.TIMG0).timer0,
        peripherals.FROM_CPU_INTR0,
    );
    // After the allocator and before the first event.
    wayfinder_log::init();

    // The first record this board emits: which firmware is running. On a part
    // reached only over a serial bridge, a banner naming the commit is what
    // distinguishes "this image booted" from "an older image is still on the
    // part".
    info!(
        version = wayfinder_version::VERSION,
        commit = wayfinder_version::COMMIT,
        dirty = wayfinder_version::DIRTY,
        source = ?wayfinder_version::SOURCE,
        "build",
    );

    // UART0 on GPIO1/GPIO3: the ESP32's U0TXD/U0RXD, which is what a dev board's
    // CP2102/CH340 bridge is wired to, so this is the port that appears on the
    // host when the USB cable goes in. `into_async` is what gives it the
    // `embedded_io_async` `Read`/`Write` that `wayfinder_server::serve` frames
    // over.
    //
    // **Both pins have to be named.** `Uart::new` builds its TX and RX as
    // `PinGuard::new_unconnected()` — it does *not* fall back to the
    // peripheral's default pins, even for UART0, even though the bootloader was
    // just logging over exactly those. A driver built without them configures
    // the peripheral, reports `Ok`, and is wired to nothing: the board answers
    // no management request and sends no byte, which from the host is
    // indistinguishable from firmware that hung during bring-up. That is
    // precisely what it did.
    let uart = Uart::new(
        peripherals.UART0,
        esp_hal::uart::Config::default().with_baudrate(MGMT_BAUD),
    );
    let mut uart = match uart {
        Ok(uart) => uart
            .with_tx(peripherals.GPIO1)
            .with_rx(peripherals.GPIO3)
            .into_async(),
        Err(e) => {
            // **The one place on this board where `esp_println` is right rather
            // than forbidden.** Everywhere else it is banned because it would
            // desynchronise the management framing on this same UART — but the
            // port just failed to configure, so there is no framing left to
            // disturb, and the `GetLogs` ring an `error!` reaches is readable
            // only over the port that does not exist. Writing the record and
            // nothing else would make this indistinguishable, from the host,
            // from a bad flash or a wrong `--baud`. `esp-println` is already
            // linked for `esp-backtrace`.
            esp_println::println!("wayfinder-esp32: FATAL: UART0 config failed: {e:?}; halting");
            error!(?e, "UART0 configuration failed; halting");
            halt();
        }
    };

    // The seed this node routes under, loaded from flash or minted on a part
    // that has never held one. Before the driver, because the mesh address is
    // derived from it.
    let mut identity: Identity =
        identity::resolve(peripherals.FLASH, peripherals.RNG, peripherals.ADC1);
    let node_mac = identity.mac();
    let mut driver: BoardDriver = Driver::with_capacities(
        node_mac,
        [MeshLink::Absent],
        EspClock,
        &TRICKLE,
        &[],
        &NAMES,
    );

    // Come back from what the last run wrote down: the clock checkpoint, then
    // the credential. Before anything is emitted, so this node's first OGM
    // already carries its authentication rather than going out unsigned and
    // being re-flooded that way.
    //
    // A board with no durable store has no record and skips this — the same
    // state as one that has never been enrolled.
    if let Some(record) = identity.record() {
        match driver.restore(record) {
            Restored::Authenticated => info!("restored membership credential from flash"),
            Restored::Unauthenticated => debug!("no stored credential; routing unauthenticated"),
            Restored::Refused(reason) => {
                warn!(
                    ?reason,
                    "stored credential refused; routing unauthenticated"
                );
            }
        }
    }

    // Which links came up, not just that the node did — the same line the nRF
    // emits, and for the reason its comment gives: a node routing over nothing
    // is otherwise indistinguishable from a healthy one, and the record saying
    // so has to exist before anyone connects to ask.
    info!(
        mac = ?node_mac,
        espnow = false,
        durable = identity.record().is_some(),
        "wayfinder started"
    );

    // The router loop and the management port, concurrently on one task.
    //
    // A `join` rather than two spawned tasks because the two need to share the
    // driver: a management *read* is answered from router state, so the query
    // channel hands a request across and the driver's own loop answers it
    // between frames. That is `run_with_mgmt`'s whole shape, and it is the same
    // arrangement `libs/wayfinder-nrf`'s `node::run` uses.
    //
    // The store a `SetAuth` over this port writes through, so an enrolment
    // survives the next reset. `Identity` picks between the flash-backed store
    // and one that refuses every write with a reason — see `identity`.
    let query_channel = EmbeddedQueryChannel::new();
    let (query_tx, query_rx) = query_channel.split();

    let (never, _) = join(
        driver.run_with_mgmt(&query_rx, identity.store_mut()),
        mgmt::serve_forever(&mut uart, &query_tx),
    )
    .await;
    never
}

/// Stop the node. For bring-up failures that no reboot would clear and that
/// leave nothing useful to run.
fn halt() -> ! {
    loop {
        // `wfi` has no Xtensa equivalent that is safe to call here without the
        // scheduler's cooperation, and this path runs before anything worth
        // powering down, so a bare spin is the honest implementation.
        core::hint::spin_loop();
    }
}
