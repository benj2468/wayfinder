//! The bring-up sequence every nRF52840 board runs, once its pins are resolved.
//!
//! Ordering here is load-bearing and mostly dictated by the SoftDevice: the
//! radios come up before the management port, and `Softdevice::enable` must
//! happen after the interrupt priorities [`crate::init_platform`] sets and
//! before any syscall USB makes.

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_nrf::Peri;
use embassy_nrf::buffered_uarte::BufferedUarte;
use embassy_nrf::gpio::Output;
use embassy_nrf::interrupt::typelevel::Binding;
use embassy_nrf::peripherals::USBD;
use embassy_nrf::usb::InterruptHandler;
use embassy_time::Duration;
use embassy_time::Timer;
use embassy_time::with_timeout;
use nrf_softdevice::SocEvent;
use nrf_softdevice::Softdevice;
use rylr998::Bandwidth;
use rylr998::CodingRate;
use rylr998::LoraError;
use rylr998::RylrClient;
use rylr998::SpreadingFactory;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;
use wayfinder::config::KeepAliveConfig;
use wayfinder::config::LinkFeatures;
use wayfinder::interfaces::frame::Mac;
use wayfinder_embedded_driver::Driver;
use wayfinder_embedded_driver::TrickleParams;
use wayfinder_server::EmbeddedQueryChannel;

use crate::clock::EmbassyClock;
use crate::link::MeshLink;
use crate::stack;
use crate::usb_mgmt;

/// The serial transport a board's RYLR998 link speaks over.
type Serial = BufferedUarte<'static>;

/// This board's link array: LoRa first, BLE second. The order is positional and
/// matched by [`TRICKLE`] and [`features`] — see [`LORA`]/[`BLE`].
type Links = [MeshLink<Serial>; 2];

/// Index of the LoRa link within [`Links`], [`TRICKLE`], and [`features`]'s
/// output. Building all three through these constants (rather than three
/// independently-ordered literals) keeps them from drifting apart: swapping
/// which link is at which index becomes one edit instead of three that all
/// have to agree.
const LORA: usize = 0;
/// Index of the BLE link within [`Links`], [`TRICKLE`], and [`features`]'s
/// output. See [`LORA`].
const BLE: usize = 1;

/// LoRa network id shared by every node in this mesh (RYLR `AT+NETWORKID`).
const LORA_NETWORK_ID: u8 = 18;

/// How many `AT` pings (1s timeout each) before concluding no RYLR998 is wired
/// to this UART and continuing BLE-only, rather than blocking boot forever on a
/// reply that will never come. ~3s covers the module's own boot delay without
/// noticeably stalling a BLE-only board.
const RYLR_PING_ATTEMPTS: u32 = 3;

/// Per-link Trickle schedules, positionally matched to [`Links`] via
/// [`LORA`]/[`BLE`]. LoRa gets a relaxed cadence suited to its airtime budget;
/// BLE's tighter bounds reflect its much higher duty-cycle budget, and its
/// `i_max` is mirrored by `ogm.i_max_ms` on the `Ble` link in
/// `var/conf/install.yml` so a host node and a board agree on the schedule.
const TRICKLE: [TrickleParams; 2] = {
    // Every slot gets overwritten below by name; this only satisfies the
    // repeat-array initializer.
    let mut t = [TrickleParams {
        i_min: core::time::Duration::from_secs(0),
        i_max: core::time::Duration::from_secs(0),
    }; 2];
    t[LORA] = TrickleParams {
        i_min: core::time::Duration::from_secs(5),
        i_max: core::time::Duration::from_secs(128),
    };
    t[BLE] = TrickleParams {
        i_min: core::time::Duration::from_secs(1),
        i_max: core::time::Duration::from_secs(20),
    };
    t
};

/// Per-link feature matrix, positionally matched to [`Links`] via
/// [`LORA`]/[`BLE`]. A function rather than a `const` because
/// [`LinkFeatures`]'s defaults are not const.
fn features() -> [LinkFeatures; 2] {
    let mut f = [LinkFeatures::default(); 2];
    f[BLE] = LinkFeatures {
        tx_keepalive: Some(KeepAliveConfig { interval_ms: 5000 }),
        ..Default::default()
    };
    f
}

/// Stop the node, leaving its liveness LED dark. For bring-up failures that no
/// reboot would clear and that leave nothing useful to run.
fn halt() -> ! {
    loop {
        cortex_m::asm::wfe();
    }
}

/// The SoftDevice's single event pump, forwarding SoC events to the USB power
/// handler. BLE events are consumed internally by `nrf-softdevice`.
#[embassy_executor::task]
async fn softdevice_task(sd: &'static Softdevice, on_soc_event: fn(SocEvent)) -> ! {
    sd.run_with_callback(on_soc_event).await
}

/// Bring up a RYLR998 on `uarte`, if one is actually wired to it.
///
/// Unlike BLE, this is an external module a board may or may not have attached,
/// so a radio that never answers `ping` is a normal shape (a BLE-only
/// deployment) and degrades to [`MeshLink::Absent`]. A module that *does* answer
/// but then rejects configuration is a different problem — present and
/// malfunctioning — and halts rather than relaying on the wrong address or
/// network, where it would be silently deaf or cross-contaminating another
/// node's fragment reassembly.
async fn bring_up_rylr(uarte: Serial, lora_address: u16) -> MeshLink<Serial> {
    let Ok(mut client) = RylrClient::new(uarte) else {
        warn!("RYLR998 serial init failed; continuing BLE-only");
        return MeshLink::Absent;
    };

    let mut detected = false;
    for _ in 0..RYLR_PING_ATTEMPTS {
        if with_timeout(Duration::from_secs(1), client.ping())
            .await
            .is_ok()
        {
            detected = true;
            break;
        }
        trace!("waiting for radio to boot");
    }
    if !detected {
        warn!("RYLR998 not detected; continuing BLE-only");
        return MeshLink::Absent;
    }

    let configured = async {
        client.set_address(lora_address).await?;
        client.set_network_id(LORA_NETWORK_ID).await?;
        client
            .set_parameters(
                SpreadingFactory::Sf7,
                Bandwidth::Khz125,
                CodingRate::Cr48,
                15,
            )
            .await?;
        Ok::<(), LoraError>(())
    }
    .await;
    if let Err(e) = configured {
        error!(?e, "RYLR998 present but configuration failed; halting");
        halt();
    }
    MeshLink::Rylr(client)
}

/// Run this node: bring up both radios and the USB management port, then drive
/// the router loop forever.
///
/// `led` is the board's liveness indicator, lit once the run loop is reached and
/// held for the task's lifetime — dropping an `Output` disconnects the pin.
/// `irqs` is the board's `bind_interrupts!` struct, which must bind `USBD`.
///
/// A radio failing is fatal, since a relay with only its optional interface
/// working looks healthy and is not; the management port failing is not, since a
/// node that routes but cannot be watched is degraded rather than dead.
pub async fn run<I>(
    node_mac: Mac,
    uarte: Serial,
    usbd: Peri<'static, USBD>,
    irqs: I,
    spawner: Spawner,
    mut led: Output<'static>,
) -> !
where
    I: Binding<embassy_nrf::interrupt::typelevel::USBD, InterruptHandler<USBD>> + 'static,
{
    let lora_address = u16::from_be_bytes([node_mac.0[4], node_mac.0[5]]);
    let rylr_link = bring_up_rylr(uarte, lora_address).await;

    // TODO: unconfirmed workaround, added during hardware bring-up with no
    // recorded root cause. Suspected to paper over a SoftDevice-enable race
    // against the RYLR998 UART bring-up above, but unverified against real
    // hardware. Don't remove without confirming BLE bring-up stays reliable.
    debug!("waiting 1s before starting BLE");
    Timer::after_secs(1).await;

    // The event pump is the only place SoC events are delivered, so USB power
    // detection rides along with it — see `usb_mgmt`.
    let sd = Softdevice::enable(&Default::default());
    match softdevice_task(sd, usb_mgmt::on_soc_event) {
        Ok(task) => spawner.spawn(task),
        Err(e) => {
            error!(?e, "softdevice event-pump task spawn failed; halting");
            halt();
        }
    }

    let ble_link = match crate::link::NrfBleLink::new(spawner, sd) {
        Ok(link) => link,
        Err(e) => {
            error!(?e, "BLE bring-up failed; halting");
            halt();
        }
    };
    debug!("BLE link brought up");

    let usb = match usb_mgmt::init(usbd, irqs, node_mac).await {
        Ok(usb) => Some(usb),
        Err(e) => {
            error!(?e, "USB management port unavailable; continuing without it");
            None
        }
    };

    // Assigned by the same LORA/BLE indices TRICKLE and features() are built
    // from, rather than a positional literal, so the three can't drift apart.
    let mut links: Links = [MeshLink::Absent, MeshLink::Absent];
    links[LORA] = rylr_link;
    links[BLE] = MeshLink::Ble(ble_link);
    // Built at this board's capacities rather than the host defaults; the link
    // and clock types are inferred, only the profile is pinned.
    let mut driver: wayfinder_embedded_driver::driver_for!(_, _, 2, crate::nrf52840) =
        Driver::with_capacities(node_mac, links, EmbassyClock, &TRICKLE, &features());

    led.set_low();
    // Every deterministic bring-up failure is behind us; from here a fault is a
    // runtime problem the node should reboot out of rather than latch on.
    crate::fault::mark_boot_healthy();
    info!("wayfinder started");

    // Best-effort: a board that cannot spawn the watcher is still a working
    // node, and losing a diagnostic is not worth refusing to run over.
    match stack::watch() {
        Ok(task) => spawner.spawn(task),
        Err(e) => warn!(?e, "stack watcher unavailable; high-water reporting off"),
    }

    // Both ends borrow the channel and both futures are joined below, so it can
    // live on this task's stack.
    let query_channel = EmbeddedQueryChannel::new();
    let (query_tx, query_rx) = query_channel.split();

    match usb {
        Some(usb) => {
            join(driver.run_with_mgmt(&query_rx), usb.run(&query_tx))
                .await
                .0
        }
        // Nothing will ever send on `query_rx`, so racing it would only cost an
        // idle future per loop iteration.
        None => driver.run().await,
    }
}
