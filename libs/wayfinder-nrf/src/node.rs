//! The bring-up sequence every nRF52840 board runs, once its pins are resolved.
//!
//! Ordering is no longer dictated by anything but taste — the radios come up
//! before USB because a radio failure is fatal and a USB failure is not, so
//! the fatal check runs first. It used to be forced: the SoftDevice had to be
//! enabled after [`crate::init_platform`] set interrupt priorities and before
//! any syscall the USB path made.

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_nrf::Peri;
use embassy_nrf::buffered_uarte::BufferedUarte;
use embassy_nrf::gpio::Output;
use embassy_nrf::peripherals::USBD;
use embassy_nrf::radio::ieee802154::Radio;
use embassy_time::Duration;
use embassy_time::with_timeout;
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
use crate::link::Ieee802154Link;
use crate::link::MeshLink;
use crate::stack;
use crate::usb_mgmt;

/// The serial transport a board's RYLR998 link speaks over.
type Serial = BufferedUarte<'static>;

/// This board's link array: LoRa first, the built-in radio second, USB third.
/// The order is positional and matched by [`TRICKLE`] and [`features`] — see
/// [`LORA`]/[`DOT15D4`]/[`USB`].
type Links = [MeshLink<Serial>; 3];

/// Index of the LoRa link within [`Links`], [`TRICKLE`], and [`features`]'s
/// output. Building all three through these constants (rather than three
/// independently-ordered literals) keeps them from drifting apart: swapping
/// which link is at which index becomes one edit instead of three that all
/// have to agree.
const LORA: usize = 0;
/// Index of the IEEE 802.15.4 link within [`Links`], [`TRICKLE`], and
/// [`features`]'s output. See [`LORA`].
const DOT15D4: usize = 1;
/// Index of the CDC-NCM USB link within [`Links`], [`TRICKLE`], and
/// [`features`]'s output. See [`LORA`].
const USB: usize = 2;

/// LoRa network id shared by every node in this mesh (RYLR `AT+NETWORKID`).
const LORA_NETWORK_ID: u8 = 18;

/// IEEE 802.15.4 channel every node in this mesh uses. Deployment policy, like
/// [`LORA_NETWORK_ID`] — nodes on different channels never hear each other.
///
/// 15 sits between the common 2.4 GHz Wi-Fi centres (channels 1, 6 and 11), so
/// it is the least likely of the sixteen to sit under an access point. Change
/// it if a site's spectrum says otherwise; valid values are 11..=26 and
/// `Ieee802154Link::new` rejects anything else rather than panicking.
const DOT15D4_CHANNEL: u8 = 15;

/// How many `AT` pings (1s timeout each) before concluding no RYLR998 is wired
/// to this UART and continuing without it, rather than blocking boot forever
/// on a reply that will never come. ~3s covers the module's own boot delay
/// without noticeably stalling a board that has no LoRa module.
const RYLR_PING_ATTEMPTS: u32 = 3;

/// Per-link Trickle schedules, positionally matched to [`Links`] via
/// [`LORA`]/[`DOT15D4`]/[`USB`]. LoRa gets a relaxed cadence suited to its
/// airtime budget; the 802.15.4 radio's tighter bounds reflect its much
/// higher duty-cycle budget.
///
/// The 802.15.4 slot deliberately keeps the numbers the BLE link used, even
/// though `docs/design/19-ieee802154-nrf-link.md` §2.1 measures roughly two
/// orders of magnitude more airtime headroom (~13 ms per full-cert OGM
/// against BLE extended's ~300 ms). Changing the radio and the convergence
/// schedule at once would make a regression in either indistinguishable from
/// the other. Retune once there is hardware evidence — design 19 §9.3.
const TRICKLE: [TrickleParams; 3] = {
    // Every slot gets overwritten below by name; this only satisfies the
    // repeat-array initializer.
    let mut t = [TrickleParams {
        i_min: core::time::Duration::from_secs(0),
        i_max: core::time::Duration::from_secs(0),
    }; 3];
    t[LORA] = TrickleParams {
        i_min: core::time::Duration::from_secs(5),
        i_max: core::time::Duration::from_secs(128),
    };
    t[DOT15D4] = TrickleParams {
        i_min: core::time::Duration::from_secs(1),
        i_max: core::time::Duration::from_secs(20),
    };
    // The tightest schedule of the three: USB is a wire with no airtime budget
    // to respect and no contention to back off from, so the only reason to
    // slow down is the peer's own workload. Its `i_max` is what bounds how long
    // a host waits to see the mesh after plugging in.
    t[USB] = TrickleParams {
        i_min: core::time::Duration::from_secs(1),
        i_max: core::time::Duration::from_secs(10),
    };
    t
};

/// Per-link display names, positionally matched to [`Links`] via
/// [`LORA`]/[`DOT15D4`]/[`USB`]. Without these the management API reports a
/// board's three interfaces as `0`/`1`/`2`, which tells an operator staring at
/// the TUI nothing about which radio a row describes.
const NAMES: [&str; 3] = {
    let mut n = [""; 3];
    n[LORA] = "lora";
    n[DOT15D4] = "dot15d4";
    n[USB] = "usb";
    n
};

/// Per-link feature matrix, positionally matched to [`Links`] via
/// [`LORA`]/[`DOT15D4`]/[`USB`]. A function rather than a `const` because
/// [`LinkFeatures`]'s defaults are not const.
///
/// The radio slot keeps a transmit keepalive for the same reason the BLE link
/// had one: link quality is sampled from received frames, so a neighbour that
/// has nothing to say still has to say something.
fn features() -> [LinkFeatures; 3] {
    let mut f = [LinkFeatures::default(); 3];
    f[DOT15D4] = LinkFeatures {
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

/// Bring up a RYLR998 on `uarte`, if one is actually wired to it.
///
/// Unlike the built-in 802.15.4 radio, this is an external module a board may
/// or may not have attached, so a radio that never answers `ping` is a normal
/// shape (an 802.15.4-only deployment) and degrades to [`MeshLink::Absent`]. A module that *does* answer
/// but then rejects configuration is a different problem — present and
/// malfunctioning — and halts rather than relaying on the wrong address or
/// network, where it would be silently deaf or cross-contaminating another
/// node's fragment reassembly.
async fn bring_up_rylr(uarte: Serial, lora_address: u16) -> MeshLink<Serial> {
    let Ok(mut client) = RylrClient::new(uarte) else {
        warn!("RYLR998 serial init failed; continuing without LoRa");
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
        warn!("RYLR998 not detected; continuing without LoRa");
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

/// Run this node: bring up both radios and the USB device (management port plus
/// mesh link), then drive the router loop forever.
///
/// `led` is the board's liveness indicator, lit once the run loop is reached and
/// held for the task's lifetime — dropping an `Output` disconnects the pin.
/// `make_usb_driver` carries the board's `USBD` interrupt binding — see
/// [`usb_mgmt::UsbDriverFactory`].
///
/// A radio failing is fatal, since a relay with only its optional interface
/// working looks healthy and is not; USB failing is not, since a node that
/// routes over its radios but cannot be watched — and cannot carry the wired
/// link — is degraded rather than dead.
///
/// # This is the spawned task, deliberately
///
/// A board spawns *this* function rather than its own `#[task]` that awaits
/// it, and the difference is not cosmetic — it is ~62 KB of stack.
///
/// `.await`ing this future from another `async fn` makes it a field of that
/// outer coroutine, and rustc builds it in a stack temporary and `memcpy`s it
/// in. The temporary is reserved by the outer task's poll prologue, so it is
/// held for as long as the node runs rather than freed after the copy. This
/// future is ~62 KB (it owns the ~43 KB [`Driver`]), and under `flip-link` the
/// stack is only what `memory.x` leaves over after the statics — 112,600 bytes
/// on the DK. That copy, plus this function's own frame (~28 KB) and
/// `Driver::with_capacities`' (~26 KB), came to 117,376 and ran off the bottom
/// of RAM into the SoftDevice's then-reserved region, which it trapped as
/// `NRF_FAULT_ID_APP_MEMACC` — a silent stop right after the radio's
/// bring-up log line, from a node that had already died.
///
/// The SoftDevice is gone and its 13,112 bytes are back, so that exact
/// overflow no longer fits; the reasoning is kept because the mechanism has
/// not changed, and `flip-link` now puts a stack overflow into a fault rather
/// than into the statics. `just stack-budget` is what actually holds the
/// line.
///
/// Spawning this directly removes the wrapper coroutine and so the copy: the
/// future is written into the task pool from the caller's (shallow) frame at
/// boot, and only the ~28 KB + ~26 KB remain at the deepest point.
///
/// An `#[embassy_executor::task]` cannot be generic, which is why the `USBD`
/// binding arrives as a `fn` pointer instead of an `impl Binding<..>`.
#[embassy_executor::task]
pub async fn run(
    node_mac: Mac,
    uarte: Serial,
    radio: Radio<'static>,
    usbd: Peri<'static, USBD>,
    make_usb_driver: usb_mgmt::UsbDriverFactory,
    spawner: Spawner,
    mut led: Output<'static>,
) -> ! {
    // The same short address the 802.15.4 link derives, from the same `Mac`,
    // so a node's two radios agree on its short identity.
    let lora_address = ieee802154::short_address_of(node_mac);
    let rylr_link = bring_up_rylr(uarte, lora_address).await;

    // The 1s sleep that used to sit here is gone with the SoftDevice it was
    // guarding: it was an unconfirmed workaround suspected of papering over a
    // `Softdevice::enable` race against the RYLR998 UART bring-up above. There
    // is no longer an enable to race. If bring-up turns out to be flaky
    // without it, that is a real bug to find rather than a delay to restore.
    let dot15d4_link = match Ieee802154Link::new(spawner, radio, DOT15D4_CHANNEL) {
        Ok(link) => link,
        Err(e) => {
            error!(?e, "802.15.4 bring-up failed; halting");
            halt();
        }
    };
    debug!(channel = DOT15D4_CHANNEL, "802.15.4 link brought up");

    // Both USB functions come from one device, so this either yields the
    // management port *and* the mesh link or neither.
    let (usb, usb_link) = match usb_mgmt::init(usbd, make_usb_driver, node_mac, spawner).await {
        Ok((usb, link)) => (Some(usb), MeshLink::Usb(link)),
        Err(e) => {
            error!(?e, "USB unavailable; continuing without port or mesh link");
            (None, MeshLink::Absent)
        }
    };

    // Assigned by the same LORA/DOT15D4/USB indices TRICKLE and features() are
    // built from, rather than a positional literal, so the three can't drift
    // apart.
    let mut links: Links = [MeshLink::Absent, MeshLink::Absent, MeshLink::Absent];
    links[LORA] = rylr_link;
    links[DOT15D4] = MeshLink::Dot15d4(dot15d4_link);
    links[USB] = usb_link;

    // Sampled before `links` moves into the driver.
    let lora_up = !matches!(links[LORA], MeshLink::Absent);
    let usb_up = !matches!(links[USB], MeshLink::Absent);

    // Built at this board's capacities rather than the host defaults; the link
    // and clock types are inferred, only the profile is pinned.
    let mut driver: wayfinder_embedded_driver::driver_for!(_, _, 3, crate::nrf52840) =
        Driver::with_capacities(node_mac, links, EmbassyClock, &TRICKLE, &features(), &NAMES);

    led.set_low();
    // Every deterministic bring-up failure is behind us; from here a fault is a
    // runtime problem the node should reboot out of rather than latch on.
    crate::fault::mark_boot_healthy();
    // Which links came up, not just that the node did: a board running on
    // one of three configured interfaces is otherwise indistinguishable from
    // a healthy one, and the `warn!`s that said so are long gone from the
    // bounded ring by the time anyone connects.
    info!(
        lora = lora_up,
        dot15d4 = true,
        usb = usb_up,
        "wayfinder started"
    );

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
