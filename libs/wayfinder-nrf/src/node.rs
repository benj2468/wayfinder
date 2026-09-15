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
use embassy_nrf::gpio::Output;
use embassy_nrf::peripherals::USBD;
use embassy_nrf::radio::ieee802154::Radio;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;
use wayfinder::config::KeepAliveConfig;
use wayfinder::config::LinkFeatures;
use wayfinder_embedded_driver::Driver;
use wayfinder_embedded_driver::RefusalReason;
use wayfinder_embedded_driver::Restored;
use wayfinder_embedded_driver::TrickleParams;
use wayfinder_server::EmbeddedQueryChannel;

use crate::clock::EmbassyClock;
use crate::identity::Identity;
use crate::link::Ieee802154Link;
use crate::link::MeshLink;
use crate::stack;
use crate::usb_mgmt;

/// This board's link array: the built-in radio first, USB second. The order is
/// positional and matched by [`TRICKLE`] and [`features`] — see
/// [`DOT15D4`]/[`USB`].
type Links = [MeshLink; 2];

/// Index of the IEEE 802.15.4 link within [`Links`], [`TRICKLE`], and
/// [`features`]'s output. Building all three through these constants (rather
/// than three independently-ordered literals) keeps them from drifting apart:
/// swapping which link is at which index becomes one edit instead of three
/// that all have to agree.
const DOT15D4: usize = 0;
/// Index of the CDC-NCM USB link within [`Links`], [`TRICKLE`], and
/// [`features`]'s output. See [`DOT15D4`].
const USB: usize = 1;

/// IEEE 802.15.4 channel every node in this mesh uses. Deployment policy —
/// nodes on different channels never hear each other.
///
/// 15 sits between the common 2.4 GHz Wi-Fi centres (channels 1, 6 and 11), so
/// it is the least likely of the sixteen to sit under an access point. Change
/// it if a site's spectrum says otherwise; valid values are 11..=26 and
/// `Ieee802154Link::new` rejects anything else rather than panicking.
const DOT15D4_CHANNEL: u8 = 15;

/// Per-link Trickle schedules, positionally matched to [`Links`] via
/// [`DOT15D4`]/[`USB`].
///
/// The 802.15.4 slot deliberately keeps the numbers the BLE link used, even
/// though `docs/design/19-ieee802154-nrf-link.md` §2.1 measures roughly two
/// orders of magnitude more airtime headroom (~13 ms per full-cert OGM
/// against BLE extended's ~300 ms). Changing the radio and the convergence
/// schedule at once would make a regression in either indistinguishable from
/// the other. Retune once there is hardware evidence — design 19 §9.3.
const TRICKLE: [TrickleParams; 2] = {
    // Every slot gets overwritten below by name; this only satisfies the
    // repeat-array initializer.
    let mut t = [TrickleParams {
        i_min: core::time::Duration::from_secs(0),
        i_max: core::time::Duration::from_secs(0),
    }; 2];
    t[DOT15D4] = TrickleParams {
        i_min: core::time::Duration::from_secs(1),
        i_max: core::time::Duration::from_secs(20),
    };
    // The tighter of the two: USB is a wire with no airtime budget to respect
    // and no contention to back off from, so the only reason to slow down is
    // the peer's own workload. Its `i_max` is what bounds how long a host
    // waits to see the mesh after plugging in.
    t[USB] = TrickleParams {
        i_min: core::time::Duration::from_secs(1),
        i_max: core::time::Duration::from_secs(10),
    };
    t
};

/// Per-link display names, positionally matched to [`Links`] via
/// [`DOT15D4`]/[`USB`]. Without these the management API reports a board's
/// interfaces as `0`/`1`, which tells an operator staring at the TUI nothing
/// about which medium a row describes.
const NAMES: [&str; 2] = {
    let mut n = [""; 2];
    n[DOT15D4] = "dot15d4";
    n[USB] = "usb";
    n
};

/// Per-link feature matrix, positionally matched to [`Links`] via
/// [`DOT15D4`]/[`USB`]. A function rather than a `const` because
/// [`LinkFeatures`]'s defaults are not const.
///
/// The radio slot keeps a transmit keepalive for the same reason the BLE link
/// had one: link quality is sampled from received frames, so a neighbour that
/// has nothing to say still has to say something.
fn features() -> [LinkFeatures; 2] {
    let mut f = [LinkFeatures::default(); 2];
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

/// Run this node: bring up the radio and the USB device (management port plus
/// mesh link), then drive the router loop forever.
///
/// `led` is the board's liveness indicator, lit once the run loop is reached and
/// held for the task's lifetime — dropping an `Output` disconnects the pin.
/// `make_usb_driver` carries the board's `USBD` interrupt binding — see
/// [`usb_mgmt::UsbDriverFactory`].
///
/// The radio failing is fatal — it is this board's only mesh medium, and a node
/// that cannot reach the mesh at all looks healthy and is not. USB failing is
/// not, since a node that routes over its radio but cannot be watched — and
/// cannot carry the wired link — is degraded rather than dead.
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
    mut identity: Identity,
    radio: Radio<'static>,
    usbd: Peri<'static, USBD>,
    make_usb_driver: usb_mgmt::UsbDriverFactory,
    spawner: Spawner,
    mut led: Output<'static>,
) -> ! {
    // First thing in the record, before any bring-up that might fail: on a board
    // with no probe attached this line and `GetNodeInfo` are the only ways to
    // learn which firmware is actually running, and a board that halts during
    // bring-up is exactly when that matters.
    info!(
        version = wayfinder_version::VERSION,
        commit = wayfinder_version::COMMIT,
        dirty = wayfinder_version::DIRTY,
        source = ?wayfinder_version::SOURCE,
        "build",
    );

    let node_mac = identity.mac();
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

    // Sampled before `usb_link` moves into the driver.
    let usb_up = !matches!(usb_link, MeshLink::Absent);

    // The link array lives and dies inside this block, and that scope is
    // load-bearing rather than stylistic.
    //
    // `links` is moved into `Driver::with_capacities`, so it is dead the
    // instant the driver exists. But a coroutine reserves a slot for every
    // local whose *storage* is live at any suspend point, and storage lives
    // until the enclosing scope ends -- not until the last use. Declared at
    // function scope, `links` therefore kept a slot beside the driver that
    // already owns those same links, for as long as the node ran.
    //
    // **The block must evaluate to the driver alone, not to a tuple.** A tuple
    // is materialised in the enclosing coroutine's *poll* frame and then
    // destructured, which puts a second copy of this ~27 KB value on the stack
    // the executor reserves underneath the whole task body -- measured at ~27 KB
    // in the `debug` image, before `just stack-budget` moved to reading the
    // `--release` one that actually ships. That is why `usb_up` is sampled
    // above rather than returned from here.
    let mut driver: wayfinder_embedded_driver::driver_for!(_, _, 2, crate::nrf52840) = {
        // Assigned by the same DOT15D4/USB indices TRICKLE and features() are
        // built from, rather than a positional literal, so the three can't
        // drift apart.
        let mut links: Links = [MeshLink::Absent, MeshLink::Absent];
        links[DOT15D4] = MeshLink::Dot15d4(dot15d4_link);
        links[USB] = usb_link;

        // Built at this board's capacities rather than the host defaults; the
        // link and clock types are inferred, only the profile is pinned.
        Driver::with_capacities(node_mac, links, EmbassyClock, &TRICKLE, &features(), &NAMES)
    };

    // Come back from what the last run wrote down: the clock checkpoint, then
    // the credential. Before the LED and before anything is emitted, so this
    // node's first OGM already carries its authentication rather than going
    // out unsigned and being re-flooded that way.
    //
    // A board with no durable store has no record and skips this — it has
    // nothing to come back from, which is the same state as a board that has
    // never been enrolled.
    if let Some(record) = identity.record() {
        match driver.restore(record) {
            Restored::Authenticated => info!("restored membership credential from flash"),
            Restored::Unauthenticated => {
                debug!("no stored credential; routing unauthenticated")
            }
            // `error!`, not `warn!`: node-local, not reachable by any peer, not
            // retryable this boot, and the node is running in a posture an
            // operator did not choose. Every reason is stated rather than
            // summarised, because they call for different remedies.
            Restored::Refused(why) => {
                // One of these is a *latched condition*, not just a line.
                // `SetAuth` raises this alarm for the window between installing
                // a credential and the reboot that adopts its address — a
                // window that clears itself. Reaching here means the reboot has
                // happened and the two still disagree, which is the case the
                // alarm's own doc calls the genuinely bad one, and it was the
                // only one going unreported: the board is in RAM, so the
                // install-time raise did not survive the reset.
                if why == RefusalReason::CertifiedAddressMismatch {
                    wayfinder_alarm::alarm!(
                        wayfinder_alarm::Severity::Critical,
                        wayfinder_alarm::AlarmKind::CertifiedAddressMismatch,
                        wayfinder_alarm::Subject::Node(wayfinder_alarm::NodeId::new(&node_mac.0)),
                        "a stored credential names another address; this node cannot use it, \
                         and a restart will not clear it"
                    );
                }
                error!(
                    why = why.as_str(),
                    "the stored credential could not be used; routing without it"
                )
            }
        }
    }

    led.set_low();
    // Every deterministic bring-up failure is behind us; from here a fault is a
    // runtime problem the node should reboot out of rather than latch on.
    crate::fault::mark_boot_healthy();
    // Which links came up, not just that the node did: a board routing over
    // its radio alone, with no host attached, is otherwise indistinguishable
    // from a fully healthy one, and the `warn!` that said so is long gone from
    // the bounded ring by the time anyone connects.
    info!(dot15d4 = true, usb = usb_up, "wayfinder started");

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
            join(
                driver.run_with_mgmt(&query_rx, identity.store_mut()),
                usb.run(&query_tx),
            )
            .await
            .0
        }
        // Nothing will ever send on `query_rx`, so racing it would only cost an
        // idle future per loop iteration.
        None => driver.run().await,
    }
}
