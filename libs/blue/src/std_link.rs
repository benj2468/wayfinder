//! `LinkT` adapter carrying the mesh over BLE connectionless advertising on a
//! Linux host, driving BlueZ through its D-Bus API (`bluer`).
//!
//! Built on the shared [`crate::BleLink`] core (see `generic_link.rs`): this
//! module supplies a [`BleAdvertiser`] that registers a fragment as a BlueZ
//! advertisement and a background task that turns BlueZ's discovery events
//! into [`crate::BleReportSink`] submissions. Same on-air format as
//! [`crate::NrfBleLink`] (see `crate::ad`) — BlueZ assembles the Manufacturer
//! Specific Data AD structure from `Advertisement::manufacturer_data`, so this
//! side hands it the bare `[frag_header][body]` blob (`frame::build_fragment`)
//! rather than self-framing it, and on receive BlueZ hands back that same
//! blob already parsed out of the advertisement.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::time::Duration;

use bluer::Adapter;
use bluer::AdapterEvent;
use bluer::Address;
use bluer::DeviceEvent;
use bluer::DeviceProperty;
use bluer::DiscoveryFilter;
use bluer::DiscoveryTransport;
use bluer::ErrorKind;
use bluer::Session;
use bluer::adv::Advertisement;
use bluer::adv::Type as AdvertisementType;
use bluer::monitor::Monitor;
use bluer::monitor::MonitorEvent;
use bluer::monitor::MonitorHandle;
use bluer::monitor::MonitorManager;
use bluer::monitor::Pattern;
use bluer::monitor::RssiSamplingPeriod;
use bluer::monitor::Type as MonitorType;
use bluer::monitor::data_type;
use futures::StreamExt;
use futures::stream::BoxStream;
use futures::stream::SelectAll;
use tracing::debug;
use tracing::info;
use tracing::trace;
use tracing::warn;
use wayfinder::interfaces::frame::LinkFrameData;
use wayfinder::interfaces::frame::Mac;
use wayfinder::interfaces::link::LinkError;
use wayfinder::link::LinkT;
use wayfinder::link::Received;

use crate::BleAdvertiser;
use crate::BleLink;
use crate::BleReportSink;
use crate::ad::MESH_COMPANY_ID;
use crate::addr::BleAddr;

/// Deployment parameters for a [`StdBleLink`].
pub struct BleLinkParams {
    /// BlueZ adapter to use (e.g. `hci0`). `None` selects the system's
    /// default adapter, which is the right choice on a host with one
    /// controller.
    pub adapter: Option<String>,
    /// How long each fragment's advertisement stays registered with BlueZ.
    ///
    /// This is the airtime knob, and the one value here worth tuning per
    /// deployment. BlueZ tears the advertisement down as soon as the
    /// registration is dropped, so a dwell shorter than the controller's
    /// advertising interval (BlueZ's own default is ~100 ms, and this crate
    /// deliberately doesn't override it — the `MinInterval`/`MaxInterval`
    /// advertisement properties need BlueZ ≥ 5.56 plus controller support,
    /// and registration fails outright where they're unsupported) can retire
    /// a fragment before a single advertising event carried it. Raising it
    /// costs latency directly: a frame takes `dwell × fragment_count`, and a
    /// full-size frame is 14 fragments.
    pub advertise_dwell: Duration,
}

impl BleLinkParams {
    /// Default per-fragment dwell: 150 ms, comfortably past BlueZ's ~100 ms
    /// default advertising interval so each fragment gets at least one
    /// advertising event on the air. Not yet validated against real
    /// controllers — see `libs/blue/CLAUDE.md`.
    pub const DEFAULT_ADVERTISE_DWELL: Duration = Duration::from_millis(150);
}

impl Default for BleLinkParams {
    fn default() -> Self {
        Self {
            adapter: None,
            advertise_dwell: Self::DEFAULT_ADVERTISE_DWELL,
        }
    }
}

/// The [`BleAdvertiser`] backing [`StdBleLink`]: registers one fragment as a
/// BlueZ broadcast advertisement, holds the registration for
/// [`BleLinkParams::advertise_dwell`], then drops it.
///
/// The hold is the whole point — `bluer` unregisters the advertisement when
/// its handle is dropped, so a fragment advertised and immediately released
/// would never reach a scanner.
///
/// **Depends on `Privacy = device` in the host's `main.conf`.** Reassembly
/// keys on the advertiser address (`FragKey`, see `crate::generic_link`), and
/// registering one advertisement per fragment is exactly the pattern that
/// makes that address move: non-connectable advertising asks the kernel for
/// privacy, and without an RPA configured it answers with a fresh
/// *non-resolvable* private address per advertising session — so every
/// fragment of a frame would go out under a different address and never
/// reassemble. `Privacy = device` moves it onto the RPA path, which holds one
/// address for the rotation timeout (~15 min). There is no per-advertisement
/// or per-adapter override for this in BlueZ: `Advertisement` carries no
/// address field and `Adapter` exposes `address_type` read-only. See
/// `libs/blue/CLAUDE.md` for why that host dependency was accepted rather
/// than putting a sender tag in the fragment header.
struct BluerAdvertiser {
    adapter: Adapter,
    advertise_dwell: Duration,
}

impl BleAdvertiser for BluerAdvertiser {
    async fn advertise(&self, fragment: &[u8]) -> Result<(), LinkError> {
        let advertisement = Advertisement {
            // Broadcast, not the `Peripheral` default: this link is
            // connectionless, and nothing here would answer a connection
            // attempt. BlueZ also forbids `discoverable` on a broadcast
            // advertisement, so that stays unset.
            advertisement_type: AdvertisementType::Broadcast,
            manufacturer_data: BTreeMap::from([(MESH_COMPANY_ID, fragment.to_vec())]),
            // Belt-and-braces against a leaked registration: BlueZ retires the
            // advertisement on its own once this elapses, even if the handle
            // somehow outlives the dwell below.
            timeout: Some(self.advertise_dwell),
            ..Default::default()
        };

        let handle = self.adapter.advertise(advertisement).await.map_err(|e| {
            trace!(?e, "drop: BLE advertise failed");
            LinkError::TransmitFailed
        })?;
        tokio::time::sleep(self.advertise_dwell).await;
        drop(handle);
        Ok(())
    }
}

/// A [`LinkT`] carrying the mesh over BLE connectionless advertising via
/// BlueZ, wrapping the shared [`BleLink`] core. See the module doc comment
/// for how it relates to the bare-metal [`crate::NrfBleLink`].
pub struct StdBleLink {
    inner: BleLink<BluerAdvertiser>,
}

impl StdBleLink {
    /// Open the configured BlueZ adapter, power it on, and start scanning for
    /// this mesh's advertisements on a background task, returning a
    /// `LinkT`-ready handle.
    ///
    /// The scan task runs for as long as the returned link's report channel
    /// stays open — dropping the link shuts it down.
    pub async fn new(params: BleLinkParams) -> anyhow::Result<Self> {
        let session = Session::new().await?;
        let adapter = match &params.adapter {
            Some(name) => session.adapter(name)?,
            None => session.default_adapter().await?,
        };
        adapter.set_powered(true).await?;
        // The adapter's identity address is logged rather than checked. It is
        // tempting to verify the `Privacy = device` dependency that
        // `BluerAdvertiser` documents, but nothing here can: `address_type`
        // describes the *identity* address, not whether advertising uses a
        // resolvable private address, and BlueZ exposes no `Privacy` property
        // on `org.bluez.Adapter1` at all. A check on `address_type` would pass
        // on a misconfigured host, which is worse than no check — so the
        // dependency stays a documented deployment requirement (see
        // `libs/blue/CLAUDE.md`) and this is the diagnostic breadcrumb.
        info!(
            adapter = adapter.name(),
            dwell_ms = params.advertise_dwell.as_millis(),
            address = ?adapter.address().await,
            address_type = ?adapter.address_type().await,
            "BLE mesh link bound to BlueZ adapter"
        );

        let (inner, sink) = BleLink::new(BluerAdvertiser {
            adapter: adapter.clone(),
            advertise_dwell: params.advertise_dwell,
        });
        tokio::spawn(run_scanner(adapter, sink));

        Ok(Self { inner })
    }
}

/// Watch `adapter` for advertisements carrying this mesh's marker, submitting
/// each one's fragment to `sink`. Runs until `sink`'s link is dropped.
///
/// Restarts its discovery session if the stream ever ends — BlueZ can end one
/// on its own (another client changing the discovery filter, the adapter
/// being reset), which is not a fault this node can act on, so it is retried
/// rather than treated as fatal, matching the bare-metal scan loop.
async fn run_scanner(adapter: Adapter, sink: BleReportSink) {
    // Registered once for the task's lifetime, not per session. When the
    // monitor is unavailable `register_mesh_monitor` warns with the host-config
    // fix, and registering inside the retry loop below would repeat that
    // warning every second for as long as the node runs — the `warn!` flood
    // CLAUDE.md forbids. Re-registration happens only if BlueZ releases it.
    let mut monitor = register_mesh_monitor(&adapter).await;
    // Consecutive sessions that ended without the link being dropped. One is
    // routine; a run of them means the receive path is dead and nothing is
    // arriving, which an operator needs to hear about — but at a cadence that
    // doesn't flood, hence the power-of-two gate below.
    let mut consecutive: u32 = 0;

    loop {
        let outcome = scan_once(&adapter, &sink, monitor.as_mut().map(|(_, h)| h)).await;
        match outcome {
            Ok(ScanEnd::SinkClosed) => break,
            Ok(ScanEnd::MonitorReleased) => {
                warn!(
                    adapter = adapter.name(),
                    "BLE advertisement monitor released by BlueZ; duplicate filtering is back on, re-registering"
                );
                monitor = register_mesh_monitor(&adapter).await;
                consecutive = consecutive.saturating_add(1);
            }
            Ok(ScanEnd::DiscoveryEnded) => {
                consecutive = consecutive.saturating_add(1);
                if consecutive == 1 {
                    debug!(
                        adapter = adapter.name(),
                        "BLE discovery session ended; restarting"
                    );
                } else if consecutive.is_power_of_two() {
                    warn!(
                        adapter = adapter.name(),
                        consecutive,
                        "BLE discovery keeps ending immediately; no frames are being received"
                    );
                }
            }
            Err(e) => {
                consecutive = consecutive.saturating_add(1);
                if consecutive.is_power_of_two() {
                    warn!(
                        ?e,
                        adapter = adapter.name(),
                        consecutive,
                        "BLE discovery failed; retrying"
                    );
                }
            }
        }

        if sink.is_closed() {
            break;
        }
        // Don't spin on a persistently failing adapter (unplugged controller,
        // `bluetoothd` restarting) — or on a session BlueZ keeps ending
        // immediately.
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    debug!(adapter = adapter.name(), "BLE scan task stopping");
}

/// Why a [`scan_once`] session ended. Distinguishing these is what lets
/// [`run_scanner`] stay quiet for the one benign case (the link was dropped)
/// without going silent on the two that mean the receive path is dead.
enum ScanEnd {
    /// The link was dropped, so no further report could be consumed.
    SinkClosed,
    /// BlueZ ended the discovery stream — another D-Bus client changing the
    /// discovery filter, or the adapter being reset.
    DiscoveryEnded,
    /// BlueZ released the advertisement monitor, so the controller's
    /// duplicate filter is active again and frames are being lost below us.
    MonitorReleased,
}

/// The advertisement-monitor target describing this mesh's traffic.
///
/// Registering this is what keeps fragments from being dropped below us:
/// while a monitor is active the kernel runs its LE scan with the HCI
/// `filter_duplicates` parameter *disabled*. Under ordinary BlueZ discovery
/// that parameter is enabled, and controllers deduplicate reports keyed on
/// advertiser address without comparing the payload — so after a peer's first
/// advertisement got through, every later one from the same address was
/// suppressed until a scan restart flushed the controller's filter cache.
/// Since a frame spans several fragments from one address (see
/// `crate::frame`), that cost whole frames, not stray fragments.
///
/// [`RssiSamplingPeriod::All`] is the property that asks for this — the other
/// sampling modes group or suppress repeat advertisements on purpose. The
/// pattern narrows the match to our Manufacturer Specific Data so BlueZ isn't
/// asked to wake this process for all ambient BLE traffic; `start_position`
/// counts from the first byte of the AD structure's *data*, which is where
/// the little-endian company id sits (see `crate::ad`).
fn mesh_monitor() -> Monitor {
    Monitor {
        monitor_type: MonitorType::OrPatterns,
        rssi_sampling_period: Some(RssiSamplingPeriod::All),
        patterns: Some(vec![Pattern::new(
            data_type::MANUFACTURER_SPECIFIC_DATA,
            0,
            &MESH_COMPANY_ID.to_le_bytes(),
        )]),
        ..Default::default()
    }
}

/// Register [`mesh_monitor`] on `adapter`, best-effort. Returns the handles
/// that must be held for the monitor to stay active — both of them, since
/// dropping either the manager or the handle unregisters it.
///
/// `None` means this host can't offer the monitor and the link will run
/// degraded, dropping whatever the controller's duplicate filter suppresses.
/// That is not a fault this node can act on and not a reason to tear the link
/// down, so it is reported and stepped over rather than propagated. The two
/// ways it happens are worth telling apart in the log:
///
/// - `UnknownMethod` on `RegisterMonitor` — `bluetoothd` isn't exposing
///   `org.bluez.AdvertisementMonitorManager1` at all. It needs BlueZ ≥ 5.55
///   started with `--experimental` (or `Experimental = true` in
///   `main.conf`); the interface is gated behind that flag.
/// - `AdvertisementMonitorRejected` — BlueZ has the interface but declined
///   this target, typically a controller without the offload support.
async fn register_mesh_monitor(adapter: &Adapter) -> Option<(MonitorManager, MonitorHandle)> {
    let manager = match adapter.monitor().await {
        Ok(manager) => manager,
        Err(e) => {
            warn!(
                ?e,
                adapter = adapter.name(),
                "no advertisement monitor support; expect BLE frame loss (needs BlueZ >= 5.55 with --experimental)"
            );
            return None;
        }
    };
    match manager.register(mesh_monitor()).await {
        Ok(handle) => Some((manager, handle)),
        Err(e) => {
            warn!(
                ?e,
                adapter = adapter.name(),
                "advertisement monitor rejected; expect BLE frame loss"
            );
            None
        }
    }
}

/// Await `monitor`'s next event, or never resolve when there is no monitor to
/// watch — so [`scan_once`]'s corresponding `select!` arm simply stays idle on
/// a host where registration failed, rather than needing a guard expression.
async fn next_monitor_event(monitor: &mut Option<&mut MonitorHandle>) -> Option<MonitorEvent> {
    match monitor {
        Some(handle) => handle.next().await,
        None => core::future::pending().await,
    }
}

/// One scan session: open an LE discovery session against an already-registered
/// advertisement monitor, then forward every mesh-tagged fragment until the
/// session ends.
///
/// Fragments are taken from the *value carried by* each device property
/// change, never read back to service one. The distinction matters: a
/// read-back samples whatever BlueZ holds at the time the read completes, so
/// with several fragments in flight from one peer the same (latest) blob is
/// observed repeatedly and the earlier ones are never seen at all — which
/// loses the whole frame, since reassembly needs every fragment. The single
/// read-back here is a per-device *seed*, seeding state that predates the
/// subscription; see [`read_mesh_report`].
async fn scan_once(
    adapter: &Adapter,
    sink: &BleReportSink,
    monitor: Option<&mut MonitorHandle>,
) -> bluer::Result<ScanEnd> {
    adapter
        .set_discovery_filter(DiscoveryFilter {
            transport: DiscoveryTransport::Le,
            // Still required alongside the advertisement monitor, not
            // superseded by it: the two suppress duplicates at different
            // layers. The monitor disables the *controller*'s address-keyed
            // filter; this disables BlueZ's own, which otherwise emits one
            // `ManufacturerData` property change per peer and hides every
            // fragment after the first. `DiscoveryFilter` derives `Default`,
            // so leaving it off means BlueZ-level filtering is on.
            duplicate_data: true,
            ..Default::default()
        })
        .await?;
    let mut discovery = adapter.discover_devices().await?;
    let mut monitor = monitor;

    // Per-device property streams, multiplexed. Each ends when its device is
    // removed, so `SelectAll` drops it on its own. Note the bound is BlueZ's
    // cache eviction, not our discovery filter: that filter is LE-transport
    // only (the company-id pattern narrows the *monitor*, not discovery), so
    // one entry exists per ambient BLE device in range, not per mesh peer.
    let mut device_events: SelectAll<BoxStream<'static, (Address, DeviceEvent)>> = SelectAll::new();
    // Last RSSI seen per peer, bounded the same way. BlueZ delivers RSSI as
    // its own property change, which may land either side of the
    // `ManufacturerData` change it accompanies, so a fragment is tagged with
    // the freshest value known rather than blocking on one — a slightly stale
    // link-quality reading is worth far more than a dropped frame.
    let mut rssi: HashMap<Address, i16> = HashMap::new();

    loop {
        tokio::select! {
            // Checked as an arm rather than a loop condition: on a quiet radio
            // no other arm ever resolves, and a dropped link would otherwise
            // leave the discovery session and every subscription alive.
            () = sink.closed() => return Ok(ScanEnd::SinkClosed),

            // Drained purely so bluer's bounded (1024-slot) monitor event
            // channel cannot fill: its producer *awaits* the send from inside
            // BlueZ's D-Bus dispatch, so a full channel would back-pressure
            // the same dispatch that carries discovery and advertisement
            // registration. Fragment bytes come from the per-device streams
            // below, never from here.
            event = next_monitor_event(&mut monitor) => {
                if event.is_none() {
                    // The stream ends when BlueZ releases the monitor — after
                    // which the controller filters duplicates again and whole
                    // frames vanish. Surface it rather than scanning on blind.
                    return Ok(ScanEnd::MonitorReleased);
                }
            }

            event = discovery.next() => match event {
                Some(AdapterEvent::DeviceAdded(addr)) => {
                    let device = match adapter.device(addr) {
                        Ok(device) => device,
                        Err(e) => {
                            trace!(?e, ?addr, "drop: no device handle");
                            continue;
                        }
                    };
                    // Not a per-frame drop: this subscription is the only path
                    // carrying fragment bytes for this peer, so losing it makes
                    // the peer invisible for the rest of the session — while
                    // the seed below may still deliver one fragment, giving the
                    // peer a single flicker of existence. Too costly to swallow.
                    let events = match device.events().await {
                        Ok(events) => events,
                        Err(e) if matches!(e.kind, ErrorKind::DoesNotExist | ErrorKind::NotAvailable) => {
                            // Routine: peers churn out of BlueZ's cache
                            // continuously, so one vanishing here is expected.
                            trace!(?addr, "drop: device gone before event subscription");
                            continue;
                        }
                        Err(e) => {
                            warn!(
                                ?e,
                                ?addr,
                                "BLE peer event subscription failed; its frames are lost for this session"
                            );
                            continue;
                        }
                    };
                    device_events.push(events.map(move |event| (addr, event)).boxed());
                    // Seed from current state: the advertisement that caused
                    // this discovery was already recorded before the
                    // subscription above existed, so events alone would miss
                    // a peer's opening fragment. A device BlueZ already knew
                    // about replays a possibly stale fragment here, which is
                    // harmless — an incomplete message expires out of the
                    // reassembler under capacity pressure, and a complete one
                    // is a duplicate the router discards on OGM sequence
                    // number.
                    if let Some((ble_addr, seed_rssi, fragment)) = read_mesh_report(adapter, addr).await {
                        if let Some(value) = seed_rssi {
                            rssi.insert(addr, value);
                        }
                        sink.submit(ble_addr, seed_rssi, &fragment);
                    }
                }
                Some(AdapterEvent::DeviceRemoved(addr)) => {
                    rssi.remove(&addr);
                }
                Some(AdapterEvent::PropertyChanged(_)) => {}
                None => return Ok(ScanEnd::DiscoveryEnded),
            },

            Some((addr, DeviceEvent::PropertyChanged(property))) = device_events.next(),
                if !device_events.is_empty() =>
            {
                match property {
                    DeviceProperty::Rssi(value) => {
                        rssi.insert(addr, value);
                    }
                    DeviceProperty::ManufacturerData(data) => {
                        if let Some(fragment) = data.get(&MESH_COMPANY_ID) {
                            sink.submit(BleAddr::from(addr.0), rssi.get(&addr).copied(), fragment);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Read `addr`'s current advertising state, returning its BLE address, RSSI,
/// and mesh-tagged fragment bytes if it carries this mesh's marker. `None`
/// for ambient BLE traffic, and for any device whose properties have already
/// gone away — peers churn out of BlueZ's cache continuously, so a device
/// vanishing between the event and this read is routine, not an error.
///
/// Called once per newly discovered device, to seed from state that predates
/// our property subscription. Deliberately *not* used to service property
/// changes: a read-back samples current state rather than consuming the
/// value that changed, which loses fragments (see [`scan_once`]).
async fn read_mesh_report(
    adapter: &Adapter,
    addr: Address,
) -> Option<(BleAddr, Option<i16>, Vec<u8>)> {
    let device = adapter.device(addr).ok()?;
    // A bare `.ok()?` here would collapse "this device has no advertising
    // data" (routine) together with a D-Bus fault such as `bluetoothd` having
    // died or a policy denying `org.bluez.Device1` access (not routine). Those
    // look identical from outside — peers' opening fragments simply never
    // arrive — so the fault case has to say so itself.
    let manufacturer_data = match device.manufacturer_data().await {
        Ok(Some(data)) => data,
        Ok(None) => return None,
        Err(e) if matches!(e.kind, ErrorKind::DoesNotExist | ErrorKind::NotAvailable) => {
            return None;
        }
        Err(e) => {
            warn!(?e, ?addr, "BLE device property read failed");
            return None;
        }
    };
    let fragment = manufacturer_data.get(&MESH_COMPANY_ID)?.clone();
    // A separate property read, which can independently be absent for a
    // cached, out-of-range device; a missing RSSI must not discard an
    // otherwise good fragment.
    let rssi = device.rssi().await.ok().flatten();
    Some((BleAddr::from(addr.0), rssi, fragment))
}

impl LinkT for StdBleLink {
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        self.inner.send(origin, data).await
    }

    async fn recv<'a>(&'a mut self) -> Result<Received<'a>, LinkError> {
        self.inner.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The monitor exists for its kernel-level side effect, so the two
    /// properties that produce it are pinned here: `RssiSamplingPeriod::All`
    /// (anything else re-groups or suppresses repeat advertisements before
    /// they reach us) and a pattern narrow enough that BlueZ isn't asked to
    /// wake this process for all ambient BLE traffic.
    #[test]
    fn mesh_monitor_requests_every_advertisement_packet() {
        let monitor = mesh_monitor();
        assert_eq!(monitor.rssi_sampling_period, Some(RssiSamplingPeriod::All));
        assert_eq!(monitor.monitor_type, MonitorType::OrPatterns);
    }

    #[test]
    fn mesh_monitor_matches_our_company_id_at_the_start_of_manufacturer_data() {
        let monitor = mesh_monitor();
        // `start_position` 0 is the first byte of the AD structure's *data*
        // (BlueZ counts from after the length/type bytes), which is where the
        // little-endian company id sits -- see `crate::ad`.
        assert_eq!(
            monitor.patterns,
            Some(vec![Pattern::new(
                data_type::MANUFACTURER_SPECIFIC_DATA,
                0,
                &MESH_COMPANY_ID.to_le_bytes(),
            )])
        );
    }
}
