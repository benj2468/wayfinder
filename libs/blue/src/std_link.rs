//! `LinkT` adapter carrying the mesh over BLE connectionless advertising on a
//! Linux host, driving BlueZ through its D-Bus API (`bluer`).
//!
//! Built on the shared [`crate::BleLink`] core: this module supplies a
//! [`BleAdvertiser`] that registers a fragment as a BlueZ advertisement, plus a
//! background task turning BlueZ's discovery events into
//! [`crate::BleReportSink`] submissions.
//!
//! BlueZ assembles the Manufacturer Specific Data AD structure itself, so this
//! side passes the bare `[frag_header][body]` blob (`frame::build_fragment`)
//! rather than self-framing it as [`crate::NrfBleLink`] does — the asymmetry
//! `libs/blue/CLAUDE.md` warns about.

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
    /// The airtime knob, and the one value here worth tuning per deployment.
    /// It must outlast [`ADVERTISING_INTERVAL`] (the on-air repeat interval
    /// this crate explicitly requests, `min_interval`/`max_interval` on the
    /// `Advertisement`) by enough to cover several repeats, not just one — a
    /// single on-air transmission is one coin flip against a scanner that
    /// isn't listening at that exact moment. Raising it costs latency
    /// directly: a frame takes `dwell × fragment_count`, up to 14 fragments.
    pub advertise_dwell: Duration,
}

impl BleLinkParams {
    /// Default per-fragment dwell: 150 ms, giving several repeats at
    /// [`ADVERTISING_INTERVAL`] (20 ms) before the advertising set is torn
    /// down. Confirmed via `btmon` against a real controller — see
    /// `libs/blue/CLAUDE.md`.
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
/// never reaches a scanner.
///
/// No longer depends on `Privacy = device` in the host's `main.conf` for
/// correctness (previously documented here): registering a fresh
/// advertisement per fragment was assumed to hold one address for BlueZ's
/// RPA rotation timeout, but a `btmon` capture against a real controller
/// showed it drawing a new random address on *every* registration — so
/// reassembly no longer keys on the advertiser address at all (see
/// `crate::frame::ORIGIN_LEN`) and this requirement is gone. See
/// `libs/blue/CLAUDE.md`.
struct BluerAdvertiser {
    adapter: Adapter,
    advertise_dwell: Duration,
}

/// On-air advertising interval requested for each fragment's advertising set,
/// in both `MinInterval` and `MaxInterval` — BlueZ's own protocol minimum
/// (`bluer::adv::Advertisement::min_interval`'s valid range starts at 20ms)
/// and the same cadence `nrf_link.rs`'s `ADV_INTERVAL_625US` uses.
///
/// Left unset, BlueZ picks its own default — observed at 1280ms on one real
/// controller (`btmon`), an order of magnitude past `advertise_dwell`. A
/// fragment's advertising set is only enabled for `advertise_dwell` before
/// being torn down, so at a 1280ms interval most fragments got exactly one
/// on-air transmission before teardown and some got zero (confirmed via the
/// `LE Advertising Set Terminated` event's "Number of completed extended
/// advertising events" field) — no redundancy against a scanner that isn't
/// listening at that exact moment. At 20ms, `advertise_dwell` (150ms default)
/// instead covers several repeats per fragment.
const ADVERTISING_INTERVAL: Duration = Duration::from_millis(20);

/// Build the BlueZ advertisement for one fragment: broadcast-only manufacturer
/// data carrying `fragment`, torn down no later than `advertise_dwell`, and
/// repeated on-air every [`ADVERTISING_INTERVAL`] for as long as it stays
/// registered.
fn build_advertisement(fragment: &[u8], advertise_dwell: Duration) -> Advertisement {
    Advertisement {
        // Broadcast, not the `Peripheral` default: nothing here would
        // answer a connection attempt. BlueZ forbids `discoverable` on a
        // broadcast advertisement, so that stays unset.
        advertisement_type: AdvertisementType::Broadcast,
        manufacturer_data: BTreeMap::from([(MESH_COMPANY_ID, fragment.to_vec())]),
        // Backstop against a leaked registration outliving the dwell below.
        timeout: Some(advertise_dwell),
        min_interval: Some(ADVERTISING_INTERVAL),
        max_interval: Some(ADVERTISING_INTERVAL),
        ..Default::default()
    }
}

impl BleAdvertiser for BluerAdvertiser {
    async fn advertise(&self, fragment: &[u8]) -> Result<(), LinkError> {
        let advertisement = build_advertisement(fragment, self.advertise_dwell);

        let handle = self.adapter.advertise(advertisement).await.map_err(|e| {
            trace!(?e, "drop: BLE advertise failed");
            LinkError::TransmitFailed
        })?;
        trace!(
            dwell_ms = self.advertise_dwell.as_millis(),
            "BLE advertisement registered"
        );
        tokio::time::sleep(self.advertise_dwell).await;
        // `drop(handle)` only closes a oneshot channel; the actual
        // `UnregisterAdvertisement` D-Bus call runs on a task `bluer` detaches
        // internally and is not awaited here, so in principle this
        // fragment's registration could still be live with BlueZ when the
        // next fragment's `advertise()` call registers a second one. A
        // `btmon` capture against a real controller found no such overlap in
        // practice (each advertising set's `LE Remove Advertising Set`
        // completed before the next one's registration began) — the
        // confirmed failure mode was the on-air advertising interval, not
        // this race; see `ADVERTISING_INTERVAL` and `libs/blue/CLAUDE.md`.
        // Left as a documented latent risk, not a demonstrated one.
        drop(handle);
        trace!("BLE advertisement unregister requested (not confirmed by bluer)");
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
        // Logged, not checked. `BluerAdvertiser`'s `Privacy = device`
        // dependency is unverifiable from here: `address_type` describes the
        // *identity* address, and BlueZ exposes no `Privacy` property at all,
        // so a check would pass on a misconfigured host. This is the
        // diagnostic breadcrumb instead.
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
    // Once for the task's lifetime, not per session: `register_mesh_monitor`
    // warns when unavailable, and registering inside the retry loop would
    // repeat that warning every second for as long as the node runs.
    let mut monitor = register_mesh_monitor(&adapter).await;
    // Consecutive sessions that ended without the link being dropped. One is
    // routine; a run of them means the receive path is dead. The power-of-two
    // gate below is what keeps saying so from becoming a flood.
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
/// Registering this is what keeps fragments from being dropped below us: only
/// while a monitor is active does the kernel run its LE scan with HCI
/// `filter_duplicates` *disabled*. Otherwise the controller deduplicates on
/// advertiser address without comparing payloads, and since a frame spans
/// several fragments from one address that costs whole frames.
///
/// [`RssiSamplingPeriod::All`] is the property that asks for it — every other
/// sampling mode groups or suppresses repeats on purpose. The pattern narrows
/// the match so BlueZ need not wake this process for ambient BLE traffic;
/// `start_position` counts from the AD structure's *data*, where the
/// little-endian company id sits.
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
/// `None` means this host can't offer the monitor and the link runs degraded,
/// dropping whatever the controller's duplicate filter suppresses — reported
/// and stepped over rather than torn down, since the node cannot act on it.
/// Two distinct causes, worth telling apart in the log: `UnknownMethod` means
/// `bluetoothd` is not exposing `AdvertisementMonitorManager1` (needs BlueZ ≥
/// 5.55 with `Experimental = true`), while `AdvertisementMonitorRejected`
/// means it has the interface but declined this target.
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
/// Fragments come from the *value carried by* each property change, never a
/// read-back: a read samples whatever BlueZ holds when it completes, so with
/// several fragments in flight from one peer it observes the latest blob
/// repeatedly and loses the whole frame. The one read-back here seeds state
/// predating the subscription; see [`read_mesh_report`].
async fn scan_once(
    adapter: &Adapter,
    sink: &BleReportSink,
    monitor: Option<&mut MonitorHandle>,
) -> bluer::Result<ScanEnd> {
    adapter
        .set_discovery_filter(DiscoveryFilter {
            transport: DiscoveryTransport::Le,
            // Required alongside the monitor, not superseded by it: the two
            // filter at different layers. This one disables BlueZ's own
            // suppression, which otherwise emits a single `ManufacturerData`
            // change per peer and hides every fragment after the first.
            // `DiscoveryFilter` derives `Default`, so omitting it leaves the
            // filtering on.
            duplicate_data: true,
            ..Default::default()
        })
        .await?;
    let mut discovery = adapter.discover_devices().await?;
    let mut monitor = monitor;

    // Per-device property streams, multiplexed; each ends when its device is
    // removed, so `SelectAll` drops it. Bounded by BlueZ's cache eviction, not
    // by the discovery filter — the company-id pattern narrows the *monitor* —
    // so there is one entry per ambient BLE device in range, not per peer.
    let mut device_events: SelectAll<BoxStream<'static, (Address, DeviceEvent)>> = SelectAll::new();
    // Last RSSI seen per peer, bounded the same way. RSSI arrives as its own
    // property change, either side of the `ManufacturerData` one it
    // accompanies, so a fragment is tagged with the freshest value known
    // rather than waiting — a stale reading beats a dropped frame.
    let mut rssi: HashMap<Address, i16> = HashMap::new();

    loop {
        tokio::select! {
            // Checked as an arm rather than a loop condition: on a quiet radio
            // no other arm ever resolves, and a dropped link would otherwise
            // leave the discovery session and every subscription alive.
            () = sink.closed() => return Ok(ScanEnd::SinkClosed),

            // Drained purely so bluer's bounded monitor event channel cannot
            // fill: its producer awaits the send from inside BlueZ's D-Bus
            // dispatch, the same dispatch carrying discovery and advertisement
            // registration. Fragment bytes never come from here.
            event = next_monitor_event(&mut monitor) => {
                if event.is_none() {
                    // BlueZ released the monitor, so the controller filters
                    // duplicates again and whole frames vanish.
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
                    // the peer invisible for the rest of the session.
                    let events = match device.events().await {
                        Ok(events) => events,
                        Err(e) if matches!(e.kind, ErrorKind::DoesNotExist | ErrorKind::NotAvailable) => {
                            // Routine: peers churn out of BlueZ's cache.
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
                    // this discovery predates the subscription above, so events
                    // alone would miss a peer's opening fragment. Replaying a
                    // stale fragment for an already-known device is harmless —
                    // an incomplete message expires out of the reassembler, and
                    // a complete one is a duplicate the router discards.
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
/// and fragment bytes if it carries this mesh's marker. `None` for ambient BLE
/// traffic and for a device whose properties have already gone away, which is
/// routine — peers churn out of BlueZ's cache continuously.
///
/// Called once per newly discovered device, to seed state predating our
/// property subscription. Deliberately *not* used to service property changes;
/// see [`scan_once`].
async fn read_mesh_report(
    adapter: &Adapter,
    addr: Address,
) -> Option<(BleAddr, Option<i16>, Vec<u8>)> {
    let device = adapter.device(addr).ok()?;
    // A bare `.ok()?` would collapse "no advertising data" (routine) into a
    // D-Bus fault such as a dead `bluetoothd` (not routine). Both look
    // identical from outside — opening fragments never arrive — so the fault
    // case has to say so itself.
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

    /// Left unset, BlueZ picks its own default advertising interval instead
    /// of ours — observed via `btmon` at 1280ms on a real controller, an
    /// order of magnitude past `advertise_dwell`, which starves most
    /// fragments of more than one on-air transmission before their
    /// advertising set is torn down. Both bounds must be set to
    /// `ADVERTISING_INTERVAL` explicitly so a fragment gets repeated
    /// transmissions within its dwell window instead of relying on
    /// whatever BlueZ defaults to.
    #[test]
    fn build_advertisement_sets_explicit_advertising_interval() {
        let advertisement = build_advertisement(&[1, 2, 3], Duration::from_millis(150));
        assert_eq!(advertisement.min_interval, Some(ADVERTISING_INTERVAL));
        assert_eq!(advertisement.max_interval, Some(ADVERTISING_INTERVAL));
    }

    #[test]
    fn build_advertisement_carries_fragment_as_manufacturer_data_and_dwell_as_timeout() {
        let dwell = Duration::from_millis(150);
        let advertisement = build_advertisement(&[1, 2, 3], dwell);
        assert_eq!(
            advertisement.advertisement_type,
            AdvertisementType::Broadcast
        );
        assert_eq!(
            advertisement.manufacturer_data,
            BTreeMap::from([(MESH_COMPANY_ID, vec![1, 2, 3])])
        );
        assert_eq!(advertisement.timeout, Some(dwell));
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
