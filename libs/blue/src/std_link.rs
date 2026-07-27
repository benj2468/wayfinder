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
use std::time::Duration;

use bluer::Adapter;
use bluer::AdapterEvent;
use bluer::Address;
use bluer::DiscoveryFilter;
use bluer::DiscoveryTransport;
use bluer::Session;
use bluer::adv::Advertisement;
use bluer::adv::Type as AdvertisementType;
use futures::StreamExt;
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
        info!(
            adapter = adapter.name(),
            dwell_ms = params.advertise_dwell.as_millis(),
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
    while !sink.is_closed() {
        if let Err(e) = scan_once(&adapter, &sink).await {
            warn!(
                ?e,
                adapter = adapter.name(),
                "BLE discovery failed; retrying"
            );
        }
        // Don't spin on a persistently failing adapter (unplugged controller,
        // `bluetoothd` restarting) — or on a session BlueZ keeps ending
        // immediately.
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    debug!(adapter = adapter.name(), "BLE scan task stopping");
}

/// One discovery session: filter to LE-only with duplicate advertising data
/// retained, then forward every mesh-tagged report until the session ends.
///
/// `duplicate_data` is required, not an optimization — BlueZ suppresses
/// repeated `ManufacturerData` by default, which would hide every fragment
/// after a peer's first one.
async fn scan_once(adapter: &Adapter, sink: &BleReportSink) -> bluer::Result<()> {
    adapter
        .set_discovery_filter(DiscoveryFilter {
            transport: DiscoveryTransport::Le,
            duplicate_data: true,
            ..Default::default()
        })
        .await?;

    // `discover_devices_with_changes`, not `discover_devices`: the latter
    // reports each peer once, on first discovery, so only a peer's opening
    // fragment would ever be seen. This variant re-reports a device on every
    // property change, which is what a fresh advertisement from it looks like.
    let mut events = adapter.discover_devices_with_changes().await?;
    while let Some(event) = events.next().await {
        let AdapterEvent::DeviceAdded(addr) = event else {
            continue;
        };
        // A device BlueZ already knew about is replayed when the session
        // opens, so its `ManufacturerData` can be a stale fragment from
        // before this node started. Harmless — an incomplete message expires
        // out of the reassembler under capacity pressure, and a complete one
        // is a duplicate the router already discards on OGM sequence number.
        let Some((ble_addr, rssi, fragment)) = read_mesh_report(adapter, addr).await else {
            continue;
        };
        sink.submit(ble_addr, rssi, &fragment);
    }
    Ok(())
}

/// Read `addr`'s current advertising state, returning its BLE address, RSSI,
/// and mesh-tagged fragment bytes if it carries this mesh's marker. `None`
/// for ambient BLE traffic, and for any device whose properties have already
/// gone away — peers churn out of BlueZ's cache continuously, so a device
/// vanishing between the event and this read is routine, not an error.
async fn read_mesh_report(
    adapter: &Adapter,
    addr: Address,
) -> Option<(BleAddr, Option<i16>, Vec<u8>)> {
    let device = adapter.device(addr).ok()?;
    let manufacturer_data = device.manufacturer_data().await.ok()??;
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
