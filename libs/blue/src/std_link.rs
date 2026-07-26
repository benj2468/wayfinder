//! `LinkT` adapter carrying the mesh over BLE connectionless advertising on a
//! Linux host, driving BlueZ through its D-Bus API (`bluer`).
//!
//! The counterpart to [`crate::NrfBleLink`]: same on-air format (see
//! `crate::ad`), same fragmentation, so an nRF52840 node and a Linux node
//! join the same BLE mesh. What differs is who builds the advertising data —
//! BlueZ assembles the Manufacturer Specific Data AD structure from
//! `Advertisement::manufacturer_data`, so this side hands it the bare
//! `[frag_header][body]` blob (`frame::build_fragment`) rather than
//! self-framing it, and on receive BlueZ hands back that same blob already
//! parsed out of the advertisement.

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
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::error::TrySendError;
use tracing::debug;
use tracing::info;
use tracing::trace;
use tracing::warn;
use wayfinder::interfaces::frame::LinkFrame;
use wayfinder::interfaces::frame::LinkFrameData;
use wayfinder::interfaces::frame::Mac;
use wayfinder::interfaces::link::LinkError;
use wayfinder::interfaces::link::LinkMetrics;
use wayfinder::link::LinkT;
use wayfinder::link::Received;
use wayfinder_link_utils::FragKey;
use wayfinder_link_utils::parse_fragment;
use zerocopy::FromBytes;

use crate::ad::MESH_COMPANY_ID;
use crate::addr::BleAddr;
use crate::frame::MAX_FRAGMENT_BYTES;
use crate::frame::MAX_REASSEMBLED_LEN;
use crate::frame::RawReport;
use crate::frame::Reassembler;
use crate::frame::{self};

/// Depth of the queue between the background scan task and `recv`'s consumer.
/// Not derived from a hard limit — a small multiple of what one `recv` call
/// can plausibly fall behind by; capacity pressure drops the newest report
/// rather than stalling the scan task (see [`run_scanner`]), matching the
/// bare-metal side's policy.
const REPORT_QUEUE_DEPTH: usize = 32;

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

/// A [`LinkT`] carrying the mesh over BLE connectionless advertising via
/// BlueZ. See the module doc comment for how it relates to the bare-metal
/// [`crate::NrfBleLink`].
pub struct StdBleLink {
    /// The BlueZ adapter this link advertises on. Scanning happens on a clone
    /// of it, owned by the background task spawned in [`StdBleLink::new`].
    adapter: Adapter,
    /// How long each fragment's advertisement is held registered; see
    /// [`BleLinkParams::advertise_dwell`].
    advertise_dwell: Duration,
    /// Mesh-tagged advertisements observed by the background scan task.
    report_rx: Receiver<RawReport>,
    /// Fragmentation message-id counter, incremented once per `send()` call.
    msg_id_ctr: u8,
    /// This link's reassembly table, keyed by advertiser address.
    reassembler: Reassembler,
    /// Scratch buffer for the fragment `send` is currently building.
    tx_fragment: [u8; MAX_FRAGMENT_BYTES],
    /// Scratch buffer holding the most recently reassembled mesh frame,
    /// borrowed by [`LinkT::recv`].
    rx_frame: [u8; MAX_REASSEMBLED_LEN],
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

        let (report_tx, report_rx) = tokio::sync::mpsc::channel(REPORT_QUEUE_DEPTH);
        tokio::spawn(run_scanner(adapter.clone(), report_tx));

        Ok(Self {
            adapter,
            advertise_dwell: params.advertise_dwell,
            report_rx,
            msg_id_ctr: 0,
            reassembler: Reassembler::new(),
            tx_fragment: [0u8; MAX_FRAGMENT_BYTES],
            rx_frame: [0u8; MAX_REASSEMBLED_LEN],
        })
    }

    /// Allocate the next fragmentation message id, wrapping at 256.
    fn next_msg_id(&mut self) -> u8 {
        let id = self.msg_id_ctr;
        self.msg_id_ctr = self.msg_id_ctr.wrapping_add(1);
        id
    }

    /// Put one already-built fragment on the air: register it as a broadcast
    /// (non-connectable) advertisement, hold the registration for the dwell,
    /// then drop it.
    ///
    /// The hold is the whole point — `bluer` unregisters the advertisement
    /// when its handle is dropped, so a fragment advertised and immediately
    /// released would never reach a scanner.
    async fn advertise_fragment(&self, fragment: &[u8]) -> Result<(), LinkError> {
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

/// Watch `adapter` for advertisements carrying this mesh's marker, forwarding
/// each one's fragment to `report_tx`. Runs until the receiver is dropped.
///
/// Restarts its discovery session if the stream ever ends — BlueZ can end one
/// on its own (another client changing the discovery filter, the adapter
/// being reset), which is not a fault this node can act on, so it is retried
/// rather than treated as fatal, matching the bare-metal scan loop.
async fn run_scanner(adapter: Adapter, report_tx: Sender<RawReport>) {
    while !report_tx.is_closed() {
        if let Err(e) = scan_once(&adapter, &report_tx).await {
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
async fn scan_once(adapter: &Adapter, report_tx: &Sender<RawReport>) -> bluer::Result<()> {
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
        let Some(report) = read_mesh_report(adapter, addr).await else {
            continue;
        };
        // Backpressure drops the newest report rather than stalling the
        // discovery stream — acceptable on a lossy, fire-and-forget medium,
        // and the same tolerance every other link here assumes.
        if let Err(TrySendError::Full(dropped)) = report_tx.try_send(report) {
            trace!(addr = ?dropped.addr, "drop: report queue full");
        }
    }
    Ok(())
}

/// Read `addr`'s current advertising state, returning a [`RawReport`] if it
/// carries this mesh's marker. `None` for ambient BLE traffic, and for any
/// device whose properties have already gone away — peers churn out of
/// BlueZ's cache continuously, so a device vanishing between the event and
/// this read is routine, not an error.
async fn read_mesh_report(adapter: &Adapter, addr: Address) -> Option<RawReport> {
    let device = adapter.device(addr).ok()?;
    let manufacturer_data = device.manufacturer_data().await.ok()??;
    let fragment = manufacturer_data.get(&MESH_COMPANY_ID)?;
    // A separate property read, which can independently be absent for a
    // cached, out-of-range device; a missing RSSI must not discard an
    // otherwise good fragment.
    let rssi = device.rssi().await.ok().flatten();
    Some(RawReport::new(BleAddr::from(addr.0), rssi, fragment))
}

impl LinkT for StdBleLink {
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        let (frame_bytes, frame_len) = frame::assemble_frame(origin, data)?;
        let count = frame::fragment_count(frame_len)?;
        let msg_id = self.next_msg_id();

        for index in 0..count {
            let n = frame::build_fragment(
                &frame_bytes,
                frame_len,
                msg_id,
                index,
                count,
                &mut self.tx_fragment,
            )?;
            self.advertise_fragment(&self.tx_fragment[..n]).await?;
        }

        trace!(?origin, dst = ?data.dst, frame_len, count, "tx frame");
        Ok(frame_len)
    }

    async fn recv<'a>(&'a mut self) -> Result<Received<'a>, LinkError> {
        // Keep consuming physical reports, feeding each into the
        // reassembler, until *some* message completes — not necessarily the
        // fragment just read, mirroring `rylr998::link::recv`.
        loop {
            let Some(report) = self.report_rx.recv().await else {
                // The scan task is gone, so no further report will ever
                // arrive: this link is dead, not momentarily idle.
                return Err(LinkError::ReceiveFailed);
            };
            let Some((hdr, body)) = parse_fragment(&report.data[..report.len as usize]) else {
                trace!(addr = ?report.addr, "drop: malformed fragment header");
                continue;
            };
            let key = FragKey {
                addr: report.addr,
                msg_id: hdr.msg_id,
            };
            let metrics = LinkMetrics {
                rssi_dbm: report.rssi,
                snr_db: None,
                quality: None,
            };

            if let Some((len, metrics)) =
                self.reassembler
                    .accept(key, &hdr, body, metrics, &mut self.rx_frame)
            {
                let frame = LinkFrame::ref_from_bytes(&self.rx_frame[..len])
                    .map_err(|_| LinkError::InvalidPacket)?;
                return Ok(Received { frame, metrics });
            }
        }
    }
}
