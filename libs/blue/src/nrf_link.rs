//! `LinkT` adapter bridging [`NrfBleLink`] onto the mesh using connectionless
//! BLE advertising broadcast: `send` broadcasts a frame's fragments as
//! short-lived non-connectable/non-scannable advertisements, `recv`
//! reassembles fragments observed via continuous passive scanning. See
//! `libs/blue/CLAUDE.md` for the on-air format and why `nrf-softdevice`
//! (rather than `trouble-host`/`nrf-sdc`) drives the hardware.

use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use nrf_softdevice::Softdevice;
use nrf_softdevice::ble::central::ScanConfig;
use nrf_softdevice::ble::central::{self};
use nrf_softdevice::ble::peripheral::Config as AdvConfig;
use nrf_softdevice::ble::peripheral::NonconnectableAdvertisement;
use nrf_softdevice::ble::peripheral::{self};
use static_cell::StaticCell;
use tracing::trace;
use tracing::warn;
use wayfinder::interfaces::frame::LinkFrame;
use wayfinder::interfaces::frame::LinkFrameData;
use wayfinder::interfaces::frame::Mac;
use wayfinder::interfaces::link::LinkError;
use wayfinder::interfaces::link::LinkMetrics;
use wayfinder::link::LinkT;
use wayfinder::link::Received;
use wayfinder_link_utils::parse_fragment;
use zerocopy::FromBytes;

use crate::BleError;
use crate::ad::find_mesh_fragment;
use crate::ad::{self};
use crate::addr::BleAddr;
use crate::frame::MAX_REASSEMBLED_LEN;
use crate::frame::RawReport;
use crate::frame::Reassembler;
use crate::frame::{self};

/// Depth of the queue between the SoftDevice's synchronous scan callback and
/// `recv`'s async consumer. Not derived from a hard limit — a small multiple
/// of what one `recv` call away from the queue can plausibly fall behind by;
/// capacity pressure drops the newest report rather than blocking the scan
/// callback (see [`ble_scan_task`]).
const REPORT_QUEUE_DEPTH: usize = 8;

/// Bridges the SoftDevice's synchronous scan callback (driven by the spawned
/// [`ble_scan_task`]) to `recv`'s async consumer. Only reports carrying our
/// mesh marker (see `crate::ad`) are queued; everything else — ambient BLE
/// traffic, malformed AD structures — is discarded in the callback so `recv`
/// never has to look at it.
struct ReportQueue {
    channel: Channel<NoopRawMutex, RawReport, REPORT_QUEUE_DEPTH>,
}

// SAFETY: single-core, single-executor firmware (see `SdHandle`'s doc
// comment below) — `NoopRawMutex` opts out of `Sync` only because it does no
// real synchronization, which is unsound solely under concurrent access from
// a second real thread, which never happens here.
unsafe impl Sync for ReportQueue {}

// Wraps `&'static Softdevice` to satisfy `LinkT: Send`.
//
// `Softdevice` deliberately opts out of `Send`/`Sync` (its C API isn't
// documented as safe to call concurrently from independent threads), but
// this firmware runs a single embassy executor on one Cortex-M core — there
// is never a second real thread to race against, only cooperatively
// scheduled async tasks, so sharing the reference across them is sound.
#[derive(Clone, Copy)]
struct SdHandle(&'static Softdevice);

// SAFETY: see the comment above — single-core, single-executor,
// non-preemptive-across-tasks firmware, never actually shared across a real
// thread boundary.
unsafe impl Send for SdHandle {}

/// `LinkT` adapter for the nRF52840's built-in BLE radio: connectionless
/// advertising broadcast only. See the module doc comment for the on-air
/// scheme.
pub struct NrfBleLink {
    sd: SdHandle,
    adv_config: AdvConfig,
    reports: &'static ReportQueue,
    /// Fragmentation message-id counter, incremented once per `send()` call.
    msg_id_ctr: u8,
    reassembler: Reassembler,
    /// Scratch buffer holding the most recently reassembled mesh frame,
    /// borrowed by `LinkT::recv`.
    rx_frame: [u8; MAX_REASSEMBLED_LEN],
}

impl NrfBleLink {
    /// Enable the SoftDevice and start passive scanning, returning a
    /// `LinkT`-ready handle. Spawns the SoftDevice's event-pump loop and the
    /// scan loop as background tasks on `spawner` — both must keep running
    /// for the lifetime of the returned link.
    ///
    /// Uses the SoftDevice's own default configuration (`Config::default()`)
    /// throughout — the default role/connection counts haven't been tuned
    /// against real hardware yet; see `libs/blue/CLAUDE.md`.
    pub fn new(spawner: Spawner) -> Result<Self, BleError> {
        let sd: &'static Softdevice = Softdevice::enable(&nrf_softdevice::Config::default());
        spawner.spawn(softdevice_task(sd).map_err(|_| BleError::SoftdeviceTaskSpawn)?);

        static REPORTS: StaticCell<ReportQueue> = StaticCell::new();
        let reports = REPORTS.init(ReportQueue {
            channel: Channel::new(),
        });
        spawner.spawn(ble_scan_task(sd, reports).map_err(|_| BleError::ScanTaskSpawn)?);

        Ok(Self {
            sd: SdHandle(sd),
            adv_config: AdvConfig {
                // 40ms (SoftDevice `Config::timeout` is in 10ms units): long
                // enough for a scanner to catch at least one advertising
                // event before `send` moves on to the next fragment.
                timeout: Some(4),
                ..Default::default()
            },
            reports,
            msg_id_ctr: 0,
            reassembler: Reassembler::new(),
            rx_frame: [0u8; MAX_REASSEMBLED_LEN],
        })
    }

    /// Allocate the next fragmentation message id, wrapping at 256.
    fn next_msg_id(&mut self) -> u8 {
        let id = self.msg_id_ctr;
        self.msg_id_ctr = self.msg_id_ctr.wrapping_add(1);
        id
    }
}

#[embassy_executor::task]
async fn softdevice_task(sd: &'static Softdevice) -> ! {
    sd.run().await
}

/// Drives passive scanning forever, dispatching only mesh-marker-tagged
/// reports (see `crate::ad::find_mesh_fragment`) to `reports`. `central::scan`
/// returning is not itself a hardware fault — it can happen on internal
/// SoftDevice housekeeping — so it's retried rather than treated as fatal,
/// matching the mgmt-link retry pattern this board's firmware already uses.
#[embassy_executor::task]
async fn ble_scan_task(sd: &'static Softdevice, reports: &'static ReportQueue) -> ! {
    let config = ScanConfig {
        active: false,
        timeout: 0,
        ..Default::default()
    };
    loop {
        let result: Result<(), central::ScanError> = central::scan(sd, &config, |report| {
            // SAFETY: `p_data`/`len` describe a buffer the SoftDevice owns
            // for the duration of this callback only (see `ble_data_t`'s
            // doc); never retained past this call.
            let data = unsafe {
                core::slice::from_raw_parts(report.data.p_data, report.data.len as usize)
            };
            let fragment = find_mesh_fragment(data)?;
            let addr = BleAddr(report.peer_addr.addr);

            // Backpressure drops the newest report rather than blocking this
            // synchronous callback — acceptable on a lossy, fire-and-forget
            // medium, same tolerance every other link here already assumes —
            // but still logged, matching every other capacity-driven drop in
            // this codebase (`Reassembler`'s eviction, rylr998's `rx_queue`).
            if let Err(embassy_sync::channel::TrySendError::Full(dropped)) = reports
                .channel
                .try_send(RawReport::new(addr, Some(i16::from(report.rssi)), fragment))
            {
                trace!(addr = ?dropped.addr, "drop: report queue full");
            }
            None // keep scanning
        })
        .await;
        if let Err(e) = result {
            // Handled by retrying the scan loop, not fatal -- warn!, not
            // error! (CLAUDE.md: a handled-and-retried fault is warn!).
            warn!(?e, "BLE scan error; restarting");
        }
    }
}

impl LinkT for NrfBleLink {
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        let (frame_bytes, frame_len) = frame::assemble_frame(origin, data)?;
        let count = frame::fragment_count(frame_len)?;
        let msg_id = self.next_msg_id();

        for index in 0..count {
            let mut ad_buf = [0u8; ad::MAX_LEGACY_ADV_DATA_LEN];
            let n = frame::build_fragment_ad(
                &frame_bytes,
                frame_len,
                msg_id,
                index,
                count,
                &mut ad_buf,
            )?;

            // One advertising session per fragment: it runs until
            // `adv_config.timeout` elapses (the expected way this ends —
            // `AdvertiseError::Timeout` below), giving passive scanners in
            // range a chance to catch it before we move to the next.
            let advertisement = NonconnectableAdvertisement::NonscannableUndirected {
                adv_data: &ad_buf[..n],
            };
            match peripheral::advertise(self.sd.0, advertisement, &self.adv_config).await {
                Ok(()) | Err(peripheral::AdvertiseError::Timeout) => {}
                Err(e) => {
                    trace!(?e, "drop: BLE advertise failed");
                    return Err(LinkError::TransmitFailed);
                }
            }
        }

        Ok(frame_len)
    }

    async fn recv<'a>(&'a mut self) -> Result<Received<'a>, LinkError> {
        // Keep consuming physical reports, feeding each into the
        // reassembler, until *some* message completes — not necessarily the
        // fragment just read, mirroring `rylr998::link::recv`.
        loop {
            let report = self.reports.channel.receive().await;
            let Some((hdr, body)) = parse_fragment(&report.data[..report.len as usize]) else {
                trace!(addr = ?report.addr, "drop: malformed fragment header");
                continue;
            };
            let key = wayfinder_link_utils::FragKey {
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
