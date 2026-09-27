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
use zerocopy::FromBytes;

use crate::BleError;
use crate::ad::find_mesh_fragment;
use crate::ad::{self};
use crate::addr::BleAddr;
use crate::frame::ExtendedReassembler;
use crate::frame::LegacyReassembler;
use crate::frame::MAX_REASSEMBLED_LEN;
use crate::frame::RawReport;
use crate::frame::{self};
use crate::mode::BleAdvFormat;
use crate::mode::BleSendMode;

/// Depth of the queue between the SoftDevice's synchronous scan callback and
/// `recv`'s async consumer. Capacity pressure drops the newest report rather
/// than blocking the callback (see [`ble_scan_task`]).
const REPORT_QUEUE_DEPTH: usize = 8;

/// Advertising events each fragment gets on the air before `send` moves on.
///
/// `send` blocks the driver's event loop for a whole advertising session, so
/// this times [`ADV_INTERVAL_625US`] is the per-fragment latency budget. Four
/// gives a duty-cycled scanner several chances without pinning the executor.
const ADV_EVENTS_PER_FRAGMENT: u8 = 4;

/// Advertising interval in 625µs units — 20ms, the SoftDevice's documented
/// `BLE_GAP_ADV_INTERVAL_MIN`. Not `Config::default()`'s 400 (250ms), at which
/// [`ADV_EVENTS_PER_FRAGMENT`] events cost a second per fragment — ~2s of
/// blocked event loop for an ordinary two-fragment OGM, against ~80ms here.
const ADV_INTERVAL_625US: u32 = 32;

/// Backstop advertising timeout in 10ms units, should the
/// [`ADV_EVENTS_PER_FRAGMENT`] events somehow not elapse. Both terminations
/// surface identically as `AdvertiseError::Timeout`.
const ADV_TIMEOUT_BACKSTOP_10MS: u16 = 50;

// A backstop only backs up what it outlasts; below that, `timeout` silently
// becomes the primary terminator and fragments truncate mid-burst. This file
// needs real SoftDevice silicon to test, so the invariant is checked at
// compile time on the firmware build instead.
const _: () = assert!(
    (ADV_EVENTS_PER_FRAGMENT as u32) * ADV_INTERVAL_625US * 625 / 1000
        < (ADV_TIMEOUT_BACKSTOP_10MS as u32) * 10,
    "ADV_TIMEOUT_BACKSTOP_10MS must outlast ADV_EVENTS_PER_FRAGMENT advertising intervals"
);

/// Bridges the SoftDevice's synchronous scan callback (driven by the spawned
/// [`ble_scan_task`]) to `recv`'s async consumer. Only reports carrying our
/// mesh marker (see `crate::ad`) are queued; everything else — ambient BLE
/// traffic, malformed AD structures — is discarded in the callback so `recv`
/// never has to look at it.
struct ReportQueue {
    channel: Channel<NoopRawMutex, RawReport, REPORT_QUEUE_DEPTH>,
}

// SAFETY: single-core, single-executor firmware. `NoopRawMutex` opts out of
// `Sync` because it does no real synchronization, which is unsound only under
// concurrent access from a second real thread — never the case here.
unsafe impl Sync for ReportQueue {}

/// Wraps `&'static Softdevice` to satisfy `LinkT: Send`. `Softdevice` opts out
/// of `Send`/`Sync` because its C API isn't documented as concurrency-safe;
/// this firmware runs one embassy executor on one core, so the only sharing is
/// between cooperatively scheduled tasks.
#[derive(Clone, Copy)]
struct SdHandle(&'static Softdevice);

// SAFETY: see above — never actually shared across a real thread boundary.
unsafe impl Send for SdHandle {}

/// `LinkT` adapter for the nRF52840's built-in BLE radio: connectionless
/// advertising broadcast only. See the module doc comment for the on-air
/// scheme.
pub struct NrfBleLink {
    sd: SdHandle,
    adv_config: AdvConfig,
    /// Which format(s) this node transmits. Receiving is always both — see
    /// [`BleSendMode`].
    send_mode: BleSendMode,
    reports: &'static ReportQueue,
    /// Fragmentation message-id counter, incremented once per `send()` call.
    msg_id_ctr: u8,
    /// Reassembly table for legacy-format fragments.
    legacy: LegacyReassembler,
    /// Reassembly table for extended-format fragments. Separate because the
    /// two place a fragment's bytes at different strides — see
    /// `frame::MODE_TAG_LEN`.
    extended: ExtendedReassembler,
    /// Scratch buffer holding the most recently reassembled mesh frame,
    /// borrowed by `LinkT::recv`.
    rx_frame: [u8; MAX_REASSEMBLED_LEN],
}

impl NrfBleLink {
    /// Start passive scanning on the soft device, returning a
    /// `LinkT`-ready handle. Spawns the scan loop as a background task on
    /// `spawner` — it must keep running for the lifetime of the returned
    /// link.
    ///
    /// The caller must already have enabled the SoftDevice and be pumping its
    /// events. Role/connection counts are left at `Config::default()`, untuned
    /// against real hardware; see `libs/blue/CLAUDE.md`.
    ///
    /// `send_mode` chooses which on-air format(s) this node transmits.
    /// Receiving is unaffected: `ScanConfig::default()` already sets
    /// `extended: true`, and `nrf-softdevice`'s scan buffer is 256 bytes —
    /// past S140's own `BLE_GAP_SCAN_BUFFER_EXTENDED_MIN` of 255 — so this
    /// backend has been able to *hear* extended advertisements since before
    /// it could send them.
    pub fn new(
        spawner: Spawner,
        sd: &'static Softdevice,
        send_mode: BleSendMode,
    ) -> Result<Self, BleError> {
        static REPORTS: StaticCell<ReportQueue> = StaticCell::new();
        let reports = REPORTS.init(ReportQueue {
            channel: Channel::new(),
        });
        spawner.spawn(ble_scan_task(sd, reports).map_err(|_| BleError::ScanTaskSpawn)?);

        Ok(Self {
            sd: SdHandle(sd),
            adv_config: AdvConfig {
                // What normally ends a fragment's session. `None` maps to
                // `max_adv_evts = 0` (unlimited), leaving `timeout` as the only
                // bound — a full second of blocked event loop per fragment.
                max_events: Some(ADV_EVENTS_PER_FRAGMENT),
                timeout: Some(ADV_TIMEOUT_BACKSTOP_10MS),
                interval: ADV_INTERVAL_625US,
                ..Default::default()
            },
            send_mode,
            reports,
            msg_id_ctr: 0,
            legacy: LegacyReassembler::new(),
            extended: ExtendedReassembler::new(),
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

/// Scan interval/window, in 625µs units. Deliberately not equal: a window that
/// fills its interval leaves the SoftDevice's radio scheduler no gap for any
/// other role, and every `peripheral::advertise` then fails with
/// `RawError::Resources`. ~90% duty cycle keeps the advertiser schedulable.
const SCAN_INTERVAL_625US: u32 = 180; // 112.5ms
const SCAN_WINDOW_625US: u32 = 160; // 100ms

/// Drives passive scanning forever, dispatching only mesh-marker-tagged
/// reports to `reports`. `central::scan` returning is not a hardware fault —
/// SoftDevice housekeeping can end a scan — so it is retried, matching the
/// BlueZ backend's scan-restart pattern.
#[embassy_executor::task]
async fn ble_scan_task(sd: &'static Softdevice, reports: &'static ReportQueue) -> ! {
    let config = ScanConfig {
        active: false,
        timeout: 0,
        window: SCAN_WINDOW_625US,
        interval: SCAN_INTERVAL_625US,
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
            let peer_addr_id = report.peer_addr.addr_id_peer();
            let peer_addr = report.peer_addr.addr;
            let direct_addr_id = report.direct_addr.addr_id_peer();
            let direct_addr = report.direct_addr.addr;
            trace!(
                ?peer_addr_id,
                ?peer_addr,
                ?direct_addr_id,
                ?direct_addr,
                "rx mesh fragment"
            );
            let addr = BleAddr::from(report.peer_addr.addr);

            // Backpressure drops the newest report rather than blocking this
            // synchronous callback — acceptable on a lossy, fire-and-forget
            // medium, but logged like every other capacity-driven drop here.
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
            warn!(?e, "BLE scan error; restarting");
        }
    }
}

impl LinkT for NrfBleLink {
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        let (frame_bytes, frame_len) = frame::assemble_frame(origin, data)?;
        // One `msg_id` across formats: their fragments land in different
        // reassembly tables, so reusing it cannot collide. See
        // `generic_link.rs`'s matching comment for what a peer actually does
        // with the two copies — OGMs and broadcast dedup, unicast does not.
        let msg_id = self.next_msg_id();

        // A frame is sent if *any* configured format reached the air — see
        // the matching comment in `generic_link.rs`, which carries the full
        // argument. Both backends must agree on this or a `Both` node's
        // behaviour would depend on which one it runs.
        let mut delivered = false;
        // The *first* failure, not the last — legacy goes out first and is
        // the format whose failure means the mesh is down. Must match
        // `generic_link.rs`, or a `Both` node's reported error would depend
        // on which backend it runs.
        let mut first_err: Option<LinkError> = None;

        for &format in self.send_mode.formats() {
            // Fragmented independently per format, at that format's own
            // budget. `?` rather than tolerated: `assemble_frame` already
            // bounded the frame by the tightest format's capacity, so this is
            // unreachable by construction.
            let count = frame::fragment_count(frame_len, format)?;
            let mut format_delivered = true;
            for index in 0..count {
                // Sized for the extended case regardless of `format`, so one
                // buffer serves both; `build_fragment_ad` enforces the
                // per-format ceiling on what it actually writes.
                let mut ad_buf = [0u8; ad::MAX_EXTENDED_ADV_DATA_LEN];
                // Not a `?`, unlike `fragment_count` above. This backend
                // wraps the fragment in its own AD framing, so
                // `build_fragment_ad` re-checks the result against the
                // format's advertising-data budget — a fallible step the host
                // path structurally does not have, since BlueZ builds that
                // structure itself. Propagating it would abandon a `Both`
                // send whose legacy half had *already reached the air*,
                // reporting a delivered frame as dropped, and would do so
                // only on this backend. Treated exactly like an advertise
                // failure instead.
                let n = match frame::build_fragment_ad(
                    &frame_bytes[..frame_len],
                    frame::FragmentSpec {
                        origin,
                        msg_id,
                        index,
                        count,
                        format,
                    },
                    &mut ad_buf,
                ) {
                    Ok(n) => n,
                    Err(e) => {
                        warn!(
                            ?e,
                            ?format,
                            index,
                            count,
                            "drop: fragment could not be framed"
                        );
                        first_err.get_or_insert(e);
                        format_delivered = false;
                        break;
                    }
                };

                // One advertising session per fragment, ending on
                // `max_events` or the `timeout` backstop — both
                // `AdvertiseError::Timeout` below.
                //
                // S140 has exactly one advertising set
                // (`BLE_GAP_ADV_SET_COUNT_MAX = 1`), so `set_id: 0` is the
                // only legal value and the two formats' passes must run
                // sequentially through it — never concurrently, which this
                // radio cannot do. `anonymous: false` keeps today's identity
                // semantics; this crate carries identity at the application
                // layer (`frame::ORIGIN_LEN`) regardless of what the medium's
                // address does.
                let advertisement = match format {
                    BleAdvFormat::Legacy => NonconnectableAdvertisement::NonscannableUndirected {
                        adv_data: &ad_buf[..n],
                    },
                    BleAdvFormat::Extended => {
                        NonconnectableAdvertisement::ExtendedNonscannableUndirected {
                            set_id: 0,
                            anonymous: false,
                            adv_data: &ad_buf[..n],
                        }
                    }
                };
                match peripheral::advertise(self.sd.0, advertisement, &self.adv_config).await {
                    Ok(()) | Err(peripheral::AdvertiseError::Timeout) => {}
                    Err(e) => {
                        // Abandon this format's remaining fragments, not the
                        // other format's pass.
                        trace!(?e, ?format, index, count, "drop: BLE advertise failed");
                        first_err.get_or_insert(LinkError::TransmitFailed);
                        format_delivered = false;
                        break;
                    }
                }
            }
            if format_delivered {
                delivered = true;
                trace!(?origin, dst = ?data.dst, frame_len, ?format, count, "tx frame");
            }
        }

        if delivered {
            Ok(frame_len)
        } else {
            // Same invariant, and the same assertion, as `generic_link.rs`:
            // nothing clears `format_delivered` without recording why.
            debug_assert!(
                first_err.is_some(),
                "no format reached the air but no error was recorded"
            );
            Err(first_err.unwrap_or(LinkError::TransmitFailed))
        }
    }

    async fn recv<'a>(&'a mut self) -> Result<Received<'a>, LinkError> {
        // Keep consuming reports until *some* message completes — not
        // necessarily the one the last fragment belonged to.
        loop {
            let report = self.reports.channel.receive().await;
            trace!(addr = ?report.addr, rssi = ?report.rssi, len = report.len, "rx report");
            let Some((format, hdr, origin, body)) =
                frame::parse_fragment_with_origin(&report.data[..report.len as usize])
            else {
                trace!(addr = ?report.addr, "drop: malformed fragment header");
                continue;
            };
            // Keyed on the origin `Mac` embedded in every fragment, not
            // `report.addr` — see `frame::ORIGIN_LEN` for why the medium's
            // own advertiser address can't be trusted as a reassembly key
            // (confirmed against the BlueZ backend; this backend's own
            // address is stable, but the wire format must interoperate with
            // one that isn't).
            let key = wayfinder_link_utils::FragKey {
                addr: origin,
                msg_id: hdr.msg_id,
            };
            let metrics = LinkMetrics {
                rssi_dbm: report.rssi,
                snr_db: None,
                quality: None,
            };

            // Each format's fragments are laid out at its own `FRAG_PAYLOAD`
            // stride, so the mode tag picks the table. Unconditional on
            // `send_mode` — a node transmitting legacy still reassembles a
            // peer's extended advertisements, which is what makes a
            // node-by-node rollout safe.
            let completed = match format {
                BleAdvFormat::Legacy => {
                    self.legacy
                        .accept(key, &hdr, body, metrics, &mut self.rx_frame)
                }
                BleAdvFormat::Extended => {
                    self.extended
                        .accept(key, &hdr, body, metrics, &mut self.rx_frame)
                }
            };

            if let Some((len, metrics)) = completed {
                // Logged per completed frame, not per fragment, and carrying
                // the format: this is the only signal that says a peer's
                // *extended* advertisements are actually being heard and
                // reassembled end to end. Neither backend's extended path has
                // run on real hardware, and every BLE failure this crate has
                // had presented as a link that looked alive and moved no
                // traffic — so "frames arrive, and these are the formats they
                // arrive in" is the observation bring-up needs.
                trace!(?format, ?origin, len, "rx frame");
                let frame = LinkFrame::ref_from_bytes(&self.rx_frame[..len])
                    .map_err(|_| LinkError::MalformedFrame)?;
                return Ok(Received { frame, metrics });
            }
        }
    }
}
