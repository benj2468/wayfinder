//! `LinkT` core carrying the mesh over BLE connectionless advertising,
//! generic over a platform-supplied [`BleAdvertiser`] rather than driving a
//! concrete BLE stack directly.
//!
//! [`crate::StdBleLink`] builds on this, wrapping it with a `BleAdvertiser`
//! that registers advertisements through BlueZ. Since BlueZ builds the
//! Manufacturer Specific Data AD structure itself, this core hands the
//! advertiser the bare `[mode][frag_header][origin][body]` blob rather than
//! self-framing it
//! via `crate::ad` as [`crate::NrfBleLink`] does. Each backend still owns its
//! *receive* side, which is platform-specific in a way advertising a pre-built
//! fragment is not.
//!
//! Injecting the advertise call rather than hard-wiring it is what makes this
//! unit-testable against a fake [`BleAdvertiser`], with no `bluetoothd`
//! dependency — unlike [`crate::NrfBleLink`], which needs real silicon.

use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tracing::trace;
use wayfinder::interfaces::frame::LinkFrame;
use wayfinder::interfaces::frame::LinkFrameData;
use wayfinder::interfaces::frame::Mac;
use wayfinder::interfaces::link::LinkError;
use wayfinder::interfaces::link::LinkMetrics;
use wayfinder::link::LinkT;
use wayfinder::link::Received;
use wayfinder_link_utils::FragKey;
use zerocopy::FromBytes;

use crate::addr::BleAddr;
use crate::frame::ExtendedReassembler;
use crate::frame::LegacyReassembler;
use crate::frame::MAX_FRAGMENT_BYTES;
use crate::frame::MAX_REASSEMBLED_LEN;
use crate::frame::RawReport;
use crate::frame::{self};
use crate::mode::BleAdvFormat;
use crate::mode::BleSendMode;

/// Depth of the queue between the platform's scan producer and `recv`'s
/// consumer. Capacity pressure drops the newest report rather than blocking
/// the producer, matching every other link in this crate.
const REPORT_QUEUE_DEPTH: usize = 32;

/// Platform hook for putting one already-built fragment on the air, tagged
/// with `crate::ad::MESH_COMPANY_ID` and held for however long the
/// implementation decides. [`crate::StdBleLink`]'s registers a BlueZ
/// advertisement and holds it for `advertise_dwell`.
///
/// Generic rather than a trait object so [`BleLink`] stays host-testable
/// against a fake implementation.
#[allow(async_fn_in_trait)]
pub trait BleAdvertiser: Send {
    /// Broadcast `fragment` — the bare `[mode][frag_header][origin][body]`
    /// blob from `frame::build_fragment` — as this mesh's manufacturer data,
    /// then stop advertising it.
    ///
    /// `format` says which kind of advertisement to register. It is passed
    /// rather than re-derived from the fragment's own mode tag because the
    /// two are different things: the tag tells a *receiver* how to reassemble,
    /// while this tells the *platform* which PDU type to put on the air, and a
    /// backend has to set that on the advertisement itself (BlueZ:
    /// `secondary_channel`; SoftDevice: the advertisement variant).
    async fn advertise(&self, format: BleAdvFormat, fragment: &[u8]) -> Result<(), LinkError>;
}

/// Cloneable handle a backend's scan producer feeds observed mesh-tagged
/// advertisements into. Separate from [`BleLink`] because that producer and
/// the `LinkT` consumer can live on opposite sides of a task boundary.
#[derive(Clone)]
pub struct BleReportSink {
    tx: mpsc::Sender<RawReport>,
}

impl BleReportSink {
    /// Submit one observed advertisement's mesh-tagged manufacturer data.
    /// Drops the report (logging at `trace!`) rather than blocking if the
    /// queue between the scan producer and [`LinkT::recv`] is full —
    /// backpressure on a lossy, fire-and-forget medium.
    pub fn submit(&self, addr: BleAddr, rssi: Option<i16>, fragment: &[u8]) {
        let report = RawReport::new(addr, rssi, fragment);
        if let Err(TrySendError::Full(dropped)) = self.tx.try_send(report) {
            trace!(addr = ?dropped.addr, "drop: report queue full");
        }
    }

    /// Whether this sink's [`BleLink`] (and thus its `recv` consumer) has
    /// been dropped, so a backend's scan producer knows to stop feeding it.
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    /// Resolves once this sink's [`BleLink`] has been dropped.
    ///
    /// A scan producer selects on this rather than polling [`Self::is_closed`]
    /// between events: re-checking only after the *next* radio event keeps the
    /// scan apparatus alive indefinitely on a quiet radio.
    pub async fn closed(&self) {
        self.tx.closed().await;
    }
}

/// A [`LinkT`] carrying the mesh over BLE connectionless advertising, generic
/// over a [`BleAdvertiser`] that performs the actual platform advertise call.
/// See the module doc comment for how backends build on this.
pub struct BleLink<A: BleAdvertiser> {
    /// Platform hook this link's `send` calls once per fragment.
    advertiser: A,
    /// Which format(s) this node transmits. A local policy — it does not
    /// affect what this link *receives*, which is always both.
    send_mode: BleSendMode,
    /// Mesh-tagged advertisements submitted via this link's
    /// [`BleReportSink`].
    report_rx: mpsc::Receiver<RawReport>,
    /// Fragmentation message-id counter, incremented once per `send()` call.
    msg_id_ctr: u8,
    /// Reassembly table for legacy-format fragments, keyed by the origin
    /// `Mac` embedded in every fragment (see `frame::ORIGIN_LEN`), not the
    /// advertiser address.
    legacy: LegacyReassembler,
    /// Reassembly table for extended-format fragments.
    ///
    /// Separate from [`Self::legacy`] because the two place a fragment's
    /// bytes at different offsets (`index * FRAG_PAYLOAD`, a const generic) —
    /// so a single table could not correctly hold both, even for one sender.
    /// `recv` picks between them on the fragment's mode tag.
    extended: ExtendedReassembler,
    /// Scratch buffer for the fragment `send` is currently building. Sized
    /// for the larger format; a legacy fragment uses a prefix of it.
    tx_fragment: [u8; MAX_FRAGMENT_BYTES],
    /// Scratch buffer holding the most recently reassembled mesh frame,
    /// borrowed by [`LinkT::recv`]. Shared by both reassemblers, which write
    /// a completed frame into it rather than keeping it.
    rx_frame: [u8; MAX_REASSEMBLED_LEN],
}

impl<A: BleAdvertiser> BleLink<A> {
    /// Build a `LinkT`-ready handle wrapping `advertiser` and transmitting
    /// under `send_mode`, along with the [`BleReportSink`] a backend's scan
    /// producer feeds.
    pub fn new(advertiser: A, send_mode: BleSendMode) -> (Self, BleReportSink) {
        let (tx, rx) = mpsc::channel(REPORT_QUEUE_DEPTH);
        (
            Self {
                advertiser,
                send_mode,
                report_rx: rx,
                msg_id_ctr: 0,
                legacy: LegacyReassembler::new(),
                extended: ExtendedReassembler::new(),
                tx_fragment: [0u8; MAX_FRAGMENT_BYTES],
                rx_frame: [0u8; MAX_REASSEMBLED_LEN],
            },
            BleReportSink { tx },
        )
    }

    /// Allocate the next fragmentation message id, wrapping at 256.
    fn next_msg_id(&mut self) -> u8 {
        let id = self.msg_id_ctr;
        self.msg_id_ctr = self.msg_id_ctr.wrapping_add(1);
        id
    }
}

impl<A: BleAdvertiser> LinkT for BleLink<A> {
    /// A broadcast medium: every `send` reaches every neighbor, whatever
    /// `data.dst` says. See [`wayfinder::link::BROADCAST_FAN_OUT`].
    fn fan_out(&self) -> Option<core::num::NonZeroU8> {
        wayfinder::link::BROADCAST_FAN_OUT
    }

    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        let (frame_bytes, frame_len) = frame::assemble_frame(origin, data)?;
        // One `msg_id` for the whole send, shared across formats: the two
        // formats' fragments live in different reassembly tables, so reusing
        // it cannot collide.
        //
        // What a peer does with the two copies depends on the frame kind, and
        // only some of it is free. `BatmanEngine` deduplicates OGMs on seqno
        // and broadcast on `(orig, seqno)`, so those really do collapse to
        // one. `handle_unicast` has no dedup — it delivers locally (rule 1) or
        // relays (rule 3) unconditionally — so under `Both` a directed frame
        // is delivered or forwarded *twice* on this hop. Tolerable, and the
        // price of `Both`'s legacy control copy during bring-up, but it is not
        // nothing: it doubles relayed unicast traffic, and with mesh auth on,
        // the second copy is dropped by the pairwise replay guard instead.
        let msg_id = self.next_msg_id();

        // A frame is sent if *any* configured format reached the air, not if
        // every one did. Under `BleSendMode::Both` on a controller that cannot
        // register extended advertisements — a pre-Bluetooth-5 controller, the
        // exact hardware `Both` exists to tolerate — the legacy copy really
        // does get delivered, and reporting `TransmitFailed` for it would make
        // `Both` strictly worse than `Legacy` there while the mesh visibly
        // worked. Design 07 §3.5's claim that adopting `Both` "loses nothing"
        // is only true with this accounting.
        let mut delivered = false;
        // The *first* failure, not the last. `formats()` puts legacy first,
        // and legacy is the format whose failure means the mesh is down —
        // keeping the last error would report the extended attempt (the one
        // an operator already knows may not work) and discard the legacy
        // cause entirely on a link that has genuinely died.
        let mut first_err: Option<LinkError> = None;

        for &format in self.send_mode.formats() {
            // Fragmented independently per format, at that format's own
            // budget — not one fragmentation re-wrapped, which would waste
            // the extended budget entirely.
            //
            // Not tolerated the way an advertise failure is: `assemble_frame`
            // already bounded the frame by the *tightest* format's capacity
            // (`frame::MAX_REASSEMBLED_LEN`), so this is unreachable by
            // construction and a `?` keeps it loud if that invariant breaks.
            let count = frame::fragment_count(frame_len, format)?;
            let mut format_delivered = true;
            for index in 0..count {
                let n = frame::build_fragment(
                    &frame_bytes[..frame_len],
                    frame::FragmentSpec {
                        origin,
                        msg_id,
                        index,
                        count,
                        format,
                    },
                    &mut self.tx_fragment,
                )?;
                if let Err(e) = self
                    .advertiser
                    .advertise(format, &self.tx_fragment[..n])
                    .await
                {
                    // Abandon this format's remaining fragments — a partly
                    // advertised frame is bytes on the air no peer can
                    // reassemble — but not the other format's pass.
                    // `?e` matters here even though `BluerAdvertiser` logs
                    // its own cause: `BleAdvertiser` is a public trait, and an
                    // implementation that does not log internally would
                    // otherwise have its error swallowed entirely whenever
                    // another format succeeded.
                    trace!(
                        ?e,
                        ?format,
                        index,
                        count,
                        "drop: format abandoned mid-frame"
                    );
                    first_err.get_or_insert(e);
                    format_delivered = false;
                    break;
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
            // The invariant that makes the fallback dead is not "`formats()`
            // is never empty" but the stronger "nothing clears
            // `format_delivered` without recording why". A future per-format
            // skip (don't attempt extended after N failures, say) is the
            // natural way to break it, and would turn a frame this node chose
            // not to send into a `TransmitFailed` the driver reports as a
            // dropped frame — a control-flow bug wearing a hardware error's
            // clothes. Assert it rather than trusting the comment.
            debug_assert!(
                first_err.is_some(),
                "no format reached the air but no error was recorded"
            );
            Err(first_err.unwrap_or(LinkError::TransmitFailed))
        }
    }

    async fn recv<'a>(&'a mut self) -> Result<Received<'a>, LinkError> {
        // Keep consuming physical reports, feeding each into the
        // reassembler, until *some* message completes — not necessarily the
        // fragment just read.
        loop {
            let Some(report) = self.report_rx.recv().await else {
                // The sink is gone, so no further report will ever arrive:
                // this link is dead, not momentarily idle.
                return Err(LinkError::ReceiveFailed);
            };
            let Some((format, hdr, origin, body)) =
                frame::parse_fragment_with_origin(&report.data[..report.len as usize])
            else {
                // Deliberately not distinguished further here: an unknown
                // *format tag* is separated out inside
                // `parse_fragment_with_origin`, because version skew and RF
                // garbage want different responses from whoever reads this.
                trace!(addr = ?report.addr, "drop: malformed fragment header");
                continue;
            };
            // Keyed on the origin `Mac` embedded in every fragment, not the
            // advertiser address `report.addr` reports: a `btmon` capture
            // against a real controller showed BlueZ drawing a fresh random
            // address on every advertising-set registration, so no
            // multi-fragment message's fragments ever shared an address —
            // see `frame::ORIGIN_LEN`.
            let key = FragKey {
                addr: origin,
                msg_id: hdr.msg_id,
            };
            let metrics = LinkMetrics {
                rssi_dbm: report.rssi,
                snr_db: None,
                quality: None,
            };

            // The mode tag's whole purpose: each format's fragments are laid
            // out at that format's own `FRAG_PAYLOAD` stride, so they must go
            // to the table built for it. Receiving is unconditional here —
            // `send_mode` governs transmission only, which is what lets a
            // node be upgraded to a new format without its peers moving.
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;

    use super::*;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    fn addr(n: u8) -> BleAddr {
        BleAddr::from([0, 0, 0, 0, 0, n])
    }

    /// Build one on-air fragment of `payload` addressed `mac(1) -> mac(2)`,
    /// as a peer's transmitter would, so a receive test can feed it to a
    /// sink without going through `send`.
    fn fragment_of(
        origin: Mac,
        protocol: u16,
        payload: &[u8],
        msg_id: u8,
        index: usize,
        format: BleAdvFormat,
    ) -> (Vec<u8>, usize) {
        let (frame_bytes, frame_len) = frame::assemble_frame(
            origin,
            &LinkFrameData {
                dst: mac(2),
                protocol,
                payload,
            },
        )
        .unwrap();
        let count = frame::fragment_count(frame_len, format).unwrap();
        let mut out = [0u8; MAX_FRAGMENT_BYTES];
        let n = frame::build_fragment(
            &frame_bytes[..frame_len],
            frame::FragmentSpec {
                origin,
                msg_id,
                index,
                count,
                format,
            },
            &mut out,
        )
        .unwrap();
        (out[..n].to_vec(), count)
    }

    /// Every fragment one `send` put on the air, in transmission order,
    /// paired with the format its advertisement was registered as.
    type SentFragments = Arc<Mutex<Vec<(BleAdvFormat, Vec<u8>)>>>;

    /// Records every fragment handed to `advertise` along with the format it
    /// was cut for, optionally failing instead — the seam a real backend
    /// (BlueZ) implements for real, stood in for here so `BleLink`'s logic is
    /// testable without any `bluetoothd` dependency.
    #[derive(Clone, Default)]
    struct FakeAdvertiser {
        sent: SentFragments,
        fail: bool,
        /// Formats this advertiser refuses, standing in for a controller that
        /// cannot register one kind of advertisement — the real, and
        /// *expected*, case of a pre-Bluetooth-5 controller under
        /// `BleSendMode::Both`.
        refuse: Vec<BleAdvFormat>,
    }

    impl FakeAdvertiser {
        fn failing() -> Self {
            Self {
                sent: Arc::new(Mutex::new(Vec::new())),
                fail: true,
                refuse: Vec::new(),
            }
        }

        fn refusing(formats: &[BleAdvFormat]) -> Self {
            Self {
                sent: Arc::new(Mutex::new(Vec::new())),
                fail: false,
                refuse: formats.to_vec(),
            }
        }

        fn sent(&self) -> Vec<(BleAdvFormat, Vec<u8>)> {
            self.sent.lock().unwrap().clone()
        }

        /// Just the fragments cut for one format, in transmission order.
        fn sent_in(&self, format: BleAdvFormat) -> Vec<Vec<u8>> {
            self.sent()
                .into_iter()
                .filter(|(f, _)| *f == format)
                .map(|(_, bytes)| bytes)
                .collect()
        }
    }

    impl BleAdvertiser for FakeAdvertiser {
        async fn advertise(&self, format: BleAdvFormat, fragment: &[u8]) -> Result<(), LinkError> {
            if self.fail || self.refuse.contains(&format) {
                return Err(LinkError::TransmitFailed);
            }
            self.sent.lock().unwrap().push((format, fragment.to_vec()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn send_advertises_each_fragment_in_order() {
        let advertiser = FakeAdvertiser::default();
        let (mut link, _sink) = BleLink::new(advertiser.clone(), BleSendMode::Legacy);

        // Sized so `HEADER_LEN + payload.len()` lands in `(frag_payload,
        // 2*frag_payload]` — exactly two fragments, regardless of the exact
        // budget the legacy format happens to have.
        let budget = BleAdvFormat::Legacy.frag_payload();
        let payload: Vec<u8> = (0..(budget - frame::HEADER_LEN + 5) as u8).collect();
        let frame_len = link
            .send(
                mac(1),
                &LinkFrameData {
                    dst: mac(2),
                    protocol: 0x1234,
                    payload: &payload,
                },
            )
            .await
            .unwrap();

        let mut expected_frame = Vec::new();
        expected_frame.extend_from_slice(&mac(2).0);
        expected_frame.extend_from_slice(&mac(1).0);
        expected_frame.extend_from_slice(&0x1234u16.to_be_bytes());
        expected_frame.extend_from_slice(&payload);
        assert_eq!(frame_len, expected_frame.len());

        let sent = advertiser.sent_in(BleAdvFormat::Legacy);
        assert_eq!(sent.len(), 2);

        let (fmt0, hdr0, origin0, body0) = frame::parse_fragment_with_origin(&sent[0]).unwrap();
        assert_eq!(fmt0, BleAdvFormat::Legacy);
        assert_eq!((hdr0.index, hdr0.count), (0, 2));
        assert_eq!(origin0, mac(1));
        assert_eq!(body0, &expected_frame[..budget]);

        let (_, hdr1, origin1, body1) = frame::parse_fragment_with_origin(&sent[1]).unwrap();
        assert_eq!((hdr1.index, hdr1.count), (1, 2));
        assert_eq!(origin1, mac(1));
        assert_eq!(body1, &expected_frame[budget..]);
        assert_eq!(hdr0.msg_id, hdr1.msg_id);
    }

    /// The point of the whole design: a frame that legacy has to cut into
    /// many fragments — each one its own advertising session, each paying the
    /// dwell — fits in a handful under extended.
    #[tokio::test]
    async fn send_in_extended_mode_collapses_a_frame_legacy_would_fragment_heavily() {
        let advertiser = FakeAdvertiser::default();
        let (mut link, _sink) = BleLink::new(advertiser.clone(), BleSendMode::Extended);

        // A full-cert-OGM-sized frame, the case design 07 costs out at 14
        // legacy fragments.
        let payload = vec![0xa5u8; 250 - frame::HEADER_LEN];
        link.send(
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0x4305,
                payload: &payload,
            },
        )
        .await
        .unwrap();

        assert!(advertiser.sent_in(BleAdvFormat::Legacy).is_empty());
        let extended = advertiser.sent_in(BleAdvFormat::Extended);
        assert_eq!(extended.len(), 2);
        assert_eq!(
            frame::fragment_count(250, BleAdvFormat::Legacy).unwrap(),
            14,
            "the legacy cost this is measured against"
        );
    }

    /// `Both` fragments the frame independently per format — not one
    /// fragmentation replayed as two PDU types, which would put legacy-sized
    /// fragments in extended advertisements and waste the entire budget.
    #[tokio::test]
    async fn send_in_both_mode_fragments_independently_per_format() {
        let advertiser = FakeAdvertiser::default();
        let (mut link, _sink) = BleLink::new(advertiser.clone(), BleSendMode::Both);

        let payload = vec![0x33u8; 100 - frame::HEADER_LEN];
        link.send(
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0x4305,
                payload: &payload,
            },
        )
        .await
        .unwrap();

        assert_eq!(advertiser.sent_in(BleAdvFormat::Legacy).len(), 6);
        assert_eq!(advertiser.sent_in(BleAdvFormat::Extended).len(), 1);

        // Legacy first: the format every peer can receive must not queue
        // behind airtime spent on the other.
        assert_eq!(advertiser.sent()[0].0, BleAdvFormat::Legacy);
    }

    /// A `Both` sender on a controller that cannot register extended
    /// advertisements must still deliver the legacy copy, and must report the
    /// send as a **success** — the legacy fragments really did reach the air.
    ///
    /// This is not a hypothetical: it is what a pre-Bluetooth-5 controller
    /// does, and design 07 §3.5's whole claim for `Both` is that adopting it
    /// "loses nothing". Reporting the frame as dropped would make `Both`
    /// strictly worse than `Legacy` on exactly the hardware it exists to
    /// tolerate, and would surface to an operator as the driver logging every
    /// single frame as lost while the mesh worked fine.
    #[tokio::test]
    async fn send_in_both_mode_succeeds_when_only_one_format_reaches_the_air() {
        let advertiser = FakeAdvertiser::refusing(&[BleAdvFormat::Extended]);
        let (mut link, _sink) = BleLink::new(advertiser.clone(), BleSendMode::Both);

        let payload = vec![0x77u8; 100 - frame::HEADER_LEN];
        let frame_len = link
            .send(
                mac(1),
                &LinkFrameData {
                    dst: mac(2),
                    protocol: 0x4305,
                    payload: &payload,
                },
            )
            .await
            .expect("the legacy copy reached the air, so the frame was sent");
        assert_eq!(frame_len, 100);

        // Every legacy fragment still went out, in full.
        assert_eq!(advertiser.sent_in(BleAdvFormat::Legacy).len(), 6);
        assert!(advertiser.sent_in(BleAdvFormat::Extended).is_empty());
    }

    /// The mirror case: a controller that somehow refuses legacy but takes
    /// extended is still a working link. Nothing privileges legacy here —
    /// what matters is that *some* copy reached the air.
    #[tokio::test]
    async fn send_in_both_mode_succeeds_on_the_extended_copy_alone() {
        let advertiser = FakeAdvertiser::refusing(&[BleAdvFormat::Legacy]);
        let (mut link, _sink) = BleLink::new(advertiser.clone(), BleSendMode::Both);

        let payload = vec![0x77u8; 100 - frame::HEADER_LEN];
        link.send(
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0x4305,
                payload: &payload,
            },
        )
        .await
        .expect("the extended copy reached the air");

        assert!(advertiser.sent_in(BleAdvFormat::Legacy).is_empty());
        assert_eq!(advertiser.sent_in(BleAdvFormat::Extended).len(), 1);
    }

    /// Only when *no* configured format reached the air is the frame actually
    /// lost — that is a real transmit failure and the driver must hear about
    /// it.
    #[tokio::test]
    async fn send_fails_only_when_every_configured_format_fails() {
        let advertiser = FakeAdvertiser::refusing(&[BleAdvFormat::Legacy, BleAdvFormat::Extended]);
        let (mut link, _sink) = BleLink::new(advertiser, BleSendMode::Both);

        let payload = [0xaa; 3];
        let err = link
            .send(
                mac(1),
                &LinkFrameData {
                    dst: mac(2),
                    protocol: 0,
                    payload: &payload,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, LinkError::TransmitFailed));
    }

    /// A format that fails partway through abandons its *remaining* fragments
    /// rather than advertising the rest of a frame no peer can reassemble —
    /// but does not abandon the other format's pass.
    #[tokio::test]
    async fn a_failing_format_does_not_abort_the_other_formats_fragments() {
        let advertiser = FakeAdvertiser::refusing(&[BleAdvFormat::Legacy]);
        let (mut link, _sink) = BleLink::new(advertiser.clone(), BleSendMode::Both);

        // Multi-fragment in legacy, single-fragment in extended: legacy fails
        // on its very first fragment, and extended must still run.
        let payload = vec![0x5au8; 100 - frame::HEADER_LEN];
        link.send(
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0x4305,
                payload: &payload,
            },
        )
        .await
        .unwrap();

        assert!(advertiser.sent_in(BleAdvFormat::Legacy).is_empty());
        assert_eq!(advertiser.sent_in(BleAdvFormat::Extended).len(), 1);
    }

    #[tokio::test]
    async fn send_propagates_advertiser_failure() {
        let (mut link, _sink) = BleLink::new(FakeAdvertiser::failing(), BleSendMode::Legacy);
        let payload = [0xaa; 3];

        let err = link
            .send(
                mac(1),
                &LinkFrameData {
                    dst: mac(2),
                    protocol: 0,
                    payload: &payload,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, LinkError::TransmitFailed));
    }

    #[tokio::test]
    async fn recv_reassembles_single_fragment_report() {
        let (mut link, sink) = BleLink::new(FakeAdvertiser::default(), BleSendMode::Legacy);

        let payload = [0xde, 0xad];
        let (fragment, count) = fragment_of(mac(1), 0x55, &payload, 9, 0, BleAdvFormat::Legacy);
        assert_eq!(count, 1);
        sink.submit(addr(1), Some(-40), &fragment);

        let received = link.recv().await.unwrap();
        assert_eq!(received.frame.dst, mac(2));
        assert_eq!(received.frame.protocol.get(), 0x55);
        assert_eq!(&received.frame.payload, &payload);
        assert_eq!(received.metrics.rssi_dbm, Some(-40));
    }

    #[tokio::test]
    async fn recv_reassembles_multi_fragment_report() {
        let (mut link, sink) = BleLink::new(FakeAdvertiser::default(), BleSendMode::Legacy);

        let budget = BleAdvFormat::Legacy.frag_payload();
        let payload: Vec<u8> = (0..(budget - frame::HEADER_LEN + 5) as u8).collect();
        for index in 0..2 {
            let (fragment, count) =
                fragment_of(mac(1), 0x77, &payload, 3, index, BleAdvFormat::Legacy);
            assert_eq!(count, 2);
            sink.submit(addr(1), Some(-60), &fragment);
        }

        let received = link.recv().await.unwrap();
        assert_eq!(received.frame.dst, mac(2));
        assert_eq!(received.frame.protocol.get(), 0x77);
        assert_eq!(&received.frame.payload, payload.as_slice());
    }

    /// Receiving is unconditional: a node configured to *send* legacy still
    /// reassembles a peer's extended advertisements. Send policy is local, and
    /// this is what makes design 07's node-by-node rollout safe.
    #[tokio::test]
    async fn recv_accepts_extended_fragments_from_a_legacy_sending_node() {
        let (mut link, sink) = BleLink::new(FakeAdvertiser::default(), BleSendMode::Legacy);

        let payload = vec![0xc3u8; 150];
        let (fragment, count) = fragment_of(mac(1), 0x88, &payload, 4, 0, BleAdvFormat::Extended);
        assert_eq!(count, 1, "150 bytes must fit one extended fragment");
        sink.submit(addr(1), Some(-50), &fragment);

        let received = link.recv().await.unwrap();
        assert_eq!(&received.frame.payload, payload.as_slice());
    }

    /// The demux's load-bearing case. Both messages share an origin `Mac`
    /// *and* a `msg_id`, so they share a `FragKey` — a single reassembler
    /// would collide them and complete neither correctly. Two tables, picked
    /// by the mode tag, keep them apart.
    #[tokio::test]
    async fn recv_demuxes_two_formats_sharing_one_reassembly_key() {
        let (mut link, sink) = BleLink::new(FakeAdvertiser::default(), BleSendMode::Legacy);

        let budget = BleAdvFormat::Legacy.frag_payload();
        let legacy_payload: Vec<u8> = (0..(budget - frame::HEADER_LEN + 5) as u8).collect();
        // Two fragments in *both* formats, so both tables genuinely hold a
        // partial entry under the shared key at the same time. A
        // single-fragment extended message would complete on arrival and
        // never overlap the legacy one, which makes the interleaving below
        // decorative rather than load-bearing.
        let extended_payload = vec![0x5au8; frame::MAX_REASSEMBLED_LEN - frame::HEADER_LEN];

        let (legacy_0, legacy_count) =
            fragment_of(mac(1), 0x11, &legacy_payload, 3, 0, BleAdvFormat::Legacy);
        let (legacy_1, _) = fragment_of(mac(1), 0x11, &legacy_payload, 3, 1, BleAdvFormat::Legacy);
        assert_eq!(legacy_count, 2);
        let (extended_0, extended_count) = fragment_of(
            mac(1),
            0x22,
            &extended_payload,
            3, // same msg_id, same origin: same FragKey
            0,
            BleAdvFormat::Extended,
        );
        let (extended_1, _) = fragment_of(
            mac(1),
            0x22,
            &extended_payload,
            3,
            1,
            BleAdvFormat::Extended,
        );
        assert_eq!(extended_count, 2);

        // Fully interleaved: neither message's fragments are adjacent, so a
        // shared table would have to survive both being in flight at once.
        sink.submit(addr(1), None, &legacy_0);
        sink.submit(addr(1), None, &extended_0);
        sink.submit(addr(1), None, &legacy_1);
        sink.submit(addr(1), None, &extended_1);

        let first = link.recv().await.unwrap();
        assert_eq!(first.frame.protocol.get(), 0x11);
        assert_eq!(&first.frame.payload, legacy_payload.as_slice());

        let second = link.recv().await.unwrap();
        assert_eq!(second.frame.protocol.get(), 0x22);
        assert_eq!(&second.frame.payload, extended_payload.as_slice());
    }

    /// The headline path, and until now the untested one: an extended message
    /// large enough to need a second fragment, reassembled end to end.
    ///
    /// Every other extended receive test uses a single fragment, which lands
    /// at offset 0 — where the extended table's 231-byte stride is
    /// indistinguishable from the legacy table's 18. This is the only test
    /// that asks `ExtendedReassembler` to place bytes at `1 * 231`, which is
    /// the whole reason the two tables are separate instantiations.
    ///
    /// Sized to `MAX_REASSEMBLED_LEN` deliberately: the second fragment then
    /// spans exactly `231..270`, landing on `Reassembler::accept`'s bound
    /// check. A `>` / `>=` slip there would reject every full-cert OGM while
    /// legacy kept working — a mesh that looks healthy and moves no extended
    /// traffic, which is the failure shape this crate keeps producing.
    #[tokio::test]
    async fn recv_reassembles_a_multi_fragment_extended_message() {
        let (mut link, sink) = BleLink::new(FakeAdvertiser::default(), BleSendMode::Legacy);

        let payload: Vec<u8> = (0..(frame::MAX_REASSEMBLED_LEN - frame::HEADER_LEN))
            .map(|i| i as u8)
            .collect();

        let (frag_0, count) = fragment_of(mac(7), 0x4305, &payload, 5, 0, BleAdvFormat::Extended);
        let (frag_1, _) = fragment_of(mac(7), 0x4305, &payload, 5, 1, BleAdvFormat::Extended);
        assert_eq!(count, 2, "the case the extended format exists for");

        sink.submit(addr(1), None, &frag_0);
        sink.submit(addr(1), None, &frag_1);

        let received = link.recv().await.unwrap();
        assert_eq!(received.frame.src, mac(7));
        assert_eq!(received.frame.protocol.get(), 0x4305);
        assert_eq!(&received.frame.payload, payload.as_slice());
    }

    /// A fragment tagged with a format this build predates is dropped, not
    /// guessed at — feeding it to either reassembler would corrupt that
    /// table's offsets.
    #[tokio::test]
    async fn recv_skips_a_fragment_with_an_unknown_mode_tag() {
        let (mut link, sink) = BleLink::new(FakeAdvertiser::default(), BleSendMode::Legacy);

        let payload = [0x42];
        let (mut unknown, _) = fragment_of(mac(1), 0x11, &payload, 1, 0, BleAdvFormat::Legacy);
        unknown[0] = 0xee;
        sink.submit(addr(1), None, &unknown);

        let (good, _) = fragment_of(mac(1), 0x11, &payload, 2, 0, BleAdvFormat::Legacy);
        sink.submit(addr(1), None, &good);

        let received = link.recv().await.unwrap();
        assert_eq!(&received.frame.payload, &payload);
    }

    #[tokio::test]
    async fn recv_skips_malformed_fragment() {
        let (mut link, sink) = BleLink::new(FakeAdvertiser::default(), BleSendMode::Legacy);

        // Malformed: count == 0 is rejected by `parse_fragment`.
        sink.submit(addr(1), None, &[BleAdvFormat::Legacy.tag(), 0, 0]);

        let payload = [0x42];
        let (fragment, _) = fragment_of(mac(1), 0x11, &payload, 1, 0, BleAdvFormat::Legacy);
        sink.submit(addr(1), None, &fragment);

        let received = link.recv().await.unwrap();
        assert_eq!(&received.frame.payload, &payload);
    }

    #[tokio::test]
    async fn recv_returns_receive_failed_when_sink_dropped() {
        let (mut link, sink) = BleLink::new(FakeAdvertiser::default(), BleSendMode::Legacy);
        drop(sink);

        assert!(matches!(link.recv().await, Err(LinkError::ReceiveFailed)));
    }

    /// A non-connectable advertisement is heard by every scanner in range.
    #[test]
    fn declares_broadcast_fan_out() {
        let (link, _sink) = BleLink::new(FakeAdvertiser::default(), BleSendMode::Legacy);
        assert_eq!(link.fan_out(), wayfinder::link::BROADCAST_FAN_OUT);
    }
}
