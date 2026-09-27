#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! [`LinkT`] adapter for the nRF52840's built-in IEEE 802.15.4 radio
//! (`embassy_nrf::radio::ieee802154::Radio`).
//!
//! On-air framing and fragmentation are handled by the hardware-agnostic
//! [`ieee802154`] crate (see the `at86rf233` crate for the SPI-radio
//! equivalent); this crate only adapts it to `embassy-nrf`'s [`Packet`] buffer
//! and [`Radio::try_send`]/[`Radio::receive`].
//!
//! [`Packet::CAPACITY`] (125) equals [`ieee802154::MAX_FRAME_LEN`] (also 125),
//! so every fragment [`ieee802154::build_fragment`] produces fits in a
//! [`Packet`] without truncation; this is checked at compile time below.
//!
//! # Why the radio lives in a task
//!
//! **`LinkT::recv` must be cancel-safe here, and awaiting [`Radio::receive`]
//! directly is not.** `wayfinder_embedded_driver` builds one `recv` future per
//! link, races them against the OGM timer with `select_array`, and **drops
//! every loser** — so a `recv` is torn down on each timer tick and each frame
//! from any other link.
//!
//! [`Radio::receive`] survives that without memory unsafety: it installs an
//! `OnDrop` guard that issues `tasks_stop`, spins until the radio reaches
//! `DISABLED`/`RX_IDLE`, and fences DMA. What it does *not* survive is the
//! frame. Cancelling loses whatever was mid-reception, and — worse — leaves
//! the radio **off** until the next `recv`, so the receiver is duty-cycled by
//! events on entirely unrelated links and pays RX ramp-up on every re-entry.
//! The result is a link that comes up, reports plausible metrics, moves *some*
//! traffic, and drops frames in a pattern that reads as poor RF.
//!
//! So [`Radio`] never leaves `radio_task`, which is spawned once and never
//! cancelled; `recv` only awaits a channel, which is cancel-safe. This mirrors
//! `wayfinder_nrf::usb_link` and `blue`'s `ReportQueue`, which exist for the
//! same reason. **Do not "simplify" this back into a direct await.**
//!
//! The task *does* drop its in-flight `receive` to service a transmit, which
//! is the one place cancelling is correct: the radio is half-duplex, so a
//! frame arriving during this node's own transmission was never receivable
//! anyway. That bounds the loss window to this node's own sends rather than to
//! every timer tick on every link.
//!
//! See `docs/design/implemented/19-ieee802154-nrf-link.md` §3.3.

use embassy_executor::SpawnError;
use embassy_executor::Spawner;
use embassy_futures::select::Either;
use embassy_futures::select::select;
use embassy_nrf::radio::Error as RadioError;
use embassy_nrf::radio::ieee802154::Cca;
use embassy_nrf::radio::ieee802154::Packet;
use embassy_nrf::radio::ieee802154::Radio;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use ieee802154::FragmentSpec;
use ieee802154::Ieee802154Reassembler;
use ieee802154::MAX_FRAME_LEN;
use ieee802154::MAX_REASSEMBLED_LEN;
use ieee802154::accept_fragment;
use ieee802154::assemble_frame;
use ieee802154::build_fragment;
use ieee802154::decode_frame;
use ieee802154::fragment_count;
use ieee802154::short_address_of;
use interfaces::frame::LinkFrameData;
use interfaces::frame::Mac;
use interfaces::link::LinkError;
use interfaces::link::LinkMetrics;
use tracing::debug;
use tracing::trace;
use wayfinder::link::LinkT;
use wayfinder::link::Received;

const _: () = assert!(Packet::CAPACITY as usize == MAX_FRAME_LEN);

/// Lowest and highest IEEE 802.15.4 channel in the 2.4 GHz band.
///
/// [`Radio::set_channel`] **panics** outside this range, so
/// [`Ieee802154Link::new`] checks it first: a mistyped channel is a
/// configuration error an operator should see reported, not a board that
/// panics during bring-up.
const CHANNEL_MIN: u8 = 11;
/// See [`CHANNEL_MIN`].
const CHANNEL_MAX: u8 = 26;

/// Transmission power this link requests, in dBm. Set explicitly rather than
/// left at the peripheral's reset default.
const TX_POWER_DBM: i8 = 0;

/// Received fragments the task has not yet handed to [`LinkT::recv`].
///
/// Sized off *this format*, not off another link: one whole frame's worth of
/// fragments plus one. `usb_link`'s queue holds whole frames, so a dropped
/// entry there costs one frame; this one holds fragments, and the reassembler
/// has no ARQ, so dropping any single entry voids the entire frame it belonged
/// to. A queue shallower than `MAX_REASSEMBLED_LEN / FRAG_PAYLOAD` could not
/// buffer one maximum-size frame even in principle.
///
/// The driver cancels `recv` on every OGM tick and every frame from any other
/// link, and dispatches sends sequentially — a LoRa transmit can hold the loop
/// for hundreds of milliseconds while this task keeps receiving — so the
/// headroom is doing real work.
const RX_QUEUE_DEPTH: usize = MAX_REASSEMBLED_LEN.div_ceil(ieee802154::FRAG_PAYLOAD) + 1;

/// One received fragment, copied out of the task's [`Packet`] so the task can
/// immediately go back to receiving.
struct RxFragment {
    bytes: [u8; MAX_FRAME_LEN],
    len: u8,
    /// IEEE 802.15.4 LQI on the `0..=255` scale, already scaled out of the
    /// hardware's correlator indicator by [`ieee_lqi`] — the raw value exists
    /// only at the `packet.lqi()` call site.
    lqi: u8,
}

/// What `radio_task` hands to [`LinkT::recv`].
///
/// Failures travel the queue rather than being logged and forgotten inside
/// the task. The driver's `handle_link_result` is what raises
/// `AlarmKind::LinkErrors` for a link that is failing, and it only ever sees
/// what `recv` returns — so a radio on the wrong channel, behind a broken
/// antenna, or under a jammer would otherwise fail every receive while
/// presenting to the management API as a link that is merely quiet. Moving
/// the radio into a task must not also move its errors out of view.
enum RxEvent {
    /// A fragment the radio received and CRC-checked.
    Fragment(RxFragment),
    /// A receive that failed. Coalesced by the alarm board, so a persistently
    /// broken radio is one row with a rising count rather than a flood.
    Failed(LinkError),
}

/// One fragment [`LinkT::send`] wants transmitted.
struct TxRequest {
    bytes: [u8; MAX_FRAME_LEN],
    len: u8,
}

/// Fragments received by `radio_task`, drained by [`LinkT::recv`].
static RX_QUEUE: Channel<CriticalSectionRawMutex, RxEvent, RX_QUEUE_DEPTH> = Channel::new();

/// Transmit requests from [`LinkT::send`] to `radio_task`, and the outcomes
/// coming back.
///
/// [`Signal`] rather than a depth-1 [`Channel`] pair: a signal is exactly
/// "one slot, latest value wins, never blocks". That matters on the result
/// side, where `radio_task` publishes the outcome — a full channel would make
/// its `send` *await*, stalling the one task that owns the radio and stopping
/// reception until something drained it. It also makes a stale result
/// structurally impossible rather than something `send` has to defensively
/// drain, which is what a cancelled `send` would otherwise leave behind.
///
/// Not correlated by any request id: [`LinkT::send`] takes `&mut self`, so at
/// most one transmit is ever in flight.
static TX_REQUEST: Signal<CriticalSectionRawMutex, TxRequest> = Signal::new();
/// See [`TX_REQUEST`].
static TX_RESULT: Signal<CriticalSectionRawMutex, Result<(), LinkError>> = Signal::new();

/// Why [`Ieee802154Link::new`] could not bring the radio up.
///
/// `PartialEq`/`Eq` are not derived because [`SpawnError`] implements
/// neither; match on the variant instead.
#[derive(Debug, Clone, Copy)]
pub enum BringUpError {
    /// The requested channel is outside the 2.4 GHz band's 11..=26. Reported
    /// rather than passed to [`Radio::set_channel`], which panics on it.
    InvalidChannel(u8),
    /// The radio task could not be spawned, so nothing would ever drive the
    /// radio. Returned rather than ignored: the link would look present and
    /// be permanently deaf and mute.
    TaskSpawn(SpawnError),
}

/// Own the radio forever: receive fragments into `RX_QUEUE`, and transmit
/// whatever [`TX_REQUEST`] carries.
///
/// Never returns and is never cancelled — see the module docs for why that is
/// the whole point of this task's existence.
#[embassy_executor::task]
async fn radio_task(mut radio: Radio<'static>) -> ! {
    let mut packet = Packet::new();
    loop {
        // Bound the borrow of `radio`/`packet` to this statement so the match
        // arms below can use both. The losing future is dropped here, which
        // for `receive` runs its `OnDrop` radio-stop guard.
        let outcome = select(radio.receive(&mut packet), TX_REQUEST.wait()).await;

        match outcome {
            Either::First(Ok(())) => {
                let Some(fragment) = capture(&packet) else {
                    continue;
                };

                // Dropping the newest fragment is correct when the driver is
                // not draining: the medium is lossy, the reassembler is built
                // for gaps, and blocking here would stop the receiver
                // entirely. `trace!`, not `warn!` — reachable from arbitrary
                // peer input.
                if RX_QUEUE.try_send(RxEvent::Fragment(fragment)).is_err() {
                    trace!("drop: 802.15.4 rx queue full");
                }
            }
            Either::First(Err(e)) => {
                // A CRC failure is an ordinary event on a shared radio, so it
                // is `trace!` here — but it still has to reach the driver, or
                // a radio failing every receive is indistinguishable from a
                // quiet one. `try_send` so a full queue never stalls the task.
                trace!(?e, "802.15.4 receive failed");
                let _ = RX_QUEUE.try_send(RxEvent::Failed(map_err(e)));
            }
            Either::Second(request) => {
                let mut packet = Packet::new();
                packet.copy_from_slice(&request.bytes[..request.len as usize]);
                let result = radio.try_send(&mut packet).await.map_err(map_err);
                TX_RESULT.signal(result);
            }
        }
    }
}

/// A [`LinkT`] mesh interface backed by the nRF52840's built-in IEEE 802.15.4
/// radio.
///
/// The [`Radio`] itself lives in `radio_task`; this type holds only the
/// framing state and talks to it over channels. Construct with
/// [`Ieee802154Link::new`].
pub struct Ieee802154Link {
    /// IEEE 802.15.4 sequence number for the next fragment [`LinkT::send`]
    /// transmits, incremented (with wraparound) after each one.
    seq: u8,
    /// Fragment-reassembly message id for the next *frame* [`LinkT::send`]
    /// transmits, incremented (with wraparound) after each one. Distinct from
    /// [`Self::seq`]: every fragment of one frame shares a `msg_id`, while
    /// each gets its own MAC sequence number.
    msg_id: u8,
    /// Assembled frame bytes being fragmented by the current [`LinkT::send`].
    /// A field rather than a `send` local so it does not enlarge that
    /// future's poll frame — this board's stack budget is measured.
    tx_frame: [u8; MAX_REASSEMBLED_LEN],
    /// In-flight fragment reassemblies, keyed on peers' short addresses.
    reassembler: Ieee802154Reassembler,
    /// Landing buffer for a completed reassembly; [`LinkT::recv`] borrows its
    /// returned [`Received`] from this.
    rx_frame: [u8; MAX_REASSEMBLED_LEN],
}

impl Ieee802154Link {
    /// Configure `radio`, hand it to `radio_task`, and return the link.
    ///
    /// `channel` is an IEEE 802.15.4 2.4 GHz channel, 11..=26. Clear-channel
    /// assessment is carrier-sense (what [`Radio::try_send`] reports as
    /// [`RadioError::ChannelInUse`]) and transmission power is
    /// `TX_POWER_DBM`.
    ///
    /// **Call once per boot.** The queues this link talks to the task over are
    /// process-wide statics — there is one `RADIO` peripheral, so a second
    /// link would be a second consumer of one radio's frames, silently
    /// splitting them.
    pub fn new(
        spawner: Spawner,
        mut radio: Radio<'static>,
        channel: u8,
    ) -> Result<Self, BringUpError> {
        if !(CHANNEL_MIN..=CHANNEL_MAX).contains(&channel) {
            return Err(BringUpError::InvalidChannel(channel));
        }
        radio.set_channel(channel);
        radio.set_cca(Cca::CarrierSense);
        radio.set_transmission_power(TX_POWER_DBM);

        // The task builder allocates the task's storage and so can fail
        // before `spawn` is ever reached; `spawn` itself returns `()`.
        let task = radio_task(radio).map_err(BringUpError::TaskSpawn)?;
        spawner.spawn(task);
        debug!(channel, "802.15.4 radio task started");

        Ok(Self {
            seq: 0,
            msg_id: 0,
            tx_frame: [0u8; MAX_REASSEMBLED_LEN],
            reassembler: Ieee802154Reassembler::new(),
            rx_frame: [0u8; MAX_REASSEMBLED_LEN],
        })
    }
}

/// Map an `embassy-nrf` radio error to a [`LinkError`].
///
/// [`RadioError::CrcFailed`] (a corrupted received frame, from
/// [`Radio::receive`]) maps to [`LinkError::MalformedFrame`] — noise, a
/// collision, or anyone on the channel can produce one, so it must not raise
/// the interface's `LinkErrors` alarm — and
/// [`RadioError::ChannelInUse`] (clear-channel assessment found the channel
/// busy, from [`Radio::try_send`]) maps to [`LinkError::TransmitFailed`]. All
/// other variants — including any added later, since [`RadioError`] is
/// `#[non_exhaustive]` — map to [`LinkError::Io`].
fn map_err(err: RadioError) -> LinkError {
    match err {
        RadioError::CrcFailed(_) => LinkError::MalformedFrame,
        RadioError::ChannelInUse => LinkError::TransmitFailed,
        _ => LinkError::Io,
    }
}

/// The nRF52840's energy-detection scale factor, from the RADIO chapter of
/// the Product Specification (`PRF[dBm] = ED_RSSIOFFS + ED_RSSISCALE x
/// VALHARDWARE`). The same constant converts a correlator indicator into an
/// IEEE 802.15.4 LQI.
///
/// It is **4 on this part** and 5 on the nRF52833/nRF5340. Nothing enforces
/// that — `embassy-nrf`'s chip-feature guard only fires when *no* part is
/// selected, and Cargo features are additive — so what keeps the constant
/// honest is that porting this crate means editing the `nrf52840` feature in
/// its `Cargo.toml`, and `ed_rssiscale_is_the_nrf52840_value` makes that edit
/// fail loudly. Note the exhaustive test derives its expectation *from* this
/// constant, so it moves with it; the pinned table is what catches a change.
const ED_RSSISCALE: u8 = 4;

/// Top of the correlator indicator's useful domain. The Product
/// Specification saturates anything above this at [`u8::MAX`] rather than
/// scaling it, so a reading over 63 carries no information beyond "as good as
/// the hardware can report".
const HW_LQI_MAX: u8 = 63;

/// Scale the radio's raw correlator indicator into an IEEE 802.15.4 LQI on
/// the `0..=255` scale [`LinkMetrics::quality`] is defined on.
///
/// [`Packet::lqi`] returns the byte the hardware appends after the payload,
/// which is *not* an LQI: its useful domain is `0..=63`. The Product
/// Specification's RADIO chapter states the conversion as
/// `LQI_IEEE = (uint8_t)(val > 63 ? 255 : val * ED_RSSISCALE)`, and Nordic's
/// own driver applies the same mapping in `nrf_802154_core.c`'s `lqi_get`.
///
/// Handing the raw value over instead was not cosmetic — it suppressed
/// routing through this radio. Design 19 §12.7 records the incident, the
/// measured readings and the reasoning.
fn ieee_lqi(hw: u8) -> u8 {
    if hw > HW_LQI_MAX {
        return u8::MAX;
    }
    // Saturating, not plain `*`: the product cannot exceed 252 with today's
    // constants, but a wrapping multiply would turn a strong link into a weak
    // one if either ever moved, and a panicking one would take down a `-> !`
    // task on a board.
    hw.saturating_mul(ED_RSSISCALE)
}

/// Copy a received [`Packet`] into an [`RxFragment`], scaling its LQI, or
/// return `None` for a packet whose length makes it unusable.
///
/// Split out of [`radio_task`] so the capture step is reachable from a host
/// test: `Packet` is host-constructible, so a test can plant a chosen
/// hardware LQI and assert the fragment carries the *scaled* value. Inline,
/// the only coverage was of `ieee_lqi` itself — and deleting its call here
/// would have left every test green.
///
/// `Packet::len` is `buffer[0] - 2` on a byte the radio's DMA wrote, with no
/// bound of its own: a PHR of 0 or 1 wraps to 254/255 in a release build, and
/// `&packet[..len]` below would then slice `Packet`'s own 128-byte internal
/// buffer out of range — a panic inside a `-> !` task, on the one board whose
/// only diagnostic path is USB.
/// The sibling `at86rf233` driver validates its equivalent field; this one
/// must too. That guard has no test and cannot have one here:
/// `MAX_FRAME_LEN` and `Packet::CAPACITY` are both 125 and `Packet::set_len`
/// asserts at 125, so a host test cannot build the oversized packet it
/// rejects — only the radio's DMA can. A test written against it would assert
/// nothing.
///
/// There is deliberately no *lower* bound, though [`Packet::lqi`] is
/// documented to return an invalid value for packets under 3 bytes. Such a
/// fragment cannot carry its LQI to the router: `decode_fragment` rejects
/// anything below `HEADER_LEN + FRAG_HDR_LEN` (11 bytes) before `recv` breaks
/// out of its loop, so the metrics are dropped with the fragment. Adding a
/// bound here would only duplicate that one.
fn capture(packet: &Packet) -> Option<RxFragment> {
    let len = usize::from(packet.len());
    if len > MAX_FRAME_LEN {
        trace!(len, "drop: implausible 802.15.4 phy length");
        return None;
    }

    // Both numbers, because the scaled one alone cannot be verified. Every
    // hardware reading of 64 or more maps to 255, so the management API's
    // link-quality column — which is how bring-up measured 49 and 67 in the
    // first place — can no longer tell a correctly saturated link from a
    // wrong scale factor or a stale buffer read. This is the only place in the
    // receive path where the raw value still exists. Per-frame and `trace!` per the logging rules;
    // metadata only, no payload.
    let hw_lqi = packet.lqi();
    let lqi = ieee_lqi(hw_lqi);
    trace!(hw_lqi, lqi, len, "rx 802.15.4 fragment");

    let mut fragment = RxFragment {
        bytes: [0u8; MAX_FRAME_LEN],
        len: len as u8,
        lqi,
    };
    fragment.bytes[..len].copy_from_slice(&packet[..len]);
    Some(fragment)
}

/// The nRF52840 radio has no software-controlled retry/ack and no SNR
/// concept: `send` performs hardware clear-channel assessment before
/// transmitting each fragment and reports a busy channel as
/// [`LinkError::TransmitFailed`]; `recv` reports an IEEE 802.15.4 LQI as
/// [`LinkMetrics::quality`], leaving `rssi_dbm` and `snr_db` as `None`.
///
/// # The LQI is scaled, and has to be
///
/// [`Packet::lqi`] does not return an LQI — it returns the correlator
/// indicator the hardware appends, whose useful domain is `0..=63`. The
/// private `ieee_lqi` converts it; see
/// `wayfinder::link_quality::normalize_quality` for why that mapping stays
/// here rather than moving into the router.
impl LinkT for Ieee802154Link {
    /// Fragment `data` and transmit every fragment, returning the total
    /// on-air bytes.
    ///
    /// A fragment that fails to transmit abandons the whole frame rather than
    /// sending the rest: the receiver cannot complete a reassembly missing a
    /// fragment, so the remaining airtime would be spent for nothing. Trickle
    /// re-emission is the recovery path, per the fire-and-forget `LinkT`
    /// contract.
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        // No stale-result drain is needed: `TX_RESULT` is a `Signal`, so a
        // value left by a cancelled `send` is overwritten by this frame's
        // outcome rather than consumed as it.
        TX_RESULT.reset();

        let frame_len = assemble_frame(origin, data, &mut self.tx_frame)?;
        let count = fragment_count(frame_len)?;
        let src_addr = short_address_of(origin);
        let msg_id = self.msg_id;
        self.msg_id = self.msg_id.wrapping_add(1);

        let mut sent = 0;
        for index in 0..count {
            let mut request = TxRequest {
                bytes: [0u8; MAX_FRAME_LEN],
                len: 0,
            };
            let n = build_fragment(
                &self.tx_frame[..frame_len],
                FragmentSpec {
                    seq: self.seq,
                    src_addr,
                    msg_id,
                    index,
                    count,
                },
                &mut request.bytes,
            )?;
            request.len = n as u8;
            self.seq = self.seq.wrapping_add(1);

            TX_REQUEST.signal(request);
            if let Err(e) = TX_RESULT.wait().await {
                // Name which fragment of how many was lost and how much
                // airtime the frame already cost. The driver's own log says
                // only "link send failed", and `sent` is otherwise discarded
                // by `?` — so a node abandoning frame after frame under CCA
                // contention would publish `tx_fps = 0` while saturating the
                // channel.
                trace!(?e, index, count, sent, "abandoning frame: fragment failed");
                return Err(e);
            }
            sent += n;
        }

        Ok(sent)
    }

    /// Take fragments off `RX_QUEUE` until one completes a frame.
    ///
    /// Awaits only the channel, which is cancel-safe — see the module docs. A
    /// fragment that does not complete a message is not an event the driver
    /// has anything to do with, so this loops rather than returning.
    async fn recv<'a>(&'a mut self) -> Result<Received<'a>, LinkError> {
        let (len, metrics) = loop {
            let fragment = match RX_QUEUE.receive().await {
                RxEvent::Fragment(fragment) => fragment,
                // Straight out to the driver, which logs it and raises the
                // coalescing `LinkErrors` alarm.
                RxEvent::Failed(e) => return Err(e),
            };
            let metrics = LinkMetrics {
                rssi_dbm: None,
                snr_db: None,
                quality: Some(fragment.lqi),
            };
            if let Some(complete) = accept_fragment(
                &mut self.reassembler,
                &fragment.bytes[..fragment.len as usize],
                metrics,
                &mut self.rx_frame,
            ) {
                break complete;
            }
        };

        Ok(Received {
            frame: decode_frame(&self.rx_frame[..len])?,
            metrics,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// Pins [`ieee_lqi`]'s mapping at the points hardware produced; see that
    /// function for the Product Specification formula it implements.
    ///
    /// 49 and 67 are the readings bring-up actually measured between two
    /// desk-distance boards (design 19 §12.7).
    #[test]
    fn hardware_lqi_is_scaled_into_the_ieee_range() {
        // (hardware correlator indicator, IEEE 802.15.4 LQI)
        let cases = [
            (0u8, 0u8),
            (1, 4),
            (49, 196), // measured at desk range
            (63, 252), // top of the hardware domain
            (64, 255), // first value the PS saturates
            (67, 255), // measured at desk range, already over the ceiling
            // The correlator cannot produce this, but `lqi()` is an unchecked
            // read of a byte the hardware may never have written (a runt frame
            // leaves stale buffer contents there), so it must not wrap.
            (255, 255),
        ];
        for (hw, ieee) in cases {
            assert_eq!(ieee_lqi(hw), ieee, "hardware lqi {hw}");
        }
    }

    /// The table above documents the mapping at seven points; this pins it at
    /// all 256, so no input is left to a reading of the formula.
    ///
    /// Worth having as well as the table because a weaker property would not
    /// catch much: monotonicity alone is satisfied by a function returning a
    /// constant, and the table alone pins the 64-value linear region at only
    /// four points.
    #[test]
    fn every_hardware_value_maps_per_the_product_specification() {
        for hw in 0..=HW_LQI_MAX {
            assert_eq!(
                u16::from(ieee_lqi(hw)),
                u16::from(hw) * u16::from(ED_RSSISCALE),
                "in the scaled domain, hardware lqi {hw}"
            );
        }
        for hw in (HW_LQI_MAX + 1)..=u8::MAX {
            assert_eq!(ieee_lqi(hw), u8::MAX, "past the ceiling, hardware lqi {hw}");
        }
    }

    /// The scale factor is a per-part constant — 4 here, 5 on the
    /// nRF52833/nRF5340 — and every row of the table above moves with it.
    /// Pinned as a named fact the way [`CHANNEL_MIN`] is in
    /// `channel_bounds_match_the_24ghz_band`, so a port to another part fails
    /// here rather than quietly rescaling every link in the mesh.
    #[test]
    fn ed_rssiscale_is_the_nrf52840_value() {
        assert_eq!(ED_RSSISCALE, 4);
        assert_eq!(HW_LQI_MAX, 63);
    }

    /// `capture` must hand on the *scaled* LQI, not the hardware byte.
    ///
    /// This is the test the first version of this change was missing: every
    /// assertion above passes against a `capture` that never calls
    /// [`ieee_lqi`] at all, so reverting the fix was a one-token edit away
    /// from going unnoticed. `recv` itself is not reachable from a host test
    /// — it awaits a process-global `Channel` and this workspace registers no
    /// host `critical-section` implementation — but `Packet` is
    /// host-constructible, which puts the capture step within reach.
    #[test]
    fn capture_reports_a_scaled_lqi() {
        let mut packet = Packet::new();
        let body = [0xaa; 16];
        packet.copy_from_slice(&body);

        // `lqi()` reads `buffer[1 + len()]`, so plant the byte by briefly
        // lengthening the packet over it. Upstream documents the aliasing:
        // `copy_from_slice` and `set_len` + `deref_mut` overwrite the stored
        // LQI, which is exactly the seam being used here.
        packet.set_len(body.len() as u8 + 1);
        packet[body.len()] = 49;
        packet.set_len(body.len() as u8);
        assert_eq!(packet.lqi(), 49, "planting the hardware lqi");

        let fragment = capture(&packet).expect("a 16-byte packet is capturable");
        assert_eq!(fragment.len as usize, body.len());
        assert_eq!(
            fragment.lqi, 196,
            "capture must scale 49 to 196, not pass the hardware byte through"
        );
    }

    /// `map_err` distinguishes the two `RadioError` variants `recv`/`send`
    /// can actually produce (`CrcFailed` from [`Radio::receive`],
    /// `ChannelInUse` from [`Radio::try_send`]) and falls back to
    /// [`LinkError::Io`] for everything else, including future
    /// `#[non_exhaustive]` variants.
    ///
    /// A CRC failure is off-air corruption — noise, a collision, or anyone on
    /// the channel transmitting garbage — so it is `MalformedFrame`, which does
    /// not latch the interface's `LinkErrors` alarm (#75).
    #[test]
    fn map_err_distinguishes_known_variants() {
        assert!(matches!(
            map_err(RadioError::CrcFailed(0)),
            LinkError::MalformedFrame
        ));
        assert!(matches!(
            map_err(RadioError::ChannelInUse),
            LinkError::TransmitFailed
        ));
        assert!(matches!(map_err(RadioError::BufferTooLong), LinkError::Io));
    }

    /// Only 2.4 GHz channels 11..=26 exist, and `Radio::set_channel` panics
    /// outside that range — so `new` must reject the value before reaching
    /// it. The boundaries are what a hand-written config gets wrong.
    #[test]
    fn channel_bounds_match_the_24ghz_band() {
        assert_eq!(CHANNEL_MIN, 11);
        assert_eq!(CHANNEL_MAX, 26);
        for bad in [0u8, 10, 27, 255] {
            assert!(!(CHANNEL_MIN..=CHANNEL_MAX).contains(&bad));
        }
        for good in [11u8, 15, 26] {
            assert!((CHANNEL_MIN..=CHANNEL_MAX).contains(&good));
        }
    }

    /// A fragment round-trips through [`Packet::copy_from_slice`] /
    /// [`Deref`](core::ops::Deref) / reassembly, exactly as
    /// [`Ieee802154Link::send`] and `radio_task` use it (`send` via the
    /// build half, the task via the `Deref` + queue half).
    #[test]
    fn fragments_round_trip_through_packet() {
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let mut frame = [0u8; MAX_REASSEMBLED_LEN];
        let frame_len = assemble_frame(
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0x4305,
                payload: &payload,
            },
            &mut frame,
        )
        .unwrap();

        let mut reassembler = Ieee802154Reassembler::new();
        let mut out = [0u8; MAX_REASSEMBLED_LEN];
        let count = fragment_count(frame_len).unwrap();

        let mut completed = None;
        for index in 0..count {
            let mut air = [0u8; MAX_FRAME_LEN];
            let n = build_fragment(
                &frame[..frame_len],
                FragmentSpec {
                    seq: index as u8,
                    src_addr: short_address_of(mac(1)),
                    msg_id: 0,
                    index,
                    count,
                },
                &mut air,
            )
            .unwrap();

            let mut packet = Packet::new();
            packet.copy_from_slice(&air[..n]);
            completed =
                accept_fragment(&mut reassembler, &packet, LinkMetrics::default(), &mut out)
                    .or(completed);
        }

        let (len, _) = completed.unwrap();
        let decoded = decode_frame(&out[..len]).unwrap();
        assert_eq!(decoded.src, mac(1));
        assert_eq!(decoded.dst, mac(2));
        assert_eq!(decoded.protocol.get(), 0x4305);
        assert_eq!(&decoded.payload, &payload);
    }

    /// A maximum-size fragment (`MAX_FRAME_LEN` bytes, the largest
    /// `build_fragment` will ever produce) exactly fills a `Packet`'s
    /// capacity without panicking in `copy_from_slice`, and fits an
    /// [`RxFragment`]/[`TxRequest`] buffer without truncation.
    #[test]
    fn max_size_fragment_fits_in_packet_and_the_queues() {
        let mut frame = [0u8; MAX_REASSEMBLED_LEN];
        let frame_len = assemble_frame(
            mac(1),
            &LinkFrameData {
                dst: mac(2),
                protocol: 0,
                payload: &[0u8; ieee802154::FRAG_PAYLOAD - ieee802154::LINK_HEADER_LEN],
            },
            &mut frame,
        )
        .unwrap();

        let mut request = TxRequest {
            bytes: [0u8; MAX_FRAME_LEN],
            len: 0,
        };
        let n = build_fragment(
            &frame[..frame_len],
            FragmentSpec {
                seq: 0,
                src_addr: 1,
                msg_id: 0,
                index: 0,
                count: 1,
            },
            &mut request.bytes,
        )
        .unwrap();
        assert_eq!(n, MAX_FRAME_LEN);
        request.len = n as u8;

        let mut packet = Packet::new();
        packet.copy_from_slice(&request.bytes[..request.len as usize]);
        assert_eq!(packet.len(), MAX_FRAME_LEN as u8);

        // The queue entries carry a `u8` length, so a full fragment must not
        // overflow it.
        assert!(MAX_FRAME_LEN <= u8::MAX as usize);
        let fragment = RxFragment {
            bytes: [0u8; MAX_FRAME_LEN],
            len: MAX_FRAME_LEN as u8,
            lqi: 0,
        };
        assert_eq!(fragment.bytes[..fragment.len as usize].len(), MAX_FRAME_LEN);
    }
}
