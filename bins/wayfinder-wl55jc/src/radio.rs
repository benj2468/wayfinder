//! The mesh link over this board's on-die LoRa radio: a `LinkT` on one side,
//! `lora-phy` on the other, and `lora-link`'s wire format between them.
//!
//! # One task owns the radio, and that is the whole design
//!
//! `wayfinder_embedded_driver` races **every link's `recv` against the OGM
//! timer** and drops every loser, so a `recv` that awaits the radio directly is
//! torn down on every timer tick and every frame from any other link. It stays
//! memory-safe and loses the frame in flight, leaving the receiver out of RX
//! until the next `recv` — which reads as *poor RF, not a bug*, on a mesh whose
//! job is judging link quality. `libs/lora-link/CLAUDE.md` carries the full
//! argument; `at86rf233` is the driver in this repo that still has the bug.
//!
//! So [`radio_task`] owns the radio for its whole life and is never cancelled,
//! and [`LoraLink::recv`] awaits only a channel.
//!
//! # Why the task owns *transmit* too
//!
//! A half-duplex radio cannot be shared by a mutex here: the receive side sits
//! parked inside `rx()` holding the radio, so a `send` waiting on that mutex
//! would wait until a frame happened to arrive. Instead the task races `rx()`
//! against a transmit queue and abandons the receive when work shows up —
//! cancelling `lora-phy`'s `rx` future *inside* the task, which is safe
//! because the task then re-enters RX itself rather than being destroyed.
//!
//! [`LoraLink::send`] therefore hands one fragment to the queue and waits for
//! the task to report back. `send` is awaited to completion by its caller and
//! is not raced, so blocking there is fine.

use embassy_futures::select::Either;
use embassy_futures::select::select;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use embassy_time::Delay;
use embassy_time::Duration;
use embassy_time::Timer;
use lora_phy::LoRa;
use lora_phy::RxMode;
use lora_phy::mod_params::Bandwidth;
use lora_phy::mod_params::CodingRate;
use lora_phy::mod_params::SpreadingFactor;
use lora_phy::sx126x::Stm32wl;
use lora_phy::sx126x::Sx126x;
use tracing::debug;
use tracing::error;
use tracing::trace;
use tracing::warn;
use wayfinder::interfaces::frame::LinkFrameData;
use wayfinder::interfaces::frame::Mac;
use wayfinder::interfaces::link::LinkError;
use wayfinder::interfaces::link::LinkMetrics;
use wayfinder::link::LinkT;
use wayfinder::link::Received;

use crate::iv::Stm32wlInterfaceVariant;
use crate::spi_device::SubghzSpiDevice;

/// Concrete radio type this board builds: the on-die SX126x over `SUBGHZSPI`,
/// with the STM32WL's register-backed control lines.
pub type BoardRadio = Sx126x<
    SubghzSpiDevice<'static>,
    Stm32wlInterfaceVariant<embassy_stm32::gpio::Output<'static>>,
    Stm32wl,
>;

/// The `lora-phy` handle, as this board instantiates it.
pub type BoardLoRa = LoRa<BoardRadio, Delay>;

/// One on-air packet, owned so it can cross a channel.
///
/// Sized to the PHY's own ceiling, which is also exactly one full fragment.
pub type Packet = heapless::Vec<u8, { lora_link::MAX_FRAME_LEN }>;

/// Received packets the task has not yet handed to `recv`.
///
/// Four is enough to absorb the burst of fragments one multi-fragment frame
/// arrives as while `recv` is not being polled, without the queue becoming a
/// place frames go to age: each slot is a full [`Packet`], so this is ~1 KiB
/// of a 64 KiB part.
const RX_DEPTH: usize = 4;

/// Packets received but not yet collected by [`LoraLink::recv`].
static RX_QUEUE: Channel<CriticalSectionRawMutex, RxPacket, RX_DEPTH> = Channel::new();

/// One fragment waiting to go out. Depth one: `send` hands over a fragment and
/// waits for it, so a second can never be outstanding.
static TX_QUEUE: Channel<CriticalSectionRawMutex, Packet, 1> = Channel::new();

/// Whether the fragment [`TX_QUEUE`] last carried made it onto the air.
static TX_DONE: Signal<CriticalSectionRawMutex, bool> = Signal::new();

/// A received packet with the physical-layer measurements for it.
struct RxPacket {
    bytes: Packet,
    metrics: LinkMetrics,
}

/// The radio settings every node on this mesh must agree on.
///
/// Not defaulted: two nodes disagreeing on any of these do not hear each other
/// at all, and the symptom is an empty routing table rather than an error.
#[derive(Clone, Copy)]
pub struct RadioConfig {
    /// Centre frequency in Hz. The JC1 board is the high-band build, so this
    /// belongs in the 868 MHz (EU) or 915 MHz (US) ISM allocation.
    pub frequency_hz: u32,
    /// LoRa spreading factor. Higher reaches further and costs airtime
    /// proportionally.
    pub spreading_factor: SpreadingFactor,
    /// Channel bandwidth.
    pub bandwidth: Bandwidth,
    /// Forward-error-correction rate.
    pub coding_rate: CodingRate,
    /// Transmit power in dBm, as `lora-phy` takes it.
    ///
    /// **Regulated.** This board's duty cycle is not governed anywhere in this
    /// firmware (design 25 §6.3), so a deployed node needs a real airtime
    /// governor and a power figure chosen for its region, not this default.
    pub output_power: i32,
}

/// Own the radio for the life of the node: receive continuously, and interrupt
/// that to transmit whenever [`LoraLink::send`] queues a fragment.
///
/// Never returns, and **must never be cancelled** — see the module docs.
#[embassy_executor::task]
pub async fn radio_task(
    spi: SubghzSpiDevice<'static>,
    iv: Stm32wlInterfaceVariant<embassy_stm32::gpio::Output<'static>>,
    sx_config: lora_phy::sx126x::Config<Stm32wl>,
    config: RadioConfig,
) -> ! {
    // Built here rather than in `main` and handed over: a `LoRa` constructed
    // in `main` is a stack temporary in `main`'s poll frame, which is held for
    // the life of the node. `scripts/stack-budget.py` is what catches that.
    let mut lora = match LoRa::new(Sx126x::new(spi, iv, sx_config), false, Delay).await {
        Ok(lora) => lora,
        Err(e) => {
            error!(?e, "radio: bring-up failed; this link is down");
            park().await
        }
    };
    // Nothing this task can do about a rejected parameter set, and returning
    // is not an option. Park rather than spin, and say why once.
    let modulation = match lora.create_modulation_params(
        config.spreading_factor,
        config.bandwidth,
        config.coding_rate,
        config.frequency_hz,
    ) {
        Ok(modulation) => modulation,
        Err(e) => {
            error!(
                ?e,
                "radio: modulation parameters refused; this link is down"
            );
            park().await
        }
    };

    // `max_payload_length` is the PHY ceiling, which is also one whole
    // fragment; a longer packet is not something this format can produce.
    let rx_params = match lora.create_rx_packet_params(
        PREAMBLE_SYMBOLS,
        false,
        lora_link::MAX_FRAME_LEN as u8,
        true,
        false,
        &modulation,
    ) {
        Ok(params) => params,
        Err(e) => {
            error!(?e, "radio: rx packet parameters refused; this link is down");
            park().await
        }
    };
    let mut tx_params =
        match lora.create_tx_packet_params(PREAMBLE_SYMBOLS, false, true, false, &modulation) {
            Ok(params) => params,
            Err(e) => {
                error!(?e, "radio: tx packet parameters refused; this link is down");
                park().await
            }
        };

    if let Err(e) = lora.init().await {
        error!(?e, "radio: init failed; this link is down");
        park().await
    }

    let mut buf = [0u8; lora_link::MAX_FRAME_LEN];
    // Consecutive failures to enter receive, for the backoff and so the streak
    // is reported once rather than per attempt.
    let mut rx_failures: u32 = 0;
    loop {
        // Re-entered every pass: a transmit leaves the radio in standby, and
        // `rx` refuses to run unless the mode says receive.
        if let Err(e) = lora
            .prepare_for_rx(RxMode::Continuous, &modulation, &rx_params)
            .await
        {
            // Node-local (an SPI or radio-mode fault, not anything a peer
            // sends), so `warn!` — once per streak, not per retry.
            if rx_failures == 0 {
                warn!(?e, "radio: entering rx failed; retrying with backoff");
            }
            rx_failures = rx_failures.saturating_add(1);
            // Back off, but keep serving transmit while doing it: going
            // straight back to `prepare_for_rx` never reaches the `select`
            // below, and every `send` would wait on `TX_DONE` forever — the
            // whole driver loop with it.
            let backoff = Duration::from_millis(10 << rx_failures.min(6));
            if let Either::Second(packet) = select(Timer::after(backoff), TX_QUEUE.receive()).await
            {
                let sent = transmit(&mut lora, &modulation, &mut tx_params, &config, &packet).await;
                TX_DONE.signal(sent);
            }
            continue;
        }
        if rx_failures > 0 {
            debug!(rx_failures, "radio: entering rx recovered");
            rx_failures = 0;
        }

        // Bound to a `let` so the borrows of `lora` and `buf` end here, before
        // the match body needs `lora` again.
        let outcome = select(lora.rx(&rx_params, &mut buf), TX_QUEUE.receive()).await;

        match outcome {
            Either::First(Ok((len, status))) => {
                let len = len as usize;
                // A packet longer than the buffer cannot happen — the PHY
                // length field caps at the buffer's own size — but truncating
                // silently would corrupt a reassembly, so it is refused.
                let Some(bytes) = buf.get(..len).and_then(|b| Packet::from_slice(b).ok()) else {
                    trace!(len, "drop: received packet longer than the phy allows");
                    continue;
                };
                let metrics = LinkMetrics {
                    rssi_dbm: Some(status.rssi),
                    snr_db: Some(status.snr as i8),
                    // Left `None` deliberately: the engine derives the score.
                    // A hand-rolled LQI would be committing to a 0..=255 scale
                    // with no datasheet mapping behind it.
                    quality: None,
                };
                // Full queue drops the *newest*, which is the right end: the
                // frames already queued are closer to completing a reassembly.
                if RX_QUEUE.try_send(RxPacket { bytes, metrics }).is_err() {
                    trace!("drop: rx queue full");
                }
            }
            // Reachable from the air (a corrupt CRC, a truncated packet), so
            // `trace!` and never `warn!`.
            Either::First(Err(e)) => trace!(?e, "drop: radio receive error"),
            Either::Second(packet) => {
                let sent = transmit(&mut lora, &modulation, &mut tx_params, &config, &packet).await;
                TX_DONE.signal(sent);
            }
        }
    }
}

/// Preamble length in symbols. Both ends must agree; 8 is the SX126x default
/// and what every other LoRa stack on this band uses.
const PREAMBLE_SYMBOLS: u16 = 8;

/// Put one packet on the air, reporting only whether it made it.
///
/// `LinkT` is deliberately fire-and-forget — no ACK, no retry, no CCA in the
/// trait — so there is nothing more to report and nothing to retry here.
async fn transmit(
    lora: &mut BoardLoRa,
    modulation: &lora_phy::mod_params::ModulationParams,
    tx_params: &mut lora_phy::mod_params::PacketParams,
    config: &RadioConfig,
    packet: &[u8],
) -> bool {
    if let Err(e) = lora
        .prepare_for_tx(modulation, tx_params, config.output_power, packet)
        .await
    {
        trace!(?e, "drop: preparing transmit failed");
        return false;
    }
    match lora.tx().await {
        Ok(()) => true,
        Err(e) => {
            trace!(?e, "drop: transmit failed");
            false
        }
    }
}

/// Give up on the radio without taking the node down with it.
///
/// **Parked still serves the transmit queue**, failing every packet at once.
/// [`LoraLink::send`] hands each fragment to this task and awaits a verdict,
/// so a task that simply stopped would hold that `send` — and with it the
/// whole driver loop, since the driver awaits `send` outside its `select` —
/// forever. `recv` just stays pending, which is correct for a dead link.
///
/// On this board (one interface, no management port) that leaves a node that
/// is deaf and mute on the mesh while its timers and tables keep running; the
/// `error!` at each call site is the record of why. A board with another link
/// or a management port keeps both.
async fn park() -> ! {
    loop {
        let _ = TX_QUEUE.receive().await;
        TX_DONE.signal(false);
    }
}

/// The mesh interface over this board's radio.
///
/// Holds only the framing state — the radio itself belongs to
/// [`radio_task`].
pub struct LoraLink {
    /// This mesh's discriminator, checked on every received packet.
    net_id: u8,
    /// This node's 16-bit short identity, stamped into every fragment.
    src_id: u16,
    /// Per-frame message id, incremented once per `send` and allowed to wrap.
    msg_id: u8,
    reassembler: lora_link::LoraReassembler,
    /// Where a completed frame is assembled, and what [`Received::frame`]
    /// borrows until the next `recv`.
    frame: [u8; lora_link::MAX_REASSEMBLED_LEN],
}

impl LoraLink {
    /// Build the link. `src_id` is `lora_link::short_address_of` the node's
    /// `Mac`, and **must differ between physical nodes**, or their fragments
    /// spoil each other's reassembly.
    pub fn new(net_id: u8, src_id: u16) -> Self {
        Self {
            net_id,
            src_id,
            msg_id: 0,
            reassembler: lora_link::LoraReassembler::new(),
            frame: [0u8; lora_link::MAX_REASSEMBLED_LEN],
        }
    }
}

impl LinkT for LoraLink {
    /// A broadcast medium: every `send` reaches every neighbor, whatever
    /// `data.dst` says. See [`wayfinder::link::FanOut::broadcast`].
    fn fan_out(&self) -> Option<wayfinder::link::FanOut> {
        Some(wayfinder::link::FanOut::broadcast(
            lora_link::MAX_REASSEMBLED_LEN,
        ))
    }

    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        let mut frame = [0u8; lora_link::MAX_REASSEMBLED_LEN];
        let frame_len = lora_link::assemble_frame(origin, data, &mut frame)?;
        let count = lora_link::fragment_count(frame_len)?;

        let msg_id = self.msg_id;
        self.msg_id = self.msg_id.wrapping_add(1);

        for index in 0..count {
            let mut out = [0u8; lora_link::MAX_FRAME_LEN];
            let n = lora_link::build_fragment(
                self.net_id,
                self.src_id,
                &frame[..frame_len],
                lora_link::FragmentSpec {
                    msg_id,
                    index,
                    count,
                },
                &mut out,
            )?;
            let packet = Packet::from_slice(&out[..n]).map_err(|_| LinkError::BufferFull)?;

            // Cleared before queueing, so the verdict awaited below can only
            // be this fragment's. Depth-1 queue plus that wait means `send`
            // never blocks on a previous fragment of our own.
            TX_DONE.reset();
            TX_QUEUE.send(packet).await;
            if !TX_DONE.wait().await {
                // **Abandon the whole frame.** A receiver cannot complete a
                // reassembly that is missing a fragment, so the remaining
                // airtime would be spent for nothing.
                trace!(
                    index,
                    count, "drop: abandoning frame after a failed fragment"
                );
                return Err(LinkError::TransmitFailed);
            }
        }
        Ok(frame_len)
    }

    async fn recv<'a>(&'a mut self) -> Result<Received<'a>, LinkError> {
        // **Loop.** A lone fragment buffers and the loop continues; only a
        // completed frame returns. The driver's receive arm expects a whole
        // frame or nothing, never a short one.
        loop {
            let packet = RX_QUEUE.receive().await;
            if let Some((len, metrics)) = lora_link::accept_fragment(
                &mut self.reassembler,
                self.net_id,
                &packet.bytes,
                packet.metrics,
                &mut self.frame,
            ) {
                let frame = lora_link::decode_frame(&self.frame[..len])?;
                return Ok(Received { frame, metrics });
            }
        }
    }
}
