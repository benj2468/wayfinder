//! The `LinkT` half of a raw-LoRa adapter: framing over a pair of channels to
//! a radio-owning task.
//!
//! `wayfinder_embedded_driver` races every link's `recv` against the OGM timer
//! and drops the loser, so a `recv` that awaited the radio directly would lose
//! the frame in flight on every timer tick (this crate's `CLAUDE.md`). The
//! shape that survives it is a never-cancelled task owning the radio, with
//! `recv` awaiting only a channel — and that half has no chip in it, so it
//! lives here where its cancel-safety is a host test rather than a claim.
//!
//! The board supplies the statics ([`RadioPort`]) and the task that serves
//! them; `bins/wayfinder-wl55jc/src/radio.rs` is the reference.

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use interfaces::frame::LinkFrameData;
use interfaces::frame::Mac;
use interfaces::link::LinkError;
use interfaces::link::LinkMetrics;
use tracing::trace;
use wayfinder::link::LinkT;
use wayfinder::link::Received;

use crate::LoraReassembler;
use crate::MAX_FRAME_LEN;
use crate::MAX_REASSEMBLED_LEN;

/// One on-air packet, owned so it can cross a channel. Sized to the PHY's own
/// ceiling, which is also exactly one full fragment.
pub type Packet = heapless::Vec<u8, MAX_FRAME_LEN>;

/// A received packet with the physical-layer measurements for it.
pub struct RxPacket {
    /// The packet as the radio delivered it.
    pub bytes: Packet,
    /// RSSI/SNR for this packet, `quality` left `None` (see `CLAUDE.md`).
    pub metrics: LinkMetrics,
}

/// The channels between a [`ChannelLink`] and the task that owns the radio.
///
/// `RX` is the receive queue's depth. Transmit is depth one on purpose:
/// `send` hands over a fragment and waits for its verdict on `tx_done`, so a
/// second can never be outstanding.
pub struct RadioPort<'a, M: RawMutex, const RX: usize> {
    /// Packets the radio task received and `recv` has not yet collected.
    pub rx: &'a Channel<M, RxPacket, RX>,
    /// The fragment waiting to go out.
    pub tx: &'a Channel<M, Packet, 1>,
    /// Whether the fragment `tx` last carried made it onto the air.
    pub tx_done: &'a Signal<M, bool>,
}

/// A mesh interface over a radio owned by another task.
pub struct ChannelLink<'a, M: RawMutex, const RX: usize> {
    port: RadioPort<'a, M, RX>,
    /// This mesh's discriminator, checked on every received packet.
    net_id: u8,
    /// This node's 16-bit short identity, stamped into every fragment.
    src_id: u16,
    /// Per-frame message id, incremented once per `send` and allowed to wrap.
    msg_id: u8,
    reassembler: LoraReassembler,
    /// Where a completed frame is assembled, and what [`Received::frame`]
    /// borrows until the next `recv`.
    frame: [u8; MAX_REASSEMBLED_LEN],
}

impl<'a, M: RawMutex, const RX: usize> ChannelLink<'a, M, RX> {
    /// Build the link. `src_id` is [`crate::short_address_of`] the node's
    /// `Mac`, and **must differ between physical nodes**, or their fragments
    /// spoil each other's reassembly.
    pub fn new(port: RadioPort<'a, M, RX>, net_id: u8, src_id: u16) -> Self {
        Self {
            port,
            net_id,
            src_id,
            msg_id: 0,
            reassembler: LoraReassembler::new(),
            frame: [0u8; MAX_REASSEMBLED_LEN],
        }
    }
}

impl<M: RawMutex + Sync, const RX: usize> LinkT for ChannelLink<'_, M, RX> {
    async fn send(&mut self, origin: Mac, data: &LinkFrameData<'_>) -> Result<usize, LinkError> {
        let mut frame = [0u8; MAX_REASSEMBLED_LEN];
        let frame_len = crate::assemble_frame(origin, data, &mut frame)?;
        let count = crate::fragment_count(frame_len)?;

        let msg_id = self.msg_id;
        self.msg_id = self.msg_id.wrapping_add(1);

        for index in 0..count {
            let mut out = [0u8; MAX_FRAME_LEN];
            let n = crate::build_fragment(
                self.net_id,
                self.src_id,
                &frame[..frame_len],
                crate::FragmentSpec {
                    msg_id,
                    index,
                    count,
                },
                &mut out,
            )?;
            let packet = Packet::from_slice(&out[..n]).map_err(|_| LinkError::BufferFull)?;

            // Cleared before queueing, so the verdict awaited below can only
            // be this fragment's. The depth-1 queue plus that wait means `send`
            // never blocks on a previous fragment of its own.
            self.port.tx_done.reset();
            self.port.tx.send(packet).await;
            if !self.port.tx_done.wait().await {
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

    async fn recv<'b>(&'b mut self) -> Result<Received<'b>, LinkError> {
        // **Loop.** A lone fragment buffers and the loop continues; only a
        // completed frame returns. The driver's receive arm expects a whole
        // frame or nothing, never a short one.
        //
        // And the only `.await` is the channel. Everything a half-received
        // frame needs lives in `self.reassembler`, not in this future, which
        // is what lets the driver drop this future at any await point and
        // lose nothing (`a_recv_dropped_mid_frame_loses_nothing`).
        loop {
            let packet = self.port.rx.receive().await;
            if let Some((len, metrics)) = crate::accept_fragment(
                &mut self.reassembler,
                self.net_id,
                &packet.bytes,
                packet.metrics,
                &mut self.frame,
            ) {
                let frame = crate::decode_frame(&self.frame[..len])?;
                return Ok(Received { frame, metrics });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use core::pin::pin;
    use core::task::Poll;

    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use interfaces::frame::LinkFrameData;
    use interfaces::frame::Mac;

    use super::*;
    use crate::FragmentSpec;

    const NET: u8 = 18;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    /// The air-side fragments a peer `from` sends for one frame to `to`.
    fn fragments_of(from: Mac, to: Mac, payload: &[u8]) -> std::vec::Vec<Packet> {
        let data = LinkFrameData {
            dst: to,
            protocol: 0x4305,
            payload,
        };
        let mut frame = [0u8; MAX_REASSEMBLED_LEN];
        let len = crate::assemble_frame(from, &data, &mut frame).unwrap();
        let count = crate::fragment_count(len).unwrap();
        (0..count)
            .map(|index| {
                let mut out = [0u8; MAX_FRAME_LEN];
                let n = crate::build_fragment(
                    NET,
                    crate::short_address_of(from),
                    &frame[..len],
                    FragmentSpec {
                        msg_id: 7,
                        index,
                        count,
                    },
                    &mut out,
                )
                .unwrap();
                Packet::from_slice(&out[..n]).unwrap()
            })
            .collect()
    }

    fn rx(bytes: Packet) -> RxPacket {
        RxPacket {
            bytes,
            metrics: LinkMetrics {
                rssi_dbm: Some(-80),
                snr_db: Some(5),
                quality: None,
            },
        }
    }

    /// **Design 25 test 9.** The driver drops a `recv` that loses its race —
    /// on every OGM tick — so one dropped mid-frame, after it has taken the
    /// first fragment off the queue, must not lose that fragment: the next
    /// `recv` completes the frame from where the dropped one left off. This is
    /// the property that, broken, reads as poor RF rather than as a bug.
    #[test]
    fn a_recv_dropped_mid_frame_loses_nothing() {
        let rx_q: Channel<CriticalSectionRawMutex, RxPacket, 4> = Channel::new();
        let tx_q: Channel<CriticalSectionRawMutex, Packet, 1> = Channel::new();
        let done: Signal<CriticalSectionRawMutex, bool> = Signal::new();
        let mut link = ChannelLink::new(
            RadioPort {
                rx: &rx_q,
                tx: &tx_q,
                tx_done: &done,
            },
            NET,
            crate::short_address_of(mac(1)),
        );

        let payload = [0xA5u8; 300]; // two fragments
        let mut frags = fragments_of(mac(2), mac(1), &payload).into_iter();
        let first = frags.next().unwrap();
        let second = frags.next().unwrap();
        assert!(frags.next().is_none());

        rx_q.try_send(rx(first)).ok().unwrap();
        {
            let fut = pin!(link.recv());
            // Takes the first fragment, then waits for the second.
            assert!(matches!(embassy_futures::poll_once(fut), Poll::Pending));
        } // ...and is dropped there, as a lost race would drop it.
        assert!(
            rx_q.is_empty(),
            "the dropped recv consumed the first fragment"
        );

        rx_q.try_send(rx(second)).ok().unwrap();
        // One poll, not `block_on`: with the second fragment queued a correct
        // `recv` completes immediately, and one that lost the first fragment
        // with the dropped future would otherwise wait forever, a hang rather
        // than a failure.
        let fut = pin!(link.recv());
        let Poll::Ready(received) = embassy_futures::poll_once(fut) else {
            panic!("the first fragment was lost with the dropped recv");
        };
        let received = received.unwrap();
        assert_eq!(received.frame.src, mac(2));
        assert_eq!(&received.frame.payload, &payload[..]);
    }

    /// A frame-sized `send` hands its fragments to the radio task one at a
    /// time, each after the previous one's verdict, and they reassemble at a
    /// peer into the frame that was sent.
    #[test]
    fn send_queues_every_fragment_and_reports_the_frame() {
        let rx_q: Channel<CriticalSectionRawMutex, RxPacket, 4> = Channel::new();
        let tx_q: Channel<CriticalSectionRawMutex, Packet, 1> = Channel::new();
        let done: Signal<CriticalSectionRawMutex, bool> = Signal::new();
        let mut link = ChannelLink::new(
            RadioPort {
                rx: &rx_q,
                tx: &tx_q,
                tx_done: &done,
            },
            NET,
            crate::short_address_of(mac(1)),
        );
        let payload = [0x3Cu8; 300];
        let data = LinkFrameData {
            dst: mac(2),
            protocol: 0x4305,
            payload: &payload,
        };

        // The fake radio acknowledges every fragment for as long as `send`
        // runs; `select` ends it when `send` returns, so a `send` that stops
        // early fails the assertions below rather than hanging the test.
        let sent = core::cell::RefCell::new(std::vec::Vec::new());
        let radio = async {
            loop {
                let packet = tx_q.receive().await;
                sent.borrow_mut().push(packet);
                done.signal(true);
            }
        };
        let result = match futures::executor::block_on(futures::future::select(
            pin!(link.send(mac(1), &data)),
            pin!(radio),
        )) {
            futures::future::Either::Left((result, _)) => result,
            futures::future::Either::Right(((), _)) => unreachable!(),
        };
        assert!(result.unwrap() > payload.len());
        let sent = sent.into_inner();
        assert_eq!(sent.len(), 2);

        let mut peer = LoraReassembler::new();
        let mut frame = [0u8; MAX_REASSEMBLED_LEN];
        let mut done_len = None;
        for packet in &sent {
            done_len =
                crate::accept_fragment(&mut peer, NET, packet, LinkMetrics::default(), &mut frame)
                    .map(|(len, _)| len);
        }
        let decoded = crate::decode_frame(&frame[..done_len.unwrap()]).unwrap();
        assert_eq!(&decoded.payload, &payload[..]);
    }

    /// A failed fragment abandons the frame: a receiver cannot complete a
    /// reassembly missing one, so the rest would be airtime spent for nothing.
    #[test]
    fn a_failed_fragment_abandons_the_rest_of_the_frame() {
        let rx_q: Channel<CriticalSectionRawMutex, RxPacket, 4> = Channel::new();
        let tx_q: Channel<CriticalSectionRawMutex, Packet, 1> = Channel::new();
        let done: Signal<CriticalSectionRawMutex, bool> = Signal::new();
        let mut link = ChannelLink::new(
            RadioPort {
                rx: &rx_q,
                tx: &tx_q,
                tx_done: &done,
            },
            NET,
            crate::short_address_of(mac(1)),
        );
        let payload = [0x3Cu8; 300];
        let data = LinkFrameData {
            dst: mac(2),
            protocol: 0x4305,
            payload: &payload,
        };

        // Fails the first fragment, then keeps listening so a `send` that
        // queued a second would be caught by the emptiness check below.
        let radio = async {
            let _ = tx_q.receive().await;
            done.signal(false);
            core::future::pending::<()>().await
        };
        let result = match futures::executor::block_on(futures::future::select(
            pin!(link.send(mac(1), &data)),
            pin!(radio),
        )) {
            futures::future::Either::Left((result, _)) => result,
            futures::future::Either::Right(((), _)) => unreachable!(),
        };
        assert!(matches!(result, Err(LinkError::TransmitFailed)));
        assert!(tx_q.is_empty(), "no second fragment after the first failed");
    }
}
