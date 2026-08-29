//! Reachability probing — the mesh's `ping`.
//!
//! A [`PingSession`] is what a node is doing when an operator asks it to ping a
//! peer: emit probes at a fixed cadence, match the replies that come back,
//! give up on the ones that don't, and keep the statistics `ping(8)` prints.
//!
//! # Why the node owns this and not the client
//!
//! The obvious alternative is for `wayfinderctl` to drive the whole thing —
//! one management request per probe, all arithmetic host-side. It was rejected
//! because a probe's round trip is measured against *the node's* clock, on the
//! node's own timer, and interposing a management round trip between "send" and
//! "the clock reading that dates it" measures the management link as much as the
//! mesh. Keeping the session here also means an nRF52840 pings exactly the way a
//! Linux gateway does, over the same code.
//!
//! The client holds a *handle* instead: [`PingSession::session_seq`], issued
//! when the session starts and presented on every status read. A node runs one
//! session at a time and a new one replaces it, so without that handle a client
//! whose session had been displaced would silently report somebody else's
//! numbers.
//!
//! # Bounded by construction
//!
//! Everything here is fixed-size, because it lands in
//! [`CentralRouter`](crate::CentralRouter) on every target. The ring holds the
//! last [`MAX_PING_PROBES`] probe *rows* for display; the statistics are folded
//! as each probe resolves, so loss and min/avg/max/mdev stay exact however many
//! probes a session runs — the ring going round does not cost accuracy, only
//! detail.

use core::time::Duration;

use interfaces::frame::Mac;

/// How many recent probe rows a session keeps for display.
///
/// Detail only: the aggregates below are folded as probes resolve, so a session
/// of 500 probes still reports exact loss and RTT statistics from a ring of
/// this size. Sized so a terminal pane's worth of history survives.
pub const MAX_PING_PROBES: usize = 16;

/// Largest pad payload a probe may carry, in bytes.
///
/// A probe's pad exists so an operator can size one against a link's MTU. The
/// cap is what keeps that from becoming a way to ask a node to emit something
/// its own transmit buffer cannot hold, and is well under the smallest mesh
/// MTU this stack runs over.
pub const MAX_PING_PAYLOAD: u16 = 64;

/// Largest number of probes one session may be asked for.
///
/// A bound rather than a policy: a session is an operator's diagnostic, and one
/// that ran unbounded would keep a node emitting long after whoever started it
/// had gone.
pub const MAX_PING_COUNT: u16 = 1000;

/// Probes a session sends when the caller does not say (mirrors `ping -c`'s
/// usual short run).
pub const DEFAULT_PING_COUNT: u16 = 5;

/// Cadence between probes when the caller does not say — `ping(8)`'s one
/// second.
pub const DEFAULT_PING_INTERVAL: Duration = Duration::from_secs(1);

/// How long a probe waits for its reply before it counts as lost, when the
/// caller does not say.
///
/// Generous against `ping(8)`'s convention because the paths underneath can be:
/// a multi-hop LoRa route's round trip is measured in seconds, not
/// milliseconds, and a timeout tuned for Ethernet would report a working mesh
/// as totally lossy.
pub const DEFAULT_PING_TIMEOUT: Duration = Duration::from_secs(5);

/// Pad bytes a probe carries when the caller does not say.
pub const DEFAULT_PING_PAYLOAD: u16 = 16;

/// Longest a probe may be asked to wait for its reply, and the longest cadence
/// a session may be asked to keep.
///
/// Not a taste judgement about how patient a diagnostic should be — it is what
/// keeps two pieces of arithmetic here honest. [`ProbeRecord::sent_at_us`] is
/// read through `wrapping_sub`, which is exact only for elapsed intervals under
/// ~71.6 minutes, and [`PingSession`]'s squared-round-trip accumulator is sized
/// against round trips bounded by *this* value; an unbounded caller-chosen
/// timeout would saturate `rtt_us` and make the deviation garbage after two
/// samples. Ten minutes is far past any real mesh round trip and comfortably
/// short of both hazards.
pub const MAX_PING_INTERVAL: Duration = Duration::from_secs(600);

/// Shortest cadence and timeout a session may be asked for.
///
/// A floor for the same reason `MIN_KEEPALIVE_INTERVAL` has one: a degenerate
/// value is far more often a typo than an intention, and both directions do
/// real damage here. `-i 1` from an operator whose fingers remember `ping(8)`'s
/// *seconds* is a thousandfold cadence amplification, which walks straight
/// around the airtime bound [`MAX_PING_COUNT`] exists to impose. `-W 5` from
/// the same reflex expires every probe before any reply can physically arrive,
/// reporting a healthy path as totally lossy with nothing to say why.
pub const MIN_PING_INTERVAL: Duration = Duration::from_millis(50);

/// The settings a session runs under, after the router has applied its defaults
/// and caps.
///
/// Bundled rather than passed loose because they travel together everywhere —
/// out of the management request, through the clamping, into the session, and
/// back out to the caller as "what you actually got".
#[derive(Debug, Clone, Copy)]
pub struct PingConfig {
    /// How many probes to send.
    pub count: u16,
    /// Cadence between probes.
    pub interval: Duration,
    /// How long a probe waits before counting as lost.
    pub timeout: Duration,
    /// Pad bytes each probe carries.
    pub payload_len: u16,
}

/// What became of one probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeState {
    /// Sent, still waiting for its reply, not yet past its timeout.
    Pending,
    /// Answered. [`ProbeRecord::rtt_us`] and both hop counts are meaningful.
    Replied,
    /// Sent, and its timeout passed with no reply. Counts as loss.
    TimedOut,
    /// Never sent: at the moment it fell due this node had no live route to the
    /// target. Counts as loss, and is reported apart from
    /// [`ProbeState::TimedOut`] because the two mean different things to an
    /// operator — "I could not even try" against "I tried and heard nothing".
    NoRoute,
}

/// One probe's row: what was sent, and what came back.
#[derive(Debug, Clone, Copy)]
pub struct ProbeRecord {
    /// This probe's sequence number within its session, echoed on the wire.
    pub seqno: u16,
    /// When it was sent, in **microseconds** of the router's monotonic clock,
    /// truncated to 32 bits.
    ///
    /// Microseconds, not milliseconds, because the round trip derived from this
    /// is reported in microseconds and a millisecond clock cannot produce one:
    /// every RTT on a UDP or VPN mesh — where sub-millisecond really happens —
    /// would read as a flat zero, which the summary would then print as a
    /// measurement.
    ///
    /// Truncated deliberately, and read back only through `wrapping_sub`, which
    /// makes it exact for any elapsed interval under ~71.6 minutes. That is not
    /// a comfortable margin, it is a *bound*: [`MAX_PING_INTERVAL`] caps a
    /// probe's timeout below it, which is what makes the wrap unreachable. The
    /// two constants have to move together.
    pub sent_at_us: u32,
    /// Round-trip time in microseconds. Meaningful only when
    /// [`state`](Self::state) is [`ProbeState::Replied`].
    pub rtt_us: u32,
    /// Relays the request crossed on the way out. Meaningful only when replied.
    pub fwd_hops: u8,
    /// Relays the reply crossed on the way back. Meaningful only when replied,
    /// and not necessarily equal to [`fwd_hops`](Self::fwd_hops) — mesh paths
    /// are routinely asymmetric, which is exactly why both are reported.
    pub rev_hops: u8,
    /// What became of this probe.
    pub state: ProbeState,
}

/// A node's single in-flight ping session.
///
/// See the [module docs](self) for why this lives on the node. Construct one
/// through [`CentralRouter::start_ping`](crate::CentralRouter::start_ping)
/// rather than directly; the router owns issuing session handles.
#[derive(Debug)]
pub struct PingSession {
    /// The handle a client presents to read this session's status.
    session_seq: u32,
    /// The node being pinged.
    target: Mac,
    /// How many probes were asked for.
    requested: u16,
    /// Cadence between probes.
    interval: Duration,
    /// How long a probe waits before counting as lost.
    timeout: Duration,
    /// Pad bytes each probe carries.
    payload_len: u16,
    /// The sequence number this session's first probe carried.
    ///
    /// Sessions do **not** restart numbering at zero, and that is load-bearing
    /// rather than tidy. A reply names only `(orig, seqno)` — nothing says
    /// which session sent it — so an operator who restarts a ping against the
    /// same host before the old session's probes have timed out would have
    /// stale replies credited to the new session's identically-numbered
    /// probes, stamping a round trip measured from the wrong send. The router
    /// hands each session a fresh block instead; see
    /// [`CentralRouter::start_ping`](crate::CentralRouter::start_ping).
    first_seqno: u16,
    /// How many probes this session has emitted. The next one carries
    /// `first_seqno + emitted`.
    emitted: u16,
    /// When the next probe falls due.
    next_due: Duration,
    /// Probes emitted (or refused for want of a route), over the whole session.
    sent: u32,
    /// Probes answered, over the whole session.
    received: u32,
    /// Probes that timed out or had no route, over the whole session.
    lost: u32,
    /// Smallest round trip seen, in microseconds; `u32::MAX` while none.
    rtt_min_us: u32,
    /// Largest round trip seen, in microseconds.
    rtt_max_us: u32,
    /// Sum of round trips, for the mean.
    rtt_sum_us: u64,
    /// Sum of squared round trips, for the deviation. `u64` is ample *because*
    /// a round trip is bounded by [`MAX_PING_INTERVAL`]: at most 3.6e9 µs,
    /// squared is ~1.3e19 per sample — so the bound is what keeps
    /// `MAX_PING_COUNT` samples from overflowing, not a comfortable margin.
    /// Remove the clamp in `start_ping` and this comment becomes false.
    rtt_sum_sq_us: u64,
    /// The recent probe rows, oldest first.
    probes: heapless::Deque<ProbeRecord, MAX_PING_PROBES>,
}

/// Microseconds of the router's monotonic clock, truncated to 32 bits.
///
/// See [`ProbeRecord::sent_at_us`] for why truncating is safe here, and why the
/// unit is microseconds.
fn us(now: Duration) -> u32 {
    now.as_micros() as u32
}

impl PingSession {
    /// Start a session pinging `target`, due to emit its first probe
    /// immediately.
    ///
    /// `config` is taken as given — defaulting and clamping are the router's
    /// job, at the point it turns a management request into a session, so this
    /// type has one caller and one set of rules rather than two.
    pub(crate) fn new(
        session_seq: u32,
        target: Mac,
        config: PingConfig,
        first_seqno: u16,
        now: Duration,
    ) -> Self {
        Self {
            session_seq,
            target,
            requested: config.count,
            interval: config.interval,
            timeout: config.timeout,
            payload_len: config.payload_len,
            first_seqno,
            emitted: 0,
            next_due: now,
            sent: 0,
            received: 0,
            lost: 0,
            rtt_min_us: u32::MAX,
            rtt_max_us: 0,
            rtt_sum_us: 0,
            rtt_sum_sq_us: 0,
            probes: heapless::Deque::new(),
        }
    }

    /// The handle a client presents to read this session. Never zero — zero is
    /// how "no session" is spelled on the wire.
    pub fn session_seq(&self) -> u32 {
        self.session_seq
    }

    /// The node being pinged.
    pub fn target(&self) -> Mac {
        self.target
    }

    /// How many probes this session was asked for.
    pub fn requested(&self) -> u16 {
        self.requested
    }

    /// Cadence between probes.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// How long a probe waits before counting as lost.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Pad bytes each probe carries — what was actually put on the wire, which
    /// is not always what was asked for. See
    /// [`note_payload_emitted`](Self::note_payload_emitted).
    pub fn payload_len(&self) -> u16 {
        self.payload_len
    }

    /// Record the pad size actually emitted, when the router had to shrink the
    /// requested one to fit its transmit buffer.
    ///
    /// The whole stated purpose of the pad is sizing a probe against a link's
    /// MTU, so a session that reported the size it *asked for* while sending a
    /// smaller one would invert its own purpose — an operator would conclude 64
    /// bytes traverse a path that in fact carried 40.
    pub(crate) fn note_payload_emitted(&mut self, len: u16) {
        self.payload_len = len;
    }

    /// Probes emitted so far, including ones refused for want of a route.
    pub fn sent(&self) -> u32 {
        self.sent
    }

    /// Probes answered so far.
    pub fn received(&self) -> u32 {
        self.received
    }

    /// Probes that timed out or had no route.
    pub fn lost(&self) -> u32 {
        self.lost
    }

    /// Smallest round trip seen, in microseconds, or `None` if nothing has been
    /// answered yet.
    pub fn rtt_min_us(&self) -> Option<u32> {
        (self.received > 0).then_some(self.rtt_min_us)
    }

    /// Largest round trip seen, in microseconds, or `None` if nothing has been
    /// answered yet.
    pub fn rtt_max_us(&self) -> Option<u32> {
        (self.received > 0).then_some(self.rtt_max_us)
    }

    /// Mean round trip, in microseconds, or `None` if nothing has been answered
    /// yet.
    pub fn rtt_avg_us(&self) -> Option<u32> {
        (self.received > 0).then(|| (self.rtt_sum_us / u64::from(self.received)) as u32)
    }

    /// Standard deviation of the round trips, in microseconds — `ping(8)`'s
    /// `mdev` — or `None` if nothing has been answered yet.
    ///
    /// Computed from the running sums rather than from the ring, so it covers
    /// the whole session and not just the rows still on display. The
    /// `saturating_sub` guards the one way `E[x²] - E[x]²` can go negative
    /// here: integer division rounds each mean down independently, which for a
    /// set of near-identical round trips can leave the squared mean the larger
    /// of the two.
    pub fn rtt_mdev_us(&self) -> Option<u32> {
        if self.received == 0 {
            return None;
        }
        let n = u64::from(self.received);
        let mean = self.rtt_sum_us / n;
        let mean_sq = self.rtt_sum_sq_us / n;
        Some(mean_sq.saturating_sub(mean * mean).isqrt() as u32)
    }

    /// The recent probe rows, oldest first.
    pub fn probes(&self) -> impl Iterator<Item = &ProbeRecord> {
        self.probes.iter()
    }

    /// Whether this session still has work to do: probes left to send, or
    /// probes still outstanding. A client polls until this goes false.
    pub fn active(&self) -> bool {
        self.emitted < self.requested
            || self
                .probes
                .iter()
                .any(|p| matches!(p.state, ProbeState::Pending))
    }

    /// Whether a probe falls due at `now`.
    pub(crate) fn due(&self, now: Duration) -> bool {
        self.emitted < self.requested && now >= self.next_due
    }

    /// Time from `now` until this session next needs servicing — the next probe
    /// falling due, or the soonest outstanding probe's timeout, whichever comes
    /// first. `None` once the session is finished.
    ///
    /// A driver that sleeps must fold this into the same `min` as its OGM and
    /// keep-alive deadlines, or probes go out on whatever cadence the mesh's
    /// other traffic happens to wake the loop at — which on a settled mesh is
    /// minutes, and would make every probe time out.
    pub(crate) fn next_due_after(&self, now: Duration) -> Option<Duration> {
        let mut soonest = if self.emitted < self.requested {
            self.next_due.saturating_sub(now)
        } else {
            Duration::MAX
        };

        let now_us = us(now);
        let timeout_us = self.timeout.as_micros() as u32;
        for probe in &self.probes {
            if !matches!(probe.state, ProbeState::Pending) {
                continue;
            }
            let elapsed = now_us.wrapping_sub(probe.sent_at_us);
            let remaining = Duration::from_micros(u64::from(timeout_us.saturating_sub(elapsed)));
            soonest = soonest.min(remaining);
        }

        (soonest != Duration::MAX).then_some(soonest)
    }

    /// Mark the next probe as emitted at `now`, returning the sequence number it
    /// must carry on the wire.
    pub(crate) fn record_sent(&mut self, now: Duration) -> u16 {
        let seqno = self.first_seqno.wrapping_add(self.emitted);
        self.emitted = self.emitted.saturating_add(1);
        self.next_due = now + self.interval;
        self.sent = self.sent.saturating_add(1);
        self.push(ProbeRecord {
            seqno,
            sent_at_us: us(now),
            rtt_us: 0,
            fwd_hops: 0,
            rev_hops: 0,
            state: ProbeState::Pending,
        });
        seqno
    }

    /// Mark the next probe as unsendable at `now` — no live route to the target
    /// — which counts against the session as loss without anything reaching the
    /// air.
    pub(crate) fn record_no_route(&mut self, now: Duration) {
        let seqno = self.first_seqno.wrapping_add(self.emitted);
        self.emitted = self.emitted.saturating_add(1);
        self.next_due = now + self.interval;
        self.sent = self.sent.saturating_add(1);
        self.lost = self.lost.saturating_add(1);
        self.push(ProbeRecord {
            seqno,
            sent_at_us: us(now),
            rtt_us: 0,
            fwd_hops: 0,
            rev_hops: 0,
            state: ProbeState::NoRoute,
        });
    }

    /// Credit a reply against the probe it answers, returning whether one
    /// matched.
    ///
    /// `false` for a reply from the wrong peer, for a sequence number this
    /// session never sent, or for one already resolved — a duplicate or a
    /// straggler arriving after its timeout. A straggler is deliberately *not*
    /// resurrected: it was already counted as loss, and crediting it now would
    /// leave `sent`, `received` and `lost` disagreeing with each other.
    pub(crate) fn record_reply(
        &mut self,
        now: Duration,
        peer: Mac,
        seqno: u16,
        fwd_hops: u8,
        rev_hops: u8,
    ) -> bool {
        if peer != self.target {
            return false;
        }
        let now_us = us(now);
        let Some(probe) = self
            .probes
            .iter_mut()
            .find(|p| p.seqno == seqno && matches!(p.state, ProbeState::Pending))
        else {
            return false;
        };

        let rtt_us = now_us.wrapping_sub(probe.sent_at_us);
        probe.rtt_us = rtt_us;
        probe.fwd_hops = fwd_hops;
        probe.rev_hops = rev_hops;
        probe.state = ProbeState::Replied;

        self.received = self.received.saturating_add(1);
        self.rtt_min_us = self.rtt_min_us.min(rtt_us);
        self.rtt_max_us = self.rtt_max_us.max(rtt_us);
        self.rtt_sum_us = self.rtt_sum_us.saturating_add(u64::from(rtt_us));
        self.rtt_sum_sq_us = self
            .rtt_sum_sq_us
            .saturating_add(u64::from(rtt_us) * u64::from(rtt_us));
        true
    }

    /// Fold every outstanding probe whose timeout has passed into the loss
    /// count. Idempotent, so a driver may call it on every poll.
    pub(crate) fn expire(&mut self, now: Duration) {
        let now_us = us(now);
        let timeout_us = self.timeout.as_micros() as u32;
        let mut newly_lost = 0u32;
        for probe in self.probes.iter_mut() {
            if !matches!(probe.state, ProbeState::Pending) {
                continue;
            }
            if now_us.wrapping_sub(probe.sent_at_us) >= timeout_us {
                probe.state = ProbeState::TimedOut;
                newly_lost += 1;
            }
        }
        self.lost = self.lost.saturating_add(newly_lost);
    }

    /// Stop this session where it stands, keeping everything it measured.
    ///
    /// The statistics are deliberately preserved rather than discarded, exactly
    /// as `ping(8)` prints its summary on Ctrl+C: the probes that completed are
    /// the answer the operator was waiting for, and the airtime they cost has
    /// already been spent.
    ///
    /// Two things have to happen together, and missing either leaves the
    /// session undead — still `active`, still polled, still reporting a
    /// deadline a driver will wake on. Nothing further may fall due, which is
    /// what pulling `requested` down to what was actually emitted achieves; and
    /// no probe may be left `Pending`, since a row nothing can ever resolve
    /// would keep `active` true on its own. In-flight probes become loss, which
    /// is also the honest reading — the operator stopped waiting for them.
    ///
    /// Idempotent, so a client retrying a cancel it did not see acknowledged
    /// cannot double-count the losses it already recorded.
    ///
    /// Takes no `now`: unlike [`expire`](Self::expire) this resolves every
    /// outstanding probe regardless of how long it has been waiting, so there
    /// is no deadline to compare against.
    pub(crate) fn cancel(&mut self) {
        self.requested = self.emitted;
        // Ageing everything outstanding, rather than only what has timed out.
        let mut newly_lost = 0u32;
        for probe in self.probes.iter_mut() {
            if matches!(probe.state, ProbeState::Pending) {
                probe.state = ProbeState::TimedOut;
                newly_lost += 1;
            }
        }
        self.lost = self.lost.saturating_add(newly_lost);
    }

    /// Push a row, evicting the oldest when the ring is full.
    ///
    /// An evicted row that was still `Pending` is counted as lost on its way
    /// out: nothing can credit it once its row is gone, so leaving it
    /// uncounted would let `sent` exceed `received + lost` forever.
    fn push(&mut self, record: ProbeRecord) {
        if self.probes.is_full()
            && let Some(evicted) = self.probes.pop_front()
            && matches!(evicted.state, ProbeState::Pending)
        {
            self.lost = self.lost.saturating_add(1);
        }
        // Cannot fail: the ring was just made room in if it was full.
        let _ = self.probes.push_back(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compact `u8` → `Mac`, matching the router/engine test convention.
    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// A session with a 1 s cadence and a 5 s timeout, pinging node 9.
    fn session(count: u16) -> PingSession {
        PingSession::new(
            1,
            mac(9),
            PingConfig {
                count,
                interval: secs(1),
                timeout: secs(5),
                payload_len: 16,
            },
            0,
            Duration::ZERO,
        )
    }

    /// The invariant every other test leans on: every probe the session has
    /// started is accounted for exactly once, as answered, lost, or still in
    /// flight. If this can drift, every statistic derived from it is a lie.
    fn assert_invariants(s: &PingSession) {
        let pending = s
            .probes()
            .filter(|p| matches!(p.state, ProbeState::Pending))
            .count() as u32;
        assert_eq!(
            s.sent(),
            s.received() + s.lost() + pending,
            "sent must equal received + lost + still-outstanding"
        );
        assert!(
            u32::from(s.requested()) >= s.sent(),
            "sent past the request"
        );
        assert!(s.probes().count() <= MAX_PING_PROBES);
    }

    /// A fresh session is due immediately — an operator pressing "ping" should
    /// not wait out an interval first — and its statistics are empty rather
    /// than zero, since zero is a measurement and "nothing yet" is not.
    #[test]
    fn a_fresh_session_is_due_at_once_and_has_no_statistics() {
        let s = session(3);
        assert!(s.due(Duration::ZERO));
        assert!(s.active());
        assert_eq!(s.rtt_min_us(), None);
        assert_eq!(s.rtt_avg_us(), None);
        assert_eq!(s.rtt_max_us(), None);
        assert_eq!(s.rtt_mdev_us(), None);
        assert_invariants(&s);
    }

    /// Probes are paced at the interval, not emitted as fast as they are
    /// polled.
    #[test]
    fn probes_are_paced_at_the_interval() {
        let mut s = session(3);
        assert_eq!(s.record_sent(Duration::ZERO), 0);

        assert!(
            !s.due(Duration::from_millis(999)),
            "still inside the interval"
        );
        assert!(s.due(secs(1)), "due once the interval has elapsed");
        assert_eq!(s.record_sent(secs(1)), 1);
        assert_invariants(&s);
    }

    /// Pacing is measured from *now*, not from the last deadline. A driver that
    /// slept through several intervals — a quiet mesh, a busy board — must not
    /// wake to a burst of back-to-back probes, which would measure the burst
    /// rather than the path.
    #[test]
    fn a_long_gap_does_not_produce_a_catch_up_burst() {
        let mut s = session(10);
        s.record_sent(Duration::ZERO);

        s.record_sent(secs(30));
        assert!(!s.due(secs(30)), "the next probe is one interval from now");
        assert!(s.due(secs(31)));
        assert_invariants(&s);
    }

    /// A reply folds its round trip and *both* hop counts into the probe it
    /// answers.
    #[test]
    fn a_reply_is_credited_against_its_probe() {
        let mut s = session(2);
        let seqno = s.record_sent(Duration::ZERO);

        assert!(s.record_reply(Duration::from_millis(40), mac(9), seqno, 2, 3));

        let probe = s.probes().next().expect("one row");
        assert_eq!(probe.state, ProbeState::Replied);
        assert_eq!(probe.rtt_us, 40_000);
        assert_eq!(probe.fwd_hops, 2);
        assert_eq!(probe.rev_hops, 3, "an asymmetric path reports both legs");
        assert_eq!(s.received(), 1);
        assert_eq!(s.lost(), 0);
        assert_eq!(s.rtt_min_us(), Some(40_000));
        assert_eq!(s.rtt_avg_us(), Some(40_000));
        assert_eq!(s.rtt_max_us(), Some(40_000));
        assert_invariants(&s);
    }

    /// Three replies that are not equal produce the statistics `ping` prints.
    #[test]
    fn statistics_summarise_every_reply() {
        let mut s = session(3);
        for (i, rtt) in [10u64, 20, 60].into_iter().enumerate() {
            let at = secs(i as u64);
            let seqno = s.record_sent(at);
            assert!(s.record_reply(at + Duration::from_millis(rtt), mac(9), seqno, 1, 1));
        }

        assert_eq!(s.received(), 3);
        assert_eq!(s.rtt_min_us(), Some(10_000));
        assert_eq!(s.rtt_max_us(), Some(60_000));
        assert_eq!(s.rtt_avg_us(), Some(30_000));
        // sqrt(E[x²] − E[x]²) over {10, 20, 60} ms ≈ 21.6 ms.
        let mdev = s.rtt_mdev_us().expect("three samples");
        assert!(
            (21_000..22_000).contains(&mdev),
            "mdev {mdev} µs should be ≈21.6 ms"
        );
        assert!(!s.active(), "every probe sent and answered");
        assert_invariants(&s);
    }

    /// A reply nobody asked for changes nothing. Three ways to be unwanted, and
    /// each is a way an unmatched reply could otherwise corrupt a measurement.
    #[test]
    fn an_unmatched_reply_is_ignored() {
        let mut s = session(2);
        let seqno = s.record_sent(Duration::ZERO);

        assert!(
            !s.record_reply(secs(1), mac(8), seqno, 1, 1),
            "a reply from a node we are not pinging"
        );
        assert!(
            !s.record_reply(secs(1), mac(9), seqno + 5, 1, 1),
            "a sequence number this session never sent"
        );
        assert!(s.record_reply(secs(1), mac(9), seqno, 1, 1));
        assert!(
            !s.record_reply(secs(1), mac(9), seqno, 1, 1),
            "a duplicate of one already credited"
        );
        assert_eq!(s.received(), 1);
        assert_invariants(&s);
    }

    /// An outstanding probe past its timeout becomes loss, and stays loss: a
    /// straggler arriving afterwards must not be credited, or the counts would
    /// stop adding up.
    #[test]
    fn a_probe_past_its_timeout_is_lost_and_stays_lost() {
        let mut s = session(1);
        let seqno = s.record_sent(Duration::ZERO);

        s.expire(secs(4));
        assert_eq!(s.lost(), 0, "still inside the timeout");

        s.expire(secs(5));
        assert_eq!(s.lost(), 1);
        assert_eq!(
            s.probes().next().expect("one row").state,
            ProbeState::TimedOut
        );
        assert!(!s.active(), "nothing left to send or wait for");

        assert!(
            !s.record_reply(secs(6), mac(9), seqno, 1, 1),
            "a straggler must not un-lose an already-counted probe"
        );
        assert_eq!(s.received(), 0);
        assert_eq!(s.lost(), 1);
        assert_invariants(&s);
    }

    /// Expiry runs on every poll, so it has to be idempotent — otherwise a
    /// driver polling twice in a millisecond would count one loss twice.
    #[test]
    fn expiry_is_idempotent() {
        let mut s = session(1);
        s.record_sent(Duration::ZERO);
        s.expire(secs(9));
        s.expire(secs(9));
        s.expire(secs(20));
        assert_eq!(s.lost(), 1);
        assert_invariants(&s);
    }

    /// A probe that could not be sent for want of a route is loss too, but a
    /// distinguishable kind: an operator reads "unreachable" differently from
    /// "no answer".
    #[test]
    fn a_probe_with_no_route_is_lost_immediately() {
        let mut s = session(2);
        s.record_no_route(Duration::ZERO);

        assert_eq!(s.lost(), 1);
        assert_eq!(s.sent(), 1);
        assert_eq!(
            s.probes().next().expect("one row").state,
            ProbeState::NoRoute
        );
        assert_invariants(&s);
    }

    /// The ring bounds display, not accuracy. A session longer than the ring
    /// keeps exact totals while showing only the recent rows — and an
    /// outstanding probe evicted before its answer is counted as lost on the
    /// way out, since nothing can credit it once its row is gone.
    #[test]
    fn a_session_longer_than_the_ring_keeps_exact_totals() {
        let count = MAX_PING_PROBES as u16 * 3;
        let mut s = session(count);

        for i in 0..count {
            let at = secs(u64::from(i));
            let seqno = s.record_sent(at);
            assert!(s.record_reply(at + Duration::from_millis(10), mac(9), seqno, 1, 1));
        }

        assert_eq!(s.probes().count(), MAX_PING_PROBES, "display is bounded");
        assert_eq!(s.received(), u32::from(count), "accounting is not");
        assert_eq!(s.rtt_avg_us(), Some(10_000));
        assert_invariants(&s);
    }

    /// An unanswered probe pushed out of the ring by newer ones is counted as
    /// lost rather than silently forgotten.
    #[test]
    fn an_outstanding_probe_evicted_from_the_ring_counts_as_lost() {
        let count = MAX_PING_PROBES as u16 + 1;
        let mut s = session(count);

        // Send one and never answer it, then fill the ring past it. The
        // timeout is deliberately long enough that expiry is not what catches
        // this — eviction is.
        for i in 0..count {
            s.record_sent(Duration::from_millis(u64::from(i)));
        }

        assert_eq!(s.lost(), 1, "the evicted probe was accounted for");
        assert_invariants(&s);
    }

    /// The deadline a sleeping driver needs: whichever of "next probe due" and
    /// "soonest outstanding timeout" comes first, and nothing once the session
    /// is done.
    #[test]
    fn the_next_deadline_is_the_sooner_of_probe_and_timeout() {
        let mut s = session(2);
        s.record_sent(Duration::ZERO);

        // Next probe at 1 s, that probe's timeout at 5 s.
        assert_eq!(s.next_due_after(Duration::ZERO), Some(secs(1)));

        s.record_sent(secs(1));
        // Every probe sent; the first one's timeout at 5 s is all that's left.
        assert_eq!(s.next_due_after(secs(1)), Some(secs(4)));

        s.expire(secs(10));
        assert_eq!(s.next_due_after(secs(10)), None, "session finished");
        assert_invariants(&s);
    }

    /// A session of zero probes is finished the moment it starts rather than
    /// waiting forever for a probe that will never be due.
    #[test]
    fn a_zero_probe_session_is_immediately_finished() {
        let s = session(0);
        assert!(!s.active());
        assert!(!s.due(Duration::ZERO));
        assert_eq!(s.next_due_after(Duration::ZERO), None);
        assert_invariants(&s);
    }

    /// Cancelling stops the session where it stands and keeps the statistics.
    ///
    /// `ping(8)`'s Ctrl+C prints its summary rather than discarding the run,
    /// and for the same reason: the probes that already completed are the
    /// answer the operator was waiting for, and throwing them away for the sake
    /// of the ones that did not would waste the airtime already spent.
    #[test]
    fn cancelling_stops_the_session_and_keeps_what_it_measured() {
        let mut s = session(5);
        s.record_sent(Duration::ZERO);
        assert!(s.record_reply(secs(1), mac(9), 0, 1, 1));
        s.record_sent(secs(1));

        s.cancel();

        assert!(!s.active(), "a cancelled session has no work left");
        assert_eq!(s.received(), 1, "what was measured survives");
        assert_eq!(s.rtt_avg_us(), Some(1_000_000));
        assert_eq!(
            s.sent(),
            2,
            "and the count reflects what went out, not what was asked for"
        );
        assert_invariants(&s);
    }

    /// An outstanding probe at the moment of cancellation is loss, not a
    /// pending row left to dangle — otherwise `active()` stays true and the
    /// session the operator just stopped goes on being polled forever.
    #[test]
    fn cancelling_resolves_probes_still_in_flight() {
        let mut s = session(5);
        s.record_sent(Duration::ZERO);
        s.record_sent(secs(1));

        s.cancel();

        assert_eq!(s.lost(), 2, "both in-flight probes are accounted for");
        assert!(
            s.probes().all(|p| p.state != ProbeState::Pending),
            "no row is left pending"
        );
        assert!(!s.active());
        assert_invariants(&s);
    }

    /// And it stops the node emitting: no probe falls due afterwards, and the
    /// session reports no deadline for a driver to wake on.
    #[test]
    fn a_cancelled_session_never_falls_due_again() {
        let mut s = session(5);
        s.record_sent(Duration::ZERO);
        s.cancel();

        assert!(!s.due(secs(10)), "nothing more is owed");
        assert_eq!(
            s.next_due_after(secs(10)),
            None,
            "and no deadline is left for a driver to spin on"
        );
    }

    /// Cancelling twice is not an error and does not double-count the losses it
    /// already recorded — a client that retries a cancel it did not see
    /// acknowledged must not corrupt the summary.
    #[test]
    fn cancelling_twice_changes_nothing() {
        let mut s = session(5);
        s.record_sent(Duration::ZERO);
        s.cancel();
        let lost = s.lost();
        let sent = s.sent();

        s.cancel();

        assert_eq!(s.lost(), lost);
        assert_eq!(s.sent(), sent);
        assert_invariants(&s);
    }
}
