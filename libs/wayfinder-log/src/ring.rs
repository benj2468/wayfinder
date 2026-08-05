//! The bounded in-memory record ring the management API serves `GetLogs` from.
//!
//! Every sink-bound record is also pushed here, so a management client can read
//! a node's recent logs over whatever transport it already speaks — USB CDC-ACM
//! on the nRF, a socket on a host node. On a board with no debug probe attached
//! this is the only way its logs are observable at all.
//!
//! # Why a ring, polled, rather than a stream
//!
//! The management protocol is strictly one request to one response
//! (`wayfinder_server::serve`), and a stream would have to break that for every
//! client. More importantly a stream only shows what happened while someone was
//! watching, which is the wrong property for the case this exists to serve:
//! plugging into a node *after* it misbehaved and asking what it just did. A
//! bounded ring answers that, and bounds its own cost while doing it.
//!
//! Records are never dropped in favour of a slow reader: at capacity the oldest
//! is evicted, so a client that stops polling — or was never attached — can
//! never exert backpressure on the router. What a caller missed is reported to
//! it explicitly rather than the gap silently closing up; see
//! [`LogSnapshot::dropped`].

use alloc::vec::Vec;

use crate::filter::Level;
use crate::filter::TARGET_CAP;
use crate::sync::Lock;

/// Longest message retained per record, in bytes.
///
/// A record's message is the rendered event text plus its structured fields —
/// macs, lengths, seqnos — and never payload bytes, so this is generous for
/// what this project's logging rules actually permit on the wire.
pub const MESSAGE_CAP: usize = 160;

/// Records retained before the oldest is evicted.
///
/// Sized per target, since the constraint differs by two orders of magnitude:
/// on a board this is a `static` competing with the router for 256 KiB of RAM
/// (at roughly 240 bytes a record, 64 of them is ~15 KiB), while a host node has
/// no such pressure and benefits from surviving a longer client absence.
#[cfg(target_os = "none")]
pub const RING_CAPACITY: usize = 64;
/// Records retained before the oldest is evicted. See the bare-metal definition.
#[cfg(not(target_os = "none"))]
pub const RING_CAPACITY: usize = 512;

/// Records returned when a caller does not specify a batch size.
const DEFAULT_BATCH: usize = RING_CAPACITY;

/// One retained log record.
#[derive(Clone, Debug)]
pub struct LogRecord {
    /// Monotonic position in this node's log stream, starting at 0 on boot.
    /// A client polls with the last [`LogSnapshot::next_seq`] it was handed, so
    /// it sees each record exactly once.
    pub seq: u64,
    /// Milliseconds since boot, at the moment the record was emitted.
    ///
    /// Uptime rather than wall-clock time because it is the one reading
    /// available identically on both targets — a board has no RTC and no notion
    /// of the epoch — and because it is what correlates with the mesh's own
    /// timers (Trickle intervals, keep-alive cadences).
    pub uptime_ms: u64,
    /// The record's verbosity.
    pub level: Level,
    /// The emitting module path, truncated to [`TARGET_CAP`].
    pub target: heapless::String<TARGET_CAP>,
    /// The rendered message and its structured fields, truncated to
    /// [`MESSAGE_CAP`].
    pub message: heapless::String<MESSAGE_CAP>,
}

/// What one [`logs_since`] call found.
pub struct LogSnapshot {
    /// The matching records, oldest first.
    pub records: Vec<LogRecord>,
    /// The `since_seq` to pass on the next poll to resume exactly where this
    /// batch ended.
    pub next_seq: u64,
    /// How many records this caller missed: those between the `since_seq` it
    /// asked for and the oldest still retained. Zero whenever the caller kept
    /// up. Reported so a gap is visible as a gap rather than as the stream
    /// quietly closing over it.
    pub dropped: u64,
}

/// Truncate `s` to at most `N` bytes on a character boundary.
///
/// Truncating rather than rejecting: a record with a clipped tail is still worth
/// having, and logging must never fail. Splitting on a boundary keeps the result
/// valid UTF-8, which the protobuf `string` field it ends up in requires.
fn truncated<const N: usize>(s: &str) -> heapless::String<N> {
    let mut end = s.len().min(N);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    heapless::String::try_from(&s[..end]).unwrap_or_default()
}

/// The record store: a fixed-capacity queue plus the sequence counter that
/// numbers what goes into it.
struct Ring {
    /// Retained records, oldest at the front, seqs strictly ascending and
    /// contiguous.
    buf: heapless::Deque<LogRecord, RING_CAPACITY>,
    /// The seq the next pushed record will carry — also one past the newest
    /// retained record's seq.
    next_seq: u64,
}

impl Ring {
    /// An empty ring whose first record will be seq 0. `const` so the global
    /// lives in a `static` with no initializer.
    const fn new() -> Self {
        Self {
            buf: heapless::Deque::new(),
            next_seq: 0,
        }
    }

    /// Append one record, evicting the oldest if the ring is full.
    fn push(&mut self, level: Level, target: &str, message: &str, uptime_ms: u64) {
        if self.buf.is_full() {
            self.buf.pop_front();
        }
        let record = LogRecord {
            seq: self.next_seq,
            uptime_ms,
            level,
            target: truncated(target),
            message: truncated(message),
        };
        // The capacity check above guarantees room; a failure here would mean
        // dropping a record we already made space for.
        let _ = self.buf.push_back(record);
        self.next_seq = self.next_seq.wrapping_add(1);
    }

    /// Records from `since_seq` onward, at most `max_records` of them.
    fn since(&self, since_seq: u64, max_records: usize) -> LogSnapshot {
        let max_records = if max_records == 0 {
            DEFAULT_BATCH
        } else {
            max_records
        };
        let oldest = self.buf.front().map_or(self.next_seq, |r| r.seq);

        let records: Vec<LogRecord> = self
            .buf
            .iter()
            .filter(|r| r.seq >= since_seq)
            .take(max_records)
            .cloned()
            .collect();

        LogSnapshot {
            // One past the last record handed over, or — when nothing matched —
            // wherever the stream currently is, so a caller that has caught up
            // does not rewind on its next poll.
            next_seq: records.last().map_or(self.next_seq, |r| r.seq + 1),
            dropped: oldest.saturating_sub(since_seq),
            records,
        }
    }

    /// Check the ordering and counter invariants the reader relies on: seqs
    /// ascending and contiguous, and `next_seq` one past the newest.
    #[cfg(test)]
    fn assert_invariants(&self) {
        assert!(self.buf.len() <= RING_CAPACITY, "ring over capacity");
        let mut expected = self.buf.front().map(|r| r.seq);
        for record in self.buf.iter() {
            assert_eq!(Some(record.seq), expected, "seqs must be contiguous");
            expected = Some(record.seq + 1);
            assert!(record.target.len() <= TARGET_CAP);
            assert!(record.message.len() <= MESSAGE_CAP);
        }
        if let Some(next) = expected {
            assert_eq!(
                next, self.next_seq,
                "next_seq must follow the newest record"
            );
        } else {
            assert!(self.buf.is_empty());
        }
    }
}

/// The process-wide record store.
///
/// A `static` because the thing that writes it — the installed `tracing`
/// subscriber — is itself process-wide, with no way to carry a handle. That is
/// also what lets `RouterAdapter` answer `GetLogs` without threading a reference
/// through the router, the driver, and every board's bring-up.
static RING: Lock<Ring> = Lock::new(Ring::new());

/// Append one record to the global ring.
///
/// Callers gate on [`crate::filter::enabled`] first: this does no filtering of
/// its own, so an unfiltered call would evict records an operator asked for.
pub fn record(level: Level, target: &str, message: &str) {
    let uptime_ms = crate::clock::uptime_ms();
    RING.with(|ring| ring.push(level, target, message, uptime_ms));
}

/// Read records from the global ring, from `since_seq` onward.
///
/// `max_records` of 0 means "the server's default batch" — a client that did not
/// specify one wants records, not an empty answer that would wedge its polling
/// loop.
pub fn logs_since(since_seq: u64, max_records: usize) -> LogSnapshot {
    RING.with(|ring| ring.since(since_seq, max_records))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Push `n` records with ascending, easily-identifiable messages.
    fn fill(ring: &mut Ring, n: usize) {
        for i in 0..n {
            ring.push(Level::Info, "t", &alloc::format!("m{i}"), i as u64);
            ring.assert_invariants();
        }
    }

    #[test]
    fn a_fresh_ring_is_empty_and_starts_at_seq_zero() {
        let ring = Ring::new();
        ring.assert_invariants();
        let snap = ring.since(0, 16);
        assert!(snap.records.is_empty());
        assert_eq!(snap.next_seq, 0);
        assert_eq!(snap.dropped, 0);
    }

    #[test]
    fn pushed_records_come_back_in_order_with_ascending_seqs() {
        let mut ring = Ring::new();
        fill(&mut ring, 3);

        let snap = ring.since(0, 16);
        assert_eq!(snap.records.len(), 3);
        assert_eq!(snap.next_seq, 3);
        assert_eq!(snap.dropped, 0);
        for (i, r) in snap.records.iter().enumerate() {
            assert_eq!(r.seq, i as u64);
            assert_eq!(r.message.as_str(), alloc::format!("m{i}"));
            assert_eq!(r.uptime_ms, i as u64);
        }
    }

    #[test]
    fn record_carries_its_level_and_target() {
        let mut ring = Ring::new();
        ring.push(Level::Warn, "wayfinder::router", "rx frame", 42);

        let snap = ring.since(0, 16);
        let r = &snap.records[0];
        assert_eq!(r.level, Level::Warn);
        assert_eq!(r.target, "wayfinder::router");
        assert_eq!(r.message, "rx frame");
        assert_eq!(r.uptime_ms, 42);
    }

    /// `since_seq` is exclusive of everything before it: a client polls with the
    /// `next_seq` it was last handed and sees each record exactly once.
    #[test]
    fn since_seq_returns_only_newer_records() {
        let mut ring = Ring::new();
        fill(&mut ring, 5);

        let snap = ring.since(3, 16);
        assert_eq!(snap.records.len(), 2);
        assert_eq!(snap.records[0].seq, 3);
        assert_eq!(snap.next_seq, 5);
    }

    /// Polling with the previous `next_seq` when nothing new has happened is the
    /// steady state of a TUI refresh tick; it must be empty, not a re-send.
    #[test]
    fn polling_at_next_seq_returns_nothing() {
        let mut ring = Ring::new();
        fill(&mut ring, 4);
        let snap = ring.since(4, 16);
        assert!(snap.records.is_empty());
        assert_eq!(snap.next_seq, 4);
        assert_eq!(snap.dropped, 0);
    }

    /// A `since_seq` past the end (a client talking to a node that restarted and
    /// reset its counter) yields nothing rather than panicking or wrapping.
    #[test]
    fn since_seq_beyond_the_end_returns_nothing() {
        let mut ring = Ring::new();
        fill(&mut ring, 2);
        let snap = ring.since(99, 16);
        assert!(snap.records.is_empty());
        assert_eq!(snap.next_seq, 2);
    }

    #[test]
    fn max_records_caps_the_batch_and_next_seq_resumes_there() {
        let mut ring = Ring::new();
        fill(&mut ring, 10);

        let snap = ring.since(0, 4);
        assert_eq!(snap.records.len(), 4);
        assert_eq!(snap.records[0].seq, 0);
        assert_eq!(
            snap.next_seq, 4,
            "the client resumes at the first unsent seq"
        );

        let snap = ring.since(snap.next_seq, 4);
        assert_eq!(snap.records[0].seq, 4);
        assert_eq!(snap.next_seq, 8);
    }

    /// A zero `max_records` is a client that didn't specify one, not a client
    /// asking for nothing — an empty batch there would wedge a polling loop.
    #[test]
    fn zero_max_records_serves_the_default_batch() {
        let mut ring = Ring::new();
        fill(&mut ring, 3);
        let snap = ring.since(0, 0);
        assert_eq!(snap.records.len(), 3);
    }

    /// At capacity the oldest record is evicted, so a wedged or absent client
    /// never blocks the router — the newest records are always the ones kept.
    #[test]
    fn pushing_at_capacity_evicts_the_oldest() {
        let mut ring = Ring::new();
        fill(&mut ring, RING_CAPACITY + 3);

        let snap = ring.since(0, RING_CAPACITY * 2);
        assert_eq!(snap.records.len(), RING_CAPACITY);
        assert_eq!(snap.records[0].seq, 3, "the first three were evicted");
        assert_eq!(snap.next_seq, (RING_CAPACITY + 3) as u64);
    }

    /// The count a caller missed is reported explicitly, so a gap in the stream
    /// is visible rather than silently closing up.
    #[test]
    fn dropped_reports_what_this_caller_missed() {
        let mut ring = Ring::new();
        fill(&mut ring, RING_CAPACITY + 5);

        // Asking from 0 when the oldest retained is 5: five records are gone.
        let snap = ring.since(0, RING_CAPACITY * 2);
        assert_eq!(snap.dropped, 5);

        // Asking from within the retained window misses nothing.
        let snap = ring.since(10, RING_CAPACITY * 2);
        assert_eq!(snap.dropped, 0);
        assert_eq!(snap.records[0].seq, 10);
    }

    /// Eviction that happens while a client is *not* polling is still reported
    /// on its next poll, against the seq it actually asked for.
    #[test]
    fn dropped_is_relative_to_the_requested_seq() {
        let mut ring = Ring::new();
        fill(&mut ring, RING_CAPACITY);
        // Client has consumed everything so far.
        let snap = ring.since(0, RING_CAPACITY * 2);
        assert_eq!(snap.dropped, 0);
        let resume = snap.next_seq;

        // Two full ring-fulls go by before the client comes back.
        fill(&mut ring, RING_CAPACITY * 2);
        let snap = ring.since(resume, RING_CAPACITY * 2);
        assert_eq!(snap.records.len(), RING_CAPACITY);
        assert_eq!(snap.dropped, (RING_CAPACITY * 2 - RING_CAPACITY) as u64);
    }

    /// A single record is a boundary case for the deque bookkeeping.
    #[test]
    fn single_record_ring_round_trips() {
        let mut ring = Ring::new();
        ring.push(Level::Error, "t", "only", 1);
        ring.assert_invariants();
        let snap = ring.since(0, 16);
        assert_eq!(snap.records.len(), 1);
        assert_eq!(snap.next_seq, 1);
    }

    /// An over-long target or message is truncated, never dropped and never a
    /// panic — a record with a clipped tail is still worth having.
    #[test]
    fn overlong_target_and_message_are_truncated() {
        let mut ring = Ring::new();
        let target = "t".repeat(TARGET_CAP * 2);
        let message = "m".repeat(MESSAGE_CAP * 2);
        ring.push(Level::Info, &target, &message, 0);
        ring.assert_invariants();

        let snap = ring.since(0, 16);
        let r = &snap.records[0];
        assert_eq!(r.target.len(), TARGET_CAP);
        assert_eq!(r.message.len(), MESSAGE_CAP);
    }

    /// Truncation splits on a character boundary, so the record stays valid
    /// UTF-8 and can be encoded into a protobuf `string` field.
    #[test]
    fn truncation_never_splits_a_multibyte_char() {
        let mut ring = Ring::new();
        let message = "日".repeat(MESSAGE_CAP);
        ring.push(Level::Info, "t", &message, 0);

        let snap = ring.since(0, 16);
        let m = &snap.records[0].message;
        assert!(m.len() <= MESSAGE_CAP);
        assert!(m.chars().all(|c| c == '日'));
    }

    // ── The global ring ──────────────────────────────────────────────────────

    /// The global ring is what the subscribers write to and the management API
    /// reads from; it must be reachable without any initialization call.
    #[test]
    fn global_ring_records_and_reads_back() {
        let start = logs_since(0, 0).next_seq;
        record(Level::Info, "wayfinder-log::test", "global record");

        let snap = logs_since(start, 0);
        assert!(
            snap.records
                .iter()
                .any(|r| r.message == "global record" && r.target == "wayfinder-log::test"),
            "the pushed record is visible through the global reader"
        );
    }
}
