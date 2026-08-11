//! The dashboard's accumulated client-side state.
//!
//! A snapshot is a point-in-time answer, but three things the dashboard shows
//! are *histories* the node does not keep for us: the log scrollback, the
//! throughput trend, and the last data that arrived before the node went away.
//! This module folds successive polls into those, away from any component, so
//! the folding is unit testable and the views stay declarative.
//!
//! The semantics deliberately match `wayfinder-tui`'s `ingest_logs` and
//! `record_throughput` — including the priming rule, which is the kind of detail
//! that is invisible until it greets every fresh session with a false alarm.

use std::collections::VecDeque;

use wayfinder_protos::wayfinder::v1alpha::LogRecord;
use wayfinder_protos::wayfinder::v1alpha::LogRecords;

use crate::snapshot::NodeSnapshot;

/// Lines of log scrollback the dashboard retains.
///
/// Far deeper than any node's own ring (64 records on a board, 512 on a host),
/// because the two bound different things: the node's ring bounds what is lost
/// while nobody is polling, this bounds what an operator can scroll back through
/// in a session. Still bounded — a tab left open for days must not grow without
/// limit.
pub const LOG_SCROLLBACK: usize = 5000;

/// Throughput samples retained for the trend chart.
///
/// One per poll, so at the default cadence this is roughly the last five
/// minutes: long enough to show a burst or a collapse in context, short enough
/// that the chart stays legible at a glance.
pub const THROUGHPUT_HISTORY: usize = 300;

/// One line in the log view: a record, or a marker standing in for records that
/// were evicted before this client could read them.
///
/// The gap is an entry in stream position rather than a counter in a corner: a
/// discontinuity between two adjacent lines is exactly the thing an operator
/// reading logs must not have to infer.
#[derive(Clone, Debug, PartialEq)]
pub enum LogEntry {
    /// A record the node reported.
    Record(LogRecord),
    /// This many records were dropped at this point in the stream.
    Gap(u64),
}

/// One throughput sample: the node-wide totals at the moment of a poll.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ThroughputSample {
    /// Node-wide receive rate, bytes per second.
    pub rx_bps: f64,
    /// Node-wide transmit rate, bytes per second.
    pub tx_bps: f64,
}

/// What the dashboard accumulates across polls.
#[derive(Clone, Debug, Default)]
pub struct History {
    /// Log scrollback, oldest first, bounded by [`LOG_SCROLLBACK`].
    pub entries: VecDeque<LogEntry>,
    /// The cursor to resume the log stream from on the next poll.
    pub next_seq: u64,
    /// The filter the node reports as in force.
    pub filter: String,
    /// Throughput trend, oldest first, bounded by [`THROUGHPUT_HISTORY`].
    pub throughput: VecDeque<ThroughputSample>,
    /// Whether a first poll has completed. Until it has, a reported drop count
    /// describes history that predates this session — see [`History::ingest_logs`].
    primed: bool,
}

impl History {
    /// Fold one poll's log batch into the scrollback and advance the cursor.
    ///
    /// A reported drop count becomes a [`LogEntry::Gap`] in stream position,
    /// except on the priming poll: the first request asks from seq 0, so a
    /// long-running node reports everything it has already evicted as dropped.
    /// Rendering that would greet every fresh session with an alarm about
    /// history nobody was there to miss.
    pub fn ingest_logs(&mut self, batch: LogRecords) {
        if self.primed && batch.dropped > 0 {
            self.entries.push_back(LogEntry::Gap(batch.dropped));
        }

        for record in batch.records {
            self.entries.push_back(LogEntry::Record(record));
        }

        self.next_seq = batch.next_seq;
        self.primed = true;

        // Track what the node reports rather than what this client last asked
        // for, so the filter line stays right across a node restart, a startup
        // RUST_LOG this session never set, and a change made by another client.
        self.filter = batch.filter;

        while self.entries.len() > LOG_SCROLLBACK {
            self.entries.pop_front();
        }
    }

    /// Append this poll's node-wide throughput totals to the trend.
    pub fn record_throughput(&mut self, snapshot: &NodeSnapshot) {
        self.throughput.push_back(ThroughputSample {
            rx_bps: snapshot.throughput.total_rx_bps,
            tx_bps: snapshot.throughput.total_tx_bps,
        });
        while self.throughput.len() > THROUGHPUT_HISTORY {
            self.throughput.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record at `seq`, tagged so tests can tell them apart.
    fn rec(seq: u64) -> LogRecord {
        LogRecord {
            seq,
            uptime_ms: seq * 10,
            level: 3,
            target: "test".into(),
            message: format!("m{seq}"),
        }
    }

    /// A batch of records `seqs`, reporting `dropped` missed before them.
    fn batch(seqs: &[u64], dropped: u64) -> LogRecords {
        LogRecords {
            records: seqs.iter().copied().map(rec).collect(),
            next_seq: seqs.last().map_or(0, |s| s + 1),
            dropped,
            filter: "info".into(),
        }
    }

    #[test]
    fn ingest_appends_records_and_advances_the_cursor() {
        let mut history = History::default();
        history.ingest_logs(batch(&[0, 1, 2], 0));

        assert_eq!(history.entries.len(), 3);
        assert_eq!(history.next_seq, 3);
    }

    #[test]
    fn ingest_records_a_gap_as_an_entry_in_stream_position() {
        // A discontinuity between two adjacent lines is exactly the thing an
        // operator reading logs must not have to infer, so it is an entry in
        // the stream rather than a counter in a corner.
        let mut history = History::default();
        history.ingest_logs(batch(&[0], 0));
        history.ingest_logs(batch(&[9], 8));

        assert_eq!(history.entries.len(), 3);
        assert!(matches!(history.entries[1], LogEntry::Gap(8)));
    }

    #[test]
    fn ingest_suppresses_the_gap_on_the_priming_poll() {
        // The first poll asks from seq 0, so a long-running node reports
        // everything it already evicted as dropped. Banner-ing that would greet
        // every fresh session with an alarm about history nobody was there to
        // miss.
        let mut history = History::default();
        history.ingest_logs(batch(&[500], 500));

        assert_eq!(history.entries.len(), 1);
        assert!(matches!(history.entries[0], LogEntry::Record(_)));
    }

    #[test]
    fn ingest_bounds_the_scrollback() {
        let mut history = History::default();
        for start in 0..(LOG_SCROLLBACK as u64 / 10 + 20) {
            let seqs: Vec<u64> = (start * 10..start * 10 + 10).collect();
            history.ingest_logs(batch(&seqs, 0));
        }

        assert_eq!(history.entries.len(), LOG_SCROLLBACK);
    }

    #[test]
    fn ingest_tracks_the_filter_the_node_reports() {
        // What is actually in force, not what this client last asked for, so the
        // line stays right across a node restart or a change made elsewhere.
        let mut history = History::default();
        let mut b = batch(&[0], 0);
        b.filter = "info,batman=trace".into();
        history.ingest_logs(b);

        assert_eq!(history.filter, "info,batman=trace");
    }

    #[test]
    fn throughput_history_is_bounded() {
        let mut history = History::default();
        for _ in 0..(THROUGHPUT_HISTORY + 50) {
            history.record_throughput(&NodeSnapshot::default());
        }

        assert_eq!(history.throughput.len(), THROUGHPUT_HISTORY);
    }

    #[test]
    fn throughput_history_keeps_the_most_recent_samples() {
        let mut history = History::default();
        for i in 0..(THROUGHPUT_HISTORY + 10) {
            let mut snap = NodeSnapshot::default();
            snap.throughput.total_rx_bps = i as f64;
            history.record_throughput(&snap);
        }

        let newest = history.throughput.back().expect("history is non-empty");
        assert_eq!(newest.rx_bps, (THROUGHPUT_HISTORY + 9) as f64);
    }
}
