//! Ephemeral on-disk persistence for TUI session state.
//!
//! The throughput history shown on the Metrics tab is kept across runs so that
//! closing and reopening the dashboard continues the trend chart instead of
//! starting from a blank slate. State is stored as JSON under
//! `~/.wayfinder/tui/state.json`. Persistence is strictly best-effort: any I/O
//! or parse failure degrades to an empty history rather than disrupting the UI.
//!
//! Every sample carries the wall-clock instant it was captured at, and the load
//! path replays it onto the timeline at that instant rather than at "now": a
//! history saved ten seconds before the TUI reopens resumes ten seconds back on
//! the chart, and one saved an hour ago is dropped entirely instead of being
//! passed off as current traffic.

use std::collections::VecDeque;
use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

use crate::app::THROUGHPUT_HISTORY;
use crate::app::ThroughputSample;
use crate::app::now_ms;

/// On-disk schema version. Bumped if the persisted layout changes incompatibly
/// so a stale file from an older build is discarded rather than mis-parsed.
///
/// v2 added [`ThroughputSample::at_ms`]; a v1 file has no capture times and so
/// cannot be placed on the timeline at all.
const STATE_VERSION: u32 = 2;

/// The persisted TUI session state, serialised as JSON.
#[derive(Serialize, Deserialize)]
pub struct PersistedState {
    /// Schema version of this file; see [`STATE_VERSION`]. A mismatch causes the
    /// file to be ignored on load.
    pub version: u32,
    /// Rolling throughput history, oldest first — the same ordering as
    /// [`crate::app::App::throughput_history`].
    pub throughput_history: Vec<ThroughputSample>,
}

/// Resolve the default state-file path, `~/.wayfinder/tui/state.json`.
///
/// Returns `None` when no home directory is known (e.g. `HOME` is unset), in
/// which case the caller skips persistence.
pub fn state_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let mut path = PathBuf::from(home);
    path.push(".wayfinder");
    path.push("tui");
    path.push("state.json");
    Some(path)
}

/// Load the throughput history from the default state path, keeping only the
/// samples captured within the last `window_ms`, and returning an empty history
/// if the file is missing, unreadable, malformed, or from an incompatible
/// schema version.
pub fn load(window_ms: u64) -> VecDeque<ThroughputSample> {
    match state_path() {
        Some(path) => load_from(&path, now_ms(), window_ms),
        None => VecDeque::new(),
    }
}

/// Persist the throughput history to the default state path. Best-effort: a
/// missing home directory is a silent no-op, and any I/O error is returned for
/// the caller to log but is not otherwise fatal.
pub fn save(history: &VecDeque<ThroughputSample>) -> std::io::Result<()> {
    match state_path() {
        Some(path) => save_to(&path, history),
        None => Ok(()),
    }
}

/// Load and validate persisted history from an explicit path, as of the
/// wall-clock instant `now_ms` and the retained window `window_ms`.
///
/// A simply-absent file is the normal first-run case and yields an empty
/// history. A file that *exists* but cannot be loaded (unreadable, malformed, or
/// an incompatible schema version) is treated as corrupt: it is deleted so the
/// bad state cannot linger across runs, and an empty history is returned so the
/// session starts clean.
pub fn load_from(path: &Path, now_ms: u64, window_ms: u64) -> VecDeque<ThroughputSample> {
    match try_load(path, now_ms, window_ms) {
        Ok(history) => history,
        Err(_) => {
            // Reset: discard the unusable file (best-effort).
            let _ = std::fs::remove_file(path);
            VecDeque::new()
        }
    }
}

/// Read and validate the state file. Returns an empty history when the file is
/// simply absent; any present-but-unusable file is an `Err` so [`load_from`] can
/// reset it.
///
/// A successfully parsed history is filtered to the samples that still belong on
/// the chart — captured no earlier than `now_ms - window_ms` and no later than
/// `now_ms` — and then clamped to [`THROUGHPUT_HISTORY`] in case the file was
/// written by a build with a larger cap. Discarding future-stamped samples
/// bounds the damage from a wall clock that stepped backwards between sessions,
/// which would otherwise plot history to the right of "now".
fn try_load(
    path: &Path,
    now_ms: u64,
    window_ms: u64,
) -> std::io::Result<VecDeque<ThroughputSample>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(VecDeque::new()),
        Err(e) => return Err(e),
    };
    let state: PersistedState = serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
    if state.version != STATE_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "incompatible state version",
        ));
    }
    let cutoff = now_ms.saturating_sub(window_ms);
    let mut history: VecDeque<ThroughputSample> = state
        .throughput_history
        .into_iter()
        .filter(|s| s.at_ms >= cutoff && s.at_ms <= now_ms)
        .collect();
    while history.len() > THROUGHPUT_HISTORY {
        history.pop_front();
    }
    Ok(history)
}

/// Write the history to an explicit path, creating parent directories as
/// needed. The write is atomic — a temp file is written and renamed into place
/// — so a crash mid-write cannot leave a truncated state file.
pub fn save_to(path: &Path, history: &VecDeque<ThroughputSample>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let state = PersistedState {
        version: STATE_VERSION,
        throughput_history: history.iter().copied().collect(),
    };
    let bytes = serde_json::to_vec_pretty(&state).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed wall-clock "now" (2023-11-14T22:13:20Z) so the age-based
    /// retention assertions are deterministic rather than clock-dependent.
    const NOW: u64 = 1_700_000_000_000;

    /// The retained window used by the tests: two minutes, matching a default
    /// 1 s refresh across [`THROUGHPUT_HISTORY`] samples.
    const WINDOW: u64 = 120_000;

    /// A unique scratch path under the system temp dir, so tests don't touch the
    /// real `~/.wayfinder` and don't collide with each other.
    fn tmp_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "wayfinder-tui-test-{}-{}-{}.json",
            tag,
            std::process::id(),
            // monotonic-ish nonce to avoid reuse within a process
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        p
    }

    fn sample(at_ms: u64, rx: f64, tx: f64) -> ThroughputSample {
        ThroughputSample {
            at_ms,
            rx_bps: rx,
            tx_bps: tx,
        }
    }

    #[test]
    fn round_trips_history_through_disk() {
        let path = tmp_path("roundtrip");
        let mut history = VecDeque::new();
        history.push_back(sample(NOW - 2000, 1.0, 2.0));
        history.push_back(sample(NOW - 1000, 3.0, 4.0));

        save_to(&path, &history).expect("save");
        let loaded = load_from(&path, NOW, WINDOW);
        std::fs::remove_file(&path).ok();

        // Capture times survive the round trip: without them the chart could
        // only replay the samples as if they had all just been taken.
        assert_eq!(loaded, history);
    }

    #[test]
    fn missing_file_loads_empty() {
        let path = tmp_path("missing");
        // Never created.
        assert!(load_from(&path, NOW, WINDOW).is_empty());
    }

    #[test]
    fn version_mismatch_is_discarded_and_reset() {
        let path = tmp_path("version");
        let json =
            br#"{"version":999,"throughput_history":[{"at_ms":1,"rx_bps":1.0,"tx_bps":2.0}]}"#;
        std::fs::write(&path, json).expect("write");
        let loaded = load_from(&path, NOW, WINDOW);
        assert!(loaded.is_empty());
        // An incompatible file is reset rather than left to linger.
        assert!(!path.exists(), "incompatible state file should be removed");
    }

    #[test]
    fn untimestamped_v1_file_is_discarded() {
        let path = tmp_path("v1");
        // The pre-timestamp layout: samples with no capture time, which cannot
        // be placed on the timeline at all.
        let json = br#"{"version":1,"throughput_history":[{"rx_bps":1.0,"tx_bps":2.0}]}"#;
        std::fs::write(&path, json).expect("write");
        assert!(load_from(&path, NOW, WINDOW).is_empty());
        assert!(!path.exists(), "stale-schema state file should be removed");
    }

    #[test]
    fn malformed_file_loads_empty_and_reset() {
        let path = tmp_path("malformed");
        std::fs::write(&path, b"not json").expect("write");
        let loaded = load_from(&path, NOW, WINDOW);
        assert!(loaded.is_empty());
        // A corrupt file is reset rather than left to linger.
        assert!(!path.exists(), "corrupt state file should be removed");
    }

    #[test]
    fn load_drops_samples_older_than_the_window() {
        let path = tmp_path("stale");
        let mut history = VecDeque::new();
        history.push_back(sample(NOW - WINDOW - 1, 1.0, 0.0)); // just too old
        history.push_back(sample(NOW - WINDOW, 2.0, 0.0)); // exactly at the edge
        history.push_back(sample(NOW - 1000, 3.0, 0.0));
        save_to(&path, &history).expect("save");

        let loaded = load_from(&path, NOW, WINDOW);
        std::fs::remove_file(&path).ok();

        // Samples that have aged out of the chart's window are not carried
        // forward: they would otherwise sit off the left edge of the timeline.
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.front().unwrap().rx_bps, 2.0);
        assert_eq!(loaded.back().unwrap().rx_bps, 3.0);
    }

    #[test]
    fn load_drops_samples_stamped_in_the_future() {
        let path = tmp_path("future");
        let mut history = VecDeque::new();
        history.push_back(sample(NOW - 1000, 1.0, 0.0));
        history.push_back(sample(NOW + 60_000, 2.0, 0.0));
        save_to(&path, &history).expect("save");

        let loaded = load_from(&path, NOW, WINDOW);
        std::fs::remove_file(&path).ok();

        // A backwards step of the wall clock between sessions must not put a
        // sample to the right of "now" on the chart.
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.back().unwrap().rx_bps, 1.0);
    }

    #[test]
    fn wholly_stale_file_loads_empty() {
        let path = tmp_path("ancient");
        let mut history = VecDeque::new();
        history.push_back(sample(NOW - 86_400_000, 1.0, 0.0));
        save_to(&path, &history).expect("save");

        // A state file from a session a day ago contributes nothing — the
        // chart starts blank rather than pretending yesterday's traffic is now.
        let loaded = load_from(&path, NOW, WINDOW);
        std::fs::remove_file(&path).ok();
        assert!(loaded.is_empty());
    }

    #[test]
    fn load_clamps_to_capacity() {
        let path = tmp_path("clamp");
        let over: Vec<ThroughputSample> = (0..THROUGHPUT_HISTORY + 10)
            .map(|i| sample(NOW - (THROUGHPUT_HISTORY + 10 - i) as u64, i as f64, 0.0))
            .collect();
        let state = PersistedState {
            version: STATE_VERSION,
            throughput_history: over,
        };
        std::fs::write(&path, serde_json::to_vec(&state).unwrap()).expect("write");

        let loaded = load_from(&path, NOW, WINDOW);
        std::fs::remove_file(&path).ok();

        assert_eq!(loaded.len(), THROUGHPUT_HISTORY);
        // The oldest entries were dropped, the newest retained.
        assert_eq!(
            loaded.back().unwrap().rx_bps,
            (THROUGHPUT_HISTORY + 10 - 1) as f64
        );
    }
}
