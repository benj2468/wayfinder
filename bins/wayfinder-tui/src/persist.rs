//! Ephemeral on-disk persistence for TUI session state.
//!
//! The throughput history shown on the Metrics tab is kept across runs so that
//! closing and reopening the dashboard continues the trend chart instead of
//! starting from a blank slate. State is stored as JSON under
//! `~/.wayfinder/tui/state.json`. Persistence is strictly best-effort: any I/O
//! or parse failure degrades to an empty history rather than disrupting the UI.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::app::{THROUGHPUT_HISTORY, ThroughputSample};

/// On-disk schema version. Bumped if the persisted layout changes incompatibly
/// so a stale file from an older build is discarded rather than mis-parsed.
const STATE_VERSION: u32 = 1;

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

/// Load the throughput history from the default state path, returning an empty
/// history if the file is missing, unreadable, malformed, or from an
/// incompatible schema version.
pub fn load() -> VecDeque<ThroughputSample> {
    match state_path() {
        Some(path) => load_from(&path),
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

/// Load and validate persisted history from an explicit path.
///
/// A simply-absent file is the normal first-run case and yields an empty
/// history. A file that *exists* but cannot be loaded (unreadable, malformed, or
/// an incompatible schema version) is treated as corrupt: it is deleted so the
/// bad state cannot linger across runs, and an empty history is returned so the
/// session starts clean.
pub fn load_from(path: &Path) -> VecDeque<ThroughputSample> {
    match try_load(path) {
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
/// reset it. A successfully parsed history is clamped to [`THROUGHPUT_HISTORY`]
/// in case the file was written by a build with a larger cap.
fn try_load(path: &Path) -> std::io::Result<VecDeque<ThroughputSample>> {
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
    let mut history: VecDeque<ThroughputSample> = state.throughput_history.into_iter().collect();
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

    fn sample(rx: f64, tx: f64) -> ThroughputSample {
        ThroughputSample {
            rx_bps: rx,
            tx_bps: tx,
        }
    }

    #[test]
    fn round_trips_history_through_disk() {
        let path = tmp_path("roundtrip");
        let mut history = VecDeque::new();
        history.push_back(sample(1.0, 2.0));
        history.push_back(sample(3.0, 4.0));

        save_to(&path, &history).expect("save");
        let loaded = load_from(&path);
        std::fs::remove_file(&path).ok();

        assert_eq!(loaded, history);
    }

    #[test]
    fn missing_file_loads_empty() {
        let path = tmp_path("missing");
        // Never created.
        assert!(load_from(&path).is_empty());
    }

    #[test]
    fn version_mismatch_is_discarded_and_reset() {
        let path = tmp_path("version");
        let json = br#"{"version":999,"throughput_history":[{"rx_bps":1.0,"tx_bps":2.0}]}"#;
        std::fs::write(&path, json).expect("write");
        let loaded = load_from(&path);
        assert!(loaded.is_empty());
        // An incompatible file is reset rather than left to linger.
        assert!(!path.exists(), "incompatible state file should be removed");
    }

    #[test]
    fn malformed_file_loads_empty_and_reset() {
        let path = tmp_path("malformed");
        std::fs::write(&path, b"not json").expect("write");
        let loaded = load_from(&path);
        assert!(loaded.is_empty());
        // A corrupt file is reset rather than left to linger.
        assert!(!path.exists(), "corrupt state file should be removed");
    }

    #[test]
    fn load_clamps_to_capacity() {
        let path = tmp_path("clamp");
        let over: Vec<ThroughputSample> = (0..THROUGHPUT_HISTORY + 10)
            .map(|i| sample(i as f64, 0.0))
            .collect();
        let state = PersistedState {
            version: STATE_VERSION,
            throughput_history: over,
        };
        std::fs::write(&path, serde_json::to_vec(&state).unwrap()).expect("write");

        let loaded = load_from(&path);
        std::fs::remove_file(&path).ok();

        assert_eq!(loaded.len(), THROUGHPUT_HISTORY);
        // The oldest entries were dropped, the newest retained.
        assert_eq!(
            loaded.back().unwrap().rx_bps,
            (THROUGHPUT_HISTORY + 10 - 1) as f64
        );
    }
}
