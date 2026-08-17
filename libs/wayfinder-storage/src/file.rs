//! `std`-backed [`DurableStore`]: a file, written atomically via a `.tmp`
//! sibling + `rename`.

use std::io::Write;
use std::io::{self};
use std::path::Path;
use std::path::PathBuf;

use crate::DurableStore;

/// A [`DurableStore`] backed by a single file at a fixed path.
///
/// `save` writes to a `.tmp` sibling, flushes it, then renames it over the
/// target — atomic on the same filesystem, so a crash mid-write leaves the
/// previous blob (or nothing, on the first save), never a torn one. A failure
/// best-effort removes the `.tmp`; if even that fails, it is logged and the
/// original write error returned, since a lingering `.tmp` costs disk space
/// rather than correctness.
///
/// Deliberately not `fsync`ed at the parent-directory level: the rename's own
/// metadata is not flushed, so a power loss immediately after one could still
/// lose it on some filesystems. Accepted, and carried forward unchanged from
/// the `save_atomic` this was extracted from.
pub struct FileStore {
    path: PathBuf,
    /// Unix permission bits to stamp on the file, when the blob is sensitive
    /// enough that the process umask is not a safe default. `None` leaves the
    /// mode to the umask, which is right for everything that isn't a secret.
    mode: Option<u32>,
}

impl FileStore {
    /// A store backed by `path`. The file need not exist yet — the first
    /// `load` will see it as an empty store (`Ok(None)`).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            mode: None,
        }
    }

    /// Restrict the stored file to `mode` (Unix permission bits, e.g.
    /// `0o600`), for a blob that carries a secret — a node identity seed, say.
    ///
    /// Applied to the `.tmp` file *before* the rename, so the blob is never
    /// briefly world-readable: the rename carries the temporary file's
    /// permissions onto the target, and re-applies them on every save rather
    /// than only when the file is first created. A no-op on non-Unix targets,
    /// where the mode has no meaning.
    pub fn with_mode(mut self, mode: u32) -> Self {
        self.mode = Some(mode);
        self
    }

    /// The path this store is backed by, for callers naming it in their own
    /// messages — this type's [`DurableStore::Error`] is a bare [`io::Error`],
    /// which cannot carry it.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn tmp_path(&self) -> PathBuf {
        let mut tmp = self.path.as_os_str().to_os_string();
        tmp.push(".tmp");
        PathBuf::from(tmp)
    }
}

impl DurableStore for FileStore {
    type Error = io::Error;

    fn load(&mut self, out: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        if bytes.len() > out.len() {
            return Err(io::Error::other(format!(
                "durable blob at {} is {} bytes, exceeds the {}-byte read buffer",
                self.path.display(),
                bytes.len(),
                out.len()
            )));
        }
        out[..bytes.len()].copy_from_slice(&bytes);
        Ok(Some(bytes.len()))
    }

    fn save(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let tmp_path = self.tmp_path();
        let result = save_via_tmp(&tmp_path, &self.path, data, self.mode);
        if let Err(write_err) = &result
            && let Err(cleanup_err) = std::fs::remove_file(&tmp_path)
            && cleanup_err.kind() != io::ErrorKind::NotFound
        {
            // `NotFound` means the write failed before creating the `.tmp` at
            // all — nothing to clean up. Anything else means one exists and
            // could not be removed.
            tracing::warn!(
                path = %tmp_path.display(),
                write_error = %write_err,
                cleanup_error = %cleanup_err,
                "failed to clean up a stale .tmp file after a failed durable write; \
                 it will be overwritten by the next successful save"
            );
        }
        result
    }
}

/// Write `data` to `tmp_path`, flush it, then rename it over `path`.
/// Factored out of [`DurableStore::save`] so the `.tmp`-cleanup-on-failure
/// step in the caller has a single fallible operation to wrap.
///
/// `mode`, when set, is applied to the temporary file before the rename, so
/// the blob is already restricted the instant it becomes visible at `path`
/// (see [`FileStore::with_mode`]).
fn save_via_tmp(tmp_path: &Path, path: &Path, data: &[u8], mode: Option<u32>) -> io::Result<()> {
    let mut tmp = std::fs::File::create(tmp_path)?;
    tmp.write_all(data)?;
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt;
        tmp.set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    tmp.sync_all()?;
    std::fs::rename(tmp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_path(label: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "wayfinder-storage-test-{}-{label}-{n}.bin",
            std::process::id()
        ))
    }

    /// A store with nothing saved yet reads as a legitimately fresh store,
    /// not an error.
    #[test]
    fn load_before_any_save_is_none() {
        let path = unique_path("fresh");
        let mut store = FileStore::new(&path);
        let mut buf = [0u8; 64];

        assert_eq!(store.load(&mut buf).unwrap(), None);
    }

    /// A saved blob round-trips through load byte-for-byte.
    #[test]
    fn save_then_load_round_trips() {
        let path = unique_path("roundtrip");
        let mut store = FileStore::new(&path);
        let data = b"the quick brown fox";

        store.save(data).unwrap();

        let mut buf = [0u8; 64];
        let n = store.load(&mut buf).unwrap().unwrap();
        assert_eq!(&buf[..n], data);

        std::fs::remove_file(&path).ok();
    }

    /// A second save replaces the first, not appends to it.
    #[test]
    fn second_save_replaces_first() {
        let path = unique_path("replace");
        let mut store = FileStore::new(&path);

        store.save(b"version one").unwrap();
        store.save(b"v2").unwrap();

        let mut buf = [0u8; 64];
        let n = store.load(&mut buf).unwrap().unwrap();
        assert_eq!(&buf[..n], b"v2");

        std::fs::remove_file(&path).ok();
    }

    /// A blob larger than the caller's read buffer is an error, not a
    /// silent truncation.
    #[test]
    fn load_rejects_undersized_buffer() {
        let path = unique_path("oversized");
        let mut store = FileStore::new(&path);
        store
            .save(b"this string is longer than four bytes")
            .unwrap();

        let mut tiny = [0u8; 4];
        assert!(store.load(&mut tiny).is_err());

        std::fs::remove_file(&path).ok();
    }

    /// `save` never leaves a `.tmp` sibling behind after a successful write
    /// — it should have been renamed away, not merely copied.
    #[test]
    fn successful_save_leaves_no_tmp_sibling() {
        let path = unique_path("no-tmp-litter");
        let mut store = FileStore::new(&path);

        store.save(b"data").unwrap();

        assert!(
            !store.tmp_path().exists(),
            "a successful save must rename its .tmp file away, not leave a copy"
        );
        std::fs::remove_file(&path).ok();
    }

    /// A store carrying a secret must land on disk already restricted: the
    /// mode is applied to the `.tmp` file *before* the rename, since the
    /// rename carries the temporary file's permissions onto the target. A
    /// mode set only after the rename would leave a window in which the
    /// secret is readable by everyone.
    #[cfg(unix)]
    #[test]
    fn save_with_a_mode_applies_it_to_the_renamed_file() {
        use std::os::unix::fs::PermissionsExt;

        let path = unique_path("mode");
        let mut store = FileStore::new(&path).with_mode(0o600);

        store.save(b"a secret").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "a store given a mode must restrict the file it renames into place"
        );

        std::fs::remove_file(&path).ok();
    }

    /// Re-saving over an existing file keeps the restricted mode: the second
    /// save renames a fresh `.tmp` over the target, so the mode has to be
    /// re-applied every time rather than only on creation.
    #[cfg(unix)]
    #[test]
    fn resave_with_a_mode_keeps_the_file_restricted() {
        use std::os::unix::fs::PermissionsExt;

        let path = unique_path("mode-resave");
        let mut store = FileStore::new(&path).with_mode(0o600);

        store.save(b"first").unwrap();
        store.save(b"second").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        std::fs::remove_file(&path).ok();
    }

    /// A `save` into a directory that doesn't exist fails (no directory
    /// auto-creation — that's a caller decision, this type doesn't guess),
    /// and does not fabricate a saved blob: a subsequent `load` still finds
    /// nothing.
    #[test]
    fn save_into_missing_directory_fails_cleanly() {
        let path = std::env::temp_dir()
            .join(format!(
                "wayfinder-storage-test-{}-no-such-dir",
                std::process::id()
            ))
            .join("deep")
            .join("file.bin");
        let mut store = FileStore::new(&path);

        assert!(store.save(b"data").is_err());

        let mut buf = [0u8; 64];
        assert_eq!(store.load(&mut buf).unwrap(), None);
    }
}
