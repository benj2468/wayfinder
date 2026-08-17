//! The node's durable runtime settings: what an operator changed through the
//! management API that must still be true after a restart.
//!
//! # Why this is not simply "write the config back"
//!
//! A node's startup configuration is an operator-authored YAML file. Writing it
//! back would destroy its comments and layout, need write access to `/etc`, and
//! leave no way to tell a value the operator typed from one the dashboard set.
//! So runtime changes land here instead, as a separate blob of *overrides*: a
//! field with no override follows the YAML, which keeps editing the YAML
//! meaningful for everything the operator has not pinned, and deleting this
//! file returns the node wholly to its configured state.
//!
//! # What is persisted, and what is not
//!
//! Only settings whose lifetime is the node's: the fail-closed gate, lazy cert
//! distribution, and the mesh identity installed by `SetAuth`. Per-interface
//! knobs (Trickle bounds, participation gates) are deliberately left in memory
//! — they are keyed by interface *index*, which is a position in the startup
//! config's link list, so a persisted override would silently re-point at a
//! different link the moment an operator reorders or removes one.
//!
//! [`SettingsStore`] is the `no_std + alloc` seam the adapter writes through,
//! mirroring how `MeshAuthority` keeps the CA's `std` half out of the adapter;
//! [`SettingsFile`] is the host implementation, a thin skin over
//! [`wayfinder_storage::Persisted`] in the same shape as
//! [`CaLog`](crate::persistence).

use alloc::string::String;
use alloc::vec::Vec;

/// The mesh identity material a node was handed at runtime: the same three
/// blobs `wayfinder-tap` otherwise loads from the files an `auth:` config block
/// points at.
///
/// Deliberately one struct rather than three independent fields: a cert only
/// verifies against the anchor it was issued under, and only matches the MAC
/// derived from its own seed, so a half-updated identity is not a weaker
/// identity but a non-functional one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeIdentity {
    /// The node's 32-byte Ed25519 identity seed. Secret — it *is* the node's
    /// identity, and it is why the on-disk form is owner-only.
    pub seed: Vec<u8>,
    /// The node's membership certificate (raw `MembershipCert` bytes).
    pub cert: Vec<u8>,
    /// The mesh trust anchor (raw `TrustAnchor` bytes) the cert chains to.
    pub trust_anchor: Vec<u8>,
}

/// A node's persisted runtime settings, as a set of overrides over the startup
/// configuration.
///
/// Every field is `None` when the operator has never changed it, which is what
/// keeps the startup config authoritative for anything not explicitly set at
/// runtime. Also used as the *update* type: applying one merges its present
/// fields onto the stored settings and leaves the absent ones alone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeSettings {
    /// Whether the node fails closed while it holds no membership cert.
    pub require_auth: Option<bool>,
    /// Whether the node's OGMs carry a cert fingerprint rather than the full
    /// membership cert.
    pub lazy_cert_distribution: Option<bool>,
    /// The mesh identity installed over the management API.
    pub identity: Option<NodeIdentity>,
}

impl NodeSettings {
    /// Merge `update`'s present fields onto `self`, leaving the absent ones as
    /// they are.
    pub fn merge(&mut self, update: NodeSettings) {
        if let Some(require_auth) = update.require_auth {
            self.require_auth = Some(require_auth);
        }
        if let Some(lazy) = update.lazy_cert_distribution {
            self.lazy_cert_distribution = Some(lazy);
        }
        if let Some(identity) = update.identity {
            self.identity = Some(identity);
        }
    }

    /// Whether this carries any override at all — false for the settings a
    /// node with no persisted state starts from.
    pub fn is_empty(&self) -> bool {
        self.require_auth.is_none()
            && self.lazy_cert_distribution.is_none()
            && self.identity.is_none()
    }
}

/// Where a node's runtime settings are durably recorded.
///
/// Byte-oriented and free of `std` so the adapter can write through it on any
/// target, the same way [`MeshAuthority`](crate::MeshAuthority) keeps the CA's
/// host half out of the `no_std` layer.
pub trait SettingsStore {
    /// The settings currently recorded.
    fn settings(&self) -> &NodeSettings;

    /// Merge `update` into the recorded settings and commit them durably.
    ///
    /// `Err` when the change could not be made durable, and in that case the
    /// recorded settings are left exactly as they were: a caller must treat it
    /// as "this did not take effect", not "this is not durable yet", and must
    /// not apply the change in memory either — an operator told a security
    /// setting is in force has a right to expect it to survive a restart.
    fn persist(&mut self, update: NodeSettings) -> Result<(), String>;
}

#[cfg(feature = "std")]
pub use file::SettingsFile;

#[cfg(feature = "std")]
mod file {
    use super::NodeIdentity;
    use super::NodeSettings;
    use super::SettingsStore;

    use alloc::format;
    use alloc::string::String;
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;
    use std::path::Path;
    use std::path::PathBuf;

    use serde::Deserialize;
    use serde::Serialize;
    use wayfinder_storage::Codec;
    use wayfinder_storage::FileStore;
    use wayfinder_storage::LoadError;
    use wayfinder_storage::PersistError;
    use wayfinder_storage::PersistOutcome;
    use wayfinder_storage::Persisted;

    /// Largest encoded settings blob [`SettingsFile::load`] will read. Chosen
    /// like `CaLog`'s: far above the few hundred bytes this actually occupies
    /// (three short blobs and two flags), small enough that the startup
    /// allocation is not worth worrying about, and a hard ceiling rather than
    /// a silent truncation.
    const MAX_SETTINGS_BYTES: usize = 64 * 1024;

    /// Current on-disk schema version. Bump this — and add an ordered
    /// migration into [`parse_state`] — whenever [`SettingsState`]'s shape
    /// changes.
    const CURRENT_SETTINGS_VERSION: u32 = 1;

    /// Permission bits the settings file is written with: owner-only, because
    /// it carries the node's identity seed once `SetAuth` has installed one.
    const SETTINGS_FILE_MODE: u32 = 0o600;

    /// The persisted settings blob (current schema).
    ///
    /// Its own JSON schema rather than the management-API wire form, so the
    /// two evolve on separate schedules — the same split `CaLog` makes.
    #[derive(Serialize, Deserialize, Default)]
    struct SettingsState {
        /// The schema version this blob was written under.
        version: u32,
        /// Whether the node fails closed with no cert installed.
        #[serde(default)]
        require_auth: Option<bool>,
        /// Whether OGMs carry a cert fingerprint rather than the full cert.
        #[serde(default)]
        lazy_cert_distribution: Option<bool>,
        /// The mesh identity installed at runtime.
        #[serde(default)]
        identity: Option<IdentityRecord>,
    }

    /// One installed identity in the on-disk blob. Byte vectors are stored as
    /// arrays of numbers by `serde_json`, which is verbose but needs no
    /// encoding scheme of its own — and this blob is written once per
    /// enrollment, not on a hot path.
    #[derive(Serialize, Deserialize, Clone)]
    struct IdentityRecord {
        seed: Vec<u8>,
        cert: Vec<u8>,
        trust_anchor: Vec<u8>,
    }

    /// Just enough of the blob to read `version` before committing to a full
    /// parse, so [`parse_state`] can dispatch to the right schema.
    #[derive(Deserialize)]
    struct VersionProbe {
        version: u32,
    }

    /// Decode a settings blob, dispatching on its version.
    ///
    /// Any outcome that isn't a clean, known-version blob is `Err` rather than
    /// an empty default: starting empty would silently drop the fail-closed
    /// gate and the installed identity, taking a node that was configured to
    /// refuse unauthenticated operation and quietly opening it up.
    fn parse_state(bytes: &[u8], path: Option<&Path>) -> Result<SettingsState, String> {
        let name = || match path {
            Some(p) => format!("node settings file {}", p.display()),
            None => "node settings blob".to_string(),
        };
        let corrupt = |e: serde_json::Error| {
            format!(
                "{} is corrupt or not a recognized settings blob: {e}",
                name()
            )
        };
        let probe: VersionProbe = serde_json::from_slice(bytes).map_err(corrupt)?;
        match probe.version {
            CURRENT_SETTINGS_VERSION => serde_json::from_slice(bytes).map_err(corrupt),
            v if v > CURRENT_SETTINGS_VERSION => Err(format!(
                "{} has version {v} but this build only understands up to version \
                 {CURRENT_SETTINGS_VERSION}; refusing to load a newer-than-known blob \
                 (upgrade the node before restarting it against this file)",
                name()
            )),
            v => Err(format!(
                "{} has version {v}, and this build has no migration path from it to \
                 version {CURRENT_SETTINGS_VERSION}",
                name()
            )),
        }
    }

    /// Translates [`NodeSettings`] to and from the on-disk blob — the only
    /// caller-specific piece [`Persisted`] needs.
    struct SettingsCodec {
        /// The file this codec's blobs come from, kept only to name it in
        /// decode errors; `None` for an in-memory-only store.
        path: Option<PathBuf>,
    }

    impl Codec<NodeSettings> for SettingsCodec {
        type Error = String;
        type Encoded = Vec<u8>;

        fn encode(&self, value: &NodeSettings) -> Result<Vec<u8>, String> {
            let state = SettingsState {
                version: CURRENT_SETTINGS_VERSION,
                require_auth: value.require_auth,
                lazy_cert_distribution: value.lazy_cert_distribution,
                identity: value.identity.as_ref().map(|i| IdentityRecord {
                    seed: i.seed.clone(),
                    cert: i.cert.clone(),
                    trust_anchor: i.trust_anchor.clone(),
                }),
            };
            // Compact rather than pretty, unlike the CA log: this blob carries
            // a secret, so it is not meant to be read over someone's shoulder.
            serde_json::to_vec(&state)
                .map_err(|e| format!("failed to serialize node settings: {e}"))
        }

        fn decode(&self, bytes: &[u8]) -> Result<NodeSettings, String> {
            let state = parse_state(bytes, self.path.as_deref())?;
            Ok(NodeSettings {
                require_auth: state.require_auth,
                lazy_cert_distribution: state.lazy_cert_distribution,
                identity: state.identity.map(|i| NodeIdentity {
                    seed: i.seed,
                    cert: i.cert,
                    trust_anchor: i.trust_anchor,
                }),
            })
        }
    }

    /// A node's runtime settings backed by a file.
    ///
    /// As with `CaLog`, the wrapped value is reachable only through
    /// [`SettingsStore::settings`] and [`SettingsStore::persist`], so "every
    /// mutation is followed by a persist attempt" is a property of the type
    /// rather than something call sites must remember.
    pub struct SettingsFile {
        persisted: Persisted<NodeSettings, Option<FileStore>, SettingsCodec>,
        /// Mirrors the path inside `persisted`'s own store and codec (whose
        /// fields are private), purely so a persist failure can name the file
        /// — `DurableStore::Error` is a bare `io::Error` and carries no path.
        path: Option<PathBuf>,
    }

    impl SettingsFile {
        /// Load the settings recorded at `path`, or start empty when the file
        /// does not exist yet.
        ///
        /// `None` builds an in-memory-only store, which accepts changes and
        /// forgets them on restart — the behavior of a node with no runtime
        /// state path configured.
        ///
        /// A corrupt or newer-than-known file is `Err`: see [`parse_state`].
        pub fn load(path: Option<PathBuf>) -> Result<Self, String> {
            let codec = SettingsCodec { path: path.clone() };
            let persisted = match &path {
                Some(path) => {
                    let mut buf = vec![0u8; MAX_SETTINGS_BYTES];
                    Persisted::load(
                        Some(FileStore::new(path).with_mode(SETTINGS_FILE_MODE)),
                        codec,
                        NodeSettings::default(),
                        &mut buf,
                    )
                    .map_err(|e| match e {
                        LoadError::Store(io_err) => format!(
                            "failed to read node settings file {}: {io_err}",
                            path.display()
                        ),
                        LoadError::Decode(msg) => msg,
                    })?
                }
                None => Persisted::new(NodeSettings::default(), None, codec),
            };
            Ok(Self { persisted, path })
        }

        /// Whether this store actually writes anywhere. A node without a
        /// runtime state path still accepts settings changes — it just cannot
        /// carry them across a restart, which is worth saying out loud at
        /// startup rather than discovering after a reboot.
        pub fn is_durable(&self) -> bool {
            self.path.is_some()
        }

        /// Turn a persist outcome into the error string the management API
        /// answers with, naming the offending file — `DurableStore::Error` is
        /// a bare `io::Error` and carries no path of its own.
        ///
        /// Also logged: the caller propagates this to one client, while an
        /// operator watching the node needs to see that its security settings
        /// have stopped being durable at all. `warn!` rather than `error!` —
        /// the node keeps running on its previous settings, which is a handled
        /// outcome rather than a violated invariant.
        fn report_persist_outcome(
            &self,
            outcome: PersistOutcome<std::io::Error, String>,
        ) -> Result<(), String> {
            outcome.map_err(|e| {
                let path = self
                    .path
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();
                let msg = match e {
                    PersistError::Encode(encode_err) => {
                        format!("failed to persist node settings to {path}: {encode_err}")
                    }
                    PersistError::Store(io_err) => {
                        format!("failed to persist node settings to {path}: {io_err}")
                    }
                };
                tracing::warn!(
                    %path,
                    "node settings change rolled back: it could not be made durable"
                );
                msg
            })
        }
    }

    impl SettingsStore for SettingsFile {
        fn settings(&self) -> &NodeSettings {
            self.persisted.get()
        }

        fn persist(&mut self, update: NodeSettings) -> Result<(), String> {
            let (_, outcome) = self.persisted.mutate(|settings| settings.merge(update));
            self.report_persist_outcome(outcome)
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use alloc::vec;
    use std::path::PathBuf;

    /// A unique per-call settings path, so parallel tests never collide.
    fn unique_path(label: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "wayfinder-settings-test-{}-{label}-{n}.json",
            std::process::id()
        ))
    }

    fn identity() -> NodeIdentity {
        NodeIdentity {
            seed: vec![7; 32],
            cert: vec![1, 2, 3],
            trust_anchor: vec![4, 5, 6],
        }
    }

    /// A node that has never had a setting changed starts from no overrides at
    /// all, so every value follows its startup configuration.
    #[test]
    fn a_missing_file_loads_as_no_overrides() {
        let store = SettingsFile::load(Some(unique_path("missing"))).unwrap();

        assert!(store.settings().is_empty());
    }

    /// The point of the whole module: a setting changed at runtime is still in
    /// force after the process restarts.
    #[test]
    fn settings_survive_a_restart() {
        let path = unique_path("restart");

        {
            let mut store = SettingsFile::load(Some(path.clone())).unwrap();
            store
                .persist(NodeSettings {
                    require_auth: Some(true),
                    identity: Some(identity()),
                    ..Default::default()
                })
                .unwrap();
        } // Dropped here, simulating a process restart.

        let store = SettingsFile::load(Some(path.clone())).unwrap();
        assert_eq!(store.settings().require_auth, Some(true));
        assert_eq!(store.settings().identity, Some(identity()));
        assert_eq!(
            store.settings().lazy_cert_distribution,
            None,
            "a setting never changed keeps following the startup config"
        );

        std::fs::remove_file(&path).ok();
    }

    /// An update names only what it changes: persisting one setting must not
    /// wipe another an operator set earlier.
    #[test]
    fn a_later_update_merges_rather_than_replaces() {
        let path = unique_path("merge");
        let mut store = SettingsFile::load(Some(path.clone())).unwrap();

        store
            .persist(NodeSettings {
                require_auth: Some(true),
                ..Default::default()
            })
            .unwrap();
        store
            .persist(NodeSettings {
                lazy_cert_distribution: Some(true),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(store.settings().require_auth, Some(true));
        assert_eq!(store.settings().lazy_cert_distribution, Some(true));

        std::fs::remove_file(&path).ok();
    }

    /// Turning a setting back off is an override to `false`, not the absence
    /// of one — otherwise disabling the fail-closed gate would silently revert
    /// to whatever the YAML says on the next restart.
    #[test]
    fn turning_a_setting_off_persists_as_false() {
        let path = unique_path("off");

        {
            let mut store = SettingsFile::load(Some(path.clone())).unwrap();
            store
                .persist(NodeSettings {
                    require_auth: Some(true),
                    ..Default::default()
                })
                .unwrap();
            store
                .persist(NodeSettings {
                    require_auth: Some(false),
                    ..Default::default()
                })
                .unwrap();
        } // Dropped here, simulating a process restart.

        let store = SettingsFile::load(Some(path.clone())).unwrap();
        assert_eq!(store.settings().require_auth, Some(false));

        std::fs::remove_file(&path).ok();
    }

    /// The file carries the node's identity seed, so it must not be readable
    /// by anyone but its owner.
    #[cfg(unix)]
    #[test]
    fn the_settings_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let path = unique_path("mode");
        let mut store = SettingsFile::load(Some(path.clone())).unwrap();
        store
            .persist(NodeSettings {
                identity: Some(identity()),
                ..Default::default()
            })
            .unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the settings file carries the identity seed and must be owner-only"
        );

        std::fs::remove_file(&path).ok();
    }

    /// A corrupt file fails closed rather than starting empty: silently
    /// dropping a persisted `require_auth` would put a node that was told to
    /// refuse unauthenticated operation back on the open mesh.
    #[test]
    fn a_corrupt_file_fails_closed() {
        let path = unique_path("corrupt");
        std::fs::write(&path, b"not json").unwrap();

        let err = match SettingsFile::load(Some(path.clone())) {
            Ok(_) => panic!("a corrupt settings file must not be treated as empty"),
            Err(e) => e,
        };
        assert!(
            err.to_lowercase().contains("settings"),
            "the error should name the settings file, got: {err}"
        );

        std::fs::remove_file(&path).ok();
    }

    /// A blob written by a newer node is refused rather than reinterpreted
    /// under the older schema.
    #[test]
    fn a_newer_version_fails_closed() {
        let path = unique_path("newer");
        std::fs::write(&path, br#"{"version": 999999}"#).unwrap();

        assert!(SettingsFile::load(Some(path.clone())).is_err());

        std::fs::remove_file(&path).ok();
    }

    /// A change that cannot be written is reported as a failure *and* leaves
    /// the in-memory settings untouched, so the node never runs a setting it
    /// has already told the operator it could not keep.
    #[test]
    fn a_failed_write_reports_an_error_and_rolls_back() {
        let dir = std::env::temp_dir().join(format!(
            "wayfinder-settings-test-{}-nodir",
            std::process::id()
        ));
        std::fs::remove_dir_all(&dir).ok();
        let mut store = SettingsFile::load(Some(dir.join("settings.json"))).unwrap();

        let result = store.persist(NodeSettings {
            require_auth: Some(true),
            ..Default::default()
        });

        assert!(result.is_err(), "an unwritable change must fail");
        assert!(
            store.settings().is_empty(),
            "and must not be left applied in memory"
        );
    }

    /// A node with no runtime state path still accepts changes — it simply
    /// cannot carry them across a restart, and says so.
    #[test]
    fn an_in_memory_store_accepts_changes_but_is_not_durable() {
        let mut store = SettingsFile::load(None).unwrap();

        store
            .persist(NodeSettings {
                require_auth: Some(true),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(store.settings().require_auth, Some(true));
        assert!(!store.is_durable());
    }
}
