//! Durable on-disk snapshot of [`CertAuthority`](crate::CertAuthority)'s
//! issued-certificate log and held-CSR store, so the impersonation guard,
//! revocations, and pending operator approvals survive a restart.
//!
//! The on-disk schema is independent of the management-API protobuf wire
//! format (which is free to evolve on its own schedule): a JSON snapshot with
//! an explicit [`CURRENT_STATE_VERSION`], so a future format change ships with
//! an encoded migration rather than silently reinterpreting old bytes.
//!
//! [`CaLog`] itself is a thin, CA-specific skin over
//! [`wayfinder_storage::Persisted`]: the "mutate, then persist, then roll
//! back in memory if the persist failed" orchestration lives entirely in
//! that generic type now — this module only supplies *what's inside the
//! blob* ([`CaLogState`]) and *how it's encoded* ([`CaStateCodec`]).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use std::path::Path;
use std::path::PathBuf;
use wayfinder_protos::service::IssuedCertData;

use serde::Deserialize;
use serde::Serialize;
use wayfinder_storage::Codec;
use wayfinder_storage::FileStore;
use wayfinder_storage::LoadError;
use wayfinder_storage::PersistError;
use wayfinder_storage::PersistOutcome;
use wayfinder_storage::Persisted;

use crate::authority::HeldCsr;

/// Largest encoded CA-state snapshot [`CaLog::load`] will read. `FileStore`
/// (per `DurableStore::load`'s contract) needs a caller-supplied buffer
/// rather than allocating to fit the file, so `CaLog::load` allocates (and
/// zero-fills) a buffer this size up front, once, per load — 1 MiB is
/// generous (tens-to-hundreds of times) over the "tens of KB" this snapshot
/// is expected to occupy in practice, without being large enough for the
/// startup allocation itself to be worth worrying about; a snapshot that
/// somehow exceeds it fails closed (via `DurableStore`'s own oversized-blob
/// error) rather than silently truncating.
const MAX_STATE_BYTES: usize = 1024 * 1024;

/// Current on-disk schema version. Bump this — and add an ordered migration
/// from the prior version into [`parse_state`] — whenever [`CaState`]'s shape
/// changes.
pub(crate) const CURRENT_STATE_VERSION: u32 = 3;

/// Permission bits the CA state file is written with.
///
/// Restricted rather than left to the umask because the snapshot carries the
/// enrollment token once an operator has set one at runtime — a shared secret
/// that gates who may join the mesh. The file held no secrets before version 3,
/// so this tightens the mode of an existing snapshot on its first rewrite.
const STATE_FILE_MODE: u32 = 0o600;

/// One issued-certificate record in the on-disk snapshot. Mirrors
/// [`IssuedCertData`] but with fixed-size arrays (the snapshot's own schema,
/// decoupled from the protobuf wire form — `IssuedCertData` is prost-generated
/// and only derives `Serialize`, never `Deserialize`, so it could not round-trip
/// as an on-disk format even if we wanted to reuse it directly).
#[derive(Serialize, Deserialize, Clone)]
struct IssuedRecord {
    /// The certificate holder's MAC.
    node_mac: [u8; 6],
    /// The holder's Ed25519 identity public key.
    ed_pubkey: [u8; 32],
    /// Validity window start (unix seconds).
    not_before: u64,
    /// Validity window end (unix seconds).
    not_after: u64,
    /// Whether this certificate has been revoked.
    revoked: bool,
}

impl IssuedRecord {
    /// Convert from the in-memory `IssuedCertData` the authority already
    /// keeps for `ListCerts`. `None` if the byte-slice fields are the wrong
    /// length, which the authority never produces itself — callers must not
    /// let that `None` vanish silently (see the call site in
    /// [`CaStateCodec::encode`]), since a dropped record can carry a
    /// revocation.
    fn from_proto(c: &IssuedCertData) -> Option<Self> {
        Some(Self {
            node_mac: c.node_mac.as_slice().try_into().ok()?,
            ed_pubkey: c.ed_pubkey.as_slice().try_into().ok()?,
            not_before: c.not_before,
            not_after: c.not_after,
            revoked: c.revoked,
        })
    }

    /// Convert back to the wire/`ListCerts` representation.
    fn to_proto(&self) -> IssuedCertData {
        IssuedCertData {
            node_mac: self.node_mac.to_vec(),
            ed_pubkey: self.ed_pubkey.to_vec(),
            not_before: self.not_before,
            not_after: self.not_after,
            revoked: self.revoked,
        }
    }
}

/// The persisted CA state (current schema, [`CURRENT_STATE_VERSION`]): the
/// issued-certificate log (which also carries revocation status via
/// [`IssuedRecord::revoked`]) and the held-CSR store.
///
/// The held-CSR section reuses [`HeldCsr`]/`CsrStatus` directly (via
/// `#[derive(Serialize, Deserialize)]` on those types in `authority.rs`)
/// rather than mirroring them into separate on-disk record types the way
/// [`IssuedRecord`] mirrors `IssuedCertData`: unlike `IssuedCertData`,
/// `HeldCsr`/`CsrStatus` are plain crate-internal state with no wire contract
/// pulling them in a different direction, so a decoupled mirror type would
/// only be duplicated shape with no actual independence.
#[derive(Serialize, Deserialize)]
struct CaState {
    /// The schema version this snapshot was written under.
    version: u32,
    /// The issued-certificate log.
    issued: Vec<IssuedRecord>,
    /// The held-CSR store (pending/approved/denied, awaiting or past operator
    /// review). Added in version 2 — see [`CaStateV1`] for the prior shape.
    held: Vec<HeldCsr>,
    /// The operator's runtime enrollment-policy overrides. Added in version 3;
    /// a version-2 snapshot migrates forward with none, which is exactly the
    /// behavior it had (every field following the startup config).
    #[serde(default)]
    policy: PolicyOverrides,
}

/// The runtime enrollment-policy overrides an operator has applied, as stored.
///
/// Every field is an *override*, not a value: `None` means the operator never
/// changed it and the authority keeps following its startup `ProviderConfig`,
/// so editing the YAML still moves anything the operator has not pinned. Only
/// what was explicitly set at runtime is remembered — which is what makes
/// "revert to the config" a matter of deleting the override rather than
/// guessing which value the operator meant.
#[derive(Serialize, Deserialize, Clone, Default)]
pub(crate) struct PolicyOverrides {
    /// Whether submitted CSRs are parked pending operator approval.
    #[serde(default)]
    pub(crate) require_approval: Option<bool>,
    /// The validity window applied to issued certificates, in seconds.
    #[serde(default)]
    pub(crate) cert_ttl_secs: Option<u64>,
    /// The shared enrollment token, when the operator has changed it.
    ///
    /// [`TokenOverride`] rather than the `Option<Option<String>>` this looks
    /// like it wants to be: JSON has one `null`, so a nested option encodes
    /// "never overridden" and "overridden to no token" identically, and a
    /// deliberately cleared token would come back as unset and silently revert
    /// to the configured one — re-closing an enrollment the operator opened.
    #[serde(default)]
    pub(crate) enrollment_token: Option<TokenOverride>,
}

/// What an operator changed the shared enrollment token to.
///
/// Distinct from `TokenUpdate` in the management-API layer, which is the same
/// two cases as a *request*: this one is the on-disk schema, free to evolve on
/// its own schedule the way the rest of this snapshot is.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) enum TokenOverride {
    /// The token was cleared: enrollment is open (TOFU).
    Cleared,
    /// The token was set to this value; a CSR must present it.
    Set(String),
}

/// Version 1 of the on-disk schema: the issued-certificate log only, with no
/// held-CSR section at all (not even an empty one) — held-CSR persistence was
/// introduced in version 2. Kept so [`parse_state`] can migrate a snapshot
/// written under the older schema.
#[derive(Deserialize)]
struct CaStateV1 {
    issued: Vec<IssuedRecord>,
}

/// Version 2 of the on-disk schema: issued certificates and held CSRs, with no
/// enrollment-policy section — the policy was startup-config-only until
/// version 3. Kept so [`parse_state`] can migrate a version-2 snapshot.
#[derive(Deserialize)]
struct CaStateV2 {
    issued: Vec<IssuedRecord>,
    held: Vec<HeldCsr>,
}

/// Migrate a version-1 snapshot forward: the held-CSR store didn't exist yet,
/// so it starts empty (the same behavior a version-1-only node had — held
/// CSRs are simply not something that schema could have durably remembered).
fn migrate_v1_to_v2(v1: CaStateV1) -> CaStateV2 {
    CaStateV2 {
        issued: v1.issued,
        held: Vec::new(),
    }
}

/// Migrate a version-2 snapshot forward: no policy overrides were recorded, so
/// the authority follows its startup `ProviderConfig` for every field —
/// precisely the behavior a version-2 node had.
fn migrate_v2_to_v3(v2: CaStateV2) -> CaState {
    CaState {
        version: 3,
        issued: v2.issued,
        held: v2.held,
        policy: PolicyOverrides::default(),
    }
}

/// Just enough of the snapshot to read `version` before committing to a full
/// parse, so [`parse_state`] can dispatch to the right schema/migration.
#[derive(Deserialize)]
struct VersionProbe {
    version: u32,
}

/// Decode a CA state snapshot's raw bytes (as read from a [`FileStore`] via
/// [`CaStateCodec::decode`]), dispatching to the right schema/migration by
/// probing `version` first. `path`, when known, is used only to name the
/// offending file in error messages — `None` when this snapshot isn't backed
/// by a real file (in-memory-only `CaLog`s never reach this function, since
/// their `Persisted` store starts empty rather than loading anything).
///
/// Any outcome that isn't a clean, known-version snapshot (after migration)
/// — corrupt JSON, a foreign shape, or a newer-than-known version — is
/// `Err`: the caller must fail closed rather than silently starting empty,
/// since that would silently un-revoke every previously-revoked node and
/// forget every pending approval.
fn parse_state(bytes: &[u8], path: Option<&Path>) -> Result<CaState, String> {
    let name = || match path {
        Some(p) => format!("CA state file {}", p.display()),
        None => "CA state snapshot".to_string(),
    };
    let corrupt = |e: serde_json::Error| {
        format!(
            "{} is corrupt or not a recognized CA state snapshot: {e}",
            name()
        )
    };
    let probe: VersionProbe = serde_json::from_slice(bytes).map_err(corrupt)?;
    match probe.version {
        1 => {
            let v1: CaStateV1 = serde_json::from_slice(bytes).map_err(corrupt)?;
            Ok(migrate_v2_to_v3(migrate_v1_to_v2(v1)))
        }
        2 => {
            let v2: CaStateV2 = serde_json::from_slice(bytes).map_err(corrupt)?;
            Ok(migrate_v2_to_v3(v2))
        }
        CURRENT_STATE_VERSION => serde_json::from_slice(bytes).map_err(corrupt),
        v if v > CURRENT_STATE_VERSION => Err(format!(
            "{} has version {v} but this build only understands up to version \
             {CURRENT_STATE_VERSION}; refusing to load a newer-than-known snapshot (upgrade the \
             node before restarting it against this state file)",
            name()
        )),
        v => Err(format!(
            "{} has version {v}, and this build has no migration path from it to version \
             {CURRENT_STATE_VERSION}",
            name()
        )),
    }
}

/// The in-memory value a [`CaLog`] wraps in [`Persisted`]: everything
/// `authority.rs` can mutate. Cheap to `Clone` at the scale this is meant for
/// (see [`Persisted::mutate`]'s own doc on why that bound exists) — needed so
/// a failed persist can roll the in-memory value back to its pre-mutation
/// snapshot.
#[derive(Clone)]
struct CaLogState {
    issued: Vec<IssuedCertData>,
    held: Vec<HeldCsr>,
    policy: PolicyOverrides,
}

impl CaLogState {
    /// The state a fresh CA (no snapshot loaded yet) starts from.
    fn empty() -> Self {
        Self {
            issued: Vec::new(),
            held: Vec::new(),
            policy: PolicyOverrides::default(),
        }
    }
}

/// Translates [`CaLogState`] to/from the CA's on-disk JSON snapshot
/// ([`CaState`]) — the only caller-specific piece [`Persisted`] needs;
/// everything about *when* to encode/decode and *what to do with the bytes*
/// is [`Persisted`]'s own concern, not this type's.
struct CaStateCodec {
    /// The state file this codec's blobs are read from/written to, kept only
    /// to name the offending file in error messages — `None` for an
    /// in-memory-only `CaLog`, where `decode` is never reached and `encode`'s
    /// own errors never named a path anyway.
    path: Option<PathBuf>,
}

impl Codec<CaLogState> for CaStateCodec {
    type Error = String;
    type Encoded = Vec<u8>;

    fn encode(&self, value: &CaLogState) -> Result<Vec<u8>, String> {
        let mut issued = Vec::with_capacity(value.issued.len());
        for c in &value.issued {
            match IssuedRecord::from_proto(c) {
                Some(record) => issued.push(record),
                None => tracing::warn!(
                    node_mac_len = c.node_mac.len(),
                    ed_pubkey_len = c.ed_pubkey.len(),
                    "dropping malformed issued-cert record from CA state snapshot; its \
                     revocation status, if any, will not survive a restart"
                ),
            }
        }
        let state = CaState {
            version: CURRENT_STATE_VERSION,
            issued,
            held: value.held.clone(),
            policy: value.policy.clone(),
        };
        serde_json::to_vec_pretty(&state).map_err(|e| format!("failed to serialize CA state: {e}"))
    }

    fn decode(&self, bytes: &[u8]) -> Result<CaLogState, String> {
        let state = parse_state(bytes, self.path.as_deref())?;
        Ok(CaLogState {
            issued: state.issued.iter().map(IssuedRecord::to_proto).collect(),
            held: state.held,
            policy: state.policy,
        })
    }
}

/// The authority's durable state: the issued-certificate log and the
/// held-CSR store, both backed by one snapshot file — a thin skin over
/// [`Persisted`], which owns the actual "mutate, persist, roll back on
/// failure" mechanics (see [`Self::mutate_issued`]/[`Self::mutate_held`]/
/// [`Self::mutate_issued_and_held`]).
///
/// `persisted`'s fields are private to [`Persisted`] itself, so
/// `authority.rs` has no way to reach either `Vec` except through the
/// read-only [`Self::issued`]/[`Self::held`] views or the `mutate_*` methods
/// — this is what makes "every mutation is followed by a persist attempt" a
/// property of the type rather than a convention call sites must remember.
/// This is a per-*call* guarantee: an operator action that only needs to
/// touch one collection performs one `mutate_*` call and one persist, but an
/// action that must keep both collections in lockstep (`approve_csr`, which
/// records a newly-issued certificate and flips the held entry to
/// `Approved`) uses [`Self::mutate_issued_and_held`] so that one persist
/// covers the whole action rather than durably splitting across two — see
/// that method's own doc for the impersonation-guard gap a split write would
/// otherwise open.
pub(crate) struct CaLog {
    persisted: Persisted<CaLogState, Option<FileStore>, CaStateCodec>,
    /// Mirrors the path (if any) inside `persisted`'s own `FileStore` (and
    /// inside `persisted`'s `CaStateCodec`, which keeps its own copy for its
    /// decode-error messages) — three copies of one fact, purely so each
    /// layer can name the offending file in its own error/log messages
    /// without a way to read it back out of `Persisted`, whose `store` and
    /// `codec` fields are both private. Safe only because none of the three
    /// copies is ever mutated after `Self::load`/`Self::empty` builds them
    /// all from the same `state_path` value — a future change that lets one
    /// of them change independently (e.g. rebinding the store) would need
    /// to keep all three in sync by hand. Used by [`Self::mutate_issued`]/
    /// [`Self::mutate_held`]/[`Self::mutate_issued_and_held`] (via
    /// [`Self::report_persist_outcome`]) to name the offending file when a
    /// persist's underlying I/O fails — `DurableStore::Error` (a bare
    /// `io::Error` for `FileStore`) carries no path of its own.
    state_path: Option<PathBuf>,
}

impl CaLog {
    /// An empty, in-memory-only log (no snapshot file). Used by
    /// [`CertAuthority::new`](crate::CertAuthority::new), which has no
    /// `ProviderConfig` to read a `state_path` from.
    pub(crate) fn empty() -> Self {
        Self {
            persisted: Persisted::new(CaLogState::empty(), None, CaStateCodec { path: None }),
            state_path: None,
        }
    }

    /// Build a log for `state_path`. When `Some`, the existing snapshot (if
    /// any) is loaded now via a [`FileStore`] — migrating an older schema
    /// version if needed; a corrupt, foreign, or newer-than-known snapshot is
    /// `Err` (fail closed — see [`parse_state`]). `None` behaves like
    /// [`Self::empty`].
    pub(crate) fn load(state_path: Option<PathBuf>) -> Result<Self, String> {
        let codec = CaStateCodec {
            path: state_path.clone(),
        };
        let persisted = match &state_path {
            Some(path) => {
                let mut buf = vec![0u8; MAX_STATE_BYTES];
                Persisted::load(
                    Some(FileStore::new(path).with_mode(STATE_FILE_MODE)),
                    codec,
                    CaLogState::empty(),
                    &mut buf,
                )
                .map_err(|e| match e {
                    LoadError::Store(io_err) => {
                        format!("failed to read CA state file {}: {io_err}", path.display())
                    }
                    LoadError::Decode(msg) => msg,
                })?
            }
            None => Persisted::new(CaLogState::empty(), None, codec),
        };
        Ok(Self {
            persisted,
            state_path,
        })
    }

    /// Read-only view of the issued-certificate log.
    pub(crate) fn issued(&self) -> &[IssuedCertData] {
        &self.persisted.get().issued
    }

    /// Read-only view of the held-CSR store.
    pub(crate) fn held(&self) -> &[HeldCsr] {
        &self.persisted.get().held
    }

    /// Read-only view of the operator's runtime enrollment-policy overrides.
    pub(crate) fn policy(&self) -> &PolicyOverrides {
        &self.persisted.get().policy
    }

    /// Run `f` against the enrollment-policy overrides, then attempt to
    /// persist the full state, with the same rollback guarantee as
    /// [`Self::mutate_held`]: a failed persist leaves the overrides as they
    /// were, so an operator is never told a security setting took effect when
    /// the next restart would discard it.
    pub(crate) fn mutate_policy<R>(
        &mut self,
        f: impl FnOnce(&mut PolicyOverrides) -> R,
    ) -> (R, Result<(), String>) {
        let (result, persisted) = self.persisted.mutate(|state| f(&mut state.policy));
        (result, self.report_persist_outcome(persisted))
    }

    /// Run `f` against the issued-certificate log, then attempt to persist
    /// the full state (issued + held) to `state_path` (if set), returning
    /// both `f`'s result and the persist outcome so the caller can decide how
    /// to react to a durability failure (see [`Self::mutate_held`] for the
    /// shared persist behavior).
    pub(crate) fn mutate_issued<R>(
        &mut self,
        f: impl FnOnce(&mut Vec<IssuedCertData>) -> R,
    ) -> (R, Result<(), String>) {
        let (result, persisted) = self.persisted.mutate(|state| f(&mut state.issued));
        (result, self.report_persist_outcome(persisted))
    }

    /// Run `f` against the held-CSR store, then attempt to persist the full
    /// state (issued + held) to `state_path` (if set) — the only way
    /// `authority.rs` can mutate either collection, so a persist attempt can
    /// never be forgotten. Returns `f`'s result alongside the persist
    /// outcome: a failed persist **rolls the entire state (both `issued` and
    /// `held`) back** to what it was before `f` ran, via
    /// [`Persisted::mutate`]'s own rollback guarantee, so the in-memory log
    /// never diverges from what's durably stored. `f`'s own return value is
    /// still handed back regardless — it's the caller's business, not tied
    /// to whether the mutation stuck — but the caller must treat a
    /// persist-failure `Err` as "this did not take effect", not just "this
    /// isn't durable yet", and is expected to propagate it to whoever asked
    /// for the mutation, since "durable" is exactly what a caller of a
    /// CA-mutating RPC has a right to assume `Ok` means.
    pub(crate) fn mutate_held<R>(
        &mut self,
        f: impl FnOnce(&mut Vec<HeldCsr>) -> R,
    ) -> (R, Result<(), String>) {
        let (result, persisted) = self.persisted.mutate(|state| f(&mut state.held));
        (result, self.report_persist_outcome(persisted))
    }

    /// Run `f` against *both* the issued-certificate log and the held-CSR
    /// store, then attempt to persist the combined result as a single write
    /// — for the one caller (`CertAuthority::approve_csr`) that must record a
    /// newly-issued certificate and flip its held entry to `Approved` as one
    /// durable unit, not two independent `mutate_issued`/`mutate_held` calls.
    ///
    /// That distinction matters because of [`Self::mutate_held`]'s own
    /// rollback guarantee: two separate calls means two separate persists,
    /// so if the *first* (recording the cert) durably succeeds but the
    /// *second* (flipping the held entry to `Approved`) fails and rolls
    /// back, the held entry reverts to `Pending` while the certificate stays
    /// durably `issued` — an operator who sees "approve failed" and calls
    /// `deny_csr` on the now-`Pending`-again entry gets a "successful"
    /// denial that never touches `issued`, silently leaving an
    /// already-issued, still-valid certificate un-revocable through the
    /// normal held-CSR flow. Running both mutations inside one
    /// [`Persisted::mutate`] call closes that gap: either both land
    /// durably, or [`Persisted::mutate`]'s rollback undoes both together.
    pub(crate) fn mutate_issued_and_held<R>(
        &mut self,
        f: impl FnOnce(&mut Vec<IssuedCertData>, &mut Vec<HeldCsr>) -> R,
    ) -> (R, Result<(), String>) {
        let (result, persisted) = self
            .persisted
            .mutate(|state| f(&mut state.issued, &mut state.held));
        (result, self.report_persist_outcome(persisted))
    }

    /// Turn a [`Persisted::mutate`] outcome into the `Result<(), String>`
    /// `authority.rs` expects, logging a `warn!` on the way through a
    /// failure. `Persisted` itself never logs (it's a generic crate with no
    /// notion of "CA state") — this is that logging's one call site, shared
    /// by `mutate_issued`, `mutate_held`, and `mutate_issued_and_held` rather
    /// than duplicated across all three.
    fn report_persist_outcome(
        &self,
        persisted: PersistOutcome<std::io::Error, String>,
    ) -> Result<(), String> {
        persisted.map_err(|e| {
            let path_display = self
                .state_path
                .as_deref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            // Both arms get the same "failed to persist ... to <path>"
            // framing and structured `path` field below, even though an
            // `Encode` failure (unlike `Store`) never actually touched the
            // filesystem — `CaStateCodec::encode` serializing this schema
            // (fixed arrays, `String`, `bool`, `u64`) essentially can't
            // fail, so keeping the two arms' shape consistent matters more
            // here than distinguishing an outcome that shouldn't occur.
            let msg = match e {
                PersistError::Encode(encode_err) => {
                    format!("failed to persist CA state to {path_display}: {encode_err}")
                }
                PersistError::Store(io_err) => {
                    format!("failed to persist CA state to {path_display}: {io_err}")
                }
            };
            // A handled-and-retried I/O error (the caller keeps serving from
            // memory and the next successful mutation retries the write), so
            // `warn!` rather than `error!` — but still surfaced to the
            // caller as an `Err`, since the caller is best placed to decide
            // whether to retry, alert, or accept the risk.
            tracing::warn!(
                path = %path_display,
                error = %msg,
                "failed to persist CA state; issued-certificate/held-CSR durability is degraded until this is fixed"
            );
            msg
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_dir(label: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "wayfinder-server-persistence-test-{}-{label}-{n}",
            std::process::id()
        ))
    }

    /// A minimal current-schema snapshot with one issued cert and one held
    /// (`Pending`) CSR — written as raw JSON, not built via `IssuedCertData`/
    /// `HeldCsr` field access, since those types' fields are private to
    /// `authority.rs`, a sibling module this one has no access into (only
    /// the type names are `pub(crate)`). This mirrors the raw-JSON seeding
    /// `authority.rs`'s own `v1_state_file_migrates_to_v2_with_empty_held`
    /// test already uses for the same reason.
    fn seed_snapshot() -> serde_json::Value {
        let key = [0u8; 32];
        serde_json::json!({
            "version": CURRENT_STATE_VERSION,
            "issued": [{
                "node_mac": [0, 0, 0, 0, 0, 1],
                "ed_pubkey": key,
                "not_before": 0,
                "not_after": 1,
                "revoked": false,
            }],
            "held": [{
                "node_mac": [0, 0, 0, 0, 0, 2],
                "ed_pubkey": key,
                "x_pubkey": key,
                "requested_at": 0,
                "status": "Pending",
            }],
        })
    }

    /// `mutate_issued_and_held` is backed by a single [`Persisted::mutate`]
    /// call, so a persist failure must roll back *both* collections
    /// together — never leaving one mutation durably applied while the
    /// other silently reverts. This is the actual mechanism
    /// `CertAuthority::approve_csr` relies on (see this method's own doc for
    /// the impersonation-guard gap a split write would otherwise open);
    /// tested here directly against `CaLog`, with full control over the
    /// failure timing, rather than through `approve_csr`'s black-box surface
    /// — there's no way to force only the *second* of two separate
    /// `mutate_*` calls to fail against a real filesystem without a
    /// fault-injecting store, so this white-box level is what actually
    /// proves the combined call is atomic.
    #[test]
    fn mutate_issued_and_held_rolls_back_both_collections_together_on_persist_failure() {
        let dir = unique_dir("atomic-combined");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        std::fs::write(&path, seed_snapshot().to_string()).unwrap();

        let mut log = CaLog::load(Some(path)).unwrap();
        assert_eq!(log.issued().len(), 1);
        assert_eq!(log.held().len(), 1);
        let existing_issued = log.issued()[0].clone();
        let existing_held = log.held()[0].clone();

        // Doom every subsequent write.
        std::fs::remove_dir_all(&dir).ok();

        let (_, persisted) = log.mutate_issued_and_held(|issued, held| {
            issued.push(existing_issued);
            held.push(existing_held);
        });
        assert!(
            persisted.is_err(),
            "the write should have failed: its directory is gone"
        );

        assert_eq!(
            log.issued().len(),
            1,
            "the issued-side mutation must roll back when the combined persist fails"
        );
        assert_eq!(
            log.held().len(),
            1,
            "the held-side mutation must roll back too — not just the issued side, which \
             would reproduce the exact split-durability hazard this method exists to close"
        );
    }

    /// Demonstrates *why* [`CaLog::mutate_issued_and_held`] exists, by
    /// reproducing the split-durability hazard directly: two separate
    /// `mutate_issued`/`mutate_held` calls (what `approve_csr` used before
    /// this method existed) can durably split — the first succeeds and
    /// stays committed even though a second, later call fails and rolls
    /// back. Unlike a black-box test through `approve_csr` (where a broken
    /// store dooms every write inside one function call uniformly, so
    /// nothing actually discriminates "combined" from "split"), this test
    /// controls the fault's timing directly: the directory is removed
    /// *between* the two calls, which only a white-box test at this level
    /// can arrange.
    #[test]
    fn separate_mutate_issued_and_mutate_held_calls_can_durably_split() {
        let dir = unique_dir("split-durability");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        std::fs::write(&path, seed_snapshot().to_string()).unwrap();

        let mut log = CaLog::load(Some(path)).unwrap();
        let existing_issued = log.issued()[0].clone();
        let existing_held = log.held()[0].clone();

        // The first write succeeds — its directory still exists.
        let (_, first) = log.mutate_issued(|issued| issued.push(existing_issued));
        assert!(first.is_ok());

        // Now doom the second write.
        std::fs::remove_dir_all(&dir).ok();
        let (_, second) = log.mutate_held(|held| held.push(existing_held));
        assert!(second.is_err());

        assert_eq!(
            log.issued().len(),
            2,
            "the first write's mutation stays committed — it already durably persisted \
             before the directory was removed, and CaLog has no way to undo a write that \
             already succeeded"
        );
        assert_eq!(
            log.held().len(),
            1,
            "the second write's mutation rolled back, in isolation from the first"
        );
    }
}
