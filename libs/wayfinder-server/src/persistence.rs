//! Durable on-disk snapshot of [`CertAuthority`](crate::CertAuthority)'s
//! issued-certificate log and held-CSR store, so the impersonation guard,
//! revocations, and pending operator approvals survive a restart.
//!
//! The on-disk schema is independent of the management-API protobuf wire
//! format (which is free to evolve on its own schedule): a JSON snapshot with
//! an explicit [`CURRENT_STATE_VERSION`], so a future format change ships with
//! an encoded migration rather than silently reinterpreting old bytes.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use std::io::Write;
use std::path::{Path, PathBuf};
use wayfinder_protos::service::IssuedCertData;

use serde::{Deserialize, Serialize};

use crate::authority::HeldCsr;

/// Current on-disk schema version. Bump this — and add an ordered migration
/// from the prior version into [`load`] — whenever [`CaState`]'s shape
/// changes.
const CURRENT_STATE_VERSION: u32 = 2;

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
    /// [`CaLog::persist`]), since a dropped record can carry a revocation.
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
}

/// Version 1 of the on-disk schema: the issued-certificate log only, with no
/// held-CSR section at all (not even an empty one) — held-CSR persistence was
/// introduced in version 2. Kept so [`load`] can migrate a snapshot written
/// under the older schema.
#[derive(Deserialize)]
struct CaStateV1 {
    issued: Vec<IssuedRecord>,
}

/// Migrate a version-1 snapshot forward: the held-CSR store didn't exist yet,
/// so it starts empty (the same behavior a version-1-only node had — held
/// CSRs are simply not something that schema could have durably remembered).
fn migrate_v1_to_v2(v1: CaStateV1) -> CaState {
    CaState {
        version: 2,
        issued: v1.issued,
        held: Vec::new(),
    }
}

/// Just enough of the snapshot to read `version` before committing to a full
/// parse, so [`load`] can dispatch to the right schema/migration.
#[derive(Deserialize)]
struct VersionProbe {
    version: u32,
}

/// Load the CA state snapshot at `path`.
///
/// Returns `Ok(None)` when no file exists at `path` — a fresh install starts
/// with an empty authority, which is not a failure. Any other outcome that
/// isn't a clean, known-version snapshot (after migration) — corrupt JSON, a
/// foreign shape, a newer-than-known version, or an I/O error — is `Err`: the
/// caller must fail closed rather than silently starting empty, since that
/// would silently un-revoke every previously-revoked node and forget every
/// pending approval.
fn load(path: &Path) -> Result<Option<CaState>, String> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(format!(
                "failed to read CA state file {}: {e}",
                path.display()
            ));
        }
    };
    let corrupt = |e: serde_json::Error| {
        format!(
            "CA state file {} is corrupt or not a recognized CA state snapshot: {e}",
            path.display()
        )
    };
    let probe: VersionProbe = serde_json::from_slice(&bytes).map_err(corrupt)?;
    let state = match probe.version {
        1 => {
            let v1: CaStateV1 = serde_json::from_slice(&bytes).map_err(corrupt)?;
            migrate_v1_to_v2(v1)
        }
        CURRENT_STATE_VERSION => serde_json::from_slice(&bytes).map_err(corrupt)?,
        v if v > CURRENT_STATE_VERSION => {
            return Err(format!(
                "CA state file {} has version {v} but this build only understands up to \
                 version {CURRENT_STATE_VERSION}; refusing to load a newer-than-known snapshot \
                 (upgrade the node before restarting it against this state file)",
                path.display()
            ));
        }
        v => {
            return Err(format!(
                "CA state file {} has version {v}, and this build has no migration path from \
                 it to version {CURRENT_STATE_VERSION}",
                path.display()
            ));
        }
    };
    Ok(Some(state))
}

/// Atomically write `state` to `path`: serialize to a `.tmp` sibling file in
/// the same directory, `fsync` it, then rename over `path`. The rename is
/// atomic on the same filesystem, so a crash mid-write can only ever leave the
/// previous snapshot (or nothing) at `path` — never a half-written one. On any
/// failure the `.tmp` sibling is best-effort removed so repeated failures
/// don't leave stale partial files next to the real snapshot.
///
/// Deliberately not `fsync`ed: the parent directory's own metadata (that the
/// rename landed) isn't flushed, so a *power loss* (as opposed to a process
/// crash) immediately after a rename could in principle still lose the
/// rename on some filesystems. Accepted for now as a lower-severity gap than
/// the mid-write tear this function does defend against; revisit if this
/// authority is ever deployed somewhere power loss (not just process crash)
/// is a real threat model.
fn save_atomic(path: &Path, state: &CaState) -> std::io::Result<()> {
    let mut tmp_path = path.as_os_str().to_os_string();
    tmp_path.push(".tmp");
    let tmp_path = PathBuf::from(tmp_path);

    let result = (|| {
        let json = serde_json::to_vec_pretty(state)
            .map_err(|e| std::io::Error::other(format!("failed to serialize CA state: {e}")))?;
        let mut tmp = std::fs::File::create(&tmp_path)?;
        tmp.write_all(&json)?;
        tmp.sync_all()?;
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

/// The authority's durable state: the issued-certificate log and the
/// held-CSR store, both backed by one snapshot file.
///
/// Storage is sealed behind [`Self::mutate_issued`]/[`Self::mutate_held`] so a
/// mutation can never be committed without an attempted persist: the
/// `issued`, `held`, and `state_path` fields are private to this module, so
/// `authority.rs` has no way to reach either `Vec` except through the
/// read-only [`Self::issued`]/[`Self::held`] views or the `mutate_*` methods.
/// This is what makes "every mutation is followed by a
/// persist attempt" a property of the type rather than a convention call
/// sites must remember. Note this is a per-call, not a per-operation,
/// guarantee: an operator action that touches both collections (e.g.
/// `approve_csr`, which issues a certificate and then updates the held
/// entry) performs two separate `mutate_*` calls and so two separate
/// persists, not one atomic combined write.
pub(crate) struct CaLog {
    issued: Vec<IssuedCertData>,
    held: Vec<HeldCsr>,
    state_path: Option<PathBuf>,
}

impl CaLog {
    /// An empty, in-memory-only log (no snapshot file). Used by
    /// [`CertAuthority::new`](crate::CertAuthority::new), which has no
    /// `ProviderConfig` to read a `state_path` from.
    pub(crate) fn empty() -> Self {
        Self {
            issued: Vec::new(),
            held: Vec::new(),
            state_path: None,
        }
    }

    /// Build a log for `state_path`. When `Some`, the existing snapshot (if
    /// any) is loaded now — migrating an older schema version if needed; a
    /// corrupt, foreign, or newer-than-known snapshot is `Err` (fail closed —
    /// see [`load`]). `None` behaves like [`Self::empty`].
    pub(crate) fn load(state_path: Option<PathBuf>) -> Result<Self, String> {
        let state = match &state_path {
            Some(path) => load(path)?,
            None => None,
        };
        let (issued, held) = match state {
            Some(state) => (
                state.issued.iter().map(IssuedRecord::to_proto).collect(),
                state.held,
            ),
            None => (Vec::new(), Vec::new()),
        };
        Ok(Self {
            issued,
            held,
            state_path,
        })
    }

    /// Read-only view of the issued-certificate log.
    pub(crate) fn issued(&self) -> &[IssuedCertData] {
        &self.issued
    }

    /// Read-only view of the held-CSR store.
    pub(crate) fn held(&self) -> &[HeldCsr] {
        &self.held
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
        let result = f(&mut self.issued);
        let persisted = self.persist();
        (result, persisted)
    }

    /// Run `f` against the held-CSR store, then attempt to persist the full
    /// state (issued + held) to `state_path` (if set) — the only way
    /// `authority.rs` can mutate either collection, so a persist attempt can
    /// never be forgotten. Returns `f`'s result alongside the persist
    /// outcome: a failed persist does not undo `f`'s in-memory effect (the
    /// authority stays serviceable even if the disk is temporarily
    /// unwritable), but the caller is expected to propagate the failure to
    /// whoever asked for the mutation, since "durable" is exactly what a
    /// caller of a CA-mutating RPC has a right to assume `Ok` means.
    pub(crate) fn mutate_held<R>(
        &mut self,
        f: impl FnOnce(&mut Vec<HeldCsr>) -> R,
    ) -> (R, Result<(), String>) {
        let result = f(&mut self.held);
        let persisted = self.persist();
        (result, persisted)
    }

    fn persist(&self) -> Result<(), String> {
        let Some(path) = &self.state_path else {
            return Ok(());
        };
        let mut issued = Vec::with_capacity(self.issued.len());
        for c in &self.issued {
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
            held: self.held.clone(),
        };
        save_atomic(path, &state).map_err(|e| {
            // A handled-and-retried I/O error (the caller keeps serving from
            // memory and the next successful mutation retries the write), so
            // `warn!` rather than `error!` — but still surfaced to the
            // caller as an `Err`, since the caller is best placed to decide
            // whether to retry, alert, or accept the risk.
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "failed to persist CA state; issued-certificate/held-CSR durability is degraded until this is fixed"
            );
            format!("failed to persist CA state to {}: {e}", path.display())
        })
    }
}
