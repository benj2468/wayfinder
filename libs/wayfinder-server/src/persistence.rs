//! The durable state of [`CertAuthority`](crate::CertAuthority) — issued
//! certificates, held CSRs, policy overrides, accounts and invitations — so the
//! impersonation guard, revocations, and pending operator approvals survive a
//! restart.
//!
//! [`CaLog`] holds it in memory and writes it through to a SQLite
//! [`CaStore`] record by record (design 26 phase 2). The records' serialised
//! forms are this module's own schema, independent of the management-API
//! protobuf.
//!
//! The JSON snapshot the CA used to keep (`ca-state.json`, versioned by
//! [`CURRENT_STATE_VERSION`] with ordered migrations in [`parse_state`]) is now
//! read once, as an import, the first time a CA starts against an empty
//! database.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use std::path::Path;
use std::path::PathBuf;
use wayfinder_protos::service::IssuedCertData;

use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use wayfinder_storage::Codec;

use crate::ca_store::CaStore;
use crate::ca_store::ChangeSet;
use crate::ca_store::Collection;
use crate::ca_store::Loaded;
use crate::ca_store::Row;
use crate::ca_store::SqliteStore;

use crate::authority::HeldCsr;
use wayfinder_auth::CERT_FLAG_ADMIN;
use wayfinder_auth::CERT_FLAG_USER;
use wayfinder_auth::CERT_FLAG_VIEWER;

use crate::users::AccountId;
use crate::users::UserInvite;
use crate::users::UserRecord;

/// Largest legacy `ca-state.json` the one-time import will read. The cap the
/// snapshot was always read under, kept for the import so a file it could never
/// have loaded fails closed here too rather than being half-trusted. Nothing
/// is read under it after the import: the database has no such cliff.
const MAX_STATE_BYTES: usize = 1024 * 1024;

/// Current on-disk schema version. Bump this — and add an ordered migration
/// from the prior version into [`parse_state`] — whenever [`CaState`]'s shape
/// changes.
pub(crate) const CURRENT_STATE_VERSION: u32 = 7;

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
    /// The certificate's signed capability bits, as issued. Recorded rather
    /// than re-derived because the certificate itself is not kept — only this
    /// summary of it — so without the flags an operator reading the list back
    /// after a restart cannot tell a person's session from a device's
    /// membership. Defaulted to 0 for a record written before version 5, which
    /// is accurate for every certificate that could have existed then: user
    /// and viewer certificates did not.
    #[serde(default)]
    flags: u8,
    /// The account whose sign-in produced this certificate, or `None` for a
    /// device's membership certificate.
    ///
    /// Added in version 7. `None` for a record written before it, which is the
    /// honest answer rather than a guess: nothing in an earlier snapshot ever
    /// recorded whose session a certificate was, so those cannot be attributed
    /// and expire on their own schedule.
    #[serde(default)]
    account_id: Option<AccountId>,
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
            flags: pack_flags(c),
            // A wrong-length id is dropped rather than refusing the whole
            // record: the certificate and its revocation status are the part
            // that must survive, and an unattributable session is exactly what
            // a `None` here says.
            account_id: c
                .account_id
                .as_slice()
                .try_into()
                .ok()
                .map(AccountId::from_bytes),
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
            user: self.flags & CERT_FLAG_USER != 0,
            admin: self.flags & CERT_FLAG_ADMIN != 0,
            viewer: self.flags & CERT_FLAG_VIEWER != 0,
            account_id: self
                .account_id
                .map(|id| id.as_bytes().to_vec())
                .unwrap_or_default(),
        }
    }
}

/// Pack an [`IssuedCertData`]'s three capability booleans back into the signed
/// flag byte, for storage.
///
/// The booleans are what the management API reports and the byte is what the
/// certificate actually carries; keeping the byte on disk means a flag added
/// later is storable without another schema version, and means this record
/// says what the certificate said rather than what today's build knows how to
/// name.
fn pack_flags(c: &IssuedCertData) -> u8 {
    let mut flags = 0u8;
    if c.user {
        flags |= CERT_FLAG_USER;
    }
    if c.admin {
        flags |= CERT_FLAG_ADMIN;
    }
    if c.viewer {
        flags |= CERT_FLAG_VIEWER;
    }
    flags
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
    /// The operator's runtime enrollment-policy overrides. Added in version 3
    /// (a version-2 snapshot migrates forward with none, which is exactly the
    /// behavior it had — every field following the startup config), and
    /// re-shaped in version 4, which replaced the `require_approval` override
    /// with its inverse.
    #[serde(default)]
    policy: PolicyOverrides,
    /// The certificate authority's user accounts. Added in version 5; a
    /// version-4 snapshot migrates forward with none, which is exactly what a
    /// version-4 provider had — no accounts, and so no way to log in.
    #[serde(default)]
    users: Vec<UserRecord>,
    /// Pending invitations to register an account. Added in version 6; a
    /// version-5 snapshot migrates forward with none.
    ///
    /// A collection of its own beside [`users`](Self::users), never a flag on a
    /// `UserRecord`: no code path that iterates accounts can then authenticate
    /// a half-built one, and that guarantee does not depend on every future
    /// reader remembering to check a field.
    #[serde(default)]
    invites: Vec<UserInvite>,
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
    /// Whether submitted CSRs are signed on submission, rather than parked
    /// pending operator approval.
    #[serde(default)]
    pub(crate) auto_approve: Option<bool>,
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

/// Version 3 of the on-disk schema: as version 4, except that the enrollment
/// posture was recorded the other way round — see [`PolicyOverridesV3`]. Kept
/// so [`parse_state`] can migrate a version-3 snapshot.
#[derive(Deserialize)]
struct CaStateV3 {
    issued: Vec<IssuedRecord>,
    held: Vec<HeldCsr>,
    #[serde(default)]
    policy: PolicyOverridesV3,
}

/// Version 3's policy overrides, whose posture field was `require_approval` —
/// the inverse of the `auto_approve` that replaced it. Only the posture
/// differs, but the whole shape is mirrored here rather than deserialized into
/// the current type with an alias: an alias would silently read a version-3
/// `true` ("hold every request") as a version-4 `true` ("sign on submission"),
/// which is the one misreading this rename must not permit.
#[derive(Deserialize, Default)]
struct PolicyOverridesV3 {
    #[serde(default)]
    require_approval: Option<bool>,
    #[serde(default)]
    cert_ttl_secs: Option<u64>,
    #[serde(default)]
    enrollment_token: Option<TokenOverride>,
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
fn migrate_v2_to_v3(v2: CaStateV2) -> CaStateV3 {
    CaStateV3 {
        issued: v2.issued,
        held: v2.held,
        policy: PolicyOverridesV3::default(),
    }
}

/// Migrate a version-3 snapshot forward, inverting the enrollment posture: the
/// override was recorded as `require_approval` and is now its opposite,
/// `auto_approve`.
///
/// Inverted rather than dropped. This override is the operator's most recent
/// stated intent, and the two ways of getting it wrong are not symmetric: a
/// provider that comes back from an upgrade signing for whoever asks, when its
/// operator had pinned "hold every request", is handing out mesh membership
/// unattended.
fn migrate_v3_to_v4(v3: CaStateV3) -> CaStateV4 {
    CaStateV4 {
        issued: v3.issued,
        held: v3.held,
        policy: PolicyOverrides {
            auto_approve: v3.policy.require_approval.map(|held| !held),
            cert_ttl_secs: v3.policy.cert_ttl_secs,
            enrollment_token: v3.policy.enrollment_token,
        },
    }
}

/// Version 4 of the on-disk schema: as version 5, but with no `users` section
/// — the certificate authority had no user store until version 5. Kept so
/// [`parse_state`] can migrate a version-4 snapshot.
#[derive(Deserialize)]
struct CaStateV4 {
    issued: Vec<IssuedRecord>,
    held: Vec<HeldCsr>,
    #[serde(default)]
    policy: PolicyOverrides,
}

/// Migrate a version-4 snapshot forward: no user accounts were recorded, so
/// there are none — which is not a loss of state but a faithful description of
/// a provider that had no user store at all. Bootstrapping the first account is
/// an offline, deliberate act (`wayfinderctl user add`), exactly as
/// bootstrapping the root key is; inventing one here would be inventing a
/// credential nobody chose.
fn migrate_v4_to_v5(v4: CaStateV4) -> CaStateV5 {
    CaStateV5 {
        issued: v4.issued,
        held: v4.held,
        policy: v4.policy,
        users: Vec::new(),
    }
}

/// Version 5 of the on-disk schema: as version 6, but with no `invites`
/// section — the certificate authority had no invite store until version 6.
/// Kept so [`parse_state`] can migrate a version-5 snapshot.
#[derive(Deserialize)]
struct CaStateV5 {
    issued: Vec<IssuedRecord>,
    held: Vec<HeldCsr>,
    #[serde(default)]
    policy: PolicyOverrides,
    #[serde(default)]
    users: Vec<UserRecord>,
}

/// Migrate a version-5 snapshot forward: no invites were recorded, so there are
/// none — a faithful description of a provider that had no invite store at all,
/// not a loss of state. An invite is a bearer credential with an expiry, so
/// there is nothing here that could be reconstructed even in principle.
fn migrate_v5_to_v6(v5: CaStateV5) -> CaStateV6 {
    CaStateV6 {
        issued: v5.issued,
        held: v5.held,
        policy: v5.policy,
        users: v5.users,
        invites: Vec::new(),
    }
}

/// Version 6 of the on-disk schema: as version 7, but with no account ids on
/// its accounts and no owning account on its issued certificates — the
/// authority did not link a session certificate to the account that minted it
/// until version 7. Kept so [`parse_state`] can migrate a version-6 snapshot.
#[derive(Deserialize)]
struct CaStateV6 {
    issued: Vec<IssuedRecord>,
    held: Vec<HeldCsr>,
    #[serde(default)]
    policy: PolicyOverrides,
    #[serde(default)]
    users: Vec<UserRecord>,
    #[serde(default)]
    invites: Vec<UserInvite>,
}

/// Migrate a version-6 snapshot forward: a shape-preserving step, because the
/// two fields version 7 adds carry `serde` defaults that have already done the
/// work by the time this runs.
///
/// This is the [`IssuedRecord::flags`] pattern rather than a rewrite, and both
/// halves matter. Each [`UserRecord`] takes a **freshly minted**
/// [`AccountId`] — `#[serde(default = "AccountId::generate")]` is called once
/// per record with a missing field, so no two accounts share one; a default
/// returning a constant would make every account's revocation cut every other,
/// invisibly. Each [`IssuedRecord`] takes `None`, which is accurate for every
/// certificate that could exist in a version-6 snapshot: nothing there ever
/// recorded whose session it was, so those certificates cannot be attributed
/// and run to their own expiry. `RevokeNode` on the MAC remains the tool for
/// one of them.
///
/// The step is still written out rather than collapsed into "deserialize as
/// version 7", so the chain stays a sequence of versions each of which existed.
fn migrate_v6_to_v7(v6: CaStateV6) -> CaState {
    CaState {
        version: 7,
        issued: v6.issued,
        held: v6.held,
        policy: v6.policy,
        users: v6.users,
        invites: v6.invites,
    }
}

/// Just enough of the snapshot to read `version` before committing to a full
/// parse, so [`parse_state`] can dispatch to the right schema/migration.
#[derive(Deserialize)]
struct VersionProbe {
    version: u32,
}

/// Decode a CA state snapshot's raw bytes (via [`CaStateCodec::decode`]),
/// dispatching to the right schema/migration by probing `version` first.
/// `path`, when known, is used only to name the offending file in error
/// messages.
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
            Ok(migrate_v6_to_v7(migrate_v5_to_v6(migrate_v4_to_v5(
                migrate_v3_to_v4(migrate_v2_to_v3(migrate_v1_to_v2(v1))),
            ))))
        }
        2 => {
            let v2: CaStateV2 = serde_json::from_slice(bytes).map_err(corrupt)?;
            Ok(migrate_v6_to_v7(migrate_v5_to_v6(migrate_v4_to_v5(
                migrate_v3_to_v4(migrate_v2_to_v3(v2)),
            ))))
        }
        3 => {
            let v3: CaStateV3 = serde_json::from_slice(bytes).map_err(corrupt)?;
            Ok(migrate_v6_to_v7(migrate_v5_to_v6(migrate_v4_to_v5(
                migrate_v3_to_v4(v3),
            ))))
        }
        4 => {
            let v4: CaStateV4 = serde_json::from_slice(bytes).map_err(corrupt)?;
            Ok(migrate_v6_to_v7(migrate_v5_to_v6(migrate_v4_to_v5(v4))))
        }
        5 => {
            let v5: CaStateV5 = serde_json::from_slice(bytes).map_err(corrupt)?;
            Ok(migrate_v6_to_v7(migrate_v5_to_v6(v5)))
        }
        6 => {
            let v6: CaStateV6 = serde_json::from_slice(bytes).map_err(corrupt)?;
            Ok(migrate_v6_to_v7(v6))
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

/// The in-memory value a [`CaLog`] wraps in the store: everything
/// `authority.rs` can mutate. Cheap to `Clone` at the scale this is meant for
/// (see one commit's own doc on why that bound exists) — needed so
/// a failed persist can roll the in-memory value back to its pre-mutation
/// snapshot.
#[derive(Clone)]
struct CaLogState {
    issued: Vec<IssuedCertData>,
    held: Vec<HeldCsr>,
    policy: PolicyOverrides,
    users: Vec<UserRecord>,
    invites: Vec<UserInvite>,
}

impl CaLogState {
    /// The state a fresh CA (no snapshot loaded yet) starts from.
    fn empty() -> Self {
        Self {
            issued: Vec::new(),
            held: Vec::new(),
            policy: PolicyOverrides::default(),
            users: Vec::new(),
            invites: Vec::new(),
        }
    }
}

/// Translates [`CaLogState`] to/from the legacy JSON snapshot ([`CaState`]):
/// decoding for the one-time import, encoding only for tests that hand-age a
/// snapshot.
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
            users: value.users.clone(),
            invites: value.invites.clone(),
        };
        serde_json::to_vec_pretty(&state).map_err(|e| format!("failed to serialize CA state: {e}"))
    }

    fn decode(&self, bytes: &[u8]) -> Result<CaLogState, String> {
        let state = parse_state(bytes, self.path.as_deref())?;
        Ok(CaLogState {
            issued: state.issued.iter().map(IssuedRecord::to_proto).collect(),
            held: state.held,
            policy: state.policy,
            users: state.users,
            invites: state.invites,
        })
    }
}

/// The authority's durable state: the issued-certificate log, held CSRs,
/// enrollment-policy overrides, user accounts and invitations, held in memory
/// and written through to a [`CaStore`] record by record (design 26 phase 2).
///
/// The only way `authority.rs` can change any of it is a `mutate_*` call, and
/// every one of those ends in a commit attempt — "every mutation is followed by
/// a persist" is a property of the type, not a convention call sites must
/// remember. A mutation touching two collections (`approve_csr` recording a
/// certificate and approving its CSR) commits them as one transaction, so the
/// two can never durably split; see [`Self::mutate_issued_and_held`].
///
/// A commit writes only what changed. Each collection is re-encoded after the
/// mutation and diffed, by content, against the rows the store already holds
/// (`index`): rows whose record disappeared are deleted and new records are
/// inserted. An unchanged record is never rewritten, so a login costs one row,
/// not the whole CA.
pub(crate) struct CaLog {
    /// What the authority reads. Always the committed state: a mutation whose
    /// commit fails is rolled back before the caller sees it.
    state: CaLogState,
    /// Where `state` is persisted, or `None` for an in-memory-only CA.
    backing: Option<Backing>,
}

/// A [`CaLog`]'s store, and its record of what the store holds.
struct Backing {
    store: Box<dyn CaStore>,
    /// Per collection, each stored record body and the ids of the rows holding
    /// it — a multiset, since two records can serialise identically. Kept in
    /// step with the store by every successful commit.
    index: HashMap<Collection, HashMap<Vec<u8>, Vec<i64>>>,
    /// The database file, to name in a failure's log line. `None` for a store
    /// that is not a file.
    path: Option<PathBuf>,
    /// Fault injection: while set, every commit fails without reaching the
    /// store. The only way to make a SQLite write fail on demand — removing
    /// the directory under an open database does not.
    #[cfg(test)]
    fail_commits: bool,
}

impl CaLog {
    /// An empty, in-memory-only log. Used by
    /// [`CertAuthority::new`](crate::CertAuthority::new), which has no
    /// `ProviderConfig` to read a `state_path` from.
    pub(crate) fn empty() -> Self {
        Self {
            state: CaLogState::empty(),
            backing: None,
        }
    }

    /// The log persisted in the SQLite database at `db`, created if absent.
    ///
    /// `legacy` is the `ca-state.json` this CA ran on before the database
    /// existed. On the first start against an uninitialized database it is
    /// imported — through the versioned loader, so any schema version
    /// upgrades — committed in one transaction, and renamed to
    /// `<name>.imported`. It is kept, not deleted: it is the only copy of the
    /// CA's state that predates the database. A file still present beside an
    /// initialized database is either an import that committed and crashed
    /// before the rename (same contents: the rename is finished) or a
    /// different CA's state (refused, since picking either loses the other's
    /// revocations).
    pub(crate) fn open(db: &Path, legacy: Option<&Path>) -> Result<Self, String> {
        let store = SqliteStore::open(db)?;
        let mut log = Self::with_store(Box::new(store), legacy)?;
        if let Some(backing) = log.backing.as_mut() {
            backing.path = Some(db.to_path_buf());
        }
        Ok(log)
    }

    /// The log persisted in `store`. See [`Self::open`] for `legacy`.
    pub(crate) fn with_store(
        mut store: Box<dyn CaStore>,
        legacy: Option<&Path>,
    ) -> Result<Self, String> {
        let loaded = store.load()?;
        let legacy = match legacy {
            Some(path) if path.exists() => Some((path, read_legacy(path)?)),
            _ => None,
        };
        let mut backing = Backing {
            store,
            index: HashMap::new(),
            path: None,
            #[cfg(test)]
            fail_commits: false,
        };

        if !loaded.initialized {
            // A fresh database: take the legacy snapshot's state if there is
            // one, and commit it — or an empty CA — so the database is marked
            // initialized and a later start never imports over it.
            let state = legacy
                .as_ref()
                .map_or_else(CaLogState::empty, |(_, state)| state.clone());
            let mut change = ChangeSet::default();
            let mut pending = Vec::new();
            for collection in Collection::ALL {
                for body in encode_collection(&state, collection)? {
                    change.insert(collection, body.clone());
                    pending.push((collection, body));
                }
            }
            let ids = backing.store.commit(&change)?;
            for ((collection, body), id) in pending.into_iter().zip(ids) {
                backing.remember(collection, body, id);
            }
            if let Some((path, _)) = &legacy {
                move_aside(path);
            }
            return Ok(Self {
                state,
                backing: Some(backing),
            });
        }

        let state = decode_rows(&loaded)?;
        for row in loaded.rows {
            backing.remember(row.collection, row.body, row.id);
        }
        if let Some((path, legacy_state)) = legacy {
            if same_records(&state, &legacy_state)? {
                move_aside(path);
            } else {
                return Err(format!(
                    "{} is still present beside an initialized CA database and holds                      different state; refusing to start rather than choose between                      them. If its state is already in the database, move it aside",
                    path.display()
                ));
            }
        }
        Ok(Self {
            state,
            backing: Some(backing),
        })
    }

    /// Make every later commit fail, as a full disk or a failing device would.
    #[cfg(test)]
    pub(crate) fn fail_commits(&mut self) {
        if let Some(backing) = self.backing.as_mut() {
            backing.fail_commits = true;
        }
    }

    /// Let commits reach the store again after [`Self::fail_commits`], as
    /// though the disk had been freed.
    #[cfg(test)]
    pub(crate) fn restore_commits(&mut self) {
        if let Some(backing) = self.backing.as_mut() {
            backing.fail_commits = false;
        }
    }

    /// The whole state as a current-version `ca-state.json`, for tests that
    /// need to hand-age a snapshot written through the ordinary path.
    #[cfg(test)]
    pub(crate) fn snapshot_json(&self) -> Vec<u8> {
        CaStateCodec { path: None }.encode(&self.state).unwrap()
    }

    /// Run `f` against the state, then commit the collections in `touched`.
    /// On a failed commit the state is rolled back to what it was before `f`,
    /// and the error returned; `f`'s own result is returned either way.
    fn mutate<R>(
        &mut self,
        touched: &[Collection],
        f: impl FnOnce(&mut CaLogState) -> R,
    ) -> (R, Result<(), String>) {
        let Some(backing) = self.backing.as_mut() else {
            return (f(&mut self.state), Ok(()));
        };
        let before = self.state.clone();
        let result = f(&mut self.state);
        match backing.commit(&self.state, touched) {
            Ok(()) => (result, Ok(())),
            Err(detail) => {
                self.state = before;
                (result, Err(backing.report_failure(&detail)))
            }
        }
    }

    /// Read-only view of the issued-certificate log.
    pub(crate) fn issued(&self) -> &[IssuedCertData] {
        &self.state.issued
    }

    /// Read-only view of the held-CSR store.
    pub(crate) fn held(&self) -> &[HeldCsr] {
        &self.state.held
    }

    /// Read-only view of the operator's runtime enrollment-policy overrides.
    pub(crate) fn policy(&self) -> &PolicyOverrides {
        &self.state.policy
    }

    /// Read-only view of the certificate authority's user accounts.
    pub(crate) fn users(&self) -> &[UserRecord] {
        &self.state.users
    }

    /// Run `f` against the user store, then attempt to persist the full state,
    /// with the same rollback guarantee as [`Self::mutate_held`].
    ///
    /// A login is a *mutation* here even when it succeeds — it advances the
    /// TOTP replay guard — and a failed one has to be recorded too, or the
    /// lockout counter resets on restart and an attacker can trigger the reset
    /// themselves. So this is on the path of every authentication attempt, not
    /// only of administrative changes.
    pub(crate) fn mutate_users<R>(
        &mut self,
        f: impl FnOnce(&mut Vec<UserRecord>) -> R,
    ) -> (R, Result<(), String>) {
        let (result, persisted) = self.mutate(&[Collection::Users], |state| f(&mut state.users));
        (result, persisted)
    }

    /// Read-only view of the pending invitations.
    pub(crate) fn invites(&self) -> &[UserInvite] {
        &self.state.invites
    }

    /// Run `f` against the invite store, then attempt to persist the full
    /// state, with the same rollback guarantee as [`Self::mutate_held`].
    ///
    /// Minting, starting and revoking an invite each go through here.
    /// *Completing* one does not — it must also create an account, and the two
    /// halves have to land as one write: see [`Self::mutate_users_and_invites`].
    pub(crate) fn mutate_invites<R>(
        &mut self,
        f: impl FnOnce(&mut Vec<UserInvite>) -> R,
    ) -> (R, Result<(), String>) {
        let (result, persisted) =
            self.mutate(&[Collection::Invites], |state| f(&mut state.invites));
        (result, persisted)
    }

    /// Run `f` against *both* the user store and the invite store, persisting
    /// the combined result as a single write — for the one caller
    /// (`CertAuthority::complete_user_registration`) that must create an account
    /// and delete the invite it was registered from as one durable unit.
    ///
    /// The same hazard [`Self::mutate_issued_and_held`] exists for, with a
    /// sharper consequence. Two separate calls means two separate persists: if
    /// the account is written durably and the invite deletion then fails and
    /// rolls back, the invite comes back as `Started` with an account already
    /// under its name — and the registrant, who has no way to see either store,
    /// is told their registration failed. If the deletion lands first and the
    /// account write fails, the invite is gone and the person holding the handle
    /// has nothing left to redeem and no way to ask for another. One
    /// one commit closes both: either the account exists and the
    /// invite is gone, or neither happened.
    pub(crate) fn mutate_users_and_invites<R>(
        &mut self,
        f: impl FnOnce(&mut Vec<UserRecord>, &mut Vec<UserInvite>) -> R,
    ) -> (R, Result<(), String>) {
        let (result, persisted) = self.mutate(&[Collection::Users, Collection::Invites], |state| {
            f(&mut state.users, &mut state.invites)
        });
        (result, persisted)
    }

    /// Run `f` against *both* the user store and the issued-certificate log,
    /// persisting the combined result as a single write — for the one caller
    /// (`CertAuthority::remove_user_revoking_sessions`) that must delete an
    /// account and revoke the certificates it holds as one durable unit.
    ///
    /// The same hazard [`Self::mutate_users_and_invites`] exists for, pointed at
    /// the pair design 14 §5.6 is about, and it splits badly in both directions.
    /// If the account is deleted durably and the revocations then fail and roll
    /// back, the operator is told the account is gone while every session it
    /// held keeps working — which is precisely the bug that design exists to
    /// end, reintroduced in the window where it is hardest to notice. If the
    /// revocations land and the deletion rolls back, the account survives with
    /// its sessions cut and can simply sign in again for a fresh one. One
    /// one commit closes both: either the account is gone and its
    /// sessions are revoked, or neither happened.
    pub(crate) fn mutate_users_and_issued<R>(
        &mut self,
        f: impl FnOnce(&mut Vec<UserRecord>, &mut Vec<IssuedCertData>) -> R,
    ) -> (R, Result<(), String>) {
        let (result, persisted) = self.mutate(&[Collection::Users, Collection::Issued], |state| {
            f(&mut state.users, &mut state.issued)
        });
        (result, persisted)
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
        let (result, persisted) = self.mutate(&[Collection::Policy], |state| f(&mut state.policy));
        (result, persisted)
    }

    /// Run `f` against the issued-certificate log, then attempt to persist
    /// the change, returning
    /// both `f`'s result and the persist outcome so the caller can decide how
    /// to react to a durability failure (see [`Self::mutate_held`] for the
    /// shared persist behavior).
    pub(crate) fn mutate_issued<R>(
        &mut self,
        f: impl FnOnce(&mut Vec<IssuedCertData>) -> R,
    ) -> (R, Result<(), String>) {
        let (result, persisted) = self.mutate(&[Collection::Issued], |state| f(&mut state.issued));
        (result, persisted)
    }

    /// Run `f` against the held-CSR store, then attempt to persist the
    /// change — the only way
    /// `authority.rs` can mutate either collection, so a persist attempt can
    /// never be forgotten. Returns `f`'s result alongside the persist
    /// outcome: a failed persist **rolls the entire state (both `issued` and
    /// `held`) back** to what it was before `f` ran, via
    /// the commit's rollback, so the in-memory log
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
        let (result, persisted) = self.mutate(&[Collection::Held], |state| f(&mut state.held));
        (result, persisted)
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
    /// one commit call closes that gap: either both land
    /// durably, or the commit's rollback undoes both together.
    pub(crate) fn mutate_issued_and_held<R>(
        &mut self,
        f: impl FnOnce(&mut Vec<IssuedCertData>, &mut Vec<HeldCsr>) -> R,
    ) -> (R, Result<(), String>) {
        let (result, persisted) = self.mutate(&[Collection::Issued, Collection::Held], |state| {
            f(&mut state.issued, &mut state.held)
        });
        (result, persisted)
    }
}

impl Backing {
    /// Record that row `id` holds `body` in `collection`.
    fn remember(&mut self, collection: Collection, body: Vec<u8>, id: i64) {
        self.index
            .entry(collection)
            .or_default()
            .entry(body)
            .or_default()
            .push(id);
    }

    /// Commit `state`'s `touched` collections: diff each against what the
    /// store holds, and write the difference as one change set.
    fn commit(&mut self, state: &CaLogState, touched: &[Collection]) -> Result<(), String> {
        #[cfg(test)]
        if self.fail_commits {
            return Err("commit failed by test fault injection".into());
        }
        let mut change = ChangeSet::default();
        let mut deleted = Vec::new();
        let mut inserted = Vec::new();
        for &collection in touched {
            let mut wanted: HashMap<Vec<u8>, usize> = HashMap::new();
            let mut order = Vec::new();
            for body in encode_collection(state, collection)? {
                let n = wanted.entry(body.clone()).or_default();
                *n += 1;
                order.push(body);
            }
            let held = self.index.get(&collection);
            // Rows whose body is wanted fewer times than it is held go.
            if let Some(held) = held {
                for (body, ids) in held {
                    let keep = wanted.get(body).copied().unwrap_or(0);
                    for &id in ids.iter().skip(keep) {
                        change.delete(collection, id);
                        deleted.push((collection, body.clone(), id));
                    }
                }
            }
            // Bodies wanted more times than they are held come in, in the
            // order the collection lists them.
            let mut have: HashMap<&[u8], usize> = HashMap::new();
            for body in &order {
                let held_n = held.and_then(|h| h.get(body)).map_or(0, Vec::len);
                let seen = have.entry(body.as_slice()).or_default();
                *seen += 1;
                if *seen > held_n {
                    change.insert(collection, body.clone());
                    inserted.push((collection, body.clone()));
                }
            }
        }
        if change.is_empty() {
            return Ok(());
        }
        let ids = self.store.commit(&change)?;
        for (collection, body, id) in deleted {
            if let Some(ids) = self
                .index
                .get_mut(&collection)
                .and_then(|m| m.get_mut(&body))
            {
                ids.retain(|&x| x != id);
                if ids.is_empty() {
                    self.index.get_mut(&collection).map(|m| m.remove(&body));
                }
            }
        }
        for ((collection, body), id) in inserted.into_iter().zip(ids) {
            self.remember(collection, body, id);
        }
        Ok(())
    }

    /// Log a failed commit and turn it into the message the caller is given.
    fn report_failure(&self, detail: &str) -> String {
        let path_display = self
            .path
            .as_deref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        // The path and the store's error go to the log, not to the caller.
        // Three of this store's mutations sit behind requests on the
        // enrollment tier, which admits a caller holding no credential at
        // all — and `begin_user_registration` reaches one on a token that
        // matches nothing. Returning this verbatim showed an anonymous
        // visitor the CA's absolute state-file path and its errno, under
        // the heading "This invitation cannot be used".
        //
        // A handled-and-retried error (the caller keeps serving from memory
        // and the next successful mutation retries the write), so `warn!`
        // rather than `error!` — but still surfaced to the caller as an
        // `Err`, since the caller is best placed to decide whether to retry,
        // alert, or accept the risk.
        tracing::warn!(
            path = %path_display,
            error = %detail,
            "failed to persist CA state; durability of certificates, held CSRs, accounts and invitations is degraded until this is fixed"
        );
        "the node could not record this change; it is still serving from memory. \
         Try again shortly, and check the node's logs"
            .to_string()
    }
}

/// Every record of `collection` in `state`, serialised as the store holds it.
///
/// Issued certificates go through [`IssuedRecord`], the on-disk mirror of the
/// protobuf type; one too malformed to mirror is dropped with a warning, as the
/// JSON snapshot always did.
fn encode_collection(state: &CaLogState, collection: Collection) -> Result<Vec<Vec<u8>>, String> {
    fn json<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
        serde_json::to_vec(value).map_err(|e| format!("failed to serialize CA record: {e}"))
    }
    match collection {
        Collection::Issued => {
            let mut out = Vec::with_capacity(state.issued.len());
            for c in &state.issued {
                match IssuedRecord::from_proto(c) {
                    Some(record) => out.push(json(&record)?),
                    None => tracing::warn!(
                        node_mac_len = c.node_mac.len(),
                        ed_pubkey_len = c.ed_pubkey.len(),
                        "dropping malformed issued-cert record from CA state; its \
                         revocation status, if any, will not survive a restart"
                    ),
                }
            }
            Ok(out)
        }
        Collection::Held => state.held.iter().map(json).collect(),
        Collection::Policy => Ok(vec![json(&state.policy)?]),
        Collection::Users => state.users.iter().map(json).collect(),
        Collection::Invites => state.invites.iter().map(json).collect(),
    }
}

/// Rebuild the state from a store's rows, in the order they were written.
fn decode_rows(loaded: &Loaded) -> Result<CaLogState, String> {
    fn json<T: for<'de> Deserialize<'de>>(row: &Row) -> Result<T, String> {
        serde_json::from_slice(&row.body)
            .map_err(|e| format!("CA database row {} is not a valid record: {e}", row.id))
    }
    let mut rows: Vec<&Row> = loaded.rows.iter().collect();
    rows.sort_by_key(|r| r.id);
    let mut state = CaLogState::empty();
    let mut policies = 0;
    for row in rows {
        match row.collection {
            Collection::Issued => state.issued.push(json::<IssuedRecord>(row)?.to_proto()),
            Collection::Held => state.held.push(json(row)?),
            Collection::Policy => {
                policies += 1;
                state.policy = json(row)?;
            }
            Collection::Users => state.users.push(json(row)?),
            Collection::Invites => state.invites.push(json(row)?),
        }
    }
    if policies > 1 {
        return Err(format!(
            "CA database holds {policies} enrollment-policy rows where there can be one"
        ));
    }
    Ok(state)
}

/// Read and decode a legacy `ca-state.json`, migrating any older schema.
///
/// Bounded: a snapshot larger than [`MAX_STATE_BYTES`] fails closed rather than
/// being read in whole, as it always has.
fn read_legacy(path: &Path) -> Result<CaLogState, String> {
    let len = std::fs::metadata(path)
        .map_err(|e| format!("failed to read CA state file {}: {e}", path.display()))?
        .len();
    if len > MAX_STATE_BYTES as u64 {
        return Err(format!(
            "CA state file {} is {len} bytes, over the {MAX_STATE_BYTES}-byte import limit",
            path.display()
        ));
    }
    let bytes = std::fs::read(path)
        .map_err(|e| format!("failed to read CA state file {}: {e}", path.display()))?;
    CaStateCodec {
        path: Some(path.to_path_buf()),
    }
    .decode(&bytes)
}

/// Whether two states hold the same records in every collection, ignoring
/// order.
fn same_records(a: &CaLogState, b: &CaLogState) -> Result<bool, String> {
    for collection in Collection::ALL {
        let mut x = encode_collection(a, collection)?;
        let mut y = encode_collection(b, collection)?;
        x.sort();
        y.sort();
        if x != y {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Rename an imported `ca-state.json` to `<name>.imported`. A failure is only
/// logged: the state is committed, and the next start finds the same contents
/// beside the database and finishes the rename then.
fn move_aside(path: &Path) {
    let mut aside = path.as_os_str().to_owned();
    aside.push(".imported");
    match std::fs::rename(path, &aside) {
        Ok(()) => tracing::info!(
            from = %path.display(),
            "imported the CA state snapshot into the database and moved it aside"
        ),
        Err(e) => tracing::warn!(
            path = %path.display(),
            error = %e,
            "imported the CA state snapshot but could not move it aside; the next start will retry"
        ),
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

        let mut log = CaLog::open(&path.with_extension("sqlite3"), Some(&path)).unwrap();
        assert_eq!(log.issued().len(), 1);
        assert_eq!(log.held().len(), 1);
        let existing_issued = log.issued()[0].clone();
        let existing_held = log.held()[0].clone();

        // Doom every subsequent write, as a full disk would.
        log.fail_commits();

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

        let mut log = CaLog::open(&path.with_extension("sqlite3"), Some(&path)).unwrap();
        let existing_issued = log.issued()[0].clone();
        let existing_held = log.held()[0].clone();

        // The first write succeeds — its directory still exists.
        let (_, first) = log.mutate_issued(|issued| issued.push(existing_issued));
        assert!(first.is_ok());

        // Now doom the second write.
        log.fail_commits();
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

    /// A role change and the revocations it forces are one durable act.
    ///
    /// [`CaLog::mutate_users_and_issued`] backs `RemoveUser` and, since design
    /// 15, every demotion and disable — each of which changes an account *and*
    /// marks its session certificates revoked. Two separate writes could
    /// durably split (`separate_mutate_issued_and_mutate_held_calls_can_durably_split`
    /// above shows how), and the direction that matters is an account recorded
    /// as demoted whose admin certificates came back un-revoked: the operator
    /// is told the access ended, and it did not.
    ///
    /// White-box, at this level, for the reason its two siblings are: only here
    /// can the failure be forced to land *after* both halves of the mutation
    /// have run. From `CertAuthority` there is no way to intervene between two
    /// internal writes, so a test up there cannot tell one write from two.
    #[test]
    fn mutate_users_and_issued_rolls_back_both_collections_together_on_persist_failure() {
        let dir = unique_dir("atomic-users-issued");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        std::fs::write(&path, seed_snapshot().to_string()).unwrap();

        let mut log = CaLog::open(&path.with_extension("sqlite3"), Some(&path)).unwrap();
        log.mutate_users(|users| {
            users.push(
                UserRecord::new("rowan", "hunter2", crate::users::UserRole::Admin, 3600).unwrap(),
            );
        })
        .1
        .expect("the setup write lands while the directory is still there");
        assert!(!log.issued()[0].revoked, "and the seeded cert is live");

        // Doom every subsequent write, as a full disk would.
        log.fail_commits();

        let (_, persisted) = log.mutate_users_and_issued(|users, issued| {
            users[0].role = crate::users::UserRole::Viewer;
            issued[0].revoked = true;
        });
        assert!(
            persisted.is_err(),
            "the write should have failed: its directory is gone"
        );

        assert_eq!(
            log.users()[0].role,
            crate::users::UserRole::Admin,
            "the demotion must roll back with the revocation"
        );
        assert!(
            !log.issued()[0].revoked,
            "and the revocation must roll back with the demotion — a certificate \
             marked revoked whose account came back an administrator is the same \
             split seen from the other side"
        );
    }

    /// Completing a registration creates the account and deletes the invite,
    /// and those are one durable act or the whole flow is unrecoverable: a
    /// crash between two separate writes leaves a burnt invite with no account
    /// behind it, and the person holding the handle has nothing left to redeem.
    ///
    /// Same white-box level, and for the same reason, as
    /// [`mutate_issued_and_held_rolls_back_both_collections_together_on_persist_failure`]:
    /// only here can the failure be forced to land after both halves of the
    /// mutation have run.
    #[test]
    fn mutate_users_and_invites_rolls_back_both_collections_together_on_persist_failure() {
        let dir = unique_dir("atomic-users-invites");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        std::fs::write(&path, seed_snapshot().to_string()).unwrap();

        let mut log = CaLog::open(&path.with_extension("sqlite3"), Some(&path)).unwrap();
        assert!(log.users().is_empty());
        assert!(log.invites().is_empty());

        // Doom every subsequent write, as a full disk would.
        log.fail_commits();

        let (_, persisted) = log.mutate_users_and_invites(|users, invites| {
            users.push(
                UserRecord::new("rowan", "hunter2", crate::users::UserRole::Viewer, 3600).unwrap(),
            );
            invites.push(crate::users::UserInvite::new(
                "wren",
                crate::users::UserRole::Viewer,
                3600,
                [7u8; 32],
                0,
                1,
            ));
        });
        assert!(
            persisted.is_err(),
            "the write should have failed: its directory is gone"
        );

        assert!(
            log.users().is_empty(),
            "the account must roll back with the invite deletion, or a failed \
             persist leaves an account nobody asked to create"
        );
        assert!(
            log.invites().is_empty(),
            "and the invite side must roll back too — the split is exactly the \
             hazard this method exists to close"
        );
    }

    /// A snapshot written before invites existed loads with an empty invite
    /// store, which is not a loss of state but a faithful description of a
    /// provider that had no invite store at all.
    #[test]
    fn a_v5_snapshot_migrates_forward_with_an_empty_invite_store() {
        let dir = unique_dir("v5-migration");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "version": 5,
                "issued": [],
                "held": [],
                "users": [{
                    "username": "ops",
                    "password_hash": "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
                    "totp_secret": null,
                    "session_ttl_secs": 3600,
                }],
            })
            .to_string(),
        )
        .unwrap();

        let log = CaLog::open(&path.with_extension("sqlite3"), Some(&path)).unwrap();

        assert_eq!(log.users().len(), 1, "the account survives the migration");
        assert!(
            log.invites().is_empty(),
            "and the invite store starts empty rather than being invented"
        );

        // The migrated state is what the database now holds.
        drop(log);
        let log = CaLog::open(&path.with_extension("sqlite3"), Some(&path)).unwrap();
        assert_eq!(log.users().len(), 1);
        assert!(log.invites().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A snapshot written before accounts had ids gives each one its own,
    /// freshly minted.
    ///
    /// Per account, not one shared default: the id is what links a session
    /// certificate to its owner, so two accounts sharing one would make every
    /// revocation cut both. That is the whole failure mode a `#[serde(default)]`
    /// returning a constant would introduce, and it would be invisible until
    /// somebody was cut off by somebody else's removal.
    #[test]
    fn a_v6_snapshot_mints_a_distinct_account_id_per_account() {
        let dir = unique_dir("v6-migration");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let hash = "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2g";
        let key = [0u8; 32];
        std::fs::write(
            &path,
            serde_json::json!({
                "version": 6,
                "issued": [{
                    "node_mac": [0, 0, 0, 0, 0, 1],
                    "ed_pubkey": key,
                    "not_before": 0,
                    "not_after": 1,
                    "revoked": false,
                }],
                "held": [],
                "invites": [],
                "users": [
                    {
                        "username": "ops",
                        "password_hash": hash,
                        "totp_secret": null,
                        "session_ttl_secs": 3600,
                    },
                    {
                        "username": "watcher",
                        "password_hash": hash,
                        "totp_secret": null,
                        "session_ttl_secs": 3600,
                    },
                ],
            })
            .to_string(),
        )
        .unwrap();

        let mut log = CaLog::open(&path.with_extension("sqlite3"), Some(&path)).unwrap();

        assert_eq!(log.users().len(), 2, "both accounts survive the migration");
        assert_ne!(
            log.users()[0].id,
            log.users()[1].id,
            "each account is given its own id, or a revocation would cut both"
        );
        assert!(
            log.issued()[0].account_id.is_empty(),
            "a certificate from before the link existed is attributed to nobody,              which is the honest answer rather than a guess"
        );

        // The ids minted on import are committed with it, so they are the
        // same ids after a restart — before any account has been touched.
        let minted: Vec<_> = log.users().iter().map(|u| u.id).collect();
        let (_, persisted) = log.mutate_users(|_| {});
        persisted.unwrap();
        drop(log);
        let log = CaLog::open(&path.with_extension("sqlite3"), Some(&path)).unwrap();
        let reloaded: Vec<_> = log.users().iter().map(|u| u.id).collect();
        assert_eq!(reloaded, minted);

        std::fs::remove_dir_all(&dir).ok();
    }

    // ── the SQLite-backed log (design 26 phase 2) ─────────────────────────

    use crate::ca_store::CaStore;
    use crate::ca_store::ChangeSet;
    use crate::ca_store::Loaded;
    use crate::ca_store::SqliteStore;
    use std::sync::Arc;
    use std::sync::Mutex;

    /// A store that records every change set it is asked to commit, so a test
    /// can see exactly which rows a mutation wrote.
    struct RecordingStore {
        inner: SqliteStore,
        commits: Arc<Mutex<Vec<ChangeSet>>>,
    }

    impl CaStore for RecordingStore {
        fn load(&mut self) -> Result<Loaded, String> {
            self.inner.load()
        }

        fn commit(&mut self, change: &ChangeSet) -> Result<Vec<i64>, String> {
            self.commits.lock().unwrap().push(change.clone());
            self.inner.commit(change)
        }
    }

    fn recording_log() -> (CaLog, Arc<Mutex<Vec<ChangeSet>>>) {
        let commits = Arc::new(Mutex::new(Vec::new()));
        let store = RecordingStore {
            inner: SqliteStore::open_in_memory().unwrap(),
            commits: Arc::clone(&commits),
        };
        let log = CaLog::with_store(Box::new(store), None).unwrap();
        commits.lock().unwrap().clear();
        (log, commits)
    }

    fn user(name: &str) -> UserRecord {
        UserRecord::new(name, "correct horse", crate::users::UserRole::Admin, 900).unwrap()
    }

    /// The problem the store exists to solve: a login rewrote the whole CA.
    /// Now changing one account writes that account's row and nothing else —
    /// not the other accounts, and not the issued log beside them.
    #[test]
    fn a_mutation_writes_only_the_rows_it_changed() {
        let (mut log, commits) = recording_log();
        let (_, r) = log.mutate_users(|users| {
            users.push(user("a"));
            users.push(user("b"));
            users.push(user("c"));
        });
        r.unwrap();
        assert_eq!(commits.lock().unwrap().last().unwrap().inserts().len(), 3);

        let (_, r) = log.mutate_users(|users| users[1].failed_attempts += 1);
        r.unwrap();
        let commits = commits.lock().unwrap();
        let change = commits.last().unwrap();
        assert_eq!(
            change.inserts().len(),
            1,
            "only the changed account is written"
        );
        assert_eq!(change.deletes().len(), 1, "and only its old row is removed");
    }

    /// A mutation that changes nothing writes nothing — the common case for a
    /// read-modify-write that finds nothing to modify.
    #[test]
    fn a_mutation_that_changes_nothing_writes_nothing() {
        let (mut log, commits) = recording_log();
        let (_, r) = log.mutate_users(|users| users.push(user("a")));
        r.unwrap();
        let before = commits.lock().unwrap().len();

        let (_, r) = log.mutate_users(|_| {});
        r.unwrap();
        let commits = commits.lock().unwrap();
        assert!(
            commits.len() == before || commits.last().unwrap().is_empty(),
            "an unchanged collection must not be rewritten"
        );
    }

    /// Everything a CA holds comes back after a restart, through the database.
    #[test]
    fn state_survives_a_restart_through_the_database() {
        let dir = unique_dir("sqlite-restart");
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("ca.sqlite3");
        {
            let mut log = CaLog::open(&db, None).unwrap();
            log.mutate_users(|users| users.push(user("ops"))).1.unwrap();
            log.mutate_policy(|p| p.auto_approve = Some(true))
                .1
                .unwrap();
        }
        let log = CaLog::open(&db, None).unwrap();
        assert_eq!(log.users().len(), 1);
        assert_eq!(log.users()[0].username, "ops");
        assert_eq!(log.policy().auto_approve, Some(true));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A commit that fails rolls every collection the mutation touched back,
    /// in memory as well as on disk.
    #[test]
    fn a_failed_commit_rolls_back_every_collection_touched() {
        let (mut log, _) = recording_log();
        log.mutate_users(|users| users.push(user("kept")))
            .1
            .unwrap();
        log.fail_commits();

        let (_, r) = log.mutate_users_and_invites(|users, invites| {
            users.clear();
            invites.clear();
        });
        assert!(r.is_err());
        assert_eq!(log.users().len(), 1, "the in-memory users rolled back");
        assert_eq!(log.users()[0].username, "kept");
    }

    /// On its first start against an empty database, a CA takes its state from
    /// the `ca-state.json` it ran on before, commits it, and moves the file
    /// aside — so the import happens once, and the file is kept rather than
    /// deleted.
    #[test]
    fn a_legacy_snapshot_is_imported_once_and_moved_aside() {
        let dir = unique_dir("import");
        std::fs::create_dir_all(&dir).unwrap();
        let json = dir.join("ca-state.json");
        let db = dir.join("ca.sqlite3");
        std::fs::write(&json, seed_snapshot().to_string()).unwrap();

        let log = CaLog::open(&db, Some(&json)).unwrap();
        assert_eq!(log.issued().len(), 1);
        assert_eq!(log.held().len(), 1);
        assert!(!json.exists(), "the snapshot is moved aside once imported");
        assert!(dir.join("ca-state.json.imported").exists());
        drop(log);

        let log = CaLog::open(&db, Some(&json)).unwrap();
        assert_eq!(
            log.issued().len(),
            1,
            "the imported state is in the database"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The import runs through the versioned loader, so a snapshot from any
    /// schema version upgrades on the way in — here a v1, which had no held
    /// CSRs at all.
    #[test]
    fn an_old_schema_snapshot_upgrades_on_import() {
        let dir = unique_dir("import-v1");
        std::fs::create_dir_all(&dir).unwrap();
        let json = dir.join("ca-state.json");
        let key = [0u8; 32];
        std::fs::write(
            &json,
            serde_json::json!({
                "version": 1,
                "issued": [{
                    "node_mac": [0, 0, 0, 0, 0, 1],
                    "ed_pubkey": key,
                    "not_before": 0,
                    "not_after": 1,
                    "revoked": true,
                }],
            })
            .to_string(),
        )
        .unwrap();
        let log = CaLog::open(&dir.join("ca.sqlite3"), Some(&json)).unwrap();
        assert_eq!(log.issued().len(), 1);
        assert!(log.issued()[0].revoked);
        assert!(log.held().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A snapshot still sitting beside a database that already holds a CA is
    /// either the leftover of an import that committed but crashed before the
    /// rename — same contents, so finish the rename — or two different CAs, and
    /// then neither can be picked without losing the other's revocations.
    #[test]
    fn a_snapshot_beside_a_database_that_disagrees_fails_closed() {
        let dir = unique_dir("import-conflict");
        std::fs::create_dir_all(&dir).unwrap();
        let json = dir.join("ca-state.json");
        let db = dir.join("ca.sqlite3");
        {
            let mut log = CaLog::open(&db, None).unwrap();
            log.mutate_users(|users| users.push(user("someone-else")))
                .1
                .unwrap();
        }
        std::fs::write(&json, seed_snapshot().to_string()).unwrap();

        let err = CaLog::open(&db, Some(&json))
            .err()
            .expect("must fail closed");
        assert!(
            err.contains("ca-state.json"),
            "the error names the file: {err}"
        );
        assert!(json.exists(), "nothing is moved aside when refusing");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_snapshot_beside_a_database_that_agrees_finishes_the_import() {
        let dir = unique_dir("import-resume");
        std::fs::create_dir_all(&dir).unwrap();
        let json = dir.join("ca-state.json");
        let db = dir.join("ca.sqlite3");
        std::fs::write(&json, seed_snapshot().to_string()).unwrap();
        drop(CaLog::open(&db, Some(&json)).unwrap());
        // Put the file back as though the rename had never happened.
        std::fs::rename(dir.join("ca-state.json.imported"), &json).unwrap();

        let log = CaLog::open(&db, Some(&json)).unwrap();
        assert_eq!(log.issued().len(), 1, "imported once, not twice");
        assert!(!json.exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
