//! The board's [`SettingsStore`]: what makes a management-API write durable
//! on a node with no filesystem.
//!
//! `RouterAdapter::with_settings` is the seam `SetAuth` and the runtime config
//! writes go through, and until now a board supplied nothing for it — so a
//! credential installed over a board's management port lived until the next
//! reset and no further. This is the other half of
//! [`crate::identity`]'s record: the record is *what* is kept, this is *who*
//! writes it.
//!
//! Designed in `docs/design/implemented/22-embedded-node-record.md` §4.1.
//!
//! # Two shapes of the same state
//!
//! The adapter speaks `NodeSettings`; the medium holds a [`NodeRecord`]. They
//! are not the same shape and the difference is deliberate — a board has a
//! seed from its first boot and a credential only later, so the record hoists
//! the seed out of the identity that a host keeps it inside. [`RecordSettings`]
//! holds both: the record, and the `NodeSettings` view of it that
//! [`SettingsStore::settings`] must be able to hand out by reference. The two
//! are only ever advanced together, and a persist that fails advances neither.

use alloc::string::String;

use wayfinder_protos::service::RenewalProviderData;
use wayfinder_protos::service::RenewalTargetData;
use wayfinder_protos::service::SharedSecret;

use wayfinder_server::NodeIdentity;
use wayfinder_server::NodeSettings;
use wayfinder_server::SettingsStore;
use wayfinder_storage::DurableStore;
use wayfinder_storage::PersistError;
use wayfinder_storage::Persisted;

use crate::NodeStore;
use crate::identity::NodeRecord;
use crate::identity::RecordCodec;

/// A board's [`SettingsStore`], backed by its durable [`NodeRecord`].
pub struct RecordSettings<S: DurableStore> {
    record: Persisted<NodeRecord, S, RecordCodec>,
    /// The `NodeSettings` projection of `record`, kept in step with it so
    /// [`SettingsStore::settings`] can return a reference.
    view: NodeSettings,
}

impl<S: DurableStore> RecordSettings<S>
where
    S::Error: core::fmt::Debug,
{
    /// Wrap a record loaded by
    /// [`load_or_init_record`](crate::identity::load_or_init_record).
    pub fn new(record: Persisted<NodeRecord, S, RecordCodec>) -> RecordSettings<S> {
        let view = project(record.get());
        RecordSettings { record, view }
    }

    /// The durable record behind these settings — for the boot path, which
    /// needs the seed and the clock checkpoint that `NodeSettings` has no
    /// field for.
    pub fn record(&self) -> &NodeRecord {
        self.record.get()
    }
}

impl<S: DurableStore> NodeStore for RecordSettings<S>
where
    S::Error: core::fmt::Debug,
{
    fn stored_checkpoint(&self) -> Option<u64> {
        Some(self.record.get().checkpoint_unix)
    }

    /// Through [`Persisted::mutate`] and *not* `mutate_sealed`: this replaces
    /// no secret, and it is the frequent writer whose wear budget design 22
    /// §4.5 sizes at one erase per write. It is also why the checkpoint lives
    /// in the same blob as the credential rather than beside it — design 20
    /// §4.5 requires the two be written, loaded and erased together.
    fn checkpoint(&mut self, unix: u64) -> Result<(), String> {
        let (_, outcome) = self.record.mutate(|record| record.checkpoint_unix = unix);
        describe(outcome)
    }
}

/// The `NodeSettings` a record presents to the adapter.
///
/// The identity is `Some` only when the record holds *both* a certificate and
/// the anchor it chains to: a certificate that cannot be verified against
/// anything is not an identity, and `NodeIdentity`'s own doc makes the point
/// that a half-updated identity is non-functional rather than merely weaker.
fn project(record: &NodeRecord) -> NodeSettings {
    NodeSettings {
        require_auth: record.require_auth,
        lazy_cert_distribution: record.lazy_cert_distribution,
        identity: record
            .cert
            .zip(record.trust_anchor)
            .map(|(cert, trust_anchor)| NodeIdentity {
                seed: record.seed.to_vec(),
                cert: cert.to_vec(),
                trust_anchor: trust_anchor.to_vec(),
                // The pinned key and nothing else, because that is all the
                // record keeps — see `NodeRecord::renewal_provider_key`. A
                // board renews over the mesh (design 24), so it has no use for
                // the socket address or the enrollment token a host's client
                // connection presents, and reporting either would be a claim
                // about something this node does not do.
                //
                // Design 22 §4.2 had this as a flat `None`, on the reasoning
                // that a board cannot renew at all. That reasoning is what
                // design 24 overturned.
                provider: record
                    .renewal_provider_key
                    .map(|node_key| RenewalProviderData {
                        target: RenewalTargetData {
                            address: String::new(),
                            node_key,
                        },
                        enrollment_token: SharedSecret::new(""),
                    }),
            }),
        self_revocation: record.self_revocation.map(|r| r.to_vec()),
    }
}

/// The record `settings` describes, starting from `base`.
///
/// `base` is what carries the fields `NodeSettings` has no room for — the
/// clock checkpoint, and the seed of a board that holds no credential yet.
/// Rebuilding a record from the settings alone would drop the checkpoint on
/// every `SetAuth`, which is exactly what design 20 §4.5 forbids.
fn apply(base: &NodeRecord, settings: &NodeSettings) -> Result<NodeRecord, String> {
    let mut next = base.clone();
    next.require_auth = settings.require_auth;
    next.lazy_cert_distribution = settings.lazy_cert_distribution;

    if let Some(identity) = &settings.identity {
        next.seed = fixed(&identity.seed, "seed")?;
        next.cert = Some(fixed(&identity.cert, "certificate")?);
        next.trust_anchor = Some(fixed(&identity.trust_anchor, "trust anchor")?);
        // Replaced wholesale with the credential it arrived beside, never
        // merged: an install naming no provider leaves none behind, so a board
        // re-enrolled somewhere else stops renewing against where it was.
        next.renewal_provider_key = identity.provider.as_ref().map(|p| p.target.node_key);
    }

    // `settings` is always a *merged* value, and `NodeSettings::merge` has
    // already resolved both of this field's conventions: absent means "leave
    // alone", and the empty vector a re-admitting `SetAuth` writes to mean
    // "clear" has already become `None`. So there is deliberately no
    // empty-vector arm here — one would be dead code implying this is where
    // the clear happens, which is somewhere else.
    next.self_revocation = match &settings.self_revocation {
        Some(record) => Some(fixed(record, "revocation")?),
        None => None,
    };
    Ok(next)
}

/// A blob of exactly `N` bytes, or a message naming which field was wrong.
///
/// The record stores these verbatim and never parses them — they are what the
/// next boot parses, and re-encoding them here would only add a way for the
/// stored and the intended to disagree. That makes this length check the only
/// thing between a malformed install and a record the next boot cannot read.
fn fixed<const N: usize>(bytes: &[u8], field: &str) -> Result<[u8; N], String> {
    bytes.try_into().map_err(|_| {
        alloc::format!(
            "{field} must be exactly {N} bytes, got {len}",
            len = bytes.len()
        )
    })
}

/// Render a persist outcome as the `String` error [`SettingsStore`] speaks.
///
/// Deliberately does **not** log. It serves two callers with different subjects
/// — a settings change and a clock checkpoint — so anything it said would be
/// wrong for one of them, and the checkpoint path already logs this failure
/// itself with the cause in a field. A `warn!` here produced two records per
/// failure, one of them naming the wrong thing and carrying no cause at all.
fn describe<SE, CE>(outcome: Result<(), PersistError<SE, CE>>) -> Result<(), String>
where
    SE: core::fmt::Debug,
    CE: core::fmt::Debug,
{
    outcome.map_err(|e| match e {
        PersistError::Encode(e) => alloc::format!("could not encode the node record: {e:?}"),
        PersistError::Store(e) => alloc::format!("could not write the node record to flash: {e:?}"),
    })
}

impl<S: DurableStore> SettingsStore for RecordSettings<S>
where
    S::Error: core::fmt::Debug,
{
    fn settings(&self) -> &NodeSettings {
        &self.view
    }

    fn persist(&mut self, update: NodeSettings) -> Result<(), String> {
        let mut merged = self.view.clone();
        merged.merge(update);
        // Projected before anything is written, so a malformed blob is refused
        // without spending an erase — and, per the trait's contract, without
        // the change being applied in memory either.
        let next = apply(self.record.get(), &merged)?;

        // Only a change of *seed* supersedes a secret. A flag change or a
        // checkpoint does not, and paying an extra erase for one would spend
        // the budget design 22 §4.5 sizes for the checkpoint.
        let rotates_seed = next.seed != self.record.get().seed;
        let (_, outcome) = if rotates_seed {
            self.record.mutate_sealed(|record| *record = next)
        } else {
            self.record.mutate(|record| *record = next)
        };
        describe(outcome)?;

        // Advanced last, and only on a write that landed: `mutate` has already
        // rolled the record back on failure, and the view must not be the one
        // place that remembers a change the medium does not.
        //
        // Projected from the record rather than assigned from `merged`, so the
        // two cannot differ in *content* either. They could: the record keeps
        // only the pinned half of a renewal provider (design 24 §4.4), and a
        // view carrying the address and token the medium does not would report
        // a renewal target that vanishes at the next reset — a durable lie told
        // in memory.
        self.view = project(self.record.get());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use std::rc::Rc;
    use wayfinder::wayfinder_auth::Keypair;
    use wayfinder::wayfinder_auth::MembershipCert;
    use wayfinder::wayfinder_auth::RevocationRecord;
    use wayfinder::wayfinder_auth::TrustAnchor;
    use wayfinder_server::NodeIdentity;
    use wayfinder_server::NodeSettings;
    use wayfinder_server::SettingsStore;
    use wayfinder_storage::DurableStore;
    use wayfinder_storage::Persisted;

    use crate::identity::NodeRecord;
    use crate::identity::RECORD_READ_BUF_LEN;
    use crate::identity::RecordCodec;
    use crate::identity::load_or_init_record;

    fn seed(n: u8) -> [u8; Keypair::SEED_LEN] {
        [n; Keypair::SEED_LEN]
    }

    /// An in-memory [`DurableStore`] shared via `Rc<RefCell<_>>` so a test can
    /// reload through a second handle to see what durably landed, and which
    /// records its calls in order — the scrub properties below are about
    /// *which* writes pay for an erase, not about final state.
    #[derive(Default, Clone)]
    struct MemStore {
        blob: Rc<RefCell<Option<Vec<u8>>>>,
        calls: Rc<RefCell<Vec<&'static str>>>,
    }

    impl MemStore {
        fn calls(&self) -> Vec<&'static str> {
            self.calls.borrow().clone()
        }
    }

    impl DurableStore for MemStore {
        type Error = core::convert::Infallible;

        fn load(&mut self, out: &mut [u8]) -> Result<Option<usize>, Self::Error> {
            self.calls.borrow_mut().push("load");
            Ok(self.blob.borrow().as_ref().map(|b| {
                out[..b.len()].copy_from_slice(b);
                b.len()
            }))
        }

        fn save(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            self.calls.borrow_mut().push("save");
            *self.blob.borrow_mut() = Some(data.to_vec());
            Ok(())
        }

        fn scrub(&mut self) -> Result<(), Self::Error> {
            self.calls.borrow_mut().push("scrub");
            Ok(())
        }

        fn erase(&mut self) -> Result<(), Self::Error> {
            self.calls.borrow_mut().push("erase");
            *self.blob.borrow_mut() = None;
            Ok(())
        }
    }

    /// A store whose `save` always fails, for the rollback contract.
    #[derive(Default)]
    struct FailingStore;

    impl DurableStore for FailingStore {
        type Error = &'static str;

        fn load(&mut self, _out: &mut [u8]) -> Result<Option<usize>, Self::Error> {
            Ok(None)
        }

        fn save(&mut self, _data: &[u8]) -> Result<(), Self::Error> {
            Err("flash write failed")
        }

        fn erase(&mut self) -> Result<(), Self::Error> {
            Err("flash write failed")
        }
    }

    /// A settings store over a fresh in-memory medium, plus the handle to
    /// reload through.
    fn fresh(seed_byte: u8) -> (RecordSettings<MemStore>, MemStore) {
        let store = MemStore::default();
        let mut buf = [0u8; RECORD_READ_BUF_LEN];
        let (record, _) = load_or_init_record(store.clone(), || seed(seed_byte), &mut buf).unwrap();
        (RecordSettings::new(record), store)
    }

    /// Reload a settings store from a medium that already holds a record.
    fn reload(store: MemStore) -> RecordSettings<MemStore> {
        let mut buf = [0u8; RECORD_READ_BUF_LEN];
        let (record, _) =
            load_or_init_record(store, || panic!("already provisioned"), &mut buf).unwrap();
        RecordSettings::new(record)
    }

    /// A `NodeIdentity` naming `seed_byte`'s seed, with well-formed blobs.
    fn identity(seed_byte: u8) -> NodeIdentity {
        NodeIdentity {
            seed: seed(seed_byte).to_vec(),
            cert: vec![0xC0; MembershipCert::SERIALIZED_LEN],
            trust_anchor: vec![0xA0; TrustAnchor::SERIALIZED_LEN],
            provider: None,
        }
    }

    /// A board that has only ever minted a seed presents no overrides at all —
    /// which is what keeps the build's startup defaults authoritative.
    #[test]
    fn a_fresh_record_presents_no_overrides() {
        let (store, _) = fresh(0x11);
        assert!(store.settings().is_empty());
    }

    /// **A seed without a credential is not an identity.** `NodeIdentity`
    /// bundles a seed with a certificate because on a host the three arrive
    /// together; a board has the seed from its first boot and only later,
    /// maybe, the rest. Design 22 §4.1.
    #[test]
    fn a_seed_alone_does_not_present_as_an_identity() {
        let (store, _) = fresh(0x22);
        assert_eq!(store.settings().identity, None);
        assert_eq!(store.record().seed, seed(0x22));
    }

    /// A stored credential presents as a `NodeIdentity` carrying the record's
    /// own seed — the seed is put back into the shape the adapter expects, and
    /// there is only ever one of it.
    #[test]
    fn a_stored_credential_presents_as_an_identity_carrying_the_record_seed() {
        let (mut store, medium) = fresh(0x33);
        store
            .persist(NodeSettings {
                identity: Some(identity(0x44)),
                ..Default::default()
            })
            .unwrap();

        let reloaded = reload(medium);
        let id = reloaded.settings().identity.clone().expect("installed");
        assert_eq!(id.seed, seed(0x44).to_vec());
        assert_eq!(id.cert, vec![0xC0; MembershipCert::SERIALIZED_LEN]);
        assert_eq!(id.trust_anchor, vec![0xA0; TrustAnchor::SERIALIZED_LEN]);
        assert_eq!(
            reloaded.record().seed,
            seed(0x44),
            "installing an identity replaces the board's seed, so its address follows on \
             the next boot"
        );
    }

    /// **Installing an identity scrubs.** It replaces the seed, and the copy
    /// the flash store keeps behind to provide atomicity would otherwise hold
    /// the previous private key in the clear. Design 22 §4.4.
    #[test]
    fn installing_an_identity_persists_and_then_scrubs() {
        let (mut store, medium) = fresh(0x55);
        let before = medium.calls().len();

        store
            .persist(NodeSettings {
                identity: Some(identity(0x66)),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(&medium.calls()[before..], &["save", "scrub"]);
    }

    /// A change that does not touch the seed does **not** scrub: the extra
    /// erase is what the checkpoint's wear budget cannot afford (design 22
    /// §4.5), and there is no superseded secret to erase.
    #[test]
    fn a_settings_change_that_keeps_the_seed_does_not_scrub() {
        let (mut store, medium) = fresh(0x77);
        let before = medium.calls().len();

        store
            .persist(NodeSettings {
                require_auth: Some(true),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(&medium.calls()[before..], &["save"]);
        assert_eq!(reload(medium).settings().require_auth, Some(true));
    }

    /// Re-installing the *same* seed is not a rotation and needs no scrub —
    /// certifying the identity a board already holds, which is the enrolment
    /// shape #55 will use.
    #[test]
    fn recertifying_the_same_seed_does_not_scrub() {
        let (mut store, medium) = fresh(0x88);
        store
            .persist(NodeSettings {
                identity: Some(identity(0x99)),
                ..Default::default()
            })
            .unwrap();
        let before = medium.calls().len();

        store
            .persist(NodeSettings {
                identity: Some(NodeIdentity {
                    cert: vec![0xC1; MembershipCert::SERIALIZED_LEN],
                    ..identity(0x99)
                }),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(&medium.calls()[before..], &["save"]);
    }

    /// **The checkpoint survives a credential install**, because they are one
    /// blob. Design 20 §4.5 requires the checkpoint be written, loaded and
    /// erased *with* the credential; a projection that rebuilt the record from
    /// the settings alone would silently drop it on every `SetAuth`.
    #[test]
    fn installing_a_credential_leaves_the_clock_checkpoint_alone() {
        let (mut store, medium) = fresh(0xAA);
        store.checkpoint(1_800_000_000).unwrap();

        store
            .persist(NodeSettings {
                identity: Some(identity(0xBB)),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(reload(medium).record().checkpoint_unix, 1_800_000_000);
    }

    /// A checkpoint write persists the new high-water mark and does not scrub:
    /// it replaces no secret, and this is the write whose wear budget design
    /// 22 §4.5 sizes at one erase.
    #[test]
    fn a_checkpoint_write_persists_without_scrubbing() {
        let (mut store, medium) = fresh(0xCC);
        let before = medium.calls().len();

        store.checkpoint(1_800_000_000).unwrap();

        assert_eq!(&medium.calls()[before..], &["save"]);
        assert_eq!(reload(medium).record().checkpoint_unix, 1_800_000_000);
    }

    /// The `SettingsStore` contract's rollback clause: a change that could not
    /// be made durable must leave the recorded settings exactly as they were,
    /// so a caller reads it as "this did not take effect" rather than "this is
    /// not durable yet".
    #[test]
    fn a_persist_that_cannot_be_made_durable_changes_nothing() {
        // Built directly rather than through the loader: on a store that
        // cannot write, the loader's own mint would fail first and there would
        // be no settings store to test.
        let mut store = RecordSettings::new(Persisted::new(
            NodeRecord::fresh(seed(0xDD)),
            FailingStore,
            RecordCodec,
        ));

        let err = store
            .persist(NodeSettings {
                require_auth: Some(true),
                ..Default::default()
            })
            .expect_err("the store cannot write");
        assert!(err.contains("flash write failed"), "got: {err}");

        assert!(
            store.settings().is_empty(),
            "a failed persist must not be applied in memory either"
        );
        assert_eq!(store.record().seed, seed(0xDD));
    }

    /// A seed of the wrong length is refused, and refused *before* anything is
    /// written: the record's seed is a fixed 32 bytes, and a caller handing
    /// over 31 has a bug the node must name rather than pad.
    #[test]
    fn an_identity_whose_seed_is_the_wrong_length_is_refused() {
        let (mut store, medium) = fresh(0xEE);
        let before = medium.calls().len();

        let err = store
            .persist(NodeSettings {
                identity: Some(NodeIdentity {
                    seed: vec![0x01; Keypair::SEED_LEN - 1],
                    ..identity(0x01)
                }),
                ..Default::default()
            })
            .expect_err("a 31-byte seed is not a seed");
        assert!(
            err.contains("seed"),
            "the message must name the field: {err}"
        );

        assert_eq!(medium.calls().len(), before, "nothing was written");
        assert_eq!(store.record().seed, seed(0xEE));
    }

    /// Likewise a certificate that is not a `MembershipCert`'s length. The
    /// record stores the bytes as received and never parses them, so this
    /// length check is the only thing standing between a malformed install and
    /// a record the next boot cannot make sense of.
    #[test]
    fn an_identity_whose_certificate_is_the_wrong_length_is_refused() {
        let (mut store, _) = fresh(0x12);

        let err = store
            .persist(NodeSettings {
                identity: Some(NodeIdentity {
                    cert: vec![0xC0; MembershipCert::SERIALIZED_LEN + 1],
                    ..identity(0x13)
                }),
                ..Default::default()
            })
            .expect_err("a cert one byte too long is not a cert");
        assert!(err.contains("certificate"), "got: {err}");
        assert_eq!(store.settings().identity, None);
    }

    /// ...and a trust anchor.
    #[test]
    fn an_identity_whose_trust_anchor_is_the_wrong_length_is_refused() {
        let (mut store, _) = fresh(0x14);

        let err = store
            .persist(NodeSettings {
                identity: Some(NodeIdentity {
                    trust_anchor: vec![0xA0; TrustAnchor::SERIALIZED_LEN - 1],
                    ..identity(0x15)
                }),
                ..Default::default()
            })
            .expect_err("a short anchor is not an anchor");
        assert!(err.contains("trust anchor"), "got: {err}");
        assert_eq!(store.settings().identity, None);
    }
    /// **A board persists the authority it renews against.**
    ///
    /// This replaces `a_renewal_provider_is_not_persisted`, which guarded the
    /// opposite behaviour and is deleted here because design 24 makes it false.
    /// The comment it stood on said a board "cannot renew its own certificate",
    /// which was true only because renewal meant opening a client connection
    /// and a board has no IP stack to open one with. It is a routing member of
    /// a mesh the authority is also on, so it renews over that.
    ///
    /// What is kept is the provider's **pinned key** and nothing else. The MAC
    /// to route a renewal to is derived from it (design 09 §5), so storing both
    /// would store one fact twice with the two able to disagree; the socket
    /// address and the enrollment token are for the client connection a board
    /// will never open, and keeping them would be a durable claim about
    /// something this node does not do.
    #[test]
    fn a_board_persists_the_provider_it_renews_against() {
        use wayfinder_protos::service::RenewalProviderData;
        use wayfinder_protos::service::RenewalTargetData;
        use wayfinder_protos::service::SharedSecret;

        let (mut store, medium) = fresh(0x16);
        store
            .persist(NodeSettings {
                identity: Some(NodeIdentity {
                    provider: Some(RenewalProviderData {
                        target: RenewalTargetData {
                            address: "ca.example:7700".into(),
                            node_key: [0x0B; 32],
                        },
                        enrollment_token: SharedSecret::new("s3cret"),
                    }),
                    ..identity(0x17)
                }),
                ..Default::default()
            })
            .unwrap();

        let reloaded = reload(medium);
        let provider = reloaded
            .settings()
            .identity
            .as_ref()
            .and_then(|i| i.provider.clone())
            .expect("the authority to renew against survives a reset");
        assert_eq!(provider.target.node_key, [0x0B; 32]);
        assert_eq!(
            provider.target.address, "",
            "a board keeps no socket address: it has no stack to dial one with"
        );
        assert_eq!(
            provider.enrollment_token.expose(),
            "",
            "and no enrollment token, which only the client connection would present"
        );
    }

    /// A self-revocation survives a reset. Design 16's whole premise is a
    /// record the node re-verifies against its trust anchor on every boot, and
    /// today a board loses it on the first power cycle.
    #[test]
    fn a_self_revocation_survives_a_reload() {
        let (mut store, medium) = fresh(0x18);

        store
            .persist(NodeSettings {
                self_revocation: Some(vec![0x9E; RevocationRecord::SERIALIZED_LEN]),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(
            reload(medium).settings().self_revocation,
            Some(vec![0x9E; RevocationRecord::SERIALIZED_LEN])
        );
    }

    /// An **empty** revocation clears the stored one — `NodeSettings::merge`'s
    /// convention, which the adapter relies on to drop a record in the same
    /// durable write that installs a re-admitting certificate. The projection
    /// onto the record has to preserve it, or a re-admitted board re-locks
    /// itself on its next boot.
    #[test]
    fn an_empty_self_revocation_clears_the_stored_one() {
        let (mut store, medium) = fresh(0x19);
        store
            .persist(NodeSettings {
                self_revocation: Some(vec![0x9E; RevocationRecord::SERIALIZED_LEN]),
                ..Default::default()
            })
            .unwrap();

        store
            .persist(NodeSettings {
                self_revocation: Some(Vec::new()),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(store.settings().self_revocation, None);
        assert_eq!(reload(medium).record().self_revocation, None);
    }

    /// A revocation of the wrong length is refused rather than stored, for the
    /// same reason as the certificate: nothing downstream re-checks it.
    #[test]
    fn a_self_revocation_of_the_wrong_length_is_refused() {
        let (mut store, _) = fresh(0x1A);

        let err = store
            .persist(NodeSettings {
                self_revocation: Some(vec![0x9E; RevocationRecord::SERIALIZED_LEN + 1]),
                ..Default::default()
            })
            .expect_err("a long revocation is not a revocation");
        assert!(err.contains("revocation"), "got: {err}");
    }
}
