//! This node's durable identity: a seed minted once from the chip's RNG and
//! kept in flash, with the mesh address derived from it.
//!
//! Design 22. Two identities live here and they are deliberately different
//! things:
//!
//! - The **mesh address** is `Keypair::from_seed(&seed).derived_mac()`. Since
//!   design 09 §5 a certificate's MAC *is* the address its identity key
//!   derives, so deriving it here is what makes a certificate issued for this
//!   node a certificate for the address it actually routes under. It changes
//!   when the seed does — on the next boot after a `SetAuth`, never mid-flight.
//! - The **board id** is [`from_ficr`], the chip's factory-unique device ID.
//!   It names a physical part, not a mesh node, so it does not move when the
//!   node's identity does. It is the USB serial number (see
//!   [`crate::usb_mgmt`]) and the address a board with no usable flash falls
//!   back to.
//!
//! # Why the seed is not derived from FICR
//!
//! The device ID is a 64-bit factory value that is not secret — anything on
//! the chip can read it, and it is printed on the part — so a private key
//! derived from it is derivable by anyone who knows it. A *public address*
//! derived from FICR is fine, because an address is public by nature. The two
//! uses are not interchangeable, which is the whole reason both functions are
//! in this file.

use embassy_nrf::Peri;
use embassy_nrf::nvmc::Nvmc;
use embassy_nrf::peripherals::NVMC;
use embassy_nrf::peripherals::RNG;
use embassy_nrf::rng::Rng;
use tracing::error;
use tracing::info;
use tracing::warn;
use wayfinder::interfaces::frame::Mac;
use wayfinder::wayfinder_auth::Keypair;
use wayfinder_embedded_driver::NodeStore;
use wayfinder_embedded_driver::NullStore;
use wayfinder_embedded_driver::identity::IdentityError;
use wayfinder_embedded_driver::identity::NodeRecord;
use wayfinder_embedded_driver::identity::Provisioned;
use wayfinder_embedded_driver::identity::RECORD_READ_BUF_LEN;
use wayfinder_embedded_driver::identity::load_or_init_record;
use wayfinder_embedded_driver::settings::RecordSettings;
use wayfinder_storage::FlashStore;

/// The board's durable store, once its flash geometry has been accepted.
type BoardStore = RecordSettings<FlashStore<Nvmc<'static>>>;

/// Derive this **board's** identifier from the nRF52840's factory-programmed
/// FICR device ID.
///
/// A per-chip unique 64-bit value burned in at manufacture, so it is stable
/// across reboots and across reflashing, and distinct between physical boards
/// with no provisioning step. The top octet is forced to locally-administered
/// unicast (L/A bit set, I/G multicast bit cleared) so the value is a
/// well-formed MAC wherever one is wanted.
///
/// This is **not** the node's mesh address on a board with a durable store —
/// see the module docs. It is what identifies the part: the USB serial number,
/// and the fallback address for a board that has nowhere to keep a seed.
pub fn from_ficr() -> Mac {
    let ficr = embassy_nrf::pac::FICR;
    let lo = ficr.deviceid(0).read().to_le_bytes();
    let hi = ficr.deviceid(1).read().to_le_bytes();
    let mut octets = [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1]];
    octets[0] = (octets[0] & 0xFE) | 0x02;
    Mac(octets)
}

/// What this board came up as, and where it writes.
///
/// An `enum` rather than an `Option`-shaped struct because the two arms have
/// genuinely different capabilities, and the type is what stops a caller
/// forgetting that: a board with no durable store has no seed, so it cannot
/// hold a credential and every management write against it is refused with a
/// reason (see [`NullStore`]).
pub enum Identity {
    /// The board loaded — or, on a fresh device, minted — a durable record.
    Durable {
        /// The record as loaded, for [`Driver::restore`].
        ///
        /// A snapshot taken at boot rather than a borrow of `store`: it is only
        /// read once, and holding it separately keeps the store free to be
        /// borrowed mutably for the life of the run loop.
        ///
        /// [`Driver::restore`]: wayfinder_embedded_driver::Driver::restore
        record: NodeRecord,
        /// The settings store the management API writes through.
        store: BoardStore,
    },
    /// No usable durable medium. The board routes under its [`from_ficr`]
    /// address with **no seed**, so it cannot hold a credential.
    ///
    /// The address stays deterministic across reboots, which is the property
    /// that matters here: minting a random seed into RAM instead would give
    /// the board a new mesh address on every power cycle and churn every
    /// peer's originator table. Design 22 §4.3.
    Ephemeral {
        /// The FICR-derived address this board routes under.
        mac: Mac,
        /// A store that refuses every write, with a reason.
        store: NullStore,
    },
}

impl Identity {
    /// The mesh address this node routes under.
    pub fn mac(&self) -> Mac {
        match self {
            Identity::Durable { record, .. } => record.mac(),
            Identity::Ephemeral { mac, .. } => *mac,
        }
    }

    /// The durable record to restore from, if there is one.
    pub fn record(&self) -> Option<&NodeRecord> {
        match self {
            Identity::Durable { record, .. } => Some(record),
            Identity::Ephemeral { .. } => None,
        }
    }

    /// The store the driver hands the management API.
    pub fn store_mut(&mut self) -> &mut dyn NodeStore {
        match self {
            Identity::Durable { store, .. } => store,
            Identity::Ephemeral { store, .. } => store,
        }
    }
}

/// Bring up this node's identity from the durable store at `store_base`,
/// minting a seed on a device that has never held one.
///
/// `store_base` is the flash offset of the A/B page pair the board's
/// `memory.x` carves out of `FLASH`; the two must agree.
///
/// # Every failure degrades rather than halts
///
/// Including a misaddressed `store_base`, which an earlier version of this
/// function halted on. Nothing is lost by continuing: [`FlashStore::new`]
/// *rejects* a bad geometry rather than proceeding, so there is no risk of
/// writing into a region the linker is using — the board simply has no store.
/// And a relay that routes without a credential is strictly more useful than
/// one sitting in `wfe` with its LED dark, especially since the condition is
/// then visible over the management API (every write is refused with a stated
/// reason) rather than only to whoever is standing next to it.
///
/// The one thing that does *not* degrade quietly is the address: an
/// undecodable record is reported as an error even though this boot recovers
/// from it, because it means the node came up under a different mesh address
/// than it had before and an operator should see that rather than infer it.
pub fn resolve(nvmc: Peri<'static, NVMC>, rng: Peri<'static, RNG>, store_base: u32) -> Identity {
    let mut rng = Rng::new_blocking(rng);
    let mint = || {
        let mut seed = [0u8; Keypair::SEED_LEN];
        rng.blocking_fill_bytes(&mut seed);
        seed
    };

    let store = match FlashStore::new(Nvmc::new(nvmc), store_base) {
        Ok(store) => store,
        Err(e) => {
            error!(
                ?e,
                "durable store misconfigured; this node has no identity of its own and \
                 cannot hold a credential"
            );
            return ephemeral();
        }
    };

    let mut buf = [0u8; RECORD_READ_BUF_LEN];
    match load_or_init_record(store, mint, &mut buf) {
        Ok((persisted, how)) => {
            let record = persisted.get().clone();
            let mac = record.mac();
            match how {
                Provisioned::Loaded => info!(
                    ?mac,
                    credentialed = record.cert.is_some(),
                    checkpoint = record.checkpoint_unix,
                    "resolved node identity"
                ),
                Provisioned::Minted => info!(?mac, "minted this node's identity on first boot"),
                // `warn!`, and worth it: the node's mesh address just changed
                // permanently, so every peer's originator table is about to
                // churn. Reported here rather than left to be inferred from a
                // node coming back under a name nobody recognises.
                Provisioned::MigratedFromV1 => warn!(
                    ?mac,
                    "migrated a pre-seed identity record; this node's mesh address has \
                     changed and will not change again"
                ),
            }
            Identity::Durable {
                record,
                store: RecordSettings::new(persisted),
            }
        }
        // Permanent, not transient — and the two repair outcomes need
        // different words. Saying "a fresh identity has been written" when the
        // erase also failed would send an operator looking for a new address
        // that never arrives, on a board that will hit this identical failure
        // on every boot until its flash is erased by hand.
        Err(IdentityError::Decode { error, repaired }) => {
            if repaired {
                error!(
                    ?error,
                    "the stored node record was unreadable; a fresh identity has been \
                     written and this node comes up under a new mesh address next boot"
                );
            } else {
                error!(
                    ?error,
                    "the stored node record was unreadable and could not be replaced; this \
                     node cannot hold a credential and will fail identically on every boot \
                     until its flash is erased"
                );
            }
            ephemeral()
        }
        // `error!` like its two siblings, and for the same reasons: node-local,
        // unreachable by any peer, not retryable this boot, and it leaves the
        // node permanently unable to hold a credential — CLAUDE.md's
        // "permanently lost resource".
        //
        // "could not be read" rather than "is unavailable": this arm also
        // catches a record *longer* than the read buffer, which is a healthy
        // store holding a record written by newer firmware. Naming the
        // hardware there would point at the wrong thing entirely.
        Err(e) => {
            error!(
                ?e,
                "this node's durable record could not be read; it cannot hold a credential"
            );
            ephemeral()
        }
    }
}

/// The no-store posture: a FICR address and nothing durable behind it.
fn ephemeral() -> Identity {
    let mac = from_ficr();
    warn!(?mac, "running under the board's FICR address with no seed");
    Identity::Ephemeral {
        mac,
        store: NullStore::default(),
    }
}
