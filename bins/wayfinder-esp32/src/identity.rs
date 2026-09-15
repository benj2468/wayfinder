//! This node's durable identity: a seed minted once from the chip's true
//! random source and kept in a flash partition, with the mesh address derived
//! from it.
//!
//! Design 22, and the same two-identity split `libs/wayfinder-nrf`'s
//! `identity.rs` makes — read that one first; this is its ESP32 counterpart and
//! differs only where the hardware forces it.
//!
//! - The **mesh address** is `Keypair::from_seed(&seed).derived_mac()`. A
//!   certificate's MAC *is* the address its identity key derives (design 09
//!   §5), so deriving it here is what makes a certificate issued for this node
//!   a certificate for the address it actually routes under.
//! - The **board id** is [`from_efuse`], the factory MAC burned into eFuse. It
//!   names a physical part, not a mesh node, so it does not move when the
//!   node's identity does, and it is the address a board with no usable store
//!   falls back to.
//!
//! # Three things this board does differently
//!
//! **The store's address comes from the partition table, not from a constant.**
//! The nRF reserves its two pages in `memory.x` and repeats the offset as
//! `DURABLE_STORE_BASE`, with a comment asking the next person to keep them in
//! step. There is no linker script to carve from here, so the offset is read
//! back at runtime from the table the bootloader already used —
//! `partitions.csv` is the single source of truth and nothing restates it. A
//! table without the partition is a clear startup error rather than a write
//! into whatever happens to be at a hardcoded address.
//!
//! **The seed is minted from the SAR ADC entropy source, not the bare RNG.**
//! On this part `Rng` is *pseudo*-random unless the RF subsystem is on or an
//! ADC is feeding it noise — the ESP32 TRM says so and `esp-hal`'s `rng` module
//! repeats it. A node's identity seed is its private key, so minting one from a
//! pseudo-random source would be a real weakness rather than a quality
//! question, and this board has no radio running to supply the other condition.
//! [`TrngSource`] enables the ADC path for exactly as long as the mint takes.
//!
//! **A write stalls execution, because the flash being written is the flash the
//! code runs from.** `esp-storage` disables the cache and runs the erase/write
//! from IRAM, so a `SetAuth` that persists is not free for the router loop the
//! way it is on a part with separate program memory. It is milliseconds, once,
//! at the point an operator enrols the node — worth knowing, not worth
//! designing around.

use esp_hal::efuse;
use esp_hal::peripherals::ADC1;
use esp_hal::peripherals::FLASH;
use esp_hal::peripherals::RNG;
use esp_hal::rng::Trng;
use esp_hal::rng::TrngSource;
use esp_storage::FlashStorage;
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

/// The partition `partitions.csv` declares for the durable store, by label.
///
/// Matched by **name** rather than by type or subtype: `undefined` is a
/// catch-all several unrelated components also use, so a lookup by subtype
/// could hand back somebody else's partition and write a node record over it.
const STORE_PARTITION: &str = "wayfinder";

/// The board's durable store, once its flash geometry has been accepted.
type BoardStore = RecordSettings<FlashStore<FlashStorage<'static>>>;

/// Derive this **board's** identifier from the factory MAC burned into eFuse.
///
/// Unique per part, stable across reboots and reflashing, and — unlike the
/// nRF's FICR device id — already a well-formed globally-administered MAC, so
/// nothing is masked into it. `esp-hal`'s own accessor rather than a hand-rolled
/// read: the six bytes are stored big-endian across two eFuse words, and
/// getting that order wrong yields a plausible-looking address that is simply
/// the wrong node.
///
/// This is **not** the mesh address on a board with a working store — see the
/// module docs. It identifies the part, and is what a board with nowhere to
/// keep a seed routes under.
pub fn from_efuse() -> Mac {
    let mut octets = [0u8; 6];
    octets.copy_from_slice(efuse::base_mac_address().as_bytes());
    Mac(octets)
}

/// What this board came up as, and where it writes.
///
/// An `enum` rather than an `Option`-shaped struct for the reason
/// `wayfinder-nrf`'s equivalent gives: the two arms have genuinely different
/// capabilities, and the type is what stops a caller forgetting it. A board
/// with no durable store has no seed, so it cannot hold a credential and every
/// management write against it is refused with a reason (see [`NullStore`]).
///
/// The two arms differ in size by the `NodeRecord` and the store, and boxing to
/// even them out would put a node's credential behind a pointer on a board with
/// one allocator shared with the management API's framing buffers. Exactly one
/// of these exists, for the life of the node.
#[expect(
    clippy::large_enum_variant,
    reason = "typed instead of boxed; one exists"
)]
pub enum Identity {
    /// The board loaded — or, on a fresh part, minted — a durable record.
    Durable {
        /// The record as loaded, for `Driver::restore`.
        ///
        /// A snapshot taken at boot rather than a borrow of `store`: it is read
        /// once, and holding it separately leaves the store free to be borrowed
        /// mutably for the life of the run loop.
        record: NodeRecord,
        /// The settings store the management API writes through.
        store: BoardStore,
    },
    /// No usable durable medium. The board routes under its [`from_efuse`]
    /// address with **no seed**, so it cannot hold a credential.
    ///
    /// The address stays deterministic across reboots, which is the property
    /// that matters: minting a seed into RAM instead would give the board a new
    /// mesh address on every power cycle and churn every peer's originator
    /// table. Design 22 §4.3.
    Ephemeral {
        /// The eFuse-derived address this board routes under.
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

/// Look up the durable store's flash offset in the partition table the
/// bootloader already used, returning `(offset, len)`.
///
/// Reading the table rather than trusting a constant is what keeps this in step
/// with `partitions.csv` — see the module docs. The buffer is the table's
/// maximum size and lives only for this call; it is 3 KiB of a 114 KiB stack,
/// during bring-up, before the router exists.
fn store_partition(flash: &mut FlashStorage<'static>) -> Option<(u32, u32)> {
    let mut buf = [0u8; esp_bootloader_esp_idf::partitions::PARTITION_TABLE_MAX_LEN];
    let table = match esp_bootloader_esp_idf::partitions::read_partition_table(flash, &mut buf) {
        Ok(table) => table,
        Err(e) => {
            error!(?e, "the partition table could not be read");
            return None;
        }
    };
    for i in 0..table.len() {
        let Ok(entry) = table.get_partition(i) else {
            continue;
        };
        if entry.label_as_str() == STORE_PARTITION {
            return Some((entry.offset(), entry.len()));
        }
    }
    error!(
        partition = STORE_PARTITION,
        "no such partition in the table; this image was flashed without \
         `partitions.csv` and has nowhere to keep an identity"
    );
    None
}

/// Bring up this node's identity from the durable store, minting a seed on a
/// part that has never held one.
///
/// # Every failure degrades rather than halts
///
/// The same rule `wayfinder-nrf`'s `resolve` states, and for the same reasons.
/// `FlashStore::new` *rejects* a bad geometry rather than proceeding, so there
/// is no risk of writing into a region something else is using — the board
/// simply has no store. A relay that routes without a credential is strictly
/// more useful than one halted with no way to ask why, especially since the
/// condition is then visible over the management API (every write refused with
/// a stated reason) rather than only to whoever is standing next to it.
///
/// The one thing that does not degrade quietly is the address: an undecodable
/// record is reported as an error even though this boot recovers from it,
/// because it means the node came up under a different mesh address than it had
/// before and an operator should see that rather than infer it.
pub fn resolve(flash: FLASH<'static>, rng: RNG<'static>, adc1: ADC1<'static>) -> Identity {
    let mut flash = FlashStorage::new(flash);
    let Some((offset, len)) = store_partition(&mut flash) else {
        return ephemeral();
    };

    // `FlashStore::new` bounds its two pages against the whole chip, which is
    // not the question — the store must fit the partition *declared for it*, or
    // it would happily write past the end into whatever follows. Checked here
    // because only this function knows which partition was asked for.
    let needed = 2 * FlashStorage::SECTOR_SIZE;
    if len < needed {
        error!(
            partition = STORE_PARTITION,
            len, needed, "the store partition is too small for two erase pages"
        );
        return ephemeral();
    }
    let store = match FlashStore::new(flash, offset) {
        Ok(store) => store,
        Err(e) => {
            error!(
                ?e,
                offset, "durable store misconfigured; this node cannot hold a credential"
            );
            return ephemeral();
        }
    };

    // The ADC entropy source, held for exactly as long as a mint could need it
    // — see the module docs for why the bare `Rng` will not do here. Enabling
    // it costs nothing on a boot that loads an existing record; `mint` is only
    // called when there is no seed to load.
    let _trng_source = TrngSource::new(rng, adc1);
    let mint = || {
        let mut seed = [0u8; Keypair::SEED_LEN];
        match Trng::try_new() {
            Ok(trng) => trng.read(&mut seed),
            // Unreachable while `_trng_source` is alive, and a seed is not
            // something to guess at: a board that cannot prove its randomness
            // is good comes up with no identity rather than a weak one.
            Err(e) => error!(?e, "no true random source; refusing to mint a seed"),
        }
        seed
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
                // churn.
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
        Err(e) => {
            error!(
                ?e,
                "this node's durable record could not be read; it cannot hold a credential"
            );
            ephemeral()
        }
    }
}

/// The no-store posture: an eFuse address and nothing durable behind it.
fn ephemeral() -> Identity {
    let mac = from_efuse();
    warn!(
        ?mac,
        "no durable store; routing without an identity of its own"
    );
    Identity::Ephemeral {
        mac,
        store: NullStore::default(),
    }
}
