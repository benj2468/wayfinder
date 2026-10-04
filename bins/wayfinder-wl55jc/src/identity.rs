//! This node's durable identity: a seed minted once from the part's TRNG and
//! kept in the A/B flash store `memory.x` carves out of the top of `FLASH`,
//! with the mesh address derived from it.
//!
//! The same design 22 shape `wayfinder_nrf::identity` has, cut down to what a
//! board with no management port can use. There is no settings store handed
//! to the driver: the driver writes renewals and clock checkpoints back only
//! from `run_with_mgmt`, which this relay does not run, so what the store buys
//! here is
//!
//! - a mesh address that is **unique per board and stable across reflashing**,
//!   in place of the compile-time `Mac` every image used to share — two boards
//!   flashed from one build used to collide on the air; and
//! - a record for [`Driver::restore`] at boot, so a credential written by a
//!   later image with a management port survives into this one.
//!
//! A board whose store cannot be used falls back to [`from_uid`], an address
//! derived from the part's factory unique ID: deterministic across reboots
//! (so peers' originator tables do not churn) but with no seed behind it.
//!
//! [`Driver::restore`]: wayfinder_embedded_driver::Driver::restore

use embassy_stm32::Peri;
use embassy_stm32::flash::Flash;
use embassy_stm32::peripherals::FLASH;
use embassy_stm32::peripherals::RNG;
use embassy_stm32::rng::Rng;
use tracing::error;
use tracing::info;
use tracing::warn;
use wayfinder::interfaces::frame::Mac;
use wayfinder::wayfinder_auth::Keypair;
use wayfinder_embedded_driver::identity::NodeRecord;
use wayfinder_embedded_driver::identity::Provisioned;
use wayfinder_embedded_driver::identity::RECORD_READ_BUF_LEN;
use wayfinder_embedded_driver::identity::load_or_init_record;
use wayfinder_storage::FlashStore;

/// Flash offset of the durable store's A/B page pair: the two 2 KiB pages at
/// the very top of the part's 256 KiB. **Must stay consistent with
/// `memory.x`**, whose `FLASH` `LENGTH` stops short of them so the linker
/// leaves them free.
pub const DURABLE_STORE_BASE: u32 = 256 * 1024 - 2 * 2048;

/// What this board came up as.
pub struct Identity {
    /// The mesh address this node routes under.
    pub mac: Mac,
    /// The durable record, for `Driver::restore`; `None` on the fallback
    /// address, which has nothing to restore.
    pub record: Option<NodeRecord>,
}

/// A locally-administered unicast address derived from the part's 96-bit
/// factory unique ID.
///
/// Public by nature, so derivable from a public value; never the seed's
/// source, which must be random (see `load_or_init_record`'s docs). The low
/// six bytes are the ones that vary between parts in a lot: wafer X/Y and
/// lot/wafer number.
pub fn from_uid() -> Mac {
    let uid = embassy_stm32::uid::uid();
    let mut octets = [uid[0], uid[1], uid[2], uid[3], uid[4], uid[5]];
    octets[0] = (octets[0] & 0xFE) | 0x02;
    Mac(octets)
}

/// Load this node's record from flash, minting a seed from the TRNG on a part
/// that has never held one. Every failure degrades to [`from_uid`] rather
/// than halting, for the reasons `wayfinder_nrf::identity::resolve` records.
pub fn resolve(flash: Peri<'static, FLASH>, mut rng: Rng<'static, RNG>) -> Identity {
    let mint = || {
        let mut seed = [0u8; Keypair::SEED_LEN];
        rng.fill_bytes(&mut seed);
        seed
    };

    let store = match FlashStore::new(Flash::new_blocking(flash), DURABLE_STORE_BASE) {
        Ok(store) => store,
        Err(e) => {
            error!(
                ?e,
                "durable store misconfigured; routing under the factory id"
            );
            return fallback();
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
                    "resolved node identity"
                ),
                Provisioned::Minted => info!(?mac, "minted this node's identity on first boot"),
                Provisioned::MigratedFromV1 => warn!(
                    ?mac,
                    "migrated a pre-seed identity record; this node's mesh address has changed"
                ),
            }
            Identity {
                mac,
                record: Some(record),
            }
        }
        // Node-local and permanent for this boot: `error!`.
        Err(e) => {
            error!(
                ?e,
                "durable node record unusable; routing under the factory id"
            );
            fallback()
        }
    }
}

fn fallback() -> Identity {
    let mac = from_uid();
    warn!(?mac, "running under the part's factory id with no seed");
    Identity { mac, record: None }
}
