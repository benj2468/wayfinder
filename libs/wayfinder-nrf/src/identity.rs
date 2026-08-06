//! This node's durable mesh identity: persisted in flash if it can be, derived
//! from the chip's factory FICR device ID if not.

use embassy_nrf::Peri;
use embassy_nrf::nvmc::Nvmc;
use embassy_nrf::peripherals::NVMC;
use tracing::error;
use tracing::info;
use wayfinder::interfaces::frame::Mac;
use wayfinder_embedded_driver::identity::IDENTITY_READ_BUF_LEN;
use wayfinder_embedded_driver::identity::IdentityError;
use wayfinder_embedded_driver::identity::load_or_init_identity;
use wayfinder_storage::FlashStore;

/// Derive this node's mesh MAC from the nRF52840's factory-programmed FICR
/// device ID.
///
/// That ID is a per-chip unique 64-bit value burned in at manufacture, so the
/// derived address is stable across reboots *before* it is persisted and
/// distinct between physical boards with no provisioning step — which is why a
/// flash failure below is recoverable rather than fatal. The top octet is forced
/// to locally-administered unicast (L/A bit set, I/G multicast bit cleared).
pub fn from_ficr() -> Mac {
    let ficr = embassy_nrf::pac::FICR;
    let lo = ficr.deviceid(0).read().to_le_bytes();
    let hi = ficr.deviceid(1).read().to_le_bytes();
    let mut octets = [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1]];
    octets[0] = (octets[0] & 0xFE) | 0x02;
    Mac(octets)
}

/// Load this node's MAC from the durable store at `store_base`, falling back to
/// [`from_ficr`] and persisting it on a never-provisioned board.
///
/// `store_base` is the flash offset of the A/B page pair the board's `memory.x`
/// carves out of `FLASH`; the two must agree, and a mismatch is a build-time
/// programming error with nothing to recover from — hence the halt rather than
/// running against a misaddressed flash region.
///
/// Every other failure is degraded, not fatal: the FICR-derived MAC is
/// deterministic, so the node still boots with a correct, stable address and
/// only its *persistence* is lost. Both arms are `error!` rather than `warn!` —
/// node-local, not attacker-reachable, and not retryable this boot.
pub fn resolve(nvmc: Peri<'static, NVMC>, store_base: u32) -> Mac {
    let store = match FlashStore::new(Nvmc::new(nvmc), store_base) {
        Ok(store) => store,
        Err(e) => {
            error!(?e, "durable identity store misconfigured; halting");
            loop {
                cortex_m::asm::wfe();
            }
        }
    };

    let mut buf = [0u8; IDENTITY_READ_BUF_LEN];
    let mac = match load_or_init_identity(store, from_ficr, &mut buf) {
        Ok(identity) => *identity.get(),
        // Corrupt or foreign blob: permanent, not transient.
        // `load_or_init_identity` has already tried to re-persist a fresh one so
        // a later boot converges; this boot uses the same value in memory.
        Err(e @ IdentityError::Decode(_)) => {
            error!(
                ?e,
                "persisted node identity unreadable; re-derived from FICR"
            );
            from_ficr()
        }
        Err(e) => {
            error!(
                ?e,
                "durable identity store unavailable; using FICR-derived MAC in memory"
            );
            from_ficr()
        }
    };
    info!(?mac, "resolved node identity");
    mac
}
