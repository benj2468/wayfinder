//! Resolves the `GetLogs` record ring's capacity at build time, so a board can
//! choose it.
//!
//! The ring is a `static` inside this crate, so a board cannot instantiate a
//! smaller one — and the size it wants is a property of *that board's* RAM,
//! not of bare metal in general. `#[cfg(target_os = "none")]` cannot express
//! that: it separates a board from a host, while the distinction that now
//! matters is between two boards four times apart in SRAM (the nRF52840's
//! 256 KiB against the STM32WL55's 64 KiB, where a 64-record ring is a quarter
//! of all memory).
//!
//! **Why an environment variable and not a Cargo feature.** Features are
//! additive and unify across a dependency graph, so `ring-16` and `ring-64`
//! appearing together would silently resolve to one of them — and the axis here
//! is a *quantity*, which features model badly at any granularity. Each board
//! being its own `[workspace]` hides that hazard today rather than removing it.
//!
//! A board sets it in its own `.cargo/config.toml`, beside the other facts
//! about how it is built. See `docs/design/25-stm32wl55-subghz-node.md` §4.7.

use std::env;
use std::fs;
use std::path::PathBuf;

/// The variable a board sets to override the per-target default.
const VAR: &str = "WAYFINDER_LOG_RING_CAPACITY";

/// Records retained on a bare-metal target when nothing overrides it. The
/// value this crate shipped with before the override existed, so an
/// unconfigured board is unaffected.
const DEFAULT_BARE_METAL: usize = 64;

/// Records retained on a host, which has neither the framing cap nor the heap
/// pressure that motivates a small ring.
const DEFAULT_HOST: usize = 512;

// As `libs/wayfinder-protos/build.rs` does: a build script has no error path
// worth taking. If `OUT_DIR` is missing or unwritable, cargo's own contract is
// broken and failing the build with the reason is the whole of the correct
// behaviour.
#[allow(clippy::expect_used)]
fn main() {
    println!("cargo::rerun-if-env-changed={VAR}");
    println!("cargo::rerun-if-changed=build.rs");

    // `none` is what `target_os = "none"` reads as here; every board in this
    // repo is one.
    let bare_metal = env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none");
    let default = if bare_metal {
        DEFAULT_BARE_METAL
    } else {
        DEFAULT_HOST
    };

    let capacity = match env::var(VAR) {
        Err(_) => default,
        Ok(raw) => {
            // A typo must fail the build. Falling back to the default would
            // hand a 64 KiB board a 16 KiB ring it explicitly asked not to
            // have, and nothing downstream would say so — the symptom is a
            // stack that overflows into statics on a part whose `memory.x`
            // still looks right.
            let parsed: usize = raw.trim().parse().unwrap_or_else(|e| {
                panic!("{VAR} is set to {raw:?}, which is not a number of records: {e}")
            });
            // `heapless::Deque<_, 0>` cannot hold the record `push` always
            // writes, and `DEFAULT_BATCH` would be zero, so `GetLogs` would
            // return nothing while reporting no drops.
            assert!(parsed > 0, "{VAR} must be at least 1, got {parsed}");
            parsed
        }
    };

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is always set by cargo"));
    fs::write(
        out.join("ring_capacity.rs"),
        format!("pub(crate) const RING_CAPACITY_CONFIGURED: usize = {capacity};\n"),
    )
    .expect("OUT_DIR is always writable");
}
