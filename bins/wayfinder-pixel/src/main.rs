//! Placeholder binary for the future Android-hosted mesh node.
//!
//! Cross-compiled for `aarch64-linux-android` via `cargo-ndk`, this exists
//! today only to prove that the crates `blue`'s shared `BleLink` core
//! depends on (`blue` itself with the `android` feature, and `wayfinder`)
//! actually link against the NDK's toolchain — see `libs/blue/CLAUDE.md`.
//! `NoopAdvertiser` stands in for the real Android `BluetoothLeAdvertiser`
//! binding.
//!
//! This binary is *not* what the Android app will load: that's `lib.rs`,
//! this crate's other target, a `cdylib` exposing a UniFFI interface Kotlin
//! calls into directly. Kept alongside it as a lighter-weight NDK-linking
//! smoke test with no UniFFI proc-macro expansion in the loop.

use blue::BleAdvertiser;
use blue::BleLink;
use wayfinder::interfaces::link::LinkError;

/// Stand-in [`BleAdvertiser`] proving `BleLink` constructs and links cleanly
/// for this target; the real Android BLE glue is a later phase.
struct NoopAdvertiser;

impl BleAdvertiser for NoopAdvertiser {
    async fn advertise(&self, _fragment: &[u8]) -> Result<(), LinkError> {
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let (_link, _sink) = BleLink::new(NoopAdvertiser);
    println!("hello from wayfinder-pixel");
}
