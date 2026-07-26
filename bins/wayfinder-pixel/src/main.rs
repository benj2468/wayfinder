//! Placeholder binary for the future Android-hosted mesh node.
//!
//! Cross-compiled for `aarch64-linux-android` via `cargo-ndk`, this exists
//! today only to prove that the crates `blue`'s `AndroidBleLink` seam
//! depends on (`blue` itself with the `android` feature, and `wayfinder`)
//! actually link against the NDK's toolchain, before any JNI glue exists —
//! see `libs/blue/CLAUDE.md`. `NoopAdvertiser` stands in for the real
//! Android `BluetoothLeAdvertiser` binding, which is a later phase.

use blue::AndroidBleLink;
use blue::BleAdvertiser;
use wayfinder::interfaces::link::LinkError;

/// Stand-in [`BleAdvertiser`] proving `AndroidBleLink` constructs and links
/// cleanly for this target; the real Android BLE glue is a later phase.
struct NoopAdvertiser;

impl BleAdvertiser for NoopAdvertiser {
    async fn advertise(&self, _fragment: &[u8]) -> Result<(), LinkError> {
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let (_link, _sink) = AndroidBleLink::new(NoopAdvertiser);
    println!("hello from wayfinder-pixel");
}
