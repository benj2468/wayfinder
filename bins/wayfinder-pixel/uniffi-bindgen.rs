//! Standalone CLI that generates foreign-language bindings (Kotlin, for the
//! eventual Android app) from `src/lib.rs`'s `#[uniffi::export]` surface.
//!
//! Built and run on demand only — see the `uniffi-bindgen` feature/`[[bin]]`
//! in `Cargo.toml` — never as part of a normal `cargo build`/`cargo ndk
//! build`. Usage:
//!
//! ```sh
//! cargo build --lib
//! cargo run --bin uniffi-bindgen --features uniffi-bindgen -- generate \
//!     --library target/debug/libwayfinder_pixel.so \
//!     --language kotlin --out-dir bindings/
//! ```
fn main() {
    uniffi::uniffi_bindgen_main()
}
