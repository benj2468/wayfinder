//! A `defmt` global logger that discards everything.
//!
//! **This is not a logging decision — it is the price of `lora-phy`.** That
//! crate depends on `defmt` non-optionally and calls its macros, and `defmt`
//! will not link without a `#[global_logger]`. This repo logs through
//! `tracing`, which `wayfinder-log` renders onto the RTT channel it owns;
//! linking `defmt-rtt` instead would put a second RTT implementation in the
//! image, both claiming the control block.
//!
//! The cost is `lora-phy`'s six records (three `trace`, two `debug`, one
//! `warn`). Bridging them is not a real option: `defmt`'s whole premise is
//! *deferred* formatting, so a logger receives an interned frame rather than a
//! string, and rendering one on-target would mean shipping the decoder and this
//! image's own symbol table. If those records are ever wanted, the honest
//! routes are a `defmt` feature upstream or a second RTT channel.
//!
//! See `docs/design/25-stm32wl55-subghz-node.md` §4.6.

/// The discarding logger.
///
/// Every method is a no-op, which is safe for the reason the trait's contract
/// is otherwise hard to satisfy: with no buffer and no output there is no
/// state to corrupt if `acquire` is re-entered, and nothing to flush.
#[defmt::global_logger]
struct Discard;

// SAFETY: `defmt::Logger`'s contract governs a logger that buffers and emits.
// This one does neither — `acquire`/`release` take and release nothing, and
// `write` drops its bytes — so every invariant about interleaving, framing and
// re-entrancy holds trivially.
unsafe impl defmt::Logger for Discard {
    fn acquire() {}

    unsafe fn flush() {}

    unsafe fn release() {}

    unsafe fn write(_bytes: &[u8]) {}
}
