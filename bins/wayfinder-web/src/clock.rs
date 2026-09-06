//! The viewer's wall clock, for the one thing a browser has to decide locally:
//! how far away a date the operator picked is.
//!
//! Everything else on this dashboard reads a time the *node* stamped, which is
//! the right default — the node is the authority on its own state, and a
//! browser's clock can be anything. A duration the operator is composing is
//! the exception: they typed a date, the node speaks seconds-from-now, and the
//! conversion has to happen where the date was typed.
//!
//! The gap between the two clocks lands on the resulting lifetime, so a
//! browser an hour fast issues a certificate an hour short. That is tolerable
//! for a lifetime measured in days and would not be for a deadline measured in
//! seconds — which is why this is only ever used to compose a *duration*, and
//! never to judge whether something has expired.

/// The browser's wall clock in Unix seconds, or zero when there is none.
///
/// Zero is "undecidable", not "the epoch": every caller treats it as a reason
/// to defer to the provider rather than to compute a deadline from it.
#[cfg(feature = "hydrate")]
#[must_use]
pub fn now_unix() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Server rendering decides no deadlines.
#[cfg(not(feature = "hydrate"))]
#[must_use]
pub fn now_unix() -> u64 {
    0
}
