//! The one mutual-exclusion primitive this crate's global state is guarded by,
//! in the two forms the two targets can supply.
//!
//! Neither implementation is exotic; what matters is that the *same* call sites
//! work on both. A bare-metal board has no `std::sync`, and a host has no
//! `critical-section` implementation registered (that comes from
//! `cortex-m/critical-section-single-core` on the boards), so a single choice
//! would break one target or the other.
//!
//! # Why a critical section is affordable here
//!
//! Masking interrupts is not free on a board running the SoftDevice, whose radio
//! timing depends on being serviced promptly. Every [`Lock`] in this crate is
//! therefore taken *after* the lock-free level gate in [`crate::filter`] has
//! already passed — that is, only for records that are about to be formatted and
//! written to RTT anyway, which costs far more than the lock does. Rejected
//! records (the overwhelming majority when the filter is at `info` and the mesh
//! is busy) never reach a [`Lock`] at all.

/// A mutex around global logging state, with the same API on both targets.
///
/// Deliberately offers only [`with`](Self::with) rather than a guard type: a
/// guard could be held across an `await` or a nested log call, and on the
/// bare-metal side that means interrupts masked for an unbounded window. Taking
/// a closure keeps every critical section syntactically bounded.
pub(crate) struct Lock<T> {
    #[cfg(target_os = "none")]
    inner: critical_section::Mutex<core::cell::RefCell<T>>,
    #[cfg(not(target_os = "none"))]
    inner: std::sync::Mutex<T>,
}

impl<T> Lock<T> {
    /// Wrap `value`. `const` so the crate's global ring and filter can live in
    /// `static`s with no runtime initializer — logging must work from the first
    /// instruction, before anything has had a chance to call an `init`.
    pub(crate) const fn new(value: T) -> Self {
        Self {
            #[cfg(target_os = "none")]
            inner: critical_section::Mutex::new(core::cell::RefCell::new(value)),
            #[cfg(not(target_os = "none"))]
            inner: std::sync::Mutex::new(value),
        }
    }

    /// Run `f` with exclusive access to the wrapped value.
    ///
    /// On the host a poisoned mutex is recovered from rather than propagated: a
    /// panic in some unrelated thread that happened to be logging must not turn
    /// every subsequent log call into a second panic.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        #[cfg(target_os = "none")]
        {
            critical_section::with(|cs| f(&mut self.inner.borrow_ref_mut(cs)))
        }
        #[cfg(not(target_os = "none"))]
        {
            match self.inner.lock() {
                Ok(mut guard) => f(&mut guard),
                Err(poisoned) => f(&mut poisoned.into_inner()),
            }
        }
    }
}
