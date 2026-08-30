//! Whether the host's system clock is disciplined enough to make credential
//! decisions with.
//!
//! Time is a trust input for this node: it decides a certificate's validity
//! window, when an invitation stops being redeemable, when a lockout lifts, how
//! long a revocation is enforced, and which TOTP step a code belongs to. A
//! wrong clock is not a cosmetic fault — it is an expired bearer token that
//! still works, or a valid membership rejected mesh-wide.
//!
//! [`Clock::System`](crate::Clock)'s existing `MIN_PLAUSIBLE_UNIX` floor
//! catches a clock that was *never set* (a board with no RTC reading 1970). It
//! cannot catch the case this module exists for: a clock that is plausible and
//! wrong — off by hours because the node booted before NTP reached it, which is
//! the ordinary condition of a field-deployed mesh with no upstream.
//!
//! **`chronyd` is the source of truth**; this module reads the verdict chronyd
//! publishes rather than talking to it. `ntp_adjtime(2)` reports the kernel's
//! NTP status word: `STA_UNSYNC` while the clock is not disciplined, cleared
//! once it is, plus `maxerror`, a bound on how wrong the clock may currently
//! be. Both a daemon and the kernel write them — the kernel sets `STA_UNSYNC`
//! itself on every `settimeofday` and once `maxerror` saturates at 16 s, and
//! `STA_UNSYNC` is in turn what makes the syscall return `TIME_ERROR`.
//!
//! Reading it through the kernel means no chrony IPC, no socket permissions and
//! no subprocess, and it works with any daemon that maintains the status word.
//! They do not all maintain it alike, which is why the NixOS module installs
//! chrony specifically: `chronyd` and `ntpd` write a real dispersion into
//! `maxerror`, `systemd-timesyncd` writes zero on every sync and tracks no
//! dispersion at all, and `openntpd` never touches the status word — so the
//! `max_error_us` half of the policy is only meaningful under the first two,
//! while `STA_UNSYNC` is honoured by all but the last.

/// Default bound on the kernel's estimated clock error, in microseconds, below
/// which the clock is still considered trustworthy.
///
/// Five seconds. The functional requirements are much looser: `verify_totp`
/// accepts the adjacent step either side, so 30 s of error is still tolerated,
/// and a certificate window is hours. The bound is therefore set by what does
/// *not* flap rather than by what is barely sufficient — the kernel grows
/// `maxerror` by 500 µs per second between a daemon's updates, so a healthy
/// node at chrony's default 1024 s `maxpoll` peaks around half a second. Five
/// seconds is an order of magnitude above that and still far inside every
/// credential requirement.
pub const DEFAULT_MAX_CLOCK_ERROR_US: u64 = 5_000_000;

/// How a [`Clock::System`](crate::Clock) decides whether to trust its reading.
///
/// An enum rather than a bare bool because the production variant has to be
/// re-read at every use (a clock becomes trusted partway through a node's life,
/// which is the whole point), while the two fixed variants must be pinnable for
/// tests and for hosts where the kernel exposes no verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockTrust {
    /// Consult the kernel's NTP status at every read, trusting the clock only
    /// while it is disciplined and its estimated error is within `max_error_us`.
    ///
    /// What a real node runs on. On a platform with no `ntp_adjtime`, this
    /// degrades to [`ClockSync::Unsupported`] — see [`clock_sync`](crate::clock_sync) for why that is
    /// treated as trusted rather than fail-closed.
    Ntp {
        /// Bound on the kernel's `maxerror`, in microseconds. See
        /// [`DEFAULT_MAX_CLOCK_ERROR_US`].
        max_error_us: u64,
    },
    /// Trust the host clock unconditionally, asking the kernel nothing.
    ///
    /// The operator's opt-out (`require_time_sync = false`), and what a test
    /// that cares about some *other* property uses so it does not depend on the
    /// build machine's NTP state.
    Assume,
    /// Never trust the host clock.
    ///
    /// Exists so the gate itself is testable: it pins the untrusted branch on a
    /// machine whose clock is perfectly fine, the same way
    /// [`Clock::Fixed`](crate::Clock) pins a time on a machine whose clock is
    /// moving.
    Never,
}

impl Default for ClockTrust {
    /// The shipping posture: enforce, at [`DEFAULT_MAX_CLOCK_ERROR_US`].
    ///
    /// One place states it, rather than each crate that constructs a clock
    /// re-deriving the same literal — a second spelling is how one of them ends
    /// up permissive after the other is tightened.
    fn default() -> Self {
        Self::Ntp {
            max_error_us: DEFAULT_MAX_CLOCK_ERROR_US,
        }
    }
}

impl ClockTrust {
    /// Choose a policy from the operator's settings.
    ///
    /// `require_time_sync` defaults to `true` in the config, so a node nobody
    /// configured enforces. Turning it off yields [`Assume`](Self::Assume) and
    /// discards `max_clock_error_us` entirely — an operator who asked for no
    /// gate must not get one that fires anyway on a wide `maxerror`.
    #[must_use]
    pub fn from_settings(require_time_sync: bool, max_clock_error_us: Option<u64>) -> Self {
        if require_time_sync {
            Self::Ntp {
                max_error_us: max_clock_error_us.unwrap_or(DEFAULT_MAX_CLOCK_ERROR_US),
            }
        } else {
            Self::Assume
        }
    }
}

/// What the host's NTP subsystem says about the system clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockSync {
    /// The clock is disciplined and its estimated error is within bound.
    Synchronized {
        /// The kernel's current error bound, in microseconds.
        max_error_us: u64,
    },
    /// No disciplining daemon has brought the clock into sync — `STA_UNSYNC` is
    /// set, or the syscall reported `TIME_ERROR`.
    Unsynchronized,
    /// The clock is nominally disciplined, but the kernel's own error bound
    /// exceeds what this node will accept.
    ErrorTooLarge {
        /// The kernel's current error bound, in microseconds.
        max_error_us: u64,
        /// The bound that was exceeded, in microseconds.
        bound_us: u64,
    },
    /// The status word could not be read at all — the syscall itself failed.
    ///
    /// Distinct from [`Unsynchronized`](Self::Unsynchronized), and the
    /// distinction is the whole point: "the answer was no" and "we were not
    /// allowed to ask" call for completely different operator actions. A
    /// container without `CAP_SYS_TIME` gets `EPERM` from Docker's default
    /// seccomp profile, and reporting that as "no NTP sync" sends the operator
    /// to start a time daemon that will change nothing.
    Unreadable {
        /// The raw `errno`, so the log names the actual failure.
        errno: i32,
    },
    /// No verdict is being enforced here: either this platform exposes no NTP
    /// status to read, or the operator turned enforcement off
    /// (`require_time_sync = false`).
    ///
    /// One variant for both because they are the same state as far as the node
    /// is concerned — nothing is vouching for this clock — and because a
    /// projection that distinguished them would be reporting the *reason* an
    /// operator is unprotected rather than the fact of it. The startup log line
    /// says which.
    Unsupported,
}

impl ClockSync {
    /// Whether a clock in this state may be used for a credential decision.
    ///
    /// [`Unsupported`](Self::Unsupported) counts as trusted — see
    /// [`clock_sync`](crate::clock_sync).
    #[must_use]
    pub const fn is_trusted(self) -> bool {
        matches!(self, Self::Synchronized { .. } | Self::Unsupported)
    }

    /// A stable snake-case name for the log line and the operator-facing
    /// projection.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Synchronized { .. } => "synchronized",
            Self::Unsynchronized => "unsynchronized",
            Self::Unreadable { .. } => "unreadable",
            Self::ErrorTooLarge { .. } => "error_too_large",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Classify one `ntp_adjtime` result.
///
/// A pure function over the three values the syscall reports, so every boundary
/// below is testable without a machine whose clock is actually wrong — the same
/// reason `plausible_or_zero` is split out from
/// [`Clock::System`](crate::Clock).
///
/// `ret` is the syscall's return value, `status` the returned `timex.status`
/// word, `maxerror_us` its estimated error bound in microseconds, and
/// `bound_us` the largest such bound this node will accept.
///
/// Order matters: the "not disciplined" verdicts are decisive and are checked
/// before the bound. `maxerror` is a value a daemon writes, not something the
/// kernel derives — anything holding `CAP_SYS_TIME` can set it to zero while
/// `STA_UNSYNC` is still set — so a narrow bound must never be able to vouch
/// for a clock that nothing is disciplining.
#[cfg(any(target_os = "linux", test))]
fn classify(ret: i32, status: i32, maxerror_us: i64, bound_us: u64) -> ClockSync {
    /// The kernel's "clock is not synchronized" status bit.
    const STA_UNSYNC: i32 = 0x0040;
    /// `ntp_adjtime`'s "clock not synchronized" return value.
    const TIME_ERROR: i32 = 5;

    if ret == TIME_ERROR || status & STA_UNSYNC != 0 {
        return ClockSync::Unsynchronized;
    }
    // Not a value the kernel should ever report. Refuse it rather than casting:
    // a negative cast to `u64` is enormous (landing in `ErrorTooLarge` by
    // accident), and clamping to zero would trust a clock on the strength of a
    // reading that makes no sense.
    let Ok(max_error_us) = u64::try_from(maxerror_us) else {
        return ClockSync::Unsynchronized;
    };
    if max_error_us > bound_us {
        return ClockSync::ErrorTooLarge {
            max_error_us,
            bound_us,
        };
    }
    ClockSync::Synchronized { max_error_us }
}

/// Ask the host what it thinks of its own clock, under the given policy.
///
/// [`ClockTrust::Ntp`] consults the kernel afresh on every call — a clock
/// becomes trusted partway through a node's life, and a verdict cached at
/// startup would be exactly the staleness this module exists to remove.
///
/// On a platform with no `ntp_adjtime` this reports
/// [`ClockSync::Unsupported`], which counts as **trusted**. Failing closed
/// there would make a macOS dev machine unable to run a provider at all, and
/// the enforcement is a defence against a misconfigured deployment rather than
/// against a developer's laptop; the startup warning is what keeps that honest.
#[must_use]
pub fn read(trust: ClockTrust) -> ClockSync {
    match trust {
        ClockTrust::Assume => ClockSync::Unsupported,
        ClockTrust::Never => ClockSync::Unsynchronized,
        ClockTrust::Ntp { max_error_us } => read_host(max_error_us),
    }
}

/// Read the kernel's NTP status word on a host that has one.
#[cfg(target_os = "linux")]
fn read_host(bound_us: u64) -> ClockSync {
    // SAFETY: `libc::timex` is a plain struct of integers and padding with no
    // niche, so an all-zero bit pattern is a valid value for it.
    let mut buf: libc::timex = unsafe { core::mem::zeroed() };
    // SAFETY: `ntp_adjtime` reads and writes only through the pointer it is
    // handed, which is a valid, aligned, exclusively-borrowed local. A zeroed
    // `modes` is the documented query form (`man 2 adjtimex`: "If modes is
    // zero, then no values are changed"), so this cannot perturb the host clock
    // — a node must not discipline the clock it is merely asking about — and it
    // needs no `CAP_SYS_TIME`, which is what lets a node with an empty
    // capability set call it at all.
    let ret = unsafe { libc::ntp_adjtime(&mut buf) };
    if ret < 0 {
        // Fails closed like `Unsynchronized`, but says so differently: the
        // errno is the only thing that distinguishes a seccomp-blocked syscall
        // from a clock nobody is disciplining, and an operator told the wrong
        // one will fix the wrong thing.
        return ClockSync::Unreadable {
            errno: std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or_default(),
        };
    }
    classify(ret, buf.status, buf.maxerror, bound_us)
}

/// Report no NTP status on a platform that exposes none. See [`read`].
#[cfg(not(target_os = "linux"))]
fn read_host(_bound_us: u64) -> ClockSync {
    ClockSync::Unsupported
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kernel's `STA_UNSYNC` bit, spelled out rather than taken from `libc`
    /// so these tests describe the wire-level contract on every host — including
    /// the macOS dev machines where `libc` does not export it.
    const STA_UNSYNC: i32 = 0x0040;
    /// `ntp_adjtime`'s `TIME_OK` return.
    const TIME_OK: i32 = 0;
    /// `ntp_adjtime`'s `TIME_ERROR` return — "clock not synchronized".
    const TIME_ERROR: i32 = 5;

    const BOUND: u64 = DEFAULT_MAX_CLOCK_ERROR_US;

    /// A clock the kernel is disciplining, well inside the error bound, is the
    /// only state that unlocks credential decisions.
    #[test]
    fn a_disciplined_clock_within_bound_is_synchronized() {
        assert_eq!(
            classify(TIME_OK, 0, 1_000, BOUND),
            ClockSync::Synchronized {
                max_error_us: 1_000
            }
        );
        assert!(classify(TIME_OK, 0, 1_000, BOUND).is_trusted());
    }

    /// `STA_UNSYNC` is the daemon saying "I have not disciplined this clock".
    /// It is decisive on its own, whatever the return value or the error bound
    /// say — a freshly booted node reports a small `maxerror` alongside it.
    #[test]
    fn the_unsync_status_bit_is_decisive() {
        assert_eq!(
            classify(TIME_OK, STA_UNSYNC, 0, BOUND),
            ClockSync::Unsynchronized
        );
        assert!(!classify(TIME_OK, STA_UNSYNC, 0, BOUND).is_trusted());
    }

    /// `TIME_ERROR` is a *superset* of the status bit — the kernel also returns
    /// it for `STA_CLOCKERR` and for an unsatisfied PPS condition. Checked
    /// independently and folded into the same verdict deliberately: none of
    /// those states is a clock to make a credential decision against, and
    /// "simplifying" one check away would silently drop the other two.
    #[test]
    fn a_time_error_return_is_unsynchronized() {
        assert_eq!(classify(TIME_ERROR, 0, 0, BOUND), ClockSync::Unsynchronized);
    }

    /// The state this node's own bound exists to catch: nominally disciplined,
    /// but the kernel's own estimate of how wrong it might be is wider than we
    /// will make a credential decision across.
    #[test]
    fn an_error_bound_past_the_limit_is_not_trusted() {
        let over = BOUND as i64 + 1;
        assert_eq!(
            classify(TIME_OK, 0, over, BOUND),
            ClockSync::ErrorTooLarge {
                max_error_us: over as u64,
                bound_us: BOUND,
            }
        );
        assert!(!classify(TIME_OK, 0, over, BOUND).is_trusted());
    }

    /// The bound is inclusive: a reading exactly at the limit is still inside
    /// it. Pinned because an off-by-one here silently narrows the operator's
    /// configured tolerance.
    #[test]
    fn the_error_bound_is_inclusive() {
        assert_eq!(
            classify(TIME_OK, 0, BOUND as i64, BOUND),
            ClockSync::Synchronized {
                max_error_us: BOUND
            }
        );
    }

    /// The saturated reading an undisciplined Linux host produces:
    /// `TIME_ERROR`, `STA_UNSYNC`, and `maxerror` pinned at the kernel's 16 s
    /// ceiling. Pinned as a named case because it is what an unconfigured host
    /// actually looks like, and the one every developer will hit first.
    #[test]
    fn an_undisciplined_host_reads_as_unsynchronized() {
        assert_eq!(
            classify(TIME_ERROR, STA_UNSYNC, 16_000_000, BOUND),
            ClockSync::Unsynchronized
        );
    }

    /// A negative `maxerror` is not a value the kernel should ever report.
    /// Refuse it rather than casting it into an enormous `u64` (which would
    /// land in `ErrorTooLarge` by accident) or a small one (which would land in
    /// `Synchronized`, trusting a clock on the strength of a malformed
    /// reading).
    #[test]
    fn a_negative_error_bound_is_refused() {
        assert_eq!(classify(TIME_OK, 0, -1, BOUND), ClockSync::Unsynchronized);
    }

    /// The default posture enforces, at the default bound. Spelled out because
    /// this is the one that ships: a node nobody configured must be the safe
    /// one, not the permissive one.
    #[test]
    fn the_default_settings_enforce_at_the_default_bound() {
        assert_eq!(
            ClockTrust::from_settings(true, None),
            ClockTrust::Ntp {
                max_error_us: DEFAULT_MAX_CLOCK_ERROR_US
            }
        );
    }

    /// An operator-chosen bound is used verbatim.
    #[test]
    fn a_configured_bound_is_honoured() {
        assert_eq!(
            ClockTrust::from_settings(true, Some(250_000)),
            ClockTrust::Ntp {
                max_error_us: 250_000
            }
        );
    }

    /// Turning enforcement off ignores the bound rather than half-applying it.
    /// A node configured `require_time_sync = false` must not still refuse on a
    /// wide `maxerror` — the operator asked for no gate, and a gate that fires
    /// anyway is worse than either choice.
    #[test]
    fn the_opt_out_ignores_a_configured_bound() {
        assert_eq!(ClockTrust::from_settings(false, None), ClockTrust::Assume);
        assert_eq!(
            ClockTrust::from_settings(false, Some(1)),
            ClockTrust::Assume
        );
    }

    /// `Assume` is the operator's opt-out and must ask the kernel nothing, so
    /// it reports trusted whatever the build host's real NTP state is.
    #[test]
    fn assume_trusts_without_consulting_the_kernel() {
        assert!(read(ClockTrust::Assume).is_trusted());
    }

    /// `Never` pins the untrusted branch regardless of the host's real state,
    /// so the gate is testable on a machine with a perfectly good clock.
    #[test]
    fn never_is_untrusted_whatever_the_host_says() {
        assert!(!read(ClockTrust::Never).is_trusted());
        assert_eq!(read(ClockTrust::Never), ClockSync::Unsynchronized);
    }

    /// A platform with no NTP status to read is trusted rather than fail-closed.
    /// Deliberate: failing closed there would make a macOS dev machine unable to
    /// run a provider at all, and the enforcement is a defence against a
    /// misconfigured deployment, not against the developer's own laptop. The
    /// startup warning is what keeps it honest.
    #[test]
    fn an_unsupported_platform_is_trusted() {
        assert!(ClockSync::Unsupported.is_trusted());
    }

    /// Each state has a distinct stable name; an operator-facing projection
    /// must not render two different conditions identically.
    #[test]
    fn every_state_has_a_distinct_name() {
        let names = [
            ClockSync::Synchronized { max_error_us: 0 }.name(),
            ClockSync::Unsynchronized.name(),
            ClockSync::ErrorTooLarge {
                max_error_us: 0,
                bound_us: 0,
            }
            .name(),
            ClockSync::Unsupported.name(),
        ];
        let mut seen = Vec::new();
        for n in names {
            assert!(!n.is_empty(), "every state has a name");
            assert!(!seen.contains(&n), "state name {n} is not unique");
            seen.push(n);
        }
    }
}
