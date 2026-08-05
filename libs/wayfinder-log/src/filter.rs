//! The runtime `RUST_LOG`-style filter every sink in this crate gates on.
//!
//! One filter serves every sink on every target — RTT and the ring on a board,
//! the console and the ring on a host — so `SetLogLevel` means the same thing
//! wherever it is sent, and one test suite covers the grammar.
//!
//! # Why not `EnvFilter`
//!
//! [`tracing_subscriber::EnvFilter`] is the obvious thing to reach for and
//! cannot be used: it pulls in `regex`/`matchers`/`thread_local` and is `std`
//! only, so it cannot exist on the boards — which are precisely the nodes whose
//! logs are otherwise unreachable. Rather than run a different filter grammar on
//! each target, both run this one.
//!
//! [`tracing_subscriber::EnvFilter`]: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html
//!
//! # The supported grammar
//!
//! A comma-separated list of directives, matching `env_logger`/`EnvFilter` for
//! the subset it covers:
//!
//! - `level` — the fallback for targets no other directive matches (`info`).
//! - `target=level` — that level for `target` and everything beneath it
//!   (`wayfinder::router=debug`).
//! - `target` — everything from that target (`batman`, equivalent to
//!   `batman=trace`).
//! - `off` as a level disables matching records entirely.
//!
//! Targets match on module-path prefix, and the **longest** matching directive
//! wins regardless of the order it was written in. A target no directive matches
//! is disabled — a bare `target=level` does not imply a global default, exactly
//! as in `EnvFilter`.
//!
//! Prefixes match at module boundaries, which is one deliberate divergence from
//! those crates; see [`target_matches`] for why this workspace in particular
//! cannot use their plain `starts_with`.
//!
//! `EnvFilter`'s span and field extensions (`target[span{field=value}]=level`)
//! are **not** supported and are rejected outright by [`Filter::parse`]. Silently
//! reinterpreting `wayfinder[handle_frame]=trace` as a target name would enable
//! far more than the operator asked for, on the one path where over-logging is
//! most expensive.
//!
//! # The two-stage gate
//!
//! [`enabled`] runs on every callsite evaluation, sometimes from an interrupt,
//! on a board whose radio timing does not tolerate long interrupt masking. So it
//! is split:
//!
//! 1. [`level_enabled`] — one relaxed load of [`MAX_LEVEL`] (the coarsest level
//!    any directive admits) and a compare. Lock-free, and rejects the bulk of
//!    the traffic whenever the filter is not at `trace`.
//! 2. Only for what survives, the directive list under a [`Lock`]. That runs at
//!    most at the rate of records that are about to be formatted and written,
//!    which costs more than the lock does.
//!
//! Stage 1 must therefore never be *more* restrictive than stage 2, or records
//! would be dropped before their directive was ever consulted; that relationship
//! is what `max_level_admits_a_superset_of_what_directives_allow` pins down.

use core::sync::atomic::AtomicU8;
use core::sync::atomic::Ordering;

use crate::sync::Lock;

/// Longest target a directive may name. Comfortably past the longest module path
/// in this workspace (`wayfinder::router::multicast` and friends); a longer one
/// is rejected rather than silently truncated into a prefix that would match far
/// more than the operator wrote.
pub const TARGET_CAP: usize = 64;

/// Most directives one filter may carry. Well past the handful of crates an
/// operator narrows to in practice, and bounded because the whole filter lives
/// in a `static` on a board with 256 KiB of RAM.
pub const MAX_DIRECTIVES: usize = 12;

/// Longest filter spec accepted, in bytes. Retained verbatim for readback, so
/// this also bounds the `static` that holds it.
pub const SPEC_CAP: usize = 192;

/// The filter in force before anything sets one, and what an empty spec means.
///
/// Derived from [`DEFAULT_LEVEL`] rather than written out, so the two cannot
/// disagree — this is the string an operator reads back (`Filter::spec`, and
/// `LogRecords.filter` on every `GetLogs`), so it naming a different threshold
/// than the one actually in force would be a lie told by the observability
/// system about itself.
///
/// Never `off`: a node that has never been configured should still record the
/// lifecycle events an operator needs to see it come up, and neither `info` nor
/// `debug` can flood the ring on its own — this project's logging rules put
/// everything per-frame at `trace`.
pub const DEFAULT_SPEC: &str = DEFAULT_LEVEL.as_spec();

/// Verbosity of a single log record, ordered least to most verbose.
///
/// A local type rather than `tracing_core::Level` or `log::Level` because both
/// facades feed the same ring and the same filter, and because the host layer
/// and the bare-metal subscriber must agree on the wire value the management API
/// reports. Conversions from both facades live alongside their adapters.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Level {
    /// A failure an operator must act on, originating in this node.
    Error = 1,
    /// Unexpected but handled, worth operator attention.
    Warn = 2,
    /// A lifecycle or topology event an observer wants.
    Info = 3,
    /// A developer-facing state transition.
    Debug = 4,
    /// Per-frame/packet flow — the bulk of the records.
    Trace = 5,
}

impl From<tracing_core::Level> for Level {
    /// Map a `tracing` level onto this crate's own. Total in both directions —
    /// the two enums have the same five variants — so no record can arrive at a
    /// level the ring cannot represent.
    fn from(level: tracing_core::Level) -> Self {
        match level {
            tracing_core::Level::ERROR => Self::Error,
            tracing_core::Level::WARN => Self::Warn,
            tracing_core::Level::INFO => Self::Info,
            tracing_core::Level::DEBUG => Self::Debug,
            tracing_core::Level::TRACE => Self::Trace,
        }
    }
}

impl core::fmt::Display for Level {
    /// The uppercase name, as it appears in a rendered log line.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        })
    }
}

/// A directive's threshold: a [`Level`] plus the `off` that admits nothing.
///
/// Distinct from [`Level`] because `off` is expressible as a *filter* but never
/// as a record's own level — a record is always emitted at some real level.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum LevelFilter {
    /// Admits nothing.
    Off = 0,
    /// Admits `error`.
    Error = 1,
    /// Admits `error`, `warn`.
    Warn = 2,
    /// Admits `error`, `warn`, `info`.
    Info = 3,
    /// Admits everything but `trace`.
    Debug = 4,
    /// Admits everything.
    Trace = 5,
}

impl LevelFilter {
    /// Whether a record at `level` passes this threshold.
    fn admits(self, level: Level) -> bool {
        (level as u8) <= (self as u8)
    }

    /// This level's canonical spec name — the inverse of [`parse`](Self::parse)
    /// for the names `parse` round-trips (the `err`/`warning` aliases parse but
    /// are never produced).
    ///
    /// `const` so [`DEFAULT_SPEC`] can be *derived* from [`DEFAULT_LEVEL`]
    /// rather than restated. The two must name the same threshold, and a pair of
    /// hand-maintained constants relies on whoever edits one remembering the
    /// other; deriving makes the mismatch unrepresentable.
    const fn as_spec(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    /// Parse a level name, case-insensitively. `warn`/`warning` and
    /// `error`/`err` are both accepted, matching `env_logger`.
    fn parse(name: &str) -> Option<Self> {
        // `eq_ignore_ascii_case` rather than allocating a lowercased copy: this
        // has to work in `no_std` without the heap.
        for (text, level) in [
            ("off", Self::Off),
            ("error", Self::Error),
            ("err", Self::Error),
            ("warn", Self::Warn),
            ("warning", Self::Warn),
            ("info", Self::Info),
            ("debug", Self::Debug),
            ("trace", Self::Trace),
        ] {
            if name.eq_ignore_ascii_case(text) {
                return Some(level);
            }
        }
        None
    }
}

/// Why a filter spec was refused. Every variant leaves the previous filter in
/// force — a typo must never blind a node.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FilterParseError {
    /// A directive's level name is not one of the recognized names (or is
    /// empty, as in a trailing `wayfinder=`).
    UnknownLevel,
    /// The directive uses `EnvFilter`'s span/field syntax, which this filter
    /// does not implement. See the module doc.
    Unsupported,
    /// A directive's target is longer than [`TARGET_CAP`].
    TargetTooLong,
    /// The spec carries more than [`MAX_DIRECTIVES`] directives.
    TooManyDirectives,
    /// The spec is longer than [`SPEC_CAP`] bytes.
    SpecTooLong,
}

impl core::fmt::Display for FilterParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            Self::UnknownLevel => "unknown log level (expected off/error/warn/info/debug/trace)",
            Self::Unsupported => {
                "span and field filters are not supported; use target=level directives"
            }
            Self::TargetTooLong => "directive target is too long",
            Self::TooManyDirectives => "too many directives",
            Self::SpecTooLong => "filter spec is too long",
        };
        f.write_str(text)
    }
}

/// One parsed directive: a target prefix and the threshold it grants.
#[derive(Clone)]
struct Directive {
    /// The module-path prefix this applies to. Empty means "everything", which
    /// is how a bare `level` directive is represented — and, since the empty
    /// string is a prefix of every target and the shortest possible one, it
    /// naturally sorts last and acts as the fallback.
    target: heapless::String<TARGET_CAP>,
    /// The threshold granted to targets this directive matches.
    level: LevelFilter,
}

/// A parsed filter: the directive list plus the spec it came from.
pub struct Filter {
    /// Sorted by descending target length, so the first prefix match found is
    /// the longest — which is what makes `wayfinder=info,wayfinder::router=trace`
    /// mean the same thing as its reverse.
    directives: heapless::Vec<Directive, MAX_DIRECTIVES>,
    /// The spec verbatim, for readback. Empty means [`DEFAULT_SPEC`].
    spec: heapless::String<SPEC_CAP>,
    /// The coarsest level any directive admits — [`MAX_LEVEL`]'s value, cached
    /// here so installing a filter is one store rather than a re-scan.
    max_level: LevelFilter,
}

impl Filter {
    /// The filter in force before anything sets one: [`DEFAULT_SPEC`].
    ///
    /// `const` so the global lives in a `static` with no initializer. An empty
    /// directive list is *not* "nothing enabled" — [`Filter::enabled`] reads it
    /// as the default level, which is what lets logging work before any `init`
    /// has run.
    const fn default_filter() -> Self {
        Self {
            directives: heapless::Vec::new(),
            spec: heapless::String::new(),
            max_level: DEFAULT_LEVEL,
        }
    }

    /// Parse a `RUST_LOG`-style spec. See the module doc for the grammar.
    ///
    /// An empty (or all-whitespace) spec yields the default filter rather than
    /// an error, so clearing the field in a TUI restores the default instead of
    /// being refused.
    pub fn parse(spec: &str) -> Result<Self, FilterParseError> {
        if spec.len() > SPEC_CAP {
            return Err(FilterParseError::SpecTooLong);
        }
        // Rejected before the split so it is caught wherever it appears, rather
        // than only when it lands in a position the directive parser inspects.
        if spec.contains(['[', ']', '{', '}']) {
            return Err(FilterParseError::Unsupported);
        }

        let mut directives: heapless::Vec<Directive, MAX_DIRECTIVES> = heapless::Vec::new();
        for piece in spec.split(',') {
            let piece = piece.trim();
            // A trailing or doubled comma is a typo, not grounds to refuse the
            // whole update and leave the operator with the old filter.
            if piece.is_empty() {
                continue;
            }

            let (target, level) = match piece.split_once('=') {
                // `target=level`; an empty target (`=info`) is the fallback.
                Some((target, level)) => (
                    target.trim(),
                    LevelFilter::parse(level.trim()).ok_or(FilterParseError::UnknownLevel)?,
                ),
                // A bare word: a level name if it is one, else a target at trace.
                None => match LevelFilter::parse(piece) {
                    Some(level) => ("", level),
                    None => (piece, LevelFilter::Trace),
                },
            };

            let target =
                heapless::String::try_from(target).map_err(|_| FilterParseError::TargetTooLong)?;
            directives
                .push(Directive { target, level })
                .map_err(|_| FilterParseError::TooManyDirectives)?;
        }

        // Longest target first, so the first prefix hit in `enabled` is the most
        // specific one and the empty-target fallback is consulted last.
        directives.sort_unstable_by_key(|d| core::cmp::Reverse(d.target.len()));

        let max_level = directives
            .iter()
            .map(|d| d.level)
            .max()
            .unwrap_or(DEFAULT_LEVEL);

        #[expect(
            clippy::expect_used,
            reason = "the length was checked against SPEC_CAP above"
        )]
        let spec = heapless::String::try_from(spec).expect("spec length checked above");

        Ok(Self {
            directives,
            spec,
            max_level,
        })
    }

    /// Whether a record at `level` from `target` passes this filter.
    ///
    /// With no directives at all this is the default level, which is what the
    /// pre-`init` global reports.
    pub fn enabled(&self, level: Level, target: &str) -> bool {
        if self.directives.is_empty() {
            return DEFAULT_LEVEL.admits(level);
        }
        for directive in &self.directives {
            if target_matches(target, directive.target.as_str()) {
                return directive.level.admits(level);
            }
        }
        // No directive matched. Unlike a bare level, a spec made only of target
        // directives leaves everything else off.
        false
    }

    /// The coarsest level any directive admits — the fast path's screen.
    pub fn max_level(&self) -> LevelFilter {
        self.max_level
    }

    /// The spec this filter was parsed from, or [`DEFAULT_SPEC`] if it was
    /// empty. Echoed verbatim rather than re-rendered from the directives so a
    /// client displays exactly what was installed.
    pub fn spec(&self) -> &str {
        if self.spec.is_empty() {
            DEFAULT_SPEC
        } else {
            self.spec.as_str()
        }
    }
}

/// Whether `target` falls under the module path `prefix`.
///
/// A prefix matches at a module boundary only: `wayfinder` covers `wayfinder`
/// and `wayfinder::router::demux`, but not `wayfinder_server::adapter`. The
/// empty prefix matches everything, which is what makes a bare level the
/// fallback.
///
/// **This is a deliberate divergence from `env_logger`/`EnvFilter`**, both of
/// which use a plain `starts_with` and would let `wayfinder` cover
/// `wayfinder_server` too. That difference is invisible in most workspaces and
/// acutely wrong in this one, where nearly every crate is named `wayfinder_*`:
/// under plain prefix matching, `wayfinder=trace` would quietly turn on trace
/// for the auth stack, the driver, the server, and the protos as well — on the
/// one path where over-logging costs the most. An operator who does want the
/// broad sweep can still write it as several directives.
fn target_matches(target: &str, prefix: &str) -> bool {
    if prefix.is_empty() {
        return true;
    }
    let Some(rest) = target.strip_prefix(prefix) else {
        return false;
    };
    rest.is_empty() || rest.starts_with("::")
}

/// The default threshold, and the single source of truth for the startup
/// filter — [`DEFAULT_SPEC`] is derived from it.
///
/// `debug` in a development build, `info` in a release one. A node that nobody
/// has configured should be as talkative as the build implies: on a board there
/// is no `RUST_LOG` to consult, so this constant *is* the default (a host node
/// reads `RUST_LOG` first and only falls back here).
///
/// Keyed on `debug_assertions` rather than a Cargo feature deliberately: a
/// feature is additive and unifies across the workspace, so one crate enabling
/// a hypothetical `verbose-default` would raise the default for every other
/// crate in the build — a value, unlike a capability, is the wrong thing to
/// express as a feature.
///
/// The coupling to `debug_assertions` is worth knowing about, though: a release
/// profile that sets `debug-assertions = true` (a normal thing to do when
/// chasing a fault on hardware) also gets `debug` logging, and on the nRF board
/// that means `embassy-nrf`/`nrf-softdevice` chatter through the RTT and ring
/// critical sections. Set the filter explicitly via `SetLogLevel` if that
/// matters more than the default.
const DEFAULT_LEVEL: LevelFilter = if cfg!(debug_assertions) {
    LevelFilter::Debug
} else {
    LevelFilter::Info
};

/// The coarsest level the installed filter admits: the whole of the lock-free
/// fast path.
///
/// Separate from [`FILTER`] rather than read out of it because the point is to
/// answer the common case without taking a lock at all. `Relaxed` throughout:
/// this gates logging, so the only consequence of an in-flight filter change
/// being observed late is a record or two decided under the previous filter.
static MAX_LEVEL: AtomicU8 = AtomicU8::new(DEFAULT_LEVEL as u8);

/// The installed filter's directive list. Consulted only for records the fast
/// path already admitted.
static FILTER: Lock<Filter> = Lock::new(Filter::default_filter());

/// Install `spec` as the global filter, replacing whatever was in force.
///
/// On success every sink in this crate immediately gates on the new filter. On
/// failure nothing changes — the previous filter stays in force, so a rejected
/// spec costs an operator an error message rather than a node's logs.
pub fn set_filter(spec: &str) -> Result<(), FilterParseError> {
    let filter = Filter::parse(spec)?;
    let max_level = filter.max_level();
    FILTER.with(|f| *f = filter);
    // Stored after the directives, so any window between the two stores has the
    // fast path admitting *more* than the directives allow rather than less. The
    // slow path is authoritative, so a record in that window is still judged
    // correctly; the reverse order could drop one outright.
    MAX_LEVEL.store(max_level as u8, Ordering::Relaxed);
    Ok(())
}

/// The spec currently in force, for readback by a management client.
pub fn current_spec() -> heapless::String<SPEC_CAP> {
    FILTER.with(|f| {
        #[expect(
            clippy::expect_used,
            reason = "the stored spec is at most SPEC_CAP bytes by construction"
        )]
        heapless::String::try_from(f.spec()).expect("spec fits by construction")
    })
}

/// The lock-free half of the gate: whether `level` could pass under the
/// installed filter, ignoring targets.
///
/// Cheap enough for a per-frame callsite. A `true` here does **not** mean the
/// record is enabled — call [`enabled`] for that — but a `false` is conclusive.
pub fn level_enabled(level: Level) -> bool {
    (level as u8) <= MAX_LEVEL.load(Ordering::Relaxed)
}

/// Whether a record at `level` from `target` is enabled under the installed
/// filter. Screens on [`level_enabled`] before touching the lock.
pub fn enabled(level: Level, target: &str) -> bool {
    level_enabled(level) && FILTER.with(|f| f.enabled(level, target))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a spec that the tests expect to be well-formed.
    fn parse(spec: &str) -> Filter {
        Filter::parse(spec).expect("spec should parse")
    }

    #[test]
    fn bare_level_sets_the_global_default() {
        let f = parse("info");
        assert!(f.enabled(Level::Error, "anything"));
        assert!(f.enabled(Level::Info, "anything"));
        assert!(!f.enabled(Level::Debug, "anything"));
        assert!(!f.enabled(Level::Trace, "anything"));
    }

    #[test]
    fn level_names_are_case_insensitive() {
        assert_eq!(parse("WARN").max_level(), LevelFilter::Warn);
        assert_eq!(parse("Warn").max_level(), LevelFilter::Warn);
        assert_eq!(parse("warn").max_level(), LevelFilter::Warn);
    }

    /// A target-only directive scopes that target and leaves everything else
    /// disabled — matching `env_logger`/`EnvFilter`, where a bare `target=level`
    /// does *not* imply a global default.
    #[test]
    fn target_directive_does_not_grant_a_global_default() {
        let f = parse("wayfinder=debug");
        assert!(f.enabled(Level::Debug, "wayfinder::router"));
        assert!(!f.enabled(Level::Trace, "wayfinder::router"));
        assert!(!f.enabled(Level::Error, "batman::ogm"));
    }

    /// A bare target with no `=level` means "everything from this target",
    /// i.e. trace.
    #[test]
    fn bare_target_means_trace_for_that_target() {
        let f = parse("batman");
        assert!(f.enabled(Level::Trace, "batman::ogm"));
        assert!(!f.enabled(Level::Error, "wayfinder::router"));
    }

    /// Targets match on module-path prefix, so one directive covers a whole
    /// crate's submodules.
    #[test]
    fn target_matches_are_prefix_matches() {
        let f = parse("wayfinder=debug");
        assert!(f.enabled(Level::Debug, "wayfinder"));
        assert!(f.enabled(Level::Debug, "wayfinder::router::demux"));
        assert!(!f.enabled(Level::Debug, "wayfinderx"));
        assert!(!f.enabled(Level::Debug, "other::wayfinder"));
    }

    /// The motivating case for boundary-aware matching: almost every crate here
    /// is named `wayfinder_*`, so a plain `starts_with` would make
    /// `wayfinder=trace` silently turn on trace for the auth stack, the server,
    /// and the driver too.
    #[test]
    fn sibling_crates_sharing_a_name_prefix_are_not_swept_in() {
        let f = parse("wayfinder=trace");
        assert!(f.enabled(Level::Trace, "wayfinder"));
        assert!(f.enabled(Level::Trace, "wayfinder::router::demux"));
        assert!(!f.enabled(Level::Error, "wayfinder_server::adapter"));
        assert!(!f.enabled(Level::Error, "wayfinder_auth::cert"));
    }

    /// The most specific (longest) matching target wins regardless of the order
    /// the directives were written in — otherwise `wayfinder=info,wayfinder::router=trace`
    /// and its reverse would mean different things.
    #[test]
    fn longest_target_prefix_wins_regardless_of_order() {
        for spec in [
            "wayfinder=info,wayfinder::router=trace",
            "wayfinder::router=trace,wayfinder=info",
        ] {
            let f = parse(spec);
            assert!(f.enabled(Level::Trace, "wayfinder::router"), "{spec}");
            assert!(!f.enabled(Level::Debug, "wayfinder::demux"), "{spec}");
            assert!(f.enabled(Level::Info, "wayfinder::demux"), "{spec}");
        }
    }

    /// A bare level combines with target directives as the fallback for
    /// everything they don't cover.
    #[test]
    fn bare_level_is_the_fallback_for_unmatched_targets() {
        let f = parse("warn,batman=trace");
        assert!(f.enabled(Level::Trace, "batman::ogm"));
        assert!(f.enabled(Level::Warn, "wayfinder::router"));
        assert!(!f.enabled(Level::Info, "wayfinder::router"));
    }

    #[test]
    fn off_disables_a_target_entirely() {
        let f = parse("info,blue=off");
        assert!(f.enabled(Level::Info, "wayfinder"));
        assert!(!f.enabled(Level::Error, "blue::nrf"));
    }

    /// The empty spec is the built-in default rather than "nothing enabled" — a
    /// node that has never been told otherwise still logs.
    ///
    /// Asserted against `DEFAULT_LEVEL` rather than a hardcoded level: the
    /// contract is "empty means the default", and the default legitimately
    /// varies by build profile. Naming a literal level here would make this fail
    /// whenever the default changed, without the contract having broken — while
    /// still not checking the thing it is for.
    #[test]
    fn empty_spec_is_the_default_level() {
        let f = parse("");
        for level in [
            Level::Error,
            Level::Warn,
            Level::Info,
            Level::Debug,
            Level::Trace,
        ] {
            assert_eq!(
                f.enabled(level, "anything"),
                DEFAULT_LEVEL.admits(level),
                "the empty spec must admit exactly what {DEFAULT_LEVEL:?} does, at {level:?}"
            );
        }
        // Not vacuous even though the default is a threshold: `off` would admit
        // nothing at all, which is what this test exists to rule out.
        assert!(f.enabled(Level::Error, "anything"));
        assert_eq!(f.spec(), DEFAULT_SPEC);
    }

    /// Whitespace around directives is tolerated, since these arrive from a
    /// human typing into a TUI field.
    #[test]
    fn surrounding_whitespace_is_ignored() {
        let f = parse("  info , batman = trace ");
        assert!(f.enabled(Level::Trace, "batman::ogm"));
        assert!(f.enabled(Level::Info, "wayfinder"));
        assert!(!f.enabled(Level::Debug, "wayfinder"));
    }

    /// Empty directives between commas are skipped rather than rejected — a
    /// trailing comma is a typo, not a reason to refuse the whole update.
    #[test]
    fn empty_directives_are_skipped() {
        let f = parse("info,,batman=trace,");
        assert!(f.enabled(Level::Trace, "batman::ogm"));
        assert!(f.enabled(Level::Info, "wayfinder"));
    }

    /// `max_level` is the coarsest level any directive admits: the value the
    /// lock-free fast path screens on before any target matching happens. It
    /// must never be lower than what some directive would actually allow, or
    /// records would be dropped before the directive was consulted.
    #[test]
    fn max_level_is_the_most_verbose_directive() {
        assert_eq!(parse("info").max_level(), LevelFilter::Info);
        assert_eq!(parse("warn,batman=trace").max_level(), LevelFilter::Trace);
        assert_eq!(parse("error,blue=off").max_level(), LevelFilter::Error);
        assert_eq!(parse("off").max_level(), LevelFilter::Off);
    }

    /// Everything `max_level` admits must still be re-checked against the
    /// directives; the fast path is a screen, not the decision.
    #[test]
    fn max_level_admits_a_superset_of_what_directives_allow() {
        let f = parse("warn,batman=trace");
        assert_eq!(f.max_level(), LevelFilter::Trace);
        assert!(!f.enabled(Level::Trace, "wayfinder"));
    }

    #[test]
    fn unknown_level_name_is_rejected() {
        assert!(matches!(
            Filter::parse("wayfinder=verbose"),
            Err(FilterParseError::UnknownLevel)
        ));
    }

    /// A directive with an `=` but nothing after it is a typo, not "trace".
    #[test]
    fn empty_level_after_equals_is_rejected() {
        assert!(matches!(
            Filter::parse("wayfinder="),
            Err(FilterParseError::UnknownLevel)
        ));
    }

    /// `EnvFilter`'s span/field extensions are not implemented here. They must
    /// be refused rather than silently reinterpreted as a target name, which
    /// would enable far more than the operator asked for.
    #[test]
    fn span_and_field_directives_are_rejected() {
        assert!(matches!(
            Filter::parse("wayfinder[handle_frame]=trace"),
            Err(FilterParseError::Unsupported)
        ));
        assert!(matches!(
            Filter::parse("[{payload_len}]=trace"),
            Err(FilterParseError::Unsupported)
        ));
    }

    #[test]
    fn overlong_target_is_rejected() {
        let spec = alloc::format!("{}=info", "m".repeat(TARGET_CAP + 1));
        assert!(matches!(
            Filter::parse(&spec),
            Err(FilterParseError::TargetTooLong)
        ));
    }

    #[test]
    fn too_many_directives_is_rejected() {
        let mut spec = alloc::string::String::new();
        for i in 0..=MAX_DIRECTIVES {
            spec.push_str(&alloc::format!("t{i}=info,"));
        }
        assert!(matches!(
            Filter::parse(&spec),
            Err(FilterParseError::TooManyDirectives)
        ));
    }

    #[test]
    fn overlong_spec_is_rejected() {
        let spec = alloc::format!("a={}", "x".repeat(SPEC_CAP));
        assert!(matches!(
            Filter::parse(&spec),
            Err(FilterParseError::SpecTooLong)
        ));
    }

    /// The spec is echoed back verbatim so a client can display exactly what is
    /// in force, rather than a re-rendering that might not round-trip.
    #[test]
    fn spec_is_retained_for_readback() {
        assert_eq!(parse("warn,batman=trace").spec(), "warn,batman=trace");
    }

    /// The default spec and the default level are two spellings of one thing;
    /// they drift apart silently otherwise, leaving a node whose readback says
    /// one level while it filters at another.
    ///
    /// `DEFAULT_SPEC` is derived from `DEFAULT_LEVEL` via `as_spec`, so this now
    /// holds by construction — kept as the guard on that construction, since
    /// restating either constant by hand would make it fail again.
    #[test]
    fn default_spec_matches_default_level() {
        assert_eq!(
            LevelFilter::parse(DEFAULT_SPEC),
            Some(DEFAULT_LEVEL),
            "DEFAULT_SPEC must name DEFAULT_LEVEL"
        );
    }

    /// Every level's `as_spec` name parses back to that same level.
    ///
    /// This is the invariant `DEFAULT_SPEC`'s derivation rests on: `as_spec` is
    /// only a safe way to render a threshold as a spec if it is a true inverse
    /// of `parse`. A typo in one arm of `as_spec` would otherwise surface as a
    /// node reporting a filter it is not running.
    #[test]
    fn as_spec_round_trips_through_parse() {
        for level in [
            LevelFilter::Off,
            LevelFilter::Error,
            LevelFilter::Warn,
            LevelFilter::Info,
            LevelFilter::Debug,
            LevelFilter::Trace,
        ] {
            assert_eq!(
                LevelFilter::parse(level.as_spec()),
                Some(level),
                "{:?}.as_spec() must parse back to itself",
                level
            );
        }
    }

    // ── The global filter ────────────────────────────────────────────────────

    /// The tests below install the process-wide filter, so they must not run
    /// concurrently with each other. Poisoning is ignored: a panic in one of
    /// them should surface as that test's own failure, not as a cascade of
    /// unrelated ones.
    fn global_filter_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Installing a filter updates both the lock-free fast path and the
    /// directive list they gate, and is visible to `enabled` immediately.
    #[test]
    fn set_filter_installs_and_is_observable() {
        let _guard = global_filter_guard();
        set_filter("info,batman=trace").expect("valid spec");
        assert!(enabled(Level::Trace, "batman::ogm"));
        assert!(enabled(Level::Info, "wayfinder"));
        assert!(!enabled(Level::Debug, "wayfinder"));
        assert_eq!(current_spec(), "info,batman=trace");

        set_filter("error").expect("valid spec");
        assert!(!enabled(Level::Trace, "batman::ogm"));
        assert!(enabled(Level::Error, "batman::ogm"));
        assert_eq!(current_spec(), "error");
    }

    /// A rejected spec leaves the previous filter in force — an operator typo
    /// must not blind the node.
    #[test]
    fn rejected_spec_leaves_the_previous_filter_intact() {
        let _guard = global_filter_guard();
        set_filter("debug").expect("valid spec");
        assert!(set_filter("wayfinder=verbose").is_err());
        assert_eq!(current_spec(), "debug");
        assert!(enabled(Level::Debug, "anything"));
    }

    /// The fast path must not admit anything the full match would reject, and
    /// must not reject anything it would admit.
    #[test]
    fn fast_path_agrees_with_the_full_match() {
        let _guard = global_filter_guard();
        set_filter("warn,batman=trace").expect("valid spec");
        for level in [
            Level::Error,
            Level::Warn,
            Level::Info,
            Level::Debug,
            Level::Trace,
        ] {
            for target in ["batman::ogm", "wayfinder::router"] {
                if enabled(level, target) {
                    assert!(
                        level_enabled(level),
                        "{level:?}/{target} passed the full match but not the fast path"
                    );
                }
            }
        }
    }
}
