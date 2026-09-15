//! What build is this node running?
//!
//! A mesh node cannot be asked which code it is executing. On a host that is
//! merely inconvenient; on a bare-metal board it is unanswerable — no
//! filesystem to inspect, no package manager, and often no debug probe
//! attached. Diagnosing a live auth question ("does *this* board carry the
//! rebooted-peer re-anchor fix?") came down to reading the mtime of a `.hex`
//! file and asking the operator when they last flashed. That is not a
//! diagnosis.
//!
//! This crate is the compile-time half of the answer: a build identity baked
//! into `.rodata`, costing nothing at runtime, available to `no_std` targets,
//! and reported over the management API by every node. See
//! `docs/design/implemented/23-build-provenance.md`.
//!
//! ```text
//! tagged HEAD       -> v0.4.0
//! tag + 12 commits  -> v0.4.0-12-g35dcaee
//! no tag            -> 35dcaee
//! modified tree     -> ...-dirty
//! ```
//!
//! Everything here is a `const` resolved by `build.rs`, so reading it is free
//! and nothing is parsed at runtime.

#![no_std]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// Turning raw build-environment facts into a build identity.
///
/// Deliberately **pure**: it takes the strings a build script has already
/// collected (environment variables, the stdout of two `git` invocations) and
/// decides what the node should report. Nothing here runs a process, reads a
/// file or touches the clock, which is what makes the rules testable at all — a
/// `build.rs` cannot be unit-tested, so every decision lives here and the
/// script stays a thin collector.
///
/// `build.rs` compiles this same source with `include!`, so the code that runs
/// at build time is the code the unit tests pin down.
pub mod resolve;

pub use resolve::BuildSource;
pub use resolve::Resolved;

/// The human-readable build identity — the tag, describe string or short hash.
pub const VERSION: &str = env!("WAYFINDER_BUILD_VERSION_RESOLVED");

/// The short commit hash, or [`resolve::UNKNOWN`] if it could not be determined.
pub const COMMIT: &str = env!("WAYFINDER_BUILD_COMMIT_RESOLVED");

/// Whether this binary was built from a tree with uncommitted changes.
///
/// See `build.rs` for the one case where this can lag by a build.
pub const DIRTY: bool = matches!(env!("WAYFINDER_BUILD_DIRTY_RESOLVED").as_bytes(), b"true");

/// How much to trust [`VERSION`].
pub const SOURCE: BuildSource = resolve::source_from_name(env!("WAYFINDER_BUILD_SOURCE_RESOLVED"));

/// Everything above, as one value to hand to a management-API response.
///
/// Deliberately the same [`Resolved`] type the build script produced, rather
/// than a second struct of the same shape: two types for one concept drift
/// apart silently — add a field to one and the other quietly under-reports.
pub const BUILD: Resolved<'static> = Resolved {
    version: VERSION,
    commit: COMMIT,
    dirty: DIRTY,
    source: SOURCE,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Whatever environment this is built in, the crate must report *something*
    /// coherent — the point of the three-tier fallthrough is that there is no
    /// build configuration in which these consts are absent or empty.
    #[test]
    fn the_build_identity_is_always_populated() {
        assert!(!VERSION.is_empty());
        assert!(!COMMIT.is_empty());
    }

    /// The consts and [`BUILD`] must agree, which is really a test of the
    /// `build.rs` → `lib.rs` handshake: four values cross that boundary as
    /// strings, and each is only meaningful if it round-trips.
    #[test]
    fn the_build_identity_is_self_consistent() {
        // Whether a source was determined and whether a version was determined
        // are the same question, and disagreeing would mean one of the four
        // `rustc-env` values did not survive the crossing.
        assert_eq!(
            SOURCE == BuildSource::Unknown,
            VERSION == resolve::UNKNOWN,
            "source={SOURCE:?} disagrees with version={VERSION}"
        );

        // A known build cannot be nameless, and a `-dirty` suffix and the flag
        // must never contradict each other.
        if SOURCE != BuildSource::Unknown {
            assert!(!VERSION.is_empty());
            assert_eq!(
                DIRTY,
                VERSION.ends_with("-dirty"),
                "the dirty flag and the version string disagree: {VERSION}"
            );
        }
    }

    /// Deliberately *not* asserting `SOURCE != Unknown`: that asserts a property
    /// of the machine, not of this crate. The CI image ships no `git` (see
    /// `containers/testenv.Dockerfile`) and neither does a source tarball or the
    /// Nix sandbox, so `Unknown` is a legitimate outcome there and an earlier
    /// version of this test would have failed the pipeline for it. What must
    /// hold everywhere is that an *answered* build names its commit.
    #[test]
    fn a_build_that_knows_its_source_also_names_a_commit_or_says_it_cannot() {
        match SOURCE {
            // The git tier reads `rev-parse` in the same breath as `describe`,
            // so a commit is always available when git answered at all.
            BuildSource::Git => assert_ne!(COMMIT, resolve::UNKNOWN),
            // An injected identity may legitimately carry no commit — a bare
            // tag has no hash in it — so the only requirement is that it says
            // so rather than inventing one.
            BuildSource::Injected => assert!(!COMMIT.is_empty()),
            BuildSource::Unknown => assert_eq!(COMMIT, resolve::UNKNOWN),
        }
    }
}
