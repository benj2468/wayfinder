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
//!
//! A host binary can also take its identity from the environment it is
//! *started* in, through [`build`] and the `std` feature. That is how Nix
//! stamps a package: the compile carries no identity, so it is the same
//! derivation on every commit and comes from the binary cache, and a wrapper
//! sets the variables on the binary. Boards never enable `std` and keep the
//! compile-time answer.

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

#[cfg(feature = "std")]
extern crate std;

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

/// The build identity this process should report.
///
/// Without the `std` feature this is [`BUILD`]. With it, an identity injected
/// into the process environment (`$WAYFINDER_BUILD_VERSION` and
/// `$WAYFINDER_BUILD_COMMIT`, the variables `build.rs` reads at compile time)
/// takes precedence; see [`with_runtime`] for the rule.
///
/// Prefer this to the consts in anything that reports the build of a host
/// binary. The `std` feature is unified across a build, so a `no_std` crate
/// that calls this (`wayfinder-protos`, answering `GetNodeInfo`) reports the
/// runtime identity whenever the binary it is linked into enabled it.
pub fn build() -> Resolved<'static> {
    #[cfg(feature = "std")]
    {
        use std::string::String;
        use std::sync::OnceLock;

        // Read once: the answer describes the binary, so it cannot change
        // under a running process, and every `GetNodeInfo` reuses it.
        static RUNTIME: OnceLock<(Option<String>, Option<String>)> = OnceLock::new();
        let (version, commit) = RUNTIME.get_or_init(|| {
            (
                std::env::var("WAYFINDER_BUILD_VERSION").ok(),
                std::env::var("WAYFINDER_BUILD_COMMIT").ok(),
            )
        });
        with_runtime(BUILD, version.as_deref(), commit.as_deref())
    }
    #[cfg(not(feature = "std"))]
    {
        BUILD
    }
}

/// Prefer an identity injected at runtime over the compiled one.
///
/// The runtime pair is resolved exactly as `build.rs` resolves the
/// compile-time variables, so blank and control-character values count as
/// absent, and a usable version reports as [`BuildSource::Injected`]. With no
/// usable runtime version the compiled identity stands unchanged: an unset
/// environment says nothing, rather than "unknown". Pure, so the rule is
/// tested without touching the process environment.
pub fn with_runtime<'a>(
    compiled: Resolved<'a>,
    version: Option<&'a str>,
    commit: Option<&'a str>,
) -> Resolved<'a> {
    let runtime = resolve::resolve(resolve::Inputs {
        injected_version: version,
        injected_commit: commit,
        ..resolve::Inputs::default()
    });
    if runtime.source == BuildSource::Unknown {
        compiled
    } else {
        runtime
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPILED: Resolved<'static> = Resolved {
        version: "35dcaee",
        commit: "35dcaee",
        dirty: false,
        source: BuildSource::Git,
    };

    #[test]
    fn a_runtime_identity_overrides_the_compiled_one() {
        let r = with_runtime(COMPILED, Some("6409f0c-dirty"), Some("6409f0c"));

        assert_eq!(r.version, "6409f0c-dirty");
        assert_eq!(r.commit, "6409f0c");
        assert!(r.dirty);
        assert_eq!(r.source, BuildSource::Injected);
    }

    #[test]
    fn no_runtime_identity_keeps_the_compiled_one() {
        assert_eq!(with_runtime(COMPILED, None, None), COMPILED);
        // A commit alone names no version, so it is not an identity.
        assert_eq!(with_runtime(COMPILED, None, Some("6409f0c")), COMPILED);
    }

    #[test]
    fn an_unusable_runtime_version_keeps_the_compiled_one() {
        assert_eq!(with_runtime(COMPILED, Some("  "), None), COMPILED);
        assert_eq!(with_runtime(COMPILED, Some("v1\nx"), None), COMPILED);
    }

    #[test]
    fn a_runtime_version_without_a_commit_does_not_borrow_the_compiled_commit() {
        let r = with_runtime(COMPILED, Some("v1.2.3"), None);

        assert_eq!(r.version, "v1.2.3");
        assert_eq!(r.commit, resolve::UNKNOWN);
    }

    /// Run without the variables set, which is how every test runs.
    #[test]
    fn build_without_a_runtime_identity_is_the_compiled_one() {
        if std_env_is_clear() {
            assert_eq!(build(), BUILD);
        }
    }

    #[cfg(feature = "std")]
    fn std_env_is_clear() -> bool {
        std::env::var_os("WAYFINDER_BUILD_VERSION").is_none()
    }

    #[cfg(not(feature = "std"))]
    fn std_env_is_clear() -> bool {
        true
    }

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
