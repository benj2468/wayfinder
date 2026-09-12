// Turning raw build-environment facts into a build identity.
//
// The module's documentation lives on its declaration in `lib.rs`, not here:
// `build.rs` pulls this file in with `include!`, and a macro expansion cannot
// carry `//!` inner doc comments. Keep this header as plain comments, and keep
// the file free of `use crate::…` paths, so the same source compiles in both
// places.

/// Where a reported build identity came from.
///
/// On the wire this separates an identity that is exact by construction from
/// one that is best-effort. An `Injected` value was handed to the build by
/// something that knows the answer authoritatively (Nix's flake metadata, a CI
/// variable, a container build argument). A `Git` value was derived by asking
/// `git` in the source tree during the build, which is accurate in practice but
/// can lag a working-tree edit that never touched the index — see
/// [`Resolved::dirty`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildSource {
    /// Derived from `git` in the source tree at build time. Best-effort.
    Git,
    /// Supplied by the build environment, which knew the answer exactly.
    Injected,
    /// Neither was available — a source archive with no git metadata and no
    /// injected variables. The build still succeeds; it just cannot say what
    /// it is.
    Unknown,
}

/// The raw, untrimmed facts a build script can collect about its environment.
///
/// Every field is optional because every one of them is absent in some real
/// build: the injected variables are absent in a developer's tree, and the
/// `git` outputs are absent under `nix build` (no `.git` in the store source),
/// in the container build (the `Dockerfile` never copies `.git`) and in any
/// build from a source archive.
///
/// Values arrive exactly as captured — trailing newlines from `git` stdout and
/// empty strings from an environment variable that is set but blank are both
/// expected, and are normalised by [`resolve`] rather than by the caller.
#[derive(Debug, Clone, Copy, Default)]
pub struct Inputs<'a> {
    /// `$WAYFINDER_BUILD_VERSION` — a complete, already-formatted identity.
    pub injected_version: Option<&'a str>,
    /// `$WAYFINDER_BUILD_COMMIT` — the commit hash, when supplied separately.
    ///
    /// Needed because an injected `version` may be a bare tag (`v1.2.3`) with no
    /// hash in it at all, leaving the commit otherwise unrecoverable from a
    /// released build.
    pub injected_commit: Option<&'a str>,
    /// stdout of `git describe --tags --always --dirty --abbrev=7 --match 'v[0-9]*'`.
    pub describe: Option<&'a str>,
    /// stdout of `git rev-parse --short=7 HEAD`.
    pub commit: Option<&'a str>,
}

/// A resolved build identity, borrowed from the [`Inputs`] it came from.
///
/// Borrowed rather than owned so this crate needs neither `alloc` nor `std`:
/// every field is either a subslice of an input or a `&'static str` constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolved<'a> {
    /// The human-readable identity, and the one an operator reads first.
    ///
    /// A tagged commit reports its **tag** (`v0.4.0`) — the tag is the identity
    /// of a release, and the hash under it is an implementation detail. A
    /// commit past a tag reports the distance and hash `git describe` gives it
    /// (`v0.4.0-12-g35dcaee`), an untagged tree reports the bare short hash
    /// (`35dcaee`), and a modified tree carries a `-dirty` suffix on any of
    /// those.
    pub version: &'a str,
    /// The short commit hash on its own, for a consumer that wants to look the
    /// build up rather than display it. [`UNKNOWN`] when unavailable.
    pub commit: &'a str,
    /// Whether the tree had uncommitted changes to tracked files.
    ///
    /// Untracked files do not count, matching `git describe --dirty`. This is
    /// the field most worth branching on during bench bring-up, because most
    /// bench flashes are from a modified tree.
    pub dirty: bool,
    /// How much to trust the above.
    pub source: BuildSource,
}

/// What a build reports when it cannot determine its own identity.
pub const UNKNOWN: &str = "unknown";

/// The exact argument vector `build.rs` passes to `git describe`.
///
/// Kept here, beside the rules that interpret its output, so the two cannot
/// drift — and so the `--match` filter is covered by a test. That filter is
/// load-bearing rather than cosmetic: without it `describe` will happily report
/// *any* nearby tag as the node's version, and this repo already carries a
/// `backup/pre-rebase-expired-invite` tag that would qualify.
pub const DESCRIBE_ARGS: &[&str] = &[
    "describe",
    "--tags",
    "--always",
    "--dirty",
    "--abbrev=7",
    "--match",
    "v[0-9]*",
];

/// The argument vector `build.rs` passes to `git rev-parse` for the hash.
pub const REV_PARSE_ARGS: &[&str] = &["rev-parse", "--short=7", "HEAD"];

/// Git paths whose change must make cargo rerun the build script.
///
/// Resolved through `git rev-parse --git-path` at build time, so each works in a
/// worktree (where `.git` is a file) and under a separate `GIT_DIR`.
///
/// `refs/tags` is the one that is easy to leave out and expensive to omit:
/// creating or moving a tag touches none of the others — not `HEAD`, not the
/// branch ref, not the index — so without it, tagging a release leaves every
/// already-built binary still reporting its pre-tag version. That is the single
/// case tag support exists for, and it is silent when broken, which is why it is
/// pinned by a test rather than left to the build script.
pub const WATCHED_GIT_PATHS: &[&str] = &[
    // The commit, when HEAD is detached or moves between branches.
    "HEAD",
    // Refreshed by `git status`/`git add`; the best available signal for the
    // dirty marker. See `build.rs` for why it is imperfect.
    "index",
    // A commit on the current branch moves the loose ref, not `HEAD` itself.
    // (The specific ref is resolved separately; this covers the pack.)
    "packed-refs",
    // Every tag, which decides the whole reported version.
    "refs/tags",
];

/// The suffix `git describe --dirty` appends to a modified tree's description.
const DIRTY_SUFFIX: &str = "-dirty";

/// Decide what this build should report about itself.
///
/// Resolution is a strict three-tier fallthrough, and the order is the point:
///
/// 1. **Injected** — an environment that knows the answer exactly overrides
///    everything. This is the only tier that can fire under `nix build` or in
///    the container build, where `git` metadata is unavailable by construction.
/// 2. **Git** — ask the tree. The normal developer path.
/// 3. **Unknown** — report that, rather than failing the build. A source
///    archive with no git metadata must still compile.
///
/// Blank and whitespace-only inputs are treated as absent throughout, because
/// that is what a set-but-empty variable and a failed `git` invocation both
/// look like.
pub fn resolve<'a>(inputs: Inputs<'a>) -> Resolved<'a> {
    // Each tier answers with its *own* facts only. Pairing an injected version
    // with this checkout's `rev-parse` hash (or vice versa) would report a
    // build that never existed.
    if let Some(version) = present(inputs.injected_version) {
        return Resolved {
            version,
            commit: present(inputs.injected_commit).unwrap_or(UNKNOWN),
            // Read off the string rather than taken as a separate marker. The
            // two environments that inject — a Nix flake, which formats a
            // modified tree as `<rev>-dirty`, and CI, which only ever builds a
            // clean checkout — both encode it there already, so a third
            // injectable variable would be a knob with no setter and one more
            // way for the answer to contradict itself.
            dirty: has_dirty_suffix(version),
            source: BuildSource::Injected,
        };
    }

    if let Some(version) = present(inputs.describe) {
        return Resolved {
            version,
            commit: present(inputs.commit).unwrap_or(UNKNOWN),
            dirty: has_dirty_suffix(version),
            source: BuildSource::Git,
        };
    }

    Resolved {
        version: UNKNOWN,
        commit: UNKNOWN,
        dirty: false,
        source: BuildSource::Unknown,
    }
}

/// Trim an input and discard it if it is empty or unusable.
///
/// `git` stdout arrives with a trailing newline, and an environment variable
/// that is set but blank arrives as `""` — a set-but-empty variable means "no
/// answer", not "the empty version".
///
/// A value containing a **control character is rejected outright**, and that is
/// a safety property rather than tidiness. The build script prints these values
/// into `cargo::` directive lines, which are newline-delimited, so an interior
/// newline lets the value's second line *become a directive* — smuggling in a
/// `cargo::rustc-cfg` (silently changing what the binary reports) or an
/// unrecognised key (which aborts the build outright, breaking the promise that
/// this can never fail a build). Both were reproduced before this guard existed.
///
/// Rejecting rather than stripping is deliberate: a version string with a
/// newline in it is not a version string, and quietly using half of it would
/// report a build identity nobody chose.
fn present(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim)
        .filter(|s| !s.is_empty())
        .filter(|s| !s.chars().any(char::is_control))
}

/// Whether a raw input was discarded as unusable rather than simply absent.
///
/// Lets the build script warn about a variable it was handed and refused,
/// instead of silently falling through to the next tier — a misassembled CI
/// variable should say so, not quietly mislabel the build.
pub fn rejected(raw: Option<&str>) -> bool {
    matches!(raw, Some(value) if !value.trim().is_empty() && present(raw).is_none())
}

/// Whether a version string carries `git describe`'s modified-tree marker.
///
/// A suffix test, not a substring test: a tag may legitimately contain the word
/// (`v0.4.0-dirty-release`) without the tree being modified.
fn has_dirty_suffix(version: &str) -> bool {
    version.ends_with(DIRTY_SUFFIX)
}

/// Parse a [`BuildSource`] back from the name `build.rs` emitted for it.
///
/// The build script and the library agree on these three spellings, and this is
/// the only place that agreement is expressed. A `const fn` so `SOURCE` stays a
/// compile-time constant with nothing parsed at runtime.
///
/// An unrecognised name resolves to [`BuildSource::Unknown`] — the honest answer
/// for "the build could not tell us", which is what a broken handshake amounts
/// to. Pinned by `every_source_round_trips_through_its_name`, because this
/// replaced a `cfg!`-value handshake where the same mistake was *completely*
/// silent: rustc's `--check-cfg` does not diagnose an undeclared cfg **value**.
pub const fn source_from_name(name: &str) -> BuildSource {
    // `match` on a `&str` is not permitted in a `const fn`; bytes are.
    match name.as_bytes() {
        b"git" => BuildSource::Git,
        b"injected" => BuildSource::Injected,
        _ => BuildSource::Unknown,
    }
}

/// The name `build.rs` emits for a [`BuildSource`], and [`source_from_name`]
/// reads back.
pub const fn source_name(source: BuildSource) -> &'static str {
    match source {
        BuildSource::Git => "git",
        BuildSource::Injected => "injected",
        BuildSource::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The common case for a developer's tree: untagged, so `describe --always`
    /// falls back to the bare hash.
    fn from_git<'a>(describe: &'a str, commit: &'a str) -> Inputs<'a> {
        Inputs {
            describe: Some(describe),
            commit: Some(commit),
            ..Inputs::default()
        }
    }

    #[test]
    fn a_tagged_build_reports_the_tag_not_the_hash() {
        let r = resolve(from_git("v0.4.0\n", "35dcaee\n"));

        assert_eq!(r.version, "v0.4.0");
        assert_eq!(r.commit, "35dcaee");
        assert!(!r.dirty);
        assert_eq!(r.source, BuildSource::Git);
    }

    #[test]
    fn a_build_past_a_tag_keeps_the_distance_and_hash() {
        let r = resolve(from_git("v0.4.0-12-g35dcaee\n", "35dcaee\n"));

        assert_eq!(r.version, "v0.4.0-12-g35dcaee");
        assert!(!r.dirty);
        assert_eq!(r.source, BuildSource::Git);
    }

    #[test]
    fn an_untagged_build_reports_the_bare_short_hash() {
        let r = resolve(from_git("35dcaee\n", "35dcaee\n"));

        assert_eq!(r.version, "35dcaee");
        assert_eq!(r.commit, "35dcaee");
        assert!(!r.dirty);
    }

    #[test]
    fn a_modified_tagged_tree_is_marked_dirty_and_keeps_the_suffix() {
        let r = resolve(from_git("v0.4.0-dirty\n", "35dcaee\n"));

        // The suffix stays in the displayed version — an operator reading one
        // string should not have to consult a second field to notice.
        assert_eq!(r.version, "v0.4.0-dirty");
        assert!(r.dirty);
    }

    #[test]
    fn a_modified_untagged_tree_is_marked_dirty() {
        let r = resolve(from_git("35dcaee-dirty\n", "35dcaee\n"));

        assert_eq!(r.version, "35dcaee-dirty");
        assert!(r.dirty);
    }

    #[test]
    fn dirty_is_a_suffix_not_a_substring() {
        // A tag that happens to contain the word must not read as a modified
        // tree; only a trailing `-dirty` counts.
        let r = resolve(from_git("v0.4.0-dirty-release-2-g35dcaee", "35dcaee"));

        assert!(!r.dirty);
    }

    #[test]
    fn an_injected_version_wins_over_git() {
        let r = resolve(Inputs {
            injected_version: Some("v1.2.3"),
            injected_commit: Some("abcdef1"),
            describe: Some("35dcaee-dirty"),
            commit: Some("35dcaee"),
        });

        assert_eq!(r.version, "v1.2.3");
        assert_eq!(r.commit, "abcdef1");
        assert!(!r.dirty);
        assert_eq!(r.source, BuildSource::Injected);
    }

    /// The injected combination that actually ships: a Nix flake formats a
    /// modified tree as `<rev>-dirty` and injects only that one string, so the
    /// dirty marker has to be read off it.
    #[test]
    fn an_injected_version_carries_its_own_dirty_marker() {
        let r = resolve(Inputs {
            injected_version: Some("35dcaee-dirty"),
            ..Inputs::default()
        });

        assert!(r.dirty);
        assert_eq!(r.source, BuildSource::Injected);
    }

    #[test]
    fn an_injected_version_without_a_commit_reports_an_unknown_commit() {
        let r = resolve(Inputs {
            injected_version: Some("v1.2.3"),
            ..Inputs::default()
        });

        assert_eq!(r.version, "v1.2.3");
        assert_eq!(r.commit, UNKNOWN);
        assert_eq!(r.source, BuildSource::Injected);
    }

    #[test]
    fn no_git_and_no_injection_is_unknown_rather_than_a_build_failure() {
        let r = resolve(Inputs::default());

        assert_eq!(r.version, UNKNOWN);
        assert_eq!(r.commit, UNKNOWN);
        assert!(!r.dirty);
        assert_eq!(r.source, BuildSource::Unknown);
    }

    #[test]
    fn blank_inputs_are_treated_as_absent() {
        // What a set-but-empty variable and a failed `git` both look like.
        let r = resolve(Inputs {
            injected_version: Some("  "),
            injected_commit: Some(""),
            describe: Some("\n"),
            commit: Some(""),
        });

        assert_eq!(r.version, UNKNOWN);
        assert_eq!(r.source, BuildSource::Unknown);
    }

    #[test]
    fn a_describe_without_a_rev_parse_still_reports_a_version() {
        let r = resolve(Inputs {
            describe: Some("v0.4.0"),
            ..Inputs::default()
        });

        assert_eq!(r.version, "v0.4.0");
        assert_eq!(r.commit, UNKNOWN);
        assert_eq!(r.source, BuildSource::Git);
    }

    #[test]
    fn describe_is_filtered_to_release_tags() {
        // Without `--match`, this repo's `backup/pre-rebase-expired-invite`
        // tag would be a candidate version for every node built from `main`.
        let matched = DESCRIBE_ARGS
            .windows(2)
            .find(|w| w[0] == "--match")
            .expect("describe must filter tags");

        assert_eq!(matched[1], "v[0-9]*");
        assert!(DESCRIBE_ARGS.contains(&"--dirty"));
        assert!(DESCRIBE_ARGS.contains(&"--always"));
    }

    /// Pins the *contents* of the watch list, not the rerun mechanism — cargo's
    /// rerun behaviour cannot be observed from inside a unit test, so this
    /// cannot prove a rebuild happens. What it does prevent is the historical
    /// bug's cause: `refs/tags` going missing from the list. A tag decides the
    /// entire reported version and creating one touches no other watched path,
    /// so its omission made tagging a release change nothing about what any
    /// binary reported — found only by moving a tag against real hardware.
    #[test]
    fn the_watch_list_covers_tags_the_commit_and_the_dirty_marker() {
        assert!(
            WATCHED_GIT_PATHS.contains(&"refs/tags"),
            "without refs/tags, tagging a release does not change what a build reports"
        );
        assert!(WATCHED_GIT_PATHS.contains(&"HEAD"));
        assert!(WATCHED_GIT_PATHS.contains(&"index"));
    }

    /// A value carrying a newline would otherwise have its second line printed
    /// as a `cargo::` directive by the build script. Reproduced before the
    /// guard existed: `WAYFINDER_BUILD_VERSION="v1.2\ncargo::rustc-cfg=..."`
    /// smuggled a cfg through, and an unrecognised key aborted the build.
    #[test]
    fn a_value_containing_a_control_character_is_refused() {
        let smuggled = "v1.2\ncargo::rustc-cfg=wayfinder_build_dirty";

        let r = resolve(Inputs {
            injected_version: Some(smuggled),
            ..Inputs::default()
        });

        assert_eq!(r.version, UNKNOWN, "a directive must not become a version");
        assert!(!r.dirty);
        assert_eq!(r.source, BuildSource::Unknown);
        assert!(rejected(Some(smuggled)), "and the caller can warn about it");
    }

    #[test]
    fn a_merely_absent_value_is_not_reported_as_rejected() {
        assert!(!rejected(None));
        assert!(!rejected(Some("   ")));
        assert!(!rejected(Some("v1.2.3")));
    }

    /// The build script emits a source by name and the library parses it back.
    /// That handshake replaced a `cfg!`-value one in which a misspelling was
    /// entirely silent — rustc does not diagnose an undeclared cfg *value* —
    /// and would have made every release build report `Unknown`.
    #[test]
    fn every_source_round_trips_through_its_name() {
        for source in [
            BuildSource::Git,
            BuildSource::Injected,
            BuildSource::Unknown,
        ] {
            assert_eq!(source_from_name(source_name(source)), source);
        }

        assert_eq!(source_from_name("typo"), BuildSource::Unknown);
    }
}
