//! Collect this build's identity and bake it into the crate.
//!
//! A thin collector by design: it gathers environment variables and the stdout
//! of two `git` invocations, hands them to [`resolve`] — the pure, unit-tested
//! rules, `include!`d below so the script and the library cannot drift — and
//! emits the answer as `rustc-env` values for `src/lib.rs` to read.
//!
//! **This script must never fail a build.** A source archive with no git
//! metadata, a `nix build` sandbox (no `.git` in the store source, no network),
//! and a container build whose `Dockerfile` never copies `.git` are all normal.
//! Each one simply resolves to `BuildSource::Unknown` unless the environment
//! injected an answer.

use std::process::Command;

/// The library's resolution rules, compiled into the build script itself.
///
/// A module purely for namespacing — `use resolve::Inputs` reads better than
/// having the file's items land at the script's top level. It is not what makes
/// the `include!` legal: an included file cannot carry a `//!` header at either
/// position, which is why `src/resolve.rs` opens with plain `//` comments.
// The script needs the rules and the arg vectors, not the whole surface — the
// library is the consumer of the rest (e.g. `source_from_name`, which turns the
// name emitted below back into an enum in const context).
#[allow(dead_code)]
mod resolve {
    include!("src/resolve.rs");
}

use resolve::DESCRIBE_ARGS;
use resolve::Inputs;
use resolve::REV_PARSE_ARGS;
use resolve::WATCHED_GIT_PATHS;
use resolve::rejected;
use resolve::resolve;
use resolve::source_name;

/// The environment variable carrying a complete, pre-formatted identity.
const ENV_VERSION: &str = "WAYFINDER_BUILD_VERSION";
/// The environment variable carrying the commit hash on its own.
const ENV_COMMIT: &str = "WAYFINDER_BUILD_COMMIT";

fn main() {
    // Injection is the tier that fires where git is unavailable, so its
    // variables have to be able to *retrigger* this script. Without these, a
    // changed injected version would be baked in once and then cached forever.
    for var in [ENV_VERSION, ENV_COMMIT] {
        println!("cargo::rerun-if-env-changed={var}");
    }

    // Read at *compile* time, so there is no fallible lookup to handle: cargo
    // sets this when it builds the script as well as when it runs it. A runtime
    // `env::var(...).unwrap_or_default()` would hand `git` an empty `-C` and
    // happen to work, which is not the same as being correct.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");

    let describe = git(manifest_dir, DESCRIBE_ARGS);
    let commit = git(manifest_dir, REV_PARSE_ARGS);

    let injected_version = std::env::var(ENV_VERSION).ok();
    let injected_commit = std::env::var(ENV_COMMIT).ok();

    // A value handed to us and then refused is a misconfiguration, not an
    // absence — say so rather than quietly mislabelling the build.
    for (var, value) in [
        (ENV_VERSION, injected_version.as_deref()),
        (ENV_COMMIT, injected_commit.as_deref()),
    ] {
        if rejected(value) {
            println!(
                "cargo::warning={var} contains a control character (a newline?); ignoring it. \
                 The build will report what git says, or \"unknown\"."
            );
        }
    }

    let resolved = resolve(Inputs {
        injected_version: injected_version.as_deref(),
        injected_commit: injected_commit.as_deref(),
        describe: describe.as_deref(),
        commit: commit.as_deref(),
    });

    watch_git_state(manifest_dir);

    // All four values cross into the library as `rustc-env` strings.
    //
    // `dirty` and `source` used to travel as `rustc-cfg` instead, which was a
    // silent-failure trap worth not reintroducing: rustc does **not** diagnose
    // an undeclared cfg *value* (only an undeclared name), so misspelling
    // "injected" in either this file or `lib.rs` would have made every release
    // build report `Unknown` with no warning and every test still green.
    // `resolve::source_from_name` now owns that handshake and is round-trip
    // tested.
    //
    // `present()` has already refused any value containing a control character,
    // so none of these can inject a second `cargo::` line.
    for (key, value) in [
        ("WAYFINDER_BUILD_VERSION_RESOLVED", resolved.version),
        ("WAYFINDER_BUILD_COMMIT_RESOLVED", resolved.commit),
        (
            "WAYFINDER_BUILD_DIRTY_RESOLVED",
            if resolved.dirty { "true" } else { "false" },
        ),
        (
            "WAYFINDER_BUILD_SOURCE_RESOLVED",
            source_name(resolved.source),
        ),
    ] {
        println!("cargo::rustc-env={key}={value}");
    }
}

/// Run `git` in the source tree and return its trimmed stdout, or `None`.
///
/// `None` covers every way this legitimately fails: no `git` on `PATH`, no
/// repository, a repository `git` refuses to read (a foreign owner, which is
/// the norm inside a container), or no matching tag. None of them is an error
/// here.
fn git(manifest_dir: &str, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        // `-C` rather than assuming a `.git` *directory* next to the manifest:
        // in a git worktree `.git` is a file pointing elsewhere, and that is
        // exactly where this repo's development happens.
        .arg("-C")
        .arg(manifest_dir)
        .args(args)
        .output()
        .ok()?;

    if !out.status.success() {
        // One failure has an exact remedy the operator cannot guess from
        // `version=unknown` alone — a repository git refuses to read because it
        // is owned by another user, which is the norm inside a container and is
        // fixed by `git config --global --add safe.directory <path>`. Surfacing
        // git's own words costs nothing and is never reached on a healthy build.
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("dubious ownership") {
            println!(
                "cargo::warning=git refused to read the repository: {}",
                stderr.trim()
            );
        }
        return None;
    }

    Some(String::from_utf8_lossy(&out.stdout).trim().to_string()).filter(|s| !s.is_empty())
}

/// Ask cargo to rerun this script when the tree's git state moves.
///
/// Paths come from `git rev-parse --git-path`, which resolves correctly in a
/// worktree (where `.git` is a file) and for a separate `GIT_DIR` — guessing
/// `.git/HEAD` would silently stop working in both.
///
/// **Known limitation, worth stating plainly:** cargo reruns on file
/// *modification*, so an edit to a tracked file that never touches the index
/// can leave the `dirty` marker one build stale, until anything refreshes the
/// index (`git status`, `git add`, a commit). `vergen` and `git-version` carry
/// the same caveat. It is why [`BuildSource`] is reported on the wire: an
/// `Injected` identity is exact by construction, a `Git` one is best-effort.
fn watch_git_state(manifest_dir: &str) {
    // `refs/tags` among these is a directory, which cargo walks recursively, so
    // a tag added, moved or deleted anywhere under it counts.
    for path in WATCHED_GIT_PATHS {
        if let Some(resolved) = git(manifest_dir, &["rev-parse", "--git-path", path]) {
            println!("cargo::rerun-if-changed={resolved}");
        }
    }

    // Resolved separately because it is not a fixed path: the ref HEAD points
    // at. A commit on the current branch moves this file while `HEAD` itself is
    // unchanged.
    //
    // Emitted only if the file exists, which matters more than it looks: after a
    // `git gc`/`pack-refs` — the normal state of a fresh clone — the branch ref
    // lives in `packed-refs` (watched above) and this path does not exist at
    // all. Cargo treats a missing dependency as stale, so naming it
    // unconditionally would rerun this script on *every* cargo invocation, and
    // since this crate sits beneath `wayfinder-protos` that is two `git`
    // processes on every build in the workspace.
    if let Some(head_ref) = git(manifest_dir, &["symbolic-ref", "--quiet", "HEAD"])
        && let Some(path) = git(manifest_dir, &["rev-parse", "--git-path", &head_ref])
        && std::path::Path::new(&path).exists()
    {
        println!("cargo::rerun-if-changed={path}");
    }
}
