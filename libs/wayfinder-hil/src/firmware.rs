//! Building test-only firmware from inside a test.
//!
//! For the rare test whose subject needs an image no operator flashes by hand
//! (`tests/reyax_interop.rs`'s echo firmware), and whose build depends on the
//! inventory — the radio's frequency is a build-time input, because which band
//! is licence-free depends on where the rig is. A recipe could not know that
//! value without parsing the inventory itself.
//!
//! The board crates are each their own Cargo workspace with their own target,
//! so this shells out to `cargo` in that directory, exactly as a human would.
//! It needs the devShell's embedded toolchain, which `just hil` runs inside.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

/// Build `example` in the board crate at `crate_dir` (relative to the
/// repository root) in release mode, with `env` set for the build, and return
/// the path of the ELF it produced.
///
/// The path comes from cargo's own `--message-format=json` report rather than
/// being assembled from a target triple and a `target/` layout, which
/// `CARGO_TARGET_DIR` and a board's `.cargo/config.toml` can each move.
pub fn build_example(
    crate_dir: &str,
    example: &str,
    env: &[(&str, &str)],
) -> anyhow::Result<PathBuf> {
    let dir = repo_root().join(crate_dir);
    let mut command = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    command
        .current_dir(&dir)
        .args(["build", "--release", "--locked", "--example", example])
        .arg("--message-format=json-render-diagnostics")
        .envs(env.iter().copied())
        .stderr(Stdio::inherit());
    let rendered = format!("{command:?} in {}", dir.display());
    let output = command
        .output()
        .map_err(|e| anyhow::anyhow!("running {rendered}: {e}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "{rendered} exited {} (its diagnostics are above)",
            output.status
        );
    }
    executable_of(&String::from_utf8_lossy(&output.stdout), example).ok_or_else(|| {
        anyhow::anyhow!("{rendered} succeeded but reported no executable for {example:?}")
    })
}

/// The repository root, from this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The `executable` cargo reported for the example named `example`, from its
/// JSON message stream.
fn executable_of(stdout: &str, example: &str) -> Option<PathBuf> {
    stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|msg| msg["reason"] == "compiler-artifact")
        .filter(|msg| msg["target"]["name"] == example)
        .filter(|msg| {
            msg["target"]["kind"]
                .as_array()
                .is_some_and(|kinds| kinds.iter().any(|k| k == "example"))
        })
        .find_map(|msg| msg["executable"].as_str().map(PathBuf::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trimmed from a real `cargo build --example … --message-format=json`: a
    /// dependency's artifact, then the example's, then the build summary.
    const MESSAGES: &str = r#"{"reason":"compiler-artifact","target":{"kind":["lib"],"name":"rylr998"},"executable":null}
{"reason":"compiler-artifact","target":{"kind":["example"],"name":"hil_reyax_echo"},"executable":"/w/target/thumbv7em-none-eabi/release/examples/hil_reyax_echo"}
{"reason":"build-finished","success":true}"#;

    #[test]
    fn finds_the_examples_executable() {
        assert_eq!(
            executable_of(MESSAGES, "hil_reyax_echo"),
            Some(PathBuf::from(
                "/w/target/thumbv7em-none-eabi/release/examples/hil_reyax_echo"
            ))
        );
    }

    /// A same-named library is not the example, and an absent example is
    /// `None` rather than whichever artifact came last.
    #[test]
    fn matches_only_an_example_of_that_name() {
        assert_eq!(executable_of(MESSAGES, "rylr998"), None);
        assert_eq!(executable_of(MESSAGES, "other"), None);
        assert_eq!(executable_of("not json\n", "hil_reyax_echo"), None);
    }
}
