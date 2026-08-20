//! The client's own credential store: a logged-in session, and the node keys
//! it has pinned.
//!
//! Two files under `~/.config/wayfinder/`, both solving the same complaint —
//! that reaching a node needed three flags (`--identity`, `--cert`,
//! `--node-key`) and a manual file copy before any of them existed.
//!
//! * `session/` holds the keypair a login generated and the certificate the
//!   provider returned for it, so every other subcommand finds a credential
//!   with no flags at all. `logout` deletes it.
//! * `known_nodes` records the Ed25519 key each address was first seen with.
//!   `Endpoint::load` defaults an unspecified `--node-key` to the *client's
//!   own* public key, which fails closed but means reaching any node other
//!   than during bootstrap costs 64 hex characters on the command line. The
//!   pin is recorded on first connect, behind a prompt showing the
//!   fingerprint, and a changed key is a loud failure rather than a silent
//!   re-pin.

use std::io::IsTerminal;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::bail;
use serde::Deserialize;
use serde::Serialize;

/// Permission bits every file this module writes is created with.
///
/// The session seed is a private key and the certificate names who holds it;
/// both are created narrowly rather than written and chmod'd afterwards, so
/// there is no instant at which they exist world-readable.
#[cfg(unix)]
const SECRET_FILE_MODE: u32 = 0o600;

/// What fraction of a session certificate's life must remain for the session to
/// be considered fresh.
///
/// A quarter: the client renews inside the last quarter of the window, which is
/// long enough that a renewal failure leaves time to notice and short enough
/// that a session is not renewed constantly. Expressed as a divisor so the rule
/// scales with whatever lifetime the granting admin chose, rather than being a
/// fixed number of minutes that means "always" for a short session and "never"
/// for a long one.
pub const RENEWAL_FRACTION: u64 = 4;

/// The metadata stored beside a session's keys: who logged in, where, and what
/// they were given.
///
/// Never the password, and never the TOTP secret — neither is stored anywhere
/// on the client. What is here is what `whoami` needs to answer "what am I
/// holding and when does it stop working?", which nothing could answer before.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionMeta {
    /// The account this session was issued to.
    pub username: String,
    /// The provider the login was performed against.
    pub provider: String,
    /// The provider's pinned Ed25519 key, hex, so a renewal reaches the same
    /// authority the session came from.
    pub provider_key: String,
    /// Unix seconds the certificate stops being valid.
    pub not_after: u64,
    /// Unix seconds the certificate started being valid, so the renewal window
    /// can be computed as a fraction of the whole.
    pub not_before: u64,
}

impl SessionMeta {
    /// Whether the session is inside the last [`RENEWAL_FRACTION`] of its life
    /// as of `now_unix`, and so should be refreshed.
    ///
    /// A session already past `not_after` is *not* "due renewal" — it is
    /// expired, and the difference matters because a renewal reuses nothing
    /// from an expired session: the operator logs in again.
    pub fn due_renewal(&self, now_unix: u64) -> bool {
        if now_unix >= self.not_after {
            return false;
        }
        let window = self.not_after.saturating_sub(self.not_before);
        let renew_from = self.not_after.saturating_sub(window / RENEWAL_FRACTION);
        now_unix >= renew_from
    }

    /// Whether the session has expired as of `now_unix`.
    pub fn expired(&self, now_unix: u64) -> bool {
        now_unix >= self.not_after
    }
}

/// A logged-in session as it exists on disk.
pub struct Session {
    /// The session keypair's 32-byte seed.
    pub seed: [u8; 32],
    /// The certificate the provider issued for it.
    pub cert: Vec<u8>,
    /// Who, where and until when.
    pub meta: SessionMeta,
}

/// The directory holding the session and the known-nodes file.
///
/// `$WAYFINDER_CONFIG_HOME` wins when set, so an operator can keep two meshes'
/// credentials apart without either overwriting the other.
///
/// Resolved once by the caller and then *passed* to everything in this module,
/// rather than being read inside each function. That is what lets the tests
/// point at a temporary directory without touching the process environment —
/// which is global, and so cannot be set per test without serializing the
/// whole suite.
pub fn config_dir() -> anyhow::Result<PathBuf> {
    if let Some(dir) = std::env::var_os("WAYFINDER_CONFIG_HOME") {
        return Ok(PathBuf::from(dir));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .context("neither WAYFINDER_CONFIG_HOME, XDG_CONFIG_HOME nor HOME is set")?;
    Ok(base.join("wayfinder"))
}

/// Where a session's three files live, under `config`.
fn session_dir(config: &Path) -> PathBuf {
    config.join("session")
}

/// Create `path` with [`SECRET_FILE_MODE`] and write `bytes` to it, replacing
/// whatever was there.
///
/// The mode is applied at creation, not afterwards: a file written first and
/// tightened second is world-readable for the interval between, and the
/// interval is exactly when the secret is on disk.
fn write_secret(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(SECRET_FILE_MODE);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Persist a freshly issued session, replacing any previous one.
pub fn store(
    config: &Path,
    seed: &[u8; 32],
    cert: &[u8],
    meta: &SessionMeta,
) -> anyhow::Result<()> {
    let dir = session_dir(config);
    write_secret(&dir.join("seed"), seed)?;
    write_secret(&dir.join("cert"), cert)?;
    let json = serde_json::to_vec_pretty(meta).context("serializing session metadata")?;
    write_secret(&dir.join("meta.json"), &json)?;
    Ok(())
}

/// Load the stored session, or `None` if there is none.
///
/// A session whose three files are not all present is treated as absent rather
/// than as an error: that is what a half-finished `logout` or an interrupted
/// `login` leaves behind, and the useful response to both is "log in".
pub fn load(config: &Path) -> anyhow::Result<Option<Session>> {
    let dir = session_dir(config);
    let (seed_path, cert_path, meta_path) =
        (dir.join("seed"), dir.join("cert"), dir.join("meta.json"));
    if !seed_path.exists() || !cert_path.exists() || !meta_path.exists() {
        return Ok(None);
    }
    let seed: [u8; 32] = std::fs::read(&seed_path)
        .with_context(|| format!("reading {}", seed_path.display()))?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("session seed at {} must be 32 bytes", seed_path.display()))?;
    let cert =
        std::fs::read(&cert_path).with_context(|| format!("reading {}", cert_path.display()))?;
    let meta: SessionMeta = serde_json::from_slice(
        &std::fs::read(&meta_path).with_context(|| format!("reading {}", meta_path.display()))?,
    )
    .with_context(|| format!("parsing {}", meta_path.display()))?;
    Ok(Some(Session { seed, cert, meta }))
}

/// Delete the stored session, reporting whether there was one.
pub fn clear(config: &Path) -> anyhow::Result<bool> {
    let dir = session_dir(config);
    let mut removed = false;
    for name in ["seed", "cert", "meta.json"] {
        let path = dir.join(name);
        if path.exists() {
            std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
            removed = true;
        }
    }
    Ok(removed)
}

/// The known-nodes pin file under `config`.
fn known_nodes_path(config: &Path) -> PathBuf {
    config.join("known_nodes")
}

/// The pinned key recorded for `addr`, if any.
pub fn pinned_key(config: &Path, addr: &str) -> anyhow::Result<Option<[u8; 32]>> {
    let path = known_nodes_path(config);
    if !path.exists() {
        return Ok(None);
    }
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(recorded), Some(hex)) = (parts.next(), parts.next()) else {
            continue;
        };
        if recorded == addr {
            return Ok(Some(wayfinder_client::parse_key32(hex).with_context(
                || format!("parsing the pinned key for {addr} in {}", path.display()),
            )?));
        }
    }
    Ok(None)
}

/// Record `key` as `addr`'s pin.
pub fn pin(config: &Path, addr: &str, key: &[u8; 32]) -> anyhow::Result<()> {
    let path = known_nodes_path(config);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut text = if path.exists() {
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?
    } else {
        String::from(
            "# wayfinder known nodes: one \"address hex-ed25519-key\" per line.\n\
             # A key that changes for a recorded address is refused, not re-pinned.\n",
        )
    };
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&format!("{addr} {}\n", hex(key)));
    std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Accept a key the *operator stated* for `addr`, recording it if nothing is
/// recorded yet.
///
/// No prompt, unlike [`resolve_pin`]. The prompt exists to make a human look at
/// a fingerprint learned from the network before trusting it; a fingerprint the
/// operator typed on the command line has already been stated out of band, and
/// asking them to confirm what they just said is a dialog that trains people to
/// press `y`. It is still checked against a recorded pin, and a mismatch is the
/// same refusal — an operator who states the wrong key must be told so, not
/// quietly re-pinned.
///
/// This is what makes a non-interactive login possible: `--node-key` is the
/// answer to the question [`resolve_pin`]'s prompt would have asked.
pub fn pin_stated(config: &Path, addr: &str, stated: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
    match pinned_key(config, addr)? {
        Some(recorded) if &recorded == stated => Ok(recorded),
        Some(recorded) => bail!(
            "the key given for {addr} is not the one recorded for it.\n  \
             recorded: {}\n  given:    {}\n\
             If the node was legitimately re-keyed, remove its line from {} and \
             connect again.",
            hex(&recorded),
            hex(stated),
            known_nodes_path(config).display(),
        ),
        None => {
            pin(config, addr, stated)?;
            Ok(*stated)
        }
    }
}

/// Resolve the key to pin for `addr`: the recorded one, or — after asking — the
/// one `offered` presents.
///
/// The prompt is the whole point. Trust-on-first-use without one is not
/// trust-on-first-use, it is no pinning at all with extra steps: the operator
/// has to see the fingerprint at least once to have any chance of noticing it
/// is the wrong node. A non-interactive caller is refused rather than
/// defaulted, since nobody is there to look.
///
/// A *changed* key is an error, always. It is what a man-in-the-middle looks
/// like, and it is also what a legitimately re-keyed node looks like — the
/// operator resolves which by editing `known_nodes`, which is a deliberate act
/// with the old value in front of them.
pub fn resolve_pin(config: &Path, addr: &str, offered: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
    match pinned_key(config, addr)? {
        Some(recorded) if &recorded == offered => Ok(recorded),
        Some(recorded) => bail!(
            "the key offered by {addr} is not the one recorded for it.\n  \
             recorded: {}\n  offered:  {}\n\
             This is what an impersonated node looks like. If the node was legitimately \
             re-keyed, remove its line from {} and connect again.",
            hex(&recorded),
            hex(offered),
            known_nodes_path(config).display(),
        ),
        None => {
            if !std::io::stdin().is_terminal() {
                bail!(
                    "no key is recorded for {addr} and there is no terminal to confirm one on. \
                     Pass --node-key {} if that fingerprint is the node you mean.",
                    hex(offered),
                );
            }
            println!("The node at {addr} is not yet known.");
            println!("  Ed25519 key: {}", hex(offered));
            print!("Record this key and continue? [y/N] ");
            std::io::stdout().flush().ok();
            let mut answer = String::new();
            std::io::stdin()
                .read_line(&mut answer)
                .context("reading confirmation")?;
            if !matches!(answer.trim(), "y" | "Y" | "yes") {
                bail!("not confirmed; nothing recorded");
            }
            pin(config, addr, offered)?;
            Ok(*offered)
        }
    }
}

/// Lower-case hex, for keys in files and prompts.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session round-trips: what `store` wrote is what `load` returns, and
    /// `clear` leaves nothing behind.
    #[test]
    fn a_session_round_trips_and_clears() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path();

        assert!(load(config).unwrap().is_none(), "no session to begin with");

        let meta = SessionMeta {
            username: "ops".into(),
            provider: "10.0.0.1:7700".into(),
            provider_key: "aa".repeat(32),
            not_before: 1000,
            not_after: 1000 + 28_800,
        };
        store(config, &[7u8; 32], b"cert-bytes", &meta).unwrap();

        let loaded = load(config).unwrap().expect("a session was stored");
        assert_eq!(loaded.seed, [7u8; 32]);
        assert_eq!(loaded.cert, b"cert-bytes");
        assert_eq!(loaded.meta.username, "ops");
        assert_eq!(loaded.meta.not_after, 1000 + 28_800);

        assert!(clear(config).unwrap(), "clear reports it removed something");
        assert!(load(config).unwrap().is_none());
        assert!(
            !clear(config).unwrap(),
            "and reports nothing the second time"
        );
    }

    /// The session's secrets are created `0600`, not written and tightened
    /// afterwards.
    #[cfg(unix)]
    #[test]
    fn session_files_are_created_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        store(
            dir.path(),
            &[7u8; 32],
            b"cert-bytes",
            &SessionMeta {
                username: "ops".into(),
                provider: "10.0.0.1:7700".into(),
                provider_key: "aa".repeat(32),
                not_before: 0,
                not_after: 1,
            },
        )
        .unwrap();

        for name in ["seed", "cert", "meta.json"] {
            let path = dir.path().join("session").join(name);
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, SECRET_FILE_MODE,
                "{name} must not be readable by others"
            );
        }
    }

    /// A recorded pin is returned; a *different* key for the same address is an
    /// error rather than a silent re-pin, which is the only behaviour that
    /// makes recording one worth anything.
    #[test]
    fn a_changed_node_key_is_refused_not_re_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path();

        pin(config, "10.0.0.1:7700", &[1u8; 32]).unwrap();
        assert_eq!(
            pinned_key(config, "10.0.0.1:7700").unwrap(),
            Some([1u8; 32])
        );
        assert_eq!(
            resolve_pin(config, "10.0.0.1:7700", &[1u8; 32]).unwrap(),
            [1u8; 32]
        );

        let err = resolve_pin(config, "10.0.0.1:7700", &[2u8; 32])
            .unwrap_err()
            .to_string();
        assert!(err.contains("not the one recorded"), "{err}");
        assert_eq!(
            pinned_key(config, "10.0.0.1:7700").unwrap(),
            Some([1u8; 32]),
            "the refusal must not have overwritten the pin"
        );

        // Pins are per address: another node is simply unknown.
        assert_eq!(pinned_key(config, "10.0.0.2:7700").unwrap(), None);
    }

    /// A key the operator states is recorded without a prompt, is idempotent,
    /// and still refuses to overwrite a different recorded one.
    ///
    /// The no-prompt half is what makes a non-interactive login possible at
    /// all: `resolve_pin` needs a terminal, and `login` used to reach for it
    /// even when `--node-key` had been given — so it refused with a message
    /// telling the operator to pass the very flag it was ignoring.
    #[test]
    fn a_stated_node_key_is_recorded_without_a_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path();

        assert_eq!(
            pin_stated(config, "10.0.0.1:7700", &[1u8; 32]).unwrap(),
            [1u8; 32],
            "an unknown address takes the stated key"
        );
        assert_eq!(
            pinned_key(config, "10.0.0.1:7700").unwrap(),
            Some([1u8; 32]),
            "and records it"
        );
        assert_eq!(
            pin_stated(config, "10.0.0.1:7700", &[1u8; 32]).unwrap(),
            [1u8; 32],
            "stating the same key again is a no-op, not a duplicate"
        );

        let err = pin_stated(config, "10.0.0.1:7700", &[2u8; 32])
            .unwrap_err()
            .to_string();
        assert!(err.contains("not the one recorded"), "{err}");
        assert_eq!(
            pinned_key(config, "10.0.0.1:7700").unwrap(),
            Some([1u8; 32]),
            "a mismatch must not re-pin"
        );
    }

    /// Renewal starts inside the last quarter of the window, is not triggered
    /// early, and an expired session is expired rather than "due renewal" —
    /// there is nothing left to renew from.
    #[test]
    fn renewal_starts_in_the_last_quarter_of_the_window() {
        let meta = SessionMeta {
            username: "ops".into(),
            provider: "10.0.0.1:7700".into(),
            provider_key: "aa".repeat(32),
            not_before: 0,
            not_after: 8000,
        };

        assert!(!meta.due_renewal(0));
        assert!(!meta.due_renewal(5_999));
        assert!(meta.due_renewal(6_000), "the last quarter begins at 6000");
        assert!(meta.due_renewal(7_999));

        assert!(!meta.due_renewal(8_000), "expired is not due renewal");
        assert!(meta.expired(8_000));
        assert!(!meta.expired(7_999));
    }
}
