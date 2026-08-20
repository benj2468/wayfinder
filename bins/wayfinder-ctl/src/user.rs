//! Offline administration of a certificate authority's user accounts.
//!
//! Operates directly on the provider's state file, the way `cert init-ca`
//! operates directly on the root seed, and for the same reason: **the first
//! account cannot be created over the management API, because creating it needs
//! the credential it creates.** Breaking that loop is what an offline tool is
//! for.
//!
//! It stays the tool for the rest of the account lifecycle too, rather than
//! growing a matching set of management-API requests. A user store is the mesh's
//! root of administrative trust — every account in it can mint a certificate the
//! whole mesh honours — so keeping its mutation on the provider host, behind
//! whatever guards that host's shell already has, is one fewer remotely
//! reachable surface than the alternative buys anything for.
//!
//! Requires the provider to be **stopped**, or at least not writing: this
//! rewrites the same snapshot `CertAuthority` owns, and the durable-store
//! contract is about torn reads, not about two writers.

use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::bail;
use clap::Subcommand;
use wayfinder_server::CertAuthority;
use wayfinder_server::DEFAULT_SESSION_TTL_SECS;
use wayfinder_server::UserRecord;
use wayfinder_server::UserRole;

/// Account administration on a provider's state file.
#[derive(Subcommand, Debug)]
pub enum UserCommand {
    /// Create an account and print its TOTP enrolment URI.
    Add {
        /// The provider's state file (`provider.state_path` in its config).
        #[arg(long)]
        state: PathBuf,
        /// The account name, as presented at login.
        #[arg(long)]
        username: String,
        /// Grant the management-administration capability to the certificates
        /// this account is issued.  Without it the account is a viewer: it may
        /// read the management API and change nothing.
        #[arg(long)]
        admin: bool,
        /// Validity window for this account's session certificates, in seconds.
        ///
        /// The lifetime belongs to the admin granting the account, not to the
        /// code: an automation account may be worth minutes and a field
        /// operator a shift.  Bounded by the provider's own certificate cap.
        #[arg(long, default_value_t = DEFAULT_SESSION_TTL_SECS)]
        session_ttl: u64,
        /// Create the account with **no** second factor.
        ///
        /// Any account here can mint a certificate the whole mesh honours, so a
        /// password alone makes fleet-wide administrative access a phishable
        /// secret.  This exists for an automation account that cannot present a
        /// code — which should generally hold a long-lived certificate issued
        /// offline (`cert issue`) rather than log in at all.
        #[arg(long)]
        no_totp: bool,
        /// Read the password from standard input instead of prompting, taking
        /// the first line and no confirmation.
        ///
        /// The prompt reads `/dev/tty`, not stdin, so a script that pipes a
        /// password does not supply one — it blocks on whatever terminal the
        /// process inherited.  This is the flag for a caller that has no
        /// terminal at all (`scripts/topology.py`, an installer, a
        /// configuration-management run), and the reason the password is not
        /// simply an argument: argv is readable by every process on the host.
        #[arg(long)]
        password_stdin: bool,
    },

    /// List the accounts on file (never their hashes or TOTP secrets).
    List {
        /// The provider's state file.
        #[arg(long)]
        state: PathBuf,
    },

    /// Change an account's password, clearing any lockout.
    Passwd {
        /// The provider's state file.
        #[arg(long)]
        state: PathBuf,
        /// The account to change.
        #[arg(long)]
        username: String,
        /// Read the new password from standard input instead of prompting.
        /// See `add --password-stdin`.
        #[arg(long)]
        password_stdin: bool,
    },

    /// Disable an account: it can obtain no new sessions.
    ///
    /// A certificate already issued is unaffected — that is what `revoke` and
    /// expiry are for — so this ends future logins, not a session in flight.
    Disable {
        /// The provider's state file.
        #[arg(long)]
        state: PathBuf,
        /// The account to disable.
        #[arg(long)]
        username: String,
    },

    /// Re-enable a disabled account, clearing any lockout with it.
    Enable {
        /// The provider's state file.
        #[arg(long)]
        state: PathBuf,
        /// The account to enable.
        #[arg(long)]
        username: String,
    },

    /// Remove an account entirely.
    Remove {
        /// The provider's state file.
        #[arg(long)]
        state: PathBuf,
        /// The account to remove.
        #[arg(long)]
        username: String,
    },
}

/// Run an offline `user` subcommand.
pub fn run(cmd: UserCommand) -> anyhow::Result<()> {
    match cmd {
        UserCommand::Add {
            state,
            username,
            admin,
            session_ttl,
            no_totp,
            password_stdin,
        } => add(
            &state,
            &username,
            admin,
            session_ttl,
            no_totp,
            password_stdin,
        ),
        UserCommand::List { state } => list(&state),
        UserCommand::Passwd {
            state,
            username,
            password_stdin,
        } => passwd(&state, &username, password_stdin),
        UserCommand::Disable { state, username } => set_disabled(&state, &username, true),
        UserCommand::Enable { state, username } => set_disabled(&state, &username, false),
        UserCommand::Remove { state, username } => remove(&state, &username),
    }
}

/// Open the authority backing `state`, for a command that only touches the user
/// store.
///
/// The mesh id and root seed are irrelevant here — nothing this module does
/// signs anything — so a placeholder root is used rather than requiring the
/// operator to hand the mesh root key to a command that has no use for it. The
/// state file's other sections round-trip untouched: `CaLog` loads and rewrites
/// the whole snapshot, so the issued log, held CSRs and policy overrides come
/// back exactly as they went in.
fn open(state: &Path) -> anyhow::Result<CertAuthority> {
    let cfg = wayfinder::config::ProviderConfig {
        root_seed_path: String::new(),
        mesh_id: 0,
        cert_ttl_secs: DEFAULT_SESSION_TTL_SECS,
        enrollment_token: None,
        auto_approve: false,
        allow_unbounded_cert_ttl: false,
        pending_ttl_secs: 3600,
        state_path: Some(state.display().to_string()),
    };
    CertAuthority::from_config(&[0u8; 32], &cfg)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("opening CA state at {}", state.display()))
}

/// Obtain a new password, either from stdin or by prompting twice.
fn new_password(from_stdin: bool) -> anyhow::Result<String> {
    if from_stdin {
        return read_password_line(&mut std::io::stdin().lock());
    }
    prompt_new_password()
}

/// Take a password from the first line of `reader`.
///
/// One line, with its trailing newline removed and nothing else trimmed: a
/// leading or trailing space is a legitimate part of a password, and silently
/// stripping one would produce an account whose password is not the one the
/// caller piped — a failure that only shows up at the first login, with nothing
/// to point at.  There is no confirmation, because a piped password cannot be
/// mistyped twice differently and a second read would simply block.
fn read_password_line(reader: &mut impl std::io::BufRead) -> anyhow::Result<String> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("reading the password from stdin")?;
    let password = line.strip_suffix('\n').unwrap_or(&line);
    let password = password.strip_suffix('\r').unwrap_or(password);
    if password.is_empty() {
        bail!("password must not be empty");
    }
    Ok(password.to_string())
}

/// Prompt twice for a new password on a terminal that does not echo it, and
/// refuse an empty one.
///
/// Twice because a mistyped password here is not recoverable by the person who
/// typed it: they cannot see what they entered, and the next thing they learn
/// is that logging in does not work.
fn prompt_new_password() -> anyhow::Result<String> {
    let first = rpassword::prompt_password("New password: ").context("reading password")?;
    if first.is_empty() {
        bail!("password must not be empty");
    }
    let second = rpassword::prompt_password("Repeat password: ").context("reading password")?;
    if first != second {
        bail!("passwords did not match");
    }
    Ok(first)
}

/// Create an account.
fn add(
    state: &Path,
    username: &str,
    admin: bool,
    session_ttl: u64,
    no_totp: bool,
    password_stdin: bool,
) -> anyhow::Result<()> {
    let mut ca = open(state)?;
    let password = new_password(password_stdin)?;
    let role = if admin {
        UserRole::Admin
    } else {
        UserRole::Viewer
    };
    let mut user =
        UserRecord::new(username, &password, role, session_ttl).map_err(anyhow::Error::msg)?;
    if no_totp {
        user = user.without_totp();
    }
    // Read the URI out before the record moves into the store: it is shown
    // once, here, and the secret is never printed again.
    let uri = user.totp_enrolment_uri("wayfinder");
    ca.add_user(user).map_err(anyhow::Error::msg)?;

    println!("created user {username}");
    println!("  role:        {}", role_label(role));
    println!("  session ttl: {session_ttl}s");
    match uri {
        Some(uri) => {
            println!("  enrol this in an authenticator app now — it is not shown again:");
            println!("    {uri}");
        }
        None => println!(
            "  second factor: none. This account's password is the whole credential; \
             prefer an offline `cert issue --admin` certificate for automation."
        ),
    }
    Ok(())
}

/// Print the accounts on file.
fn list(state: &Path) -> anyhow::Result<()> {
    let ca = open(state)?;
    let users = ca.list_users();
    if users.is_empty() {
        println!("no users");
        return Ok(());
    }
    println!("USERNAME             ROLE     SESSION_TTL  TOTP  STATUS");
    for u in users {
        let status = match (u.disabled, u.locked) {
            (true, _) => "disabled",
            (_, true) => "locked",
            _ => "active",
        };
        println!(
            "{:<20} {:<8} {:>10}s  {:<4}  {}",
            u.username,
            role_label(u.role),
            u.session_ttl_secs,
            if u.totp_enrolled { "yes" } else { "no" },
            status,
        );
    }
    Ok(())
}

/// Change an account's password.
fn passwd(state: &Path, username: &str, password_stdin: bool) -> anyhow::Result<()> {
    let mut ca = open(state)?;
    let password = new_password(password_stdin)?;
    let mut failed = None;
    ca.update_user(username, |user| {
        // `set_password` can fail (Argon2 parameters), and `update_user`'s
        // callback returns nothing, so the failure is carried out rather than
        // swallowed — a "changed" password that did not change is the worst
        // possible outcome here.
        if let Err(e) = user.set_password(&password) {
            failed = Some(e);
        }
    })
    .map_err(anyhow::Error::msg)?;
    if let Some(e) = failed {
        bail!("{e}");
    }
    println!("changed password for {username} (any lockout cleared)");
    Ok(())
}

/// Disable or re-enable an account.
fn set_disabled(state: &Path, username: &str, disabled: bool) -> anyhow::Result<()> {
    let mut ca = open(state)?;
    ca.update_user(username, |user| {
        user.disabled = disabled;
        if !disabled {
            // Re-enabling clears the lockout too: an operator turning an
            // account back on means it should work, not that it should work in
            // fifteen minutes.
            user.failed_attempts = 0;
            user.locked_until = 0;
        }
    })
    .map_err(anyhow::Error::msg)?;
    if disabled {
        println!(
            "disabled {username}; existing certificates are unaffected — revoke them if the account is compromised"
        );
    } else {
        println!("enabled {username}");
    }
    Ok(())
}

/// Remove an account.
fn remove(state: &Path, username: &str) -> anyhow::Result<()> {
    let mut ca = open(state)?;
    ca.remove_user(username).map_err(anyhow::Error::msg)?;
    println!(
        "removed {username}; existing certificates are unaffected — revoke them if the account is compromised"
    );
    Ok(())
}

/// The word for a role in operator-facing output.
fn role_label(role: UserRole) -> &'static str {
    match role {
        UserRole::Admin => "admin",
        UserRole::Viewer => "viewer",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A piped password is the line as typed, minus its line ending: the
    /// newline `echo` adds is not part of the password, and a space at either
    /// end is.
    #[test]
    fn a_piped_password_keeps_everything_but_its_line_ending() {
        let read =
            |bytes: &str| read_password_line(&mut bytes.as_bytes()).map_err(|e| e.to_string());

        assert_eq!(read("hunter2\n").unwrap(), "hunter2");
        assert_eq!(read("hunter2\r\n").unwrap(), "hunter2");
        assert_eq!(read("hunter2").unwrap(), "hunter2", "no trailing newline");
        assert_eq!(
            read(" pass phrase \n").unwrap(),
            " pass phrase ",
            "spaces are part of a password, not padding"
        );
        assert_eq!(
            read("first\nsecond\n").unwrap(),
            "first",
            "only the first line is the password"
        );

        // An empty line is refused rather than creating an account whose
        // password is the empty string.
        assert!(read("\n").is_err());
        assert!(read("").is_err());
    }
}
