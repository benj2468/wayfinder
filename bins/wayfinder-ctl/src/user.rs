//! Administration of a certificate authority's user accounts, over the
//! management API.
//!
//! **Every subcommand here is an RPC to a running provider.** None of them
//! opens the provider's state file, and that is the point: a provider holds the
//! whole CA snapshot in memory and rewrites it whole on every login, issuance
//! and revocation, so a second writer editing the file beside it does not merge
//! with those writes — it races them. Whichever writes last wins the *entire*
//! file, so an offline edit either vanishes at the provider's next write or
//! takes the provider's issued-certificate log back to whatever it was when the
//! file was read. The durable store's atomic rename does not help: it promises
//! a reader never sees a torn old/new mix, not that a stale writer is refused.
//! Neither outcome is visible to whoever ran the command, which is what made it
//! worth removing rather than documenting.
//!
//! # The bootstrap loop, and how it is broken
//!
//! The first account cannot be created *by an account*: creating one needs the
//! credential it creates. That loop is what an offline tool used to be for.
//!
//! It is broken from the other side instead. Whoever runs this is on the
//! provider host — that was always the requirement — and the host holds the
//! node's own identity seed. A client presenting that seed authenticates at the
//! self-key tier, which is admitted to every request, so:
//!
//! ```text
//! wayfinderctl user add --identity /var/lib/wayfinder/identity.seed \
//!     --username rowan --admin
//! ```
//!
//! creates the first administrator against the *running* provider. The same
//! credential is the way back from a mesh whose last administrator was removed:
//! it does not depend on any account existing.
//!
//! Nothing here needs the provider stopped, and nothing here can corrupt it.

use anyhow::Context;
use anyhow::bail;
use clap::Subcommand;
use wayfinder_client::Client;

/// The role named on the command line by `set-role`.
///
/// A stated role rather than an `--admin` flag, which is what `add` and
/// `invite` use: on those the absence of the flag means "create the account
/// that can do less", and creating is unambiguous. Here the absence of a flag
/// would have to mean *demote*, so an operator who forgot it would silently
/// take away an access instead of failing. Both directions are spelled.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoleArg {
    /// Session certificates carry the management-administration capability.
    Admin,
    /// Session certificates are read-only.
    Viewer,
}

impl RoleArg {
    /// Whether this role is the administrative one, as the wire spells it.
    fn is_admin(self) -> bool {
        matches!(self, RoleArg::Admin)
    }

    /// The word for this role in operator-facing output.
    fn label(self) -> &'static str {
        match self {
            RoleArg::Admin => "admin",
            RoleArg::Viewer => "viewer",
        }
    }
}

/// Account administration against a running provider.
#[derive(Subcommand, Debug)]
pub enum UserCommand {
    /// Create an account and print its TOTP enrolment URI.
    ///
    /// The URI is shown once, here. Prefer `invite` where the person the
    /// account is for can redeem it themselves: this command mints their second
    /// factor on *this* terminal, so it is permanently known to somebody other
    /// than its owner.
    Add {
        /// The account name, as presented at login.
        #[arg(long)]
        username: String,
        /// Grant the management-administration capability to the certificates
        /// this account is issued. Without it the account is a viewer: it may
        /// read the management API and change nothing.
        #[arg(long)]
        admin: bool,
        /// Validity window for this account's session certificates, in seconds.
        /// Zero means the provider's own default.
        ///
        /// The lifetime belongs to the admin granting the account, not to the
        /// code: an automation account may be worth minutes and a field
        /// operator a shift. Bounded by the provider's certificate cap.
        #[arg(long, default_value_t = 0)]
        session_ttl: u64,
        /// Create the account with **no** second factor.
        ///
        /// Any account here can mint a certificate the whole mesh honours, so a
        /// password alone makes fleet-wide administrative access a phishable
        /// secret. This exists for an automation account that cannot present a
        /// code — which should generally hold a long-lived certificate issued
        /// offline (`cert issue`) rather than log in at all.
        #[arg(long)]
        no_totp: bool,
        /// Read the password from standard input instead of prompting, taking
        /// the first line and no confirmation.
        ///
        /// The prompt reads `/dev/tty`, not stdin, so a script that pipes a
        /// password does not supply one — it blocks on whatever terminal the
        /// process inherited. This is the flag for a caller that has no
        /// terminal at all (`scripts/topology.py`, an installer, a
        /// configuration-management run), and the reason the password is not
        /// simply an argument: argv is readable by every process on the host.
        #[arg(long)]
        password_stdin: bool,
    },

    /// Mint a one-time invitation and print the token that redeems it.
    ///
    /// The difference from `add`, and the whole reason this exists: `add`
    /// generates the account's TOTP secret and prints its `otpauth://` URI on
    /// this terminal, so the person the account is for receives their second
    /// factor from somebody else. An invitation carries the secret instead, and
    /// reveals it only to whoever redeems it.
    Invite {
        /// The account name the invitation will create. Refused if the name is
        /// already an account or already invited.
        #[arg(long)]
        username: String,
        /// Grant the management-administration capability to the account this
        /// invitation creates. Decided here and never by the redeemer.
        #[arg(long)]
        admin: bool,
        /// Validity window for the created account's session certificates, in
        /// seconds. Zero means the provider's own default.
        #[arg(long, default_value_t = 0)]
        session_ttl: u64,
        /// How long the invitation may go unredeemed, in seconds. Zero means
        /// the provider's own default.
        ///
        /// The bound on how long the token is worth anything to whoever finds
        /// it later. Short is better; the cost of it expiring is one more mint.
        #[arg(long, default_value_t = 0)]
        invite_ttl: u64,
    },

    /// List the invitations on file (never their tokens or TOTP secrets).
    ///
    /// The column to read is `STARTED`. A started invitation with no account
    /// under its name means somebody took the account's second factor and did
    /// not finish registering — either an abandoned registration or a
    /// disclosure, and the response to both is `revoke-invite` and a fresh
    /// `invite`.
    Invites,

    /// Delete an invitation, at any status.
    RevokeInvite {
        /// The account name the invitation was minted for.
        #[arg(long)]
        username: String,
    },

    /// List the accounts on file (never their hashes or TOTP secrets).
    List,

    /// Change an account's role between admin and read-only.
    ///
    /// **A demotion also ends the admin sessions the account already holds.**
    /// The capability is stamped on the certificate, not read from the account
    /// at each request, so a session minted while the account was an
    /// administrator would go on administering until it expired. The
    /// revocations flood the mesh as part of the change.
    ///
    /// Refused if it would leave the mesh with no enabled administrator.
    SetRole {
        /// The account to change.
        #[arg(long)]
        username: String,
        /// The role the account should hold.
        #[arg(long, value_enum)]
        role: RoleArg,
    },

    /// Change an account's password, clearing any lockout.
    ///
    /// The administrative reset, for somebody who has lost their password. It
    /// leaves the second factor alone, and revokes nothing — when the reset
    /// answers a compromise rather than a forgotten password, `revoke-sessions`
    /// is the command that ends what the account is holding.
    Passwd {
        /// The account to change.
        #[arg(long)]
        username: String,
        /// Read the new password from standard input instead of prompting.
        /// See `add --password-stdin`.
        #[arg(long)]
        password_stdin: bool,
    },

    /// Disable an account: it can obtain no new sessions, and the sessions it
    /// already holds are revoked.
    ///
    /// Both halves, so that "disabled" is a statement about access now rather
    /// than only about future sign-ins. Refused if it would leave the mesh with
    /// no enabled administrator.
    Disable {
        /// The account to disable.
        #[arg(long)]
        username: String,
    },

    /// Re-enable a disabled account, clearing any lockout with it.
    Enable {
        /// The account to enable.
        #[arg(long)]
        username: String,
    },

    /// End every session certificate an account holds, leaving the account
    /// itself in place.
    ///
    /// The control for a lost laptop where the person still works here: they
    /// sign in again for a fresh certificate; what they cannot do is keep using
    /// the old one.
    RevokeSessions {
        /// The account whose sessions to end.
        #[arg(long)]
        username: String,
    },

    /// Remove an account entirely, revoking every session it holds.
    ///
    /// One act, not two: an account deleted whose certificates kept working
    /// would leave a compromise running for up to its whole session lifetime.
    /// Refused if it would leave the mesh with no enabled administrator.
    Remove {
        /// The account to remove.
        #[arg(long)]
        username: String,
    },
}

/// Run one `user` subcommand against `client`, returning what to print.
pub async fn run(cmd: UserCommand, client: &mut Client) -> anyhow::Result<String> {
    match cmd {
        UserCommand::Add {
            username,
            admin,
            session_ttl,
            no_totp,
            password_stdin,
        } => {
            let password = new_password(password_stdin)?;
            let uri = client
                .create_user(&username, &password, admin, session_ttl, no_totp)
                .await
                .context("creating the account")?;
            Ok(created(&username, admin, &uri))
        }

        UserCommand::Invite {
            username,
            admin,
            session_ttl,
            invite_ttl,
        } => {
            let minted = client
                .create_user_invite(&username, admin, session_ttl, invite_ttl)
                .await
                .context("minting the invitation")?;
            Ok(invited(
                &minted.username,
                admin,
                minted.expires_at,
                &minted.token,
            ))
        }

        UserCommand::Invites => {
            let listing = client
                .list_user_invites()
                .await
                .context("listing invitations")?;
            Ok(invite_listing(&listing))
        }

        UserCommand::RevokeInvite { username } => {
            client
                .revoke_user_invite(&username)
                .await
                .context("revoking the invitation")?;
            Ok(format!("revoked the invitation for {username}"))
        }

        UserCommand::List => {
            let listing = client.list_users().await.context("listing accounts")?;
            Ok(account_listing(&listing))
        }

        UserCommand::SetRole { username, role } => {
            let (revoked, unchanged) = client
                .set_user_role(&username, role.is_admin())
                .await
                .context("changing the account's role")?;
            if unchanged {
                return Ok(format!(
                    "{username} is already {}; nothing changed",
                    role.label()
                ));
            }
            Ok(with_revocations(
                format!("{username} is now {}", role.label()),
                revoked,
                "admin session",
            ))
        }

        UserCommand::Passwd {
            username,
            password_stdin,
        } => {
            let password = new_password(password_stdin)?;
            client
                .set_user_password(&username, &password)
                .await
                .context("changing the password")?;
            Ok(format!(
                "changed the password for {username} (any lockout cleared)\n  \
                 sessions it already holds are untouched — `user revoke-sessions \
                 --username {username}` ends those, if the reset answers a compromise"
            ))
        }

        UserCommand::Disable { username } => {
            let (revoked, unchanged) = client
                .set_user_enabled(&username, false)
                .await
                .context("disabling the account")?;
            if unchanged {
                return Ok(format!("{username} is already disabled; nothing changed"));
            }
            Ok(with_revocations(
                format!("disabled {username}"),
                revoked,
                "session",
            ))
        }

        UserCommand::Enable { username } => {
            let (revoked, unchanged) = client
                .set_user_enabled(&username, true)
                .await
                .context("enabling the account")?;
            if unchanged {
                return Ok(format!("{username} is already enabled; nothing changed"));
            }
            // The count is reported rather than discarded, even though an
            // enable is documented to revoke nothing. That guarantee belongs to
            // the authority, and `AuthorityAdapter::keep` deliberately keeps
            // whatever an ungated direction signs instead of assuming zero —
            // so a record that reached the mesh must reach the operator too.
            Ok(with_revocations(
                format!("enabled {username} (any lockout cleared)"),
                revoked,
                "session",
            ))
        }

        UserCommand::RevokeSessions { username } => {
            let revoked = client
                .revoke_user_sessions(&username)
                .await
                .context("revoking the account's sessions")?;
            if revoked == 0 {
                return Ok(format!(
                    "{username} held no live session certificates; nothing was revoked"
                ));
            }
            Ok(with_revocations(
                format!("{username} keeps its account"),
                revoked,
                "session",
            ))
        }

        UserCommand::Remove { username } => {
            client
                .remove_user(&username)
                .await
                .context("removing the account")?;
            Ok(format!(
                "removed {username}, and revoked every session certificate it held"
            ))
        }
    }
}

/// Append what a change revoked, when it revoked anything.
///
/// The count is worth a line of its own because "this also cut off two live
/// sessions" and "it cut off nothing" call for different follow-up — and
/// because a revocation is the half of the act the operator did not explicitly
/// ask for.
fn with_revocations(head: String, revoked: u32, noun: &str) -> String {
    if revoked == 0 {
        return head;
    }
    let plural = if revoked == 1 { "" } else { "s" };
    format!("{head}; revoked {revoked} live {noun} certificate{plural}")
}

/// What to print after creating an account.
fn created(username: &str, admin: bool, totp_enrolment_uri: &str) -> String {
    let mut out = format!(
        "created user {username}\n  role: {}",
        if admin { "admin" } else { "viewer" }
    );
    if totp_enrolment_uri.is_empty() {
        out.push_str(
            "\n  second factor: none. This account's password is the whole credential; \
             prefer an offline `cert issue --admin` certificate for automation.",
        );
    } else {
        out.push_str(&format!(
            "\n  enrol this in an authenticator app now — it is not shown again:\n    \
             {totp_enrolment_uri}"
        ));
    }
    out
}

/// What to print after minting an invitation.
fn invited(username: &str, admin: bool, expires_at: u64, token: &str) -> String {
    format!(
        "invited {username}\n  role:    {}\n  expires: {expires_at} (unix)\n  \
         send this token to them now — it is not shown again:\n    token: {token}\n  \
         they redeem it at the dashboard's /register page (the token belongs in the URL's \
         fragment, after the '#', so it never reaches a server log or a link preview).\n  \
         Their password and second factor are chosen there; nothing about them is printed here.",
        if admin { "admin" } else { "viewer" }
    )
}

/// Render the account roster.
fn account_listing(listing: &wayfinder_protos::wayfinder::v1alpha::ListUsersResponse) -> String {
    if listing.users.is_empty() {
        return "no users".to_string();
    }
    let mut out = String::from("USERNAME             ROLE     SESSION_TTL  TOTP  STATUS");
    for u in &listing.users {
        let status = match (u.disabled, u.locked) {
            (true, _) => "disabled",
            (_, true) => "locked",
            _ => "active",
        };
        out.push_str(&format!(
            "\n{:<20} {:<8} {:>10}s  {:<4}  {}",
            u.username,
            if u.admin { "admin" } else { "viewer" },
            u.session_ttl_secs,
            if u.totp_enrolled { "yes" } else { "no" },
            status,
        ));
    }
    out
}

/// Render the outstanding invitations.
fn invite_listing(
    listing: &wayfinder_protos::wayfinder::v1alpha::ListUserInvitesResponse,
) -> String {
    if listing.invites.is_empty() {
        return "no invitations".to_string();
    }
    let mut out = String::from("USERNAME             ROLE     EXPIRES        STARTED");
    for i in &listing.invites {
        // Spelled out rather than shown as a timestamp: this is the row an
        // operator is scanning for, and "somebody has the second factor" is the
        // thing to notice, not when.
        let started = match i.started_at {
            0 => "no".to_string(),
            at => format!("yes, at {at} — revoke and re-invite if unexpected"),
        };
        out.push_str(&format!(
            "\n{:<20} {:<8} {:<14} {}",
            i.username,
            if i.admin { "admin" } else { "viewer" },
            i.expires_at,
            started,
        ));
    }
    out
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
/// to point at. There is no confirmation, because a piped password cannot be
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

    /// A change that revoked nothing says so by saying nothing: the count line
    /// appears only when there is something to report.
    #[test]
    fn only_a_change_that_revoked_something_mentions_revocations() {
        assert_eq!(with_revocations("demoted".into(), 0, "session"), "demoted");
        assert!(
            with_revocations("demoted".into(), 1, "session").contains("1 live session certificate")
        );
        // The plural belongs on the noun the count counts, which is the
        // certificate — three sessions is three certificates, not "sessions".
        assert!(
            with_revocations("demoted".into(), 3, "session")
                .contains("3 live session certificates")
        );
    }
}
