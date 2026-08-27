//! The `wayfinderctl user` account lifecycle, driven against an in-process
//! provider over real TLS.
//!
//! **These commands have no offline mode.** Every one of them is an RPC to a
//! running provider, and the reason is the failure the state-file version had:
//! a provider holds the whole CA snapshot in memory and rewrites it whole on
//! every login, issuance and revocation, so an edit made to the file beside it
//! was discarded by the provider's next write — silently, taking the operator's
//! change with it, or taking the provider's issued-certificate log with it in
//! the other order. Neither is detectable by whoever ran the command.
//!
//! What made that seem necessary was a bootstrap loop: the first account cannot
//! be created *by an account*, because creating one needs the credential it
//! creates. It is broken from the other side instead — an operator on the
//! provider host holds the node's own identity seed, which authenticates at the
//! self-key tier and may invoke every request. The first test here is that
//! claim, driven end to end.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod provider;

use wayfinderctl::Command;
use wayfinderctl::Endpoint;
use wayfinderctl::output::OutputFormat;
use wayfinderctl::run_query;
use wayfinderctl::user::RoleArg;
use wayfinderctl::user::UserCommand;

use provider::spawn_provider;

/// Run one `user` subcommand against `endpoint`, returning what it rendered.
async fn user(endpoint: &Endpoint, cmd: UserCommand) -> anyhow::Result<String> {
    run_query(Command::User(cmd), endpoint, OutputFormat::Human).await
}

/// The roster, as `user list` renders it.
async fn roster(endpoint: &Endpoint) -> String {
    user(endpoint, UserCommand::List).await.unwrap()
}

/// Create an account through the real binary, with its password on stdin.
///
/// Through the binary because a password is the one input that cannot come from
/// the library path: the prompt reads `/dev/tty`, and `--password-stdin` is
/// about the process's own stdin, which a test harness cannot replace.
fn add_account(endpoint: &Endpoint, seed_path: &std::path::Path, username: &str, admin: bool) {
    use std::io::Write;

    let mut args = vec![
        "--connect".to_string(),
        endpoint.addr.to_string(),
        "--identity".to_string(),
        seed_path.display().to_string(),
        "user".to_string(),
        "add".to_string(),
        "--username".to_string(),
        username.to_string(),
        "--no-totp".to_string(),
        "--password-stdin".to_string(),
    ];
    if admin {
        args.push("--admin".to_string());
    }
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_wayfinder-ctl"))
        .args(&args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"hunter2\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "user add failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Write the node's identity seed where the CLI can present it, the way it sits
/// on a real provider host at `/var/lib/wayfinder/identity.seed`.
fn seed_file(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("identity.seed");
    std::fs::write(&path, [9u8; 32]).unwrap();
    path
}

/// **The first administrator is created over the management API**, by an
/// operator holding nothing but the node's own identity seed.
///
/// This is the test the whole change rests on. The account store starts empty,
/// so there is no credential to authenticate with and no account to create one
/// — the loop that made `wayfinderctl user add --state <file>` look unavoidable.
/// The way out is that the operator running it is on the provider host, and the
/// host holds the node's seed: the self-key tier is admitted to every request,
/// so the provider itself vouches for the operator standing at its console.
///
/// Driven through the real binary with a real seed file, because the claim is
/// about what an operator can actually type.
///
/// Multi-threaded on purpose: [`add_account`] blocks on the child process, and
/// the provider it is talking to lives in *this* process. On the default
/// single-threaded runtime the blocking wait would stop the listener from ever
/// accepting, and the two would deadlock.
#[tokio::test(flavor = "multi_thread")]
async fn the_first_administrator_is_created_over_rpc_with_the_nodes_own_identity() {
    let endpoint = spawn_provider(None).await;
    let dir = tempfile::tempdir().unwrap();
    let seed = seed_file(dir.path());

    assert!(
        !roster(&endpoint).await.contains("rowan"),
        "the store starts empty"
    );

    add_account(&endpoint, &seed, "rowan", true);

    let listing = roster(&endpoint).await;
    assert!(listing.contains("rowan"), "got:\n{listing}");
    assert!(
        listing.contains("admin"),
        "and it holds the role the operator asked for:\n{listing}"
    );
}

/// The rest of the lifecycle runs over the same connection: role, status,
/// removal.
///
/// One test rather than four because what is under test is that each subcommand
/// reaches its RPC and the roster reflects it — the semantics of each change
/// (what a demotion revokes, what the guards refuse) belong to the authority's
/// own tests, where they can be asserted without a socket.
///
/// Multi-threaded for the reason the test above is.
#[tokio::test(flavor = "multi_thread")]
async fn the_account_lifecycle_runs_entirely_over_rpc() {
    let endpoint = spawn_provider(None).await;
    let dir = tempfile::tempdir().unwrap();
    let seed = seed_file(dir.path());
    // Two administrators: the guard refuses to demote or disable the last one,
    // and this test is about the commands rather than about that refusal.
    add_account(&endpoint, &seed, "rowan", true);
    add_account(&endpoint, &seed, "second", true);

    let out = user(
        &endpoint,
        UserCommand::SetRole {
            username: "rowan".into(),
            role: RoleArg::Viewer,
        },
    )
    .await
    .unwrap();
    assert!(out.contains("viewer"), "got: {out}");
    assert!(roster(&endpoint).await.contains("viewer"));

    // Restating a role is a success that says nothing changed.
    let out = user(
        &endpoint,
        UserCommand::SetRole {
            username: "rowan".into(),
            role: RoleArg::Viewer,
        },
    )
    .await
    .unwrap();
    assert!(out.contains("already"), "got: {out}");

    user(
        &endpoint,
        UserCommand::Disable {
            username: "rowan".into(),
        },
    )
    .await
    .unwrap();
    assert!(roster(&endpoint).await.contains("disabled"));

    user(
        &endpoint,
        UserCommand::Enable {
            username: "rowan".into(),
        },
    )
    .await
    .unwrap();
    assert!(!roster(&endpoint).await.contains("disabled"));

    user(
        &endpoint,
        UserCommand::Remove {
            username: "rowan".into(),
        },
    )
    .await
    .unwrap();
    let listing = roster(&endpoint).await;
    assert!(!listing.contains("rowan"), "got:\n{listing}");

    // And a name that is not on file is an error rather than a silent success.
    assert!(
        user(
            &endpoint,
            UserCommand::SetRole {
                username: "nobody".into(),
                role: RoleArg::Admin,
            },
        )
        .await
        .is_err()
    );
}

/// Invitations are minted, listed and revoked over the wire too.
///
/// The invite path is the one that matters most for a *first* administrator —
/// it is how an account's second factor reaches its owner without the operator
/// ever holding it — so it must work against a running provider, which is
/// exactly what the offline version could not do.
#[tokio::test]
async fn invitations_are_minted_and_revoked_over_rpc() {
    let endpoint = spawn_provider(None).await;

    let minted = user(
        &endpoint,
        UserCommand::Invite {
            username: "rowan".into(),
            admin: true,
            session_ttl: 0,
            invite_ttl: 0,
        },
    )
    .await
    .unwrap();
    let token = minted
        .lines()
        .find_map(|l| l.trim().strip_prefix("token: "))
        .unwrap_or_else(|| panic!("no token in:\n{minted}"))
        .trim();
    assert!(!token.is_empty());
    assert!(
        !minted.contains("otpauth://"),
        "the operator must not be shown the second factor:\n{minted}"
    );

    let listing = user(&endpoint, UserCommand::Invites).await.unwrap();
    assert!(listing.contains("rowan"), "got:\n{listing}");

    user(
        &endpoint,
        UserCommand::RevokeInvite {
            username: "rowan".into(),
        },
    )
    .await
    .unwrap();
    let listing = user(&endpoint, UserCommand::Invites).await.unwrap();
    assert!(!listing.contains("rowan"), "got:\n{listing}");
}

/// **There is no `--state` flag left to reach a CA state file with.**
///
/// The regression test for the whole change. Every `user` subcommand used to
/// take one, and passing it while a provider was running silently discarded
/// either the operator's change or the provider's certificate log. Removing the
/// commands is not enough on its own — what must not come back is the flag, so
/// this asserts the CLI rejects it rather than trusting that nobody re-adds it.
#[test]
fn there_is_no_state_file_flag() {
    for subcommand in ["list", "set-role", "remove", "add", "invite"] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_wayfinder-ctl"))
            .args(["user", subcommand, "--state", "/tmp/ca-state.json"])
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "`user {subcommand} --state` was accepted; the offline path is back"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("--state") || stderr.contains("unexpected argument"),
            "the refusal should name the flag, got: {stderr}"
        );
    }
}
