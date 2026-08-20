//! The offline `wayfinderctl user` commands, against a real CA state file.
//!
//! What these cover is the part that is easy to get wrong without noticing —
//! that a command touching the *user* section rewrites the snapshot without
//! disturbing anything else in it, and that the state file it produces is one a
//! real provider can load — plus the one path a script depends on, `add
//! --password-stdin`, which is driven through the real binary because the
//! process's own stdin is what it is about.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use wayfinder_server::CertAuthority;
use wayfinder_server::UserRecord;
use wayfinder_server::UserRole;
use wayfinderctl::user::UserCommand;
use wayfinderctl::user::run;

/// A `ProviderConfig` pointing at `state`, for building an authority the way
/// `user`'s own `open` does.
fn config(state: &std::path::Path) -> wayfinder::config::ProviderConfig {
    wayfinder::config::ProviderConfig {
        root_seed_path: String::new(),
        mesh_id: 0xABCD,
        cert_ttl_secs: 3600,
        enrollment_token: None,
        auto_approve: true,
        allow_unbounded_cert_ttl: false,
        pending_ttl_secs: 3600,
        state_path: Some(state.display().to_string()),
    }
}

/// Seed a state file with one account and one issued device certificate, so a
/// later command has both sections to preserve.
fn seed_state(state: &std::path::Path) {
    let mut ca = CertAuthority::from_config(&[1u8; 32], &config(state)).unwrap();
    ca.set_now_unix(1_700_000_000);
    ca.add_user(UserRecord::new("ops", "hunter2", UserRole::Admin, 900).unwrap())
        .unwrap();
    let node = wayfinder_auth::Keypair::from_seed(&[2u8; 32]);
    // Through the public enrollment path, so the record is exactly what a real
    // provider would have written.
    wayfinder_server::MeshAuthority::submit_csr(
        &mut ca,
        &[0, 0, 0, 0, 0, 9],
        &node.ed_pubkey(),
        &node.x_pubkey(),
        "",
    )
    .unwrap();
}

/// Disabling an account through the CLI is durable, and leaves the rest of the
/// snapshot — the issued-certificate log a provider's impersonation guard and
/// revocations depend on — exactly as it was.
///
/// The negative half is the one worth the test. `user` opens the whole CA state
/// to touch one section of it and writes the whole thing back, so a mistake
/// here does not corrupt the user list, it silently discards a provider's
/// certificate history.
#[test]
fn disabling_an_account_persists_and_preserves_the_rest_of_the_state() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("ca.json");
    seed_state(&state);

    run(UserCommand::Disable {
        state: state.clone(),
        username: "ops".into(),
    })
    .unwrap();

    let ca = CertAuthority::from_config(&[1u8; 32], &config(&state)).unwrap();
    let users = ca.list_users();
    assert_eq!(users.len(), 1);
    assert!(users[0].disabled, "the change survived the rewrite");
    assert_eq!(
        wayfinder_server::MeshAuthority::list_certs(&ca).len(),
        1,
        "the issued-certificate log came back untouched"
    );

    // And back again.
    run(UserCommand::Enable {
        state: state.clone(),
        username: "ops".into(),
    })
    .unwrap();
    let ca = CertAuthority::from_config(&[1u8; 32], &config(&state)).unwrap();
    assert!(!ca.list_users()[0].disabled);
}

/// Removing an account is durable, and removing one that is not there is an
/// error rather than a silent success — an operator who mistyped a name must
/// not be told the account is gone.
#[test]
fn removing_an_account_persists_and_a_missing_one_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("ca.json");
    seed_state(&state);

    run(UserCommand::Remove {
        state: state.clone(),
        username: "ops".into(),
    })
    .unwrap();

    let ca = CertAuthority::from_config(&[1u8; 32], &config(&state)).unwrap();
    assert!(ca.list_users().is_empty());

    assert!(
        run(UserCommand::Remove {
            state: state.clone(),
            username: "ops".into(),
        })
        .is_err(),
        "removing an absent account is an error"
    );
}

/// `user list` reads a state file written by a provider, which is the whole
/// premise of the command being offline: the two agree on the schema.
#[test]
fn listing_reads_a_state_file_a_provider_wrote() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("ca.json");
    seed_state(&state);

    run(UserCommand::List {
        state: state.clone(),
    })
    .unwrap();
}

/// An account can be created with no terminal at all, taking its password from
/// stdin.
///
/// The prompt `add` otherwise uses reads `/dev/tty`, not stdin — so a script
/// that pipes a password to it does not supply one, it *hangs on the operator's
/// terminal*. That is the whole reason this flag exists: `scripts/topology.py`
/// mints the simulation's accounts before the stack comes up, and it has no
/// terminal to type at.
///
/// Driven through the real binary rather than `run()`, because the process's
/// own stdin is the thing under test and a test harness cannot replace it.
#[test]
fn an_account_can_be_created_with_the_password_on_stdin() {
    use std::io::Write;

    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("ca.json");
    seed_state(&state);

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_wayfinder-ctl"))
        .args([
            "user",
            "add",
            "--state",
            state.to_str().unwrap(),
            "--username",
            "sim-admin",
            "--admin",
            "--no-totp",
            "--password-stdin",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"hunter2\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "user add --password-stdin failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The account is real: it authenticates with the piped password, which is
    // the only assertion that proves no stray newline came with it.
    let mut ca = CertAuthority::from_config(&[1u8; 32], &config(&state)).unwrap();
    ca.set_now_unix(1_700_000_000);
    let session = wayfinder_auth::Keypair::from_seed(&[3u8; 32]);
    let outcome = wayfinder_server::MeshAuthority::authenticate_user(
        &mut ca,
        "sim-admin",
        "hunter2",
        "",
        &session.ed_pubkey(),
        &session.x_pubkey(),
    )
    .unwrap();
    assert!(
        matches!(
            outcome,
            wayfinder_protos::service::UserAuthOutcome::Issued(_)
        ),
        "the piped password is the account's password"
    );

    // And the seeded account is still there: `add` rewrites the whole snapshot.
    assert_eq!(ca.list_users().len(), 2);
}
