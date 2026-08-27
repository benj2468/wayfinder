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
        headscale: None,
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

/// The reason `user invite` exists offline, driven end to end: **the first
/// administrator can be created without anybody but its owner ever seeing its
/// second factor.**
///
/// `user add` cannot do that. It mints the TOTP secret and prints the
/// `otpauth://` URI on the operator's terminal, so the person the account is
/// for receives their second factor from somebody else — and `user add` is the
/// only way to create the first account, because creating it over the
/// management API needs the credential it creates. An invitation breaks that
/// loop from the other side: it is minted before the provider starts, and
/// redeemed against the running provider by the person it is for.
///
/// Driven through the real binary because the token is printed once, on stdout,
/// and never recoverable afterwards — which is exactly the property under test.
#[test]
fn an_invitation_minted_offline_is_redeemed_against_the_running_provider() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("ca.json");
    seed_state(&state);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_wayfinder-ctl"))
        .args([
            "user",
            "invite",
            "--state",
            state.to_str().unwrap(),
            "--username",
            "rowan",
            "--admin",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "user invite failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let printed = String::from_utf8(output.stdout).unwrap();

    // The token is printed for the operator to deliver, and nothing else that
    // belongs to the account is.
    let token = printed
        .lines()
        .find_map(|l| l.trim().strip_prefix("token: "))
        .unwrap_or_else(|| panic!("no token in:\n{printed}"))
        .trim()
        .to_string();
    assert!(!token.is_empty());
    assert!(
        !printed.contains("otpauth://"),
        "the operator must not be shown the second factor — that is the whole \
         point of inviting rather than adding:\n{printed}"
    );

    // Now the provider is running, and the person the account is for redeems
    // it. Nothing here touches the filesystem the CLI wrote: this is what the
    // management API would drive.
    let mut ca = CertAuthority::from_config(&[1u8; 32], &config(&state)).unwrap();
    let now = 1_700_000_000;
    ca.set_now_unix(now);
    let started = ca.begin_user_registration(&token).unwrap();
    assert_eq!(started.username, "rowan");
    assert!(started.totp_enrolment_uri.starts_with("otpauth://totp/"));

    let secret = secret_from_uri(&started.totp_enrolment_uri);
    let code = totp_code_at(&secret, now);
    ca.complete_user_registration(&started.handle, "correct horse battery staple", &code)
        .unwrap();

    // The account exists, holds the role the operator chose, and signs in with
    // credentials the operator never saw.
    let session = wayfinder_auth::Keypair::from_seed(&[4u8; 32]);
    let later = now + 30;
    ca.set_now_unix(later);
    let outcome = wayfinder_server::MeshAuthority::authenticate_user(
        &mut ca,
        "rowan",
        "correct horse battery staple",
        &totp_code_at(&secret, later),
        &session.ed_pubkey(),
        &session.x_pubkey(),
    )
    .unwrap();
    assert!(matches!(
        outcome,
        wayfinder_protos::service::UserAuthOutcome::Issued(_)
    ));

    // And the seeded account is still there: `invite` rewrites the whole
    // snapshot, like every other `user` subcommand.
    assert_eq!(ca.list_users().len(), 2);
    assert!(
        ca.list_user_invites().is_empty(),
        "a redeemed invitation is deleted, not left behind"
    );
}

/// `user invites` shows what is outstanding, including the state an operator
/// acts on: started, and not finished.
#[test]
fn the_offline_listing_shows_an_outstanding_invitation() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("ca.json");
    seed_state(&state);

    run(UserCommand::Invite {
        state: state.clone(),
        username: "rowan".into(),
        admin: false,
        session_ttl: 900,
        invite_ttl: 3600,
    })
    .unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_wayfinder-ctl"))
        .args(["user", "invites", "--state", state.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let printed = String::from_utf8(output.stdout).unwrap();

    assert!(printed.contains("rowan"), "got:\n{printed}");
    assert!(
        !printed.contains("otpauth://"),
        "a listing must never carry a second factor:\n{printed}"
    );

    run(UserCommand::RevokeInvite {
        state: state.clone(),
        username: "rowan".into(),
    })
    .unwrap();
    let ca = CertAuthority::from_config(&[1u8; 32], &config(&state)).unwrap();
    assert!(ca.list_user_invites().is_empty());
}

/// An invitation that expired yesterday is not shown as one an operator can
/// still expect somebody to redeem.
///
/// `open` deliberately does not set a clock — nothing else in `user` needs one
/// — but `list_user_invites` filters on exactly that clock, and an unset clock
/// is zero. `invite_is_live` reads zero as "now is the epoch", under which no
/// expiry has arrived yet and every dead invitation is live: the listing an
/// admin triages by shows rows that can never produce an account, and the
/// `STARTED` column that means *act now* alongside them.
#[test]
fn an_expired_invitation_is_not_listed() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("ca.json");
    seed_state(&state);

    // Minted a day ago with a one-hour lifetime: dead by any clock the operator
    // running this command has.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    {
        let mut ca = CertAuthority::from_config(&[1u8; 32], &config(&state)).unwrap();
        ca.set_now_unix(now - 86_400);
        ca.create_user_invite("rowan", UserRole::Viewer, 900, 3600)
            .unwrap();
    }

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_wayfinder-ctl"))
        .args(["user", "invites", "--state", state.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let printed = String::from_utf8(output.stdout).unwrap();

    assert!(
        !printed.contains("rowan"),
        "an invitation that expired yesterday cannot produce an account, and \
         listing it tells the admin the opposite:\n{printed}"
    );
    assert!(printed.contains("no invitations"), "got:\n{printed}");
}

/// The 20-byte TOTP secret an `otpauth://` URI carries, for a test that has to
/// present a live code the way an authenticator app would.
fn secret_from_uri(uri: &str) -> Vec<u8> {
    let encoded = uri
        .split_once("secret=")
        .and_then(|(_, rest)| rest.split('&').next())
        .expect("the enrolment URI carries a secret");
    let mut out = Vec::new();
    let mut buffer: u16 = 0;
    let mut bits: u32 = 0;
    for c in encoded.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            other => panic!("not base32: {other}"),
        };
        buffer = (buffer << 5) | u16::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out
}

/// The RFC 6238 code an authenticator would show for `secret` at `now_unix`.
fn totp_code_at(secret: &[u8], now_unix: u64) -> String {
    use hmac::Mac as _;
    let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(secret).unwrap();
    mac.update(&(now_unix / 30).to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    format!("{:06}", binary % 1_000_000)
}
