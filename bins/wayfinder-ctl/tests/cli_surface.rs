//! The command grammar itself: what argv `wayfinderctl` accepts and what it
//! parses to.
//!
//! Everything else in this directory builds [`Command`] values directly and so
//! exercises dispatch, not the surface an operator actually types. That left
//! the command *names* — the thing every script, nix module and doc in the repo
//! depends on — with no test at all, which is why renaming one was previously a
//! silent break. This file is the specification of the grammar: the groups, and
//! the compatibility aliases that keep existing call sites working.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use clap::Parser;
use wayfinderctl::Cli;
use wayfinderctl::Command;
use wayfinderctl::auth::AuthCommand;
use wayfinderctl::csr::CsrCommand;
use wayfinderctl::link::LinkCommand;
use wayfinderctl::provider::ProviderCommand;
use wayfinderctl::provider::RequestsCommand;
use wayfinderctl::user::UserCommand;
use wayfinderctl::vpn::VpnCommand;

/// Parse an argv tail into the [`Command`] it reaches, panicking if clap
/// rejects it.
///
/// Canonicalized, because parsing is two steps: clap yields whichever spelling
/// was typed, and `canonical` says which command that spelling *is*. What these
/// tests specify is where an argv lands, not which of its names was used.
fn parse(argv: &[&str]) -> Command {
    let mut full = vec!["wayfinderctl"];
    full.extend_from_slice(argv);
    Cli::parse_from(full).command.canonical()
}

/// Whether clap accepts this argv at all — for pinning that a retired spelling
/// is actually gone rather than silently still working.
fn accepts(argv: &[&str]) -> bool {
    let mut full = vec!["wayfinderctl"];
    full.extend_from_slice(argv);
    Cli::try_parse_from(full).is_ok()
}

// ── link: one subject, one group ────────────────────────────────────────────

/// The per-interface reads. These were three unrelated top-level names
/// (`links`, `link-features`, `ogm-schedule`) describing one subject.
#[test]
fn link_reads_parse() {
    assert!(matches!(
        parse(&["link", "list"]),
        Command::Link(LinkCommand::List)
    ));
    assert!(matches!(
        parse(&["link", "features"]),
        Command::Link(LinkCommand::Features)
    ));
    assert!(matches!(
        parse(&["link", "schedule"]),
        Command::Link(LinkCommand::Schedule)
    ));
}

/// The per-interface writes, alongside the reads they modify.
#[test]
fn link_writes_parse() {
    assert!(matches!(
        parse(&["link", "enable", "--iface", "1"]),
        Command::Link(LinkCommand::Enable { iface: 1 })
    ));
    assert!(matches!(
        parse(&["link", "disable", "--iface", "2"]),
        Command::Link(LinkCommand::Disable { iface: 2 })
    ));
    assert!(matches!(
        parse(&[
            "link", "trickle", "--iface", "0", "--min-ms", "500", "--max-ms", "4000"
        ]),
        Command::Link(LinkCommand::Trickle {
            iface: 0,
            min_ms: 500,
            max_ms: 4000
        })
    ));
}

/// `link set` leaves every gate it is not given alone, which is what lets one
/// capability be flipped without restating the others.
#[test]
fn link_set_leaves_unnamed_gates_unchanged() {
    let Command::Link(LinkCommand::Set {
        iface,
        tx_ogm,
        rx_ogm,
        tx_data,
        rx_data,
        ..
    }) = parse(&["link", "set", "--iface", "3", "--tx-ogm", "false"])
    else {
        panic!("expected link set");
    };
    assert_eq!(iface, 3);
    assert_eq!(tx_ogm, Some(false));
    assert_eq!(rx_ogm, None);
    assert_eq!(tx_data, None);
    assert_eq!(rx_data, None);
}

// ── auth: this node's own credential, and how it advertises it ──────────────

/// `auth set` takes flags, not the three bare positionals `set-auth` used. The
/// old shape made a swapped cert/anchor pair a silent mistake.
#[test]
fn auth_set_takes_named_paths() {
    let Command::Auth(AuthCommand::Set {
        seed,
        cert,
        trust_anchor,
    }) = parse(&[
        "auth",
        "set",
        "--seed",
        "/s",
        "--cert",
        "/c",
        "--trust-anchor",
        "/a",
    ])
    else {
        panic!("expected auth set");
    };
    assert_eq!(seed.to_str(), Some("/s"));
    assert_eq!(cert.to_str(), Some("/c"));
    assert_eq!(trust_anchor.to_str(), Some("/a"));
}

/// `--seed` is required. `auth set` re-identifies a node, and the operation
/// that certifies the identity a node already holds is `csr install` — one
/// command each, rather than one command whose destructiveness depends on
/// whether a flag was passed.
#[test]
fn auth_set_requires_a_seed() {
    assert!(!accepts(&[
        "auth",
        "set",
        "--cert",
        "/c",
        "--trust-anchor",
        "/a"
    ]));
}

#[test]
fn auth_status_and_lazy_certs_parse() {
    assert!(matches!(
        parse(&["auth", "status"]),
        Command::Auth(AuthCommand::Status)
    ));
    assert!(matches!(
        parse(&["auth", "lazy-certs", "--enabled", "true"]),
        Command::Auth(AuthCommand::LazyCerts { enabled: true })
    ));
}

/// `--enabled` takes a value in both directions, and requires one.
///
/// The `false` case is the whole reason this argument changed: declared as a
/// bare `bool`, clap derived it as a presence flag, so the switch could be
/// thrown on and never off. A bare `--enabled` is now an error rather than
/// silently meaning `true`.
#[test]
fn lazy_certs_can_be_switched_off_as_well_as_on() {
    assert!(matches!(
        parse(&["auth", "lazy-certs", "--enabled", "false"]),
        Command::Auth(AuthCommand::LazyCerts { enabled: false })
    ));
    assert!(!accepts(&["auth", "lazy-certs", "--enabled"]));
    assert!(!accepts(&["auth", "lazy-certs"]));
}

#[test]
fn auth_enroll_parses() {
    assert!(matches!(
        parse(&[
            "auth",
            "enroll",
            "--out-seed",
            "/s",
            "--out-cert",
            "/c",
            "--out-anchor",
            "/a"
        ]),
        Command::Auth(AuthCommand::Enroll { .. })
    ));
}

// ── provider: the node as the mesh's certificate authority ──────────────────

/// The provider scope mirrors `wayfinder_web::Scope::Provider`, and — the part
/// that matters operationally — every command in it is pointed at the CA rather
/// than at your own node.
#[test]
fn provider_commands_parse() {
    assert!(matches!(
        parse(&["provider", "members"]),
        Command::Provider(ProviderCommand::Members)
    ));
    assert!(matches!(
        parse(&["provider", "revoke", "--mac", "02:00:00:00:00:09"]),
        Command::Provider(ProviderCommand::Revoke { .. })
    ));
}

/// The CSR queue is a provider-side operator action, so it lives here rather
/// than beside `csr request`/`submit`/`install`, which talk to the enrolling
/// node instead.
#[test]
fn provider_requests_parse() {
    assert!(matches!(
        parse(&["provider", "requests", "list"]),
        Command::Provider(ProviderCommand::Requests(RequestsCommand::List))
    ));
    assert!(matches!(
        parse(&[
            "provider",
            "requests",
            "approve",
            "--mac",
            "02:00:00:00:00:09"
        ]),
        Command::Provider(ProviderCommand::Requests(RequestsCommand::Approve { .. }))
    ));
    assert!(matches!(
        parse(&["provider", "requests", "deny", "--mac", "02:00:00:00:00:09"]),
        Command::Provider(ProviderCommand::Requests(RequestsCommand::Deny { .. }))
    ));
}

#[test]
fn provider_nests_user_and_vpn() {
    assert!(matches!(
        parse(&["provider", "user", "list"]),
        Command::Provider(ProviderCommand::User(UserCommand::List))
    ));
    assert!(matches!(
        parse(&["provider", "vpn", "list"]),
        Command::Provider(ProviderCommand::Vpn(VpnCommand::List))
    ));
}

/// `ca` is the short spelling, so the extra nesting costs two characters rather
/// than eight on the commands an operator runs most.
#[test]
fn ca_is_an_alias_for_provider() {
    assert!(matches!(
        parse(&["ca", "members"]),
        Command::Provider(ProviderCommand::Members)
    ));
    assert!(matches!(
        parse(&["ca", "user", "list"]),
        Command::Provider(ProviderCommand::User(UserCommand::List))
    ));
}

// ── csr: the out-of-band chain, node-side ───────────────────────────────────

/// What stays under `csr` is exactly the chain that carries a request out and a
/// certificate back. The provider-side queue actions moved to
/// `provider requests`.
#[test]
fn csr_keeps_the_out_of_band_chain() {
    assert!(matches!(
        parse(&["csr", "request", "--out-request", "/r"]),
        Command::Csr(CsrCommand::Request { .. })
    ));
    assert!(matches!(
        parse(&[
            "csr",
            "submit",
            "--request",
            "/r",
            "--out-cert",
            "/c",
            "--out-anchor",
            "/a"
        ]),
        Command::Csr(CsrCommand::Submit { .. })
    ));
    assert!(matches!(
        parse(&["csr", "install", "--cert", "/c", "--trust-anchor", "/a"]),
        Command::Csr(CsrCommand::Install { .. })
    ));
}

/// `csr install` deliberately offers no `--seed`: an install certifies the
/// identity a node already holds and must never be able to re-identify it.
/// `auth set --seed` is the command that does that, and it is a different thing
/// to type on purpose.
#[test]
fn csr_install_cannot_reidentify_a_node() {
    assert!(!accepts(&[
        "csr",
        "install",
        "--cert",
        "/c",
        "--trust-anchor",
        "/a",
        "--seed",
        "/s"
    ]));
}

// ── compatibility: the spellings with call sites across the repo ────────────

/// `user`, `vpn` and `enroll` account for ~70 call sites in docs, nix modules
/// and CI. They keep working as top-level shortcuts rather than being rewritten
/// — `docs/design/implemented/**` in particular is a record of what shipped and
/// should not be edited to match a later rename.
#[test]
fn legacy_top_level_spellings_still_work() {
    assert!(matches!(
        parse(&["user", "list"]),
        Command::Provider(ProviderCommand::User(UserCommand::List))
    ));
    assert!(matches!(
        parse(&["vpn", "list"]),
        Command::Provider(ProviderCommand::Vpn(VpnCommand::List))
    ));
    assert!(matches!(
        parse(&[
            "enroll",
            "--out-seed",
            "/s",
            "--out-cert",
            "/c",
            "--out-anchor",
            "/a"
        ]),
        Command::Auth(AuthCommand::Enroll { .. })
    ));
}

/// `security` is the name the TUI tab and the web tab both use, so it stays
/// reachable even though the subject now lives under `auth`.
#[test]
fn security_still_reaches_auth_status() {
    assert!(matches!(
        parse(&["security"]),
        Command::Auth(AuthCommand::Status)
    ));
}

/// The retired spellings that had few enough call sites to just fix. Pinned as
/// *gone* so the restructure cannot half-land, leaving two names for one thing.
#[test]
fn retired_spellings_are_rejected() {
    for argv in [
        &["links"][..],
        &["link-features"][..],
        &["ogm-schedule"][..],
        &["link-enable", "--iface", "0"][..],
        &["link-disable", "--iface", "0"][..],
        &["set-link-features", "--iface", "0"][..],
        &[
            "set-trickle-config",
            "--iface",
            "0",
            "--min-ms",
            "1",
            "--max-ms",
            "2",
        ][..],
        &["set-lazy-cert-distribution", "--enabled", "true"][..],
        &["set-auth", "/s", "/c", "/a"][..],
        &["list-certs"][..],
        &["revoke", "--mac", "02:00:00:00:00:09"][..],
        &["csr", "list"][..],
        &["csr", "approve", "--mac", "02:00:00:00:00:09"][..],
        &["csr", "deny", "--mac", "02:00:00:00:00:09"][..],
    ] {
        assert!(!accepts(argv), "{argv:?} should no longer parse");
    }
}

// ── the reads that did not move ─────────────────────────────────────────────

/// Pinned because `resolve` and `throughput` had no call site anywhere in the
/// repo — no test, no script, no doc — and so nothing establishing that they
/// parse at all. The rest are here to make this the one list of what did not
/// move, rather than leaving that only implicit in the groups above.
#[test]
fn unmoved_reads_still_parse() {
    assert!(matches!(parse(&["node-info"]), Command::NodeInfo));
    assert!(matches!(parse(&["routes"]), Command::Routes));
    assert!(matches!(parse(&["keepalive"]), Command::Keepalive));
    assert!(matches!(parse(&["throughput"]), Command::Throughput));
    assert!(matches!(parse(&["metrics"]), Command::Metrics));
    assert!(matches!(parse(&["logs"]), Command::Logs { .. }));
    assert!(matches!(
        parse(&["resolve", "02:00:00:00:00:09"]),
        Command::Resolve { .. }
    ));
}
