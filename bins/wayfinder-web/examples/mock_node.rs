//! Run a stand-in node, so the dashboard can be developed without hardware.
//!
//! Starts the real `wayfinder-server` TLS management listener over canned data
//! and writes the identity seed a client authenticates with to a temporary file,
//! then prints the exact command to point the dashboard at it.
//!
//! ```text
//! cargo run -p wayfinder-web --features mock-node --example mock_node [FLAVOR]
//! ```
//!
//! `FLAVOR` picks which kind of node to stand in for, since the Security tab
//! looks materially different against each:
//!
//! * `provider` (the default) — a certificate authority: an enrollment policy
//!   and a request waiting to be approved.
//! * `member` — an authenticated plain member, with neither.
//! * `unauthenticated` — mesh authentication switched off, so every identity
//!   field is empty. The flavor with the least on the screen, and the one whose
//!   emptiness the other two never exercise.
//! * `login` — a certificate authority holding two accounts, one administrator
//!   and one read-only, so the dashboard can be run in **login mode**. The only
//!   flavor that exercises the provider scope's other half: every other one
//!   runs on a static credential, which `Viewer::can_administer` treats as an
//!   administrator, so the read-only view is unreachable from them.
//!
//! Leave it running and start the dashboard in another shell with the command
//! it prints. The data is fixed — this exercises layout and wiring, not live
//! behaviour.

#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a dev-tool example"
)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let flavor = std::env::args().nth(1).unwrap_or_else(|| "provider".into());
    let mock = match flavor.as_str() {
        "provider" => wayfinder_web::mock::Mock::provider(),
        "member" => wayfinder_web::mock::Mock::default(),
        "unauthenticated" => wayfinder_web::mock::Mock::unauthenticated(),
        "login" => wayfinder_web::mock::Mock::login_provider(),
        other => {
            anyhow::bail!(
                "unknown flavor {other:?}: expected provider, member, unauthenticated or login"
            )
        }
    };
    let login = flavor == "login";
    let (addr, node_key) = wayfinder_web::mock::serve_mock_node_with(mock).await;

    // The dashboard authenticates by proving a key. Against an un-enrolled node
    // that is the node's own seed, so write it somewhere `--identity` can read.
    let seed_path = std::env::temp_dir().join("wayfinder-mock-node.seed");
    std::fs::write(&seed_path, wayfinder_web::mock::NODE_SEED)?;

    let key_hex: String = node_key.iter().map(|b| format!("{b:02x}")).collect();

    println!("mock node listening on {addr}");
    println!("identity seed written to {}", seed_path.display());
    println!();
    println!("point the dashboard at it with:");
    println!();
    if login {
        // Login mode holds no credential of its own, so neither key can be
        // defaulted from an identity — there is none. This node is its own
        // authority, so both keys are the same one.
        println!("  cargo leptos watch -- \\");
        println!("    --connect {addr} \\");
        println!("    --node-key {key_hex} \\");
        println!("    --provider {addr} \\");
        println!("    --provider-key {key_hex}");
        println!();
        println!(
            "sign in as {} (administrator) or {} (read-only), password {}",
            wayfinder_web::mock::MOCK_ADMIN_USER,
            wayfinder_web::mock::MOCK_VIEWER_USER,
            wayfinder_web::mock::MOCK_PASSWORD,
        );
    } else {
        println!("  cargo leptos watch -- \\");
        println!("    --connect {addr} \\");
        println!("    --identity {} \\", seed_path.display());
        println!("    --node-key {key_hex}");
    }
    println!();
    println!("then open http://127.0.0.1:8080/  (ctrl-c here to stop the node)");

    std::future::pending::<()>().await;
    Ok(())
}
