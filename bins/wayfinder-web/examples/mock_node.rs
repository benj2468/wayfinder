//! Run a stand-in node, so the dashboard can be developed without hardware.
//!
//! Starts the real `wayfinder-server` TLS management listener over canned data
//! and writes the identity seed a client authenticates with to a temporary file,
//! then prints the exact command to point the dashboard at it.
//!
//! ```text
//! cargo run -p wayfinder-web --features mock-node --example mock_node
//! ```
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
    let (addr, node_key) = wayfinder_web::mock::serve_mock_provider_node().await;

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
    println!("  cargo leptos watch -- \\");
    println!("    --addr {addr} \\");
    println!("    --identity {} \\", seed_path.display());
    println!("    --node-key {key_hex}");
    println!();
    println!("then open http://127.0.0.1:8080/  (ctrl-c here to stop the node)");

    std::future::pending::<()>().await;
    Ok(())
}
