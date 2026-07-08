//! Thin `clap` front end over the `wayfinderctl` library.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use clap::Parser;
use tracing_subscriber::EnvFilter;
use wayfinderctl::{Cli, run};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Without this, `tracing`'s default no-op dispatcher silently drops
    // every `warn!`/`error!` the library emits (e.g. `wayfinder_driver`'s
    // schema generation flagging a malformed third-party link schema) —
    // `wayfinderctl` would appear to succeed while a real problem went
    // unreported. Defaults to `warn` so routine query output on stdout stays
    // uncluttered; set `RUST_LOG` for more.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();

    run(Cli::parse()).await
}
