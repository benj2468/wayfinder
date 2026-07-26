//! Thin `clap` front end over the `wayfinderctl` library.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use clap::Parser;
use wayfinderctl::Cli;
use wayfinderctl::run;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run(Cli::parse()).await
}
