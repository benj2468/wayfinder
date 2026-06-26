//! Thin `clap` front end over the `wayfinderctl` library.

use clap::Parser;
use wayfinderctl::{Cli, run};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run(Cli::parse()).await
}
