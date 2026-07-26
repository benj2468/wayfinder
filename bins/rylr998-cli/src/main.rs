//! Thin `clap` front end: open the real serial port and dispatch to
//! [`rylr998_cli::run_command`].

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::time::Duration;

use clap::Parser;
use embedded_io_adapters::tokio_1::FromTokio;
use rylr998::RylrClient;
use rylr998_cli::Cli;
use rylr998_cli::run_command;
use tokio_serial::SerialPortBuilderExt;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let stream = tokio_serial::new(&cli.port, cli.baud).open_native_async()?;
    let mut client = RylrClient::new(FromTokio::new(stream))?;
    client.set_timeout(Duration::from_secs(cli.timeout_secs));

    run_command(&mut client, &cli.command).await?;
    Ok(())
}
