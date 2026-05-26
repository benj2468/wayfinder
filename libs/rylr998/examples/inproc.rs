use std::time::Duration;

use anyhow::bail;
use embedded_io_adapters::tokio_1::FromTokio;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio::task::JoinHandle;
use tracing::debug;
use tracing::error;
use tracing::trace;
use tracing::warn;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let (client, server) = tokio::io::duplex(1024);

    let client = rylr998::RylrClient::new(FromTokio::new(client))?;

    let mut server: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        let (reader, mut writer) = tokio::io::split(server);

        let mut buf_reader = BufReader::new(reader);

        let mut buffer = String::new();

        loop {
            let read = buf_reader.read_line(&mut buffer).await?;

            if read == 0 {
                continue;
            }

            let line = buffer.trim();
            if line.is_empty() {
                break;
            }

            trace!("read_line: line={line:?}");

            match line {
                "AT+RESET" => {
                    debug!("Resetting Radio");

                    writer.write_all(b"+RESET\n").await?;
                    writer.flush().await?;

                    tokio::time::sleep(Duration::from_secs(1)).await;

                    writer.write_all(b"+READY\n").await?;
                    writer.flush().await?;

                    debug!("Radio reset complete");
                }
                _ => {
                    warn!("Received unknown command: {line:?}");
                }
            }

            buffer.clear();
        }

        Ok(())
    });

    let mut tester: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        let mut client = client;

        // First lets reset the radio
        client.reset().await?;

        Ok(())
    });

    tokio::select! {
        res = &mut server => {
            bail!("Simulated LORA unexpectedly failed: {res:?}");
        },
        res = &mut tester => {
            res??;
        },
        _ = tokio::signal::ctrl_c() => {
            error!("User interrupted");

            server.abort();
            server.await??;

            tester.abort();
            tester.await??;

            bail!("Shutdown Complete");
        }
    }

    Ok(())
}
