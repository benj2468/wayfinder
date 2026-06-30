//! `wayfinderctl` — a command-line client for the Wayfinder management API.
//!
//! Two families of subcommands:
//! * **Query** commands open a [`wayfinder_client::Client`] to a running node
//!   (TCP or Unix-datagram) and print one management-API response.
//! * **`cert`** commands run entirely offline, minting the seed / certificate /
//!   trust-anchor files a node loads to join an authenticated mesh.
//!
//! The library surface exists so the renderers and the cert tooling can be unit-
//! tested; `main.rs` is a thin `clap` front end over [`run`].

pub mod cert;
pub mod output;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use wayfinder_auth::Keypair;
use wayfinder_client::{Client, ConnectTarget};

use crate::output::OutputFormat;

/// Top-level command-line interface.
#[derive(Parser, Debug)]
#[command(
    name = "wayfinder-ctl",
    version,
    about = "Command-line client for the Wayfinder management API"
)]
pub struct Cli {
    /// Management-API endpoint: an `IP:port` (TCP) or a `unix:`/filesystem path
    /// (Unix datagram).  Ignored by the offline `cert` subcommands.
    #[arg(
        long,
        short = 'c',
        global = true,
        env = "WAYFINDERCTL_CONNECT",
        default_value = "127.0.0.1:7700"
    )]
    pub connect: String,

    /// Output format for query commands.
    #[arg(long, short = 'o', global = true, default_value = "human")]
    pub output: OutputFormat,

    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Every `wayfinderctl` subcommand.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Basic identity and capacity of the node.
    NodeInfo,
    /// The BATMAN originator (routing) table.
    Routes,
    /// The per-(neighbor, interface) link-quality table.
    Links,
    /// The per-interface adaptive OGM emission schedule.
    OgmSchedule,
    /// Per-interface and node-wide throughput estimates.
    Throughput,
    /// Aggregate node health and topology metrics.
    Metrics,
    /// Mesh authentication / security posture: auth on/off, the mesh and
    /// own-cert header, and per-originator verified / expiry / revoked state.
    Security,
    /// Resolve the next hop and egress interface for a destination.
    Resolve {
        /// Destination identifier: a MAC like `02:00:00:00:00:09`, or raw hex.
        dest: String,
    },
    /// Store authenticate data into the application
    SetAuth {
        /// Seed for the node
        seed: PathBuf,
        /// Certificate for the node, signed by the CA
        cert: PathBuf,
        /// Trust anchor of the CA
        trust_anchor: PathBuf,
    },
    /// Enroll with a provider: generate a keypair, submit a CSR, and write the
    /// returned certificate and trust anchor (online enrollment).
    Enroll {
        /// This node's MAC, bound into the issued certificate.
        #[arg(long)]
        mac: String,
        /// Enrollment token, if the provider requires one.
        #[arg(long, default_value = "")]
        token: String,
        /// Where to write the generated 32-byte identity seed (secret).
        #[arg(long)]
        out_seed: PathBuf,
        /// Where to write the issued certificate.
        #[arg(long)]
        out_cert: PathBuf,
        /// Where to write the mesh trust anchor.
        #[arg(long)]
        out_anchor: PathBuf,
    },
    /// Revoke a node from the mesh (talks to a provider node).
    Revoke {
        /// MAC of the node to revoke.
        #[arg(long)]
        mac: String,
    },
    /// List the certificates a provider node has issued.
    ListCerts,
    /// Offline certificate / trust-anchor tooling (no node connection).
    #[command(subcommand)]
    Cert(cert::CertCommand),
}

/// Run the parsed CLI: dispatch offline `cert` work synchronously, else open a
/// client, service one query, and print the rendered result.
pub async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Cert(cmd) => cert::run(cmd),
        other => {
            let rendered = run_query(other, &cli.connect, cli.output).await?;
            println!("{rendered}");
            Ok(())
        }
    }
}

/// Open a client to `connect`, issue one query `command`, and return the
/// rendered response (so callers/tests can print or assert it).  `command` must
/// not be [`Command::Cert`], which is handled offline by [`run`].
pub async fn run_query(
    command: Command,
    connect: &str,
    output: OutputFormat,
) -> anyhow::Result<String> {
    let target: ConnectTarget = connect
        .parse()
        .with_context(|| format!("parsing --connect target '{connect}'"))?;
    let mut client = Client::connect(&target).await?;

    Ok(match command {
        Command::NodeInfo => output::node_info(&client.node_info().await?, output)?,
        Command::Routes => output::routing_table(&client.routing_table().await?, output)?,
        Command::Links => output::link_quality_table(&client.link_quality_table().await?, output)?,
        Command::OgmSchedule => output::ogm_schedule(&client.ogm_schedule().await?, output)?,
        Command::Throughput => output::throughput(&client.throughput().await?, output)?,
        Command::Metrics => output::node_metrics(&client.node_metrics().await?, output)?,
        Command::Security => output::security(&client.security_status().await?, output)?,
        Command::Resolve { dest } => {
            let id = parse_id(&dest)?;
            output::resolve(&client.resolve_route(id).await?, output)?
        }
        Command::SetAuth {
            seed,
            cert,
            trust_anchor,
        } => {
            client
                .set_auth(
                    &std::fs::read(&seed)?,
                    &std::fs::read(&cert)?,
                    &std::fs::read(&trust_anchor)?,
                )
                .await
                .context("failed to set auth")?;
            "auth updated".to_string()
        }
        Command::Enroll {
            mac,
            token,
            out_seed,
            out_cert,
            out_anchor,
        } => {
            let seed: [u8; 32] = rand::random();
            let kp = Keypair::from_seed(&seed);
            let mac_bytes = parse_mac6(&mac)?;
            let resp = client
                .submit_csr(&mac_bytes, &kp.ed_pubkey(), &kp.x_pubkey(), &token)
                .await
                .context("enrollment (submit_csr) failed")?;
            cert::write_secret(&out_seed, &seed)?;
            std::fs::write(&out_cert, &resp.cert)
                .with_context(|| format!("writing certificate to {}", out_cert.display()))?;
            std::fs::write(&out_anchor, &resp.trust_anchor)
                .with_context(|| format!("writing trust anchor to {}", out_anchor.display()))?;
            format!("enrolled {mac}: wrote seed, certificate, and trust anchor")
        }
        Command::Revoke { mac } => {
            let mac_bytes = parse_mac6(&mac)?;
            client
                .revoke_node(&mac_bytes)
                .await
                .context("revocation failed")?;
            format!("revoked {mac}")
        }
        Command::ListCerts => output::list_certs(&client.list_certs().await?, output)?,
        Command::Cert(_) => unreachable!("cert is dispatched before run_query"),
    })
}

/// Parse a node identifier from `s`: a colon-delimited MAC
/// (`02:00:00:00:00:09`) or a bare hex string (`020000000009`), into raw bytes.
pub fn parse_id(s: &str) -> anyhow::Result<Vec<u8>> {
    if s.contains(':') {
        s.split(':')
            .map(|byte| u8::from_str_radix(byte, 16))
            .collect::<Result<Vec<u8>, _>>()
            .with_context(|| format!("'{s}' is not a colon-delimited hex identifier"))
    } else {
        if !s.len().is_multiple_of(2) {
            anyhow::bail!("hex identifier '{s}' must have an even number of digits");
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .with_context(|| format!("'{s}' is not a valid hex identifier"))
    }
}

/// Parse a 6-byte MAC from `s` (colon-delimited or bare hex), erroring if it is
/// not exactly six bytes.
pub fn parse_mac6(s: &str) -> anyhow::Result<[u8; 6]> {
    let bytes = parse_id(s)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("'{s}' must be a 6-byte MAC, got {} bytes", bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_id_colon_mac() {
        assert_eq!(
            parse_id("02:00:00:00:00:09").unwrap(),
            vec![0x02, 0, 0, 0, 0, 9]
        );
    }

    #[test]
    fn parse_id_bare_even_hex() {
        // The previously-inverted guard rejected valid even-length bare hex.
        assert_eq!(parse_id("020000000009").unwrap(), vec![0x02, 0, 0, 0, 0, 9]);
        assert_eq!(parse_id("ff00").unwrap(), vec![0xff, 0x00]);
    }

    #[test]
    fn parse_id_bare_odd_hex_rejected() {
        let err = parse_id("abc").unwrap_err().to_string();
        assert!(err.contains("even number"), "got: {err}");
    }

    #[test]
    fn parse_id_non_hex_rejected() {
        assert!(parse_id("zz:00").is_err());
        assert!(parse_id("gggg").is_err());
    }

    #[test]
    fn parse_mac6_requires_six_bytes() {
        assert_eq!(parse_mac6("01:02:03:04:05:06").unwrap(), [1, 2, 3, 4, 5, 6]);
        assert!(parse_mac6("01:02:03").is_err());
        assert!(parse_mac6("0102030405").is_err()); // 5 bytes
    }
}
