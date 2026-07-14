//! Offline certificate / trust-anchor tooling — the operator-side half of mesh
//! enrollment that needs no running node.  Produces exactly the raw-byte files a
//! `wayfinder-tap` loads via its `AuthConfig` (`seed_path`, `cert_path`,
//! `trust_anchor_path`): a 32-byte identity/root seed, a 156-byte
//! [`MembershipCert`], and a 36-byte [`TrustAnchor`].

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use clap::Subcommand;
use interfaces::frame::Mac;
use wayfinder_auth::{Authority, Keypair, MembershipCert, TrustAnchor};
use zerocopy::IntoBytes;

use crate::parse_mac6;

/// Length of a serialized [`MembershipCert`] on disk.
const CERT_LEN: usize = core::mem::size_of::<MembershipCert>();

/// Offline certificate-authority and node-identity operations.
#[derive(Subcommand, Debug)]
pub enum CertCommand {
    /// Generate a 32-byte node identity seed and print its public keys.  The
    /// seed is the node's `AuthConfig.seed_path` input.
    Keygen {
        /// Where to write the 32-byte seed.
        #[arg(long)]
        out_seed: Option<PathBuf>,
    },

    /// Initialise a mesh certificate authority: take (or generate) a root seed
    /// and write the public trust anchor every member verifies against.
    InitCa {
        /// Mesh id (decimal, or `0x`-prefixed hex).
        #[arg(long, value_parser = parse_u32)]
        mesh_id: u32,
        /// Use an existing 32-byte root seed from this file.
        #[arg(long, conflicts_with = "generate")]
        seed: Option<PathBuf>,
        /// Generate a fresh root seed instead of reading one.
        #[arg(long, requires = "out_seed")]
        generate: bool,
        /// Where to write a generated root seed (with `--generate`).
        #[arg(long)]
        out_seed: Option<PathBuf>,
        /// Where to write the trust anchor.
        #[arg(long)]
        out_anchor: PathBuf,
    },

    /// Issue a membership certificate binding a node MAC to its keys, signed by
    /// the mesh root.
    Issue {
        /// The mesh root seed file (kept secret on the CA host).
        #[arg(long)]
        ca_seed: PathBuf,
        /// Mesh id (decimal, or `0x`-prefixed hex); must match the CA's mesh.
        #[arg(long, value_parser = parse_u32)]
        mesh_id: u32,
        /// The node's MAC, e.g. `02:00:00:00:00:09`. Defaults to the MAC
        /// deterministically derived from `--node-seed` (the same derivation
        /// `wayfinder-tap` applies at startup), so the cert matches the MAC
        /// the node will actually run under; pass this to override that
        /// default.
        #[arg(long)]
        mac: Option<String>,
        /// The node's 32-byte identity seed file (its public keys are bound).
        #[arg(long)]
        node_seed: PathBuf,
        /// Validity window start (unix seconds).
        #[arg(long)]
        not_before: u64,
        /// Validity window end (unix seconds).  Keep it short — expiry is the
        /// passive revocation mechanism.
        #[arg(long)]
        not_after: u64,
        /// Where to write the certificate.
        #[arg(long)]
        out_cert: PathBuf,
    },

    /// Decode and print a certificate or trust-anchor file.
    Show {
        /// A cert (156 bytes) or trust-anchor (36 bytes) file.
        file: PathBuf,
    },
}

/// Run an offline `cert` subcommand.
pub fn run(cmd: CertCommand) -> anyhow::Result<()> {
    match cmd {
        CertCommand::Keygen { out_seed } => keygen(&out_seed),
        CertCommand::InitCa {
            mesh_id,
            seed,
            generate,
            out_seed,
            out_anchor,
        } => init_ca(mesh_id, seed, generate, out_seed, &out_anchor),
        CertCommand::Issue {
            ca_seed,
            mesh_id,
            mac,
            node_seed,
            not_before,
            not_after,
            out_cert,
        } => issue(
            &ca_seed, mesh_id, &mac, &node_seed, not_before, not_after, &out_cert,
        ),
        CertCommand::Show { file } => show(&file),
    }
}

/// Generate and write a node identity seed, printing its public keys.
fn keygen(out_seed: &Option<PathBuf>) -> anyhow::Result<()> {
    let seed: [u8; 32] = rand::random();
    if let Some(out_seed) = out_seed {
        write_secret(out_seed, &seed)?;
        println!("wrote identity seed to {}", out_seed.display());
    }
    let kp = Keypair::from_seed(&seed);
    println!("  ed25519: {}", hex(&kp.ed_pubkey()));
    println!("  x25519:  {}", hex(&kp.x_pubkey()));
    Ok(())
}

/// Build an authority and write its public trust anchor.
fn init_ca(
    mesh_id: u32,
    seed: Option<PathBuf>,
    generate: bool,
    out_seed: Option<PathBuf>,
    out_anchor: &Path,
) -> anyhow::Result<()> {
    let root_seed: [u8; 32] = match (seed, generate) {
        (Some(path), false) => read_seed(&path)?,
        (None, true) => {
            let s: [u8; 32] = rand::random();
            // `requires = "out_seed"` guarantees this is Some.
            #[expect(
                clippy::expect_used,
                reason = "clap's `requires = \"out_seed\"` on --generate guarantees this is Some"
            )]
            let out = out_seed.expect("--generate requires --out-seed");
            write_secret(&out, &s)?;
            println!("wrote root seed to {}", out.display());
            s
        }
        _ => bail!("provide exactly one of --seed <file> or --generate"),
    };

    let authority = Authority::from_seed(&root_seed, mesh_id);
    let anchor = authority.trust_anchor();
    std::fs::write(out_anchor, anchor.to_bytes())
        .with_context(|| format!("writing trust anchor to {}", out_anchor.display()))?;
    println!("wrote trust anchor to {}", out_anchor.display());
    println!("  mesh_id: {:#x}", anchor.mesh_id);
    println!("  root ed25519: {}", hex(&anchor.root_pubkey));
    Ok(())
}

/// Issue a membership certificate for a node.
#[allow(clippy::too_many_arguments)]
fn issue(
    ca_seed: &Path,
    mesh_id: u32,
    mac: &Option<String>,
    node_seed: &Path,
    not_before: u64,
    not_after: u64,
    out_cert: &Path,
) -> anyhow::Result<()> {
    if not_after <= not_before {
        bail!("--not-after ({not_after}) must be greater than --not-before ({not_before})");
    }
    let authority = Authority::from_seed(&read_seed(ca_seed)?, mesh_id);
    let node = Keypair::from_seed(&read_seed(node_seed)?);
    let mac = match mac {
        Some(mac) => Mac(parse_mac6(mac)?),
        None => node.derived_mac(),
    };

    let cert = authority.issue_cert(
        mac,
        node.ed_pubkey(),
        node.x_pubkey(),
        not_before,
        not_after,
    );
    std::fs::write(out_cert, cert.as_bytes())
        .with_context(|| format!("writing certificate to {}", out_cert.display()))?;
    println!("wrote certificate to {}", out_cert.display());
    println!("  mesh_id:    {mesh_id:#x}");
    println!("  node_mac:   {}", crate::output::format_mac(&mac.0));
    println!("  valid:      [{not_before}, {not_after}] unix");
    Ok(())
}

/// Decode a cert or trust-anchor file by length and print its fields.
fn show(file: &Path) -> anyhow::Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    match bytes.len() {
        CERT_LEN => {
            let cert = MembershipCert::from_bytes(&bytes)
                .context("file is not a valid membership cert")?;
            println!("membership certificate ({} bytes)", bytes.len());
            println!("  mesh_id:    {:#x}", cert.mesh_id.get());
            println!(
                "  node_mac:   {}",
                crate::output::format_mac(&cert.node_mac)
            );
            println!("  ed25519:    {}", hex(&cert.ed_pubkey));
            println!("  x25519:     {}", hex(&cert.x_pubkey));
            println!(
                "  valid:      [{}, {}] unix",
                cert.not_before.get(),
                cert.not_after.get()
            );
        }
        _ => {
            let anchor = TrustAnchor::from_bytes(&bytes)
                .context("file is neither a 156-byte cert nor a valid trust anchor")?;
            println!("trust anchor ({} bytes)", bytes.len());
            println!("  mesh_id:      {:#x}", anchor.mesh_id);
            println!("  root ed25519: {}", hex(&anchor.root_pubkey));
        }
    }
    Ok(())
}

/// Read a 32-byte seed file.  `pub(crate)` so `enroll` can reuse an
/// already-written identity seed on a retry instead of minting a new one.
pub(crate) fn read_seed(path: &Path) -> anyhow::Result<[u8; 32]> {
    let bytes = std::fs::read(path).with_context(|| format!("reading seed {}", path.display()))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("seed {} must be exactly 32 bytes", path.display()))
}

/// Write secret key material with owner-only permissions where supported.
pub(crate) fn write_secret(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting permissions on {}", path.display()))?;
    }
    Ok(())
}

/// Lower-case hex of a byte slice.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a `u32` accepting decimal or a `0x`-prefixed hex literal (for mesh ids).
fn parse_u32(s: &str) -> Result<u32, std::num::ParseIntError> {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => s.parse::<u32>(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A truncated/corrupt seed file must surface a clean `Err`, not panic —
    /// `read_seed` is reused on the `enroll` retry path, which reads whatever
    /// is already on disk without knowing in advance that it's well-formed.
    #[test]
    fn read_seed_rejects_wrong_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seed");
        std::fs::write(&path, [0u8; 10]).unwrap();

        let err = read_seed(&path).unwrap_err();
        assert!(err.to_string().contains("32 bytes"), "got: {err}");
    }
}
