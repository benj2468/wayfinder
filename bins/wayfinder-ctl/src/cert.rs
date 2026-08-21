//! Certificate-authority tooling — the operator-side half of mesh enrollment
//! that needs no running node: a 32-byte identity/root seed, a 156-byte
//! [`MembershipCert`], and a 36-byte [`TrustAnchor`].
//!
//! Everything here writes files on the *operator's* box, never onto a node.
//! Provisioning a node is [`crate::csr`]'s job and goes over the management API
//! (`SetAuth`), because a node may be a board with no filesystem to write to —
//! see the root `CLAUDE.md` rule. So the artifacts below are inputs an operator
//! carries: to `csr install`, or to a `wayfinder-tap` config the operator
//! themselves points at them.

use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::bail;
use clap::Subcommand;
use interfaces::frame::Mac;
use wayfinder_auth::Authority;
use wayfinder_auth::CERT_FLAG_ADMIN;
use wayfinder_auth::CERT_FLAG_USER;
use wayfinder_auth::CERT_FLAG_VIEWER;
use wayfinder_auth::Keypair;
use wayfinder_auth::MembershipCert;
use wayfinder_auth::TrustAnchor;
use wayfinder_protos::wayfinder::v1alpha::SubmitCsrRequest;
use zerocopy::IntoBytes;

use crate::parse_mac6;

/// Length of a serialized [`MembershipCert`] on disk.
const CERT_LEN: usize = core::mem::size_of::<MembershipCert>();

/// Offline certificate-authority and node-identity operations.
#[derive(Subcommand, Debug)]
pub enum CertCommand {
    /// Generate a 32-byte identity seed and print its public keys.
    ///
    /// An operator-side artifact: a `wayfinder-tap` can be pointed at it via
    /// `AuthConfig.seed_path`, but nothing here installs it onto a node — a
    /// node that mints its own identity is enrolled through `csr request`
    /// instead, and never needs this.
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
        /// Also grant the management-administration capability: the holder may
        /// invoke privileged management-API operations (revocation, runtime
        /// reconfiguration, CSR approval), not merely route.
        ///
        /// Required to reach the management API of an *enrolled* node at all —
        /// once a node holds a trust anchor, a plain membership cert is refused
        /// (see `decide_access` in `wayfinder-server`). Grant it to operator
        /// identities and to tooling that manages a node, never to a routine
        /// member whose only job is to carry traffic.
        #[arg(long)]
        admin: bool,
        /// Instead grant the read-only management capability: the holder may
        /// invoke the management API's queries (routing table, link quality,
        /// metrics, logs) and none of its mutations or secrets.
        ///
        /// A capability of its own, not the absence of `--admin`: an ordinary
        /// membership cert reaches nothing on an enrolled node's management
        /// API, which is deliberate, since every node on the mesh holds one.
        /// Mutually exclusive with `--admin`, which subsumes it.
        #[arg(long, conflicts_with = "admin")]
        viewer: bool,
    },

    /// Decode and print a certificate or trust-anchor file.
    Show {
        /// A cert (156 bytes) or trust-anchor (36 bytes) file.
        file: PathBuf,
    },

    /// Sign a certificate for a CSR file, without ever needing the requesting
    /// node's private seed.
    ///
    /// The middle step of enrolling a node that cannot reach the provider over
    /// any network: `csr request` writes the CSR at the node, the file travels
    /// out-of-band (email, a USB stick, a courier), this signs it wherever the
    /// mesh root key lives, and the resulting certificate travels back to
    /// `csr install`. Nothing in that chain needs the two ends to be mutually
    /// reachable — which is the whole point, and what online `enroll` cannot do.
    Approve {
        /// The mesh root seed file (kept secret on the CA host).
        #[arg(long)]
        ca_seed: PathBuf,
        /// Mesh id (decimal, or `0x`-prefixed hex); must match the CA's mesh.
        #[arg(long, value_parser = parse_u32)]
        mesh_id: u32,
        /// The CSR file `csr request` produced at the node.
        #[arg(long)]
        request: PathBuf,
        /// Validity window start (unix seconds).
        #[arg(long)]
        not_before: u64,
        /// Validity window end (unix seconds).
        #[arg(long)]
        not_after: u64,
        /// Where to write the certificate.
        #[arg(long)]
        out_cert: PathBuf,
        /// Grant the management-administration capability. See `cert issue
        /// --admin`.
        #[arg(long)]
        admin: bool,
        /// Grant the read-only management capability. See `cert issue
        /// --viewer`.
        #[arg(long, conflicts_with = "admin")]
        viewer: bool,
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
            admin,
            viewer,
        } => issue(
            &ca_seed, mesh_id, &mac, &node_seed, not_before, not_after, &out_cert, admin, viewer,
        ),
        CertCommand::Show { file } => show(&file),
        CertCommand::Approve {
            ca_seed,
            mesh_id,
            request,
            not_before,
            not_after,
            out_cert,
            admin,
            viewer,
        } => approve(
            &ca_seed, mesh_id, &request, not_before, not_after, &out_cert, admin, viewer,
        ),
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
    admin: bool,
    viewer: bool,
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

    let cert = issue_with_flags(
        &authority,
        mac,
        node.ed_pubkey(),
        node.x_pubkey(),
        not_before,
        not_after,
        admin,
        viewer,
    )?;
    write_cert_with_summary(
        out_cert, &cert, mesh_id, mac, not_before, not_after, admin, viewer,
    )
}

/// Sign a certificate under the correct capability: plain membership, admin,
/// or read-only viewer. Shared by `issue` (which derives `mac`/pubkeys from a
/// node seed it holds) and `approve` (which takes them from a CSR file
/// instead, never seeing that seed).
///
/// Distinct calls rather than a flags argument: a capability is a privilege
/// grant, and the constructor's name is what says so at every call site that
/// has one. `issue_user_cert` also stamps `CERT_FLAG_USER`, which is why the
/// viewer path uses it — a read-only credential is a person's, not a device's.
///
/// `admin` and `viewer` are mutually exclusive: the CLI enforces that with
/// `conflicts_with`, but this is also called directly (tests, and any future
/// caller), so the same rule is checked again here rather than trusted to
/// clap — silently picking one of two conflicting capability grants would be
/// the wrong failure mode for a security-relevant choice.
#[allow(clippy::too_many_arguments)]
fn issue_with_flags(
    authority: &Authority,
    mac: Mac,
    ed_pubkey: [u8; 32],
    x_pubkey: [u8; 32],
    not_before: u64,
    not_after: u64,
    admin: bool,
    viewer: bool,
) -> anyhow::Result<MembershipCert> {
    if admin && viewer {
        bail!("--admin and --viewer are mutually exclusive; a cert cannot carry both");
    }
    Ok(if admin {
        authority.issue_user_cert(mac, ed_pubkey, x_pubkey, not_before, not_after, true)
    } else if viewer {
        authority.issue_user_cert(mac, ed_pubkey, x_pubkey, not_before, not_after, false)
    } else {
        authority.issue_cert(mac, ed_pubkey, x_pubkey, not_before, not_after)
    })
}

/// Write a signed certificate to disk and print the same summary shape
/// `issue`/`approve` both report.
#[allow(clippy::too_many_arguments)]
fn write_cert_with_summary(
    out_cert: &Path,
    cert: &MembershipCert,
    mesh_id: u32,
    mac: Mac,
    not_before: u64,
    not_after: u64,
    admin: bool,
    viewer: bool,
) -> anyhow::Result<()> {
    std::fs::write(out_cert, cert.as_bytes())
        .with_context(|| format!("writing certificate to {}", out_cert.display()))?;
    println!("wrote certificate to {}", out_cert.display());
    println!("  mesh_id:    {mesh_id:#x}");
    println!("  node_mac:   {}", crate::output::format_mac(&mac.0));
    println!("  valid:      [{not_before}, {not_after}] unix");
    // Printed only when set: a line reading "admin: false" on every ordinary
    // cert would train the reader to skip the one line that matters.
    if admin {
        println!("  capability: management-administration (admin)");
    } else if viewer {
        println!("  capability: read-only management (viewer)");
    }
    Ok(())
}

/// Sign a certificate for a `request`-produced CSR file, without ever seeing
/// the requesting node's private seed.
#[allow(clippy::too_many_arguments)]
fn approve(
    ca_seed: &Path,
    mesh_id: u32,
    request: &Path,
    not_before: u64,
    not_after: u64,
    out_cert: &Path,
    admin: bool,
    viewer: bool,
) -> anyhow::Result<()> {
    if not_after <= not_before {
        bail!("--not-after ({not_after}) must be greater than --not-before ({not_before})");
    }
    let bytes =
        std::fs::read(request).with_context(|| format!("reading request {}", request.display()))?;
    let req: SubmitCsrRequest =
        serde_json::from_slice(&bytes).context("request file is not valid JSON")?;

    // `enrollment_token` is meaningful only to a live provider checking it
    // against a configured value; here, the operator's decision to run
    // `approve` at all *is* the authorization, so it is read but never
    // enforced.
    let _ = &req.enrollment_token;

    let mac: [u8; 6] = req
        .node_mac
        .try_into()
        .map_err(|_| anyhow::anyhow!("request node_mac must be exactly 6 bytes"))?;
    let ed_pubkey: [u8; 32] = req
        .ed_pubkey
        .try_into()
        .map_err(|_| anyhow::anyhow!("request ed_pubkey must be exactly 32 bytes"))?;
    let x_pubkey: [u8; 32] = req
        .x_pubkey
        .try_into()
        .map_err(|_| anyhow::anyhow!("request x_pubkey must be exactly 32 bytes"))?;
    let mac = Mac(mac);

    let authority = Authority::from_seed(&read_seed(ca_seed)?, mesh_id);
    let cert = issue_with_flags(
        &authority, mac, ed_pubkey, x_pubkey, not_before, not_after, admin, viewer,
    )?;
    write_cert_with_summary(
        out_cert, &cert, mesh_id, mac, not_before, not_after, admin, viewer,
    )
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
            println!("  capability: {}", describe_flags(cert.flags));
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

/// Render a certificate's signed capability bits for `cert show`.
///
/// Unlike `issue`, which prints a capability line only when there is one to
/// print, `show` prints this unconditionally: someone running `show` is asking
/// what a certificate *is*, and "none (routing membership only)" is the answer
/// most worth being explicit about — it is what an ordinary node holds, and it
/// is what reaches nothing on an enrolled node's management API.
fn describe_flags(flags: u8) -> String {
    let mut parts = Vec::new();
    if flags & CERT_FLAG_ADMIN != 0 {
        parts.push("management-administration (admin)");
    }
    if flags & CERT_FLAG_VIEWER != 0 {
        parts.push("read-only management (viewer)");
    }
    if flags & CERT_FLAG_USER != 0 {
        parts.push("user session, not a device");
    }
    if parts.is_empty() {
        return "none (routing membership only)".into();
    }
    parts.join(", ")
}

/// Read and parse a membership certificate file.
///
/// `pub(crate)` because both installs go through it — the offline one copying
/// files into place, and `csr install` sending the same bytes over the wire —
/// so a file that is not a certificate is refused identically by either, before
/// anything has been written or transmitted.
pub(crate) fn read_cert(path: &Path) -> anyhow::Result<MembershipCert> {
    let bytes = std::fs::read(path).with_context(|| format!("reading cert {}", path.display()))?;
    MembershipCert::from_bytes(&bytes).ok_or_else(|| {
        anyhow::anyhow!(
            "cert {} is not a valid {CERT_LEN}-byte membership certificate",
            path.display()
        )
    })
}

/// Read and parse a trust-anchor file.  See [`read_cert`] for why it is shared.
pub(crate) fn read_trust_anchor(path: &Path) -> anyhow::Result<TrustAnchor> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading trust anchor {}", path.display()))?;
    TrustAnchor::from_bytes(&bytes)
        .ok_or_else(|| anyhow::anyhow!("{} is not a valid trust anchor", path.display()))
}

/// Refuse a certificate and trust anchor that describe different meshes.
///
/// The pair is installed together and the node verifies one against the other,
/// so a mismatch here is a node that would come up unable to validate its own
/// certificate — worth catching while the operator still has both filenames in
/// front of them.
pub(crate) fn check_mesh_match(cert: &MembershipCert, anchor: &TrustAnchor) -> anyhow::Result<()> {
    if cert.mesh_id.get() != anchor.mesh_id {
        bail!(
            "cert mesh_id {:#x} does not match trust anchor mesh_id {:#x}",
            cert.mesh_id.get(),
            anchor.mesh_id
        );
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

    /// `approve` consuming a CSR file must sign exactly the same certificate
    /// `issue` would for equivalent inputs — the whole point of factoring both
    /// onto one issuance path.
    ///
    /// The CSR is built here from the node's public keys alone, which is the
    /// shape `csr request` delivers: an operator carrying a request to the CA
    /// holds the node's public halves and nothing else. `issue`, which needs
    /// the private seed, is the comparison — so this pins that the key-only
    /// path loses nothing.
    #[test]
    fn approve_matches_issue_for_equivalent_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let ca_seed_path = dir.path().join("ca.seed");
        write_secret(&ca_seed_path, &[7u8; 32]).unwrap();
        let node_seed_path = dir.path().join("node.seed");
        write_secret(&node_seed_path, &[9u8; 32]).unwrap();

        let out_cert_issue = dir.path().join("issue.cert");
        issue(
            &ca_seed_path,
            42,
            &None,
            &node_seed_path,
            0,
            1000,
            &out_cert_issue,
            false,
            false,
        )
        .unwrap();

        let node = Keypair::from_seed(&read_seed(&node_seed_path).unwrap());
        let out_request = dir.path().join("req.json");
        std::fs::write(
            &out_request,
            serde_json::to_vec(&SubmitCsrRequest {
                node_mac: node.derived_mac().0.to_vec(),
                ed_pubkey: node.ed_pubkey().to_vec(),
                x_pubkey: node.x_pubkey().to_vec(),
                enrollment_token: String::new(),
            })
            .unwrap(),
        )
        .unwrap();

        let out_cert_approve = dir.path().join("approve.cert");
        approve(
            &ca_seed_path,
            42,
            &out_request,
            0,
            1000,
            &out_cert_approve,
            false,
            false,
        )
        .unwrap();

        assert_eq!(
            std::fs::read(&out_cert_issue).unwrap(),
            std::fs::read(&out_cert_approve).unwrap()
        );
    }

    /// The same equivalence holds with `--admin`/`--viewer` set: `approve`'s
    /// own threading of those flags into `issue_with_flags` is otherwise
    /// unexercised, since every other `approve` test above leaves both false.
    #[test]
    fn approve_matches_issue_for_admin_and_viewer_capabilities() {
        for (admin, viewer) in [(true, false), (false, true)] {
            let dir = tempfile::tempdir().unwrap();
            let ca_seed_path = dir.path().join("ca.seed");
            write_secret(&ca_seed_path, &[7u8; 32]).unwrap();
            let node_seed_path = dir.path().join("node.seed");
            write_secret(&node_seed_path, &[9u8; 32]).unwrap();

            let out_cert_issue = dir.path().join("issue.cert");
            issue(
                &ca_seed_path,
                42,
                &None,
                &node_seed_path,
                0,
                1000,
                &out_cert_issue,
                admin,
                viewer,
            )
            .unwrap();

            let node = Keypair::from_seed(&read_seed(&node_seed_path).unwrap());
            let out_request = dir.path().join("req.json");
            std::fs::write(
                &out_request,
                serde_json::to_vec(&SubmitCsrRequest {
                    node_mac: node.derived_mac().0.to_vec(),
                    ed_pubkey: node.ed_pubkey().to_vec(),
                    x_pubkey: node.x_pubkey().to_vec(),
                    enrollment_token: String::new(),
                })
                .unwrap(),
            )
            .unwrap();

            let out_cert_approve = dir.path().join("approve.cert");
            approve(
                &ca_seed_path,
                42,
                &out_request,
                0,
                1000,
                &out_cert_approve,
                admin,
                viewer,
            )
            .unwrap();

            assert_eq!(
                std::fs::read(&out_cert_issue).unwrap(),
                std::fs::read(&out_cert_approve).unwrap(),
                "admin={admin} viewer={viewer}"
            );
        }
    }

    /// `--admin` and `--viewer` together must be rejected, not silently
    /// resolved to one of the two: `conflicts_with` stops this at the CLI
    /// layer, but `issue`/`approve` are also reachable directly (as this test
    /// does), so the same rule has to hold below clap too.
    #[test]
    fn issue_rejects_admin_and_viewer_together() {
        let dir = tempfile::tempdir().unwrap();
        let ca_seed_path = dir.path().join("ca.seed");
        write_secret(&ca_seed_path, &[1u8; 32]).unwrap();
        let node_seed_path = dir.path().join("node.seed");
        write_secret(&node_seed_path, &[2u8; 32]).unwrap();

        let err = issue(
            &ca_seed_path,
            42,
            &None,
            &node_seed_path,
            0,
            1000,
            &dir.path().join("out.cert"),
            true,
            true,
        )
        .unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"), "got: {err}");
    }

    /// The same rule holds for `approve`, the CSR-file path into the same
    /// shared `issue_with_flags` helper.
    #[test]
    fn approve_rejects_admin_and_viewer_together() {
        let dir = tempfile::tempdir().unwrap();
        let ca_seed_path = dir.path().join("ca.seed");
        write_secret(&ca_seed_path, &[1u8; 32]).unwrap();

        let request = SubmitCsrRequest {
            node_mac: vec![0, 0, 0, 0, 0, 5],
            ed_pubkey: vec![0u8; 32],
            x_pubkey: vec![0u8; 32],
            enrollment_token: String::new(),
        };
        let req_path = dir.path().join("req.json");
        std::fs::write(&req_path, serde_json::to_vec(&request).unwrap()).unwrap();

        let err = approve(
            &ca_seed_path,
            42,
            &req_path,
            0,
            1000,
            &dir.path().join("out.cert"),
            true,
            true,
        )
        .unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"), "got: {err}");
    }

    /// A CSR file with a malformed (wrong-length) field is rejected with a
    /// clear error rather than panicking on a failed slice conversion.
    #[test]
    fn approve_rejects_malformed_request() {
        let dir = tempfile::tempdir().unwrap();
        let ca_seed_path = dir.path().join("ca.seed");
        write_secret(&ca_seed_path, &[1u8; 32]).unwrap();

        let bad_request = SubmitCsrRequest {
            node_mac: vec![1, 2, 3],
            ed_pubkey: vec![0u8; 32],
            x_pubkey: vec![0u8; 32],
            enrollment_token: String::new(),
        };
        let req_path = dir.path().join("bad.json");
        std::fs::write(&req_path, serde_json::to_vec(&bad_request).unwrap()).unwrap();

        let out_cert = dir.path().join("out.cert");
        let err = approve(
            &ca_seed_path,
            1,
            &req_path,
            0,
            1000,
            &out_cert,
            false,
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("mac"), "got: {err}");
    }

    /// A file that is not a certificate is refused by length rather than
    /// reinterpreted. `csr install` sends these bytes to a node, so a swapped
    /// `--cert`/`--trust-anchor` pair must be caught here — before anything is
    /// transmitted — not diagnosed from a remote rejection.
    #[test]
    fn read_cert_rejects_a_wrong_length_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-cert");
        std::fs::write(&path, [0u8; 12]).unwrap();

        let err = read_cert(&path).unwrap_err();
        assert!(
            err.to_string().contains("membership certificate"),
            "got: {err}"
        );
    }

    /// The same for a trust anchor, which is the other half of the pair an
    /// install sends and the easier of the two to pass in the wrong slot.
    #[test]
    fn read_trust_anchor_rejects_a_wrong_length_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-an-anchor");
        std::fs::write(&path, [0u8; 12]).unwrap();

        let err = read_trust_anchor(&path).unwrap_err();
        assert!(err.to_string().contains("trust anchor"), "got: {err}");
    }

    /// A certificate and anchor from *different* meshes are individually
    /// well-formed, so nothing but this cross-check catches them. Installed as
    /// a pair they would leave a node unable to verify its own certificate.
    #[test]
    fn check_mesh_match_rejects_a_cross_mesh_pair() {
        let ours = Authority::from_seed(&[1u8; 32], 0xABCD);
        let theirs = Authority::from_seed(&[2u8; 32], 0xBEEF);
        let node = Keypair::from_seed(&[9u8; 32]);
        let cert = ours.issue_cert(
            node.derived_mac(),
            node.ed_pubkey(),
            node.x_pubkey(),
            0,
            1000,
        );

        let err = check_mesh_match(&cert, &theirs.trust_anchor()).unwrap_err();
        assert!(err.to_string().contains("mesh_id"), "got: {err}");
        check_mesh_match(&cert, &ours.trust_anchor()).expect("a matched pair must pass");
    }
}
