//! The command-line arguments every management-API client takes.
//!
//! `wayfinderctl` and the TUI reach a node the same way — an address, an
//! identity seed, an optional certificate, a pinned key, or a serial port
//! instead of all of them — and each used to declare that set for itself. Two
//! copies of six arguments drift: a flag renamed on one side, a default changed
//! on the other, and the two clients disagree about what reaching a node means.
//! Declaring them once here makes that impossible, and gives an operator one
//! vocabulary rather than one per binary.
//!
//! Flattened into a binary's own `Parser` with `#[command(flatten)]`, leaving it
//! to add only what is genuinely its own (the TUI's refresh interval, the CLI's
//! subcommand and output format).

use std::path::Path;
use std::path::PathBuf;

use crate::ConnectTarget;
use crate::Endpoint;
use crate::NodeAddr;

/// The connection arguments shared by every management-API client.
///
/// Flatten into a binary's `Parser`:
///
/// ```ignore
/// #[derive(Parser)]
/// struct Args {
///     #[command(flatten)]
///     connection: ConnectArgs,
///     /// ...whatever is genuinely this binary's own
///     #[arg(long, default_value_t = 1000)]
///     interval: u64,
/// }
/// ```
///
/// Every argument is `global`, so it is accepted before or after a subcommand.
/// That matters for `wayfinderctl` (`wayfinderctl routes --connect …` is what an
/// operator types) and costs a binary without subcommands nothing.
#[derive(clap::Args, Debug, Clone)]
pub struct ConnectArgs {
    /// Management-API endpoint: the node's `host:port` TLS listener, where
    /// `host` is a DNS name (`ca.wayfndr.dev:7700`), an IPv4 literal, or a
    /// bracketed IPv6 literal. A name is resolved per connection attempt, not
    /// once at startup, so a node that moves is followed without a restart.
    #[arg(
        long,
        short = 'c',
        global = true,
        env = "WAYFINDER_CONNECT",
        default_value = "127.0.0.1:7700"
    )]
    pub connect: NodeAddr,

    /// Path to this client's 32-byte Ed25519 identity seed (secret), presented
    /// as an RFC 7250 raw public key in the TLS handshake. To bootstrap an
    /// un-enrolled node, point this at the node's own identity seed and omit
    /// `--cert`. Defaults to `/var/lib/wayfinder/identity.seed`.
    //
    // The default is [`ConnectArgs::DEFAULT_IDENTITY_PATH`], applied by
    // [`ConnectArgs::identity_path`] rather than by clap: a caller has to be
    // able to tell "unset" from "set to the default path", because
    // `wayfinderctl` reads an absent identity as "use the stored login
    // session" instead. The doc line above is `--help` text, so it spells the
    // path out rather than naming the constant.
    #[arg(long, global = true, env = "WAYFINDER_IDENTITY")]
    pub identity: Option<PathBuf>,

    /// Path to this client's membership certificate, binding its identity to a
    /// capability. Omit to bootstrap an un-enrolled node (the client then
    /// authenticates by proving the node's own key via `--identity`).
    #[arg(long, global = true, env = "WAYFINDER_CERT")]
    pub cert: Option<PathBuf>,

    /// Address of the node to fetch this client's membership certificate from,
    /// instead of reading one with `--cert`.
    ///
    /// For an operator standing on a node's own host who needs to present that
    /// node's certificate somewhere else — asking the certificate authority for
    /// a VPN credential, say. The node already holds the certificate it
    /// enrolled with, so this asks it over the management API rather than
    /// making the operator run a second enrollment to obtain a copy.
    ///
    /// It changes only the credential presented, never where this client
    /// connects: `--connect` still names the far end. The node named here is
    /// pinned to `--identity`'s own public key and cannot be pointed elsewhere
    /// — a certificate is useful only to the holder of the key it names, so the
    /// node holding a useful one is the node whose seed `--identity` is.
    #[arg(
        long,
        global = true,
        env = "WAYFINDER_CERT_FROM",
        conflicts_with = "cert"
    )]
    pub cert_from: Option<NodeAddr>,

    /// The node's Ed25519 public key (64 hex chars) to pin, so a man-in-the-
    /// middle can't impersonate it. When omitted it defaults to the public key
    /// of `--identity` — correct when bootstrapping a node with its own seed,
    /// but you must pass it explicitly to reach a *different* node.
    #[arg(long, global = true, env = "WAYFINDER_NODE_KEY")]
    pub node_key: Option<String>,

    /// Serial port of an embedded node's *unauthenticated* management API (e.g.
    /// `/dev/ttyACMX` for an nRF52840 over its USB CDC-ACM management port).
    /// The connection carries no TLS or authentication.
    ///
    /// `--identity`/`--cert`/`--node-key` cannot be combined with this (clap
    /// rejects it, since they'd imply a TLS handshake this transport never
    /// performs); `--connect` is simply unused.
    #[arg(long, global = true, conflicts_with_all = ["identity", "cert", "cert_from", "node_key"])]
    pub serial: Option<String>,

    /// Baud rate for `--serial`. An embedded management port is USB CDC-ACM
    /// rather than a real UART, so this is a formality `tokio_serial` requires
    /// to open the port rather than a rate the device enforces — any value
    /// opens it identically.
    #[arg(long, global = true, default_value_t = 115_200)]
    pub baud: u32,
}

impl ConnectArgs {
    /// Where a client looks for its identity seed when `--identity` is not
    /// given: the path `wayfinder-tap` persists a generated management-TLS
    /// identity to, so a client run on the node's own host finds it with no
    /// flags.
    pub const DEFAULT_IDENTITY_PATH: &'static str = "/var/lib/wayfinder/identity.seed";

    /// The identity seed path in force: `--identity`, else
    /// [`DEFAULT_IDENTITY_PATH`](Self::DEFAULT_IDENTITY_PATH).
    pub fn identity_path(&self) -> &Path {
        self.identity
            .as_deref()
            .unwrap_or(Path::new(Self::DEFAULT_IDENTITY_PATH))
    }

    /// Resolve these arguments into the target a client connects over.
    ///
    /// `--serial` wins outright: it names a different transport, not a
    /// different address, and clap has already rejected the TLS credentials
    /// alongside it. Otherwise the seed and certificate are read from disk and
    /// the pin resolved, per [`Endpoint::load`].
    ///
    /// A caller with its own notion of a credential (`wayfinderctl`'s stored
    /// login session) reads the fields directly instead.
    pub fn target(&self) -> anyhow::Result<ConnectTarget> {
        if let Some(path) = &self.serial {
            return Ok(ConnectTarget::Serial {
                path: path.clone(),
                baud: self.baud,
            });
        }
        Ok(ConnectTarget::Tls(Endpoint::load(
            self.connect.clone(),
            self.identity_path(),
            self.cert.as_deref(),
            self.node_key.as_deref(),
        )?))
    }

    /// Resolve these arguments into a connect target, asking the node named by
    /// `--cert-from` for a certificate when one is given.
    ///
    /// The async counterpart to [`target`](Self::target), and what a caller
    /// should reach for by default: it is the same resolution plus the one step
    /// that cannot be done from disk, and it degrades to exactly `target` when
    /// no `--cert-from` was passed. `target` stays for a caller that has no
    /// runtime to await on.
    ///
    /// A serial target is returned untouched: that transport performs no
    /// handshake, so it has no certificate to present, and clap has already
    /// refused the combination.
    pub async fn resolve_target(&self) -> anyhow::Result<ConnectTarget> {
        let mut target = self.target()?;
        if let (ConnectTarget::Tls(endpoint), Some(source)) = (&mut target, &self.cert_from) {
            endpoint.load_cert_from_node(source).await?;
        }
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    /// A parser carrying nothing but the shared arguments, standing in for the
    /// binaries that flatten them.
    #[derive(Parser, Debug)]
    struct Harness {
        /// The arguments under test.
        #[command(flatten)]
        connection: ConnectArgs,
    }

    /// Parse `args` (with a program name prepended) or panic.
    fn parse(args: &[&str]) -> ConnectArgs {
        let mut argv = vec!["harness"];
        argv.extend_from_slice(args);
        Harness::parse_from(argv).connection
    }

    #[test]
    fn the_argument_definitions_are_valid() {
        // clap's own consistency check: duplicate ids, a `conflicts_with` naming
        // an argument that does not exist, and so on. It runs at parse time in
        // debug builds, but only for the paths a test happens to take.
        use clap::CommandFactory;
        Harness::command().debug_assert();
    }

    #[test]
    fn defaults_to_the_local_node() {
        assert_eq!(parse(&[]).connect.to_string(), "127.0.0.1:7700");
    }

    #[test]
    fn accepts_a_hostname_for_the_endpoint() {
        let args = parse(&["--connect", "ca.wayfndr.dev:7700"]);
        assert_eq!(args.connect.host(), "ca.wayfndr.dev");
        assert_eq!(args.connect.port(), 7700);
    }

    #[test]
    fn serial_cannot_be_combined_with_the_tls_credentials() {
        // They would imply a handshake the serial transport never performs, so
        // clap refuses the combination rather than silently ignoring one side.
        for credential in [["--cert", "c"], ["--identity", "i"], ["--node-key", "k"]] {
            let attempt = Harness::try_parse_from([
                "harness",
                "--serial",
                "/dev/ttyACM0",
                credential[0],
                credential[1],
            ]);
            assert!(
                attempt.is_err(),
                "--serial with {} should be rejected",
                credential[0]
            );
        }
    }

    #[test]
    fn the_identity_path_defaults_when_unset() {
        assert_eq!(
            parse(&[]).identity_path(),
            Path::new(ConnectArgs::DEFAULT_IDENTITY_PATH)
        );
        assert_eq!(
            parse(&["--identity", "/tmp/seed"]).identity_path(),
            Path::new("/tmp/seed")
        );
    }

    #[test]
    fn a_serial_port_wins_over_the_tls_endpoint() {
        let target = parse(&["--serial", "/dev/ttyACM0", "--baud", "9600"])
            .target()
            .unwrap();
        match target {
            ConnectTarget::Serial { path, baud } => {
                assert_eq!(path, "/dev/ttyACM0");
                assert_eq!(baud, 9600);
            }
            ConnectTarget::Tls(_) => panic!("--serial should not resolve to a TLS endpoint"),
        }
    }

    #[test]
    fn the_tls_target_pins_the_identitys_own_key_by_default() {
        // The self-key bootstrap: no --node-key, so the pin is the identity's
        // own public key — which is what reaches an un-enrolled node.
        let dir = tempfile::tempdir().unwrap();
        let seed_path = dir.path().join("identity.seed");
        let seed = [7u8; 32];
        std::fs::write(&seed_path, seed).unwrap();

        let target = parse(&[
            "--connect",
            "ca.wayfndr.dev:7700",
            "--identity",
            seed_path.to_str().unwrap(),
        ])
        .target()
        .unwrap();
        match target {
            ConnectTarget::Tls(endpoint) => {
                assert_eq!(endpoint.addr.host(), "ca.wayfndr.dev");
                assert_eq!(
                    endpoint.node_key,
                    wayfinder_auth::Keypair::from_seed(&seed).ed_pubkey()
                );
                assert_eq!(endpoint.identity.seed, seed);
                assert!(endpoint.identity.cert.is_empty(), "no --cert was given");
            }
            ConnectTarget::Serial { .. } => panic!("no --serial was given"),
        }
    }

    /// `--cert-from` names a node to ask for a certificate, in the same
    /// address syntax `--connect` takes.
    #[test]
    fn cert_from_takes_a_node_address() {
        let args = parse(&["--cert-from", "127.0.0.1:7700"]);
        let from = args.cert_from.expect("--cert-from was given");
        assert_eq!(from.host(), "127.0.0.1");
        assert_eq!(from.port(), 7700);
        assert!(parse(&[]).cert_from.is_none(), "opt-in, with no default");
    }

    /// A certificate comes from a file or from a node, never from both: two
    /// sources silently disagreeing about which credential is being presented
    /// is the failure this rules out, and clap rules it out at parse time
    /// rather than by a precedence rule nobody would remember.
    #[test]
    fn cert_from_cannot_be_combined_with_a_cert_file() {
        assert!(
            Harness::try_parse_from(["harness", "--cert", "c", "--cert-from", "127.0.0.1:7700"])
                .is_err()
        );
    }

    /// A serial port performs no handshake, so there is no certificate for it
    /// to present and nothing for `--cert-from` to supply — refused alongside
    /// the other TLS credentials rather than silently ignored.
    #[test]
    fn cert_from_cannot_be_combined_with_a_serial_port() {
        assert!(
            Harness::try_parse_from([
                "harness",
                "--serial",
                "/dev/ttyACM0",
                "--cert-from",
                "127.0.0.1:7700"
            ])
            .is_err()
        );
    }

    #[test]
    fn a_missing_identity_seed_names_the_path_it_looked_at() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.seed");
        // Matched rather than `unwrap_err`ed: `ConnectTarget` is deliberately
        // not `Debug` (an `Endpoint` holds a secret seed), so the failure case
        // has to be named explicitly.
        let error = match parse(&["--identity", missing.to_str().unwrap()]).target() {
            Err(error) => error.to_string(),
            Ok(_) => panic!("a missing identity seed should not resolve to a target"),
        };
        assert!(
            error.contains(missing.to_str().unwrap()),
            "error should name the path it read: {error}"
        );
    }
}
