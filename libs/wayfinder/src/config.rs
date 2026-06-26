extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;
use core::net::Ipv4Addr;
use core::net::SocketAddr;
use serde::{Deserialize, Serialize};

/// Per-link adaptive OGM emission bounds (Trickle backoff, RFC 6206), supplied
/// at runtime by each link's configuration so a fast LAN link and a slow LoRa
/// link can back off on different schedules.  The emission interval starts at
/// `i_min_ms`, doubles toward `i_max_ms` while the topology is stable, and snaps
/// back to `i_min_ms` whenever the routing view changes.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct TrickleConfig {
    /// Smallest (most aggressive) OGM interval, in milliseconds — the interval
    /// the link resets to on any topology change and the floor of the backoff.
    #[serde(default = "TrickleConfig::default_i_min_ms")]
    pub i_min_ms: u64,
    /// Largest (quietest) OGM interval, in milliseconds — the ceiling the
    /// doubling backoff saturates at while the topology stays stable.
    #[serde(default = "TrickleConfig::default_i_max_ms")]
    pub i_max_ms: u64,
}

impl TrickleConfig {
    /// Default `i_min`: 1 s — quick enough to reconverge promptly after a change.
    const fn default_i_min_ms() -> u64 {
        1_000
    }
    /// Default `i_max`: 64 s — quiet in steady state versus the former fixed 10 s.
    const fn default_i_max_ms() -> u64 {
        64_000
    }
    /// The configured minimum interval as a [`core::time::Duration`].
    pub fn i_min(&self) -> core::time::Duration {
        core::time::Duration::from_millis(self.i_min_ms)
    }
    /// The configured maximum interval as a [`core::time::Duration`].
    pub fn i_max(&self) -> core::time::Duration {
        core::time::Duration::from_millis(self.i_max_ms)
    }
}

impl Default for TrickleConfig {
    fn default() -> Self {
        Self {
            i_min_ms: Self::default_i_min_ms(),
            i_max_ms: Self::default_i_max_ms(),
        }
    }
}

/// A single mesh interface's transport carrier (how its frames cross the wire).
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum LinkTransport {
    /// Carry the link over UDP, bridging a local bind address to a fixed remote.
    Udp {
        /// Local address the UDP socket binds to.
        bind_addr: SocketAddr,
        /// Remote peer the socket is connected to (send/recv target).
        remote_addr: SocketAddr,
    },
    /// Carry the link over a raw IP socket (`AF_INET`/`SOCK_RAW`), point-to-point
    /// like [`Udp`](LinkTransport::Udp) but using an IP protocol number instead
    /// of UDP ports.  Requires `CAP_NET_RAW`.
    RawIp {
        /// Local IP address the raw socket binds to.
        bind_addr: IpAddr,
        /// Remote peer the socket is connected to (send/recv target).
        remote_addr: IpAddr,
        /// IP protocol number carried in the IPv4 header's protocol field
        /// (e.g. a value from the experimental/unassigned range).
        protocol: u8,
    },
    /// Carry the link natively over a raw L2 packet socket (`AF_PACKET`) bound to
    /// a NIC.  Our frames map directly onto Ethernet frames; multi-access, routed
    /// by destination MAC.  Requires `CAP_NET_RAW`.
    RawL2 {
        /// Name of the network interface to bind to (e.g. `"eth0"`).
        interface: String,
        /// EtherType this interface filters received frames on and stamps onto
        /// sent frames.
        ethertype: u16,
    },
    /// Test Link, used for testing only, will fail validation in real mode
    Test { switch_name: String },
}

/// A single mesh interface: its transport carrier plus the per-link OGM backoff
/// bounds.  The `ogm` block is optional in the config and defaults to
/// [`TrickleConfig::default`] when omitted.
#[derive(Serialize, Deserialize, Debug)]
pub struct LinkConfig {
    /// How this link's frames cross the wire.
    #[serde(flatten)]
    pub transport: LinkTransport,
    /// This link's adaptive OGM emission bounds.
    #[serde(default)]
    pub ogm: TrickleConfig,
}

impl LinkConfig {
    /// Build a test link onto the named switch with default OGM bounds.  Keeps
    /// the test harness's link construction terse.
    pub fn test(switch_name: impl Into<String>) -> Self {
        Self {
            transport: LinkTransport::Test {
                switch_name: switch_name.into(),
            },
            ogm: TrickleConfig::default(),
        }
    }
}

/// Transport over which the management API is exposed.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum ServerConfig {
    /// Connectionless management API over a Unix datagram socket.
    UnixSocket {
        /// Filesystem path the socket is bound to.
        path: String,
    },
    /// Stream-based management API over TCP.
    Tcp {
        /// Address the listener binds to.
        addr: SocketAddr,
    },
    /// Connectionless management API over UDP.
    Udp {
        /// Address the socket binds to.
        addr: SocketAddr,
    },
}

/// Configuration for the local host-facing TAP device.
#[derive(Serialize, Deserialize, Debug)]
pub struct TapConfig {
    /// Name of the kernel TAP device to create.
    pub device_name: String,
    /// Optional IPv4 address to assign to the device.
    ///
    /// When omitted, the TAP is brought up without an IPv4 address — the host
    /// is left to assign one itself (e.g. via DHCP or a separate `ip addr`
    /// call), or to operate the interface at L2 only. The mesh itself routes on
    /// MAC addresses and does not require the TAP to be addressed.
    #[serde(default)]
    pub ip_address: Option<Ipv4Addr>,
    /// Optional IPv4 netmask paired with [`ip_address`](Self::ip_address).
    ///
    /// Only meaningful when an `ip_address` is set. Defaults to `255.255.255.0`
    /// (a /24) when an address is given without an explicit netmask, and is
    /// ignored when no address is set.
    #[serde(default)]
    pub netmask: Option<Ipv4Addr>,
}

impl TapConfig {
    /// Default IPv4 netmask applied when an [`ip_address`](Self::ip_address) is
    /// configured without an explicit [`netmask`](Self::netmask): a /24.
    pub const DEFAULT_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
}

/// Configuration for the local host facing Distribution Mechanism
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum LocalDistributionMechanism {
    Tap(TapConfig),
}

/// Opt-in mesh authentication for this node.
///
/// When present, the node loads its cryptographic identity and membership
/// material from these files, signs the OGMs it emits, and drops incoming OGMs
/// that do not verify against the mesh trust anchor — segregating this mesh from
/// others sharing the medium.  When absent, the node runs unauthenticated (the
/// open, pre-auth behavior).  The files are produced by the enrollment portal.
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthConfig {
    /// Path to the node's 32-byte Ed25519 identity seed (raw bytes).  Keep this
    /// secret; it *is* the node's identity.
    pub seed_path: String,
    /// Path to the node's membership certificate (raw `MembershipCert` bytes,
    /// signed by the mesh root).
    pub cert_path: String,
    /// Path to the mesh trust anchor (raw `TrustAnchor` bytes: the mesh id and
    /// root public key the node verifies certificates against).
    pub trust_anchor_path: String,
}

/// Top-level configuration loaded from the YAML config file.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Config {
    /// The local host-facing Distribution Mechanism.
    ///
    /// If not specified, the behavior is based on the implementation.
    /// For example, in test mode it will just be an observable vector
    pub local_egress: Option<LocalDistributionMechanism>,
    /// The mesh interfaces this node participates on.
    #[serde(default)]
    pub links: Vec<LinkConfig>,
    /// Optional management-API server.
    #[serde(default)]
    pub server: Option<ServerConfig>,
    /// Optional opt-in mesh authentication.  Absent ⇒ unauthenticated.
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    /// Optional certificate-authority (provider) mode.  Absent ⇒ the node is a
    /// plain member and rejects enrollment requests.
    #[serde(default)]
    pub provider: Option<ProviderConfig>,
}

/// Enables certificate-authority (provider) mode on a node: it holds the mesh
/// root key and serves enrollment (`SubmitCsr`/`GetTrustAnchor`/`RevokeNode`)
/// over the management API, so members can obtain certificates without the root
/// key ever leaving this node.
#[derive(Serialize, Deserialize, Debug)]
pub struct ProviderConfig {
    /// Path to the mesh root seed (32 raw bytes).  This is the mesh root of
    /// trust — keep it secret and only on the provider.
    pub root_seed_path: String,
    /// The mesh id this authority signs for.
    pub mesh_id: u32,
    /// Validity window length applied to issued certificates, in seconds.  Keep
    /// it short — passive expiry is the primary revocation mechanism.
    pub cert_ttl_secs: u64,
    /// Optional shared enrollment token.  When set, a CSR must present the
    /// matching value; when absent, enrollment is open (TOFU — suitable for
    /// closed or simulated networks).
    #[serde(default)]
    pub enrollment_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full TAP config (address + netmask) round-trips through YAML.
    #[test]
    fn tap_config_with_address_parses() {
        let yaml = "\
local_egress:
  type: Tap
  device_name: wayfinder0
  ip_address: 10.0.0.1
  netmask: 255.255.255.0
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let Some(LocalDistributionMechanism::Tap(tap)) = config.local_egress else {
            panic!("expected a TAP egress");
        };
        assert_eq!(tap.ip_address, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(tap.netmask, Some(Ipv4Addr::new(255, 255, 255, 0)));
    }

    /// The IP/netmask are optional: a TAP config may omit them entirely.
    #[test]
    fn tap_config_without_address_parses() {
        let yaml = "\
local_egress:
  type: Tap
  device_name: wayfinder0
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let Some(LocalDistributionMechanism::Tap(tap)) = config.local_egress else {
            panic!("expected a TAP egress");
        };
        assert_eq!(tap.device_name, "wayfinder0");
        assert_eq!(tap.ip_address, None);
        assert_eq!(tap.netmask, None);
    }

    /// An address may be given without an explicit netmask; the binary falls
    /// back to [`TapConfig::DEFAULT_NETMASK`] in that case.
    #[test]
    fn tap_config_address_without_netmask_parses() {
        let yaml = "\
local_egress:
  type: Tap
  device_name: wayfinder0
  ip_address: 10.0.0.1
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let Some(LocalDistributionMechanism::Tap(tap)) = config.local_egress else {
            panic!("expected a TAP egress");
        };
        assert_eq!(tap.ip_address, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(tap.netmask, None);
        assert_eq!(TapConfig::DEFAULT_NETMASK, Ipv4Addr::new(255, 255, 255, 0));
    }

    /// An `auth` block parses into the cert/seed/anchor paths.
    #[test]
    fn config_with_auth_parses() {
        let yaml = "\
local_egress:
  type: Tap
  device_name: wayfinder0
auth:
  seed_path: /etc/wayfinder/seed
  cert_path: /etc/wayfinder/cert
  trust_anchor_path: /etc/wayfinder/anchor
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let auth = config.auth.expect("auth block present");
        assert_eq!(auth.seed_path, "/etc/wayfinder/seed");
        assert_eq!(auth.cert_path, "/etc/wayfinder/cert");
        assert_eq!(auth.trust_anchor_path, "/etc/wayfinder/anchor");
    }

    /// Auth is optional: a config without an `auth` block leaves it `None`
    /// (the unauthenticated default).
    #[test]
    fn config_without_auth_is_none() {
        let yaml = "\
local_egress:
  type: Tap
  device_name: wayfinder0
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.auth.is_none());
    }
}
