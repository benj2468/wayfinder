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
    /// Default `i_max`: 128 s — quiet in steady state versus the former fixed 10 s.
    const fn default_i_max_ms() -> u64 {
        128_000
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
    /// Carry the link over a REYAX RYLR998/RYLR498 LoRa module attached to a
    /// local serial port (see `libs/rylr998`). LoRa is a shared broadcast
    /// medium; the mesh filters on the embedded `Mac`, not on `address`.
    Rylr998 {
        /// Serial device path the module is attached to (e.g. `/dev/ttyUSB0`).
        device: String,
        /// UART baud rate. Defaults to the module's factory rate (115200).
        #[serde(default = "LinkTransport::default_rylr998_baud_rate")]
        baud_rate: u32,
        /// This node's `AT+ADDRESS` value. Must be distinct from every other
        /// node sharing `network_id` — the fragment reassembler keys on it
        /// (see `libs/rylr998/CLAUDE.md`'s fragmentation deployment note).
        address: u16,
        /// `AT+NETWORKID` group; only modules sharing this ID exchange packets.
        network_id: u8,
        /// LoRa spreading factor (`AT+PARAMETER`'s first field): 5..=11.
        spreading_factor: u8,
        /// RF channel bandwidth in kHz (`AT+PARAMETER`'s second field): 125,
        /// 250, or 500.
        bandwidth_khz: u16,
        /// LoRa coding rate, as the `4/x` denominator (`AT+PARAMETER`'s third
        /// field): 5, 6, 7, or 8.
        coding_rate_denominator: u8,
        /// Programming preamble length (`AT+PARAMETER`'s fourth field).
        preamble: u8,
    },
    /// Test Link, used for testing only, will fail validation in real mode
    Test {
        /// Name of the in-process test `Switch` this link attaches to.
        switch_name: String,
    },
}

impl LinkTransport {
    /// The RYLR998/RYLR498's factory-default UART baud rate.
    fn default_rylr998_baud_rate() -> u32 {
        115_200
    }
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
    /// Optional TAP MTU (the largest L3 payload the host stack may hand us in
    /// one frame).
    ///
    /// When omitted, [`TapConfig::DEFAULT_MTU`] is used: it is deliberately
    /// below 1500 so that a host frame at the MTU, once wrapped in mesh
    /// encapsulation ([`TAP_ENCAP_OVERHEAD`] bytes), still fits inside a
    /// 1500-byte carrier without IP fragmentation or a silent oversize drop.
    /// Raise it only when the mesh links run over a lower-overhead carrier
    /// (e.g. `RawL2`) or a jumbo-frame underlay.
    #[serde(default)]
    pub mtu: Option<u16>,
}

impl TapConfig {
    /// Default IPv4 netmask applied when an [`ip_address`](Self::ip_address) is
    /// configured without an explicit [`netmask`](Self::netmask): a /24.
    pub const DEFAULT_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

    /// Default TAP MTU when [`mtu`](Self::mtu) is unset: `1500` minus the mesh
    /// encapsulation and a conservative underlay allowance ([`TAP_ENCAP_OVERHEAD`]),
    /// so a full-size host frame traverses the mesh without fragmentation.
    pub const DEFAULT_MTU: u16 = 1500 - TAP_ENCAP_OVERHEAD as u16;
}

/// Bytes of encapsulation added to a host L3 payload before it leaves this node
/// over a mesh link, used only to derive [`TapConfig::DEFAULT_MTU`].
///
/// Accounts for, on top of the host L3 payload:
/// - the host Ethernet header carried verbatim with the frame (`14`),
/// - the Wayfinder [`LinkFrame`] header — dst + src + protocol (`14`),
/// - the BATMAN unicast header ([`BatmanUnicastPacket`], `9`),
/// - the pairwise auth trailer present when auth is enabled ([`DIRECTED_TRAILER_LEN`], `24`), and
/// - a conservative allowance for a UDP/IPv4 underlay on a 1500-byte path (`28`).
///
/// The literal is asserted against the real header sizes in the unit tests, so
/// it cannot silently drift if a wire format changes.
///
/// [`LinkFrame`]: crate::interfaces::frame::LinkFrame
/// [`BatmanUnicastPacket`]: batman::wire::BatmanUnicastPacket
/// [`DIRECTED_TRAILER_LEN`]: crate::auth::DIRECTED_TRAILER_LEN
pub const TAP_ENCAP_OVERHEAD: usize = 14 + 14 + 9 + 24 + 28;

/// Configuration for the local host facing Distribution Mechanism
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum LocalDistributionMechanism {
    /// Bridge the mesh onto a host TAP device (see [`TapConfig`]).
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
    /// Fail closed: when `true`, the router stays inert on the mesh (see
    /// [`CentralRouter::auth_locked`](crate::CentralRouter::auth_locked)) —
    /// processing, forwarding, delivering, and emitting nothing — until a
    /// valid membership cert is installed, whether via a startup `auth:`
    /// block or a later runtime `set-auth`. Defaults to `false`, preserving
    /// the historical behavior where a node with no cert yet still routes in
    /// the open, unauthenticated mode.
    #[serde(default)]
    pub require_auth: bool,
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
    /// When `true`, an incoming CSR is parked as *pending* until an operator
    /// approves it (`wayfinderctl csr approve`), rather than being signed on
    /// submission.  Defaults to `false` (open/token-gated enrollment).
    #[serde(default)]
    pub require_approval: bool,
    /// How long a held CSR (pending, approved-but-uncollected, or a denial
    /// tombstone) survives before it is evicted, in seconds.  Eviction bounds
    /// the held-CSR table and frees a MAC for a fresh request after a stale one
    /// times out.  Defaults to one hour — long enough for a human operator to
    /// approve, short enough to keep the table small.
    #[serde(default = "default_pending_ttl_secs")]
    pub pending_ttl_secs: u64,
    /// Path to a JSON snapshot file for the authority's durable state — the
    /// issued-certificate log (with revocation status) and the held-CSR
    /// store — so the impersonation guard, revocations, and pending
    /// operator approvals all survive a restart. When absent, state is
    /// in-memory only and a restart clears it. A corrupt, foreign, or
    /// newer-than-known snapshot at this path is refused at startup rather
    /// than silently treated as empty.
    #[serde(default)]
    pub state_path: Option<String>,
}

/// Default [`ProviderConfig::pending_ttl_secs`]: one hour.
fn default_pending_ttl_secs() -> u64 {
    3600
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

    /// An explicit `mtu` is parsed; when omitted it is `None` so the binary
    /// applies [`TapConfig::DEFAULT_MTU`].
    #[test]
    fn tap_config_mtu_parses() {
        let with = "\
local_egress:
  type: Tap
  device_name: wayfinder0
  mtu: 1280
";
        let Some(LocalDistributionMechanism::Tap(tap)) =
            serde_yaml::from_str::<Config>(with).unwrap().local_egress
        else {
            panic!("expected a TAP egress");
        };
        assert_eq!(tap.mtu, Some(1280));

        let without = "\
local_egress:
  type: Tap
  device_name: wayfinder0
";
        let Some(LocalDistributionMechanism::Tap(tap)) = serde_yaml::from_str::<Config>(without)
            .unwrap()
            .local_egress
        else {
            panic!("expected a TAP egress");
        };
        assert_eq!(tap.mtu, None);
    }

    /// The default TAP MTU must leave enough headroom that a full host frame,
    /// once wrapped in mesh encapsulation, fits a 1500-byte carrier — and the
    /// overhead literal must match the real header sizes so it can't drift.
    #[test]
    fn default_tap_mtu_leaves_encap_headroom() {
        use crate::auth::DIRECTED_TRAILER_LEN;
        use batman::wire::BatmanUnicastPacket;

        // Host Ethernet header (14) + LinkFrame header (14) + BATMAN unicast
        // header + auth trailer + a UDP/IPv4 underlay allowance (28).
        let real_overhead =
            14 + 14 + core::mem::size_of::<BatmanUnicastPacket>() + DIRECTED_TRAILER_LEN + 28;
        assert_eq!(
            TAP_ENCAP_OVERHEAD, real_overhead,
            "TAP_ENCAP_OVERHEAD drifted from the real wire header sizes"
        );

        // A host frame at the default MTU, fully wrapped, fits a 1500 carrier.
        const {
            assert!(TapConfig::DEFAULT_MTU as usize + TAP_ENCAP_OVERHEAD <= 1500);
            // And it must comfortably exceed the IPv6 minimum so the link is usable.
            assert!(TapConfig::DEFAULT_MTU >= 1280);
        }
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

    /// `require_auth` defaults to `false` (open/pre-auth behavior preserved)
    /// when omitted from the config.
    #[test]
    fn require_auth_defaults_to_false() {
        let yaml = "\
local_egress:
  type: Tap
  device_name: wayfinder0
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(!config.require_auth);
    }

    /// An explicit `require_auth: true` parses, so an operator can opt a node
    /// into failing closed (inert until a valid cert is installed).
    #[test]
    fn require_auth_true_parses() {
        let yaml = "\
local_egress:
  type: Tap
  device_name: wayfinder0
require_auth: true
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.require_auth);
    }

    /// A `Rylr998` link transport parses its serial/radio parameters, and
    /// `baud_rate` defaults to the module's factory rate when omitted.
    #[test]
    fn rylr998_link_transport_parses_with_default_baud_rate() {
        let yaml = "\
type: Rylr998
device: /dev/ttyUSB0
address: 1
network_id: 18
spreading_factor: 7
bandwidth_khz: 125
coding_rate_denominator: 5
preamble: 15
";
        let link: LinkConfig = serde_yaml::from_str(yaml).unwrap();
        let LinkTransport::Rylr998 {
            device,
            baud_rate,
            address,
            network_id,
            spreading_factor,
            bandwidth_khz,
            coding_rate_denominator,
            preamble,
        } = link.transport
        else {
            panic!("expected a Rylr998 link transport");
        };
        assert_eq!(device, "/dev/ttyUSB0");
        assert_eq!(baud_rate, 115_200);
        assert_eq!(address, 1);
        assert_eq!(network_id, 18);
        assert_eq!(spreading_factor, 7);
        assert_eq!(bandwidth_khz, 125);
        assert_eq!(coding_rate_denominator, 5);
        assert_eq!(preamble, 15);
    }

    /// An explicit `baud_rate` overrides the factory-rate default.
    #[test]
    fn rylr998_link_transport_parses_explicit_baud_rate() {
        let yaml = "\
type: Rylr998
device: /dev/ttyUSB0
baud_rate: 57600
address: 1
network_id: 18
spreading_factor: 7
bandwidth_khz: 125
coding_rate_denominator: 5
preamble: 15
";
        let link: LinkConfig = serde_yaml::from_str(yaml).unwrap();
        let LinkTransport::Rylr998 { baud_rate, .. } = link.transport else {
            panic!("expected a Rylr998 link transport");
        };
        assert_eq!(baud_rate, 57_600);
    }
}
