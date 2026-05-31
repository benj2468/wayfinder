extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::net::Ipv4Addr;
use core::net::SocketAddr;
use serde::{Deserialize, Serialize};

/// A single mesh interface's transport configuration.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum LinkConfig {
    /// Carry the link over UDP, bridging a local bind address to a fixed remote.
    Udp {
        /// Local address the UDP socket binds to.
        bind_addr: SocketAddr,
        /// Remote peer the socket is connected to (send/recv target).
        remote_addr: SocketAddr,
    },
    /// Test Link, used for testing only, will fail validation in real mode
    Test { switch_name: String },
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
    /// IPv4 address assigned to the device.
    pub ip_address: Ipv4Addr,
    /// IPv4 netmask assigned to the device.
    pub netmask: Ipv4Addr,
}

/// Configuration for the local host facing Distribution Mechanism
#[derive(Serialize, Deserialize, Debug)]
pub enum LocalDistributionMechanism {
    Tap { tap: TapConfig },
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
}
