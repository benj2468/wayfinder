//! Configuration types: the YAML config file schema and CLI arguments.

use core::net::Ipv4Addr;
use std::{net::SocketAddr, path::PathBuf};

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
}

/// Transport over which the management API is exposed.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum ServerConfig {
    /// Connectionless management API over a Unix datagram socket.
    UnixSocket {
        /// Filesystem path the socket is bound to.
        path: PathBuf,
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

/// Top-level configuration loaded from the YAML config file.
#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    /// The local host-facing TAP device.
    pub(crate) tap: TapConfig,
    /// The mesh interfaces this node participates on.
    #[serde(default)]
    pub(crate) links: Vec<LinkConfig>,
    /// Optional management-API server.
    #[serde(default)]
    pub(crate) server: Option<ServerConfig>,
}

/// Command-line arguments.
#[derive(clap::Parser, Debug)]
pub struct Args {
    /// Path to the YAML configuration file.
    #[clap(short, long, default_value = "var/conf/install.yml")]
    pub(crate) config: PathBuf,
}
