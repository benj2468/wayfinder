//! Where a management client connects, and how.

use crate::Client;
use crate::Endpoint;

/// How a client reaches a node: the authenticated TLS management API, or an
/// embedded node's unauthenticated serial port.
///
/// The two transports are not interchangeable in what they prove — TLS
/// authenticates both ends by mesh identity, the serial port trusts the
/// physical link — but they serve the identical request set, so every caller
/// above this point is written once against whichever it was handed.
pub enum ConnectTarget {
    /// The node's TLS management API, with the pinned node key and the client's
    /// identity.
    Tls(Endpoint),
    /// A serial port opened at a fixed baud rate. No TLS and no authentication
    /// — an embedded node's debug management port (e.g. the nRF52840's USB
    /// CDC-ACM port).
    Serial {
        /// The serial device path (e.g. `/dev/ttyACM0`).
        path: String,
        /// The baud rate to open it at.
        baud: u32,
    },
}

impl ConnectTarget {
    /// Open a fresh [`Client`] over this target.
    ///
    /// Called per connection rather than once: a client that reconnects (every
    /// dashboard does, on any failed poll) needs a new stream, and a TLS
    /// endpoint named by hostname re-resolves here, so a node that moves is
    /// followed without a restart.
    pub async fn connect(&self) -> anyhow::Result<Client> {
        match self {
            ConnectTarget::Tls(endpoint) => {
                Client::connect_tls(&endpoint.addr, &endpoint.node_key, &endpoint.identity).await
            }
            ConnectTarget::Serial { path, baud } => Client::connect_serial(path, *baud).await,
        }
    }

    /// A short human-readable label naming what the client is pointed at, so it
    /// is never ambiguous which node is on screen.
    pub fn label(&self) -> String {
        match self {
            ConnectTarget::Tls(endpoint) => endpoint.addr.to_string(),
            ConnectTarget::Serial { path, baud } => format!("{path} @ {baud} baud"),
        }
    }
}
