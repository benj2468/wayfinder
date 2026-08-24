//! The address of a node's management API, as an operator writes it.
//!
//! A management endpoint is reached by *name* at least as often as by number —
//! `ca.wayfndr.dev:7700` for the cloud certificate authority — and a
//! [`SocketAddr`] cannot hold one: it parses numerically, so a hostname is
//! rejected before any resolution could happen. [`NodeAddr`] keeps the host
//! *unresolved* (a hostname, an IPv4 literal or an IPv6 literal) alongside the
//! port, and leaves resolution to the moment of connection, where a DNS
//! failure is an ordinary connect error rather than a CLI parse error.
//!
//! Deliberately not used for *bind* addresses: a listener binds to a concrete
//! local address, and accepting a name there would invite a bind to whatever a
//! resolver happened to return.

use std::fmt;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::str::FromStr;

/// A management endpoint written the way an operator writes it: a host that may
/// be a name, plus a port.
///
/// The host is stored **unresolved**. That is the whole point of the type: a
/// name like `ca.wayfndr.dev` has no numeric value at parse time, and pinning
/// one at startup would also freeze it for the life of the process. Resolution
/// happens per connection attempt, inside `TcpStream::connect`.
///
/// Parsed from `host:port` (an IPv6 literal bracketed, `[::1]:7700`). There is
/// no default port: a management API is not on a well-known one, so a bare host
/// is rejected rather than guessed at.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NodeAddr {
    /// The host as written: a DNS name, an IPv4 literal, or an IPv6 literal
    /// *without* brackets (they are display syntax, not part of the address).
    host: String,
    /// The TCP port of the management listener.
    port: u16,
}

impl NodeAddr {
    /// Build an address from an already-separated host and port.
    ///
    /// `host` is taken as written and never validated as a name — anything a
    /// resolver might accept is allowed, and being wrong surfaces as a connect
    /// error. Strip the brackets from an IPv6 literal before calling this.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// The unresolved host: a DNS name or an IP literal, without brackets.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The TCP port of the management listener.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The pair `tokio`'s `ToSocketAddrs` resolves at connect time.
    ///
    /// Exists so every caller reaches a node through the same conversion, and
    /// so no caller is tempted to resolve the host early and hold the result.
    pub fn connect_target(&self) -> (&str, u16) {
        (self.host.as_str(), self.port)
    }
}

impl FromStr for NodeAddr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // A numeric address is authoritative when it parses: it settles the
        // bracketed-IPv6 case and every port edge case in one step.
        if let Ok(socket) = s.parse::<SocketAddr>() {
            return Ok(Self::from(socket));
        }
        let (host, port) = s
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("'{s}' has no port; expected host:port"))?;
        if host.is_empty() {
            anyhow::bail!("'{s}' has no host; expected host:port");
        }
        // Anything left holding a colon is an unbracketed IPv6 literal (a bare
        // `::1:7700` cannot be split into address and port without guessing) —
        // or something stranger. Either way, brackets are the answer.
        if host.contains(':') {
            anyhow::bail!("'{s}' is ambiguous; bracket an IPv6 literal as [addr]:port");
        }
        let port: u16 = port
            .parse()
            .map_err(|_| anyhow::anyhow!("'{port}' in '{s}' is not a port number (0-65535)"))?;
        Ok(Self::new(host, port))
    }
}

impl From<SocketAddr> for NodeAddr {
    fn from(addr: SocketAddr) -> Self {
        Self::new(addr.ip().to_string(), addr.port())
    }
}

impl fmt::Display for NodeAddr {
    /// Renders back into something [`NodeAddr::from_str`] accepts, which means
    /// re-bracketing an IPv6 literal. Used in log lines, error context and the
    /// key under which a client records a node's pinned key, so a round trip
    /// through it has to be lossless.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.parse::<Ipv6Addr>().is_ok() {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_hostname_and_port() {
        let addr: NodeAddr = "ca.wayfndr.dev:7700".parse().unwrap();
        assert_eq!(addr.host(), "ca.wayfndr.dev");
        assert_eq!(addr.port(), 7700);
        assert_eq!(addr.to_string(), "ca.wayfndr.dev:7700");
    }

    #[test]
    fn parses_an_ipv4_literal() {
        let addr: NodeAddr = "127.0.0.1:7700".parse().unwrap();
        assert_eq!(addr.host(), "127.0.0.1");
        assert_eq!(addr.port(), 7700);
        assert_eq!(addr.to_string(), "127.0.0.1:7700");
    }

    #[test]
    fn parses_a_bracketed_ipv6_literal() {
        let addr: NodeAddr = "[::1]:7700".parse().unwrap();
        assert_eq!(addr.host(), "::1");
        assert_eq!(addr.port(), 7700);
        // Re-displayed bracketed, so the round trip parses again.
        assert_eq!(addr.to_string(), "[::1]:7700");
        assert_eq!("[::1]:7700".parse::<NodeAddr>().unwrap(), addr);
    }

    #[test]
    fn rejects_a_missing_port() {
        // A management endpoint has no default port to fall back on, so a bare
        // host is an error rather than a guess.
        assert!("ca.wayfndr.dev".parse::<NodeAddr>().is_err());
        assert!("127.0.0.1".parse::<NodeAddr>().is_err());
    }

    #[test]
    fn rejects_an_unbracketed_ipv6_literal() {
        // `::1:7700` is ambiguous: the trailing group is as much part of the
        // address as it is a port. Requiring brackets is what removes the guess.
        assert!("::1:7700".parse::<NodeAddr>().is_err());
    }

    #[test]
    fn rejects_a_bad_port() {
        assert!("host:".parse::<NodeAddr>().is_err());
        assert!("host:not-a-port".parse::<NodeAddr>().is_err());
        assert!("host:70000".parse::<NodeAddr>().is_err());
    }

    #[test]
    fn rejects_an_empty_host() {
        assert!(":7700".parse::<NodeAddr>().is_err());
        assert!("".parse::<NodeAddr>().is_err());
    }

    #[test]
    fn converts_from_a_socket_addr() {
        let socket: SocketAddr = "10.0.0.4:7700".parse().unwrap();
        let addr = NodeAddr::from(socket);
        assert_eq!(addr.host(), "10.0.0.4");
        assert_eq!(addr.port(), 7700);

        let socket: SocketAddr = "[::1]:7700".parse().unwrap();
        assert_eq!(NodeAddr::from(socket).to_string(), "[::1]:7700");
    }
}
