//! Client-side adapter bridging the mesh Ed25519 identity to rustls **raw
//! public keys** (RFC 7250) for connecting to a node's management API.
//!
//! The shared bridge — presenting our own identity key, recovering a peer's —
//! is [`wayfinder_tls_mgmt`]; this module builds on it to pin the node we're
//! connecting to. The server-side counterpart (`server_config`'s twin) lives in
//! `wayfinder-server` instead of here, so neither management-TLS crate depends
//! on the other.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{AlwaysResolvesClientRawPublicKeys, ClientConfig};
use rustls::crypto::{WebPkiSupportedAlgorithms, ring};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use wayfinder_tls_mgmt::{
    certified_key_from_seed, raw_ed25519_from_spki, verify_raw_key_signature,
};

/// Client-side verifier for the server's **raw public key** (RFC 7250).
///
/// The management client knows which node it is talking to, so it pins the
/// node's expected Ed25519 key: the handshake fails unless the server presents
/// exactly that key. This is what stops a man-in-the-middle from impersonating
/// the node (during bootstrap the client is provisioning that very key, so it
/// knows it a priori).
#[derive(Debug)]
struct RawKeyServerVerifier {
    expected_server_key: [u8; 32],
    supported_algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for RawKeyServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let presented = raw_ed25519_from_spki(end_entity.as_ref()).ok_or_else(|| {
            rustls::Error::General("server presented a non-Ed25519 raw key".into())
        })?;
        if presented != self.expected_server_key {
            return Err(rustls::Error::General(
                "server raw public key does not match the pinned node key".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "TLS 1.2 is not supported by the management API".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_raw_key_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// Build the client-side rustls config for the management API: TLS 1.3 only,
/// presenting `own_seed`'s key as a raw public key and pinning the server to
/// `expected_server_key` (the node's known identity key). `ring` provider.
pub(crate) fn client_config(
    own_seed: &[u8; 32],
    expected_server_key: &[u8; 32],
) -> Result<Arc<ClientConfig>, rustls::Error> {
    let certified = certified_key_from_seed(own_seed)?;
    let provider = Arc::new(ring::default_provider());
    let verifier = Arc::new(RawKeyServerVerifier {
        expected_server_key: *expected_server_key,
        supported_algs: provider.signature_verification_algorithms,
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(certified)));
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{ClientConnection, ServerConnection};
    use wayfinder_auth::Keypair;
    use wayfinder_server::server_config;

    /// Pump TLS records between an in-memory client and server until both finish
    /// handshaking (or a verifier rejects, surfaced as `Err`).
    fn drive(
        client: &mut ClientConnection,
        server: &mut ServerConnection,
    ) -> Result<(), rustls::Error> {
        for _ in 0..16 {
            let mut to_server = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut to_server).unwrap();
            }
            let mut rd = to_server.as_slice();
            while !rd.is_empty() {
                server.read_tls(&mut rd).unwrap();
            }
            server.process_new_packets()?;

            let mut to_client = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut to_client).unwrap();
            }
            let mut rd = to_client.as_slice();
            while !rd.is_empty() {
                client.read_tls(&mut rd).unwrap();
            }
            client.process_new_packets()?;

            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        Ok(())
    }

    /// The client pins the server's key: a node presenting a different key than
    /// the one the client expects fails the handshake (anti-impersonation).
    /// Exercised against the production `wayfinder-server::server_config` (a
    /// dev-dependency of this crate) so the pinning behaviour under test is the
    /// real cross-crate interop, not a stand-in.
    #[test]
    fn client_rejects_server_with_unpinned_key() {
        let server_seed = [11u8; 32];
        let client_seed = [22u8; 32];
        let wrong_key = Keypair::from_seed(&[99u8; 32]).ed_pubkey();

        let mut server = ServerConnection::new(server_config(&server_seed).unwrap()).unwrap();
        let mut client = ClientConnection::new(
            client_config(&client_seed, &wrong_key).unwrap(),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();

        assert!(
            drive(&mut client, &mut server).is_err(),
            "a server key that doesn't match the pin must fail the handshake"
        );
    }
}
