//! Server-side adapter bridging the mesh Ed25519 identity to rustls **raw
//! public keys** (RFC 7250) for the management API's TLS listener.
//!
//! The shared bridge — presenting our own identity key, recovering a peer's —
//! is [`wayfinder_tls_mgmt`]; this module builds on it to accept a raw-key
//! client at the TLS layer. The client-side counterpart ([`client_config`]'s
//! twin) lives in `wayfinder-client` instead of here, so neither management-TLS
//! crate depends on the other.

use std::sync::Arc;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{WebPkiSupportedAlgorithms, ring};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{AlwaysResolvesServerRawPublicKeys, ServerConfig};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use wayfinder_tls_mgmt::{certified_key_from_seed, verify_raw_key_signature};

/// Server-side verifier for a client's **raw public key** (RFC 7250).
///
/// It only authenticates the TLS layer — that the client holds the private key
/// for the raw key it presented (the `CertificateVerify` signature). *Which*
/// identity that key represents, and whether it may manage this node, is decided
/// afterwards at the app layer by `decide_access` against the key read from
/// `peer_certificates()`. So any well-formed raw key whose handshake signature
/// verifies is accepted here; authorization is deliberately not done in the TLS
/// verifier.
#[derive(Debug)]
struct RawKeyClientVerifier {
    supported_algs: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for RawKeyClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // Raw public keys chain to no CA, so there are no issuer hints to offer.
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // Accept the raw key at the TLS layer; identity + authorization happen in
        // `decide_access` once the app reads the peer key.
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // The management API is TLS 1.3 only, so this path is never taken.
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

/// Build the server-side rustls config for the management API: TLS 1.3 only,
/// presenting the node's own key (`own_seed`) as a raw public key and requiring
/// the client to present one too (verified at the app layer). `ring` provider.
pub fn server_config(own_seed: &[u8; 32]) -> Result<Arc<ServerConfig>, rustls::Error> {
    let certified = certified_key_from_seed(own_seed)?;
    let provider = Arc::new(ring::default_provider());
    let verifier = Arc::new(RawKeyClientVerifier {
        supported_algs: provider.signature_verification_algorithms,
    });
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(certified)));
    Ok(Arc::new(config))
}

/// A minimal client-side raw-key pinning verifier and config builder, used only
/// to drive tests (in this module and in [`crate::transport`]) against
/// [`server_config`]. The production client-side config — this verifier's real
/// counterpart — lives in `wayfinder-client`; this crate does not depend on it
/// even for tests, so the server's own suites exercise the listener with this
/// narrow standalone client instead.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::client::{AlwaysResolvesClientRawPublicKeys, ClientConfig};
    use rustls::crypto::{WebPkiSupportedAlgorithms, ring};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use wayfinder_tls_mgmt::{
        certified_key_from_seed, raw_ed25519_from_spki, verify_raw_key_signature,
    };

    #[derive(Debug)]
    struct TestPinnedServerVerifier {
        expected_server_key: [u8; 32],
        supported_algs: WebPkiSupportedAlgorithms,
    }

    impl ServerCertVerifier for TestPinnedServerVerifier {
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

    /// Build a client-side rustls config pinning `expected_server_key`, for
    /// tests that need a real RFC 7250 client to drive against [`server_config`]
    /// (see [`super::server_config`]).
    pub(crate) fn test_client_config(
        own_seed: &[u8; 32],
        expected_server_key: &[u8; 32],
    ) -> Arc<ClientConfig> {
        let certified = certified_key_from_seed(own_seed).unwrap();
        let provider = Arc::new(ring::default_provider());
        let verifier = Arc::new(TestPinnedServerVerifier {
            expected_server_key: *expected_server_key,
            supported_algs: provider.signature_verification_algorithms,
        });
        let config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(certified)));
        Arc::new(config)
    }

    /// Like [`test_client_config`], but presents no client certificate at all —
    /// for tests of the server's `client_auth_mandatory` enforcement.
    pub(crate) fn test_client_config_no_client_auth(
        expected_server_key: &[u8; 32],
    ) -> Arc<ClientConfig> {
        let provider = Arc::new(ring::default_provider());
        let verifier = Arc::new(TestPinnedServerVerifier {
            expected_server_key: *expected_server_key,
            supported_algs: provider.signature_verification_algorithms,
        });
        let config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Arc::new(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use rustls::{ClientConnection, ServerConnection};
    use wayfinder::wayfinder_auth::Keypair;
    use wayfinder_tls_mgmt::raw_ed25519_from_spki;

    use super::test_support::{test_client_config, test_client_config_no_client_auth};

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

    /// A full RFC 7250 handshake between [`server_config`] and a standalone test
    /// client completes, and each end reads the other's raw Ed25519 identity key
    /// back out of `peer_certificates()` — the keys the app layer then feeds to
    /// `decide_access`.
    #[test]
    fn rpk_handshake_surfaces_each_peers_raw_key() {
        let server_seed = [11u8; 32];
        let client_seed = [22u8; 32];
        let server_key = Keypair::from_seed(&server_seed).ed_pubkey();
        let client_key = Keypair::from_seed(&client_seed).ed_pubkey();

        let mut server = ServerConnection::new(server_config(&server_seed).unwrap()).unwrap();
        let mut client = ClientConnection::new(
            test_client_config(&client_seed, &server_key),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();

        drive(&mut client, &mut server).unwrap();
        assert!(!client.is_handshaking() && !server.is_handshaking());

        let seen_client =
            raw_ed25519_from_spki(server.peer_certificates().unwrap()[0].as_ref()).unwrap();
        assert_eq!(
            seen_client, client_key,
            "server sees the client's identity key"
        );

        let seen_server =
            raw_ed25519_from_spki(client.peer_certificates().unwrap()[0].as_ref()).unwrap();
        assert_eq!(
            seen_server, server_key,
            "client sees the node's identity key"
        );
    }

    /// Client auth is mandatory: a client that presents *no* raw key is rejected
    /// by the handshake, so an unauthenticated peer never reaches the app layer.
    /// Guards the `client_auth_mandatory()` invariant in `RawKeyClientVerifier`.
    #[test]
    fn server_rejects_client_that_presents_no_key() {
        let server_seed = [11u8; 32];
        let server_key = Keypair::from_seed(&server_seed).ed_pubkey();

        let mut server = ServerConnection::new(server_config(&server_seed).unwrap()).unwrap();
        let mut client = ClientConnection::new(
            test_client_config_no_client_auth(&server_key),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();

        assert!(
            drive(&mut client, &mut server).is_err(),
            "a client presenting no key must be rejected: client auth is mandatory"
        );
    }
}
