//! The concrete mesh certificate authority for a node in provider mode.
//!
//! Host-only (`std`): holds the mesh root key (via `wayfinder_auth::Authority`)
//! and issues / revokes member certificates in response to management-API
//! enrollment requests.  Embedded nodes never link this — they only verify
//! against a trust anchor.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use wayfinder::interfaces::frame::Mac;
use wayfinder_auth::Authority;
use zerocopy::IntoBytes;

use crate::provider::MeshAuthority;

/// A running certificate authority: the mesh root key plus the issuance policy
/// (certificate lifetime and an optional shared enrollment token).
pub struct CertAuthority {
    /// Custody of the mesh root key and the mesh id it signs for.
    authority: Authority,
    /// Validity window length applied to issued certificates, in seconds.  Keep
    /// it short — passive expiry is the primary revocation mechanism.
    cert_ttl_secs: u64,
    /// Optional shared enrollment token.  When set, a CSR must present the
    /// matching value; when `None`, enrollment is open (TOFU).
    enrollment_token: Option<String>,
    /// Current wall-clock time in unix seconds, refreshed by the driver so issued
    /// validity windows track the node's auth clock.  Zero until first set.
    now_unix: u64,
}

impl CertAuthority {
    /// Build a CA from a 32-byte root seed and its issuance policy.
    pub fn new(
        root_seed: &[u8; 32],
        mesh_id: u32,
        cert_ttl_secs: u64,
        enrollment_token: Option<String>,
    ) -> Self {
        Self {
            authority: Authority::from_seed(root_seed, mesh_id),
            cert_ttl_secs,
            enrollment_token,
            now_unix: 0,
        }
    }

    /// Update the current wall-clock time (unix seconds) used to stamp issued
    /// certificate / revocation validity windows.  Called by the driver before
    /// serving a request, the same way the router's auth clock is refreshed.
    pub fn set_now_unix(&mut self, now_unix: u64) {
        self.now_unix = now_unix;
    }

    /// The mesh id this authority signs for.
    pub fn mesh_id(&self) -> u32 {
        self.authority.mesh_id()
    }
}

/// Convert a byte slice to a fixed array, with a descriptive error.
fn fixed<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], String> {
    bytes
        .try_into()
        .map_err(|_| alloc::format!("{what} must be {N} bytes"))
}

impl MeshAuthority for CertAuthority {
    fn trust_anchor_bytes(&self) -> Vec<u8> {
        self.authority.trust_anchor().to_bytes().to_vec()
    }

    fn issue_cert(
        &mut self,
        node_mac: &[u8],
        ed_pubkey: &[u8],
        x_pubkey: &[u8],
        token: &str,
    ) -> Result<Vec<u8>, String> {
        // The clock must have been set (via `set_now_unix`), or we'd issue a cert
        // whose validity window starts at the unix epoch and is already expired
        // against any real wall clock.  Fail closed.
        if self.now_unix == 0 {
            return Err("authority clock not set; cannot issue certificates yet".to_string());
        }
        // A plain `!=` is sufficient: the enrollment token is a *shared* secret
        // over a network management API, not a per-user credential, so a
        // byte-compare timing side-channel is not a realistic threat (network
        // jitter dwarfs it) and a constant-time compare would add no security.
        if let Some(expected) = &self.enrollment_token
            && token != expected
        {
            return Err("invalid or missing enrollment token".to_string());
        }
        let mac = Mac(fixed::<6>(node_mac, "node_mac")?);
        let ed = fixed::<32>(ed_pubkey, "ed_pubkey")?;
        let x = fixed::<32>(x_pubkey, "x_pubkey")?;
        let not_after = self.now_unix.saturating_add(self.cert_ttl_secs);
        let cert = self
            .authority
            .issue_cert(mac, ed, x, self.now_unix, not_after);
        Ok(cert.as_bytes().to_vec())
    }

    fn revoke(&mut self, node_mac: &[u8]) -> Result<Vec<u8>, String> {
        if self.now_unix == 0 {
            return Err("authority clock not set; cannot sign revocations yet".to_string());
        }
        let mac = Mac(fixed::<6>(node_mac, "node_mac")?);
        // The revocation must outlive any cert we issued for the node, so reuse
        // the same ttl window from now; passive expiry then takes over.
        let not_after = self.now_unix.saturating_add(self.cert_ttl_secs);
        let record = self.authority.revoke(mac, self.now_unix, not_after);
        Ok(record.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wayfinder_auth::{Keypair, MembershipCert, RevocationRecord, TrustAnchor};
    use zerocopy::FromBytes;

    fn node_keys(seed: u8) -> ([u8; 32], [u8; 32]) {
        let kp = Keypair::from_seed(&[seed; 32]);
        (kp.ed_pubkey(), kp.x_pubkey())
    }

    #[test]
    fn issued_cert_verifies_against_the_anchor() {
        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None);
        ca.set_now_unix(100);
        let (ed, x) = node_keys(2);
        let cert_bytes = ca.issue_cert(&[0, 0, 0, 0, 0, 9], &ed, &x, "").unwrap();

        let anchor = TrustAnchor::from_bytes(&ca.trust_anchor_bytes()).unwrap();
        let cert = MembershipCert::from_bytes(&cert_bytes).unwrap();
        let verified = anchor.verify_cert(&cert, 500).expect("verifies in window");
        assert_eq!(verified.mac.0, [0, 0, 0, 0, 0, 9]);
        assert_eq!(verified.ed_pubkey, ed);
    }

    #[test]
    fn token_is_enforced_when_configured() {
        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, Some("s3cret".to_string()));
        ca.set_now_unix(100);
        let (ed, x) = node_keys(2);
        let mac = [0, 0, 0, 0, 0, 9];
        assert!(ca.issue_cert(&mac, &ed, &x, "wrong").is_err());
        assert!(ca.issue_cert(&mac, &ed, &x, "").is_err());
        assert!(ca.issue_cert(&mac, &ed, &x, "s3cret").is_ok());
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None);
        ca.set_now_unix(100); // past the clock guard, so we test input validation
        let (ed, x) = node_keys(2);
        assert!(ca.issue_cert(&[0, 0, 0], &ed, &x, "").is_err()); // short MAC
        assert!(ca.issue_cert(&[0; 6], &ed[..16], &x, "").is_err()); // short ed key
    }

    #[test]
    fn issuance_rejected_before_clock_is_set() {
        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None);
        let (ed, x) = node_keys(2);
        let err = ca.issue_cert(&[0; 6], &ed, &x, "").unwrap_err();
        assert!(err.contains("clock not set"), "got: {err}");
    }

    #[test]
    fn revoke_produces_a_verifiable_record() {
        let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, None);
        ca.set_now_unix(100);
        let record_bytes = ca.revoke(&[0, 0, 0, 0, 0, 9]).unwrap();
        let (record, _) = RevocationRecord::ref_from_prefix(&record_bytes).unwrap();
        let anchor = TrustAnchor::from_bytes(&ca.trust_anchor_bytes()).unwrap();
        assert_eq!(
            anchor.verify_revocation(record).unwrap().0,
            [0, 0, 0, 0, 0, 9]
        );
    }
}
