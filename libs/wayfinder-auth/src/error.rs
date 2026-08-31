//! The single error type returned by certificate and tag verification.

/// Why a certificate, signature, or revocation record failed to verify.
///
/// Verification is fail-closed: any of these variants means the subject is
/// **not** trusted and the frame carrying it must be dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// The bytes were too short or otherwise could not be parsed into the
    /// expected fixed-layout record.
    Malformed,
    /// The record's version byte is not one this build understands.
    BadVersion,
    /// The record is for a different mesh than the verifying trust anchor.
    WrongMesh,
    /// The signature did not verify against the expected public key.
    BadSignature,
    /// `now` is past the certificate's `not_after` — it has expired.
    Expired,
    /// `now` is before the certificate's `not_before` — not yet valid.
    NotYetValid,
    /// The subject MAC has been revoked.
    Revoked,
    /// The certificate binds its subject to a **reserved** MAC address —
    /// broadcast, any multicast (group-bit) address, or the all-zeros null
    /// address — none of which a node can route under.
    ///
    /// Distinct from [`BadSignature`](Self::BadSignature): the mesh root
    /// really did sign it, so this is a *misissuance*, and the receiver
    /// refusing it is what keeps one bad signature from admitting a member at
    /// an address every node already treats specially.
    ReservedAddress,
    /// A revocation record carries no revocation instant (`not_before == 0`).
    ///
    /// Structurally malformed rather than merely stale: `not_before` is also
    /// the issuance cut-off a certificate is judged against, so a zero would
    /// cancel nothing while still verifying and flooding — a revocation that
    /// silently does nothing.  It is also exactly the shape a v1 record has,
    /// so refusing it here is what keeps the two versions from being confused.
    NoRevocationInstant,
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            AuthError::Malformed => "malformed record",
            AuthError::BadVersion => "unsupported record version",
            AuthError::WrongMesh => "wrong mesh",
            AuthError::BadSignature => "bad signature",
            AuthError::Expired => "certificate expired",
            AuthError::NotYetValid => "certificate not yet valid",
            AuthError::Revoked => "subject revoked",
            AuthError::ReservedAddress => "certificate binds a reserved address",
            AuthError::NoRevocationInstant => "revocation carries no instant",
        };
        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AuthError {}
