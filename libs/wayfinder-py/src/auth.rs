//! Mesh identity, membership certificates, and the certificate authority,
//! exposed to Python.
//!
//! These are the pieces a simulation needs to stand up an *authenticated*
//! mesh rather than an open one: mint a mesh root ([`PyAuthority`]), give
//! each node an identity ([`PyKeypair`]) and a certificate binding it to the
//! mesh ([`PyMembershipCert`]), and hand the resulting triple to
//! [`PyDriver::set_auth`](crate::PyDriver).
//!
//! They are equally what an adversarial scenario needs: a second
//! [`PyAuthority`] is a *foreign* mesh root, and [`PyAuthority::issue_cert`]
//! takes raw public keys rather than a keypair precisely so a scenario can
//! mint deliberately mismatched credentials — a certificate naming one node's
//! MAC over another's key — and check that the router refuses them.
//!
//! Scope note, inherited from `wayfinder-auth`: this buys **authenticity and
//! mesh segregation, never confidentiality**. Payloads are not encrypted, so
//! a passive listener on a link can always read them. A scenario that
//! "successfully" eavesdrops has confirmed the design, not broken it.

use interfaces::frame::Mac;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use wayfinder_auth::Authority;
use wayfinder_auth::Keypair;
use wayfinder_auth::MembershipCert;
use wayfinder_auth::RevocationRecord;
use wayfinder_auth::TrustAnchor;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

use crate::types::PyMac;

/// A node's cryptographic identity: one 32-byte seed, from which the Ed25519
/// signing keypair (control plane), the X25519 agreement key (directed data
/// plane) and the node's mesh [`PyMac`] are all derived.
///
/// The MAC being *derived from the key* rather than assigned is what makes a
/// node's address survive restarts — and what stops an attacker from picking
/// an address it has no key for.
#[pyclass(module = "wayfinder_py", name = "PyKeypair")]
pub struct PyKeypair {
    /// The 32-byte seed the whole identity derives from. Retained (rather
    /// than only the derived [`Keypair`]) because `Keypair` is deliberately
    /// neither `Clone` nor seed-readable, while a Python caller must be able
    /// to install one identity on a driver *and* keep using it — e.g. to sign
    /// something by hand afterwards. The seed is the identity, so keeping it
    /// is what makes a second copy possible at all.
    seed: [u8; 32],
    inner: Keypair,
}

impl PyKeypair {
    /// Rebuild the underlying keypair, for handing an owned one to
    /// [`OgmAuth`](wayfinder::auth::OgmAuth) without consuming this object.
    pub(crate) fn to_keypair(&self) -> Keypair {
        Keypair::from_seed(&self.seed)
    }

    fn from_seed_bytes(seed: [u8; 32]) -> Self {
        Self {
            seed,
            inner: Keypair::from_seed(&seed),
        }
    }
}

#[pymethods]
impl PyKeypair {
    /// Derive an identity deterministically from a 32-byte seed — the form a
    /// simulation wants, so a run is reproducible.
    #[staticmethod]
    fn from_seed(seed: &[u8]) -> PyResult<Self> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| PyValueError::new_err("a keypair seed is exactly 32 bytes"))?;
        Ok(Self::from_seed_bytes(seed))
    }

    /// Draw a fresh identity from the OS RNG.
    #[staticmethod]
    fn generate() -> Self {
        Self::from_seed_bytes(Keypair::generate_seed())
    }

    /// The 32-byte seed this identity derives from — enough to reconstruct it
    /// in full, so treat it as the secret it is.
    #[getter]
    fn seed<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.seed)
    }

    /// The Ed25519 public key, which certificates bind and OGM signatures
    /// verify against.
    #[getter]
    fn ed_pubkey<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.ed_pubkey())
    }

    /// The X25519 public key, used to derive the pairwise keys that tag
    /// directed (unicast/multicast) frames hop by hop.
    #[getter]
    fn x_pubkey<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.x_pubkey())
    }

    /// The mesh address this identity owns, derived from `ed_pubkey`.
    #[getter]
    fn derived_mac(&self) -> PyMac {
        PyMac(self.inner.derived_mac())
    }

    /// Sign `msg` with the Ed25519 key — for a scenario crafting signed
    /// material by hand.
    fn sign<'py>(&self, py: Python<'py>, msg: &[u8]) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.sign(msg))
    }

    fn __repr__(&self) -> String {
        format!("PyKeypair({})", self.inner.derived_mac())
    }
}

/// The public half of a mesh's root of trust: the mesh id plus the root
/// Ed25519 public key every member verifies certificates and revocations
/// against.
///
/// This is the whole of what segregates one mesh from another. Two meshes
/// with different anchors cannot route to each other however identical their
/// configuration.
#[pyclass(module = "wayfinder_py", name = "PyTrustAnchor", from_py_object)]
#[derive(Clone, Copy)]
pub struct PyTrustAnchor(pub(crate) TrustAnchor);

#[pymethods]
impl PyTrustAnchor {
    /// Parse an anchor from its serialized form (`bytes(anchor)`).
    #[new]
    fn new(raw: &[u8]) -> PyResult<Self> {
        TrustAnchor::from_bytes(raw)
            .map(Self)
            .ok_or_else(|| PyValueError::new_err("not a well-formed trust anchor"))
    }

    /// The mesh this anchor is the root of.
    #[getter]
    fn mesh_id(&self) -> u32 {
        self.0.mesh_id
    }

    /// The root Ed25519 public key certificates are verified against.
    #[getter]
    fn root_pubkey<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.root_pubkey)
    }

    /// The serialized anchor, as distributed to members.
    fn __bytes__<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.to_bytes())
    }

    fn __repr__(&self) -> String {
        format!("PyTrustAnchor(mesh_id=0x{:08x})", self.0.mesh_id)
    }
}

/// A root-signed attestation that one Ed25519 key owns one MAC in one mesh,
/// over a validity window.
///
/// The window is the *passive* revocation mechanism — keep it short, because
/// expiry is what bounds the damage from a leaked key with no network
/// involved. [`PyRevocationRecord`] is the active counterpart.
#[pyclass(module = "wayfinder_py", name = "PyMembershipCert", from_py_object)]
#[derive(Clone, Copy)]
pub struct PyMembershipCert(pub(crate) MembershipCert);

#[pymethods]
impl PyMembershipCert {
    /// Parse a certificate from its on-wire bytes (`bytes(cert)`).
    #[new]
    fn new(raw: &[u8]) -> PyResult<Self> {
        MembershipCert::from_bytes(raw)
            .map(Self)
            .ok_or_else(|| PyValueError::new_err("not a well-formed membership certificate"))
    }

    /// The MAC this certificate attests ownership of.
    #[getter]
    fn node_mac(&self) -> PyMac {
        PyMac(Mac(self.0.node_mac))
    }

    /// The mesh this certificate is valid in.
    #[getter]
    fn mesh_id(&self) -> u32 {
        self.0.mesh_id.get()
    }

    /// The Ed25519 public key bound to `node_mac`.
    #[getter]
    fn ed_pubkey<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.ed_pubkey)
    }

    /// The X25519 public key bound to `node_mac`.
    #[getter]
    fn x_pubkey<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.x_pubkey)
    }

    /// Start of the validity window, in unix seconds.
    #[getter]
    fn not_before(&self) -> u64 {
        self.0.not_before.get()
    }

    /// End of the validity window, in unix seconds.
    #[getter]
    fn not_after(&self) -> u64 {
        self.0.not_after.get()
    }

    /// Whether this certificate carries the admin capability (management-API
    /// access), as opposed to plain mesh membership.
    #[getter]
    fn admin(&self) -> bool {
        self.0.flags & wayfinder_auth::CERT_FLAG_ADMIN != 0
    }

    /// The 8-byte fingerprint an OGM advertises under lazy cert distribution,
    /// in place of the whole certificate.
    #[getter]
    fn fingerprint<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.fingerprint())
    }

    /// The on-wire certificate bytes.
    fn __bytes__<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.0.as_bytes())
    }

    fn __repr__(&self) -> String {
        format!(
            "PyMembershipCert(mac={}, mesh_id=0x{:08x}, not_after={})",
            Mac(self.0.node_mac),
            self.0.mesh_id.get(),
            self.0.not_after.get()
        )
    }
}

/// A root-signed order to purge one MAC from the mesh, flooded on OGMs — the
/// *active* revocation mechanism, shortening the window that certificate
/// expiry alone would leave open.
#[pyclass(module = "wayfinder_py", name = "PyRevocationRecord", from_py_object)]
#[derive(Clone, Copy)]
pub struct PyRevocationRecord(pub(crate) RevocationRecord);

#[pymethods]
impl PyRevocationRecord {
    /// Parse a revocation from its on-wire bytes (`bytes(record)`).
    #[new]
    fn new(raw: &[u8]) -> PyResult<Self> {
        RevocationRecord::read_from_bytes(raw)
            .map(Self)
            .map_err(|_| PyValueError::new_err("not a well-formed revocation record"))
    }

    /// The MAC being purged.
    #[getter]
    fn node_mac(&self) -> PyMac {
        PyMac(Mac(self.0.node_mac))
    }

    /// The mesh this revocation applies to.
    #[getter]
    fn mesh_id(&self) -> u32 {
        self.0.mesh_id.get()
    }

    /// When the revocation takes effect, in unix seconds.
    #[getter]
    fn not_before(&self) -> u64 {
        self.0.not_before.get()
    }

    /// When members may forget this record — at least the revoked
    /// certificate's own expiry, or the purge lapses early.
    #[getter]
    fn not_after(&self) -> u64 {
        self.0.not_after.get()
    }

    /// The on-wire revocation bytes.
    fn __bytes__<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.0.as_bytes())
    }

    fn __repr__(&self) -> String {
        format!("PyRevocationRecord(mac={})", Mac(self.0.node_mac))
    }
}

/// A mesh's certificate authority — custody of the root key.
///
/// One `PyAuthority` *is* one mesh. A scenario that wants an intruder holding
/// "valid-looking" credentials builds a second authority and enrolls the
/// intruder against that: every field checks out, and the signature still
/// fails against the real mesh's anchor.
#[pyclass(module = "wayfinder_py", name = "PyAuthority")]
pub struct PyAuthority(Authority);

#[pymethods]
impl PyAuthority {
    /// Build an authority by deriving the root keypair from a 32-byte seed —
    /// the reproducible form a simulation wants.
    #[staticmethod]
    fn from_seed(seed: &[u8], mesh_id: u32) -> PyResult<Self> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| PyValueError::new_err("a root seed is exactly 32 bytes"))?;
        Ok(Self(Authority::from_seed(&seed, mesh_id)))
    }

    /// Build an authority over a freshly drawn root key.
    #[staticmethod]
    fn generate(mesh_id: u32) -> Self {
        Self(Authority::new(Keypair::generate(), mesh_id))
    }

    /// The mesh this authority is the root of.
    #[getter]
    fn mesh_id(&self) -> u32 {
        self.0.mesh_id()
    }

    /// The public anchor distributed to every member.
    fn trust_anchor(&self) -> PyTrustAnchor {
        PyTrustAnchor(self.0.trust_anchor())
    }

    /// Issue a certificate binding `mac` to the given raw public keys, valid
    /// over `[not_before, not_after]` in unix seconds.
    ///
    /// Takes the keys separately rather than a [`PyKeypair`] so a scenario can
    /// deliberately mint a *mismatched* credential — a MAC that isn't derived
    /// from the key it is issued over — which is exactly the shape an
    /// impersonation attempt takes. Use [`enroll`](Self::enroll) for the
    /// ordinary case.
    fn issue_cert(
        &self,
        mac: PyMac,
        ed_pubkey: &[u8],
        x_pubkey: &[u8],
        not_before: u64,
        not_after: u64,
    ) -> PyResult<PyMembershipCert> {
        let ed: [u8; 32] = ed_pubkey
            .try_into()
            .map_err(|_| PyValueError::new_err("an Ed25519 public key is exactly 32 bytes"))?;
        let x: [u8; 32] = x_pubkey
            .try_into()
            .map_err(|_| PyValueError::new_err("an X25519 public key is exactly 32 bytes"))?;
        Ok(PyMembershipCert(
            self.0.issue_cert(mac.0, ed, x, not_before, not_after),
        ))
    }

    /// Enroll `keypair` as a member: a certificate over its own keys, for the
    /// MAC those keys derive. The ordinary case, and the one where MAC and key
    /// agree by construction.
    fn enroll(&self, keypair: &PyKeypair, not_before: u64, not_after: u64) -> PyMembershipCert {
        PyMembershipCert(self.0.issue_cert(
            keypair.inner.derived_mac(),
            keypair.inner.ed_pubkey(),
            keypair.inner.x_pubkey(),
            not_before,
            not_after,
        ))
    }

    /// Issue a user (operator) session certificate rather than a node's,
    /// optionally carrying the admin capability the management API gates on.
    #[pyo3(signature = (keypair, not_before, not_after, admin=false))]
    fn issue_user_cert(
        &self,
        keypair: &PyKeypair,
        not_before: u64,
        not_after: u64,
        admin: bool,
    ) -> PyMembershipCert {
        PyMembershipCert(self.0.issue_user_cert(
            keypair.inner.derived_mac(),
            keypair.inner.ed_pubkey(),
            keypair.inner.x_pubkey(),
            not_before,
            not_after,
            admin,
        ))
    }

    /// Sign a revocation purging `mac`, effective at `not_before` and
    /// forgettable after `not_after` (unix seconds).
    fn revoke(&self, mac: PyMac, not_before: u64, not_after: u64) -> PyRevocationRecord {
        PyRevocationRecord(self.0.revoke(mac.0, not_before, not_after))
    }

    fn __repr__(&self) -> String {
        format!("PyAuthority(mesh_id=0x{:08x})", self.0.mesh_id())
    }
}
