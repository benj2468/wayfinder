//! A throwaway mesh for a hardware test: a trust anchor, a node identity, and
//! a certificate binding them.
//!
//! Design 20's board claims are about a node that **holds a credential**, and
//! most of them are unobservable without one. `GetNodeInfo`'s `clock_posture`
//! is read from the router's own auth state
//! (`RouterAdapter::clock_posture` — "authentication off answers `Unknown`,
//! and that is exactly true"), so on a board with authentication off it reports
//! `Unknown` no matter what the wall clock holds. A test that anchors the clock
//! and then asserts `Unknown` on such a board passes without proving anything.
//!
//! So the rig mints its own mesh. Everything here is ephemeral: a fresh root
//! key per call, never written to disk, and unrelated to any real mesh.
//!
//! # The board takes an identity from the rig
//!
//! [`TestMesh::install`] uses `SetAuth`, which replaces the node's seed — so
//! the board stops using its FICR-derived MAC and adopts the one this mesh
//! issued. That is the right trade on a bench: a certificate binds a key to a
//! MAC, and the alternative (`InstallCert`, keeping the board's own key) needs
//! a certificate issued for a public key the board has never disclosed, which
//! is the enrollment flow rather than a test fixture.
//!
//! A board is returned to its own identity by reflashing it.
//!
//! # The board does not adopt the MAC, and that is a known gap
//!
//! Installing this credential leaves the node **routing under one MAC and
//! certified under another**. `GetNodeInfo`'s `node_id` is the router's own
//! address — FICR-derived on an nRF board — and nothing in `SetAuth` updates
//! it, while `GetSecurityStatus`'s `node_mac` is the certificate's. The node
//! accepts the install without complaint.
//!
//! That is fine for the clock tests, which are about a posture read from the
//! auth state and never touch the key↔MAC binding. It would not be fine for a
//! test involving a peer, because a certificate binds a key to a MAC and this
//! node's OGMs carry an originator its credential does not name.
//!
//! **Tracked as GitLab #58, and the fix is not in this file.** The rule already
//! exists: since design 09 §5 a certificate's MAC *is* the address its identity
//! key derives, and a node comes up under it on the next boot from the *seed*,
//! never by copying the certificate. `wayfinder-tap` complies. The nRF board is
//! the only identity in the workspace that is not seed-derived — it derives a
//! MAC from FICR and persists a MAC, with no seed anywhere — and that single
//! fact is the whole of this gap. It is resolved as part of GitLab #52, which
//! is what gives the board a persisted seed in the first place.
//!
//! Two consequences for whoever comes back to this once #52 lands:
//!
//! - **Switch to certifying the identity the board already holds** — `SetAuth`
//!   with an *empty* seed. That branch checks the certificate's MAC against the
//!   node's and would refuse a mismatch, where the wholesale-install path used
//!   here is deliberately exempt. It needs the board's public key, so the rig
//!   grows a CSR step rather than minting a seed locally.
//! - **Do not try to fix it here by grinding a keypair** to match the board's
//!   FICR address. The MAC is a hash of the public key; that is not a fixture
//!   problem.

use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use wayfinder_auth::Authority;
use wayfinder_auth::Keypair;
use wayfinder_auth::MIN_PLAUSIBLE_UNIX;
use zerocopy::IntoBytes;

use crate::node::Node;

/// The mesh id every rig-minted mesh uses.
///
/// Fixed rather than random so a stray frame from a test board is
/// recognisable, and deliberately not a value any real deployment would pick.
pub const HIL_MESH_ID: u32 = 0x4849_4C00;

/// How far either side of `now` a minted certificate is valid.
///
/// Deliberately wide: these tests are about the clock *posture*, not about
/// expiry, and a narrow window would make them fail for a reason they are not
/// testing.
const WINDOW_SECS: u64 = 365 * 86_400;

/// A trust anchor plus one node credential issued under it.
pub struct TestMesh {
    /// The authority that issued the credential.
    authority: Authority,
    /// The node's identity seed, which `SetAuth` installs.
    seed: [u8; 32],
    /// The node's keypair, derived from `seed`.
    keypair: Keypair,
    /// Start of the certificate's validity window.
    not_before: u64,
    /// End of it.
    not_after: u64,
}

impl TestMesh {
    /// Mint a fresh mesh with a credential valid around `now`.
    ///
    /// The window is deliberately wide (a year either side): these tests are
    /// about the *clock posture*, not about expiry, and a narrow window would
    /// make them fail for a reason they are not testing.
    pub fn mint(now_unix: u64) -> TestMesh {
        let root_seed: [u8; 32] = rand::random();
        let seed: [u8; 32] = rand::random();
        TestMesh {
            authority: Authority::from_seed(&root_seed, HIL_MESH_ID),
            keypair: Keypair::from_seed(&seed),
            seed,
            // Both ends floored, not just the start: flooring `not_before`
            // alone lets a `now` below the floor produce `not_after <
            // not_before` — a certificate that is never valid, minted in
            // silence. `mint` is public, so that is reachable.
            not_before: now_unix.saturating_sub(WINDOW_SECS).max(MIN_PLAUSIBLE_UNIX),
            not_after: now_unix
                .saturating_add(WINDOW_SECS)
                .max(MIN_PLAUSIBLE_UNIX.saturating_add(WINDOW_SECS)),
        }
    }

    /// Mint a mesh against this host's clock.
    pub fn mint_now() -> anyhow::Result<TestMesh> {
        Ok(TestMesh::mint(host_unix()?))
    }

    /// Mint a mesh whose certificate **cannot date the board**.
    ///
    /// The credentialed-but-`Unknown` state is the one design 20 is actually
    /// about, and it is not reachable with an ordinary certificate: install
    /// floors the anchor at `max(installer_unix, cert.not_before)`, and any
    /// real certificate's start is past `MIN_PLAUSIBLE_UNIX`, so installing one
    /// *always* anchors the board to at least that. A test that installs a
    /// normal credential and then asserts `Unknown` is asserting something
    /// false.
    ///
    /// A `not_before` of zero is what leaves the board undated: it verifies
    /// (an `Unknown` verifier judges no window), and then fails the
    /// plausibility floor, so nothing moves the clock. That is the shape of a
    /// credential minted by an authority that could not tell the time either —
    /// and the state design 20 §7 says must raise `ClockUnsynchronized` while
    /// the node keeps routing.
    pub fn mint_undatable() -> anyhow::Result<TestMesh> {
        let mut mesh = TestMesh::mint(host_unix()?);
        mesh.not_before = 0;
        Ok(mesh)
    }

    /// The MAC the board will answer to once this credential is installed.
    pub fn mac(&self) -> [u8; 6] {
        self.keypair.derived_mac().0
    }

    /// Start of the issued certificate's validity window, when there is one the
    /// board can be dated by.
    ///
    /// `None` for a [`mint_undatable`](Self::mint_undatable) mesh, whose start
    /// is zero. An `Option` because the obvious use is arithmetic — "a year past
    /// where the install anchored me" — and doing that to zero yields an
    /// implausible instant that `SetTime` refuses, failing a test for a reason
    /// unrelated to what it asserts.
    ///
    /// The board floors its clock anchor at this value on install (design 20
    /// §4.4), so a test that wants to know where the floor landed needs it.
    pub fn not_before(&self) -> Option<u64> {
        (self.not_before >= MIN_PLAUSIBLE_UNIX).then_some(self.not_before)
    }

    /// Install this credential on `node` over `SetAuth`, stamping
    /// `installer_unix`.
    ///
    /// After this the node holds a credential, so its `clock_posture` becomes
    /// the router's real posture rather than the authentication-off `Unknown`.
    pub async fn install(&self, node: &mut Node, installer_unix: u64) -> anyhow::Result<()> {
        let cert = self.authority.issue_cert(
            self.keypair.derived_mac(),
            self.keypair.ed_pubkey(),
            self.keypair.x_pubkey(),
            self.not_before,
            self.not_after,
        );
        node.set_auth(
            &self.seed,
            cert.as_bytes(),
            &self.authority.trust_anchor().to_bytes(),
            None,
            installer_unix,
        )
        .await
    }
}

/// This host's wall clock in unix seconds.
///
/// Used to place a test certificate's window, and stamped as `installer_unix`
/// by the reset test — so a wrong value here becomes the board's clock anchor.
///
/// **Refuses rather than substituting.** Falling back to `MIN_PLAUSIBLE_UNIX`
/// on a machine whose RTC battery is dead would mint a certificate around an
/// invented date and hand a fabricated instant to the one suite whose whole
/// subject is clock semantics. A hardware clock test on a host that cannot tell
/// the time should refuse to run and say so.
pub fn host_unix() -> anyhow::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| {
            anyhow::anyhow!(
                "this host's clock reads before the unix epoch ({e}); it cannot place a test \
                 certificate's window, and these tests are about clock semantics"
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use wayfinder_auth::Clocked;
    use wayfinder_auth::WallClock;

    /// Reproduce what a board does on install: verify the certificate under the
    /// posture it currently holds, then let it move the clock.
    fn install_on(mesh: &TestMesh, clock: &mut WallClock, installer_unix: u64) -> Clocked {
        let now = Duration::from_secs(1);
        let cert = mesh.authority.issue_cert(
            mesh.keypair.derived_mac(),
            mesh.keypair.ed_pubkey(),
            mesh.keypair.x_pubkey(),
            mesh.not_before,
            mesh.not_after,
        );
        let verified = mesh
            .authority
            .trust_anchor()
            .verify_cert(&cert, clock.posture(now))
            .expect("a freshly issued certificate verifies under its own anchor");
        clock.install_anchor(installer_unix, &verified, now);
        clock.posture(now)
    }

    /// **The claim the whole clock suite rests on**, checked without a board:
    /// an ordinary credential *always* dates the node, because install floors
    /// the anchor at the certificate's own start. A hardware test that installs
    /// one and then asserts `Unknown` is asserting something false.
    #[test]
    fn an_ordinary_credential_always_anchors_the_clock() {
        let mesh = TestMesh::mint_now().unwrap();
        let mut clock = WallClock::new();
        assert_eq!(clock.posture(Duration::from_secs(1)), Clocked::Unknown);

        // Zero installer stamp: the certificate's start carries it alone.
        let posture = install_on(&mesh, &mut clock, 0);
        assert!(
            matches!(posture, Clocked::AtLeast(_)),
            "an ordinary credential must date the board, got {posture:?}"
        );
    }

    /// ...and the converse, which is what makes the credentialed-and-`Unknown`
    /// state reachable at all: a certificate starting at zero verifies under an
    /// `Unknown` verifier and then fails the plausibility floor, so nothing
    /// moves the clock.
    #[test]
    fn an_undatable_credential_leaves_the_clock_unknown() {
        let mesh = TestMesh::mint_undatable().unwrap();
        let mut clock = WallClock::new();

        assert_eq!(
            install_on(&mesh, &mut clock, 0),
            Clocked::Unknown,
            "a certificate that cannot date the board must leave it undated"
        );
    }

    /// The accessor refuses to hand out a start a test would do arithmetic on
    /// and get an implausible instant from.
    #[test]
    fn only_a_datable_mesh_reports_a_start() {
        assert!(TestMesh::mint_now().unwrap().not_before().is_some());
        assert!(TestMesh::mint_undatable().unwrap().not_before().is_none());
    }

    /// A `now` far below the plausibility floor must not mint a window that is
    /// never valid. `mint` is public, so this is reachable.
    #[test]
    fn a_certificate_window_is_never_inverted() {
        for now in [
            0,
            1,
            MIN_PLAUSIBLE_UNIX - 1,
            MIN_PLAUSIBLE_UNIX,
            host_unix().unwrap(),
        ] {
            let mesh = TestMesh::mint(now);
            assert!(
                mesh.not_before < mesh.not_after,
                "mint({now}) produced [{}, {}), which is never valid",
                mesh.not_before,
                mesh.not_after,
            );
        }
    }

    /// The MAC a board adopts is the one its certificate names — the property
    /// `verify_cert`'s key-to-MAC binding checks.
    #[test]
    fn the_issued_certificate_names_the_macs_key() {
        let mesh = TestMesh::mint_now().unwrap();
        assert_eq!(mesh.mac(), mesh.keypair.derived_mac().0);
    }
}
