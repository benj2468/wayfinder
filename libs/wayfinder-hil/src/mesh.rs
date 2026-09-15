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
//! the board stops using the identity it minted for itself and adopts the one
//! this mesh issued. That is the right trade on a bench: a certificate binds a
//! key to a MAC, and the alternative (keeping the board's own key) needs a
//! certificate issued for a public key the board has never disclosed, which is
//! the enrollment flow rather than a test fixture.
//!
//! **Since design 22 that seed is durable**, so an installed identity outlives
//! the run that installed it — and outlives a reflash, because the store sits
//! in two pages the linker keeps clear of the image. A DK that has run this
//! suite therefore keeps a rig-minted mesh identity until it is taken back by
//! erasing the whole chip and reflashing — `just hil-fresh`, which exists
//! because `tests/fresh_board.rs` needs exactly that.
//!
//! That is a property of the bench, not a leak: the anchor is a fresh random
//! root per call and never leaves the process that minted it, so a board
//! holding a stale rig credential is a member of a mesh that no longer exists
//! anywhere.
//!
//! # The board adopts the MAC on its next boot, not at install time
//!
//! Between the install and the next reset the node **routes under one MAC and
//! is certified under another**: `GetNodeInfo`'s `node_id` is the router's own
//! address and `GetSecurityStatus`'s `node_mac` is the certificate's.
//! `CentralRouter::self_ident` is fixed at construction and has no setter,
//! deliberately — a mid-flight address change is a topology event, and every
//! peer holds the old originator — so the address follows the seed on the next
//! boot, which is also exactly what `wayfinder-tap` does.
//!
//! Two things follow for a test written here:
//!
//! - **The window is expected, and the node says so.** It raises
//!   `AlarmKind::CertifiedAddressMismatch` while it holds it, which is what
//!   `an_installed_credential_is_adopted_across_a_reset` asserts on both sides
//!   of the reset. A test that needs the board answering under its certified
//!   address must reset it after installing.
//! - **A test involving a peer must reset first.** A certificate binds a key
//!   to a MAC, so before the reset this node's OGMs carry an originator its
//!   credential does not name and a clocked peer should refuse them.
//!
//! This used to be GitLab #58 — a board whose address was FICR-derived and
//! could therefore *never* match its certificate, on any boot. Design 22 made
//! the board seed-derived, so the two agree by construction and the divergence
//! is bounded by one restart. Two notes kept from that entry:
//!
//! - **Certifying the identity the board already holds** — `SetAuth` with an
//!   *empty* seed — is the other shape, and it checks the certificate's MAC
//!   against the node's rather than being exempt as the wholesale install is.
//!   It needs the board's public key, so it wants a CSR step here rather than
//!   a locally minted seed. That is the enrolment path, GitLab #53.
//! - **Do not try to avoid the window by grinding a keypair** to match some
//!   address the board already has. The MAC is a hash of the public key; that
//!   was never a fixture problem.

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

/// The smallest renewal window [`TestMesh::mint_in_renewal_window`] will issue.
///
/// It derives the window from how far `now` sits above
/// [`MIN_PLAUSIBLE_UNIX`] rather than hardcoding one, so this is only a floor:
/// below it the last quarter is too short to be worth asserting against a board
/// whose clock may be days ahead of the host's, and the fixture says so rather
/// than producing a certificate that reads as fresh for a reason the test's
/// failure message cannot explain.
const MIN_RENEWAL_WINDOW_SECS: u64 = 30 * 86_400;

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

    /// Mint a mesh whose credential is **already deep inside its renewal
    /// window** as of `now_unix` — the last quarter, which is the only state
    /// design 24's renewal path is ever reached from.
    ///
    /// Its own constructor rather than a parameter on [`mint`](Self::mint),
    /// because `mint` deliberately places a wide window either side of `now`:
    /// those tests are about clock posture, and a narrow window would make them
    /// fail for a reason they are not testing. This one wants exactly the
    /// narrow window they avoid.
    ///
    /// `not_after` stays ahead of `now`, so the certificate is *renewable*
    /// rather than lapsed — a lapsed one is a different state with a different
    /// remedy (design 24 §5.2), and a fixture that confused the two would
    /// assert the wrong half.
    ///
    /// The window is placed so `now_unix` lands exactly on `renew_from`, which
    /// leaves the whole last quarter ahead of it.
    ///
    /// That slack is the point, and it is why the window is *derived* rather
    /// than a constant. A board's clock is a floor it never rolls back (design
    /// 20), and this suite's own clock tests anchor it deliberately far forward
    /// — the reference bench sits a month ahead of the host, and a board that
    /// has run the `SetTime` test is over a year ahead. Any floor from
    /// `now_unix` up to `not_after` reads as due-and-not-expired, so the fixture
    /// buys as much of that range as it can.
    ///
    /// The limit is [`MIN_PLAUSIBLE_UNIX`]: `not_before` cannot go below it
    /// without being refused, so the widest usable window is
    /// `4/3 × (now - MIN_PLAUSIBLE_UNIX)` — three quarters behind `now`, one
    /// quarter ahead. Clamping `not_before` *after* choosing a fixed width is
    /// what this replaces, and it failed silently: the clamp slid the whole
    /// window forward, putting `renew_from` years in the future while the
    /// certificate still looked perfectly well-formed.
    pub fn mint_in_renewal_window(now_unix: u64) -> anyhow::Result<TestMesh> {
        let mut mesh = TestMesh::mint(now_unix);
        let headroom = now_unix.saturating_sub(MIN_PLAUSIBLE_UNIX);
        // `now - not_before` is three quarters of the window, so the window is
        // four thirds of the headroom and the final quarter is a third of it.
        let window = headroom.saturating_mul(4) / 3;
        anyhow::ensure!(
            window >= MIN_RENEWAL_WINDOW_SECS,
            "this host's clock ({now_unix}) is too close to the plausibility floor \
             ({MIN_PLAUSIBLE_UNIX}) to place a renewal window: the widest one available \
             is {window}s, under the {MIN_RENEWAL_WINDOW_SECS}s this fixture needs to \
             stay meaningful against a board whose own clock runs ahead",
        );
        mesh.not_before = MIN_PLAUSIBLE_UNIX;
        mesh.not_after = MIN_PLAUSIBLE_UNIX.saturating_add(window);
        Ok(mesh)
    }

    /// End of the issued certificate's validity window.
    pub fn not_after(&self) -> u64 {
        self.not_after
    }

    /// The instant this certificate becomes due for renewal: the start of its
    /// last quarter, as [`MembershipCert::renew_from`] computes it.
    pub fn renew_from(&self) -> u64 {
        self.not_after
            .saturating_sub((self.not_after - self.not_before) / 4)
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

    /// Admit the identity `node` **already holds** to this mesh, and return the
    /// address it will keep.
    ///
    /// The other half of [`install`](Self::install), and the one a test with
    /// two boards needs. `install` replaces the node's seed, so the node adopts
    /// its certified address only on its next boot — fine for a DK, and
    /// impossible for a dongle, which has no debugger and cannot be reset from
    /// the host. This certifies the key the node is already running under, so
    /// **no reboot is involved**: the address does not change, and the
    /// credential is usable the moment it lands.
    ///
    /// It is also the shape real enrolment takes (GitLab #53). The node's
    /// public keys come off `GetSecurityStatus` — an un-enrolled node reports
    /// them, which is exactly what makes this possible — and the subject is
    /// *derived* from the Ed25519 key rather than taken from the node's word
    /// for it, so a node whose address does not match its own key is refused
    /// here rather than handed a certificate it could not use.
    ///
    /// Every node certified against one `TestMesh` shares its trust anchor,
    /// which is what puts two boards on one mesh.
    /// `provider_key`, when given, additionally records **where this node
    /// renews**: the authority whose Ed25519 identity key that is (design 24).
    ///
    /// The key, not the address. A node's mesh address is the address its
    /// identity key derives (design 09 §5), so a board stores the pinned key
    /// and derives the MAC to route a renewal to — which is what makes it
    /// impossible for the two to disagree. The socket address in the block is
    /// left empty on purpose: a board has no IP stack to dial one with, and it
    /// is the absence of that, not of a route, that design 24 works around.
    pub async fn certify(
        &self,
        node: &mut Node,
        installer_unix: u64,
        provider_key: Option<&[u8; 32]>,
    ) -> anyhow::Result<[u8; 6]> {
        let role = node.role().to_string();
        let status = node.security_status().await?;
        // Named, because with two boards in play "no usable key" says nothing
        // about which one to reflash — and an empty key here has exactly one
        // cause: firmware that predates the driver passing its seed to the
        // adapter, so `GetSecurityStatus` has no identity to report.
        let ed: [u8; 32] = status.own_ed_pubkey.clone().try_into().map_err(|_| {
            anyhow::anyhow!(
                "board {role:?} reports no Ed25519 identity key, so there is nothing to \
                 certify. Its firmware predates the board passing its seed to the \
                 management adapter; reflash it."
            )
        })?;
        let x: [u8; 32] = status.own_x_pubkey.clone().try_into().map_err(|_| {
            anyhow::anyhow!("board {role:?} reports no usable X25519 agreement key")
        })?;

        // Derived, never taken from `node_id`: a certificate's MAC *is* the
        // address its key derives (design 09 §5), so deriving it here is what
        // makes the certificate usable. A node whose reported address differs
        // is one this path cannot serve — `SetAuth` would refuse the result —
        // so say which two values disagreed rather than letting the node's own
        // refusal be the first anyone hears of it.
        let mac = wayfinder_auth::derive_mac(&ed);
        let node_id = node.node_info().await?.node_id;
        anyhow::ensure!(
            node_id == mac.0,
            "board {role:?} routes as {node_id:x?} but its identity key derives {:x?}; its \
             address is not derived from its seed, so no certificate can name both",
            mac.0,
        );

        let cert = self
            .authority
            .issue_cert(mac, ed, x, self.not_before, self.not_after);
        // An **empty** seed: certify what the node has, do not replace it.
        node.set_auth(
            &[],
            cert.as_bytes(),
            &self.authority.trust_anchor().to_bytes(),
            provider_key.map(
                |node_key| wayfinder_protos::wayfinder::v1alpha::RenewalProvider {
                    address: String::new(),
                    node_key: node_key.to_vec(),
                    enrollment_token: String::new(),
                },
            ),
            installer_unix,
        )
        .await?;
        Ok(mac.0)
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
