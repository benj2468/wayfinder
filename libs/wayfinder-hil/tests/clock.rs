//! Design 20's board claims, on the hardware they are about.
//!
//! Every claim in `docs/design/implemented/20-embedded-clock-independence.md`
//! about what a *board* does when it cannot tell the time is checked elsewhere
//! on x86, against a `WallClock` handed a `Duration` by hand. These are the
//! same claims against an nRF52840 free-running on an internal RC oscillator,
//! which is the hardware the design's §2.1 objection is about.
//!
//! All `#[ignore]`d: `cargo nextest run --workspace` compiles them and runs
//! none. `just hil` runs them, and each skips cleanly when the inventory names
//! no board for its role.
//!
//! **Every test here installs a credential, and since design 22 that is
//! durable.** So each one leaves the board anchored for good — the estimate
//! never decreases — and design 20's `Unknown` claims are not testable from
//! here at all. They live in `fresh_board.rs`, which says why.

use wayfinder_auth::MIN_PLAUSIBLE_UNIX;
use wayfinder_hil::Node;
use wayfinder_hil::Rig;
use wayfinder_hil::mesh::TestMesh;
use wayfinder_hil::mesh::host_unix;
use wayfinder_protos::wayfinder::v1alpha::ClockPosture;

/// Design 21 §5's test 2, and design 20 §4.7's three rules for `SetTime`:
/// a plausible time anchors the floor, an implausible one is refused, and a
/// correction *behind* the current estimate is refused rather than silently
/// rolling the node back.
///
/// The rollback half is observable only because a refused anchor is reported
/// rather than swallowed — `GetNodeInfo` carries the posture but not the floor,
/// so "the estimate did not move" cannot be read directly.
#[tokio::test]
#[ignore = "needs hardware: a board playing the role \"alpha\""]
async fn set_time_anchors_forward_and_refuses_to_roll_back() -> anyhow::Result<()> {
    let rig = Rig::load()?;
    let Some(board) = rig.board("alpha") else {
        return Ok(());
    };

    board.reset()?;
    let mut node = Node::attach(&board).await?;

    // A credential first, for observability rather than admission: `SetTime`
    // itself would succeed uncredentialed (a board always has a `WallClock`;
    // the "no anchor to set" refusal is the *host* case, where the node reads
    // its own clock). But `clock_posture` is read from the router's auth state
    // and answers `Unknown` with authentication off, so every assertion below
    // would be vacuous. Its `not_before` is a year back, so the install itself
    // anchors the board and the posture is `AtLeast` before `SetTime` is called.
    let mesh = TestMesh::mint_now()?;
    mesh.install(&mut node, 0).await?;

    node.with_diagnostics(async |node: &mut Node| {
        anyhow::ensure!(
            node.node_info().await?.clock_posture() == ClockPosture::AtLeast,
            "installing a credential whose window has opened should floor the clock at \
             its not_before (design 20 §4.4)",
        );

        // Ahead of the floor the install left, so it is a real correction. The
        // install anchored at the certificate's start; go a year past it. That
        // gap is also what makes the later backwards `SetTime` meaningful: the
        // forward move is not directly observable, and the refusal of
        // `anchor - 1 day` (still far past the install floor) is what proves
        // the estimate actually moved.
        let Some(not_before) = mesh.not_before() else {
            anyhow::bail!("mint_now must produce a datable certificate");
        };
        let anchor = not_before + 400 * 86_400;

        node.set_time(anchor).await?;
        let info = node.node_info().await?;
        anyhow::ensure!(
            info.clock_posture() == ClockPosture::AtLeast,
            "an anchored board holds a floor, not a reading; got {:?}",
            info.clock_posture(),
        );

        // Below the floor: the node has never been powered in 1970, and a
        // source reading zero is a source that was never set.
        let Err(err) = node.set_time(MIN_PLAUSIBLE_UNIX - 1).await else {
            anyhow::bail!(
                "a time below MIN_PLAUSIBLE_UNIX must be refused, but SetTime reported success"
            );
        };
        // Specifically the plausibility refusal, not merely *a* refusal: this
        // value is also behind the current estimate, so accepting "no change"
        // would let the test keep passing if the floor check were ever dropped
        // and only monotonicity remained.
        anyhow::ensure!(
            format!("{err:#}").contains("plausible"),
            "a time below MIN_PLAUSIBLE_UNIX should be refused as implausible, got: {err:#}",
        );

        // Behind the current estimate: monotonicity working, and reported.
        let Err(err) = node.set_time(anchor - 86_400).await else {
            anyhow::bail!(
                "a correction behind the current estimate must be refused, but SetTime \
                 reported success -- the estimate-never-decreases invariant is broken"
            );
        };
        anyhow::ensure!(
            format!("{err:#}").contains("no change"),
            "a backwards correction should say it changed nothing, got: {err:#}",
        );

        // ...and the posture is unchanged by either refusal.
        anyhow::ensure!(
            node.node_info().await?.clock_posture() == ClockPosture::AtLeast,
            "a refused anchor must not disturb the posture",
        );
        Ok(())
    })
    .await
}

/// Design 21 §5's test 3, **flipped**, which is what its previous form said to
/// do when #54 landed.
///
/// It used to assert that a reset returned the board to `Unknown`, because
/// nothing persisted a clock checkpoint. Design 22 persists one, in the same
/// durable record as the credential — design 20 §4.5 requires the two be
/// written, loaded and erased together — so a reset now comes back anchored.
///
/// **The `AtLeast` here is not the whole assertion.** A board that restored its
/// clock from its own certificate's `not_before` would also report `AtLeast`,
/// and that is the rollback design 20 §4.4 forbids in bold: it resets the
/// expiry clock on every power cycle, by an amount that grows with the
/// certificate's age, triggerable by anyone who can pull the cable. What
/// distinguishes the two is the *value*, so the floor is checked against the
/// certificate's start rather than merely being present.
#[tokio::test]
#[ignore = "needs hardware: a probed board playing the role \"alpha\""]
async fn a_reset_restores_the_credential_and_the_clock() -> anyhow::Result<()> {
    let rig = Rig::load()?;
    let Some(board) = rig.board("alpha") else {
        return Ok(());
    };

    // From a known state, like the other two: the group serialises access to
    // the board but does not order the tests, so this would otherwise inherit
    // whatever anchor its predecessor left — and the clock only moves forward.
    board.reset()?;
    let mut node = Node::attach(&board).await?;

    // Anchoring needs a credential: `clock_posture` is read from the router's
    // auth state, so an uncredentialed board reports `Unknown` however the wall
    // clock stands, and there would be nothing for the reset to preserve.
    //
    // Stamped well past the certificate's `not_before`, which is a year back.
    // That gap is the whole measurement: a board restoring from the checkpoint
    // comes back near this value, and one restoring from the certificate comes
    // back near `mesh.not_before()`.
    let installed_at = host_unix()?;
    let mesh = TestMesh::mint_now()?;
    mesh.install(&mut node, installed_at).await?;
    anyhow::ensure!(
        node.node_info().await?.clock_posture() == ClockPosture::AtLeast,
        "the board should be anchored before the reset that is supposed to preserve it",
    );
    // A second read, deliberately. The checkpoint is written at the top of a
    // pass of the driver loop, so the pass that *served* the install had
    // already made its check with nothing to write. One more request guarantees
    // another pass, and so a checkpoint on the medium before the reset.
    node.security_status().await?;
    drop(node);

    // A reset, which is not a power cycle -- see `Board::reset`. Under a real
    // power cut these assertions are strictly stronger, never weaker: the
    // checkpoint would be the same and the free-run since it would be lost.
    board.reset()?;

    let mut node = Node::attach(&board).await?;
    node.with_diagnostics(async |node: &mut Node| {
        let info = node.node_info().await?;
        // `auth_locked` is *not* this check, and using it made this half of the
        // tripwire inert: it is `self_revoked || (require_auth && no cert)`, and
        // no board sets `require_auth`, so it reads false both before and after
        // a reset. `auth_enabled` is the fact wanted.
        anyhow::ensure!(
            node.security_status().await?.auth_enabled,
            "the credential is persisted, so a reset must bring it back; the board came \
             back unauthenticated",
        );
        anyhow::ensure!(
            info.clock_posture() == ClockPosture::AtLeast,
            "the checkpoint is persisted alongside the credential, so a reset must bring \
             the anchor back too; got {:?}",
            info.clock_posture(),
        );

        // `SetTime` is the only way to read the floor back: it refuses anything
        // at or below the current estimate, so a value the board accepts is one
        // it had not already reached.
        //
        // Halfway between the certificate's start and the install stamp. A
        // board restored from the checkpoint is already past this and refuses;
        // one restored from `not_before` is behind it and accepts. Accepting is
        // the failure.
        let Some(not_before) = mesh.not_before() else {
            anyhow::bail!("mint_now must produce a datable certificate");
        };
        let midpoint = not_before + (installed_at - not_before) / 2;
        // Specifically the monotonicity refusal, not merely *a* refusal: a
        // transport hiccup or an unimplemented request would otherwise read as
        // proof the floor is where it should be, on the one property this
        // whole design exists for.
        let Err(err) = node.set_time(midpoint).await else {
            anyhow::bail!(
                "the board accepted a time between its certificate's start and the install \
                 stamp, so its restored floor is behind the checkpoint -- it anchored from \
                 the certificate's not_before, which design 20 §4.4 forbids"
            );
        };
        anyhow::ensure!(
            format!("{err:#}").contains("no change"),
            "the refusal must be the estimate-already-past one; got: {err:#}",
        );
        Ok(())
    })
    .await
}

/// **#60, on the hardware that found it.**
///
/// A certificate binds a key to a MAC, and since design 09 §5 that MAC *is* the
/// address the key derives. The nRF board used to derive its address from FICR
/// instead, so the two could never agree: it accepted a credential naming a MAC
/// it did not route under, and its OGMs carried an originator its credential
/// did not name.
///
/// Design 22 makes the board seed-derived, which fixes it in the only way that
/// closes it — by construction rather than by a check. What is left is a
/// *bounded* divergence: `CentralRouter::self_ident` is fixed at construction,
/// so the address follows the new seed on the next boot rather than mid-flight.
/// Both halves are asserted here, because a test that only checked the second
/// would pass on a build that had quietly stopped installing anything.
#[tokio::test]
#[ignore = "needs hardware: a probed board playing the role \"alpha\""]
async fn an_installed_credential_is_adopted_across_a_reset() -> anyhow::Result<()> {
    let rig = Rig::load()?;
    let Some(board) = rig.board("alpha") else {
        return Ok(());
    };

    board.reset()?;
    let mut node = Node::attach(&board).await?;

    let mesh = TestMesh::mint_now()?;
    let before = node.node_info().await?.node_id.clone();
    mesh.install(&mut node, host_unix()?).await?;

    node.with_diagnostics(async |node: &mut Node| {
        // The window, and the node reporting it. Not a bug being tolerated: a
        // mid-flight address change strands every peer holding the old
        // originator, so the node holds its address and says the two disagree.
        anyhow::ensure!(
            node.node_info().await?.node_id == before,
            "the router's address must not change under a running node",
        );
        anyhow::ensure!(
            node.security_status().await?.node_mac == mesh.mac(),
            "the installed certificate's MAC is what GetSecurityStatus reports",
        );
        anyhow::ensure!(
            node.alarms().await?.alarms.iter().any(|a| {
                a.kind()
                    == wayfinder_protos::wayfinder::v1alpha::AlarmKind::CertifiedAddressMismatch
            }),
            "a node certified for an address it does not route under must say so rather \
             than leaving an operator to compare two fields",
        );
        Ok(())
    })
    .await?;
    drop(node);

    board.reset()?;

    let mut node = Node::attach(&board).await?;
    node.with_diagnostics(async |node: &mut Node| {
        let info = node.node_info().await?;
        anyhow::ensure!(
            info.node_id == mesh.mac(),
            "after the reset the board must route under the address its persisted seed \
             derives, which is the address its certificate names; got {:?}, wanted {:?}",
            info.node_id,
            mesh.mac(),
        );
        anyhow::ensure!(
            node.security_status().await?.node_mac == info.node_id,
            "the certified address and the routed address must now be one value -- that \
             is the whole of #60",
        );
        // Holding it *after* a reboot is the case that does not self-clear, and
        // the board raises it from its own boot path — so this is a real
        // assertion rather than one the reset satisfies for free by wiping an
        // in-memory board.
        anyhow::ensure!(
            !node.alarms().await?.alarms.iter().any(|a| {
                a.kind()
                    == wayfinder_protos::wayfinder::v1alpha::AlarmKind::CertifiedAddressMismatch
            }),
            "the board re-raised a certified-address mismatch at boot, which means its \
             address did not follow the seed its credential names",
        );
        Ok(())
    })
    .await
}

/// The clock floor never goes backwards across a reboot, which is the invariant
/// the whole checkpoint scheme rests on (design 20 §4.4).
///
/// A second reset is where a naive implementation shows itself: one that
/// restored from a stale flash page, or re-anchored from the certificate, would
/// come back *behind* where the first restore left it. The board cannot measure
/// how long it was off, so it may come back behind where it was *running* —
/// that deficit is expected and safe — but never behind what it wrote down.
#[tokio::test]
#[ignore = "needs hardware: a probed board playing the role \"alpha\""]
async fn a_second_reset_does_not_move_the_floor_backwards() -> anyhow::Result<()> {
    let rig = Rig::load()?;
    let Some(board) = rig.board("alpha") else {
        return Ok(());
    };

    let mut node = Node::attach(&board).await?;
    let installed_at = host_unix()?;
    TestMesh::mint_now()?
        .install(&mut node, installed_at)
        .await?;
    node.security_status().await?;
    drop(node);

    for pass in 1..=2 {
        board.reset()?;
        let mut node = Node::attach(&board).await?;
        node.with_diagnostics(async |node: &mut Node| {
            anyhow::ensure!(
                node.node_info().await?.clock_posture() == ClockPosture::AtLeast,
                "pass {pass}: the board must come back anchored",
            );
            // A day before the install stamp is well behind any floor the board
            // can legitimately hold, so accepting it means the estimate moved
            // backwards.
            let Err(err) = node.set_time(installed_at - 86_400).await else {
                anyhow::bail!(
                    "pass {pass}: the board accepted a time a day before its install stamp, \
                     so its floor went backwards across a reboot"
                );
            };
            anyhow::ensure!(
                format!("{err:#}").contains("no change"),
                "pass {pass}: the refusal must be the monotonicity one; got: {err:#}",
            );
            Ok(())
        })
        .await?;
    }
    Ok(())
}
