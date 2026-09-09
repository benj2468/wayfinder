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

use wayfinder_auth::MIN_PLAUSIBLE_UNIX;
use wayfinder_hil::Node;
use wayfinder_hil::Rig;
use wayfinder_hil::mesh::TestMesh;
use wayfinder_hil::mesh::host_unix;
use wayfinder_protos::wayfinder::v1alpha::ClockPosture;

/// **The regression test for design 20's whole objection** (§10's test 13, and
/// §5's test 1 here): a board that cannot tell the time keeps working.
///
/// Under the superseded design an unanchored board rejected every certificate a
/// real authority issues and went inert. It must now report `Unknown` — judging
/// no validity window — and still answer as a router.
///
/// The half this cannot prove alone is "and has a neighbour": that needs a
/// second node, which is design 21 §5's test 4. What is checked here is that
/// the router is *running and answering*, which is what went away in the
/// failure this guards against.
#[tokio::test]
#[ignore = "needs hardware: a board playing the role \"alpha\""]
async fn an_unanchored_board_reports_unknown_and_keeps_answering() -> anyhow::Result<()> {
    let rig = Rig::load()?;
    let Some(board) = rig.board("alpha") else {
        return Ok(());
    };

    // Start from a known state: a board that has been given a time earlier in
    // the run is still holding it, and its clock only moves forward.
    board.reset()?;
    let mut node = Node::attach(&board).await?;

    // A credential that cannot date the board, installed with a zero stamp —
    // the fail-closed value a host sends when it cannot vouch for its own
    // clock. See `TestMesh::mint_undatable`: this is the only way to reach
    // credentialed-and-`Unknown`, and it is the state the whole design is
    // about.
    let mesh = TestMesh::mint_undatable()?;
    mesh.install(&mut node, 0).await?;

    node.with_diagnostics(async |node: &mut Node| {
        let info = node.node_info().await?;
        anyhow::ensure!(
            info.clock_posture() != ClockPosture::Unspecified,
            "the board reports no clock posture at all, which means its firmware predates \
             design 20 -- reflash it before trusting anything this test says",
        );
        // Proven before the assertion that rests on it: a `SetAuth` that
        // silently did nothing would otherwise be reported as "should judge no
        // windows", pointing at the clock instead of at the install.
        //
        // `auth_locked` is *not* this check: it means "required to
        // authenticate and holding no certificate yet", i.e. the inert state,
        // so a successful install makes it false.
        anyhow::ensure!(
            node.security_status().await?.auth_enabled,
            "the credential should be installed, so the node reports authentication on",
        );
        anyhow::ensure!(
            info.clock_posture() == ClockPosture::Unknown,
            "a credentialed board with nothing to date itself by should judge no windows, \
             got {:?}",
            info.clock_posture(),
        );

        // The router answers, which is the property that disappeared when an
        // unclocked node refused everything.
        node.routing_table().await?;
        node.link_quality_table().await?;

        // Design 21 §5's test 5, which is the same state: this is how a board
        // with no probe attached says "I am routing, and I am not judging
        // expiry".
        let alarms = node.alarms().await?;
        anyhow::ensure!(
            alarms.alarms.iter().any(|a| {
                a.kind() == wayfinder_protos::wayfinder::v1alpha::AlarmKind::ClockUnsynchronized
            }),
            "a credentialed board that cannot judge windows should raise \
             ClockUnsynchronized; alarms were {:?}",
            alarms.alarms.iter().map(|a| a.kind()).collect::<Vec<_>>(),
        );
        Ok(())
    })
    .await
}

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

/// Design 21 §5's test 3. **This test is written to be flipped, and deleting it
/// is the wrong way to make it pass.**
///
/// Today nothing persists a clock checkpoint, so a reset returns a board to
/// `Unknown`. That is the shipped behaviour and this pins it.
///
/// It is the executable form of design 20 §4.5's constraint on GitLab #52:
/// when a credential is persisted, the checkpoint must be persisted with it,
/// and boot must restore *from the checkpoint and nothing else*. When #52
/// lands, this test should be changed to assert `AtLeast` after a reset — and
/// if it starts reporting `AtLeast` while #52 is still open, or reports a floor
/// derived from the node's own certificate `not_before`, that is the rollback
/// design 20 §4.4 forbids in bold, not a test that needs updating.
#[tokio::test]
#[ignore = "needs hardware: a probed board playing the role \"alpha\""]
async fn a_reset_returns_the_board_to_unknown() -> anyhow::Result<()> {
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
    // clock stands, and there would be nothing for the reset to visibly clear.
    let mesh = TestMesh::mint_now()?;
    mesh.install(&mut node, host_unix()?).await?;
    anyhow::ensure!(
        node.node_info().await?.clock_posture() == ClockPosture::AtLeast,
        "the board should be anchored before the reset that is supposed to clear it",
    );
    drop(node);

    // A reset, which is not a power cycle -- see `Board::reset`. Under a real
    // power cut this assertion is strictly stronger, never weaker.
    board.reset()?;

    let mut node = Node::attach(&board).await?;
    node.with_diagnostics(async |node: &mut Node| {
        let info = node.node_info().await?;
        // `auth_locked` is *not* this check, and using it made this half of the
        // tripwire inert: it is `self_revoked || (require_auth && no cert)`, and
        // no board sets `require_auth`, so it reads false both before and after
        // a reset. `auth_enabled` is the fact wanted.
        anyhow::ensure!(
            !node.security_status().await?.auth_enabled,
            "nothing persists a credential yet, so a reset must clear it too; the board \
             came back still authenticated, which means #52 has landed and this test \
             needs the reading in its doc comment",
        );
        anyhow::ensure!(
            info.clock_posture() == ClockPosture::Unknown,
            "nothing persists a clock checkpoint yet, so a reset must clear the anchor; \
             got {:?}. If GitLab #52 has landed, read this test's doc comment \
             before changing it.",
            info.clock_posture(),
        );
        Ok(())
    })
    .await
}
