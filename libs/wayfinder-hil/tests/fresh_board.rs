//! Claims that are only true of a board which has **never held a credential**,
//! and which therefore need their own invocation.
//!
//! # Why this is not in `clock.rs`
//!
//! Design 22 made a board's credential and its clock checkpoint durable, so
//! anchoring one is a one-way door: the estimate never decreases, by design, and
//! nothing over the management API takes it back. Every test in `clock.rs`
//! installs a credential, so after any one of them has run the board can no
//! longer be in the state this file is about.
//!
//! Keeping these tests in the same binary looked fine and was not: nextest runs
//! a binary's tests in name order, `a_reset_…` and `a_second_…` sort before
//! `an_unanchored_…`, and the unanchored test skipped on **every** run —
//! including against a freshly erased board. A green suite in which the headline
//! regression test for design 20 never executes is exactly the unfalsifiable
//! failure design 21 §6.4 is written against.
//!
//! Ordering was not the fix. Renaming a test so it sorts first makes the suite
//! depend on an ordering nextest does not promise, and the failure mode when it
//! changes is silence again. The precondition is real, so it is stated:
//!
//! ```text
//! just hil-fresh
//! ```
//!
//! erases the board, reflashes it and runs this binary alone. `just hil` still
//! runs it, and it still skips there — but the skip names that command, so the
//! gap is a decision an operator makes rather than a green run they misread.
//!
//! The board is *not* left blank afterwards — `SetAuth` is durable since design
//! 22, so it holds a rig-minted, undatable credential. What matters is that its
//! checkpoint is still zero, so it still reads `Unknown` and this file can be
//! re-run; every other test installs its own credential over the top.

use wayfinder_hil::Node;
use wayfinder_hil::Rig;
use wayfinder_hil::mesh::TestMesh;
use wayfinder_protos::wayfinder::v1alpha::ClockPosture;

/// **The regression test for design 20's whole objection** (its §10 test 13,
/// and design 21 §5's test 1): a board that cannot tell the time keeps working.
///
/// Under the superseded design an unanchored board rejected every certificate a
/// real authority issues and went inert. It must instead report `Unknown` —
/// judging no validity window — and still answer as a router.
///
/// The half this cannot prove alone is "and has a neighbour": that needs a
/// second node, design 21 §5's test 4. What is checked here is that the router
/// is *running and answering*, which is what went away in the failure this
/// guards against.
///
/// The state under test is credentialed-and-`Unknown`, which is reachable only
/// on a board with no persisted checkpoint — see this file's module docs for
/// why that means its own invocation.
#[tokio::test]
#[ignore = "needs hardware: a freshly erased board playing the role \"alpha\" (just hil-fresh)"]
async fn an_unanchored_board_reports_unknown_and_keeps_answering() -> anyhow::Result<()> {
    let rig = Rig::load()?;
    let Some(board) = rig.board("alpha") else {
        return Ok(());
    };

    // Clears a credential held in RAM, but *not* the durable record behind one
    // — which is exactly what the check below is about.
    board.reset()?;
    let mut node = Node::attach(&board).await?;

    // `clock_posture` is read from the router's auth state, so an
    // uncredentialed board reports `Unknown` however the wall clock stands.
    // `AtLeast` here therefore means two things at once: the board restored a
    // credential *and* a checkpoint from flash, and neither can be undone from
    // the host.
    if node.node_info().await?.clock_posture() == ClockPosture::AtLeast {
        eprintln!(
            "SKIP: board \"alpha\" restored a credential and a clock checkpoint from flash, \
             so it cannot be returned to Unknown from the host -- the estimate never \
             decreases, by design. Run `just hil-fresh` to erase the board, reflash it \
             and run this test against a blank one."
        );
        return Ok(());
    }

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
        anyhow::ensure!(
            info.clock_posture() == ClockPosture::Unknown,
            "a credentialed board with nothing to date itself by should judge no windows, \
             got {:?}",
            info.clock_posture(),
        );
        // `auth_locked` is *not* this check: it means "required to
        // authenticate and holding no certificate yet", i.e. the inert state,
        // so a successful install makes it false.
        anyhow::ensure!(
            node.security_status().await?.auth_enabled,
            "the credential should be installed, so the node reports authentication on",
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

/// A board that has never been provisioned mints a **random** seed, not one
/// derived from the chip's factory ID (design 22 §4.3).
///
/// The device ID is not secret — anything on the chip can read it, and it is
/// printed on the part — so a key derived from it is derivable by anyone who
/// knows it. That is unobservable from a single boot: what a FICR-seeded build
/// and a randomly-seeded one both produce is *an* address. What separates them
/// is that the FICR one is reproducible, so this checks the seed-derived
/// address against the board id the same chip yields.
///
/// The USB serial is the control. It *is* the board id, deliberately (design 22
/// §4.3), and the rig found this board by it — so a mesh address equal to it
/// would mean the seed came from FICR.
#[tokio::test]
#[ignore = "needs hardware: a freshly erased board playing the role \"alpha\" (just hil-fresh)"]
async fn a_fresh_board_mints_a_seed_that_is_not_its_board_id() -> anyhow::Result<()> {
    let rig = Rig::load()?;
    let Some(board) = rig.board("alpha") else {
        return Ok(());
    };

    let mut node = Node::attach(&board).await?;

    // The same precondition its sibling needs, and for a subtler reason: once
    // a rig credential is installed, `node_id` is the *rig-minted* seed's MAC,
    // which is also not the board id — so the assertion below would pass
    // without ever exercising the mint, and a regression to a FICR-derived
    // seed would be invisible on every run but a `just hil-fresh` one. A
    // silent pass rather than a silent skip, which is worse.
    if node.security_status().await?.auth_enabled {
        eprintln!(
            "SKIP: board \"alpha\" holds a rig-installed credential, so its address is not \
             the one it minted for itself and this test would pass without checking \
             anything. Run `just hil-fresh` to erase it, reflash it and run this against \
             a blank board."
        );
        return Ok(());
    }

    node.with_diagnostics(async |node: &mut Node| {
        let node_id = node.node_info().await?.node_id;

        // `hil.toml`'s `usb` field is the board id rendered as hex, which is
        // what the firmware puts in its USB serial number.
        let board_id = hex_bytes(&board.spec().usb)?;
        anyhow::ensure!(
            node_id != board_id,
            "this node's mesh address equals its FICR board id ({:x?}), so its identity \
             seed was derived from a value that is not secret",
            board_id,
        );
        anyhow::ensure!(
            node_id.len() == 6 && node_id.iter().any(|b| *b != 0),
            "a minted address should be six non-zero bytes, got {node_id:x?}",
        );
        Ok(())
    })
    .await
}

/// Parse the 12 hex digits of an inventory `usb` field into six bytes.
fn hex_bytes(text: &str) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        text.len() == 12,
        "a board id is 12 hex digits, got {text:?}"
    );
    (0..6)
        .map(|i| {
            u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
                .map_err(|e| anyhow::anyhow!("board id {text:?} is not hex: {e}"))
        })
        .collect()
}
