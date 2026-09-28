//! The rig itself: does every board the inventory names actually answer?
//!
//! Run this first when `just hil` reports something strange. It separates "the
//! rig is misconfigured" from "the firmware is wrong", which are otherwise the
//! same red.

use wayfinder_hil::Node;
use wayfinder_hil::Rig;

/// Every board in the inventory enumerates, opens, and answers `GetNodeInfo`.
///
/// Skips cleanly — and says so — on a machine with no inventory, which is the
/// ordinary state of a developer laptop.
#[tokio::test]
#[ignore = "needs hardware: whatever the inventory names"]
async fn every_inventoried_board_answers() -> anyhow::Result<()> {
    let rig = Rig::load()?;
    let boards = rig.boards();
    if boards.is_empty() {
        eprintln!("SKIP: the HIL inventory names no boards");
        return Ok(());
    }

    for board in boards {
        Node::attach(&board)
            .await
            .map_err(|e| e.context(format!("board {:?}", board.role())))?
            .report()
            .await;
    }
    Ok(())
}

/// Every board is running firmware built from *this* commit, and both sides are
/// a committed tree so that comparison means something.
///
/// The question #61 exists for, asked the only way it can be answered:
/// over the management API. Before this, "does the board carry fix X?" was
/// settled by the mtime of a `.hex` file and a question to whoever last flashed
/// it — which on a board flashed weeks ago by someone else is not even a guess.
///
/// **What this can and cannot prove**, because the difference decides whether a
/// green run means anything:
///
/// - It catches a board flashed from a different *commit*. That is the case it
///   exists for, and `just hil` does *not* flash (only `just hil-fresh` does, and
///   otherwise a board is flashed by `cargo run --release` from its own
///   directory), so running the suite against stale firmware is easy to do by
///   accident.
/// - It **cannot** distinguish two different dirty builds of the same commit:
///   `git describe --dirty` yields the identical string for every edit of a
///   commit, so fifty edits later a board still compares byte-equal. Since a
///   bench flash is normally from a modified tree, that blind spot would be the
///   common case — hence the refusal below rather than a green pass.
/// - A mismatch is *usually* the finding rather than a flake, but not always:
///   the dirty marker can lag a build on either side (see `build.rs`'s
///   `watch_git_state`), so the same tree can disagree with itself. Requiring
///   both sides clean removes that ambiguity too.
#[tokio::test]
#[ignore = "needs hardware: whatever the inventory names"]
async fn every_board_runs_the_build_in_this_tree() -> anyhow::Result<()> {
    let rig = Rig::load()?;
    let boards = rig.boards();
    if boards.is_empty() {
        eprintln!("SKIP: the HIL inventory names no boards");
        return Ok(());
    }

    for board in boards {
        let role = board.role();
        let mut node = Node::attach(&board)
            .await
            .map_err(|e| e.context(format!("board {role:?}")))?;

        let info = node.node_info().await?;
        let build = info.build_info.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "board {role:?} reports no build at all: its firmware predates \
                 build provenance, so it is certainly not this tree"
            )
        })?;

        // Equality is only evidence when neither side is a dirty build, because
        // every edit of a commit produces the same `-dirty` string. Refusing
        // here rather than passing is the point: a green run must mean the
        // firmware is this code, and against two dirty trees it cannot.
        anyhow::ensure!(
            !build.dirty && !wayfinder_version::DIRTY,
            "board {role:?} reports {} and this tree is {} — at least one is a \
             modified tree, so matching version strings would prove nothing \
             about whether the flashed firmware is this code. Commit (or stash), \
             reflash, then re-run.",
            build.version,
            wayfinder_version::VERSION,
        );

        anyhow::ensure!(
            build.version == wayfinder_version::VERSION,
            "board {role:?} is running {} ({}) but this tree is {} ({}) — \
             reflash it, or stop trusting this run: every other assertion here \
             is about firmware that is not the code under test",
            build.version,
            build.commit,
            wayfinder_version::VERSION,
            wayfinder_version::COMMIT,
        );
    }
    Ok(())
}
