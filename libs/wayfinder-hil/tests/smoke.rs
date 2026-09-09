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
