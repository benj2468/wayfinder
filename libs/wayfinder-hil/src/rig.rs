//! The entry point a hardware test starts from: the inventory, and the
//! skip-or-run decision it implies.
//!
//! The whole shape of this type is design 21 §4.3's rule — *a role the
//! inventory does not name is a skip with a stated reason, never a failure* —
//! made hard to get wrong. [`Rig::board`] returns an `Option`, so the natural
//! way to write a test is also the correct one:
//!
//! ```ignore
//! let Some(board) = rig.board("alpha") else { return Ok(()) };
//! ```
//!
//! A broken inventory still fails, because that comes back from
//! [`Rig::load`] as an error before any role is asked for.

use crate::board::Board;
use crate::inventory::Inventory;
use crate::inventory::InventoryError;
use crate::inventory::Missing;
use crate::node::Node;

/// The boards this machine has, and how tests reach them.
#[derive(Debug, Clone)]
pub struct Rig {
    inventory: Inventory,
}

impl Rig {
    /// Load the inventory: the file `WAYFINDER_HIL_CONFIG` names, or
    /// `hil.toml` found by searching the working directory and its ancestors.
    ///
    /// Errors only on a *broken* inventory. An absent one loads clean and
    /// empty, so every test skips.
    pub fn load() -> Result<Rig, InventoryError> {
        Ok(Rig {
            inventory: Inventory::load()?,
        })
    }

    /// Build a rig around an inventory already in hand, for a test of the
    /// harness itself.
    pub fn with_inventory(inventory: Inventory) -> Rig {
        Rig { inventory }
    }

    /// The board playing `role`, or `None` — having printed why.
    ///
    /// The reason goes to stderr rather than into the returned value because
    /// the caller's next move is `return Ok(())`: a skip that says nothing is
    /// indistinguishable from a test that passed, and the difference is exactly
    /// what an operator needs when `just hil` reports everything green on a
    /// machine with nothing plugged in.
    pub fn board(&self, role: &str) -> Option<Board> {
        match self.require(role) {
            Ok(board) => Some(board),
            Err(missing) => {
                eprintln!("SKIP: {missing}");
                None
            }
        }
    }

    /// The board playing `role`, or [`Missing`] — printing nothing.
    ///
    /// For a caller that *asked* for a board rather than one that can do
    /// without: a deliberate command finding no board has failed at the thing
    /// it was told to do, and should say so once rather than print a skip line
    /// and then contradict it with an error.
    pub fn require(&self, role: &str) -> Result<Board, Missing> {
        self.inventory
            .board(role)
            .map(|spec| Board::new(spec.clone()))
            .map_err(|missing| missing.clone())
    }

    /// Attach to the board playing `role`, or `None` — having said why.
    ///
    /// The whole preamble of a hardware test, in one line:
    ///
    /// ```ignore
    /// let Some(mut node) = Rig::load()?.attach("alpha").await? else {
    ///     return Ok(());
    /// };
    /// ```
    ///
    /// A test that needs the [`Board`] itself — to reset it, or to re-attach
    /// repeatedly — goes through [`board`](Self::board) and
    /// [`Node::attach`] instead, since the board outlives any one connection
    /// to it.
    pub async fn attach(&self, role: &str) -> anyhow::Result<Option<Node>> {
        let Some(board) = self.board(role) else {
            return Ok(None);
        };
        Ok(Some(Node::attach(&board).await?))
    }

    /// Every board the inventory names.
    pub fn boards(&self) -> Vec<Board> {
        self.inventory
            .boards()
            .iter()
            .cloned()
            .map(Board::new)
            .collect()
    }

    /// The inventory behind this rig.
    pub fn inventory(&self) -> &Inventory {
        &self.inventory
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// A rig with no boards has no board for any role, which is the
    /// `return Ok(())` path every hardware test takes on a machine with nothing
    /// attached.
    ///
    /// Asserted through `require` rather than `board`: the two agree, and
    /// `board`'s side effect is a `SKIP:` line on stderr, which under
    /// `success-output = "immediate"` would appear in `just hil`'s output as
    /// though a *hardware* test had skipped.
    #[test]
    fn an_empty_rig_has_no_board_for_any_role() {
        let rig = Rig::with_inventory(Inventory::empty());
        assert!(rig.require("alpha").is_err());
        assert!(rig.boards().is_empty());
    }

    /// A rig that has the board hands back a `Board` carrying its spec.
    #[test]
    fn a_named_role_yields_its_board() {
        let inventory = Inventory::parse(
            r#"
[[board]]
role  = "alpha"
kind  = "nrf52840-dk"
probe = "001050288335"
usb   = "F4CE3684A1B2"
"#,
            Path::new("hil.toml"),
        )
        .unwrap();

        let rig = Rig::with_inventory(inventory);
        let board = rig.require("alpha").expect("alpha is in the inventory");
        assert_eq!(board.role(), "alpha");
        assert_eq!(board.spec().usb, "F4CE3684A1B2");

        let missing = rig
            .require("beta")
            .expect_err("beta is not in the inventory");
        assert_eq!(missing.role, "beta");
        assert!(missing.known.contains("alpha"), "{missing}");
    }
}
