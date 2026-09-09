//! The hardware-in-the-loop harness: a host driving a real wayfinder node over
//! its management API.
//!
//! This is design 21's Tier B. It exists because four tiers of test already
//! run in this workspace and none of them executes an instruction on a
//! microcontroller, so every claim that is only true of running silicon —
//! peripherals, real cancellation, reboot, RF, heap exhaustion at real sizes —
//! is currently checked by a person at a bench, or not at all.
//!
//! # How to run it
//!
//! ```text
//! just hil-list   # what probe-rs sees, and how the inventory resolves
//! just hil        # every hardware test
//!
//! # flashing is `cargo run` in the board's own directory, which also
//! # attaches RTT so the boot output is visible:
//! cd bins/wayfinder-nrf52840 && cargo run --release
//! ```
//!
//! Nothing here runs under an ordinary `cargo nextest run --workspace`: every
//! hardware test is `#[ignore]`d, and this crate is a workspace member anyway
//! so that it *compiles* everywhere (design 21 §4.4 — a harness that only
//! builds on the rig breaks silently and is found weeks later).
//!
//! # The shape of a test
//!
//! A test names a [`role`](inventory::BoardSpec::role), never a device path,
//! and skips rather than fails when the inventory has no board for it:
//!
//! ```ignore
//! #[tokio::test]
//! #[ignore = "needs hardware"]
//! async fn unanchored_board_still_routes() -> anyhow::Result<()> {
//!     let Some(rig) = Rig::for_role("alpha")? else { return Ok(()) };
//!     let node = rig.node().await?;
//!     // ...
//! }
//! ```
//!
//! # Security note
//!
//! A board's management port is currently unauthenticated: the embedded serve
//! path dispatches straight to `handle_router` with no tier check, so anyone
//! with the cable can `SetAuth` and `SetTime`. That is why this harness needs
//! no credentials. It is tracked as GitLab #57, and **this crate must not
//! become the reason the port stays open** — every test drives a board through
//! [`wayfinder_client::Client`], so authenticating the transport later is a
//! change here and not a rewrite of the tests.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod board;
pub mod diagnostics;
pub mod inventory;
pub mod mesh;
pub mod node;
pub mod probe;
pub mod rig;
pub mod usb;

pub use board::Board;
pub use diagnostics::Diagnostics;
pub use inventory::BoardKind;
pub use inventory::BoardSpec;
pub use inventory::Inventory;
pub use inventory::InventoryError;
pub use inventory::Missing;
pub use node::Node;
pub use rig::Rig;
