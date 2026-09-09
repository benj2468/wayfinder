//! One physical board: flashing it, resetting it, and finding its management
//! port.
//!
//! Everything here shells out to `probe-rs`, which is already in the devShell
//! and is what a human at the bench would run — so a harness failure stays
//! reproducible by hand.
//!
//! **Flashing is deliberately not here.** `cargo run` in a board's own
//! directory already does it, and does more: its configured runner is
//! `probe-rs run … --allow-erase-all`, which flashes *and* attaches RTT so the
//! boot output is visible. The only thing this crate could add is picking a
//! probe by serial, which matters only once two are attached — so it belongs
//! with the second board, not before it.

use std::path::PathBuf;
use std::process::Command;

use crate::inventory::BoardSpec;
use crate::probe;
use crate::usb;

/// One attached board, addressed the way the inventory describes it.
#[derive(Debug, Clone)]
pub struct Board {
    spec: BoardSpec,
}

impl Board {
    /// Wrap an inventory entry.
    pub fn new(spec: BoardSpec) -> Board {
        Board { spec }
    }

    /// How the inventory describes this board.
    pub fn spec(&self) -> &BoardSpec {
        &self.spec
    }

    /// The role this board plays.
    pub fn role(&self) -> &str {
        &self.spec.role
    }

    /// The device node of this board's CDC-ACM management port.
    ///
    /// Resolved through the USB serial every time rather than cached: a board
    /// that resets re-enumerates, and may come back on a different node.
    pub fn management_port(&self) -> anyhow::Result<PathBuf> {
        let devices = usb::enumerate()?;
        Ok(usb::match_device(&devices, &self.spec.usb)?.to_path_buf())
    }

    /// The debug probe's serial, for a board that has one.
    ///
    /// The inventory names a *serial*; `probe-rs --probe` takes a
    /// `VID:PID:Serial` selector and rejects a bare one, so this resolves the
    /// former to the latter against what is currently attached.
    ///
    /// Guaranteed present for a probed board: the inventory rejects a
    /// [`BoardKind::has_probe`] entry without one at load time
    /// ([`InventoryError::ProbeRequired`](crate::InventoryError::ProbeRequired)),
    /// so a missing probe here is unreachable rather than merely unlikely.
    fn probe(&self) -> anyhow::Result<String> {
        let wanted = self.spec.probe.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "board {:?} ({:?}) has no probe serial",
                self.spec.role,
                self.spec.kind
            )
        })?;
        Ok(probe::resolve(&probe::list()?, wanted)?.to_string())
    }

    /// Reset this board.
    ///
    /// **A reset is not a power cycle** (design 21 §6.2): RAM contents and some
    /// peripheral state do not necessarily behave as they would across a real
    /// power cut, which matters for exactly the persistence tests that most
    /// want one. A test that depends on the difference must say so.
    pub fn reset(&self) -> anyhow::Result<()> {
        if !self.spec.kind.has_probe() {
            // Not a `todo!()`: there is no reset path to build. A dongle is
            // reset by unplugging it, so a test needing one asks for a probed
            // board and skips otherwise.
            anyhow::bail!(
                "board {:?} is a {:?}, which has no probe and so cannot be reset from the host \
                 -- ask for a probed board, or power-cycle it by hand",
                self.spec.role,
                self.spec.kind
            );
        }
        run(Command::new("probe-rs")
            .arg("reset")
            .args(["--chip", self.spec.kind.chip()])
            .args(["--probe", &self.probe()?]))
    }
}

/// Run a command, turning a non-zero exit into an error carrying its stderr.
///
/// The stderr matters more than the status: `probe-rs` reports a permissions
/// problem, a probe that is not attached, and a chip that did not respond with
/// three quite different messages and one exit code.
fn run(command: &mut Command) -> anyhow::Result<()> {
    let rendered = format!("{command:?}");
    let output = command
        .output()
        .map_err(|e| anyhow::anyhow!("running {rendered}: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "{rendered} exited {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}
