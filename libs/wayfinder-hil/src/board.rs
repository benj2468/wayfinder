//! One physical board: flashing it, resetting it, and finding its management
//! port.
//!
//! Everything here shells out to `probe-rs`, which is already in the devShell
//! and is what a human at the bench would run — so a harness failure stays
//! reproducible by hand.
//!
//! **Flashing a node is not here.** `cargo run` in a board's own directory
//! already does it, and does more: its configured runner is `probe-rs run …`,
//! which flashes *and* attaches RTT so the boot output is visible.
//! [`Board::flash`] exists for the other case — a test whose subject needs
//! firmware no operator would flash by hand, like the WL55's REYAX echo image
//! (`tests/reyax_interop.rs`). Such a test leaves that image on the board, and
//! says so.

use std::path::Path;
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
        .map(drop)
    }

    /// Flash `elf` onto this board, reset it, and confirm it booted the image.
    ///
    /// `probe-rs download` leaves the core halted in its flash loader in RAM,
    /// so the reset is what starts the image. The check after it catches the
    /// one way a correct flash still never runs: a part that boots its ROM
    /// bootloader instead (see [`BoardKind::boot_remap_register`]), which
    /// presents as firmware that does nothing at all.
    ///
    /// [`BoardKind::boot_remap_register`]: crate::BoardKind::boot_remap_register
    pub fn flash(&self, elf: &Path) -> anyhow::Result<()> {
        if !self.spec.kind.has_probe() {
            anyhow::bail!(
                "board {:?} is a {:?}, which has no probe and so cannot be flashed from the host",
                self.spec.role,
                self.spec.kind
            );
        }
        let probe = self.probe()?;
        let chip = self.spec.kind.chip();
        run(Command::new("probe-rs")
            .arg("download")
            .args(["--chip", chip])
            .args(["--probe", &probe])
            .arg("--non-interactive")
            .arg(elf))?;
        self.reset()?;

        let Some(register) = self.spec.kind.boot_remap_register() else {
            return Ok(());
        };
        let stdout = run(Command::new("probe-rs")
            .arg("read")
            .args(["--chip", chip])
            .args(["--probe", &probe])
            .arg("b32")
            .arg(format!("{register:#010x}"))
            .arg("1"))?;
        let value = parse_read_word(&stdout).ok_or_else(|| {
            anyhow::anyhow!("could not read the boot remap register from {stdout:?}")
        })?;
        if !booted_from_main_flash(value) {
            anyhow::bail!(
                "board {:?} booted its ROM bootloader, not the image just flashed \
                 (boot remap register {register:#010x} = {value:#010x}). This part decides what to \
                 boot at power-on and a reset does not revisit it: unplug and replug the board once",
                self.spec.role
            );
        }
        Ok(())
    }
}

/// The word in a `probe-rs read b32 <addr> 1` line, `"40010000: 00000001"`.
fn parse_read_word(stdout: &str) -> Option<u32> {
    let line = stdout.lines().find(|l| l.contains(':'))?;
    let word = line.split(':').nth(1)?.trim();
    u32::from_str_radix(word, 16).ok()
}

/// Whether an STM32 `SYSCFG_MEMRMP` value says main flash is mapped at `0`.
/// `MEM_MODE` is the low three bits; `000` is main flash, and every other
/// value — system flash (`001`) above all — means the image is not running.
fn booted_from_main_flash(memrmp: u32) -> bool {
    memrmp & 0b111 == 0
}

/// Run a command, turning a non-zero exit into an error carrying its stderr.
///
/// The stderr matters more than the status: `probe-rs` reports a permissions
/// problem, a probe that is not attached, and a chip that did not respond with
/// three quite different messages and one exit code.
///
/// Returns stdout, for the one caller that reads a value back.
fn run(command: &mut Command) -> anyhow::Result<String> {
    let rendered = format!("{command:?}");
    let output = command
        .output()
        .map_err(|e| anyhow::anyhow!("running {rendered}: {e}"))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    Err(anyhow::anyhow!(
        "{rendered} exited {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape `probe-rs read` prints, including the warning it emits on a
    /// dual-core part — which goes to stderr, but is tolerated here anyway.
    #[test]
    fn reads_the_word_from_probe_rs_output() {
        assert_eq!(parse_read_word("40010000: 00000001\n"), Some(1));
        assert_eq!(parse_read_word("e000ed08: 1fff0000\n"), Some(0x1FFF_0000));
        assert_eq!(parse_read_word(""), None);
        assert_eq!(parse_read_word("40010000: zz\n"), None);
    }

    /// The two values seen on the bench: main flash after a power cycle, the
    /// ROM bootloader before one.
    #[test]
    fn only_main_flash_counts_as_booted() {
        assert!(booted_from_main_flash(0b000));
        assert!(
            !booted_from_main_flash(0b001),
            "system flash: the ROM bootloader"
        );
        assert!(!booted_from_main_flash(0b011), "SRAM");
        assert!(
            booted_from_main_flash(0xFFFF_FF00),
            "only MEM_MODE's three bits count"
        );
    }
}
