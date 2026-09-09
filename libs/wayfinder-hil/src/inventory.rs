//! The board inventory: which physical parts are attached to this machine, and
//! which test role each one plays.
//!
//! Two rules shape this module, both from design 21 §4.3, and both are about
//! keeping a hardware harness alive on machines that have no hardware:
//!
//! - **A role a test asks for and the inventory does not name is a
//!   [`Missing`] — a skip with a stated reason, never a failure.** `just hil`
//!   on a laptop with nothing plugged in must exit clean, or the harness gets
//!   disabled within a week.
//! - **A malformed inventory is an [`InventoryError`] — a failure, never a
//!   skip.** The distinction between "no boards here" and "this config is
//!   broken" is the one that decides whether a silent no-op is correct, so the
//!   two never share a type.
//!
//! Tests name *roles*, never device paths. Which physical part plays a role
//! stays in one file, which is what lets the same tests run on a desk and on a
//! self-hosted runner.

use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;

/// The inventory *filename* searched for in the working directory and every
/// ancestor, when `WAYFINDER_HIL_CONFIG` is unset.
pub const DEFAULT_INVENTORY_PATH: &str = "hil.toml";

/// The environment variable naming an inventory file, overriding
/// [`DEFAULT_INVENTORY_PATH`].
pub const INVENTORY_PATH_ENV: &str = "WAYFINDER_HIL_CONFIG";

/// What kind of part a board is, which decides how it is flashed and reset.
///
/// The distinction is not cosmetic: a DK has an onboard J-Link and is
/// programmed and reset through it, while a dongle has no probe at all and is
/// reached only by DFU over USB, with "reset" meaning a re-enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum BoardKind {
    /// nRF52840 DK (PCA10056): onboard J-Link, flashed with `probe-rs`.
    #[serde(rename = "nrf52840-dk")]
    Nrf52840Dk,
    /// nRF52840 dongle (PCA10059): no probe, flashed by DFU with `nrfutil`.
    #[serde(rename = "nrf52840-dongle")]
    Nrf52840Dongle,
}

impl BoardKind {
    /// Whether a part of this kind is reached through a debug probe.
    ///
    /// Governs both halves of what a harness can do with it: only a probed
    /// board can be flashed by `probe-rs`, reset on demand, or run the
    /// on-target tests of design 21's Tier A.
    pub fn has_probe(self) -> bool {
        matches!(self, BoardKind::Nrf52840Dk)
    }

    /// The `probe-rs --chip` argument for this part.
    pub fn chip(self) -> &'static str {
        match self {
            BoardKind::Nrf52840Dk | BoardKind::Nrf52840Dongle => "nRF52840_xxAA",
        }
    }
}

/// One attached board, as the inventory describes it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardSpec {
    /// The name tests ask for (`rig.board("alpha")`).
    pub role: String,
    /// What kind of part it is.
    pub kind: BoardKind,
    /// The debug probe's serial number, for a part that has one.
    ///
    /// Addressed by serial and never by enumeration order: device nodes and
    /// probe indices reorder between plugs and across a reset, and a rig that
    /// indexes them is a rig that fails on the day a second board is attached.
    #[serde(default)]
    pub probe: Option<String>,
    /// The USB serial number of the device exposing the management port, used
    /// to find its `/dev/ttyACM*` node.
    pub usb: String,
}

/// The set of boards attached to this machine.
#[derive(Debug, Clone, Default)]
pub struct Inventory {
    boards: Vec<BoardSpec>,
    /// Where the inventory was read from, so a [`Missing`] can say what was
    /// consulted. `None` when no file existed.
    source: Option<PathBuf>,
}

/// A genuine fault in the inventory: the operator meant to describe boards and
/// the description does not make sense.
///
/// Never returned for an *absent* inventory — see the module docs.
#[derive(Debug, thiserror::Error)]
pub enum InventoryError {
    /// The file exists and could not be read.
    #[error("reading the HIL inventory at {path}")]
    Read {
        /// The path that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The file exists and is not valid TOML, or does not match the schema.
    #[error("parsing the HIL inventory at {path}")]
    Parse {
        /// The path that could not be parsed.
        path: PathBuf,
        /// The underlying deserialization error.
        #[source]
        source: toml::de::Error,
    },
    /// Two entries claim the same role, so `board(role)` has no single answer.
    #[error("the HIL inventory names the role {role:?} more than once")]
    DuplicateRole {
        /// The role named twice.
        role: String,
    },
    /// An entry names an empty `usb` serial, which would match any device
    /// reporting a blank `iSerialNumber` rather than one board.
    #[error("the HIL inventory's role {role:?} has an empty `usb` serial")]
    EmptyUsbSerial {
        /// The role with no USB serial.
        role: String,
    },
    /// A part that is reached through a probe has no probe serial, so nothing
    /// can flash or reset it. Caught at load time because failing here names
    /// the config line, where failing at flash time names a `probe-rs` exit
    /// code.
    #[error("the HIL inventory's role {role:?} is a {kind:?}, which needs a `probe` serial")]
    ProbeRequired {
        /// The role missing a probe serial.
        role: String,
        /// The kind that requires one.
        kind: BoardKind,
    },
}

/// Why a role a test asked for is not available.
///
/// Deliberately not an [`InventoryError`]: a test that receives this **skips**,
/// and says why. Keeping the two apart is what lets `just hil` be a clean no-op
/// on a machine with no boards while still failing loudly on a broken file.
/// **Deliberately not an [`Error`](std::error::Error).** That is not an
/// oversight: without the trait there is no `From<Missing> for anyhow::Error`,
/// so `inventory.board(role)?` inside an `anyhow::Result` function does not
/// compile, and a skip cannot be propagated as a failure by reflex. The rule is
/// enforced by the trait system rather than by convention — do not add
/// `#[derive(thiserror::Error)]` here for a nicer message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Missing {
    /// The role that was asked for.
    pub role: String,
    /// The roles the inventory does name, for the skip message.
    pub known: BTreeSet<String>,
    /// The file consulted, or `None` if there was no inventory at all.
    pub source: Option<PathBuf>,
}

impl std::fmt::Display for Missing {
    /// The skip line a test prints. Names the role, what was consulted, and
    /// what *is* attached — an operator reading "skipped" needs to know
    /// whether to plug something in or fix a name.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.source {
            None => write!(
                f,
                "no HIL inventory (set {} or create {}), so no board plays the role {:?}",
                INVENTORY_PATH_ENV, DEFAULT_INVENTORY_PATH, self.role
            ),
            Some(path) => {
                write!(
                    f,
                    "{} names no board for the role {:?}",
                    path.display(),
                    self.role
                )?;
                if self.known.is_empty() {
                    write!(f, " (it names no boards at all)")
                } else {
                    let known: Vec<&str> = self.known.iter().map(String::as_str).collect();
                    write!(f, " (it names: {})", known.join(", "))
                }
            }
        }
    }
}

/// The `hil.toml` schema: a list of `[[board]]` tables.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryFile {
    #[serde(default)]
    board: Vec<BoardSpec>,
}

impl Inventory {
    /// Load the file `WAYFINDER_HIL_CONFIG` names, or search the working
    /// directory and its ancestors for [`DEFAULT_INVENTORY_PATH`].
    ///
    /// An absent file is an **empty inventory**, not an error: it is the
    /// ordinary state of a machine with no boards attached, and every test then
    /// skips with a reason.
    pub fn load() -> Result<Inventory, InventoryError> {
        if let Some(named) = std::env::var_os(INVENTORY_PATH_ENV) {
            // Named explicitly: used as given, never searched for. An operator
            // who points at a file and gets a *different* one has been lied to.
            //
            // And an absence here is a **failure**, unlike the default path.
            // Absent-is-empty exists for the developer laptop that never meant
            // to have boards; someone who set this variable has stated intent,
            // and rounding their typo to "no boards attached" hands them a
            // green run on a bench with hardware plugged in — then tells them
            // to set the variable they just set.
            let path = PathBuf::from(named);
            if path.as_os_str().is_empty() {
                return Err(InventoryError::Read {
                    path,
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("{INVENTORY_PATH_ENV} is set but empty"),
                    ),
                });
            }
            return Inventory::require_from(&path);
        }
        let from = std::env::current_dir().map_err(|source| InventoryError::Read {
            path: PathBuf::from("."),
            source,
        })?;
        Inventory::discover_from(&from)
    }

    /// Search `start` and its ancestors for [`DEFAULT_INVENTORY_PATH`], and
    /// load the first one found.
    ///
    /// Upward rather than relative to the working directory, because the
    /// working directory is not something a test controls: cargo runs one with
    /// its cwd at the *package* root, so a bare `hil.toml` resolved there
    /// misses the workspace-root file entirely — and the symptom is every test
    /// skipping as though no boards were attached, which is indistinguishable
    /// from the state the skip is designed for. This is how cargo finds
    /// `Cargo.toml` and git finds `.git`.
    ///
    /// No ancestor having one is an empty inventory, per
    /// [`load_from`](Self::load_from)'s rule.
    pub(crate) fn discover_from(start: &Path) -> Result<Inventory, InventoryError> {
        for dir in start.ancestors() {
            let candidate = dir.join(DEFAULT_INVENTORY_PATH);
            // `Path::is_file` is `metadata(..).map(..).unwrap_or(false)`, so it
            // reports EACCES, ELOOP and EIO identically to "not here" and the
            // walk sails past a file that exists and cannot be read — a
            // permission problem on a shared bench then reads as "no boards".
            // Stat explicitly so only a real absence continues the search.
            match std::fs::metadata(&candidate) {
                Ok(m) if m.is_file() => return Inventory::require_from(&candidate),
                Ok(_) => {
                    return Err(InventoryError::Read {
                        path: candidate,
                        source: std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "not a regular file",
                        ),
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(InventoryError::Read {
                        path: candidate,
                        source,
                    });
                }
            }
        }
        Ok(Inventory::empty())
    }

    /// Load a file that is required to exist: every I/O failure, absence
    /// included, is an [`InventoryError`].
    ///
    /// The counterpart to [`load_from`](Self::load_from)'s absent-is-empty
    /// rule, for the paths where absence is a misconfiguration rather than the
    /// ordinary state of a machine with no boards.
    pub(crate) fn require_from(path: &Path) -> Result<Inventory, InventoryError> {
        let text = std::fs::read_to_string(path).map_err(|source| InventoryError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Inventory::parse(&text, path)
    }

    /// Parse an inventory from TOML text already read from `path`.
    ///
    /// Separate from [`load_from`](Self::load_from) so the schema, the
    /// duplicate-role check and the probe check are testable without a
    /// filesystem.
    pub fn parse(text: &str, path: &Path) -> Result<Inventory, InventoryError> {
        let file: InventoryFile = toml::from_str(text).map_err(|source| InventoryError::Parse {
            path: path.to_path_buf(),
            source,
        })?;

        let mut seen = BTreeSet::new();
        for board in &file.board {
            if !seen.insert(board.role.clone()) {
                return Err(InventoryError::DuplicateRole {
                    role: board.role.clone(),
                });
            }
            // An empty serial matches a device whose `iSerialNumber` is blank,
            // which is a different board every time it is plugged in. Refused
            // here so the mistake names the config line.
            if board.usb.trim().is_empty() {
                return Err(InventoryError::EmptyUsbSerial {
                    role: board.role.clone(),
                });
            }
            if board.kind.has_probe() && board.probe.is_none() {
                return Err(InventoryError::ProbeRequired {
                    role: board.role.clone(),
                    kind: board.kind,
                });
            }
        }

        Ok(Inventory {
            boards: file.board,
            source: Some(path.to_path_buf()),
        })
    }

    /// An inventory naming no boards, as if no file existed.
    pub fn empty() -> Inventory {
        Inventory {
            boards: Vec::new(),
            source: None,
        }
    }

    /// The board playing `role`, or why there is none.
    pub fn board(&self, role: &str) -> Result<&BoardSpec, Missing> {
        self.boards
            .iter()
            .find(|b| b.role == role)
            .ok_or_else(|| Missing {
                role: role.to_string(),
                known: self.boards.iter().map(|b| b.role.clone()).collect(),
                source: self.source.clone(),
            })
    }

    /// Every board the inventory names, in file order.
    pub fn boards(&self) -> &[BoardSpec] {
        &self.boards
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An inventory naming one DK and one dongle — the rig design 21 §10 takes
    /// as the floor.
    const TWO_BOARDS: &str = r#"
[[board]]
role  = "alpha"
kind  = "nrf52840-dk"
probe = "001050288335"
usb   = "F4CE3684A1B2"

[[board]]
role = "dongle"
kind = "nrf52840-dongle"
usb  = "CD1F4A0099EE"
"#;

    fn parse(text: &str) -> Result<Inventory, InventoryError> {
        Inventory::parse(text, Path::new("hil.toml"))
    }

    /// The ordinary case: a role the file names resolves to that board.
    #[test]
    fn a_named_role_resolves_to_its_board() {
        let inv = parse(TWO_BOARDS).unwrap();

        let alpha = inv.board("alpha").unwrap();
        assert_eq!(alpha.kind, BoardKind::Nrf52840Dk);
        assert_eq!(alpha.probe.as_deref(), Some("001050288335"));
        assert_eq!(alpha.usb, "F4CE3684A1B2");

        let dongle = inv.board("dongle").unwrap();
        assert_eq!(dongle.kind, BoardKind::Nrf52840Dongle);
        assert_eq!(dongle.probe, None);
    }

    /// A role the inventory does not name is a *skip*, and the reason names
    /// both the role asked for and what is actually attached — an operator
    /// reading "skipped" needs to know whether to plug something in or fix a
    /// name.
    #[test]
    fn an_unknown_role_is_a_skip_that_names_what_is_attached() {
        let inv = parse(TWO_BOARDS).unwrap();

        let missing = inv.board("beta").unwrap_err();
        assert_eq!(missing.role, "beta");
        assert_eq!(missing.source.as_deref(), Some(Path::new("hil.toml")));

        let msg = missing.to_string();
        assert!(msg.contains("beta"), "{msg}");
        assert!(msg.contains("alpha"), "{msg}");
        assert!(msg.contains("dongle"), "{msg}");
    }

    /// **The rule the whole module exists for.** No inventory file is the
    /// ordinary state of a developer laptop, so it yields an empty inventory
    /// and every test skips — never an error, or `just hil` fails for everyone
    /// who has no boards and gets switched off.
    #[test]
    fn an_absent_inventory_is_empty_rather_than_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let inv = Inventory::discover_from(dir.path()).unwrap();

        assert!(inv.boards().is_empty());

        let missing = inv.board("alpha").unwrap_err();
        assert_eq!(missing.source, None);
        assert!(
            missing.to_string().contains(INVENTORY_PATH_ENV),
            "the no-inventory skip should say how to create one: {missing}"
        );
    }

    /// The counterpart rule: a file that *exists* and is broken is a failure.
    /// Rounding this to a skip would make a typo indistinguishable from an
    /// unplugged board.
    #[test]
    fn a_malformed_inventory_is_an_error_rather_than_a_skip() {
        let err = parse("[[board]\nrole = ").unwrap_err();
        assert!(matches!(err, InventoryError::Parse { .. }), "{err:?}");
    }

    /// An unknown `kind` is a parse error, not a board the harness cannot
    /// flash: the set of parts a rig knows how to drive is closed.
    #[test]
    fn an_unknown_board_kind_is_a_parse_error() {
        let err = parse(
            r#"
[[board]]
role = "alpha"
kind = "esp32"
usb  = "ABC"
"#,
        )
        .unwrap_err();
        assert!(matches!(err, InventoryError::Parse { .. }), "{err:?}");
    }

    /// Two entries claiming one role has no single answer, so it is rejected at
    /// load time rather than resolved by file order.
    #[test]
    fn a_duplicate_role_is_rejected() {
        let err = parse(
            r#"
[[board]]
role = "alpha"
kind = "nrf52840-dk"
probe = "AAA"
usb  = "111"

[[board]]
role = "alpha"
kind = "nrf52840-dk"
probe = "BBB"
usb  = "222"
"#,
        )
        .unwrap_err();
        match err {
            InventoryError::DuplicateRole { role } => assert_eq!(role, "alpha"),
            other => panic!("expected DuplicateRole, got {other:?}"),
        }
    }

    /// A DK is flashed and reset through its probe, so an entry without a probe
    /// serial describes a board nothing can drive. Caught here because this
    /// failure names the config line; the same mistake caught at flash time
    /// names a `probe-rs` exit code.
    #[test]
    fn a_probed_board_without_a_probe_serial_is_rejected() {
        let err = parse(
            r#"
[[board]]
role = "alpha"
kind = "nrf52840-dk"
usb  = "111"
"#,
        )
        .unwrap_err();
        match err {
            InventoryError::ProbeRequired { role, kind } => {
                assert_eq!(role, "alpha");
                assert_eq!(kind, BoardKind::Nrf52840Dk);
            }
            other => panic!("expected ProbeRequired, got {other:?}"),
        }
    }

    /// ...and the dongle, which has no probe at all, is not held to that rule.
    #[test]
    fn a_dongle_needs_no_probe_serial() {
        let inv = parse(
            r#"
[[board]]
role = "dongle"
kind = "nrf52840-dongle"
usb  = "111"
"#,
        )
        .unwrap();
        assert!(!inv.board("dongle").unwrap().kind.has_probe());
    }

    /// **The inventory is found by searching upward, not by trusting the
    /// working directory.**
    ///
    /// Cargo runs a test with its working directory set to the *package* root
    /// (`libs/wayfinder-hil`), not the workspace root where `hil.toml` lives —
    /// so a bare relative path finds nothing, and the failure is the worst
    /// shape available: every test skips as if no boards were attached, on a
    /// bench where they are. Searching upward is how cargo finds `Cargo.toml`
    /// and git finds `.git`, and it makes the file work from the workspace
    /// root, from a crate directory, and under nextest alike.
    #[test]
    fn the_inventory_is_found_in_an_ancestor_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("hil.toml"), TWO_BOARDS).unwrap();

        let deep = root.join("libs/wayfinder-hil/src");
        std::fs::create_dir_all(&deep).unwrap();

        let found = Inventory::discover_from(&deep).unwrap();
        assert_eq!(found.boards().len(), 2, "searching up from {deep:?}");
        assert!(found.board("alpha").is_ok());

        // ...and from the directory holding it.
        assert_eq!(Inventory::discover_from(root).unwrap().boards().len(), 2);
    }

    /// No ancestor has one: an empty inventory, which is the ordinary state of
    /// a machine with no boards — not an error, and not a search that walks off
    /// the filesystem.
    #[test]
    fn no_inventory_in_any_ancestor_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let deep = dir.path().join("a/b/c");
        std::fs::create_dir_all(&deep).unwrap();

        let found = Inventory::discover_from(&deep).unwrap();
        assert!(found.boards().is_empty());
        assert_eq!(found.board("alpha").unwrap_err().source, None);
    }

    /// A file naming no boards is valid and empty — the state of a rig whose
    /// boards are all unplugged, which must skip rather than fail.
    #[test]
    fn an_empty_inventory_file_names_no_boards() {
        let inv = parse("").unwrap();
        assert!(inv.boards().is_empty());
        let msg = inv.board("alpha").unwrap_err().to_string();
        assert!(msg.contains("no boards at all"), "{msg}");
    }
}
