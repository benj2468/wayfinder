//! Finding a board's management port among the CDC-ACM devices this machine
//! has enumerated.
//!
//! The matching is kept pure and the enumeration is not, because the matching
//! is where the bug lives. Design 21 §6.4 names addressing by *serial* rather
//! than by enumeration order as one of three decisions taken specifically
//! against flakiness: `/dev/ttyACM*`
//! numbering reorders between plugs, across a board reset, and the moment a
//! second part is attached — so a rig that opens `ttyACM0` works right up until
//! it silently starts driving the wrong board.
//!
//! [`match_device`] therefore takes a slice and is tested against fixtures;
//! [`enumerate`] does the `/sys` walk and is not.

use std::path::Path;
use std::path::PathBuf;

/// Where character devices live, which is not something a fixture varies.
const DEV_DIR: &str = "/dev";

/// One enumerated CDC-ACM device: the node to open, and the USB serial number
/// of the device behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialDevice {
    /// The character device, e.g. `/dev/ttyACM0`.
    pub node: PathBuf,
    /// The USB device's serial-number string, as the kernel reports it.
    pub usb_serial: String,
}

/// Why no single device node could be chosen for a USB serial.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MatchError {
    /// Nothing enumerated carries this serial: the board is unplugged, has not
    /// finished enumerating, or the inventory names the wrong serial. The
    /// message lists what *was* seen, because those three are indistinguishable
    /// without it.
    #[error("no serial device with USB serial {wanted:?}; saw {seen:?}")]
    NotFound {
        /// The serial that was looked for.
        wanted: String,
        /// Every USB serial that was enumerated.
        seen: Vec<String>,
    },
    /// More than one device carries this serial.
    ///
    /// An error rather than a first-hit on purpose: taking the first match here
    /// would pick a board by enumeration order, which is the exact failure this
    /// module exists to prevent — and it would do it silently.
    #[error("{} serial devices share the USB serial {wanted:?}: {nodes:?}", nodes.len())]
    Ambiguous {
        /// The serial that matched more than once.
        wanted: String,
        /// The nodes that matched.
        nodes: Vec<PathBuf>,
    },
}

/// Choose the one device node whose USB serial is `wanted`.
///
/// Never falls back to position. See [`MatchError::Ambiguous`].
pub fn match_device<'a>(devices: &'a [SerialDevice], wanted: &str) -> Result<&'a Path, MatchError> {
    let matched: Vec<&SerialDevice> = devices.iter().filter(|d| d.usb_serial == wanted).collect();

    match matched.as_slice() {
        [one] => Ok(&one.node),
        [] => Err(MatchError::NotFound {
            wanted: wanted.to_string(),
            seen: devices.iter().map(|d| d.usb_serial.clone()).collect(),
        }),
        many => Err(MatchError::Ambiguous {
            wanted: wanted.to_string(),
            nodes: many.iter().map(|d| d.node.clone()).collect(),
        }),
    }
}

/// How many interface levels above a tty's `device` link to look for the USB
/// device it belongs to.
///
/// `/sys/class/tty/ttyACM0/device` resolves to a USB *interface*, and the
/// device is its parent — one hop in every topology seen, including a composite
/// device (the DK's onboard J-Link exposes `2-3.1:1.0` and `2-3.1:1.2`, two
/// interfaces of the one device `2-3.1`). This bounds the search for the
/// topologies not seen yet; it is not a licence to climb past the device.
const MAX_USB_PARENT_HOPS: usize = 3;

/// Whether `dir` is a USB **root hub**, which never names a board.
///
/// A root hub is a USB device by every local test — it has an `idVendor`
/// (`1d6b`, Linux Foundation) and a `serial` — but its serial is the host
/// controller's PCI address, e.g. `0000:0a:00.0`. Root hubs are the
/// directories named `usb<N>` directly under a PCI device.
fn is_root_hub(dir: &Path) -> bool {
    dir.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
        n.strip_prefix("usb")
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// The USB serial of the device owning `device_link`.
///
/// **Climbs to the first USB device and stops there**, rather than climbing
/// until it finds a serial. That distinction is the whole correctness of this
/// function: an interface carries no `idVendor`, so the first ancestor that
/// does *is* the device the tty belongs to, and its serial — or its absence —
/// is the answer. Continuing past it reaches the hub the board is plugged into,
/// then the root hub, both of which are ordinary USB devices that commonly
/// report serials of their own. Those serials are shared by every device
/// beneath them, so taking one makes two boards collide on a single identity
/// and trips the ambiguity check on a match that was never real — the exact
/// failure this module exists to prevent, one level up from where it is
/// usually looked for.
///
/// A blank serial is treated as no serial: it would otherwise match an
/// inventory entry that forgot one.
fn usb_serial_of(device_link: &Path) -> Option<String> {
    let mut dir = std::fs::canonicalize(device_link).ok()?;
    // Inclusive: the interface itself is examined first, then each of
    // `MAX_USB_PARENT_HOPS` parents above it.
    for _ in 0..=MAX_USB_PARENT_HOPS {
        if is_root_hub(&dir) {
            return None;
        }
        if dir.join("idVendor").exists() {
            let serial = std::fs::read_to_string(dir.join("serial")).ok()?;
            let serial = serial.trim();
            return (!serial.is_empty()).then(|| serial.to_string());
        }
        dir = dir.parent()?.to_path_buf();
    }
    None
}

/// Enumerate the CDC-ACM devices this machine currently has, with the USB
/// serial behind each.
///
/// Linux-only: it reads `/sys/class/tty`. On any other host — and in a
/// container with no `/sys` mounted — it yields an empty list rather than a
/// compile error, the same seam `wayfinder-driver`'s Linux-only carriers use.
///
/// Note what that means downstream: an empty list becomes
/// [`MatchError::NotFound`], which `Board::management_port` turns into an error
/// and `Node::attach` retries until it gives up. It **fails**, it does not skip
/// — only a role the inventory does not name skips. Failing is the safe
/// direction for a board that ought to be attached; it is recorded here because
/// the shape is easy to assume otherwise.
pub fn enumerate() -> std::io::Result<Vec<SerialDevice>> {
    enumerate_under(Path::new("/sys/class/tty"))
}

/// [`enumerate`] against an explicit `/sys/class/tty`, so the walk is
/// exercisable against a fixture tree.
///
/// Only the sysfs root is parameterised: the device-node directory never varies
/// (a fixture asserts on the composed path, not on a real file), so taking it
/// as a second argument bought nothing but a value to pass at every call site.
///
/// A tty whose tree carries no `serial` is not a USB device at all (a real
/// UART, a virtual console) and is skipped rather than reported.
pub fn enumerate_under(tty_class: &Path) -> std::io::Result<Vec<SerialDevice>> {
    let entries = match std::fs::read_dir(tty_class) {
        Ok(entries) => entries,
        // No `/sys/class/tty` at all is a non-Linux host, not a fault: the
        // caller gets an empty list and then a `NotFound`, which is
        // skip-shaped. The same seam `wayfinder-driver`'s Linux-only carriers
        // use -- gate the implementation, not the constructor.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let mut devices = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with("ttyACM") {
            continue;
        }
        let Some(usb_serial) = usb_serial_of(&entry.path().join("device")) else {
            continue;
        };
        devices.push(SerialDevice {
            node: Path::new(DEV_DIR).join(name),
            usb_serial,
        });
    }
    // Sorted so a listing is stable between runs. Nothing may *depend* on the
    // order — that is what this module forbids — but an unstable listing makes
    // a diagnostic dump needlessly hard to compare.
    devices.sort_by(|a, b| a.node.cmp(&b.node));
    Ok(devices)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(node: &str, usb_serial: &str) -> SerialDevice {
        SerialDevice {
            node: PathBuf::from(node),
            usb_serial: usb_serial.to_string(),
        }
    }

    /// **The rule this module exists for.** The board is found by its serial,
    /// whatever order the kernel enumerated it in — so a rig keeps driving the
    /// same physical part across a reset that renumbers the device nodes.
    #[test]
    fn matches_on_serial_not_on_enumeration_order() {
        let forward = [dev("/dev/ttyACM0", "AAA"), dev("/dev/ttyACM1", "BBB")];
        let reversed = [dev("/dev/ttyACM0", "BBB"), dev("/dev/ttyACM1", "AAA")];

        assert_eq!(
            match_device(&forward, "BBB").unwrap(),
            Path::new("/dev/ttyACM1")
        );
        assert_eq!(
            match_device(&reversed, "BBB").unwrap(),
            Path::new("/dev/ttyACM0")
        );
    }

    /// Two devices sharing a serial is an error, never the first hit: falling
    /// back to position here would pick a board by enumeration order and do it
    /// silently, which is precisely the failure the serial addressing prevents.
    #[test]
    fn an_ambiguous_serial_is_an_error_rather_than_the_first_hit() {
        let devices = [dev("/dev/ttyACM0", "AAA"), dev("/dev/ttyACM3", "AAA")];

        match match_device(&devices, "AAA").unwrap_err() {
            MatchError::Ambiguous { wanted, nodes } => {
                assert_eq!(wanted, "AAA");
                assert_eq!(
                    nodes,
                    vec![PathBuf::from("/dev/ttyACM0"), PathBuf::from("/dev/ttyACM3")]
                );
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    /// A serial nothing carries reports what *was* enumerated. Unplugged, still
    /// enumerating, and a wrong serial in the inventory are indistinguishable
    /// without that list.
    #[test]
    fn an_unmatched_serial_reports_what_was_seen() {
        let devices = [dev("/dev/ttyACM0", "AAA"), dev("/dev/ttyACM1", "BBB")];

        match match_device(&devices, "CCC").unwrap_err() {
            MatchError::NotFound { wanted, seen } => {
                assert_eq!(wanted, "CCC");
                assert_eq!(seen, vec!["AAA".to_string(), "BBB".to_string()]);
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    /// An empty enumeration is the no-boards-attached case, and reports as a
    /// plain miss rather than anything special.
    #[test]
    fn no_devices_at_all_is_an_ordinary_miss() {
        match match_device(&[], "AAA").unwrap_err() {
            MatchError::NotFound { wanted, seen } => {
                assert_eq!(wanted, "AAA");
                assert!(seen.is_empty());
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod sysfs_tests {
    use super::*;
    use std::fs;

    /// Build a fixture shaped like real sysfs.
    ///
    /// The shape matters, because the hazard this module guards against is
    /// structural: a tty's `device` link resolves to a USB *interface*, whose
    /// parent chain runs up through the USB device, any intervening hubs, and
    /// finally the **root hub** — which carries an `idVendor` and a `serial` of
    /// its own, that serial being the host controller's PCI address. Anything
    /// that climbs far enough will find it.
    ///
    /// `serial` is the board's own, or `None` for a device that has none.
    /// `hops` is how far below the device the interface sits.
    fn fixture(root: &Path, tty: &str, serial: Option<&str>, hops: usize) {
        // The root hub: a USB device by every local test, and never the answer.
        let root_hub = root.join("devices/usb2");
        fs::create_dir_all(&root_hub).unwrap();
        fs::write(root_hub.join("idVendor"), "1d6b\n").unwrap();
        fs::write(root_hub.join("serial"), "0000:0a:00.0\n").unwrap();

        // An intervening hub, which is an ordinary USB device and — unlike a
        // root hub — commonly reports a serial of its own. A walk that climbs
        // looking for *any* serial finds this one.
        let hub = root_hub.join("2-3");
        fs::create_dir_all(&hub).unwrap();
        fs::write(hub.join("idVendor"), "0424\n").unwrap();
        fs::write(hub.join("serial"), "HUBSERIAL\n").unwrap();

        // The board's USB device, below the hub.
        let device = hub.join(tty);
        fs::create_dir_all(&device).unwrap();
        fs::write(device.join("idVendor"), "1209\n").unwrap();
        if let Some(serial) = serial {
            fs::write(device.join("serial"), format!("{serial}\n")).unwrap();
        }

        // Its interfaces, which carry no idVendor of their own.
        let mut interface = device;
        for h in 0..hops {
            interface = interface.join(format!("iface{h}"));
        }
        fs::create_dir_all(&interface).unwrap();

        let tty_dir = root.join("class/tty").join(tty);
        fs::create_dir_all(&tty_dir).unwrap();
        std::os::unix::fs::symlink(&interface, tty_dir.join("device")).unwrap();
    }

    /// The serial lives on the USB device, and the tty's `device` link points at
    /// an *interface* some way below it. The depth differs between a simple
    /// device and a composite one, so the walk has to find it rather than index
    /// to it — a fixed `../..` is right for one topology and silently wrong for
    /// the next.
    #[test]
    fn finds_the_serial_however_deep_the_interface_sits() {
        for hops in 1..=MAX_USB_PARENT_HOPS {
            let dir = tempfile::tempdir().unwrap();
            fixture(dir.path(), "ttyACM0", Some("AAA"), hops);

            let found = enumerate_under(&dir.path().join("class/tty")).unwrap();
            assert_eq!(
                found,
                vec![SerialDevice {
                    node: PathBuf::from("/dev/ttyACM0"),
                    usb_serial: "AAA".to_string(),
                }],
                "interface {hops} level(s) below the device"
            );
        }
    }

    /// **A board with no serial of its own must not answer to the hub's.**
    ///
    /// An intervening hub is an ordinary USB device — it has an `idVendor`, and
    /// many report an `iSerialNumber`. A walk that climbs until it finds *any*
    /// serial sails past the board and takes the hub's, which is shared by
    /// every device on that hub: two boards then collide on one identity, and
    /// the ambiguity check fires on a match that was never real. This is the
    /// same hazard as the root hub one level lower down, where the `usb<N>`
    /// name guard cannot see it.
    #[test]
    fn an_intervening_hubs_serial_is_never_mistaken_for_a_board_serial() {
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path(), "ttyACM0", None, 1);

        let found = enumerate_under(&dir.path().join("class/tty")).unwrap();
        assert!(
            found.is_empty(),
            "a board with no serial must report none, not its hub's: {found:?}"
        );
    }

    /// A device reporting a blank `iSerialNumber` is skipped, not reported with
    /// an empty serial — which would otherwise match an inventory entry that
    /// forgot one. The absent-file case is covered separately; this is the
    /// present-but-empty one, which takes a different branch.
    #[test]
    fn a_blank_serial_string_is_treated_as_no_serial() {
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path(), "ttyACM0", Some("   "), 1);

        let found = enumerate_under(&dir.path().join("class/tty")).unwrap();
        assert!(found.is_empty(), "{found:?}");
    }

    /// **A device with no serial of its own must report none — never the root
    /// hub's.**
    ///
    /// A root hub carries `serial` too, and its value is the host controller's
    /// PCI address (`0000:0a:00.0` on the bench this was found on). Climbing
    /// into it is worse than finding nothing twice over: the address is not a
    /// board identifier, and it is the *same* for every device on that
    /// controller — so two boards would collide on one "serial" and the
    /// ambiguity check would fire on a match that was never real.
    #[test]
    fn the_root_hubs_pci_address_is_never_mistaken_for_a_board_serial() {
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path(), "ttyACM0", None, 1);

        let found = enumerate_under(&dir.path().join("class/tty")).unwrap();
        assert!(
            found.is_empty(),
            "a device with no serial must report none, got {found:?}"
        );
    }

    /// The same hazard in the form it would actually bite: two boards on one
    /// controller, neither carrying a serial, must not both answer to the
    /// controller's address.
    #[test]
    fn two_serialless_devices_do_not_collide_on_the_root_hub() {
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path(), "ttyACM0", None, 1);
        fixture(dir.path(), "ttyACM1", None, 1);

        let found = enumerate_under(&dir.path().join("class/tty")).unwrap();
        assert!(found.is_empty(), "{found:?}");
    }

    /// A tty with no `serial` anywhere above it is not a USB device — a real
    /// UART, a virtual console — and is skipped rather than reported with an
    /// empty serial, which would match an inventory entry that forgot one.
    #[test]
    fn a_tty_with_no_usb_serial_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path(), "ttyACM0", None, 1);
        fixture(dir.path(), "ttyACM1", Some("BBB"), 1);

        let found = enumerate_under(&dir.path().join("class/tty")).unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].usb_serial, "BBB");
    }

    /// Non-ACM ttys are ignored outright: every machine has a `ttyS0` and a
    /// `console`, and none of them is a board.
    #[test]
    fn non_acm_ttys_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path(), "ttyS0", Some("AAA"), 1);
        fixture(dir.path(), "ttyACM0", Some("BBB"), 1);

        let found = enumerate_under(&dir.path().join("class/tty")).unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].node, PathBuf::from("/dev/ttyACM0"));
    }

    /// No `/sys/class/tty` at all — a non-Linux host — is an empty list, so the
    /// caller reaches a skip-shaped `NotFound` rather than an I/O failure.
    #[test]
    fn an_absent_sysfs_yields_no_devices() {
        let dir = tempfile::tempdir().unwrap();
        let found = enumerate_under(&dir.path().join("nope")).unwrap();
        assert!(found.is_empty());
    }
}
