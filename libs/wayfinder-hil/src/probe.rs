//! Resolving a debug probe's serial number to the selector `probe-rs` wants.
//!
//! `probe-rs --probe` takes `VID:PID<-Interface>:<Serial>` and rejects a bare
//! serial. An inventory that stored that selector would be describing
//! *probe-rs's command line* rather than the bench, so `hil.toml` carries the
//! serial — the thing printed on the board and stable across tool versions —
//! and this module turns it into a selector.
//!
//! The split mirrors [`crate::usb`] deliberately: [`parse_list`] and
//! [`resolve`] are pure and tested against fixture text, while running the
//! command is not. And [`resolve`] applies the same rule its USB counterpart
//! does — match on the serial, never on list position, and refuse an ambiguous
//! match rather than taking the first.

use std::process::Command;

/// One probe as `probe-rs list` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachedProbe {
    /// The full `VID:PID<-Interface>:Serial` selector to pass to `--probe`.
    ///
    /// Private, and the only stored field of the two: the serial is the last
    /// colon-separated field of this string, so storing both would let them
    /// disagree — and `resolve` matches on *either*, which turns a disagreement
    /// into the selector of a different probe.
    selector: String,
    /// The human-readable kind, e.g. `J-Link`.
    identifier: String,
}

impl AttachedProbe {
    /// The full selector to pass to `probe-rs --probe`.
    pub fn selector(&self) -> &str {
        &self.selector
    }

    /// The serial number alone, which is what an inventory names.
    ///
    /// Total by construction: [`parse_list`] admits only selectors with a
    /// non-empty tail after a colon.
    pub fn serial(&self) -> &str {
        self.selector.rsplit_once(':').map_or("", |(_, s)| s)
    }

    /// The human-readable kind, e.g. `J-Link`.
    pub fn identifier(&self) -> &str {
        &self.identifier
    }
}

/// Why no single probe could be chosen.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProbeError {
    /// No attached probe carries this serial.
    #[error("no debug probe with serial {wanted:?}; saw {seen:?}")]
    NotFound {
        /// The serial that was looked for.
        wanted: String,
        /// Every probe serial that was found.
        seen: Vec<String>,
    },
    /// More than one attached probe carries it.
    #[error("{} debug probes share the serial {wanted:?}", selectors.len())]
    Ambiguous {
        /// The serial that matched more than once.
        wanted: String,
        /// The selectors that matched.
        selectors: Vec<String>,
    },
}

/// Parse `probe-rs list` output.
///
/// Lines look like `[0]: J-Link -- 1366:1061:001050247387 (J-Link)`. Anything
/// that does not is skipped rather than erroring — the header line is one, and
/// a future probe-rs adding a line should not take the rig down.
pub fn parse_list(text: &str) -> Vec<AttachedProbe> {
    let mut probes = Vec::new();
    for line in text.lines() {
        let Some((_, rest)) = line.split_once("]: ") else {
            continue;
        };
        let Some((identifier, tail)) = rest.split_once(" -- ") else {
            continue;
        };
        // Trim the trailing ` (J-Link)` kind annotation, if present.
        let selector = tail.split(" (").next().unwrap_or(tail).trim();
        // The serial is everything after the VID:PID (and optional
        // `-Interface`), i.e. the last colon-separated field.
        let Some((_, serial)) = selector.rsplit_once(':') else {
            continue;
        };
        if serial.is_empty() {
            continue;
        }
        probes.push(AttachedProbe {
            selector: selector.to_string(),
            identifier: identifier.trim().to_string(),
        });
    }
    probes
}

/// The selector for the probe whose serial is `wanted`.
///
/// A full selector is accepted as well as a bare serial — an operator who
/// pasted one out of `probe-rs list` is not told it is wrong — but either way it
/// is matched against what is currently attached rather than passed through, so
/// a selector for an unplugged probe is still [`NotFound`](ProbeError::NotFound).
pub fn resolve<'a>(probes: &'a [AttachedProbe], wanted: &str) -> Result<&'a str, ProbeError> {
    let matched: Vec<&AttachedProbe> = probes
        .iter()
        .filter(|p| p.serial() == wanted || p.selector == wanted)
        .collect();

    match matched.as_slice() {
        [one] => Ok(&one.selector),
        [] => Err(ProbeError::NotFound {
            wanted: wanted.to_string(),
            seen: probes.iter().map(|p| p.serial().to_string()).collect(),
        }),
        many => Err(ProbeError::Ambiguous {
            wanted: wanted.to_string(),
            selectors: many.iter().map(|p| p.selector.clone()).collect(),
        }),
    }
}

/// Ask `probe-rs` what is attached.
///
/// Checks the exit status and reports stderr, because the alternative is the
/// worst error message this harness could produce: `probe-rs` exits non-zero
/// with a permissions complaint on stderr and nothing on stdout, an empty parse
/// becomes [`ProbeError::NotFound`], and the operator is told their probe is
/// unplugged while it sits there blinking. Design 21 §4.6 names udev
/// permissions as the thing benches get wrong, and quotes probe-rs's own hint —
/// which lands on exactly the stream a bare `output.stdout` discards.
///
/// An empty parse of *non-empty* output is refused for the same reason: a
/// probe-rs release that changes the listing format would otherwise be
/// indistinguishable from no hardware.
pub fn list() -> anyhow::Result<Vec<AttachedProbe>> {
    let output = Command::new("probe-rs")
        .arg("list")
        .output()
        .map_err(|e| anyhow::anyhow!("running `probe-rs list`: {e}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "`probe-rs list` exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let probes = parse_list(&text);
    if probes.is_empty() && !text.trim().is_empty() && !text.contains("No debug probes") {
        anyhow::bail!(
            "could not parse any probe out of `probe-rs list`, which said: {}",
            text.trim()
        );
    }
    Ok(probes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim from the bench this was built on.
    const ONE_JLINK: &str = "\
The following debug probes were found:
[0]: J-Link -- 1366:1061:001050247387 (J-Link)
";

    /// The header line is not a probe, and the serial is the last field of the
    /// selector rather than the whole of it.
    #[test]
    fn parses_a_probe_rs_listing() {
        let probes = parse_list(ONE_JLINK);
        assert_eq!(probes.len(), 1, "{probes:?}");
        assert_eq!(probes[0].selector(), "1366:1061:001050247387");
        assert_eq!(probes[0].serial(), "001050247387");
        assert_eq!(probes[0].identifier(), "J-Link");
    }

    /// The selector may carry an interface — `VID:PID-Interface:Serial`, which
    /// CMSIS-DAP probes emit — and the serial is still the last field. The docs
    /// describe this form; nothing exercised it.
    #[test]
    fn parses_a_selector_carrying_an_interface() {
        let probes = parse_list("[0]: CMSIS-DAP -- 0d28:0204-0:ABCD1234 (CMSIS-DAP)\n");
        assert_eq!(probes.len(), 1, "{probes:?}");
        assert_eq!(probes[0].selector(), "0d28:0204-0:ABCD1234");
        assert_eq!(probes[0].serial(), "ABCD1234");
    }

    /// A selector with no serial at all is skipped rather than admitted with an
    /// empty one, which would match an inventory entry that forgot a serial.
    #[test]
    fn a_selector_with_no_serial_is_skipped() {
        assert!(parse_list("[0]: J-Link -- 1366:1061: (J-Link)\n").is_empty());
    }

    /// An empty listing is no probes, not a parse failure.
    #[test]
    fn parses_an_empty_listing() {
        assert!(parse_list("No debug probes were found.\n").is_empty());
    }

    /// The inventory names a serial; `--probe` gets a selector.
    #[test]
    fn resolves_a_serial_to_a_selector() {
        let probes = parse_list(ONE_JLINK);
        assert_eq!(
            resolve(&probes, "001050247387").unwrap(),
            "1366:1061:001050247387"
        );
    }

    /// An operator who pasted a whole selector is not told it is wrong.
    #[test]
    fn accepts_a_full_selector_too() {
        let probes = parse_list(ONE_JLINK);
        assert_eq!(
            resolve(&probes, "1366:1061:001050247387").unwrap(),
            "1366:1061:001050247387"
        );
    }

    /// A serial nothing carries lists what was attached, so "unplugged" and
    /// "wrong serial in the inventory" are distinguishable.
    #[test]
    fn an_unmatched_serial_reports_what_was_attached() {
        let probes = parse_list(ONE_JLINK);
        match resolve(&probes, "999").unwrap_err() {
            ProbeError::NotFound { wanted, seen } => {
                assert_eq!(wanted, "999");
                assert_eq!(seen, vec!["001050247387".to_string()]);
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    /// Two probes on one serial is an error, never the first hit — the same
    /// rule the USB side applies, for the same reason.
    #[test]
    fn an_ambiguous_serial_is_an_error() {
        let probes = parse_list(
            "\
[0]: J-Link -- 1366:1061:AAA (J-Link)
[1]: J-Link -- 1366:1062:AAA (J-Link)
",
        );
        assert!(matches!(
            resolve(&probes, "AAA"),
            Err(ProbeError::Ambiguous { .. })
        ));
    }
}
