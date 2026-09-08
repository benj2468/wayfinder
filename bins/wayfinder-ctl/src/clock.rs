//! The host-clock gate every command that stamps a time onto a node passes
//! through.
//!
//! An absolute time reaches a bare-metal node only from an operator's machine
//! (design 20 §4.6), and the node has no way to second-guess what it is told —
//! it has no clock of its own, which is the whole reason it is being told. So
//! the honesty of the anchoring scheme rests here, on whether *this* machine's
//! clock can be vouched for.
//!
//! **The policy is to fail closed**, and it is affordable only because of the
//! rewrite that came with it: under "signature always, window when known" a
//! node that ends up with no anchor still routes, still verifies its peers and
//! still raises an alarm saying it is not judging expiry. Refusing to stamp
//! costs the anchor and nothing else. Under the superseded design the same
//! refusal bricked the enrolment.

use clap::Subcommand;
use wayfinder_client::Client;
use wayfinder_client::ClockSync;
use wayfinder_client::ClockTrust;

/// The node's wall clock: the anchor it free-runs from.
#[derive(Subcommand, Debug)]
pub enum TimeCommand {
    /// Anchor the node's wall clock from this host's, without re-issuing its
    /// certificate.
    ///
    /// A board free-running on an internal RC oscillator drifts about twenty
    /// seconds a day, and one that lost its persisted checkpoint comes up with
    /// no estimate at all. Both are purely local maintenance, and routing
    /// every such correction through the certificate authority would make it a
    /// participant in something it has no part in.
    ///
    /// The node takes this as a **floor**, never a reading: it is refused
    /// below 2025, taken as `max` against whatever estimate the node already
    /// holds so it can never roll the node backwards, and floored against the
    /// `not_before` of the certificate the node is already running under.
    Set {
        /// The install carries this host's wall clock, so the same gate as
        /// `auth set` applies.
        #[command(flatten)]
        clock: ClockArgs,
    },
}

/// Dispatch one `time` subcommand against an already-connected `client`.
pub async fn run(cmd: TimeCommand, client: &mut Client) -> anyhow::Result<String> {
    match cmd {
        TimeCommand::Set { clock } => {
            let (installer_unix, note) = clock.stamp()?;
            client.set_time(installer_unix).await?;
            Ok(format!("clock anchored{note}"))
        }
    }
}

/// The `--unsafe-allow-untrustworthy-clock` opt-out, declared once and
/// flattened into every subcommand that stamps a time.
///
/// One declaration rather than three copies of the flag: three spellings of a
/// deliberately-unpleasant flag is how one of them ends up with a friendlier
/// name, or a softer doc comment, than the others.
#[derive(clap::Args, Debug, Clone, Copy, Default)]
pub struct ClockArgs {
    /// Stamp this host's clock onto the node even though nothing vouches for
    /// it.
    ///
    /// This command carries a time, so it refuses to run while the host clock
    /// is untrusted: a node with no clock of its own cannot second-guess what
    /// it is told, and enforces a wrong anchor until an operator corrects it.
    /// This is the way past that, and it maps onto the same
    /// `require_time_sync = false` opt-out a node itself has.
    ///
    /// The name is deliberately long and ugly: it should be unpleasant to type
    /// and obvious in shell history. Before reaching for it, read the refusal —
    /// a correctly-synchronised chrony still reports as unsynchronised unless
    /// its `rtcsync` directive is set, which nothing sets on a workstation, and
    /// that is a config fix rather than a reason to stamp blind.
    #[arg(long)]
    pub unsafe_allow_untrustworthy_clock: bool,
}

impl ClockArgs {
    /// [`resolve_stamp`] under these arguments.
    pub fn stamp(self) -> anyhow::Result<(u64, String)> {
        resolve_stamp(self.unsafe_allow_untrustworthy_clock)
    }
}

/// Resolve the wall clock to stamp onto a node, or refuse with a diagnosis.
///
/// `allow_untrustworthy` is the operator's opt-out
/// ([`ClockArgs::unsafe_allow_untrustworthy_clock`]), which maps onto
/// [`ClockTrust::Assume`] — the same escape hatch a node's own
/// `require_time_sync = false` gives it.
///
/// Returns the stamp and a one-line note naming the verdict it acted on, for
/// the caller to echo. The note is not only for the refusal: an operator who
/// used the opt-out should see it said back to them.
///
/// # The refusal has to be diagnostic
///
/// On a node, `nix/modules/wayfinder.nix` sets chrony's `rtcsync`, which is
/// what clears the kernel's `STA_UNSYNC` bit. **On an operator's arbitrary
/// laptop nothing sets it**, so a correctly-synchronised stock Ubuntu or
/// Fedora machine — locked to a source and reporting microseconds of offset —
/// commonly reads as [`ClockSync::Unsynchronized`] here. Naming the verdict and
/// the likely cause is the difference between an operator fixing their chrony
/// config and an operator reaching for the opt-out because the error said
/// nothing. [`ClockSync::Unreadable`] exists to separate a seccomp-blocked
/// syscall from an undisciplined clock for the same reason: an operator told
/// the wrong one will fix the wrong thing.
pub fn resolve_stamp(allow_untrustworthy: bool) -> anyhow::Result<(u64, String)> {
    stamp_under(ClockTrust::default(), allow_untrustworthy)
}

/// [`resolve_stamp`] against an explicit enforcing policy.
///
/// Split out so both branches are testable. `resolve_stamp` reads the host's
/// real NTP status, so on a machine whose clock is disciplined its refusal path
/// is unreachable from a test and on one whose clock is not, its success path
/// is — either way half the behaviour would go unpinned.
///
/// **The verdict is always read under `enforced`, even when the opt-out stamps
/// under [`ClockTrust::Assume`].** `wayfinder_clock_trust::read(Assume)`
/// answers [`ClockSync::Unsupported`] unconditionally — it asks the kernel
/// nothing — so echoing *that* would tell a Linux operator their platform
/// exposes no NTP status, when what they wanted to know was which verdict they
/// had just overridden. Design 20 §7 asks for "the clock verdict it acted on";
/// a tautology is not one.
fn stamp_under(enforced: ClockTrust, allow_untrustworthy: bool) -> anyhow::Result<(u64, String)> {
    let verdict = wayfinder_client::clock_sync(enforced);
    let policy = if allow_untrustworthy {
        ClockTrust::Assume
    } else {
        enforced
    };
    let (stamp, _) = wayfinder_client::stamp_unix(policy);
    if stamp != 0 {
        return Ok((stamp, note(stamp, verdict, allow_untrustworthy)));
    }
    Err(anyhow::anyhow!("{}", refusal(verdict, allow_untrustworthy)))
}

/// The line echoed on success, naming the verdict the stamp was made under.
///
/// Says *sent*, not *applied*: the node decides whether to adopt it. A board
/// whose estimate is already past this instant keeps the later one, and
/// `SetTime` reports that as an error — but a `SetAuth` carrying a stale stamp
/// installs the credential regardless, so a note claiming the clock was set
/// would sometimes be wrong.
fn note(stamp: u64, sync: ClockSync, allow_untrustworthy: bool) -> String {
    if allow_untrustworthy {
        format!(
            "; sent host clock {stamp} with --unsafe-allow-untrustworthy-clock \
             (overriding verdict: {})",
            sync.name()
        )
    } else {
        format!("; sent host clock {stamp} ({})", sync.name())
    }
}

/// The refusal, with the diagnosis attached.
///
/// Two shapes, because the opt-out changes what went wrong. Without it, the
/// verdict is the problem and the flag is the way past it. With it, the
/// verdict was never consulted — the reading itself is unusable, and no flag
/// rescues a clock that says 1970.
fn refusal(sync: ClockSync, allow_untrustworthy: bool) -> String {
    if allow_untrustworthy {
        return "this host's clock reads before 2025, so there is no time to stamp; \
                set the system clock before installing a credential"
            .to_string();
    }
    let mut msg = format!(
        "refusing to stamp a time this host cannot vouch for (clock verdict: {})",
        sync.name()
    );
    match sync {
        ClockSync::Unsynchronized => msg.push_str(
            "\nA synchronised chrony still reads as unsynchronised unless its `rtcsync` \
             directive is set — that is what clears the kernel's STA_UNSYNC bit, and \
             nothing sets it by default on a workstation. Check that before assuming \
             the clock is wrong.",
        ),
        ClockSync::Unreadable { errno } => msg.push_str(&format!(
            "\nThe kernel's NTP status could not be read at all (errno {errno}); the clock \
             itself may be fine. A sandbox blocking ntp_adjtime(2) looks exactly like this.",
        )),
        ClockSync::ErrorTooLarge {
            max_error_us,
            bound_us,
        } => msg.push_str(&format!(
            "\nThe clock is disciplined but the kernel's own error bound is {max_error_us} µs, \
             past the {bound_us} µs this build accepts. Give the daemon time to converge.",
        )),
        // Both are trusted verdicts, so a zero stamp under them means the
        // reading itself was below the plausibility floor.
        ClockSync::Synchronized { .. } | ClockSync::Unsupported => {
            return "this host's clock reads before 2025, so there is no time to stamp; \
                    set the system clock before installing a credential"
                .to_string();
        }
    }
    msg.push_str(
        "\nTo proceed anyway, pass --unsafe-allow-untrustworthy-clock. The node cannot \
         second-guess the time it is given, and a wrong anchor is enforced until an \
         operator corrects it.",
    );
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The gate refuses an install while the host clock is untrusted** —
    /// design 20 §10's test 15, first half.
    ///
    /// Driven through `stamp_under` with an explicit policy rather than
    /// `resolve_stamp`, because `resolve_stamp` asks the *build machine* about
    /// its own NTP status: on a disciplined host this branch is unreachable
    /// from a test, and on an undisciplined one the success branch is.
    #[test]
    fn an_untrusted_host_clock_refuses_to_stamp() {
        let err = stamp_under(ClockTrust::Never, false)
            .expect_err("an untrusted clock must not be stamped onto a node");
        let msg = format!("{err}");
        assert!(msg.contains("cannot vouch for"), "{msg}");
        assert!(
            msg.contains("--unsafe-allow-untrustworthy-clock"),
            "the way past it is named: {msg}"
        );
    }

    /// ...and proceeds with the opt-out — the second half of test 15.
    #[test]
    fn the_opt_out_stamps_an_untrusted_clock() {
        let (stamp, note) = stamp_under(ClockTrust::Never, true)
            .expect("the opt-out stamps a clock nothing vouches for");
        assert!(stamp >= wayfinder_auth::MIN_PLAUSIBLE_UNIX);
        assert!(
            note.contains("--unsafe-allow-untrustworthy-clock"),
            "the opt-out must be echoed back: {note}"
        );
    }

    /// **The note names the verdict that was overridden, not a tautology.**
    ///
    /// Stamping under the opt-out means asking `ClockTrust::Assume`, and
    /// `read(Assume)` answers `Unsupported` unconditionally — it consults the
    /// kernel about nothing. Echoing *that* would tell a Linux operator their
    /// platform exposes no NTP status, when what they overrode was a real
    /// verdict. §7 asks for "the clock verdict it acted on".
    #[test]
    fn the_opt_out_echoes_the_verdict_it_overrode() {
        let (_, note) = stamp_under(ClockTrust::Never, true).expect("stamps");
        assert!(
            note.contains("unsynchronized"),
            "the overridden verdict must be named, not `unsupported`: {note}"
        );
        assert!(
            !note.contains("unsupported"),
            "`read(Assume)`'s tautological answer must not be what is reported: {note}"
        );
    }

    /// The opt-out reaches a stamp on any machine whose clock is merely
    /// An untrusted verdict is refused, and the refusal names the verdict
    /// rather than only reporting failure.
    #[test]
    fn an_untrusted_verdict_is_refused_diagnostically() {
        let msg = refusal(ClockSync::Unsynchronized, false);
        assert!(msg.contains("unsynchronized"), "{msg}");
        assert!(msg.contains("rtcsync"), "the likely cause is named: {msg}");
        assert!(
            msg.contains("--unsafe-allow-untrustworthy-clock"),
            "the way past it is named: {msg}"
        );
    }

    /// A blocked syscall is diagnosed as a blocked syscall, not as a wrong
    /// clock — an operator told the wrong one fixes the wrong thing.
    #[test]
    fn an_unreadable_status_is_not_reported_as_a_bad_clock() {
        let msg = refusal(ClockSync::Unreadable { errno: 1 }, false);
        assert!(msg.contains("errno 1"), "{msg}");
        assert!(
            msg.contains("may be fine"),
            "must not blame the clock itself: {msg}"
        );
    }

    /// `Unsupported` — a macOS operator machine, which the devShell supports —
    /// counts as trusted, so the only way it refuses is an implausible
    /// reading, and it says *that* rather than naming a verdict.
    #[test]
    fn an_unsupported_platform_is_refused_only_for_an_implausible_reading() {
        let msg = refusal(ClockSync::Unsupported, false);
        assert!(msg.contains("before 2025"), "{msg}");
        assert!(
            !msg.contains("--unsafe-allow-untrustworthy-clock"),
            "no flag rescues a clock that reads 1970: {msg}"
        );
    }
}
