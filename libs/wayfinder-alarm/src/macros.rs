//! The raise-site macro.

/// Report that a condition holds, on whichever board is current.
///
/// The detail is a `format!`-style template rendered into a fixed-capacity
/// string, so it costs no allocation and truncates rather than failing. Keep it
/// to the metadata that explains the condition — a rate, a count, a window —
/// under the same rule the logging macros follow: never payload bytes.
///
/// Expands to a [`raise`](crate::raise) call and evaluates to its
/// [`Raised`](crate::Raised) outcome, which most call sites ignore.
///
/// ```
/// use wayfinder_alarm::AlarmKind;
/// use wayfinder_alarm::NodeId;
/// use wayfinder_alarm::Severity;
/// use wayfinder_alarm::Subject;
/// use wayfinder_alarm::alarm;
///
/// let peer = Subject::Node(NodeId::new(&[0x02, 0, 0, 0, 0, 0x07]));
/// alarm!(
///     Severity::Critical,
///     AlarmKind::OgmReplay,
///     peer,
///     "seqno={}",
///     41
/// );
///
/// // A condition about the node itself needs no subject.
/// alarm!(
///     Severity::Warning,
///     AlarmKind::TableSaturation,
///     Subject::None,
///     "table=originators"
/// );
/// ```
#[macro_export]
macro_rules! alarm {
    ($severity:expr, $kind:expr, $subject:expr, $($detail:tt)+) => {
        $crate::raise(
            $kind,
            $subject,
            $severity,
            ::core::format_args!($($detail)+),
        )
    };
    ($severity:expr, $kind:expr, $subject:expr $(,)?) => {
        $crate::raise($kind, $subject, $severity, ::core::format_args!(""))
    };
}
