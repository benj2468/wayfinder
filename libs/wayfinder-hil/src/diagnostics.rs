//! What a hardware test reports when it fails.
//!
//! An assertion failure against a board is nearly useless on its own: the
//! interesting state is on the part, and the part may have reset. Design 21
//! §4.5 makes the dump part of the harness rather than something each test
//! remembers to do, because the test that most needs it is the one that failed
//! in a way its author did not anticipate.
//!
//! Everything here is best-effort. A node that has stopped answering is
//! precisely the case worth diagnosing, so a failure to collect one section is
//! recorded in that section and never masks the original failure.

use std::fmt::Write as _;
use std::future::Future;
use std::time::Duration;

use wayfinder_protos::wayfinder::v1alpha::AlarmKind;
use wayfinder_protos::wayfinder::v1alpha::LogLevel;

use crate::node::Node;

/// How many log records a dump pulls back.
///
/// Not the safety mechanism it might look like: `RING_CAPACITY` is 64 on a
/// board, so this asks for the whole ring. What actually bounds the response is
/// `wayfinder_log::ring::BATCH_BYTE_BUDGET` (2 KiB on a board), which truncates
/// by *bytes* before the encode can grow a `Vec` past the 32 KiB heap — the
/// reset this crate has a regression test for. A count cannot do that job,
/// because record sizes span roughly 100 to 264 bytes.
///
/// So this is a readability bound on the dump, not a protection.
pub const DUMP_LOG_RECORDS: u32 = 64;

/// How long any one collection step may take before it is recorded as a
/// non-answer.
///
/// The board being diagnosed has just failed, and the most interesting way for
/// it to fail is to stop answering *without* dropping its USB endpoint — a read
/// that never completes and never errors. Unbounded, the dump written to
/// explain a fault is what stops the fault being reported at all: the original
/// error sits in a local while `collect` waits forever.
pub const COLLECT_TIMEOUT: Duration = Duration::from_secs(5);

/// A snapshot of a node's state, collected when a test failed.
///
/// Each section is the text of an answer or the reason there is none. A
/// `Result` rather than an `Option` beside a shared error list, because a
/// section's outcome is one fact: the earlier shape let a section be absent
/// with nothing saying why, and present with an error recorded anyway, and
/// nothing but four hand-written pairs kept the two in step.
#[derive(Debug)]
pub struct Diagnostics {
    /// The role of the board this describes.
    pub role: String,
    /// `GetNodeInfo`, or why it could not be read.
    pub info: Result<String, String>,
    /// `GetSecurityStatus`, or why it could not be read.
    pub security: Result<String, String>,
    /// The latched alarm conditions, or why they could not be read.
    pub alarms: Result<String, String>,
    /// The tail of the log ring, or why it could not be read.
    pub logs: Result<String, String>,
}

/// Await `fut`, turning both an error and a non-answer into a stated reason.
///
/// A timeout is reported as such rather than as a generic failure: "the node
/// did not answer in 5s" and "the node refused the request" send an operator to
/// different places.
async fn step<T>(what: &str, fut: impl Future<Output = anyhow::Result<T>>) -> Result<T, String> {
    match tokio::time::timeout(COLLECT_TIMEOUT, fut).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(format!("{what}: {e:#}")),
        Err(_) => Err(format!(
            "{what}: no answer within {COLLECT_TIMEOUT:?} (the node has stopped responding)"
        )),
    }
}

impl Diagnostics {
    /// Collect everything reachable over the management port.
    ///
    /// Alarms are read before logs on purpose: an alarm is a latched condition
    /// that survives the burst that caused it, where the log line that
    /// accompanied it may already have rotated out of a bounded ring.
    pub async fn collect(node: &mut Node) -> Diagnostics {
        let role = node.role().to_string();

        let info = step("GetNodeInfo", node.node_info()).await.map(|info| {
            format!(
                "node_id={} originators={} auth_locked={} clock_trusted={} clock_posture={:?} \
                 build={}",
                hex(&info.node_id),
                info.num_originators,
                info.auth_locked,
                info.clock_trusted,
                info.clock_posture(),
                // The question every "do both ends carry fix X?" investigation
                // starts with, and the reason this field exists at all: a board
                // flashed weeks ago is otherwise indistinguishable from one
                // flashed from this tree. The commit and source come too — a
                // tagged build's version carries no hash, and a `dirty` build's
                // version is the same string for every edit of that commit, so
                // the bare version is not always enough to act on.
                info.build_info.as_ref().map_or_else(
                    || "not reported".to_string(),
                    |b| {
                        format!(
                            "{} (commit={} dirty={} source={:?})",
                            b.version,
                            b.commit,
                            b.dirty,
                            b.source()
                        )
                    },
                ),
            )
        });

        // The MAC is worth printing beside `node_id`: a credential binds a key
        // to a MAC, so the two disagreeing is a real condition, and it is
        // invisible from either field alone (GitLab #58).
        let security = step("GetSecurityStatus", node.security_status())
            .await
            .map(|sec| {
                format!(
                    "auth_enabled={} mesh_id={:#010x} node_mac={} cert_not_after={} revocations={}",
                    sec.auth_enabled,
                    sec.mesh_id,
                    hex(&sec.node_mac),
                    sec.cert_not_after,
                    sec.revocation_count,
                )
            });

        let alarms = step("GetAlarms", node.alarms()).await.map(|alarms| {
            let mut s = String::new();
            // Uptime first: a value lower than a previous dump's is a board
            // that reset, which is the single most useful fact in a hardware
            // failure and is not deducible from anything else here.
            let _ = writeln!(s, "  node uptime: {}ms", alarms.now_ms);
            if alarms.alarms.is_empty() {
                s.push_str("  (no alarms)\n");
            }
            for a in &alarms.alarms {
                let _ = writeln!(
                    s,
                    "  {} {:?} count={} first={}ms last={}ms {}",
                    alarm_kind(a.kind),
                    a.severity(),
                    a.count,
                    a.first_ms,
                    a.last_ms,
                    a.detail,
                );
            }
            if alarms.dropped > 0 {
                let _ = writeln!(s, "  ({} alarms dropped)", alarms.dropped);
            }
            s
        });

        let logs = step("GetLogs", node.logs(0, DUMP_LOG_RECORDS))
            .await
            .map(|records| {
                let mut s = String::new();
                for r in &records.records {
                    let _ = writeln!(
                        s,
                        "  [{:>8}ms] {:<5} {}: {}",
                        r.uptime_ms,
                        log_level(r.level),
                        r.target,
                        r.message,
                    );
                }
                if records.dropped > 0 {
                    let _ = writeln!(s, "  ({} records dropped)", records.dropped);
                }
                s
            });

        Diagnostics {
            role,
            info,
            security,
            alarms,
            logs,
        }
    }
}

impl std::fmt::Display for Diagnostics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "--- HIL diagnostics for board {:?} ---", self.role)?;
        section(f, "node info", &self.info)?;
        section(f, "security", &self.security)?;
        section(f, "alarms", &self.alarms)?;
        section(f, "logs (tail)", &self.logs)?;
        Ok(())
    }
}

/// One titled block of a dump: its content, or the reason there is none.
///
/// The reason is printed under the section it belongs to rather than collected
/// at the foot of the dump, so "logs" and "why there are no logs" are read
/// together.
fn section(
    f: &mut std::fmt::Formatter<'_>,
    title: &str,
    body: &Result<String, String>,
) -> std::fmt::Result {
    match body {
        Ok(body) if body.trim().is_empty() => writeln!(f, "{title}: (empty)"),
        Ok(body) => writeln!(f, "{title}:\n{}", body.trim_end()),
        Err(why) => writeln!(f, "{title}: unavailable -- {why}"),
    }
}

/// Name an [`AlarmKind`] discriminant, keeping the raw value when it is one this
/// build does not know.
///
/// Rounding an unknown kind to `Unspecified` would discard the number in the one
/// place whose whole job is explaining a failure nobody anticipated — and a
/// discriminant the harness cannot name is most likely firmware newer than the
/// protos it was built against, which is itself the finding.
fn alarm_kind(kind: i32) -> String {
    match AlarmKind::try_from(kind) {
        Ok(known) => format!("{known:?}"),
        Err(_) => format!("Unknown({kind})"),
    }
}

/// Name a [`LogLevel`] discriminant, keeping the raw value when unknown. See
/// [`alarm_kind`].
fn log_level(level: i32) -> String {
    match LogLevel::try_from(level) {
        Ok(known) => format!("{known:?}"),
        Err(_) => format!("Unknown({level})"),
    }
}

/// Lowercase hex, for a MAC or node id in a diagnostic line.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The case the dump exists for: a node that answered nothing. Every
    /// section must still be titled and must carry its own reason, because this
    /// is the output an operator reads when everything else has already gone
    /// wrong.
    #[test]
    fn a_dump_with_no_answers_still_explains_every_section() {
        let d = Diagnostics {
            role: "alpha".to_string(),
            info: Err("GetNodeInfo: no answer within 5s".to_string()),
            security: Err("GetSecurityStatus: broken pipe".to_string()),
            alarms: Err("GetAlarms: broken pipe".to_string()),
            logs: Err("GetLogs: broken pipe".to_string()),
        };
        let rendered = d.to_string();

        for title in ["node info", "security", "alarms", "logs (tail)"] {
            assert!(rendered.contains(title), "missing {title}: {rendered}");
        }
        assert!(rendered.contains("alpha"), "{rendered}");
        assert!(rendered.contains("no answer within"), "{rendered}");
        assert!(rendered.contains("broken pipe"), "{rendered}");
    }

    /// An alarm kind this build cannot name keeps its number, which is what
    /// makes it findable in the proto file.
    #[test]
    fn an_unknown_discriminant_keeps_its_raw_value() {
        assert_eq!(alarm_kind(9999), "Unknown(9999)");
        assert_eq!(log_level(9999), "Unknown(9999)");
        assert_eq!(
            alarm_kind(AlarmKind::ClockUnsynchronized as i32),
            "ClockUnsynchronized"
        );
    }
}
