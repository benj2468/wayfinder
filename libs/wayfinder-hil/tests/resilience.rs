//! The two hardware bugs found at the bench, kept from coming back.
//!
//! Both were found by a person noticing a board misbehave, and neither is
//! reachable from any other test in this workspace (design 21 §2.2).
//!
//! One of the two turns out to be **already fixed**: `BATCH_BYTE_BUDGET`
//! (`libs/wayfinder-log/src/ring.rs`) landed in `d45f74b` and its doc names
//! this exact failure — "Exceeding the heap is a `handle_alloc_error` panic,
//! which on a board is a reset; and it happens during the encode, before the
//! framing layer gets to refuse the result." So `a_full_log_ring_...` is a
//! regression test for that budget, not a reproduction of something open. The
//! HardFault has no such fix and may still be red.

use std::time::Duration;

use wayfinder_hil::Diagnostics;
use wayfinder_hil::Node;
use wayfinder_hil::Rig;

/// How many attach/detach cycles the fault test performs.
const MGMT_ATTACH_CYCLES: usize = 20;

/// Records requested when deliberately provoking the largest response the ring
/// can produce.
///
/// Far more than `RING_CAPACITY` (64 on a board) on purpose, so that what
/// bounds the answer is `BATCH_BYTE_BUDGET` rather than the count. Asking for
/// fewer would let a future change to that budget go unnoticed here.
const FULL_RING_RECORDS: u32 = 4096;

/// **Regression test for the `GetLogs` OOM reset** (design 21 §5's test 6).
///
/// A dashboard refresh used to reset the dongle: a full-ring `GetLogs` response
/// OOMed the 32 KiB heap. The USB transaction error seen alongside it was
/// downstream of the reset, not its cause — a distinction that cost real time
/// to establish.
///
/// What keeps it fixed is `wayfinder_log::ring::BATCH_BYTE_BUDGET` (2 KiB on a
/// board), which truncates a batch by *bytes* before the encode can grow a
/// `Vec` past the heap. This test asks for far more records than the ring holds
/// precisely so that budget is what bounds the answer; if someone raises it, or
/// removes it in favour of a record count, this is what should go red.
///
/// Runs against the **dongle** by default, because that is the part the bug was
/// reported on; the DK has the same heap and should behave the same way.
#[tokio::test]
#[ignore = "needs hardware: a board playing the role \"dongle\""]
async fn a_full_log_ring_does_not_reset_the_board() -> anyhow::Result<()> {
    let Some(mut node) = Rig::load()?.attach("dongle").await? else {
        return Ok(());
    };

    // Uptime before, so a reset during the request is detectable afterwards.
    let before = node.alarms().await?.now_ms;

    // Fill the ring: trace level plus enough time for the router's per-frame
    // records to wrap it.
    node.set_log_level("trace").await?;
    tokio::time::sleep(Duration::from_secs(10)).await;

    let requested = node.logs(0, FULL_RING_RECORDS).await;

    // Restore before asserting, so a failure does not leave the board at trace
    // — but do not discard the outcome. Boards are a serialised singleton, so a
    // board left at trace changes the heap pressure and timing every later test
    // runs under, in a suite whose bugs are a heap OOM and a fault under load.
    let restored = node.set_log_level("info").await;
    let records = requested?;
    if let Err(e) = restored {
        eprintln!(
            "WARNING: could not restore the log level on {:?}; it is still at trace and \
             later tests share this board: {e:#}",
            node.role(),
        );
    }

    node.with_diagnostics(async |node: &mut Node| {
        // Uptime, not "did a request succeed": the failure mode is a *reset*,
        // and a board that resets and re-enumerates answers the next request
        // perfectly well. Only a clock that went backwards proves it restarted.
        let after = node.alarms().await?.now_ms;
        anyhow::ensure!(
            after >= before,
            "the board's uptime went backwards ({before}ms -> {after}ms): a full-ring \
             GetLogs reset it, which is the bug BATCH_BYTE_BUDGET exists to prevent",
        );
        anyhow::ensure!(
            !records.records.is_empty(),
            "the ring should have held records after 10s at trace level",
        );
        Ok(())
    })
    .await
}

/// **Reproduction for the management-port HardFault** (design 21 §5's test 7).
///
/// A management client attaching HardFaults the board — not a panic, a
/// HardFault, with stack overflow ruled out by measurement.
///
/// The detector is **uptime going backwards**, not a failed request. A board
/// that faults resets and re-enumerates well inside `ATTACH_TIMEOUT`, so the
/// next cycle attaches and answers perfectly well: without this check the test
/// passes whether or not the board faulted, unless it stays dead for twenty
/// continuous seconds.
///
/// The firmware writes a retained fault record and logs it at the *next* boot
/// (`wayfinder_nrf::fault: previous boot ended in a hardfault … cfsr=…`), so
/// the CFSR is reachable — but only through the log ring after the reset, which
/// is why this test reports the log tail on failure rather than claiming the
/// dump is itself a CFSR. Design 21 §4.5's "reset and re-read the fault record"
/// step is not implemented; see §12.
#[tokio::test]
#[ignore = "needs hardware: a board playing the role \"alpha\""]
async fn repeated_management_attach_does_not_fault_the_board() -> anyhow::Result<()> {
    let rig = Rig::load()?;
    let Some(board) = rig.board("alpha") else {
        return Ok(());
    };

    let mut previous_uptime_ms = 0;
    for cycle in 0..MGMT_ATTACH_CYCLES {
        let mut node = Node::attach(&board)
            .await
            .map_err(|e| e.context(format!("attach cycle {cycle} of {MGMT_ATTACH_CYCLES}")))?;
        node.node_info()
            .await
            .map_err(|e| e.context(format!("GetNodeInfo on cycle {cycle}")))?;

        let uptime_ms = node.alarms().await?.now_ms;
        if uptime_ms < previous_uptime_ms {
            let dump = Diagnostics::collect(&mut node).await;
            anyhow::bail!(
                "the board reset between cycle {} and {cycle}: uptime went {previous_uptime_ms}ms \
                 -> {uptime_ms}ms. Look for `previous boot ended in a hardfault` with a CFSR in \
                 the log tail below.\n{dump}",
                cycle.saturating_sub(1),
            );
        }
        previous_uptime_ms = uptime_ms;

        // The detach is the interesting half: `serve_forever` tears the
        // connection down and re-arms, and that is where the fault was seen.
        drop(node);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Whatever the board says about itself after the soak.
    Node::attach(&board).await?.report().await;
    Ok(())
}
