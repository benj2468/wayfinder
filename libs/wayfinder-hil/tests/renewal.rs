//! Design 24's board claims, on the hardware they are about.
//!
//! A board that has enrolled cannot stay enrolled: it has no IP stack to open a
//! client connection to its authority with, so it drops off the mesh every time
//! its certificate lapses. Design 24's answer is that it does not need one — it
//! is a routing member of a mesh the authority is also on, so it asks over that.
//!
//! `#[ignore]`d like the rest of this suite: `cargo nextest run --workspace`
//! compiles these and runs none, `just hil` runs them, and each skips cleanly
//! when the inventory names no board for its role.
//!
//! # What is on hardware here, and what is not
//!
//! Two tests, split by how many boards a bench has.
//!
//! **One board** — that a real board, free-running on an internal RC oscillator
//! with a credential in its own flash, judges its own renewal window against a
//! clock that is a floor rather than a reading (§4.5), and raises the alarm an
//! operator reads (§7). It is pointed at an authority that does not exist, which
//! is also §5.4's partitioned case: quiet on the wire, loud on the alarm board.
//!
//! **Two boards** — that it then actually *asks*, putting a `RenewReq` on real
//! RF toward the address its recorded provider key derives.
//!
//! **Not the answering half**, at any board count. That needs a certificate
//! authority *on the mesh*: a host node carrying both a radio and a
//! `CertAuthority` — the `wayfinder-ca` posture with an 802.15.4 link, for which
//! this rig defines no role. The exchange end to end lives in `wayfinder-test`'s
//! `a_board_renews_its_certificate_over_the_mesh`, against the same
//! `CertAuthority` a provider runs.

use std::time::Duration;
use std::time::Instant;

use wayfinder_hil::Node;
use wayfinder_hil::Rig;
use wayfinder_hil::mesh::TestMesh;
use wayfinder_hil::mesh::host_unix;

/// How long to wait for the board to reach its first renewal poll.
///
/// The poll is paced at `RENEWAL_POLL_INTERVAL` (fifteen minutes), but the
/// *first* one is due immediately — the deadline starts at zero, matching the
/// host renewer's "the first turn evaluates". So this only has to cover the
/// board noticing: one turn of its event loop, which its OGM timer wakes within
/// a couple of seconds on an 802.15.4 link, plus generous slack for a board
/// that was mid-backoff when the credential landed.
const ASK_TIMEOUT: Duration = Duration::from_secs(60);

/// How often to poll the board while waiting.
const POLL: Duration = Duration::from_millis(500);

/// **A board inside its renewal window knows it, and says so** — on the part,
/// with a credential in its own flash and a clock that is a floor rather than a
/// reading.
///
/// One board, so this runs on a bench that has only one. It is the half of
/// design 24 that needs no peer: the board judges `renew_from` against
/// `Clocked::AtLeast` (§4.5), reports `cert_due_renewal`, and raises the
/// operator-facing alarm. The authority it is pointed at does not exist on this
/// bench, which is also the point — §5.4's partitioned case, where a board that
/// cannot reach its authority stays quiet on the wire and loud on the alarm
/// board.
#[tokio::test]
#[ignore = "needs hardware: a board playing the role \"alpha\""]
async fn a_board_in_its_renewal_window_reports_due_and_alarms() -> anyhow::Result<()> {
    let rig = Rig::load()?;
    let Some(alpha) = rig.board("alpha") else {
        return Ok(());
    };

    alpha.reset()?;
    let mut node = Node::attach(&alpha).await?;

    // A window this board is already three-quarters through, and an authority
    // key nothing on this bench holds — so it is due, it knows where it would
    // ask, and it can never get there.
    let now = host_unix()?;
    let due = TestMesh::mint_in_renewal_window(now)?;
    due.certify(&mut node, now, Some(&[0xAB; 32])).await?;

    // **Reset, and let the board come back on what it stored.** Two reasons,
    // and the second is the better one:
    //
    // 1. The renewal poll is paced at fifteen minutes and the board spent its
    //    first one at boot, before this credential existed. Waiting out the
    //    interval would make this a fifteen-minute test; a reset restarts the
    //    deadline at zero, which is where a board's first poll always is.
    // 2. It means the credential *and the authority it renews against* have to
    //    survive real flash to get here. That is design 24 §4.4 and design 22
    //    together, on the medium — where every x86 test for it runs against an
    //    in-memory store.
    alpha.reset()?;
    let mut node = Node::attach(&alpha).await?;

    node.with_diagnostics(async |node: &mut Node| {
        let status = node.security_status().await?;
        let info = node.node_info().await?;
        anyhow::ensure!(
            status.cert_due_renewal,
            "the board must read its certificate as due: it holds not_after={}, the              fixture issued [{}, {}] with renew_from={}, and the board's clock posture              is {:?}",
            status.cert_not_after,
            due.not_before().unwrap_or(0),
            due.not_after(),
            due.renew_from(),
            info.clock_posture(),
        );
        // Quiet on the wire: nothing here can answer, and §5.4 says a board
        // partitioned from its authority retries rather than complains.
        anyhow::ensure!(
            status.renewal_replies_accepted == 0,
            "nothing on this bench can issue a certificate",
        );

        // Loud on the alarm board, which is §7's operator-facing half — and on
        // a board with no debug probe attached, the only place it would be seen.
        let deadline = Instant::now() + ASK_TIMEOUT;
        loop {
            let alarms = node.alarms().await?;
            if alarms
                .alarms
                .iter()
                .any(|a| a.detail.contains("certificate is in its last quarter"))
            {
                break;
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "a board inside its renewal window must raise `CertExpiring` within \
                 {}s; got {:?}",
                ASK_TIMEOUT.as_secs(),
                alarms.alarms,
            );
            tokio::time::sleep(POLL).await;
        }
        Ok(())
    })
    .await
}

/// **A board inside its renewal window asks, over the mesh, unattended.**
///
/// The whole of design 24 §2.2's claim, on the part: the blocker was never that
/// a board has no way to *reach* an authority, only that it had no way to speak
/// to one, because every management conversation in this project is TLS over
/// TCP. Give it a packet type and it asks by itself.
///
/// The certificate installed here is deliberately deep inside its renewal
/// window — the last quarter — because that is the only state this path is ever
/// reached from, and a fixture with a fresh certificate would assert nothing
/// while passing.
///
/// The authority it is pointed at is a second board, which is not one and will
/// not answer. That is the point: this asserts the asking, the counters and the
/// alarm, and leaves the answering to the host-side test that can actually mint
/// a certificate.
#[tokio::test]
#[ignore = "needs hardware: boards playing the roles \"alpha\" and \"beta\""]
async fn a_board_asks_to_renew_over_the_mesh() -> anyhow::Result<()> {
    let rig = Rig::load()?;
    let (Some(alpha), Some(beta)) = (rig.board("alpha"), rig.board("beta")) else {
        return Ok(());
    };

    alpha.reset()?;
    beta.reset()?;
    let mut renewing = Node::attach(&alpha).await?;
    let mut standin = Node::attach(&beta).await?;

    // One mesh, both boards on it, each certified in place so neither has to
    // reboot to adopt an address — `certify`, not `install`, for the reason
    // `interop.rs` gives.
    let now = host_unix()?;
    let mesh = TestMesh::mint(now);
    mesh.certify(&mut standin, now, None).await?;
    // The **key**, not the address: a board records the pinned key and derives
    // the MAC to route a renewal to, so the two can never disagree.
    let authority_key: [u8; 32] = standin
        .security_status()
        .await?
        .own_ed_pubkey
        .try_into()
        .map_err(|_| anyhow::anyhow!("the stand-in board reports no identity key"))?;

    // The renewing board gets a window it is already most of the way through,
    // and a record of where it renews. Both halves matter: a board with a fresh
    // certificate never asks, and one with no recorded authority has nowhere to.
    let due = TestMesh::mint_in_renewal_window(now)?;
    due.certify(&mut renewing, now, Some(&authority_key))
        .await?;

    renewing
        .with_diagnostics(async |node: &mut Node| {
            let status = node.security_status().await?;
            anyhow::ensure!(
                status.cert_due_renewal,
                "the fixture's certificate must be inside its renewal window, or this \
                 test asserts nothing while passing",
            );

            // Wait for the board to act on it. Polled rather than slept on, so
            // the test is bounded by the work rather than by a guessed duration.
            let deadline = Instant::now() + ASK_TIMEOUT;
            let asked = loop {
                let status = node.security_status().await?;
                if status.renewal_requests_sent > 0 {
                    break status;
                }
                anyhow::ensure!(
                    Instant::now() < deadline,
                    "the board never asked to renew within {}s, though it reports its \
                     certificate as due and holds an authority to ask",
                    ASK_TIMEOUT.as_secs(),
                );
                tokio::time::sleep(POLL).await;
            };

            anyhow::ensure!(
                asked.renewal_replies_accepted == 0,
                "nothing on this mesh can issue a certificate, so an accepted reply \
                 would mean the board installed something it should have refused",
            );

            // And it says so. A board that asks and is never answered is the
            // failure this whole path exists to make visible, and on a board
            // with no debugger attached the alarm board is where an operator
            // sees it.
            let alarms = node.alarms().await?;
            anyhow::ensure!(
                alarms
                    .alarms
                    .iter()
                    .any(|a| a.detail.contains("certificate is in its last quarter")),
                "a board inside its renewal window must raise `CertExpiring`; got {:?}",
                alarms.alarms,
            );
            Ok(())
        })
        .await
}
