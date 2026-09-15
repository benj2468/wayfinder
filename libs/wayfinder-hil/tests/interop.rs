//! Two boards, one authenticated mesh, traffic both ways over real RF.
//!
//! Design 21 §5's test 4, and the first hardware test in this suite whose
//! subject is a *mesh* rather than a node. Everything else here drives one
//! board and reasons about what a peer would do; several of those tests say so
//! in their own doc comments ("that needs a second node, which is design 21
//! §5's test 4"). This is that test.
//!
//! # Why it can exist now
//!
//! Two things had to be true, and design 22 made both:
//!
//! - **A board's address is derived from its identity seed.** Before that an
//!   nRF board's MAC came from FICR, so no certificate could name the address
//!   it routed under (GitLab #58) — and a peer performing the key↔address
//!   binding check should have refused its OGMs. A two-node authenticated test
//!   was not merely unwritten, it could not have passed.
//! - **A board can be certified in place.** `TestMesh::certify` uses
//!   `SetAuth`'s empty-seed branch, so a node keeps the address it already
//!   runs under and the credential is usable immediately. The wholesale path
//!   (`install`) replaces the seed, and the node only adopts the new address on
//!   its next boot — which is fine for a DK and impossible for the dongle,
//!   because a dongle has no debugger and cannot be reset from the host.
//!
//! # What "bidirectional" is worth asserting
//!
//! Convergence is not symmetric by default, and the asymmetry is the
//! interesting failure. A node with authentication *on* drops OGMs it cannot
//! verify, while a node with it *off* accepts everything — so an unauthenticated
//! board will happily route to an authenticated one that is silently ignoring
//! it. Watching from one side only would report that as success.
//!
//! So this asserts both directions, and asserts them twice over: each node has
//! the other in its originator table, and each node can actually *reach* the
//! other with a `Ping`, which is the only assertion here that puts a frame on
//! the air and waits for the answer to come back.

use std::time::Duration;
use std::time::Instant;

use wayfinder_hil::Node;
use wayfinder_hil::Rig;
use wayfinder_hil::mesh::TestMesh;
use wayfinder_hil::mesh::host_unix;

/// How long to let the two boards find each other before giving up.
///
/// The 802.15.4 link's Trickle `i_max` is 20 s and a fresh adjacency starts at
/// `i_min`, so two OGM rounds is a couple of seconds; this is generous enough
/// to absorb a board that was mid-backoff when the credential landed, without
/// turning a real failure into a two-minute wait.
const CONVERGE_TIMEOUT: Duration = Duration::from_secs(45);

/// How long a `Ping` session is given to complete.
const PING_TIMEOUT_MS: u32 = 2_000;

/// How many echo requests each direction sends.
///
/// More than one so a single dropped frame is not a failed test — this is a
/// radio, and the assertion is "traffic flows", not "no frame is ever lost".
const PING_COUNT: u32 = 4;

/// **Two boards on one authenticated mesh carry traffic both ways.**
///
/// Design 21 §5's test 4. The two parts are certified under a single throwaway
/// authority, each keeping the identity it already holds, and then each is
/// required to see and reach the other.
#[tokio::test]
#[ignore = "needs hardware: two boards, roles \"alpha\" and \"dongle\""]
async fn two_boards_on_one_mesh_route_to_each_other() -> anyhow::Result<()> {
    let rig = Rig::load()?;
    let (Some(alpha_board), Some(dongle_board)) = (rig.board("alpha"), rig.board("dongle")) else {
        return Ok(());
    };

    let mut alpha = Node::attach(&alpha_board).await?;
    let mut dongle = Node::attach(&dongle_board).await?;

    // One authority, two members. Sharing the `TestMesh` is what puts them on
    // the same mesh: `certify` issues from this authority and installs its
    // trust anchor, so each node ends up able to verify the other's OGMs.
    let mesh = TestMesh::mint_now()?;
    let installed_at = host_unix()?;
    let alpha_mac = mesh.certify(&mut alpha, installed_at, None).await?;
    let dongle_mac = mesh.certify(&mut dongle, installed_at, None).await?;

    anyhow::ensure!(
        alpha_mac != dongle_mac,
        "both boards certified as {alpha_mac:?}; they are not two nodes",
    );

    // Proven before anything is asserted about routing: if a `SetAuth` was
    // refused, every failure below would point at the radio instead of at the
    // install. `certify` keeps each node's address, so unlike the wholesale
    // path there is no reboot between here and a usable credential.
    for (name, node, mac) in [
        ("alpha", &mut alpha, alpha_mac),
        ("dongle", &mut dongle, dongle_mac),
    ] {
        let status = node.security_status().await?;
        anyhow::ensure!(
            status.auth_enabled,
            "{name} did not come up authenticated after being certified",
        );
        anyhow::ensure!(
            status.mesh_id == wayfinder_hil::mesh::HIL_MESH_ID,
            "{name} is on mesh {:#x}, not the one it was just certified for",
            status.mesh_id,
        );
        // The whole point of certifying in place: the node routes under the
        // address its certificate names, with no reboot in between. If these
        // ever disagree the routing assertions below are meaningless, because
        // a peer would be right to refuse the OGMs.
        anyhow::ensure!(
            node.node_info().await?.node_id == mac,
            "{name} routes under an address its certificate does not name",
        );
    }

    // Each must see the other. Polled rather than slept on: a fixed sleep is
    // either flaky or slow, and the interesting number in a failure is how far
    // it got.
    await_originator(&mut alpha, "alpha", dongle_mac).await?;
    await_originator(&mut dongle, "dongle", alpha_mac).await?;

    // ...and each must be able to *reach* the other. The table says a route was
    // learned from an OGM; this is the only assertion that puts a frame on the
    // air and waits for the answer, which is what makes it the one that would
    // catch a one-way link.
    ping_across(&mut alpha, "alpha", dongle_mac, "dongle").await?;
    ping_across(&mut dongle, "dongle", alpha_mac, "alpha").await?;

    // Both boards have now heard each other over real RF, which is the only
    // state in which the LQI scale is measurable at all.
    assert_scaled_lqi(&mut alpha, "alpha").await?;
    assert_scaled_lqi(&mut dongle, "dongle").await?;

    Ok(())
}

/// The floor a correctly scaled 802.15.4 LQI must clear on two boards sharing
/// a desk.
///
/// Chosen to sit above what the *unscaled* driver could ever report rather
/// than at a signal strength worth having: the hardware correlator's domain
/// tops out at 63, so an unscaled build is structurally incapable of exceeding
/// it, while a scaled one maps even a mediocre 32 to 128. Anything in between
/// is the ambiguous band, so the floor goes above it.
const DESK_RANGE_LQI_FLOOR: u32 = 128;

/// **The scale half of GitLab #56, which no host test can reach.**
///
/// `ieee_lqi`'s unit tests pin the mapping against the Product Specification,
/// and `capture_reports_a_scaled_lqi` pins the wiring — but both are arguments
/// from the datasheet. Whether the byte `Packet::lqi()` actually returns on
/// this silicon is the correlator indicator those documents describe is not
/// decidable off-board, and design 19 §12.5 records the number as predicted
/// rather than measured.
///
/// This is the discriminator, and it is cheap because it needs no new
/// measurement: bring-up observed 49 and 67 on `dot15d4` at desk range, both
/// below [`DESK_RANGE_LQI_FLOOR`] and one of them already past the hardware
/// ceiling. So this fails on the pre-fix firmware and passes on the fixed one,
/// which is exactly what "verified on hardware" has to mean here.
///
/// Skips rather than fails when the node has no measured `dot15d4` row: a
/// board built without the 802.15.4 link is a legitimate configuration, and
/// failing it would make this test a claim about the build rather than about
/// the scale.
async fn assert_scaled_lqi(node: &mut Node, name: &str) -> anyhow::Result<()> {
    let table = node.link_quality_table().await?;
    let measured: Vec<_> = table
        .entries
        .iter()
        .filter(|e| e.iface_name == "dot15d4")
        .filter_map(|e| e.ewma_quality)
        .collect();

    if measured.is_empty() {
        eprintln!("SKIP: {name} reports no measured dot15d4 link-quality row");
        return Ok(());
    }

    let best = measured.iter().copied().max().unwrap_or(0);
    anyhow::ensure!(
        best >= DESK_RANGE_LQI_FLOOR,
        "{name}'s best dot15d4 link quality is {best}, under the {DESK_RANGE_LQI_FLOOR} \
         floor — at desk range that is the signature of an unscaled hardware \
         correlator indicator (domain 0..=63), not a weak link. All rows: {measured:?}",
    );
    Ok(())
}

/// Wait until `node` lists `wanted` in its originator table.
///
/// Reports what it *did* see on timeout. A bare "did not converge" sends
/// whoever reads it to the radio; the list distinguishes "heard nothing at all"
/// (an RF or channel problem) from "heard the peer and refused it" (an auth
/// problem), which are the two failures worth telling apart here.
async fn await_originator(node: &mut Node, name: &str, wanted: [u8; 6]) -> anyhow::Result<()> {
    let deadline = Instant::now() + CONVERGE_TIMEOUT;
    let mut seen: Vec<Vec<u8>> = Vec::new();

    while Instant::now() < deadline {
        seen = node
            .routing_table()
            .await?
            .entries
            .into_iter()
            .map(|e| e.destination)
            .collect();
        if seen.iter().any(|d| d.as_slice() == wanted) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let dump = node.with_diagnostics(async |_| Ok(())).await;
    let _ = dump;
    anyhow::bail!(
        "{name} never learned an originator for {wanted:x?} within {CONVERGE_TIMEOUT:?}; \
         its table held {seen:x?}. An empty table is an RF or channel problem; a table \
         with other entries but not this one is the peer being heard and refused, which \
         is an authentication problem"
    )
}

/// Require that `node` can reach `dst`, retrying whole ping sessions until it
/// can or [`CONVERGE_TIMEOUT`] runs out.
///
/// **Retried, because an originator appearing is not the same as it being
/// reachable.** A route is learned from one OGM; a *directed* frame additionally
/// carries a pairwise tag, and that needs each end to hold and have verified the
/// other's certificate — which arrives separately and, under lazy distribution,
/// only after a fetch the OGM's fingerprint triggers. So there is a real window
/// after discovery in which the table has a route and a ping is dropped as
/// unauthenticated. This waits that out rather than reporting it as a failure.
///
/// What it does not do is *lower the bar*: the run still has to end with frames
/// making the round trip, and the timeout is the same one discovery gets.
///
/// "At least one reply" rather than all of them: this is a radio, and the claim
/// under test is that traffic flows, not that the link is lossless.
async fn ping_across(
    node: &mut Node,
    name: &str,
    dst: [u8; 6],
    dst_name: &str,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + CONVERGE_TIMEOUT;
    let mut last = None;

    while Instant::now() < deadline {
        let started = node
            .ping(dst.to_vec(), PING_COUNT, 200, PING_TIMEOUT_MS, 16)
            .await?;

        // Drain this session before judging it.
        let session = loop {
            let status = node.ping_status(started.session_seq).await?;
            let Some(session) = status.session else {
                anyhow::bail!(
                    "{name}'s ping session to {dst_name} vanished before it finished; the \
                     node restarted, or another session displaced it"
                );
            };
            if !session.active {
                break session;
            }
            if Instant::now() >= deadline {
                anyhow::bail!("{name}'s ping session to {dst_name} never completed");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };

        if session.received > 0 {
            return Ok(());
        }
        last = Some((session.sent, session.received, session.lost));
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let (sent, received, lost) = last.unwrap_or((0, 0, 0));
    anyhow::bail!(
        "{name} never reached {dst_name} within {CONVERGE_TIMEOUT:?}; the last session sent \
         {sent}, received {received}, lost {lost}. Both nodes have a route and have \
         verified each other's certificates by this point, so a directed frame that never \
         comes back is the pairwise tag or the return path — not discovery, and not the \
         credential"
    )
}
