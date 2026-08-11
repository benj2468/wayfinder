//! One poll's worth of node state, and the code that fetches it.
//!
//! The browser polls this whole bundle rather than querying per tab, which
//! mirrors `wayfinder-tui`'s `fetch`: the TUI also reads every table each tick
//! regardless of which tab is showing, so switching tabs presents data that is
//! already there instead of a blank panel and a round trip. Here it buys one
//! more thing — ten management-API requests behind a single browser request,
//! and a single lock on the shared connection.
//!
//! [`build_snapshot`] is a plain async function rather than living inside the
//! `#[server]` macro so it can be driven directly by `tests/snapshot.rs` against
//! a real node, with none of the server-function machinery in the way.

use serde::Deserialize;
use serde::Serialize;
use wayfinder_protos::wayfinder::v1alpha::GetSecurityStatusResponse;
use wayfinder_protos::wayfinder::v1alpha::KeepAliveTable;
use wayfinder_protos::wayfinder::v1alpha::LinkFeaturesTable;
use wayfinder_protos::wayfinder::v1alpha::LinkQualityTable;
use wayfinder_protos::wayfinder::v1alpha::ListPendingCsrsResponse;
use wayfinder_protos::wayfinder::v1alpha::LogRecords;
use wayfinder_protos::wayfinder::v1alpha::NodeInfo;
use wayfinder_protos::wayfinder::v1alpha::NodeMetrics;
use wayfinder_protos::wayfinder::v1alpha::OgmSchedule;
use wayfinder_protos::wayfinder::v1alpha::RoutingTable;
use wayfinder_protos::wayfinder::v1alpha::Throughput;

#[cfg(feature = "ssr")]
use crate::conn::NodeConnection;

/// Records requested per poll.
///
/// Comfortably above what a node emits between polls at any sane filter, so a
/// steady stream is kept up with in one round trip; a burst that exceeds it is
/// collected over the next few polls, in order, with no loss — the node tracks
/// a resume point per client.
pub const LOG_BATCH: u32 = 256;

/// Everything the dashboard reads from a node in one poll.
///
/// Carries the generated proto types directly rather than a parallel set of view
/// structs, so each table has exactly one definition shared by the node, the
/// server and the browser. Formatting for display happens at the point of
/// render, in [`crate::format`].
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct NodeSnapshot {
    /// Identity and capacity.
    pub node_info: Option<NodeInfo>,
    /// The BATMAN originator table.
    pub routing: RoutingTable,
    /// Per-(neighbor, interface) link quality.
    pub link_quality: LinkQualityTable,
    /// Per-interface participation gates.
    pub link_features: LinkFeaturesTable,
    /// Per-neighbor keep-alive liveness.
    pub keepalive: KeepAliveTable,
    /// Per-interface adaptive OGM emission schedule.
    pub ogm_schedule: OgmSchedule,
    /// Per-interface throughput rates and node-wide totals.
    pub throughput: Throughput,
    /// Aggregate node health and topology metrics.
    pub metrics: Option<NodeMetrics>,
    /// Mesh authentication posture.
    pub security: Option<GetSecurityStatusResponse>,
    /// CSRs awaiting operator approval. `None` when the node is not a
    /// certificate-authority provider — see [`build_snapshot`].
    pub pending_csrs: Option<ListPendingCsrsResponse>,
    /// Log records since the cursor the poll asked from, plus the next cursor.
    pub logs: LogRecords,
}

/// Poll a node for one [`NodeSnapshot`], resuming the log stream at `since_seq`.
///
/// Every request goes over one connection, taken once (see
/// [`NodeConnection::run`]). A failure in any of them fails the whole poll and
/// drops the connection, because a dashboard showing eight fresh tables and two
/// silently stale ones is worse than one that says it lost the node.
///
/// The one deliberate exception is the enrollment RPC: a node that is not a
/// certificate-authority provider answers it with an error, which is a fact
/// about the node rather than a fault. That is recorded as "no provider data"
/// and the rest of the poll stands — the Security tab is one tab, not the
/// dashboard.
#[cfg(feature = "ssr")]
pub async fn build_snapshot(conn: &NodeConnection, since_seq: u64) -> anyhow::Result<NodeSnapshot> {
    conn.run(async |client| {
        Ok(NodeSnapshot {
            node_info: Some(client.node_info().await?),
            routing: client.routing_table().await?,
            link_quality: client.link_quality_table().await?,
            link_features: client.link_features_table().await?,
            keepalive: client.keepalive_table().await?,
            ogm_schedule: client.ogm_schedule().await?,
            throughput: client.throughput().await?,
            metrics: Some(client.node_metrics().await?),
            security: Some(client.security_status().await?),
            pending_csrs: client.list_pending_csrs().await.ok(),
            logs: client.logs(since_seq, LOG_BATCH).await?,
        })
    })
    .await
}
