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
use wayfinder_protos::wayfinder::v1alpha::Alarms;
use wayfinder_protos::wayfinder::v1alpha::GetSecurityStatusResponse;
use wayfinder_protos::wayfinder::v1alpha::KeepAliveTable;
use wayfinder_protos::wayfinder::v1alpha::LinkFeaturesTable;
use wayfinder_protos::wayfinder::v1alpha::LinkQualityTable;
use wayfinder_protos::wayfinder::v1alpha::ListPendingCsrsResponse;
use wayfinder_protos::wayfinder::v1alpha::ListVpnPeersResponse;
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
    /// VPN peers registered with the provider's coordination server. `None`
    /// when this node is not a provider *or* has no VPN configured — the
    /// common case, since VPN links are additive — *or* when the poll was made
    /// on a read-only connection, which the node does not serve this table to
    /// and whose viewer never sees the Provider tab it feeds. Distinguishing
    /// them would need a different answer from the node; the panel simply does
    /// not appear, which is right for all three.
    pub vpn_peers: Option<ListVpnPeersResponse>,
    /// Log records since the cursor the poll asked from, plus the next cursor.
    ///
    /// `None` on a read-only poll. The node serves its log ring to a full grant
    /// only: the ring carries whatever the process logged, which on a provider
    /// includes the account-administration records naming each username and
    /// role, and a viewer reading those recovers the roster `ListUsers` is
    /// admin-gated to protect. Same treatment as `vpn_peers` above — the query
    /// is skipped rather than sent and refused.
    ///
    /// Note the one place this reads oddly: `NodeSnapshot::default()` yields
    /// `None` too, and a default snapshot is not a poll at all. Nothing
    /// consults it before the first poll lands, but a *fixture* built from
    /// `Default` is asserting "withheld" whether it means to or not.
    pub logs: Option<LogRecords>,
    /// The node's alarm board: the conditions it currently believes are wrong.
    ///
    /// Not `Option`, unlike `metrics` and `security` beside it: an empty board
    /// is the node's answer — "nothing is wrong" — rather than the absence of
    /// one, and that answer is what the header reports as normal. Whether the
    /// node has been *reached* is `Dashboard::connected`'s question, and it is
    /// answered an inch away in the same header.
    pub alarms: Alarms,
}

/// What the credential behind a poll may ask the node for.
///
/// A closed enum rather than a bare `bool`, so a call site says which it means
/// and a third tier — should one ever gain its own visible tables — is a
/// compile error at every poll instead of a silent misread.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PollScope {
    /// An administrator's connection: every table, including the ones the node
    /// serves only to a full grant.
    Administrator,
    /// A read-only connection: the queries a viewer certificate may make, and
    /// none of the admin-gated ones.
    ReadOnly,
}

/// Poll a node for one [`NodeSnapshot`], resuming the log stream at `since_seq`.
///
/// Every request goes over one connection, taken once (see
/// [`NodeConnection::run`]). A failure in any of them fails the whole poll and
/// drops the connection, because a dashboard showing eight fresh tables and two
/// silently stale ones is worse than one that says it lost the node — and
/// because reusing a connection past a transport-level failure risks reading a
/// stale response as the answer to the next request (see
/// [`NodeConnection::run`]).
///
/// The one deliberate exception is the enrollment RPC: a node that is not a
/// certificate-authority provider answers it with a clean server-side error
/// ([`is_missing_provider`]), which is a fact about the node rather than a
/// fault. That is recorded as "no provider data" and the rest of the poll
/// stands — the Security tab is one tab, not the dashboard. Any other failure
/// on this RPC (a transport or decode error) is not recognized and fails the
/// whole poll like every other table here.
///
/// `scope` says what the connection's certificate is allowed to ask for, and
/// [`PollScope::ReadOnly`] *skips* the two admin-gated queries rather than
/// sending them and tolerating the refusal. A poll that asked anyway would both
/// fail the whole snapshot and write a security `warn!` into the node's log once
/// a second for as long as anyone left the dashboard open.
///
/// The two, and why the node keeps each off the viewer tier:
///
/// - `ListVpnPeers` is answered by calling out to the coordination server, so a
///   read-only client must not be able to drive outbound requests from the CA
///   at whatever rate it polls.
/// - `GetLogs` returns the process's whole log ring, which on a provider carries
///   the account-administration records naming each username and role — the
///   roster `ListUsers` is admin-gated to protect. Narrowed for issue #34.
#[cfg(feature = "ssr")]
pub async fn build_snapshot(
    conn: &NodeConnection,
    since_seq: u64,
    scope: PollScope,
) -> anyhow::Result<NodeSnapshot> {
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
            pending_csrs: match client.list_pending_csrs().await {
                Ok(resp) => Some(resp),
                Err(e) if is_missing_provider(&e) => None,
                Err(e) => return Err(e),
            },
            // Same treatment as `pending_csrs`, plus one more expected answer:
            // a provider with no VPN configured. Both are facts about the
            // node rather than faults, and neither should cost the operator
            // the other nine tables.
            //
            // A coordination server that is *configured but unreachable* is
            // deliberately not in that set: it fails the poll, because an
            // empty peer list and a broken tunnel control plane look identical
            // on screen and mean opposite things.
            vpn_peers: match scope {
                PollScope::ReadOnly => None,
                PollScope::Administrator => match client.list_vpn_peers().await {
                    Ok(resp) => Some(resp),
                    Err(e) if is_missing_provider(&e) || is_vpn_unconfigured(&e) => None,
                    Err(e) => return Err(e),
                },
            },
            logs: match scope {
                PollScope::ReadOnly => None,
                PollScope::Administrator => Some(client.logs(since_seq, LOG_BATCH).await?),
            },
            // Fetched on every poll, and failing the poll if it fails, like
            // every other table here: a header that kept claiming "all systems
            // normal" from a board it stopped being able to read would be
            // worse than one that says it lost the node.
            alarms: client.alarms().await?,
        })
    })
    .await
}

/// True for the one recognized "this node is not a certificate-authority
/// provider" answer to the enrollment RPCs (the exact wording served by
/// `wayfinder_server::adapter`'s `MeshAdapter`). Anything else — a transport
/// failure, a decode failure, a different server-side error — is a real fault,
/// not this specific, expected business answer, and must not be swallowed.
#[cfg(feature = "ssr")]
fn is_missing_provider(err: &anyhow::Error) -> bool {
    err.to_string()
        .contains("not a certificate-authority provider")
}

/// True for the "this provider has no VPN coordination configured" answer
/// (`wayfinder_server::vpn::VpnError::NotConfigured`'s wording), which is the
/// normal state of every deployment that does not run a tunnel.
///
/// Deliberately narrow: an unreachable or erroring coordination server is a
/// different `VpnError` with different wording, and must fail the poll rather
/// than render as "no VPN here".
#[cfg(feature = "ssr")]
fn is_vpn_unconfigured(err: &anyhow::Error) -> bool {
    err.to_string().contains("no VPN coordination configured")
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::is_missing_provider;
    use super::is_vpn_unconfigured;

    #[test]
    fn recognizes_the_not_a_provider_server_error() {
        let err = anyhow::anyhow!("server error: node is not a certificate-authority provider");
        assert!(is_missing_provider(&err));
    }

    #[test]
    fn does_not_recognize_a_transport_failure() {
        let err = anyhow::anyhow!("connection reset by peer");
        assert!(!is_missing_provider(&err));
    }

    #[test]
    fn does_not_recognize_an_unrelated_server_error() {
        let err = anyhow::anyhow!("server error: node is not enrolled");
        assert!(!is_missing_provider(&err));
    }

    /// A provider with no tunnel is a fact about the deployment; a tunnel
    /// control plane that is down is a fault. They must not be confused, since
    /// treating the second as the first renders an empty peer list on a mesh
    /// whose VPN is broken.
    #[test]
    fn tells_an_unconfigured_vpn_apart_from_a_broken_one() {
        assert!(is_vpn_unconfigured(&anyhow::anyhow!(
            "server error: this provider has no VPN coordination configured"
        )));
        assert!(!is_vpn_unconfigured(&anyhow::anyhow!(
            "server error: VPN coordination server unreachable: connection refused"
        )));
        assert!(!is_vpn_unconfigured(&anyhow::anyhow!(
            "server error: VPN coordination server returned an unexpected response: bad json"
        )));
    }
}
