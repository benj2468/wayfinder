//! Rendering of management-API responses as either human-readable text or JSON.
//!
//! Each renderer returns a `String` (rather than printing) so it is unit-
//! testable. JSON is produced by `serde_json` over the proto types, which derive
//! `serde::Serialize` via the `wayfinder-protos` `serde` feature.

use clap::ValueEnum;
use serde::Serialize;
use wayfinder_protos::wayfinder::v1alpha::GetSecurityStatusResponse;
use wayfinder_protos::wayfinder::v1alpha::KeepAliveTable;
use wayfinder_protos::wayfinder::v1alpha::LinkFeaturesTable;
use wayfinder_protos::wayfinder::v1alpha::LinkQualityTable;
use wayfinder_protos::wayfinder::v1alpha::ListCertsResponse;
use wayfinder_protos::wayfinder::v1alpha::ListPendingCsrsResponse;
use wayfinder_protos::wayfinder::v1alpha::LogLevel;
use wayfinder_protos::wayfinder::v1alpha::LogRecords;
use wayfinder_protos::wayfinder::v1alpha::NodeInfo;
use wayfinder_protos::wayfinder::v1alpha::NodeMetrics;
use wayfinder_protos::wayfinder::v1alpha::OgmSchedule;
use wayfinder_protos::wayfinder::v1alpha::ResolveRouteResponse;
use wayfinder_protos::wayfinder::v1alpha::RoutingTable;
use wayfinder_protos::wayfinder::v1alpha::Throughput;
use wayfinder_protos::wayfinder::v1alpha::resolve_route_response::Egress;

/// How a command renders its result.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Compact, human-readable text.
    Human,
    /// Pretty-printed JSON of the raw protobuf response.
    Json,
}

/// Render `value` as JSON, or via the `human` closure, per `fmt`.
fn render<T: Serialize>(
    value: &T,
    fmt: OutputFormat,
    human: impl FnOnce(&T) -> String,
) -> anyhow::Result<String> {
    Ok(match fmt {
        OutputFormat::Json => serde_json::to_string_pretty(value)?,
        OutputFormat::Human => human(value),
    })
}

/// An interface's configured name, or `-` when the node reported none.
///
/// Unlike the TUI, `wayfinderctl` keeps the numeric `IFACE` column alongside
/// this one: the index is what an operator types into `link-enable`/`set-ogm`,
/// so replacing it with the name would break the copy-paste path.
pub fn format_iface_name(name: &str) -> &str {
    if name.is_empty() { "-" } else { name }
}

/// Render a raw identifier as a colon-delimited MAC (6 bytes) or plain hex.
pub fn format_mac(bytes: &[u8]) -> String {
    if bytes.len() == 6 {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    } else {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Render [`NodeInfo`].
pub fn node_info(v: &NodeInfo, fmt: OutputFormat) -> anyhow::Result<String> {
    render(v, fmt, |v| {
        format!(
            "node {}\noriginators: {}\nlocked: {}\nruntime config: {}",
            format_mac(&v.node_id),
            v.num_originators,
            if v.auth_locked { "yes" } else { "no" },
            if v.runtime_config_active { "yes" } else { "no" }
        )
    })
}

/// Render the [`RoutingTable`] as one line per originator plus its paths.
pub fn routing_table(v: &RoutingTable, fmt: OutputFormat) -> anyhow::Result<String> {
    render(v, fmt, |v| {
        if v.entries.is_empty() {
            return "no originators".to_string();
        }
        let mut out = String::from("DESTINATION        NEXT_HOP           TQ   SEQNO  PATHS");
        for e in &v.entries {
            out.push_str(&format!(
                "\n{:<18} {:<18} {:>3} {:>6}  {}",
                format_mac(&e.destination),
                format_mac(&e.next_hop),
                e.tq,
                e.last_seqno,
                e.paths.len(),
            ));
        }
        out
    })
}

/// Render the [`LinkQualityTable`].
pub fn link_quality_table(v: &LinkQualityTable, fmt: OutputFormat) -> anyhow::Result<String> {
    render(v, fmt, |v| {
        if v.entries.is_empty() {
            return "no link-quality samples".to_string();
        }
        let mut out = String::from("NEIGHBOR           IFACE  NAME              QUALITY  SAMPLES");
        for e in &v.entries {
            out.push_str(&format!(
                "\n{:<18} {:>5}  {:<16}  {:>7}  {:>7}",
                format_mac(&e.neighbor_id),
                e.iface_idx,
                format_iface_name(&e.iface_name),
                // An unmeasurable link (raw L2, UDP) reports no quality at
                // all; show that rather than a 0 an operator would read as a
                // failing link.
                e.ewma_quality
                    .map_or_else(|| "-".to_string(), |q| q.to_string()),
                e.sample_count,
            ));
        }
        out
    })
}

/// Render the [`LinkFeaturesTable`], with a derived STATUS column (on/off/
/// mixed) so an operator can confirm a `link-enable`/`link-disable` took
/// effect at a glance.
pub fn link_features_table(v: &LinkFeaturesTable, fmt: OutputFormat) -> anyhow::Result<String> {
    render(v, fmt, |v| {
        if v.entries.is_empty() {
            return "no interfaces configured".to_string();
        }
        let mut out = String::from(
            "IFACE  NAME              TX_OGM  RX_OGM  TX_DATA  RX_DATA  KEEPALIVE_MS  STATUS",
        );
        for e in &v.entries {
            let all_on = e.tx_ogm && e.rx_ogm && e.tx_data && e.rx_data;
            let all_off = !e.tx_ogm && !e.rx_ogm && !e.tx_data && !e.rx_data;
            let status = if all_on {
                "on"
            } else if all_off {
                "off"
            } else {
                "mixed"
            };
            out.push_str(&format!(
                "\n{:>5}  {:<16}  {:>6}  {:>6}  {:>7}  {:>7}  {:>12}  {:>6}",
                e.iface_idx,
                format_iface_name(&e.iface_name),
                e.tx_ogm,
                e.rx_ogm,
                e.tx_data,
                e.rx_data,
                e.tx_keepalive_interval_ms
                    .map(|ms| ms.to_string())
                    .unwrap_or_else(|| "off".to_string()),
                status,
            ));
        }
        out
    })
}

/// Render the [`KeepAliveTable`].
pub fn keepalive_table(v: &KeepAliveTable, fmt: OutputFormat) -> anyhow::Result<String> {
    render(v, fmt, |v| {
        if v.entries.is_empty() {
            return "no keep-alive heartbeats heard".to_string();
        }
        let mut out = String::from("NEIGHBOR           MS_SINCE_HEARD  INTERVAL_MS  MISSED");
        for e in &v.entries {
            out.push_str(&format!(
                "\n{:<18} {:>14}  {:>11}  {:>6}",
                format_mac(&e.neighbor_id),
                e.ms_since_last_heard,
                e.interval_estimate_ms,
                if e.missed { "yes" } else { "no" },
            ));
        }
        out
    })
}

/// Render the [`OgmSchedule`].
pub fn ogm_schedule(v: &OgmSchedule, fmt: OutputFormat) -> anyhow::Result<String> {
    render(v, fmt, |v| {
        if v.entries.is_empty() {
            return "no interfaces configured".to_string();
        }
        let mut out = String::from("IFACE  NAME              CURRENT_MS  MIN_MS  MAX_MS");
        for e in &v.entries {
            out.push_str(&format!(
                "\n{:>5}  {:<16}  {:>10}  {:>6}  {:>6}",
                e.iface_idx,
                format_iface_name(&e.iface_name),
                e.current_interval_ms,
                e.min_interval_ms,
                e.max_interval_ms,
            ));
        }
        out
    })
}

/// Render [`Throughput`] (per-interface rows + node totals).
pub fn throughput(v: &Throughput, fmt: OutputFormat) -> anyhow::Result<String> {
    render(v, fmt, |v| {
        let mut out =
            String::from("IFACE  NAME                RX_BPS    RX_FPS    TX_BPS    TX_FPS");
        for i in &v.interfaces {
            out.push_str(&format!(
                "\n{:>5}  {:<16}  {:>8.0}  {:>8.1}  {:>8.0}  {:>8.1}",
                i.iface_idx,
                format_iface_name(&i.iface_name),
                i.rx_bps,
                i.rx_fps,
                i.tx_bps,
                i.tx_fps,
            ));
        }
        out.push_str(&format!(
            "\ntotal  {:<16}  {:>8.0}  {:>8.1}  {:>8.0}  {:>8.1}",
            "", v.total_rx_bps, v.total_rx_fps, v.total_tx_bps, v.total_tx_fps,
        ));
        out
    })
}

/// Render [`NodeMetrics`].
pub fn node_metrics(v: &NodeMetrics, fmt: OutputFormat) -> anyhow::Result<String> {
    render(v, fmt, |v| {
        let occ = |o: &Option<wayfinder_protos::wayfinder::v1alpha::TableOccupancy>| match o {
            Some(o) => format!("{}/{}", o.used, o.capacity),
            None => "-".to_string(),
        };
        format!(
            "uptime: {}s\nneighbors: {}\noriginators: {}\nbroadcast_dedup: {}\n\
             local_mcast_groups: {}\nmcast_memberships: {}\n\
             tq (min/mean/max): {}/{:.1}/{}\npaths (mean/max): {:.2}/{}\n\
             oversize_drops: {}\nrelay_oversize_drops: {}\n\
             cert_store: {}\nin_flight_cert_requests: {}\npending_cert_replies: {}\n\
             cert_req_rate: {:.2}\ncert_reply_rate: {:.2}",
            v.uptime_secs,
            v.neighbor_count,
            occ(&v.originators),
            occ(&v.broadcast_dedup),
            occ(&v.local_mcast_groups),
            occ(&v.mcast_memberships),
            v.tq_min,
            v.tq_mean,
            v.tq_max,
            v.paths_mean,
            v.paths_max,
            v.oversize_drops,
            v.relay_oversize_drops,
            occ(&v.cert_store),
            occ(&v.in_flight_cert_requests),
            occ(&v.pending_cert_replies),
            v.cert_req_rate,
            v.cert_reply_rate,
        )
    })
}

/// Render a [`ResolveRouteResponse`].
pub fn resolve(v: &ResolveRouteResponse, fmt: OutputFormat) -> anyhow::Result<String> {
    render(v, fmt, |v| {
        let egress = match &v.egress {
            Some(Egress::AllInterfaces(_)) => "all interfaces (flood)".to_string(),
            Some(Egress::InterfaceIndex(i)) => format!("interface {i}"),
            None => "unknown (no link data)".to_string(),
        };
        format!("next_hop: {}\negress: {}", format_mac(&v.next_hop), egress)
    })
}

/// Render a [`GetSecurityStatusResponse`]: the mesh header then a per-originator
/// table (NODE / VERIFIED / EXPIRES / STATUS).
pub fn security(v: &GetSecurityStatusResponse, fmt: OutputFormat) -> anyhow::Result<String> {
    render(v, fmt, |v| {
        if !v.auth_enabled {
            return "authentication: disabled".to_string();
        }
        let mut out = format!(
            "authentication: enabled\nmesh_id: {:#x}\nnode: {}\nown cert expires: {}\nrevocations: {}",
            v.mesh_id,
            format_mac(&v.node_mac),
            v.cert_not_after,
            v.revocation_count,
        );
        if v.nodes.is_empty() {
            out.push_str("\n\nno originators known");
            return out;
        }
        out.push_str("\n\nNODE               VERIFIED  EXPIRES       STATUS");
        for n in &v.nodes {
            out.push_str(&format!(
                "\n{:<18} {:<9} {:<13} {}",
                format_mac(&n.node_id),
                if n.verified { "yes" } else { "no" },
                if n.verified {
                    n.cert_not_after.to_string()
                } else {
                    "-".to_string()
                },
                if n.revoked { "revoked" } else { "active" },
            ));
        }
        out
    })
}

/// Render the provider's [`ListCertsResponse`] (issued certificates).
pub fn list_certs(v: &ListCertsResponse, fmt: OutputFormat) -> anyhow::Result<String> {
    render(v, fmt, |v| {
        if v.certs.is_empty() {
            return "no certificates issued".to_string();
        }
        let mut out = String::from("NODE_MAC           NOT_BEFORE   NOT_AFTER    STATUS   ED25519");
        for c in &v.certs {
            out.push_str(&format!(
                "\n{:<18} {:>10} {:>10}   {:<7}  {}",
                format_mac(&c.node_mac),
                c.not_before,
                c.not_after,
                if c.revoked { "revoked" } else { "active" },
                fingerprint(&c.ed_pubkey),
            ));
        }
        out
    })
}

/// Render the provider's [`ListPendingCsrsResponse`] (CSRs awaiting approval).
pub fn list_pending_csrs(v: &ListPendingCsrsResponse, fmt: OutputFormat) -> anyhow::Result<String> {
    render(v, fmt, |v| {
        if v.pending.is_empty() {
            return "no pending CSRs".to_string();
        }
        let mut out = String::from("NODE_MAC           REQUESTED_AT   ED25519    X25519");
        for c in &v.pending {
            out.push_str(&format!(
                "\n{:<18} {:>12}   {:<9}  {}",
                format_mac(&c.node_mac),
                c.requested_at,
                fingerprint(&c.ed_pubkey),
                fingerprint(&c.x_pubkey),
            ));
        }
        out
    })
}

/// A record's level as a fixed-width label, so the target column stays aligned
/// down a screenful. Padded to five characters for the same reason the TUI's
/// `level_style` pads: the shape of a batch should read before the words do.
fn level_label(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Error => "ERROR",
        LogLevel::Warn => "WARN ",
        LogLevel::Info => "INFO ",
        LogLevel::Debug => "DEBUG",
        LogLevel::Trace => "TRACE",
        // Never emitted by a node — proto3 requires the zero value to exist, and
        // an unrecognised value decodes to it. Rendered rather than hidden so a
        // version skew shows up as odd-looking output instead of missing lines.
        LogLevel::Unspecified => "?????",
    }
}

/// Format a record's uptime as `[    12.345s]` — right-aligned so the seconds
/// column stays put as a node's uptime grows. Deliberately identical to the
/// TUI's `format_uptime`, so the same ring read through either client lines up.
fn format_uptime(uptime_ms: u64) -> String {
    format!("[{:>8}.{:03}s]", uptime_ms / 1000, uptime_ms % 1000)
}

/// The human-readable body of a batch: an optional dropped-records rule
/// followed by one line per record, each newline-terminated. Empty for an empty
/// batch — the "nothing retained" wording belongs to [`logs`], since a `--follow`
/// poll that finds nothing new should print nothing at all rather than a line a
/// second saying so.
fn human_log_lines(v: &LogRecords) -> String {
    let mut out = String::new();
    // Leads the batch rather than trailing it: the gap sits immediately before
    // the oldest record that survived, which is where it happened.
    if v.dropped > 0 {
        out.push_str(&format!("──── {} records dropped ────\n", v.dropped));
    }
    for r in &v.records {
        let level = LogLevel::try_from(r.level).unwrap_or(LogLevel::Unspecified);
        out.push_str(&format!(
            "{} {} {}: {}\n",
            format_uptime(r.uptime_ms),
            level_label(level),
            r.target,
            r.message,
        ));
    }
    out
}

/// Render one [`LogRecords`] batch as the records alone, for the streaming
/// `logs --follow` path where a footer per poll would bury the records it
/// describes. JSON renders the whole batch, one document per poll (JSON Lines).
pub fn log_lines(v: &LogRecords, fmt: OutputFormat) -> anyhow::Result<String> {
    render(v, fmt, human_log_lines)
}

/// Render a [`LogRecords`] batch: the records, then a footer carrying the
/// filter in force and the `next_seq` to resume from.
///
/// The footer is not decoration. Without the filter an operator cannot tell
/// "nothing happened" from "nothing was being recorded" — the node's startup
/// filter is one it never set itself, and another client may have changed it.
/// Without `next_seq` there is no way to poll again without either re-reading
/// records or skipping them.
pub fn logs(v: &LogRecords, fmt: OutputFormat) -> anyhow::Result<String> {
    render(v, fmt, |v| {
        let mut out = human_log_lines(v);
        if out.is_empty() {
            out.push_str("no log records retained\n");
        }
        out.push_str(&format!("filter: {}  next_seq: {}", v.filter, v.next_seq));
        out
    })
}

/// First 8 hex chars of a public key, for a compact fingerprint column.
fn fingerprint(key: &[u8]) -> String {
    key.iter().take(4).map(|b| format!("{b:02x}")).collect()
}
