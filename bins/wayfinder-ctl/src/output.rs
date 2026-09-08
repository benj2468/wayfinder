//! Rendering of management-API responses as either human-readable text or JSON.
//!
//! Each renderer returns a `String` (rather than printing) so it is unit-
//! testable. JSON is produced by `serde_json` over the proto types, which derive
//! `serde::Serialize` via the `wayfinder-protos` `serde` feature.

use clap::ValueEnum;
use serde::Serialize;
use wayfinder_protos::wayfinder::v1alpha::ClockPosture;
use wayfinder_protos::wayfinder::v1alpha::GetSecurityStatusResponse;
use wayfinder_protos::wayfinder::v1alpha::IssuedCert;
use wayfinder_protos::wayfinder::v1alpha::KeepAliveTable;
use wayfinder_protos::wayfinder::v1alpha::LinkFeaturesTable;
use wayfinder_protos::wayfinder::v1alpha::LinkQualityTable;
use wayfinder_protos::wayfinder::v1alpha::ListCertsResponse;
use wayfinder_protos::wayfinder::v1alpha::ListPendingCsrsResponse;
use wayfinder_protos::wayfinder::v1alpha::ListVpnPeersResponse;
use wayfinder_protos::wayfinder::v1alpha::LogLevel;
use wayfinder_protos::wayfinder::v1alpha::LogRecords;
use wayfinder_protos::wayfinder::v1alpha::NodeInfo;
use wayfinder_protos::wayfinder::v1alpha::NodeMetrics;
use wayfinder_protos::wayfinder::v1alpha::NodeSecurity;
use wayfinder_protos::wayfinder::v1alpha::OgmSchedule;
use wayfinder_protos::wayfinder::v1alpha::PingProbe;
use wayfinder_protos::wayfinder::v1alpha::PingProbeState;
use wayfinder_protos::wayfinder::v1alpha::PingSession;
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
/// this one: the index is what an operator types into `link enable`/`link
/// trickle`,
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

/// Render a wall-clock instant (unix seconds) as an ISO 8601 UTC stamp:
/// `2023-11-14T22:13:20Z`.
///
/// Human output is read by a person, and unix seconds are not: every expiry
/// column in this client used to need a `date -d @…` to answer "is that soon?".
/// JSON keeps the raw number, so a script is not made to parse a date back out
/// of text.
///
/// Zero is `-` rather than 1970. Zero means "not recorded" across this API
/// (`cert_not_after` on an unverified node, a peer never seen), and a
/// real-looking date is the worst way to render an absent one.
///
/// Hand-rolled rather than pulling `chrono`/`time` in for one conversion,
/// matching `wayfinder-server`'s `format_rfc3339`. Civil-date arithmetic from
/// Howard Hinnant's `civil_from_days`, which is exact over the whole range.
pub fn format_timestamp(unix_secs: u64) -> String {
    if unix_secs == 0 {
        return "-".to_string();
    }
    let secs_of_day = unix_secs % 86_400;
    let z = (unix_secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// Render [`NodeInfo`].
pub fn node_info(v: &NodeInfo, fmt: OutputFormat) -> anyhow::Result<String> {
    render(v, fmt, |v| {
        format!(
            "node {}\noriginators: {}\nlocked: {}\nruntime config: {}\nclock: {}\n\
             cert windows: {}",
            format_mac(&v.node_id),
            v.num_originators,
            if v.auth_locked { "yes" } else { "no" },
            if v.runtime_config_active { "yes" } else { "no" },
            if v.clock_trusted {
                "trusted"
            } else {
                "NOT SYNCHRONIZED (credential operations refused)"
            },
            // A different question from the line above — "will this node act
            // on a credential" versus "which validity windows does its router
            // judge" — and the two come apart in both directions. `none` is
            // the one an operator must be able to see: the node routes and
            // verifies every signature while enforcing no expiry at all
            // (design 20 §7).
            match ClockPosture::try_from(v.clock_posture) {
                Ok(ClockPosture::At) => "both ends",
                Ok(ClockPosture::AtLeast) => "expiry only (free-running from an anchor)",
                Ok(ClockPosture::Unknown) => "NONE (no anchor; expiry not enforced here)",
                // A node too old to report it, not a fourth state.
                Ok(ClockPosture::Unspecified) | Err(_) => "not reported",
            }
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
/// mixed) so an operator can confirm a `link enable`/`link disable` took
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
             cert_req_rate: {:.2}\ncert_reply_rate: {:.2}\n\
             untaggable_drop_rate: {:.2}\n\
             seqno_resyncs: {}\nogm_refloods_suppressed: {}\nproofs_swept: {}",
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
            v.untaggable_drop_rate,
            v.seqno_resyncs,
            v.ogm_refloods_suppressed,
            v.proofs_swept,
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

/// One resolved probe, as `ping(8)` would print it.
///
/// Only ever called for a probe that has stopped being pending, so the two
/// arms below cover everything an operator can see; a still-pending row has no
/// line yet, which is what makes the streaming output append-only.
pub fn ping_probe(probe: &PingProbe, destination: &str, payload_bytes: u32) -> String {
    match probe.state() {
        PingProbeState::Replied => format!(
            "{payload_bytes} bytes from {destination}: seq={} hops={}/{} time={}",
            probe.seqno,
            probe.forward_hops,
            probe.return_hops,
            format_rtt(probe.rtt_us),
        ),
        PingProbeState::NoRoute => {
            format!("no route to {destination}: seq={}", probe.seqno)
        }
        // A timeout, and anything a newer node might report that this build
        // does not know: both mean "no answer", which is the honest thing to
        // print rather than dropping the row.
        _ => format!("no answer from {destination}: seq={}", probe.seqno),
    }
}

/// A round trip in milliseconds, at the precision the number deserves.
///
/// Sub-millisecond round trips are real on a local link and would all render
/// as `0.0 ms`, which reads as a broken measurement rather than a fast one.
fn format_rtt(rtt_us: u32) -> String {
    let ms = f64::from(rtt_us) / 1000.0;
    if ms < 1.0 {
        format!("{ms:.3} ms")
    } else {
        format!("{ms:.1} ms")
    }
}

/// Render a whole [`PingSession`] the way `ping` signs off: the per-probe lines,
/// then the statistics block.
pub fn ping(v: &PingSession, fmt: OutputFormat) -> anyhow::Result<String> {
    render(v, fmt, |v| {
        let destination = format_mac(&v.destination);
        let mut out = String::new();
        for probe in &v.probes {
            if probe.state() == PingProbeState::Pending {
                continue;
            }
            out.push_str(&ping_probe(probe, &destination, v.payload_bytes));
            out.push('\n');
        }
        out.push_str(&ping_summary(v));
        out
    })
}

/// The statistics block `ping` prints when it stops.
///
/// The RTT line is omitted entirely when nothing was answered, rather than
/// printed as zeros: `0.0/0.0/0.0` is a measurement, and "we measured nothing"
/// is not one.
pub fn ping_summary(v: &PingSession) -> String {
    let destination = format_mac(&v.destination);
    let loss = if v.sent == 0 {
        0.0
    } else {
        f64::from(v.lost) * 100.0 / f64::from(v.sent)
    };
    let mut out = format!(
        "\n--- {destination} ping statistics ---\n\
         {} probes attempted, {} received, {loss:.0}% loss",
        v.sent, v.received,
    );
    if v.received > 0 {
        out.push_str(&format!(
            "\nrtt min/avg/max/mdev = {}/{}/{}/{}",
            format_rtt(v.rtt_min_us),
            format_rtt(v.rtt_avg_us),
            format_rtt(v.rtt_max_us),
            format_rtt(v.rtt_mdev_us),
        ));
    }
    out
}

/// The banner `ping` opens with, before any probe has resolved.
pub fn ping_banner(destination: &[u8], payload_bytes: u32, count: u32) -> String {
    format!(
        "PING {} ({payload_bytes} data bytes, {count} probes)",
        format_mac(destination)
    )
}

/// Render a [`GetSecurityStatusResponse`]: the mesh header then a per-originator
/// table (NODE / VERIFIED / EXPIRES / STATUS).
pub fn security(v: &GetSecurityStatusResponse, fmt: OutputFormat) -> anyhow::Result<String> {
    render(v, fmt, |v| {
        if !v.auth_enabled {
            return "authentication: disabled".to_string();
        }
        let mut out = format!(
            "authentication: enabled\nmesh_id: {:#x}\nnode: {}\nown cert expires: {}\nrenews against: {}\nrevocations: {}",
            v.mesh_id,
            format_mac(&v.node_mac),
            format_timestamp(v.cert_not_after),
            // Both answers are worth a line. Renewal is unattended, so a node
            // that will do nothing when this certificate expires is something an
            // operator learns here or by losing the node off the mesh.
            match v.renewal_provider.as_ref() {
                Some(p) => p.address.clone(),
                None => "not set (renew by hand)".to_string(),
            },
            v.revocation_count,
        );
        if v.nodes.is_empty() {
            out.push_str("\n\nno originators known");
            return out;
        }
        out.push_str("\n\nNODE               VERIFIED  EXPIRES               STATUS");
        for n in &v.nodes {
            out.push_str(&format!(
                "\n{:<18} {:<9} {:<21} {}",
                format_mac(&n.node_id),
                if n.verified { "yes" } else { "no" },
                format_timestamp(if n.verified { n.cert_not_after } else { 0 }),
                revocation_status(n),
            ));
        }
        out
    })
}

/// The STATUS cell for one originator: `active`, or `revoked` with the instant
/// the revocation stops being enforced.
///
/// The date rides in this cell rather than a column of its own because it is
/// meaningful on revoked rows only, and it is worth carrying: it is when this
/// node drops the record — and so when the row stops reading as revoked and
/// disappears — which is otherwise unanswerable from the outside. A revocation
/// with no window is spelled plainly rather than dated to 1970.
fn revocation_status(n: &NodeSecurity) -> String {
    match (n.revoked, n.revocation_not_after) {
        (false, _) => "active".to_string(),
        (true, 0) => "revoked".to_string(),
        (true, until) => format!("revoked until {}", format_timestamp(until)),
    }
}

/// Render the provider's [`ListVpnPeersResponse`] (registered VPN peers).
///
/// A peer whose hostname is not one wayfinder registered shows its raw hostname
/// in the MAC column rather than being hidden: it is still a peer with tunnel
/// reachability, and an operator auditing who can reach the network needs to
/// see it precisely *because* it does not correspond to an enrolled node.
pub fn vpn_peers(v: &ListVpnPeersResponse, fmt: OutputFormat) -> anyhow::Result<String> {
    render(v, fmt, |v| {
        if v.peers.is_empty() {
            return "no VPN peers registered".to_string();
        }
        let mut out = String::from(
            "NODE               ADDRESS          STATE    LAST_SEEN             KEY_EXPIRY",
        );
        for p in &v.peers {
            out.push_str(&format!(
                "\n{:<18} {:<16} {:<8} {:<21} {}",
                if p.node_mac.is_empty() {
                    format!("({})", p.raw_hostname)
                } else {
                    format_mac(&p.node_mac)
                },
                p.tailscale_ip,
                if p.online { "online" } else { "offline" },
                // Signed on the wire, and Headscale reports an unknown
                // instant as an epoch-or-earlier value rather than exactly
                // zero, so anything not in the future of 1970 is "no date".
                if p.last_seen_unix <= 0 {
                    "never".to_string()
                } else {
                    format_timestamp(p.last_seen_unix as u64)
                },
                format_timestamp(p.key_expiry_unix.max(0) as u64),
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
        // Header built through the same widths as the rows below, rather than
        // hand-spaced: an ISO stamp is wide enough that the two drifted apart
        // the moment the columns changed.
        let mut out = format!(
            "{:<18} {:<21} {:<21} {:<7}  {:<13}  {}",
            "NODE_MAC", "NOT_BEFORE", "NOT_AFTER", "STATUS", "KIND", "ED25519",
        );
        for c in &v.certs {
            out.push_str(&format!(
                "\n{:<18} {:<21} {:<21} {:<7}  {:<13}  {}",
                format_mac(&c.node_mac),
                format_timestamp(c.not_before),
                format_timestamp(c.not_after),
                if c.revoked { "revoked" } else { "active" },
                cert_kind(c),
                fingerprint(&c.ed_pubkey),
            ));
        }
        out
    })
}

/// A one-word description of what an issued certificate *is*, for the KIND
/// column.
///
/// Both a person's session and a device's membership bind to a MAC, so without
/// this the two are indistinguishable in the list — which is the whole reason
/// `CERT_FLAG_USER` exists. The capability is folded in on the same line
/// because "user" and "admin" are the two facts an operator scanning this
/// column is looking for, and a second column for one bit would read worse.
fn cert_kind(c: &IssuedCert) -> &'static str {
    match (c.user, c.admin, c.viewer) {
        (true, true, _) => "user/admin",
        (true, _, true) => "user/viewer",
        (true, _, _) => "user",
        (false, true, _) => "device/admin",
        (false, _, true) => "device/viewer",
        (false, _, _) => "device",
    }
}

/// Render the provider's [`ListPendingCsrsResponse`] (CSRs awaiting approval).
pub fn list_pending_csrs(v: &ListPendingCsrsResponse, fmt: OutputFormat) -> anyhow::Result<String> {
    render(v, fmt, |v| {
        if v.pending.is_empty() {
            return "no pending CSRs".to_string();
        }
        let mut out = String::from("NODE_MAC           REQUESTED_AT          ED25519    X25519");
        for c in &v.pending {
            out.push_str(&format!(
                "\n{:<18} {:<21} {:<9}  {}",
                format_mac(&c.node_mac),
                format_timestamp(c.requested_at),
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

#[cfg(test)]
mod tests {
    use super::*;
    use wayfinder_protos::wayfinder::v1alpha::PendingCsr;
    use wayfinder_protos::wayfinder::v1alpha::VpnPeerStatus;

    /// 2023-11-14 22:13:20 UTC, the instant every date test below is anchored
    /// to.
    const T: u64 = 1_700_000_000;
    const T_ISO: &str = "2023-11-14T22:13:20Z";

    /// A wall-clock instant renders as an ISO 8601 UTC stamp, not the unix
    /// seconds an operator would otherwise have to pipe through `date -d @`.
    #[test]
    fn timestamp_renders_iso_8601_utc() {
        assert_eq!(format_timestamp(T), T_ISO);
    }

    /// Zero means "not recorded" across this API, so it must not render as a
    /// real-looking 1970 date in an expiry column.
    #[test]
    fn timestamp_of_zero_reads_as_unset() {
        assert_eq!(format_timestamp(0), "-");
    }

    /// The case a hand-rolled civil calendar gets wrong.
    #[test]
    fn timestamp_handles_a_leap_day() {
        assert_eq!(format_timestamp(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    /// The security view dates its own certificate and each verified
    /// originator's in ISO, and carries no bare unix seconds.
    #[test]
    fn security_renders_iso_dates() {
        let v = GetSecurityStatusResponse {
            auth_enabled: true,
            mesh_id: 0xABCD,
            node_mac: vec![0, 0, 0, 0, 0, 1],
            cert_not_after: T,
            revocation_count: 0,
            nodes: vec![NodeSecurity {
                node_id: vec![0, 0, 0, 0, 0, 2],
                verified: true,
                cert_not_after: T,
                revoked: false,
                revocation_not_after: 0,
            }],
            ..Default::default()
        };
        let out = security(&v, OutputFormat::Human).unwrap();
        assert!(out.contains(&format!("own cert expires: {T_ISO}")), "{out}");
        assert!(out.contains(T_ISO), "{out}");
        assert!(
            !out.contains(&T.to_string()),
            "raw unix seconds left in: {out}"
        );
    }

    /// A revoked originator shows *until when* the revocation is enforced —
    /// the answer to "how long will this row keep saying revoked?", which was
    /// otherwise not on the wire at all.
    #[test]
    fn security_dates_a_revocation_enforcement_window() {
        let v = GetSecurityStatusResponse {
            auth_enabled: true,
            mesh_id: 0xABCD,
            node_mac: vec![0, 0, 0, 0, 0, 1],
            cert_not_after: 0,
            revocation_count: 1,
            nodes: vec![NodeSecurity {
                node_id: vec![0, 0, 0, 0, 0, 3],
                // A revocation evicts the neighbor entry that carries the
                // cert, so a revoked row is never also a verified one.
                verified: false,
                cert_not_after: 0,
                revoked: true,
                revocation_not_after: T,
            }],
            ..Default::default()
        };
        let out = security(&v, OutputFormat::Human).unwrap();
        assert!(out.contains("revoked"), "{out}");
        assert!(out.contains(T_ISO), "{out}");
    }

    /// The issued-certificate list dates both ends of the validity window.
    #[test]
    fn list_certs_renders_iso_dates() {
        let v = ListCertsResponse {
            certs: vec![IssuedCert {
                node_mac: vec![0, 0, 0, 0, 0, 2],
                ed_pubkey: vec![0xab; 32],
                not_before: T,
                not_after: T + 86_400,
                revoked: false,
                user: false,
                admin: false,
                viewer: false,
            }],
        };
        let out = list_certs(&v, OutputFormat::Human).unwrap();
        assert!(out.contains(T_ISO), "{out}");
        assert!(out.contains("2023-11-15T22:13:20Z"), "{out}");
        assert!(
            !out.contains(&T.to_string()),
            "raw unix seconds left in: {out}"
        );
    }

    /// A pending CSR dates when it was submitted.
    #[test]
    fn list_pending_csrs_renders_an_iso_date() {
        let v = ListPendingCsrsResponse {
            pending: vec![PendingCsr {
                node_mac: vec![0, 0, 0, 0, 0, 2],
                ed_pubkey: vec![0xab; 32],
                x_pubkey: vec![0xcd; 32],
                requested_at: T,
            }],
        };
        let out = list_pending_csrs(&v, OutputFormat::Human).unwrap();
        assert!(out.contains(T_ISO), "{out}");
    }

    /// VPN peers date last-seen and key expiry, keeping the "never"/"-"
    /// wording for a peer that has neither.
    #[test]
    fn vpn_peers_renders_iso_dates() {
        let v = ListVpnPeersResponse {
            peers: vec![
                VpnPeerStatus {
                    node_mac: vec![0, 0, 0, 0, 0, 2],
                    raw_hostname: "node-2".to_string(),
                    tailscale_ip: "100.64.0.2".to_string(),
                    online: true,
                    last_seen_unix: T as i64,
                    key_expiry_unix: T as i64,
                },
                VpnPeerStatus {
                    node_mac: vec![0, 0, 0, 0, 0, 3],
                    raw_hostname: "node-3".to_string(),
                    tailscale_ip: "100.64.0.3".to_string(),
                    online: false,
                    last_seen_unix: 0,
                    key_expiry_unix: 0,
                },
            ],
        };
        let out = vpn_peers(&v, OutputFormat::Human).unwrap();
        assert!(out.contains(T_ISO), "{out}");
        assert!(out.contains("never"), "{out}");
        assert!(
            !out.contains(&T.to_string()),
            "raw unix seconds left in: {out}"
        );
    }

    /// JSON is the machine-readable half and must keep the raw unix seconds:
    /// re-spelling them as text would force a script to parse a date back out.
    #[test]
    fn json_keeps_raw_unix_seconds() {
        let v = GetSecurityStatusResponse {
            auth_enabled: true,
            cert_not_after: T,
            ..Default::default()
        };
        let out = security(&v, OutputFormat::Json).unwrap();
        assert!(out.contains(&T.to_string()), "{out}");
    }
}

#[cfg(test)]
mod ping_tests {
    use super::*;

    fn probe(seqno: u32, state: PingProbeState, rtt_us: u32) -> PingProbe {
        PingProbe {
            seqno,
            state: state as i32,
            rtt_us,
            forward_hops: 2,
            return_hops: 3,
        }
    }

    fn session(probes: Vec<PingProbe>, sent: u32, received: u32, lost: u32) -> PingSession {
        PingSession {
            session_seq: 1,
            destination: vec![0, 0, 0, 0, 0, 9],
            active: false,
            requested: sent,
            sent,
            received,
            lost,
            rtt_min_us: 10_000,
            rtt_avg_us: 12_000,
            rtt_max_us: 15_000,
            rtt_mdev_us: 2_000,
            payload_bytes: 16,
            probes,
        }
    }

    /// A replied probe reports both legs of the path separately, because they
    /// are routinely different lengths on a mesh.
    #[test]
    fn a_replied_probe_reports_both_path_lengths() {
        let line = ping_probe(
            &probe(0, PingProbeState::Replied, 12_400),
            "00:00:00:00:00:09",
            16,
        );
        assert_eq!(
            line,
            "16 bytes from 00:00:00:00:00:09: seq=0 hops=2/3 time=12.4 ms"
        );
    }

    /// A sub-millisecond round trip is a real measurement on a local link, and
    /// must not round to `0.0 ms` — which reads as broken rather than fast.
    #[test]
    fn a_sub_millisecond_round_trip_keeps_its_precision() {
        let line = ping_probe(&probe(0, PingProbeState::Replied, 420), "peer", 16);
        assert!(line.ends_with("time=0.420 ms"), "got: {line}");
    }

    /// "I could not try" and "I tried and heard nothing" are different answers
    /// and an operator acts on them differently, so they print differently.
    #[test]
    fn an_unreachable_target_reads_differently_from_a_silent_one() {
        let no_route = ping_probe(&probe(1, PingProbeState::NoRoute, 0), "peer", 16);
        let timed_out = ping_probe(&probe(2, PingProbeState::TimedOut, 0), "peer", 16);
        assert_eq!(no_route, "no route to peer: seq=1");
        assert_eq!(timed_out, "no answer from peer: seq=2");
        assert_ne!(no_route, timed_out);
    }

    /// The statistics block, and the case that makes the loss arithmetic worth
    /// testing: partial loss over a session where not every probe came back.
    #[test]
    fn the_summary_reports_loss_and_the_rtt_spread() {
        let s = session(vec![], 4, 3, 1);
        let out = ping_summary(&s);
        assert!(
            out.contains("4 probes attempted, 3 received, 25% loss"),
            "got: {out}"
        );
        assert!(
            out.contains("rtt min/avg/max/mdev = 10.0 ms/12.0 ms/15.0 ms/2.0 ms"),
            "got: {out}"
        );
    }

    /// With nothing answered there is no RTT line at all. Printing
    /// `0.0/0.0/0.0` would be reporting a measurement that was never taken.
    #[test]
    fn a_session_with_no_replies_prints_no_rtt_line() {
        let mut s = session(vec![], 3, 0, 3);
        s.rtt_min_us = 0;
        s.rtt_avg_us = 0;
        s.rtt_max_us = 0;
        s.rtt_mdev_us = 0;
        let out = ping_summary(&s);
        assert!(out.contains("3 probes attempted, 0 received, 100% loss"));
        assert!(!out.contains("rtt min/avg/max"), "got: {out}");
    }

    /// A probe still in flight has no line yet — which is what lets the
    /// streaming output be append-only rather than redrawn.
    #[test]
    fn a_pending_probe_contributes_no_line() {
        let s = session(
            vec![
                probe(0, PingProbeState::Replied, 12_000),
                probe(1, PingProbeState::Pending, 0),
            ],
            2,
            1,
            0,
        );
        let out = ping(&s, OutputFormat::Human).unwrap();
        assert!(out.contains("seq=0"), "got: {out}");
        assert!(!out.contains("seq=1"), "got: {out}");
    }
}
