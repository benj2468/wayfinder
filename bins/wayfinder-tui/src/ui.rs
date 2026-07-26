//! All ratatui rendering for the TUI, driven entirely by [`App`] state.

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    symbols::Marker,
    text::{Line, Span},
    widgets::{
        Axis, Block, Borders, Cell, Chart, Dataset, GraphType, Paragraph, Row, Table, Tabs, Wrap,
    },
};

use wayfinder_protos::wayfinder_v1alpha::LinkFeaturesEntry;

use crate::app::{App, Tab, format_id};

/// Accent colour used for headings and the active tab.
const ACCENT: Color = Color::Cyan;

/// Render the entire frame: tab bar, active view, and status bar.
pub fn render(frame: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // tab bar
            Constraint::Min(0),    // content
            Constraint::Length(1), // status bar
        ])
        .split(frame.area());

    render_tabs(frame, app, chunks[0]);
    match app.tab {
        Tab::Overview => render_overview(frame, app, chunks[1]),
        Tab::Routing => render_routing(frame, app, chunks[1]),
        Tab::LinkQuality => render_link_quality(frame, app, chunks[1]),
        Tab::Links => render_links(frame, app, chunks[1]),
        Tab::Metrics => render_metrics(frame, app, chunks[1]),
        Tab::Security => render_security(frame, app, chunks[1]),
    }
    render_status(frame, app, chunks[2]);

    // A confirmation popup (approve/deny) overlays everything else, drawn last so
    // it sits on top.
    if let Some(action) = app.confirm.clone() {
        render_confirm_popup(frame, &action, frame.area());
    }
}

/// Draw the modal approve/deny/revoke confirmation popup centred over the frame.
fn render_confirm_popup(frame: &mut Frame, action: &crate::app::OperatorAction, area: Rect) {
    use crate::app::OperatorAction;
    // (verb, subject phrase, target MAC, accent colour).
    let (verb, subject, mac, colour) = match action {
        OperatorAction::ApproveCsr(mac) => ("Approve", " the CSR from ", mac, Color::Green),
        OperatorAction::DenyCsr(mac) => ("Deny", " the CSR from ", mac, Color::Red),
        OperatorAction::RevokeNode(mac) => ("Revoke", " node ", mac, Color::Red),
    };

    // Centre a small fixed-size box within `area`.
    let popup = centered_rect(56, 7, area);
    // Clear whatever is underneath so the popup is opaque.
    frame.render_widget(ratatui::widgets::Clear, popup);

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(
                verb,
                Style::default().fg(colour).add_modifier(Modifier::BOLD),
            ),
            Span::raw(subject),
            Span::styled(
                format_id(mac),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw("?"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  y / Enter: confirm      n / Esc: cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colour))
            .title(" Confirm "),
    );
    frame.render_widget(para, popup);
}

/// A `Rect` of the given width/height centred within `area` (clamped to fit).
fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect {
        x,
        y,
        width: w,
        height: h,
    }
}

/// Draw the top tab bar.
fn render_tabs(frame: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .enumerate()
        .map(|(i, t)| Line::from(format!(" {}·{} ", i + 1, t.title())))
        .collect();
    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Wayfinder ".bold().fg(ACCENT)),
        )
        .select(app.tab.index())
        .highlight_style(Style::default().fg(Color::Black).bg(ACCENT).bold())
        .divider("|");
    frame.render_widget(tabs, area);
}

/// Draw the overview pane: node identity, capacity, and connection details.
fn render_overview(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    let (node_id, num_orig, locked) = match &app.snapshot.node_info {
        Some(info) => (
            format_id(&info.node_id),
            info.num_originators.to_string(),
            if info.auth_locked { "yes" } else { "no" }.to_string(),
        ),
        None => (
            "(waiting for data)".to_string(),
            "—".to_string(),
            "—".to_string(),
        ),
    };

    lines.push(field("Node ID", &node_id));
    lines.push(field("Originators", &num_orig));
    lines.push(field("Locked", &locked));
    lines.push(field(
        "Routing entries",
        &app.snapshot.routing.entries.len().to_string(),
    ));
    lines.push(field(
        "Link-quality rows",
        &app.snapshot.link_quality.entries.len().to_string(),
    ));
    let tp = &app.snapshot.throughput;
    lines.push(field(
        "Throughput ↓/↑",
        &format!(
            "{} / {}",
            fmt_rate(tp.total_rx_bps),
            fmt_rate(tp.total_tx_bps)
        ),
    ));
    lines.push(Line::from(""));
    lines.push(field("Server", &app.addr));
    lines.push(field("Transport", "TCP (length-delimited protobuf)"));
    lines.push(field("Refresh", &format!("{} ms", app.interval_ms)));
    lines.push(field(
        "Connection",
        if app.connected {
            "connected"
        } else {
            "connecting…"
        },
    ));

    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Node Overview "),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(para, area);
}

/// Build a `label: value` line with a dim label and bright value. Both
/// arguments are copied into owned spans, so the result is `'static`.
fn field(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{label:>18}: "),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            value.to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ])
}

/// Draw the routing table on the left and the selected entry's per-neighbor
/// path breakdown on the right.
fn render_routing(frame: &mut Frame, app: &mut App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    let header = Row::new(["Destination", "Next hop", "TQ", "Seqno", "Paths"])
        .style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = app
        .snapshot
        .routing
        .entries
        .iter()
        .map(|e| {
            Row::new(vec![
                Cell::from(format_id(&e.destination)),
                Cell::from(format_id(&e.next_hop)),
                Cell::from(Span::styled(e.tq.to_string(), tq_style(e.tq))),
                Cell::from(e.last_seqno.to_string()),
                Cell::from(e.paths.len().to_string()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Min(18),
            Constraint::Min(18),
            Constraint::Length(5),
            Constraint::Length(10),
            Constraint::Length(6),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(routing_title(app)),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::Blue)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");

    frame.render_stateful_widget(table, cols[0], &mut app.routing_state);
    render_path_detail(frame, app, cols[1]);
}

/// Title for the routing table, including a count.
fn routing_title(app: &App) -> String {
    format!(" Originators ({}) ", app.snapshot.routing.entries.len())
}

/// Draw the per-neighbor path breakdown for the currently selected originator.
fn render_path_detail(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" Paths ");

    let selected = app
        .routing_state
        .selected()
        .and_then(|i| app.snapshot.routing.entries.get(i));

    let lines: Vec<Line> = match selected {
        None => vec![Line::from(Span::styled(
            "Select an originator to inspect its paths.",
            Style::default().fg(Color::DarkGray),
        ))],
        Some(entry) => {
            let mut out = vec![
                field("Destination", &format_id(&entry.destination)),
                field("Best next hop", &format_id(&entry.next_hop)),
                field("Best TQ", &entry.tq.to_string()),
                Line::from(""),
                Line::from(Span::styled(
                    "Alternate paths (neighbor · TQ · seqno):",
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                )),
            ];
            if entry.paths.is_empty() {
                out.push(Line::from(Span::styled(
                    "  (none reported)",
                    Style::default().fg(Color::DarkGray),
                )));
            }
            for p in &entry.paths {
                out.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(format_id(&p.neighbor_id), Style::default().fg(Color::White)),
                    Span::raw("  "),
                    Span::styled(format!("tq {}", p.tq), tq_style(p.tq)),
                    Span::raw("  "),
                    Span::styled(
                        format!("seq {}", p.last_seqno),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]));
            }
            out.push(Line::from(""));
            out.extend(security_detail(app, &entry.destination));
            out
        }
    };

    let para = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    frame.render_widget(para, area);
}

/// Draw the link-quality table.
fn render_link_quality(frame: &mut Frame, app: &mut App, area: Rect) {
    let header = Row::new(["Neighbor", "Iface", "EWMA quality", "Samples"])
        .style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = app
        .snapshot
        .link_quality
        .entries
        .iter()
        .map(|e| {
            Row::new(vec![
                Cell::from(format_id(&e.neighbor_id)),
                Cell::from(e.iface_idx.to_string()),
                Cell::from(Span::styled(
                    format!("{} {}", e.ewma_quality, bar(e.ewma_quality)),
                    tq_style(e.ewma_quality),
                )),
                Cell::from(e.sample_count.to_string()),
            ])
        })
        .collect();

    let title = format!(
        " Link Quality ({}) ",
        app.snapshot.link_quality.entries.len()
    );
    let table = Table::new(
        rows,
        [
            Constraint::Min(18),
            Constraint::Length(6),
            Constraint::Min(16),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title))
    .row_highlight_style(
        Style::default()
            .bg(Color::Blue)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");

    frame.render_stateful_widget(table, area, &mut app.link_state);
}

/// Draw the Links tab: a compact per-interface table (live OGM interval plus
/// a derived on/off/mixed gate status) on the left, and the selected
/// interface's full OGM schedule and participation-feature breakdown on the
/// right. The four gates are editable in place — the `o`/`p`/`t`/`u` keys
/// shown inline queue a toggle via [`App::toggle_link_feature`].
fn render_links(frame: &mut Frame, app: &mut App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    let header = Row::new(["Iface", "Current", "Status"])
        .style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = app
        .snapshot
        .link_features
        .entries
        .iter()
        .map(|e| {
            let current = ogm_schedule_for(app, e.iface_idx)
                .map(|s| fmt_interval(s.current_interval_ms))
                .unwrap_or_else(|| "-".to_string());
            let (status, status_style) = link_feature_status(e);
            Row::new(vec![
                Cell::from(e.iface_idx.to_string()),
                Cell::from(current),
                Cell::from(Span::styled(status, status_style)),
            ])
        })
        .collect();

    let title = format!(" Links ({}) ", app.snapshot.link_features.entries.len());
    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Min(7),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title))
    .row_highlight_style(
        Style::default()
            .bg(Color::Blue)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");

    frame.render_stateful_widget(table, cols[0], &mut app.links_state);
    render_link_detail(frame, app, cols[1]);
}

/// The OGM schedule entry for `iface_idx`, if the snapshot has one. Zipped by
/// index rather than assumed positional, since the two tables come from
/// separate RPCs.
fn ogm_schedule_for(
    app: &App,
    iface_idx: u32,
) -> Option<&wayfinder_protos::wayfinder_v1alpha::OgmScheduleEntry> {
    app.snapshot
        .ogm_schedule
        .entries
        .iter()
        .find(|s| s.iface_idx == iface_idx)
}

/// Derive the on/off/mixed status label and colour for one interface's four
/// participation gates.
fn link_feature_status(e: &LinkFeaturesEntry) -> (&'static str, Style) {
    let all_on = e.tx_ogm && e.rx_ogm && e.tx_data && e.rx_data;
    let all_off = !e.tx_ogm && !e.rx_ogm && !e.tx_data && !e.rx_data;
    if all_on {
        ("on", Style::default().fg(Color::Green))
    } else if all_off {
        ("off", Style::default().fg(Color::Red))
    } else {
        ("mixed", Style::default().fg(Color::Yellow))
    }
}

/// Draw the selected interface's OGM schedule and participation-feature
/// breakdown, with inline `[key]` hints for the gate toggles `handle_key`
/// wires to `o`/`p`/`t`/`u`.
fn render_link_detail(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" Detail ");

    let selected = app
        .links_state
        .selected()
        .and_then(|i| app.snapshot.link_features.entries.get(i));

    let lines: Vec<Line> = match selected {
        None => vec![Line::from(Span::styled(
            "Select an interface to inspect and edit its features.",
            Style::default().fg(Color::DarkGray),
        ))],
        Some(entry) => {
            let mut out = vec![field("Interface", &entry.iface_idx.to_string())];
            if let Some(s) = ogm_schedule_for(app, entry.iface_idx) {
                out.push(field(
                    "Current interval",
                    &fmt_interval(s.current_interval_ms),
                ));
                out.push(field("Min interval", &fmt_interval(s.min_interval_ms)));
                out.push(field("Max interval", &fmt_interval(s.max_interval_ms)));
                out.push(Line::from(vec![
                    Span::styled(
                        format!("{:>18}: ", "Backoff"),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::raw(backoff_bar(
                        s.current_interval_ms,
                        s.min_interval_ms,
                        s.max_interval_ms,
                    )),
                ]));
            }
            out.push(Line::from(""));
            out.push(Line::from(Span::styled(
                "Participation features (keys toggle):",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            )));
            out.push(gate_line("o", "TX OGM", entry.tx_ogm));
            out.push(gate_line("p", "RX OGM", entry.rx_ogm));
            out.push(gate_line("t", "TX Data", entry.tx_data));
            out.push(gate_line("u", "RX Data", entry.rx_data));
            out.push(Line::from(""));
            out.push(field(
                "Keep-alive",
                &entry
                    .tx_keepalive_interval_ms
                    .map(|ms| format!("{ms} ms (edit via wayfinderctl)"))
                    .unwrap_or_else(|| "off".to_string()),
            ));
            out
        }
    };

    let para = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    frame.render_widget(para, area);
}

/// One `  [key] LABEL: yes/no` detail line for a participation gate,
/// colour-coded green/red.
fn gate_line(key: &str, label: &str, on: bool) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  [{key}] "), Style::default().fg(ACCENT)),
        Span::styled(
            format!("{label:<8}: "),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            if on { "yes" } else { "no" },
            Style::default()
                .fg(if on { Color::Green } else { Color::Red })
                .add_modifier(Modifier::BOLD),
        ),
    ])
}

/// Draw the Metrics view: a node-level summary panel (uptime, neighbours,
/// table occupancy, TQ / path-diversity distribution) above the per-interface
/// throughput table.  Together these are the signals an operator or an
/// application on top of the mesh uses to judge the health and shape of the
/// surrounding network.
fn render_metrics(frame: &mut Frame, app: &mut App, area: Rect) {
    // Size the per-interface and keep-alive tables to their rows (header +
    // borders + one line per entry, at least one body line) so the
    // throughput history chart gets all the remaining vertical space.
    let iface_rows = app.snapshot.throughput.interfaces.len().max(1) as u16;
    let table_height = iface_rows + 3;
    let ka_rows = app.snapshot.keepalive.entries.len().max(1) as u16;
    let ka_height = ka_rows + 3;

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(16),           // node metrics summary
            Constraint::Min(8),               // throughput history chart
            Constraint::Length(table_height), // per-interface throughput table
            Constraint::Length(ka_height),    // keep-alive liveness table
        ])
        .split(area);

    render_node_metrics(frame, app, rows[0]);
    render_throughput_chart(frame, app, rows[1]);
    render_throughput(frame, app, rows[2]);
    render_keepalive_table(frame, app, rows[3]);
}

/// Draw the per-neighbor keep-alive heartbeat liveness table: the direct-link
/// signal (see the root CLAUDE.md's Metrics section) that lets an operator
/// see a link degrade — still OGM-fresh via a relayed path, but its direct
/// heartbeat has lapsed — before it shows up only as a route switching away.
/// Read-only (no row selection): a glanceable status table, not one an
/// operator acts on a specific row of.
fn render_keepalive_table(frame: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(["Neighbor", "Since heard", "Interval", "Missed"])
        .style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = app
        .snapshot
        .keepalive
        .entries
        .iter()
        .map(|e| {
            let missed_style = if e.missed {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Green)
            };
            Row::new(vec![
                Cell::from(format_id(&e.neighbor_id)),
                Cell::from(fmt_interval(
                    e.ms_since_last_heard.min(u32::MAX as u64) as u32
                )),
                Cell::from(fmt_interval(
                    e.interval_estimate_ms.min(u32::MAX as u64) as u32
                )),
                Cell::from(Span::styled(
                    if e.missed { "yes" } else { "no" },
                    missed_style,
                )),
            ])
        })
        .collect();

    let title = format!(
        " Keep-Alive Liveness ({}) ",
        app.snapshot.keepalive.entries.len()
    );
    let table = Table::new(
        rows,
        [
            Constraint::Min(18),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(table, area);
}

/// Draw the node-wide throughput history as a two-line chart: one line for the
/// receive rate and one for the transmit rate, advancing one step per refresh.
/// This turns the instantaneous totals into a visible trend so an operator can
/// see bursts, ramps, and collapses in mesh traffic at a glance.
fn render_throughput_chart(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Throughput History ");

    let history = &app.throughput_history;
    // A line needs at least two points; until then show a placeholder.
    if history.len() < 2 {
        let para = Paragraph::new(Line::from(Span::styled(
            "Collecting throughput history…",
            Style::default().fg(Color::DarkGray),
        )))
        .block(block);
        frame.render_widget(para, area);
        return;
    }

    // x is the sample index (implicitly time, one step per refresh interval);
    // y is the rate in bytes/sec.
    let rx: Vec<(f64, f64)> = history
        .iter()
        .enumerate()
        .map(|(i, s)| (i as f64, s.rx_bps))
        .collect();
    let tx: Vec<(f64, f64)> = history
        .iter()
        .enumerate()
        .map(|(i, s)| (i as f64, s.tx_bps))
        .collect();

    let x_max = (history.len() - 1) as f64;
    // Scale the y-axis to the largest rate seen across both series, with a
    // little headroom, and never below 1 so an idle mesh still renders a flat
    // baseline rather than a degenerate zero-height axis.
    let peak = history
        .iter()
        .map(|s| s.rx_bps.max(s.tx_bps))
        .fold(0.0_f64, f64::max);
    let y_max = (peak * 1.15).max(1.0);

    // The x-axis spans the retained window; label its ends in seconds-ago so the
    // chart reads as a timeline at whatever refresh interval is in effect.
    let span_secs = x_max * app.interval_ms as f64 / 1000.0;

    let datasets = vec![
        Dataset::default()
            .name("RX")
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(Color::Green))
            .data(&rx),
        Dataset::default()
            .name("TX")
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(Color::Cyan))
            .data(&tx),
    ];

    let chart = Chart::new(datasets)
        .block(block)
        .x_axis(
            Axis::default()
                .style(Style::default().fg(Color::DarkGray))
                .bounds([0.0, x_max])
                .labels(vec![
                    Span::raw(format!("-{span_secs:.0}s")),
                    Span::raw("now"),
                ]),
        )
        .y_axis(
            Axis::default()
                .style(Style::default().fg(Color::DarkGray))
                .bounds([0.0, y_max])
                .labels(vec![
                    Span::raw("0"),
                    Span::raw(fmt_rate(y_max / 2.0)),
                    Span::raw(fmt_rate(y_max)),
                ]),
        );
    frame.render_widget(chart, area);
}

/// Draw the Security tab: the mesh authentication header above a per-originator
/// table (verified / cert expiry / revoked).
fn render_security(frame: &mut Frame, app: &mut App, area: Rect) {
    use crate::app::SecurityFocus;
    // A certificate-authority provider gets an extra panel listing the CSRs
    // awaiting its operator's approval, and can revoke originators; a non-provider
    // node omits the CSR panel and cannot revoke.
    let n_pending = app.snapshot.pending_csrs.as_ref().map(|p| p.pending.len());
    match n_pending {
        Some(n) => {
            let csr_focused = app.security_focus == SecurityFocus::PendingCsrs;
            // Size the CA panel to its rows (header + border), capped so a burst
            // of requests can't crowd out the originator table.
            let ca_height = (n as u16 + 3).clamp(4, 12);
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(7),         // mesh-level header
                    Constraint::Length(ca_height), // provider: pending CSRs
                    Constraint::Min(0),            // per-originator table
                ])
                .split(area);
            render_security_header(frame, app, rows[0]);
            render_pending_csrs(frame, app, rows[1], csr_focused);
            render_security_table(frame, app, rows[2], !csr_focused, true);
        }
        None => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(7), // mesh-level header
                    Constraint::Min(0),    // per-originator table
                ])
                .split(area);
            render_security_header(frame, app, rows[0]);
            // Non-provider: the originator table is the only (read-only) panel.
            render_security_table(frame, app, rows[1], false, false);
        }
    }
}

/// Border style marking whether a Security-tab panel currently holds navigation
/// focus (accent when focused, dim otherwise).
fn focus_border(focused: bool) -> Style {
    if focused {
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

/// The certificate-authority panel: CSRs awaiting this operator's approval.
/// Shown only when the connected node is a provider.  The selected row is
/// approved with `a` / denied with `d` (or from the CLI, `wayfinderctl csr
/// approve|deny --mac <mac>`).
fn render_pending_csrs(frame: &mut Frame, app: &mut App, area: Rect, focused: bool) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(focus_border(focused))
        .title(" Certificate Authority — pending CSRs  (a: approve, d: deny) ");

    let Some(pending) = app.snapshot.pending_csrs.as_ref() else {
        return;
    };
    if pending.pending.is_empty() {
        let para = Paragraph::new(Line::from(Span::styled(
            "(no CSRs awaiting approval)",
            Style::default().fg(Color::DarkGray),
        )))
        .block(block);
        frame.render_widget(para, area);
        return;
    }

    let header = Row::new(["Node", "Requested", "Ed25519", "X25519"])
        .style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD));
    let rows: Vec<Row> = pending
        .pending
        .iter()
        .map(|c| {
            Row::new(vec![
                Cell::from(format_id(&c.node_mac)),
                Cell::from(c.requested_at.to_string()),
                Cell::from(fingerprint(&c.ed_pubkey)),
                Cell::from(fingerprint(&c.x_pubkey)),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Min(12),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(block)
    .row_highlight_style(
        Style::default()
            .bg(Color::Blue)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");
    frame.render_stateful_widget(table, area, &mut app.csr_state);
}

/// First four bytes of a public key as hex — a compact fingerprint column.
fn fingerprint(key: &[u8]) -> String {
    key.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// The mesh-level crypto header: auth on/off, mesh id, this node's own cert and
/// expiry, and the number of revocations held.
fn render_security_header(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Mesh Security ");

    let lines: Vec<Line> = match &app.snapshot.security {
        None => vec![Line::from(Span::styled(
            "(waiting for data)",
            Style::default().fg(Color::DarkGray),
        ))],
        Some(s) if !s.auth_enabled => vec![field("Authentication", "disabled")],
        Some(s) => vec![
            field("Authentication", "enabled"),
            field("Mesh id", &format!("{:#x}", s.mesh_id)),
            field("This node", &format_id(&s.node_mac)),
            field("Own cert expires", &s.cert_not_after.to_string()),
            field("Revocations held", &s.revocation_count.to_string()),
        ],
    };

    let para = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    frame.render_widget(para, area);
}

/// The per-originator security table: identity, whether its OGM cert verified,
/// the cert expiry, and revocation status.
fn render_security_table(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    focused: bool,
    can_revoke: bool,
) {
    let header = Row::new(["Node", "Verified", "Expires", "Status"])
        .style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD));

    let nodes = app
        .snapshot
        .security
        .as_ref()
        .map(|s| s.nodes.as_slice())
        .unwrap_or(&[]);

    let rows: Vec<Row> = nodes
        .iter()
        .map(|n| {
            let (vtext, vstyle) = if n.verified {
                ("yes", Style::default().fg(Color::Green))
            } else {
                ("no", Style::default().fg(Color::Red))
            };
            let (stext, sstyle) = if n.revoked {
                (
                    "revoked",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )
            } else {
                ("active", Style::default().fg(Color::Green))
            };
            Row::new(vec![
                Cell::from(format_id(&n.node_id)),
                Cell::from(Span::styled(vtext, vstyle)),
                Cell::from(if n.verified {
                    n.cert_not_after.to_string()
                } else {
                    "—".to_string()
                }),
                Cell::from(Span::styled(stext, sstyle)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Min(12),
            Constraint::Length(10),
            Constraint::Length(14),
            Constraint::Min(8),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(focus_border(focused))
            // The revoke hint appears only on a provider, which can actually
            // sign and flood a revocation.
            .title(if can_revoke {
                " Originators  (x: revoke) "
            } else {
                " Originators "
            }),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::Blue)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");

    frame.render_stateful_widget(table, area, &mut app.security_state);
}

/// The security annotation for one originator, shown in the Routing tab's
/// per-endpoint detail: verified status, cert expiry, and revocation.
fn security_detail(app: &App, node_id: &[u8]) -> Vec<Line<'static>> {
    let header = Line::from(Span::styled(
        "Security:",
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
    ));
    let dim = |s: &str| {
        Line::from(Span::styled(
            format!("  {s}"),
            Style::default().fg(Color::DarkGray),
        ))
    };
    let body = match (&app.snapshot.security, app.snapshot.security_for(node_id)) {
        (None, _) => dim("(waiting for data)"),
        (Some(s), _) if !s.auth_enabled => dim("authentication disabled"),
        (Some(_), None) => dim("no certificate seen"),
        (Some(_), Some(n)) => {
            let mut spans = vec![
                Span::raw("  verified: "),
                if n.verified {
                    Span::styled("yes", Style::default().fg(Color::Green))
                } else {
                    Span::styled("no", Style::default().fg(Color::Red))
                },
            ];
            if n.verified {
                spans.push(Span::raw("  expires: "));
                spans.push(Span::raw(n.cert_not_after.to_string()));
            }
            if n.revoked {
                spans.push(Span::styled(
                    "  REVOKED",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ));
            }
            Line::from(spans)
        }
    };
    vec![header, body]
}

/// Draw the node-level metrics summary panel.
fn render_node_metrics(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Node Metrics ");

    let lines: Vec<Line> = match &app.snapshot.metrics {
        None => vec![Line::from(Span::styled(
            "(waiting for data)",
            Style::default().fg(Color::DarkGray),
        ))],
        Some(m) => {
            let occ = |o: &Option<wayfinder_protos::wayfinder_v1alpha::TableOccupancy>| match o {
                Some(t) => format!("{}/{}", t.used, t.capacity),
                None => "—".to_string(),
            };
            vec![
                field("Uptime", &fmt_uptime(m.uptime_secs)),
                field("Neighbors (1-hop)", &m.neighbor_count.to_string()),
                field("Originators (used/cap)", &occ(&m.originators)),
                field("Broadcast dedup", &occ(&m.broadcast_dedup)),
                field(
                    "Mcast groups / members",
                    &format!(
                        "{} / {}",
                        occ(&m.local_mcast_groups),
                        occ(&m.mcast_memberships)
                    ),
                ),
                field(
                    "TQ min/mean/max",
                    &format!("{} / {:.0} / {}", m.tq_min, m.tq_mean, m.tq_max),
                ),
                field(
                    "Paths mean/max",
                    &format!("{:.2} / {}", m.paths_mean, m.paths_max),
                ),
                field("Oversize drops", &m.oversize_drops.to_string()),
                field("Relay oversize drops", &m.relay_oversize_drops.to_string()),
                field("Cert store", &occ(&m.cert_store)),
                field("In-flight cert requests", &occ(&m.in_flight_cert_requests)),
                field("Pending cert replies", &occ(&m.pending_cert_replies)),
                field("Cert req rate", &format!("{:.2}/s", m.cert_req_rate)),
                field("Cert reply rate", &format!("{:.2}/s", m.cert_reply_rate)),
            ]
        }
    };

    let para = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    frame.render_widget(para, area);
}

/// Draw the per-interface throughput table: smoothed receive and transmit
/// rates (bytes/sec and frames/sec) for each interface, with the node-wide
/// totals in the block title so the whole-application throughput is visible
/// alongside the per-interface breakdown.
fn render_throughput(frame: &mut Frame, app: &mut App, area: Rect) {
    let header = Row::new(["Iface", "RX rate", "RX fps", "TX rate", "TX fps"])
        .style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = app
        .snapshot
        .throughput
        .interfaces
        .iter()
        .map(|e| {
            Row::new(vec![
                Cell::from(e.iface_idx.to_string()),
                Cell::from(Span::styled(
                    fmt_rate(e.rx_bps),
                    Style::default().fg(Color::Green),
                )),
                Cell::from(fmt_fps(e.rx_fps)),
                Cell::from(Span::styled(
                    fmt_rate(e.tx_bps),
                    Style::default().fg(Color::Cyan),
                )),
                Cell::from(fmt_fps(e.tx_fps)),
            ])
        })
        .collect();

    let tp = &app.snapshot.throughput;
    let title = format!(
        " Throughput — total ↓ {} ↑ {} ",
        fmt_rate(tp.total_rx_bps),
        fmt_rate(tp.total_tx_bps)
    );
    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Min(12),
            Constraint::Length(10),
            Constraint::Min(12),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title))
    .row_highlight_style(
        Style::default()
            .bg(Color::Blue)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");

    frame.render_stateful_widget(table, area, &mut app.metrics_state);
}

/// Render an uptime in seconds as a compact `d h m s` string, dropping
/// leading zero units so a fresh node reads as `42s` and a long-lived one as
/// `3d 4h`.
fn fmt_uptime(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m {s}s")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Render a byte-per-second rate as a compact human-readable string, scaling
/// through B/s, KiB/s, and MiB/s so both a near-idle LoRa link and a busy
/// Ethernet-carried link read clearly.
fn fmt_rate(bps: f64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    if bps < KIB {
        format!("{bps:.0} B/s")
    } else if bps < MIB {
        format!("{:.1} KiB/s", bps / KIB)
    } else {
        format!("{:.2} MiB/s", bps / MIB)
    }
}

/// Render a frames-per-second rate with adaptive precision: whole numbers once
/// past 10 fps, one decimal below that so slow links don't read as a flat 0.
fn fmt_fps(fps: f64) -> String {
    if fps >= 10.0 {
        format!("{fps:.0}/s")
    } else {
        format!("{fps:.1}/s")
    }
}

/// Render a millisecond interval as a compact human-readable string: sub-second
/// values in `ms`, everything else in seconds with one decimal.
fn fmt_interval(ms: u32) -> String {
    if ms < 1000 {
        format!("{ms} ms")
    } else {
        format!("{:.1} s", ms as f64 / 1000.0)
    }
}

/// A 10-cell bar placing `current` on the `[min, max]` scale: empty at the
/// aggressive floor, full at the quiet ceiling.  Visualises how far the Trickle
/// timer has backed off.  Degenerate (`min == max`) schedules render full.
fn backoff_bar(current: u32, min: u32, max: u32) -> String {
    let filled = if max <= min {
        10
    } else {
        let pos = current.saturating_sub(min) as u64 * 10 / (max - min) as u64;
        pos.min(10) as usize
    };
    let mut s = String::new();
    for i in 0..10 {
        s.push(if i < filled { '█' } else { '·' });
    }
    s
}

/// A small unicode bar visualising a 0–255 quality value.
fn bar(q: u32) -> String {
    let filled = (q.min(255) as usize * 10) / 255;
    let mut s = String::new();
    for i in 0..10 {
        s.push(if i < filled { '█' } else { '·' });
    }
    s
}

/// Colour a 0–255 TQ/quality value: green high, yellow mid, red low.
fn tq_style(q: u32) -> Style {
    let color = if q >= 170 {
        Color::Green
    } else if q >= 85 {
        Color::Yellow
    } else {
        Color::Red
    };
    Style::default().fg(color)
}

/// Draw the bottom status/help bar.
fn render_status(frame: &mut Frame, app: &App, area: Rect) {
    let mut spans = vec![
        Span::styled(" q ", Style::default().fg(Color::Black).bg(ACCENT)),
        Span::raw(" quit  "),
        Span::styled(" ←/→ ", Style::default().fg(Color::Black).bg(ACCENT)),
        Span::raw(" switch  "),
        Span::styled(" ↑/↓ ", Style::default().fg(Color::Black).bg(ACCENT)),
        Span::raw(" select  "),
        Span::styled(" r ", Style::default().fg(Color::Black).bg(ACCENT)),
        Span::raw(" refresh  "),
    ];

    // Links-tab gate toggles: applied immediately on keypress, no confirm step.
    if app.tab == Tab::Links {
        spans.push(Span::styled(
            " o/p/t/u ",
            Style::default().fg(Color::Black).bg(Color::Green),
        ));
        spans.push(Span::raw(" toggle gate  "));
    }

    // Security-tab operator actions (provider node only): approve/deny CSRs,
    // revoke originators, and Tab to switch which panel has focus.
    if app.tab == Tab::Security && app.snapshot.pending_csrs.is_some() {
        spans.push(Span::styled(
            " Tab ",
            Style::default().fg(Color::Black).bg(ACCENT),
        ));
        spans.push(Span::raw(" focus  "));
        spans.push(Span::styled(
            " a/d ",
            Style::default().fg(Color::Black).bg(Color::Green),
        ));
        spans.push(Span::raw(" appr/deny  "));
        spans.push(Span::styled(
            " x ",
            Style::default().fg(Color::Black).bg(Color::Red),
        ));
        spans.push(Span::raw(" revoke  "));
    }

    let status = match &app.last_error {
        Some(err) => Span::styled(
            format!("⚠ {err}"),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        None if app.connected => {
            Span::styled("● connected".to_string(), Style::default().fg(Color::Green))
        }
        None => Span::styled(
            "○ connecting…".to_string(),
            Style::default().fg(Color::Yellow),
        ),
    };
    spans.push(status);

    let para = Paragraph::new(Line::from(spans)).alignment(Alignment::Left);
    frame.render_widget(para, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Tab;
    use ratatui::{Terminal, backend::TestBackend};

    /// Render the Metrics tab through a real `TestBackend` so the chart's axis
    /// bounds, label vectors, and layout split are exercised end to end — both
    /// before any history exists (placeholder path) and once two-plus samples
    /// make the RX/TX lines drawable.
    #[test]
    fn metrics_tab_renders_chart_with_and_without_history() {
        let mut app = App::new("test".to_string(), 1000);
        app.tab = Tab::Metrics;

        let backend = TestBackend::new(80, 40);
        let mut terminal = Terminal::new(backend).expect("terminal");

        // Empty history: the placeholder branch must render without panicking.
        terminal
            .draw(|frame| render(frame, &mut app))
            .expect("draw empty");

        // Populate enough samples (including an all-idle pair) to force the
        // line-drawing path and the y-axis peak/headroom computation.
        for i in 0..5 {
            app.snapshot.throughput.total_rx_bps = (i * 100) as f64;
            app.snapshot.throughput.total_tx_bps = (i * 50) as f64;
            app.record_throughput();
        }
        terminal
            .draw(|frame| render(frame, &mut app))
            .expect("draw with history");

        // Populate node metrics so the node-metrics panel — including the new
        // oversize-drops row — renders its values, not the "no data" placeholder.
        app.snapshot.metrics = Some(wayfinder_protos::wayfinder_v1alpha::NodeMetrics {
            oversize_drops: 42,
            relay_oversize_drops: 17,
            cert_store: Some(wayfinder_protos::wayfinder_v1alpha::TableOccupancy {
                used: 5,
                capacity: 64,
            }),
            cert_req_rate: 0.5,
            cert_reply_rate: 1.5,
            ..Default::default()
        });
        app.snapshot.keepalive = wayfinder_protos::wayfinder_v1alpha::KeepAliveTable {
            entries: vec![wayfinder_protos::wayfinder_v1alpha::KeepAliveEntry {
                neighbor_id: vec![0, 0, 0, 0, 0, 2],
                ms_since_last_heard: 4200,
                interval_estimate_ms: 1000,
                missed: true,
            }],
        };
        terminal
            .draw(|frame| render(frame, &mut app))
            .expect("draw with metrics");
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(
            text.contains("Oversize drops"),
            "oversize-drops row missing"
        );
        assert!(text.contains("42"), "oversize-drops value missing");
        assert!(
            text.contains("Relay oversize drops"),
            "relay-oversize-drops row missing"
        );
        assert!(text.contains("17"), "relay-oversize-drops value missing");
        assert!(text.contains("Cert store"), "cert-store row missing");
        assert!(text.contains("5/64"), "cert-store occupancy value missing");
        assert!(text.contains("Cert req rate"), "cert-req-rate row missing");
        assert!(
            text.contains("Cert reply rate"),
            "cert-reply-rate row missing"
        );
        assert!(
            text.contains("Keep-Alive Liveness"),
            "keep-alive panel title missing"
        );
        assert!(text.contains("yes"), "missed keep-alive flag not rendered");
    }

    /// The Security tab shows the provider CSR panel only when the connected node
    /// is a certificate-authority provider (i.e. `pending_csrs` is `Some`), and
    /// lists each pending request there.
    #[test]
    fn security_tab_shows_pending_csrs_only_for_a_provider() {
        use wayfinder_protos::wayfinder_v1alpha::{
            GetSecurityStatusResponse, ListPendingCsrsResponse, PendingCsr,
        };

        let mut app = App::new("test".to_string(), 1000);
        app.tab = Tab::Security;
        app.snapshot.security = Some(GetSecurityStatusResponse {
            auth_enabled: true,
            mesh_id: 0xABCD,
            node_mac: vec![2, 0, 0, 0, 0, 1],
            ..Default::default()
        });

        let render_to_text = |app: &mut App| -> String {
            let backend = TestBackend::new(100, 30);
            let mut terminal = Terminal::new(backend).expect("terminal");
            terminal.draw(|frame| render(frame, app)).expect("draw");
            terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|cell| cell.symbol())
                .collect()
        };

        // Non-provider node: no CA panel.
        app.snapshot.pending_csrs = None;
        assert!(!render_to_text(&mut app).contains("pending CSRs"));

        // Provider node with one waiting CSR: the panel appears and lists it.
        app.snapshot.pending_csrs = Some(ListPendingCsrsResponse {
            pending: vec![PendingCsr {
                node_mac: vec![2, 0, 0, 0, 0, 9],
                ed_pubkey: vec![0xab; 32],
                x_pubkey: vec![0xcd; 32],
                requested_at: 1234,
            }],
        });
        let text = render_to_text(&mut app);
        assert!(text.contains("pending CSRs"), "CA panel missing");
        assert!(text.contains("02:00:00:00:00:09"), "pending MAC missing");

        // Staging an approve opens the modal confirmation popup over the tab.
        app.tab = Tab::Security;
        app.csr_state.select(Some(0)); // a selection is required to act
        app.request_csr_action(true);
        let text = render_to_text(&mut app);
        assert!(text.contains("Confirm"), "confirmation popup missing");
        assert!(
            text.contains("Approve the CSR from"),
            "popup prompt missing"
        );
        assert!(
            text.contains("02:00:00:00:00:09"),
            "popup target MAC missing"
        );
    }

    /// On a provider the originator panel offers a revoke action, and staging one
    /// opens the revoke confirmation popup.
    #[test]
    fn security_tab_offers_revoke_for_a_provider() {
        use crate::app::SecurityFocus;
        use wayfinder_protos::wayfinder_v1alpha::{
            GetSecurityStatusResponse, ListPendingCsrsResponse, NodeSecurity,
        };

        let mut app = App::new("test".to_string(), 1000);
        app.tab = Tab::Security;
        app.snapshot.pending_csrs = Some(ListPendingCsrsResponse::default());
        app.snapshot.security = Some(GetSecurityStatusResponse {
            auth_enabled: true,
            nodes: vec![NodeSecurity {
                node_id: vec![2, 0, 0, 0, 0, 7],
                verified: true,
                ..Default::default()
            }],
            ..Default::default()
        });

        let render_to_text = |app: &mut App| -> String {
            let backend = TestBackend::new(100, 30);
            let mut terminal = Terminal::new(backend).expect("terminal");
            terminal.draw(|frame| render(frame, app)).expect("draw");
            terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|cell| cell.symbol())
                .collect()
        };

        // The originator panel advertises the revoke key.
        assert!(
            render_to_text(&mut app).contains("x: revoke"),
            "revoke hint missing"
        );

        // Focus the originator panel, select a node, and stage a revoke.
        app.security_focus = SecurityFocus::Originators;
        app.security_state.select(Some(0));
        app.request_revoke();
        let text = render_to_text(&mut app);
        assert!(text.contains("Confirm"), "revoke popup missing");
        assert!(text.contains("Revoke node"), "revoke prompt missing");
        assert!(
            text.contains("02:00:00:00:00:07"),
            "revoke target MAC missing"
        );
    }

    /// The Links tab renders the merged OGM-schedule + participation-feature
    /// view: the list shows the derived on/off/mixed status, and the detail
    /// panel for the selected interface shows the OGM interval, each gate's
    /// yes/no state with its toggle-key hint, and the keep-alive cadence.
    #[test]
    fn links_tab_shows_schedule_and_feature_detail_for_selected_interface() {
        use wayfinder_protos::wayfinder_v1alpha::{
            LinkFeaturesEntry, LinkFeaturesTable, OgmSchedule, OgmScheduleEntry,
        };

        let mut app = App::new("test".to_string(), 1000);
        app.tab = Tab::Links;
        app.snapshot.link_features = LinkFeaturesTable {
            entries: vec![LinkFeaturesEntry {
                iface_idx: 3,
                tx_ogm: true,
                rx_ogm: false,
                tx_data: true,
                rx_data: true,
                tx_keepalive_interval_ms: Some(2000),
            }],
        };
        app.snapshot.ogm_schedule = OgmSchedule {
            entries: vec![OgmScheduleEntry {
                iface_idx: 3,
                current_interval_ms: 4000,
                min_interval_ms: 1000,
                max_interval_ms: 64000,
            }],
        };
        app.links_state.select(Some(0));

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| render(frame, &mut app))
            .expect("draw");
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect();

        assert!(text.contains("mixed"), "derived status missing: {text}");
        assert!(
            text.contains("4.0 s"),
            "current OGM interval missing: {text}"
        );
        assert!(text.contains("[o]"), "tx_ogm key hint missing: {text}");
        assert!(text.contains("[p]"), "rx_ogm key hint missing: {text}");
        assert!(text.contains("[t]"), "tx_data key hint missing: {text}");
        assert!(text.contains("[u]"), "rx_data key hint missing: {text}");
        assert!(
            text.contains("2000 ms"),
            "keep-alive cadence missing: {text}"
        );
    }
}
