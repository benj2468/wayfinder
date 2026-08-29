//! All ratatui rendering for the TUI, driven entirely by [`App`] state.

use ratatui::Frame;
use ratatui::layout::Alignment;
use ratatui::layout::Constraint;
use ratatui::layout::Direction;
use ratatui::layout::Layout;
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::style::Modifier;
use ratatui::style::Style;
use ratatui::style::Stylize;
use ratatui::symbols::Marker;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Axis;
use ratatui::widgets::Block;
use ratatui::widgets::Borders;
use ratatui::widgets::Cell;
use ratatui::widgets::Chart;
use ratatui::widgets::Dataset;
use ratatui::widgets::GraphType;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Row;
use ratatui::widgets::Table;
use ratatui::widgets::Tabs;
use ratatui::widgets::Wrap;

use wayfinder_protos::wayfinder::v1alpha::Alarm;
use wayfinder_protos::wayfinder::v1alpha::AlarmKind;
use wayfinder_protos::wayfinder::v1alpha::AlarmSeverity;
use wayfinder_protos::wayfinder::v1alpha::Alarms;
use wayfinder_protos::wayfinder::v1alpha::LinkFeaturesEntry;
use wayfinder_protos::wayfinder::v1alpha::LogLevel;
use wayfinder_protos::wayfinder::v1alpha::PingProbe;
use wayfinder_protos::wayfinder::v1alpha::PingProbeState;
use wayfinder_protos::wayfinder::v1alpha::PingSession;
use wayfinder_protos::wayfinder::v1alpha::alarm::Subject as AlarmSubject;

use std::collections::VecDeque;

use crate::app::App;
use crate::app::LogEntry;
use crate::app::Tab;
use crate::app::ThroughputSample;
use crate::app::format_id;
use crate::app::now_ms;

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
        Tab::Logs => render_logs(frame, app, chunks[1]),
    }
    render_status(frame, app, chunks[2]);

    // A confirmation popup (approve/deny) overlays everything else, drawn last so
    // it sits on top.
    if let Some(action) = app.confirm.clone() {
        render_confirm_popup(frame, &action, frame.area());
    }
}

/// The colour a record's level is rendered in.
///
/// Warm for the things that need acting on and cold for the routine, so the
/// shape of a screenful reads before any of the words do: red and yellow pull
/// the eye, trace recedes into the background it usually is.
fn level_style(level: LogLevel) -> (&'static str, Style) {
    match level {
        LogLevel::Error => (
            "ERROR",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        LogLevel::Warn => ("WARN ", Style::default().fg(Color::Yellow)),
        LogLevel::Info => ("INFO ", Style::default().fg(Color::Green)),
        LogLevel::Debug => ("DEBUG", Style::default().fg(Color::Blue)),
        LogLevel::Trace => ("TRACE", Style::default().fg(Color::DarkGray)),
        // Never emitted by a node — proto3 requires the zero value to exist, and
        // an unrecognised value decodes to it. Rendered rather than hidden so a
        // version skew shows up as odd-looking output instead of missing lines.
        LogLevel::Unspecified => ("?????", Style::default().fg(Color::Magenta)),
    }
}

/// Format a record's uptime as `[    12.345s]` — right-aligned so the seconds
/// column stays put as a node's uptime grows.
fn format_uptime(uptime_ms: u64) -> String {
    format!("[{:>8}.{:03}s]", uptime_ms / 1000, uptime_ms % 1000)
}

/// Draw the Logs tab: the scrollable record view plus the filter line.
fn render_logs(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),    // the records
            Constraint::Length(3), // the filter line
        ])
        .split(area);

    render_log_records(frame, app, chunks[0]);
    render_log_filter(frame, app, chunks[1]);
}

/// Draw the record view, honouring the app's scroll offset.
fn render_log_records(frame: &mut Frame, app: &mut App, area: Rect) {
    // Two border rows are not text.
    let height = area.height.saturating_sub(2) as usize;
    let total = app.logs.entries.len();

    // `scroll` counts lines between the viewport's bottom and the buffer's
    // bottom. Clamped here rather than at keypress time because only rendering
    // knows the viewport height — a key handler cannot tell how far back "one
    // screen" is.
    let scroll = app.logs.scroll.min(total.saturating_sub(height));
    let end = total.saturating_sub(scroll);
    let start = end.saturating_sub(height);

    let lines: Vec<Line> = app
        .logs
        .entries
        .iter()
        .skip(start)
        .take(end - start)
        .map(|entry| match entry {
            LogEntry::Record(record) => {
                let level = LogLevel::try_from(record.level).unwrap_or(LogLevel::Unspecified);
                let (label, style) = level_style(level);
                Line::from(vec![
                    Span::styled(
                        format_uptime(record.uptime_ms),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::raw(" "),
                    Span::styled(label, style),
                    Span::raw(" "),
                    Span::styled(record.target.clone(), Style::default().fg(Color::DarkGray)),
                    Span::raw(": "),
                    Span::raw(record.message.clone()),
                ])
            }
            // Drawn as a full-width rule so a discontinuity is impossible to
            // scroll past without noticing — the alternative, a small counter
            // somewhere else on screen, is exactly how a missing record turns
            // into a wrong conclusion.
            LogEntry::Gap(dropped) => Line::from(Span::styled(
                format!("──── {dropped} records dropped ────"),
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            )),
        })
        .collect();

    let title = if app.logs.follow {
        " Logs (following) ".to_string()
    } else {
        // The offset tells an operator how far from live they are, which is the
        // question that matters once the view is detached.
        format!(" Logs (paused, {scroll} lines back — G to resume) ")
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if app.logs.follow {
            ACCENT
        } else {
            Color::Yellow
        }))
        .title(title);

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// Draw the runtime filter line — the spec in force, or the edit buffer.
fn render_log_filter(frame: &mut Frame, app: &mut App, area: Rect) {
    let (content, style, title) = match &app.logs.editing {
        Some(buffer) => (
            format!("{buffer}▏"),
            Style::default().fg(Color::White),
            " Filter (Enter: apply   Esc: cancel) ",
        ),
        None => (
            if app.logs.filter.is_empty() {
                "(unknown — no response yet)".to_string()
            } else {
                app.logs.filter.clone()
            },
            Style::default().fg(Color::DarkGray),
            " Filter (f to edit) ",
        ),
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if app.logs.editing.is_some() {
            ACCENT
        } else {
            Color::DarkGray
        }))
        .title(title);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(content, style))).block(block),
        area,
    );
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
                .title(" Wayfinder ".bold().fg(ACCENT))
                // Top-right of the frame, opposite the product mark: the one
                // thing on screen that is true whichever tab is showing, so it
                // belongs in the chrome rather than in any one view.
                .title_top(alarm_badge(&app.snapshot.alarms).right_aligned()),
        )
        .select(app.tab.index())
        .highlight_style(Style::default().fg(Color::Black).bg(ACCENT).bold())
        .divider("|");
    frame.render_widget(tabs, area);
}

/// Draw the overview pane: node identity, capacity, and connection details.
fn render_overview(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    let (node_id, num_orig, locked, clock) = match &app.snapshot.node_info {
        Some(info) => (
            format_id(&info.node_id),
            info.num_originators.to_string(),
            if info.auth_locked { "yes" } else { "no" }.to_string(),
            // "trusted", not "synchronized": the flag is true whenever the
            // node will act on its clock, which includes a node whose operator
            // turned enforcement off. Claiming synchronisation there would be
            // a lie about a security posture.
            if info.clock_trusted {
                "trusted".to_string()
            } else {
                "NOT SYNCHRONIZED".to_string()
            },
        ),
        None => (
            "(waiting for data)".to_string(),
            "—".to_string(),
            "—".to_string(),
            "—".to_string(),
        ),
    };

    lines.push(field("Node ID", &node_id));
    lines.push(field("Originators", &num_orig));
    lines.push(field("Locked", &locked));
    lines.push(field("Clock", &clock));
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

    lines.push(Line::from(""));
    lines.extend(alarm_lines(&app.snapshot.alarms));

    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Node Overview "),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(para, area);
}

/// The tab bar's alarm badge: what the node believes is wrong, in one span.
///
/// Three states, because two would collapse a distinction that matters. A board
/// with nothing on it and a board whose conditions have all gone quiet are both
/// "nothing is happening right now", but the second means something *did*
/// happen and the operator has not seen it yet — which is the whole reason the
/// board latches instead of expiring.
///
/// Coloured by the worst *active* severity, so the badge's colour answers "how
/// bad is it" before its text is read.
fn alarm_badge(board: &Alarms) -> Line<'static> {
    let active = board.alarms.iter().filter(|a| a.active).count();
    let quiet = board.alarms.len() - active;

    if active == 0 {
        let mut spans = vec![Span::styled(
            " ● all systems normal",
            Style::default().fg(Color::Green),
        )];
        if quiet > 0 {
            spans.push(Span::styled(
                format!(" · {quiet} recent "),
                Style::default().fg(Color::DarkGray),
            ));
        } else {
            spans.push(Span::raw(" "));
        }
        return Line::from(spans);
    }

    let worst = board
        .alarms
        .iter()
        .filter(|a| a.active)
        .map(|a| a.severity)
        .max()
        .unwrap_or(AlarmSeverity::Info as i32);
    let plural = if active == 1 { "" } else { "s" };
    Line::from(Span::styled(
        format!(" ▲ {active} alarm{plural} "),
        severity_style(worst).add_modifier(Modifier::BOLD),
    ))
}

/// The Overview pane's alarm section: the badge's detail, spelled out.
///
/// Every row the node holds, not only the firing ones — a condition that
/// stopped is dimmed rather than hidden, because "it happened and stopped" is
/// what an operator who attached afterwards came to find out.
fn alarm_lines(board: &Alarms) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(Span::styled(
        "Alarms",
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
    ))];

    if board.alarms.is_empty() {
        lines.push(Line::from(Span::styled(
            "  nothing wrong — the node is holding no conditions",
            Style::default().fg(Color::Green),
        )));
        return lines;
    }

    for alarm in &board.alarms {
        lines.push(alarm_line(alarm, board.now_ms));
    }

    // A gap in the board is reported as a gap, exactly as a gap in the log
    // stream is: a row that silently vanished would be indistinguishable from a
    // condition that never happened.
    if board.dropped > 0 {
        lines.push(Line::from(Span::styled(
            format!(
                "  ⚠ {} condition(s) refused or evicted for want of room",
                board.dropped
            ),
            Style::default().fg(Color::Red),
        )));
    }
    lines
}

/// One alarm as a line: severity, kind, subject, magnitude, age, detail.
fn alarm_line(alarm: &Alarm, now_ms: u64) -> Line<'static> {
    let style = if alarm.active {
        severity_style(alarm.severity)
    } else {
        // Quiet rows recede rather than disappear — present, but not competing
        // for attention with what is firing now.
        Style::default().fg(Color::DarkGray)
    };
    Line::from(vec![
        Span::styled(format!("  {} ", severity_glyph(alarm.severity)), style),
        Span::styled(
            format!("{:<24}", alarm_kind_name(alarm.kind)),
            style.add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("{:<20}", alarm_subject(alarm)), style),
        Span::styled(format!("×{:<6}", alarm.count), style),
        Span::styled(
            format!("{:>10}  ", format_age(now_ms, alarm.last_ms)),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(alarm.detail.clone(), Style::default().fg(Color::Gray)),
    ])
}

/// The colour a severity is rendered in: warm for what needs acting on, cool
/// for what is merely noted — the same rule [`level_style`] follows for logs.
fn severity_style(severity: i32) -> Style {
    match AlarmSeverity::try_from(severity) {
        Ok(AlarmSeverity::Critical) => Style::default().fg(Color::Red),
        Ok(AlarmSeverity::Warning) => Style::default().fg(Color::Yellow),
        Ok(AlarmSeverity::Info) => Style::default().fg(Color::Cyan),
        // Never emitted by a node; rendered rather than hidden so a version
        // skew looks odd instead of looking normal.
        _ => Style::default().fg(Color::Magenta),
    }
}

/// A one-character severity mark, so the shape of the list reads before the
/// words do even without colour.
fn severity_glyph(severity: i32) -> &'static str {
    match AlarmSeverity::try_from(severity) {
        Ok(AlarmSeverity::Critical) => "✖",
        Ok(AlarmSeverity::Warning) => "▲",
        Ok(AlarmSeverity::Info) => "•",
        _ => "?",
    }
}

/// The node's own name for a condition, so what the TUI shows and what the log
/// line beside it says are the same string.
fn alarm_kind_name(kind: i32) -> &'static str {
    match AlarmKind::try_from(kind) {
        Ok(AlarmKind::UnauthenticatedTraffic) => "unauthenticated_traffic",
        Ok(AlarmKind::TrafficFlood) => "traffic_flood",
        Ok(AlarmKind::ManagementAuthFailures) => "management_auth_failures",
        Ok(AlarmKind::OgmReplay) => "ogm_replay",
        Ok(AlarmKind::RevokedPeer) => "revoked_peer",
        Ok(AlarmKind::LinkErrors) => "link_errors",
        Ok(AlarmKind::TableSaturation) => "table_saturation",
        Ok(AlarmKind::ClockUnsynchronized) => "clock_unsynchronized",
        Ok(AlarmKind::SelfRevoked) => "self_revoked",
        // A node newer than this build, holding a condition it has no name for.
        // Shown as unknown rather than dropped: an alarm this client cannot name
        // is still an alarm.
        _ => "unknown",
    }
}

/// Who or what an alarm is about, rendered for a human.
fn alarm_subject(alarm: &Alarm) -> String {
    match &alarm.subject {
        Some(AlarmSubject::NodeId(id)) => format_id(id),
        Some(AlarmSubject::InterfaceIndex(idx)) => format!("iface{idx}"),
        // Not "—": a condition with no subject is about the node itself, which
        // is a fact rather than a missing field.
        None => "this node".to_string(),
    }
}

/// How long ago something last happened, in the node's own uptime clock.
///
/// Both instants come from the same snapshot, so this needs no clock of its own
/// and cannot disagree with the node about what "now" is.
fn format_age(now_ms: u64, then_ms: u64) -> String {
    let secs = now_ms.saturating_sub(then_ms) / 1000;
    match secs {
        0 => "now".to_string(),
        s if s < 60 => format!("{s}s ago"),
        s if s < 3600 => format!("{}m ago", s / 60),
        s => format!("{}h ago", s / 3600),
    }
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

    // The right column carries two answers to the same question, stacked: what
    // the routing table *believes* about this destination, and — underneath —
    // what a probe actually found. Keeping them adjacent is the point of
    // putting ping here rather than on a tab of its own.
    let detail = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(11)])
        .split(cols[1]);
    render_path_detail(frame, app, detail[0]);
    render_ping_detail(frame, app, detail[1]);
}

/// Draw the probe panel beneath the path breakdown: the session this client
/// started against the selected originator, or the hint that starts one.
///
/// Shows a session only when it is *for the selected row*. Moving the selection
/// therefore returns this to the hint rather than leaving one target's round
/// trips sitting under another's row, which is the way a panel like this
/// misleads.
fn render_ping_detail(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" Ping ");
    let selected = app
        .routing_state
        .selected()
        .and_then(|i| app.snapshot.routing.entries.get(i));

    let hint = |text: &str| {
        vec![Line::from(Span::styled(
            text.to_string(),
            Style::default().fg(Color::DarkGray),
        ))]
    };

    let lines: Vec<Line> = match selected {
        None => hint("Select an originator, then press p to ping it."),
        Some(entry) if !app.ping_is_for(&entry.destination) => {
            hint("Press p to ping this originator.")
        }
        // `ping_is_for` returned true, so the view is there. Falling back to
        // the hint rather than returning early: an early return would skip
        // `render_widget` below and leave an unexplained hole in the layout
        // where the bordered pane should be.
        Some(_) => match app.ping.as_ref() {
            None => hint("Press p to ping this originator."),
            Some(view) => {
                let mut out = Vec::new();
                if view.displaced {
                    out.push(Line::from(Span::styled(
                        // Two causes, one message: the node answers a handle it
                        // no longer knows the same way whether somebody else
                        // took the session or it restarted. Naming only the
                        // first would hand an operator debugging a crash-looping
                        // node a wrong lead.
                        "Session no longer running (replaced, or the node restarted).",
                        Style::default().fg(Color::Yellow),
                    )));
                }
                if let Some(error) = &view.error {
                    out.push(Line::from(Span::styled(
                        format!("Cannot read session: {error}"),
                        Style::default().fg(Color::Red),
                    )));
                }
                match &view.session {
                    None => out.extend(hint("Starting…")),
                    Some(session) => out.extend(ping_lines(session)),
                }
                out
            }
        },
    };

    let para = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    frame.render_widget(para, area);
}

/// The probe rows and running summary for one session.
fn ping_lines(session: &PingSession) -> Vec<Line<'static>> {
    let mut out = vec![Line::from(vec![
        Span::styled(
            format!("{}/{} sent", session.sent, session.requested),
            Style::default().fg(Color::White),
        ),
        Span::raw("  "),
        Span::styled(
            format!("{} recv", session.received),
            Style::default().fg(Color::Green),
        ),
        Span::raw("  "),
        Span::styled(
            format!("{} lost", session.lost),
            if session.lost > 0 {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::DarkGray)
            },
        ),
        Span::raw("  "),
        Span::styled(
            if session.active { "running" } else { "done" },
            Style::default().fg(Color::DarkGray),
        ),
    ])];

    // Omitted entirely until something has been answered: rendering
    // `0.0/0.0/0.0` would be reporting a measurement nobody took.
    if session.received > 0 {
        out.push(Line::from(Span::styled(
            format!(
                "rtt {} / {} / {} ms  (min/avg/max)",
                fmt_ms(session.rtt_min_us),
                fmt_ms(session.rtt_avg_us),
                fmt_ms(session.rtt_max_us),
            ),
            Style::default().fg(ACCENT),
        )));
    }

    // Newest first: a running ping is watched at its leading edge, and the
    // pane is shorter than the node's window.
    for probe in session.probes.iter().rev() {
        out.push(ping_probe_line(probe));
    }
    out
}

/// One probe's row, coloured by what became of it.
fn ping_probe_line(probe: &PingProbe) -> Line<'static> {
    let (text, style) = match probe.state() {
        PingProbeState::Replied => (
            format!(
                "  seq {:<4} {:>8} ms  hops {}/{}",
                probe.seqno,
                fmt_ms(probe.rtt_us),
                probe.forward_hops,
                probe.return_hops,
            ),
            Style::default().fg(Color::Green),
        ),
        PingProbeState::Pending => (
            format!("  seq {:<4}        …", probe.seqno),
            Style::default().fg(Color::DarkGray),
        ),
        PingProbeState::NoRoute => (
            format!("  seq {:<4}   no route", probe.seqno),
            Style::default().fg(Color::Red),
        ),
        // A timeout, and anything a newer node might report that this build
        // does not know: both mean "no answer", which is worth a row rather
        // than a silent omission.
        _ => (
            format!("  seq {:<4}  no answer", probe.seqno),
            Style::default().fg(Color::Red),
        ),
    };
    Line::from(Span::styled(text, style))
}

/// Microseconds as milliseconds, keeping the precision a sub-millisecond round
/// trip deserves — on a local link `0.0` would read as broken rather than fast.
fn fmt_ms(us: u32) -> String {
    let ms = f64::from(us) / 1000.0;
    if ms < 1.0 {
        format!("{ms:.3}")
    } else {
        format!("{ms:.1}")
    }
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
                Cell::from(iface_label(&e.iface_name, e.iface_idx)),
                Cell::from(match e.ewma_quality {
                    Some(q) => Span::styled(format!("{} {}", q, bar(q)), tq_style(q)),
                    // No physical-layer measurement on this link (raw L2, UDP,
                    // Unix).  Rendering it as 0 would paint a healthy wired
                    // neighbor red at an empty bar; say "unknown" instead.
                    None => Span::styled(
                        format!("{:<3} {}", "-", "·".repeat(10)),
                        Style::default().fg(Color::DarkGray),
                    ),
                }),
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
            // Wide enough for a configured name (`lora-roof`), not just the
            // `#3` index fallback.
            Constraint::Length(14),
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
                Cell::from(iface_label(&e.iface_name, e.iface_idx)),
                Cell::from(current),
                Cell::from(Span::styled(status, status_style)),
            ])
        })
        .collect();

    let title = format!(" Links ({}) ", app.snapshot.link_features.entries.len());
    let table = Table::new(
        rows,
        [
            Constraint::Length(14),
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

/// How an interface is labelled in the UI: its configured name when the node
/// reported one, else `#idx`. Interfaces are still *addressed* by index over
/// the management API — the name is display metadata — so the fallback keeps
/// an unnamed interface identifiable rather than blank.
fn iface_label(iface_name: &str, iface_idx: u32) -> String {
    if iface_name.is_empty() {
        format!("#{iface_idx}")
    } else {
        iface_name.to_string()
    }
}

/// The OGM schedule entry for `iface_idx`, if the snapshot has one. Zipped by
/// index rather than assumed positional, since the two tables come from
/// separate RPCs.
fn ogm_schedule_for(
    app: &App,
    iface_idx: u32,
) -> Option<&wayfinder_protos::wayfinder::v1alpha::OgmScheduleEntry> {
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
            // Both the label and the raw index: the index is what an operator
            // types into `wayfinderctl link enable --iface N`, so a named
            // interface must not hide it.
            let mut out = vec![
                field(
                    "Interface",
                    &iface_label(&entry.iface_name, entry.iface_idx),
                ),
                field("Index", &entry.iface_idx.to_string()),
            ];
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

/// One unbroken run of throughput samples, as chart points.
///
/// The x of each point is seconds relative to now — negative into the past, so
/// the right edge of the chart is always the present moment. Splitting the
/// history into runs is what keeps a stretch with no samples (the TUI was
/// closed, or the node was unreachable) from being drawn as a straight line
/// between the last sample before it and the first sample after: a line there
/// would assert traffic levels nobody measured.
struct ThroughputSegment {
    /// Receive-rate points, oldest first.
    rx: Vec<(f64, f64)>,
    /// Transmit-rate points, oldest first.
    tx: Vec<(f64, f64)>,
}

/// Project `history` onto a time axis anchored at `now_ms`, breaking it into
/// contiguous runs wherever consecutive samples are more than two refresh
/// intervals apart.
///
/// Two intervals is the threshold because a live session's samples land one
/// interval apart give or take scheduling jitter and a slow round trip to the
/// node; anything beyond that is a stretch that went unrecorded.
fn throughput_segments(
    history: &VecDeque<ThroughputSample>,
    now_ms: u64,
    interval_ms: u64,
) -> Vec<ThroughputSegment> {
    let max_step = interval_ms.max(1).saturating_mul(2);
    let mut segments: Vec<ThroughputSegment> = Vec::new();
    let mut prev_at: Option<u64> = None;

    for s in history {
        let contiguous = prev_at.is_some_and(|prev| s.at_ms.saturating_sub(prev) <= max_step);
        if !contiguous {
            segments.push(ThroughputSegment {
                rx: Vec::new(),
                tx: Vec::new(),
            });
        }
        // The branch above guarantees a segment to push into.
        if let Some(seg) = segments.last_mut() {
            let x = (s.at_ms as f64 - now_ms as f64) / 1000.0;
            seg.rx.push((x, s.rx_bps));
            seg.tx.push((x, s.tx_bps));
            prev_at = Some(s.at_ms);
        }
    }
    segments
}

/// Draw the node-wide throughput history as a two-line chart: one line for the
/// receive rate and one for the transmit rate, plotted against the wall-clock
/// time each sample was taken. This turns the instantaneous totals into a
/// visible trend so an operator can see bursts, ramps, and collapses in mesh
/// traffic at a glance.
///
/// Because the x-axis is real time and not sample index, a history restored
/// from a previous session sits at its true age with the interruption visible
/// as a gap, rather than being fused onto the present.
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

    let now = now_ms();
    let segments = throughput_segments(history, now, app.interval_ms);

    // The axis spans from the oldest retained sample to now. Floor the span at
    // one refresh interval so a burst of same-millisecond samples still gets a
    // non-degenerate axis.
    let interval_secs = app.interval_ms.max(1) as f64 / 1000.0;
    let oldest = history.front().map_or(0.0, |s| s.at_ms as f64);
    let x_min = ((oldest - now as f64) / 1000.0).min(-interval_secs);

    // Scale the y-axis to the largest rate seen across both series, with a
    // little headroom, and never below 1 so an idle mesh still renders a flat
    // baseline rather than a degenerate zero-height axis.
    let peak = history
        .iter()
        .map(|s| s.rx_bps.max(s.tx_bps))
        .fold(0.0_f64, f64::max);
    let y_max = (peak * 1.15).max(1.0);

    // Only the first run of each series is named, so a history broken by a gap
    // still shows one "RX" and one "TX" entry in the legend rather than one per
    // fragment.
    let mut datasets = Vec::with_capacity(segments.len() * 2);
    for (i, seg) in segments.iter().enumerate() {
        let (rx_name, tx_name) = if i == 0 { ("RX", "TX") } else { ("", "") };
        datasets.push(
            Dataset::default()
                .name(rx_name)
                .marker(Marker::Braille)
                .graph_type(GraphType::Line)
                .style(Style::default().fg(Color::Green))
                .data(&seg.rx),
        );
        datasets.push(
            Dataset::default()
                .name(tx_name)
                .marker(Marker::Braille)
                .graph_type(GraphType::Line)
                .style(Style::default().fg(Color::Cyan))
                .data(&seg.tx),
        );
    }

    let chart = Chart::new(datasets)
        .block(block)
        .x_axis(
            Axis::default()
                .style(Style::default().fg(Color::DarkGray))
                .bounds([x_min, 0.0])
                .labels(vec![
                    Span::raw(format!("-{:.0}s", -x_min)),
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
/// approved with `a` / denied with `d` (or from the CLI, `wayfinderctl provider
/// requests approve|deny --mac <mac>`).
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
        // Checked before `auth_enabled`, because going inert *is* dropping the
        // certificate: a revoked node reports auth disabled, and reporting only
        // that would hide the one thing an operator needs to know about it.
        Some(s) if s.self_revoked => vec![
            field("Authentication", "revoked"),
            field(
                "Membership",
                "revoked — inert until an authority re-admits this node",
            ),
            field(
                "Revocation enforced until",
                &s.self_revocation_not_after.to_string(),
            ),
        ],
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
            let occ = |o: &Option<wayfinder_protos::wayfinder::v1alpha::TableOccupancy>| match o {
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
                field(
                    "Untaggable drops",
                    &format!("{:.2}/s", m.untaggable_drop_rate),
                ),
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
                Cell::from(iface_label(&e.iface_name, e.iface_idx)),
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
            Constraint::Length(14),
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

    // Routing-tab probe: the one action reachable from a read-only-looking tab,
    // so it needs saying.
    if app.tab == Tab::Routing {
        spans.push(Span::styled(
            " p ",
            Style::default().fg(Color::Black).bg(Color::Green),
        ));
        spans.push(Span::raw(" ping  "));
        // Advertised only while there is something to stop, so the footer says
        // what the key will actually do right now.
        if app.ping.as_ref().is_some_and(|v| v.needs_poll()) {
            spans.push(Span::styled(
                " c ",
                Style::default().fg(Color::Black).bg(Color::Red),
            ));
            spans.push(Span::raw(" cancel  "));
        }
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
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    /// A board with three rows on it, straddling their hold windows: one
    /// critical still firing, one warning still firing, one info that has gone
    /// quiet. The same shape the mock node serves, so what these assert and what
    /// a developer sees on screen are the same thing.
    fn board_with_three_conditions() -> Alarms {
        Alarms {
            alarms: vec![
                Alarm {
                    kind: AlarmKind::ManagementAuthFailures as i32,
                    severity: AlarmSeverity::Critical as i32,
                    first_ms: 240_000,
                    last_ms: 619_000,
                    count: 412,
                    detail: "denied=412 in 6m".into(),
                    active: true,
                    subject: Some(AlarmSubject::NodeId(vec![
                        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x09,
                    ])),
                },
                Alarm {
                    kind: AlarmKind::LinkErrors as i32,
                    severity: AlarmSeverity::Warning as i32,
                    first_ms: 480_000,
                    last_ms: 600_000,
                    count: 27,
                    detail: "consecutive recv errors=27".into(),
                    active: true,
                    subject: Some(AlarmSubject::InterfaceIndex(1)),
                },
                Alarm {
                    kind: AlarmKind::UnauthenticatedTraffic as i32,
                    severity: AlarmSeverity::Info as i32,
                    first_ms: 300_000,
                    last_ms: 500_000,
                    count: 3,
                    detail: "dropped=3".into(),
                    active: false,
                    subject: Some(AlarmSubject::NodeId(vec![0, 0, 0, 0, 0, 7])),
                },
            ],
            dropped: 0,
            now_ms: 620_000,
        }
    }

    /// Draw one frame and flatten the buffer to text.
    fn rendered(app: &mut App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(140, 40)).expect("terminal");
        terminal.draw(|frame| render(frame, app)).expect("draw");
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    /// A node holding nothing says so, in the chrome and in the Overview alike.
    ///
    /// The positive statement is the point: an operator must be able to tell
    /// "checked, and nothing is wrong" from "nothing has told me anything",
    /// and a badge that appeared only when something broke could not.
    #[test]
    fn an_empty_board_reports_all_systems_normal() {
        let mut app = App::new("test".to_string(), 1000);
        app.tab = Tab::Overview;

        let text = rendered(&mut app);
        assert!(
            text.contains("all systems normal"),
            "the badge must state the normal case, not merely omit the bad one"
        );
        assert!(text.contains("nothing wrong"), "and the Overview must too");
    }

    /// With conditions on the board the badge counts the *firing* ones and the
    /// Overview spells every row out — kind, subject, magnitude and detail.
    #[test]
    fn a_board_with_conditions_shows_a_count_and_the_rows_behind_it() {
        let mut app = App::new("test".to_string(), 1000);
        app.tab = Tab::Overview;
        app.snapshot.alarms = board_with_three_conditions();

        let text = rendered(&mut app);
        assert!(
            text.contains("2 alarms"),
            "the badge counts what is firing, not what is on the board"
        );
        assert!(!text.contains("all systems normal"));

        assert!(text.contains("management_auth_failures"));
        assert!(text.contains("link_errors"));
        assert!(text.contains("aa:bb:cc:dd:ee:09"), "peer subject rendered");
        assert!(text.contains("iface1"), "interface subject rendered");
        assert!(text.contains("×412"), "the magnitude is on the row");
        assert!(text.contains("denied=412 in 6m"), "and so is the detail");
    }

    /// A condition that has gone quiet is still listed, and the badge reports it
    /// separately from the ones firing now.
    ///
    /// This is the distinction latching exists for: an operator who attached
    /// after a burst ended must still learn it happened, so "nothing is
    /// happening" and "nothing happened" cannot look the same.
    #[test]
    fn a_quiet_condition_is_still_listed_and_counted_apart() {
        let mut app = App::new("test".to_string(), 1000);
        app.tab = Tab::Overview;
        let mut board = board_with_three_conditions();
        // Leave only the row that has gone quiet.
        board.alarms.retain(|a| !a.active);
        app.snapshot.alarms = board;

        let text = rendered(&mut app);
        assert!(
            text.contains("all systems normal"),
            "nothing is firing, and the badge says so"
        );
        assert!(
            text.contains("1 recent"),
            "but it does not pretend the board is empty"
        );
        assert!(
            text.contains("unauthenticated_traffic"),
            "and the quiet row is still listed in full"
        );
    }

    /// A board that had to refuse or evict a row says so, rather than letting
    /// the missing condition look like one that never happened.
    #[test]
    fn an_evicting_board_reports_the_gap() {
        let mut app = App::new("test".to_string(), 1000);
        app.tab = Tab::Overview;
        let mut board = board_with_three_conditions();
        board.dropped = 9;
        app.snapshot.alarms = board;

        assert!(rendered(&mut app).contains("9 condition(s) refused or evicted"));
    }

    /// An alarm kind this build has no name for is rendered as unknown, not
    /// dropped: a client too old to name a condition is still a client that must
    /// not tell its operator everything is fine.
    #[test]
    fn a_condition_this_build_cannot_name_is_still_shown() {
        let mut app = App::new("test".to_string(), 1000);
        app.tab = Tab::Overview;
        app.snapshot.alarms = Alarms {
            alarms: vec![Alarm {
                kind: 9_999,
                severity: AlarmSeverity::Critical as i32,
                first_ms: 0,
                last_ms: 1_000,
                count: 1,
                detail: "from the future".into(),
                active: true,
                subject: None,
            }],
            dropped: 0,
            now_ms: 1_000,
        };

        let text = rendered(&mut app);
        assert!(text.contains("1 alarm"), "counted despite being unnameable");
        assert!(text.contains("unknown"), "and shown as what it is");
        assert!(
            text.contains("this node"),
            "a subjectless condition is about the node, not about nothing"
        );
    }

    /// A fixed wall-clock "now" (2023-11-14T22:13:20Z), so the chart's
    /// time-axis assertions don't depend on the machine clock.
    const NOW: u64 = 1_700_000_000_000;

    /// Build a history from `(seconds-ago, rx, tx)` triples, oldest first.
    fn history_ago(samples: &[(u64, f64, f64)]) -> VecDeque<ThroughputSample> {
        samples
            .iter()
            .map(|&(ago, rx, tx)| ThroughputSample {
                at_ms: NOW - ago * 1000,
                rx_bps: rx,
                tx_bps: tx,
            })
            .collect()
    }

    #[test]
    fn throughput_points_are_placed_by_capture_time() {
        let history = history_ago(&[(3, 10.0, 1.0), (2, 20.0, 2.0), (1, 30.0, 3.0)]);
        let segments = throughput_segments(&history, NOW, 1000);

        // One unbroken run, plotted as seconds before "now" — so a sample taken
        // three seconds ago sits three seconds back on the axis whether it came
        // from this session or was restored from disk.
        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0].rx,
            vec![(-3.0, 10.0), (-2.0, 20.0), (-1.0, 30.0)]
        );
        assert_eq!(segments[0].tx, vec![(-3.0, 1.0), (-2.0, 2.0), (-1.0, 3.0)]);
    }

    #[test]
    fn throughput_series_breaks_across_a_recording_gap() {
        // Two samples restored from a previous session, then a 30 s stretch
        // where the TUI was not running, then this session's samples.
        let history = history_ago(&[(40, 1.0, 0.0), (39, 2.0, 0.0), (2, 3.0, 0.0), (1, 4.0, 0.0)]);
        let segments = throughput_segments(&history, NOW, 1000);

        // The gap is a hole in the record, not a straight line down from the
        // last restored sample: each contiguous run is its own series.
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].rx, vec![(-40.0, 1.0), (-39.0, 2.0)]);
        assert_eq!(segments[1].rx, vec![(-2.0, 3.0), (-1.0, 4.0)]);
    }

    #[test]
    fn throughput_series_tolerates_refresh_jitter() {
        // Samples an interval apart give or take a little are one run: only a
        // real interruption should break the line.
        let history = history_ago(&[(3, 1.0, 0.0), (2, 2.0, 0.0), (1, 3.0, 0.0)]);
        assert_eq!(throughput_segments(&history, NOW, 900).len(), 1);
        // An empty history has no series at all.
        assert!(throughput_segments(&VecDeque::new(), NOW, 1000).is_empty());
    }

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
        // line-drawing path and the y-axis peak/headroom computation — with a
        // gap partway through, so the segmented-chart path is drawn too.
        for i in 0..5 {
            app.snapshot.throughput.total_rx_bps = (i * 100) as f64;
            app.snapshot.throughput.total_tx_bps = (i * 50) as f64;
            let ago = if i < 2 { 60 - i } else { 5 - i };
            app.record_throughput_at(now_ms().saturating_sub(ago as u64 * 1000));
        }
        terminal
            .draw(|frame| render(frame, &mut app))
            .expect("draw with history");

        // Populate node metrics so the node-metrics panel — including the new
        // oversize-drops row — renders its values, not the "no data" placeholder.
        app.snapshot.metrics = Some(wayfinder_protos::wayfinder::v1alpha::NodeMetrics {
            oversize_drops: 42,
            relay_oversize_drops: 17,
            cert_store: Some(wayfinder_protos::wayfinder::v1alpha::TableOccupancy {
                used: 5,
                capacity: 64,
            }),
            cert_req_rate: 0.5,
            cert_reply_rate: 1.5,
            untaggable_drop_rate: 0.0,
            ..Default::default()
        });
        app.snapshot.keepalive = wayfinder_protos::wayfinder::v1alpha::KeepAliveTable {
            entries: vec![wayfinder_protos::wayfinder::v1alpha::KeepAliveEntry {
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
        use wayfinder_protos::wayfinder::v1alpha::GetSecurityStatusResponse;
        use wayfinder_protos::wayfinder::v1alpha::ListPendingCsrsResponse;
        use wayfinder_protos::wayfinder::v1alpha::PendingCsr;

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
        use wayfinder_protos::wayfinder::v1alpha::GetSecurityStatusResponse;
        use wayfinder_protos::wayfinder::v1alpha::ListPendingCsrsResponse;
        use wayfinder_protos::wayfinder::v1alpha::NodeSecurity;

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
        use wayfinder_protos::wayfinder::v1alpha::LinkFeaturesEntry;
        use wayfinder_protos::wayfinder::v1alpha::LinkFeaturesTable;
        use wayfinder_protos::wayfinder::v1alpha::OgmSchedule;
        use wayfinder_protos::wayfinder::v1alpha::OgmScheduleEntry;

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
                iface_name: String::new(),
            }],
        };
        app.snapshot.ogm_schedule = OgmSchedule {
            entries: vec![OgmScheduleEntry {
                iface_idx: 3,
                current_interval_ms: 4000,
                min_interval_ms: 1000,
                max_interval_ms: 64000,
                iface_name: String::new(),
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
        // An unnamed interface still identifies itself, by index.
        assert!(text.contains("#3"), "index fallback label missing: {text}");
    }

    /// A named interface is shown by name everywhere its index used to be — the
    /// whole point of naming, since `0`/`1`/`2` tells an operator nothing about
    /// which radio a row describes.
    #[test]
    fn named_interfaces_render_by_name() {
        use wayfinder_protos::wayfinder::v1alpha::LinkFeaturesEntry;
        use wayfinder_protos::wayfinder::v1alpha::LinkFeaturesTable;

        let mut app = App::new("test".to_string(), 1000);
        app.tab = Tab::Links;
        app.snapshot.link_features = LinkFeaturesTable {
            entries: vec![LinkFeaturesEntry {
                iface_idx: 3,
                tx_ogm: true,
                rx_ogm: true,
                tx_data: true,
                rx_data: true,
                tx_keepalive_interval_ms: None,
                iface_name: "lora-roof".into(),
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

        assert!(text.contains("lora-roof"), "interface name missing: {text}");
    }

    /// The label falls back to a `#`-prefixed index when the node reports no
    /// name, so an unnamed interface is never a blank cell.
    #[test]
    fn iface_label_falls_back_to_index() {
        assert_eq!(iface_label("wlan0", 2), "wlan0");
        assert_eq!(iface_label("", 2), "#2");
    }

    // ---- the ping panel on the Routing tab ------------------------------

    /// One originator, so the Routing tab has a row to select.
    fn app_with_one_originator() -> App {
        let mut app = App::new("test".to_string(), 1000);
        app.tab = Tab::Routing;
        app.snapshot.routing = wayfinder_protos::wayfinder::v1alpha::RoutingTable {
            entries: vec![wayfinder_protos::wayfinder::v1alpha::RoutingEntry {
                destination: vec![0, 0, 0, 0, 0, 9],
                next_hop: vec![0, 0, 0, 0, 0, 2],
                tq: 200,
                last_seqno: 4,
                paths: vec![],
            }],
        };
        app.routing_state.select(Some(0));
        app
    }

    fn probe(seqno: u32, state: PingProbeState, rtt_us: u32) -> PingProbe {
        PingProbe {
            seqno,
            state: state as i32,
            rtt_us,
            forward_hops: 2,
            return_hops: 3,
        }
    }

    fn session_for(destination: Vec<u8>, probes: Vec<PingProbe>) -> PingSession {
        PingSession {
            session_seq: 1,
            destination,
            active: true,
            requested: 5,
            sent: 2,
            received: 1,
            lost: 1,
            rtt_min_us: 12_000,
            rtt_avg_us: 12_000,
            rtt_max_us: 12_000,
            rtt_mdev_us: 0,
            payload_bytes: 16,
            probes,
        }
    }

    /// With no session running, the panel tells the operator how to start one —
    /// which is the whole discoverability story for a key that is not on a tab
    /// of its own.
    #[test]
    fn the_ping_panel_advertises_the_key_when_idle() {
        let mut app = app_with_one_originator();
        let text = rendered(&mut app);
        assert!(text.contains("Press p to ping"), "got: {text}");
        assert!(text.contains(" p  ping"), "the footer names it too: {text}");
    }

    /// A running session reports its counts, its RTT spread, and each probe.
    #[test]
    fn the_ping_panel_reports_a_running_session() {
        let mut app = app_with_one_originator();
        app.ping = Some(crate::app::PingView {
            session_seq: 1,
            destination: vec![0, 0, 0, 0, 0, 9],
            session: Some(session_for(
                vec![0, 0, 0, 0, 0, 9],
                vec![
                    probe(0, PingProbeState::Replied, 12_000),
                    probe(1, PingProbeState::TimedOut, 0),
                ],
            )),
            displaced: false,
            error: None,
        });

        let text = rendered(&mut app);
        assert!(text.contains("2/5 sent"), "got: {text}");
        assert!(text.contains("1 recv"), "got: {text}");
        assert!(text.contains("1 lost"), "got: {text}");
        assert!(text.contains("hops 2/3"), "both legs reported: {text}");
        assert!(
            text.contains("no answer"),
            "the lost probe is a row: {text}"
        );
    }

    /// A session against a *different* originator must not render under the
    /// selected row. This is the way a panel like this misleads: the numbers
    /// are real, they are just about somebody else.
    #[test]
    fn another_targets_session_does_not_render_under_this_row() {
        let mut app = app_with_one_originator();
        app.ping = Some(crate::app::PingView {
            session_seq: 1,
            destination: vec![0, 0, 0, 0, 0, 8],
            session: Some(session_for(vec![0, 0, 0, 0, 0, 8], vec![])),
            displaced: false,
            error: None,
        });

        let text = rendered(&mut app);
        assert!(text.contains("Press p to ping"), "got: {text}");
        assert!(!text.contains("2/5 sent"), "got: {text}");
    }

    /// A displaced session says so rather than sitting there looking live: an
    /// operator watching a run half-finish needs to know it was taken away.
    #[test]
    fn a_displaced_session_says_so() {
        let mut app = app_with_one_originator();
        app.ping = Some(crate::app::PingView {
            session_seq: 1,
            destination: vec![0, 0, 0, 0, 0, 9],
            session: Some(session_for(vec![0, 0, 0, 0, 0, 9], vec![])),
            displaced: true,
            error: None,
        });

        // Single words, so the assertion survives the pane's word wrapping.
        // Both are asserted because the message deliberately names *both*
        // causes: the node answers an unknown handle the same way whether
        // somebody else took the session or it restarted, and naming only the
        // first would hand an operator debugging a crash-looping node a wrong
        // lead.
        let text = rendered(&mut app);
        assert!(
            text.contains("replaced"),
            "the panel must not present a taken-away session as current: {text}"
        );
        assert!(text.contains("restarted"), "got: {text}");
    }

    /// Nothing answered yet means no RTT line at all — `0.0 / 0.0 / 0.0` is a
    /// measurement, and "we measured nothing" is not one.
    #[test]
    fn a_session_with_no_replies_shows_no_rtt_line() {
        let mut app = app_with_one_originator();
        let mut session = session_for(
            vec![0, 0, 0, 0, 0, 9],
            vec![probe(0, PingProbeState::Pending, 0)],
        );
        session.received = 0;
        session.rtt_min_us = 0;
        session.rtt_avg_us = 0;
        session.rtt_max_us = 0;
        app.ping = Some(crate::app::PingView {
            session_seq: 1,
            destination: vec![0, 0, 0, 0, 0, 9],
            session: Some(session),
            displaced: false,
            error: None,
        });

        let text = rendered(&mut app);
        assert!(text.contains("0 recv"), "got: {text}");
        assert!(!text.contains("(min/avg/max)"), "got: {text}");
    }
}
