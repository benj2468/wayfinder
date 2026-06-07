//! All ratatui rendering for the TUI, driven entirely by [`App`] state.

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs, Wrap},
};

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
    }
    render_status(frame, app, chunks[2]);
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

    let (node_id, num_orig) = match &app.snapshot.node_info {
        Some(info) => (format_id(&info.node_id), info.num_originators.to_string()),
        None => ("(waiting for data)".to_string(), "—".to_string()),
    };

    lines.push(field("Node ID", &node_id));
    lines.push(field("Originators", &num_orig));
    lines.push(field(
        "Routing entries",
        &app.snapshot.routing.entries.len().to_string(),
    ));
    lines.push(field(
        "Link-quality rows",
        &app.snapshot.link_quality.entries.len().to_string(),
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
        Span::styled(" ←/→ Tab ", Style::default().fg(Color::Black).bg(ACCENT)),
        Span::raw(" switch  "),
        Span::styled(" ↑/↓ ", Style::default().fg(Color::Black).bg(ACCENT)),
        Span::raw(" select  "),
        Span::styled(" r ", Style::default().fg(Color::Black).bg(ACCENT)),
        Span::raw(" refresh  "),
    ];

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
