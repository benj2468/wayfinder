//! A terminal dashboard for a running Wayfinder node.
//!
//! Connects to the node's management API over TCP and polls it on a fixed
//! interval, presenting node info, the BATMAN routing table, and the
//! link-quality table across three tabs.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::{net::SocketAddr, time::Duration, time::Instant};

use clap::Parser;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use tokio::sync::mpsc;

use wayfinder_client::{Client, ConnectTarget};
use wayfinder_tui::app::{self, App};
use wayfinder_tui::persist;
use wayfinder_tui::ui;

/// Command-line arguments.
#[derive(Parser, Debug)]
#[command(about = "Terminal dashboard for the Wayfinder management API")]
struct Args {
    /// TCP address of the node's management API (ServerConfig::Tcp in the node config).
    #[arg(long, default_value = "127.0.0.1:7700")]
    addr: SocketAddr,

    /// Refresh interval in milliseconds.
    #[arg(long, default_value_t = 1000)]
    interval: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut terminal = ratatui::init();
    let result = run(&mut terminal, args).await;
    ratatui::restore();
    result
}

/// The main draw / event / refresh loop. Returns when the user quits.
async fn run(terminal: &mut ratatui::DefaultTerminal, args: Args) -> anyhow::Result<()> {
    let mut app = App::new(args.addr.to_string(), args.interval);

    // Restore the throughput history from a previous session so the Metrics tab
    // chart continues its trend rather than starting blank.
    app.throughput_history = persist::load();

    // Read blocking terminal events on a dedicated thread and bridge them into
    // the async loop over a channel, so input never stalls the refresh timer.
    let (input_tx, mut input_rx) = mpsc::unbounded_channel::<Event>();
    std::thread::spawn(move || {
        while let Ok(ev) = event::read() {
            if input_tx.send(ev).is_err() {
                break;
            }
        }
    });

    let mut client: Option<Client> = None;
    let mut ticker = tokio::time::interval(Duration::from_millis(args.interval.max(50)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut loop_result = Ok(());
    while app.running {
        if let Err(e) = terminal.draw(|frame| ui::render(frame, &mut app)) {
            loop_result = Err(e.into());
            break;
        }

        tokio::select! {
            _ = ticker.tick() => {
                refresh(&mut client, args.addr, &mut app).await;
            }
            ev = input_rx.recv() => {
                match ev {
                    Some(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                        handle_key(&mut app, key.code);
                        // A key may have queued an approve/deny; execute it now,
                        // since only this loop owns the client.
                        if app.pending_action.is_some() {
                            act(&mut client, args.addr, &mut app).await;
                        }
                    }
                    Some(_) => {}
                    None => app.running = false, // input thread died
                }
            }
        }
    }

    // Persist the throughput history so the next session resumes the trend.
    // Best-effort: a failure here just means the chart starts fresh next time,
    // so it must not mask a real run error.
    let _ = persist::save(&app.throughput_history);

    loop_result
}

/// Apply a keypress to the application state.
fn handle_key(app: &mut App, code: KeyCode) {
    // A confirmation popup is modal: it captures every key until the operator
    // confirms or cancels, so an approve/deny can't fire on a stray keypress.
    if app.confirm.is_some() {
        match code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => app.confirm_action(),
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => app.cancel_action(),
            _ => {}
        }
        return;
    }
    match code {
        KeyCode::Char('q') | KeyCode::Esc => app.running = false,
        // On a provider's Security tab, Tab switches focus between the two panels
        // (pending CSRs / originators) instead of cycling top-level tabs.
        KeyCode::Tab if app.tab == app::Tab::Security && app.snapshot.pending_csrs.is_some() => {
            app.toggle_security_focus()
        }
        KeyCode::Right | KeyCode::Tab | KeyCode::Char('l') => app.tab = app.tab.next(),
        KeyCode::Left | KeyCode::BackTab | KeyCode::Char('h') => app.tab = app.tab.prev(),
        KeyCode::Char('1') => app.tab = app::Tab::Overview,
        KeyCode::Char('2') => app.tab = app::Tab::Routing,
        KeyCode::Char('3') => app.tab = app::Tab::LinkQuality,
        KeyCode::Char('4') => app.tab = app::Tab::OgmSchedule,
        KeyCode::Char('5') => app.tab = app::Tab::Metrics,
        KeyCode::Char('6') => app.tab = app::Tab::Security,
        KeyCode::Down | KeyCode::Char('j') => app.move_selection(1),
        KeyCode::Up | KeyCode::Char('k') => app.move_selection(-1),
        // Provider Security tab: approve/deny the selected pending CSR (CSR panel
        // focused) or revoke the selected originator (originator panel focused).
        // Each opens a confirmation popup; all inert elsewhere.
        KeyCode::Char('a') => app.request_csr_action(true),
        KeyCode::Char('d') => app.request_csr_action(false),
        KeyCode::Char('x') => app.request_revoke(),
        // 'r' just forces the next loop iteration; the timer drives refreshes,
        // but pressing it makes the intent explicit and wakes the select.
        KeyCode::Char('r') => {}
        _ => {}
    }
}

/// Refresh the data snapshot, (re)connecting as needed. Records any failure in
/// `app.last_error` and drops the connection so the next tick reconnects.
async fn refresh(client: &mut Option<Client>, addr: SocketAddr, app: &mut App) {
    if client.is_none() {
        match Client::connect(&ConnectTarget::Tcp(addr)).await {
            Ok(c) => *client = Some(c),
            Err(e) => {
                app.connected = false;
                app.last_error = Some(format!("connect: {e}"));
                return;
            }
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "the branch above just set client to Some(_) whenever it was None"
    )]
    let conn = client.as_mut().expect("client connected above");

    match fetch(conn, app).await {
        Ok(()) => {
            app.connected = true;
            app.last_error = None;
            app.last_update = Some(Instant::now());
            app.record_throughput();
            ensure_selection(app);
        }
        Err(e) => {
            app.connected = false;
            app.last_error = Some(e.to_string());
            *client = None; // force reconnect next tick
        }
    }
}

/// Execute a queued approve/deny action against the connected provider node,
/// then refresh so the resolved CSR leaves the pending panel.  Records any
/// failure in `app.last_error`.
async fn act(client: &mut Option<Client>, addr: SocketAddr, app: &mut App) {
    let Some(action) = app.pending_action.take() else {
        return;
    };
    if client.is_none() {
        match Client::connect(&ConnectTarget::Tcp(addr)).await {
            Ok(c) => *client = Some(c),
            Err(e) => {
                app.connected = false;
                app.last_error = Some(format!("connect: {e}"));
                return;
            }
        }
    }

    let result = {
        #[expect(
            clippy::expect_used,
            reason = "the branch above just set client to Some(_) whenever it was None"
        )]
        let conn = client.as_mut().expect("client connected above");
        match &action {
            app::OperatorAction::ApproveCsr(mac) => conn.approve_csr(mac).await,
            app::OperatorAction::DenyCsr(mac) => conn.deny_csr(mac).await,
            app::OperatorAction::RevokeNode(mac) => conn.revoke_node(mac).await,
        }
    };

    match result {
        // Re-fetch immediately so the approved/denied CSR drops out of the panel
        // rather than lingering until the next tick.
        Ok(()) => {
            app.last_error = None;
            refresh(client, addr, app).await;
        }
        Err(e) => {
            app.last_error = Some(format!("CSR action failed: {e}"));
            *client = None; // force reconnect next tick
        }
    }
}

/// Issue all three queries and fold the results into the snapshot.
async fn fetch(conn: &mut Client, app: &mut App) -> anyhow::Result<()> {
    app.snapshot.node_info = Some(conn.node_info().await?);
    app.snapshot.routing = conn.routing_table().await?;
    app.snapshot.link_quality = conn.link_quality_table().await?;
    app.snapshot.ogm_schedule = conn.ogm_schedule().await?;
    app.snapshot.throughput = conn.throughput().await?;
    app.snapshot.metrics = Some(conn.node_metrics().await?);
    app.snapshot.security = Some(conn.security_status().await?);
    // Provider-only: a node that is not a certificate-authority provider errors
    // these RPCs — treat that as "no provider data" rather than a fetch failure,
    // so the rest of the snapshot still refreshes against a non-provider node.
    app.snapshot.pending_csrs = conn.list_pending_csrs().await.ok();
    Ok(())
}

/// Seed table selections once data exists, and clamp them if rows shrank.
fn ensure_selection(app: &mut App) {
    let routes = app.snapshot.routing.entries.len();
    match app.routing_state.selected() {
        Some(i) if i >= routes => app.routing_state.select(routes.checked_sub(1)),
        None if routes > 0 => app.routing_state.select(Some(0)),
        _ => {}
    }

    let links = app.snapshot.link_quality.entries.len();
    match app.link_state.selected() {
        Some(i) if i >= links => app.link_state.select(links.checked_sub(1)),
        None if links > 0 => app.link_state.select(Some(0)),
        _ => {}
    }

    let scheds = app.snapshot.ogm_schedule.entries.len();
    match app.ogm_state.selected() {
        Some(i) if i >= scheds => app.ogm_state.select(scheds.checked_sub(1)),
        None if scheds > 0 => app.ogm_state.select(Some(0)),
        _ => {}
    }

    let ifaces = app.snapshot.throughput.interfaces.len();
    match app.metrics_state.selected() {
        Some(i) if i >= ifaces => app.metrics_state.select(ifaces.checked_sub(1)),
        None if ifaces > 0 => app.metrics_state.select(Some(0)),
        _ => {}
    }

    let sec_nodes = app.snapshot.security.as_ref().map_or(0, |s| s.nodes.len());
    match app.security_state.selected() {
        Some(i) if i >= sec_nodes => app.security_state.select(sec_nodes.checked_sub(1)),
        None if sec_nodes > 0 => app.security_state.select(Some(0)),
        _ => {}
    }

    let pending = app
        .snapshot
        .pending_csrs
        .as_ref()
        .map_or(0, |p| p.pending.len());
    match app.csr_state.selected() {
        Some(i) if i >= pending => app.csr_state.select(pending.checked_sub(1)),
        None if pending > 0 => app.csr_state.select(Some(0)),
        _ => {}
    }
}
