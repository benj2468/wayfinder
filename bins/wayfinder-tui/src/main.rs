//! A terminal dashboard for a running Wayfinder node.
//!
//! Connects to a node's management API — over its authenticated TLS transport,
//! or an embedded node's unauthenticated serial link (`--serial`) — and polls
//! it on a fixed interval, presenting node info, the BATMAN routing table, and
//! per-link state across several tabs. The Links tab additionally lets an
//! operator toggle a selected interface's participation gates in place.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::time::Duration;
use std::time::Instant;

use clap::Parser;
use ratatui::crossterm::event::Event;
use ratatui::crossterm::event::KeyCode;
use ratatui::crossterm::event::KeyEventKind;
use ratatui::crossterm::event::{self};
use tokio::sync::mpsc;

use wayfinder_client::Client;
use wayfinder_client::ConnectArgs;
use wayfinder_client::ConnectTarget;
use wayfinder_client::ServerError;
use wayfinder_tui::app::App;
use wayfinder_tui::app::{self};
use wayfinder_tui::persist;
use wayfinder_tui::ui;

/// Command-line arguments.
///
/// Everything about *reaching* the node comes from [`ConnectArgs`], shared with
/// `wayfinderctl` so both clients take the same flags and defaults; only the
/// refresh interval below is the dashboard's own.
//
// `long_about = None` so `--help` prints the one-line `about` rather than this
// doc comment, which is written for a reader of the source.
#[derive(Parser, Debug)]
#[command(
    about = "Terminal dashboard for the Wayfinder management API",
    long_about = None
)]
struct Args {
    /// How to reach the node: address, credentials, or a serial port.
    #[command(flatten)]
    connection: ConnectArgs,

    /// Refresh interval in milliseconds.
    #[arg(long, default_value_t = 1000)]
    interval: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    // `resolve_target` rather than `target`: it is the same resolution plus
    // the one step that cannot be done from disk — fetching the certificate
    // from the node named by `--cert-from`, when one is named.
    let target = args.connection.resolve_target().await?;

    let mut terminal = ratatui::init();
    let result = run(&mut terminal, args, target).await;
    ratatui::restore();
    result
}

/// The main draw / event / refresh loop. Returns when the user quits.
async fn run(
    terminal: &mut ratatui::DefaultTerminal,
    args: Args,
    target: ConnectTarget,
) -> anyhow::Result<()> {
    let mut app = App::new(target.label(), args.interval);

    // Restore the throughput history from a previous session so the Metrics tab
    // chart continues its trend rather than starting blank. Samples keep their
    // capture times, so they resume at their true age on the chart's timeline
    // and anything older than the chart's window is dropped outright.
    app.throughput_history = persist::load(app.throughput_window_ms());

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
                refresh(&mut client, &target, &mut app).await;
            }
            ev = input_rx.recv() => {
                match ev {
                    Some(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                        handle_key(&mut app, key.code);
                        // A key may have queued an approve/deny; execute it now,
                        // since only this loop owns the client.
                        if app.pending_action.is_some() {
                            act(&mut client, &target, &mut app).await;
                        }
                        // Likewise a Links-tab gate toggle, applied immediately.
                        if app.pending_link_feature_toggle.is_some() {
                            act_link_feature(&mut client, &target, &mut app).await;
                        }
                        // Likewise a submitted log filter.
                        if app.logs.pending_filter.is_some() {
                            act_log_filter(&mut client, &target, &mut app).await;
                        }
                        // And a ping queued from the Routing tab, or a cancel
                        // for the one already running.
                        if app.pending_ping.is_some() {
                            act_ping(&mut client, &target, &mut app).await;
                        }
                        if app.pending_ping_cancel.is_some() {
                            act_ping_cancel(&mut client, &target, &mut app).await;
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

/// Lines a PageUp/PageDown moves the log view.
///
/// A fixed step rather than the viewport height, which the synchronous key
/// handler has no way to know — only rendering sees the terminal size.
const LOG_PAGE: isize = 20;

/// Records requested per log poll.
///
/// Comfortably above what a node emits between refresh ticks at any sane filter,
/// so a steady stream is kept up with in one round trip; a burst that exceeds it
/// is simply collected over the next few ticks, in order, with no loss (the
/// node's resume point is per-client).
const LOG_BATCH: u32 = 256;

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
    // The filter editor is modal for the same reason the confirmation popup is:
    // every printable key belongs to the buffer, so 'q' must type a 'q' rather
    // than quit the TUI out from under someone mid-word.
    if app.logs.editing.is_some() {
        match code {
            KeyCode::Enter => app.submit_filter_edit(),
            KeyCode::Esc => app.cancel_filter_edit(),
            KeyCode::Backspace => app.pop_filter_char(),
            KeyCode::Char(c) => app.push_filter_char(c),
            _ => {}
        }
        return;
    }

    // Logs-tab keys that would otherwise collide with global bindings: 'f'
    // opens the filter editor, and the paging/home/end keys scroll rather than
    // doing nothing.
    if app.tab == app::Tab::Logs {
        match code {
            KeyCode::Char('f') => {
                app.begin_filter_edit();
                return;
            }
            KeyCode::Char('G') | KeyCode::End => {
                app.scroll_logs_to_end();
                return;
            }
            KeyCode::Home => {
                app.scroll_logs_to_start();
                return;
            }
            KeyCode::PageUp => {
                app.scroll_logs(-LOG_PAGE);
                return;
            }
            KeyCode::PageDown => {
                app.scroll_logs(LOG_PAGE);
                return;
            }
            _ => {}
        }
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
        KeyCode::Char('4') => app.tab = app::Tab::Links,
        KeyCode::Char('5') => app.tab = app::Tab::Metrics,
        KeyCode::Char('6') => app.tab = app::Tab::Security,
        KeyCode::Char('7') => app.tab = app::Tab::Logs,
        KeyCode::Down | KeyCode::Char('j') => app.move_selection(1),
        KeyCode::Up | KeyCode::Char('k') => app.move_selection(-1),
        // Provider Security tab: approve/deny the selected pending CSR (CSR panel
        // focused) or revoke the selected originator (originator panel focused).
        // Each opens a confirmation popup; all inert elsewhere.
        KeyCode::Char('a') => app.request_csr_action(true),
        KeyCode::Char('d') => app.request_csr_action(false),
        KeyCode::Char('x') => app.request_revoke(),
        // Links tab: toggle one of the selected interface's four participation
        // gates, applied immediately (no confirmation) — o/p pair the OGM
        // tx/rx gates, t/u pair the data tx/rx gates. Inert off the Links tab
        // or without a selection (checked inside `toggle_link_feature`).
        KeyCode::Char('o') => app.toggle_link_feature(app::LinkFeatureGate::TxOgm),
        // Routing tab: ping the selected originator — "the table believes this
        // path exists; does it work?" — started immediately, like the gate
        // toggles and for the same reason. `p` is the Links tab's rx-OGM
        // toggle below; the two cannot collide, since each is a no-op off its
        // own tab, but the guard says so rather than leaving it to be
        // rediscovered by whoever next reads this list.
        KeyCode::Char('p') if app.tab == app::Tab::Routing => app.start_ping(),
        // And stop it. The node owns the session, so leaving the panel — or the
        // dashboard — does not end it; without a key for this an operator can
        // start a run they cannot call off.
        KeyCode::Char('c') if app.tab == app::Tab::Routing => app.cancel_ping(),
        KeyCode::Char('p') => app.toggle_link_feature(app::LinkFeatureGate::RxOgm),
        KeyCode::Char('t') => app.toggle_link_feature(app::LinkFeatureGate::TxData),
        KeyCode::Char('u') => app.toggle_link_feature(app::LinkFeatureGate::RxData),
        // 'r' just forces the next loop iteration; the timer drives refreshes,
        // but pressing it makes the intent explicit and wakes the select.
        KeyCode::Char('r') => {}
        _ => {}
    }
}

/// Refresh the data snapshot, (re)connecting as needed. Records any failure in
/// `app.last_error` and drops the connection so the next tick reconnects.
async fn refresh(client: &mut Option<Client>, target: &ConnectTarget, app: &mut App) {
    if client.is_none() {
        match target.connect().await {
            Ok(c) => {
                // A new connection may carry a different credential, so what
                // the last one was refused says nothing about this one.
                app.logs.reset_for_new_connection();
                *client = Some(c);
            }
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
async fn act(client: &mut Option<Client>, target: &ConnectTarget, app: &mut App) {
    let Some(action) = app.pending_action.take() else {
        return;
    };
    if client.is_none() {
        match target.connect().await {
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
            refresh(client, target, app).await;
        }
        Err(e) => {
            app.last_error = Some(format!("CSR action failed: {e}"));
            *client = None; // force reconnect next tick
        }
    }
}

/// Send a submitted log filter to the connected node and record the spec it
/// reports back as in force.
///
/// A node that rejects the spec answers with an error, which lands in
/// `app.last_error` while `app.logs.filter` keeps showing what is *actually*
/// applied — the operator sees both what they tried and what is still running,
/// rather than a filter line that lies about a rejected edit.
async fn act_log_filter(client: &mut Option<Client>, target: &ConnectTarget, app: &mut App) {
    let Some(directives) = app.logs.pending_filter.take() else {
        return;
    };
    if client.is_none() {
        match target.connect().await {
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
        conn.set_log_level(&directives).await
    };

    match result {
        Ok(effective) => {
            app.logs.filter = effective;
            app.last_error = None;
        }
        // Not a connection failure — a rejected spec is a well-formed error
        // response — so the client is deliberately left connected.
        Err(e) => app.last_error = Some(format!("set log level: {e}")),
    }
}

/// Execute a queued Links-tab gate toggle against the connected node, then
/// refresh so the new state shows immediately rather than waiting for the
/// next tick.  Records any failure in `app.last_error`.
async fn act_link_feature(client: &mut Option<Client>, target: &ConnectTarget, app: &mut App) {
    let Some(toggle) = app.pending_link_feature_toggle.take() else {
        return;
    };
    if client.is_none() {
        match target.connect().await {
            Ok(c) => *client = Some(c),
            Err(e) => {
                app.connected = false;
                app.last_error = Some(format!("connect: {e}"));
                return;
            }
        }
    }

    let mut features = wayfinder_protos::wayfinder::v1alpha::LinkFeatures {
        iface_idx: toggle.iface_idx,
        ..Default::default()
    };
    match toggle.gate {
        app::LinkFeatureGate::TxOgm => features.tx_ogm = Some(toggle.new_value),
        app::LinkFeatureGate::RxOgm => features.rx_ogm = Some(toggle.new_value),
        app::LinkFeatureGate::TxData => features.tx_data = Some(toggle.new_value),
        app::LinkFeatureGate::RxData => features.rx_data = Some(toggle.new_value),
    }

    let result = {
        #[expect(
            clippy::expect_used,
            reason = "the branch above just set client to Some(_) whenever it was None"
        )]
        let conn = client.as_mut().expect("client connected above");
        conn.set_link_features(features).await
    };

    match result {
        Ok(()) => {
            app.last_error = None;
            refresh(client, target, app).await;
        }
        Err(e) => {
            app.last_error = Some(format!("link feature toggle failed: {e}"));
            *client = None; // force reconnect next tick
        }
    }
}

/// Start the ping queued by the Routing tab's `p`, keeping the handle the node
/// issues so [`fetch`] can poll it.
///
/// The node runs the session; this only starts it and remembers the handle.
/// Starting one displaces whatever session the node was running — including one
/// this client started against a different target — so the previous view is
/// dropped outright rather than left to look live.
async fn act_ping(client: &mut Option<Client>, target: &ConnectTarget, app: &mut App) {
    let Some(destination) = app.pending_ping.take() else {
        return;
    };
    if client.is_none() {
        match target.connect().await {
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
        // Zeros throughout: the node owns the defaults, and a dashboard that
        // substituted its own would be answering a question the node has
        // already answered — and answering it differently on every client.
        conn.ping(destination.clone(), 0, 0, 0, 0).await
    };

    match result {
        Ok(started) => {
            app.last_error = None;
            app.ping = Some(app::PingView {
                session_seq: started.session_seq,
                destination,
                session: None,
                displaced: false,
                error: None,
            });
            refresh(client, target, app).await;
        }
        Err(e) => {
            app.last_error = Some(format!("ping failed: {e}"));
            *client = None; // force reconnect next tick
        }
    }
}

/// Stop the session queued by the Routing tab's `c`.
///
/// Failure is reported in the ping panel rather than as `last_error`, for the
/// same reason the status poll is: this is a diagnostic the operator opted
/// into, and it must not be able to report the node as disconnected or freeze
/// the tabs beside it.
async fn act_ping_cancel(client: &mut Option<Client>, target: &ConnectTarget, app: &mut App) {
    let Some(session_seq) = app.pending_ping_cancel.take() else {
        return;
    };
    if client.is_none() {
        match target.connect().await {
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
        conn.cancel_ping(session_seq).await
    };

    match result {
        Ok(cancelled) => {
            // Only if the view is still the one that was cancelled: the
            // operator may have started a fresh session in the meantime, and
            // overwriting it with the stopped one's final state would show a
            // running ping as finished.
            if let Some(view) = app.ping.as_mut()
                && view.session_seq == session_seq
            {
                view.error = None;
                match cancelled.session {
                    Some(session) => view.session = Some(session),
                    None => view.displaced = true,
                }
            }
        }
        Err(e) => {
            if let Some(view) = app.ping.as_mut() {
                view.error = Some(format!("cancel failed: {e}"));
            }
        }
    }
}

/// Issue every query the dashboard needs and fold the results into the
/// snapshot.
async fn fetch(conn: &mut Client, app: &mut App) -> anyhow::Result<()> {
    app.snapshot.node_info = Some(conn.node_info().await?);
    app.snapshot.routing = conn.routing_table().await?;
    app.snapshot.link_quality = conn.link_quality_table().await?;
    app.snapshot.link_features = conn.link_features_table().await?;
    app.snapshot.keepalive = conn.keepalive_table().await?;
    app.snapshot.ogm_schedule = conn.ogm_schedule().await?;
    app.snapshot.throughput = conn.throughput().await?;
    app.snapshot.metrics = Some(conn.node_metrics().await?);
    app.snapshot.security = Some(conn.security_status().await?);
    // Provider-only: a node that is not a certificate-authority provider errors
    // these RPCs — treat that as "no provider data" rather than a fetch failure,
    // so the rest of the snapshot still refreshes against a non-provider node.
    app.snapshot.pending_csrs = conn.list_pending_csrs().await.ok();
    // Polled every tick like the tables above, and for a stronger reason: the
    // badge that reports it is on screen whichever tab is showing, so a stale
    // board would be a node saying "all normal" from a tab that never asked.
    app.snapshot.alarms = conn.alarms().await?;

    // Poll the ping session this client started, if it still holds one. An
    // unset `session` means the node no longer recognises our handle — another
    // client's ping displaced it, or the node restarted — which is reported as
    // such rather than by clearing the panel: an operator who just watched a
    // run half-finish needs to know it was taken away, not to see it vanish.
    if let Some(view) = app.ping.as_mut()
        && view.needs_poll()
    {
        // Deliberately not `?`. Every other read here aborts the refresh on
        // error, which marks the node disconnected and freezes the remaining
        // tabs — right for the node's own state, wrong for a diagnostic panel
        // an operator opted into. A ping that cannot be read says so in its own
        // pane and leaves the dashboard alone.
        match conn.ping_status(view.session_seq).await {
            Ok(status) => {
                view.error = None;
                match status.session {
                    Some(session) => {
                        view.session = Some(session);
                        view.displaced = false;
                    }
                    None => view.displaced = true,
                }
            }
            Err(e) => view.error = Some(e.to_string()),
        }
    }

    // Polled every tick regardless of which tab is showing, so switching to the
    // Logs tab presents the history that accumulated while it was hidden rather
    // than starting from blank — but only until the node refuses it, after
    // which asking again every second would flood the very ring being read
    // (see `LogView::refused`).
    if !app.logs.refused {
        match conn.logs(app.logs.next_seq, LOG_BATCH).await {
            Ok(batch) => {
                app.logs.error = None;
                app.ingest_logs(batch);
            }
            // A `ServerError` is the node's considered answer on a healthy
            // stream: the frame went out, a reply came back, and it said no.
            // Swallowed rather than propagated for the reason the ping poll
            // above is not `?` — the node serves its log ring to a full grant
            // only, so a viewer-tier credential is refused this one read while
            // every other table on this refresh is fine, and aborting would
            // blank six working tabs over the one that credential was never
            // entitled to.
            //
            // Anything else — a send or recv failure, a decode failure, an
            // empty envelope — means the stream itself is suspect and must take
            // the reconnect every other poll here gets. This is the *last* call
            // in `fetch`, so swallowing a transport failure would have `refresh`
            // report a freshly-stamped, connected node on the strength of a call
            // that never reached it.
            Err(e) => match e.downcast::<ServerError>() {
                Ok(refusal) => {
                    app.logs.error = Some(refusal.to_string());
                    app.logs.refused = true;
                }
                Err(transport) => return Err(transport),
            },
        }
    }
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

    // Bounds are driven by `link_features` (one row per registered
    // interface); `ogm_schedule` is zipped in by iface_idx for display only.
    let links_len = app.snapshot.link_features.entries.len();
    match app.links_state.selected() {
        Some(i) if i >= links_len => app.links_state.select(links_len.checked_sub(1)),
        None if links_len > 0 => app.links_state.select(Some(0)),
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
