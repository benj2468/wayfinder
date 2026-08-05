//! A terminal dashboard for a running Wayfinder node.
//!
//! Connects to a node's management API — over its authenticated TLS transport,
//! or an embedded node's unauthenticated serial link (`--serial`) — and polls
//! it on a fixed interval, presenting node info, the BATMAN routing table, and
//! per-link state across several tabs. The Links tab additionally lets an
//! operator toggle a selected interface's participation gates in place.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use clap::Parser;
use ratatui::crossterm::event::Event;
use ratatui::crossterm::event::KeyCode;
use ratatui::crossterm::event::KeyEventKind;
use ratatui::crossterm::event::{self};
use tokio::sync::mpsc;

use wayfinder_client::Client;
use wayfinder_client::Endpoint;
use wayfinder_tui::app::App;
use wayfinder_tui::app::{self};
use wayfinder_tui::persist;
use wayfinder_tui::ui;

/// Command-line arguments.
#[derive(Parser, Debug)]
#[command(about = "Terminal dashboard for the Wayfinder management API")]
struct Args {
    /// TLS address of the node's management API (`ServerConfig::Tls` in the
    /// node config).
    #[arg(long, default_value = "127.0.0.1:7700")]
    addr: SocketAddr,

    /// Path to this client's 32-byte Ed25519 identity seed (secret), presented
    /// as an RFC 7250 raw public key in the TLS handshake. To bootstrap an
    /// un-enrolled node, point this at the node's own identity seed and omit
    /// `--cert`. Required unless `--serial` is used.
    #[arg(
        long,
        env = "WAYFINDER_TUI_IDENTITY",
        default_value = "/var/lib/wayfinder/identity.seed"
    )]
    identity: Option<PathBuf>,

    /// Serial port of an embedded node's *unauthenticated* management API (e.g.
    /// `/dev/ttyACMX` for an nRF52840 over its USB CDC-ACM management port),
    /// and the connection carries no TLS or authentication. `--identity`/`--cert`/
    /// `--node-key` cannot be combined with this (clap rejects it, since they'd
    /// imply a TLS handshake this transport never performs); `--addr` is simply
    /// unused.
    #[arg(long, conflicts_with_all = ["identity", "cert", "node_key"])]
    serial: Option<String>,

    /// Baud rate for `--serial`. The nRF52840 firmware's management port is
    /// USB CDC-ACM, not a real UART, so this is a formality `tokio_serial`
    /// requires to open the port rather than a rate the device enforces —
    /// any value opens it identically.
    #[arg(long, default_value_t = 115_200)]
    baud: u32,

    /// Path to this client's membership certificate. Omit to bootstrap an
    /// un-enrolled node (authenticate by proving the node's own key).
    #[arg(long, env = "WAYFINDER_TUI_CERT")]
    cert: Option<PathBuf>,

    /// The node's Ed25519 public key (64 hex chars) to pin. When omitted it
    /// defaults to the public key of `--identity` (the self-key bootstrap case);
    /// pass it explicitly to reach a *different* node.
    #[arg(long, env = "WAYFINDER_TUI_NODE_KEY")]
    node_key: Option<String>,

    /// Refresh interval in milliseconds.
    #[arg(long, default_value_t = 1000)]
    interval: u64,
}

/// How the TUI reaches the node: either the authenticated TLS endpoint or an
/// embedded node's unauthenticated serial port.
enum ConnectTarget {
    /// The node's TLS management API, with the pinned key and client identity.
    Tls(Endpoint),
    /// A serial port opened at a fixed baud rate (no TLS, no authentication).
    Serial {
        /// The serial device path (e.g. `/dev/ttyACMX` for an nRF52840's USB
        /// CDC-ACM management port).
        path: String,
        /// The baud rate to open it at.
        baud: u32,
    },
}

impl ConnectTarget {
    /// Open a fresh [`Client`] over this target.
    async fn connect(&self) -> anyhow::Result<Client> {
        match self {
            ConnectTarget::Tls(endpoint) => {
                Client::connect_tls(endpoint.addr, &endpoint.node_key, &endpoint.identity).await
            }
            ConnectTarget::Serial { path, baud } => Client::connect_serial(path, *baud).await,
        }
    }

    /// A short human-readable label for the status pane.
    fn label(&self) -> String {
        match self {
            ConnectTarget::Tls(endpoint) => endpoint.addr.to_string(),
            ConnectTarget::Serial { path, baud } => format!("{path} @ {baud} baud"),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let target = match &args.serial {
        Some(path) => ConnectTarget::Serial {
            path: path.clone(),
            baud: args.baud,
        },
        None => {
            // clap's `required_unless_present = "serial"` guarantees this branch
            // has an identity, but surface a clear error rather than unwrap.
            let identity = args.identity.as_deref().ok_or_else(|| {
                anyhow::anyhow!("--identity is required unless --serial is given")
            })?;
            ConnectTarget::Tls(Endpoint::load(
                args.addr,
                identity,
                args.cert.as_deref(),
                args.node_key.as_deref(),
            )?)
        }
    };

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

    let mut features = wayfinder_protos::wayfinder_v1alpha::LinkFeatures {
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

/// Issue all three queries and fold the results into the snapshot.
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

    // Polled every tick regardless of which tab is showing, so switching to the
    // Logs tab presents the history that accumulated while it was hidden rather
    // than starting from blank.
    let batch = conn.logs(app.logs.next_seq, LOG_BATCH).await?;
    app.ingest_logs(batch);
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
