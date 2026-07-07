//! In-process RYLR998/RYLR498 AT-command simulator, shared by `rylr998`'s own
//! integration tests and by other crates' end-to-end tests that want to drive
//! a real [`rylr998::RylrClient`] without hardware.
//!
//! [`RylrSimulator`] speaks the module's AT-command protocol over one half of
//! a `tokio::io::DuplexStream`; [`LoraSwitch`] fans `AT+SEND` traffic between
//! several attached simulators the way LoRa's shared broadcast medium would,
//! filtering by network id/frequency/mode and applying per-directed-link
//! signal quality.
//!
//! Kept as its own crate (depending on `rylr998`) rather than a `#[cfg(test)]`
//! module or feature flag on `rylr998` itself, since `rylr998` is deliberately
//! `no_std`-first and shouldn't carry tokio/`DuplexStream` test scaffolding in
//! its dependency graph even behind a flag.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-support crate: panics are the intended failure mode on misuse"
)]

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use embedded_io_adapters::tokio_1::FromTokio;
use rylr998::RylrClient;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// A [`RylrClient`] paired with an in-process [`RylrSimulator`] over a
/// `tokio::io::DuplexStream`.
pub type TestClient = RylrClient<FromTokio<DuplexStream>>;

/// Radio configuration that both the simulator and the [`LoraSwitch`] need to
/// read. Kept behind an `Arc<RwLock<_>>` so the switch can inspect current
/// values while the simulator task updates them as AT commands arrive.
#[derive(Debug, Default, Clone)]
pub struct NodeState {
    /// This node's configured `AT+ADDRESS`.
    pub address: u16,
    /// This node's configured `AT+NETWORKID`.
    pub network_id: u8,
    /// This node's configured RF frequency, in Hz.
    pub frequency: u32,
    /// This node's wireless mode: 0 = Transceiver, 1 = Sleep, 2 = SmartReceiving.
    pub mode: u8,
}

/// A packet emitted by one simulator node's `AT+SEND` command, carrying a
/// snapshot of the sender's configuration at transmit time.
#[derive(Debug, Clone)]
pub struct SentPacket {
    /// The sender's configured `AT+ADDRESS` at transmit time.
    pub source_address: u16,
    /// The `AT+SEND` target address (0 = broadcast).
    pub target_address: u16,
    /// The raw (already hex-encoded, if the caller is using the `link`
    /// feature) data field of the `AT+SEND` command.
    pub data: String,
    /// The sender's configured `AT+NETWORKID` at transmit time.
    pub network_id: u8,
    /// The sender's configured RF frequency at transmit time, in Hz.
    pub frequency: u32,
}

/// Signal quality for a directed link between two nodes.
/// The test runner can update this at any time, enabling future integration
/// with a physics simulation.
#[derive(Debug, Clone, Copy)]
pub struct LinkQuality {
    /// Received signal strength, in dBm.
    pub rssi: i32,
    /// Signal-to-noise ratio, in dB.
    pub snr: i32,
}

impl Default for LinkQuality {
    fn default() -> Self {
        Self { rssi: -60, snr: 10 }
    }
}

/// In-process simulator that accepts AT commands and responds exactly as the
/// real RYLR998/RYLR498 module would.
pub struct RylrSimulator {
    reader: BufReader<tokio::io::ReadHalf<DuplexStream>>,
    writer: tokio::io::WriteHalf<DuplexStream>,
    uid: String,
    /// Milliseconds to wait between +RESET and +READY (simulates reboot).
    pub reset_delay_ms: u64,
    /// When `Some(code)`, every command returns `+ERR=<code>` instead of the
    /// normal response. Useful for error-handling tests.
    pub force_error: Option<i32>,
    /// Inject arbitrary lines (e.g. `+RCV=…`) into the byte stream at any time.
    inject_rx: mpsc::Receiver<String>,
    /// Current radio configuration; shared with the [`LoraSwitch`] that owns
    /// this node (if attached).
    pub state: Arc<RwLock<NodeState>>,
    /// If attached to a [`LoraSwitch`], outbound packets are forwarded here for
    /// the switch to route. `None` when running standalone.
    pub outbound_tx: Option<mpsc::Sender<SentPacket>>,
}

/// Cloneable handle returned alongside [`RylrSimulator::new`].
#[derive(Clone)]
pub struct SimulatorHandle {
    inject_tx: mpsc::Sender<String>,
}

impl SimulatorHandle {
    /// Push a fully-formed `+RCV=` line into the simulator's output stream.
    pub async fn inject_rcv(&self, addr: u16, data: &str, rssi: i32, snr: i32) {
        let line = format!("+RCV={},{},{},{},{}\r\n", addr, data.len(), data, rssi, snr);
        self.inject_tx.send(line).await.unwrap();
    }

    /// Push any raw line (without CRLF – the method appends it).
    pub async fn inject_line(&self, line: &str) {
        self.inject_tx.send(format!("{}\r\n", line)).await.unwrap();
    }
}

impl RylrSimulator {
    /// Build a new simulator over `stream`, returning it alongside a
    /// [`SimulatorHandle`] for out-of-band packet injection.
    pub fn new(stream: DuplexStream) -> (Self, SimulatorHandle) {
        let (reader, writer) = tokio::io::split(stream);
        let (inject_tx, inject_rx) = mpsc::channel(64);
        let sim = Self {
            reader: BufReader::new(reader),
            writer,
            uid: "RYLR998-SIM-001".to_string(),
            reset_delay_ms: 50,
            force_error: None,
            inject_rx,
            state: Arc::new(RwLock::new(NodeState::default())),
            outbound_tx: None,
        };
        (sim, SimulatorHandle { inject_tx })
    }

    async fn send(&mut self, bytes: &str) {
        let _ = self.writer.write_all(bytes.as_bytes()).await;
        let _ = self.writer.flush().await;
    }

    async fn handle_cmd(&mut self, cmd: &str) {
        if let Some(code) = self.force_error {
            self.send(&format!("+ERR={}\r\n", code)).await;
            return;
        }

        if cmd == "AT" {
            self.send("+OK\r\n").await;
        } else if cmd == "AT+RESET" {
            self.send("+RESET\r\n").await;
            tokio::time::sleep(Duration::from_millis(self.reset_delay_ms)).await;
            self.send("+READY\r\n").await;
        } else if cmd == "AT+UID?" {
            self.send(&format!("+UID={}\r\n", self.uid)).await;
        } else if let Some(rest) = cmd.strip_prefix("AT+MODE=") {
            if let Ok(mode) = rest.parse::<u8>() {
                self.state.write().unwrap().mode = mode;
                self.send("+OK\r\n").await;
            } else {
                self.send("+ERR=-1\r\n").await;
            }
        } else if let Some(rest) = cmd.strip_prefix("AT+IPR=") {
            match rest.parse::<u32>() {
                Ok(baud) => self.send(&format!("+IPR={}\r\n", baud)).await,
                Err(_) => self.send("+ERR=-1\r\n").await,
            }
        } else if let Some(rest) = cmd.strip_prefix("AT+BAND=") {
            // Optional `,M` suffix means "save to flash"
            let freq_str = rest.strip_suffix(",M").unwrap_or(rest);
            if let Ok(freq) = freq_str.parse::<u32>() {
                self.state.write().unwrap().frequency = freq;
                self.send("+OK\r\n").await;
            } else {
                self.send("+ERR=-1\r\n").await;
            }
        } else if cmd.starts_with("AT+PARAMETER=") {
            self.send("+OK\r\n").await;
        } else if let Some(rest) = cmd.strip_prefix("AT+ADDRESS=") {
            if let Ok(address) = rest.parse::<u16>() {
                self.state.write().unwrap().address = address;
                self.send("+OK\r\n").await;
            } else {
                self.send("+ERR=-1\r\n").await;
            }
        } else if let Some(rest) = cmd.strip_prefix("AT+NETWORKID=") {
            if let Ok(net_id) = rest.parse::<u8>() {
                self.state.write().unwrap().network_id = net_id;
                self.send("+OK\r\n").await;
            } else {
                self.send("+ERR=-1\r\n").await;
            }
        } else if let Some(rest) = cmd.strip_prefix("AT+CRFOP=") {
            if let Ok(_crfop) = rest.parse::<u8>() {
                self.send("+OK\r\n").await;
            } else {
                self.send("+ERR=-1\r\n").await;
            }
        } else if let Some(rest) = cmd.strip_prefix("AT+SEND=") {
            // AT+SEND=<addr>,<len>,<data>
            let mut parts = rest.splitn(3, ',');
            match (parts.next(), parts.next(), parts.next()) {
                (Some(addr_s), Some(_len_s), Some(data_s)) => match addr_s.parse::<u16>() {
                    Ok(target_address) => {
                        if let Some(tx) = &self.outbound_tx {
                            // Snapshot state while holding the lock, then drop before .await
                            let pkt = {
                                let s = self.state.read().unwrap();
                                SentPacket {
                                    source_address: s.address,
                                    target_address,
                                    data: data_s.to_string(),
                                    network_id: s.network_id,
                                    frequency: s.frequency,
                                }
                            };
                            let _ = tx.try_send(pkt);
                        }
                        self.send("+OK\r\n").await;
                    }
                    Err(_) => self.send("+ERR=-1\r\n").await,
                },
                _ => self.send("+ERR=-1\r\n").await,
            }
        } else {
            self.send("+ERR=-1\r\n").await;
        }
    }

    /// Run the simulator event loop. Exits cleanly when the client drops its
    /// stream half (EOF on `reader`).
    pub async fn run(mut self) {
        let mut line = String::new();
        loop {
            line.clear();
            tokio::select! {
                result = self.reader.read_line(&mut line) => {
                    match result {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            let cmd = line.trim().to_string();
                            if !cmd.is_empty() {
                                self.handle_cmd(&cmd).await;
                            }
                        }
                    }
                }
                Some(msg) = self.inject_rx.recv() => {
                    let _ = self.writer.write_all(msg.as_bytes()).await;
                    let _ = self.writer.flush().await;
                }
            }
        }
    }
}

/// Create a matched `(client, sim_handle, sim_task)` triple, running the
/// simulator standalone (not attached to a [`LoraSwitch`]).
pub fn make_pair() -> (TestClient, SimulatorHandle, JoinHandle<()>) {
    let (client_stream, sim_stream) = tokio::io::duplex(4096);
    let client = RylrClient::new(FromTokio::new(client_stream)).unwrap();
    let (sim, handle) = RylrSimulator::new(sim_stream);
    let task = tokio::spawn(sim.run());
    (client, handle, task)
}

/// Same as [`make_pair`], but every command the simulator receives returns
/// `+ERR=-1`.
pub fn make_error_pair() -> (TestClient, JoinHandle<()>) {
    let (client_stream, sim_stream) = tokio::io::duplex(4096);
    let client = RylrClient::new(FromTokio::new(client_stream)).unwrap();
    let (mut sim, _handle) = RylrSimulator::new(sim_stream);
    sim.force_error = Some(-1);
    let task = tokio::spawn(sim.run());
    (client, task)
}

/// One slot in a [`LoraSwitch`]'s node table.
struct NodeSlot {
    handle: SimulatorHandle,
    state: Arc<RwLock<NodeState>>,
}

/// Simulated LoRa air medium.
///
/// Nodes attached via [`attach`](Self::attach) can only communicate when they
/// share the same `network_id` AND `frequency`. Signal quality (RSSI/SNR) for
/// any directed link can be updated at any time via
/// [`set_link_quality`](Self::set_link_quality), allowing the test runner —
/// or a future physics simulation — to control what each receiver observes.
pub struct LoraSwitch {
    nodes: Vec<NodeSlot>,
    outbound_tx: mpsc::Sender<SentPacket>,
    outbound_rx: mpsc::Receiver<SentPacket>,
    /// Per-directed-link quality, keyed by (from_addr, to_addr).
    link_quality: HashMap<(u16, u16), LinkQuality>,
    /// Used when no specific entry exists for a link.
    default_quality: LinkQuality,
}

impl Default for LoraSwitch {
    fn default() -> Self {
        Self::new()
    }
}

impl LoraSwitch {
    /// Build an empty switch with no attached nodes.
    pub fn new() -> Self {
        let (outbound_tx, outbound_rx) = mpsc::channel(256);
        Self {
            nodes: vec![],
            outbound_tx,
            outbound_rx,
            link_quality: HashMap::new(),
            default_quality: LinkQuality::default(),
        }
    }

    /// Wire `sim` into the switch. The caller retains the [`SimulatorHandle`]
    /// for direct injection in tests; the switch stores its own clone.
    pub fn attach(&mut self, sim: &mut RylrSimulator, handle: SimulatorHandle) {
        sim.outbound_tx = Some(self.outbound_tx.clone());
        self.nodes.push(NodeSlot {
            handle,
            state: Arc::clone(&sim.state),
        });
    }

    /// Override signal quality for one directed link.
    /// Call this any time – even while the switch is running.
    pub fn set_link_quality(&mut self, from_addr: u16, to_addr: u16, quality: LinkQuality) {
        self.link_quality.insert((from_addr, to_addr), quality);
    }

    /// Change the default quality used for links with no explicit entry.
    pub fn set_default_quality(&mut self, quality: LinkQuality) {
        self.default_quality = quality;
    }

    /// Deliver one packet to every eligible receiver.
    async fn route(&mut self, pkt: SentPacket) {
        for slot in &self.nodes {
            // Read all fields we need while holding the lock, then drop it
            // before any await point.
            let (net_id, freq, mode, dest_addr) = {
                let s = slot.state.read().unwrap();
                (s.network_id, s.frequency, s.mode, s.address)
            };

            if net_id != pkt.network_id {
                continue;
            }
            if freq != pkt.frequency {
                continue;
            }
            if mode != 0 {
                continue;
            } // sleep / smart-receiving nodes do not receive
            if dest_addr == pkt.source_address {
                continue;
            } // no self-delivery
            if pkt.target_address != 0 && dest_addr != pkt.target_address {
                continue;
            }

            let quality = self
                .link_quality
                .get(&(pkt.source_address, dest_addr))
                .copied()
                .unwrap_or(self.default_quality);

            slot.handle
                .inject_rcv(pkt.source_address, &pkt.data, quality.rssi, quality.snr)
                .await;
        }
    }

    /// Drain and route every packet queued since the last call.
    /// Useful in tests where the caller controls the dispatch cadence.
    pub async fn tick(&mut self) {
        while let Ok(pkt) = self.outbound_rx.try_recv() {
            self.route(pkt).await;
        }
    }

    /// Run the switch as a background task, blocking until every attached
    /// simulator has been dropped (all senders gone).
    pub async fn run(mut self) {
        while let Some(pkt) = self.outbound_rx.recv().await {
            self.route(pkt).await;
            // Drain any further packets that arrived while routing.
            while let Ok(pkt) = self.outbound_rx.try_recv() {
                self.route(pkt).await;
            }
        }
    }
}

/// Create a fully-configured node attached to `switch` and spawn its sim task.
pub async fn make_node(
    switch: &mut LoraSwitch,
    addr: u16,
    net_id: u8,
    freq: u32,
) -> (TestClient, JoinHandle<()>) {
    let (client_stream, sim_stream) = tokio::io::duplex(4096);
    let mut client = RylrClient::new(FromTokio::new(client_stream)).unwrap();
    let (mut sim, handle) = RylrSimulator::new(sim_stream);
    switch.attach(&mut sim, handle);
    let task = tokio::spawn(sim.run());

    tokio::time::timeout(Duration::from_secs(2), async {
        client.set_address(addr).await?;
        client.set_network_id(net_id).await?;
        client.set_rf_frequency(freq, false).await
    })
    .await
    .expect("node setup timed out")
    .expect("node setup command failed");

    (client, task)
}
