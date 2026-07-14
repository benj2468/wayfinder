//! Integration tests for `rylr998-cli`'s command dispatch — driven against
//! `rylr998-sim`'s in-process AT-command simulator, so a subcommand's mapping
//! onto the right `RylrClient` call (and arguments) can be verified without
//! real hardware.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, RwLock};
use std::time::Duration;

use embedded_io_adapters::tokio_1::FromTokio;
use rylr998::RylrClient;
use rylr998_cli::{
    BandwidthArg, CodingRateArg, Command, SpreadingFactorArg, WirelessModeArg, run_command,
};
use rylr998_sim::{NodeState, RylrSimulator, TestClient, make_pair};
use tokio::sync::mpsc;

/// Wrap a future in a timeout so a stuck dispatch doesn't hang the suite.
macro_rules! timed {
    ($fut:expr) => {
        tokio::time::timeout(Duration::from_secs(2), $fut)
            .await
            .expect("operation timed out")
    };
}

/// Build a client/simulator pair, keeping direct access to the simulator's
/// `NodeState` (not exposed by `rylr998_sim::make_pair`) so setter commands
/// can be asserted against.
fn make_pair_with_state() -> (TestClient, Arc<RwLock<NodeState>>) {
    let (client_stream, sim_stream) = tokio::io::duplex(4096);
    let client = RylrClient::new(FromTokio::new(client_stream)).unwrap();
    let (sim, _handle) = RylrSimulator::new(sim_stream);
    let state = Arc::clone(&sim.state);
    tokio::spawn(sim.run());
    (client, state)
}

#[tokio::test]
async fn ping_succeeds_against_simulator() {
    let (mut client, _h, _t) = make_pair();
    timed!(run_command(&mut client, &Command::Ping)).expect("ping failed");
}

#[tokio::test]
async fn reset_succeeds_against_simulator() {
    let (mut client, _h, _t) = make_pair();
    timed!(run_command(&mut client, &Command::Reset)).expect("reset failed");
}

#[tokio::test]
async fn module_id_succeeds_against_simulator() {
    let (mut client, _h, _t) = make_pair();
    timed!(run_command(&mut client, &Command::ModuleId)).expect("module-id failed");
}

#[tokio::test]
async fn set_mode_reaches_the_module() {
    let (mut client, state) = make_pair_with_state();
    timed!(run_command(
        &mut client,
        &Command::SetMode {
            mode: WirelessModeArg::Sleep,
        }
    ))
    .expect("set-mode failed");
    assert_eq!(state.read().unwrap().mode, 1);
}

#[tokio::test]
async fn set_address_reaches_the_module() {
    let (mut client, state) = make_pair_with_state();
    timed!(run_command(
        &mut client,
        &Command::SetAddress { address: 77 }
    ))
    .expect("set-address failed");
    assert_eq!(state.read().unwrap().address, 77);
}

#[tokio::test]
async fn set_network_id_reaches_the_module() {
    let (mut client, state) = make_pair_with_state();
    timed!(run_command(
        &mut client,
        &Command::SetNetworkId { network_id: 9 }
    ))
    .expect("set-network-id failed");
    assert_eq!(state.read().unwrap().network_id, 9);
}

#[tokio::test]
async fn set_rf_frequency_reaches_the_module() {
    let (mut client, state) = make_pair_with_state();
    timed!(run_command(
        &mut client,
        &Command::SetRfFrequency {
            frequency_hz: 915_000_000,
            remember: false,
        }
    ))
    .expect("set-rf-frequency failed");
    assert_eq!(state.read().unwrap().frequency, 915_000_000);
}

#[tokio::test]
async fn set_parameters_reaches_the_module() {
    let (mut client, state) = make_pair_with_state();
    timed!(run_command(
        &mut client,
        &Command::SetParameters {
            spreading_factor: SpreadingFactorArg::Sf9,
            bandwidth: BandwidthArg::Khz250,
            coding_rate: CodingRateArg::Cr47,
            preamble: 12,
        }
    ))
    .expect("set-parameters failed");
    let s = state.read().unwrap();
    assert_eq!(s.spreading_factor, 9);
    assert_eq!(s.bandwidth, 8);
    assert_eq!(s.coding_rate, 3);
    assert_eq!(s.preamble, 12);
}

#[tokio::test]
async fn send_transmits_the_given_target_and_payload() {
    let (client_stream, sim_stream) = tokio::io::duplex(4096);
    let mut client = RylrClient::new(FromTokio::new(client_stream)).unwrap();
    let (mut sim, _handle) = RylrSimulator::new(sim_stream);
    let (tx, mut rx) = mpsc::channel(4);
    sim.outbound_tx = Some(tx);
    tokio::spawn(sim.run());

    timed!(run_command(
        &mut client,
        &Command::Send {
            target_address: 51,
            data: "HELLO".to_string(),
        }
    ))
    .expect("send failed");

    let sent = timed!(rx.recv()).expect("no packet observed on the simulated air");
    assert_eq!(sent.target_address, 51);
    assert_eq!(sent.data, "HELLO");
}

#[tokio::test]
async fn listen_stops_after_the_requested_count() {
    let (mut client, handle, _t) = make_pair();
    handle.inject_rcv(51, "one", -40, 8).await;
    handle.inject_rcv(52, "two", -41, 9).await;

    timed!(run_command(
        &mut client,
        &Command::Listen { count: Some(2) }
    ))
    .expect("listen failed");
}
