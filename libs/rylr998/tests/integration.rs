//! Integration tests for the RYLR998/RYLR498 LoRa client.
//!
//! Pairs the real `RylrClient` against an in-process simulator that speaks
//! the same AT-command protocol over a `tokio::io::DuplexStream`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use embedded_io_adapters::tokio_1::FromTokio;
use rylr998::{Bandwidth, CodingRate, LoraError, RylrClient, SpreadingFactory, WirelessMode};
use rylr998_sim::{LinkQuality, LoraSwitch, make_error_pair, make_node, make_pair};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Wrap a future in a 2-second timeout so tests never hang silently.
macro_rules! timed {
    ($fut:expr) => {
        tokio::time::timeout(Duration::from_secs(2), $fut)
            .await
            .expect("operation timed out – possible client deadlock")
    };
}

// ─────────────────────────────────────────────
//  Happy-path command tests
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_ping() {
    let (mut client, _h, _t) = make_pair();
    timed!(client.ping()).expect("ping failed");
}

#[tokio::test]
async fn test_reset() {
    let (mut client, _h, _t) = make_pair();
    timed!(client.reset()).expect("reset failed");
}

#[tokio::test]
async fn test_set_mode_transceiver() {
    let (mut client, _h, _t) = make_pair();
    timed!(client.set_mode(WirelessMode::Transceiver)).expect("set_mode failed");
}

#[tokio::test]
async fn test_set_mode_sleep() {
    let (mut client, _h, _t) = make_pair();
    timed!(client.set_mode(WirelessMode::Sleep)).expect("set_mode failed");
}

#[tokio::test]
async fn test_set_mode_smart_receiving() {
    let (mut client, _h, _t) = make_pair();
    timed!(client.set_mode(WirelessMode::SmartReceiving)).expect("set_mode failed");
}

#[tokio::test]
async fn test_set_baud_rate() {
    let (mut client, _h, _t) = make_pair();
    timed!(client.set_baud_rate(115200)).expect("set_baud_rate failed");
}

#[tokio::test]
async fn test_set_rf_frequency() {
    let (mut client, _h, _t) = make_pair();
    timed!(client.set_rf_frequency(915_000_000, false)).expect("set_rf_frequency failed");
}

#[tokio::test]
async fn test_set_rf_frequency_save_to_flash() {
    let (mut client, _h, _t) = make_pair();
    timed!(client.set_rf_frequency(868_000_000, true)).expect("set_rf_frequency (flash) failed");
}

#[tokio::test]
async fn test_set_parameters() {
    let (mut client, _h, _t) = make_pair();
    timed!(client.set_parameters(
        SpreadingFactory::Sf7,
        Bandwidth::Khz125,
        CodingRate::Cr45,
        15,
    ))
    .expect("set_parameters failed");
}

#[tokio::test]
async fn test_set_parameters_all_sf_bw_cr_combos() {
    let (mut client, _h, _t) = make_pair();
    let sfs = [
        SpreadingFactory::Sf5,
        SpreadingFactory::Sf6,
        SpreadingFactory::Sf7,
        SpreadingFactory::Sf8,
        SpreadingFactory::Sf9,
        SpreadingFactory::Sf10,
        SpreadingFactory::Sf11,
    ];
    for sf in sfs {
        timed!(client.set_parameters(sf, Bandwidth::Khz500, CodingRate::Cr48, 12))
            .unwrap_or_else(|_| panic!("set_parameters failed for sf={:?}", sf));
    }
}

#[tokio::test]
async fn test_set_address() {
    let (mut client, _h, _t) = make_pair();
    timed!(client.set_address(42)).expect("set_address failed");
}

#[tokio::test]
async fn test_set_address_max() {
    let (mut client, _h, _t) = make_pair();
    timed!(client.set_address(u16::MAX)).expect("set_address(MAX) failed");
}

#[tokio::test]
async fn test_set_network_id() {
    let (mut client, _h, _t) = make_pair();
    timed!(client.set_network_id(18)).expect("set_network_id failed");
}

#[tokio::test]
async fn test_set_rf_output_power() {
    let (mut client, _h, _t) = make_pair();
    timed!(client.set_rf_output_power(22)).expect("set_rf_output_power failed");
}

#[tokio::test]
async fn test_send_data_unicast() {
    let (mut client, _h, _t) = make_pair();
    timed!(client.send_data(100, "HELLO")).expect("send_data failed");
}

#[tokio::test]
async fn test_send_data_broadcast() {
    // Address 0 is the broadcast address per the RYLR998 spec.
    let (mut client, _h, _t) = make_pair();
    timed!(client.send_data(0, "BROADCAST")).expect("broadcast send_data failed");
}

#[tokio::test]
async fn test_send_data_max_payload() {
    let (mut client, _h, _t) = make_pair();
    let payload = "Z".repeat(240);
    timed!(client.send_data(1, &payload)).expect("max-payload send_data failed");
}

#[tokio::test]
async fn test_query_module_id() {
    let (mut client, _h, _t) = make_pair();
    let uid = timed!(client.query_module_id()).expect("query_module_id failed");
    assert_eq!(uid.as_str(), "RYLR998-SIM-001");
}

// ─────────────────────────────────────────────
//  Error-handling tests
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_error_response_on_ping() {
    let (mut client, _t) = make_error_pair();
    let err = timed!(client.ping()).expect_err("expected error, got Ok");
    assert!(matches!(err, LoraError::ModuleError(_)));
}

#[tokio::test]
async fn test_error_response_on_set_address() {
    let (mut client, _t) = make_error_pair();
    let err = timed!(client.set_address(5)).expect_err("expected error, got Ok");
    assert!(matches!(err, LoraError::ModuleError(_)));
}

#[tokio::test]
async fn test_error_response_on_send_data() {
    let (mut client, _t) = make_error_pair();
    let err = timed!(client.send_data(1, "hi")).expect_err("expected error, got Ok");
    assert!(matches!(err, LoraError::ModuleError(_)));
}

/// The client enforces the 240-byte payload limit before touching the wire.
#[tokio::test]
async fn test_send_oversize_payload_rejected_client_side() {
    let (mut client, _h, _t) = make_pair();
    let oversized = "X".repeat(241);
    let err =
        timed!(client.send_data(1, &oversized)).expect_err("expected payload-too-large error");
    assert!(matches!(err, LoraError::RequestTooLarge));
}

// ─────────────────────────────────────────────
//  listen_for_packet tests
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_listen_for_packet_basic() {
    let (mut client, handle, _t) = make_pair();

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        handle.inject_rcv(42, "hello", -90, -10).await;
    });

    let pkt = timed!(client.listen_for_packet()).expect("listen_for_packet failed");
    assert_eq!(pkt.address, 42);
    assert_eq!(pkt.length, 5);
    assert_eq!(pkt.data.as_str(), "hello");
    assert_eq!(pkt.rssi, -90);
    assert_eq!(pkt.snr, -10);
}

#[tokio::test]
async fn test_listen_for_packet_negative_snr() {
    let (mut client, handle, _t) = make_pair();

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        handle.inject_rcv(7, "data", -120, -20).await;
    });

    let pkt = timed!(client.listen_for_packet()).expect("listen_for_packet failed");
    assert_eq!(pkt.rssi, -120);
    assert_eq!(pkt.snr, -20);
}

#[tokio::test]
async fn test_listen_for_multiple_packets_sequential() {
    let (mut client, handle, _t) = make_pair();

    tokio::spawn(async move {
        for i in 0u16..5 {
            tokio::time::sleep(Duration::from_millis(15)).await;
            handle.inject_rcv(i, "pkt", -80, -5).await;
        }
    });

    for expected_addr in 0u16..5 {
        let pkt = timed!(client.listen_for_packet())
            .unwrap_or_else(|_| panic!("packet {} never arrived", expected_addr));
        assert_eq!(pkt.address, expected_addr);
    }
}

/// `listen_for_packet` must silently discard lines that aren't `+RCV=`
/// and keep waiting.
#[tokio::test]
async fn test_listen_skips_non_rcv_lines() {
    let (mut client, handle, _t) = make_pair();

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        // Inject junk that should be skipped
        handle.inject_line("+OK").await;
        handle.inject_line("+READY").await;
        handle.inject_line("some_garbage").await;
        handle.inject_line("").await; // blank line
        // Then inject the real packet
        handle.inject_rcv(99, "real", -70, -3).await;
    });

    let pkt = timed!(client.listen_for_packet()).expect("listen_for_packet failed");
    assert_eq!(pkt.address, 99);
    assert_eq!(pkt.data.as_str(), "real");
}

/// `listen_for_packet` with a payload that is close to (but within) the
/// `String<256>` line-buffer limit.
#[tokio::test]
async fn test_listen_for_packet_large_payload() {
    let (mut client, handle, _t) = make_pair();
    // With addr=1, len=3 digits, rssi/snr each -4 digits the framing overhead is ~22 chars.
    // 230-char payload keeps us safely under the 256-byte line buffer.
    let big = "B".repeat(230);
    let big_clone = big.clone();

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        handle.inject_rcv(1, &big_clone, -85, -12).await;
    });

    let pkt = timed!(client.listen_for_packet()).expect("listen_for_packet failed");
    assert_eq!(pkt.data.as_str(), big.as_str());
    assert_eq!(pkt.length, 230);
}

// ─────────────────────────────────────────────
//  `expect` loop / response-parsing stress tests
// ─────────────────────────────────────────────

/// The `expect` helper in the client loops until it sees the awaited prefix.
/// Verify it correctly skips irrelevant lines sent before the real response.
#[tokio::test]
async fn test_expect_skips_lines_before_ok() {
    let (client_stream, sim_stream) = tokio::io::duplex(4096);
    let mut client = RylrClient::new(FromTokio::new(client_stream)).unwrap();

    tokio::spawn(async move {
        let (reader, mut writer) = tokio::io::split(sim_stream);
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap(); // consume "AT\r\n"

        // Send several lines the client should ignore before the real +OK
        writer.write_all(b"noise\r\n").await.unwrap();
        writer.write_all(b"+MAYBE=something\r\n").await.unwrap();
        writer.write_all(b"\r\n").await.unwrap(); // blank
        writer.write_all(b"+OK\r\n").await.unwrap();
        writer.flush().await.unwrap();
    });

    timed!(client.ping()).expect("ping should succeed despite preceding noise");
}

/// Same for `AT+RESET`: the client sends the command, waits for `+RESET`,
/// then waits for `+READY`.  Extra lines in between must be ignored.
#[tokio::test]
async fn test_reset_tolerates_noise_between_reset_and_ready() {
    let (client_stream, sim_stream) = tokio::io::duplex(4096);
    let mut client = RylrClient::new(FromTokio::new(client_stream)).unwrap();

    tokio::spawn(async move {
        let (reader, mut writer) = tokio::io::split(sim_stream);
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap(); // consume "AT+RESET\r\n"

        writer.write_all(b"+RESET\r\n").await.unwrap();
        writer.write_all(b"booting...\r\n").await.unwrap();
        writer.write_all(b"+READY\r\n").await.unwrap();
        writer.flush().await.unwrap();
    });

    timed!(client.reset()).expect("reset should succeed despite noise between RESET and READY");
}

/// `set_baud_rate` expects `+IPR=<rate>` – verify the response is parsed
/// correctly for several standard baud rates.
#[tokio::test]
async fn test_set_baud_rate_all_standard_rates() {
    let (mut client, _h, _t) = make_pair();
    for &rate in &[9600u32, 19200, 38400, 57600, 115200, 230400] {
        timed!(client.set_baud_rate(rate))
            .unwrap_or_else(|_| panic!("set_baud_rate({}) failed", rate));
    }
}

// ─────────────────────────────────────────────
//  Line-buffer sizing
// ─────────────────────────────────────────────

/// The line buffer (`LINE_BUF_LEN` in `lib.rs`) must hold a worst-case
/// `+RCV=<addr>,<len>,<data>,<rssi>,<snr>` line: max-width address, a full
/// 240-char `<Data>` field (the module's own maximum), and max-width RSSI/SNR
/// — `+RCV=65535,240,<240 chars>,-130,-20` is ~264 chars. This is exactly the
/// line shape a maximal RYLR998 on-air fragment produces once hex-encoded.
#[tokio::test]
async fn test_listen_for_packet_worst_case_line_length() {
    let (mut client, handle, _t) = make_pair();
    let data = "A".repeat(240);

    tokio::spawn({
        let data = data.clone();
        async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            handle.inject_rcv(65535, &data, -130, -20).await;
        }
    });

    let pkt = timed!(client.listen_for_packet()).expect("worst-case line should be readable");
    assert_eq!(pkt.address, 65535);
    assert_eq!(pkt.data.as_str(), data.as_str());
    assert_eq!(pkt.rssi, -130);
    assert_eq!(pkt.snr, -20);
}

// ─────────────────────────────────────────────
//  Unsolicited-packet interleaving tests
// ─────────────────────────────────────────────

/// An unsolicited `+RCV` line arriving while `expect()` is waiting for a
/// command's `+OK` must not be silently discarded — it must still be
/// deliverable via `listen_for_packet` afterward.
#[tokio::test]
async fn test_rcv_interleaved_during_command_wait_is_not_dropped() {
    let (mut client, handle, _t) = make_pair();

    // Get the `+RCV` line sitting in the stream ahead of the command we're
    // about to send, so `expect("+OK")` reads it first.
    handle.inject_rcv(5, "dead", -50, 7).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    timed!(client.send_data(0, "ab")).expect("send_data failed");

    let pkt = timed!(client.listen_for_packet()).expect("listen_for_packet failed");
    assert_eq!(pkt.address, 5);
    assert_eq!(pkt.data.as_str(), "dead");
    assert_eq!(pkt.rssi, -50);
    assert_eq!(pkt.snr, 7);
}

/// The unsolicited-packet queue is bounded: when more `+RCV` lines arrive
/// during one command wait than fit, the oldest are evicted to make room for
/// the newest, rather than growing unbounded or blocking.
#[tokio::test]
async fn test_rcv_queue_evicts_oldest_when_full() {
    let (mut client, handle, _t) = make_pair();

    // Queue depth is 8 (`RX_QUEUE_DEPTH` in `lib.rs`); inject one more than
    // that so the oldest (address 0) must be evicted.
    for addr in 0u16..9 {
        handle.inject_rcv(addr, &format!("p{addr}"), -60, 5).await;
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    timed!(client.send_data(0, "x")).expect("send_data failed");

    for expected_addr in 1u16..9 {
        let pkt = timed!(client.listen_for_packet())
            .unwrap_or_else(|_| panic!("packet {} never arrived", expected_addr));
        assert_eq!(pkt.address, expected_addr);
    }

    // Address 0 was evicted, not delivered; nothing should be left to read.
    let none_left =
        tokio::time::timeout(Duration::from_millis(100), client.listen_for_packet()).await;
    assert!(
        none_left.is_err(),
        "queue should be drained; address 0 should have been evicted"
    );
}

// ─────────────────────────────────────────────
//  Full-sequence integration tests
// ─────────────────────────────────────────────

/// Execute the typical device-initialization sequence found in the serial
/// example, verifying that every command round-trips cleanly.
#[tokio::test]
async fn test_full_init_sequence() {
    let (mut client, _h, _t) = make_pair();

    tokio::time::timeout(Duration::from_secs(2), async {
        client.reset().await?;
        client.set_address(50).await?;
        client.set_network_id(18).await?;
        client
            .set_parameters(
                SpreadingFactory::Sf7,
                Bandwidth::Khz125,
                CodingRate::Cr48,
                15,
            )
            .await?;
        client.set_rf_frequency(915_000_000, false).await?;
        client.set_rf_output_power(22).await?;
        Ok::<_, LoraError>(())
    })
    .await
    .expect("init sequence timed out")
    .expect("a command in the init sequence failed");
}

/// After a full init sequence, sending data and listening for a reply should
/// both work without any state corruption.
#[tokio::test]
async fn test_send_then_receive() {
    let (mut client, handle, _t) = make_pair();

    // First transmit a packet
    timed!(client.send_data(51, "PING")).expect("send failed");

    // Then arrange for an inbound packet and receive it
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        handle.inject_rcv(51, "PONG", -75, -8).await;
    });

    let pkt = timed!(client.listen_for_packet()).expect("receive failed");
    assert_eq!(pkt.address, 51);
    assert_eq!(pkt.data.as_str(), "PONG");
}

/// Fire many commands in tight succession to shake out any buffering issues.
#[tokio::test]
async fn test_rapid_fire_commands() {
    let (mut client, _h, _t) = make_pair();

    tokio::time::timeout(Duration::from_secs(2), async {
        for i in 0u16..20 {
            client.set_address(i).await?;
        }
        Ok::<_, LoraError>(())
    })
    .await
    .expect("rapid-fire commands timed out")
    .expect("a command failed");
}

// ─────────────────────────────────────────────
//  LoraSwitch tests
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_switch_unicast_delivery() {
    let mut switch = LoraSwitch::new();
    let (mut node_a, _ta) = make_node(&mut switch, 1, 18, 915_000_000).await;
    let (mut node_b, _tb) = make_node(&mut switch, 2, 18, 915_000_000).await;

    timed!(node_a.send_data(2, "hello")).expect("send failed");
    switch.tick().await;

    let pkt = timed!(node_b.listen_for_packet()).expect("receive failed");
    assert_eq!(pkt.address, 1); // source address
    assert_eq!(pkt.data.as_str(), "hello");
}

/// Nodes on different network IDs are invisible to each other.
#[tokio::test]
async fn test_switch_different_network_id_blocked() {
    let mut switch = LoraSwitch::new();
    let (mut node_a, _ta) = make_node(&mut switch, 1, 18, 915_000_000).await;
    let (mut node_b, _tb) = make_node(&mut switch, 2, 99, 915_000_000).await;

    timed!(node_a.send_data(2, "hello")).expect("send failed");
    switch.tick().await;

    let result = tokio::time::timeout(Duration::from_millis(100), node_b.listen_for_packet()).await;
    assert!(
        result.is_err(),
        "packet should be blocked by mismatched network_id"
    );
}

/// Nodes on different RF frequencies cannot hear each other.
#[tokio::test]
async fn test_switch_different_frequency_blocked() {
    let mut switch = LoraSwitch::new();
    let (mut node_a, _ta) = make_node(&mut switch, 1, 18, 915_000_000).await;
    let (mut node_b, _tb) = make_node(&mut switch, 2, 18, 868_000_000).await;

    timed!(node_a.send_data(2, "hello")).expect("send failed");
    switch.tick().await;

    let result = tokio::time::timeout(Duration::from_millis(100), node_b.listen_for_packet()).await;
    assert!(
        result.is_err(),
        "packet should be blocked by mismatched frequency"
    );
}

/// Address 0 is broadcast – all compatible nodes receive it.
#[tokio::test]
async fn test_switch_broadcast_reaches_all() {
    let mut switch = LoraSwitch::new();
    let (mut node_a, _ta) = make_node(&mut switch, 1, 18, 915_000_000).await;
    let (mut node_b, _tb) = make_node(&mut switch, 2, 18, 915_000_000).await;
    let (mut node_c, _tc) = make_node(&mut switch, 3, 18, 915_000_000).await;

    timed!(node_a.send_data(0, "broadcast")).expect("send failed");
    switch.tick().await;

    let pkt_b = timed!(node_b.listen_for_packet()).expect("node_b did not receive broadcast");
    let pkt_c = timed!(node_c.listen_for_packet()).expect("node_c did not receive broadcast");
    assert_eq!(pkt_b.data.as_str(), "broadcast");
    assert_eq!(pkt_c.data.as_str(), "broadcast");
}

/// Broadcast is not delivered to the sender itself.
#[tokio::test]
async fn test_switch_broadcast_not_echoed_to_sender() {
    let mut switch = LoraSwitch::new();
    let (mut node_a, _ta) = make_node(&mut switch, 1, 18, 915_000_000).await;
    let (mut node_b, _tb) = make_node(&mut switch, 2, 18, 915_000_000).await;

    timed!(node_a.send_data(0, "bc")).expect("send failed");
    switch.tick().await;

    // node_b gets it
    timed!(node_b.listen_for_packet()).expect("node_b should receive");
    // node_a should NOT receive its own broadcast
    let self_recv =
        tokio::time::timeout(Duration::from_millis(100), node_a.listen_for_packet()).await;
    assert!(
        self_recv.is_err(),
        "sender should not receive its own broadcast"
    );
}

/// A unicast to address X should not be delivered to a node with address Y.
#[tokio::test]
async fn test_switch_unicast_not_delivered_to_wrong_address() {
    let mut switch = LoraSwitch::new();
    let (mut node_a, _ta) = make_node(&mut switch, 1, 18, 915_000_000).await;
    let (mut node_b, _tb) = make_node(&mut switch, 2, 18, 915_000_000).await;
    let (mut node_c, _tc) = make_node(&mut switch, 3, 18, 915_000_000).await;

    timed!(node_a.send_data(2, "for_b_only")).expect("send failed");
    switch.tick().await;

    timed!(node_b.listen_for_packet()).expect("node_b should receive");
    let to_c = tokio::time::timeout(Duration::from_millis(100), node_c.listen_for_packet()).await;
    assert!(
        to_c.is_err(),
        "node_c should not receive a unicast addressed to node_b"
    );
}

/// Per-link RSSI/SNR set on the switch is what receivers observe.
#[tokio::test]
async fn test_switch_link_quality_applied() {
    let mut switch = LoraSwitch::new();
    let (mut node_a, _ta) = make_node(&mut switch, 1, 18, 915_000_000).await;
    let (mut node_b, _tb) = make_node(&mut switch, 2, 18, 915_000_000).await;

    switch.set_link_quality(
        1,
        2,
        LinkQuality {
            rssi: -112,
            snr: -15,
        },
    );

    timed!(node_a.send_data(2, "quality_test")).expect("send failed");
    switch.tick().await;

    let pkt = timed!(node_b.listen_for_packet()).expect("receive failed");
    assert_eq!(pkt.rssi, -112);
    assert_eq!(pkt.snr, -15);
}

/// Link quality is directional: A→B and B→A can be different.
#[tokio::test]
async fn test_switch_link_quality_is_directional() {
    let mut switch = LoraSwitch::new();
    let (mut node_a, _ta) = make_node(&mut switch, 1, 18, 915_000_000).await;
    let (mut node_b, _tb) = make_node(&mut switch, 2, 18, 915_000_000).await;

    switch.set_link_quality(1, 2, LinkQuality { rssi: -80, snr: 5 });
    switch.set_link_quality(
        2,
        1,
        LinkQuality {
            rssi: -100,
            snr: -8,
        },
    );

    timed!(node_a.send_data(2, "ab")).expect("a→b send failed");
    switch.tick().await;
    let pkt_b = timed!(node_b.listen_for_packet()).expect("b receive failed");
    assert_eq!(pkt_b.rssi, -80);

    timed!(node_b.send_data(1, "ba")).expect("b→a send failed");
    switch.tick().await;
    let pkt_a = timed!(node_a.listen_for_packet()).expect("a receive failed");
    assert_eq!(pkt_a.rssi, -100);
}

/// A node in sleep mode does not receive packets.
#[tokio::test]
async fn test_switch_sleep_mode_does_not_receive() {
    let mut switch = LoraSwitch::new();
    let (mut node_a, _ta) = make_node(&mut switch, 1, 18, 915_000_000).await;
    let (mut node_b, _tb) = make_node(&mut switch, 2, 18, 915_000_000).await;

    timed!(node_b.set_mode(WirelessMode::Sleep)).expect("set_mode failed");

    timed!(node_a.send_data(2, "wake_up")).expect("send failed");
    switch.tick().await;

    let result = tokio::time::timeout(Duration::from_millis(100), node_b.listen_for_packet()).await;
    assert!(result.is_err(), "sleeping node should not receive");
}

/// `LoraSwitch::run()` drives routing automatically as a background task.
#[tokio::test]
async fn test_switch_run_routes_automatically() {
    let mut switch = LoraSwitch::new();
    let (mut node_a, _ta) = make_node(&mut switch, 1, 18, 915_000_000).await;
    let (mut node_b, _tb) = make_node(&mut switch, 2, 18, 915_000_000).await;

    let _switch_task = tokio::spawn(switch.run());

    timed!(node_a.send_data(2, "auto")).expect("send failed");

    let pkt = timed!(node_b.listen_for_packet()).expect("receive failed");
    assert_eq!(pkt.address, 1);
    assert_eq!(pkt.data.as_str(), "auto");
}

/// Verify multi-hop style: A→B then B→C, each hop independently routed.
#[tokio::test]
async fn test_switch_sequential_hops() {
    let mut switch = LoraSwitch::new();
    let (mut node_a, _ta) = make_node(&mut switch, 1, 18, 915_000_000).await;
    let (mut node_b, _tb) = make_node(&mut switch, 2, 18, 915_000_000).await;
    let (mut node_c, _tc) = make_node(&mut switch, 3, 18, 915_000_000).await;

    let _switch_task = tokio::spawn(switch.run());

    // A → B
    timed!(node_a.send_data(2, "hop1")).expect("A→B send failed");
    let pkt_b = timed!(node_b.listen_for_packet()).expect("B did not receive hop1");
    assert_eq!(pkt_b.data.as_str(), "hop1");

    // B → C (forwarding)
    timed!(node_b.send_data(3, "hop2")).expect("B→C send failed");
    let pkt_c = timed!(node_c.listen_for_packet()).expect("C did not receive hop2");
    assert_eq!(pkt_c.data.as_str(), "hop2");
}

/// `set_default_quality` applies when no per-link entry is present.
#[tokio::test]
async fn test_switch_default_quality_applied() {
    let mut switch = LoraSwitch::new();
    switch.set_default_quality(LinkQuality { rssi: -95, snr: -4 });

    let (mut node_a, _ta) = make_node(&mut switch, 1, 18, 915_000_000).await;
    let (mut node_b, _tb) = make_node(&mut switch, 2, 18, 915_000_000).await;

    timed!(node_a.send_data(2, "default_q")).expect("send failed");
    switch.tick().await;

    let pkt = timed!(node_b.listen_for_packet()).expect("receive failed");
    assert_eq!(pkt.rssi, -95);
    assert_eq!(pkt.snr, -4);
}
