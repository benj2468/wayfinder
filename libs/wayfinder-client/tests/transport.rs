//! End-to-end check that [`wayfinder_client::Client`] speaks the same wire
//! protocol as the production `wayfinder-server` TLS listener.
//!
//! The test spins up the real `serve_tls_server` backed by a canned data
//! provider, then drives it with an authenticated client, asserting the decoded
//! responses match what the provider returned. This exercises the full
//! RFC 7250 handshake → prost-encode → frame → decode path on both sides without
//! a TAP device.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;

use tokio::sync::mpsc;
use tokio::sync::oneshot;
use wayfinder_client::Client;
use wayfinder_protos::service::AlarmsData;
use wayfinder_protos::service::AuthorityDataProvider;
use wayfinder_protos::service::EgressDecisionData;
use wayfinder_protos::service::InterfaceThroughputData;
use wayfinder_protos::service::KeepAliveEntryData;
use wayfinder_protos::service::LinkFeaturesEntryData;
use wayfinder_protos::service::LinkQualityEntryData;
use wayfinder_protos::service::LogLevelData;
use wayfinder_protos::service::LogRecordData;
use wayfinder_protos::service::LogsData;
use wayfinder_protos::service::NeighborPathData;
use wayfinder_protos::service::NodeMetricsData;
use wayfinder_protos::service::OgmScheduleEntryData;
use wayfinder_protos::service::PingSessionData;
use wayfinder_protos::service::PingStartData;
use wayfinder_protos::service::RegistrationStartedData;
use wayfinder_protos::service::RouteResolutionData;
use wayfinder_protos::service::RouterReads;
use wayfinder_protos::service::RouterWrites;
use wayfinder_protos::service::RoutingEntryData;
use wayfinder_protos::service::RuntimeConfigData;
use wayfinder_protos::service::TableOccupancyData;
use wayfinder_protos::service::UserInviteData;
use wayfinder_protos::service::UserInviteMintedData;
use wayfinder_protos::service::WayfinderService;
use wayfinder_protos::wayfinder::v1alpha::LogLevel;
use wayfinder_protos::wayfinder::v1alpha::WayfinderRequest;
use wayfinder_protos::wayfinder::v1alpha::WayfinderResponse;
use wayfinder_protos::wayfinder::v1alpha::resolve_route_response::Egress;

/// Render a 6-byte identifier as a colon-delimited MAC, else as plain hex.
fn format_mac(bytes: &[u8]) -> String {
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

/// A canned data provider with one originator, one link-quality row, and a
/// resolvable route, so every typed client method has something to return.
struct Mock;

impl RouterReads for Mock {
    fn node_id(&self) -> Vec<u8> {
        vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]
    }

    fn num_originators(&self) -> u32 {
        2
    }

    fn auth_locked(&self) -> bool {
        true
    }

    fn routing_table(&self) -> Vec<RoutingEntryData> {
        vec![RoutingEntryData {
            destination: vec![0, 0, 0, 0, 0, 2],
            next_hop: vec![0, 0, 0, 0, 0, 3],
            tq: 240,
            last_seqno: 17,
            paths: vec![NeighborPathData {
                neighbor_id: vec![0, 0, 0, 0, 0, 3],
                tq: 240,
                last_seqno: 17,
                proven: true,
            }],
        }]
    }

    fn link_quality_table(&self) -> Vec<LinkQualityEntryData> {
        vec![LinkQualityEntryData {
            neighbor_id: vec![0, 0, 0, 0, 0, 3],
            iface_idx: 0,
            ewma_quality: Some(200),
            sample_count: 9,
            iface_name: "lora0".into(),
        }]
    }

    fn link_features_table(&self) -> Vec<LinkFeaturesEntryData> {
        vec![]
    }

    fn keepalive_table(&self) -> Vec<KeepAliveEntryData> {
        vec![KeepAliveEntryData {
            neighbor_id: vec![0, 0, 0, 0, 0, 3],
            ms_since_last_heard: 4200,
            interval_estimate_ms: 1000,
            missed: true,
        }]
    }

    fn ogm_schedule(&self) -> Vec<OgmScheduleEntryData> {
        vec![OgmScheduleEntryData {
            iface_idx: 0,
            current_interval_ms: 4000,
            min_interval_ms: 1000,
            max_interval_ms: 64000,
            iface_name: "lora0".into(),
        }]
    }

    fn throughput(&self) -> Vec<InterfaceThroughputData> {
        vec![InterfaceThroughputData {
            iface_idx: 0,
            rx_bps: 1500.0,
            rx_fps: 12.0,
            tx_bps: 800.0,
            tx_fps: 6.0,
            iface_name: "lora0".into(),
        }]
    }

    fn node_metrics(&self) -> NodeMetricsData {
        NodeMetricsData {
            uptime_secs: 7384,
            neighbor_count: 1,
            originators: TableOccupancyData {
                used: 1,
                capacity: 128,
            },
            broadcast_dedup: TableOccupancyData {
                used: 1,
                capacity: 128,
            },
            local_mcast_groups: TableOccupancyData {
                used: 0,
                capacity: 16,
            },
            mcast_memberships: TableOccupancyData {
                used: 0,
                capacity: 64,
            },
            tq_min: 240,
            tq_max: 240,
            tq_mean: 240.0,
            paths_max: 1,
            paths_mean: 1.0,
            oversize_drops: 2,
            relay_oversize_drops: 4,
            cert_store: TableOccupancyData {
                used: 3,
                capacity: 64,
            },
            in_flight_cert_requests: TableOccupancyData {
                used: 1,
                capacity: 16,
            },
            pending_cert_replies: TableOccupancyData {
                used: 2,
                capacity: 16,
            },
            cert_req_rate: 0.25,
            cert_reply_rate: 0.75,
            untaggable_drop_rate: 0.0,
            seqno_resyncs: 0,
            ogm_refloods_suppressed: 0,
            ogm_echoes_dropped: 0,
            ogm_tails_malformed: 0,
            broadcast_dedup_evictions: 0,
            broadcast_seqno_refusals: 0,
            proofs_swept: 0,
            unjudged_cert_admissions: 0,
        }
    }

    fn resolve_route(&self, _destination: &[u8]) -> Option<RouteResolutionData> {
        Some(RouteResolutionData {
            next_hop: vec![0, 0, 0, 0, 0, 3],
            egress: Some(EgressDecisionData::Interface(0)),
        })
    }

    /// This mock runs no ping session, and says so rather than
    /// fabricating one — a handle that always resolved would hide exactly
    /// the displaced-session case the handle exists to expose.
    fn ping_session(&self, _session_seq: u32) -> Option<PingSessionData> {
        None
    }

    fn runtime_config_active(&self) -> bool {
        false
    }

    fn clock_posture(&self) -> wayfinder_protos::service::ClockPostureData {
        // A mock with no clock policy to report: `At` matches the `true` it
        // reports for `clock_trusted`, so the two do not contradict.
        wayfinder_protos::service::ClockPostureData::At
    }

    fn clock_trusted(&self) -> bool {
        true
    }

    /// Delegates to the real process-wide ring, exactly as `RouterAdapter`
    /// does, so the end-to-end test below proves a record emitted on the server
    /// side actually reaches a client over the wire — not just that the stub's
    /// canned value survives encoding.
    fn alarms(&self) -> AlarmsData {
        // Nothing wrong: an empty board is the node's "all systems normal", and
        // none of these cases is about alarms.
        AlarmsData::default()
    }

    fn logs(&self, since_seq: u64, max_records: u32) -> LogsData {
        let snapshot = wayfinder_log::logs_since(since_seq, max_records as usize);
        LogsData {
            records: snapshot
                .records
                .into_iter()
                .map(|r| LogRecordData {
                    seq: r.seq,
                    uptime_ms: r.uptime_ms,
                    level: match r.level {
                        wayfinder_log::Level::Error => LogLevelData::Error,
                        wayfinder_log::Level::Warn => LogLevelData::Warn,
                        wayfinder_log::Level::Info => LogLevelData::Info,
                        wayfinder_log::Level::Debug => LogLevelData::Debug,
                        wayfinder_log::Level::Trace => LogLevelData::Trace,
                    },
                    target: r.target.as_str().into(),
                    message: r.message.as_str().into(),
                })
                .collect(),
            next_seq: snapshot.next_seq,
            dropped: snapshot.dropped,
            filter: wayfinder_log::current_spec().as_str().into(),
        }
    }
}

impl RouterWrites for Mock {
    fn set_auth(
        &mut self,
        _seed: &[u8],
        _cert: &[u8],
        _trust_anchor: &[u8],
        _provider: Option<wayfinder_protos::service::RenewalProviderData>,
        _installer_unix: u64,
    ) -> Result<(), String> {
        Ok(())
    }

    fn set_time(&mut self, _installer_unix: u64) -> Result<(), String> {
        Ok(())
    }

    fn set_config(&mut self, _config: RuntimeConfigData) -> Result<(), String> {
        Ok(())
    }

    /// Accepts a session and echoes back what was asked for, defaulting
    /// zeroes the way a real node does, but never emits anything: there is
    /// no mesh behind this mock to probe.
    fn start_ping(
        &mut self,
        destination: &[u8],
        count: u32,
        interval_ms: u32,
        timeout_ms: u32,
        payload_bytes: u32,
    ) -> Result<PingStartData, String> {
        if destination.len() != 6 {
            return Err("destination must be a 6-byte node identifier".into());
        }
        Ok(PingStartData {
            session_seq: 1,
            count: if count == 0 { 5 } else { count },
            interval_ms: if interval_ms == 0 { 1_000 } else { interval_ms },
            timeout_ms: if timeout_ms == 0 { 5_000 } else { timeout_ms },
            payload_bytes: if payload_bytes == 0 {
                16
            } else {
                payload_bytes
            },
        })
    }

    /// Nothing to cancel: these mocks run no session. Distinct from a mock
    /// that cancelled anything asked of it, which would hide the wrong-handle
    /// case the handle exists to catch.
    fn cancel_ping(&mut self, _session_seq: u32) -> Option<PingSessionData> {
        None
    }

    fn set_log_level(&mut self, directives: &str) -> Result<String, String> {
        wayfinder_log::set_filter(directives)
            .map(|()| wayfinder_log::current_spec().as_str().to_string())
            .map_err(|e| format!("{e}"))
    }
}

impl AuthorityDataProvider for Mock {
    fn get_trust_anchor(&self) -> Result<Vec<u8>, String> {
        Ok(vec![0xab; 36])
    }

    fn create_user_invite(
        &mut self,
        username: &str,
        _admin: bool,
        _session_ttl_secs: u64,
        _invite_ttl_secs: u64,
    ) -> Result<UserInviteMintedData, String> {
        Ok(UserInviteMintedData {
            username: username.to_string(),
            token: "JBSWY3DPEHPK3PXP".to_string(),
            expires_at: 1_800_086_400,
        })
    }

    fn list_user_invites(&self) -> Result<(Vec<UserInviteData>, u32), String> {
        Ok((
            vec![UserInviteData {
                username: "rowan".to_string(),
                admin: true,
                session_ttl_secs: 900,
                created_at: 1_800_000_000,
                expires_at: 1_800_086_400,
                started_at: 1_800_000_600,
                handle_expires_at: 1_800_001_500,
            }],
            128,
        ))
    }

    fn revoke_user_invite(&mut self, _username: &str) -> Result<(), String> {
        Ok(())
    }

    fn begin_user_registration(&mut self, _token: &str) -> Result<RegistrationStartedData, String> {
        Ok(RegistrationStartedData {
            username: "rowan".to_string(),
            totp_enrolment_uri: "otpauth://totp/wayfinder:rowan?secret=AAAA".to_string(),
            handle: "handle-abc".to_string(),
            handle_expires_at: 1_800_001_500,
        })
    }

    fn complete_user_registration(
        &mut self,
        _handle: &str,
        _password: &str,
        _totp_code: &str,
    ) -> Result<(), String> {
        Ok(())
    }
}

/// Spawn the production `WayfinderService` query loop behind a channel and
/// return the sender the transport listeners forward decoded requests to.
fn spawn_service() -> mpsc::Sender<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)> {
    let (query_tx, mut query_rx) =
        mpsc::channel::<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>(16);
    tokio::spawn(async move {
        let mut service = WayfinderService::new(Mock);
        while let Some((req, resp_tx)) = query_rx.recv().await {
            let _ = resp_tx.send(service.handle(req));
        }
    });
    query_tx
}

/// Grab an almost-certainly-free localhost port by binding to :0 and releasing.
fn free_port() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

/// Assert every typed query returns the provider's canned values.
async fn assert_full_roundtrip(client: &mut Client) {
    let info = client.node_info().await.unwrap();
    assert_eq!(format_mac(&info.node_id), "aa:bb:cc:dd:ee:01");
    assert_eq!(info.num_originators, 2);
    assert!(info.auth_locked);
    assert!(!info.runtime_config_active);

    let routing = client.routing_table().await.unwrap();
    assert_eq!(routing.entries.len(), 1);
    let entry = &routing.entries[0];
    assert_eq!(format_mac(&entry.destination), "00:00:00:00:00:02");
    assert_eq!(format_mac(&entry.next_hop), "00:00:00:00:00:03");
    assert_eq!(entry.tq, 240);

    let links = client.link_quality_table().await.unwrap();
    assert_eq!(links.entries.len(), 1);
    assert_eq!(links.entries[0].ewma_quality, Some(200));

    let keepalive = client.keepalive_table().await.unwrap();
    assert_eq!(keepalive.entries.len(), 1);
    assert_eq!(keepalive.entries[0].interval_estimate_ms, 1000);
    assert!(keepalive.entries[0].missed);

    let schedule = client.ogm_schedule().await.unwrap();
    assert_eq!(schedule.entries[0].current_interval_ms, 4000);

    let throughput = client.throughput().await.unwrap();
    assert_eq!(throughput.interfaces[0].rx_bps, 1500.0);
    assert_eq!(throughput.total_tx_fps, 6.0);

    let metrics = client.node_metrics().await.unwrap();
    assert_eq!(metrics.uptime_secs, 7384);
    assert_eq!(metrics.originators.unwrap().capacity, 128);
    assert_eq!(metrics.oversize_drops, 2);
    assert_eq!(metrics.relay_oversize_drops, 4);
    assert_eq!(metrics.cert_store.unwrap().used, 3);
    assert_eq!(metrics.in_flight_cert_requests.unwrap().used, 1);
    assert_eq!(metrics.pending_cert_replies.unwrap().used, 2);
    assert_eq!(metrics.cert_req_rate, 0.25);
    assert_eq!(metrics.cert_reply_rate, 0.75);

    let route = client.resolve_route(vec![0, 0, 0, 0, 0, 2]).await.unwrap();
    assert_eq!(format_mac(&route.next_hop), "00:00:00:00:00:03");
    assert_eq!(route.egress, Some(Egress::InterfaceIndex(0)));

    // Both halves of the ping surface round-trip: a write that hands back a
    // handle, and the read that presents it. The mock runs no session, so
    // polling that handle answers "gone" — which is not an error, and is the
    // signal a client stops on rather than a failure it reports.
    let started = client
        .ping(vec![0, 0, 0, 0, 0, 2], 0, 0, 0, 0)
        .await
        .unwrap();
    assert_ne!(started.session_seq, 0, "a handle is always issued");
    assert_eq!(
        started.count, 5,
        "the node's defaults come back, not our zeros"
    );
    assert_eq!(started.interval_ms, 1_000);
    assert_eq!(started.timeout_ms, 5_000);
    assert_eq!(started.payload_bytes, 16);

    let status = client.ping_status(started.session_seq).await.unwrap();
    assert!(status.session.is_none());

    // A destination that is not a node identifier is refused rather than
    // silently probing a truncated address.
    assert!(client.ping(vec![1, 2, 3], 0, 0, 0, 0).await.is_err());

    // A provider RPC also round-trips over this transport (exercises the new
    // GetTrustAnchor request/response framing).
    let anchor = client.get_trust_anchor().await.unwrap();
    assert_eq!(anchor.trust_anchor, vec![0xab; 36]);

    // SetConfig round-trips too (exercises the mutating-request framing).
    client.set_trickle_config(0, 500, 4000).await.unwrap();

    assert_logs_roundtrip(client).await;
}

/// A record emitted on the server side is readable by the client, and the
/// runtime filter can be set and read back — the whole point of the feature,
/// over the real wire rather than through a canned provider value.
async fn assert_logs_roundtrip(client: &mut Client) {
    // Where the stream is now, so the assertions below don't have to reason
    // about whatever else the process has logged.
    let start = client.logs(0, 0).await.unwrap().next_seq;

    wayfinder_log::record(
        wayfinder_log::Level::Warn,
        "wayfinder_client::transport_test",
        "drop: no route",
    );

    let batch = client.logs(start, 0).await.unwrap();
    let record = batch
        .records
        .iter()
        .find(|r| r.target == "wayfinder_client::transport_test")
        .expect("the record emitted above crossed the wire");
    assert_eq!(record.level, LogLevel::Warn as i32);
    assert_eq!(record.message, "drop: no route");
    // Not "> 0": the clock starts on first use, so the first record in a
    // process legitimately stamps at ~0ms. What must hold is that the stamps
    // never go backwards, or the log view would render out of order.
    assert!(
        batch
            .records
            .windows(2)
            .all(|w| w[0].uptime_ms <= w[1].uptime_ms),
        "uptime stamps must be non-decreasing across a batch"
    );
    assert_eq!(
        batch.next_seq,
        record.seq + 1,
        "the resume point follows the last record handed over"
    );

    // The filter round-trips, and an unparsable spec is refused without
    // disturbing what is in force.
    let effective = client.set_log_level("info,batman=trace").await.unwrap();
    assert_eq!(effective, "info,batman=trace");
    assert_eq!(
        client.logs(batch.next_seq, 0).await.unwrap().filter,
        "info,batman=trace",
        "every batch reports the filter actually in force"
    );

    let error = client
        .set_log_level("wayfinder=verbose")
        .await
        .expect_err("an unknown level must be refused");
    assert!(error.to_string().contains("unknown log level"), "{error}");
    assert_eq!(
        client.logs(batch.next_seq, 0).await.unwrap().filter,
        "info,batman=trace",
        "a rejected spec leaves the previous filter in force"
    );

    // Leave the process-wide filter as it was found.
    client
        .set_log_level(wayfinder_log::DEFAULT_SPEC)
        .await
        .unwrap();
}

#[tokio::test]
async fn client_roundtrips_against_real_tls_server() {
    use wayfinder_client::Identity;

    let node_seed = [7u8; 32];
    // Derive the node's public key from its seed via the exported RPK helpers so
    // the client can pin it; in bootstrap the client holds the node's own seed.
    let ck = wayfinder_tls_mgmt::certified_key_from_seed(&node_seed).unwrap();
    let node_key = wayfinder_tls_mgmt::raw_ed25519_from_spki(ck.cert[0].as_ref()).unwrap();

    let query_tx = spawn_service();

    // Un-enrolled router snapshot responder (bootstrap mode): no anchor, nothing
    // revoked.
    let (snapshot_tx, mut snapshot_rx) =
        mpsc::channel::<oneshot::Sender<wayfinder_server::AuthSnapshot>>(8);
    tokio::spawn(async move {
        while let Some(reply) = snapshot_rx.recv().await {
            let _ = reply.send(wayfinder_server::AuthSnapshot {
                own_key: Some(node_key),
                anchor: None,
                revoked: Vec::new(),
                own_mac: wayfinder_server::Mac([2, 0, 0, 0, 0, 1]),
            });
        }
    });

    let listener = wayfinder_server::bind_tcp_server(free_port())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    // The authority half runs on its own channel now, exactly as it does on a
    // real provider node: the connection task routes an authority-facing
    // request there rather than to the task that owns the router. Backed by the
    // same `Mock`, so `GetTrustAnchor` still round-trips real framing.
    let (authority_tx, mut authority_rx) =
        tokio::sync::mpsc::channel::<wayfinder_server::AuthorityCommand>(8);
    tokio::spawn(async move {
        while let Some(command) = authority_rx.recv().await {
            match command {
                wayfinder_server::AuthorityCommand::Request(request, reply) => {
                    let mut provider = Mock;
                    let response =
                        wayfinder_protos::service::handle_authority(&mut provider, request)
                            .unwrap_or_else(|_| wayfinder_server::not_a_provider_response());
                    let _ = reply.send(response);
                }
                wayfinder_server::AuthorityCommand::SetEnrollmentPolicy(_, reply) => {
                    let _ = reply.send(Ok(()));
                }
                // Unreachable here: a mesh renewal arrives from a router loop,
                // and this harness drives a client over a socket.
                wayfinder_server::AuthorityCommand::RenewOverMesh { reply, .. } => {
                    let _ = reply.send(Ok(wayfinder_server::RenewalOutcome::Refused(
                        "this harness does not renew".into(),
                    )));
                }
            }
        }
    });
    tokio::spawn(async move {
        let _ = wayfinder_server::serve_tls_server_with_vpn(
            listener,
            node_seed,
            snapshot_tx,
            query_tx,
            wayfinder_server::ServerServices {
                authority_tx: Some(authority_tx),
                // No shared read handle: this harness has no driver behind
                // the listener, so reads travel the query channel as they
                // always did.
                ..Default::default()
            },
        )
        .await;
    });

    // Bootstrap: present the node's own seed and an empty cert; pin the node key.
    let identity = Identity {
        seed: node_seed,
        cert: Vec::new(),
    };
    let mut client = Client::connect_tls(&addr.into(), &node_key, &identity)
        .await
        .unwrap();
    assert_full_roundtrip(&mut client).await;
    assert_invite_roundtrip(&mut client).await;
}

/// The five invitation requests reach the authority half and their responses
/// come back projected whole.
///
/// Worth a round trip of its own rather than trusting the dispatch tests: these
/// are the requests whose fields *are* the secrets, so a client method that
/// dropped one — the token from a mint, the handle from a start — would leave a
/// caller with an invitation nobody can redeem and nothing to say so.
async fn assert_invite_roundtrip(client: &mut Client) {
    let minted = client
        .create_user_invite("rowan", true, 900, 0)
        .await
        .unwrap();
    assert_eq!(minted.username, "rowan");
    assert_eq!(minted.token, "JBSWY3DPEHPK3PXP");
    assert_eq!(minted.expires_at, 1_800_086_400);

    let listed = client.list_user_invites().await.unwrap();
    assert_eq!(listed.capacity, 128, "current-vs-cap survives the wire");
    assert_eq!(listed.invites.len(), 1);
    assert_eq!(
        listed.invites[0].started_at, 1_800_000_600,
        "the started-and-unfinished signal is the point of the listing"
    );

    client.revoke_user_invite("rowan").await.unwrap();

    let started = client.begin_user_registration("some-token").await.unwrap();
    assert_eq!(started.username, "rowan");
    assert!(started.totp_enrolment_uri.starts_with("otpauth://totp/"));
    assert_eq!(started.handle, "handle-abc");
    assert_eq!(started.handle_expires_at, 1_800_001_500);

    client
        .complete_user_registration("handle-abc", "hunter2", "287082")
        .await
        .unwrap();
}

/// A node that accepts the connection, completes the handshake, and then never
/// answers must surface as an error rather than hanging the caller forever.
///
/// This is the shape a board reset takes on the serial transport, which is
/// where it was found: a reset mid-stream leaves the length codec holding a
/// partial frame — or a length prefix decoded out of the ROM bootloader's
/// banner — and waiting for bytes that will never arrive. There is no EOF on a
/// serial port to end that wait, so a caller polling on a timer (the TUI) stops
/// dead and never reaches the reconnect path it already has.
///
/// Driven over TLS here because that is the transport a test can stand up
/// without a board, and the deadline belongs to `Client::request` rather than
/// to either transport — a TCP peer that accepts and goes silent strands a
/// caller exactly the same way.
///
/// `start_paused` so the deadline is reached by advancing the clock rather than
/// by waiting out a real one: the runtime auto-advances once every task is
/// parked, which is precisely the state this test puts it in.
#[tokio::test(start_paused = true)]
async fn request_against_a_node_that_never_answers_fails_rather_than_hanging() {
    use wayfinder_client::Identity;

    let node_seed = [9u8; 32];
    let ck = wayfinder_tls_mgmt::certified_key_from_seed(&node_seed).unwrap();
    let node_key = wayfinder_tls_mgmt::raw_ed25519_from_spki(ck.cert[0].as_ref()).unwrap();

    // The service half that never replies: hold every responder so the server
    // stays connected and silent, rather than dropping them (which would close
    // the stream and surface as an ordinary "connection closed").
    let (query_tx, mut query_rx) =
        mpsc::channel::<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>(16);
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some((_req, resp_tx)) = query_rx.recv().await {
            held.push(resp_tx);
        }
    });

    let (snapshot_tx, mut snapshot_rx) =
        mpsc::channel::<oneshot::Sender<wayfinder_server::AuthSnapshot>>(8);
    tokio::spawn(async move {
        while let Some(reply) = snapshot_rx.recv().await {
            let _ = reply.send(wayfinder_server::AuthSnapshot {
                own_key: Some(node_key),
                anchor: None,
                revoked: Vec::new(),
                own_mac: wayfinder_server::Mac([2, 0, 0, 0, 0, 9]),
            });
        }
    });

    let listener = wayfinder_server::bind_tcp_server(free_port())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = wayfinder_server::serve_tls_server_with_vpn(
            listener,
            node_seed,
            snapshot_tx,
            query_tx,
            wayfinder_server::ServerServices::default(),
        )
        .await;
    });

    let identity = Identity {
        seed: node_seed,
        cert: Vec::new(),
    };
    let mut client = Client::connect_tls(&addr.into(), &node_key, &identity)
        .await
        .unwrap();

    let err = client
        .node_info()
        .await
        .expect_err("a node that never answers must not strand the caller");
    let rendered = err.to_string();
    assert!(
        rendered.contains("did not answer"),
        "the error should name the deadline that expired, got: {rendered}"
    );
}
