//! `enroll` / `revoke` against an in-process provider node: the provider runs a
//! real `CertAuthority`, and `run_query` drives the full client → server →
//! authority path.  Asserts the issued certificate verifies against the anchor
//! the client wrote.

use std::net::SocketAddr;

use tokio::sync::{mpsc, oneshot};
use wayfinder_auth::{MembershipCert, TrustAnchor};
use wayfinder_protos::service::{
    EnrollData, InterfaceThroughputData, IssuedCertData, LinkQualityEntryData, NodeMetricsData,
    OgmScheduleEntryData, RouteResolutionData, RoutingEntryData, TableOccupancyData,
    WayfinderDataProvider, WayfinderService,
};
use wayfinder_protos::wayfinder_v1alpha::{WayfinderRequest, WayfinderResponse};
use wayfinder_server::{CertAuthority, MeshAuthority, run_tcp_server};
use wayfinderctl::output::OutputFormat;
use wayfinderctl::{Command, run_query};

/// A provider node: a real certificate authority behind the data-provider trait.
/// Only the provider methods carry behaviour; the rest are trivial.
struct ProviderMock {
    ca: CertAuthority,
}

fn occ() -> TableOccupancyData {
    TableOccupancyData {
        used: 0,
        capacity: 0,
    }
}

impl WayfinderDataProvider for ProviderMock {
    fn node_id(&self) -> Vec<u8> {
        vec![0, 0, 0, 0, 0, 1]
    }
    fn num_originators(&self) -> u32 {
        0
    }
    fn routing_table(&self) -> Vec<RoutingEntryData> {
        vec![]
    }
    fn link_quality_table(&self) -> Vec<LinkQualityEntryData> {
        vec![]
    }
    fn ogm_schedule(&self) -> Vec<OgmScheduleEntryData> {
        vec![]
    }
    fn throughput(&self) -> Vec<InterfaceThroughputData> {
        vec![]
    }
    fn node_metrics(&self) -> NodeMetricsData {
        NodeMetricsData {
            uptime_secs: 0,
            neighbor_count: 0,
            originators: occ(),
            broadcast_dedup: occ(),
            local_mcast_groups: occ(),
            mcast_memberships: occ(),
            tq_min: 0,
            tq_max: 0,
            tq_mean: 0.0,
            paths_max: 0,
            paths_mean: 0.0,
            oversize_drops: 0,
        }
    }
    fn resolve_route(&self, _destination: &[u8]) -> Option<RouteResolutionData> {
        None
    }
    fn set_auth(&mut self, _seed: &[u8], _cert: &[u8], _trust_anchor: &[u8]) -> Result<(), String> {
        Ok(())
    }

    fn get_trust_anchor(&self) -> Result<Vec<u8>, String> {
        Ok(self.ca.trust_anchor_bytes())
    }
    fn submit_csr(
        &mut self,
        node_mac: &[u8],
        ed_pubkey: &[u8],
        x_pubkey: &[u8],
        enrollment_token: &str,
    ) -> Result<EnrollData, String> {
        let cert = self
            .ca
            .issue_cert(node_mac, ed_pubkey, x_pubkey, enrollment_token)?;
        let trust_anchor = self.ca.trust_anchor_bytes();
        Ok(EnrollData { cert, trust_anchor })
    }
    fn revoke_node(&mut self, node_mac: &[u8]) -> Result<(), String> {
        self.ca.revoke(node_mac).map(|_| ())
    }
    fn list_certs(&self) -> Result<Vec<IssuedCertData>, String> {
        Ok(self.ca.list_certs())
    }
}

fn free_port() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// Spawn a provider node (mesh `0xABCD`, optional token) and return its address.
async fn spawn_provider(token: Option<String>) -> SocketAddr {
    let addr = free_port();
    let mut ca = CertAuthority::new(&[1; 32], 0xABCD, 1000, token);
    ca.set_now_unix(100);
    let (query_tx, mut query_rx) =
        mpsc::channel::<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>(16);
    tokio::spawn(async move {
        let _ = run_tcp_server(addr, query_tx).await;
    });
    tokio::spawn(async move {
        let mut service = WayfinderService::new(ProviderMock { ca });
        while let Some((req, resp_tx)) = query_rx.recv().await {
            let _ = resp_tx.send(service.handle(req));
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    addr
}

#[tokio::test]
async fn enroll_yields_a_cert_that_verifies_against_the_anchor() {
    let addr = spawn_provider(None).await;
    let dir = tempfile::tempdir().unwrap();
    let seed = dir.path().join("seed");
    let cert = dir.path().join("cert");
    let anchor = dir.path().join("anchor");

    let out = run_query(
        Command::Enroll {
            mac: "02:00:00:00:00:09".into(),
            token: String::new(),
            out_seed: seed.clone(),
            out_cert: cert.clone(),
            out_anchor: anchor.clone(),
        },
        &addr.to_string(),
        OutputFormat::Human,
    )
    .await
    .expect("enroll succeeds");
    assert!(out.contains("enrolled"), "got: {out}");

    // The written seed is 32 bytes; the issued cert verifies against the written
    // anchor within its validity window.
    assert_eq!(std::fs::metadata(&seed).unwrap().len(), 32);
    let anchor = TrustAnchor::from_bytes(&std::fs::read(&anchor).unwrap()).unwrap();
    let cert = MembershipCert::from_bytes(&std::fs::read(&cert).unwrap()).unwrap();
    let verified = anchor.verify_cert(&cert, 500).expect("cert verifies");
    assert_eq!(verified.mac.0, [0x02, 0, 0, 0, 0, 9]);
}

#[tokio::test]
async fn enroll_rejected_without_required_token() {
    let addr = spawn_provider(Some("s3cret".to_string())).await;
    let dir = tempfile::tempdir().unwrap();
    let err = run_query(
        Command::Enroll {
            mac: "02:00:00:00:00:09".into(),
            token: String::new(), // missing
            out_seed: dir.path().join("seed"),
            out_cert: dir.path().join("cert"),
            out_anchor: dir.path().join("anchor"),
        },
        &addr.to_string(),
        OutputFormat::Human,
    )
    .await
    .unwrap_err();
    // Format with the full cause chain (`{:#}`) so the provider's "invalid or
    // missing enrollment token" message is visible, not just the top context.
    let err = format!("{err:#}");
    assert!(err.contains("token"), "got: {err}");
}

#[tokio::test]
async fn list_certs_shows_an_enrolled_node() {
    let addr = spawn_provider(None).await;
    let dir = tempfile::tempdir().unwrap();
    run_query(
        Command::Enroll {
            mac: "02:00:00:00:00:09".into(),
            token: String::new(),
            out_seed: dir.path().join("seed"),
            out_cert: dir.path().join("cert"),
            out_anchor: dir.path().join("anchor"),
        },
        &addr.to_string(),
        OutputFormat::Json,
    )
    .await
    .unwrap();

    let out = run_query(Command::ListCerts, &addr.to_string(), OutputFormat::Json)
        .await
        .expect("list-certs succeeds");
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    let certs = parsed["certs"].as_array().unwrap();
    assert_eq!(certs.len(), 1, "the provider lists the enrolled node");
    // node_mac is the raw bytes of 02:00:00:00:00:09.
    assert_eq!(certs[0]["node_mac"][0], 2);
    assert_eq!(certs[0]["node_mac"][5], 9);
}

#[tokio::test]
async fn list_certs_is_empty_before_any_enrollment() {
    let addr = spawn_provider(None).await;
    let out = run_query(Command::ListCerts, &addr.to_string(), OutputFormat::Human)
        .await
        .unwrap();
    assert!(out.contains("no certificates issued"), "got: {out}");
}

#[tokio::test]
async fn revoke_round_trips() {
    let addr = spawn_provider(None).await;
    let out = run_query(
        Command::Revoke {
            mac: "02:00:00:00:00:09".into(),
        },
        &addr.to_string(),
        OutputFormat::Human,
    )
    .await
    .expect("revoke succeeds");
    assert!(out.contains("revoked"), "got: {out}");
}
