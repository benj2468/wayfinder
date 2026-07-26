//! The management-API transport: the authenticated TLS listener loop, the
//! in-process channel server, and the query channel the event loop services.
//!
//! Queries are forwarded to the main loop over a channel so the router is never
//! shared across tasks. This module requires the `std` feature.

use std::net::SocketAddr;

use bytes::Bytes;
use futures::SinkExt;
use futures::StreamExt;
use prost::Message;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::Framed;
use tokio_util::codec::LengthDelimitedCodec;
use wayfinder::interfaces::frame::Mac;
use wayfinder::wayfinder_auth::Keypair;
use wayfinder::wayfinder_auth::MembershipCert;
use wayfinder::wayfinder_auth::TrustAnchor;
use wayfinder_protos::wayfinder_v1alpha::Empty;
use wayfinder_protos::wayfinder_v1alpha::ErrorResponse;
use wayfinder_protos::wayfinder_v1alpha::WayfinderRequest;
use wayfinder_protos::wayfinder_v1alpha::WayfinderResponse;
use wayfinder_protos::wayfinder_v1alpha::wayfinder_request::Request as ReqKind;
use wayfinder_protos::wayfinder_v1alpha::wayfinder_response::Response as RespKind;

use crate::MgmtAccess;
use crate::decide_access;

/// Sender half of the channel server tasks use to forward queries to the loop.
pub type QueryTx = mpsc::Sender<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>;
/// Receiver half, owned by the event loop.
pub type QueryRx = mpsc::Receiver<(WayfinderRequest, oneshot::Sender<WayfinderResponse>)>;

/// One in-process management request: encoded [`WayfinderRequest`] bytes paired
/// with a one-shot channel the server replies on with encoded
/// [`WayfinderResponse`] bytes.
pub type ChannelRequest = (Bytes, oneshot::Sender<Bytes>);
/// Receiver half of the in-process channel server, owned by
/// [`run_channel_server`].
pub type ChannelServerRx = mpsc::Receiver<ChannelRequest>;
/// Sender half of the in-process channel server, held by a caller that wants to
/// issue management queries without going through a real socket (e.g. tests).
pub type ChannelServerTx = mpsc::Sender<ChannelRequest>;

/// The router state a management connection is authorized against, snapshotted
/// once when the connection authenticates.
///
/// The serve task must not touch the router directly (it lives on another task),
/// so the router's auth-relevant state is projected into this value and the serve
/// task evaluates [`decide_access`] locally against it. Snapshotting at
/// connect time means a connection's authorization reflects the mesh state when
/// it opened.
pub struct AuthContext {
    /// The node's own Ed25519 identity key, for the bootstrap comparison
    /// (un-enrolled admission requires the handshake key to equal this).
    pub own_key: [u8; 32],
    /// The installed trust anchor, or `None` when the node is un-enrolled
    /// (bootstrap mode — self-key admission only).
    pub anchor: Option<TrustAnchor>,
    /// Node MACs with an active revocation as of the snapshot instant.
    pub revoked: Vec<Mac>,
    /// Current unix time (seconds), for certificate validity checks.
    pub now_unix: u64,
}

/// Encode and send one [`WayfinderResponse`] over the framed connection.
async fn send_response<S>(
    framed: &mut Framed<S, LengthDelimitedCodec>,
    response: RespKind,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let envelope = WayfinderResponse {
        response: Some(response),
    };
    let mut buf = Vec::new();
    envelope.encode(&mut buf)?;
    framed.send(Bytes::from(buf)).await?;
    Ok(())
}

/// Serve one already-TLS-authenticated management connection.
///
/// `peer_key` is the client's Ed25519 raw public key that the TLS handshake
/// proved possession of (RFC 7250). The first frame must be an
/// [`AuthenticateRequest`](wayfinder_protos::wayfinder_v1alpha::AuthenticateRequest)
/// carrying the client's membership cert (empty on an un-enrolled node); it is
/// bound to `peer_key` and checked by [`decide_access`] against `ctx`. A grant
/// is acknowledged with an [`Empty`] response (which the client waits on) before
/// the normal request/response loop runs; a denial is answered with a generic
/// [`ErrorResponse`] and the connection closed.
///
/// Transport-agnostic over `S` so it serves a real `TlsStream` in production and
/// an in-memory duplex in tests — the TLS handshake itself is exercised
/// separately in [`crate::tls`].
pub async fn serve_authenticated_stream<S>(
    stream: S,
    peer_key: [u8; 32],
    ctx: AuthContext,
    query_tx: QueryTx,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut framed: Framed<S, LengthDelimitedCodec> =
        LengthDelimitedCodec::builder().new_framed(stream);

    // The connection must authenticate before anything else.
    let Some(frame) = framed.next().await else {
        // Client disconnected before authenticating; nothing to serve.
        return Ok(());
    };
    // A framing or protobuf-decode failure on the very first frame is arbitrary
    // remote input (the peer need only complete the RPK handshake to reach
    // here), so drop it at trace rather than escalating to the connection-error
    // warn! — a malformed packet must not flood the logs.
    let frame = match frame {
        Ok(frame) => frame,
        Err(e) => {
            tracing::trace!(error = ?e, "drop: management framing error before auth");
            return Ok(());
        }
    };
    let request = match WayfinderRequest::decode(frame) {
        Ok(request) => request,
        Err(e) => {
            tracing::trace!(error = ?e, "drop: malformed first management frame");
            return Ok(());
        }
    };
    let cert_bytes = match request.request {
        Some(ReqKind::Authenticate(auth)) => auth.cert,
        _ => {
            send_response(
                &mut framed,
                RespKind::Error(ErrorResponse {
                    message: "first message on a management connection must be Authenticate".into(),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    // An empty cert means "bootstrap" (no membership cert yet); non-empty must
    // parse, else the connection is refused rather than served.
    let cert = if cert_bytes.is_empty() {
        None
    } else {
        match MembershipCert::from_bytes(&cert_bytes) {
            Some(cert) => Some(cert),
            None => {
                send_response(
                    &mut framed,
                    RespKind::Error(ErrorResponse {
                        message: "malformed membership certificate".into(),
                    }),
                )
                .await?;
                return Ok(());
            }
        }
    };

    let decision = decide_access(
        &peer_key,
        cert.as_ref(),
        ctx.anchor.as_ref(),
        &ctx.own_key,
        ctx.now_unix,
        |mac| ctx.revoked.contains(&mac),
    );
    if let MgmtAccess::Denied(reason) = decision {
        // A rejected management login is security-relevant and worth an
        // operator's attention, but is remotely triggerable, so cap it at warn.
        // The precise `reason` stays in this local log only: a generic message
        // goes over the wire so a not-yet-authenticated peer can't use the
        // response as an oracle (wrong-key vs revoked vs expired vs not-admin)
        // while probing with a stolen or revoked cert.
        tracing::warn!(?reason, "drop: management authentication denied");
        send_response(
            &mut framed,
            RespKind::Error(ErrorResponse {
                message: "authentication denied".into(),
            }),
        )
        .await?;
        return Ok(());
    }
    tracing::debug!(?decision, "management connection authenticated");
    // Acknowledge a successful authentication before serving requests.
    send_response(&mut framed, RespKind::Empty(Empty {})).await?;

    // Authenticated: serve requests until the peer hangs up.
    while let Some(frame) = framed.next().await {
        let request = WayfinderRequest::decode(frame?)?;
        let (resp_tx, resp_rx) = oneshot::channel();
        query_tx.send((request, resp_tx)).await?;
        let response = resp_rx.await?;
        let mut buf = Vec::new();
        response.encode(&mut buf)?;
        framed.send(Bytes::from(buf)).await?;
    }
    Ok(())
}

/// The router-owned half of an [`AuthContext`]: the auth state the TLS accept
/// loop must read from the router (which lives on another task) to authorize a
/// connection. `own_key` and the clock are supplied by the accept loop itself
/// (from the node's seed and the system clock), so only these router-derived
/// fields travel over the channel.
pub struct AuthSnapshot {
    /// The installed trust anchor, or `None` when the node is un-enrolled.
    pub anchor: Option<TrustAnchor>,
    /// Node MACs with an active revocation.
    pub revoked: Vec<Mac>,
}

/// Sender the TLS accept loop uses to ask the router loop for an
/// [`AuthSnapshot`]; the router replies on the enclosed one-shot.
pub type AuthSnapshotTx = mpsc::Sender<oneshot::Sender<AuthSnapshot>>;
/// Receiver half, serviced by the router event loop alongside [`QueryRx`].
pub type AuthSnapshotRx = mpsc::Receiver<oneshot::Sender<AuthSnapshot>>;

/// Current unix time in seconds, for certificate validity checks on the host.
///
/// Errors (rather than defaulting) if the host clock is before the Unix epoch:
/// `0` is the most-permissive value for a `not_after` comparison, so silently
/// substituting it would let an *expired* admin cert pass the expiry gate on a
/// mis-set clock. Failing here closes the connection instead — fail-closed.
fn now_unix() -> anyhow::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| {
            anyhow::anyhow!("system clock is before the Unix epoch; refusing to authorize: {e}")
        })
}

/// Accept TLS management connections on `listener`, authenticate each by its
/// RFC 7250 raw public key, and serve authorized ones.
///
/// The node presents `own_seed`'s Ed25519 key as its TLS identity; each client
/// presents its own raw key, which the handshake proves possession of. Per
/// connection the loop reads that key, snapshots the router's auth state via
/// `snapshot_tx`, and hands both to [`serve_authenticated_stream`], which makes
/// the [`decide_access`] decision. `own_seed` must be the node's persistent
/// identity seed and exists even before enrollment (bootstrap presents it).
pub async fn serve_tls_server(
    listener: TcpListener,
    own_seed: [u8; 32],
    snapshot_tx: AuthSnapshotTx,
    query_tx: QueryTx,
) -> anyhow::Result<()> {
    let config = crate::server_config(&own_seed)
        .map_err(|e| anyhow::anyhow!("building management TLS server config: {e}"))?;
    let acceptor = TlsAcceptor::from(config);
    let own_key = Keypair::from_seed(&own_seed).ed_pubkey();

    loop {
        let (tcp, peer) = listener.accept().await?;
        tracing::debug!(%peer, "management TLS connection accepted");
        let acceptor = acceptor.clone();
        let snapshot_tx = snapshot_tx.clone();
        let query_tx = query_tx.clone();
        tokio::spawn(async move {
            if let Err(e) =
                serve_tls_connection(acceptor, tcp, own_key, snapshot_tx, query_tx).await
            {
                tracing::warn!(%peer, error = ?e, "management TLS connection error");
            }
        });
    }
}

/// Complete the TLS handshake, recover the client's raw public key, snapshot the
/// router's auth state, and serve the connection.
async fn serve_tls_connection(
    acceptor: TlsAcceptor,
    tcp: tokio::net::TcpStream,
    own_key: [u8; 32],
    snapshot_tx: AuthSnapshotTx,
    query_tx: QueryTx,
) -> anyhow::Result<()> {
    let tls = acceptor.accept(tcp).await?;

    // Recover the client's Ed25519 identity from the raw public key it presented
    // in the handshake (which TLS just proved it holds the private half of).
    let peer_key = {
        let (_io, conn) = tls.get_ref();
        let spki = conn
            .peer_certificates()
            .and_then(<[_]>::first)
            .ok_or_else(|| anyhow::anyhow!("client presented no raw public key"))?;
        wayfinder_tls_mgmt::raw_ed25519_from_spki(spki.as_ref())
            .ok_or_else(|| anyhow::anyhow!("client key is not a raw Ed25519 public key"))?
    };

    // Snapshot the router's current auth state (anchor + revocations).
    let (reply_tx, reply_rx) = oneshot::channel();
    snapshot_tx
        .send(reply_tx)
        .await
        .map_err(|_| anyhow::anyhow!("router loop unavailable for auth snapshot"))?;
    let snapshot = reply_rx
        .await
        .map_err(|_| anyhow::anyhow!("router loop dropped the auth-snapshot request"))?;

    let ctx = AuthContext {
        own_key,
        anchor: snapshot.anchor,
        revoked: snapshot.revoked,
        now_unix: now_unix()?,
    };
    serve_authenticated_stream(tls, peer_key, ctx, query_tx).await
}

/// Bind the TCP listener the TLS management server accepts on, without serving
/// it.
///
/// Split out from [`serve_tls_server`] so a caller can bind every configured
/// listener up front -- surfacing a bind failure (e.g. address in use)
/// synchronously -- before spawning the accept loops and declaring itself
/// ready.
pub async fn bind_tcp_server(addr: SocketAddr) -> anyhow::Result<TcpListener> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("management API listening on TCP {addr}");
    Ok(listener)
}

/// Why [`handle_connectionless`] failed to produce a response.
#[derive(Debug)]
enum ConnectionlessError {
    /// The request bytes didn't decode as a [`WayfinderRequest`] — the
    /// peer's fault.  Safe to drop just this one datagram and keep serving
    /// others.
    Decode(prost::DecodeError),
    /// The router event loop is unreachable: its receiver was dropped, or it
    /// dropped the reply oneshot without responding (e.g. it panicked
    /// mid-request).  The server can no longer do anything useful and should
    /// stop, not keep silently discarding every future request.
    RouterGone,
}

/// Decode one connectionless request, forward it to the loop, and encode the reply.
async fn handle_connectionless(
    buf: &[u8],
    query_tx: QueryTx,
) -> Result<Vec<u8>, ConnectionlessError> {
    let request = WayfinderRequest::decode(buf).map_err(ConnectionlessError::Decode)?;

    let (resp_tx, resp_rx) = oneshot::channel();
    query_tx
        .send((request, resp_tx))
        .await
        .map_err(|_| ConnectionlessError::RouterGone)?;

    let response = resp_rx.await.map_err(|_| ConnectionlessError::RouterGone)?;
    let mut out = Vec::new();
    #[expect(
        clippy::expect_used,
        reason = "encoding into a growable Vec<u8> cannot fail (BufMut::remaining_mut is unbounded)"
    )]
    response
        .encode(&mut out)
        .expect("encoding into a growable Vec<u8> cannot fail");
    Ok(out)
}

/// Serve the management API over an in-process mpsc channel.
///
/// Mirrors the socket listeners but carries already-/still-encoded protobuf
/// bytes over a channel instead of a kernel transport, so a caller in the same
/// process (the integration tests) can exercise the full encode → forward →
/// decode path without binding a socket.  Each request is a `(bytes, reply)`
/// pair; the encoded response is sent back on `reply`.
pub async fn run_channel_server(mut rx: ChannelServerRx, query_tx: QueryTx) -> anyhow::Result<()> {
    while let Some((request, reply)) = rx.recv().await {
        // A caller that sends a malformed request must not take down the loop
        // for everyone else queued behind it.
        let response = match handle_connectionless(&request, query_tx.clone()).await {
            Ok(response) => response,
            Err(ConnectionlessError::Decode(e)) => {
                tracing::trace!(error = ?e, "drop: malformed management request");
                continue;
            }
            Err(ConnectionlessError::RouterGone) => {
                anyhow::bail!("management router event loop is unreachable");
            }
        };
        let _ = reply.send(Bytes::from(response));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::net::TcpStream;
    use tokio::sync::mpsc;
    use wayfinder_protos::wayfinder_v1alpha::AuthenticateRequest;
    use wayfinder_protos::wayfinder_v1alpha::GetNodeInfoRequest;
    use wayfinder_protos::wayfinder_v1alpha::NodeInfo;
    use wayfinder_protos::wayfinder_v1alpha::WayfinderRequest;
    use wayfinder_protos::wayfinder_v1alpha::WayfinderResponse;
    use wayfinder_protos::wayfinder_v1alpha::wayfinder_request::Request;
    use wayfinder_protos::wayfinder_v1alpha::wayfinder_response::Response;

    use super::*;

    /// A free TCP port on loopback, picked by asking the OS for one and
    /// releasing it immediately.
    fn free_tcp_addr() -> SocketAddr {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    // These tests specify the bind/serve split needed so a caller (e.g.
    // `wayfinder-tap`'s `main`) can bind every listener synchronously, up
    // front, and only afterwards spawn the accept loops and signal readiness
    // -- rather than binding as a side effect of a spawned task, which races
    // readiness against the socket actually being live.

    #[tokio::test]
    async fn bind_tcp_server_accepts_before_any_serve_loop_runs() {
        let addr = free_tcp_addr();
        let _listener = bind_tcp_server(addr)
            .await
            .expect("bind must succeed on a free port");

        // The socket is already in LISTEN state at the OS level as soon as
        // `bind_tcp_server` returns -- no accept loop has been spawned yet, and
        // none is needed for the kernel to accept the connection into its
        // backlog.
        tokio::time::timeout(Duration::from_millis(200), TcpStream::connect(addr))
            .await
            .expect("connect must not time out")
            .expect("connect must succeed against an already-bound listener");
    }

    #[tokio::test]
    async fn bind_tcp_server_reports_port_conflict_synchronously() {
        let addr = free_tcp_addr();
        let _held = std::net::TcpListener::bind(addr).unwrap();

        // The whole point of separating bind from serve: a conflict is
        // visible to the caller as soon as `bind_tcp_server` returns, not
        // only later when a spawned serve-loop future happens to be polled.
        assert!(bind_tcp_server(addr).await.is_err());
    }

    /// Answers every forwarded query with a canned `NodeInfo`, so a well-formed
    /// reply can be told apart from silence.
    fn spawn_echo(mut rx: QueryRx) {
        tokio::spawn(async move {
            while let Some((_, resp_tx)) = rx.recv().await {
                let response = WayfinderResponse {
                    response: Some(Response::NodeInfo(NodeInfo {
                        node_id: vec![1, 2, 3, 4, 5, 6],
                        num_originators: 7,
                        auth_locked: false,
                        runtime_config_active: false,
                    })),
                };
                let _ = resp_tx.send(response);
            }
        });
    }

    /// Encode a `WayfinderRequest` into a length-delimited frame payload.
    fn encode_request(request: Request) -> Bytes {
        let envelope = WayfinderRequest {
            request: Some(request),
        };
        let mut buf = Vec::new();
        envelope.encode(&mut buf).unwrap();
        Bytes::from(buf)
    }

    /// Drive `serve_authenticated_stream` over an in-memory duplex, returning a
    /// framed client handle and the server task's join handle.
    fn spawn_authenticated_server(
        peer_key: [u8; 32],
        ctx: AuthContext,
    ) -> (
        Framed<tokio::io::DuplexStream, LengthDelimitedCodec>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        let (query_tx, query_rx) = mpsc::channel(16);
        spawn_echo(query_rx);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(serve_authenticated_stream(
            server_io, peer_key, ctx, query_tx,
        ));
        (
            LengthDelimitedCodec::builder().new_framed(client_io),
            server,
        )
    }

    /// On an un-enrolled node, a client that proves the node's own key
    /// (bootstrap) is granted, then its subsequent requests are served.
    #[tokio::test]
    async fn authenticated_stream_bootstrap_grants_then_serves() {
        let key = [5u8; 32];
        let ctx = AuthContext {
            own_key: key, // bootstrap: handshake key equals the node's own key
            anchor: None, // un-enrolled
            revoked: Vec::new(),
            now_unix: 100,
        };
        let (mut client, server) = spawn_authenticated_server(key, ctx);

        // Authenticate with an empty cert (bootstrap).
        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: Vec::new(),
            })))
            .await
            .unwrap();
        let ack = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(
            matches!(ack.response, Some(Response::Empty(_))),
            "bootstrap authentication is acknowledged with Empty"
        );

        // A normal request is now served.
        client
            .send(encode_request(Request::GetNodeInfo(GetNodeInfoRequest {})))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(resp.response, Some(Response::NodeInfo(_))));

        drop(client);
        let _ = server.await;
    }

    /// A client whose handshake key is not the node's own key (on an un-enrolled
    /// node) is refused, and the connection is closed without serving anything.
    #[tokio::test]
    async fn authenticated_stream_denies_wrong_bootstrap_key() {
        let ctx = AuthContext {
            own_key: [1u8; 32],
            anchor: None,
            revoked: Vec::new(),
            now_unix: 100,
        };
        let (mut client, server) = spawn_authenticated_server([2u8; 32], ctx);

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: Vec::new(),
            })))
            .await
            .unwrap();

        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        match resp.response {
            Some(Response::Error(e)) => assert!(e.message.contains("denied"), "got: {}", e.message),
            other => panic!("expected an error response, got {other:?}"),
        }
        // The server closed the connection after refusing.
        assert!(
            client.next().await.is_none(),
            "connection is closed after a denied authentication"
        );
        let _ = server.await;
    }

    /// The full stack over a real loopback TLS connection: a client presenting
    /// the node's own key (bootstrap) completes the RFC 7250 handshake, the
    /// accept loop recovers its key and snapshots the (un-enrolled) router, and
    /// authenticated requests are served. Exercises `serve_tls_server` end to end
    /// with a genuine `tokio-rustls` client.
    #[tokio::test]
    async fn tls_server_serves_a_bootstrapping_client_end_to_end() {
        use tokio_rustls::TlsConnector;

        let server_seed = [7u8; 32];
        let server_key = Keypair::from_seed(&server_seed).ed_pubkey();

        // Stand-in router loop: un-enrolled (bootstrap), nothing revoked.
        let (snapshot_tx, mut snapshot_rx) = mpsc::channel::<oneshot::Sender<AuthSnapshot>>(4);
        tokio::spawn(async move {
            while let Some(reply) = snapshot_rx.recv().await {
                let _ = reply.send(AuthSnapshot {
                    anchor: None,
                    revoked: Vec::new(),
                });
            }
        });

        let (query_tx, query_rx) = mpsc::channel(16);
        spawn_echo(query_rx);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_tls_server(
            listener,
            server_seed,
            snapshot_tx,
            query_tx,
        ));

        // Client presents the node's own key (bootstrap) and pins the node key.
        let connector = TlsConnector::from(crate::tls::test_support::test_client_config(
            &server_seed,
            &server_key,
        ));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let tls = connector.connect(server_name, tcp).await.unwrap();
        let mut client = LengthDelimitedCodec::builder().new_framed(tls);

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: Vec::new(),
            })))
            .await
            .unwrap();
        let ack = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(
            matches!(ack.response, Some(Response::Empty(_))),
            "bootstrap authentication succeeds over real TLS"
        );

        client
            .send(encode_request(Request::GetNodeInfo(GetNodeInfoRequest {})))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(resp.response, Some(Response::NodeInfo(_))));
    }

    /// Sending a normal request before authenticating is refused — the first
    /// frame must be Authenticate.
    #[tokio::test]
    async fn authenticated_stream_requires_authenticate_first() {
        let key = [5u8; 32];
        let ctx = AuthContext {
            own_key: key,
            anchor: None,
            revoked: Vec::new(),
            now_unix: 100,
        };
        let (mut client, server) = spawn_authenticated_server(key, ctx);

        // Skip authentication and send a query first.
        client
            .send(encode_request(Request::GetNodeInfo(GetNodeInfoRequest {})))
            .await
            .unwrap();

        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        match resp.response {
            Some(Response::Error(e)) => {
                assert!(e.message.contains("Authenticate"), "got: {}", e.message)
            }
            other => panic!("expected an error response, got {other:?}"),
        }
        assert!(client.next().await.is_none());
        let _ = server.await;
    }

    /// On an *enrolled* node, a client presenting a valid admin membership cert
    /// bound to its handshake key is granted and then served — the production
    /// (non-bootstrap) authorization path over the wire, which the unit tests in
    /// `authz` exercise only in isolation.
    #[tokio::test]
    async fn authenticated_stream_enrolled_admin_grants_then_serves() {
        use wayfinder::wayfinder_auth::Authority;
        use zerocopy::IntoBytes;

        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let admin_kp = Keypair::from_seed(&[2u8; 32]);
        let admin_cert = authority.issue_admin_cert(
            Mac([0, 0, 0, 0, 0, 5]),
            admin_kp.ed_pubkey(),
            admin_kp.x_pubkey(),
            0,
            200,
        );
        let ctx = AuthContext {
            own_key: [9u8; 32], // not the client's key: only the cert can admit it
            anchor: Some(authority.trust_anchor()),
            revoked: Vec::new(),
            now_unix: 100,
        };
        let (mut client, server) = spawn_authenticated_server(admin_kp.ed_pubkey(), ctx);

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: admin_cert.as_bytes().to_vec(),
            })))
            .await
            .unwrap();
        let ack = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(
            matches!(ack.response, Some(Response::Empty(_))),
            "a bound admin cert is granted on an enrolled node"
        );

        client
            .send(encode_request(Request::GetNodeInfo(GetNodeInfoRequest {})))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        assert!(matches!(resp.response, Some(Response::NodeInfo(_))));

        drop(client);
        let _ = server.await;
    }

    /// On an enrolled node, a revoked admin's cert is refused over the wire even
    /// though it verifies and is key-bound: revocation dominates the admin bit.
    #[tokio::test]
    async fn authenticated_stream_denies_revoked_admin() {
        use wayfinder::wayfinder_auth::Authority;
        use zerocopy::IntoBytes;

        let authority = Authority::from_seed(&[1u8; 32], 0xABCD);
        let admin_kp = Keypair::from_seed(&[2u8; 32]);
        let admin_mac = Mac([0, 0, 0, 0, 0, 5]);
        let admin_cert = authority.issue_admin_cert(
            admin_mac,
            admin_kp.ed_pubkey(),
            admin_kp.x_pubkey(),
            0,
            200,
        );
        let ctx = AuthContext {
            own_key: [9u8; 32],
            anchor: Some(authority.trust_anchor()),
            revoked: vec![admin_mac], // this admin's node is revoked
            now_unix: 100,
        };
        let (mut client, server) = spawn_authenticated_server(admin_kp.ed_pubkey(), ctx);

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: admin_cert.as_bytes().to_vec(),
            })))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        match resp.response {
            Some(Response::Error(e)) => assert!(e.message.contains("denied"), "got: {}", e.message),
            other => panic!("expected an error response, got {other:?}"),
        }
        assert!(
            client.next().await.is_none(),
            "connection is closed after a revoked admin is refused"
        );
        let _ = server.await;
    }

    /// A non-empty but unparseable membership cert is refused explicitly (not
    /// silently treated as "no cert" / bootstrap), and the connection closed.
    #[tokio::test]
    async fn authenticated_stream_denies_malformed_cert() {
        let ctx = AuthContext {
            own_key: [9u8; 32],
            anchor: None,
            revoked: Vec::new(),
            now_unix: 100,
        };
        let (mut client, server) = spawn_authenticated_server([2u8; 32], ctx);

        client
            .send(encode_request(Request::Authenticate(AuthenticateRequest {
                cert: vec![0xFF; 8], // not a valid MembershipCert
            })))
            .await
            .unwrap();
        let resp = WayfinderResponse::decode(client.next().await.unwrap().unwrap()).unwrap();
        match resp.response {
            Some(Response::Error(e)) => {
                assert!(e.message.contains("malformed"), "got: {}", e.message)
            }
            other => panic!("expected an error response, got {other:?}"),
        }
        assert!(client.next().await.is_none());
        let _ = server.await;
    }
}
