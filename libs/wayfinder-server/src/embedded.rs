//! The `no_std` embedded management transport: an [`embassy_sync`] query channel
//! plus the [`serve`] loop that drives a management byte stream against it.
//!
//! This is the `no_std` counterpart to the `std` module's tokio listeners and
//! `QueryTx`/`QueryRx` mpsc channel. The shape is the same — a serve task reads
//! a request off a byte stream and forwards it to the single task that owns the
//! router, which replies — but here the transport is a UART, the channel is
//! [`embassy_sync`], and there is no heap beyond the request/response buffers.
//!
//! The router is never shared: the [`serve`] loop holds only a [`EmbeddedQueryTx`] and
//! forwards decoded [`WayfinderRequest`]s to whatever task owns the router (the
//! embedded driver's event loop), which holds the paired [`EmbeddedQueryRx`], services
//! each request against a `RouterAdapter`, and replies. A single serial
//! connection issues one request at a time, so the send and the reply strictly
//! alternate and never queue behind another query — but each direction is a
//! capacity-1 **buffered** channel, not a synchronous rendezvous: a `send`
//! completes as soon as the one slot is free, whether or not the other side is
//! currently awaiting it (see [`EmbeddedQueryRx::reply`]'s doc for why that
//! matters if the requester has already gone away).

use alloc::vec::Vec;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::channel::Receiver;
use embassy_sync::channel::Sender;
use embedded_io_async::Read;
use embedded_io_async::Write;
use prost::Message;
use tracing::trace;
use tracing::warn;
use wayfinder_protos::wayfinder::v1alpha::ErrorResponse;
use wayfinder_protos::wayfinder::v1alpha::WayfinderRequest;
use wayfinder_protos::wayfinder::v1alpha::WayfinderResponse;
use wayfinder_protos::wayfinder::v1alpha::wayfinder_response::Response as RespKind;

use crate::framing::FrameError;
use crate::framing::MAX_FRAME_LEN;
use crate::framing::read_frame;
use crate::framing::write_frame;

/// The two capacity-1 channels that bridge a [`serve`] loop to the task that
/// owns the router: one carries a decoded request toward the router, the other
/// carries the response back.
///
/// Guarded by [`NoopRawMutex`]: every board this crate targets is single-core,
/// so there is no other [`RawMutex`](embassy_sync::blocking_mutex::raw::RawMutex)
/// this would ever be instantiated with. Construct one (typically in a
/// `static`), then [`split`](Self::split) it into the [`EmbeddedQueryTx`] the
/// serve loop holds and the [`EmbeddedQueryRx`] the router loop holds.
pub struct EmbeddedQueryChannel {
    request: Channel<NoopRawMutex, WayfinderRequest, 1>,
    response: Channel<NoopRawMutex, WayfinderResponse, 1>,
    /// Set by [`split`](Self::split) the first time it's called, so a second
    /// call panics instead of silently handing out a second, aliasing
    /// `Tx`/`Rx` pair over the same two channels — which would let two
    /// unrelated management sessions cross-talk (one session's reply
    /// delivered to another's `query()` caller) with no error, no panic, and
    /// no test able to catch it after the fact.
    split: AtomicBool,
}

impl Default for EmbeddedQueryChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl EmbeddedQueryChannel {
    /// A fresh, empty query channel. `const` so it can live in a `static`
    /// without a runtime initializer.
    pub const fn new() -> Self {
        Self {
            request: Channel::new(),
            response: Channel::new(),
            split: AtomicBool::new(false),
        }
    }

    /// Split into the serve-side [`EmbeddedQueryTx`] and the router-side
    /// [`EmbeddedQueryRx`]. Both borrow the channel, so it must outlive the two
    /// loops (e.g. a `static`).
    ///
    /// # Panics
    ///
    /// Panics if called more than once on the same channel — see the `split`
    /// field's doc for why a second split must never silently succeed.
    pub fn split(&self) -> (EmbeddedQueryTx<'_>, EmbeddedQueryRx<'_>) {
        assert!(
            !self.split.swap(true, Ordering::Relaxed),
            "EmbeddedQueryChannel::split called more than once"
        );
        (
            EmbeddedQueryTx {
                request: self.request.sender(),
                response: self.response.receiver(),
            },
            EmbeddedQueryRx {
                request: self.request.receiver(),
                response: self.response.sender(),
            },
        )
    }
}

/// The serve-loop end of a [`EmbeddedQueryChannel`]: sends a request toward the router
/// and awaits the matching response.
pub struct EmbeddedQueryTx<'a> {
    request: Sender<'a, NoopRawMutex, WayfinderRequest, 1>,
    response: Receiver<'a, NoopRawMutex, WayfinderResponse, 1>,
}

impl EmbeddedQueryTx<'_> {
    /// Forward one request to the router loop and await its response. Because a
    /// single serial connection has at most one request outstanding, the send
    /// and the receive strictly alternate and never queue behind another query.
    pub async fn query(&self, request: WayfinderRequest) -> WayfinderResponse {
        self.request.send(request).await;
        self.response.receive().await
    }
}

/// The router-loop end of a [`EmbeddedQueryChannel`]: receives a forwarded request and
/// sends back the response the router produced.
///
/// The owning event loop typically races [`recv`](Self::recv) as one arm of its
/// `select`, services the request against a `RouterAdapter`, then
/// [`reply`](Self::reply)s — mirroring the `std` driver's `query_rx.recv()` arm.
pub struct EmbeddedQueryRx<'a> {
    request: Receiver<'a, NoopRawMutex, WayfinderRequest, 1>,
    response: Sender<'a, NoopRawMutex, WayfinderResponse, 1>,
}

impl EmbeddedQueryRx<'_> {
    /// Await the next management request forwarded by a [`serve`] loop.
    pub async fn recv(&self) -> WayfinderRequest {
        self.request.receive().await
    }

    /// Send the response back to the serve loop waiting on it.
    ///
    /// Under normal operation this completes immediately: the serve loop that
    /// issued the request is already awaiting the response and the one-slot
    /// channel is empty. That also holds even if the serve loop has since died
    /// (e.g. its UART errored) without ever calling
    /// [`query`](EmbeddedQueryTx::query) again — the underlying channel is a
    /// buffered slot, not a rendezvous, so `send` only blocks on a *full*
    /// queue, never on an absent receiver. A reply to a requester that's gone
    /// is simply queued and never read (a leaked message, not a stuck sender),
    /// so this can never hang the router loop.
    pub async fn reply(&self, response: WayfinderResponse) {
        self.response.send(response).await;
    }
}

/// Serve the management API over one framed byte `stream` (a UART), forwarding
/// each request to the router loop via `query` and writing back its response.
///
/// Runs until the stream errors or closes — mid-frame, or cleanly between
/// frames (a UART generally never does either, so in practice this loops for
/// the node's lifetime). A request that fails to decode is answered with an
/// [`ErrorResponse`] rather than the connection being torn down — a garbled
/// frame must not kill the management link — but it **is** answered: the caller
/// blocked on that request's reply must never be left hanging just because this
/// one frame didn't parse. A desynchronising [`FrameError::Oversized`] or a
/// genuine I/O error is returned so the caller can reset the link.
pub async fn serve<S>(
    stream: &mut S,
    query: &EmbeddedQueryTx<'_>,
) -> Result<(), FrameError<S::Error>>
where
    S: Read + Write,
{
    let mut in_buf = Vec::new();
    let mut out_buf = Vec::new();
    loop {
        read_frame(stream, &mut in_buf).await?;
        let response = match WayfinderRequest::decode(in_buf.as_slice()) {
            Ok(request) => {
                trace!("forwarding management query to router");
                query.query(request).await
            }
            Err(e) => {
                trace!(error = ?e, "drop: malformed management request");
                WayfinderResponse {
                    response: Some(RespKind::Error(ErrorResponse {
                        message: "malformed request".into(),
                    })),
                }
            }
        };

        // Refused before it is built, not after. `write_frame` rejects an
        // oversized body too, but by then the cost has been paid: `encode` grows
        // its `Vec` by doubling, so a response several times `MAX_FRAME_LEN`
        // asks for an allocation several times again that, next to the request
        // buffer and whatever the response already materialised. On an embedded
        // node's small heap that allocation fails, and a failed allocation is a
        // panic — which this crate's boards answer with a reset.
        let encoded_len = response.encoded_len();
        let response = if encoded_len > MAX_FRAME_LEN {
            warn!(len = encoded_len, "management response too large to frame");
            WayfinderResponse {
                response: Some(RespKind::Error(ErrorResponse {
                    message: "response too large".into(),
                })),
            }
        } else {
            response
        };

        out_buf.clear();
        #[expect(
            clippy::expect_used,
            reason = "encoding into a growable Vec<u8> cannot fail (BufMut::remaining_mut is unbounded)"
        )]
        response
            .encode(&mut out_buf)
            .expect("encoding into a growable Vec<u8> cannot fail");
        write_frame(stream, &out_buf).await?;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;

    use core::convert::Infallible;

    use wayfinder_protos::wayfinder::v1alpha::NodeInfo;
    use wayfinder_protos::wayfinder::v1alpha::wayfinder_request::Request as ReqKind;

    use super::*;
    use crate::framing::MAX_FRAME_LEN;

    /// A one-shot in-memory stream for driving [`serve`] through exactly one
    /// request/response: reads drain `to_read` (a single pre-framed request)
    /// and then report EOF, so `serve` handles the one request, writes its
    /// response into `written`, and returns [`FrameError::UnexpectedEof`] on the
    /// next read. Reads are chunked to exercise the framing's partial-read loop.
    #[derive(Default)]
    struct OneShotStream {
        to_read: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
    }

    impl embedded_io_async::ErrorType for OneShotStream {
        type Error = Infallible;
    }

    impl Read for OneShotStream {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let remaining = &self.to_read[self.read_pos..];
            let n = remaining.len().min(buf.len()).min(3);
            buf[..n].copy_from_slice(&remaining[..n]);
            self.read_pos += n;
            Ok(n)
        }
    }

    impl Write for OneShotStream {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        async fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    /// Encode a [`WayfinderRequest`] into a length-delimited frame: 4-byte BE
    /// length prefix + body.
    fn framed_request(request: ReqKind) -> Vec<u8> {
        let envelope = WayfinderRequest {
            request: Some(request),
        };
        let mut body = Vec::new();
        envelope.encode(&mut body).unwrap();
        let mut framed = Vec::new();
        framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
        framed.extend_from_slice(&body);
        framed
    }

    /// A framed request written to the stream is decoded, forwarded over the
    /// channel to a stub router that replies with a canned `NodeInfo`, and that
    /// response is framed back onto the stream — the full serve → channel →
    /// reply → serve round trip.
    #[test]
    fn serve_round_trips_one_request_through_the_channel() {
        let channel = EmbeddedQueryChannel::new();
        let (tx, rx) = channel.split();

        let mut stream = OneShotStream {
            to_read: framed_request(ReqKind::GetNodeInfo(Default::default())),
            ..Default::default()
        };

        // The stub router: service exactly one request, then stop.
        let router = async {
            let request = rx.recv().await;
            assert!(
                matches!(request.request, Some(ReqKind::GetNodeInfo(_))),
                "the decoded request reaches the router loop intact"
            );
            rx.reply(WayfinderResponse {
                response: Some(RespKind::NodeInfo(NodeInfo {
                    node_id: std::vec![1, 2, 3, 4, 5, 6],
                    num_originators: 9,
                    auth_locked: false,
                    runtime_config_active: false,
                })),
            })
            .await;
        };

        let serve_loop = serve(&mut stream, &tx);

        // Run both to completion: the serve loop ends with UnexpectedEof once the
        // single framed request is consumed and the response is written.
        let (serve_result, ()) =
            futures::executor::block_on(futures::future::join(serve_loop, router));
        assert!(
            matches!(serve_result, Err(FrameError::UnexpectedEof)),
            "serve returns once the one-shot stream is drained"
        );

        // Decode the framed response the serve loop wrote back.
        assert!(stream.written.len() > 4, "a response frame was written");
        let len = u32::from_be_bytes(stream.written[..4].try_into().unwrap()) as usize;
        assert_eq!(len, stream.written.len() - 4, "prefix matches body length");
        let response = WayfinderResponse::decode(&stream.written[4..]).unwrap();
        match response.response {
            Some(RespKind::NodeInfo(info)) => {
                assert_eq!(info.num_originators, 9);
                assert_eq!(info.node_id, std::vec![1, 2, 3, 4, 5, 6]);
            }
            other => panic!("expected a NodeInfo response, got {other:?}"),
        }
    }

    /// A malformed request frame is answered with an `Error` response — never
    /// forwarded to the router, but never left silently unanswered either —
    /// and serving continues rather than tearing down the link.
    ///
    /// No router task is run: had `serve` forwarded the garbage frame instead of
    /// answering it directly, this would block forever awaiting a response that
    /// never comes (deadlocking `block_on`). Reaching the `UnexpectedEof` return
    /// after a response was written proves the malformed frame was answered
    /// locally, without ever reaching the channel.
    #[test]
    fn serve_answers_a_malformed_request_frame_with_an_error() {
        let channel = EmbeddedQueryChannel::new();
        let (tx, _rx) = channel.split();

        // A frame whose body is not a valid WayfinderRequest.
        let garbage_body = [0xffu8, 0xff, 0xff, 0xff];
        let mut framed = Vec::new();
        framed.extend_from_slice(&(garbage_body.len() as u32).to_be_bytes());
        framed.extend_from_slice(&garbage_body);
        let mut stream = OneShotStream {
            to_read: framed,
            ..Default::default()
        };

        let serve_result = futures::executor::block_on(serve(&mut stream, &tx));
        assert!(
            matches!(serve_result, Err(FrameError::UnexpectedEof)),
            "serve answers the bad frame, then reads on until EOF"
        );

        let len = u32::from_be_bytes(stream.written[..4].try_into().unwrap()) as usize;
        assert_eq!(len, stream.written.len() - 4, "prefix matches body length");
        let response = WayfinderResponse::decode(&stream.written[4..]).unwrap();
        assert!(
            matches!(response.response, Some(RespKind::Error(_))),
            "a client blocked on this request's reply must never hang: got {:?}",
            response.response
        );
    }

    /// Two requests queued on the same connection are both served, in order —
    /// `serve` is a persistent per-connection loop, not a one-shot handler.
    #[test]
    fn serve_answers_two_sequential_requests_on_one_connection() {
        let channel = EmbeddedQueryChannel::new();
        let (tx, rx) = channel.split();

        let mut to_read = framed_request(ReqKind::GetNodeInfo(Default::default()));
        to_read.extend_from_slice(&framed_request(ReqKind::GetNodeInfo(Default::default())));
        let mut stream = OneShotStream {
            to_read,
            ..Default::default()
        };

        // Answer exactly two requests, tagging each reply distinctly so the two
        // responses on the wire can be told apart and their order verified.
        let router = async {
            for num_originators in [1u32, 2u32] {
                let request = rx.recv().await;
                assert!(matches!(request.request, Some(ReqKind::GetNodeInfo(_))));
                rx.reply(WayfinderResponse {
                    response: Some(RespKind::NodeInfo(NodeInfo {
                        node_id: std::vec![],
                        num_originators,
                        auth_locked: false,
                        runtime_config_active: false,
                    })),
                })
                .await;
            }
        };

        let (serve_result, ()) =
            futures::executor::block_on(futures::future::join(serve(&mut stream, &tx), router));
        assert!(matches!(serve_result, Err(FrameError::UnexpectedEof)));

        // Decode both response frames off the wire and check their order.
        let mut rest = stream.written.as_slice();
        let mut seen = Vec::new();
        while !rest.is_empty() {
            let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            let response = WayfinderResponse::decode(&rest[4..4 + len]).unwrap();
            match response.response {
                Some(RespKind::NodeInfo(info)) => seen.push(info.num_originators),
                other => panic!("expected NodeInfo, got {other:?}"),
            }
            rest = &rest[4 + len..];
        }
        assert_eq!(
            seen,
            std::vec![1, 2],
            "both requests are answered, in the order they were received"
        );
    }

    /// A response the router produced but that cannot be framed is answered
    /// with an error, and the session carries on.
    ///
    /// The check has to happen *before* the encode, which is what this pins:
    /// `write_frame` refuses an oversized body too, but only once it exists, and
    /// building it is the expensive part. `encode` grows its `Vec` by doubling,
    /// so a response several times `MAX_FRAME_LEN` asks for an allocation
    /// several times again that — which on an embedded node's small heap fails,
    /// and a failed allocation is a panic, and a panic on a board is a reset.
    /// A `GetLogs` answer carrying a full log ring is exactly that shape.
    #[test]
    fn serve_refuses_an_oversized_response_before_encoding_it() {
        let channel = EmbeddedQueryChannel::new();
        let (tx, rx) = channel.split();

        let mut stream = OneShotStream {
            to_read: framed_request(ReqKind::GetNodeInfo(Default::default())),
            ..Default::default()
        };

        // A well-formed response that simply cannot fit a frame.
        let router = async {
            let _request = rx.recv().await;
            rx.reply(WayfinderResponse {
                response: Some(RespKind::NodeInfo(NodeInfo {
                    node_id: std::vec![0u8; MAX_FRAME_LEN * 2],
                    num_originators: 0,
                    auth_locked: false,
                    runtime_config_active: false,
                })),
            })
            .await;
        };

        let (serve_result, ()) =
            futures::executor::block_on(futures::future::join(serve(&mut stream, &tx), router));
        assert!(
            matches!(serve_result, Err(FrameError::UnexpectedEof)),
            "the session survives an unframeable response: {serve_result:?}"
        );

        let len = u32::from_be_bytes(stream.written[..4].try_into().unwrap()) as usize;
        assert!(len <= MAX_FRAME_LEN, "what went out fits a frame: {len}");
        let response = WayfinderResponse::decode(&stream.written[4..]).unwrap();
        assert!(
            matches!(response.response, Some(RespKind::Error(_))),
            "the caller is told, never left waiting: {:?}",
            response.response
        );
    }

    /// An oversized length prefix desynchronises the stream, so `serve` resets
    /// the link (returns `Oversized`) rather than trying to answer it — this is
    /// the one failure mode `serve` cannot treat like a malformed body, since
    /// the frame boundary itself can no longer be trusted.
    #[test]
    fn serve_resets_the_link_on_an_oversized_frame() {
        let channel = EmbeddedQueryChannel::new();
        let (tx, _rx) = channel.split();

        let len = (MAX_FRAME_LEN as u32) + 1;
        let mut stream = OneShotStream {
            to_read: len.to_be_bytes().to_vec(),
            ..Default::default()
        };

        let serve_result = futures::executor::block_on(serve(&mut stream, &tx));
        assert!(
            matches!(serve_result, Err(FrameError::Oversized(l)) if l == len),
            "got {serve_result:?}"
        );
        assert!(
            stream.written.is_empty(),
            "no response is attempted once the frame boundary is untrustworthy"
        );
    }
}
