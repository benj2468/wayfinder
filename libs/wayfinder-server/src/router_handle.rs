//! Shared read access to the node's router, so a management read is served on
//! the connection's own task instead of on the driver's event loop.
//!
//! # What this changes, and what it deliberately does not
//!
//! Every management request used to travel the same path: the connection task
//! forwarded it over `QueryTx`, the driver's `select!` picked it up between
//! frames, built a [`RouterAdapter`](crate::RouterAdapter) against its
//! exclusively-owned `&mut CentralRouter`, and replied. That is still exactly
//! what a *mutation* does, and should be — `set_auth`, `set_config` and
//! `set_log_level` are operator actions, rare, and `set_auth` writes back
//! through an identity-seed slot the loop owns.
//!
//! It was also what every *read* did, and reads are not rare: a dashboard polls
//! seven tables a second, and each one built its response `Vec`s on the loop
//! that forwards mesh frames, one at a time, behind a depth-16 channel. Sixteen
//! of the provider's nineteen methods take `&self` and never touch a byte of
//! router state, so none of that serialisation was buying anything.
//!
//! [`RouterHandle`] gives those reads a shared borrow instead. Three things
//! follow, and the third is the one to keep in mind:
//!
//! * Reads run **concurrently with each other**, on the tasks that asked for
//!   them, rather than single-file through one channel.
//! * A read costs **no round trip**. The old path was a channel send, a loop
//!   wake-up, and a oneshot reply for every `GetNodeInfo`.
//! * A read still **contends with the loop**, because the loop takes the write
//!   lock to handle a frame. This is not a claim that reads are free — it is
//!   that they no longer cost *more* than the work they do. A large `GetLogs`
//!   blocked the loop for its whole duration before and still does; what has
//!   gone is every read waiting behind every other read.
//!
//! [`tokio::sync::RwLock`] is write-preferring, which is what bounds the third
//! point: a waiting writer stops new readers from entering, so a dashboard
//! polling in a tight loop cannot starve the mesh. Do not swap it for a
//! read-preferring lock.
//!
//! # There is no `no_std` twin, on purpose
//!
//! An embedded node keeps the channel (`embedded.rs`). Its executor is
//! cooperative and single-core, and its management port is one serial
//! connection issuing one request at a time — so there is no concurrency for a
//! lock to recover, and an `RwLock` there would be ceremony bought with flash.
//! The `no_std` half of this crate is unchanged.

use alloc::sync::Arc;
use core::time::Duration;

use tokio::sync::RwLock;
use tokio::sync::watch;
use wayfinder::CentralRouter;
use wayfinder_protos::service::EnrollmentPolicyStatusData;
use wayfinder_protos::service::handle_router_read;
use wayfinder_protos::wayfinder::v1alpha::WayfinderRequest;
use wayfinder_protos::wayfinder::v1alpha::WayfinderResponse;

use crate::adapter::RouterView;
use crate::authority_task::EnrollmentPolicyRx;

/// The node state a management read is answered from, held behind one lock.
///
/// The identity seed lives here rather than beside the router because
/// `security_status` reports the keys it derives — the ones a client asks a
/// provider to certify — and a read served off the loop has no other way to see
/// the value a `SetAuth` has since installed. Keeping the two under one lock is
/// also what stops a read from observing a router that has been re-keyed while
/// the seed still names the old identity.
pub struct SharedRouter {
    /// The routing engine. `&mut` only ever through the driver's write guard.
    pub router: CentralRouter,
    /// This node's own identity seed, or `None` on a node that has none.
    ///
    /// Written by `SetAuth` on the driver loop, read here and by the TLS accept
    /// loop's per-connection authorization snapshot — which is what makes a
    /// rotated seed stop earning the self-key tier on the very next connection.
    pub identity_seed: Option<[u8; 32]>,
}

impl SharedRouter {
    /// Wrap `router` with no identity seed configured.
    pub fn new(router: CentralRouter) -> Self {
        Self {
            router,
            identity_seed: None,
        }
    }
}

/// A cloneable handle onto the shared router, for serving management reads.
///
/// Cheap to clone — an `Arc`, an `Instant`, and a `watch::Receiver` — so every
/// connection task can hold one. Holds no mutable capability at all: there is
/// no method here that takes a write lock, which is what makes "reads are
/// served from this, mutations from the loop" a property of the type rather
/// than a rule to remember.
#[derive(Clone)]
pub struct RouterHandle {
    inner: Arc<RwLock<SharedRouter>>,
    /// Reference instant for the router's monotonic clock — the same `start`
    /// the driver measures `now` from.
    ///
    /// Read here rather than passed in per request because a read must be
    /// evaluated at the instant it is served: throughput is a *rate*, so an
    /// interface that has gone quiet has to read as decaying rather than stale.
    start: std::time::Instant,
    /// The enrollment policy the authority task publishes.
    ///
    /// A `watch` receiver, read without awaiting: the router loop must never
    /// block on the authority (it may be mid-Argon2id) and neither may a
    /// connection task holding a read lock the loop is waiting to take.
    ///
    /// Still an `Option` at the *handle* level — a caller may decline to wire
    /// one — but the receiver inside is valid from the moment `AuthorityComms`
    /// is constructed, so a handle built before `attach_authority` observes the
    /// policy an authority publishes afterwards. Capturing a dead receiver was
    /// otherwise a silent way to report "no enrollment policy" forever on a CA.
    enrollment: Option<EnrollmentPolicyRx>,
    /// Whether the driver's clock is disciplined enough for a credential
    /// decision, as its loop last published it.
    ///
    /// A `watch` receiver read without awaiting, exactly like `enrollment`, and
    /// for the same two reasons: the driver loop must never block on a reader,
    /// and a reader holding the read lock must never block on the loop.
    ///
    /// Absent where nothing publishes one — a test handle, and the embedded
    /// path — which reports `true`: "no clock policy to report" is the honest
    /// answer for a node whose time comes from elsewhere, and is what
    /// `RouterView` defaults to.
    clock_trusted: Option<watch::Receiver<bool>>,
}

impl RouterHandle {
    /// Build a handle over `inner`, whose router's monotonic clock is measured
    /// from `start`.
    pub fn new(inner: Arc<RwLock<SharedRouter>>, start: std::time::Instant) -> Self {
        Self {
            inner,
            start,
            enrollment: None,
            clock_trusted: None,
        }
    }

    /// Report the enrollment policy from `rx` on `GetSecurityStatus`.
    ///
    /// Absent on a node that runs no certificate authority, which reports no
    /// policy rather than a default one — "not reported" and "open" are
    /// different answers and a dashboard renders them differently.
    #[must_use]
    pub fn with_enrollment_policy(mut self, rx: Option<EnrollmentPolicyRx>) -> Self {
        self.enrollment = rx;
        self
    }

    /// Report the clock-trust verdict from `rx` on `GetNodeInfo`.
    ///
    /// The driver's own verdict, forwarded — never recomputed here. This half
    /// runs on a connection task with no view of the driver's clock policy, and
    /// a second opinion formed locally would be free to disagree with the one
    /// the node's auth clock actually acted on.
    #[must_use]
    pub fn with_clock_trust(mut self, rx: Option<watch::Receiver<bool>>) -> Self {
        self.clock_trusted = rx;
        self
    }

    /// The shared state, for a test that needs to hold a guard against this
    /// handle or write through it.
    ///
    /// `cfg(test)`: production never needs it. The driver owns the `Arc` and
    /// takes its own guards; nothing else may take the write half at all, which
    /// is the property this type exists to hold. A `pub` accessor here would be
    /// the one crack in it.
    #[cfg(test)]
    fn shared(&self) -> Arc<RwLock<SharedRouter>> {
        Arc::clone(&self.inner)
    }

    /// Answer one [`RequestFacet::RouterRead`] request under a shared borrow.
    ///
    /// Returns the request unconsumed as `Err` when this half does not own it —
    /// a mutation, or a request belonging to the authority or the transport — so
    /// a caller that has mis-forked can still route it correctly rather than
    /// answering with an error it invented.
    ///
    /// [`RequestFacet::RouterRead`]: wayfinder_protos::service::RequestFacet::RouterRead
    pub async fn serve_read(
        &self,
        request: WayfinderRequest,
    ) -> Result<WayfinderResponse, WayfinderRequest> {
        // Sampled before the lock is taken, so a request that waited on a busy
        // loop is still evaluated at the instant it is *served* rather than the
        // instant it was queued.
        let enrollment = self.enrollment_policy();
        let clock_trusted = self.clock_trusted();
        let guard = self.inner.read().await;
        let now = self.now();
        let view = RouterView::new(&guard.router, now)
            .with_clock_trusted(clock_trusted)
            .with_enrollment_policy(enrollment)
            .with_identity(guard.identity_seed);
        handle_router_read(&view, request)
    }

    /// This node's monotonic clock, as the driver's loop measures it.
    fn now(&self) -> Duration {
        self.start.elapsed()
    }

    /// The enrollment policy in force, read without awaiting the authority.
    fn enrollment_policy(&self) -> Option<EnrollmentPolicyStatusData> {
        self.enrollment.as_ref().and_then(|rx| rx.borrow().clone())
    }

    /// The driver's clock-trust verdict, read without awaiting its loop.
    ///
    /// `true` where no publisher was wired — see the field's doc comment.
    fn clock_trusted(&self) -> bool {
        self.clock_trusted.as_ref().is_none_or(|rx| *rx.borrow())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wayfinder::interfaces::frame::Mac;
    use wayfinder_protos::wayfinder::v1alpha::GetNodeInfoRequest;
    use wayfinder_protos::wayfinder::v1alpha::SetAuthRequest;
    use wayfinder_protos::wayfinder::v1alpha::wayfinder_request::Request as ReqKind;
    use wayfinder_protos::wayfinder::v1alpha::wayfinder_response::Response as RespKind;

    fn mac(n: u8) -> Mac {
        Mac([0, 0, 0, 0, 0, n])
    }

    fn handle(node: Mac) -> RouterHandle {
        let shared = Arc::new(RwLock::new(SharedRouter::new(CentralRouter::new(node))));
        RouterHandle::new(shared, std::time::Instant::now())
    }

    fn request(kind: ReqKind) -> WayfinderRequest {
        WayfinderRequest {
            request: Some(kind),
        }
    }

    /// The point of the type: a read is answered from the handle, with no
    /// channel and no driver loop involved.
    #[tokio::test]
    async fn a_read_is_answered_from_the_shared_borrow() {
        let handle = handle(mac(7));

        let response = handle
            .serve_read(request(ReqKind::GetNodeInfo(GetNodeInfoRequest {})))
            .await
            .expect("GetNodeInfo is a router read");

        match response.response {
            Some(RespKind::NodeInfo(info)) => {
                assert_eq!(info.node_id, mac(7).0.to_vec());
            }
            other => panic!("expected NodeInfo, got {other:?}"),
        }
    }

    /// A mutation handed to the read path comes back *unanswered*, so the
    /// caller forwards it to the loop rather than the read path inventing a
    /// refusal — or, far worse, silently reporting success for a change it
    /// never made.
    ///
    /// This is the runtime half of a guarantee the type system already makes:
    /// `RouterView` implements `RouterReads` and not `RouterWrites`, so
    /// `handle_router_read` has no arm for `SetAuth` to reach.
    #[tokio::test]
    async fn a_mutation_is_declined_rather_than_answered() {
        let handle = handle(mac(1));

        let outcome = handle
            .serve_read(request(ReqKind::SetAuth(SetAuthRequest::default())))
            .await;

        match outcome {
            Err(returned) => assert!(
                matches!(returned.request, Some(ReqKind::SetAuth(_))),
                "the request must come back intact for the caller to forward"
            ),
            Ok(response) => panic!("a mutation was answered by the read path: {response:?}"),
        }
    }

    /// Two reads are in flight at once, and neither waits for the other.
    ///
    /// Written as a *held* read guard plus a concurrent `serve_read` because
    /// that is the property the change exists for: under the old query channel
    /// the second read could not begin until the first had been answered by the
    /// driver loop. A `RwLock` admits both.
    #[tokio::test]
    async fn reads_do_not_exclude_each_other() {
        let handle = handle(mac(3));
        let shared = handle.shared();

        // Held across the call below. If reads excluded each other this would
        // deadlock, and the test would hang rather than fail — which is why the
        // timeout is here.
        let held = shared.read().await;

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            handle.serve_read(request(ReqKind::GetNodeInfo(GetNodeInfoRequest {}))),
        )
        .await
        .expect("a second reader was blocked by the first")
        .expect("GetNodeInfo is a router read");

        assert!(matches!(response.response, Some(RespKind::NodeInfo(_))));
        drop(held);
    }

    /// A read completes while a *writer* holds the router across a long
    /// operation — the shape of the driver loop sending on a slow link.
    ///
    /// This is the MR's thesis stated as a test, and it is the inverse of
    /// `a_writer_excludes_a_reader` above: that one pins that a writer *does*
    /// exclude while it holds the guard, this one pins that the driver does not
    /// hold the guard for the part that takes real time. `dispatch` plans a
    /// frame under the write guard, drops it, sends on the link, and retakes
    /// the guard to record — so a read overlaps the send.
    ///
    /// Written against the lock rather than a real `Driver` because the
    /// property belongs to the lock discipline, not to any one carrier: anyone
    /// "simplifying" `dispatch` by holding one guard across the send passes
    /// every other test in this crate and stalls management reads for the
    /// length of a LoRa transmission.
    #[tokio::test]
    async fn a_read_completes_while_a_send_is_in_flight() {
        let handle = handle(mac(6));
        let shared = handle.shared();

        // Stand in for `dispatch`: take the guard to plan, drop it, then spend
        // a long time "on the link" without holding anything.
        let sending = {
            let shared = Arc::clone(&shared);
            tokio::spawn(async move {
                {
                    let _plan = shared.write().await;
                }
                // The link send. No router guard held here — that is the whole
                // property under test.
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                let mut record = shared.write().await;
                record.identity_seed = Some([9u8; 32]);
            })
        };
        tokio::task::yield_now().await;

        // Must not wait out the send.
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            handle.serve_read(request(ReqKind::GetNodeInfo(GetNodeInfoRequest {}))),
        )
        .await
        .expect("a read waited for a link send to finish")
        .expect("GetNodeInfo is a router read");

        sending.await.expect("the sending task panicked");
    }

    /// A read observes a write that has completed, rather than a snapshot taken
    /// when the handle was built.
    ///
    /// `SharedRouter` co-locates the identity seed with the router, and its doc
    /// says why: so a read cannot see a router that has been re-keyed while the
    /// seed still names the old identity. Both are read under one guard, so the
    /// pairing holds — this pins the other half, that the handle reads the live
    /// value at all rather than having copied one at construction.
    #[tokio::test]
    async fn a_read_sees_a_completed_write() {
        let handle = handle(mac(8));
        let shared = handle.shared();

        // Before: no identity, so no keys reported.
        let before = handle
            .serve_read(request(ReqKind::GetSecurityStatus(
                wayfinder_protos::wayfinder::v1alpha::GetSecurityStatusRequest {},
            )))
            .await
            .expect("GetSecurityStatus is a router read");
        match before.response {
            Some(RespKind::SecurityStatus(status)) => assert!(
                status.own_ed_pubkey.is_empty(),
                "a node with no seed must report no identity"
            ),
            other => panic!("expected SecurityStatus, got {other:?}"),
        }

        shared.write().await.identity_seed = Some([3u8; 32]);

        // After: the same handle reports the installed identity.
        let after = handle
            .serve_read(request(ReqKind::GetSecurityStatus(
                wayfinder_protos::wayfinder::v1alpha::GetSecurityStatusRequest {},
            )))
            .await
            .expect("GetSecurityStatus is a router read");
        match after.response {
            Some(RespKind::SecurityStatus(status)) => assert!(
                !status.own_ed_pubkey.is_empty(),
                "the handle reported no identity after one was installed; it is \
                 reading a snapshot rather than the shared slot"
            ),
            other => panic!("expected SecurityStatus, got {other:?}"),
        }
    }

    /// A *waiting* writer stops new readers entering.
    ///
    /// This is the property the module header calls load-bearing ("a dashboard
    /// polling in a tight loop cannot starve the mesh. Do not swap it for a
    /// read-preferring lock") and it is the one no other test here exercises —
    /// `a_writer_excludes_a_reader` holds a write guard, which excludes readers
    /// under *any* lock. Swap in a read-preferring lock and that test stays
    /// green while the driver loop starves under dashboard load.
    ///
    /// So: hold a read, queue a writer behind it, and assert a *second* read
    /// cannot overtake the queued writer.
    #[tokio::test]
    async fn a_waiting_writer_blocks_a_new_reader() {
        let handle = handle(mac(5));
        let shared = handle.shared();

        let first_reader = shared.read().await;

        // Queue a writer. It cannot proceed while `first_reader` is held, so it
        // parks — which is precisely the state a read-preferring lock would let
        // later readers walk past.
        let writer_shared = Arc::clone(&shared);
        let writer = tokio::spawn(async move {
            let _guard = writer_shared.write().await;
        });
        // Let the writer actually reach its await before testing the reader.
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let overtaken = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            handle.serve_read(request(ReqKind::GetNodeInfo(GetNodeInfoRequest {}))),
        )
        .await;
        assert!(
            overtaken.is_err(),
            "a new reader overtook a waiting writer; this lock is read-preferring \
             and the driver loop can be starved by dashboard polling"
        );

        // Everything drains once the first reader lets go.
        drop(first_reader);
        writer.await.expect("the writer task panicked");
        handle
            .serve_read(request(ReqKind::GetNodeInfo(GetNodeInfoRequest {})))
            .await
            .expect("GetNodeInfo is a router read");
    }

    /// Every request kind the table calls a read is answered by the read
    /// dispatcher, and every kind it does not call a read is declined by it.
    ///
    /// This is the check that was missing, and its absence was the one
    /// misclassification with no detector at all. Trace the three ways an
    /// `owner:` can be wrong:
    ///
    /// * A read declared `RouterRead` with no arm in `handle_router_read` —
    ///   declined, warned about in `serve_by_facet`, forwarded, and answered
    ///   "request has no handler on this node". Loud.
    /// * A *write* declared `RouterRead` — declined, warned about, forwarded,
    ///   and served correctly by the loop. Wrong but visible, and it still
    ///   works.
    /// * A *read* declared `RouterWrite` — forwarded to the loop forever, with
    ///   **no warning, no error and no metric**. It is served correctly, just
    ///   on the slow path this whole module exists to take it off. Silent.
    ///
    /// Mutation testing confirmed the third: flipping `GetLogs` to
    /// `RouterWrite` — pushing the single largest read back onto the driver
    /// loop — left the entire suite green. So the agreement is pinned here
    /// rather than trusted, which also makes `serve_by_facet`'s "should not
    /// happen" warn genuinely unreachable.
    ///
    /// Lives in `wayfinder-server` rather than beside the table in
    /// `wayfinder-protos` because it needs both halves at once: the generated
    /// `every_request_kind()` and a concrete `RouterReads`/`RouterWrites`
    /// implementor to dispatch against.
    #[test]
    fn the_read_facet_and_the_read_dispatcher_agree_on_every_kind() {
        use wayfinder_protos::rpc::RequestFacet;
        use wayfinder_protos::rpc::every_request_kind;
        use wayfinder_protos::rpc::request_facet;
        use wayfinder_protos::rpc::request_kind_name;
        use wayfinder_protos::service::handle_router_read;

        let router = CentralRouter::new(mac(1));

        for kind in every_request_kind() {
            let view = RouterView::new(&router, Duration::from_secs(1));
            let answered = handle_router_read(
                &view,
                WayfinderRequest {
                    request: Some(kind.clone()),
                },
            )
            .is_ok();
            let declared = request_facet(&kind) == RequestFacet::RouterRead;
            assert_eq!(
                answered,
                declared,
                "{}: the table says {:?} but the read dispatcher {} it",
                request_kind_name(&kind),
                request_facet(&kind),
                if answered { "answered" } else { "declined" },
            );
        }
    }

    /// The mirror of the sweep above, for the mutating half.
    ///
    /// Asserted separately rather than folded in, because the two dispatchers
    /// take different borrows and a single loop would need a `&mut` it could
    /// not also lend out as `&`.
    #[test]
    fn the_write_facet_and_the_write_dispatcher_agree_on_every_kind() {
        use wayfinder_protos::rpc::RequestFacet;
        use wayfinder_protos::rpc::every_request_kind;
        use wayfinder_protos::rpc::request_facet;
        use wayfinder_protos::rpc::request_kind_name;
        use wayfinder_protos::service::handle_router_write;

        let mut router = CentralRouter::new(mac(2));

        for kind in every_request_kind() {
            let mut adapter = crate::RouterAdapter::new(&mut router, Duration::from_secs(1));
            let answered = handle_router_write(
                &mut adapter,
                WayfinderRequest {
                    request: Some(kind.clone()),
                },
            )
            .is_ok();
            let declared = request_facet(&kind) == RequestFacet::RouterWrite;
            assert_eq!(
                answered,
                declared,
                "{}: the table says {:?} but the write dispatcher {} it",
                request_kind_name(&kind),
                request_facet(&kind),
                if answered { "answered" } else { "declined" },
            );
        }
    }

    /// A writer excludes readers, which is what keeps the driver loop able to
    /// forward a frame while a dashboard polls: `tokio`'s `RwLock` is
    /// write-preferring, so a waiting writer stops new readers entering rather
    /// than being starved behind an endless stream of them.
    #[tokio::test]
    async fn a_writer_excludes_a_reader() {
        let handle = handle(mac(4));
        let shared = handle.shared();

        let held = shared.write().await;
        let blocked = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            handle.serve_read(request(ReqKind::GetNodeInfo(GetNodeInfoRequest {}))),
        )
        .await;
        assert!(
            blocked.is_err(),
            "a read ran while the write guard was held"
        );

        // And it completes once the writer lets go, rather than being lost.
        drop(held);
        handle
            .serve_read(request(ReqKind::GetNodeInfo(GetNodeInfoRequest {})))
            .await
            .expect("GetNodeInfo is a router read");
    }
}
