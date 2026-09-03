//! A mesh link carried over [iroh](https://docs.iroh.computer) peer-to-peer
//! QUIC, dialing peers by their Ed25519 identity key instead of by an IP
//! address.
//!
//! The internet-facing counterpart to [`UdpMultiLink`](crate::UdpMultiLink):
//! where that link reaches a CGNAT'd peer by riding a Tailscale tunnel that a
//! separate daemon and a separate coordination server keep up, this one does
//! the hole punching itself and needs neither. The node's own identity seed is
//! its network address, so the key already bound to its `MembershipCert` is
//! what peers dial — there is no second credential to mint, correlate or
//! revoke.
//!
//! See `docs/design/18-iroh-mesh-links.md` for the full argument, including
//! why this is host-only and always will be (§2) and why it is a `LinkT`
//! rather than a tunnel underneath one (§3.1).
//!
//! Structurally this is [`UdpMultiLink`](crate::UdpMultiLink) with an
//! `EndpointId` where that link keeps a `SocketAddr`: the same learn-from-
//! received-frames peer table, the same bound and TTL, the same drop-rather-
//! than-guess discipline for a destination not yet heard from. That parallel
//! is deliberate — see design 18 §3.2.

#[cfg(feature = "iroh")]
mod imp {
    use std::collections::HashMap;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::Instant;

    use bytes::Bytes;
    use interfaces::frame::LinkFrame;
    use interfaces::frame::LinkFrameData;
    use interfaces::frame::MAX_LINK_FRAME_LEN;
    use interfaces::frame::Mac;
    use interfaces::link::LinkError;
    use interfaces::link::LinkMetrics;
    use interfaces::wire::frame_into_buf;
    use iroh::Endpoint;
    use iroh::EndpointAddr;
    use iroh::EndpointId;
    use iroh::RelayMode;
    use iroh::endpoint::Connection;
    use iroh::endpoint::presets;
    use tokio::sync::Mutex;
    use tokio::sync::mpsc;
    use wayfinder::link::DynLinkT;
    use wayfinder::link::LinkT;
    use wayfinder::link::Received;
    use wayfinder_link_utils::FRAG_HDR_LEN;
    use wayfinder_link_utils::FragKey;
    use wayfinder_link_utils::MAX_FRAGMENTS;
    use wayfinder_link_utils::pack_header;
    use wayfinder_link_utils::parse_fragment;
    use zerocopy::FromBytes;

    /// The ALPN this link negotiates. Versioned, because it names a wire
    /// contract (BATMAN link frames as QUIC datagrams) that a later revision
    /// could change — a peer speaking a different one is refused by the QUIC
    /// handshake rather than by us discovering it mid-frame.
    const MESH_ALPN: &[u8] = b"wayfinder/mesh/1";

    /// How many neighbor MACs the learned peer table holds, evicting the
    /// least-recently-heard entry to admit a new one beyond this.
    ///
    /// Matches `UdpMultiLink`'s bound, and exists for a weaker version of the
    /// same reason. A UDP datagram's source address is merely asserted, so an
    /// attacker grows that table with spoofed sources; here an entry can only
    /// be created by a peer that completed a QUIC handshake proving possession
    /// of that `EndpointId`'s private key, which is a real cost per entry. The
    /// cap stays anyway: authenticating a frame is not the same as earning a
    /// permanent table slot.
    const MAX_TRACKED_PEERS: usize = 128;

    /// The per-datagram budget this link fragments to.
    ///
    /// A QUIC datagram is capped by the path MTU, which is discovered at
    /// runtime and varies per connection — where every other fragmenting
    /// carrier here has a fixed medium limit. Rather than track a moving
    /// target, this is a fixed floor chosen conservatively below what QUIC
    /// guarantees on any real path ("a little over a kilobyte at minimum"
    /// when the peer's limit is large), so a fragment always fits.
    ///
    /// `send` still checks `Connection::max_datagram_size` against it: a path
    /// that cannot carry even this is a reported drop, not a silent one.
    const IROH_DATAGRAM_FLOOR: usize = 1024;

    /// Content bytes per fragment, after the 2-byte fragmentation header.
    /// Follows the same `medium limit - FRAG_HDR_LEN` shape as `rylr998` and
    /// `blue`.
    const FRAG_PAYLOAD: usize = IROH_DATAGRAM_FLOOR - FRAG_HDR_LEN;

    /// Concurrent in-flight reassemblies. One per peer mid-transfer; a mesh
    /// frame needs at most two fragments at [`FRAG_PAYLOAD`], so this is deep
    /// enough for every peer on a busy hub to have one outstanding.
    const MAX_REASSEMBLIES: usize = 32;

    /// Reassembly state, keyed by the endpoint a fragment arrived from —
    /// which, unlike a UDP source address or a LoRa `AT+ADDRESS`, is
    /// cryptographically proven, so one peer cannot inject fragments into
    /// another's reassembly.
    type IrohReassembler = wayfinder_link_utils::Reassembler<
        EndpointId,
        MAX_REASSEMBLIES,
        FRAG_PAYLOAD,
        MAX_LINK_FRAME_LEN,
    >;

    /// How long a learned peer stays eligible for unicast resolution after it
    /// was last heard from. Checked lazily against a caller-supplied `now`, so
    /// a departed peer ages out with no timer.
    const PEER_TTL: Duration = Duration::from_secs(600);

    /// Learned mapping of neighbor MAC to the iroh endpoint its frames arrive
    /// from, refreshed from `Connection::remote_id()` on every receive.
    ///
    /// A neighbor is only ever learned this way — there is no static peer list
    /// beyond the bootstrap dial — so a destination is reachable by unicast
    /// only once at least one frame (in practice an OGM) has been heard from
    /// it. Bounded by [`MAX_TRACKED_PEERS`] and aged by [`PEER_TTL`].
    ///
    /// **Unicast resolution only.** A broadcast fans out over the live
    /// connection set instead — see [`IrohLink::send`] for why the table is
    /// the wrong source for that.
    #[derive(Default)]
    pub(super) struct IrohPeerTable {
        peers: HashMap<Mac, (EndpointId, Instant)>,
    }

    impl IrohPeerTable {
        /// Record (or refresh, if it moved) the endpoint a frame from `mac`
        /// was most recently heard from, at `now`.
        ///
        /// If this is a new peer and the table is at [`MAX_TRACKED_PEERS`],
        /// the least-recently-heard entry is evicted first — a departed peer
        /// is by construction the likeliest candidate.
        pub(super) fn learn(&mut self, mac: Mac, id: EndpointId, now: Instant) {
            let at_capacity =
                !self.peers.contains_key(&mac) && self.peers.len() >= MAX_TRACKED_PEERS;
            if at_capacity
                && let Some(&oldest) = self
                    .peers
                    .iter()
                    .min_by_key(|(_, (_, heard_at))| *heard_at)
                    .map(|(mac, _)| mac)
            {
                self.peers.remove(&oldest);
            }
            self.peers.insert(mac, (id, now));
        }

        /// The endpoint most recently learned for `mac`, if it was heard from
        /// within [`PEER_TTL`] of `now`.
        pub(super) fn resolve(&self, mac: Mac, now: Instant) -> Option<EndpointId> {
            self.peers
                .get(&mac)
                .filter(|(_, heard_at)| now.saturating_duration_since(*heard_at) < PEER_TTL)
                .map(|(id, _)| *id)
        }

        /// Invariants: the table never exceeds its cap, and no MAC is recorded
        /// twice (a `HashMap` guarantees the latter structurally; asserting it
        /// keeps the property visible if the backing store ever changes).
        #[cfg(test)]
        pub(super) fn assert_invariants(&self) {
            assert!(
                self.peers.len() <= MAX_TRACKED_PEERS,
                "peer table over capacity: {} > {MAX_TRACKED_PEERS}",
                self.peers.len()
            );
            let distinct: HashSet<&Mac> = self.peers.keys().collect();
            assert_eq!(distinct.len(), self.peers.len(), "a MAC appears twice");
        }
    }

    /// Live connections, shared between the accept loop, the per-connection
    /// reader tasks, and [`IrohLink::send`].
    type ConnMap = Arc<Mutex<HashMap<EndpointId, Connection>>>;

    /// One received datagram, tagged with the endpoint it arrived from.
    type Inbound = (EndpointId, Bytes);

    /// Everything needed to stand up an iroh mesh link. See the matching
    /// fields on `wayfinder::config::LinkTransport::Iroh` for what each means
    /// to an operator.
    pub struct IrohLinkParams {
        /// UDP port the QUIC endpoint binds; `None` picks an ephemeral one.
        pub bind_port: Option<u16>,
        /// A self-hosted `iroh-relay` URL, or `None` to disable relaying
        /// entirely. Never iroh's public relays — design 18 §3.6.
        pub relay_url: Option<String>,
        /// Hex-encoded Ed25519 public keys to dial at startup.
        pub bootstrap_peers: Vec<String>,
        /// The certificate-derived `Mac → key` directory this link resolves
        /// through before falling back to what it learned from received
        /// frames. Default (empty) is correct for a mesh with authentication
        /// off; see [`crate::AuthView`].
        pub directory: crate::AuthView,
    }

    /// The parts of an [`IrohLink`] that exist only once the node has an
    /// identity to bind an endpoint to.
    struct Bound {
        /// The QUIC endpoint. Retained for dialing; the accept loop runs on
        /// its own task against a clone.
        endpoint: Endpoint,
        /// The identity seed this endpoint was bound to, so a rotation is
        /// detectable without re-deriving the public half.
        seed: [u8; 32],
        /// Connections currently usable for sending.
        conns: ConnMap,
        /// Endpoints a background dial is already in flight for.
        dialing: Arc<Mutex<HashSet<EndpointId>>>,
        /// Datagrams from every live connection, fed by the reader tasks.
        inbox: mpsc::Receiver<Inbound>,
        /// Handed to each new connection's reader task.
        inbox_tx: mpsc::Sender<Inbound>,
        /// Cancels the accept loop when this endpoint is torn down.
        accept_task: tokio::task::AbortHandle,
    }

    /// A mesh interface carried over iroh peer-to-peer QUIC. Construct with
    /// [`build_iroh_link`].
    ///
    /// **Dormant until the node has an identity.** A link's endpoint key *is*
    /// this node's identity key, and a node that has not enrolled has no
    /// identity worth announcing — the seed it generated at boot may not be the
    /// one it ends up certified under, since `SetAuth` can install a wholly new
    /// one. Binding early would put an endpoint on the air under a key no
    /// certificate names, and rebinding later would move the node's address
    /// mid-flight.
    ///
    /// So the link is created inert: it binds nothing, dials nothing, and drops
    /// every frame with a reason. When [`AuthView`](crate::AuthView) reports an
    /// identity it binds and begins dialing its bootstrap peers; if the
    /// identity is later rotated it tears the endpoint down and rebinds. Both
    /// transitions are live, because `SetAuth` replaces the router's auth
    /// without a restart.
    pub struct IrohLink {
        /// `None` until this node has an identity; see the type docs.
        bound: Option<Bound>,
        /// The port every binding uses, so a rebind lands on the same one.
        bind_port: Option<u16>,
        /// Relay configuration, retained for rebinding.
        relay_url: Option<String>,
        /// Bootstrap peers, redialled on every (re)bind.
        bootstrap: Vec<EndpointAddr>,
        /// Learned neighbor endpoints, refreshed on every receive. Consulted
        /// only when [`directory`](Self::directory) has nothing for a MAC.
        peers: IrohPeerTable,
        /// Certificate-derived auth state, published by the driver:
        /// authoritative for peer resolution where it has an answer (see
        /// [`Self::resolve_dst`]), and the source of the stale-key sweep that
        /// closes revoked and superseded connections (see [`Self::reconcile`]).
        directory: crate::AuthView,
        /// Wakes [`recv`](LinkT::recv) when the auth view changes, so an idle
        /// link closes a revoked connection promptly instead of waiting for a
        /// send it may never make.
        auth_changed: tokio::sync::watch::Receiver<u64>,
        /// The [`crate::AuthView`] generation this link has already swept for.
        /// Compared on every send, so the common case — nothing changed — costs
        /// one integer load rather than a lock and a table walk.
        swept_generation: u64,
        /// Reassembly state for inbound fragmented frames.
        ///
        /// Boxed: the table is `MAX_REASSEMBLIES` buffers of
        /// `MAX_LINK_FRAME_LEN` each — tens of kilobytes, sized that way
        /// because `wayfinder-link-utils` is a `no_std` type that owns its
        /// storage inline. Inline here it would make every move of an
        /// `IrohLink` a large memcpy and put that much on the stack of anything
        /// holding one by value. This carrier is host-only and has an
        /// allocator, so it uses it; the `no_std` carriers that cannot keep
        /// theirs inline with much smaller bounds.
        reassembler: Box<IrohReassembler>,
        /// Per-link fragmentation message counter, wrapping. Distinguishes
        /// concurrent messages from the same peer; a wrap that collides with
        /// an in-flight reassembly resets that slot rather than merging (see
        /// `Reassembler::accept`).
        next_msg_id: u8,
        /// Scratch buffer for the most recently sent or received frame, sized
        /// like every other data-path buffer.
        wire_buf: [u8; MAX_LINK_FRAME_LEN],
    }

    impl IrohLink {
        /// Register `conn` and start reading datagrams off it.
        ///
        /// Shared by the accept loop and the dialer so an inbound and an
        /// outbound connection are treated identically once established —
        /// which side dialed says nothing about which direction frames flow.
        fn adopt(conns: &ConnMap, tx: &mpsc::Sender<Inbound>, conn: Connection) {
            // Infallible: iroh verifies the peer's identity during the QUIC
            // handshake, so a `Connection` that exists at all has one. This is
            // the property the whole link rests on — the endpoint a frame
            // arrived from is proven, not asserted the way a UDP source
            // address is.
            let remote = conn.remote_id();
            let conns = Arc::clone(conns);
            let tx = tx.clone();
            tokio::spawn(async move {
                conns.lock().await.insert(remote, conn.clone());
                tracing::debug!(peer = %remote.fmt_short(), "iroh connection established");
                loop {
                    match conn.read_datagram().await {
                        Ok(bytes) => {
                            // A full inbox means the driver loop is behind.
                            // Dropping the frame is right: the mesh re-emits,
                            // and blocking here would stall every *other*
                            // peer's reader behind this one.
                            if tx.try_send((remote, bytes)).is_err() {
                                tracing::trace!(
                                    peer = %remote.fmt_short(),
                                    "drop: iroh inbox full"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::debug!(
                                peer = %remote.fmt_short(),
                                error = ?e,
                                "iroh connection closed"
                            );
                            conns.lock().await.remove(&remote);
                            return;
                        }
                    }
                }
            });
        }

        /// Start a background dial to `peer` unless one is already in flight.
        ///
        /// Never awaited by [`send`](LinkT::send): a QUIC handshake plus a
        /// hole punch is far longer than the driver's event loop can be held.
        /// See design 18 §3.5.
        fn dial(bound: &Bound, addr: EndpointAddr) {
            let endpoint = bound.endpoint.clone();
            let conns = Arc::clone(&bound.conns);
            let dialing = Arc::clone(&bound.dialing);
            let tx = bound.inbox_tx.clone();
            let peer = addr.id;
            tokio::spawn(async move {
                if !dialing.lock().await.insert(peer) {
                    return;
                }
                match endpoint.connect(addr, MESH_ALPN).await {
                    Ok(conn) => Self::adopt(&conns, &tx, conn),
                    // Expected whenever a peer is off, unreachable, or not yet
                    // listening — a mesh node retries on its own cadence, so
                    // this is not an operator-actionable failure.
                    Err(e) => {
                        tracing::debug!(peer = %peer.fmt_short(), error = ?e, "iroh dial failed")
                    }
                }
                dialing.lock().await.remove(&peer);
            });
        }

        /// The endpoint to address `dst` at: the certificate directory first,
        /// then whatever was learned from received frames.
        ///
        /// The order is the point. A learned entry records *who relayed* a
        /// frame, which on a hub topology is the hub for every spoke behind it
        /// — deliverable, but it sends every spoke-to-spoke packet through the
        /// hub. A certificate binds a MAC to the key of the node that actually
        /// owns it, so a directory hit is a direct path where the learned
        /// answer was a detour.
        ///
        /// The learned table is still the fallback, not dead weight: it is the
        /// only answer with authentication disabled, and the only answer for a
        /// peer whose certificate this node has not fetched yet.
        fn resolve_dst(&self, dst: Mac, now: Instant) -> Option<EndpointId> {
            if let Some(key) = self.directory.resolve(dst)
                && let Ok(id) = EndpointId::from_bytes(&key)
            {
                return Some(id);
            }
            self.peers.resolve(dst, now)
        }

        /// Bind a QUIC endpoint to `seed` and start its accept loop.
        async fn bind(&self, seed: [u8; 32]) -> anyhow::Result<Bound> {
            let relay_mode = match self.relay_url.as_deref() {
                Some(url) => RelayMode::custom([url
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid iroh relay_url {url}: {e}"))?]),
                None => RelayMode::Disabled,
            };
            let mut builder = Endpoint::builder(presets::Minimal)
                .secret_key(iroh::SecretKey::from_bytes(&seed))
                .alpns(vec![MESH_ALPN.to_vec()])
                .relay_mode(relay_mode);
            if let Some(port) = self.bind_port {
                builder = builder.bind_addr(std::net::SocketAddr::from(([0, 0, 0, 0], port)))?;
            }
            let endpoint = builder.bind().await?;

            tracing::info!(
                endpoint_id = %endpoint.id(),
                bootstrap_peers = self.bootstrap.len(),
                ca_from_enrolment = self.directory.ca_endpoint().is_some(),
                relayed = self.relay_url.is_some(),
                "iroh mesh link bound"
            );

            let (inbox_tx, inbox) = mpsc::channel(256);
            let conns: ConnMap = Arc::new(Mutex::new(HashMap::new()));
            let accept_task = {
                let endpoint = endpoint.clone();
                let conns = Arc::clone(&conns);
                let tx = inbox_tx.clone();
                tokio::spawn(async move {
                    while let Some(incoming) = endpoint.accept().await {
                        match incoming.await {
                            Ok(conn) => IrohLink::adopt(&conns, &tx, conn),
                            // Reachable by arbitrary remote input (a half-open
                            // scan, a mismatched ALPN), so this must never be
                            // louder than `trace!`.
                            Err(e) => {
                                tracing::trace!(error = ?e, "drop: inbound iroh handshake failed")
                            }
                        }
                    }
                })
                .abort_handle()
            };

            Ok(Bound {
                endpoint,
                seed,
                conns,
                dialing: Arc::new(Mutex::new(HashSet::new())),
                inbox,
                inbox_tx,
                accept_task,
            })
        }

        /// Bind the endpoint if this node has an identity and none is bound, or
        /// rebind if the identity was rotated.
        ///
        /// Doing nothing is the correct behaviour before enrolment: a link's
        /// endpoint key is the node's identity, so there is no address to take
        /// until one exists. Binding to the boot-generated seed and rebinding
        /// later would move the node mid-flight, and would advertise an
        /// endpoint under a key no certificate names.
        async fn rebind_if_identity_changed(&mut self) {
            let identity = self.directory.identity();
            match (&self.bound, identity) {
                // Already bound to this identity: nothing to do, the common
                // case on every generation bump.
                (Some(b), Some(seed)) if b.seed == seed => return,
                // Never had one, still does not.
                (None, None) => return,
                // The identity went away — the node was un-enrolled. Tear the
                // endpoint down rather than keep announcing a key the mesh no
                // longer vouches for.
                (Some(_), None) => {
                    tracing::info!("iroh link going dormant: this node has no identity");
                    self.teardown().await;
                    return;
                }
                // First identity, or a rotation. Both bind; a rotation tears
                // the old endpoint down first so the key it announced stops
                // answering.
                (Some(_), Some(_)) => {
                    tracing::info!("iroh link rebinding: this node's identity was rotated");
                    self.teardown().await;
                }
                (None, Some(_)) => {}
            }
            let Some(seed) = identity else {
                return;
            };
            match self.bind(seed).await {
                Ok(bound) => {
                    // The authority first, and it is usually the only one: a
                    // node that enrolled online was *told* where the authority
                    // is (`SetAuth`), so it needs nothing in its config to find
                    // its way onto the mesh. A configured bootstrap peer is the
                    // fallback for a node provisioned entirely offline, which
                    // never had that conversation.
                    let learned = self.directory.ca_endpoint();
                    let from_enrolment = learned.as_deref().and_then(|spec| {
                        parse_bootstrap_peer(spec)
                            .inspect_err(|e| {
                                // Recorded by this node's own authority, so a
                                // malformed one is an operator-visible fault
                                // rather than remote input.
                                tracing::warn!(error = ?e, "ignoring unparsable ca_endpoint")
                            })
                            .ok()
                    });
                    for peer in from_enrolment
                        .into_iter()
                        .chain(self.bootstrap.iter().cloned())
                    {
                        Self::dial(&bound, peer);
                    }
                    self.bound = Some(bound);
                }
                // Not fatal: the node keeps running and the next generation
                // bump tries again. A port already in use is the likely cause,
                // and it is an operator's to fix.
                Err(e) => {
                    tracing::error!(error = ?e, "iroh link failed to bind; staying dormant")
                }
            }
        }

        /// Drop the current endpoint, stopping its accept loop and closing
        /// every connection it holds.
        async fn teardown(&mut self) {
            let Some(bound) = self.bound.take() else {
                return;
            };
            bound.accept_task.abort();
            for (_, conn) in bound.conns.lock().await.drain() {
                conn.close(0u32.into(), b"endpoint rebinding");
            }
            bound.endpoint.close().await;
            // A rebind is a new medium as far as reassembly is concerned.
            *self.reassembler = IrohReassembler::new();
            self.peers = IrohPeerTable::default();
        }

        /// Close any connection whose key the mesh has stopped vouching for.
        ///
        /// Two conditions, one response. A **revoked** peer must lose its
        /// connection or revocation stops at the routing layer: the engine
        /// refuses its frames while the carrier keeps the socket, keeps it in
        /// the broadcast fan-out set, and keeps reading from it. A
        /// **superseded** key — one whose MAC now certifies a different key —
        /// must go too, or a re-keyed peer's old connection shadows its new
        /// identity. `AuthView` merges both into one stale set precisely
        /// because the action is identical.
        ///
        /// Cheap on the hot path: a generation compare, and nothing else
        /// unless something actually changed.
        async fn reconcile(&mut self) {
            let generation = self.directory.generation();
            if generation == self.swept_generation {
                return;
            }
            self.swept_generation = generation;
            self.rebind_if_identity_changed().await;

            let Some(bound) = self.bound.as_ref() else {
                return;
            };
            let stale = self.directory.stale_keys();
            if stale.is_empty() {
                return;
            }
            let mut conns = bound.conns.lock().await;
            for key in stale {
                let Ok(id) = EndpointId::from_bytes(&key) else {
                    continue;
                };
                if let Some(conn) = conns.remove(&id) {
                    // Security-relevant and not reachable by arbitrary remote
                    // input — it takes a revocation this node verified, or a
                    // certificate rotation — so `warn!` rather than `trace!`.
                    tracing::warn!(
                        peer = %id.fmt_short(),
                        "closing iroh connection: key revoked or superseded"
                    );
                    // The reader task holding the other handle exits on the
                    // resulting error and removes nothing, since this already
                    // has.
                    conn.close(0u32.into(), b"key no longer certified");
                }
            }
        }

        /// Put `frame` on the wire to `peer`, or report why it could not go.
        ///
        /// Returns `true` if the datagram was handed to QUIC. A peer with no
        /// live connection gets a background dial and a dropped frame rather
        /// than a stalled loop.
        async fn send_to(bound: &Bound, peer: EndpointId, frame: &[u8], msg_id: u8) -> bool {
            let conn = bound.conns.lock().await.get(&peer).cloned();
            let Some(conn) = conn else {
                Self::dial(bound, EndpointAddr::new(peer));
                tracing::trace!(peer = %peer.fmt_short(), "drop: no iroh connection yet, dialing");
                return false;
            };
            // A QUIC datagram is capped by the path MTU, which is below
            // MAX_LINK_FRAME_LEN on any real internet path — hence the
            // fragmentation below. What is checked here is the *floor* that
            // fragmentation assumes: a path too small even for one fragment is
            // a reported drop, never a silent truncation. Design 18 §3.4.
            match conn.max_datagram_size() {
                Some(max) if max < IROH_DATAGRAM_FLOOR => {
                    tracing::trace!(
                        peer = %peer.fmt_short(),
                        max,
                        floor = IROH_DATAGRAM_FLOOR,
                        "drop: iroh path below the fragment floor"
                    );
                    return false;
                }
                None => {
                    tracing::trace!(
                        peer = %peer.fmt_short(),
                        "drop: peer does not accept datagrams"
                    );
                    return false;
                }
                Some(_) => {}
            }

            // Always framed, even for a single fragment: a uniform 2-byte
            // header means the receive path has one shape rather than a
            // "fragmented or not?" discriminator it would have to guess.
            let count = frame.len().div_ceil(FRAG_PAYLOAD).max(1);
            if count > MAX_FRAGMENTS {
                tracing::trace!(
                    len = frame.len(),
                    count,
                    "drop: frame needs too many fragments"
                );
                return false;
            }
            let mut sent_any = false;
            for index in 0..count {
                let start = index * FRAG_PAYLOAD;
                let end = core::cmp::min(start + FRAG_PAYLOAD, frame.len());
                let mut datagram = Vec::with_capacity(FRAG_HDR_LEN + (end - start));
                datagram.extend_from_slice(&pack_header(msg_id, index, count));
                datagram.extend_from_slice(&frame[start..end]);
                match conn.send_datagram(Bytes::from(datagram)) {
                    Ok(()) => sent_any = true,
                    Err(e) => {
                        tracing::trace!(
                            peer = %peer.fmt_short(),
                            error = ?e,
                            "drop: iroh send failed"
                        );
                        bound.conns.lock().await.remove(&peer);
                        // A partial message is not worth continuing: the
                        // remaining fragments would only occupy the peer's
                        // reassembly slot until capacity reclaims it.
                        return false;
                    }
                }
            }
            sent_any
        }
    }

    impl LinkT for IrohLink {
        // No native fan-out: one QUIC datagram reaches exactly one peer, so N
        // copies genuinely cost N and flooding is never cheaper on this link's
        // account. Same answer `UdpMultiLink` gives in its hub/star mode, and
        // for the same reason.
        fn fan_out(&self) -> Option<core::num::NonZeroU8> {
            None
        }

        async fn send(
            &mut self,
            origin: Mac,
            data: &LinkFrameData<'_>,
        ) -> Result<usize, LinkError> {
            // Before a target is chosen, not after: a frame must never go out
            // over a connection the mesh has just stopped vouching for, and a
            // link that has just gained an identity should use it.
            self.reconcile().await;
            if self.bound.is_none() {
                // The pre-enrolment state. Not an error: the node is running
                // and reachable over its management API, it simply has no
                // identity to put on the air yet.
                tracing::trace!("drop: iroh link is dormant (this node has no identity yet)");
                return Ok(0);
            }
            let now = Instant::now();
            // No wire-vs-mesh protocol split: the ALPN is already the demux,
            // so the EtherType-shaped field written is `data.protocol` itself
            // — as on UDP, where the port plays that role.
            let Some(n) = frame_into_buf(origin, data.protocol, data, &mut self.wire_buf) else {
                tracing::trace!(
                    payload_len = data.payload.len(),
                    "drop: frame exceeds iroh wire buffer"
                );
                return Ok(0);
            };
            let frame_end = n;

            let targets = if data.dst.is_multicast() {
                // Every live connection, not merely every *learned* peer.
                // A bootstrapped connection has taught us nothing yet — no
                // frame has arrived on it — so a table-driven fan-out would
                // never send it the first OGM, and the peer would therefore
                // never reply, and nothing would ever be learned. The
                // connection map is also better information than the table: it
                // is keyed by endpoint, so it is deduplicated by construction
                // where a MAC-keyed table needs collapsing.
                match self.bound.as_ref() {
                    Some(b) => b.conns.lock().await.keys().copied().collect(),
                    None => Vec::new(),
                }
            } else {
                match self.resolve_dst(data.dst, now) {
                    Some(id) => vec![id],
                    None => {
                        // Reached only when *this* node addresses a peer it has
                        // never heard from, i.e. before the engine would have a
                        // route to it. Metadata only, no payload.
                        tracing::trace!(dst = ?data.dst, "drop: no known iroh peer for destination");
                        return Ok(0);
                    }
                }
            };
            if targets.is_empty() {
                tracing::trace!("drop: no known peers to fan broadcast out to");
                return Ok(0);
            }

            // One id per frame, shared by every target: the reassembly key
            // includes the peer, so two receivers cannot collide with each
            // other, and a broadcast is one message however many peers hear it.
            let msg_id = self.next_msg_id;
            self.next_msg_id = self.next_msg_id.wrapping_add(1);
            let mut any_sent = false;
            for peer in targets {
                // One peer failing must not withhold the frame from the rest —
                // a departed spoke is no reason to starve every other one.
                let Some(bound) = self.bound.as_ref() else {
                    break;
                };
                any_sent |= Self::send_to(bound, peer, &self.wire_buf[..frame_end], msg_id).await;
            }
            // Unlike a socket write, every failure here is already a
            // *reported* drop (no connection yet, oversized, peer gone), and
            // each is recoverable on the mesh's own retry cadence. Reporting
            // `Ok(0)` keeps them out of the driver's link-error policy, which
            // exists for a carrier that has genuinely broken.
            if any_sent { Ok(n) } else { Ok(0) }
        }

        async fn recv(&mut self) -> Result<Received<'_>, LinkError> {
            // Loops until a whole frame is reassembled. A fragment that merely
            // advances a reassembly is not something to hand the driver, and
            // neither is a malformed one — both are ordinary on a link
            // carrying arbitrary remote input, so neither is an error.
            let n = loop {
                // Raced against the auth view so an idle link still reacts to a
                // revocation. Borrows are scoped to the `select!` so
                // `reconcile` can take `&mut self` afterwards.
                let inbound = {
                    let auth = &mut self.auth_changed;
                    match self.bound.as_mut() {
                        // Dormant: there is no inbox to read, so the auth view
                        // is the only thing that can wake this link — which is
                        // exactly right, since gaining an identity is the only
                        // event that changes anything for it.
                        None => {
                            let _ = auth.changed().await;
                            None
                        }
                        Some(bound) => {
                            let inbox = &mut bound.inbox;
                            tokio::select! {
                                msg = inbox.recv() => Some(msg),
                                changed = auth.changed() => {
                                    // `Err` means the sender is gone, which
                                    // cannot happen while this link holds an
                                    // `AuthView`.
                                    if changed.is_err() {
                                        core::future::pending::<()>().await;
                                    }
                                    None
                                }
                            }
                        }
                    }
                };
                let Some(msg) = inbound else {
                    self.reconcile().await;
                    continue;
                };
                // `None` means every sender is gone, which cannot happen while
                // this link holds `inbox_tx`.
                let (peer, bytes) = msg.ok_or(LinkError::Io)?;
                let Some((hdr, body)) = parse_fragment(&bytes) else {
                    tracing::trace!(peer = %peer.fmt_short(), "drop: malformed iroh fragment");
                    continue;
                };
                // QUIC carries no physical-layer signal information.
                if let Some((len, _)) = self.reassembler.accept(
                    FragKey {
                        addr: peer,
                        msg_id: hdr.msg_id,
                    },
                    &hdr,
                    body,
                    LinkMetrics::default(),
                    &mut self.wire_buf,
                ) {
                    // Learned on completion rather than per fragment: a peer
                    // is only known to have sent a frame once a whole one
                    // exists to read a source MAC off.
                    if let Ok(frame) = LinkFrame::ref_from_bytes(&self.wire_buf[..len]) {
                        self.peers.learn(frame.src, peer, Instant::now());
                    }
                    break len;
                }
            };
            let frame =
                LinkFrame::ref_from_bytes(&self.wire_buf[..n]).map_err(|_| LinkError::Io)?;
            Ok(Received {
                frame,
                metrics: LinkMetrics::default(),
            })
        }
    }

    /// Parse a configured bootstrap peer into a dialable [`EndpointAddr`].
    ///
    /// Two accepted forms:
    ///
    /// * `<64 hex chars>` — the peer's Ed25519 public key alone. Dialable only
    ///   when something can turn a key into a route: a configured relay, or an
    ///   address-lookup service. This is the internet case, where the peer's
    ///   address is not knowable in advance anyway.
    /// * `<64 hex chars>@<addr>[,<addr>…]` — the key plus one or more direct
    ///   `ip:port` addresses. Needs no relay and no discovery, which is what
    ///   makes a LAN or air-gapped mesh work with `relay_url` unset — and what
    ///   makes this link testable without standing up a relay.
    ///
    /// The key is spelled in hex, as every other wayfinder surface spells an
    /// `ed_pubkey`, rather than in iroh's own z-base-32 — so an operator
    /// pastes the same string they already hold. In the deployed hub/spoke
    /// topology that string is *not* a new secret to go find: reaching the CA
    /// to enroll at all already requires pinning its identity key
    /// (`Client::connect_tls`'s `node_key`) and knowing its address. A
    /// bootstrap peer is those two values, joined by an `@`.
    fn parse_bootstrap_peer(spec: &str) -> anyhow::Result<EndpointAddr> {
        let spec = spec.trim();
        let (hex, addrs) = match spec.split_once('@') {
            Some((hex, addrs)) => (hex, Some(addrs)),
            None => (spec, None),
        };
        anyhow::ensure!(
            hex.len() == 64,
            "an iroh bootstrap peer starts with a 64-character hex Ed25519 public key \
             (optionally followed by `@ip:port`), got {} characters",
            hex.len()
        );
        let mut raw = [0u8; 32];
        for (i, byte) in raw.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| anyhow::anyhow!("iroh bootstrap peer {hex} is not valid hex"))?;
        }
        let id = EndpointId::from_bytes(&raw)
            .map_err(|e| anyhow::anyhow!("iroh bootstrap peer {hex} is not a valid key: {e}"))?;

        let mut addr = EndpointAddr::new(id);
        for a in addrs.into_iter().flat_map(|a| a.split(',')) {
            let a = a.trim();
            if a.is_empty() {
                continue;
            }
            addr = addr.with_ip_addr(a.parse().map_err(|_| {
                anyhow::anyhow!("iroh bootstrap peer address {a:?} is not a valid ip:port")
            })?);
        }
        Ok(addr)
    }

    /// Build a mesh link over iroh, type-erased as a [`LinkT`].
    ///
    /// Binds the QUIC endpoint (so a port already in use is a startup error,
    /// not a first-frame surprise), starts the accept loop, and kicks off a
    /// background dial to each bootstrap peer. Bootstrap dials are *not*
    /// awaited: a node whose peers are all down must still come up, serve its
    /// management API and carry its other links.
    pub async fn build_iroh_link(params: IrohLinkParams) -> anyhow::Result<Box<DynLinkT<'static>>> {
        Ok(DynLinkT::new_box(bind_iroh_link(params).await?))
    }

    /// [`build_iroh_link`] without the type erasure, so a caller that needs the
    /// concrete link — the tests, which read the bound endpoint's address off
    /// it — can have one. The erasing wrapper is what the driver uses.
    async fn bind_iroh_link(params: IrohLinkParams) -> anyhow::Result<IrohLink> {
        // Only the configuration is validated here. Binding waits for an
        // identity — see [`IrohLink`] — so a node with an iroh link in its
        // config starts cleanly whether or not it has enrolled yet, and an
        // unenrollable node fails on the config rather than on the socket.
        let bootstrap = params
            .bootstrap_peers
            .iter()
            .map(|p| parse_bootstrap_peer(p))
            .collect::<anyhow::Result<Vec<_>>>()?;
        if let Some(url) = params.relay_url.as_deref() {
            url.parse::<iroh::RelayUrl>()
                .map_err(|e| anyhow::anyhow!("invalid iroh relay_url {url}: {e}"))?;
        }

        let mut link = IrohLink {
            bound: None,
            bind_port: params.bind_port,
            relay_url: params.relay_url,
            bootstrap,
            peers: IrohPeerTable::default(),
            auth_changed: params.directory.watch(),
            directory: params.directory,
            swept_generation: 0,
            reassembler: Box::new(IrohReassembler::new()),
            next_msg_id: 0,
            wire_buf: [0u8; MAX_LINK_FRAME_LEN],
        };
        // A node that already holds an identity — one provisioned by file, or
        // restarted after enrolling — binds here rather than on its first
        // `send`, so its endpoint is on the air as early as any other link's.
        link.rebind_if_identity_changed().await;
        if link.bound.is_none() {
            tracing::info!(
                "iroh mesh link is dormant: this node has no identity yet, so there is \
                 no endpoint key to bind. It will come up when one is installed."
            );
        }
        Ok(link)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Compact node addresses, per this repo's test conventions.
        fn mac(n: u8) -> Mac {
            Mac([0, 0, 0, 0, 0, n])
        }

        /// Distinct endpoints, derived from distinct seeds.
        fn endpoint_id(n: u8) -> EndpointId {
            iroh::SecretKey::from_bytes(&[n; 32]).public()
        }

        #[test]
        fn learns_then_resolves_a_peer() {
            let mut table = IrohPeerTable::default();
            let now = Instant::now();
            assert_eq!(table.resolve(mac(1), now), None, "nothing known yet");

            table.learn(mac(1), endpoint_id(1), now);
            table.assert_invariants();
            assert_eq!(table.resolve(mac(1), now), Some(endpoint_id(1)));
        }

        /// A peer that moved to a new endpoint (a re-keyed or restarted node)
        /// replaces its old entry rather than accumulating a second one.
        #[test]
        fn relearning_replaces_rather_than_duplicates() {
            let mut table = IrohPeerTable::default();
            let now = Instant::now();
            table.learn(mac(1), endpoint_id(1), now);
            table.learn(mac(1), endpoint_id(2), now);
            table.assert_invariants();
            assert_eq!(table.resolve(mac(1), now), Some(endpoint_id(2)));
        }

        #[test]
        fn a_peer_ages_out_after_its_ttl() {
            let mut table = IrohPeerTable::default();
            let learned_at = Instant::now();
            table.learn(mac(1), endpoint_id(1), learned_at);

            let still_live = learned_at + PEER_TTL - Duration::from_secs(1);
            assert_eq!(table.resolve(mac(1), still_live), Some(endpoint_id(1)));

            let expired = learned_at + PEER_TTL;
            assert_eq!(table.resolve(mac(1), expired), None, "stale entry not used");
        }

        /// At capacity, admitting a new peer evicts the least-recently-heard
        /// one and leaves every fresher entry intact.
        #[test]
        fn at_capacity_the_stalest_peer_is_evicted() {
            let mut table = IrohPeerTable::default();
            let base = Instant::now();
            for i in 0..MAX_TRACKED_PEERS {
                // Ascending timestamps, so peer 0 is the stalest.
                let heard_at = base + Duration::from_millis(i as u64);
                table.learn(
                    Mac([0, 0, 0, 0, (i >> 8) as u8, i as u8]),
                    endpoint_id(1),
                    heard_at,
                );
            }
            table.assert_invariants();
            let full = base + Duration::from_millis(MAX_TRACKED_PEERS as u64);

            table.learn(mac(200), endpoint_id(2), full);
            table.assert_invariants();
            assert_eq!(
                table.resolve(mac(200), full),
                Some(endpoint_id(2)),
                "the new peer was admitted"
            );
            assert_eq!(
                table.resolve(Mac([0, 0, 0, 0, 0, 0]), full),
                None,
                "the stalest peer was the one evicted"
            );
        }

        /// Refreshing an existing peer at capacity must not evict anything —
        /// the table is not growing, so nothing has to make room.
        #[test]
        fn refreshing_at_capacity_evicts_nothing() {
            let mut table = IrohPeerTable::default();
            let base = Instant::now();
            for i in 0..MAX_TRACKED_PEERS {
                let heard_at = base + Duration::from_millis(i as u64);
                table.learn(
                    Mac([0, 0, 0, 0, (i >> 8) as u8, i as u8]),
                    endpoint_id(1),
                    heard_at,
                );
            }
            let later = base + Duration::from_secs(1);

            table.learn(Mac([0, 0, 0, 0, 0, 5]), endpoint_id(2), later);
            table.assert_invariants();
            assert_eq!(
                table.resolve(Mac([0, 0, 0, 0, 0, 0]), later),
                Some(endpoint_id(1)),
                "the stalest peer survives a refresh of another"
            );
        }

        /// Several MACs reached through one relaying peer resolve to that one
        /// endpoint. Broadcast dedup is no longer this table's job (a
        /// broadcast fans out over the connection map, which is endpoint-keyed
        /// and so deduplicated by construction), but unicast to each MAC must
        /// still land on the right peer.
        #[test]
        fn several_macs_can_share_one_relaying_endpoint() {
            let mut table = IrohPeerTable::default();
            let now = Instant::now();
            let hub = endpoint_id(9);
            table.learn(mac(1), hub, now);
            table.learn(mac(2), hub, now);
            table.learn(mac(3), endpoint_id(3), now);
            table.assert_invariants();

            assert_eq!(table.resolve(mac(1), now), Some(hub));
            assert_eq!(table.resolve(mac(2), now), Some(hub));
            assert_eq!(table.resolve(mac(3), now), Some(endpoint_id(3)));
        }

        /// Hex encoding of a public key, the form config carries.
        fn hex_key(key: EndpointId) -> String {
            key.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
        }

        #[test]
        fn bootstrap_peers_parse_from_hex() {
            let key = endpoint_id(7);
            let hex = hex_key(key);
            let addr = parse_bootstrap_peer(&hex).unwrap();
            assert_eq!(addr.id, key);
            assert!(addr.is_empty(), "a bare key carries no route of its own");
            // Surrounding whitespace is a copy/paste artifact, not an error.
            assert_eq!(parse_bootstrap_peer(&format!("  {hex}\n")).unwrap().id, key);
        }

        /// The `key@addr` form is what makes a relay-less mesh dialable: with
        /// no relay and no discovery service, a bare key names a peer nothing
        /// can route to.
        #[test]
        fn bootstrap_peers_parse_direct_addresses() {
            let key = endpoint_id(7);
            let addr = parse_bootstrap_peer(&format!("{}@192.0.2.5:41999", hex_key(key))).unwrap();
            assert_eq!(addr.id, key);
            let addrs: Vec<_> = addr.ip_addrs().copied().collect();
            assert_eq!(addrs, vec!["192.0.2.5:41999".parse().unwrap()]);

            // A dual-stack peer names both, comma-separated.
            let addr = parse_bootstrap_peer(&format!(
                "{}@192.0.2.5:41999,[2001:db8::1]:41999",
                hex_key(key)
            ))
            .unwrap();
            assert_eq!(addr.ip_addrs().count(), 2);
        }

        #[test]
        fn a_malformed_bootstrap_peer_is_rejected_with_its_reason() {
            let err = parse_bootstrap_peer("abc").unwrap_err().to_string();
            assert!(
                err.contains("64-character"),
                "names the expected shape: {err}"
            );

            let err = parse_bootstrap_peer(&"z".repeat(64))
                .unwrap_err()
                .to_string();
            assert!(err.contains("not valid hex"), "names the problem: {err}");

            let err = parse_bootstrap_peer(&format!("{}@not-an-addr", hex_key(endpoint_id(1))))
                .unwrap_err()
                .to_string();
            assert!(err.contains("ip:port"), "names the problem: {err}");
        }

        /// The direct spoke-to-spoke fix: a certificate-derived key beats what
        /// the link learned from whoever relayed the frame.
        ///
        /// This is the whole point of the directory. On a hub topology every
        /// spoke's frames arrive relayed by the hub, so the learned table maps
        /// *every* remote MAC to the hub's endpoint — deliverable, but it
        /// routes spoke-to-spoke traffic through the hub. The certificate says
        /// who actually owns the MAC.
        #[tokio::test]
        async fn the_certificate_directory_outranks_a_relayed_learned_entry() {
            let directory = crate::AuthView::new();
            let mut link = bind_iroh_link(IrohLinkParams {
                bind_port: None,
                relay_url: None,
                bootstrap_peers: vec![],
                directory: directory.clone(),
            })
            .await
            .expect("binds");

            let hub = endpoint_id(9);
            let spoke = endpoint_id(3);
            let now = Instant::now();

            // Everything this node has heard from the spoke came via the hub.
            link.peers.learn(mac(3), hub, now);
            assert_eq!(
                link.resolve_dst(mac(3), now),
                Some(hub),
                "with no certificate, the relayed path is the only answer"
            );

            // The spoke's certificate arrives (design 01's lazy fetch), and the
            // driver republishes the directory.
            directory.publish(Some([0x55; 32]), None, [(mac(3), *spoke.as_bytes())], []);
            assert_eq!(
                link.resolve_dst(mac(3), now),
                Some(spoke),
                "the certificate names the owner, so the path goes direct"
            );

            // A MAC with no certificate still falls back to what was learned —
            // the directory adds an answer, it does not remove one.
            link.peers.learn(mac(7), hub, now);
            assert_eq!(link.resolve_dst(mac(7), now), Some(hub));
        }

        /// With authentication off the directory is empty, and the link must
        /// behave exactly as it did before one existed.
        #[tokio::test]
        async fn an_empty_directory_changes_nothing() {
            let mut link = bind_iroh_link(IrohLinkParams {
                bind_port: None,
                relay_url: None,
                bootstrap_peers: vec![],
                directory: crate::AuthView::new(),
            })
            .await
            .expect("binds");

            let now = Instant::now();
            assert_eq!(link.resolve_dst(mac(1), now), None);
            link.peers.learn(mac(1), endpoint_id(1), now);
            assert_eq!(link.resolve_dst(mac(1), now), Some(endpoint_id(1)));
        }

        /// Revocation reaches the *transport*, not just the router.
        ///
        /// This is the gap the auth view exists to close. Before it, a revoked
        /// peer kept its QUIC connection: the engine refused its frames, but
        /// the carrier held the socket open, kept it in the broadcast fan-out
        /// set, and kept reading from it. Routing was denied; the connection
        /// was not.
        #[tokio::test]
        async fn a_revoked_peer_loses_its_connection() {
            let dialer_seed = [0x77u8; 32];
            let view = enrolled_view(dialer_seed);
            let (mut dialer, listener) =
                connected_pair_with([0x88; 32], view.clone(), enrolled_view([0x88; 32])).await;
            let listener_key = *listener
                .bound
                .as_ref()
                .expect("bound")
                .endpoint
                .id()
                .as_bytes();

            // Bring the connection up the way a real node would: by sending
            // until a frame actually leaves.
            send_until_delivered(&mut dialer, &[1, 2, 3, 4]).await;
            assert!(
                dialer
                    .bound
                    .as_ref()
                    .expect("bound")
                    .conns
                    .lock()
                    .await
                    .contains_key(&listener.bound.as_ref().expect("bound").endpoint.id()),
                "a connection exists to begin with"
            );

            // The listener is certified, then revoked. The driver publishes the
            // MAC only — the router has already evicted the certificate — so
            // the view is what remembers which key to condemn.
            view.publish(Some(dialer_seed), None, [(mac(2), listener_key)], []);
            view.publish(Some(dialer_seed), None, [], [mac(2)]);

            // A send is enough to trigger the sweep; so is an idle `recv`.
            let _ = dialer
                .send(
                    mac(1),
                    &LinkFrameData {
                        dst: Mac::BROADCAST,
                        protocol: 0x4305,
                        payload: &[9],
                    },
                )
                .await
                .expect("a send never errors");

            assert!(
                !dialer
                    .bound
                    .as_ref()
                    .expect("bound")
                    .conns
                    .lock()
                    .await
                    .contains_key(&listener.bound.as_ref().expect("bound").endpoint.id()),
                "the revoked peer's connection was closed"
            );
        }

        /// A re-keyed peer's old connection is closed too, so the stale
        /// identity cannot shadow the new one.
        #[tokio::test]
        async fn a_superseded_key_loses_its_connection() {
            let dialer_seed = [0x99u8; 32];
            let view = enrolled_view(dialer_seed);
            let (mut dialer, listener) =
                connected_pair_with([0xaa; 32], view.clone(), enrolled_view([0xaa; 32])).await;
            let listener_key = *listener
                .bound
                .as_ref()
                .expect("bound")
                .endpoint
                .id()
                .as_bytes();

            send_until_delivered(&mut dialer, &[1, 2, 3, 4]).await;
            assert!(
                dialer
                    .bound
                    .as_ref()
                    .expect("bound")
                    .conns
                    .lock()
                    .await
                    .contains_key(&listener.bound.as_ref().expect("bound").endpoint.id())
            );

            // Same MAC, different key: the peer rotated its certificate.
            view.publish(Some(dialer_seed), None, [(mac(2), listener_key)], []);
            view.publish(Some(dialer_seed), None, [(mac(2), [0xbb; 32])], []);

            dialer.reconcile().await;
            assert!(
                !dialer
                    .bound
                    .as_ref()
                    .expect("bound")
                    .conns
                    .lock()
                    .await
                    .contains_key(&listener.bound.as_ref().expect("bound").endpoint.id()),
                "the superseded key's connection was closed"
            );
        }

        /// The sweep is skipped entirely when nothing changed — the property
        /// that keeps it off the cost of every send.
        #[tokio::test]
        async fn an_unchanged_view_is_not_reswept() {
            let view = crate::AuthView::new();
            let mut link = bind_iroh_link(IrohLinkParams {
                bind_port: None,
                relay_url: None,
                bootstrap_peers: vec![],
                directory: view.clone(),
            })
            .await
            .expect("binds");

            view.publish(Some([0xcc; 32]), None, [(mac(1), [1u8; 32])], []);
            link.reconcile().await;
            let swept = link.swept_generation;
            assert!(swept > 0, "the first change was swept");

            view.publish(Some([0xcc; 32]), None, [(mac(1), [1u8; 32])], []);
            link.reconcile().await;
            assert_eq!(
                link.swept_generation, swept,
                "an identical republish did not advance the generation"
            );
        }

        /// A frame larger than one QUIC datagram survives the round trip.
        ///
        /// This is the property design 18 §3.4 promises and phase 1 did not
        /// have: before fragmentation such a frame was dropped, which was
        /// honest but useless. The payload deliberately spans more than one
        /// [`FRAG_PAYLOAD`], so it exercises split *and* reassembly rather
        /// than the one-fragment fast path every other test takes.
        #[tokio::test]
        async fn an_oversized_frame_is_fragmented_and_reassembled() {
            let (mut dialer, mut listener) = connected_pair([0x33; 32], [0x44; 32]).await;

            // Distinct bytes, so a mis-ordered or duplicated fragment shows up
            // as wrong content rather than coincidentally-correct zeroes.
            let payload: Vec<u8> = (0..(FRAG_PAYLOAD + 500)).map(|i| (i % 251) as u8).collect();
            assert!(
                payload.len() + 14 > IROH_DATAGRAM_FLOOR,
                "the test frame must actually need fragmenting"
            );

            send_until_delivered(&mut dialer, &payload).await;

            let received = tokio::time::timeout(Duration::from_secs(10), listener.recv())
                .await
                .expect("a reassembled frame arrives")
                .expect("it parses");
            assert_eq!(received.frame.src, mac(1));
            assert_eq!(
                &received.frame.payload,
                payload.as_slice(),
                "every fragment landed, in order"
            );
        }

        /// An `AuthView` already carrying `seed` as this node's identity — the
        /// state of a node that has enrolled, which is what a link needs before
        /// it will bind anything.
        fn enrolled_view(seed: [u8; 32]) -> crate::AuthView {
            let view = crate::AuthView::new();
            view.publish(Some(seed), None, [], []);
            view
        }

        /// Two links on loopback with the dialer bootstrapped to the listener.
        async fn connected_pair(
            dialer_seed: [u8; 32],
            listener_seed: [u8; 32],
        ) -> (IrohLink, IrohLink) {
            connected_pair_with(
                listener_seed,
                enrolled_view(dialer_seed),
                enrolled_view(listener_seed),
            )
            .await
        }

        /// [`connected_pair`], with each end's auth view supplied so a test can
        /// publish into it.
        async fn connected_pair_with(
            listener_seed: [u8; 32],
            dialer_view: crate::AuthView,
            listener_view: crate::AuthView,
        ) -> (IrohLink, IrohLink) {
            let listener_key = iroh::SecretKey::from_bytes(&listener_seed).public();
            let listener = bind_iroh_link(IrohLinkParams {
                bind_port: None,
                relay_url: None,
                bootstrap_peers: vec![],
                directory: listener_view,
            })
            .await
            .expect("listener binds");

            let addrs = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let addr = listener.bound.as_ref().expect("bound").endpoint.addr();
                    if !addr.is_empty() {
                        return addr;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .expect("the listener discovers a direct address");

            let dialer = bind_iroh_link(IrohLinkParams {
                bind_port: None,
                relay_url: None,
                bootstrap_peers: addrs
                    .ip_addrs()
                    .map(|a| format!("{}@{a}", hex_key(listener_key)))
                    .collect(),
                directory: dialer_view,
            })
            .await
            .expect("dialer binds");
            (dialer, listener)
        }

        /// Broadcast `payload` until one send reports bytes on the wire.
        ///
        /// The bootstrap dial is deliberately not awaited (design 18 §3.5), so
        /// early sends drop — this stands in for Trickle's re-emission, which
        /// is what a real node relies on.
        async fn send_until_delivered(link: &mut IrohLink, payload: &[u8]) {
            tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    let n = link
                        .send(
                            mac(1),
                            &LinkFrameData {
                                dst: Mac::BROADCAST,
                                protocol: 0x4305,
                                payload,
                            },
                        )
                        .await
                        .expect("a send never errors; it drops with a reason");
                    if n > 0 {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await
            .expect("the bootstrap dial completes and a frame goes out");
        }

        /// The end-to-end shape: two real iroh endpoints, no relay and no
        /// discovery service, exchange a mesh frame through the `LinkT` trait
        /// the driver actually calls.
        ///
        /// This is the test that proves the link works at all — the peer-table
        /// tests above only pin its bookkeeping. It runs relay-less on
        /// loopback, so it exercises everything *except* NAT traversal, which
        /// is the one property no in-process test can assert (design 18 §6.1).
        #[tokio::test]
        async fn two_endpoints_exchange_a_frame() {
            let (mut dialer, mut listener) = connected_pair([0x22; 32], [0x11; 32]).await;

            let payload = [0xde, 0xad, 0xbe, 0xef];
            send_until_delivered(&mut dialer, &payload).await;

            let received = tokio::time::timeout(Duration::from_secs(10), listener.recv())
                .await
                .expect("a frame arrives")
                .expect("it parses");
            assert_eq!(received.frame.src, mac(1), "the sender's MAC survives");
            assert_eq!(received.frame.dst, Mac::BROADCAST);
            assert_eq!(&received.frame.payload, &payload, "the payload survives");

            // And the receive taught the listener how to reach the sender — the
            // learn-from-received-frames property the peer table exists for.
            assert_eq!(
                listener.peers.resolve(mac(1), Instant::now()),
                Some(dialer.bound.as_ref().expect("bound").endpoint.id()),
                "the sender is now addressable by MAC"
            );
        }

        /// A node that has not enrolled binds nothing and dials nothing.
        ///
        /// The pre-enrolment state, and the reason a spoke can ship an iroh
        /// link in its startup config: a link's endpoint key *is* this node's
        /// identity, and a node that has none has no address to take. Binding
        /// to the seed it generated at boot would put an endpoint on the air
        /// under a key no certificate names — and `SetAuth` can install a
        /// wholly different one, which would then move the node mid-flight.
        #[tokio::test]
        async fn a_link_is_dormant_until_the_node_has_an_identity() {
            let view = crate::AuthView::new();
            let mut link = bind_iroh_link(IrohLinkParams {
                bind_port: None,
                relay_url: None,
                bootstrap_peers: vec![],
                directory: view.clone(),
            })
            .await
            .expect("a dormant link still constructs");

            assert!(link.bound.is_none(), "nothing was bound");

            // Sending is a reported drop, not an error: the node is running and
            // reachable over its management API, it simply has nothing to say
            // on the mesh yet.
            let n = link
                .send(
                    mac(1),
                    &LinkFrameData {
                        dst: Mac::BROADCAST,
                        protocol: 0x4305,
                        payload: &[1, 2, 3],
                    },
                )
                .await
                .expect("a dormant send never errors");
            assert_eq!(n, 0);

            // Enrolment arrives — `SetAuth` installs an identity, the driver
            // republishes, and the link comes up on its own.
            view.publish(Some([0x42; 32]), None, [], []);
            link.reconcile().await;

            let bound = link.bound.as_ref().expect("the link bound on enrolment");
            assert_eq!(
                bound.endpoint.id(),
                iroh::SecretKey::from_bytes(&[0x42; 32]).public(),
                "it bound to the identity it was given, not to anything it invented"
            );
        }

        /// A node with no configured bootstrap peer still has one to dial, if
        /// enrolment recorded where the authority is.
        ///
        /// This is what lets a spoke ship a config containing no key at all:
        /// `SetAuth` is the only moment a node is told who the authority *is*,
        /// so carrying it there is the difference between a link that can find
        /// the mesh and one an operator must hand-configure — which a node with
        /// no filesystem cannot be.
        #[tokio::test]
        async fn the_authority_learned_at_enrolment_is_dialed() {
            let ca = iroh::SecretKey::from_bytes(&[0xd1; 32]).public();
            let view = crate::AuthView::new();
            view.publish(
                Some([0x42; 32]),
                Some(format!("{}@192.0.2.9:6001", hex_key(ca))),
                [],
                [],
            );

            let link = bind_iroh_link(IrohLinkParams {
                bind_port: None,
                relay_url: None,
                // Deliberately empty: the config names nobody.
                bootstrap_peers: vec![],
                directory: view.clone(),
            })
            .await
            .expect("binds");

            assert!(link.bound.is_some(), "an identity was present, so it bound");
            assert_eq!(
                view.ca_endpoint()
                    .as_deref()
                    .map(|s| s.split('@').next().unwrap()),
                Some(hex_key(ca).as_str()),
                "the endpoint it was told about is what it dials"
            );
        }

        /// A malformed `ca_endpoint` is ignored rather than blocking the bind.
        /// It is recorded by this node's own authority, so it is an
        /// operator-visible fault, not something to fail closed over.
        #[tokio::test]
        async fn a_malformed_authority_endpoint_does_not_block_the_bind() {
            let view = crate::AuthView::new();
            view.publish(Some([0x42; 32]), Some("not-a-key".into()), [], []);

            let link = bind_iroh_link(IrohLinkParams {
                bind_port: None,
                relay_url: None,
                bootstrap_peers: vec![],
                directory: view,
            })
            .await
            .expect("binds despite the bad endpoint");
            assert!(link.bound.is_some());
        }

        /// A rotated identity moves the node's endpoint rather than leaving it
        /// answering under a key the mesh no longer certifies.
        #[tokio::test]
        async fn a_rotated_identity_rebinds_the_endpoint() {
            let view = crate::AuthView::new();
            view.publish(Some([0x42; 32]), None, [], []);
            let mut link = bind_iroh_link(IrohLinkParams {
                bind_port: None,
                relay_url: None,
                bootstrap_peers: vec![],
                directory: view.clone(),
            })
            .await
            .expect("binds");
            let first = link.bound.as_ref().expect("bound").endpoint.id();

            view.publish(Some([0x43; 32]), None, [], []);
            link.reconcile().await;

            let second = link.bound.as_ref().expect("rebound").endpoint.id();
            assert_ne!(first, second, "the endpoint moved with the identity");
            assert_eq!(second, iroh::SecretKey::from_bytes(&[0x43; 32]).public());
        }

        /// Losing the identity takes the endpoint down: a node that has been
        /// un-enrolled must stop answering under the key it held.
        #[tokio::test]
        async fn losing_the_identity_goes_dormant_again() {
            let view = crate::AuthView::new();
            view.publish(Some([0x42; 32]), None, [], []);
            let mut link = bind_iroh_link(IrohLinkParams {
                bind_port: None,
                relay_url: None,
                bootstrap_peers: vec![],
                directory: view.clone(),
            })
            .await
            .expect("binds");
            assert!(link.bound.is_some());

            view.publish(None, None, [], []);
            link.reconcile().await;
            assert!(link.bound.is_none(), "the endpoint was torn down");
        }
    }
}

#[cfg(feature = "iroh")]
pub use imp::IrohLink;
#[cfg(feature = "iroh")]
pub use imp::IrohLinkParams;
#[cfg(feature = "iroh")]
pub use imp::build_iroh_link;

/// The `iroh`-feature-off counterpart of [`IrohLinkParams`], so a node's
/// config parsing and link-building code stays `cfg`-free.
#[cfg(not(feature = "iroh"))]
pub struct IrohLinkParams {
    /// UDP port the QUIC endpoint would bind.
    pub bind_port: Option<u16>,
    /// A self-hosted `iroh-relay` URL, or `None` to disable relaying.
    pub relay_url: Option<String>,
    /// Hex-encoded Ed25519 public keys to dial at startup.
    pub bootstrap_peers: Vec<String>,
    /// The auth view the link would bind its endpoint from and resolve peers
    /// through.
    pub directory: crate::AuthView,
}

/// The `iroh`-feature-off counterpart of `build_iroh_link`; see its
/// documentation.
///
/// Always fails. The signature is identical with the feature on or off — the
/// same shape `build_ble_link` keeps across platforms — so a configured iroh
/// link on a build without the feature is a startup error naming the reason,
/// rather than a compile error in the caller.
#[cfg(not(feature = "iroh"))]
pub async fn build_iroh_link(
    _params: IrohLinkParams,
) -> anyhow::Result<Box<wayfinder::link::DynLinkT<'static>>> {
    anyhow::bail!(
        "this build has no iroh support (the `iroh` feature of `wayfinder-driver` \
         is off); remove the `Iroh` link from the config or rebuild with it enabled"
    )
}
