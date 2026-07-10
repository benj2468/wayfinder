# Design: Lazy certificate distribution (fingerprint + on-demand fetch)

**Status:** Proposed — approved for implementation in a later session. This
document is self-contained: it carries all the context and decisions from the
design discussion so the implementing session needs nothing else.

**Scope:** OGM authentication only (`libs/wayfinder/src/auth.rs`,
`libs/wayfinder-auth`), plus two new routed control packets in the `batman`
engine (`libs/batman/src/wire.rs` + `engine.rs`) and a small originate/deliver
hook in `CentralRouter` (`libs/wayfinder/src/lib.rs`). No change to the mesh
`LinkT`/`FrameIo` surface. Payloads are still never encrypted — this is an
authenticity/segregation feature only, unchanged from today.

---

## 1. Motivation

When a mesh enables authentication, **every OGM carries the originator's full
membership certificate** in a `TvlvType::Cert` record, on every Trickle
emission. The cert is a fixed `#[repr(C, packed)]` record:

```
version(1) flags(1) mesh_id(4) node_mac(6) ed_pubkey(32)
x_pubkey(32) not_before(8) not_after(8) signature(64)          = 156 bytes
```

Plus a 4-byte TVLV header = **160 bytes of cert on every OGM**, alongside the
64-byte `OgmSig`. On a LoRa link backed off to an `i_max` of ~1 minute, that is
160 bytes re-sent per originator per minute *forever*, even though the cert only
changes on rotation (hours/days). It is the dominant control-plane airtime cost
on the medium.

The cert is **static per node per cert-lifetime**. There is no reason to
re-broadcast it every interval. Send a tiny fingerprint in the OGM; distribute
the full cert **once, on demand**, point-to-point, to each node that actually
needs it.

### Savings

- **Per OGM:** replace a 160-byte cert record with a 12-byte fingerprint record
  (8-byte hash + 4-byte TVLV header) → **~148 bytes saved per OGM**.
- **One-time fetch cost** per `(needer, originator)` pair per cert-lifetime:
  ~220-byte request (carries requester's cert + signature) + ~160-byte reply.
  Amortized over hours of 1-minute OGMs, this is negligible.
- Cert traffic goes from `O(originators × intervals × links)` (a continuous
  flood) to `O(needers × originators)` point-to-point transfers, each sent
  exactly once.

---

## 2. Core idea

1. OGMs carry an **8-byte cert fingerprint** (`TvlvType::CertFp`), not the cert.
2. A node keeps a **cert store** keyed by originator MAC. When it receives an
   OGM whose fingerprint it already holds, it verifies the `OgmSig` against the
   **cached** cert — zero cert bytes on the wire.
3. On a **fingerprint miss** (unknown originator, or a *changed* fingerprint =
   rotation), the node **fetches** the cert on demand: a unicast `CertReq`
   routed toward the originator; any node along the path that holds the cert —
   ultimately the originator itself — answers with a `CertReply`.
4. The request is **self-authenticating**: it carries the requester's own cert
   (root-signed) plus a signature, so the responder can verify the requester
   without a third party, and the responder's pending-state can't be stuffed by
   outsiders.

The `OgmSig` still signs `domain ‖ orig ‖ seqno ‖ cert_bytes` (unchanged
`signed_message`, `auth.rs:445`). With fingerprint-only OGMs the **verifier
reconstructs the signed message from the cached cert bytes** the fingerprint
selects. The fingerprint is *not* a security boundary — the fetched cert is
still verified against the trust anchor — it only (a) selects which cached cert
to check the signature against and (b) detects rotation. 8 bytes is ample to
avoid accidental collisions between legitimate certs.

---

## 3. Why this is correct (the load-bearing arguments)

These were worked out in design and must survive implementation; encode them as
tests.

### 3.1 The fetch always terminates at a cert holder

Under the fingerprint scheme the two things an OGM used to install have come
apart:

- **A route to the originator** is installed by `batman` (`engine.rs`
  `handle_rx`). Open nodes (`auth = None`) install it unconditionally; auth
  nodes install it only after `verify_ogm` succeeds.
- **The cert** is cached only by auth nodes that verified.

A `CertReq` addressed to originator `A` is routed hop-by-hop toward `A` using
each node's normal next-hop for `A`. "Has a route to `A`" is exactly the set of
nodes that saw `A`'s OGM propagate, so each can forward the request onward; among
them every **auth** node also holds the cert (route ⟺ cert for auth nodes) and
answers early; every **open** relay forwards on; **`A` terminates**. So the
request is guaranteed to hit a holder, worst case `A` — with **no new
per-hop forwarding state**.

### 3.2 The one seam: the requester has no route to the originator

Because `verify_ogm` gates before the engine (`lib.rs:566` returns before
`handle_rx` at `:590`), a node that can't resolve a fingerprint has **no route**
to that originator. So it cannot originate a normally-routed unicast to `A`.
Fix: **seed the first hop with the OGM's link source** (`frame.src`, the
neighbor it actually heard the OGM from), which by construction has a route to
`A`. First hop is next-hop-overridden; every hop after routes normally.

### 3.3 The reply's return path exists whenever the requester needs it

The `CertReply` must get back to the requester `B`, i.e. the responder needs a
route to `B`. This is the crux objection ("if `A` can't hear `B`, `B` never
hears back"). It is resolved by BATMAN's **quality-weighted, effectively
bidirectional routing**: `engine.rs:486` clamps a forwarded OGM's advertised TQ
at the *local* link quality to the relaying neighbor (the "inflated-TQ
blackhole defense"). A one-way link is clamped toward unusable. Therefore:

- **Permanent asymmetry (A genuinely can't route to B):** then B has no usable
  route *to* A either, so B would never send to A and **correctly does not need
  A's cert**. The unresolved fingerprint is the right state — the cert scheme
  fails exactly where routing already fails, nowhere else.
- **Transient (route not installed at request time):** self-resolves. The
  request reached A over links that are bidirectional by construction, so B's
  OGM flows back to A the same way. A holds the query in a bounded
  **pending-query list** and flushes the reply once B's OGM verifies (see 3.5).

### 3.4 Cold-start bootstraps outward, ring by ring

A totally cold mesh (nobody has anyone's cert, every OGM initially unverifiable)
still bootstraps, because **a request to a direct neighbor needs no routing**:

- Ring 1: a direct neighbor `X` of `A` hears `A`'s OGM on the link, link-
  addresses a `CertReq` straight to `A` (1 hop, no route needed), gets `A`'s
  cert, verifies `A`'s OGMs, installs the route to `A`, forwards `A`'s OGM
  outward.
- Ring 2: `B` (behind `X`) requests `A`'s cert seeded via `X`; `X` now has a
  route to `A` and forwards; `A` replies.

Resolved certs trail the OGM frontier by one request-RTT, rippling outward from
every originator. No deadlock — the innermost ring is always link-addressed and
route-free, and each ring installs the routes the next ring rides.

### 3.5 Pending-query list vs. stateless retry (a decision)

When a responder can't yet route to the requester, two options:

- **Pending-query list (recommended for LoRa):** responder parks the request in
  a bounded, TTL'd table and flushes the reply when it gains a route to the
  requester (i.e. on the next verifiable OGM from it). Fewer retransmissions —
  the expensive thing on LoRa — at the cost of a little bounded state at
  responders.
- **Stateless + requester-retry:** responder drops what it can't answer; the
  requester (which is sitting on unresolvable OGMs anyway) re-requests on its own
  backoff until the responder has a route. Zero state at responders, chattier.

Recommendation: implement the pending-query list; keep requester-retry too as
the ultimate backstop (a dropped reply must not wedge). Bound both.

---

## 4. Wire format changes

### 4.1 New TVLV type (`libs/batman/src/wire.rs`)

Existing: `Cert = 0x80`, `OgmSig = 0x81`, `Revoke = 0x82`.

```
CertFp = 0x83   // 8-byte cert fingerprint, replaces Cert in a fingerprint OGM
```

Value is `blake2::Blake2s256(cert.as_bytes())[..8]`. `blake2` is already a
`no_std` dependency of `wayfinder-auth` (`Blake2s256`, used in `key.rs` /
`pairwise.rs`). Add a `MembershipCert::fingerprint(&self) -> [u8; 8]` on
`libs/wayfinder-auth/src/cert.rs`. Fingerprint is over the **whole 156-byte
cert** so it changes on any field change (rotation of keys or validity window).

### 4.2 New routed control packets (`libs/batman/src/wire.rs`)

Mirror `BatmanUnicastPacket` / `BatmanMcastPacket` exactly (they are the
template: `packet_type, version, ttl, dest`, routed hop-by-hop toward `dest`,
delivered locally on arrival, TTL-limited). Keeping them as distinct packet
types (not payloads inside `BATADV_UNICAST`) follows the repo's stated precedent
— `BATADV_MCAST` is "kept distinct from `BATADV_UNICAST` so multicast traffic
stays identifiable on the wire" — and lets the dissector and metrics see cert
traffic.

```
BATADV_CERT_REQ   = 0x05   struct BatmanCertReqPacket   { packet_type, version, ttl, dest: Mac }
BATADV_CERT_REPLY = 0x06   struct BatmanCertReplyPacket { packet_type, version, ttl, dest: Mac }
```

Payloads (follow the header):

- **CertReq body:** requester's `MembershipCert` (156 B) + Ed25519 signature
  (64 B) over a domain-separated `(orig_being_requested ‖ requester_mac)` so a
  request can't be replayed as a different message. The requested originator is
  the packet `dest`.
- **CertReply body:** the requested `MembershipCert` (156 B). The requester
  verifies it against the trust anchor exactly as `verify_cert` does today; no
  new trust path.

**Alternative considered:** carry req/reply as inner payloads of
`BATADV_UNICAST`, reusing all existing unicast forwarding. Simpler (no new engine
packet types) but conflates cert control with data on the wire and hides it from
the dissector. Rejected in favor of distinct types, but noted for the
implementer — if engine forwarding of two new types proves heavy, this is the
fallback.

### 4.3 Engine forwarding (`libs/batman/src/engine.rs`)

Teach `handle_rx` to route `BATADV_CERT_REQ` / `BATADV_CERT_REPLY` like a
unicast: look up `next_hop(dest)`, decrement TTL, re-emit; on arrival at `dest`
(dest == self) surface as a **local delivery** to the router (a new
`RoutingAction` / `RxOutcome.deliver_local` variant tagging it as cert-control,
so the router routes it to `OgmAuth` rather than the host). This stays
**crypto-free** — the engine only moves bytes, exactly as it forwards unknown
TVLVs verbatim today. All cert verification stays in the router/`OgmAuth`.

---

## 5. Router / `OgmAuth` changes (`libs/wayfinder/src/auth.rs`, `lib.rs`)

### 5.1 Cert store with fingerprint indexing

The store already exists: `verify_ogm` caches `VerifiedCert` per originator MAC
via `cache_neighbor` (`auth.rs:656`, bounded at `MAX_NEIGHBOR_KEYS = 64`, crude
first-slot eviction). Extend `NeighborKeys` (or add a parallel store) to also
retain the **raw cert bytes** (needed to reconstruct `signed_message`) and the
**fingerprint**. Add lookup-by-MAC returning `(cert_bytes, fingerprint)`.

Note the eviction caveat: a forwarder that verified `A` may have evicted `A`'s
cert under churn before a downstream request arrives. That is fine — it degrades
to "responder forwards the request onward / requester retries," never to
incorrectness. Do **not** assume a cache hit is guaranteed.

### 5.2 `verify_ogm` grows a third outcome

Today it returns `bool` (accept/drop). Change to an enum:

```
enum OgmVerdict { Verified, Rejected, NeedCert { orig: Mac, fp: [u8; 8] } }
```

- `CertFp + OgmSig` present, fingerprint **matches** a stored cert → verify
  `OgmSig` against the cached cert bytes → `Verified` (route proceeds).
- Fingerprint **missing or changed** → `NeedCert` (router triggers a fetch;
  **this OGM copy is dropped**, not forwarded — the next emission after the cert
  arrives verifies and forwards normally).
- Malformed / anchor failure / revoked / MAC-mismatch → `Rejected` (as today,
  all at `trace!`).

The router (`lib.rs:566` area) maps `NeedCert` to a `CertReq` origination and
drops the copy; `Verified` proceeds to `handle_rx`; `Rejected` drops.

### 5.3 Requester side

- On `NeedCert { orig, fp }`: if no request for `orig` is already in flight,
  originate a `CertReq` toward `orig`, **first hop = the OGM's `frame.src`**
  (next-hop override — the requester has no route to `orig`). Carry own cert +
  signature.
- Track in-flight requests in a small bounded set with a **retry/backoff**
  timer; retransmit until answered or a cap; clear on reply.
- On `CertReply`: verify the enclosed cert against the trust anchor
  (`verify_cert`), confirm it matches the `orig` and the fingerprint that
  triggered the fetch, cache it. Subsequent OGMs from `orig` now verify from
  cache.

### 5.4 Responder side

- On local delivery of a `CertReq`: verify the requester's cert + signature (drop
  silently at `trace!` if bad — self-authenticating gate). Look up the requested
  `orig` (== packet `dest` == self, in the terminal case; an intermediate holder
  may also answer early if it has the cert).
- If a route to the requester exists (`next_hop`), send a `CertReply`. Else park
  in the **pending-query list** (bounded, TTL'd, keyed by requester MAC) and
  flush when a route appears (opportunistically on `verify_ogm` success for that
  MAC, or on a periodic sweep).
- **Also cache the requester's cert** from the request — it's a free, verified
  cert exchange that pre-populates the store and lets the responder verify the
  requester's OGMs sooner.

---

## 6. Interaction with `require_auth` and open nodes

- `require_auth` is **not** the axis; it only drives `auth_locked()`
  (`require_auth && auth.is_none()`, `lib.rs:440`), a bootstrap self-lock.
  Verification (and thus this whole scheme) is gated on `auth.is_some()`.
- **`auth = None` (open) nodes** never attach or verify certs; `augment_ogm`
  isn't called for them (`lib.rs:775`). They are unaffected by the wire change
  and simply relay auth OGMs verbatim. As relays they hold a *route* to an
  originator but not its cert, so they forward `CertReq`s onward rather than
  answering — which is exactly what §3.1 relies on.

---

## 7. Migration / versioning

The change is **wire-incompatible**: an un-upgraded auth node runs
`find_tvlv(TvlvType::Cert)` in `verify_ogm`, finds nothing in a fingerprint OGM,
and drops it. So:

- Gate the switchover behind a config flag (e.g. `lazy_cert_distribution: bool`
  in `libs/wayfinder/src/config.rs`, default `false`). While `false`,
  `augment_ogm` sends the full `Cert` TVLV as today.
- This is a research project with coordinated deploys, so a **flag day**
  (upgrade the whole mesh, then flip the flag) is acceptable and is the
  recommended path. Document it. Dual-sending both `Cert` and `CertFp` during a
  transition is possible but defeats the savings, so avoid it unless a rolling
  upgrade is truly required.
- Consider bumping the TVLV/OGM `version` byte so a mixed mesh fails loudly
  rather than silently dropping.

---

## 8. Security considerations

- **Self-authenticating requests** (cert + signature verified against the
  anchor) mean only real members can create responder pending-state → the
  pending-query list can't be stuffed by outsiders. Bound and TTL it anyway.
- **Rate-limit** `CertReq` handling per requester per interval even for valid
  members, so a compromised member can't amplify cert broadcasts / airtime.
- **TTL** on both packets bounds wandering; add a request-ID + dedup if a request
  can arrive via multiple paths.
- The **fingerprint is not a trust boundary** — the fetched cert is always
  anchor-verified. Truncation to 8 bytes only needs collision-resistance among
  legitimate certs.
- **Rotation/replay:** a changed fingerprint triggers a re-fetch; an attacker
  can't forge a cert that verifies. Replaying an old `(fingerprint, OGM, sig)`
  triple is bounded by existing OGM seqno replay protection and by cert validity
  windows (expired certs are rejected by `verify_cert`). No new replay surface
  beyond today.
- **Logging:** obey the repo rules — never log cert bytes. Fingerprints, MACs,
  and lengths only; parse failures of remotely-supplied req/reply frames are
  `trace!`, not `warn!`.

---

## 9. Observability (per CLAUDE.md "metrics are first-class")

State lives in `CentralRouter` / `OgmAuth`, not the driver, so it exists on
embedded too. Prefer bounded here-and-now signals. Wire each end-to-end with the
**`add-metric`** skill (proto → service → `RouterAdapter` → client → TUI →
smoke test), using `GetLinkQualityTable` as the shape reference:

- Cert-store occupancy (`TableOccupancy` gauge: entries / capacity).
- Pending-query-list depth (gauge).
- Outstanding/in-flight fetches (gauge).
- `CertReq` / `CertReply` send+recv rates (`RateEstimator`).
- (Optional) fetch RTT / miss rate.

Update the `wayfinder-shark` dissector (`libs/wayfinder-shark`) for the new
`CertFp` TVLV and the two packet types, with pytest coverage.

---

## 10. Implementation phases (each is a TDD checkpoint)

Develop **test-first** (invoke the `tdd` skill). Each phase is independently
reviewable; the wire switchover (Phase 5) ships **last**, after the fetch path
works end to end, so the mesh never loses the ability to bootstrap.

- **Phase 0 — Fingerprint primitive + `CertFp` TVLV.** Additive, no behavior
  change. `MembershipCert::fingerprint`, `TvlvType::CertFp = 0x83`. Tests:
  fingerprint determinism + change-on-mutation; TVLV round-trip.
- **Phase 1 — Cert store with fingerprint indexing.** Extend the neighbor/cert
  cache to retain raw cert bytes + fingerprint; lookup by MAC; rotation
  (changed-fingerprint) detection. Tests on the store in isolation, including
  eviction behavior.
- **Phase 2 — `CertReq`/`CertReply` wire types + engine forwarding.** New packet
  types, `handle_rx` routes them like unicast with local delivery on arrival.
  Crypto-free. Test multi-hop forwarding + local-delivery via the
  `wayfinder-test` `Switch` harness.
- **Phase 3 — Requester side.** `verify_ogm` → `OgmVerdict` enum; on `NeedCert`
  originate a self-authenticating `CertReq` seeded from `frame.src`; in-flight
  dedup + retry/backoff; ingest+verify `CertReply` into the store. Tests over the
  `Switch` harness (A—X—B).
- **Phase 4 — Responder side.** Verify incoming request, answer via `next_hop`
  or park in the bounded pending-query list; flush on route availability; cache
  the requester's cert. Tests: immediate-answer, deferred-answer-via-pending,
  eviction/TTL.
- **Phase 5 — Switchover (ships last, behind `lazy_cert_distribution`).**
  `augment_ogm` emits `CertFp` instead of `Cert`; `verify_ogm` resolves from the
  store and returns `NeedCert` on miss. Integration test: two fresh auth nodes
  reach mutual verified routing with **zero** full certs on any OGM, only via
  fetch. Verify airtime drop.
- **Phase 6 — Observability + dissector + TUI.** Metrics (§9), `wayfinder-shark`
  update + pytest, TUI security/metrics surfacing.

---

## 11. Open decisions for the implementing session

1. **Anycast early-answer vs. always-to-origin.** Allowing any on-path cert
   holder to answer (not just the originator) cuts latency and airtime in the
   common case (the holder is usually B's 1-hop neighbor, who can link-reply),
   but spreads pending-query state to intermediate nodes. Recommendation: allow
   early-answer; it's the >95% fast path and the pending list is bounded
   everywhere anyway.
2. **Pending-query list vs. stateless requester-retry** (§3.5). Recommendation:
   both — list as the optimization, retry as the backstop.
3. **Fingerprint length** (8 bytes proposed) and **hash** (`Blake2s256`,
   already a dep). Confirm 8 bytes vs. a larger tag.
4. **Rollout:** flag day vs. `version`-byte hard cutover (§7).
5. **Reply first-hop when the responder is the origin but has no route to the
   requester yet:** rely on pending-list flush (recommended) vs. a reverse-path
   hint carried in the request. The design closed *without* needing reverse-path
   breadcrumbs (§3.3–3.5); do not add them unless a measured case demands it.

---

## 12. Key file map for the implementer

- `libs/wayfinder-auth/src/cert.rs` — `MembershipCert` (156 B), add
  `fingerprint()`.
- `libs/batman/src/wire.rs` — `TvlvType` (add `CertFp`), packet-type consts +
  new `BatmanCertReq/ReplyPacket` structs (mirror `BatmanUnicastPacket`).
- `libs/batman/src/engine.rs` — `handle_rx` forwarding + local delivery of the
  new packet types; reuse `next_hop`; the TQ clamp at `:486` is the correctness
  anchor for §3.3.
- `libs/wayfinder/src/auth.rs` — `augment_ogm` (`:467`), `verify_ogm` (`:562`,
  → `OgmVerdict`), `signed_message` (`:445`, feed cached cert bytes),
  `cache_neighbor` (`:656`, extend store), new requester/responder/pending
  logic.
- `libs/wayfinder/src/lib.rs` — OGM verify gate (`:566`), OGM originate
  (`:775`), new deliver-local hook for cert-control packets; `set_require_auth`
  /`auth_locked` context (`:417`/`:440`).
- `libs/wayfinder/src/config.rs` — `lazy_cert_distribution` flag.
- `libs/wayfinder-server` + `libs/wayfinder-protos` + `bins/wayfinder-tui` —
  metrics (§9) via the `add-metric` skill.
- `libs/wayfinder-shark` — dissector + pytest for the new records.
- `libs/wayfinder/fuzz` — extend the `verify_ogm` target for the new verdict
  paths; consider a `cert_req` parse target.
