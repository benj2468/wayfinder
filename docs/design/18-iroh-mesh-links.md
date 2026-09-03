# Design: Mesh links over iroh — peer-to-peer QUIC dialed by the node's own identity key

**Status:** Implemented, with two phase-2 items **not built** (§5). The
Headscale/Tailscale control plane design 08 introduced is gone from the tree —
see that document's superseded note for the inventory. Move this file to
`implemented/` when §5's remaining rows land and §6.1 has an answer from a real
deployment.

> **What is not built, stated up front because one of these is a live
> operational gap:**
>
> * **The CA's endpoint reaches a spoke only through hand-written config.** A
>   spoke's `bootstrap_peers` is the sole way `IrohLink` learns the key to dial
>   for first contact — §3.3b describes delivering it over RPC instead, and that
>   is not implemented. This is config parity with what design 08 required
>   (a spoke already hand-configured `discovery_addr` pointing at the CA), so it
>   is not a regression; it is an unrealised improvement.
> * **Path state is not a metric.** Direct-vs-relayed and per-path RTT are
>   available from `iroh`'s `PathEventStream`/`RemoteInfo` and are not surfaced
>   through `CentralRouter`. So "is this node hole-punching or relaying?" — the
>   exact question §6.1 turns on — is currently answerable only from `debug!`
>   logs, which is a poor position from which to gather the evidence phase 3
>   was supposed to wait for.

> **The phase-3 gate was not met, and that was a deliberate call.** §5 below
> gates retiring Headscale on two real CGNAT'd hosts holding a direct iroh
> path. That evidence does not exist; the retirement was authorized anyway.
>
> Two things make it defensible, and one thing does not:
>
> * **The failure mode is a wash.** If hole punching fails, an iroh connection
>   relays through the CA — which is exactly where a DERP-relayed Tailscale
>   path went. Slower than direct, and no worse than what it replaced.
> * **Phase 3 is atomic.** `GetVpnEnrollment` is how a node collected its
>   Headscale preauth key, so removing it while Headscale still ran would have
>   left nodes unable to enroll into the tunnel. There was no half-retirement
>   to stage.
> * **What is not covered: migration.** A node already deployed with a
>   `UdpMulti`-over-Tailscale link keeps working only until its config is
>   redeployed, and it must gain an `Iroh` link naming the CA in
>   `bootstrap_peers` at that point. Nothing in this repo performs that
>   transition, and no test covers a mesh with one node on each path.

**Scope (phase 1):** `libs/wayfinder/src/config.rs` (a new `LinkTransport`
variant), `libs/wayfinder-driver/src/iroh.rs` (a new `LinkT`), a dispatch arm
in `bins/wayfinder-tap/src/main.rs`, and the Cargo wiring for a non-default
`iroh` feature. **No change** to the `no_std` core (`libs/interfaces`,
`libs/batman`, `CentralRouter`), to the `LinkT`/`FrameIo` trait surface, to
`libs/wayfinder-auth`, or to anything Headscale-related. Nothing is deleted.

---

## 1. Motivation

`docs/design/implemented/08-internet-links-headscale-vpn.md` reaches two
Starlink-CGNAT nodes by running a Tailscale tunnel underneath an ordinary
`LinkTransport::Udp`/`UdpMulti` link. It works and is deployed. Its cost is
that the mesh has **two credentials, two namespaces and two control planes**
for one question — "may this node reach that node?" — and the seam between them
has leaked into places it should not have.

The clearest evidence is in `libs/wayfinder-server/src/authz.rs`, a file
carrying its own `SECURITY ALERT` banner:

> That is why `MgmtAccess::GrantedMember` names exactly one request: anything
> added to it is added to the entire mesh at once.

An entire authorization tier, a certificate flag (`CERT_FLAG_MEMBER`), and a
row in the RPC table exist to serve exactly one RPC — `GetVpnEnrollment` —
which exists to hand out a Headscale preauth key. Design 08's Correction 1
records that this tier did not exist when the design was written and had to be
invented mid-implementation, because an enrolled node presenting its own
certificate landed on `Denied(NoCapability)`.

iroh removes the second credential rather than integrating it better. An iroh
`EndpointId` **is** an Ed25519 public key — `iroh_base::SecretKey` is literally
`ed25519_dalek::SigningKey` with `from_bytes(&[u8; 32])`, the same shape as this
node's identity seed. So the key in a node's `MembershipCert` is already its
network address, and design 01's lazy certificate distribution already spreads
those keys mesh-wide. There is nothing to allocate, nothing to correlate, and
no second thing to revoke.

Design 08 considered and rejected exactly this shape (its alternative 2, "a
wayfinder-native coordination protocol"), on the grounds that it meant building
address allocation, live peer-list distribution and NAT traversal from scratch.
That objection was correct then and does not apply to iroh: it is a library
that does two of those, and **eliminates** the third, because there is no
address to allocate.

### Why not just do it, then?

Because the Headscale path works, is deployed, and is covered by two NixOS VM
tests, and because the one thing that would actually justify the switch is the
one thing neither design can assert from a test bench. Design 08 is candid
about it:

> What no test covers is two hosts behind *real* NAT, which is where
> hole-punching either happens or silently degrades to relaying.

So phase 1 ships an iroh link *beside* the existing one and changes no default.
Retiring Headscale is phase 3, gated on evidence from a real deployment.

---

## 2. Can this run on an embedded board? No — and it should not.

Asked during design; recorded here so it is not re-asked.

**iroh is `std`-only and will not be otherwise.** Neither `iroh` nor
`iroh-base` declares `#![no_std]`; the crate depends unconditionally on
`tokio`, `hickory-resolver`, `portmapper` and `noq` (n0's QUIC), and pulls 112
crates this workspace does not already have. None of that is portable to a
Cortex-M.

But the stronger answer is that it would be pointless if it *were* portable.
iroh's entire job is establishing direct connectivity **across the internet**
between hosts that cannot accept inbound connections. An nRF52840 has no IP
stack, no internet, and no NAT to traverse — it reaches the mesh over LoRa, BLE
or 802.15.4, where the medium is a shared broadcast domain and the relevant
problems are duty cycle and a 2048-byte MTU, not hole punching.

This is the same line design 08 already drew for `tailscaled` ("Not covering
embedded boards... it has no OS network stack to put one on"), and it is the
same line `libs/blue`'s BlueZ backend and `wayfinder-driver`'s raw-L2 carriers
sit on. The rule from `CLAUDE.md` applies unchanged:

> Keep that shape when adding a Linux-only carrier: gate the implementation,
> not the seam.

So `IrohLink` is gated, its **constructor exists on every target**, and a
config naming an `iroh` link on a build without the feature is a *startup
error naming the reason*, never a compile error.

One consequence worth stating plainly: **an iroh link is an internet link, and
an internet link is a host-node concern.** A mesh of MCUs still reaches the
wider mesh the way it does today — through a `wayfinder-tap` host that fronts
them on a radio and carries the internet hop on its own behalf. iroh changes
what that host's internet hop is made of; it changes nothing below it.

---

## 3. Design (phase 1)

### 3.1 The link is a `LinkT`, not a tunnel underneath one

This is the one real architectural difference from design 08, and it is worth
being explicit about because it inverts that design's headline property.

Headscale gives an **IP-level tunnel**: `bind_addr`/`remote_addr` stay plain
`SocketAddr`s that happen to point into `100.64.0.0/10`, and the mesh code is
unchanged — design 08's "zero changes to the core" win. iroh gives **QUIC
connections keyed by public key**. There is no interface to bind and no address
to name, so it cannot slide underneath `LinkTransport::Udp`. It has to *be* a
link.

That is a cost (new code on the packet path) and a benefit (the tunnel becomes
a thing the node can see, log, meter and alarm on, instead of a daemon it has
no handle to).

### 3.2 Peer resolution: learn `Mac → EndpointId`, exactly as UDP learns `Mac → SocketAddr`

`UdpMultiLink` keeps a `UdpPeerTable` mapping neighbor MAC to transport
address, learned from the sender address of every received datagram, bounded by
`MAX_TRACKED_PEERS` (128) and aged by `PEER_TTL` (600s). `IrohLink` keeps the
identical structure with `EndpointId` in place of `SocketAddr`, learned from
`Connection::remote_id()` of the connection a frame arrived on.

Deliberately **not** resolved from the certificate store, even though the
`MembershipCert` binds exactly this `Mac ↔ Ed25519 pubkey` pair and would give
a better answer. Three reasons:

1. It would couple a link to `wayfinder-auth`, which no other link is.
2. It would not work with authentication disabled, which is a supported mode.
3. It makes phase 1 structurally parallel to a carrier that has already been
   reviewed, which is worth more in a first increment than the better answer.

The bounds carry over for the same reason they exist on UDP: a learned entry is
attacker-influenced. It is *less* so here — an entry can only be created by a
peer that completed a QUIC handshake proving possession of that `EndpointId`'s
private key, where a UDP datagram's source address is merely asserted — so the
cap and TTL are conservative rather than load-bearing. They stay anyway; a
mesh-authenticated frame is still not an authorization to occupy a table slot
forever.

### 3.3 Consequence: spoke-to-spoke transits the hub, as it does today

Because a MAC is learned from the connection that carried it, a spoke that
hears spoke B's OGM relayed by the hub learns `B → hub's EndpointId`, and
addresses B through the hub. That is **exactly today's behavior** (design 08 §9
answer 7), so phase 1 is a parity change, not a regression.

Phase 2 fixes it, and this is where iroh's identity model pays: the fix design
08 describes ("the node's own UDP endpoint carried in an OGM TVLV so peers
could learn it without static configuration") needs no new wire format here,
because the address is the key and the key is already in the certificate. Phase
2 is "when auth is on, prefer the cert store over the learned table" — a
resolution-order change, not a protocol change.

### 3.3b Bootstrap: the operator already holds the value, but enrollment does not carry it

Asked during design: *can't a node just get the CA's public key from
enrollment?* Nearly — and the distinction matters, because one plausible
version of it dials a key nothing listens on.

**What enrollment returns is the wrong key.** `SubmitCsrResponse::CsrIssued`
carries `{cert, trust_anchor}`, and the trust anchor is the **mesh root signing
key** — the thing certificates are verified against.
`nix/machines/wayfinder-ca/common.nix` keeps it in `root.seed`, a *different
file* from the CA node's own `identity.seed`. Deriving a bootstrap peer from
the trust anchor would produce a perfectly well-formed `EndpointId` that no
endpoint has ever bound. Two keys, two jobs; only the second is an address.

**What enrollment already *requires* is the right key.** To reach the CA at
all, a client calls `Client::connect_tls(addr, node_key, identity)`, where
`node_key` is the CA node's 32-byte identity public key, pinned in the RPK
handshake. So whoever runs `wayfinderctl enroll` necessarily holds the CA's
`EndpointId` *and* its address before sending a single byte — earlier than
enrollment, not later, and with no proto change to obtain it.

That is why a bootstrap peer is spelled `<hex key>@<ip:port>` (§3.3c): both
halves are values the operator already typed to enroll. It is a re-spelling of
existing knowledge, not a new secret to go find.

**The remaining gap is that nothing carries it *to the node*.** A node's config
holds `trust_anchor_path` but no field for the CA's identity key, so today an
operator writes `bootstrap_peers` by hand. Closing that is phase 2, and the
shape is constrained by `CLAUDE.md`'s rule that host tooling must never
provision a node by writing files it expects that node to read: the CA's
endpoint travels **over RPC**, alongside the identity `SetAuth` already
installs — not by `enroll` editing the node's YAML.

**And past first contact it is moot.** `EndpointId == ed_pubkey`, and design
01 already distributes certificates mesh-wide on demand, so any node whose
certificate this node holds is already dialable. Bootstrap is only ever about
the very first peer.

### 3.3c Two bootstrap forms, because a relay-less mesh has no other route

`<hex key>` alone is dialable only when something can turn a key into a route —
a configured relay, or an address-lookup service. With `relay_url` unset and no
discovery, a bare key names a peer nothing can reach.

So a bootstrap peer may also be written `<hex key>@<ip:port>[,<ip:port>…]`,
supplying direct addresses. That is what makes a LAN or air-gapped mesh work
with no relay at all — and what makes this link testable without standing up
relay infrastructure, which is how the gap was found.

### 3.4 Frames are QUIC datagrams, and that caps the MTU

A mesh frame is unreliable and self-contained; QUIC's unreliable datagram
extension is the honest match, and using streams would add ordering and
retransmission that BATMAN does not want and would pay for head-of-line
blocking it cannot use.

The cost is size. `Connection::max_datagram_size()` is path-derived and in
practice lands near 1200 bytes, below `MAX_LINK_FRAME_LEN` (2048). Phase 1
**checks the limit and drops with a `trace!` naming the reason** rather than
truncating or silently failing — the same discipline as `UdpMultiLink`'s
`"drop: frame exceeds udp-multi wire buffer"`.

This is not a new exposure. A frame that large already fails over a WireGuard
tunnel with a 1280-byte MTU; it is simply now *visible* and attributable
instead of being an IP-fragmentation problem one layer down. Phase 2 wires in
`libs/wayfinder-link-utils`, which exists for precisely this and already backs
`rylr998` and `blue`.

### 3.5 Dialing never blocks the driver loop

`LinkT::send` is called from the driver's event loop. Dialing a peer takes a
QUIC handshake and possibly a hole-punch, which is far too long to hold that
loop.

So `send` **never dials inline**. If a live connection to the resolved peer
exists, the datagram goes out; if not, a background dial is started (deduped,
so a repeatedly-addressed unreachable peer starts one attempt, not one per
frame) and the frame is dropped with a `trace!`.

Dropping is correct rather than merely convenient: it is what `UdpMultiLink`
already does for an unlearned destination (`"drop: no known udp address for
destination"`), and the mesh's own repetition is the recovery mechanism —
Trickle re-emits OGMs, so the connection established by the dial is used by the
next emission a second or so later. A link that stalled the loop to guarantee
the *first* frame would be trading the whole node's liveness for one OGM.

### 3.6 Relays

`relay_url` absent ⇒ `RelayMode::Disabled`: direct paths only, which is the
correct posture for a LAN or an air-gapped mesh and makes iroh's default
behavior (n0's public relays) unreachable by accident.

`relay_url` present ⇒ `RelayMode::Custom`, pointed at a self-hosted
`iroh-relay`. This is the direct analog of design 08's embedded-DERP decision
(iroh's relay protocol *is* a revised DERP), and it preserves that design's
Correction 4 property — no traffic path depends on a third party's
infrastructure.

**`RelayMode::Default` is deliberately not reachable from config.** An operator
should not be able to route an isolated mesh's traffic through n0's servers by
omitting a field, for the same reason `wayfinder-tailscale.nix` pins
`loginServer` — design 08's note that a bare `tailscale up` reaching Tailscale
Inc.'s coordination server "would leak an isolated network's coordination
metadata to a third party, quietly and without anything failing" is exactly the
failure to avoid twice.

### 3.7 Key reuse

The node's identity seed becomes the iroh `SecretKey`, so the `EndpointId` is
the `ed_pubkey` in its `MembershipCert`. This is the second such reuse, not the
first: `libs/wayfinder-tls-mgmt` already presents the same seed as an RFC 7250
raw public key in the management TLS handshake.

Both consumers are TLS 1.3 signatures over transcripts with distinct,
standard-mandated context strings, and both are domain-separated from
`OgmSig`'s `domain ‖ orig ‖ seqno ‖ cert_bytes`. Recorded as a deliberate
decision rather than an accident, because a third consumer with a
non-context-separated signing scheme would not be safe to add on the same
grounds.

---

## 4. What phase 1 does *not* do

- **Delete nothing.** Headscale, `tailscaled`, `vpn.rs`, the VPN panel, both
  Nix modules and both VM tests are untouched, and no default changes.
- **No `GetVpnEnrollment` change**, no `CERT_FLAG_MEMBER` change, no
  `authz.rs` change. The tier those serve stays until phase 3.
- **No management-API transport change.** Reaching a node's mgmt API by
  `EndpointId` is a real opportunity (`connect_tls` has an obvious iroh
  sibling, and `Connection::remote_id()` lands on the same authorization seam
  the RPK handshake already feeds) but it is a separate design.
- **No fragmentation** (§3.4), **no cert-store resolution** (§3.3).

---

## 5. Phases

| | What | Gate to start |
|---|---|---|
| **1** | `LinkTransport::Iroh` + `IrohLink`, beside the existing links | — (done) |
| **2a** | ✅ `wayfinder-link-utils` fragmentation, at a fixed 1022-byte budget (§3.4) | — |
| **2b** | ✅ `PeerDirectory`: certificate-derived `Mac → EndpointId`, outranking the learned table, for direct spoke-to-spoke (§3.2) | — |
| **2c** | ❌ **Not built.** The CA's endpoint delivered over RPC rather than hand-written into a spoke's `bootstrap_peers` (§3.3b) | — |
| **2d** | ❌ **Not built.** Path state (direct vs relayed, per-path RTT) as a `CentralRouter` metric | — |
| **3** | ✅ Retire Headscale: `vpn.rs`, both Nix modules, `vpn-data-plane.nix`, the three VPN RPCs, the `GrantedMember` tier, `wayfinderctl vpn`, the dashboard's VPN panel. `CERT_FLAG_MEMBER` (0x08) kept as a **reserved** bit — field certificates carry it inside a signature | Gate **not met**; shipped on the judgment in the status note above |

Phase 3's gate is the whole point. If iroh degrades to relaying through the CA
on real Starlink, the switch buys nothing the current deployment does not
already have — a relayed iroh path and a DERP-relayed Tailscale path are the
same trip through the same box — and Headscale should stay.

---

## 6. Open questions

1. **Does hole punching hold, Starlink to Starlink?** The only question that
   decides phase 3. Not answerable in-process, in a VM, or in CI.
2. **What does an iroh link cost at idle?** `HOLEPUNCH_ATTEMPTS_INTERVAL` is
   5s and QUIC keepalives run per-connection, so a hub with N spokes holds N
   connections with independent timers. Design 08 already flags the N² OGM
   flooding cost on a shared segment; this is a second per-peer cost on the
   same box and should be measured before it is assumed small.
3. **One endpoint or one per link?** Phase 1 binds one `Endpoint` per
   configured iroh link, which is simple and matches how every other transport
   behaves. Two iroh links on one node would bind two QUIC sockets and hold two
   independent NAT mappings for the same key. Probably fine, possibly
   wasteful, currently untested — validation rejects the second one rather than
   shipping an untested topology.

---

## 7. Key file map

- `libs/wayfinder/src/config.rs` — `LinkTransport::Iroh`, its validation, and
  the `"iroh"` short kind name.
- `libs/wayfinder-driver/src/iroh.rs` — `IrohPeerTable`, `IrohLink`,
  `IrohLinkParams`, `build_iroh_link`. The `#[cfg]`-off stub constructor lives
  here too, so the seam is unconditional.
- `libs/wayfinder-driver/Cargo.toml` — the non-default `iroh` feature,
  following the `ble` precedent (a heavy backend split out of `std`/`tokio`).
- `bins/wayfinder-tap/src/main.rs` — the dispatch arm; enables the feature by
  default so a real node keeps zero-config behavior.
