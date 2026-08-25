# Design: Internet-connected mesh links via a Headscale-managed tunnel, managed from the wayfinder UI

**Status:** Implemented and deployed. The control plane, the CLI, the dashboard
panel and the Nix modules are in; `nix/tests/ca-provider.nix` exercises the
control-plane flow against a real Headscale in a VM, and
`nix/tests/vpn-data-plane.nix` covers the data plane with real `tailscaled`
clients in containers. The cloud CA (`nix/machines/wayfinder-ca`) runs the
Headscale and Headplane this design calls for.

What no test covers is two hosts behind *real* NAT, which is where hole-punching
either happens or silently degrades to relaying.

> **Five corrections to this document, found while implementing it.** Each was
> a specific claim below that did not survive contact with the code or with
> Headscale, and each is annotated inline where it appears:
>
> 1. **§3.2's authorization tier did not exist.** `GrantedSelfKey` is granted
>    when the handshake key is the *node's own* key, not when it matches a
>    verified `MembershipCert` — so an enrolled node presenting its own
>    certificate landed on `Denied(NoCapability)` and had its connection closed
>    before it could send a request. Fixed by adding `CERT_FLAG_MEMBER` to the
>    certificate and a `GrantedMember` tier that is exactly one request wide.
>    The bit is set explicitly rather than inferred from the absence of the
>    management bits — see §3.2.
> 2. **§3.3/§10 put the handlers in `RouterAdapter`. They cannot go there.**
>    The router loop is never told *who* is calling (`QueryTx` carries a
>    request and a reply channel, nothing else), and `GetVpnEnrollment` has no
>    fields precisely because the identity it mints for is the connection's.
>    The adapter is also synchronous and runs on the task that emits OGMs, so
>    awaiting an HTTP round-trip there would stall routing. They live in the
>    transport instead.
> 3. **Headscale scopes a preauth key to a numeric user id, not a name.**
>    §3.2's single `CreatePreAuthKey` call is really find-or-create-user
>    followed by the mint. This turned out to be an improvement: giving each
>    node its own Headscale user named by its MAC answers §9.2's open question
>    about correlation robustness, since a user is not the display name an
>    operator renames.
> 4. **Headscale refuses to start with an empty DERP map**, so §3.1's embedded
>    relay is not merely preferable to the public one — it is what makes
>    dropping the public map possible at all.
> 5. **`reqwest` under `rustls-no-provider` panics without a process-wide
>    crypto provider**, which `tls.rs` never installs (it names providers
>    explicitly per config). Uncaught, this would have surfaced as a panic at
>    the first node's enrollment rather than at the CA's startup.
> 6. **§3.1 does not say Headscale must be served over TLS. It must.** Not as
>    hardening — `tailscaled` refuses a plaintext DERP connection outright,
>    whatever scheme headscale advertises, and its `NetInfo`/STUN probing
>    depends on that handshake succeeding *at all*. So a plain-HTTP
>    coordination server registers every node correctly and then leaves them
>    unable to reach each other, including two peers on the same LAN. Nothing
>    reachable with `curl` shows it, which is why a control-plane test
>    (`ca-provider.nix`) passes over plain HTTP while the deployment would not
>    work; `vpn-data-plane.nix` is what found it. `tls.mode` in
>    `nix/modules/wayfinder-headscale.nix` now defaults to Let's Encrypt, and
>    plain HTTP is a thing a configuration has to ask for and gets warned about.

Grew out of a design discussion about deploying a wayfinder node in the cloud
as an auth provider/CA, and how two Starlink-connected boxes (no stable public
IP, behind CGNAT) reach each other.

> **Update:** the CA half of that discussion has since shipped on its own —
> see `docs/design/implemented/11-cloud-auth-provider.md`. There is now a
> `wayfinder-tap` in provider mode on an Oracle Always Free instance
> (`nix/machines/wayfinder-ca`, provisioned by `infra/oracle/`), carrying no
> mesh links, which is the "cloud box with a stable public address" §1 below
> assumes. Three things that design settled and this one can build on:
> the instance defaults take *half* the Always Free allowance specifically to
> leave room for the Headscale box; the UDP ingress rule this design needs is
> already written and commented in `infra/oracle/main.tf`; and the host was
> chosen partly *because* it has real UDP ingress — Cloudflare was rejected for
> lacking it, which would have made Headscale's embedded DERP (STUN on
> UDP/3478) impossible.

**Scope:** `libs/wayfinder-protos` (new/extended RPCs), `libs/wayfinder-server`
(`Authority`/`authority.rs`, `RouterAdapter`/`adapter.rs`), `bins/wayfinder-ctl`
(`enroll` flow), `bins/wayfinder-web` (a new VPN-peers panel), and
`nix/modules/` (colocating Headscale/Headplane with `services.wayfinder`, plus
new `tailscaled`-on-each-host config). **No change** to the `no_std` core
(`libs/interfaces`, `libs/batman`, `CentralRouter`), the `LinkT`/`FrameIo`
trait surface, `libs/wayfinder-auth`'s `MembershipCert`/OGM-auth semantics, or
`LinkTransport::Udp`'s wire shape (`bind_addr`/`remote_addr` stay plain
`SocketAddr`s — they just end up pointing at Tailscale-assigned addresses
instead of LAN ones).

## 1. Motivation

Two mesh nodes behind Starlink CGNAT cannot reach each other directly — Elon
literally can't route between them without something creating a tunnel,
because neither side can accept an inbound connection. A cloud-deployed
wayfinder auth provider (the CA — see `Authority` in
`libs/wayfinder-server/src/authority.rs`, already designed to run standalone
in "provider mode") is the one box in this topology with a stable public
address, making it the natural place to also host VPN coordination.

Three designs were considered in the discussion that led here, in order:

1. **Static WireGuard**, hand-configured per node/peer in Nix. Rejected: no
   dynamic enrollment (editing peer lists by hand for every join/leave/
   rotation), and no NAT-traversal story beyond a manually-built hub-and-spoke
   topology.
2. **A wayfinder-native coordination protocol** — extend `SubmitCsr`-style
   enrollment to also allocate a tunnel address and distribute a live peer
   list, reconciled by a new client-side poll loop. Rejected on inspection:
   this repo has **no existing address-allocator concept anywhere** (mesh MACs
   aren't CA-allocated either — they're derived client-side and merely
   validated) and **no streaming RPC support**
   (`WayfinderService::handle` in `libs/wayfinder-protos/src/service.rs:1036`
   is strictly unary). Building this means reimplementing, from scratch and
   under this project's own security bar, exactly the parts of Tailscale/
   Headscale that are hardest to get right: address allocation, live peer-list
   distribution, and NAT traversal (STUN/DERP-style relay).
3. **This design** — deploy Headscale (the open-source Tailscale coordination
   server) as the VPN control plane, and make wayfinder's own CA the only
   thing an operator has to touch: registration and revocation happen in the
   wayfinder UI, which thinly proxies to Headscale's API. Headplane (a
   Headscale web UI) is deployed too, but only as an out-of-band admin
   fallback, not a surface operators are routed to for normal use.

## 2. Goals / Non-goals

**Goals**
- A node enrolling into the mesh (`wayfinderctl enroll`) can, in the same
  step, be handed everything it needs to join the VPN automatically — no
  separate manual `tailscale up` with a hand-carried key.
- VPN peer registration and revocation are visible and actionable **from the
  wayfinder UI/CLI only**. An operator's day-to-day workflow never requires
  opening Headplane.
- No new address allocator, no new peer-list distribution/reconciliation loop,
  no new NAT-traversal logic in wayfinder — Headscale's existing, audited
  implementation owns all of that.
- Getting a working VPN identity requires already holding a valid
  `MembershipCert` — VPN membership is gated behind mesh trust, not a parallel
  independent trust root.
- Two Starlink-connected boxes can reach each other's mesh UDP link with zero
  changes to `LinkTransport::Udp` or anything in the `no_std` core.

**Non-goals**
- Not building a custom Rust WireGuard/tunnel implementation. `tailscaled` is
  a separate process this design assumes is installed on every host node;
  wayfinder never links against it.
- Not covering embedded boards. `tailscaled` needs a real OS network stack —
  this is `wayfinder-tap`/host-only, same category as `ethernetAccess` in the
  Nix module today. No change reaches `libs/wayfinder-nrf` or the board
  binaries.
- Not attempting real-time bidirectional push from wayfinder-server to nodes.
  Headscale already pushes live peer updates to `tailscaled` directly — the
  wayfinder control plane only needs to *initiate* (enroll) and *terminate*
  (revoke) a node's Headscale registration, not shuttle peer-list state itself.
- **Not preserving easy swap to a non-WireGuard VPN backend.** An earlier
  sketch (static WireGuard/IPsec via a Nix `backend` option, or a
  wayfinder-native `VpnBackend` trait) kept that door open. Headscale is
  fundamentally a Tailscale/WireGuard coordination server — adopting it
  commits to WireGuard as the tunneling protocol. Moving to IPsec later would
  mean leaving the Headscale ecosystem entirely, not swapping a config flag.
  This is a real trade-off against the earlier goal, made explicitly rather
  than left implicit: the win (mature NAT traversal, no allocator, no
  reconciliation loop, one integration surface) is judged worth the lock-in.

## 3. Design

### 3.1 Topology

The cloud box runs three things side by side:

- **`wayfinder-server`** in provider/CA mode (as today), plus the new
  Headscale-integration logic below.
- **`headscale`**, configured with its own embedded DERP relay, so no traffic
  path depends on Tailscale Inc.'s infrastructure — consistent with treating
  this as an *isolated* network. `--login-server`/DERP map on every client
  point at this box, not the public defaults.
- **`headplane`**, network-restricted (e.g. bound to an admin-only interface
  or behind an IP allowlist) — deliberately *not* linked from the primary
  `wayfinder-web` navigation. It exists for the case where `wayfinder-server`
  itself is down but Headscale/tailscaled data-plane connectivity is fine (see
  §4) — an operator can still manage VPN membership directly.

Every Starlink-side (or otherwise internet-only) `wayfinder-tap` host also
runs `tailscaled`, pointed at this Headscale instance. `LinkTransport::Udp`'s
`bind_addr`/`remote_addr` on that host are just whatever address Tailscale
assigned it (`100.64.0.0/10` range) — no wayfinder config schema change.

### 3.2 Enrollment: one CLI command, two RPCs, two different trust tiers

Today's flow (`bins/wayfinder-ctl/src/lib.rs`, `poll_enroll`) sends
`SubmitCsrRequest{node_mac, ed_pubkey, x_pubkey, enrollment_token}`
(`wayfinder.proto:576-593`) and gets back `SubmitCsrResponse::CsrIssued{cert,
trust_anchor}` (`wayfinder.proto:1357-1366`) on success.

**The VPN preauth key must not travel in `CsrIssued`.** `SubmitCsr` runs at
the `GrantedEnrollment` authorization tier — reachable by any client that
completes the (always-encrypted, but identity-unverified) RPK TLS handshake
and supplies a correct `enrollment_token`. Per `authz.rs`'s own docstring,
`node_mac`/`ed_pubkey`/`x_pubkey` in that request are "entirely
client-supplied and bound to nothing about this connection" — self-asserted,
not verified. Bundling a network-reachability-granting VPN key into that same
response means anyone holding the (single, shared, bearer) enrollment token —
already flagged as a weaker-trust step in `docs/design/
06-management-api-authentication.md` F3/F8 — walks away with both a cert
*and* VPN reachability for whatever identity they claimed, in one shot, with
no proof they're the actual node. That collapses §6's "two gates in series"
claim into one gate producing two artifacts — not two independent checks.

Instead, add a second RPC that only a client *holding the newly-issued
private key* can call:

```protobuf
message GetVpnEnrollmentRequest {}
message GetVpnEnrollmentResponse {
  string vpn_login_server = 1;
  string vpn_preauth_key = 2;   // single-use, short-TTL, minted on this call
}
```

> **Correction 1 (as implemented).** This paragraph named the wrong tier, and
> the tier it described did not exist. `GrantedSelfKey` is granted when the
> handshake key is the *node's own* key — the operator holding the CA's seed —
> not when it matches a verified `MembershipCert`. A device certificate carries
> neither the admin nor the viewer bit, so an enrolling node presenting it was
> `Denied(NoCapability)` and had its connection closed before it could send
> anything.
>
> What shipped instead: a new `CERT_FLAG_MEMBER` bit on the certificate, set by
> `Authority::issue_cert` (the device path) and *not* by `issue_user_cert` (the
> operator path), and a `GrantedMember` tier earned by that bit. The bit is
> explicit rather than inferred from "carries none of the other bits" — an
> inferred tier would silently widen every time a capability was added, and
> would make a certificate's meaning depend on which bits the reader happens to
> know about. Certificates issued before the bit existed keep landing on
> `Denied(NoCapability)`, so this was additive rather than a flag day.
>
> `permits` gates this request *ahead of* the tier match, and refuses it to the
> full grants: `GetVpnEnrollment` mints a credential for the caller's device
> identity, and neither an operator's session certificate nor the node's own
> seed is a device. That inverts the previous invariant that a full grant may
> invoke everything, which is the point — it is what makes the two gates below
> genuinely independent rather than one gate producing two artifacts.

Gated at the **member tier** (`MgmtAccess::GrantedMember`), which
`decide_access` grants only when the *TLS handshake key itself* matches a
verified, non-revoked `MembershipCert` carrying `CERT_FLAG_MEMBER`. That's
proof of possession of the issued identity's private key over an authenticated
connection, not a self-asserted claim — a materially different, and much
stronger, gate than `SubmitCsr`'s.

Server-side, this handler (not the CSR-issuance path) makes the new outbound
calls: if Headscale integration is configured (`provider.headscale.{api_url,
api_key_path, login_server, node_tag, preauth_ttl_secs}`, alongside the
existing `enrollment_token`/`auto_approve` fields), mint a single-use key
tagged `tag:wayfinder-node` and return it. No new persisted state on the CA
side for this step.

> **Correction 3 (as implemented).** Headscale scopes every preauth key to a
> *user*, identified by a numeric id — passing a name is rejected outright
> (`invalid value for uint64 field user`). So this is two calls, not one:
> find-or-create a Headscale user named by the node's MAC as hex, then mint the
> key against its id. Losing the find-or-create race is treated as success by
> re-reading, since both callers wanted the user to exist.
>
> This is a better answer to §9.2 than the hostname join this document
> proposed. A hostname is a display name an operator can rename in Headscale's
> own UI; the owning user is not, so correlation and revocation target the user
> and fall back to the hostname only for peers registered by hand — which are
> listed rather than hidden, since a peer with tunnel reachability and no mesh
> identity behind it is exactly what an audit needs to surface.
>
> **Correction 2 (as implemented).** The handler is in the management
> *transport*, not `RouterAdapter`. Two independent reasons: the router loop is
> never told which peer is calling — `QueryTx` carries a request and a reply
> channel and nothing else, which is also *why* `GetVpnEnrollmentRequest` can
> have no fields — and the adapter is synchronous, running on the same task
> that emits OGMs and forwards frames, so awaiting an HTTP round-trip there
> would stall routing for the length of the coordination server's timeout.

Client-side, `wayfinderctl enroll` still does this as one command, just as
two sequential connections: after `SubmitCsr` returns `CsrIssued` and the
cert/trust_anchor are written locally, it reconnects — now presenting its own
freshly-issued identity as the TLS client key, which is what earns
`GrantedSelfKey` — calls `GetVpnEnrollment`, and shells out to:

```
tailscale up --login-server=<vpn_login_server> --authkey=<vpn_preauth_key>
```

> **Correction 3, continued.** As shipped, this does *not* pass `--hostname`.
> Correlation instead runs through the Headscale *user* each node registers
> under (see Correction 3 above) — the preauth key mints the user
> find-or-created for this MAC, so the node lands under that user's ownership
> without needing to also name itself on the command line. `§3.3`'s
> `ListVpnPeers`/`RevokeVpnPeer` join against that owning user, falling back to
> the hostname only for a peer with no owning user.

If Headscale integration isn't configured on a given CA deployment,
`GetVpnEnrollment` isn't called (or returns an empty/error result the CLI
treats as "no VPN configured") and enrollment behaves exactly as it does
today — VPN join is additive, not required.

### 3.3 Management surface: wayfinder proxies Headscale, doesn't replace it

Two new provider-mode RPCs on `WayfinderDataProvider`, authorized the same way
`SetAuth` is (`GrantedAdmin`/`GrantedSelfKey`, `authz.rs`'s `permits` — the
`MgmtAccess::GrantedAdmin | MgmtAccess::GrantedSelfKey => true` arm):

```protobuf
// illustrative — see the real message in wayfinder.proto, which also carries
// raw_hostname
message ListVpnPeersRequest {}
message ListVpnPeersResponse { repeated VpnPeerStatus peers = 1; }
message VpnPeerStatus {
  bytes node_mac = 1;          // joined against the owning Headscale user, falling back to hostname
  string tailscale_ip = 2;
  bool online = 3;
  int64 last_seen_unix = 4;
  int64 key_expiry_unix = 5;
}

message RevokeVpnPeerRequest { bytes node_mac = 1; }
message RevokeVpnPeerResponse {}
```

> **Corrections 2 and 3 (as implemented).** These live in the management
> transport, not `RouterAdapter` — see §3.2. And revocation deletes the node's
> Headscale *user* rather than its nodes: that takes the registrations **and
> any minted-but-unspent preauth keys** with it, so a revocation racing an
> enrollment cannot leave a usable credential behind for a node that was just
> removed. It is idempotent by contract, because the retry path for a
> half-completed revoke has to converge.

The transport implements these by calling Headscale's `ListNodes` /
`DeleteUser` REST endpoints and matching on the owning user (§3.2) — no new
mapping table, since the wayfinder MAC *is* that user's name.

**Revocation is one action in the UI that does two things.** A `RevokeNode`
that the router answers successfully is followed, in the transport, by the
Headscale-side removal. An operator clicks "revoke" once in `wayfinder-web`;
both the mesh membership and the VPN registration go away.

> **As implemented (answering §9.4).** Ordered mesh-first, because mesh
> membership is what grants routing trust: a failure there leaves the tunnel
> alone rather than stranding a node that is still a member. If the mesh half
> succeeds and the VPN half fails, the response is an **error naming both
> outcomes**, not a success — the node can no longer route but can still reach
> the tunnel, and an operator who is told "revoked" would never go looking.
> `RevokeVpnPeer` is the retry, exposed as `wayfinderctl vpn revoke` and as the
> dashboard's per-peer *Remove*, and it is idempotent so the retry converges.
> Enforced server-side rather than by the client, so a client that forgets the
> second call cannot produce a silent partial revoke.

`bins/wayfinder-web` gets a new panel (likely alongside the existing
Security-tab area, given that's where enrollment/cert UI already lives per
`docs/design/06-management-api-authentication.md`'s history) listing
`VpnPeerStatus` rows with a revoke button. Headplane is linked from an
"Advanced" or footer area only, framed as a fallback, not a primary action.

### 3.4 What does *not* need building

- **No peer-list reconciliation loop.** `tailscaled` maintains its own live
  connection to Headscale and receives peer updates directly — wayfinder never
  ships peer state to a node after the initial `tailscale up`.
- **No address allocator.** Tailscale assigns from its own CGNAT range.
- **No NAT-traversal/relay logic.** Headscale's DERP relay + the standard
  Tailscale STUN-based hole-punching handle this entirely outside wayfinder.
- **No new persisted CA state.** `ListVpnPeers`/`RevokeVpnPeer` are computed
  on demand from Headscale's own node list, joined by the owning Headscale
  user (falling back to hostname for a hand-registered peer); nothing new is
  added to `CaLog`/`Persisted` storage.

## 4. Correctness / edge cases

- **Headscale/DERP outage.** Already-established `tailscaled` connections
  (and the WireGuard tunnels under them) keep working — coordination-plane
  downtime doesn't tear down the data plane. Only new enrollments and
  peer-list changes stall until it recovers.
- **`wayfinder-server` down, Headscale/tailscaled fine.** Mesh VPN
  connectivity is unaffected; only new enrollment and the wayfinder-UI revoke
  path are unavailable. This is exactly the case Headplane's break-glass
  deployment (§3.1) exists for.
- **Stolen/leaked preauth key.** Grants network *reachability* on the tunnel,
  not mesh *membership* — an attacker with only a stolen key can open a raw
  connection to another node's UDP socket, but wayfinder's own OGM/frame
  authentication (`libs/wayfinder-auth`, "authenticity + segregation only")
  still rejects it at the mesh layer. Single-use + short TTL bounds the window
  regardless. This mirrors the bearer-secret framing `docs/design/
  06-management-api-authentication.md` §F8 already applied to
  `enrollment_token` — same class of risk, same mitigation shape.
- **Half-completed revoke** (cert revoked but the Headscale API call fails, or
  vice versa). Not a security hole per the point above — VPN reachability
  alone isn't mesh trust — but it is an operational inconsistency the UI
  should surface (a "VPN revoke failed, retry" state) rather than silently
  reporting success. Flagged as an open decision in §9.
- **Re-enrollment with the same MAC** (e.g. after a cert was revoked and
  reissued) will attempt to register a new Headscale node under a hostname
  that already exists. Needs Headscale's reauth/force-reregister behavior
  confirmed during implementation — see §9.

## 5. Migration / versioning

Additive on the wire: `CsrIssued` is unchanged, and all new RPCs
(`GetVpnEnrollment`, `ListVpnPeers`, `RevokeVpnPeer`) are new message types,
so existing (non-VPN) enrollment and CA deployments without Headscale
configured are unaffected. No existing message is renumbered or removed.

## 6. Security considerations

- **Two gates in series, genuinely — not just in name.** Obtaining a VPN
  preauth key requires calling `GetVpnEnrollment` at the `GrantedSelfKey`
  tier (§3.2), which `decide_access` only grants when the TLS handshake key
  itself matches a verified, non-revoked `MembershipCert` — i.e. proof of
  possession of the issued identity's private key, not the self-asserted
  claim `SubmitCsr` accepts. A party that only has the shared
  `enrollment_token` (§3.2's own risk analysis) can get *a* cert issued for
  a self-chosen identity, but cannot separately prove possession of that
  identity's private key to reach `GetVpnEnrollment` unless they generated
  and are holding that exact keypair — which is the same guarantee
  `SubmitCsr`'s self-asserted MAC/pubkey already rests on for cert issuance
  itself, not a new weaker link. A stolen preauth key, once obtained, still
  doesn't grant mesh routing trust (§4). Compromising either system alone
  doesn't grant full access.
- **The Headscale API key held by `wayfinder-server` is a high-value secret**
  — it can mint keys that grant network reachability to the tunnel. It needs
  the same protection tier as the CA's root key and `enrollment_token`
  (`authority.rs:79-116`), not a casual config value.
- **`--login-server`/DERP map must be pinned to the self-hosted Headscale
  instance** on every client, not left to Tailscale's public defaults, or the
  "isolated network" property this whole design is motivated by silently
  leaks to third-party infrastructure.
- **OGM/dataplane signing stays on regardless of transport — it must not
  become conditional on a link being VPN-backed.** It's tempting to reason
  that a VPN link's transport integrity makes wayfinder's own signing
  redundant there; it doesn't, for two independent reasons. First, BATMAN-adv
  is multi-hop: a signed OGM is forwarded and re-verified by nodes many hops
  past the originator, over links (LoRa, BLE, 802.15.4) the originating VPN
  tunnel never covers — VPN integrity secures exactly the one hop it
  terminates, not the path a frame travels afterward. Second, it would break
  the "two gates in series" property above: VPN reachability proves a peer
  holds a valid tunnel credential, not that its `MembershipCert` is currently
  valid. A stolen preauth key (§4) or a mesh member whose cert was revoked
  but whose Headscale registration lags behind (the "half-completed revoke"
  case, §4) would get fully trusted, unauthenticated mesh access on that
  link — and revocation would stop being enforced there at all, silently
  defeating `docs/design/03-revocation-durability.md` for exactly the links
  this design adds. See §8 — this was considered and rejected, not omitted.

## 7. Observability

This is provider/CA-side state, not `CentralRouter` state, so the root
`CLAUDE.md`'s "state lives in `CentralRouter`" rule for metrics doesn't apply
here — `ListVpnPeers`' online/last-seen/expiry fields (§3.3) already give the
dashboard what it needs without inventing a router metric for something the
router never sees. Worth surfacing on the same Security-tab area: count of
enrolled VPN peers, and Headscale API reachability (so an operator immediately
sees the §4 "wayfinder-server down" case rather than a mysteriously empty peer
list).

## 8. Alternatives considered

- **Static WireGuard, Nix-configured.** Rejected in the discussion that led
  here — no dynamic enrollment, no NAT traversal beyond a manually maintained
  hub-and-spoke.
- **A wayfinder-native coordination protocol** (custom allocator + streaming/
  poll peer-list distribution). Rejected — reimplements the exact hardest,
  most security-sensitive part of what Headscale already does, and this
  codebase has no existing allocator pattern to build on (see §1).
- **Headplane as the only management surface.** Rejected per explicit
  requirement: operators must not need to leave the wayfinder UI for routine
  registration/revocation. Kept only as an admin fallback.
- **gRPC against Headscale's own API** instead of REST. Deferred — see §9;
  REST avoids pulling Headscale's own protobuf definitions into
  `wayfinder-server`'s dependency graph for something that's a handful of
  calls (`CreatePreAuthKey`, `ListNodes`, `DeleteNode`/`ExpireNode`).
- **Making OGM/dataplane signing configurable per link, skipped for
  VPN-backed links, on the theory that VPN transport integrity already
  covers it.** Rejected — see §6. A VPN link only ever secures the one hop it
  terminates, not the multi-hop path an OGM or forwarded frame travels
  afterward, and VPN peer reachability is not equivalent to current
  `MembershipCert` validity — disabling signing there would defeat live
  revocation checking for that link, not skip a redundant check.

## 9. Open decisions — resolved

> Answered during implementation; the original questions are kept below with
> what each turned out to be.
>
> 1. **REST vs. gRPC.** REST, as recommended. Verified against Headscale
>    0.29.3: `GET/POST /api/v1/user`, `DELETE /api/v1/user/{id}`,
>    `POST /api/v1/preauthkey`, `GET /api/v1/node`. Two contract details the
>    document did not anticipate — `user` is a uint64 id on input (a name is
>    rejected outright), and ids come back as JSON *strings* per the protobuf
>    JSON mapping.
> 2. **Correlation robustness.** Resolved better than hostname, and by
>    necessity: since Headscale scopes every key to a user, each node gets its
>    own user named by its MAC. A user is not the display name an operator
>    renames, so that is the primary join; the hostname is a fallback that
>    keeps hand-registered peers *visible* rather than hidden, which is what an
>    audit of "who can reach this network" needs.
> 3. **The revocation call site.** Not `authority.rs` — the coupling is in the
>    transport, after the router answers `RevokeNode` successfully. See §3.3.
> 4. **Half-completed revoke UX.** Server-side, mesh-first, reported as an
>    error naming both outcomes, with an idempotent retry. See §3.3.
> 5. **Re-enrollment / hostname collision.** Find-or-create on the node's user
>    makes a second enrollment collect the existing user and mint a fresh key,
>    so re-enrolling the same MAC is normal rather than a collision. Losing the
>    create race is treated as success by re-reading.
> 6. **Headplane.** `services.headplane` exists in nixpkgs (0.7.0) and is
>    wired in `nix/modules/wayfinder-headscale.nix`, bound to loopback and off
>    by default — reaching it is an SSH tunnel, which is the friction that
>    keeps it a fallback.
> 7. **Does the cloud box need special-casing as a routing hub?** No, as
>    believed. It takes a tunnel address like any other node and BATMAN-adv
>    selects paths over it normally; nothing in the implementation special-cases
>    it.

## 9.1 The original questions

1. **REST vs. gRPC against Headscale's API.** REST is recommended (§8) to
   avoid a new protobuf dependency, but confirm Headscale's REST API covers
   everything needed (preauth key creation with tags/short TTL, node
   list/delete) at the pinned Headscale version before committing.
2. **Correlation robustness.** Hostname-based join (§3.2/§3.3) is simple but
   breaks if an operator manually renames a device in Headscale. Check whether
   Headscale supports a stable tag/label instead and prefer that if so.
3. **Locate the existing cert-revocation call site** in `authority.rs` (grep
   for where `IssuedCertData.revoked` is set) to extend it with the Headscale
   `RevokeVpnPeer` call, per §3.3.
4. **Half-completed revoke UX** (§4) — design the retry/error state in
   `wayfinder-web` rather than presenting a partial revoke as success.
5. **Re-enrollment/hostname-collision behavior** in Headscale (§4) — confirm
   and handle explicitly (force-reauth vs. reject vs. auto-rename).
6. **Headplane deployment mechanism** — verify current nixpkgs support for a
   `services.headplane`-equivalent module (containerized vs. native) and its
   network-exposure policy (should not be as broadly reachable as
   `wayfinder-web`).
7. **Does the cloud box's own `wayfinder-tap` instance need special-casing**
   as a routing hub, or does it just get a Tailscale address like any other
   node and BATMAN-adv path selection routes through it naturally? Current
   belief is the latter (no special-casing needed) — confirm during
   implementation.

## 10. Key file map

- `libs/wayfinder-protos/protos/wayfinder.proto` — `CsrIssued`
  (`wayfinder.proto:1357-1366`) is **unchanged**; add
  `GetVpnEnrollmentRequest/Response`, `ListVpnPeersRequest/Response`,
  `RevokeVpnPeerRequest/Response` messages and their
  `WayfinderRequest`/`WayfinderResponse` oneof cases (pattern at
  `wayfinder.proto:668` for `submit_csr`).
- `libs/wayfinder-auth/src/cert.rs`, `authority.rs` — **`CERT_FLAG_MEMBER`**
  (0x08), set by `issue_cert` and not by `issue_user_cert`, surfaced as
  `VerifiedCert::member`. Additive: unknown flag bits are masked rather than
  rejected, so an older verifier still accepts a newer certificate.
- `libs/wayfinder-server/src/authz.rs` — the `GrantedMember` tier and the
  request-first gate in `permits`. **Security-critical file**; the change is
  five non-test lines.
- `libs/wayfinder-server/src/vpn.rs` — the `VpnCoordinator` trait and the
  Headscale REST client behind it, plus the MAC↔user/hostname correlation.
- `libs/wayfinder-server/src/transport.rs` — the three VPN handlers and the
  mesh-revoke coupling, *here* rather than in `adapter.rs` (§3.2). The
  connection's verified certificate is what a credential is minted against.
- `libs/wayfinder/src/config.rs` — `HeadscaleConfig`, reachable as
  `provider.headscale`. The config schema lives beside every other config
  type; the client that consumes it lives in `wayfinder-server`.
- `nix/tests/ca-provider.nix` — the whole flow against a real Headscale.
- `bins/wayfinder-ctl/src/vpn.rs` and the `Enroll` arm of `lib.rs` — after
  writing the issued cert/trust_anchor locally, reconnect *presenting that
  identity* and call `GetVpnEnrollment`, then invoke `tailscale up`. A failure
  in that second step is reported in the summary rather than failing the
  command: the enrollment is already durable, and failing would discard it
  over an optional step. `wayfinderctl vpn list|revoke|enrollment` are the
  operator-side and retry entry points.
- `bins/wayfinder-web` — new VPN-peers panel near the existing Security-tab
  area; a clearly-labeled fallback link to Headplane, not primary nav.
- `nix/modules/wayfinder-headscale.nix` — colocates `headscale` (embedded DERP
  only) and, off by default, loopback-bound `headplane`.
  `nix/modules/wayfinder-tailscale.nix` — `tailscaled` on a host node, pinned
  to the mesh's own login server. `nix/modules/wayfinder.nix` itself needs no
  change: `services.wayfinder.config` is freeform, so `provider.headscale`
  passes through to the binary that owns the schema.
