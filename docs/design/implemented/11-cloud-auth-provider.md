# Design: a cloud-hosted Wayfinder certificate authority

**Status:** Implemented and deployed. The node posture, the NixOS machine and
the OpenTofu module all landed together; see the key file map in §10.

**§12 supersedes the "no mesh links" posture** this document was written
around. Design 08 landed on this same box, and the CA now joins the tunnel it
coordinates and carries one `UdpMulti` link over it. Everything else here —
no local egress, no capabilities, the sandbox, the offline-minted root — is
unchanged. Where a section below still says "no links", §12 says what replaced
it; the sections are left as written rather than edited in place, because the
reasoning that held with no link is what makes it clear what the link changed.

**Scope:** `libs/wayfinder-driver` (a `NullEgress` carrier), `libs/wayfinder`
(`Config::resolved_mac_state_path` and a top-level `mac_state_path`),
`bins/wayfinder-tap` (a local egress becomes optional), `nix/modules/wayfinder.nix`
(capabilities derived rather than assumed), `nix/machines/wayfinder-ca/`,
`nix/tests/ca-provider.nix` and `infra/oracle/`. **No change** to the `no_std`
core (`libs/interfaces`, `libs/batman`, `CentralRouter`), to the `LinkT`/`FrameIo`
trait surface, to `libs/wayfinder-auth`'s `MembershipCert`/OGM-auth semantics, to
the management-API wire format, or to any client — `wayfinder-ctl --connect
<host>:7700` reaches this node exactly as it reaches any other.

## 1. Motivation

Wayfinder deploys to a Jetson Orin Nano, to bare-metal boards, and to Docker.
None of those has a stable public address, and
`docs/design/implemented/08-internet-links-headscale-vpn.md` names the consequence
directly: two Starlink-connected nodes behind CGNAT cannot reach each other,
and *"a cloud-deployed wayfinder auth provider (the CA) is the one box in this
topology with a stable public address"*.

Design 08's VPN half is not built. But the CA half does not depend on it, and
it is the half that unblocks everything else: until some box holds the mesh root
of trust at an address every node can reach, `require_auth` meshes have to be
provisioned by hand-carrying certificates. A node in **provider mode** with no
mesh links at all is a complete, useful deployment: it serves `SubmitCsr`,
`ApproveCsr`, `GetTrustAnchor` and `RevokeNode`, and nothing else.

## 2. Goals / Non-goals

**Goals**

- One `wayfinder-tap` node, in provider mode, on a cloud instance with a stable
  public address, reachable by the existing clients with no client change.
- The mesh root key is generated *offline*, by the operator, and never appears
  in this repository, the Nix store, or Terraform state.
- The CA's own posture is minimal by construction: no mesh links, no local
  egress, no network capabilities, and a systemd sandbox. (§12 revisits the
  first of those. The other three are unchanged, and the capability set is
  still empty *with* a link — which is the assertion `ca-provider.nix` grew.)
- Reproducible: the instance from `tofu apply`, the system from
  `nixosConfigurations.wayfinder-ca`, and both verifiable without a cloud
  account (`nix build .#wayfinder-ca-provider`).

**Non-goals**

- **No mesh links on this node.** There is no encrypted internet link to carry
  one; that is design 08. Everything here is arranged so adding one later is a
  config change plus a firewall rule, not a redesign. (§12: that turned out to
  be true — a config block and one ingress rule, no redesign.)
- Not managing the four secret files declaratively. `sops-nix`/`agenix` is the
  natural follow-up; v1 copies them once, by hand, per `infra/oracle/README.md`.
- Not deploying from CI. That needs cloud credentials in GitLab CI and is a
  separate decision.

## 3. Why not Cloudflare, and why not GCP

This began as "deploy to Cloudflare, we have an account". Recording the two
findings that ruled each out, so neither is re-litigated:

**Cloudflare cannot host this node, now or later.** Cloudflare Containers can
run the binary, but the platform has *no general TCP ingress* — inbound TCP to
a Worker is a Spectrum-backed private beta — and *no UDP ingress at all* outside
Enterprise Spectrum. Three consequences, in increasing order of severity:

1. The management API's TLS-over-TCP stream would have to be tunnelled inside a
   WebSocket, requiring a new transport in `wayfinder-client` and a Worker to
   proxy it into the container's port.
2. Container disk is ephemeral and containers sleep (`sleepAfter`, 10 min
   default), so the mesh root seed, the mgmt-TLS identity clients *pin*, and the
   issued-certificate log would each need external storage plumbing. A CA whose
   pinned key changes when it idles is not a root of trust.
3. The box could never carry a `LinkTransport::Udp` mesh link, and could never
   host design 08's Headscale — whose embedded DERP relay needs STUN on
   UDP/3478. Without STUN, two CGNAT'd peers never negotiate a direct path and
   *all* mesh traffic falls back to DERP relay, i.e. through a Worker into a
   sleeping container.

(1) and (2) are cost. (3) is the disqualifier: it makes the box permanently
control-plane-only, which contradicts design 08's whole premise that this is
the one box with a stable public address.

**GCP's free tier is not free for this shape.** Always Free covers one
`e2-micro` in three US regions, 30 GB of standard PD and 1 GB/month of egress —
but *not* the external IPv4 address, which GCP has billed since Feb 2024 at
~$0.005/hr (≈$3.65/mo). A publicly reachable CA needs that address. External
IPv6 is free, but an IPv6-only CA is unreachable from an IPv4-only operator.

**Oracle Always Free** covers 2 Ampere A1 OCPUs and 12 GB across all A1
instances, *two* AMD `VM.Standard.E2.1.Micro` (1/8 OCPU, 1 GB) instances, 200 GB
of block storage, 10 TB/month of egress, *and* the public IPv4 address, with
full TCP and UDP.

A1 is aarch64, which this repo already targets (the Orin Nano) and this
project's dev host already is, so an A1 system builds natively. **In practice A1
is frequently unobtainable**: the first real deployment of this design hit "Out
of host capacity" on every attempt, and the tenancy had exactly one region and
one availability domain — Always Free resources exist only in the home region,
so there is no other pool to try and no queue to join.

That is why `instance_shape` is a variable rather than a constant, and why the
default is `VM.Standard.E2.1.Micro`. E2 is x86_64, so the system is built under
binfmt emulation on an aarch64 workstation rather than natively — slower, but
the same derivation. **1 GB is ~150× this node's measured working set** (§8), so
for a certificate authority the smaller shape costs nothing that matters. Switch
back to A1 by changing the variable and `nixpkgs.hostPlatform.system` together;
they must agree, or the install completes and the instance cannot boot.

The remaining Always Free caveat is documented in the runbook rather than
designed around: Oracle reclaims *idle* Always Free compute.

## 4. Design

### 4.1 A node that bridges nothing

`bins/wayfinder-tap` required `local_egress` and refused to start without it.
That is wrong for a CA on two counts: it has no host traffic to bridge, and a
cloud instance would not grant the `CAP_NET_ADMIN` and `/dev/net/tun` a TAP
needs anyway.

`local_egress` becomes optional. When absent the driver's local device is
`NullEgress` (`libs/wayfinder-driver/src/transport.rs`): `send` accepts and
discards, `recv` **parks forever**. Parking rather than returning `Ok(0)` is the
load-bearing detail — a zero-length read is how a real device reports
end-of-file, and the driver's local-device `select!` arm would treat it as a
readable device with an empty frame and spin. Parking leaves that arm
permanently unready, which is what "there is no local device" actually means.

Nothing else about the node changes: it holds an identity, derives its MAC,
serves the management API and runs provider mode exactly as any other node
does.

### 4.2 A MAC without a device

A node's MAC *is* its mesh identity, and it must survive a restart or the
fleet's pinned view of this node breaks. Both egress kinds already persisted it
at a path named after their device. With no device there was no path, so
`Config` gains a top-level `mac_state_path` and
`Config::resolved_mac_state_path` resolves all three cases in one place:

| configured | path |
|---|---|
| `Tap` egress | that egress's `mac_state_path`, else `/var/lib/wayfinder/<device>.mac` |
| `RawL2Egress` | that egress's `mac_state_path`, else `/var/lib/wayfinder/<interface>.mac` |
| neither | top-level `mac_state_path`, else `/var/lib/wayfinder/node.mac` |

An egress outranks the top-level field deliberately: adding the field must not
silently move an existing node's already-written MAC. In practice the CA never
reaches this path at all — it has an `auth:` block, so its MAC is derived from
its keypair — but a node with neither is a legitimate configuration (an
un-enrolled CA before its secrets are installed) and must not have to invent a
device to name a file after.

### 4.3 Capabilities derived, not assumed

`nix/modules/wayfinder.nix` granted `CAP_NET_RAW` + `CAP_NET_ADMIN` and widened
`/dev/net/tun` unconditionally, because every node so far has been a routing
node. A CA needs neither: its only socket is a TCP listener an ordinary user can
bind.

`services.wayfinder.rawNetworkAccess` now derives from the configured carriers
— true exactly when a `Tap`/`RawL2Egress` egress or a `RawL2`/`RawIp` link is
present — and is overridable. When false the unit gets an **empty** capability
set, no udev rule, and the sandbox that only becomes possible once the
capabilities are gone: `ProtectSystem = "strict"` with `ReadWritePaths` limited
to `/var/lib/wayfinder`, `PrivateDevices`, `NoNewPrivileges`,
`MemoryDenyWriteExecute`, and a `@system-service` syscall filter.

This matters more here than anywhere else in the fleet: it is the one node on
the open internet, and it is the one holding a key that can mint mesh
membership.

### 4.4 Trust material

Four files, minted offline with tooling that already exists
(`wayfinder-ctl cert init-ca` / `keygen` / `issue`) and copied to
`/var/lib/wayfinder` (mode 0400, owner `wayfinder`):

| file | what it is |
|---|---|
| `root.seed` | the mesh root of trust — **this file is the mesh** |
| `identity.seed` | this node's own Ed25519 identity; its public half is what clients pin |
| `node.cert` | this node's admin membership in the mesh it signs for |
| `trust-anchor` | the public anchor every member verifies against |

The node must not be able to rewrite its own root of trust. The first
implementation bought that with a separate `/var/lib/wayfinder-secrets`, outside
the unit's `ReadWritePaths` — correct, and it cost something every day: this is
the box an operator types the most commands on, and `wayfinder-ctl` defaults
`--identity` to `/var/lib/wayfinder/identity.seed`, so a CA whose identity lived
elsewhere made every local invocation spell out paths it would otherwise have
found. The files now sit in the node's own state directory and the property is
held by `ReadOnlyPaths` instead: each of the four is re-mounted read-only inside
the unit's namespace, which is the same guarantee by a more specific mechanism.

Two consequences worth stating, because both fail quietly:

- **`ReadOnlyPaths` entries are `-`-prefixed.** These files are legitimately
  absent on a box that has been installed but not yet provisioned, and a unit
  that refused to start then would hide the real error (a missing seed) behind
  a namespace failure. The cost is that a file placed while the node is running
  is protected only from its next restart — which `scripts/wayfinder-ca.sh
  secrets` performs anyway.
- **Never `chmod 0400 /var/lib/wayfinder/*`.** That directory also holds
  `ca-state.json`, `settings.json` and `node.mac`, which the node writes; a glob
  takes them with it and leaves an authority that cannot record what it issues.
  The script and both VM tests name the four files one by one for this reason.

This does not conflict with the root `CLAUDE.md`'s "nodes are reached over RPC,
never through their filesystem". That rule forbids host tooling provisioning
*another* node by writing files it expects that node to read. This is the node's
own host configuration, the same category as the `auth = { seed_path = ...; }`
block the Nix module already documents. Every interaction with any *other* node
still goes over the management API — which is exactly what `csr install` does.

### 4.5 Two halves, kept apart

`tofu apply` creates the instance, network, firewall and a **reserved** public
IP. `nixos-anywhere` installs the system over the stock image. Neither can
disturb the other: a node rebuild never risks the instance, and `tofu apply`
never rebuilds the node. `oci_core_instance` carries `ignore_changes` on the
source image and metadata, since both describe an OS that no longer exists once
NixOS is installed over it — without that, a provider-side image refresh would
propose destroying a running CA and its state.

The IP is reserved rather than ephemeral for the same reason the MAC is
persisted: every node is configured with this address and pins the CA's key
against it, and an ephemeral address is released on stop/start.

## 5. Correctness and edge cases

- **`NullEgress::recv` must never resolve.** Covered by a unit test asserting
  `now_or_never()` is `None`; a `recv` that returned `Ok(0)` would spin the
  driver at 100% CPU.
- **A CA restart must not forget what it issued.** `provider.state_path` is set,
  and `nix/tests/ca-provider.nix` restarts the service and asserts the enrolled
  node still appears in `list-certs`. Without it the impersonation guard starts
  empty and every revocation is lost.
- **The cert must bind the node's MAC.** `wayfinder-tap` already refuses to
  start otherwise; the runbook's `cert issue` defaults the MAC to the one the
  node's seed derives, so the two agree by construction.
- **`mesh_id` must match the trust anchor.** `wayfinder-tap` bails on a
  mismatch rather than signing for the wrong mesh.
- **An egress must outrank the new top-level `mac_state_path`,** or adding the
  field would move an existing node's MAC. Unit-tested.
- **The capability set must be asserted at runtime, not in the Nix source.**
  Writing `CapabilityBoundingSet = [ ]` looks like it clears the bounding set
  and does not: NixOS renders a list as one `Name=element` line per element, so
  an empty list emits *no line at all* and the unit silently keeps systemd's
  default — every capability. `CapabilityBoundingSet = ""` emits
  `CapabilityBoundingSet=`, which systemd documents as "reset to the empty
  capability set". The first form was written, reviewed, and looked right;
  `nix/tests/ca-provider.nix` caught it by reading `CapBnd` out of
  `/proc/<pid>/status` and finding `0x1fff7fcffff`. This is the whole argument
  for asserting on observed process state rather than on configuration: a
  hardening option that silently does nothing fails no test that only checks
  the option's value.

### 5.1 Two bugs the first real deployment found

Both were in the OpenTofu, both would have been invisible until an apply, and
both are the kind that a validate pass cannot catch:

- **`assign_public_ip = true` and a reserved `oci_core_public_ip` are mutually
  exclusive.** The first attaches an *ephemeral* address at launch, and a
  private IP may hold only one public IP, so the reserved one then fails with a
  409-Conflict. Ephemeral is also the wrong lifetime here — it is released when
  the instance stops, which would hand the fleet a CA it can no longer find
  after a routine stop/start, which is the entire reason a reserved address is
  in this design. Fixed by setting it false and letting `oci_core_public_ip`
  own the address.
- **A `shape_config` block is only valid for a `.Flex` shape.** E2.1.Micro's
  resources are fixed and OCI rejects one supplied for it, so the block is now
  emitted by a `dynamic` guarded on the shape name.

## 6. Security considerations

The management API is exposed to the internet on 7700. That is the point of the
box, and it is defensible because the port is not unguarded:

- Every connection authenticates by mesh identity as an RFC 7250 raw public key
  in the TLS handshake, and clients pin the node's key.
- A peer with no certificate is admitted to the **enrollment tier only** —
  `SubmitCsr` and nothing else.
- That tier is rate-limited per source (`SUBMIT_CSR_BURST = 5`, refilling one
  per five seconds — 12/min), new connections are rate-limited per source
  (`CONNECT_BURST = 20`, two per second), and uncredentialed connections are
  capped at 64 concurrently.

This was observed working rather than assumed: an unpaced 300-request
enrollment loop against a real node was throttled after 7 issues and then had
its handshakes refused outright.

Two deliberate postures on top: `auto_approve = false`, so a CSR parks for an
operator rather than being signed on arrival — what an unattended provider hands
out is mesh membership itself; and `cert_ttl_secs` of one week, because passive
expiry is this design's primary revocation mechanism and *this node has no mesh
links to flood an active revocation over*.

The dashboard performs no authentication of its own, so on this node — where
the identity is an admin of the mesh root — it stays bound to loopback and is
reached over an SSH forward.

## 7. Observability

Nothing new is exposed. The CA answers the same `GetNodeInfo`,
`GetSecurityStatus`, `GetMetrics` and `GetLogs` every node does, and
`list-certs` / `csr list` already surface the authority's own state. A metric
worth adding later, in the spirit of the root `CLAUDE.md`'s "prefer bounded
here-and-now signals": a `TableOccupancy`-style gauge over the held-CSR table,
so an operator can see enrollment pressure without polling `csr list`.

## 8. Measurements

Taken against a release build in the original posture (no egress, no links,
provider mode, offline-minted root), driving live enrollments over the
management API. The single `UdpMulti` link added in §12 does not move these
numbers meaningfully — one more UDP socket and one originator table on a node
whose whole working set is 3 MB — but they were measured before it and are left
labelled as what they are rather than restated as current:

| | measured |
|---|---|
| RSS at startup | 6.8 MB |
| RSS at idle, after reclaim | 3.1 MB |
| RSS while actively issuing | 6.3 MB |
| CA snapshot, 7 issued certs | 4,665 bytes |
| CA snapshot, 68 issued certs | 43,969 bytes |
| marginal cost per issued cert | 644 bytes on disk; no measurable RSS |
| issued certificate on the wire | 156 bytes |

RSS does not scale with the issued-certificate log in any measurable way. Disk
does, linearly and cheaply: a 1,000-node mesh is a ~644 KB snapshot. Against
Always Free's 12 GB of RAM and 200 GB of storage that is ~2,000× headroom, so
the instance shape was chosen for the *other* reasons — UDP, a stable address,
and room for design 08 — rather than for capacity. The default takes half the
free allowance (1 OCPU / 6 GB) so a second Always Free box remains available for
Headscale.

## 9. Alternatives considered

- **Cloudflare Workers + Containers, with the mgmt stream tunnelled over a
  WebSocket.** Rejected: see §3. It was designed in full (a `Client::connect_wss`
  transport, a Worker piping a `WebSocketPair` into `getTcpPort(7700)`, and R2
  state sync through the Worker) before the UDP finding made the box a dead end.
- **GCP `e2-micro` Always Free.** Rejected on the external-IPv4 charge (§3).
- **Fly.io / Hetzner.** Both work and both are paid. Hetzner remains the obvious
  fallback if Oracle's capacity or idle-reclamation becomes annoying — the
  machine definition is provider-agnostic apart from `disk.nix`'s device name.
- **Running the existing `containers/Dockerfile` `tap` image on a cloud VM
  instead of NixOS.** Rejected: `nix/modules/wayfinder.nix` already models this
  service properly, and the capability derivation in §4.3 belongs there rather
  than in a `docker run` invocation nobody reviews.
- **`sops-nix` for the four secrets.** Deferred, not rejected — it is the right
  answer and is a follow-up rather than a v1 blocker.

## 10. Key file map

| file | what changed |
|---|---|
| `libs/wayfinder-driver/src/transport.rs` | `NullEgress` + tests |
| `libs/wayfinder-driver/src/lib.rs` | re-export |
| `libs/wayfinder/src/config.rs` | `Config::mac_state_path`, `Config::resolved_mac_state_path` + tests |
| `bins/wayfinder-tap/src/main.rs` | `local_egress` optional; `NullEgress` when absent |
| `nix/modules/wayfinder.nix` | `rawNetworkAccess`, derived capabilities, systemd sandbox |
| `nix/machines/wayfinder-ca/{common,system,disk}.nix` | the machine |
| `flake.nix` | `mkCloudSystem`, `nixosConfigurations.wayfinder-ca`, `opentofu`/`nixos-anywhere` in the dev shell |
| `nix/tests/ca-provider.nix` | the VM test |
| `infra/oracle/` | OpenTofu module + runbook |
| `justfile` | `build-ca`, `test-ca`, `ca-*` passthroughs |
| `scripts/wayfinder-ca.sh` | the deployment lifecycle: provision, install, secrets, update, verify, user-add |
| `infra/oracle/tunnel.tf` | the Cloudflare Tunnel and DNS for the dashboard |

## 11. Follow-ups

- ~~**Design 08 lands here.**~~ Done, in two steps. Headscale moved onto this
  same box rather than the second Always Free one (`mkCloudSystem` builds one
  system; a second box would have been a second deployment to keep alive for a
  service that idles). The CA then stopped being link-less: see §12.
- **`sops-nix`** for the four secret files.
- **A held-CSR occupancy metric** (§7).
- **CI deploys**, once there is somewhere safe to keep OCI credentials.
- **Hold a GC root on a long emulated build.** The x86_64 system takes ~90
  minutes to build under qemu on an aarch64 workstation, and a build run with
  `--no-link` leaves no garbage-collection root behind. During this work a
  completed system closure was collected by an unrelated
  `nix-collect-garbage` — run to free disk space for a different reason — and
  had to be rebuilt from scratch. Pass `--out-link`, or register a root with
  `nix-store --add-root`, for anything that expensive.

  (An earlier revision of this document blamed `nix/default.nix`'s source
  filter for that rebuild. That was wrong and is corrected here:
  `nix/default.nix` already narrows the source with `cleanSourceWith` to
  Cargo sources, protos and web assets, so editing `docs/`, `infra/`,
  `scripts/` or a `.nix` file does *not* invalidate the Rust build.)

- **Emulated builds are flaky as well as slow.** A rebuild during this work died
  with `qemu: uncaught target signal 11` inside `rustc -vV`, in a derivation
  that had built cleanly an hour earlier; a retry succeeded. If the deployment
  settles on the x86_64 shape long-term, an x86_64 remote builder — or a
  CI-built closure — is worth more than the emulation is.

## 12. The CA joins the mesh it signs for

§2 promised a node with **no mesh links**, and §9's non-goals said so plainly:
*"There is no encrypted internet link to carry one; that is design 08.
Everything here is arranged so adding one later is a config change plus a
firewall rule, not a redesign."*

Design 08 landed, and that turned out to be exactly right — the change is a
config block and an ingress rule. Recording what it is, and the three things
that were *not* obvious.

### 12.1 What was added

| where | what |
|---|---|
| `nix/machines/wayfinder-ca/common.nix` | one `UdpMulti` link (`vpn0`), `services.wayfinder-tailscale`, `selfJoin.enable` |
| `nix/modules/wayfinder-headscale.nix` | `selfJoin` — the box joining the tunnel it coordinates, over the same enrollment RPC every node uses |
| `infra/oracle/main.tf` | the UDP/41641 ingress rule, uncommented |
| `nix/tests/ca-provider.nix` | the link, and the capability assertion made about a node that has one |
| `nix/tests/vpn-data-plane.nix` | its hub now uses `selfJoin` rather than joining by hand |

The link is `UdpMulti` in **hub/fan-out mode** — no `discovery_addr`. A
Tailscale tunnel is a set of point-to-point WireGuard links, not a shared
segment, so there is no broadcast address to put one datagram into; a
broadcast-destined frame is fanned out to every peer learned from a received
datagram instead. Every spoke is learned from the OGMs it sends here, which is
why this is the one link configuration in the fleet that needs no
runtime-discovered address and can be rendered at build time. A spoke's link is
the mirror image, and its `discovery_addr` is this node's tunnel address.

### 12.2 How the CA enrols itself

Through `GetVpnEnrollment`, the same request every other node's join goes
through. `wayfinder-headscale-selfjoin.service` runs `wayfinderctl vpn
enrollment` against the node's own management API over loopback, presenting the
node's own identity seed, and spends the credential it gets back.

> **This section used to say the CA *could not* do that.** The claim was that
> `GetVpnEnrollment` is scoped to a **device** identity while a node connecting
> to itself earns `GrantedSelfKey`, a full management grant and not a device —
> so the unit reimplemented the mint in shell against the local `headscale`
> CLI, on the argument that a box running the coordination server does not need
> the RPC hop anyway.
>
> Half of that was wrong. The node's own seed *is* a device identity — the
> node's — and whoever holds it already signs that node's OGMs and terminates
> its TLS. What actually blocked the request was narrower and mechanical: the
> transport read the MAC off the certificate presented on the connection, which
> is sound only on the member tier, where `decide_access` verified it against
> the anchor and bound it to the handshake key. The self-key tier short-circuits
> before any of that, so a MAC read there would have been a value the client
> chose — and here that means registering a device under *another* node's
> Headscale user.
>
> The fix was to stop taking it from the connection: the router publishes its
> own mesh address through `AuthSnapshot::own_mac`, and the self-key tier mints
> for that. It cannot name anyone else even when it attaches a certificate that
> does. The admin tier stays refused — an operator's session certificate is a
> person, not a device — so `GetVpnEnrollment` is still the one request a *full*
> grant can be denied, just not both of them. See design 08's Correction 1.
>
> What this bought was not the RPC hop, which the box genuinely does not need.
> It was deleting sixty lines of shell that held a convention `vpn.rs` also
> holds, with nothing asserting the two agreed.

A unit rather than a runbook step, for the same reason
`wayfinder-headscale-apikey.service` is one: a preauth key can only be issued
by a running Headscale, so it cannot be provisioned alongside the offline-minted
mesh trust material, and a manual step is one that gets skipped when the box is
rebuilt.

**It registers under the MAC-named user**, not under a label of its own. That
name is the peer↔mesh-identity correlation — `hostname_for` in
`libs/wayfinder-server/src/vpn.rs`, and the design deliberately persists it
nowhere else — so a self-join under a convenient name would leave this box the
one peer `wayfinderctl vpn list` could not name, and would do it silently: the
tunnel works either way. Going through the RPC is what makes that hold by
construction rather than by two implementations agreeing:
`Coordinator::enroll` names the user, for this node exactly as for every other.
`nix/tests/vpn-data-plane.nix` asserts the user exists under that name.

One consequence to note: `Coordinator::enroll` applies an ACL tag to every key
it mints, so this box is now a *tagged* device and Headscale reports its owner
as the synthetic `tagged-devices` user. `vpn list` correlates it anyway —
through the per-MAC user the *key* was scoped to, which is checked first
precisely because of tagging — and the shape a tagged device leaves behind on
revocation does not arise here, since this is the box doing the revoking.

### 12.3 What the link does and does not change

- **A revocation now has somewhere to go.** §6 called passive expiry "this
  design's primary revocation mechanism" *because this node has no mesh links
  to flood an active revocation over*. It has one now. But `cert_ttl_secs` stays
  at a week: a flood reaches the nodes that are up and on the tunnel, and a
  spoke that is offline when it goes out never hears it. Expiry remains the only
  bound that holds for every member; what the link changes is the common case,
  not the worst one.
- **Two spokes converge through this node.** The hub has exactly one link for
  both of them, so relaying between them depends on a flood going back out of
  the interface it arrived on — which is why the split-horizon removal
  (`driver_core::Egress::Auto`) is load-bearing here and not an optimization
  detail. `nix/tests/vpn-data-plane.nix` is the regression test for precisely
  that gap.
- **The capability set stays empty.** `UdpMulti` is not in
  `nix/modules/wayfinder.nix`'s `rawNetKinds`, so a link on this node must not
  pull `CAP_NET_RAW` back in. That is the one regression here that would be
  completely invisible — the node works exactly as well either way, on an
  internet-facing box holding the mesh root key — so `ca-provider.nix` now
  carries the link specifically to keep asserting on `/proc/<pid>/status` with
  one configured.
- **Nothing new is exposed publicly.** The rule added to the security list is
  UDP/41641, `tailscaled`'s own port, so a spoke can hole-punch a direct path
  instead of relaying through the DERP server on this same box — which would
  make every frame between two spokes cross it twice. The **mesh link's** port
  is deliberately not opened: it binds `0.0.0.0`, but only `tailscale0` is a
  trusted interface in the host firewall, so it is reachable inside the tunnel
  and nowhere else. The public address still hears TCP/22, TCP/7700, TCP/443,
  UDP/3478 and UDP/41641, and nothing else.
