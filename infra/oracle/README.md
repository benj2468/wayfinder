# Deploying the Wayfinder certificate authority to Oracle Always Free

This provisions the one box in a Wayfinder deployment that has a stable public
address: a `wayfinder-tap` node in **provider (certificate authority) mode**,
holding the mesh root of trust and serving enrollment over the management API.
It carries **no local egress** — see
[`docs/design/implemented/11-cloud-auth-provider.md`](../../docs/design/implemented/11-cloud-auth-provider.md)
for why, and for why Cloudflare and GCP were evaluated and set aside.

It does carry one mesh link, over the Tailscale tunnel it coordinates: see
[The VPN control plane](#the-vpn-control-plane) below. That makes it a routing
participant as well as an authority, so a revocation has somewhere to be
flooded and two spokes with no direct path can converge through it.

Two halves, deliberately kept apart:

| | what it does | when you run it |
|---|---|---|
| `tofu apply` (this directory) | creates a bare Ubuntu instance, a public subnet, a reserved public IP and a firewall | once, and when the *infrastructure* changes |
| `nixos-anywhere` (repo root) | installs `nixosConfigurations.wayfinder-ca` over that image | at install, and on every node change |

So a node rebuild never risks the instance, and `tofu apply` never rebuilds
the node.

**`scripts/wayfinder-ca.sh` drives both halves** and is what you should reach
for after the first time through. It reads the instance address out of
OpenTofu state, so nothing is hardcoded and nothing has to be passed around:

```
./scripts/wayfinder-ca.sh provision   # tofu apply
./scripts/wayfinder-ca.sh install     # nixos-anywhere   (DESTRUCTIVE, once)
./scripts/wayfinder-ca.sh secrets     # copy the trust material onto the node
./scripts/wayfinder-ca.sh verify      # prove it answers
./scripts/wayfinder-ca.sh update      # every change after that
```

`just ca-provision` / `ca-install` / `ca-secrets` / `ca-update` / `ca-verify` /
`ca-dashboard` are passthroughs to the same script. The steps below explain
what each one does and why; the script is the repeatable form.

The one thing the script will not do is **step 1**: it never generates a mesh
root seed. That is a one-time offline act whose output *is* the mesh, and a
script that silently re-minted it on a re-run would be a foot-gun.

## What it costs

Nothing, if you stay inside the defaults. Oracle Always Free covers 2 Ampere A1
OCPUs and 12 GB across all A1 instances, 200 GB of block storage, 10 TB/month
of egress, and the public IPv4 address. The defaults here take **half** of the
compute allowance (1 OCPU / 6 GB) so a second Always Free box is still
available — which is where design 08's Headscale coordination server goes.

Two Always Free caveats that are real and not misconfiguration:

- **A1 (Ampere/aarch64) capacity is often unobtainable**, and there is no queue
  to join — a launch just fails with `500-InternalError, Out of host capacity`.
  Retrying sometimes works and sometimes does not. Note that Always Free
  resources exist **only in your home region**, so if that region is dry there
  is no other region to try: subscribing to a second region does not help.

  This is why `instance_shape` defaults to `VM.Standard.E2.1.Micro` (AMD
  x86_64, 1/8 OCPU, 1 GB) rather than A1. 1 GB is ~150x this node's measured
  working set, so for a CA the smaller shape costs nothing that matters. If you
  want A1, set `instance_shape = "VM.Standard.A1.Flex"` **and**
  `nixpkgs.hostPlatform.system = "aarch64-linux"` in
  `nix/machines/wayfinder-ca/common.nix` — they must agree, or the install
  completes and the instance cannot boot.

- **Oracle reclaims idle Always Free compute.** A CA that answers real
  enrollment and revocation requests is not idle, but a mesh that goes quiet
  for months might be. Check on it.

## 0. Prerequisites

From the repo's dev shell (`nix develop`), which ships `opentofu` and
`nixos-anywhere`. `wayfinder-ctl` is *not* in the dev shell — the commands
below reach it as `nix run .#wayfinder-ctl --`, which builds it from this
checkout. Substitute a `cargo run -p wayfinder-ctl --` or an installed binary
if you prefer.

You will also need:

- An OCI account with `~/.oci/config` set up (`oci setup config`), or the
  `OCI_*` environment variables.
- Your compartment OCID — the tenancy root compartment is a fine answer.
- An SSH keypair whose public half goes in `terraform.tfvars`.
- A Cloudflare API token, if `manage_tunnel` or `manage_dns` is set — scoped
  `Zone:DNS:Edit` on the zone and `Account:Cloudflare Tunnel:Edit`, plus
  `Zone:Zone:Read` and `Zone:Cache Purge:Purge` so that
  `scripts/wayfinder-ca.sh update` can drop the previous dashboard bundle from
  the edge cache (without those two the rollout still succeeds and warns, and
  viewers keep the old stylesheet for up to four hours). Put it in
  `~/.cf-token` (mode `0600`, the token and nothing else) and
  `scripts/wayfinder-ca.sh` reads it; override the path with
  `CA_CF_TOKEN_FILE`. A bare `tofu` does not read that file — it only ever
  looks at `$CLOUDFLARE_API_TOKEN`, and without it an apply fails with
  Cloudflare's unhelpful `400 Missing X-Auth-Key, X-Auth-Email or
  Authorization headers`.

## 1. Mint the mesh identity, offline

**Do this before deploying, on a machine you trust, and keep the output off
this repo and out of the Nix store.** The mesh root seed *is* the mesh: whoever
holds it can issue membership certificates that every node accepts.

```bash
mkdir -p ca-secrets && cd ca-secrets
MESH_ID=0x5741594e          # any 32-bit id; it identifies this mesh

# The mesh root of trust, and the public anchor every member verifies against.
nix run .#wayfinder-ctl -- cert init-ca --mesh-id $MESH_ID \
    --generate --out-seed root.seed --out-anchor trust-anchor

# This node's own identity, and its membership in the mesh it signs for.
nix run .#wayfinder-ctl -- cert keygen --out-seed identity.seed

NOW=$(date +%s)
nix run .#wayfinder-ctl -- cert issue \
    --ca-seed root.seed --mesh-id $MESH_ID \
    --node-seed identity.seed \
    --not-before "$NOW" --not-after "$((NOW + 31536000))" \
    --admin --out-cert node.cert
```

`cert issue` prints the node's **Ed25519 public key** and **MAC**. Keep the
public key: it is what every client pins with `--node-key`, and pinning is what
stops a man-in-the-middle impersonating your CA.

The CA's own certificate is issued for a year while the certificates it hands
out live a week (`certTtlSecs`). That asymmetry is intended — the CA's identity
is what the fleet pins and should be stable, while member certificates expire
often *because* passive expiry is the only revocation mechanism that reaches
*every* member. The CA's mesh link means a node that is up and on the tunnel
learns of a revocation in seconds; a node that is offline when it goes out
still only finds out by ageing out, which is what the week bounds.

## 2. Provision the instance

```bash
cd infra/oracle
cp terraform.tfvars.example terraform.tfvars   # then edit it
tofu init
CLOUDFLARE_API_TOKEN="$(cat ~/.cf-token)" tofu apply   # the token only if managing Cloudflare
```

Or `./scripts/wayfinder-ca.sh provision`, which is the same apply with the
Cloudflare token loaded from `~/.cf-token` for you.

Note the `public_ip` output.

## 3. Point the machine at your mesh, and at your SSH key

In `nix/machines/wayfinder-ca/common.nix`:

```nix
wayfinder.ca.meshId = 1463900494;   # must equal the --mesh-id above, in decimal

users.users.root.openssh.authorizedKeys.keys = [
  "ssh-ed25519 AAAA... you@example.org"
];
```

`meshId` must match what the trust anchor was created with; a mismatch is
refused at startup rather than silently signing for the wrong mesh.

The authorized key is **not** the same setting as `ssh_public_key` in
`terraform.tfvars`, and the difference bites exactly once: that one authorises
the *stock image's* user so `nixos-anywhere` can connect and install, and
`nixos-anywhere` does not carry it into the system it installs. Leave it empty
and step 4 completes and locks you out — the build warns, but the warning
scrolls past. In practice put the same key in both.

## 4. Install NixOS over the stock image

```bash
cd ../..                       # repo root
nixos-anywhere --flake .#wayfinder-ca --target-host ubuntu@<public_ip>
```

This kexecs a NixOS installer over the running Ubuntu, partitions per
`nix/machines/wayfinder-ca/disk.nix`, and reboots into the built system. The
instance's own boot volume is rewritten — nothing of the stock image survives,
which is the point.

The build runs locally. Ampere A1 is aarch64 and so is this repo's dev host, so
it is a native build; there is no cross-compilation or remote builder.

## 5. Provision the secrets

The node will not start until these are in place — it fails at startup with a
missing seed rather than coming up as a CA with no root of trust.

```bash
cd ca-secrets
files='root.seed identity.seed node.cert trust-anchor'
ssh root@<public_ip> 'install -d -m 0700 -o wayfinder -g wayfinder /var/lib/wayfinder'
scp $files root@<public_ip>:/var/lib/wayfinder/
# One by one, never `/var/lib/wayfinder/*` — see the warning below.
ssh root@<public_ip> "cd /var/lib/wayfinder && chown wayfinder:wayfinder $files && chmod 0400 $files"
ssh root@<public_ip> 'systemctl restart wayfinder && systemctl status wayfinder'
```

`./scripts/wayfinder-ca.sh secrets` is this same sequence, made repeatable, and
it also carries `cloudflared.json` when the deployment has a dashboard tunnel.

They go in `/var/lib/wayfinder`, beside the state the node writes, because
`wayfinder-ctl` defaults `--identity` to `/var/lib/wayfinder/identity.seed` and
the CA is the box you type the most commands on. The node still cannot rewrite
its own root of trust: `nix/machines/wayfinder-ca/common.nix` re-mounts these
four files read-only inside the unit's namespace, which is what a separate
directory used to buy.

> **Never `chmod 0400 /var/lib/wayfinder/*`.** That directory also holds
> `ca-state.json`, `settings.json` and `node.mac`, which the node writes. A
> glob takes them with it and leaves a certificate authority that cannot record
> what it issues.

These four files are the one thing this deployment does *not* manage
declaratively. `sops-nix` or `agenix` is the natural next step; until then they
are copied by hand and live only on the box and in your offline backup.

> This is the node's own host configuration, not remote provisioning of someone
> else's node — the distinction the root `CLAUDE.md` draws. Nothing here writes
> a file that some *other* node is expected to read; every interaction with
> another node still goes over the management API.

## 6. Verify

```bash
nix run .#wayfinder-ctl -- --connect <public_ip>:7700 \
    --identity ca-secrets/identity.seed --cert ca-secrets/node.cert \
    node-info
```

Then enrol a node against it, end to end:

```bash
# On the node being enrolled (self-key access; it has no trust anchor yet):
nix run .#wayfinder-ctl -- --connect <node>:7700 --identity <node-seed> \
    csr request --out-request req.json

# Anywhere that can reach the CA:
nix run .#wayfinder-ctl -- --connect <public_ip>:7700 --identity <any-seed> --node-key <ca-pubkey> \
    csr submit --request req.json --out-cert node.cert --out-anchor anchor

# `autoApprove` is false, so approve it as an operator, then re-run the submit
# above to collect — re-submitting the same CSR is how a certificate is fetched.
nix run .#wayfinder-ctl -- --connect <public_ip>:7700 \
    --identity ca-secrets/identity.seed --cert ca-secrets/node.cert \
    csr approve --mac <node-mac>

# Back on the node:
nix run .#wayfinder-ctl -- --connect <node>:7700 --identity <node-seed> \
    csr install --cert node.cert --trust-anchor anchor
```

That chain is for a node that has **no certificate yet**. Once it is installed,
the node holds it — in the runtime state `csr install` persisted, or in the file
static auth loads — and nothing afterwards should make you produce a second
copy. Putting an already-enrolled node on the tunnel is therefore one command,
run on the node's own host:

```bash
nix run .#wayfinder-ctl -- --connect <public_ip>:7700 --node-key <ca-pubkey> \
    --cert-from 127.0.0.1:7700 vpn enrollment
```

`--cert-from` asks the node at that address for the certificate it is running
under and presents *that* to the CA, so there is no `csr request`/`csr submit`
round trip and no certificate file on your disk. It changes only the credential
presented — `--connect` still names the CA — and the node it reads from is
pinned to `--identity`'s own public key, which defaults to
`/var/lib/wayfinder/identity.seed`, the seed the node runs as. A node holding no
certificate is told to enroll rather than handed an empty one.

## The dashboard

`services.wayfinder.web` is enabled but bound to loopback, and must stay there.
It performs no authentication of its own, so whoever reaches its port has
whatever access its identity carries — and on *this* node that identity is an
admin of the mesh root. Reach it over an SSH forward:

```bash
ssh -L 8080:localhost:8081 root@<public_ip>
# then open http://127.0.0.1:8080
```

The far side is 8081, not 8080: Headscale has 8080 on this box. The dashboard
does not compare ports when checking the `Host` header, so the mismatch is
invisible to it. `./scripts/wayfinder-ca.sh dashboard` does the same thing.

## The VPN control plane

The CA also runs Headscale, which is what lets two CGNAT'd nodes reach each
other's mesh UDP link at all — see
`docs/design/implemented/08-internet-links-headscale-vpn.md`. Nothing extra is
provisioned for it: `tofu apply` opens TCP/443, UDP/3478 and UDP/41641 and
creates the `vpn` DNS record, and both secrets it needs are made on the box —
the API key the CA mints tunnel credentials with
(`wayfinder-headscale-apikey.service`, at first boot, renewed a month before it
expires) and the TLS certificate, which Headscale obtains from Let's Encrypt
itself.

**The CA is on that tunnel too.** `wayfinder-headscale-selfjoin.service` mints
a preauth key against the local Headscale at first boot and spends it, so this
box holds a `100.64.0.0/10` address like any other node — which is what its own
`UdpMulti` mesh link is reached on, and what every spoke's `discovery_addr`
points at. It registers under the Headscale user named after its own MAC, the
same convention an enrolled node's credential is scoped to, so `wayfinderctl
vpn list` names this peer like the rest.

It cannot use the `vpn enrollment` RPC every other node uses: that credential is
scoped to a *device* identity and a node connecting to itself with its own key
is refused by design. It does not need to — the coordination server is on the
same box.

`UDP/41641` is `tailscaled`'s own port, so a spoke can hole-punch a direct
WireGuard path here. The mesh link's port is *not* opened: it binds `0.0.0.0`
but only `tailscale0` is a trusted interface, so the link is reachable inside
the tunnel and nowhere else.

```bash
ssh root@<public_ip> 'tailscale ip -4'      # the address spokes point at
ssh root@<public_ip> 'ss -lun | grep 6000'  # the mesh link, bound
```

`./scripts/wayfinder-ca.sh verify` checks both, and `status` prints the tunnel
address beside the public one.

TLS is not optional here, and it is the part most likely to look fine when it
is not: a `tailscaled` refuses a plaintext DERP connection and loses its
`NetInfo`/STUN probing with it, so nodes register happily against a plain-HTTP
coordination server and then cannot reach each other — even on the same LAN.
The certificate is obtained with the TLS-ALPN-01 challenge, answered on the
same 443 listener, which is why nothing here opens port 80.

Two things to confirm after a deploy, both of which fail quietly:

```bash
./scripts/wayfinder-ca.sh verify      # mgmt API, TLS certificate, STUN
./scripts/wayfinder-ca.sh vpn         # units, cert, key expiry, registered peers
```

`verify` checks the certificate is real and for the right name (on a first boot
this can take a minute; until it succeeds, no node completes a tunnel
handshake), and probes STUN with a real binding request. A failed check prints
what it means and what to run next.

The STUN result is a **warning, not a failure**, on purpose: an unanswered UDP
datagram looks the same whether the relay is down or something between you and
it drops UDP, so confirm on the box (`ss -lun | grep 3478`) before believing a
complaint from your own laptop.

**Do not check STUN by hand with a generic tool.** Two obvious ways to do it
both lie, in opposite directions:

- `nc -zvu <host> 3478` prints `succeeded` whenever no ICMP port-unreachable
  comes back — a black hole and a healthy relay produce the identical line.
- A textbook-conformant client (`stunclient`, a hand-rolled 20-byte binding
  request) gets **silence**, because tailscale's STUN server answers only
  tailscale: `ParseBindingRequest` demands a SOFTWARE attribute equal to the
  literal `"tailnode"`, a FINGERPRINT as the last attribute, and a matching
  CRC-32. Everything else is dropped without a word. `stunclient` reports
  `Binding test: fail` against a relay that is working perfectly.

`wayfinder-ca.sh verify` sends the exact request a real client sends, which is
the only probe that answers the question you actually care about.

Note that `https://vpn.<your-zone>/` in a browser is a **blank page**, and that
is correct — Headscale serves an empty document at `/` and has no web UI. The
admin UI is Headplane, below; the day-to-day surface is the dashboard's VPN
panel.

An enrolling node then gets its tunnel credential in the same step as its
membership certificate, and registers against
`https://vpn.<your-zone>:443` — the `login_server` in
`nix/machines/wayfinder-ca/common.nix`, which must resolve **from the nodes**,
not merely from here.

### Headplane

A break-glass admin UI for the case where the wayfinder dashboard is down but
the tunnel is fine. It is loopback-bound, deliberately, and it is not a surface
to route anyone to for day-to-day work — that is the dashboard's VPN panel.

```bash
./scripts/wayfinder-ca.sh headplane   # or: ssh -L 3000:localhost:3000 root@<public_ip>
# then open http://127.0.0.1:3000/admin
```

Sign in by pasting a Headscale API key. Mint a throwaway one rather than
reusing the node's, which has no expiry anyone is watching:

```bash
ssh root@<public_ip> headscale apikeys create --expiration 24h
```

## Troubleshooting

**`tofu apply` fails with "Out of host capacity".** A1 capacity, not your
configuration. Retry, or change `region`.

**The management API is unreachable but SSH works.** Two firewalls sit in
front of it: the OCI security list in `main.tf`, and NixOS' own
`networking.firewall`, opened by `wayfinder.ca.openFirewallOn`. That option
names an *interface*, and the default (`ens3`) depends on the image — run
`ip link` on the instance and set it to what you actually have.

**The node will not start.** `journalctl -u wayfinder -n 50`. The usual causes
are step 5 not done, a `meshId` that disagrees with the trust anchor, or the
membership certificate not matching the identity seed's derived MAC.

**A node enrols but gets no tunnel credential.** `journalctl -u wayfinder |
grep -i vpn` on the CA. If the node's own start-up log has no "VPN coordination
enabled", the API key was unreadable at start-up — check
`systemctl status wayfinder-headscale-apikey` and that
`/var/lib/wayfinder-headscale/api.key` is mode 0400 owned by `wayfinder`.

**Nodes register but cannot reach each other.** Check TLS before anything
else: `journalctl -u headscale | grep -i acme`. A plaintext coordination
server, or one whose certificate never arrived, leaves `tailscaled` refusing
the DERP connection — which also disables its STUN probing, so even two peers
on the same LAN fail. The control plane keeps working throughout, which is what
makes this one hard to see.

**Tunnels work but everything is slow.** Almost always STUN: with UDP/3478
unreachable, peers cannot hole-punch and every packet relays through this box.
Check the security list rule in `main.tf` first, then `ss -lun | grep 3478` on
the instance.

**You have locked yourself out over SSH.** Use Oracle's serial console; the
system is configured with `console=ttyS0` for exactly this.
