# The cloud certificate authority: a `wayfinder-tap` node that holds the mesh
# root of trust, coordinates the tunnel every internet-connected node reaches
# the mesh over, and carries one mesh link riding that same tunnel.
#
# It has **no local egress** — see
# `docs/design/implemented/11-cloud-auth-provider.md`. That is not a limitation
# of the host so much as the point: this box exists to be the one address every
# other node can reach, on the open internet, so the less of the mesh it
# touches the better. It bridges no host traffic, needs no TAP, and therefore
# needs no network capability at all: `rawNetworkAccess` derives to false and
# the unit runs with an empty capability set under systemd's sandbox (see
# `nix/modules/wayfinder.nix`).
#
# It runs the mesh's *iroh relay* beside the CA — see
# `nix/modules/wayfinder-iroh-relay.nix` and design 18. That is the same
# argument as the CA itself: this is the one box with a stable public address,
# so it is where two CGNAT'd nodes have to meet. It replaced the Headscale
# tunnel control plane design 08 put here, along with the second credential
# every node used to collect at enrollment.
#
# And, since design 08 landed, it is a mesh **participant** rather than only a
# coordinator. It joins the tunnel it serves (`selfJoin` below) and carries a
# single `UdpMulti` link in hub/fan-out mode over it. Two things follow that
# the link-less posture could not do: a revocation has somewhere to be flooded
# rather than waiting out a certificate's expiry, and two spokes with no direct
# path converge through this node — a flood arriving on the one link goes back
# out of it, which is exactly what `driver_core::Egress::Auto` stopped
# withholding. `nix/tests/vpn-data-plane.nix` is that shape, tested.
#
# **The files under `secretsDir` are not in this repo and not in the Nix
# store.** They are minted offline and copied to the box before first start —
# see `infra/oracle/README.md`. The mesh root seed in particular *is* the mesh:
# whoever holds it can issue membership certificates for it.
#
# This is one deployment, not a reusable module: the values below are stated
# directly rather than exposed as options, because nothing else imports this
# file to set them.
{ config, lib, ... }:
let
  # Where this node's four provisioned files live, all mode 0400 owned by
  # `wayfinder`: `root.seed` (the mesh root of trust), `identity.seed`,
  # `node.cert` and `trust-anchor` (this node's own membership in the mesh it
  # signs for).
  #
  # The node's own state directory, deliberately — the same one it writes
  # `ca-state.json` and `settings.json` into. An earlier revision kept these in
  # a separate `/var/lib/wayfinder-secrets`, on the argument that the node
  # should not be able to rewrite its own root of trust. That property is worth
  # keeping and is kept, by `ReadOnlyPaths` below rather than by the directory
  # split; what the split cost was ergonomics, every day, on the box where an
  # operator does the most typing: `wayfinder-ctl` defaults `--identity` to
  # `/var/lib/wayfinder/identity.seed`, so a CA whose identity lived elsewhere
  # made every local invocation spell out paths it would otherwise have found.
  secretsDir = "/var/lib/wayfinder";

  # Everything an operator provisions into `secretsDir`, re-mounted read-only
  # *for the node's own unit*.
  #
  # `ReadWritePaths` in `nix/modules/wayfinder.nix` covers `secretsDir` now
  # that it is the state directory, so without this the process that reads the
  # mesh root of trust could also overwrite it — and could rewrite the
  # Cloudflare Tunnel credentials, which are not its business at all. Each file
  # is re-mounted read-only inside the unit's namespace, which restores exactly
  # what the separate directory used to give.
  #
  # Nothing legitimate is lost: `wayfinder-tap` only ever *reads* all of these.
  # An identity installed at runtime by `SetAuth` is persisted to
  # `runtime_state_path`, not written back over `cert_path`.
  #
  # `-`-prefixed: these are operator-provisioned and legitimately absent on a
  # box that has been installed but not yet given its secrets, and a unit that
  # refuses to start then would hide the real error (a missing seed) behind a
  # namespace failure. The cost is that a file placed while the node is running
  # is protected only from its next restart — which `scripts/wayfinder-ca.sh
  # secrets` performs anyway.
  nodeReadOnly = map (f: "-${secretsDir}/${f}") [
    "root.seed"
    "identity.seed"
    "node.cert"
    "trust-anchor"
    "cloudflared.json"
  ];

  # This node's Ed25519 public key, as 64 hex characters — the public half of
  # `identity.seed` in `secretsDir`, printed by `wayfinderctl cert issue` when
  # the identity was minted (see infra/oracle/README.md step 1).
  #
  # The dashboard pins it, and so does every client that reaches this CA
  # (`wayfinder-ctl --node-key ...`). Pinning is what stops a man-in-the-middle
  # impersonating the authority; in login mode it is also what stops a sign-in
  # sending a password to whatever happens to answer on the port.
  #
  # Stated rather than derived from the seed, because the seed is provisioned
  # out of band and is deliberately not readable when this configuration is
  # evaluated.
  nodeKey = "21eca19792e0c231a790d86b0353e7625560f9139d32fff062a091be5fa49707";

  # Public hostname the web dashboard is served on, through the Cloudflare
  # Tunnel below. Three things follow from it: `cloudflared` dials out to
  # Cloudflare, the dashboard runs in **login mode** (each viewer signs in for
  # a short-lived session certificate of their own rather than sharing one
  # identity held by the process), and this name is on the dashboard's
  # `allowed-host` list — it refuses a `Host` it was not told about, which is
  # what stops a page on any site pointing a name it controls at it.
  #
  # Note what is *not* opened: a tunnel is an **outbound** connection from this
  # host to Cloudflare, so nothing is exposed on the public address and the
  # security list needs no HTTP rule at all. The trade-off is that Cloudflare
  # terminates TLS and therefore sees the dashboard's plaintext, including a
  # password at sign-in — a real trust decision, not a free lunch. See
  # `docs/design/implemented/11-cloud-auth-provider.md`.
  #
  # Design 12's `/register` page crosses the same boundary, and it is worth
  # saying plainly because that design's whole point is secret custody: the
  # invitation token, the `otpauth://` URI carrying an account's TOTP secret,
  # and the password chosen at registration all pass through the tunnel. So
  # against this deployment, "the person registering is the first party to see
  # the second factor" means the first party *other than the tunnel provider*.
  # That is not a new class of exposure — sign-in already crosses it — and it
  # was chosen deliberately rather than inherited. The alternative, if that
  # trade stops being acceptable for the TOTP secret specifically, is a
  # registration-only vhost on a DNS-only name with its own ACME certificate,
  # the way `irohRelayHostname` below already works. See
  # `docs/design/implemented/12-self-service-user-registration.md` §5.1.
  dashboardHostname = "dash.wayfndr.dev";

  # Public name of this box's iroh relay — the hole-punch coordination point
  # and fallback path for `LinkTransport::Iroh` links (design 18).
  #
  # A separate record from the management API's, because the relay and the CA
  # are independently movable: a mesh could point its links at somebody else's
  # relay without moving its root of trust. DNS-only and never proxied — QUIC
  # address discovery is UDP, which no HTTP proxy carries, and the name has to
  # resolve here for the relay's own ACME challenge.
  irohRelayHostname = "relay.wayfndr.dev";

  # UDP port the relay answers QUIC address discovery on. Needs a matching
  # Oracle security-list rule, like UDP/3478 does for STUN.
  irohQuicPort = 7842;

  # UDP port this node's own iroh link binds. Pinned rather than ephemeral so
  # the NAT mapping survives a restart and a peer can hole-punch back to a
  # stable address. The Tailscale port this replaces was pinned for the same
  # reason.
  irohMeshPort = 6001;

  # Public name of this node's *management API* — the address a device asking to
  # join the mesh connects to, and the one the dashboard's "What a node needs to
  # join" panel hands an operator.
  #
  # A third record, separate from both above, and each for its own reason. Not
  # `dashboardHostname`: that one is proxied by Cloudflare, and the management
  # API is a bespoke protocol over TLS on 7700 that no HTTP proxy carries — see
  # `infra/oracle/dns.tf`, where this record is `proxied = false` for exactly
  # that. Not `irohRelayHostname`: the relay is independently movable.
  #
  # Display only. The dashboard still *dials* the node over loopback below; this
  # is what it tells a device that is not on this host. Without it the panel
  # reads `127.0.0.1:7700`, which is true of this process and useless to
  # everyone it is shown to.
  caHostname = "ca.wayfndr.dev";

  # The dashboard's loopback port. Off 8080 historically (Headscale held it);
  # kept there because the Cloudflare ingress below names it.
  # Nothing outside this file sees it: the dashboard is reached through the
  # Cloudflare Tunnel below, whose ingress is the one thing that names it.
  dashboardPort = 8081;
in
{
  imports = [
    ../../modules/wayfinder.nix
  ];

  services.wayfinder = {
    enable = true;

    web = {
      enable = true;
      listen = "127.0.0.1:${toString dashboardPort}";
      provider = "127.0.0.1:7700";
      # Where a joining node reaches that same authority. See `caHostname`:
      # loopback is how this dashboard gets there, and nothing else can.
      publicProviderAddress = "${caHostname}:7700";
      allowedHosts = [ dashboardHostname ];
      inherit nodeKey;
    };

    # The cloud NIC's name depends on the image — check `ip link` on the
    # instance before trusting this.
    openFirewall = [ "ens3" ];

    config = {
      # No `local_egress`: see the header. `wayfinder-tap` runs a `NullEgress`
      # for the local device in this posture — the node routes, it just has no
      # host traffic of its own to bridge.
      server = {
        type = "Tls";
        addr = "0.0.0.0:7700";
      };

      # The one mesh link, and it is the iroh one (design 18). What used to sit beside
      # it was a `UdpMulti` riding a Tailscale tunnel this box also coordinated;
      # retiring that took a Headscale, a Headplane, a `tailscaled`, an API key
      # this host minted for itself, and a second credential every node had to
      # collect at enrollment — all replaced by a link that dials peers by the
      # key their `MembershipCert` already binds.
      links = [
        {
          # Hole punching to a spoke where possible, relaying through this
          # box's own relay when not — the same two-tier reach the Tailscale
          # path had, with the coordination server deleted.
          #
          # The question design 18 §5 raised — does hole punching hold between
          # two *real* CGNAT'd hosts — is not answerable in a VM or in CI, and
          # is not answered here. What is answered is what happens when it
          # fails: the connection relays through this node, which is exactly
          # where a DERP-relayed Tailscale path went too. The failure mode is a
          # wash; only the machinery is gone.
          name = "iroh0";
          type = "Iroh";
          bind_port = irohMeshPort;

          # This box's own relay, started below. Never iroh's public default
          # relays: an isolated mesh's coordination metadata must not reach a
          # third party. The pinned `--login-server` this replaces existed for
          # the same reason.
          relay_url = "https://${irohRelayHostname}";

          # Empty, and correct: this is the hub. Every spoke names *this* node
          # in its own `bootstrap_peers` (its `nodeKey` above, which is exactly
          # the endpoint peers dial) and connects inbound; a hub that dialled
          # back would need the peer list that adopting iroh exists to delete.
          bootstrap_peers = [ ];
        }
      ];

      # This node's own membership in the mesh it signs for. A provider
      # should be a member: it is what lets it flood revocations over the link
      # above, and it means the key clients pin is a certified identity rather
      # than a bare bootstrap key.
      auth = {
        seed_path = "${secretsDir}/identity.seed";
        cert_path = "${secretsDir}/node.cert";
        trust_anchor_path = "${secretsDir}/trust-anchor";
      };

      provider = {
        root_seed_path = "${secretsDir}/root.seed";

        # The mesh this authority signs for: 0x5741594e. Must equal the
        # `--mesh-id` the trust anchor in `secretsDir` was created with
        # (`wayfinder-ctl cert init-ca`) — `wayfinder-tap` refuses to start on
        # a mismatch rather than signing for the wrong mesh.
        mesh_id = 1463900494;

        # Validity window applied to issued membership certificates.
        #
        # Deliberately short, and still short now that this node has a link.
        # An active revocation reaches only the nodes the flood actually gets
        # to — a spoke that is offline, or off the tunnel, when the revocation
        # goes out never hears it — so a certificate lifetime remains the only
        # bound that holds for *every* member. What the link changes is the
        # common case, not the worst one: a node that is up learns of a
        # revocation in seconds instead of ageing out over a week. One week
        # means a node re-enrols weekly and an unreachable withdrawn node ages
        # out within a week.
        cert_ttl_secs = 7 * 24 * 60 * 60;

        # False, and it matters: this node is reachable from the open
        # internet, and what an unattended provider hands out is mesh
        # membership itself. A submitted CSR is parked for an operator
        # (`wayfinder-ctl provider requests approve`, or the dashboard's Security tab).
        auto_approve = false;

        # The issued-certificate log, its revocation status, and held CSRs.
        # Without this a restart forgets every revocation and every pending
        # approval, and the impersonation guard starts empty — so it is not
        # optional on a node that is the mesh's root of trust.
        state_path = "/var/lib/wayfinder/ca-state.json";
      };

      # Security settings an operator changes at runtime through the
      # management API (the fail-closed gate, lazy cert distribution, an
      # identity installed by SetAuth), so they survive a restart.
      runtime_state_path = "/var/lib/wayfinder/settings.json";
    };
  };

  # The iroh relay serving this mesh's `Iroh` links (design 18): hole-punch
  # coordination via QUIC address discovery, plus the fallback path when two
  # peers cannot punch through to each other.
  #
  # Smaller than the Headscale it replaced in every sense — no user database,
  # no address allocation, no preauth keys, no admin UI — because an iroh peer
  # is named by its own public key and there is nothing to hand out. This box
  # already holds the one thing that cannot be decentralised: a stable public
  # address.
  services.wayfinder-iroh-relay = {
    enable = true;
    hostname = irohRelayHostname;
    quicBindAddr = "[::]:${toString irohQuicPort}";

    # Real TLS, for exactly the reason the Headscale before it needed it: QUIC
    # address discovery requires TLS, and without QAD a node never learns its
    # own public address and so can never hole-punch. A plaintext relay would
    # register every node correctly and quietly leave them all relaying.
    tls = {
      mode = "acme";
      contact = "admin@wayfndr.dev";
    };

    # Open, deliberately, and worth being precise about. A relay carries opaque
    # end-to-end-encrypted QUIC between two endpoints: it is not a mesh member,
    # cannot read what it forwards, and admitting a stranger grants no mesh
    # membership — that is still gated by a root-signed `MembershipCert` one
    # layer up. The exposure is bandwidth on a metered instance, not trust.
    #
    # An allowlist would close that but reintroduces the per-node list this
    # design exists to delete. The right answer is the relay's HTTP admission
    # hook pointed at this node's own certificate log; see design 18 §6.4.
    access.mode = "everyone";
  };

  # `/var/lib/wayfinder` holds both the node's own state and the trust material
  # an operator provisions (see `secretsDir`). 0700 rather than the module's
  # 0755: on this box the directory contains the mesh root seed, and only the
  # `wayfinder` user — and root — has any business traversing it.
  systemd.tmpfiles.settings."10-wayfinder".${secretsDir}.d.mode = lib.mkForce "0700";

  # The node reads its root of trust and must not be able to rewrite it. With
  # the secrets inside the unit's own `ReadWritePaths`, that is a namespace
  # remount rather than a directory it cannot reach — see `nodeReadOnly`.
  systemd.services.wayfinder.serviceConfig.ReadOnlyPaths = nodeReadOnly;

  # The tunnel: an outbound connection to Cloudflare that public requests for
  # `dashboardHostname` are routed back down. Nothing is listening on the
  # public address for this.
  services.cloudflared = {
    enable = true;
    # The tunnel's UUID, not its name. `cloudflared` can resolve a *name* only
    # by asking Cloudflare with an account-level origin certificate, which this
    # host deliberately does not have: it holds a per-tunnel credentials file
    # and nothing else, so a compromise of this box cannot reach any other
    # tunnel in the account. Created by `infra/oracle/tunnel.tf`.
    tunnels."97a81a85-ccfa-4af3-ac76-32a58feef68f" = {
      # The credentials `cloudflared` authenticates with, provisioned out of
      # band alongside the mesh trust material — it is a secret, and it is what
      # lets anything claim to be this tunnel. Created by `tofu apply` (see
      # `infra/oracle/tunnel.tf`) and copied up by `scripts/wayfinder-ca.sh
      # secrets`.
      credentialsFile = "${secretsDir}/cloudflared.json";
      ingress.${dashboardHostname} = "http://127.0.0.1:${toString dashboardPort}";
      # Anything arriving for a name this tunnel was not built for is
      # refused here rather than being quietly handed to the dashboard.
      default = "http_status:404";
    };
  };

  services.openssh = {
    enable = true;
    settings = {
      # Key-only: this box is on the open internet and holds the mesh root
      # key. `prohibit-password` still allows key-based root login, which is
      # what `nixos-anywhere` and `nixos-rebuild --target-host` both use.
      PasswordAuthentication = false;
      PermitRootLogin = "prohibit-password";
    };
  };

  # Your key goes here, and this is not the same setting as `ssh_public_key`
  # in `infra/oracle/terraform.tfvars` — the difference bites exactly once.
  # That one authorises the *stock image's* user so `nixos-anywhere` can
  # connect and install; `nixos-anywhere` does not carry it into the system
  # it installs. In practice the same key belongs in both places.
  users.users.root.openssh.authorizedKeys.keys = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJnzxkEIglEd359gj7fUp48N3VnX7bVjBkVzrAuHdvOL bcape@gantz.haganah.net"
  ];

  # An unreachable box is a worse failure than a build-time warning, and this
  # is the one setting whose absence stays silent until after the install has
  # already replaced the stock image's SSH access.
  warnings = lib.optional (config.users.users.root.openssh.authorizedKeys.keys == [ ]) ''
    nix/machines/wayfinder-ca/common.nix authorises no SSH key for root: once
    installed, this host will be reachable only through the provider's serial
    console. Set users.users.root.openssh.authorizedKeys.keys to the same
    public key you gave the provider (see infra/oracle/README.md).
  '';

  # Oracle's serial console is the way back into a box you have locked
  # yourself out of over SSH — worth having before you need it, not after.
  boot.kernelParams = [ "console=ttyS0,115200n8" ];

  programs.vim = {
    enable = true;
    defaultEditor = true;
  };

  system.stateVersion = "26.05";

  # Must match `instance_shape` in `infra/oracle/terraform.tfvars`:
  # `aarch64-linux` for `VM.Standard.A1.Flex` (Ampere), `x86_64-linux` for
  # `VM.Standard.E2.1.Micro` (AMD). A mismatch installs a system the instance
  # cannot boot, and it fails *after* `nixos-anywhere` has already replaced
  # the disk.
  nixpkgs.hostPlatform.system = "x86_64-linux";
}
