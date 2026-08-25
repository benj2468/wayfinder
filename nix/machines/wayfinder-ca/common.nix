# The cloud certificate authority: a `wayfinder-tap` node that holds the mesh
# root of trust and does nothing else.
#
# It carries **no mesh links and no local egress** — see
# `docs/design/implemented/11-cloud-auth-provider.md`. That is not a limitation of the host
# so much as the point: this box exists to be the one address every other node
# can reach, on the open internet, so the less of the mesh it touches the
# better. It serves `SubmitCsr`/`ApproveCsr`/`GetTrustAnchor`/`RevokeNode` over
# the management API and nothing else, which is why `rawNetworkAccess` derives
# to false and the unit runs with an empty capability set under systemd's
# sandbox (see `nix/modules/wayfinder.nix`).
#
# It does, however, run the *tunnel* control plane beside the mesh one — see
# `nix/modules/wayfinder-headscale.nix` and design 08. That is the same
# argument as the CA itself: this is the one box with a stable public address,
# so it is where two CGNAT'd nodes have to meet. It still carries no mesh link
# of its own; it coordinates the tunnel that other nodes' links run over.
#
# **The four files under `secretsDir` are not in this repo and not in the Nix
# store.** They are minted offline and copied to the box before first start —
# see `infra/oracle/README.md`. The mesh root seed in particular *is* the mesh:
# whoever holds it can issue membership certificates for it.
#
# This is one deployment, not a reusable module: the values below are stated
# directly rather than exposed as options, because nothing else imports this
# file to set them.
{ config, lib, ... }:
let
  # Directory holding the four files this node is provisioned with, all mode
  # 0400 owned by `wayfinder`: `root.seed` (the mesh root of trust),
  # `identity.seed`, `node.cert` and `trust-anchor` (this node's own membership
  # in the mesh it signs for).
  #
  # Separate from `/var/lib/wayfinder` on purpose. That directory is writable
  # state the node generates and rewrites; this one is operator-provisioned
  # input the node only ever reads, and the unit's `ReadWritePaths` does not
  # include it.
  secretsDir = "/var/lib/wayfinder-secrets";

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
  dashboardHostname = "dash.wayfndr.dev";

  # Public name nodes register their tunnel against. A separate record from the
  # CA's own `ca.wayfndr.dev` even though both resolve to this instance: the two
  # planes are independently movable, and a node's `--login-server` is baked
  # into its tunnel registration in a way the management endpoint is not.
  #
  # DNS-only, never proxied — the same constraint as the management API, for two
  # stronger reasons. STUN is UDP, which no HTTP proxy carries at all; and the
  # name has to resolve to *this* host for the ACME challenge below to be
  # answerable.
  vpnHostname = "vpn.wayfndr.dev";

  # The dashboard's loopback port, moved off 8080 because Headscale is there.
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
      allowedHosts = [ dashboardHostname ];
      inherit nodeKey;
    };

    # The cloud NIC's name depends on the image — check `ip link` on the
    # instance before trusting this.
    openFirewall = [ "ens3" ];

    config = {
      # No `local_egress` and no `links`: see the header. `wayfinder-tap`
      # runs a `NullEgress` for the local device in this posture.
      server = {
        type = "Tls";
        addr = "0.0.0.0:7700";
      };

      # This node's own membership in the mesh it signs for. A provider
      # should be a member: it is what lets it flood revocations once it has
      # a link to flood them over, and it means the key clients pin is a
      # certified identity rather than a bare bootstrap key.
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
        # Deliberately short: passive expiry is this design's *primary*
        # revocation mechanism — an active revocation has to reach every node
        # over the mesh, and this CA has no links to flood it over — so a
        # certificate lifetime is the real bound on how long a compromised
        # node stays a member. One week means a node re-enrols weekly and a
        # withdrawn node ages out within a week.
        cert_ttl_secs = 7 * 24 * 60 * 60;

        # False, and it matters: this node is reachable from the open
        # internet, and what an unattended provider hands out is mesh
        # membership itself. A submitted CSR is parked for an operator
        # (`wayfinder-ctl csr approve`, or the dashboard's Security tab).
        auto_approve = false;

        # VPN coordination, pointed at the Headscale started below.
        #
        # The API is reached over loopback (nothing crosses a network to get
        # there) while nodes are handed the public name, because a
        # `--login-server` of `127.0.0.1` is one every node would resolve to
        # itself. `login_server` is what makes those two able to differ.
        #
        # The key is minted on this box by
        # `wayfinder-headscale-apikey.service`, not carried here with the mesh
        # trust material: it can only be issued by a running Headscale, and
        # this host can reissue it at will.
        headscale = {
          # One URL for both halves: under TLS the certificate names the host,
          # so the loopback call and the node's `--login-server` have to be the
          # same string. The module resolves that name to 127.0.0.1 on this box
          # so the request does not depend on Oracle hairpinning it back.
          api_url = config.services.wayfinder-headscale.endpoint;
          api_key_path = config.services.wayfinder-headscale.apiKey.path;
        };

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

  # The tunnel control plane. Nodes register against `vpnHostname`, and the
  # DERP relay they fall back to when hole-punching fails is the one this box
  # runs — not Tailscale Inc.'s, which is what "isolated mesh" has to mean if
  # it means anything. The security list in `infra/oracle/main.tf` carries the
  # two matching rules: TCP/443 for the API and the relay, UDP/3478 for STUN.
  services.wayfinder-headscale = {
    enable = true;
    domain = vpnHostname;

    # Real TLS, from Let's Encrypt, on 443. Not a hardening preference: a
    # `tailscaled` refuses a plaintext DERP connection and takes STUN probing
    # down with it, so a plain-HTTP coordination server registers nodes
    # perfectly and then leaves them unable to reach each other. The
    # TLS-ALPN-01 challenge is answered on the 443 listener headscale already
    # has, so the security list needs no HTTP rule — see
    # `nix/modules/wayfinder-headscale.nix` and `nix/tests/vpn-data-plane.nix`.
    tls.mode = "acme";

    # Break-glass only: loopback-bound, reached with
    # `ssh -L 3000:localhost:3000 root@<ca>` and then http://localhost:3000/admin.
    # Sign in by pasting a throwaway Headscale API key
    # (`headscale apikeys create --expiration 24h` over that same SSH session).
    # The day-to-day surface is the dashboard's VPN panel; this is for the day
    # wayfinder-server is down and the tunnel is not.
    headplane.enable = true;
  };

  # The provisioned secrets live outside `/var/lib/wayfinder` (which the unit
  # can write) precisely so the node cannot rewrite its own root of trust.
  # Created here so the directory's mode is declared rather than depending on
  # however the operator's `scp` left it; the files inside are the operator's
  # to place.
  systemd.tmpfiles.settings."10-wayfinder-ca".${secretsDir}.d = {
    mode = "0700";
    user = "wayfinder";
    group = "wayfinder";
  };

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
