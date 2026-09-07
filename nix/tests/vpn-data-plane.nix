# Proves wayfinder's own mesh UDP link works once a real Tailscale tunnel is
# up — not that Tailscale itself can traverse NAT (that is Tailscale's job,
# already covered by its own upstream tests; the user explicitly scoped this
# out) but that the routing engine actually converges over a `UdpMulti` link
# riding on top of the resulting tunnel. `nix/tests/ca-provider.nix` proves
# the *control* plane (a real preauth key gets minted); this proves the
# *data* plane. What remains uncovered even here is what
# `docs/design/implemented/08-internet-links-headscale-vpn.md` names: two hosts
# behind *real* NAT, "which is where hole-punching either happens or silently
# degrades to relaying" — that needs two real machines, not two containers.
#
# It is also where a tunnel *registration* is revoked, for the same reason: a
# revocation can only be checked against a node that really registered, and
# every other test in the repo revokes a MAC whose preauth key was never spent.
# See the last subtest — that gap is how #27 shipped.
#
# This is also the regression test for the relay gap it originally uncovered:
# every stage but the last used to pass while the two spokes never saw each
# other's routes, because split-horizon excluded the ingress interface and the
# hub has exactly one link for both spokes. The exclusion is gone (see
# `driver_core::Egress::Auto`). `libs/wayfinder-test`'s star-fabric tests cover
# the shape without a tunnel; this covers it over a real one.
#
# Three containers on one shared network (deliberately *not* isolated onto
# disjoint vlans — see below). `hub` runs the coordination server
# (`wayfinder-headscale`) and is itself a full mesh participant with a
# `UdpMulti` link in *hub/fan-out* mode (no static `discovery_addr` — see
# `libs/wayfinder-driver/src/net.rs`): it learns spokes purely from the
# datagrams they send it. `spokeA`/`spokeB` are ordinary mesh devices.
#
# Every container shares the test framework's default network, so Tailscale
# is free to connect spokeA and spokeB directly rather than through
# Headscale's embedded DERP relay — forcing relay-only isolation is not
# needed to prove the point (the user explicitly scoped Tailscale's own NAT
# traversal out) and every `wayfinder-tap` mesh link this test configures for
# spokeA/spokeB binds only a Tailscale-assigned (`100.64.0.0/10`) address,
# never the shared vlan's own IP — there is no other wayfinder link between
# them for a route to have come from, so convergence is still real proof the
# UDP link rode the tunnel, direct or relayed.
#
# Headscale is served over real TLS (a self-signed cert generated at build
# time by `hubTls` below, `CA:FALSE` and all — see its comment), not plain
# HTTP. This turned out to be required, not optional: `tailscaled` refuses a
# plaintext DERP connection outright regardless of the URL scheme headscale
# advertises, and that refusal blocks more than relay fallback — its
# `NetInfo`/STUN probing depends on the DERP TLS handshake succeeding at all,
# even between two peers on the same LAN. Trust is distributed by directly
# overriding `/etc/ssl/certs/ca-certificates.crt`'s content (`hubCaBundle`),
# not `security.pki.certificateFiles`: that option's usual effect on this path
# does not reach a NixOS *container* the way it does a full system — confirmed
# by `curl` trusting the cert fine (OpenSSL's separate hashed-directory
# lookup, which the option does populate) while `wayfinder-server`'s `reqwest`
# client (`rustls-platform-verifier`, which reads only the single bundle file)
# did not, until the file itself was replaced.
#
# Identities are minted offline against the hub's own root seed (`cert
# keygen` + `cert issue`, no `--admin`), the same tooling `ca-provider.nix`
# uses for its own admin identity — deliberately bypassing the CSR/approval
# RPC dance that test already covers, so this one stays focused on the
# property that is actually new here.
#
# A spoke still uses the `wayfinder.nix` module — its user/group, tmpfiles
# directory and capability/hardening derivation are exactly what a real
# deployment gets, and reusing them keeps this container an honest stand-in
# for one. What the module *cannot* do is render this spoke's `UdpMulti`
# link: `discovery_addr` is a Tailscale address that does not exist until
# after `tailscale up`, and `services.wayfinder.config` is rendered once, at
# build time, into an immutable store path — there is no config value that
# would be correct yet. So `services.wayfinder.config` here is left at its
# default (`{}`; never read) and the module's own unit definition is
# overridden with `lib.mkForce` on exactly the two properties that need to
# differ: `wantedBy` (never start on boot, same reason `ca-provider.nix`
# holds `hub` back) and `ExecStart` (always read
# `/var/lib/wayfinder/config.json` — a path inside the module's own
# tmpfiles-managed, `wayfinder`-owned directory — rather than the
# module-rendered store path). The test script writes that file once the
# tunnel address is known and starts the *same* `wayfinder.service` unit the
# module defines.
{
  testers,
  lib,
  pkgs,
}:
let
  # A self-signed cert for "hub", generated once at build time — deterministic
  # and store-cached like everything else here, so no runtime cert-minting
  # step is needed. `subjectAltName` is required: Go's TLS stack (what
  # `tailscaled` and headscale are both built with) has refused to fall back
  # to the legacy CN-only match since well before either was written.
  #
  # `basicConstraints=CA:FALSE` is equally required, and less obviously so:
  # `openssl req -x509` sets `CA:TRUE` by default absent this, which OpenSSL
  # itself (curl) and Go's crypto/x509 (tailscaled) both tolerate on a
  # directly-trusted self-signed leaf, but `rustls`/`webpki` — what
  # `wayfinder-server`'s `reqwest` client uses — reject outright per RFC 5280
  # (`InvalidCertificate(CaUsedAsEndEntity)`). That divergence is exactly why
  # curl and tailscaled both worked while wayfinder-tap's own connection to
  # Headscale's REST API did not, and took three wrong turns (dual-stack
  # binding, sandboxing, the container trust-store gap) to trace back to the
  # cert itself.
  hubTls =
    pkgs.runCommand "wayfinder-vpn-data-plane-hub-tls" { nativeBuildInputs = [ pkgs.openssl ]; }
      ''
        mkdir -p $out
        openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
          -keyout $out/key.pem -out $out/cert.pem \
          -subj "/CN=hub" \
          -addext "subjectAltName=DNS:hub" \
          -addext "basicConstraints=critical,CA:FALSE" \
          -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
          -addext "extendedKeyUsage=serverAuth"
      '';

  # `security.pki.certificateFiles` turned out not to reach
  # `/etc/ssl/certs/ca-certificates.crt` on a NixOS *container* — that
  # symlink stayed pointed at the stock `cacert` package's bundle, unlike on
  # a full system. Confirmed: `curl` trusted the cert fine (OpenSSL's
  # separate hashed-directory lookup, which the option *does* populate), but
  # `rustls-platform-verifier` — which `wayfinder-server`'s `reqwest` client
  # uses, and which reads only the single bundle file via a fixed path search
  # rather than `SSL_CERT_FILE` (tried, made no difference) — did not. This
  # builds the file directly rather than depending on either mechanism.
  hubCaBundle = pkgs.runCommand "wayfinder-vpn-data-plane-ca-bundle" { } ''
    cat ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt ${hubTls}/cert.pem > $out
  '';

  mkSpoke =
    { pkgs, ... }:
    {
      imports = [
        ../modules/wayfinder.nix
      ];

      security.pki.certificateFiles = [ "${hubTls}/cert.pem" ];

      services.wayfinder-tailscale = {
        enable = true;
        loginServer = "https://hub:8080";
      };

      services.wayfinder.enable = true;

      systemd.services.wayfinder = {
        wantedBy = lib.mkForce [ ];
        serviceConfig.ExecStart = lib.mkForce (
          "${pkgs.wayfinder-tap}/bin/wayfinder-tap --config /var/lib/wayfinder/config.json"
        );
      };
    };
in
testers.nixosTest {
  name = "wayfinder-vpn-data-plane";

  containers = {
    hub =
      { config, ... }:
      {
        imports = [
          ../modules/wayfinder.nix
        ];

        services.wayfinder-headscale = {
          enable = true;
          domain = "hub";
          port = 8080;

          # Real TLS — see the top comment. A supplied certificate rather than
          # the module's ACME default, since nothing in a VM can answer an ACME
          # challenge; the module derives `https://hub:8080` from this, which is
          # what makes the scheme and the port impossible to disagree with what
          # is really listening.
          tls = {
            mode = "files";
            certFile = "${hubTls}/cert.pem";
            keyFile = "${hubTls}/key.pem";
          };

          # The hub joins the tunnel it coordinates, through the module's own
          # unit rather than the test script's shell — which is what the
          # deployment does (`nix/machines/wayfinder-ca/common.nix`), and the
          # only place that unit is exercised against a real `tailscaled`.
          #
          # An earlier revision of this test did the same sequence by hand
          # under a `hub-self` user. It worked, and it left the deployment's
          # version untested and the hub as the one peer `vpn list` could not
          # name.
          selfJoin.enable = true;
        };
        # The module's default (0.0.0.0, IPv4-only) leaves a hole on a
        # dual-stack host like this container: "hub" resolves an AAAA record
        # too, and if a client's resolver/connector tries that first with no
        # IPv4 fallback, it fails even though headscale is right there on
        # IPv4. `[::]` binds both families on Linux (no IPV6_V6ONLY set) —
        # bracketed, since the module concatenates `address:port` directly
        # and a bare `::` collides with that colon.
        services.headscale.address = lib.mkForce "[::]";

        security.pki.certificateFiles = [ "${hubTls}/cert.pem" ];

        services.wayfinder-tailscale = {
          enable = true;
          # Taken from the module, not restated: `selfJoin` asserts the two
          # agree before it will build, so a literal here would be one more
          # string to keep in step with the port and TLS mode above.
          loginServer = config.services.wayfinder-headscale.endpoint;
        };

        services.wayfinder = {
          enable = true;
          config = {
            server = {
              type = "Tls";
              addr = "0.0.0.0:7700";
            };
            # In the node's own state directory, as the deployment provisions
            # them — see `secretsDir` in `nix/machines/wayfinder-ca/common.nix`
            # for why they are not in a directory of their own. It also puts
            # the hub's paths on the same footing as the spokes' below, which
            # were always here.
            #
            # Both files are named here even though this hub is a provider and
            # could derive them, and that is deliberate: the deployment and
            # `nix/tests/ca-provider.nix` both take the derived path, so
            # without this nothing would still exercise a *configured*
            # certificate and anchor in provider mode. A named file wins over
            # derivation, and this is where that stays covered.
            auth = {
              seed_path = "/var/lib/wayfinder/identity.seed";
              cert_path = "/var/lib/wayfinder/node.cert";
              trust_anchor_path = "/var/lib/wayfinder/trust-anchor";
            };
            provider = {
              root_seed_path = "/var/lib/wayfinder/root.seed";
              mesh_id = 1463900494; # 0x5741594e, same as ca-provider.nix
              cert_ttl_secs = 604800;
              # Auto-approved: what this test exercises is the data plane, not
              # the operator-approval workflow ca-provider.nix already covers.
              auto_approve = true;
              state_path = "/var/lib/wayfinder/ca-state.json";
              headscale = {
                # Both taken from the module rather than restated: it derives
                # `https://hub:8080` from the TLS mode, the domain and the
                # port, and mints the key on the box the way the deployment
                # does. By hostname, not 127.0.0.1 — the cert's SAN only names
                # "hub", and this connection is validated for real (see the
                # top comment on rustls-platform-verifier).
                api_url = config.services.wayfinder-headscale.endpoint;
                api_key_path = config.services.wayfinder-headscale.apiKey.path;
                preauth_ttl_secs = 300;
              };
            };
            # No discovery_addr: hub/fan-out mode. Unlike the spokes' links,
            # this needs no runtime-learned address, so it is fully
            # module-rendered and never needs a config rewrite.
            #
            # Nothing here marks this node as a relay between the two spokes;
            # it works because a flood is no longer withheld from the interface
            # it arrived on. See the header.
            links = [
              {
                type = "UdpMulti";
                bind_addr = "0.0.0.0:6000";
              }
            ];
            runtime_state_path = "/var/lib/wayfinder/settings.json";
          };
        };

        # Held back until the identity mint below writes its files, same
        # reason as ca-provider.nix. The self-join reaches the node's own
        # management API, so it waits on the same thing — a node that has not
        # started is one there is nothing to ask. It would retry its way to
        # success on its own (`Restart = on-failure`), but a test that ships a
        # minute of expected failures in the journal is a test nobody reads the
        # journal of.
        systemd.services.wayfinder.wantedBy = lib.mkForce [ ];
        systemd.services.wayfinder-headscale-selfjoin.wantedBy = lib.mkForce [ ];

        # See `hubCaBundle`'s comment above: `security.pki.certificateFiles`
        # alone does not reach this path on a NixOS container.
        environment.etc."ssl/certs/ca-certificates.crt".source = lib.mkForce hubCaBundle;

        networking.firewall.allowedTCPPorts = [ 7700 ];
      };

    spokeA = mkSpoke;
    spokeB = mkSpoke;
  };

  testScript = ''
    import json

    start_all()
    hub.wait_for_unit("multi-user.target")
    spokeA.wait_for_unit("multi-user.target")
    spokeB.wait_for_unit("multi-user.target")

    with subtest("mint the mesh root of trust and the hub's own device identity"):
        # Into /var/lib/wayfinder, beside the node's own state, as the
        # deployment provisions them — the directory the `wayfinder.nix`
        # module's tmpfiles rule already created.
        hub.succeed(
            "wayfinder-ctl cert init-ca --mesh-id 0x5741594e --generate "
            "--out-seed /var/lib/wayfinder/root.seed "
            "--out-anchor /var/lib/wayfinder/trust-anchor"
        )
        hub.succeed(
            "wayfinder-ctl cert keygen --out-seed /var/lib/wayfinder/identity.seed"
        )
        now = int(hub.succeed("date +%s").strip())
        # No --admin: the hub is a device on its own mesh, not an operator of
        # it — the same distinction design 08 draws for every other node.
        hub.succeed(
            "wayfinder-ctl cert issue "
            "--ca-seed /var/lib/wayfinder/root.seed --mesh-id 0x5741594e "
            "--node-seed /var/lib/wayfinder/identity.seed "
            f"--not-before {now - 60} --not-after {now + 31536000} "
            "--out-cert /var/lib/wayfinder/node.cert"
        )
        # Named one by one rather than globbed: this directory also holds the
        # state the node writes, and `chmod 0400 /var/lib/wayfinder/*` would
        # take that with it. `scripts/wayfinder-ca.sh secrets` has the same
        # constraint for the same reason.
        secrets = " ".join(
            f"/var/lib/wayfinder/{f}"
            for f in ("root.seed", "identity.seed", "node.cert", "trust-anchor")
        )
        hub.succeed(f"chown wayfinder:wayfinder {secrets}")
        hub.succeed(f"chmod 0400 {secrets}")

    with subtest("the coordination server comes up on its own relay"):
        hub.wait_for_unit("headscale.service")
        hub.wait_for_open_port(8080, timeout=60)
        # By hostname, not 127.0.0.1: the cert's SAN only names "hub", and
        # this is a real trust-chain check (the CA was distributed via
        # security.pki.certificateFiles), not `-k`.
        hub.succeed("curl -sf https://hub:8080/health")

        # The API key the hub's own node reads is minted by the module, on the
        # box, exactly as it is in the deployment — nothing here hands it one.
        # `ca-provider.nix` is where that unit's behaviour is pinned down
        # (ownership, mode, that a re-run keeps the key); all this needs is for
        # it to have happened before the node starts below.
        hub.wait_for_unit("wayfinder-headscale-apikey.service")
        key = hub.succeed("cat /var/lib/wayfinder-headscale/api.key").strip()
        assert key.startswith("hskey-api-"), f"unexpected API key shape: {key[:16]}"

    with subtest("the hub's own mesh router and management API come up"):
        hub.succeed("systemctl start wayfinder.service")
        hub.wait_for_unit("wayfinder.service")
        hub.wait_for_open_port(7700, timeout=30)
        hub.succeed("journalctl -u wayfinder | grep -q 'VPN coordination enabled'")
        hub_cert = hub.succeed("wayfinder-ctl cert show /var/lib/wayfinder/node.cert")
        hub_key = [
            l.split()[-1]
            for l in hub_cert.splitlines()
            if l.strip().startswith("ed25519:")
        ][0]
        # The hub's own MAC, unseparated and lowercase — `hostname_for` in
        # `libs/wayfinder-server/src/vpn.rs`, and the Headscale user the
        # self-join below must register under.
        hub_mac_hex = [
            l.split()[-1].replace(":", "").lower()
            for l in hub_cert.splitlines()
            if l.strip().startswith("node_mac:")
        ][0]

    with subtest("the hub joins its own tunnel — it is a mesh device too"):
        # Through `wayfinderctl vpn enrollment` against its own management API,
        # which is the same request a spoke's enrollment makes below. The hub
        # connects to itself with its own identity seed and earns
        # `GrantedSelfKey`; the MAC the credential is minted for comes from the
        # router, so the Headscale user is the one `hostname_for` names for
        # every other node too.
        #
        # A module unit, not a shell sequence in this file: it is what
        # `nix/machines/wayfinder-ca` deploys, and this is the only test that
        # runs it against a real `tailscaled`. Started explicitly rather than
        # at boot because it needs the node started above.
        hub.succeed("systemctl start wayfinder-headscale-selfjoin.service")
        hub.wait_for_unit("wayfinder-headscale-selfjoin.service")
        hub.wait_until_succeeds("tailscale ip -4 | grep -q '^100\\.'", timeout=60)
        hub_ts_ip = hub.succeed("tailscale ip -4").strip()

        # Registered under the MAC-named user, not under some name of its own.
        # That name *is* the peer↔mesh-identity mapping — nothing persists it
        # anywhere else — so a self-join under a convenient label would leave
        # this box the one peer `wayfinderctl vpn list` could not name, and
        # would do it silently: the tunnel works either way.
        users = [u["name"] for u in json.loads(hub.succeed("headscale users list -o json"))]
        assert hub_mac_hex in users, f"no headscale user '{hub_mac_hex}' among {users}"

        # Idempotent. It runs on every boot, and a re-run that minted a fresh
        # preauth key and re-registered would churn this box's tunnel identity
        # for nothing.
        hub.succeed("systemctl restart wayfinder-headscale-selfjoin.service")
        assert hub.succeed("tailscale ip -4").strip() == hub_ts_ip, (
            "the self-join re-registered instead of recognising it was already joined"
        )

    for name, node in [("spokeA", spokeA), ("spokeB", spokeB)]:
        with subtest(f"{name} enrols offline and joins the tunnel"):
            # /var/lib/wayfinder already exists here, created by the
            # `wayfinder.nix` module's own tmpfiles rule (active once
            # services.wayfinder.enable = true), owned wayfinder:wayfinder.
            seed_b64 = hub.succeed(
                "wayfinder-ctl cert keygen --out-seed /tmp/spoke.seed >/dev/null; "
                "base64 -w0 /tmp/spoke.seed"
            ).strip()
            node.succeed(f"echo {seed_b64} | base64 -d > /var/lib/wayfinder/identity.seed")
            now = int(hub.succeed("date +%s").strip())
            hub.succeed(
                "wayfinder-ctl cert issue "
                "--ca-seed /var/lib/wayfinder/root.seed --mesh-id 0x5741594e "
                "--node-seed /tmp/spoke.seed "
                f"--not-before {now - 60} --not-after {now + 31536000} "
                "--out-cert /tmp/spoke.cert"
            )
            cert_b64 = hub.succeed("base64 -w0 /tmp/spoke.cert").strip()
            node.succeed(f"echo {cert_b64} | base64 -d > /var/lib/wayfinder/node.cert")
            anchor_b64 = hub.succeed(
                "base64 -w0 /var/lib/wayfinder/trust-anchor"
            ).strip()
            node.succeed(f"echo {anchor_b64} | base64 -d > /var/lib/wayfinder/trust-anchor")
            # Readable by the `wayfinder` user the unit runs as (written here
            # as root, over the test driver's shell channel).
            node.succeed(
                "chown wayfinder:wayfinder /var/lib/wayfinder/identity.seed "
                "/var/lib/wayfinder/node.cert /var/lib/wayfinder/trust-anchor"
            )

            # The real thing under test starts here: a genuine RPC to the hub
            # that mints a Headscale credential, followed by a real
            # `tailscale up` — not `--print-command`, unlike ca-provider.nix,
            # which deliberately stops short of it because *its* subject is
            # the RPC, not the tunnel. Here the tunnel is the subject.
            node.succeed(
                f"wayfinder-ctl --connect hub:7700 --node-key {hub_key} "
                "--identity /var/lib/wayfinder/identity.seed "
                "--cert /var/lib/wayfinder/node.cert vpn enrollment"
            )
            node.wait_until_succeeds("tailscale ip -4 | grep -q '^100\\.'", timeout=60)

    for name, node in [("spokeA", spokeA), ("spokeB", spokeB)]:
        with subtest(f"{name}'s mesh link comes up over the tunnel"):
            # This is the config the module could not have rendered — see the
            # top comment. `wayfinder.service`'s `ExecStart` was overridden to
            # always read this path, so writing it here and starting the
            # module's own unit is enough; no separate unit is needed.
            #
            # `discovery_addr` names only the Tailscale-assigned address of
            # the hub, never the shared vlan's own IP — this link has no
            # other way to reach a peer, which is what makes convergence
            # below real evidence the tunnel carried it.
            # `auth` is what signs this node's own outgoing OGMs — omitting it
            # was an earlier bug in this test, not a product one: the spoke
            # still emitted OGMs, just unsigned ones, which the hub (which
            # *does* have auth configured, hence a trust anchor) silently
            # dropped with "missing signature TVLV". No amount of tunnel
            # connectivity fixes a peer that isn't sending an OGM the other
            # side will accept.
            config = (
                '{"server":{"type":"Tls","addr":"0.0.0.0:7700",'
                '"identity_seed_path":"/var/lib/wayfinder/identity.seed"},'
                '"auth":{"seed_path":"/var/lib/wayfinder/identity.seed",'
                '"cert_path":"/var/lib/wayfinder/node.cert",'
                '"trust_anchor_path":"/var/lib/wayfinder/trust-anchor"},'
                '"mac_state_path":"/var/lib/wayfinder/node.mac",'
                '"runtime_state_path":"/var/lib/wayfinder/settings.json",'
                '"links":[{"type":"UdpMulti","bind_addr":"0.0.0.0:6000",'
                f'"discovery_addr":"{hub_ts_ip}:6000"}}]}}'
            )
            node.succeed(f"cat > /var/lib/wayfinder/config.json <<'CFGEOF'\n{config}\nCFGEOF")
            node.succeed("chown wayfinder:wayfinder /var/lib/wayfinder/config.json")
            node.succeed("systemctl start wayfinder.service")
            node.wait_for_unit("wayfinder.service")
            node.wait_for_open_port(7700, timeout=30)

    with subtest("the two spokes converge on each other's routes — the actual gate"):
        def node_mac(node):
            out = node.succeed(
                "wayfinder-ctl --connect 127.0.0.1:7700 "
                "--identity /var/lib/wayfinder/identity.seed node-info"
            )
            # First line is "node xx:xx:xx:xx:xx:xx".
            return out.splitlines()[0].split()[1]

        spokeA_mac = node_mac(spokeA)
        spokeB_mac = node_mac(spokeB)

        # Polled, not slept for a fixed time: convergence happens on the
        # Trickle schedule, not instantly.
        spokeA.wait_until_succeeds(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            "--identity /var/lib/wayfinder/identity.seed routes "
            f"| grep -qi '{spokeB_mac}'",
            timeout=120,
        )
        spokeB.wait_until_succeeds(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            "--identity /var/lib/wayfinder/identity.seed routes "
            f"| grep -qi '{spokeA_mac}'",
            timeout=120,
        )

    with subtest("revoking a spoke's registration takes its node off the tunnel"):
        # The regression this exists for (#27): `revoke` deleted only the
        # per-MAC Headscale *user*, on the reasoning that this takes the node's
        # registrations with it. It does not — `enroll` tags every key it mints
        # and Headscale reassigns a tagged node to the synthetic
        # `tagged-devices` user, so the registered node is not the MAC user's to
        # delete. Headscale answered success, the RPC logged "revoked a VPN
        # registration", and the node kept its tunnel.
        #
        # It could only show against a *registered* node, and this is the only
        # test in the repo where a real `tailscaled` has registered one:
        # `ca-provider.nix` revokes a MAC that never spent its key (no
        # tailscaled — it serves headscale over plain HTTP, which a tailscaled
        # refuses outright), and `headscale_live.rs` does the same. Both passed
        # throughout.
        def registered_ips():
            # `headscale nodes list -o json` prints snake_case, unlike the
            # camelCase protojson the REST API serves the coordinator; accept
            # either rather than pinning the CLI's rendering, which is not what
            # is under test here.
            nodes = json.loads(hub.succeed("headscale nodes list -o json")) or []
            return {
                ip
                for n in nodes
                for ip in (n.get("ip_addresses") or n.get("ipAddresses") or [])
            }

        spokeB_ts_ip = spokeB.succeed("tailscale ip -4").strip()
        spokeA_ts_ip = spokeA.succeed("tailscale ip -4").strip()
        before = registered_ips()
        assert spokeB_ts_ip in before, (
            f"spokeB ({spokeB_ts_ip}) is not registered to begin with: {before}"
        )

        # The VPN half alone, not `provider revoke` — mesh membership is a
        # separate gate, and leaving it in place keeps this subtest about the
        # tunnel. The hub asks its own management API with its own seed, which
        # reaches `GrantedSelfKey`; that tier is admitted to `RevokeVpnPeer`.
        hub.succeed(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            "--identity /var/lib/wayfinder/identity.seed "
            "--cert /var/lib/wayfinder/node.cert "
            f"provider vpn revoke --mac {spokeB_mac}"
        )

        after = registered_ips()
        assert spokeB_ts_ip not in after, (
            f"spokeB ({spokeB_ts_ip}) still holds a tunnel registration after "
            f"a successful revoke: {after}"
        )
        # Not a scorched-earth delete: revoking one peer must leave every other
        # tunnel standing, which is the failure mode a looser correlation would
        # trade this bug for.
        assert spokeA_ts_ip in after, (
            f"revoking spokeB took spokeA ({spokeA_ts_ip}) off the tunnel too: {after}"
        )
        assert hub_ts_ip in after, (
            f"revoking spokeB took the hub ({hub_ts_ip}) off the tunnel too: {after}"
        )

        # And the tunnel itself, not only the coordination server's bookkeeping:
        # spokeA is still on it, so its peer list is where a node that was
        # really removed disappears from. Polled — Headscale pushes the map
        # update, but not synchronously with the REST call above.
        #
        # Written as two commands rather than `! tailscale status | grep`: in a
        # pipeline the negation applies to `grep`'s status alone, so a
        # `tailscale` that failed outright would pass this as "the peer is
        # gone". The redirect makes tailscale's own success a precondition.
        spokeA.wait_until_succeeds(
            "tailscale status --json > /tmp/ts-status.json && "
            f"! grep -q '{spokeB_ts_ip}' /tmp/ts-status.json",
            timeout=120,
        )

        # Idempotent, and through a branch the earlier revoke did not reach:
        # the user is gone *and* so is the node. This is the retry
        # `half_completed_revoke_message` tells an operator to run.
        hub.succeed(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            "--identity /var/lib/wayfinder/identity.seed "
            "--cert /var/lib/wayfinder/node.cert "
            f"provider vpn revoke --mac {spokeB_mac}"
        )
  '';
}
