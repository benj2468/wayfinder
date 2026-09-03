# The iroh data plane: three real `wayfinder-tap` nodes, three real QUIC
# endpoints, and mesh frames actually crossing them.
#
# The replacement for `vpn-data-plane.nix`, which did the same job for the
# Headscale/Tailscale tunnel design 18 retired. Same shape and the same gate —
# a hub and two spokes, converging on *each other's* routes rather than merely
# on the hub's — because that is the assertion that distinguishes "the link
# carries frames" from "the link came up".
#
# What this covers that no unit test can:
#
#  1. Three separate processes, three separate `Endpoint`s, real UDP between
#     real network namespaces. `libs/wayfinder-driver/src/iroh.rs`'s tests put
#     two endpoints in one process on loopback; they cannot catch a node that
#     binds the wrong address, is stopped by the firewall, or never gets its
#     config rendered.
#  2. **A node's iroh endpoint id is its mesh identity key.** The whole design
#     rests on it (design 18 §1) and nothing else asserts it end to end: the
#     hub's `cert keygen` output and the endpoint id in its own log are
#     compared byte for byte.
#  3. **Spoke-to-spoke convergence over a hub that only relays OGMs.** A spoke
#     bootstraps to the hub and to nothing else; hearing the *other* spoke at
#     all means the hub re-flooded its OGM and the mesh converged over iroh
#     links.
#  4. **A spoke dials the other spoke directly.** The certificate directory
#     (`AuthView`) resolves a MAC to the key of the node that owns it, so
#     spoke-to-spoke traffic does not transit the hub. This is the fix design
#     08 §9 said would need an OGM TVLV, and it is otherwise invisible.
#  5. **Revocation reaches the transport.** Revoking a spoke at the CA floods a
#     revocation, which lands in the other spoke's `AuthView`, which closes the
#     QUIC connection. Before that path existed the engine refused the revoked
#     node's frames while the carrier kept its socket open — routing denied,
#     connection not.
#
# **Nothing here reconfigures a running node through its filesystem.** A spoke
# boots on the config it ships with and everything after that is an RPC:
# `csr request`, `csr submit`, `provider requests approve`, `csr install`,
# `provider revoke`. That is the root `CLAUDE.md` rule — "would this command
# still work against a node with no filesystem?" — and it is load-bearing for
# this test in particular, because a spoke here *is* standing in for a board
# that has none. The hub is the one exception the rule already carves out: it
# is the CA, it cannot enrol with itself, and its four secret files are
# provisioned before it starts exactly as `nix/machines/wayfinder-ca` does.
#
# That is why a spoke's iroh link is in its *startup* config, with no `auth:`
# block beside it. The link boots **dormant**: a link's endpoint key *is* the
# node's identity, and a node that has not enrolled has none, so it binds
# nothing and dials nothing. `csr install` lands an identity through `SetAuth`,
# the driver republishes the `AuthView`, and the link binds and starts dialing —
# live, with no restart and nothing rewritten on disk.
#
# An earlier draft rewrote the config mid-test to add the link once an identity
# existed. That was the filesystem provisioning this rule forbids, and it hid
# the real defect: the link had no way to *wait*, so it either demanded an
# `auth:` block it could not have had yet or bound to a boot seed the node might
# never be certified under.
#
# What this deliberately does **not** cover, and cannot:
#
#  * **NAT traversal.** Every node here is on one flat VLAN with a routable
#    address, so hole punching is never exercised — there is no NAT to punch.
#    Whether two *real* CGNAT'd hosts hold a direct path is design 18 §6.1, and
#    it is not answerable in a VM, in CI, or anywhere but a real deployment.
#    A green run here says the data plane works; it says nothing about Starlink.
#  * **Relaying.** A relayed path needs a relay a node will *trust*, and
#    `iroh-relay`'s client defaults to the compiled-in Mozilla roots
#    (`CaTlsConfig::EmbeddedWebPki`) — a self-signed certificate in a VM is
#    refused, and the escape hatches are a `test-utils` feature or an
#    extra-roots knob `LinkTransport::Iroh` does not expose. So the last subtest
#    starts the relay and checks it *serves*, which catches a module that
#    renders an invalid config — the `wayfinder-headscale` empty-DERP-map class
#    of bug — and nothing more. A node using it is untested.
{
  testers,
  lib,
  pkgs,
}:
let
  # The mesh's UDP port for iroh. Pinned rather than ephemeral for the same
  # reason the deployment pins it: a spoke's bootstrap entry names a port, so
  # it has to be one known in advance.
  meshPort = 6001;

  meshId = "0x5741594e";

  # A spoke's whole configuration, rendered at build time and never touched
  # again — and note what is *not* in it: no `auth:` block, and **no key of any
  # kind**.
  #
  # `bootstrap_peers` is empty. The spoke learns where the authority is from
  # `SetAuth` at enrolment (`csr install --ca-endpoint`), which is the only
  # moment it is told who the authority *is*, and the link dials what it was
  # told. So nothing here needs to know a key that will not exist until the hub
  # generates one at runtime — which is what a build-time constant was
  # standing in for, and why there is no longer one to go stale.
  spokeConfig = {
    server = {
      type = "Tls";
      addr = "0.0.0.0:7700";
      identity_seed_path = "/var/lib/wayfinder/identity.seed";
    };
    mac_state_path = "/var/lib/wayfinder/node.mac";
    runtime_state_path = "/var/lib/wayfinder/settings.json";
    links = [
      {
        name = "iroh0";
        type = "Iroh";
        bind_port = meshPort;
        # Empty: the authority's endpoint arrives over RPC at enrolment. A
        # configured peer is the fallback for a node provisioned entirely
        # offline, which never has that conversation — not the normal path.
        bootstrap_peers = [ ];
      }
    ];
  };

  mkSpoke =
    { ... }:
    {
      imports = [ ../modules/wayfinder.nix ];
      networking.firewall.allowedUDPPorts = [ meshPort ];
      networking.firewall.allowedTCPPorts = [ 7700 ];
      services.wayfinder = {
        enable = true;
        config = spokeConfig;
      };
    };

in
testers.nixosTest {
  name = "wayfinder-iroh-data-plane";

  nodes = {
    # Declared first, so the test framework gives it 192.168.1.1 — but the
    # script reads the address rather than assuming it.
    hub =
      { ... }:
      {
        imports = [ ../modules/wayfinder.nix ];
        networking.firewall.allowedUDPPorts = [ meshPort ];

        # The relay, in the posture a VM can actually run: plain HTTP, which
        # the module warns about because it turns QUIC address discovery off.
        # Correct *here* and only here — nothing in this test uses it as a
        # relay (see the header), and asking for ACME in a VM would fail at the
        # challenge rather than testing anything.
        services.wayfinder-iroh-relay = {
          enable = true;
          hostname = "hub";
          tls.mode = "disabled";
          httpBindAddr = "[::]:3340";
        };

        services.wayfinder = {
          enable = true;
          config = {
            server = {
              type = "Tls";
              addr = "0.0.0.0:7700";
            };
            # Unlike a spoke, the CA *is* provisioned by file — it holds the
            # root of trust, which has to exist before anything can be issued
            # against it, and it cannot enrol with itself.
            auth = {
              seed_path = "/var/lib/wayfinder/identity.seed";
              cert_path = "/var/lib/wayfinder/node.cert";
              trust_anchor_path = "/var/lib/wayfinder/trust-anchor";
            };
            mac_state_path = "/var/lib/wayfinder/node.mac";
            runtime_state_path = "/var/lib/wayfinder/settings.json";
            # No bootstrap peers: this is the hub. Every spoke names *it*, and
            # connects inbound; a hub that dialled back would need the peer
            # list adopting iroh exists to delete.
            links = [
              {
                name = "iroh0";
                type = "Iroh";
                bind_port = meshPort;
                bootstrap_peers = [ ];
              }
            ];
            provider = {
              root_seed_path = "/var/lib/wayfinder/root.seed";
              mesh_id = 1463900494; # 0x5741594e
              cert_ttl_secs = 604800;
              auto_approve = false;
              state_path = "/var/lib/wayfinder/ca-state.json";
            };
          };
        };

        # Held back so the script can mint the root of trust and this node's
        # own certificate first — its `auth:` block names files that do not
        # exist until then. The spokes need no such treatment: they boot on
        # their shipped config and enrol afterwards.
        systemd.services.wayfinder.wantedBy = lib.mkForce [ ];
        networking.firewall.allowedTCPPorts = [ 7700 ];
      };

    spokeA = mkSpoke;
    spokeB = mkSpoke;
  };

  testScript = ''
    import json

    start_all()
    for node in (hub, spokeA, spokeB):
        node.wait_for_unit("multi-user.target")

    STATE = "/var/lib/wayfinder"
    # Well inside the certificate window the CA issues, and far from any
    # boundary a slow VM could drift across.
    NOT_BEFORE = 1000000000
    NOT_AFTER = 4000000000


    def ed25519_of(output):
        """The `ed25519: <hex>` line `cert keygen`/`cert issue`/`cert show` print.

        That hex *is* the node's iroh endpoint id — `iroh_base::PublicKey`
        Displays as lowercase hex of the same 32 bytes — which is the premise
        this test exists to check.
        """
        for line in output.splitlines():
            # `cert show` also prints `root ed25519:` for a trust anchor, which
            # `startswith` correctly does not match.
            if line.strip().startswith("ed25519:"):
                return line.split(":", 1)[1].strip()
        raise AssertionError(f"no ed25519 line in: {output}")


    with subtest("provision the hub: it is the CA and cannot enrol with itself"):
        # The one node provisioned by file, and the same one
        # `nix/machines/wayfinder-ca` provisions by file: the root of trust has
        # to exist before anything can be issued against it. Every *other* node
        # here joins over RPC — see the enrolment subtest.
        #
        # Done before the unit starts, so this is provisioning rather than
        # reconfiguring something already running.
        hub_key = ed25519_of(
            hub.succeed(f"wayfinder-ctl cert keygen --out-seed {STATE}/identity.seed")
        )
        hub.succeed(
            f"wayfinder-ctl cert init-ca --mesh-id ${meshId} --generate "
            f"--out-seed {STATE}/root.seed --out-anchor {STATE}/trust-anchor"
        )
        issued = hub.succeed(
            "wayfinder-ctl cert issue "
            f"--ca-seed {STATE}/root.seed --mesh-id ${meshId} "
            f"--node-seed {STATE}/identity.seed "
            f"--not-before {NOT_BEFORE} --not-after {NOT_AFTER} "
            f"--out-cert {STATE}/node.cert"
        )
        hub.succeed(f"chown -R wayfinder:wayfinder {STATE}")

        # The certificate the hub will run under names the key it generated —
        # nothing here was pinned in advance, so there is no constant to go
        # stale.
        assert ed25519_of(issued) == hub_key, (
            f"the hub's certificate does not name its own key\n"
            f"  identity: {hub_key}\n  certificate: {ed25519_of(issued)}"
        )

        hub.succeed("systemctl start wayfinder.service")
        hub.wait_for_unit("wayfinder.service")
        hub.wait_for_open_port(7700, timeout=60)

    with subtest("the hub's iroh endpoint id is its identity key"):
        # The premise of the whole design, asserted rather than assumed: the key
        # peers dial is the key the certificate binds. A mismatch would mean
        # every `bootstrap_peers` entry an operator copies out of a certificate
        # names an endpoint nobody answers on.
        hub.wait_until_succeeds(
            "journalctl -u wayfinder | grep -q 'iroh mesh link bound'", timeout=60
        )
        bound = hub.succeed("journalctl -u wayfinder | grep 'iroh mesh link bound'")
        assert hub_key in bound, f"the endpoint id is not the identity key: {bound}"

        # Read, not assumed: it is handed to each spoke at enrolment.
        hub_ip = hub.succeed(
            "ip -4 -o addr show dev eth1 | awk '{print $4}' | cut -d/ -f1"
        ).strip()

    with subtest("it runs with no network capabilities, iroh link and all"):
        # An `Iroh` link is not in `nix/modules/wayfinder.nix`'s `rawNetKinds`,
        # so it must not pull `CAP_NET_RAW` back in and undo the sandbox. A
        # regression here is invisible: the node works perfectly, on a box
        # holding the mesh root key, with every capability systemd grants by
        # default.
        caps = hub.succeed(
            "systemctl show -p AmbientCapabilities --value wayfinder.service"
        ).strip()
        assert caps == "", f"an iroh link brought capabilities back: {caps!r}"

    with subtest("a spoke's link is dormant until it has enrolled"):
        # The property that makes an all-RPC enrolment possible. A spoke ships
        # with an iroh link and no identity, so the link binds nothing and dials
        # nothing — it says so and carries on. The node is still up and still
        # reachable over its management API, which is what enrolment needs.
        for node in (spokeA, spokeB):
            node.wait_for_unit("wayfinder.service")
            node.wait_for_open_port(7700, timeout=60)
            node.wait_until_succeeds(
                "journalctl -u wayfinder | grep -q 'iroh mesh link is dormant'", timeout=60
            )
            node.fail("journalctl -u wayfinder | grep -q 'iroh mesh link bound'")


    def node_mac(node):
        out = node.succeed(
            f"wayfinder-ctl --connect 127.0.0.1:7700 --identity {STATE}/identity.seed node-info"
        )
        # First line is "node xx:xx:xx:xx:xx:xx".
        return out.splitlines()[0].split()[1]


    macs = {"hub": node_mac(hub)}
    keys = {"hub": hub_key}

    for name, node in (("spokeA", spokeA), ("spokeB", spokeB)):
        with subtest(f"{name} enrols with the hub — entirely over RPC"):
            # Nothing below writes a file the *node* reads. `csr request` and
            # `csr install` are RPCs to the local node; `csr submit` and
            # `provider requests approve` are RPCs to the hub. The certificate
            # lands in the runtime settings store through `SetAuth`, which is
            # what makes this work against a node with no filesystem.
            node.succeed(
                "wayfinder-ctl --connect 127.0.0.1:7700 "
                f"--identity {STATE}/identity.seed "
                "csr request --out-request /tmp/req.json"
            )
            req = node.succeed("cat /tmp/req.json")
            hub.succeed(f"cat > /tmp/{name}-req.json <<'REQEOF'\n{req}\nREQEOF")
            macs[name] = ":".join(f"{b:02x}" for b in json.loads(req)["node_mac"])
            keys[name] = bytes(json.loads(req)["ed_pubkey"]).hex()

            # `auto_approve` is false on the hub, matching the deployed default,
            # so the first submit parks the request and issues nothing.
            hub.succeed(
                "wayfinder-ctl --connect 127.0.0.1:7700 "
                f"--identity {STATE}/identity.seed "
                f"csr submit --request /tmp/{name}-req.json "
                f"--out-cert /tmp/{name}.cert --out-anchor /tmp/{name}.anchor || true"
            )
            hub.succeed(f"test ! -e /tmp/{name}.cert")

            hub.succeed(
                "wayfinder-ctl --connect 127.0.0.1:7700 "
                f"--identity {STATE}/identity.seed --cert {STATE}/node.cert "
                f"provider requests approve --mac {macs[name]}"
            )
            # Re-submitting the same CSR is how an issued certificate is
            # collected; the protocol has no separate "fetch mine" call.
            hub.succeed(
                "wayfinder-ctl --connect 127.0.0.1:7700 "
                f"--identity {STATE}/identity.seed "
                f"csr submit --request /tmp/{name}-req.json "
                f"--out-cert /tmp/{name}.cert --out-anchor /tmp/{name}.anchor"
            )

            # The operator carries the issued artifacts to the node's *operator
            # shell*, then installs them over the wire. `/tmp` here is the
            # operator's scratch space, never a path the node reads.
            cert_b64 = hub.succeed(f"base64 -w0 /tmp/{name}.cert").strip()
            anchor_b64 = hub.succeed(f"base64 -w0 /tmp/{name}.anchor").strip()
            node.succeed(f"echo {cert_b64} | base64 -d > /tmp/node.cert")
            node.succeed(f"echo {anchor_b64} | base64 -d > /tmp/anchor")
            # `--ca-endpoint` is the whole point of this subtest for the link:
            # the node is told where the authority lives on the *mesh*, over the
            # same RPC that installs its certificate. That is the only moment it
            # could be told, and it is why the spoke's config names no key.
            #
            # Both halves are values this operator already has: the key is the
            # one they pinned to reach the hub's management API, and the address
            # is where they reached it — on the mesh port rather than 7700.
            node.succeed(
                "wayfinder-ctl --connect 127.0.0.1:7700 "
                f"--identity {STATE}/identity.seed "
                "csr install --cert /tmp/node.cert --trust-anchor /tmp/anchor "
                f"--ca-endpoint {hub_key}@{hub_ip}:${toString meshPort}"
            )

            # `SetAuth` has landed, so the dormant link now has an identity.
            # It binds on the driver's next poll — no restart, and nothing on
            # disk changed — and the endpoint it takes is the key the
            # certificate binds, for a node whose identity was never a file it
            # read.
            node.wait_until_succeeds(
                "journalctl -u wayfinder | grep -q 'iroh mesh link bound'", timeout=120
            )
            bound = node.succeed("journalctl -u wayfinder | grep 'iroh mesh link bound'")
            assert keys[name] in bound, (
                f"{name}'s endpoint id is not the key its certificate binds\n"
                f"  certificate: {keys[name]}\n  log: {bound}"
            )

    with subtest("the hub learns both spokes"):
        for name in ("spokeA", "spokeB"):
            hub.wait_until_succeeds(
                "wayfinder-ctl --connect 127.0.0.1:7700 "
                f"--identity {STATE}/identity.seed routes | grep -qi '{macs[name]}'",
                timeout=180,
            )

    with subtest("the two spokes converge on each other's routes — the actual gate"):
        # Neither spoke was told anything about the other: each names only the
        # hub in `bootstrap_peers`. Reaching this means the hub re-flooded each
        # spoke's OGM out the interface it arrived on (design 08 Correction 7's
        # split-horizon removal), the far spoke verified it, and the mesh
        # converged — over iroh links, end to end.
        #
        # Polled rather than slept for: convergence happens on the Trickle
        # schedule, not instantly.
        spokeA.wait_until_succeeds(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            f"--identity {STATE}/identity.seed routes | grep -qi '{macs['spokeB']}'",
            timeout=180,
        )
        spokeB.wait_until_succeeds(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            f"--identity {STATE}/identity.seed routes | grep -qi '{macs['spokeA']}'",
            timeout=180,
        )

    with subtest("a spoke dials the other spoke directly, not through the hub"):
        # The certificate directory at work. A learned entry would map spokeB's
        # MAC to the *hub's* endpoint, since that is who relayed its OGM;
        # `AuthView` maps it to the key spokeB's own certificate binds, so the
        # connection is direct. Nothing in the management API surfaces path
        # state yet (design 18, phase 2d), so the node's own log is the
        # evidence — `IrohLink::adopt` names the peer it connected to.
        spokeA.wait_until_succeeds(
            "journalctl -u wayfinder | "
            f"grep -q 'iroh connection established.*{keys['spokeB'][:10]}'",
            timeout=180,
        )

    with subtest("revoking a spoke closes the connection to it"):
        # The full path, and the one that had no coverage at all before
        # `AuthView`: the CA signs and floods a revocation, spokeA's router
        # ingests it, the driver republishes the auth view without spokeB and
        # with its key marked stale, and `IrohLink::reconcile` closes the QUIC
        # connection. Routing *and* the socket, not just routing.
        hub.succeed(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            f"--identity {STATE}/identity.seed --cert {STATE}/node.cert "
            f"provider revoke --mac {macs['spokeB']}"
        )

        spokeA.wait_until_succeeds(
            "journalctl -u wayfinder | "
            f"grep -q 'closing iroh connection.*{keys['spokeB'][:10]}'",
            timeout=180,
        )
        # And the route goes with it, so the two halves agree.
        spokeA.wait_until_fails(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            f"--identity {STATE}/identity.seed routes | grep -qi '{macs['spokeB']}'",
            timeout=180,
        )

    with subtest("the relay module renders a config the relay actually starts on"):
        # Not a connectivity test — see the header for why a VM cannot have
        # one. What it catches is the class of bug `wayfinder-headscale.nix`
        # shipped through twice: a module that renders a configuration file the
        # daemon rejects, which builds perfectly and fails at runtime.
        hub.wait_for_unit("wayfinder-iroh-relay.service")
        hub.wait_for_open_port(3340, timeout=60)
  '';
}
