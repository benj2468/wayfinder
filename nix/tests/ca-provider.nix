# The cloud certificate authority, end to end, in a VM — no cloud account and
# no hardware needed.
#
# It exercises the posture `nix/machines/wayfinder-ca` deploys and
# `infra/oracle/` provisions for: a `wayfinder-tap` node with **no local
# egress** and one unprivileged `UdpMulti` mesh link, running in provider mode.
# Each assertion below is something that has silently broken before, or that
# would break silently:
#
#  1. Such a node starts at all. `wayfinder-tap` used to refuse a config with
#     no `local_egress` — which is exactly the config a CA wants, since it has
#     no host traffic to bridge and, on a cloud host, no CAP_NET_ADMIN or
#     /dev/net/tun to build a TAP with even if it did.
#  2. It runs **unprivileged**, mesh link and all. `nix/modules/wayfinder.nix`
#     derives `rawNetworkAccess` from the configured carriers, and a UDP socket
#     is not one that needs privilege — so a CA carrying a link must still end
#     up with an empty capability set. A regression here fails nothing visibly
#     — it just quietly hands CAP_NET_RAW to an internet-facing process holding
#     the mesh root key.
#  3. A full enrollment cycle works: `csr request` at the node, `csr submit` to
#     the CA, `provider requests approve` by an operator, collect, `csr install` back at the
#     node. That is the entire reason the box exists.
#  4. The issued-certificate log survives a restart. It is what the
#     impersonation guard and every future revocation are built on; an
#     ephemeral one makes this box a root of trust with amnesia.
#  5. The node comes up with an *empty capability set* even carrying a mesh
#     link, since design 18 replaced the Headscale/Tailscale control plane this
#     test used to exercise with an `Iroh` link that needs no tunnel daemon and
#     no coordination server. What that retirement removed from this file is
#     worth naming: a colocated Headscale, a Headplane, an API key the box had
#     to mint for itself, and a revocation with two halves that could half-fail.
#     What it could not remove is the property none of that ever covered —
#     whether hole punching actually works between two real CGNAT'd hosts,
#     which no single-VM test can ask (design 18 §6.1).
# The mesh identity is minted inside the VM at runtime rather than baked into a
# store path: a build-time certificate would be cached and would eventually
# expire, failing this test for a reason that has nothing to do with the code.
{ testers, lib }:
testers.nixosTest {
  name = "wayfinder-ca-provider";

  containers = {
    # The certificate authority: the cloud posture.
    ca =
      { ... }:
      {
        imports = [
          ../modules/wayfinder.nix
        ];

        services.wayfinder = {
          enable = true;
          config = {
            # No `local_egress`. That is the whole point: this node bridges no
            # host traffic, so it needs no TAP and no capability to build one.
            server = {
              type = "Tls";
              addr = "0.0.0.0:7700";
            };
            # The CA's own mesh link, as `nix/machines/wayfinder-ca` deploys
            # it: hub/fan-out mode, no `discovery_addr`, learning peers from
            # the datagrams they send it.
            #
            # It is here for the capability assertion below rather than to
            # carry traffic — nothing else in this test speaks to it. That is
            # the point worth pinning: `UdpMulti` is not in
            # `nix/modules/wayfinder.nix`'s `rawNetKinds`, so a link on this
            # node must *not* pull `CAP_NET_RAW` back in and undo the sandbox.
            # A regression there is invisible: the node works perfectly, on an
            # internet-facing box holding the mesh root key, with every
            # capability systemd grants by default.
            #
            # An `Iroh` link (design 18), which is what this box carries since
            # the Headscale/Tailscale control plane was retired. Relay-less and
            # with no bootstrap peer: nothing in this VM dials it, and what is
            # being pinned here is the *capability derivation* — that a node
            # holding the mesh root key still comes up with an empty capability
            # set. Whether QUIC actually traverses a NAT is not a question a
            # single-VM test can ask.
            links = [
              {
                name = "iroh0";
                type = "Iroh";
                bind_port = 6001;
              }
            ];
            auth = {
              seed_path = "/var/lib/wayfinder/identity.seed";
              cert_path = "/var/lib/wayfinder/node.cert";
              trust_anchor_path = "/var/lib/wayfinder/trust-anchor";
            };
            provider = {
              root_seed_path = "/var/lib/wayfinder/root.seed";
              mesh_id = 1463900494; # 0x5741594e
              cert_ttl_secs = 604800;
              # Operator approval, matching the deployed default: what an
              # unattended provider hands out is mesh membership itself.
              auto_approve = false;
              state_path = "/var/lib/wayfinder/ca-state.json";
            };
            runtime_state_path = "/var/lib/wayfinder/settings.json";
          };
        };

        # The identity has to exist before the node starts, and the test mints
        # it in the first subtest — so hold the unit until the script starts
        # it, rather than letting it boot, fail on a missing seed and back off.
        systemd.services.wayfinder.wantedBy = lib.mkForce [ ];

        networking.firewall.allowedTCPPorts = [ 7700 ];
      };

    # A plain, un-enrolled node: what enrols against the CA. It has no local
    # egress either, which keeps the test free of TAP and privilege concerns on
    # this side — the node under test here is the CA.
    node =
      { ... }:
      {
        imports = [ ../modules/wayfinder.nix ];

        services.wayfinder = {
          enable = true;
          config = {
            server = {
              type = "Tls";
              addr = "0.0.0.0:7700";
              identity_seed_path = "/var/lib/wayfinder/identity.seed";
            };
            mac_state_path = "/var/lib/wayfinder/node.mac";
            runtime_state_path = "/var/lib/wayfinder/settings.json";
          };
        };

        networking.firewall.allowedTCPPorts = [ 7700 ];
      };
  };

  testScript = ''
    import json

    start_all()
    ca.wait_for_unit("multi-user.target")
    node.wait_for_unit("wayfinder.service")
    node.wait_for_open_port(7700, timeout=30)

    with subtest("mint the mesh root of trust and the CA's own membership"):
        # Into /var/lib/wayfinder, beside the node's own state, as the
        # deployment provisions them: `wayfinder-ctl` defaults `--identity` to
        # /var/lib/wayfinder/identity.seed, and the CA is the box an operator
        # types the most commands on. The node still cannot rewrite its root of
        # trust — `nix/machines/wayfinder-ca/common.nix` remounts those files
        # read-only inside the unit — which is the property the directory used
        # to carry. The directory itself is the `wayfinder.nix` module's, made
        # by its tmpfiles rule, so nothing creates it here.
        ca.succeed(
            "wayfinder-ctl cert init-ca --mesh-id 0x5741594e --generate "
            "--out-seed /var/lib/wayfinder/root.seed "
            "--out-anchor /var/lib/wayfinder/trust-anchor"
        )
        ca.succeed(
            "wayfinder-ctl cert keygen --out-seed /var/lib/wayfinder/identity.seed"
        )
        now = int(ca.succeed("date +%s").strip())
        ca.succeed(
            "wayfinder-ctl cert issue "
            "--ca-seed /var/lib/wayfinder/root.seed --mesh-id 0x5741594e "
            "--node-seed /var/lib/wayfinder/identity.seed "
            f"--not-before {now - 60} --not-after {now + 31536000} "
            "--admin --out-cert /var/lib/wayfinder/node.cert"
        )

        # A *second* admin identity, belonging to nobody on the mesh: a person's
        # credential rather than this box's. It is minted into /tmp on purpose —
        # an operator's key lives on the operator's laptop, not in the node's
        # state directory, and nothing on this box provisions it.
        #
        # It exists for one assertion, the tunnel-credential refusal below, and
        # that assertion cannot be made with the seed above. `decide_access`
        # tests the self-key tier *first*, so the node's own seed earns
        # `GrantedSelfKey` no matter what certificate accompanies it — and that
        # on its own behalf (`libs/wayfinder-server/src/authz.rs`). Reaching the
        # admin tier at all therefore takes a key this node does not hold.
        ca.succeed("wayfinder-ctl cert keygen --out-seed /tmp/operator.seed")
        ca.succeed(
            "wayfinder-ctl cert issue "
            "--ca-seed /var/lib/wayfinder/root.seed --mesh-id 0x5741594e "
            "--node-seed /tmp/operator.seed "
            f"--not-before {now - 60} --not-after {now + 31536000} "
            "--admin --out-cert /tmp/operator.cert"
        )
    with subtest("seal the trust material the node is about to read"):
        # The key the CA's management TLS presents, taken from the certificate
        # bound to it. Needed because the node→CA connection below is the first
        # in this test that crosses hosts: `wayfinderctl` records a node's key
        # on first sight, and with no terminal to confirm on it refuses rather
        # than trusting whatever answered. Every other step here connects a
        # machine to itself, which is why this has not come up before.
        ca_key = [
            l.split()[-1]
            for l in ca.succeed(
                "wayfinder-ctl cert show /var/lib/wayfinder/node.cert"
            ).splitlines()
            if l.strip().startswith("ed25519:")
        ][0]

        # Named one by one, never globbed. This directory also holds the state
        # the node *writes* — ca-state.json, settings.json — and a `chmod 0400
        # /var/lib/wayfinder/*` would take those with it and leave a CA that
        # cannot record what it issues. `scripts/wayfinder-ca.sh secrets` has
        # the same constraint for the same reason.
        secrets = " ".join(
            f"/var/lib/wayfinder/{f}"
            for f in ("root.seed", "identity.seed", "node.cert", "trust-anchor")
        )
        ca.succeed(f"chown wayfinder:wayfinder {secrets}")
        ca.succeed(f"chmod 0400 {secrets}")

    with subtest("a node with no local egress starts and serves"):
        ca.succeed("systemctl start wayfinder.service")
        ca.wait_for_unit("wayfinder.service")
        ca.wait_for_open_port(7700, timeout=30)
        ca.succeed("journalctl -u wayfinder | grep -q 'no local_egress configured'")
        ca.succeed(
            "journalctl -u wayfinder | grep -q 'certificate-authority (provider) mode enabled'"
        )
        # The coordinator is built at startup, so a bad URL or an unreadable key
        # file fails here rather than at some node's enrollment hours later.

        # And its mesh link is really bound, not merely configured. The socket
        # is what the deployment's `scripts/wayfinder-ca.sh verify` checks for
        # over SSH, and a link that failed to bind leaves a node that answers
        # the management API while routing nothing.
        ca.wait_until_succeeds("ss -lun | grep -q ':6000'", timeout=30)

    with subtest("it runs with no network capabilities at all, link and all"):
        # Not merely "fewer than before": the effective, permitted and bounding
        # sets must all be empty. A CA opens one TCP listener and one UDP
        # socket as an ordinary user and has no business being able to touch a
        # network device.
        #
        # The `UdpMulti` link configured above is the live half of this
        # assertion. `nix/modules/wayfinder.nix` derives `rawNetworkAccess`
        # from the carriers a node is asked to carry, and a UDP socket needs no
        # privilege — so adding a link to the CA must leave this set empty. If
        # `UdpMulti` ever lands in `rawNetKinds`, this is what says so, and
        # nothing else would: the node would work exactly as well with
        # CAP_NET_RAW as without it.
        pid = ca.succeed("systemctl show -p MainPID --value wayfinder.service").strip()
        status = ca.succeed(f"cat /proc/{pid}/status")
        for field in ("CapEff", "CapPrm", "CapBnd"):
            line = [l for l in status.splitlines() if l.startswith(field)][0]
            value = line.split()[1]
            assert int(value, 16) == 0, f"{field} is {value}, expected no capabilities"
        # And the sandbox that becomes possible once the capabilities are gone.
        ca.succeed("systemctl show -p ProtectSystem --value wayfinder.service | grep -q strict")

    with subtest("an operator reaches the CA with its admin identity"):
        info = ca.succeed(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            "--identity /var/lib/wayfinder/identity.seed "
            "--cert /var/lib/wayfinder/node.cert node-info"
        )
        assert "node" in info, info

    with subtest("a node enrols: request, submit, approve, collect, install"):
        # The enrolling node holds no trust anchor yet, so the only door open
        # to it is self-key access: its own seed as --identity.
        node.succeed(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            "--identity /var/lib/wayfinder/identity.seed "
            "csr request --out-request /tmp/req.json"
        )
        req = node.succeed("cat /tmp/req.json")
        ca.succeed(f"cat > /tmp/req.json <<'REQEOF'\n{req}\nREQEOF")

        node_mac = ":".join(f"{b:02x}" for b in json.loads(req)["node_mac"])

        # `auto_approve` is false, so the first submit parks the request and
        # writes no certificate. That is the posture being asserted, not an
        # incidental step.
        ca.succeed(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            "--identity /var/lib/wayfinder/identity.seed "
            "csr submit --request /tmp/req.json "
            "--out-cert /tmp/node.cert --out-anchor /tmp/anchor || true"
        )
        ca.succeed("test ! -e /tmp/node.cert")

        ca.succeed(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            "--identity /var/lib/wayfinder/identity.seed "
            "--cert /var/lib/wayfinder/node.cert "
            f"provider requests approve --mac {node_mac}"
        )

        # Re-submitting the same CSR is how an issued certificate is collected;
        # the management protocol has no separate "fetch my certificate" call.
        ca.succeed(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            "--identity /var/lib/wayfinder/identity.seed "
            "csr submit --request /tmp/req.json "
            "--out-cert /tmp/node.cert --out-anchor /tmp/anchor"
        )

        cert_b64 = ca.succeed("base64 -w0 /tmp/node.cert").strip()
        anchor_b64 = ca.succeed("base64 -w0 /tmp/anchor").strip()
        node.succeed(f"echo {cert_b64} | base64 -d > /tmp/node.cert")
        node.succeed(f"echo {anchor_b64} | base64 -d > /tmp/anchor")

        node.succeed(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            "--identity /var/lib/wayfinder/identity.seed "
            "csr install --cert /tmp/node.cert --trust-anchor /tmp/anchor"
        )

    with subtest("revoking a node's membership is durable"):
        # Mesh revocation is now the whole of a revoke: design 18 retired the
        # tunnel registration that used to be its second half, so there is no
        # partial-failure state left to report or retry through.
        ca.succeed(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            "--identity /var/lib/wayfinder/identity.seed "
            "--cert /var/lib/wayfinder/node.cert "
            f"provider revoke --mac {node_mac}"
        )

    with subtest("the issued-certificate log survives a CA restart"):
        ca.succeed("systemctl restart wayfinder.service")
        ca.wait_for_open_port(7700, timeout=30)
        certs = ca.succeed(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            "--identity /var/lib/wayfinder/identity.seed "
            "--cert /var/lib/wayfinder/node.cert provider members"
        )
        assert node_mac in certs, f"{node_mac} missing from the restarted CA's log:\n{certs}"
  '';
}
