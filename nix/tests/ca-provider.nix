# The cloud certificate authority, end to end, in a VM — no cloud account and
# no hardware needed.
#
# It exercises the posture `nix/machines/wayfinder-ca` deploys and
# `infra/oracle/` provisions for: a `wayfinder-tap` node with **no local egress
# and no mesh links**, running in provider mode. Each assertion below is
# something that has silently broken before, or that would break silently:
#
#  1. Such a node starts at all. `wayfinder-tap` used to refuse a config with
#     no `local_egress` — which is exactly the config a CA wants, since it has
#     no host traffic to bridge and, on a cloud host, no CAP_NET_ADMIN or
#     /dev/net/tun to build a TAP with even if it did.
#  2. It runs **unprivileged**. `nix/modules/wayfinder.nix` derives
#     `rawNetworkAccess` from the configured carriers, so a node with none must
#     end up with an empty capability set. A regression here fails nothing
#     visibly — it just quietly hands CAP_NET_RAW to an internet-facing process
#     holding the mesh root key.
#  3. A full enrollment cycle works: `csr request` at the node, `csr submit` to
#     the CA, `csr approve` by an operator, collect, `csr install` back at the
#     node. That is the entire reason the box exists.
#  4. The issued-certificate log survives a restart. It is what the
#     impersonation guard and every future revocation are built on; an
#     ephemeral one makes this box a root of trust with amnesia.
#
# The mesh identity is minted inside the VM at runtime rather than baked into a
# store path: a build-time certificate would be cached and would eventually
# expire, failing this test for a reason that has nothing to do with the code.
{ testers, lib }:
testers.nixosTest {
  name = "wayfinder-ca-provider";

  nodes = {
    # The certificate authority: the cloud posture.
    ca =
      { ... }:
      {
        imports = [ ../modules/wayfinder.nix ];

        services.wayfinder = {
          enable = true;
          config = {
            # No `local_egress` and no `links`. That is the whole point.
            server = {
              type = "Tls";
              addr = "0.0.0.0:7700";
            };
            auth = {
              seed_path = "/var/lib/wayfinder-secrets/identity.seed";
              cert_path = "/var/lib/wayfinder-secrets/node.cert";
              trust_anchor_path = "/var/lib/wayfinder-secrets/trust-anchor";
            };
            provider = {
              root_seed_path = "/var/lib/wayfinder-secrets/root.seed";
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
        ca.succeed("install -d -m 0700 -o wayfinder -g wayfinder /var/lib/wayfinder-secrets")
        ca.succeed(
            "wayfinder-ctl cert init-ca --mesh-id 0x5741594e --generate "
            "--out-seed /var/lib/wayfinder-secrets/root.seed "
            "--out-anchor /var/lib/wayfinder-secrets/trust-anchor"
        )
        ca.succeed(
            "wayfinder-ctl cert keygen --out-seed /var/lib/wayfinder-secrets/identity.seed"
        )
        now = int(ca.succeed("date +%s").strip())
        ca.succeed(
            "wayfinder-ctl cert issue "
            "--ca-seed /var/lib/wayfinder-secrets/root.seed --mesh-id 0x5741594e "
            "--node-seed /var/lib/wayfinder-secrets/identity.seed "
            f"--not-before {now - 60} --not-after {now + 31536000} "
            "--admin --out-cert /var/lib/wayfinder-secrets/node.cert"
        )
        ca.succeed("chown wayfinder:wayfinder /var/lib/wayfinder-secrets/*")
        ca.succeed("chmod 0400 /var/lib/wayfinder-secrets/*")

    with subtest("a node with no local egress and no links starts and serves"):
        ca.succeed("systemctl start wayfinder.service")
        ca.wait_for_unit("wayfinder.service")
        ca.wait_for_open_port(7700, timeout=30)
        ca.succeed("journalctl -u wayfinder | grep -q 'no local_egress configured'")
        ca.succeed(
            "journalctl -u wayfinder | grep -q 'certificate-authority (provider) mode enabled'"
        )

    with subtest("it runs with no network capabilities at all"):
        # Not merely "fewer than before": the effective, permitted and bounding
        # sets must all be empty. A CA opens one TCP listener as an ordinary
        # user and has no business being able to touch a network device.
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
            "--identity /var/lib/wayfinder-secrets/identity.seed "
            "--cert /var/lib/wayfinder-secrets/node.cert node-info"
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
            "--identity /var/lib/wayfinder-secrets/identity.seed "
            "csr submit --request /tmp/req.json "
            "--out-cert /tmp/node.cert --out-anchor /tmp/anchor || true"
        )
        ca.succeed("test ! -e /tmp/node.cert")

        ca.succeed(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            "--identity /var/lib/wayfinder-secrets/identity.seed "
            "--cert /var/lib/wayfinder-secrets/node.cert "
            f"csr approve --mac {node_mac}"
        )

        # Re-submitting the same CSR is how an issued certificate is collected;
        # the management protocol has no separate "fetch my certificate" call.
        ca.succeed(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            "--identity /var/lib/wayfinder-secrets/identity.seed "
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

    with subtest("the issued-certificate log survives a CA restart"):
        ca.succeed("systemctl restart wayfinder.service")
        ca.wait_for_open_port(7700, timeout=30)
        certs = ca.succeed(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            "--identity /var/lib/wayfinder-secrets/identity.seed "
            "--cert /var/lib/wayfinder-secrets/node.cert list-certs"
        )
        assert node_mac in certs, f"{node_mac} missing from the restarted CA's log:\n{certs}"
  '';
}
