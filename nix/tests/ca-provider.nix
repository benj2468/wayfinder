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
#  5. The VPN half (`docs/design/implemented/08-internet-links-headscale-vpn.md`): the CA
#     colocates a real Headscale, an enrolled node exchanges its *certificate*
#     for a tunnel credential, and a mesh revocation takes the tunnel
#     registration with it. Three things here are only checkable against a real
#     coordination server, and all three were wrong on the first attempt:
#     Headscale scopes a preauth key to a numeric *user id* (not a name), it
#     refuses to start with an empty DERP map, and `reqwest` under
#     `rustls-no-provider` panics unless a process-wide crypto provider is
#     installed — a failure that would first appear at a node's enrollment, not
#     at the CA's startup.
#  6. The authorization boundary that makes the credential worth gating: an
#     operator's admin identity is *refused* the tunnel credential, because the
#     response is scoped to a device identity and an operator does not have
#     one. This is the property that keeps the design's two gates independent
#     rather than one gate handing out two artifacts. It takes an admin key
#     this box does not itself hold — the node's own seed is matched by the
#     self-key tier first, and that tier is admitted to the request by design,
#     since it is the node asking for its own credential.
#  7. The two secrets the box mints for itself, neither of which can be
#     provisioned the way the mesh trust material is: the Headscale API key the
#     node reads at start-up (owned by the node's user, kept across a re-run
#     rather than churned) and Headplane's cookie secret. Both fail at runtime
#     rather than at evaluation — a key owned by the minting side, or a cookie
#     secret of the wrong length, builds perfectly and then does not start.
#
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

        # The tunnel control plane, colocated with the mesh one — the topology
        # the design deploys, since this is the only box with a stable address.
        # `wayfinder-headscale.nix` is used rather than `services.headscale`
        # directly so the module's own defaults are what gets tested, in
        # particular the embedded DERP relay that replaces Tailscale Inc.'s
        # public map.
        services.wayfinder-headscale = {
          enable = true;
          domain = "ca";
          port = 8080;
          # Plain HTTP, which the module warns about and a real deployment must
          # not do — a `tailscaled` refuses a plaintext DERP connection and
          # loses STUN probing with it. Correct *here* and only here: nothing
          # in this test is a tailscaled. It exercises the control plane, which
          # is `curl` and a `reqwest` client and works identically either way,
          # and buys back a certificate this VM has no way to obtain.
          # `nix/tests/vpn-data-plane.nix` is where real clients meet real TLS.
          tls.mode = "none";
          # The break-glass admin UI, in the posture the deployment runs it in:
          # loopback-bound, reached by an SSH forward. Enabled here because
          # every one of its start-up requirements (a 32-character cookie
          # secret, a non-Secure cookie over plain HTTP, a headscale unit it
          # can order after) fails at runtime rather than at evaluation.
          headplane.enable = true;
        };

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
            # `nix/tests/vpn-data-plane.nix` is where this link shape actually
            # carries frames, over a real tunnel. There is no `tailscaled`
            # here: this CA serves plain HTTP (see the module block above), and
            # a `tailscaled` refuses a plaintext DERP connection outright — so
            # `selfJoin` belongs in that test, not this one.
            links = [
              {
                name = "vpn0";
                type = "UdpMulti";
                bind_addr = "0.0.0.0:6000";
              }
            ];
            auth = {
              seed_path = "/var/lib/wayfinder/identity.seed";
              # No cert_path, no trust_anchor_path: this node is the authority
              # for `mesh_id` below, so it derives both from `root_seed_path`
              # at startup. Asserted further down — the node must come up
              # authenticated with nothing but a root seed and an identity
              # seed on disk.
            };
            provider = {
              root_seed_path = "/var/lib/wayfinder/root.seed";
              mesh_id = 1463900494; # 0x5741594e
              cert_ttl_secs = 604800;
              # Operator approval, matching the deployed default: what an
              # unattended provider hands out is mesh membership itself.
              auto_approve = false;
              state_path = "/var/lib/wayfinder/ca-state.json";
              # VPN coordination. The API key is a *path*: it can mint tunnel
              # reachability, so it belongs in the same custody tier as the
              # mesh root seed, not inlined into a config that lands in the
              # world-readable Nix store. The test writes it at runtime, the
              # same way the deployment's secrets arrive out of band.
              headscale = {
                api_url = "http://127.0.0.1:8080";
                # Minted on the box by the module's bootstrap unit, not
                # provisioned out of band with the mesh trust material: an API
                # key is machine-generated state this host can recreate at
                # will, so it lives in headscale's own state directory rather
                # than beside the secrets an operator carries here.
                api_key_path = "/var/lib/wayfinder-headscale/api.key";
                login_server = "http://ca:8080";
                preauth_ttl_secs = 300;
              };
            };
            runtime_state_path = "/var/lib/wayfinder/settings.json";
            # The clock gate off, here and on `node` below, and *only* in this
            # test. The containers run under systemd-nspawn, whose seccomp
            # allowlist answers `adjtimex` with EPERM unless the container holds
            # CAP_SYS_TIME — so the node reads its NTP status as `unreadable`
            # and refuses every issuance, and enrollment fails with "the
            # authority has no usable clock". Letting the syscall through would
            # not help: the status word is the *host* kernel's, so the verdict
            # would track whatever the CI runner's own time daemon is doing, and
            # there is no NTP server in the sandbox to discipline it here.
            # Nothing below tests the gate itself; it is unit-tested in
            # `wayfinder-clock-trust`.
            require_time_sync = false;
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
            # See the CA's config: nspawn denies the NTP status read, and this
            # node installs the certificate it is issued.
            require_time_sync = false;
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
        # Two files, not four. The anchor and this node's own certificate are
        # both functions of the root seed, and a node in provider mode holds
        # that root — so it derives them at startup instead of being handed
        # copies. `--out-anchor` is still a required argument (an ordinary
        # member does need the file, and gets it from an operator or from
        # enrollment), so it is written to /tmp and left there: nothing on this
        # box reads it, and putting it in the state directory would re-create
        # exactly the provisioned copy this change removes. The enrolling node
        # below collects its anchor from the CA over the wire instead.
        ca.succeed(
            "wayfinder-ctl cert init-ca --mesh-id 0x5741594e --generate "
            "--out-seed /var/lib/wayfinder/root.seed "
            "--out-anchor /tmp/trust-anchor"
        )
        ca.succeed(
            "wayfinder-ctl cert keygen --out-seed /var/lib/wayfinder/identity.seed"
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
        # tier is admitted to `GetVpnEnrollment`, because it is the node asking
        # on its own behalf (`libs/wayfinder-server/src/authz.rs`). Reaching the
        # admin tier at all therefore takes a key this node does not hold.
        ca.succeed("wayfinder-ctl cert keygen --out-seed /tmp/operator.seed")
        now = int(ca.succeed("date +%s").strip())
        ca.succeed(
            "wayfinder-ctl cert issue "
            "--ca-seed /var/lib/wayfinder/root.seed --mesh-id 0x5741594e "
            "--node-seed /tmp/operator.seed "
            f"--not-before {now - 60} --not-after {now + 31536000} "
            "--admin --out-cert /tmp/operator.cert"
        )
    with subtest("the colocated coordination server comes up on its own relay"):
        # Headscale refuses to start with an empty DERP map, so this also
        # asserts that the module's embedded relay actually replaced Tailscale
        # Inc.'s default map rather than merely being switched on beside it.
        ca.wait_for_unit("headscale.service")
        ca.wait_for_open_port(8080, timeout=60)
        ca.succeed("curl -sf http://127.0.0.1:8080/health")

        # The embedded relay is serving, and its STUN socket is bound — which
        # is what lets two CGNAT'd nodes hole-punch instead of relaying every
        # packet through this box.
        ca.succeed("curl -sf http://127.0.0.1:8080/derp/probe")
        ca.succeed("ss -lun | grep -q ':3478'")

        # And Tailscale Inc.'s public DERP map was dropped rather than merely
        # supplemented. Asserted on the rendered config because that is where
        # the property lives: `urls` is what would send an 'isolated' mesh's
        # traffic through third-party infrastructure, and a runtime probe
        # cannot tell a map with one embedded region from a map that also has
        # the public ones.
        # The path comes from the unit rather than /etc: the nixpkgs module
        # writes only a CLI stub (socket path, update check) to
        # /etc/headscale/config.yaml and passes the real settings to the daemon
        # as a separate store path, so asserting on /etc reads an almost-empty
        # file and passes for the wrong reason.
        # Two hops to reach it. The unit's ExecStart is a *generated wrapper
        # script*, not `headscale serve --config <path>`, so the path is inside
        # that script rather than on the command line — and /etc/headscale
        # holds only a CLI stub (socket path, update check), which would pass
        # this assertion for the wrong reason.
        exec_start = ca.succeed("systemctl show -p ExecStart --value headscale.service")
        start_script = exec_start.split("path=")[1].split(";")[0].strip()
        config_path = ca.succeed(
            f"grep -oE -- '--config [^ ]+' {start_script} | head -1 | cut -d' ' -f2"
        ).strip()
        assert config_path, f"no --config found in the unit script {start_script}"
        derp_cfg = ca.succeed(f"cat {config_path}")
        assert "urls: []" in derp_cfg, (
            f"the public DERP map was not dropped:\n{derp_cfg}"
        )

    with subtest("the API key the CA mints tunnel credentials with is minted on the box"):
        # At runtime and never in the Nix store: a key that can grant network
        # reachability belongs in the same custody tier as the mesh trust
        # material. Unlike that material it is *not* carried here by an
        # operator — this host can recreate it against its own headscale
        # whenever it needs to, so the module mints it and the node only reads
        # it.
        key_path = "/var/lib/wayfinder-headscale/api.key"
        ca.wait_for_unit("wayfinder-headscale-apikey.service")
        key = ca.succeed(f"cat {key_path}").strip()
        assert key.startswith("hskey-api-"), f"unexpected API key shape: {key[:16]}"

        # Readable by the node's user and by nobody else. The node runs as
        # `wayfinder`, headscale as `headscale`, so a key left owned by the
        # minting side is a startup failure at the far end of a deploy.
        assert ca.succeed(f"stat -c '%U %a' {key_path}").strip() == "wayfinder 400", (
            ca.succeed(f"stat -c '%U:%G %a' {key_path}")
        )
        assert "/nix/store" not in ca.succeed(f"readlink -f {key_path}")

        # A key headscale actually honours, not merely a well-shaped string.
        ca.succeed(
            f"curl -sf -H 'Authorization: Bearer {key}' http://127.0.0.1:8080/api/v1/node"
        )

        # Re-running the unit keeps the key it already minted. This is the
        # property that makes it safe to run on every boot and on a timer: a
        # fresh key each time would leave the running node holding one that had
        # been superseded, and nothing would say so until an enrollment failed.
        ca.succeed("systemctl restart wayfinder-headscale-apikey.service")
        assert ca.succeed(f"cat {key_path}").strip() == key, "the bootstrap churned the key"

    with subtest("headplane is up, and reachable only from the box itself"):
        # Break-glass only (see the module header). The assertion is on the
        # bound socket rather than on a refused connection alone, because a
        # firewall rule would make an 0.0.0.0 bind *look* loopback-only from
        # another host while leaving it exposed the moment the rule changes.
        ca.wait_for_unit("headplane.service")
        ca.wait_for_open_port(3000, timeout=120)
        ca.succeed("ss -lnt | grep -q '127.0.0.1:3000'")
        ca.fail("ss -lnt | grep -qE '(0\\.0\\.0\\.0|\\*):3000'")
        node.fail("curl -sf --max-time 5 http://ca:3000/")

        # It answers, which is more than the unit being active proves:
        # headplane validates its configuration at startup and a rejected
        # config leaves a process that stays up and serves nothing.
        codes = [
            ca.succeed(
                f"curl -s -o /dev/null -w '%{{http_code}}' http://127.0.0.1:3000{path}"
            ).strip()
            for path in ("/admin", "/")
        ]
        assert any(c.startswith(("2", "3")) for c in codes), (
            f"headplane served no page: {codes}\n"
            + ca.succeed("journalctl -u headplane --no-pager | tail -40")
        )

        # The cookie secret is generated on the box for the same reason the API
        # key is, and it is exactly 32 bytes — headplane refuses to start on any
        # other length, so a wrong one fails the deploy rather than this test.
        secret = ca.succeed("cat /var/lib/headplane/cookie.secret")
        assert len(secret) == 32, f"cookie secret is {len(secret)} chars, expected 32"

        # Plain HTTP over an SSH forward: a Secure cookie is dropped by the
        # browser and the sign-in silently loops back to the login page.
        cfg = ca.succeed("cat /etc/headplane/config.yaml")
        assert "cookie_secure: false" in cfg, cfg

    with subtest("seal the trust material the node is about to read"):
        # The key the CA's management TLS presents, taken from the certificate
        # bound to it. Needed because the node→CA connection below is the first
        # in this test that crosses hosts: `wayfinderctl` records a node's key
        # on first sight, and with no terminal to confirm on it refuses rather
        # than trusting whatever answered. Every other step here connects a
        # machine to itself, which is why this has not come up before.
        # Read off the identity *seed*, because there is no certificate on
        # this box to read it off any more. `cert show` summarises a seed by
        # the public keys it derives and never by its own bytes, which is what
        # makes this safe to run on a secret.
        ca_key = [
            l.split()[-1]
            for l in ca.succeed(
                "wayfinder-ctl cert show /var/lib/wayfinder/identity.seed"
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
            for f in ("root.seed", "identity.seed")
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
        # The point of the two-file provisioning above: the node computed the
        # certificate and the anchor its `auth:` block does not name, and came
        # up an authenticated member of the mesh it signs for. Both lines
        # matter — deriving without enabling auth would be a silent
        # unauthenticated CA, which is the failure this asserts against.
        ca.succeed(
            "journalctl -u wayfinder | "
            "grep -q \"deriving this provider's own membership material\""
        )
        ca.succeed(
            "journalctl -u wayfinder | "
            "grep -q 'mesh authentication enabled (mesh_id = 0x5741594e)'"
        )
        # And nothing wrote them down: the derivation happens every start, so a
        # stale copy on disk cannot come to disagree with the root seed.
        ca.succeed("test ! -e /var/lib/wayfinder/node.cert")
        ca.succeed("test ! -e /var/lib/wayfinder/trust-anchor")
        # The coordinator is built at startup, so a bad URL or an unreadable key
        # file fails here rather than at some node's enrollment hours later.
        ca.succeed("journalctl -u wayfinder | grep -q 'VPN coordination enabled'")

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
            "--cert-from 127.0.0.1:7700 node-info"
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
        # The same MAC unseparated: the name a node's Headscale user carries,
        # which is what joins a tunnel peer back to a mesh identity without the
        # CA persisting a mapping of its own.
        node_mac_hex = "".join(f"{b:02x}" for b in json.loads(req)["node_mac"])

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
            "--cert-from 127.0.0.1:7700 "
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

        # `--unsafe-allow-untrustworthy-clock` for the reason the node configs
        # set `require_time_sync = false`: `csr install` stamps the operator's
        # clock onto the node, and inside nspawn nothing can vouch for it.
        node.succeed(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            "--identity /var/lib/wayfinder/identity.seed "
            "csr install --cert /tmp/node.cert --trust-anchor /tmp/anchor "
            "--unsafe-allow-untrustworthy-clock"
        )

    with subtest("an operator's admin identity is refused a tunnel credential"):
        # The boundary that makes the two gates independent. This identity is a
        # full admin — the same authority that approved the CSR above — and it
        # still cannot obtain a tunnel credential, because the credential is
        # scoped to a *device* identity and an operator's certificate is not
        # one. If this ever starts succeeding, holding the enrollment token
        # would be one step from holding network reachability.
        #
        # The operator seed minted at the top, not the node's own one every
        # other command here uses: `decide_access` matches the self-key tier
        # before it looks at any certificate, so this box's own seed never
        # reaches the admin tier to be refused from it. It earns
        # `GrantedSelfKey` — the node asking on its own behalf — which *is*
        # admitted to this request, and is how the CA joins the tunnel it
        # coordinates (`selfJoin`, exercised in `nix/tests/vpn-data-plane.nix`).
        # Asserting the refusal with that seed asserted the opposite of what it
        # said, and passed only while `tailscale up` was missing from this
        # container.
        #
        # `--node-key` is therefore explicit here, where it is defaulted
        # everywhere else: `wayfinder-ctl` falls back to the public half of
        # `--identity`, which is the right pin only when the identity *is* the
        # node's.
        #
        # `--print-command` stops at printing what it was given, so a regression
        # fails at the authorization gate rather than at a `tailscale up` that
        # would have failed anyway for want of a daemon.
        before = json.loads(ca.succeed("headscale users list -o json")) or []  # null when empty
        refusal = ca.fail(
            f"wayfinder-ctl --connect 127.0.0.1:7700 --node-key {ca_key} "
            "--identity /tmp/operator.seed "
            "--cert /tmp/operator.cert vpn enrollment --print-command 2>&1"
        )
        # The exact wording matters here, not just the refusal: keyed on the
        # tier alone, an admin used to be told its connection "is limited to
        # enrollment", which is false and points at the wrong fix. What it must
        # say instead is the distinction the refusal actually rests on — the
        # caller is a person and the credential names a device — because that
        # is the difference between "ask for more privilege" (there is none to
        # get) and "ask from the node".
        assert "a person, not a device" in refusal, refusal
        assert "limited to enrollment" not in refusal, refusal
        # And nothing was minted for it. A refusal that still created the user
        # (or the key) would be a refusal in the response only.
        after = json.loads(ca.succeed("headscale users list -o json")) or []
        assert [u["name"] for u in before] == [u["name"] for u in after], (
            f"a refused request still touched the coordination server: {before} -> {after}"
        )

    with subtest("an enrolled node exchanges its certificate for a tunnel credential"):
        # The node reconnects presenting the certificate it was just issued —
        # the only credential that reaches this request — and gets a single-use
        # key back. `--print-vpn-command` stops short of running `tailscale up`:
        # what is under test is wayfinder's half, and bringing a real tunnel up
        # inside a VM test would be testing Tailscale's.
        out = node.succeed(
            f"wayfinder-ctl --connect ca:7700 --node-key {ca_key} "
            "--identity /var/lib/wayfinder/identity.seed "
            "--cert /tmp/node.cert vpn enrollment --print-command 2>&1"
        )
        assert "--login-server=http://ca:8080" in out, out
        assert "--authkey=hskey-auth-" in out, out

        # The key is real: it exists at the coordination server and is scoped to
        # this node's own user, which is what makes the peer↔certificate join
        # work without the CA persisting a mapping. Headscale masks the key
        # value in this listing, so the assertion is on its existence and
        # properties, not its bytes.
        #
        # `or []` because Headscale renders an empty list as JSON `null`, and
        # `.get(..., False)` because it omits false-valued fields entirely —
        # both would otherwise fail this test for a reason unrelated to the
        # code under test.
        keys = [
            k
            for k in (json.loads(ca.succeed("headscale preauthkeys list -o json")) or [])
            if k.get("user", {}).get("name") == node_mac_hex
        ]
        assert len(keys) == 1, f"expected exactly one key for {node_mac_hex}: {keys}"
        assert not keys[0].get("reusable", False), "a tunnel credential must be single-use"
        assert not keys[0].get("used", False)

    with subtest("an operator sees the node listed as a VPN peer"):
        peers = ca.succeed(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            "--identity /var/lib/wayfinder/identity.seed "
            "--cert-from 127.0.0.1:7700 provider vpn list"
        )
        # No tailscaled has registered, so there is no *node* yet — the
        # assertion is that the call round-trips against the real API, which is
        # where a schema drift in Headscale's node representation surfaces.
        assert "VPN peer" in peers or "NODE" in peers, peers

    with subtest("revoking a node's membership takes its tunnel registration too"):
        # One operator action, both halves. The half-completed case is reported
        # rather than hidden, so a clean success here means both actually ran.
        #
        # What this cannot reach, for the same reason the enrollment subtest
        # above stops at `--print-command`: no tailscaled has spent the key, so
        # there is no registered *node* to delete and only the user half of a
        # revocation runs here. That is precisely the gap #29 shipped through —
        # every assertion below passed while a node that had actually
        # registered kept its tunnel. `nix/tests/vpn-data-plane.nix` revokes a
        # spoke that a real tailscaled registered, and is the test that covers
        # it.
        ca.succeed(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            "--identity /var/lib/wayfinder/identity.seed "
            "--cert-from 127.0.0.1:7700 "
            f"provider revoke --mac {node_mac}"
        )
        users = json.loads(ca.succeed("headscale users list -o json")) or []
        assert all(u["name"] != node_mac_hex for u in users), (
            f"{node_mac_hex} still has a VPN registration after revocation: {users}"
        )
        # Deleting the user takes its unspent keys with it — otherwise a
        # revocation racing an enrollment would leave a usable credential behind
        # for a node that was just removed.
        remaining = [
            k
            for k in (json.loads(ca.succeed("headscale preauthkeys list -o json")) or [])
            if k.get("user", {}).get("name") == node_mac_hex
        ]
        assert remaining == [], f"an unspent key outlived the revoke: {remaining}"

        # Idempotent: the retry path for a partially-failed revoke has to
        # converge, so removing an already-absent registration is success.
        ca.succeed(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            "--identity /var/lib/wayfinder/identity.seed "
            "--cert-from 127.0.0.1:7700 "
            f"provider vpn revoke --mac {node_mac}"
        )

    with subtest("the issued-certificate log survives a CA restart"):
        ca.succeed("systemctl restart wayfinder.service")
        ca.wait_for_open_port(7700, timeout=30)
        certs = ca.succeed(
            "wayfinder-ctl --connect 127.0.0.1:7700 "
            "--identity /var/lib/wayfinder/identity.seed "
            "--cert-from 127.0.0.1:7700 provider members"
        )
        assert node_mac in certs, f"{node_mac} missing from the restarted CA's log:\n{certs}"
  '';
}
