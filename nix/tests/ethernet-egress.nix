# Exercises the ethernet-access-point feature end to end: a node configured
# with a `RawL2Egress` local egress and `services.wayfinder.ethernetAccess`,
# and a second, unrelated machine — standing in for an operator's laptop —
# plugged into the shared segment with no wayfinder software of its own. See
# `nix/modules/wayfinder.nix` for what `ethernetAccess` wires up and
# `libs/wayfinder-driver/src/raw.rs` for `RawL2Egress` itself.
{ testers, lib }:
let
  # Every container also gets an `eth1` on vlan 2 for free, auto-addressed
  # `192.168.2.<nodeNumber>` by the test framework's usual vlan scheme (see
  # `nixos/lib/testing/network.nix`'s `assignIPs`) — a debug side channel the
  # *host* running the test can reach directly (the framework backs each vlan
  # with a `vde_switch` plus a `vde-tap<N>` interface plugged into the driver
  # process's own netns), independent of whatever the test is actually
  # exercising. This module opens an unauthenticated sshd on it in every
  # container, mirroring what the test framework's own `sshBackdoor.enable`
  # would set. `sshBackdoor` itself isn't used: it also wires up a QEMU vsock
  # backdoor that the driver tries to tear down on exit even though this test
  # has zero `nodes` (only `containers`) to have ever created one, crashing
  # cleanup (`'Driver' object has no attribute 'vhost_vsock'`). Run `nix build
  # .#checks.<system>.wayfinder-ethernet-egress.driver &&
  # ./result/bin/nixos-test-driver` (or the `.driverInteractive` variant) to
  # get a shell where that tap is live, then e.g. `ssh root@192.168.2.2`
  # (`node`) or `root@192.168.2.1` (`laptop`) — `nodeNumber` is assigned
  # alphabetically by container name.
  debugSsh = {
    services.openssh = {
      enable = true;
      settings = {
        PermitRootLogin = "yes";
        PermitEmptyPasswords = "yes";
      };
    };
    security.pam.services.sshd.allowNullPassword = true;
  };
in
testers.nixosTest {
  name = "wayfinder-ethernet-egress";

  # A second, dedicated vlan (3) stands in for the physical ethernet cable
  # between the node's spare NIC and the laptop — this is the link the test
  # actually exercises, kept off the debug vlan so debug SSH traffic is never
  # mistaken for mesh traffic under test. `assignIP = false` on both ends:
  # the node addresses `eth2` itself via `ethernetAccess`, and the laptop is
  # meant to get its address from that node's `dnsmasq`, not the test
  # framework's own vlan auto-addressing scheme.
  containers.node =
    {
      pkgs,
      ...
    }:
    {
      imports = [
        ../modules/wayfinder.nix
        debugSsh
      ];

      # The debug vlan (see the top-level comment above): left implicit via
      # `virtualisation.vlans` rather than `virtualisation.interfaces` so it
      # picks up the framework's normal auto-addressing (`assignIP = true`)
      # and lands on `eth1`.
      virtualisation.vlans = [ 2 ];

      virtualisation.interfaces.eth2 = {
        vlan = 3;
        assignIP = false;
      };

      services.wayfinder = {
        enable = true;
        openFirewall = [ "eth2" ];
        web = {
          enable = true;
          listen = "10.55.21.1:8080";
        };
        ethernetAccess = {
          enable = true;
          interface = "eth2";
        };
        config = {
          local_egress = {
            type = "RawL2Egress";
            interface = "eth2";
          };
          server = {
            type = "Tls";
            addr = "10.55.21.1:7700";
          };
          links = [ ];
        };
      };
    };

  containers.laptop =
    {
      pkgs,
      ...
    }:
    {
      imports = [ debugSsh ];

      # The debug vlan (see the top-level comment above).
      virtualisation.vlans = [ 2 ];

      virtualisation.interfaces.eth2 = {
        vlan = 3;
        assignIP = false;
      };

      # The nspawn container base disables DHCP by default (it otherwise blocks
      # boot on a lease that, in most tests, nothing is ever going to offer) —
      # here a lease is exactly what's under test, so turn it back on for this
      # one interface.
      networking.useDHCP = lib.mkForce false;
      networking.interfaces.eth2.useDHCP = true;

      environment.systemPackages = [
        pkgs.wayfinder-ctl
        pkgs.curl
      ];
    };

  testScript = ''
    node.wait_for_unit("dnsmasq.service")
    node.wait_for_unit("wayfinder.service")
    node.wait_for_open_port(7700, "10.55.21.1")
    node.wait_for_open_port(8080, "10.55.21.1")

    # The laptop has no wayfinder software of its own — eth2, addressed by
    # the node's dnsmasq, is the interface under test (eth1 is only the
    # debug vlan).
    laptop.wait_until_succeeds("ip -4 addr show eth2 | grep -q '10\\.55\\.21\\.'")

    # `GetNodeInfo` needs a real management-API credential (see
    # `libs/wayfinder-server/src/authz.rs`) — plugging in grants mesh and
    # dashboard access, not an mgmt-API identity for free. Standing in for an
    # operator who also has the node's own seed: copy it across so
    # `wayfinder-ctl` can prove the self-key tier, same as the dashboard
    # already does locally on the node.
    seed_b64 = node.succeed("base64 -w0 /var/lib/wayfinder/identity.seed").strip()
    laptop.succeed(f"echo {seed_b64} | base64 -d > /root/identity.seed")

    laptop.succeed(
        "wayfinder-ctl --connect 10.55.21.1:7700 --identity /root/identity.seed node-info"
    )

    # The dashboard needs no credential of its own from the laptop's side —
    # it authenticates to the node locally, using its own copy of that same
    # seed (`services.wayfinder.web.identityPath`'s default).
    laptop.succeed("curl -sf http://10.55.21.1:8080/ | grep -qi '<html'")
  '';
}
