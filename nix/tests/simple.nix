{ testers, lib }:
testers.nixosTest {
  name = "wayfinder-simple";

  containers.machine = { ... }: {
    imports = [ ../modules/wayfinder.nix ];

    # Enable your module and provide test configuration
    services.wayfinder = {
      enable = true;
      config = {
        local_egress = {
          type = "Tap";
          device_name = "wayfinder0";
          ip_address = "10.0.0.1";
          netmask = "255.255.255.0";
        };
        server = {
          type = "Tls";
          addr = "0.0.0.0:7700";
        };
        links = [
          {
            type = "RawL2";
            interface = "eth1";
            ethertype = lib.trivial.fromHexString "0xcafe";
          }
        ];
      };
    };
  };

  # Python script to orchestrate the test VM
  testScript = ''
    machine.wait_for_unit("wayfinder.service")
    machine.wait_for_open_port(7700, timeout=10)

    machine.succeed("wayfinder-ctl --identity /var/lib/wayfinder/identity.seed node-info")
    machine.succeed("wayfinder-tui --help")

    # `packetCapture` defaults on. The dissector has to reach tshark through
    # the plugin directory of tshark's own install prefix, and this machine —
    # like an operator debugging a node — is root: Wireshark ignores
    # `WIRESHARK_PLUGIN_DIR` and refuses `-X lua_script:` for a privileged
    # process, so both of the obvious ways to load a Lua file would pass here
    # as a non-root user and quietly do nothing for the real one. Registering
    # the protocol is what proves the Lua actually loaded.
    machine.succeed("id -u | grep -qx 0")
    machine.succeed("tshark -G protocols | grep -q '^Wayfinder Mesh Protocol'")

    # Wireshark's own plugins must still be on the search path beside ours.
    machine.succeed("tshark -G protocols | grep -q '^PROFINET'")

    # A live capture is tshark spawning `dumpcap`, which nixpkgs patches it to
    # find on PATH before falling back to its own prefix — so a package holding
    # a lone tshark leaves it in neither place and every `tshark -i` fails with
    # "Couldn't run dumpcap in child process". `-D` is that same spawn without
    # needing traffic: with no dumpcap it still exits 0, having listed only the
    # extcap helpers, so this asserts a *kernel* interface comes back.
    machine.succeed("tshark -D | grep -qE '^[0-9]+\\. lo( |$)'")

    # termshark shells out to tshark for every decode and finds it on PATH, so
    # the dissector reaches it by way of that binary rather than any setting of
    # its own.
    machine.succeed("termshark --version")
    machine.succeed("grep -q wayfinder-tshark $(readlink -f $(command -v termshark))")
  '';
}
