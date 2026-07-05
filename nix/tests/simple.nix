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
          type = "Tcp";
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

    machine.succeed("wayfinder-ctl node-info")
    machine.succeed("wayfinder-tui --help")
  '';
}
