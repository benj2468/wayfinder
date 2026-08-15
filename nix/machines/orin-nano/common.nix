# Configuration shared by every way the Orin Nano gets built: the Jetson
# hardware itself and the wayfinder node it exists to run.
#
# Two configurations consume this — `installer.nix` (the live USB image) and
# `system.nix` (what lands on the NVMe). Anything that depends on how the disk
# is treated belongs in one of those, not here.
{ lib, ... }: {
  imports = [
    ../../modules/wayfinder.nix
  ];

  services.wayfinder = {
    enable = true;
    web.enable = true;
    config = {
      local_egress = {
        type = "Tap";
        device_name = "wayfinder0";
      };
      server = {
        type = "Tls";
        addr = "0.0.0.0:7700";
      };
      links = [
        {
          type = "RawL2";
          # this won't in the long run
          interface = "enP8p1s0";
          ethertype = lib.trivial.fromHexString "0xcafe";
        }
      ];
    };
  };

  services.openssh = {
    enable = true;
    settings = {
      PermitRootLogin = "yes";
    };
  };

  hardware.bluetooth = {
    enable = true;
    settings.General = {
      Experimental = true;
      Privacy = "device";
    };
    powerOnBoot = true;
  };

  hardware.nvidia-jetpack = {
    enable = true;
    som = "orin-nano";
    carrierBoard = "devkit";
    majorVersion = "7";
    firmware.optee.supplicant.enable = false;
  };

  system.stateVersion = "26.05";
  nixpkgs = {
    buildPlatform.system = "aarch64-linux";
    hostPlatform.system = "aarch64-linux";
  };
}
