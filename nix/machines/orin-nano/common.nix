# Configuration shared by every way the Orin Nano gets built: the Jetson
# hardware itself and the wayfinder node it exists to run.
#
# Two configurations consume this — `installer.nix` (the live USB image) and
# `system.nix` (what lands on the NVMe). Anything that depends on how the disk
# is treated belongs in one of those, not here.
{ ... }: {
  imports = [
    ../../modules/wayfinder.nix
  ];

  programs.vim = {
    enable = true;
    defaultEditor = true;
  };

  services.wayfinder = {
    enable = true;
    web.enable = true;
    openFirewall = [ "enP8p1s0" ];
    ethernetAccess = {
      enable = true;
      interface = "enP8p1s0";
    };
    config = {
      local_egress = {
        type = "RawL2Egress";
        interface = "enP8p1s0";
      };
      server = {
        type = "Tls";
        addr = "0.0.0.0:7700";
      };
      links = [
        {
          type = "Ble";
          ogm = {
            i_min_ms = 1000;
            i_max_ms = 20000;
          };
          features = {
            tx_keepalive = {
              interval_ms = 5000;
            };
          };
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
