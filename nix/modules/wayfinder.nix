{
  lib,
  config,
  pkgs,
  ...
}:
with pkgs;
let
  wayfinderCfg = config.services.wayfinder;
  configFile = writeText "wayfinder-config.json" (builtins.toJSON wayfinderCfg.config);
in
{
  options.services.wayfinder = with lib; {
    enable = mkEnableOption "Enable wayfinder";

    config = mkOption {
      type = types.submodule {
        freeformType = types.attrsOf types.json;
      };
      default = { };
      description = "settings for wayfinded";
    };
  };

  config = lib.mkIf wayfinderCfg.enable {

    environment.systemPackages = [
      wayfinder-tui
      wayfinder-ctl
    ];

    users.users.wayfinder = {
      isSystemUser = true;
      group = "wayfinder";
    };
    users.groups.wayfinder = { };

    services.udev.extraRules = ''
      KERNEL=="tun", GROUP="wayfinder", MODE="0660", OPTIONS+="static_node=net/tun"
    '';

    systemd.services.wayfinder = {
      enable = true;
      description = "Wayfinder Systemd Service";

      serviceConfig = {
        Type = "notify";
        ExecStart = "${wayfinder-tap}/bin/wayfinder-tap --config ${configFile}";

        Restart = "always";
        RestartSec = "5s";

        User = "wayfinder";
        Group = "wayfinder";

        Environment = [
          "RUST_LOG=debug"
        ];

        CapabilityBoundingSet = [
          "CAP_NET_RAW"
          "CAP_NET_ADMIN"
        ];
        AmbientCapabilities = [
          "CAP_NET_RAW"
          "CAP_NET_ADMIN"
        ];
      };

      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      wantedBy = [ "multi-user.target" ];
    };
  };
}
