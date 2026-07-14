# NixOS module for running a Wayfinder mesh node (`wayfinder-tap`) as a
# systemd service. Exposed as `nixosModules.default` in the repo's
# `flake.nix`; import it into a `nixosSystem`'s `modules` and set
# `services.wayfinder.enable = true` plus `services.wayfinder.config`. See
# `nix/tests/simple.nix` for a complete worked example (also runnable as a
# smoke test: `nix build .#wayfinder-simple`).
#
# `wayfinder-tap`/`wayfinder-tui`/`wayfinder-ctl` come from this same flake's
# `overlays.default`; pull them in separately if you want the packages without
# the module.
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
    enable = mkEnableOption "the wayfinder mesh node service";

    # A freeform attrset rather than a typed submodule because it's just
    # serialized straight to JSON and handed to `wayfinder-tap --config` — the
    # binary owns the schema (see `bins/wayfinder-tap`), not this module.
    config = mkOption {
      type = types.submodule {
        freeformType = types.attrsOf types.json;
      };
      default = { };
      description = ''
        `wayfinder-tap` node configuration, serialized to JSON and passed via
        `--config`. Same schema as the YAML config the binary accepts
        directly: `local_egress`, `server`, `links`, and optionally
        `provider`/`require_auth`/`lazy_cert_distribution` for mesh
        segregation (see `libs/wayfinder-auth`).

        For a segregated mesh (`require_auth = true`), identity/membership
        certs can be wired in two ways: statically, via an `auth = { seed_path
        = ...; cert_path = ...; trust_anchor_path = ...; }` block whose files
        must exist on disk before `wayfinder.service` starts (provision them
        with your secrets tooling of choice — this module does not); or at
        runtime, against the *already-running* node's management API via
        `wayfinder-ctl set-auth <seed> <cert> <anchor>` (a oneshot service or
        activation script gated on `wayfinder.service` being up).
      '';
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
