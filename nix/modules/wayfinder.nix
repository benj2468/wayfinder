# NixOS module for running a Wayfinder mesh node (`wayfinder-tap`) as a
# systemd service. Exposed as `nixosModules.default` in the repo's
# `flake.nix`; import it into a `nixosSystem`'s `modules` and set
# `services.wayfinder.enable = true` plus `services.wayfinder.config`. See
# `nix/tests/simple.nix` for a complete worked example (also runnable as a
# smoke test: `nix build .#wayfinder-simple`).
#
# `wayfinder-tap`/`wayfinder-tui`/`wayfinder-ctl`/`wayfinder-web` come from this
# same flake's `overlays.default`; pull them in separately if you want the
# packages without the module.
#
# `services.wayfinder.web` runs the browser dashboard. It is independent of
# `services.wayfinder.enable` — it speaks to a node over the management API, so
# it can equally be pointed at a node on another host — but the common case is
# running it beside one, where it reuses that node's identity seed and needs no
# key of its own.
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

    web = {
      enable = mkEnableOption "the wayfinder web dashboard";

      listen = mkOption {
        type = types.str;
        default = "127.0.0.1:8080";
        description = ''
          Address to serve the dashboard on.

          Loopback by default, and deliberately so: the dashboard performs no
          authentication of its own, so anyone who can reach this port has
          whatever access `identityPath` carries — including revoking nodes on a
          provider. Reach it remotely with an SSH forward
          (`ssh -L 8080:localhost:8080 host`) rather than by widening this.
        '';
      };

      allowedHosts = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "wayfinder.example.org" ];
        description = ''
          Extra `Host` names the dashboard answers to, beyond the loopback
          names and `listen`'s own address.

          Needed only behind a reverse proxy, since the browser then names the
          proxy rather than this service. Everything else is refused: a page on
          any site can point a DNS name it controls at this address and become
          same-origin with the dashboard, and the `Host` it sends is the one
          part of that it cannot choose.
        '';
      };

      addr = mkOption {
        type = types.str;
        default = "127.0.0.1:7700";
        description = ''
          The node's TLS management API address. The default matches a local
          node configured with `server.tls` on its default port.
        '';
      };

      identityPath = mkOption {
        type = types.str;
        default = "/var/lib/wayfinder/identity.seed";
        description = ''
          The Ed25519 seed the dashboard proves possession of in the management
          TLS handshake. Against a local, un-enrolled node this is the node's
          own seed — which is why the service runs as the `wayfinder` user, so
          it can read it without the file being widened.

          On an enrolled mesh, point this at an admin identity and set `cert`.
        '';
      };

      cert = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Path to the membership certificate binding `identityPath`'s key to an
          admin identity. Leave null to authenticate against an un-enrolled node
          by proving that node's own key.
        '';
      };

      nodeKey = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          The node's Ed25519 public key (64 hex chars) to pin, defeating
          impersonation. Null defaults it to `identityPath`'s own public key,
          which is correct only when reaching a node with its own seed; set it
          explicitly to reach any other node.
        '';
      };

      logLevel = mkOption {
        type = types.str;
        default = "info";
        description = "`RUST_LOG` filter for the dashboard service.";
      };
    };
  };

  config = lib.mkMerge [
    (lib.mkIf (wayfinderCfg.enable || wayfinderCfg.web.enable) {
      users.users.wayfinder = {
        isSystemUser = true;
        group = "wayfinder";
      };
      users.groups.wayfinder = { };
    })

    (lib.mkIf wayfinderCfg.web.enable {
      environment.systemPackages = [ wayfinder-web ];

      systemd.services.wayfinder-web = {
        enable = true;
        description = "Wayfinder web dashboard";

        serviceConfig = {
          ExecStart =
            "${wayfinder-web}/bin/wayfinder-web"
            + " --listen ${wayfinderCfg.web.listen}"
            + lib.concatMapStrings (host: " --allowed-host ${host}") wayfinderCfg.web.allowedHosts
            + " --addr ${wayfinderCfg.web.addr}"
            + " --identity ${wayfinderCfg.web.identityPath}"
            + lib.optionalString (wayfinderCfg.web.cert != null) " --cert ${wayfinderCfg.web.cert}"
            + lib.optionalString (wayfinderCfg.web.nodeKey != null) " --node-key ${wayfinderCfg.web.nodeKey}";

          Restart = "always";
          RestartSec = "5s";

          # The same user as the node, so the identity seed under
          # /var/lib/wayfinder is readable without loosening its mode.
          User = "wayfinder";
          Group = "wayfinder";

          Environment = [ "RUST_LOG=${wayfinderCfg.web.logLevel}" ];
        };

        # Ordered after the node when one runs here, so the first poll has
        # something to reach. Only `after`, not `requires`: the dashboard
        # reconnects on its own, and a node restart should not take the
        # dashboard down with it.
        after = [
          "network-online.target"
        ]
        ++ lib.optional wayfinderCfg.enable "wayfinder.service";
        wants = [ "network-online.target" ];

        wantedBy = [ "multi-user.target" ];
      };
    })

    (lib.mkIf wayfinderCfg.enable {
      environment.systemPackages = [
        wayfinder-tui
        wayfinder-ctl
      ];

      services.udev.extraRules = ''
        KERNEL=="tun", GROUP="wayfinder", MODE="0660", OPTIONS+="static_node=net/tun"
      '';

      systemd.tmpfiles.settings = {
        "10-wayfinder" = {
          "/var/lib/wayfinder" = {
            d = {
              mode = "0755";
              user = "wayfinder";
              group = "wayfinder";
            };
          };
        };
      };

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
    })
  ];
}
