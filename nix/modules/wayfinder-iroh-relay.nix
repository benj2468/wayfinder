# A self-hosted `iroh-relay` beside a wayfinder certificate authority.
#
# The iroh counterpart to `wayfinder-headscale.nix`, and deliberately much
# smaller than it. Headscale is a *coordination server*: it allocates tunnel
# addresses, holds a peer list, mints preauth keys and has to be told who may
# join. An iroh relay holds none of that — peers are named by their own public
# keys, so there is nothing to allocate and no membership list to keep in step
# with the mesh's. What is left is the part that genuinely needs a box with a
# stable public address: helping two CGNAT'd peers find each other, and
# carrying their traffic when they cannot.
#
# Two jobs, and the first matters more than the name "relay" suggests:
#
#   * **QUIC address discovery** — how a node learns its own public address, the
#     thing iroh replaced STUN with. Without it a node cannot hole-punch at all.
#   * **Relaying** — the fallback path when hole punching fails. Always works
#     (it is an outbound TLS connection, which every NAT permits), and slower.
#
# A relay never sees plaintext: traffic through it is end-to-end encrypted
# between the two endpoints' QUIC connections, and it is not a mesh member.
#
# **TLS is not optional in a real deployment.** QUIC address discovery requires
# it (`enable_quic_addr_discovery` errors without a `tls` section), so a
# plaintext relay silently degrades every node to relay-only — the same shape of
# failure `wayfinder-headscale.nix` records as its Correction 6, where a
# plain-HTTP coordination server registered nodes perfectly and then left them
# unable to reach each other. `tls.mode = "disabled"` therefore exists only for
# a LAN test and warns.
#
# See `docs/design/18-iroh-mesh-links.md`.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.wayfinder-iroh-relay;

  # The relay's own TOML config. Rendered from the options below rather than
  # taken as a freeform blob, because two of these fields have non-obvious
  # interactions the assertions below catch (QAD needs TLS; an allowlist that
  # is empty locks everyone out).
  relayConfig = {
    enable_relay = cfg.enableRelay;
    http_bind_addr = cfg.httpBindAddr;
    enable_quic_addr_discovery = cfg.tls.mode != "disabled";
    access =
      if cfg.access.mode == "everyone" then "everyone" else { allowlist = cfg.access.allowlist; };
  }
  // lib.optionalAttrs (cfg.tls.mode != "disabled") {
    tls = {
      https_bind_addr = cfg.httpsBindAddr;
      quic_bind_addr = cfg.quicBindAddr;
      hostname = [ cfg.hostname ];
      cert_mode = if cfg.tls.mode == "acme" then "LetsEncrypt" else "Manual";
    }
    // lib.optionalAttrs (cfg.tls.mode == "acme") {
      cert_dir = "/var/lib/wayfinder-iroh-relay/certs";
      prod_tls = cfg.tls.production;
      contact = cfg.tls.contact;
    }
    // lib.optionalAttrs (cfg.tls.mode == "manual") {
      manual_cert_path = cfg.tls.certPath;
      manual_key_path = cfg.tls.keyPath;
    };
  };

  configFile = (pkgs.formats.toml { }).generate "iroh-relay.toml" relayConfig;
in
{
  options.services.wayfinder-iroh-relay = {
    enable = lib.mkEnableOption "a self-hosted iroh relay for the mesh's internet links";

    package = lib.mkPackageOption pkgs "iroh-relay" { };

    hostname = lib.mkOption {
      type = lib.types.str;
      example = "relay.example.net";
      description = ''
        Public DNS name of this relay. Used as the TLS certificate's subject,
        and it is the name nodes put in their link's `relay_url`.
      '';
    };

    enableRelay = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Whether to relay traffic, as opposed to only answering QUIC address
        discovery.

        Setting this false gives a *holepunch-only* server: it still tells a
        node its public address (which is what makes hole punching possible at
        all) but carries no traffic, so two peers that cannot punch through
        simply fail to connect. Reasonable if bandwidth is the binding
        constraint and a failed connection is preferable to a slow one — which
        is a real position on an Always Free cloud instance with a monthly
        transfer allowance.
      '';
    };

    httpBindAddr = lib.mkOption {
      type = lib.types.str;
      default = "[::]:80";
      description = ''
        Plain-HTTP listener. Under TLS this serves only the captive-portal
        probe; everything else moves to `httpsBindAddr`.
      '';
    };

    httpsBindAddr = lib.mkOption {
      type = lib.types.str;
      default = "[::]:443";
      description = "HTTPS listener carrying the relay protocol.";
    };

    quicBindAddr = lib.mkOption {
      type = lib.types.str;
      default = "[::]:7842";
      description = ''
        UDP listener for QUIC address discovery — how a node learns its own
        public address, and so the precondition for hole punching. Must be
        reachable from the internet or every node degrades to relay-only.
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Open the TCP and UDP ports the listeners above bind. A cloud host also
        needs the matching rule in its provider's security list — see
        `infra/oracle/main.tf`.
      '';
    };

    tls = {
      mode = lib.mkOption {
        type = lib.types.enum [
          "acme"
          "manual"
          "disabled"
        ];
        default = "acme";
        description = ''
          How the relay obtains its certificate.

          `acme` (the default) uses Let's Encrypt via the relay's own built-in
          client. `manual` reads a certificate and key from disk. `disabled`
          serves plain HTTP and **turns off QUIC address discovery**, which
          leaves every node unable to hole-punch — for a LAN test only, and it
          warns.
        '';
      };

      production = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Use Let's Encrypt production rather than staging. Staging issues
          untrusted certificates, which a node will refuse — set this false
          only while working around rate limits during bring-up.
        '';
      };

      contact = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "admin@example.net";
        description = "Contact address registered with the ACME provider.";
      };

      certPath = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = "PEM certificate chain, when `tls.mode = \"manual\"`.";
      };

      keyPath = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = "PEM private key, when `tls.mode = \"manual\"`.";
      };
    };

    access = {
      mode = lib.mkOption {
        type = lib.types.enum [
          "everyone"
          "allowlist"
        ];
        default = "everyone";
        description = ''
          Who may use this relay.

          `everyone` (the default) is not the security hole it sounds like, but
          it is not nothing either. A relay carries opaque, end-to-end
          encrypted QUIC between two endpoints; it is not a mesh member, cannot
          read anything it forwards, and admitting a stranger grants **no mesh
          membership** — that is still gated by a `MembershipCert` the mesh
          root signed, one layer up. What an open relay does risk is
          *bandwidth*: a third party using this box as free NAT-traversal
          infrastructure, which on a metered cloud instance is a real cost.

          `allowlist` names the exact endpoint keys admitted. Correct and
          revocation-proof, but static: every enrolment means editing this
          list, which is the peer-list maintenance that adopting iroh was
          meant to delete.

          Neither is the end state. The relay also supports an HTTP admission
          hook (it POSTs the connecting endpoint id and honours a `true`
          response), which would let the CA answer "is this a current,
          non-revoked member?" from the certificate log it already keeps —
          membership-gated relaying with no second credential and immediate
          revocation. That needs an endpoint on `wayfinder-server` that does
          not exist yet; see design 18 §6.4.
        '';
      };

      allowlist = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "8f1b3c2d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9" ];
        description = ''
          Endpoint keys admitted when `access.mode = "allowlist"`, as
          64-character hex Ed25519 public keys — the same spelling a node's
          `bootstrap_peers` uses.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.tls.mode != "manual" || (cfg.tls.certPath != null && cfg.tls.keyPath != null);
        message = ''
          services.wayfinder-iroh-relay.tls.mode = "manual" needs both
          `tls.certPath` and `tls.keyPath`.
        '';
      }
      {
        assertion = cfg.access.mode != "allowlist" || cfg.access.allowlist != [ ];
        message = ''
          services.wayfinder-iroh-relay.access.mode = "allowlist" with an empty
          `access.allowlist` admits nobody, which silently strands every node on
          relay-less direct paths. Name at least one endpoint key, or use
          `access.mode = "everyone"`.
        '';
      }
      {
        assertion = cfg.enableRelay || cfg.tls.mode != "disabled";
        message = ''
          services.wayfinder-iroh-relay with `enableRelay = false` and
          `tls.mode = "disabled"` does nothing at all: relaying is off and QUIC
          address discovery needs TLS, so the server would answer no useful
          request.
        '';
      }
    ];

    warnings = lib.optional (cfg.tls.mode == "disabled") ''
      services.wayfinder-iroh-relay.tls.mode = "disabled" turns off QUIC address
      discovery, because it requires TLS. Nodes will not learn their own public
      addresses and so cannot hole-punch — every pair falls back to relaying,
      or fails outright if `enableRelay = false`. Use this for a LAN test only.
    '';

    systemd.services.wayfinder-iroh-relay = {
      description = "iroh relay for the wayfinder mesh";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      serviceConfig = {
        ExecStart = "${lib.getExe' cfg.package "iroh-relay"} --config-path ${configFile}";
        Restart = "on-failure";
        RestartSec = "5s";
        DynamicUser = true;
        StateDirectory = "wayfinder-iroh-relay";

        # Binding 80/443 needs the capability; nothing else here does. The
        # relay holds no mesh trust material — it cannot read what it forwards
        # and is not a member — so it gets the strictest sandbox that still
        # lets it open a low port and write its ACME cache.
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
        ];
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
        ];
      };
    };

    networking.firewall = lib.mkIf cfg.openFirewall {
      allowedTCPPorts =
        let
          portOf = addr: lib.toInt (lib.last (lib.splitString ":" addr));
        in
        [ (portOf cfg.httpBindAddr) ]
        ++ lib.optional (cfg.tls.mode != "disabled") (portOf cfg.httpsBindAddr);
      allowedUDPPorts =
        let
          portOf = addr: lib.toInt (lib.last (lib.splitString ":" addr));
        in
        lib.optional (cfg.tls.mode != "disabled") (portOf cfg.quicBindAddr);
    };
  };
}
