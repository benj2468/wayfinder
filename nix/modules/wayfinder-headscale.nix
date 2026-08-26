# Headscale colocated with a wayfinder certificate authority.
#
# The CA is the one box in a CGNAT topology with a stable public address, which
# is what makes it the natural place to also coordinate the tunnel two
# Starlink-connected nodes reach each other over. This module is the tunnel
# half of that box; `wayfinder.nix` is the mesh half, and the two are joined by
# one thing: `services.wayfinder.config.provider.headscale` pointing at the
# API this starts.
#
# Three properties this module exists to hold, all of which fail silently if
# they regress:
#
#  * **The DERP relay is the one this box runs.** Headscale ships with
#    Tailscale Inc.'s public DERP map as the default. Leaving it on means an
#    "isolated" mesh silently relays through third-party infrastructure —
#    which is the property `docs/design/implemented/11-cloud-auth-provider.md`
#    chose this host *for*, having rejected Cloudflare precisely because it
#    offers no UDP ingress and so could not host STUN.
#  * **Headscale is served over TLS.** Not a hardening preference — a
#    requirement, and one that a control-plane test cannot see. `tailscaled`
#    refuses a plaintext DERP connection outright, regardless of the scheme
#    headscale advertises, and that refusal takes `NetInfo`/STUN probing down
#    with it: two peers on the *same LAN* fail to establish. Found the hard way
#    in `nix/tests/vpn-data-plane.nix`, which is the only test here that runs a
#    real `tailscaled`; everything reachable with `curl` works perfectly over
#    plain HTTP, which is exactly what makes this one quiet. Hence
#    `tls.mode = "none"` being a thing a configuration has to ask for.
#  * **Headplane is not a primary surface.** It is a break-glass admin UI for
#    the case where wayfinder-server is down but the tunnel is fine. It binds
#    loopback, and reaching it is an explicit act (an SSH tunnel), not a link
#    in a navigation bar.
#
# Two secrets are minted **on the box** rather than carried there: the
# Headscale API key the colocated node mints tunnel credentials with, and
# Headplane's cookie secret. Both are machine-generated state this host can
# recreate against its own Headscale at any time, which is what separates them
# from the mesh trust material an operator carries to the box by hand — that is
# minted offline and is the mesh itself. Neither ever enters the Nix store.
#
# To sign in to Headplane, paste a Headscale API key at its login page; mint a
# throwaway one over SSH with `headscale apikeys create --expiration 24h`. It
# deliberately does not reuse the node's key, which has no expiry an operator
# is watching.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.wayfinder-headscale;

  # Where the API key and the note of when it expires live. The expiry is
  # recorded here at mint time rather than read back out of Headscale: the
  # renewal check then depends on nothing but a number this module wrote, and
  # cannot be broken by a change to the API's JSON shape.
  keyPath = toString cfg.apiKey.path;
  keyExpiryPath = "${keyPath}.expires";
  keyDir = builtins.dirOf keyPath;

  # Headplane runs as the Headscale user (the nixpkgs module fixes this), so
  # its cookie secret has to be readable by that user and no other.
  cookieSecretPath = "/var/lib/headplane/cookie.secret";

  tlsEnabled = cfg.tls.mode != "none";
  scheme = if tlsEnabled then "https" else "http";

  # The port is always stated, never left implicit — even when it is the
  # scheme's default. The embedded DERP relay advertises this URL's port as its
  # own (`DERPPort` in the region it serves clients), so the one way this value
  # can be wrong is by disagreeing with what headscale actually listens on.
  # Spelling it out makes the two impossible to drift apart while looking fine.
  endpoint = "${scheme}://${cfg.domain}:${toString cfg.port}";

  # The port the colocated node's management API listens on, taken from its own
  # configuration rather than restated. `selfJoin` reaches that API over
  # loopback, so a node moved off 7700 must not leave the self-join dialling the
  # old port. Split on the last colon so a bracketed IPv6 bind address
  # (`[::]:7700`) yields the port too.
  wayfinderMgmtPort = lib.last (
    lib.splitString ":" (config.services.wayfinder.config.server.addr or "0.0.0.0:7700")
  );
in
{
  options.services.wayfinder-headscale = {
    enable = lib.mkEnableOption "Headscale VPN coordination for a wayfinder CA";

    domain = lib.mkOption {
      type = lib.types.str;
      example = "vpn.example.net";
      description = ''
        Public DNS name nodes register against. This is what ends up in a
        node's `--login-server`, so it must resolve from the *nodes*, not
        merely from the CA.
      '';
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = if cfg.tls.mode == "none" then 8080 else 443;
      defaultText = lib.literalMD "443 with TLS, 8080 without";
      description = ''
        TCP port the Headscale API, control plane and embedded DERP relay
        listen on.

        443 under TLS because that is the port a client assumes for `https`
        and the one most likely to be reachable from behind whatever a node
        sits behind. Below 1024 is fine: the nixpkgs unit grants
        `CAP_NET_BIND_SERVICE` exactly when this is.
      '';
    };

    tls = {
      mode = lib.mkOption {
        type = lib.types.enum [
          "acme"
          "files"
          "none"
        ];
        default = "acme";
        description = ''
          How Headscale gets its TLS certificate.

          `acme` — Headscale's built-in Let's Encrypt client, for a deployment
          on a public name. Nothing to provision and nothing to renew.

          `files` — a certificate you supply ([`certFile`](#), [`keyFile`](#)).
          For a private CA, or a test with a self-signed certificate.

          `none` — plain HTTP. **Only correct where no real `tailscaled` ever
          connects**, which in practice means a test of the control plane
          alone: a client refuses a plaintext DERP connection, and loses STUN
          probing with it. See the module header.
        '';
      };

      acmeChallenge = lib.mkOption {
        type = lib.types.enum [
          "TLS-ALPN-01"
          "HTTP-01"
        ];
        default = "TLS-ALPN-01";
        description = ''
          Which ACME challenge Headscale answers, when
          [`mode`](#) is `acme`.

          `TLS-ALPN-01` is served on the same 443 listener, so it opens no
          further ports. `HTTP-01` needs TCP/80 reachable from the internet —
          this module opens it in the local firewall when selected, but a cloud
          security list in front of the host is a separate rule someone has to
          remember.
        '';
      };

      certFile = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = "Certificate chain to serve, when [`mode`](#) is `files`.";
      };

      keyFile = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = "Private key for [`certFile`](#), when [`mode`](#) is `files`.";
      };
    };

    endpoint = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      default = endpoint;
      defaultText = lib.literalMD "derived from `tls.mode`, `domain` and `port`";
      description = ''
        The URL this Headscale answers on, derived rather than stated so a
        colocated node cannot disagree with it.

        Both what an enrolling node is handed as `--login-server` and what the
        node beside it should use as
        `services.wayfinder.config.provider.headscale.api_url` — under TLS
        those must be the same string, because the certificate names the host
        and `127.0.0.1` is not on it. The hosts entry below is what keeps that
        request on the loopback it looks like it leaves.
      '';
    };

    stunPort = lib.mkOption {
      type = lib.types.port;
      default = 3478;
      description = ''
        UDP port the embedded DERP relay serves STUN on.

        This is the one port in this design that genuinely needs UDP ingress,
        and the reason the CA is hosted somewhere that offers it. The matching
        rule is already written in `infra/oracle/main.tf`.
      '';
    };

    ipPrefixes = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "100.64.0.0/10" ];
      description = ''
        Address ranges Headscale allocates tunnel addresses from. A node's mesh
        UDP link then binds one of these instead of a LAN address — which is
        the whole mechanism, and needs no wayfinder config change to work.
      '';
    };

    apiKey = {
      path = lib.mkOption {
        type = lib.types.path;
        default = "/var/lib/wayfinder-headscale/api.key";
        description = ''
          File the minted Headscale API key is written to, for a colocated
          `services.wayfinder` provider to read as
          `config.provider.headscale.api_key_path`.

          In headscale's own state directory, not the node's: this key is
          machine-generated state the box recreates at will, not something an
          operator carries here with the mesh trust material.
        '';
      };

      owner = lib.mkOption {
        type = lib.types.str;
        default = "wayfinder";
        description = ''
          User the key file is owned by, mode 0400. Must be whoever the node
          service runs as — the key is minted by root talking to Headscale and
          read by the node, and a key left owned by the minting side fails at
          the far end of a deploy rather than here.
        '';
      };

      lifetimeDays = lib.mkOption {
        type = lib.types.ints.positive;
        default = 365;
        description = ''
          Expiry of a newly minted key, in days.

          Headscale API keys always expire. This one is not spent and
          discarded like a preauth key — the node holds it for as long as it
          runs — so its expiry is a date on which enrollment stops working for
          no visible reason. Hence the renewal below rather than a longer
          number here.
        '';
      };

      renewWithinDays = lib.mkOption {
        type = lib.types.ints.positive;
        default = 30;
        description = ''
          Renew the key once it is this close to expiring.

          Checked daily by a timer, so the replacement happens a month before
          anything breaks and while an operator is not looking at it. The node
          is restarted when the key changes: it reads the key once, at
          startup.
        '';
      };
    };

    selfJoin = {
      enable = lib.mkEnableOption ''
        joining this box to the tunnel it coordinates.

        The CA is a mesh node as well as the coordination server, so its own
        `UdpMulti` link needs a tunnel address like every other node's — and it
        obtains one exactly the way every other node does, by asking the
        management API for a credential (`wayfinderctl vpn enrollment`) and
        spending it. The connection is to itself, over loopback, presenting its
        own identity seed, which earns `MgmtAccess::GrantedSelfKey`: the node
        asking on its own behalf. The MAC the credential is minted for comes
        from the router, so this box registers under the same MAC-named
        Headscale user an enrolled node's credential is scoped to, by the same
        code (`libs/wayfinder-server/src/vpn.rs`).

        An earlier revision reimplemented that sequence in shell against the
        local `headscale` CLI, because `GetVpnEnrollment` refused every full
        management grant. See design 08's Correction 1 for why that refusal
        was really about where the MAC came from rather than about privilege,
        and what changed.

        A unit rather than a runbook step, for the same reason
        `wayfinder-headscale-apikey` is one: a preauth key can only be issued
        by a running Headscale, so it cannot be provisioned alongside the
        offline-minted mesh trust material, and a manual step is one that gets
        skipped when the box is rebuilt from scratch
      '';

      identityFile = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = config.services.wayfinder.config.auth.seed_path or null;
        defaultText = lib.literalMD "`services.wayfinder.config.auth.seed_path`";
        description = ''
          This node's Ed25519 identity seed — the credential the self-join
          presents to the node's own management API.

          It is the node's own key, so the connection earns
          `MgmtAccess::GrantedSelfKey` and the node mints a credential for
          itself. No certificate is passed alongside it: on this tier a
          presented certificate is never verified and never consulted for the
          MAC, so passing one would suggest it does something.

          The same file also pins the connection. `wayfinder-ctl` defaults
          `--node-key` to the public half of `--identity`, which is exactly the
          key this node's TLS listener presents — the one case where that
          default is right rather than something to be spelled out.

          Read at runtime by the unit rather than at evaluation: a seed
          provisioned out of band is deliberately not readable when this
          configuration is built.
        '';
      };

      managementAddr = lib.mkOption {
        type = lib.types.str;
        default = "127.0.0.1:${wayfinderMgmtPort}";
        defaultText = lib.literalMD "loopback, on the node's own `server.addr` port";
        description = ''
          `host:port` of the colocated node's management API.

          Loopback: the two ends are on this host, so this never leaves the
          box and does not depend on the provider hairpinning a public address
          back. Only the port is taken from the node's configuration — its
          bind address is typically `0.0.0.0`, which is not an address to dial.
        '';
      };
    };

    headplane = {
      enable = lib.mkEnableOption "the Headplane admin UI (break-glass only)";

      port = lib.mkOption {
        type = lib.types.port;
        default = 3000;
        description = "Loopback port Headplane binds.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    services.headscale = {
      enable = true;
      port = cfg.port;
      address = "0.0.0.0";
      settings = {
        # Scheme and port both have to match how this is really listening.
        # Headscale warns at startup when they don't ("listening without TLS
        # but ServerURL does not start with http://"), and the mismatch is not
        # cosmetic: the embedded DERP relay advertises this URL's scheme and
        # port as its own address, so a `https://…` value with no explicit
        # port once made every client try to reach the relay on 443 — where
        # nothing listened — while headscale itself only ever served on
        # `cfg.port`. It takes two real nodes with no direct path between them
        # to surface at all; a direct WireGuard connection papers over it.
        server_url = endpoint;
        prefixes = {
          v4 = lib.head cfg.ipPrefixes;
          allocation = "sequential";
        };
        # The embedded relay, and *only* it. `urls = [ ]` is the load-bearing
        # line: it drops Tailscale Inc.'s default DERP map, so no traffic path
        # depends on infrastructure this deployment does not run.
        derp = {
          server = {
            enabled = true;
            region_id = 999;
            region_code = "wayfinder";
            region_name = "Wayfinder Embedded Relay";
            stun_listen_addr = "0.0.0.0:${toString cfg.stunPort}";
          };
          urls = [ ];
          paths = [ ];
        };
        dns = {
          override_local_dns = false;
          magic_dns = false;
        };
      }
      // lib.optionalAttrs (cfg.tls.mode == "acme") {
        tls_letsencrypt_hostname = cfg.domain;
        tls_letsencrypt_challenge_type = cfg.tls.acmeChallenge;
      }
      // lib.optionalAttrs (cfg.tls.mode == "files") {
        tls_cert_path = toString cfg.tls.certFile;
        tls_key_path = toString cfg.tls.keyFile;
      };
    };

    assertions = [
      {
        assertion = cfg.tls.mode != "files" || (cfg.tls.certFile != null && cfg.tls.keyFile != null);
        message = ''
          services.wayfinder-headscale.tls.mode = "files" needs both
          tls.certFile and tls.keyFile.
        '';
      }
      {
        assertion = !cfg.selfJoin.enable || config.services.wayfinder-tailscale.enable;
        message = ''
          services.wayfinder-headscale.selfJoin.enable joins this box to its
          own tunnel, which needs the tunnel daemon: set
          services.wayfinder-tailscale.enable = true.
        '';
      }
      {
        # Guarded on `enable` as well, so a configuration missing the daemon
        # entirely reports *that* rather than dying on an undefined
        # `loginServer` before the assertion above can be read.
        assertion =
          !(cfg.selfJoin.enable && config.services.wayfinder-tailscale.enable)
          || config.services.wayfinder-tailscale.loginServer == endpoint;
        message = ''
          services.wayfinder-tailscale.loginServer is
          "${config.services.wayfinder-tailscale.loginServer}" but this box
          coordinates "${endpoint}". They must agree, or the self-join
          registers against one coordination server while every manual
          `tailscale up` on this host reaches another.
        '';
      }
      {
        assertion = !cfg.selfJoin.enable || config.services.wayfinder.enable;
        message = ''
          services.wayfinder-headscale.selfJoin.enable joins this box to its
          own tunnel through its own management API, so there has to be a node
          serving one: set services.wayfinder.enable = true.
        '';
      }
      {
        assertion = !cfg.selfJoin.enable || cfg.selfJoin.identityFile != null;
        message = ''
          services.wayfinder-headscale.selfJoin.enable needs
          selfJoin.identityFile: the self-join authenticates to the node as
          the node, and that is the only credential which earns the tier the
          enrollment request needs.
        '';
      }
    ];

    warnings = lib.optional (cfg.tls.mode == "none") ''
      services.wayfinder-headscale serves plain HTTP (tls.mode = "none"). A
      real tailscaled refuses a plaintext DERP connection and loses STUN
      probing with it, so nodes will register and then fail to reach each
      other — including two on the same LAN. Correct only where nothing but
      the control plane is exercised.
    '';

    # The name resolves to this box, on this box. Under TLS the node beside
    # headscale has to reach it by the name on the certificate rather than by
    # `127.0.0.1`, and without this that request leaves for the public address
    # and depends on the provider hairpinning it back — which Oracle does not
    # promise.
    networking.hosts = lib.mkIf tlsEnabled {
      "127.0.0.1" = [ cfg.domain ];
    };

    # The API key the colocated node mints tunnel credentials with, minted
    # against this box's own Headscale.
    #
    # A unit rather than a step in a runbook because there is no other way to
    # get one: an API key can only be issued by a running Headscale, so it
    # cannot be provisioned alongside the offline-minted mesh trust material,
    # and a manual step here is a step that gets skipped when the box is
    # rebuilt.
    systemd.services.wayfinder-headscale-apikey = {
      description = "Mint the Headscale API key the wayfinder node uses";
      wantedBy = [ "multi-user.target" ];
      after = [ "headscale.service" ];
      requires = [ "headscale.service" ];
      path = [
        pkgs.curl
        pkgs.coreutils
        config.services.headscale.package
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        # A first boot can reach here before headscale can issue anything at
        # all. Retry rather than leave the node without a key until the timer
        # comes round tomorrow.
        Restart = "on-failure";
        RestartSec = "30s";
      };
      script = ''
        set -euo pipefail

        # By name, not by 127.0.0.1: under TLS the certificate names the host
        # and an address is not on it. The hosts entry above keeps this on the
        # loopback it looks like it leaves.
        api="${endpoint}"

        # Ordered after headscale.service, but "started" is not "serving": on a
        # fresh boot the database migration runs before the listener binds, and
        # under ACME the certificate has to arrive before anything answers.
        reachable=0
        for _ in $(seq 1 60); do
          if curl -sf -o /dev/null "$api/health"; then
            reachable=1
            break
          fi
          sleep 1
        done

        renew=1
        if [ -s ${keyPath} ] && [ -s ${keyExpiryPath} ]; then
          now=$(date +%s)
          expires=$(cat ${keyExpiryPath})
          horizon=$((expires - ${toString (cfg.apiKey.renewWithinDays * 86400)}))
          if [ "$now" -lt "$horizon" ]; then
            if [ "$reachable" = 0 ]; then
              # Unreachable is not the same as rejected. Minting a replacement
              # here would churn a perfectly good key on every boot that races
              # the certificate, and restart the node each time to hand it over.
              echo "headscale is not answering; keeping the existing key" >&2
              exit 0
            fi
            # The date says when the key *will* stop working; this says whether
            # it still does — one revoked in Headplane, or lost with the
            # database, looks perfectly valid on disk.
            curl -sf -o /dev/null -H "Authorization: Bearer $(cat ${keyPath})" \
              "$api/api/v1/apikey" && renew=0
          fi
        fi

        [ "$renew" = 1 ] || exit 0

        key=$(headscale apikeys create --expiration ${toString cfg.apiKey.lifetimeDays}d 2>/dev/null | tail -1)
        case "$key" in
          hskey-api-*) ;;
          *)
            echo "headscale did not return an API key (got: ''${key:0:12}...)" >&2
            exit 1
            ;;
        esac

        # Written through a temporary file so a reader never sees a half-written
        # key, and given its owner before it is put in place rather than after.
        umask 077
        printf '%s' "$key" > ${keyPath}.new
        chown ${cfg.apiKey.owner} ${keyPath}.new
        chmod 0400 ${keyPath}.new
        mv ${keyPath}.new ${keyPath}
        printf '%s' "$(( $(date +%s) + ${toString (cfg.apiKey.lifetimeDays * 86400)} ))" \
          > ${keyExpiryPath}
        chmod 0444 ${keyExpiryPath}
      ''
      + lib.optionalString config.services.wayfinder.enable ''

        # The node reads the key once, at startup, so a rotation it is not told
        # about leaves it holding a key that has been superseded. `try-restart`
        # rather than `restart`: this also runs before the node's first start,
        # and starting it early would race the trust material into place.
        ${config.systemd.package}/bin/systemctl try-restart wayfinder.service
      '';
    };

    # Daily, so a renewal lands a month before the expiry rather than on it.
    systemd.timers.wayfinder-headscale-apikey = {
      description = "Renew the wayfinder node's Headscale API key before it expires";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = "daily";
        Persistent = true;
        RandomizedDelaySec = "1h";
      };
    };

    # This box joining the tunnel it coordinates, so its own mesh link has a
    # tunnel address to be reached on.
    #
    # The same request every other node's join goes through, and deliberately
    # so: `wayfinderctl vpn enrollment` asks the management API for a
    # credential and spends it. What differs is only which credential opens the
    # connection — this node's own identity seed rather than a membership
    # certificate — and the answer is minted by the same `Coordinator::enroll`
    # a spoke's enrollment reaches, scoped to the same MAC-named Headscale user.
    #
    # An earlier revision did the sequence by hand here (find-or-create the
    # user, mint a preauth key, spend it) against the local `headscale` CLI,
    # because the RPC refused a self-key connection. Sixty lines of shell
    # holding a convention `vpn.rs` also holds, with no test that the two
    # agree — the drift that would have cost most was the Headscale user name,
    # which is the only record of the peer↔mesh-identity mapping and would
    # have broken silently, since the tunnel works either way.
    systemd.services.wayfinder-headscale-selfjoin = lib.mkIf cfg.selfJoin.enable {
      description = "Join this box to the tunnel it coordinates";
      wantedBy = [ "multi-user.target" ];
      after = [
        "headscale.service"
        "tailscaled.service"
        "wayfinder.service"
      ];
      requires = [
        "headscale.service"
        "tailscaled.service"
        "wayfinder.service"
      ];
      # `path` replaces PATH outright rather than extending it, so everything
      # the script below calls has to be named here. `wayfinder-ctl` shells out
      # to `tailscale` itself, which is why that is on the list as well as
      # being called directly.
      path = [
        pkgs.coreutils
        pkgs.tailscale
        pkgs.wayfinder-ctl
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        # A first boot reaches here before headscale can issue anything, and
        # under ACME before it answers at all — and before the node's
        # management listener is accepting, since systemd's "started" is not
        # "listening". Retry rather than leave the box off its own tunnel until
        # someone notices.
        Restart = "on-failure";
        RestartSec = "30s";
      };
      script = ''
        set -euo pipefail

        # Already joined. `tailscale ip` fails when logged out, so it doubles
        # as the "is this box registered" check without parsing status JSON —
        # and skipping keeps a reboot from minting a preauth key it does not
        # need.
        if tailscale ip -4 >/dev/null 2>&1; then
          echo "already on the tunnel: $(tailscale ip -4)"
          exit 0
        fi

        # Ask this node for its own tunnel credential and spend it. Over
        # loopback, presenting the node's own seed: that earns
        # `MgmtAccess::GrantedSelfKey`, and the MAC the credential is minted
        # for is read from the router rather than from anything on this
        # connection. `--node-key` is left to default to the public half of
        # `--identity`, which is the key this node's own listener presents.
        #
        # No `--cert`: on this tier a presented certificate is never verified,
        # so passing one would imply it does something.
        #
        # `vpn enrollment` runs `tailscale up` itself and exits non-zero if any
        # part of it failed, which is what `Restart = on-failure` retries.
        wayfinder-ctl \
          --connect ${cfg.selfJoin.managementAddr} \
          --identity ${cfg.selfJoin.identityFile} \
          vpn enrollment

        # `tailscale up` returns once the backend is running, but the address
        # is what the mesh link is actually reached on — so that, not the exit
        # status above, is what this unit succeeds on.
        for _ in $(seq 1 60); do
          if tailscale ip -4 >/dev/null 2>&1; then
            echo "joined the tunnel: $(tailscale ip -4)"
            exit 0
          fi
          sleep 1
        done
        echo "registered but no tunnel address was assigned" >&2
        exit 1
      '';
    };

    services.headplane = lib.mkIf cfg.headplane.enable {
      enable = true;
      settings = {
        server = {
          # Loopback on purpose — see the module header. Reaching this is an
          # SSH tunnel, which is the friction that keeps it a fallback.
          host = "127.0.0.1";
          port = cfg.headplane.port;
          cookie_secret_path = cookieSecretPath;
          # False because the SSH forward that reaches this serves plain HTTP
          # on localhost. A `Secure` cookie is dropped by the browser there, and
          # the failure is a sign-in that silently returns to the login page
          # rather than an error anyone can act on.
          cookie_secure = false;
        };
        # The same URL, for the same reason as the bootstrap unit above: under
        # TLS this has to be the name on the certificate.
        headscale.url = endpoint;
      };
    };

    # Headplane refuses to start without a 32-character cookie secret, and a
    # secret in the Nix store is world-readable — so it is generated here, once,
    # on the box.
    systemd.services.headplane-cookie-secret = lib.mkIf cfg.headplane.enable {
      description = "Generate Headplane's session cookie secret";
      requiredBy = [ "headplane.service" ];
      before = [ "headplane.service" ];
      path = [ pkgs.coreutils ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        set -euo pipefail
        [ -s ${cookieSecretPath} ] && exit 0

        umask 077
        # 24 random bytes are exactly 32 unpadded base64 characters, which is
        # the length Headplane validates; `+` and `/` are folded away so the
        # secret stays a plain word in the YAML that quotes it.
        dd if=/dev/urandom bs=24 count=1 status=none \
          | base64 | tr -d '\n' | tr '+/' 'AB' > ${cookieSecretPath}.new
        chown ${config.services.headscale.user}:${config.services.headscale.group} \
          ${cookieSecretPath}.new
        chmod 0400 ${cookieSecretPath}.new
        mv ${cookieSecretPath}.new ${cookieSecretPath}
      '';
    };

    # Both directories exist before the units that write into them. Headplane's
    # own `StateDirectory` would create the second one, but only once it starts
    # — which is after the secret it needs has to be there.
    systemd.tmpfiles.settings."10-wayfinder-headscale" = {
      ${keyDir}.d = {
        mode = "0755";
        user = "root";
        group = "root";
      };
    }
    // lib.optionalAttrs cfg.headplane.enable {
      "/var/lib/headplane".d = {
        mode = "0750";
        user = config.services.headscale.user;
        group = config.services.headscale.group;
      };
    };

    # The node reads the API key at startup and fails hard when it cannot, so
    # it waits for the unit that mints one. `wants`, not `requires`: a node
    # that is not configured for VPN coordination should still come up if
    # minting fails.
    systemd.services.wayfinder = lib.mkIf config.services.wayfinder.enable {
      after = [ "wayfinder-headscale-apikey.service" ];
      wants = [ "wayfinder-headscale-apikey.service" ];
    };

    networking.firewall = {
      allowedTCPPorts = [
        cfg.port
      ]
      # The ACME HTTP-01 challenge is answered on its own listener, on 80.
      ++ lib.optional (cfg.tls.mode == "acme" && cfg.tls.acmeChallenge == "HTTP-01") 80;
      # STUN. Without this, hole-punching fails and every tunnel falls back to
      # relaying — which still works, and is exactly the kind of degradation
      # nobody notices until they measure the latency.
      allowedUDPPorts = [ cfg.stunPort ];
    };
  };
}
