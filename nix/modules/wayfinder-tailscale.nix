# `tailscaled` on a wayfinder host node, pointed at a self-hosted Headscale.
#
# The counterpart to `wayfinder-headscale.nix`: that one runs on the CA, this
# one on every node that reaches the mesh over the internet rather than over a
# radio. It starts the tunnel daemon and pins it to the mesh's own coordination
# server; the *join* itself is not done here, but by `wayfinderctl enroll`,
# which obtains a single-use credential over the management API at the moment
# it enrolls (see `docs/design/implemented/08-internet-links-headscale-vpn.md` §3.2).
#
# That split is deliberate and is the point of the whole design: a preauth key
# baked into a Nix configuration would be a long-lived bearer secret in the
# store, readable by every user on the box. The key that actually joins this
# node lives for minutes and is used once.
#
# Host-only. An embedded board runs no tunnel daemon and never will — it has no
# OS network stack to put one on.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.wayfinder-tailscale;
in
{
  options.services.wayfinder-tailscale = {
    enable = lib.mkEnableOption "the tunnel daemon for a wayfinder node on an internet link";

    loginServer = lib.mkOption {
      type = lib.types.str;
      example = "https://vpn.example.net";
      description = ''
        The mesh's own Headscale instance.

        Pinned here as well as being handed out at enrollment so that a manual
        `tailscale up` on this host cannot silently reach Tailscale Inc.'s
        public coordination server instead — which would leak an isolated
        network's coordination metadata to a third party, quietly and without
        anything failing.
      '';
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 41641;
      description = ''
        UDP port `tailscaled` accepts direct connections on.

        Opening it is what lets two nodes hole-punch to a direct path. Without
        it they still connect, via the CA's DERP relay — working, slower, and
        routed through the one box this design tries not to make load-bearing
        for the data plane.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    services.tailscale = {
      enable = true;
      port = cfg.port;
      # The mesh's UDP links bind tunnel addresses directly, so this node is
      # only ever a leaf in Tailscale's own routing — BATMAN-adv does the path
      # selection above it.
      useRoutingFeatures = "none";
    };

    # `wayfinderctl enroll` shells out to this to join, so it has to be on the
    # PATH of whoever runs the enrollment.
    environment.systemPackages = [ pkgs.tailscale ];

    networking.firewall = {
      allowedUDPPorts = [ cfg.port ];
      # Skip the firewall for tunnel traffic itself; it is already
      # authenticated by WireGuard, and the mesh authenticates again on top.
      trustedInterfaces = [ "tailscale0" ];
    };

    # The mesh node's UDP links may name a tunnel address that does not exist
    # until the tunnel is up. Ordering keeps a restart from failing to bind on
    # a race that resolves itself a second later.
    systemd.services.wayfinder = lib.mkIf config.services.wayfinder.enable {
      after = [ "tailscaled.service" ];
      wants = [ "tailscaled.service" ];
    };
  };
}
