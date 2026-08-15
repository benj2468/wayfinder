# NixOS module for a self-contained Wayfinder installer image: everything a
# board needs to write a finished system onto its own disk, with no flake
# checkout, no channel and no network.
#
# It puts three things on the image, all derived from the one already-evaluated
# system in `target`, so the layout that gets partitioned, the `fileSystems`
# the installed system boots with, and the closure that is copied onto it
# cannot disagree:
#
#   /etc/disko/<machine>.nix          the layout, to read or to drive disko by
#                                     hand
#   /etc/wayfinder/<machine>-system   the built system. Naming it from /etc is
#                                     also what pulls its closure into the
#                                     image's store — without a reference from
#                                     the image's own closure there would be
#                                     nothing on the stick to install
#   wayfinder-install                 the wrapper that runs both install steps
#
# Applied by `mkWayfinderSystem` in the repo's `flake.nix`, which pairs each
# `nixosConfigurations.<machine>` installer with the
# `nixosConfigurations.<machine>-system` it installs.
{
  lib,
  config,
  pkgs,
  ...
}:
let
  cfg = config.wayfinder.installer;

  # Both halves of the install come out of the target system rather than out of
  # this image. `diskoScript` is the layout *already built* into a script, so
  # the board evaluates no Nix at install time — the `disko` CLI would
  # `nix-build` its script on the spot, which is exactly what a network-less
  # installer cannot rely on. `rootMountPoint` is baked into that script, so the
  # wrapper has to agree with it rather than pick its own.
  inherit (cfg.target.config.system.build) toplevel diskoScript;
  inherit (cfg.target.config.disko) rootMountPoint;

  wayfinder-install = pkgs.writeShellApplication {
    name = "wayfinder-install";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.nixos-install-tools
    ];
    text = ''
      usage() {
        cat <<'EOF'
      Usage: wayfinder-install [-y|--yes] [nixos-install args...]

      Installs ${cfg.machine} onto this board's own disk, in two steps:

        1. partition, format and mount per /etc/disko/${cfg.machine}.nix
        2. copy the system already in this image's store onto that disk and
           install its bootloader

      Step 1 destroys everything on the disks the layout names; it prints them
      and asks for confirmation first.

        -y, --yes   skip that confirmation
        -h, --help  show this

      Remaining arguments go to nixos-install, e.g. --no-root-passwd to skip
      the root password prompt.
      EOF
      }

      wipe=()
      while [ "$#" -gt 0 ]; do
        case "$1" in
          -y | --yes)
            wipe=(--yes-wipe-all-disks)
            shift
            ;;
          -h | --help)
            usage
            exit 0
            ;;
          *)
            break
            ;;
        esac
      done

      if [ "$(id -u)" -ne 0 ]; then
        echo "wayfinder-install: must be run as root" >&2
        exit 1
      fi

      echo "==> Partitioning and formatting for ${cfg.machine}"
      ${diskoScript} "''${wipe[@]}"

      echo "==> Installing ${cfg.machine} onto ${rootMountPoint}"
      nixos-install \
        --system ${toplevel} \
        --root ${rootMountPoint} \
        --no-channel-copy \
        "$@"

      echo "==> Installed. Power off, remove the installer media and boot."
    '';
  };
in
{
  options.wayfinder.installer = with lib; {
    machine = mkOption {
      type = types.str;
      description = ''
        Name of the machine this image installs, as used for the
        `nixosConfigurations.<machine>` / `<machine>-system` pair. Only names
        the `/etc` paths and the wrapper's output, so a stick found in a drawer
        says which board it belongs to.
      '';
    };

    layout = mkOption {
      type = types.path;
      description = ''
        The machine's disko layout, placed at `/etc/disko/<machine>.nix`.

        Nothing on the install path reads this file — `wayfinder-install` runs
        the layout already built into `target` — it is here for inspection and
        for driving the `disko` CLI by hand against a different device.
      '';
    };

    target = mkOption {
      type = types.raw;
      description = ''
        The evaluated `nixosSystem` this image installs: the whole thing, not
        its `toplevel`, so the closure that gets copied and the disko script
        that partitions for it come from a single evaluation and cannot be
        paired up wrong.
      '';
    };
  };

  config = {
    environment.systemPackages = [ wayfinder-install ];

    environment.etc = {
      "disko/${cfg.machine}.nix".source = cfg.layout;
      "wayfinder/${cfg.machine}-system".source = toplevel;
    };
  };
}
