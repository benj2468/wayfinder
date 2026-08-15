# The live installer for the Orin Nano: an aarch64 UEFI ISO, written to a USB
# stick and booted on the devkit.
#
# The image is self-contained — `nix/modules/installer.nix` puts this
# machine's disk layout, the built `orin-nano-system` closure and the
# `wayfinder-install` wrapper on it — so installing needs neither a checkout of
# this flake nor a network on the board. One command, as root:
#
#     wayfinder-install
#
# It partitions and formats the NVMe (destructive, and it says so and asks
# first), mounts it under /mnt, copies the system that is already in the
# stick's store onto it and installs the bootloader. `nixos-install` then
# prompts for the new root password, which is the only way into the installed
# system.
#
# `orin-nano-system` is this image's other half — `mkWayfinderSystem` in
# `flake.nix` emits the two together from one description and hands this image
# that whole system, so what boots off the stick and what lands on the NVMe are
# the same build.
#
# To install to a *different* device, or when the flake is reachable anyway,
# the disko CLIs below are the escape hatch — `--disk main <device>` overrides
# what `disk.nix` names, so an SSD that enumerates elsewhere needs no edit to
# the layout:
#
#     disko-install --flake '<this repo>#orin-nano-system' --disk main /dev/nvme0n1
{
  lib,
  pkgs,
  modulesPath,
  inputs,
  ...
}:
let
  # Taken from the flake input rather than nixpkgs so the CLI that reads
  # `disk.nix` is the same disko whose NixOS module turns that file into the
  # installed system's `fileSystems` (see `system.nix`). Two versions
  # evaluating one layout is exactly the drift this repo can avoid for free.
  disko = inputs.disko.packages.${pkgs.stdenv.hostPlatform.system};
in
{
  imports = [
    "${modulesPath}/installer/cd-dvd/installation-cd-minimal.nix"
  ];

  environment.systemPackages = [
    disko.disko
    disko.disko-install
  ];

  # The installer image carries ZFS support, which brings this on by default
  # for backwards compatibility: it force-imports a root pool even when the
  # hostid says another machine owns it. Nothing here uses ZFS, and a live
  # image is exactly where that footgun points at someone else's disk.
  boot.zfs.forceImportRoot = false;
}
