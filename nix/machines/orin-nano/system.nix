# The Orin Nano as it runs off its own SSD — the configuration
# `nixosConfigurations.orin-nano-system` builds and `disko-install` writes.
# Paired with `installer.nix` by `mkWayfinderSystem` in `flake.nix`: the same
# board as that image targets, just past the install.
#
# It owns no `fileSystems` of its own: `disk.nix` plus disko's NixOS module
# generate them from the partition layout, so the mounts the system boots with
# are the same declaration the installer partitioned from.
{
  # The devkit's UEFI firmware lives in QSPI flash, so this is an ordinary EFI
  # boot: systemd-boot in the ESP that `disk.nix` mounts at /boot. Writable EFI
  # variables let it register its own boot entry — the Orin supports this
  # (unlike the Xavier AGX, which keeps them on eMMC).
  boot.loader.grub.enable = false;
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  # Root is on NVMe, so stage 1 has to be able to reach it. `available` rather
  # than plain `kernelModules`: it is a no-op if the Jetson kernel has the
  # driver built in.
  boot.initrd.availableKernelModules = [ "nvme" ];
}
