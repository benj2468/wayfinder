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

  # Costs 90 seconds of boot if left on. `systemd-tpm2-generator` makes
  # `tpm2.target` depend on /dev/tpm0 and /dev/tpmrm0, and `sysinit.target`
  # pulls that in — so the whole initrd blocks on those device jobs until
  # `DefaultTimeoutStartSec` expires, then carries on regardless. The Orin's
  # TPM has no driver in stage 1 and only enumerates a second into stage 2,
  # so the wait can never be satisfied where it happens.
  #
  # Safe to drop because stage 1 has nothing to measure or unseal: `disk.nix`
  # is plain GPT + ext4 with no LUKS. Revisit alongside any move to
  # TPM-sealed disk encryption or measured boot — that would need the TPM
  # driver in `availableKernelModules` above rather than this turned back on.
  boot.initrd.systemd.tpm2.enable = false;
}
