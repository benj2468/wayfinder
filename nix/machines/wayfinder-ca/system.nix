# The cloud CA as it runs off its own boot volume — what
# `nixosConfigurations.wayfinder-ca` builds and `nixos-anywhere` writes.
#
# It owns no `fileSystems` of its own: `disk.nix` plus disko's NixOS module
# generate them from the partition layout, so the mounts the system boots with
# are the same declaration the installer partitioned from — the same
# arrangement `nix/machines/orin-nano/system.nix` uses.
#
# Unlike the Orin, there is no installer image beside this: a cloud instance is
# installed by `nixos-anywhere` kexec-ing over the stock image the provider
# booted, so there is no USB stick to put a layout on.
{ modulesPath, lib, ... }:
{
  imports = [
    # The generic cloud-guest profile: virtio/scsi drivers in the initrd, a
    # serial console, DHCP, and cloud-init-style host key handling. Ampere A1
    # instances boot UEFI with virtio devices, so this is the right base —
    # `qemu-guest` rather than any vendor-specific Oracle profile, which
    # nixpkgs does not ship.
    (modulesPath + "/profiles/qemu-guest.nix")
  ];

  # UEFI boot on the boot volume's ESP, which `disk.nix` mounts at /boot.
  # `canTouchEfiVariables` is false deliberately: a cloud instance's firmware
  # variables are not reliably persisted across a stop/start, and a system that
  # depends on having written a boot entry there can fail to come back. The
  # removable/fallback path (\EFI\BOOT\BOOTAA64.EFI) always boots.
  boot.loader.grub.enable = false;
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = false;
  boot.loader.systemd-boot.installDeviceTree = false;

  # Root is on a virtio-scsi boot volume, so stage 1 has to be able to reach
  # it before /  is mounted.
  boot.initrd.availableKernelModules = [
    "virtio_pci"
    "virtio_scsi"
    "virtio_blk"
    "sd_mod"
  ];

  # The instance takes its address from the cloud's DHCP; nothing here is
  # statically addressed, since the *public* address is a reserved IP the
  # provider NATs to this NIC rather than one the guest configures.
  networking.useDHCP = lib.mkDefault true;

  # A 12 GB instance with no swap will OOM-kill during a `nixos-rebuild` that
  # has to build rather than substitute. Cheap insurance on a box whose whole
  # job is to stay reachable.
  swapDevices = [
    {
      device = "/var/swapfile";
      size = 2048;
    }
  ];

  # Keep the closure small: this box has one job, and every extra path is
  # another thing to keep patched on an internet-facing host holding a root key.
  documentation.enable = false;
  documentation.nixos.enable = false;
}
