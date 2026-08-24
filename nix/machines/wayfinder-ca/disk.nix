# Partition layout for the cloud CA's boot volume.
#
# `nixos-anywhere` partitions from this and disko's NixOS module derives the
# `fileSystems` entries from the same declaration, so the two cannot drift —
# the arrangement `nix/machines/orin-nano/disk.nix` uses, with two differences
# that follow from this being a cloud instance rather than a board.
{
  disko.devices.disk.main = {
    type = "disk";
    # The provider's boot volume as the guest sees it. Oracle attaches the
    # boot volume over iSCSI/virtio and it enumerates as the first SCSI disk;
    # `/dev/sda` rather than the Orin's `/dev/nvme0n1`. Confirm with `lsblk`
    # on the stock image before the first `nixos-anywhere` run — this is the
    # one value that is wrong on a different provider, and getting it wrong
    # partitions nothing (or the wrong thing).
    device = "/dev/sda";
    content = {
      type = "gpt";
      partitions = {
        # 512M is ample here, unlike the Orin's 1G: this is a generic aarch64
        # kernel and a small initrd, not a Jetson BSP kernel, and the boot
        # volume is not where the size pressure is.
        ESP = {
          priority = 1;
          size = "512M";
          type = "EF00";
          content = {
            type = "filesystem";
            format = "vfat";
            mountpoint = "/boot";
            # FAT has no ownership bits, so the whole mount takes one mode.
            # Root-only, since the ESP holds the boot chain.
            mountOptions = [ "umask=0077" ];
          };
        };

        root = {
          size = "100%";
          content = {
            type = "filesystem";
            format = "ext4";
            mountpoint = "/";
          };
        };
      };
    };
  };
}
