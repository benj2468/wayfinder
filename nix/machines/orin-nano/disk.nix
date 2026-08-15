{
  disko.devices.disk.main = {
    type = "disk";
    device = "/dev/nvme0n1";
    content = {
      type = "gpt";
      partitions = {
        # 1G rather than the more common 512M: the Jetson kernel and its
        # initrd are large, and systemd-boot keeps every generation's pair in
        # the ESP. A too-small ESP fails at `nixos-rebuild` time, long after
        # the partitioning that caused it.
        ESP = {
          priority = 1;
          size = "1G";
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
