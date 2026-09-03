# The cloud certificate authority's instance and the network around it.
#
# What this file does NOT do is install anything. It provisions a bare Ubuntu
# instance with a public address and a hole in the firewall; `nixos-anywhere`
# then kexecs over that image and installs
# `nixosConfigurations.wayfinder-ca`. Keeping the two apart means a
# `tofu apply` never rebuilds the node, and a node rebuild never risks the
# instance. See README.md.

# Availability domain to place the instance in. A1 capacity varies by AD as
# well as by region, so this takes the first and the runbook says to try
# another when a create fails on capacity.
data "oci_identity_availability_domains" "ads" {
  compartment_id = var.compartment_ocid
}

# The newest Ubuntu aarch64 image for the A1 shape. This OS is scaffolding: it
# exists only long enough for `nixos-anywhere` to SSH in and replace it, so the
# choice matters only in that it must boot on A1 and run an SSH server.
data "oci_core_images" "ubuntu" {
  compartment_id           = var.compartment_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "22.04"
  # Filtering by shape is also what picks the architecture: OCI only returns
  # images that boot on it, so this yields aarch64 for A1 and x86_64 for E2
  # without naming either.
  shape      = var.instance_shape
  sort_by    = "TIMECREATED"
  sort_order = "DESC"
}

resource "oci_core_vcn" "ca" {
  compartment_id = var.compartment_ocid
  display_name   = var.instance_name
  cidr_blocks    = [var.vcn_cidr]
  dns_label      = "wayfinderca"
}

resource "oci_core_internet_gateway" "ca" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.ca.id
  display_name   = "${var.instance_name}-igw"
  enabled        = true
}

resource "oci_core_route_table" "ca" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.ca.id
  display_name   = "${var.instance_name}-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.ca.id
  }
}

resource "oci_core_security_list" "ca" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.ca.id
  display_name   = "${var.instance_name}-sl"

  # Outbound is unrestricted: the node fetches its own updates and, once
  # design 08 lands, will originate tunnel traffic.
  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
  }

  # SSH, for `nixos-anywhere` and for operator access afterwards.
  ingress_security_rules {
    protocol    = "6" # TCP
    source      = var.ssh_ingress_cidr
    description = "SSH"
    tcp_options {
      min = 22
      max = 22
    }
  }

  # The management API. This is the port that makes the box useful: every node
  # that enrols, every operator that approves or revokes, arrives here.
  ingress_security_rules {
    protocol    = "6" # TCP
    source      = var.mgmt_ingress_cidr
    description = "Wayfinder management API (TLS)"
    tcp_options {
      min = 7700
      max = 7700
    }
  }

  # ICMP path-MTU and unreachable messages. Dropping these is the classic
  # cause of a TLS handshake that hangs instead of failing.
  ingress_security_rules {
    protocol    = "1" # ICMP
    source      = "0.0.0.0/0"
    description = "Path MTU discovery / destination unreachable"
    icmp_options {
      type = 3
      code = 4
    }
  }

  # The tunnel control plane (design 08). Every node that joins the VPN
  # registers here, and the embedded DERP relay serves its own traffic on this
  # same port when two peers cannot reach each other directly.
  #
  # 443, and TLS is not optional on it: a `tailscaled` refuses a plaintext DERP
  # connection and loses STUN probing with it. The certificate comes from Let's
  # Encrypt, answered with the TLS-ALPN-01 challenge on this very listener —
  # which is why there is no HTTP-01 rule on port 80 here.
  ingress_security_rules {
    protocol    = "6" # TCP
    source      = "0.0.0.0/0"
    description = "Headscale coordination + embedded DERP relay (TLS)"
    tcp_options {
      min = 443
      max = 443
    }
  }

  # STUN, for the embedded relay. This is the one rule that made the host
  # choice: Cloudflare was rejected for design 11 precisely because it offers
  # no UDP ingress, which would have left every tunnel relaying through this
  # box instead of hole-punching past the CGNAT it exists to defeat.
  #
  # Losing this rule does not break connectivity — it degrades it, silently and
  # only under load. Nothing reports it but a latency measurement.
  ingress_security_rules {
    protocol    = "17" # UDP
    source      = "0.0.0.0/0"
    description = "Headscale embedded DERP relay (STUN)"
    udp_options {
      min = 3478
      max = 3478
    }
  }

  # This box's own `tailscaled`, now that the CA carries a mesh link of its own
  # (`nix/machines/wayfinder-ca/common.nix`). Opening it is what lets a spoke
  # hole-punch a direct WireGuard path to this node instead of relaying — and
  # relaying here means through the DERP server running on this same box, so
  # every mesh frame between two spokes would cross it twice.
  #
  # Note what is deliberately *not* opened: the mesh link's own UDP port. It
  # binds 0.0.0.0 but is reached only inside the tunnel, where `tailscale0` is
  # a trusted interface in the host firewall. A rule for it here would put the
  # mesh on the public address, which is the one thing this arrangement exists
  # to avoid.
  ingress_security_rules {
    protocol    = "17" # UDP
    source      = "0.0.0.0/0"
    description = "Tailscale direct connections (design 08)"
    udp_options {
      min = 41641
      max = 41641
    }
  }

  # The iroh relay's QUIC address discovery (design 18) — what replaced STUN in
  # iroh, and the exact analogue of the UDP/3478 rule above. A node asks this
  # port what its own public address is; without an answer it cannot hole-punch
  # at all and every `Iroh` link falls back to relaying through this box.
  #
  # Same silent-degradation shape as the STUN rule: losing it breaks nothing
  # visibly, it just quietly routes every spoke-to-spoke frame through here.
  ingress_security_rules {
    protocol    = "17" # UDP
    source      = "0.0.0.0/0"
    description = "iroh relay QUIC address discovery (design 18)"
    udp_options {
      min = 7842
      max = 7842
    }
  }

  # This box's own iroh mesh link, so a spoke can hole-punch a direct QUIC path
  # to it rather than relaying. The counterpart of the UDP/41641 rule above,
  # and pinned for the same reason: an ephemeral port would give the NAT a
  # fresh mapping on every restart.
  ingress_security_rules {
    protocol    = "17" # UDP
    source      = "0.0.0.0/0"
    description = "iroh mesh link direct connections (design 18)"
    udp_options {
      min = 6001
      max = 6001
    }
  }
}

resource "oci_core_subnet" "ca" {
  compartment_id    = var.compartment_ocid
  vcn_id            = oci_core_vcn.ca.id
  display_name      = "${var.instance_name}-subnet"
  cidr_block        = var.subnet_cidr
  route_table_id    = oci_core_route_table.ca.id
  security_list_ids = [oci_core_security_list.ca.id]
  dns_label         = "ca"
}

resource "oci_core_instance" "ca" {
  compartment_id      = var.compartment_ocid
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  display_name        = var.instance_name
  shape               = var.instance_shape

  # Only a `.Flex` shape takes a resource configuration; E2.1.Micro's 1/8 OCPU
  # and 1 GB are fixed, and OCI rejects a shape_config supplied for it.
  dynamic "shape_config" {
    for_each = endswith(var.instance_shape, ".Flex") ? [1] : []
    content {
      ocpus         = var.instance_ocpus
      memory_in_gbs = var.instance_memory_gbs
    }
  }

  source_details {
    source_type             = "image"
    source_id               = data.oci_core_images.ubuntu.images[0].id
    boot_volume_size_in_gbs = var.boot_volume_gbs
  }

  create_vnic_details {
    subnet_id = oci_core_subnet.ca.id
    # False, and paired with `oci_core_public_ip` below. True would have OCI
    # attach an *ephemeral* public IP at launch, and a private IP may hold only
    # one public IP — so the reserved address then fails to attach with a
    # 409-Conflict. Ephemeral is also the wrong lifetime here: it is released
    # when the instance stops, which would hand the fleet a CA it can no longer
    # find after a routine stop/start.
    assign_public_ip = false
    hostname_label   = var.instance_name
  }

  metadata = {
    ssh_authorized_keys = var.ssh_public_key
  }

  # The instance is a container for a boot volume that `nixos-anywhere`
  # rewrites in place. Every one of these is a property of the *stock* image
  # and is meaningless the moment NixOS is installed over it, so a change to
  # any of them must not tempt a replace — that would destroy a running CA and
  # its state along with it.
  lifecycle {
    ignore_changes = [
      source_details[0].source_id,
      metadata,
    ]
  }
}

# The instance's primary VNIC, resolved so the ephemeral public IP can be
# swapped for a reserved one below.
data "oci_core_vnic_attachments" "ca" {
  compartment_id = var.compartment_ocid
  instance_id    = oci_core_instance.ca.id
}

data "oci_core_private_ips" "ca" {
  vnic_id = data.oci_core_vnic_attachments.ca.vnic_attachments[0].vnic_id
}

# A *reserved* public IP, not the ephemeral one the instance is created with.
#
# The distinction is load-bearing rather than cosmetic. Every node in the mesh
# is configured with this address, and every client pins the CA's key against
# it; an ephemeral address is released when the instance is stopped, so a
# routine stop/start would silently hand the fleet a CA it can no longer find.
# A reserved IP survives that, and stays inside Always Free.
resource "oci_core_public_ip" "ca" {
  compartment_id = var.compartment_ocid
  display_name   = "${var.instance_name}-ip"
  lifetime       = "RESERVED"
  private_ip_id  = data.oci_core_private_ips.ca.private_ips[0].id
}
