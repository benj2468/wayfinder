# Inputs for the cloud CA instance. Everything with a default is set to stay
# inside Oracle's Always Free allowance; the validations exist so a typo bills
# you rather than failing, which is the failure mode that actually happens.

variable "region" {
  type        = string
  description = <<-EOT
    OCI region to create the instance in, e.g. "us-ashburn-1".

    Ampere A1 capacity is genuinely scarce in some regions and a create can
    fail with "Out of host capacity" — that is a real Always Free constraint,
    not a misconfiguration. Retrying, or picking a different region in your
    home tenancy, is the fix.
  EOT
}

variable "compartment_ocid" {
  type        = string
  description = "Compartment to create every resource in. The tenancy's root compartment OCID is a fine answer for a single-purpose tenancy."
}

variable "ssh_public_key" {
  type        = string
  description = <<-EOT
    SSH public key authorised for the stock image's default user, and
    afterwards for `root` on the installed NixOS system.

    This is the key `nixos-anywhere` connects with to install, so losing it
    before the install completes means recreating the instance.
  EOT
}

variable "ssh_ingress_cidr" {
  type        = string
  default     = "0.0.0.0/0"
  description = <<-EOT
    Source range permitted to reach SSH (22).

    Defaulted open because an operator's address is usually dynamic and a
    locked-out box has to be recovered through the serial console. Narrow it if
    you can: this host holds the mesh root key, and SSH is the only port on it
    that grants anything beyond enrollment.
  EOT
}

variable "mgmt_ingress_cidr" {
  type        = string
  default     = "0.0.0.0/0"
  description = <<-EOT
    Source range permitted to reach the management API (7700).

    Open by default, and that is the intended posture: the whole point of this
    box is that any node, anywhere, can reach it to enrol. The port is not
    unguarded — the API authenticates every connection by mesh identity in the
    TLS handshake, admits an un-certified peer to the enrollment tier only, and
    rate-limits that tier per source (5-request burst, refilling one per five
    seconds) as well as new connections (20-burst, two per second). See
    `docs/design/implemented/11-cloud-auth-provider.md`.
  EOT
}

variable "instance_shape" {
  type        = string
  default     = "VM.Standard.E2.1.Micro"
  description = <<-EOT
    Compute shape. Always Free covers two of these, and which one you can
    actually get is a capacity question, not a preference:

      * `VM.Standard.A1.Flex`   — Ampere aarch64, up to 2 OCPU / 12 GB total.
        The better machine, and frequently unobtainable: a launch fails with
        "Out of host capacity" and there is no queue to join. A1 is also the
        only one of the two that can build the node natively on an aarch64
        workstation.
      * `VM.Standard.E2.1.Micro` — AMD x86_64, fixed 1/8 OCPU and 1 GB. Almost
        always available. 1 GB is ~150x this node's measured working set (see
        `docs/design/implemented/11-cloud-auth-provider.md`), so for a
        certificate authority the smaller shape costs nothing that matters.

    Changing this **must** be paired with `nixpkgs.hostPlatform.system` in
    `nix/machines/wayfinder-ca/common.nix` — `aarch64-linux` for A1,
    `x86_64-linux` for E2. A mismatch installs a system the instance cannot
    boot, and it fails after `nixos-anywhere` has already replaced the disk.

    `instance_ocpus` and `instance_memory_gbs` apply only to `.Flex` shapes;
    E2.1.Micro's resources are fixed and OCI rejects a shape_config for it.
  EOT

  validation {
    condition = contains([
      "VM.Standard.A1.Flex",
      "VM.Standard.E2.1.Micro",
    ], var.instance_shape)
    error_message = "Only the two Always Free shapes are supported: VM.Standard.A1.Flex or VM.Standard.E2.1.Micro."
  }
}

variable "instance_name" {
  type        = string
  default     = "wayfinder-ca"
  description = "Display name for the instance and its related resources."
}

variable "instance_ocpus" {
  type        = number
  default     = 1
  description = <<-EOT
    OCPUs for the Ampere A1 instance.

    One, not the full free allowance of two: the measured working set of a
    certificate authority is single-digit megabytes and effectively no CPU (see
    the design doc), so half the allowance is left for a second Always Free box
    — which is where design 08's Headscale coordination server would go.
  EOT

  validation {
    condition     = var.instance_ocpus >= 1 && var.instance_ocpus <= 2
    error_message = "Always Free allows 2 Ampere A1 OCPUs in total; more than 2 is billed."
  }
}

variable "instance_memory_gbs" {
  type        = number
  default     = 6
  description = "Memory for the Ampere A1 instance, in GB. Always Free allows 12 GB in total across A1 instances; 6 pairs with 1 OCPU (A1 is allocated at 6 GB per OCPU)."

  validation {
    condition     = var.instance_memory_gbs >= 1 && var.instance_memory_gbs <= 12
    error_message = "Always Free allows 12 GB of Ampere A1 memory in total; more than 12 is billed."
  }
}

variable "boot_volume_gbs" {
  type        = number
  default     = 50
  description = "Boot volume size in GB. Always Free allows 200 GB of block storage in total; 50 leaves room for a second instance."

  validation {
    condition     = var.boot_volume_gbs >= 50 && var.boot_volume_gbs <= 200
    error_message = "OCI's minimum boot volume is 50 GB, and Always Free allows 200 GB in total."
  }
}

variable "vcn_cidr" {
  type        = string
  default     = "10.60.0.0/16"
  description = "Address space for the VCN. Deliberately not overlapping the 10.55.21.0/24 the Nix module's `ethernetAccess` hands out, so a future tunnel between the two does not collide."
}

variable "subnet_cidr" {
  type        = string
  default     = "10.60.1.0/24"
  description = "Address space for the public subnet the instance sits in."
}
