# Provider and version pins for the cloud certificate authority's
# infrastructure. See README.md for the deployment runbook.
#
# OpenTofu rather than Terraform: it is what the repo's dev shell ships
# (`flake.nix`), and this configuration uses nothing specific to either.
terraform {
  required_version = ">= 1.6.0"

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = "~> 6.0"
    }
    # Only used by the optional dns.tf. Declared here rather than there so a
    # `tofu init` resolves the same provider set whether or not a DNS zone is
    # configured; with `manage_dns = false` it provisions nothing.
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
    # Generates the tunnel's shared secret (see tunnel.tf). `random_bytes`
    # rather than `random_password`: cloudflared wants 32 raw bytes, base64'd.
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    # Writes the tunnel credentials file for `scripts/wayfinder-ca.sh secrets`
    # to copy onto the instance.
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

# Credentials come from the standard OCI CLI config (~/.oci/config) or the
# OCI_* environment variables, never from this repo. `tenancy_ocid` and
# `region` are the only two this configuration needs to name explicitly.
provider "oci" {
  region = var.region
}
