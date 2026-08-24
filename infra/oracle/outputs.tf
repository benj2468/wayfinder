# What the runbook's next steps need.

output "public_ip" {
  value       = oci_core_public_ip.ca.ip_address
  description = "The CA's reserved public address. This is what `nixos-anywhere` installs over, what nodes are pointed at, and what `openFirewallOn` must match an interface for."
}

output "install_command" {
  value       = "nixos-anywhere --flake .#wayfinder-ca --target-host ubuntu@${oci_core_public_ip.ca.ip_address}"
  description = "The install step. Run from the repo root after `tofu apply`; see README.md for what must be in place first."
}

output "ssh_command" {
  value       = "ssh root@${oci_core_public_ip.ca.ip_address}"
  description = "Operator access once NixOS is installed (the stock image's user is `ubuntu`; NixOS's is `root`)."
}
