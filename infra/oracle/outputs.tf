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

output "vpn_coordination_endpoint" {
  value       = "https://${oci_core_public_ip.ca.ip_address}:443"
  description = "Headscale, by address. Nodes register against the *name* (`services.wayfinder-headscale.domain` in nix/machines/wayfinder-ca/common.nix, which the `vpn_dns_name` record points here) — by address the certificate will not match, so this is for checking the port answers at all, with `curl -k`."
}
