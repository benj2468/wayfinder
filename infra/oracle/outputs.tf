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

output "site_project" {
  value       = var.manage_site ? cloudflare_pages_project.site[0].name : null
  description = "The Cloudflare Pages project `scripts/wayfinder-ca.sh site` publishes into. Null when manage_site is false, in which case the project is whatever that script's `site_project_name` default names."
}

output "site_url" {
  value       = var.manage_site ? "https://${data.cloudflare_zone.site[0].name}/" : null
  description = "The landing page's public address, once a deployment has been uploaded. The project exists empty until then — `tofu apply` provisions the container, `wayfinder-ca.sh site` fills it."
}
