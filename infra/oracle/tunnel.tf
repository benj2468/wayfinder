# The public face of the deployment: a Cloudflare Tunnel for the web dashboard,
# and a DNS name for the management API.
#
# The two are exposed in deliberately different ways, because they are
# different protocols with different threat models:
#
#   * The **dashboard** is HTTP, so it goes through a tunnel. `cloudflared` on
#     the instance dials *out* to Cloudflare and public requests are routed back
#     down that connection — so nothing is listening on the public address,
#     the security list needs no HTTP rule, and TLS and its certificates are
#     Cloudflare's problem rather than an ACME client's on a 1 GB box. The cost
#     is that Cloudflare terminates TLS and therefore sees the dashboard's
#     plaintext, including a password at sign-in. That is a real trust
#     decision; `docs/design/implemented/11-cloud-auth-provider.md` records it.
#
#   * The **management API** is not HTTP and cannot go through the same door.
#     It is a bespoke protocol over TLS on port 7700 that authenticates by mesh
#     identity as an RFC 7250 raw public key, and Cloudflare's HTTP proxy cannot
#     carry it. So it gets a plain DNS-only A record straight to the instance,
#     and the security list rule in `main.tf` is what admits it. Nothing is lost
#     by that: the protocol's own authentication is stronger than anything a
#     proxy would add, and the connection is already end-to-end encrypted with
#     keys Cloudflare does not hold.

variable "manage_tunnel" {
  type        = bool
  default     = false
  description = <<-EOT
    Create a Cloudflare Tunnel and the DNS records for it.

    Requires `cloudflare_zone_id`, `cloudflare_account_id` and a
    `CLOUDFLARE_API_TOKEN` with `Zone:DNS:Edit` on the zone and
    `Account:Cloudflare Tunnel:Edit`.
  EOT
}

variable "cloudflare_account_id" {
  type        = string
  default     = ""
  description = "Cloudflare account the tunnel belongs to. Only read when manage_tunnel is true."
}

variable "dashboard_name" {
  type        = string
  default     = "dash"
  description = "Record name for the dashboard within the zone, e.g. \"dash\" for dash.example.org."
}

variable "tunnel_name" {
  type        = string
  default     = "wayfinder-ca"
  description = <<-EOT
    Name of the tunnel. Must match `wayfinder.ca.tunnelId` in
    `nix/machines/wayfinder-ca/common.nix` — `cloudflared` names its outbound
    connection with it.
  EOT
}

# The tunnel's shared secret. Generated here rather than by Cloudflare so it can
# be written into the credentials file below without a second round trip, and
# kept in OpenTofu state rather than in the repo.
#
# `result_base64` is exactly what the credentials JSON wants; 32 bytes is what
# cloudflared expects.
resource "random_bytes" "tunnel_secret" {
  count  = var.manage_tunnel ? 1 : 0
  length = 32
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "ca" {
  count = var.manage_tunnel ? 1 : 0

  account_id    = var.cloudflare_account_id
  name          = var.tunnel_name
  tunnel_secret = random_bytes.tunnel_secret[0].base64
  config_src    = "local"
}

# `config_src = "local"` above means the ingress rules live in the instance's
# own cloudflared configuration — which NixOS generates from
# `services.cloudflared` in `nix/machines/wayfinder-ca/common.nix` — rather than
# in Cloudflare's dashboard. One place decides what the tunnel serves, and it is
# the same place that decides everything else about this host.

# What `cloudflared` on the instance authenticates with. Written locally for
# `scripts/wayfinder-ca.sh secrets` to copy up; it is a secret, so it lands
# beside the mesh trust material rather than in the repo.
resource "local_sensitive_file" "tunnel_credentials" {
  count = var.manage_tunnel ? 1 : 0

  filename        = pathexpand("${var.secrets_dir}/cloudflared.json")
  file_permission = "0400"
  content = jsonencode({
    AccountTag   = var.cloudflare_account_id
    TunnelID     = cloudflare_zero_trust_tunnel_cloudflared.ca[0].id
    TunnelSecret = random_bytes.tunnel_secret[0].base64
  })
}

# The dashboard's name, pointed at the tunnel rather than at any address.
# `proxied` must be true: a tunnel is only reachable *through* Cloudflare, so a
# DNS-only record here would resolve to a name that answers nothing.
resource "cloudflare_dns_record" "dashboard" {
  count = var.manage_tunnel ? 1 : 0

  zone_id = var.cloudflare_zone_id
  name    = var.dashboard_name
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.ca[0].id}.cfargotunnel.com"
  ttl     = 1 # required by Cloudflare for a proxied record
  proxied = true
  comment = "Wayfinder CA dashboard, via Cloudflare Tunnel"
}

variable "secrets_dir" {
  type        = string
  default     = "~/ca-secrets"
  description = <<-EOT
    Where the offline-minted mesh trust material lives, and where the tunnel
    credentials are written for `scripts/wayfinder-ca.sh secrets` to pick up.

    Matches that script's `CA_SECRETS_DIR`. Never inside this repository.
  EOT
}
