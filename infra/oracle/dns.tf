# Optional: a stable name for the CA, in Cloudflare.
#
# Off by default (`manage_dns = false`) and separated into its own file because
# it is the one resource here that is not Oracle's and not required — an IP
# address in each node's config works fine. It earns its place when the CA is
# ever rebuilt in another region, since a name can be repointed and a hundred
# pinned addresses cannot.
#
# The record is deliberately **DNS-only** (`proxied = false`). Cloudflare's
# proxy terminates HTTP; the management API is neither HTTP nor on a port the
# proxy carries, so an orange-clouded record would resolve to Cloudflare and
# then refuse the connection.

variable "manage_dns" {
  type        = bool
  default     = false
  description = "Create a Cloudflare DNS record for the CA. Requires cloudflare_zone_id and CLOUDFLARE_API_TOKEN."
}

variable "cloudflare_zone_id" {
  type        = string
  default     = ""
  description = "Cloudflare zone to create the record in. Only read when manage_dns is true."
}

variable "dns_name" {
  type        = string
  default     = "ca"
  description = "Record name within the zone, e.g. \"ca\" for ca.example.org."
}

resource "cloudflare_dns_record" "ca" {
  count = var.manage_dns ? 1 : 0

  zone_id = var.cloudflare_zone_id
  name    = var.dns_name
  type    = "A"
  content = oci_core_public_ip.ca.ip_address
  ttl     = 300
  # See the header: the management API cannot pass through Cloudflare's proxy.
  proxied = false
  comment = "Wayfinder mesh certificate authority (management API on TCP 7700)"
}
