# Optional: the wayfndr.dev landing page's Cloudflare Pages project.
#
# The page itself is *published* by `scripts/wayfinder-ca.sh site` (a
# `wrangler pages deploy` of `dist/site`), and that stays true — a static
# upload is a deploy step, not an infrastructure change, and it rides with the
# node rollout on purpose so the page never announces a change the box has not
# taken. What lives here is the thing that upload needs to *already exist*: the
# Pages project, its production branch, and the two custom domains. Those were
# a one-time click-through in the Cloudflare dashboard, which is exactly the
# kind of state that is invisible until someone has to rebuild it.
#
# So the split is: OpenTofu owns the container, `wrangler` fills it.
#
# Separated into its own file for the same reason `dns.tf` and `tunnel.tf` are:
# it is not Oracle's, and it is not required for a CA to work. A deployment
# that only wants the node sets `manage_site = false` (the default) and
# provisions nothing here.

variable "manage_site" {
  type        = bool
  default     = false
  description = <<-EOT
    Create the Cloudflare Pages project and custom domains for the landing
    page.

    Requires `cloudflare_zone_id`, `cloudflare_account_id` and a
    `CLOUDFLARE_API_TOKEN` carrying `Account:Cloudflare Pages:Edit` (which
    `scripts/wayfinder-ca.sh site` already needs to publish), `Zone:DNS:Edit`
    for the two CNAMEs, and `Zone:Zone:Read` for the zone lookup below.

    **If the Pages project already exists**, this will not create it a second
    time — it will fail. Import it instead; see README.md, "Adopting an
    existing Pages project".
  EOT
}

variable "site_project_name" {
  type        = string
  default     = "wayfinder-site"
  description = <<-EOT
    Name of the Cloudflare Pages project. Also decides the deployment
    subdomain, `<name>.pages.dev`.

    `scripts/wayfinder-ca.sh` reads this out of terraform.tfvars, so changing
    it here changes what the publish targets. The `just site-deploy` preview
    recipe hard-codes the default; change it there too if you rename this.

    Renaming is destructive: Cloudflare has no rename, so OpenTofu deletes the
    project and creates a new one, taking every previous deployment — and with
    them the instant rollback — with it.
  EOT
}

variable "site_production_branch" {
  type        = string
  default     = "main"
  description = <<-EOT
    Branch name a deployment must carry to be treated as production.

    `scripts/wayfinder-ca.sh site` passes `--branch main`; anything else lands
    as a preview on `<branch>.<project>.pages.dev` without touching the live
    site, which is what `just site-deploy <branch>` relies on.
  EOT
}

variable "site_www" {
  type        = bool
  default     = true
  description = "Also attach www.<zone> to the project. The page's own canonical link is the apex; this exists so the www spelling does not dead-end."
}

# The zone's name, which the apex record and both custom domains need as an
# FQDN. Asked of Cloudflare rather than written into terraform.tfvars, for the
# reason `scripts/wayfinder-ca.sh`'s `dashboard_hostname` gives: the zone id is
# the only identifier this configuration records, and a second copy of the
# name is a copy that goes stale the day the zone is renamed.
data "cloudflare_zone" "site" {
  count = var.manage_site ? 1 : 0

  zone_id = var.cloudflare_zone_id
}

# A **Direct Upload** project: `source` is deliberately omitted. Cloudflare's
# Git integration connects only to github.com and gitlab.com, and this project
# lives on a self-hosted GitLab whose GitHub mirror is push-only and lags — so
# pointing Pages at a repository would mean deploying from a second source of
# truth. See www/README.md.
#
# `build_config` is omitted for the same reason there is no bundler: `www/` is
# already the site, and `scripts/build-site.sh` assembles it locally.
resource "cloudflare_pages_project" "site" {
  count = var.manage_site ? 1 : 0

  account_id        = var.cloudflare_account_id
  name              = var.site_project_name
  production_branch = var.site_production_branch
}

# Attaching a custom domain does **not** create its DNS record — Cloudflare
# requires one to already exist, and validates ownership against it. Hence the
# records first and `depends_on` below; without that ordering the domain sits
# in `pending` until someone notices.
#
# `proxied` must be true, and this is the one place in this configuration where
# that is the right answer: a Pages site *is* served by Cloudflare, so unlike
# the CA and VPN records in `dns.tf` there is no origin behind the name for a
# DNS-only record to point at. The apex works as a CNAME because Cloudflare
# flattens it, which is a property of the proxy — another reason it cannot be
# turned off here.
resource "cloudflare_dns_record" "site_apex" {
  count = var.manage_site ? 1 : 0

  zone_id = var.cloudflare_zone_id
  name    = data.cloudflare_zone.site[0].name
  type    = "CNAME"
  content = cloudflare_pages_project.site[0].subdomain
  ttl     = 1 # required by Cloudflare for a proxied record
  proxied = true
  comment = "Wayfinder landing page, on Cloudflare Pages"
}

resource "cloudflare_dns_record" "site_www" {
  count = var.manage_site && var.site_www ? 1 : 0

  zone_id = var.cloudflare_zone_id
  name    = "www.${data.cloudflare_zone.site[0].name}"
  type    = "CNAME"
  content = cloudflare_pages_project.site[0].subdomain
  ttl     = 1
  proxied = true
  comment = "Wayfinder landing page, on Cloudflare Pages"
}

resource "cloudflare_pages_domain" "site_apex" {
  count = var.manage_site ? 1 : 0

  account_id   = var.cloudflare_account_id
  project_name = cloudflare_pages_project.site[0].name
  name         = data.cloudflare_zone.site[0].name

  depends_on = [cloudflare_dns_record.site_apex]
}

resource "cloudflare_pages_domain" "site_www" {
  count = var.manage_site && var.site_www ? 1 : 0

  account_id   = var.cloudflare_account_id
  project_name = cloudflare_pages_project.site[0].name
  name         = "www.${data.cloudflare_zone.site[0].name}"

  depends_on = [cloudflare_dns_record.site_www]
}
