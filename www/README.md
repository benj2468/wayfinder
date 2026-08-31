# wayfndr.dev — the public landing page

A hand-authored static site. No framework, no bundler, no build step: `www/` is
already the site, and `scripts/build-site.sh` only assembles it with the logo.

That is a deliberate choice rather than an omission. A marketing page is three
files that change a few times a year; a toolchain around them would be a second
thing to keep alive, would put a `node_modules` in the dependency graph of a
repo whose entire point is a `no_std` core, and would make the page's build the
slowest part of a pipeline that otherwise compiles Rust for four targets. If
this ever grows into a docs site with many pages, that is the moment to
reconsider — not before.

## Layout

| File                        | What it is                                                                                            |
| --------------------------- | ----------------------------------------------------------------------------------------------------- |
| `index.html`                | The whole page. One document, sectioned by comment banners.                                           |
| `styles.css`                | All styling, driven by the token block at the top.                                                    |
| `mesh.js`                   | The hero diagram, plus two small page behaviours. No dependencies.                                    |
| `og.html`                   | 1200×630 source for the social card. **Not published** — the build script deletes it from the output. |
| `_headers`                  | Cloudflare Pages security headers + cache policy.                                                     |
| `robots.txt`, `sitemap.xml` | Standard.                                                                                             |

The logo is **not** in this directory. `assets/logo/` is the repo's single
source of truth for the mark (see its own `README.md`), and the build script
copies the three files in at assemble time — so the page cannot drift from the
dashboard's copy of the mark.

## Working on it

```bash
just site-build      # assemble into dist/site
just site-serve      # assemble and serve at http://127.0.0.1:8899
nix fmt              # prettier formats www/*.{html,css,js}; treefmt owns the rest
```

There is no test suite. What there is instead: the build script fails if any
required file is missing from the output, so a renamed stylesheet cannot ship as
a 404.

## Design notes

The palette is the logo's, not a new one — warm paper, near-black ink, and the
mark's red used only as an accent. Two consequences worth knowing before
editing:

- **The page commits to one light theme.** A dashboard has to follow the
  operator's environment; a landing page has one job and is better for choosing
  a look. Rhythm comes from alternating paper and ink _sections_
  (`.section--ink` re-points the shared tokens rather than overriding every
  descendant rule), not from a colour-scheme toggle. Don't add one.
- **The footer mark is a CSS `mask`, not an `<img>`.** `wayfinder-mark-mono.svg`
  is `fill="currentColor"`, which does not resolve through a referenced SVG —
  as an `<img>` it renders black on the black footer. `assets/logo/README.md`
  covers this; the mask keys off alpha and takes its colour from
  `background-color`.

The hero diagram runs a real Dijkstra over a real link graph rather than
replaying a scripted animation, because the failure sequence would otherwise
have to be authored per edge — more code, not less. It respects
`prefers-reduced-motion` by rendering the converged graph and stopping.

### Regenerating the social card

Open Graph consumers will not render SVG, so `og.png` has to be a raster. It is
rendered from `og.html` so it stays in sync with the site's own type and
palette:

```bash
just site-build
cp www/og.html dist/site/          # build-site.sh strips it from the output
npx --yes playwright screenshot \
  --viewport-size=1200,630 --wait-for-timeout=1200 \
  dist/site/og.html www/og.png
```

Commit the resulting `www/og.png`. Until it exists the `og:image` meta tag
points at a URL that 404s, which degrades to a link preview with no image —
harmless, but worth doing before the link is shared anywhere.

## Deployment

Cloudflare Pages, uploaded by `scripts/wayfinder-ca.sh`.

**Why it ships with the CA rollout and not from CI.** It used to be its own
pipeline job, firing on every merge to `main` that touched `www/`. It is not any
more: the page describes what the deployment is running, and a page that has
already announced a change the box has not taken is the wrong way round.
`wayfinder-ca.sh update` now rolls out the node and publishes the page in one
go, and `wayfinder-ca.sh site` publishes the page alone when only copy changed.

**Why Direct Upload and not Cloudflare's Git integration:** the Git integration
connects only to `github.com` and `gitlab.com`, and this project lives on a
self-hosted GitLab. The GitHub mirror (`mirror:github`) is push-only and lags,
so pointing Cloudflare at it would mean deploying from a second source of
truth.

### One-time setup

The Pages project, its production branch and both custom domains are
**provisioned by OpenTofu**, in `infra/oracle/site.tf` — they used to be a
click-through in the Cloudflare dashboard, which is the kind of state that is
invisible until someone has to rebuild it. Two steps remain, and only one of
them is on Cloudflare's website.

1. **Mint an API token.** _My Profile → API Tokens → Create Token → Custom_:

   |                   |                                                       |
   | ----------------- | ----------------------------------------------------- |
   | Permission        | `Account` → `Cloudflare Pages` → `Edit`               |
   | Permission        | `Zone` → `DNS` → `Edit` (the two custom-domain CNAMEs) |
   | Permission        | `Zone` → `Zone` → `Read` (to resolve the zone's name)  |
   | Account resources | Include → your account                                |
   | Zone resources    | Include → your zone                                   |

   `wayfinder-ca.sh` reuses **one** token for the publish, the DNS records, the
   tunnel and the cache purge, so these are *added to* the scopes the rest of
   that script already needs — see `infra/oracle/README.md` for the full list.
   Put it in `~/.cf-token` (mode `0600`, the token and nothing else), or
   wherever `CA_CF_TOKEN_FILE` points.

2. **Turn the site on and apply.** In `infra/oracle/terraform.tfvars`:

   ```hcl
   manage_site           = true
   cloudflare_account_id = "..."
   cloudflare_zone_id    = "..."
   # site_project_name   = "wayfinder-site"   # the default
   ```

   ```bash
   ./scripts/wayfinder-ca.sh provision   # tofu apply
   ./scripts/wayfinder-ca.sh site        # the first real deployment
   ```

   The apply creates a **Direct Upload** project (no Git integration, for the
   reason above), sets its production branch to `main`, and attaches `wayfndr.dev` and
   `www.wayfndr.dev` along with the proxied `CNAME` for each. Between the two
   commands the project exists and is empty, and the domain answers a Cloudflare
   placeholder; that is the expected intermediate state. `.dev` is on the HSTS
   preload list, so the name is HTTPS-only from the first request — there is no
   HTTP fallback to test.

   The project name lives in `terraform.tfvars` and `wayfinder-ca.sh` reads it
   from there. The `just site-deploy` preview recipe hard-codes the default;
   change it there too if you rename.

**If the project already exists** — made by hand before `site.tf` did, or in
another account — `manage_site = true` tries to create it a second time and
fails on the name rather than adopting it. Import the four objects first;
`infra/oracle/README.md`, "Adopting an existing Pages project", has the
commands.

### Deploying

- **With a rollout**: `./scripts/wayfinder-ca.sh update` publishes the page
  after the node switches. Never fatal — a failed publish leaves the rollout
  done and prints the command to retry.
- **On its own**: `./scripts/wayfinder-ca.sh site`, for a copy change that does
  not need the node rebuilt.
- **Preview**: `just site-deploy my-branch` publishes to
  `<branch>.wayfinder-site.pages.dev` without touching the live site.

Rollback is instant and needs none of the above: _Pages project → Deployments →
⋯ → Rollback_ on any previous deployment.

## Content that will need revisiting

The page currently sells a **design-partner programme** — it says the system
works and is looking for pilots, which is true today. Two things are placeholders
and should be changed deliberately, not left to rot:

- **`info@wayfndr.dev`** appears in three places in `index.html` (both CTAs and
  the footer). It needs a mailbox behind it; Cloudflare Email Routing will
  forward it to a real address without hosting mail.
- **No claims carry numbers.** Every technical statement on the page is
  qualitative (`no_std`, "zero allocation on the packet path") because those are
  verifiable from the repo. Adding a throughput, range or latency figure means
  having a measurement to point at — the benchmarks in `libs/wayfinder-bench`
  are timings on a developer laptop, not field numbers, and must not be quoted
  as if they were.
- **Media are named as examples, never as the definition.** The page sells the
  `LinkT` seam — any medium that carries a frame, and a new one is a driver
  rather than a change to the router. The original rule here was to name no
  medium at all, so the page would not date every time a driver landed; that
  was reversed, because "any medium that can carry a frame" reads to a buyer as
  a tautology rather than a capability, and because nobody searches for "frame
  carrier" — they search for the radio they own. So LoRa, Bluetooth LE, raw
  Ethernet, raw IP and UDP are named, as an illustration of the seam.

  Two things that follow. **Only name a leg that actually ships**: the
  `ieee802154` / `at86rf233` / `nrf-ieee802154` crates exist and are tested, but
  no board or config instantiates them, so 802.15.4 stays off the page until one
  does. And **keep the naming in one place** — the proof strip — so a new driver
  is a one-line edit rather than a hunt.
