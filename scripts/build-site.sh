#!/usr/bin/env bash
#
# Assemble the wayfndr.dev landing page into a directory Cloudflare Pages can
# upload verbatim.
#
# There is no bundler and no framework: `www/` is already the site. The only
# thing this script does that a `cp -r` would not is pull the logo in from
# `assets/logo/`, which is the repo's single source of truth for the mark
# (assets/logo/README.md and bins/wayfinder-web/src/components/logo.rs are the
# other two consumers). Copying the SVGs into `www/` and committing them would
# make a fourth copy to keep in sync; resolving them at build time cannot drift.
#
# Usage: scripts/build-site.sh [outdir]     (default: dist/site)

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-$root/dist/site}"

rm -rf "$out"
mkdir -p "$out"

cp -R "$root/www/." "$out/"

# The favicon adapts to the viewer's colour scheme, which is why it is a
# separate file from the header mark — see assets/logo/README.md.
cp "$root/assets/logo/wayfinder-icon.svg" "$out/favicon.svg"
cp "$root/assets/logo/wayfinder-mark.svg" "$out/wayfinder-mark.svg"
cp "$root/assets/logo/wayfinder-mark-mono.svg" "$out/wayfinder-mark-mono.svg"

# og.html is the 1200x630 source for the social preview image, rendered to
# og.png out of band (see www/README.md). It must not be published as a page.
rm -f "$out/og.html"

# Fail loudly rather than shipping a page whose stylesheet 404s.
for required in index.html styles.css mesh.js favicon.svg wayfinder-mark.svg _headers; do
  [ -f "$out/$required" ] || { echo "build-site: missing $required in $out" >&2; exit 1; }
done

echo "build-site: $out ($(find "$out" -type f | wc -l | tr -d ' ') files)"
