#!/usr/bin/env bash
#
# Print a hash of every input that can change a simulation-lab result.
#
# `just sim-export` writes this into www/sim/data/inputs.sha256 when it has
# regenerated every result, and the site build compares it against the tree
# it is about to publish: a mismatch means the router, the simulator or a
# scenario changed after the numbers on the page were computed.
#
# Deliberately over-inclusive. The results run the real router, compiled from
# libs/ into the wayfinder-py extension, so any crate it links can move them;
# telling which ones it links would take cargo, which the site job does not
# have, and a false "stale" costs one regeneration while a false "fresh"
# publishes wrong numbers. Fuzz targets, benches and docs are excluded because
# they cannot reach a result.
#
# Hashes file *contents* on disk, not git's index, so an export run from a
# dirty tree stamps what it actually ran.
#
# Usage: scripts/sim-inputs-hash.sh

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

git ls-files -z -- \
  libs sim/src sim/scenarios sim/pyproject.toml \
  Cargo.lock uv.lock pyproject.toml \
  ':!:libs/*/fuzz/**' ':!:libs/wayfinder-bench/**' ':!:*.md' |
  xargs -0 sha256sum |
  sha256sum |
  cut -d' ' -f1
