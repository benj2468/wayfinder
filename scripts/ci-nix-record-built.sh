#!/bin/sh
# Nix `post-build-hook` for CI: record each store path this job *built* (not
# substituted), so `after_script` can push exactly those to the binary cache.
#
# Only records — the push happens once, at the end, in `.nix-cache`'s
# after_script. A hook runs synchronously after every derivation and blocks the
# build loop while it does, and a CI build is a thousand-odd derivations, so a
# network round-trip per derivation here would dominate the job. Recording also
# means a failed job still pushes everything it built before failing.
#
# Must never fail: a nonzero exit from a post-build-hook fails the build.
# Nix passes the outputs in $OUT_PATHS, space-separated.
# Split on spaces on purpose (one path per line); store paths never contain
# glob characters, but globbing is off anyway.
set -f
# shellcheck disable=SC2086
printf '%s\n' $OUT_PATHS >>"${CI_NIX_BUILT_PATHS:-/tmp/nix-built-paths}" || true
exit 0
