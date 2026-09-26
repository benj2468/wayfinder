#!/usr/bin/env bash
# Run one CI step unless a run with exactly the same inputs already passed.
#
#   ci-cached.sh <step> <ci-input-hash.py args...> -- <command...>
#
# The finer-grained sibling of `.skip-if-passed` in .gitlab-ci.yml, for a job
# that does several independent things, like one build per board: each step
# gets its own input hash, so touching one board rebuilds that board alone.
#
# A pass marker is written under $CI_PASS_DIR (default /sccache/ci-passed, the
# runners' persistent volume) only after <command> succeeds, and a failing
# command's exit status is passed through, so a failure is never cached.
set -euo pipefail

step="$1"
shift
hash_args=()
while [[ $# -gt 0 && "$1" != "--" ]]; do
  hash_args+=("$1")
  shift
done
[[ $# -gt 0 ]] || {
  echo "ci-cached.sh: missing -- before the command" >&2
  exit 2
}
shift

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
hash="$(python3 "$here/ci-input-hash.py" "${hash_args[@]}")"
mark="${CI_PASS_DIR:-/sccache/ci-passed}/${CI_JOB_NAME//:/_}/$step/$hash"

if [[ -e "$mark" ]]; then
  echo "[$step] inputs unchanged since a passing run; skipping"
  exit 0
fi

echo "[$step] running"
"$@"
mkdir -p "$(dirname "$mark")"
touch "$mark"
