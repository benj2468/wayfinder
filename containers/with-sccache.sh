#!/bin/sh
# Run a build command through sccache when the image build was handed the
# cache's credentials, and exactly as-is when it was not.
#
#   RUN --mount=type=secret,id=sccache,required=false with-sccache cargo build ...
#
# The credentials arrive as a BuildKit secret (an env file of SCCACHE_* and
# AWS_* lines), never an ARG or ENV: a secret is mounted only for the RUN that
# asks for it and is not part of any layer or of the layer cache key. CI's
# `deploy` job passes one; a local `docker build` or `docker compose build`
# passes none, and the build is the same uncached build it always was.
#
# The server is stopped before returning, not left to be killed with the RUN's
# container: sccache uploads asynchronously, and a server killed mid-upload
# loses the entries it had not written yet.
set -u

secret=/run/secrets/sccache
if [ -s "$secret" ]; then
  set -a
  # shellcheck disable=SC1090 # the path is the secret mount's, not the repo's
  . "$secret"
  set +a
  RUSTC_WRAPPER=/usr/local/bin/sccache
  # A Unix socket in this RUN's own filesystem, not sccache's default TCP port.
  # BuildKit's RUN steps share one network namespace, and a multi-platform
  # build runs the amd64 and arm64 builders at once: on a shared 127.0.0.1:4226
  # the second builder's compiles reach the first's server, which runs rustc
  # inside the *other* container — where the target's std is not installed
  # ("can't find crate for `core`"). A socket path cannot be shared that way.
  SCCACHE_SERVER_UDS=/tmp/sccache.sock
  export RUSTC_WRAPPER SCCACHE_SERVER_UDS
fi

"$@"
status=$?

if [ -n "${RUSTC_WRAPPER:-}" ]; then
  sccache --show-stats || true
  sccache --stop-server >/dev/null 2>&1 || true
fi
exit "$status"
