#!/usr/bin/env python3
"""Print a hash of everything a CI job for one Cargo package reads.

A job can then skip itself when a run with the same hash already passed
(see `scripts/ci-cached.sh`). That replaces hand-written
`rules: changes:` path lists, which go stale the moment a crate gains a
dependency: this walks the real dependency graph instead.

What goes in:

- every tracked file of the package and of every crate it depends on through a
  `path` dependency, transitively and in every dependency kind (dev and build
  dependencies affect tests and build scripts too), across workspaces;
- each touched workspace's root `Cargo.toml`, `Cargo.lock`, and
  `.cargo/config.toml`;
- `.github/workflows/ci.yml` and `containers/testenv.Dockerfile`, the job
  definitions and the image (and so the toolchain) they run in;
- any extra git pathspecs the job names, for inputs that aren't Rust crates.

Registry dependencies need no walking: `Cargo.lock` pins them. The graph comes
from `cargo metadata --no-deps`, which reads only local manifests, so this runs
offline and fast even with an empty `CARGO_HOME`. File contents come from git's
own blob hashes (`git ls-files -s`), so nothing is read twice. Only committed
(indexed) state counts, which is what a CI checkout has.
"""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

# Always part of the hash, relative to the repository root, if tracked.
GLOBAL_INPUTS = [".github/workflows/ci.yml", "containers/testenv.Dockerfile"]


def cargo_metadata(manifest):
    out = subprocess.run(
        [
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--offline",
            "--manifest-path",
            str(manifest),
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return json.loads(out)


def crate_closure(manifest, package):
    """The directories of `package` and every crate it reaches through `path`
    dependencies, plus the root of every workspace involved."""
    packages = {}  # manifest dir -> package entry
    workspaces = set()

    def load(manifest_path):
        meta = cargo_metadata(manifest_path)
        workspaces.add(Path(meta["workspace_root"]).resolve())
        for pkg in meta["packages"]:
            packages.setdefault(Path(pkg["manifest_path"]).resolve().parent, pkg)

    load(manifest)
    start = next((p for p in packages.values() if p["name"] == package), None)
    if start is None:
        sys.exit(f"ci-input-hash: no package {package!r} in {manifest}")

    seen = set()
    todo = [Path(start["manifest_path"]).resolve().parent]
    while todo:
        crate_dir = todo.pop()
        if crate_dir in seen:
            continue
        if crate_dir not in packages:
            load(crate_dir / "Cargo.toml")
        seen.add(crate_dir)
        for dep in packages[crate_dir]["dependencies"]:
            if dep.get("path"):
                todo.append(Path(dep["path"]).resolve())
    return sorted(seen), sorted(workspaces)


def ls_files(repo, pathspecs):
    """`git ls-files -s` lines (mode, blob hash, stage, path) for tracked
    files matching `pathspecs`, sorted."""
    if not pathspecs:
        return []
    out = subprocess.run(
        ["git", "ls-files", "-s", "--", *pathspecs],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return sorted(out.splitlines())


def input_hash(repo, manifest, package, extra):
    repo = Path(repo).resolve()
    crates, workspaces = crate_closure(Path(manifest).resolve(), package)

    def rel(path):
        return str(path.relative_to(repo))

    pathspecs = [rel(c) for c in crates]
    for ws in workspaces:
        for name in ("Cargo.toml", "Cargo.lock", ".cargo/config.toml"):
            pathspecs.append(rel(ws / name))
    pathspecs += GLOBAL_INPUTS
    pathspecs += list(extra)

    digest = hashlib.sha256()
    digest.update(f"package {package}\n".encode())
    for line in ls_files(repo, sorted(set(pathspecs))):
        digest.update(line.encode() + b"\n")
    return digest.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--package", required=True, help="Cargo package name")
    ap.add_argument(
        "--manifest-path",
        default="Cargo.toml",
        help="manifest of the workspace (or crate) to start from",
    )
    ap.add_argument(
        "--extra",
        action="append",
        default=[],
        help="additional git pathspec to hash (repeatable)",
    )
    args = ap.parse_args()
    repo = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    print(input_hash(repo, args.manifest_path, args.package, args.extra))


if __name__ == "__main__":
    main()
