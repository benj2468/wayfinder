#!/usr/bin/env python3
"""Print a hash of every input that can change a simulation-lab result.

`just sim-export` writes this into www/sim/data/inputs.sha256 once it has
regenerated every result, and the site build compares it with the tree it is
about to publish: a mismatch means the router, the simulator or a scenario
changed after the numbers on the page were computed.

**What counts.** The results run the real router, compiled into the
wayfinder-py extension, so the inputs are exactly the crates that extension
links, found by following path dependencies from libs/wayfinder-py/Cargo.toml
(including ones inherited through `dep.workspace = true`); the root
Cargo.toml those crates inherit versions and features from; the extension's
own Cargo.lock; and the simulator package, its scenarios and the Python
lockfiles. A crate the extension does not link (firmware, the TUI, the
server) cannot move a result, so changing it does not mark the page stale.

Inside a crate, tests, benches, fuzz targets, examples and docs are left out.
An in-file `#[cfg(test)]` module cannot be told apart from code without a
parser, so editing one still counts — the safe direction, since a false
"stale" costs one regeneration where a false "fresh" publishes wrong numbers.

Hashes the *contents* of tracked files as they are on disk, so an export run
from a dirty tree stamps what it actually ran; a new file must be committed
(or at least added) before it counts.

Usage: scripts/sim-inputs-hash.py
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parent.parent
EXTENSION = ROOT / "libs" / "wayfinder-py"
ALWAYS = [
    "Cargo.toml",
    "libs/wayfinder-py/Cargo.lock",
    "sim/src",
    "sim/scenarios",
    "sim/pyproject.toml",
    "pyproject.toml",
    "uv.lock",
]
SKIP_PARTS = {"tests", "benches", "fuzz", "examples"}
DEP_TABLES = ("dependencies", "build-dependencies")


def workspace_paths() -> dict[str, Path]:
    """`[workspace.dependencies]` path entries of the root workspace — what a
    member's `dep.workspace = true` resolves to."""
    root = tomllib.loads((ROOT / "Cargo.toml").read_text())
    deps = root.get("workspace", {}).get("dependencies", {})
    return {
        name: (ROOT / spec["path"]).resolve()
        for name, spec in deps.items()
        if isinstance(spec, dict) and "path" in spec
    }


def linked_crates() -> list[Path]:
    """Every crate directory the extension links, the extension included."""
    inherited = workspace_paths()
    seen: set[Path] = set()
    todo = [EXTENSION.resolve()]
    while todo:
        crate = todo.pop()
        if crate in seen:
            continue
        seen.add(crate)
        manifest = tomllib.loads((crate / "Cargo.toml").read_text())
        tables = [manifest.get(t, {}) for t in DEP_TABLES]
        for target in manifest.get("target", {}).values():
            tables += [target.get(t, {}) for t in DEP_TABLES]
        for table in tables:
            for name, spec in table.items():
                if not isinstance(spec, dict):
                    continue
                if "path" in spec:
                    todo.append((crate / spec["path"]).resolve())
                elif spec.get("workspace") and name in inherited:
                    todo.append(inherited[name])
    return sorted(seen)


def tracked(paths: list[str]) -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "--", *paths],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    return [p for p in out.decode().split("\0") if p]


def main() -> int:
    crates = [str(c.relative_to(ROOT)) for c in linked_crates()]
    files = [
        f
        for f in tracked(crates + ALWAYS)
        if not SKIP_PARTS.intersection(Path(f).parts) and not f.endswith(".md")
    ]
    if not files or len(crates) < 2:
        # An empty list would hash to a constant both sides agree on.
        print("sim-inputs-hash: found no inputs to hash", file=sys.stderr)
        return 1
    digest = hashlib.sha256()
    for f in sorted(files):
        digest.update(f.encode() + b"\0")
        digest.update(hashlib.sha256((ROOT / f).read_bytes()).digest())
    print(digest.hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
