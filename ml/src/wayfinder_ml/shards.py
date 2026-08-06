"""The portability seam.

A shard is a compressed `.npz` holding one `FeatureBatch` plus its schema
version. That format is chosen for what it does *not* require: no Arrow, no
pandas, no PyO3 extension, no Nix — numpy alone reads it. Generation runs in
this checkout where the simulator and the `wayfinder-py` extension exist;
training runs wherever the GPU is, needing only the shards copied across.

Shards are written per generation episode rather than as one file, so a long
sweep can be interrupted, resumed, and parallelised without coordination.
"""

from __future__ import annotations

import os
from pathlib import Path

import numpy as np

from .schema import SCHEMA_VERSION, FeatureBatch


def write_shard(path: str | os.PathLike[str], batch: FeatureBatch) -> None:
    """Validate `batch` and write it to `path`.

    Validation happens before the file is opened, so a rejected batch leaves
    no partial shard behind for a later run to pick up as if it were good.
    """
    batch.validate()
    np.savez_compressed(
        path,
        schema_version=np.asarray(SCHEMA_VERSION),
        candidates=batch.candidates,
        mask=batch.mask,
        context=batch.context,
        label=batch.label,
        cost=batch.cost,
    )


def read_shard(path: str | os.PathLike[str]) -> FeatureBatch:
    """Load one shard, refusing any schema version this build does not know.

    The version gate is the whole point: columns change meaning between
    versions, so a silently-accepted stale shard trains a model on features it
    was never given.
    """
    with np.load(path) as data:
        version = int(data["schema_version"])
        if version != SCHEMA_VERSION:
            raise ValueError(
                f"shard {os.fspath(path)} has schema version {version}, "
                f"but this build reads version {SCHEMA_VERSION}"
            )
        batch = FeatureBatch(
            candidates=data["candidates"],
            mask=data["mask"],
            context=data["context"],
            label=data["label"],
            cost=data["cost"],
        )
    batch.validate()
    return batch


def paths(target: str | os.PathLike[str]) -> list[Path]:
    """Every shard `target` names — one `*.npz` file, or a directory of them
    in sorted filename order so a run is reproducible.

    Raises `FileNotFoundError` on a directory holding no shards rather than
    returning nothing, which would surface as a mysteriously useless training
    run instead of an obvious mistake.
    """
    path = Path(target)
    if path.is_file():
        return [path]
    found = sorted(path.glob("*.npz"))
    if not found:
        raise FileNotFoundError(f"no *.npz shards under {os.fspath(target)}")
    return found


def read_dir(directory: str | os.PathLike[str]) -> FeatureBatch:
    """Load every `*.npz` shard under `directory` as one dataset."""
    from .schema import concat

    return concat([read_shard(p) for p in paths(directory)])
