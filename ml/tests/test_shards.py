"""Shards are the pipeline's portability seam: written in this checkout with
the PyO3 extension and SimPy present, read on a Colab runtime or an Orin that
has neither. These tests pin the round-trip and the version gate that stops a
stale shard from being silently trained on.
"""

from __future__ import annotations

import numpy as np
import pytest
from wayfinder_ml import schema, shards


def _batch(rows: int = 5) -> schema.FeatureBatch:
    rng = np.random.default_rng(1)
    mask = rng.random((rows, schema.MAX_PATHS)) > 0.2
    mask[:, 0] = True  # every row's label (0) must select a real slot
    return schema.FeatureBatch(
        candidates=rng.random(
            (rows, schema.MAX_PATHS, len(schema.CANDIDATE_FEATURES)), dtype=np.float32
        ),
        mask=mask,
        context=rng.random((rows, len(schema.CONTEXT_FEATURES)), dtype=np.float32),
        label=np.zeros(rows, dtype=np.int8),
        cost=rng.random((rows, schema.MAX_PATHS), dtype=np.float32),
    )


def test_round_trip_preserves_arrays(tmp_path) -> None:
    batch = _batch()
    path = tmp_path / "shard.npz"

    shards.write_shard(path, batch)
    loaded = shards.read_shard(path)

    np.testing.assert_array_equal(loaded.candidates, batch.candidates)
    np.testing.assert_array_equal(loaded.mask, batch.mask)
    np.testing.assert_array_equal(loaded.context, batch.context)
    np.testing.assert_array_equal(loaded.label, batch.label)
    np.testing.assert_array_equal(loaded.cost, batch.cost)


def test_written_shard_validates_before_writing(tmp_path) -> None:
    """An inconsistent batch cannot even be constructed (`FeatureBatch`
    validates itself at `__post_init__`), let alone written as a corrupt
    shard that only explodes during training."""
    batch = _batch(rows=3)
    with pytest.raises(ValueError):
        schema.FeatureBatch(
            candidates=batch.candidates,
            mask=batch.mask,
            context=batch.context,
            label=batch.label[:1],
            cost=batch.cost,
        )
    assert not (tmp_path / "bad.npz").exists()


def test_reading_a_future_schema_version_is_refused(tmp_path) -> None:
    """A shard from a newer schema has different columns; training on it would
    silently mean something else."""
    batch = _batch()
    path = tmp_path / "shard.npz"
    shards.write_shard(path, batch)

    with np.load(path) as data:
        payload = dict(data)
    payload["schema_version"] = np.asarray(schema.SCHEMA_VERSION + 1)
    np.savez(path, **payload)

    with pytest.raises(ValueError, match="schema version"):
        shards.read_shard(path)


def test_concat_merges_shards() -> None:
    """Training reads a directory of shards as one dataset."""
    a, b = _batch(rows=2), _batch(rows=3)

    merged = schema.concat([a, b])

    assert merged.rows == 5
    np.testing.assert_array_equal(merged.candidates[:2], a.candidates)
    np.testing.assert_array_equal(merged.candidates[2:], b.candidates)
    merged.validate()


def test_read_dir_loads_every_shard(tmp_path) -> None:
    for i in range(3):
        shards.write_shard(tmp_path / f"shard-{i}.npz", _batch(rows=2))

    merged = shards.read_dir(tmp_path)

    assert merged.rows == 6


def test_read_dir_on_empty_directory_raises(tmp_path) -> None:
    """Silently returning an empty dataset would show up as a mysteriously
    useless training run rather than an obvious mistake."""
    with pytest.raises(FileNotFoundError):
        shards.read_dir(tmp_path)
