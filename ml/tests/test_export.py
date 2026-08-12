"""`export_onnx` must embed the schema metadata the Rust loader checks — not
just the tensors."""

from __future__ import annotations

import pytest

torch = pytest.importorskip("torch")
onnx = pytest.importorskip("onnx")

from wayfinder_ml import schema
from wayfinder_ml.train import NextHopScorer, export_onnx, metadata


def test_export_embeds_schema_metadata(tmp_path) -> None:
    out = tmp_path / "next_hop.onnx"
    export_onnx(NextHopScorer(), out)

    model = onnx.load(str(out))
    props = {prop.key: prop.value for prop in model.metadata_props}

    assert props == metadata()
    assert props["schema_version"] == str(schema.SCHEMA_VERSION)
    assert props["candidate_features"].split(",") == list(schema.CANDIDATE_FEATURES)
