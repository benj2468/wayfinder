"""Export a trained scorer to ONNX — the handoff to the Rust inference path.

ONNX rather than a PyTorch checkpoint because the consumer is a Rust binary,
not Python: `ort` loads the same file on a workstation's CPU and on an Orin's
GPU through the TensorRT execution provider, so one artifact covers both and
the node has no Python runtime at all.

The batch dimension is exported dynamic because a node scores every originator
in its table at once, and that count changes as the mesh does. The candidate
dimension is fixed at `MAX_PATHS` — it is a protocol constant, not a shape
that varies.
"""

from __future__ import annotations

import os

import onnx
import torch

from ..schema import CANDIDATE_FEATURES, CONTEXT_FEATURES, MAX_PATHS, SCHEMA_VERSION
from .model import NextHopScorer

OPSET = 17
"""ONNX opset. 17 is comfortably supported by the TensorRT/ORT versions
shipping in current JetPack, and this model uses nothing exotic."""


def export_onnx(model: NextHopScorer, path: str | os.PathLike[str]) -> None:
    """Write `model` to `path` as ONNX, with named inputs matching the schema.

    Input names are the schema's own (`candidates`, `mask`, `context`) so the
    Rust side binds by name rather than position — a positional binding would
    survive a signature change and silently feed the model the wrong tensor.

    The file also carries `metadata()` as ONNX metadata properties, so a
    stale or reordered schema disagrees with the model on *shape* (a load
    error) rather than agreeing on shape and silently disagreeing on meaning.
    """
    model.eval()
    dummy = (
        torch.zeros(1, MAX_PATHS, len(CANDIDATE_FEATURES)),
        torch.ones(1, MAX_PATHS, dtype=torch.bool),
        torch.zeros(1, len(CONTEXT_FEATURES)),
    )
    fspath = os.fspath(path)
    torch.onnx.export(
        model,
        dummy,
        fspath,
        input_names=["candidates", "mask", "context"],
        output_names=["scores"],
        dynamic_axes={
            "candidates": {0: "batch"},
            "mask": {0: "batch"},
            "context": {0: "batch"},
            "scores": {0: "batch"},
        },
        opset_version=OPSET,
        # The dynamo-based exporter (torch's default since 2.x) pulls in
        # `onnxscript`, an extra heavy/experimental dependency this pipeline
        # doesn't otherwise need — the legacy TorchScript-based exporter is a
        # fine match for a model this simple and fixed-shape.
        dynamo=False,
    )

    onnx_model = onnx.load(fspath)
    for key, value in metadata().items():
        prop = onnx_model.metadata_props.add()
        prop.key = key
        prop.value = value
    onnx.save(onnx_model, fspath)


def metadata() -> dict[str, str]:
    """The facts the Rust side must check before trusting a model file.

    Feature *names and order* travel with the model, not just their count: a
    reordered schema and a stale model would otherwise agree on shape and
    disagree on meaning, which is invisible until routing quietly degrades.
    """
    return {
        "schema_version": str(SCHEMA_VERSION),
        "max_paths": str(MAX_PATHS),
        "candidate_features": ",".join(CANDIDATE_FEATURES),
        "context_features": ",".join(CONTEXT_FEATURES),
    }
