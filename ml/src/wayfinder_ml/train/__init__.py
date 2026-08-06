"""The portable half of the pipeline: shards in, ONNX model out.

Everything under here depends only on numpy and torch, never on the simulator
or the `wayfinder-py` extension — that is what lets training run on a Colab
runtime or an Orin with nothing but a directory of shards copied across.
"""

from .export import export_onnx, metadata
from .loop import Evaluation, evaluate, pick_device, train
from .model import NextHopScorer

__all__ = [
    "Evaluation",
    "NextHopScorer",
    "evaluate",
    "export_onnx",
    "metadata",
    "pick_device",
    "train",
]
