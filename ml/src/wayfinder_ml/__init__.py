"""Learned next-hop selection for the wayfinder mesh router.

The pipeline has two halves, split at `shards`:

  simulator -> `generate` -> shards        (needs this checkout: PyO3 + SimPy)
  shards    -> `train`    -> ONNX model    (needs only numpy + torch)

`schema` is the contract between them, and `oracle` is the privileged labeler
that turns the simulator's ground truth into supervision. See `README.md` for
the design rationale and the current state of each stage.
"""

from . import features, oracle, schema, shards

__all__ = ["features", "oracle", "schema", "shards"]
