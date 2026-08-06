# Learned next-hop selection

Training pipeline for the "smart" wayfinder — a node that augments BATMAN's
routing decisions with a learned model, deployed alongside `wayfinder-tap` on
an NVIDIA Jetson.

## What the model actually does

BATMAN already maintains up to **four** candidate paths to each originator
(`batman::OriginatorRecord::paths`, an `HVec<NeighborStats, 4>`) and selects
among them with `argmax(last_tq)`. The model does not invent routes, build a
topology view, or replace the protocol. It replaces **that one `argmax`** with
a learned score over the same four candidates.

That framing is the reason this is tractable as a first target:

- **Bounded action space.** Four slots, always. No variable-length decoding.
- **A drop-in seam.** One selection function changes; OGM handling, TVLVs,
  forwarding, and the wire format are all untouched.
- **Fail-safe by construction.** The candidate set comes from BATMAN either
  way, so the worst a bad model can do is pick a path the router already
  considered viable — a degradation, not a black hole. Blending the score with
  TQ bounds it further.
- **Honest features.** Everything the model reads is state a node already
  holds, so nothing works in training and vanishes on hardware.

## Why the simulator is the right data source

`wayfinder_sim` drives **real routers**: every node is a `wayfinder_py.PyDriver`
wrapping the actual `wayfinder_tick_driver::Driver`, ticked against Python
mobility and channel models. Features are therefore a real router's real
state, not a Python reimplementation of BATMAN that would drift from the
shipped engine the moment either changed.

And the simulator holds **ground truth no router can see** — true positions,
true per-pair delivery probability. `oracle.py` turns that into the answer
key: the next hop a perfectly-informed router would pick, by minimum expected
transmission count (ETX). Training is then supervised imitation of a
privileged expert — no reward shaping, no environment interaction loop, no RL
machinery. That is a deliberately boring choice for v1, and it is what makes
the first result cheap to get and easy to trust.

The case that motivates the whole project is one line in `test_oracle.py`: a
direct link delivering 20% of frames (ETX 5) is *worse* than two perfect hops
(ETX 2), but a hop-count-flavoured metric prefers it.

## Layout

```
schema.py     the contract: feature columns, order, scaling, versioning
oracle.py     privileged ETX labeler (pure; no simulator import)
features.py   router state -> training rows
scenarios.py  resolving a `sim/scenarios` module to something buildable
generate.py   simulation -> shards
shards.py     the portability seam (.npz)
train/        model, training loop, ONNX export   [needs only numpy + torch]
```

## Inspecting a dataset

`wayfinder-ml inspect <dir-or-shard>` answers "is this worth training on?"
without torch — it is numpy-only, so it runs wherever the shards were copied
to, and `--rows N` dumps individual rows sampled evenly across the dataset.

```
rows              333
labelled          316 (94.9%)
  unlabelled      17 — the true next hop was not among the router's candidates
with a choice     115 (34.5%) — rows offering more than one candidate
baseline agrees   82 of 115 (71.3%) where a choice existed — the figure to beat
                  283 of 316 (89.6%) pooled — flattered by single-candidate rows
etx regret        mean 0.440; 32 rows (10.1%) where the baseline's pick costs more
dead ends         1 — the baseline picks a candidate with no path behind it at all
```

Two of those deserve emphasis, because they are the ones that decide whether a
sweep produced anything:

- **Baseline agreement is reported over rows where a choice existed**, not
  pooled. A one-candidate row's label *is* its only slot, so it cannot be got
  wrong; pooling those in reports the topology's shape as if it were the
  baseline's skill. In the run above that is the difference between 71.3% and
  a comfortable-looking 89.6%.
- **ETX regret is the headroom**, and it is what separates a disagreement that
  matters from one that does not. Two near-equal paths disagreed over cost
  nothing; a pick with no path behind it at all (`dead ends`) is counted
  separately, since infinite regret would swallow the mean.

`--rows` is the last resort when a number looks wrong — it prints each
candidate's features, its oracle ETX, and which slot each policy picked:

```
row 332   2 candidates   oracle slot 0   batman slot 1
  slot            tq  link_quality  link_samples     age_ratio   ...        etx
     0         0.494         0.510         0.239         0.071   ...      1.664  oracle
     1         0.498         0.514         0.254         1.177   ...      2.739  batman
```

That row is the whole project in miniature: BATMAN takes slot 1 on a 0.004 TQ
edge, and it is the path that costs 2.74 ETX instead of 1.66.

The feature tables `inspect` prints alongside are a range check, not
decoration. Every column is scaled by a hand-written constant that the Rust
inference path transcribes by eye, so a column drifting outside its intended
range — or one that is all zeros because the state never reached it — is a
correctness bug with no other detector.

## The portability seam

The pipeline splits in two at `shards.py`, and that split is the whole
portability story:

| stage | needs | runs where |
|---|---|---|
| generation | PyO3 extension, SimPy, this checkout | dev box / CI only |
| training | numpy + torch, and a directory of `.npz` | Colab, rented GPU, Orin |

A shard is a compressed `.npz` — no Arrow, no pandas, no extension module, no
Nix. Copy the directory to whatever has the GPU and train there. Shards are
written per episode, so a long sweep can be interrupted, resumed, and
parallelised without coordination.

```bash
uv sync                                    # generation needs no extra: wayfinder-sim is a dependency
wayfinder-ml generate ../sim/scenarios/drone_relay.py --out data/
wayfinder-ml inspect data/                 # what the dataset actually contains
wayfinder-ml info --shards data/           # the schema contract
wayfinder-ml train data/ --out next_hop.onnx
```

## Pointing `generate` at a scenario

A dataset comes from a scenario under [`sim/scenarios/`](../sim/scenarios) —
an ordinary Python module that wires a topology and returns a `Simulation`.
Nothing declarative sits in between: the scenarios are already runnable on
their own, and a second description format over them could only drift.

```bash
# a path, a dotted module name, or either plus ':factory'
wayfinder-ml generate ../sim/scenarios/drone_relay.py --out data/
wayfinder-ml generate ../sim/scenarios/satellite_relay.py --out data/ --episodes 20
wayfinder-ml generate ../sim/scenarios/drone_relay.py:build_simulation --out data/
wayfinder-ml generate my_package.my_scenario --out data/   # dotted: any importable module
```

| flag | what it does |
|---|---|
| `--episodes N` | how many runs to sweep; each is a fresh simulation |
| `--seed S` | the first episode's seed — later ones take `S+1`, `S+2`, … |
| `--duration S` | simulated seconds per episode (default: the scenario's own `DURATION_S`, else 60) |
| `--interval S` | seconds between sampled instants (default 1) |
| `--warmup S` | seconds to run unsampled first, while the mesh converges |

One shard per episode, named `<scenario>-seed<NNNN>.npz`, written as each
episode finishes — so an interrupted sweep keeps what it already produced, and
two sweeps on different seed ranges can run in parallel without coordinating.
An episode that produced no rows writes nothing at all: an empty shard would
be folded silently into the dataset by `read_dir`, which is the failure mode
worth refusing.

A scenario is only asked for `build_simulation(seed)`, so it must be
importable without a plotting stack — the repo's own scenarios keep their
matplotlib imports inside their plotting functions for exactly that reason,
and `tests/test_end_to_end.py` fails if one drifts back.

### Installing torch

Left unpinned in `pyproject.toml` on purpose — the right build is per-machine:

- **CUDA box** — the PyPI default is correct: `uv sync --extra train`.
- **CPU dev box / CI** — the default drags ~3 GB of `nvidia-*` wheels it will
  never execute. Prefer the CPU index:
  `uv pip install torch --index-url https://download.pytorch.org/whl/cpu`
- **Jetson / Orin** — use JetPack's own aarch64 torch; do not let pip replace
  it with a PyPI build.

## A constraint worth knowing before you extend the model

`NextHopScorer` is **pointwise**: each candidate is scored from its own
features plus shared per-row context, with no interaction between candidates.
The model learns "what is this path worth?" and takes the argmax.

That matches the oracle exactly — "best next hop" means "lowest true ETX
through this candidate", and that is a property of the candidate alone. But it
means any target defined by *rank* among candidates ("the second-best TQ") is
not representable, and training against one converges to garbage rather than
failing loudly. Cross-candidate reasoning needs an attention block over the
four slots first.

## Deployment

Training exports **ONNX**, not a PyTorch checkpoint, because the consumer is a
Rust binary with no Python runtime. The `ort` crate loads one artifact on both
a workstation CPU and an Orin GPU (via the TensorRT execution provider).

Two rules keep the Rust and Python sides honest, both enforced by
`schema.py` + `train/export.py`:

1. **Normalization is arithmetic, never fitted.** Every feature is scaled by a
   named constant or a ratio of quantities the router already holds — no
   mean/stddev learned from a dataset. A fitted scaler would be a second
   artifact the Rust side must load and keep in step; constants can be
   transcribed and reviewed by eye.
2. **Feature names and order travel with the model.** A reordered schema and a
   stale model agree on shape and disagree on meaning — invisible until
   routing quietly degrades. `export.metadata()` carries the schema version
   and column names for the loader to check.

Worth being clear-eyed: this model is eleven inputs and four outputs, and runs
in microseconds on a CPU. The GPU earns its place in **training** — scenario
sweeps over millions of rows — and in leaving headroom for a richer context
later. It is not needed to make this forward pass fast, and the pitch should
not pretend otherwise.

## Status

The chain works end to end: a real simulation of real routers produces valid,
labelled training rows, and a model trains on them and beats the baseline.
`tests/test_end_to_end.py` asserts exactly that, and is the test that would
catch the two halves drifting apart.

`wayfinder-ml generate` sweeps a scenario over time and writes the shards, so
the command is wired end to end.

Still to do before this is a pipeline rather than a skeleton:

- **Scenario randomization.** A dataset from one topology teaches one
  topology, and the seed only varies channel draws — not the topology itself.
  `--episodes 50` over `drone_relay` is fifty samples of one flight. Needs
  scenarios that randomize node counts, mobility, and channel parameters from
  their seed.
- **Rust inference.** No `ort` integration yet — nothing consumes the exported
  ONNX on a node. The `argmax`-replacement seam in the router is untouched.
- **The honest baseline question.** On easy topologies BATMAN already agrees
  with the oracle, so `lift` is near zero and there is nothing to learn. Early
  effort should go into finding the scenarios where classical TQ is *wrong* —
  that is where the value is, and whether they are common enough to matter is
  still an open question, not a settled one.
