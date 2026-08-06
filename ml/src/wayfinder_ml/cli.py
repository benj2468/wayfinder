"""`wayfinder-ml` — the pipeline's entry points.

`train` deliberately imports torch lazily, inside the subcommand, so that
`wayfinder-ml info`/`inspect`/`generate` and `--help` work on a base install —
generation's dependencies (`numpy`, `wayfinder-sim`, `wayfinder-py`) are
unconditional, and only training needs the `[train]` extra (`torch`, `onnx`).
An eager top-level torch import would force that extra onto every install.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import scenarios, schema, shards, stats

DEFAULT_DURATION_S = 60.0
"""Episode length used when neither `--duration` nor the scenario's own
`DURATION_S` says otherwise."""

DEFAULT_INTERVAL_S = 1.0
"""How often an episode is sampled. Rows from adjacent instants are highly
correlated — a router's tables barely move in a second — so sampling much
finer than this mostly grows the dataset without adding information."""

EVAL_FRACTION = 0.1
"""Share of rows `train` holds out for `evaluate`. Training and evaluating on
the same rows measures memorization, not the generalization the reported
lift is supposed to mean."""


def _cmd_info(args: argparse.Namespace) -> int:
    """Print the schema contract — the numbers the Rust inference path must
    match."""
    print(f"schema version   {schema.SCHEMA_VERSION}")
    print(f"candidate slots  {schema.MAX_PATHS}")
    print(f"candidate feats  {', '.join(schema.CANDIDATE_FEATURES)}")
    print(f"context feats    {', '.join(schema.CONTEXT_FEATURES)}")
    if args.shards:
        batch = shards.read_dir(args.shards)
        labelled = int((batch.label != schema.NO_LABEL).sum())
        print(f"\nshards           {args.shards}")
        print(f"rows             {batch.rows}")
        print(f"labelled         {labelled} ({stats.labelled_fraction(batch):.1%})")
        print("\n(wayfinder-ml inspect for what these rows actually contain)")
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    """Report what a dataset contains, without training on it."""
    loaded = [(path, shards.read_shard(path)) for path in shards.paths(args.shards)]
    batch = schema.concat([shard for _, shard in loaded])
    summary = stats.summarize(batch)

    print(f"{args.shards}  —  {len(loaded)} shard(s), {batch.rows} rows\n")
    _print_summary(summary)
    print()
    _print_columns("candidate", stats.candidate_columns(batch))
    print()
    _print_columns("context", stats.context_columns(batch))
    print("\nper shard")
    for path, shard in loaded:
        each = stats.summarize(shard)
        print(
            f"  {path.name:<34}{each.rows:>6} rows"
            f"{each.labelled_fraction:>8.1%} labelled"
            f"{each.decision_agreement:>8.1%} baseline on "
            f"{each.labelled_decisions} choices   regret {each.mean_regret:.2f}"
        )
    if args.rows:
        _print_rows(batch, args.rows)
    return 0


def _print_summary(summary: stats.Summary) -> None:
    """The headline block: what is here, and whether it has anything to
    teach."""
    print(f"rows              {summary.rows}")
    print(f"labelled          {summary.labelled} ({summary.labelled_fraction:.1%})")
    unlabelled = summary.rows - summary.labelled
    if unlabelled:
        print(
            f"  unlabelled      {unlabelled} — the true next hop was not among "
            "the router's candidates"
        )
    print(
        f"with a choice     {summary.decisions} "
        f"({summary.decisions / summary.rows if summary.rows else 0:.1%}) "
        "— rows offering more than one candidate"
    )
    print(
        f"baseline agrees   {summary.decision_agreements} of "
        f"{summary.labelled_decisions} ({summary.decision_agreement:.1%}) "
        "where a choice existed — the figure to beat"
    )
    print(
        f"                  {summary.baseline_agreements} of {summary.labelled} "
        f"({summary.baseline_agreement:.1%}) pooled — flattered by "
        "single-candidate rows, which cannot be got wrong"
    )
    print(
        f"etx regret        mean {summary.mean_regret:.3f}; "
        f"{summary.regret_rows} rows ({summary.regret_fraction:.1%}) where the "
        "baseline's pick costs more"
    )
    if summary.baseline_dead_ends:
        print(
            f"dead ends         {summary.baseline_dead_ends} — the baseline "
            "picks a candidate with no path behind it at all"
        )
    print(
        "label slot        "
        + "  ".join(
            f"{slot}: {count}" for slot, count in enumerate(summary.label_counts)
        )
    )
    print(
        "candidates/row    "
        + "  ".join(
            f"{filled + 1}: {count}"
            for filled, count in enumerate(summary.candidate_counts)
        )
    )


def _print_columns(kind: str, columns: list[stats.ColumnStats]) -> None:
    """Per-feature spread. Reads as a range check: every column here is scaled
    by a hand-written constant the Rust side transcribes, so values far off
    `[0, 1]` — or a column of nothing but zeros — are the bug, not the data."""
    samples = columns[0].samples if columns else 0
    unit = "filled slots" if kind == "candidate" else "rows"
    width = max((len(c.name) for c in columns), default=0)
    print(f"{kind} features (over {samples} {unit})")
    print(f"  {'':<{width}}      min      med      max    zeros")
    for column in columns:
        print(
            f"  {column.name:<{width}} {column.minimum:>8.3f} "
            f"{column.median:>8.3f} {column.maximum:>8.3f} {column.zeros:>8}"
        )


def _print_rows(batch: schema.FeatureBatch, count: int) -> None:
    """Dump individual rows — the last resort when a summary number looks
    wrong and you need to see the state behind it.

    Sampled evenly across the dataset rather than taken from the front, since
    the first rows are all one episode's first instant and would say nothing
    about the rest.
    """
    import numpy as np

    if batch.rows == 0:
        return
    indices = np.unique(
        np.linspace(0, batch.rows - 1, min(count, batch.rows)).astype(int)
    )
    baseline = stats.baseline_choice(batch)
    width = max(len(name) for name in schema.CANDIDATE_FEATURES)

    print(f"\nrows ({len(indices)} of {batch.rows}, evenly spaced)")
    for index in indices:
        label = int(batch.label[index])
        pick = int(baseline[index])
        filled = int(batch.mask[index].sum())
        oracle_slot = "—" if label == schema.NO_LABEL else str(label)
        print(
            f"\nrow {index}   {filled} candidates   oracle slot {oracle_slot}   "
            f"batman slot {pick}"
        )
        header = "  ".join(f"{name:>{width}}" for name in schema.CANDIDATE_FEATURES)
        print(f"  slot  {header}  {'etx':>9}")
        for slot in range(schema.MAX_PATHS):
            if not batch.mask[index, slot]:
                continue
            values = "  ".join(
                f"{value:>{width}.3f}" for value in batch.candidates[index, slot]
            )
            cost = batch.cost[index, slot]
            marks = " ".join(
                mark
                for mark, matches in (
                    ("oracle", slot == label),
                    ("batman", slot == pick),
                )
                if matches
            )
            print(f"  {slot:>4}  {values}  {cost:>9.3f}  {marks}")
        context = "  ".join(
            f"{name} {value:.3f}"
            for name, value in zip(schema.CONTEXT_FEATURES, batch.context[index])
        )
        print(f"  context  {context}")


def _cmd_train(args: argparse.Namespace) -> int:
    from .train import evaluate, export_onnx, pick_device, train

    batch = shards.read_dir(args.shards)
    train_batch, eval_batch = schema.split(
        batch, eval_fraction=EVAL_FRACTION, seed=args.seed
    )
    device = pick_device()
    print(
        f"training on {train_batch.rows} rows, "
        f"evaluating on {eval_batch.rows} held-out rows, device={device}"
    )

    model = train(train_batch, epochs=args.epochs, device=device, seed=args.seed)
    result = evaluate(model, eval_batch, device=device)
    print(
        f"oracle agreement: model {result.model_agreement:.1%} vs "
        f"batman {result.baseline_agreement:.1%} "
        f"(lift {result.lift:+.1%}) over {result.rows} rows"
    )

    export_onnx(model, args.out)
    print(f"exported {args.out}")
    return 0


def _cmd_generate(args: argparse.Namespace) -> int:
    """Sweep a scenario and write one shard per episode.

    Shards are written as each episode finishes, not at the end, so an
    interrupted sweep keeps everything it had already produced — and are named
    by scenario and seed, so resuming or running several sweeps in parallel
    cannot have two of them claim the same file.
    """
    # Imported here, not at module scope: `generate` is the repo-bound half of
    # the pipeline, and `inspect`/`train` must stay usable on a box that only
    # ever received the shards.
    from . import generate

    scenario = scenarios.load(args.scenario)
    duration_s = args.duration
    if duration_s is None:
        duration_s = (
            scenario.duration_s
            if scenario.duration_s is not None
            else DEFAULT_DURATION_S
        )

    args.out.mkdir(parents=True, exist_ok=True)
    print(
        f"{scenario.name}: {args.episodes} episode(s) of {duration_s:g}s "
        f"sampled every {args.interval:g}s"
        + (f" after {args.warmup:g}s warmup" if args.warmup else "")
    )

    total = 0
    for episode in generate.episodes(
        scenario.build,
        count=args.episodes,
        seed=args.seed,
        duration_s=duration_s,
        interval_s=args.interval,
        warmup_s=args.warmup,
    ):
        name = f"{scenario.name}-seed{episode.seed:04d}"
        if episode.batch.rows == 0:
            # An empty shard is worse than none: `read_dir` would happily
            # fold it into a dataset, hiding the fact that this episode
            # taught nothing.
            print(f"  {name}  no rows — nothing written")
            continue
        path = args.out / f"{name}.npz"
        shards.write_shard(path, episode.batch)
        total += episode.batch.rows
        print(
            f"  {path.name}  {episode.batch.rows} rows, "
            f"{stats.labelled_fraction(episode.batch):.1%} labelled"
        )

    if total == 0:
        print(
            "no rows generated — every episode's routers held no candidates. "
            "The episode is probably too short for the mesh to converge, or "
            "the topology never links up."
        )
        return 1

    print(f"wrote {total} rows to {args.out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns a process exit code."""
    parser = argparse.ArgumentParser(prog="wayfinder-ml", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    info = sub.add_parser("info", help="show the schema contract, and shard stats")
    info.add_argument("--shards", type=Path, help="a shard directory to summarize")
    info.set_defaults(func=_cmd_info)

    inspect = sub.add_parser(
        "inspect",
        help="report what a dataset contains, without training on it",
        description=(
            "Summarize a shard directory (or one *.npz): how much of it the "
            "loss can use, how often BATMAN's own argmax(tq) already matches "
            "the label, and how much ETX it gives up when it does not — the "
            "numbers that say whether a dataset has anything to teach. numpy "
            "only, so it runs wherever the shards were copied to."
        ),
    )
    inspect.add_argument("shards", type=Path, help="a shard directory, or one *.npz")
    inspect.add_argument(
        "--rows",
        type=int,
        default=0,
        help="also dump this many individual rows, sampled evenly",
    )
    inspect.set_defaults(func=_cmd_inspect)

    train_cmd = sub.add_parser("train", help="fit a scorer and export it to ONNX")
    train_cmd.add_argument("shards", type=Path, help="directory of *.npz shards")
    train_cmd.add_argument("--out", type=Path, default=Path("next_hop.onnx"))
    train_cmd.add_argument("--epochs", type=int, default=20)
    train_cmd.add_argument("--seed", type=int, default=0)
    train_cmd.set_defaults(func=_cmd_train)

    gen = sub.add_parser(
        "generate",
        help="sweep a scenario and write shards",
        description=(
            "Run a sim/scenarios module and write one dataset shard per "
            "episode. SCENARIO is a path (sim/scenarios/drone_relay.py) or a "
            "dotted module name (scenarios.drone_relay), optionally suffixed "
            f"with ':factory' to pick a builder other than "
            f"'{scenarios.DEFAULT_FACTORY}'."
        ),
    )
    gen.add_argument("scenario", help="scenario module path or dotted name[:factory]")
    gen.add_argument(
        "--out", type=Path, required=True, help="directory to write *.npz shards into"
    )
    gen.add_argument(
        "--episodes", type=int, default=1, help="how many runs to sweep (default 1)"
    )
    gen.add_argument(
        "--duration",
        type=float,
        default=None,
        help=(
            "seconds of simulated time per episode; defaults to the "
            f"scenario's own {scenarios.DURATION_ATTR}, else "
            f"{DEFAULT_DURATION_S:g}"
        ),
    )
    gen.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL_S,
        help=f"seconds between sampled instants (default {DEFAULT_INTERVAL_S:g})",
    )
    gen.add_argument(
        "--warmup",
        type=float,
        default=0.0,
        help="seconds to run unsampled first, while the mesh converges",
    )
    gen.add_argument(
        "--seed",
        type=int,
        default=0,
        help="seed of the first episode; each later one takes the next (default 0)",
    )
    gen.set_defaults(func=_cmd_generate)

    args = parser.parse_args(argv)
    return int(args.func(args))
