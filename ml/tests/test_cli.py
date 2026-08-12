"""The command line, exercised through `main` exactly as the installed
`wayfinder-ml` entry point calls it.

`generate` and `train` are the subcommands with real wiring behind them — a
scenario to resolve and a sweep to run for the former, a held-out split and an
ONNX export for the latter — so they are the ones worth driving end to end
here, against a scenario module pointed at `fakesim`. `train`'s tests are
skipped without the `[train]` extra, same as `test_train.py`.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fakesim import SCENARIO_MODULE
from wayfinder_ml import cli, shards

ROWS_PER_INSTANT = 2
"""`FakeSim` is two nodes, each knowing one originator — so one row apiece at
every sampled instant."""


@pytest.fixture
def scenario(tmp_path) -> Path:
    """A scenario file on disk, of the shape `sim/scenarios/*.py` have."""
    path = tmp_path / "fake_scenario.py"
    path.write_text(SCENARIO_MODULE.format(tests_dir=str(Path(__file__).parent)))
    return path


def test_generate_writes_one_shard_per_episode(scenario, tmp_path) -> None:
    out = tmp_path / "data"

    code = cli.main(
        [
            "generate",
            str(scenario),
            "--out",
            str(out),
            "--episodes",
            "3",
            "--duration",
            "2",
            "--interval",
            "1",
        ]
    )

    assert code == 0
    names = sorted(p.name for p in out.glob("*.npz"))
    assert names == [
        "fake_scenario-seed0000.npz",
        "fake_scenario-seed0001.npz",
        "fake_scenario-seed0002.npz",
    ], "named by scenario and seed, so a resumed or parallel sweep cannot collide"


def test_generate_creates_the_output_directory(scenario, tmp_path) -> None:
    out = tmp_path / "nested" / "data"

    assert (
        cli.main(["generate", str(scenario), "--out", str(out), "--duration", "1"]) == 0
    )
    assert list(out.glob("*.npz"))


def test_generated_shards_load_back_as_one_dataset(scenario, tmp_path) -> None:
    """The point of the command: what it writes is what `train` reads."""
    out = tmp_path / "data"
    cli.main(
        [
            "generate",
            str(scenario),
            "--out",
            str(out),
            "--episodes",
            "2",
            "--duration",
            "2",
            "--interval",
            "1",
        ]
    )

    batch = shards.read_dir(out)

    batch.validate()
    assert batch.rows == 2 * 3 * ROWS_PER_INSTANT  # 2 episodes x 3 instants


def test_generate_falls_back_to_the_scenario_declared_duration(
    scenario, tmp_path
) -> None:
    """`DURATION_S = 4.0` in the scenario: one flight, one orbit — the length
    the scenario was written for, and better than a generic default."""
    out = tmp_path / "data"

    cli.main(["generate", str(scenario), "--out", str(out), "--interval", "1"])

    assert shards.read_dir(out).rows == 5 * ROWS_PER_INSTANT  # t=0..4s inclusive


def test_a_factory_suffix_selects_the_scenario_builder(scenario, tmp_path) -> None:
    """`path.py:factory` reaches a second topology in the same module — here
    the one whose routers never hear anything, which is also how the
    empty-dataset path gets exercised."""
    out = tmp_path / "data"

    code = cli.main(
        ["generate", f"{scenario}:build_silent", "--out", str(out), "--duration", "1"]
    )

    assert code == 1, "build_silent ran, and a run that produced no rows fails"


def test_generate_reports_an_empty_dataset_rather_than_writing_one(
    scenario, tmp_path, capsys
) -> None:
    """A silently-empty dataset surfaces much later as a mysteriously useless
    training run, which is the failure `shards.read_dir` already refuses to
    let happen."""
    out = tmp_path / "data"

    cli.main(
        ["generate", f"{scenario}:build_silent", "--out", str(out), "--duration", "1"]
    )

    assert "no rows" in capsys.readouterr().out.lower()
    assert not list(out.glob("*.npz")), "an empty shard is worse than no shard"


def test_generate_prints_per_episode_progress(scenario, tmp_path, capsys) -> None:
    """A sweep is long enough that silence is indistinguishable from a hang."""
    out = tmp_path / "data"

    cli.main(
        [
            "generate",
            str(scenario),
            "--out",
            str(out),
            "--episodes",
            "2",
            "--duration",
            "1",
            "--interval",
            "1",
        ]
    )

    lines = capsys.readouterr().out.splitlines()
    assert sum("seed0000" in line for line in lines) == 1
    assert sum("seed0001" in line for line in lines) == 1


def test_generate_rejects_an_unknown_scenario(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        cli.main(["generate", str(tmp_path / "absent.py"), "--out", str(tmp_path)])


# --- train -----------------------------------------------------------------


def test_train_fits_and_exports_a_model(scenario, tmp_path) -> None:
    """The one path with real numerical behavior behind it: a held-out split
    (so `evaluate`'s reported lift isn't just memorization), a fit, and an
    ONNX export carrying the schema metadata."""
    pytest.importorskip("torch")
    onnx = pytest.importorskip("onnx")

    data = tmp_path / "data"
    assert (
        cli.main(
            [
                "generate",
                str(scenario),
                "--out",
                str(data),
                "--episodes",
                "1",
                "--duration",
                "20",
                "--interval",
                "1",
            ]
        )
        == 0
    )

    out = tmp_path / "next_hop.onnx"
    code = cli.main(["train", str(data), "--out", str(out), "--epochs", "2"])

    assert code == 0
    model = onnx.load(str(out))
    assert {p.key for p in model.metadata_props} == {
        "schema_version",
        "max_paths",
        "candidate_features",
        "context_features",
    }


# --- inspect -------------------------------------------------------------


@pytest.fixture
def dataset(scenario, tmp_path) -> Path:
    """Two shards' worth of generated rows to inspect."""
    out = tmp_path / "data"
    cli.main(
        [
            "generate",
            str(scenario),
            "--out",
            str(out),
            "--episodes",
            "2",
            "--duration",
            "2",
            "--interval",
            "1",
        ]
    )
    return out


def test_inspect_reports_the_numbers_that_decide_whether_to_train(
    dataset, capsys
) -> None:
    """Rows alone do not say whether a dataset is worth training on. What the
    baseline already gets right, and what it gives up when wrong, do."""
    assert cli.main(["inspect", str(dataset)]) == 0

    out = capsys.readouterr().out
    assert "rows" in out
    assert "labelled" in out
    assert "baseline agrees" in out
    assert "etx regret" in out


def test_inspect_breaks_the_total_down_per_shard(dataset, capsys) -> None:
    """A pooled total hides one bad episode — a topology that never linked up
    reads as a slightly smaller dataset rather than as a broken run."""
    cli.main(["inspect", str(dataset)])

    out = capsys.readouterr().out
    assert "fake_scenario-seed0000.npz" in out
    assert "fake_scenario-seed0001.npz" in out


def test_inspect_accepts_a_single_shard(dataset, capsys) -> None:
    shard = min(dataset.glob("*.npz"))

    assert cli.main(["inspect", str(shard)]) == 0
    assert "rows" in capsys.readouterr().out


def test_inspect_lists_feature_ranges(dataset, capsys) -> None:
    """The normalization constants are transcribed by hand into the Rust
    inference path, so a column drifting outside its intended range is a
    correctness bug — visible here, or nowhere until routing degrades."""
    cli.main(["inspect", str(dataset)])

    out = capsys.readouterr().out
    for feature in ("tq", "link_quality", "seqno_lag", "neighbor_count"):
        assert feature in out


def test_inspect_dumps_rows_on_request(dataset, capsys) -> None:
    """The last resort for a number that looks wrong: read the actual row."""
    cli.main(["inspect", str(dataset), "--rows", "3"])

    out = capsys.readouterr().out
    assert out.count("\nrow ") == 3, "one block per dumped row"


def test_inspect_dumps_nothing_by_default(dataset, capsys) -> None:
    cli.main(["inspect", str(dataset)])

    assert "\nrow " not in capsys.readouterr().out


def test_inspect_rejects_a_directory_with_no_shards(tmp_path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()

    with pytest.raises(FileNotFoundError):
        cli.main(["inspect", str(empty)])
