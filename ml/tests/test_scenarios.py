"""Scenario resolution: turning `sim/scenarios/drone_relay.py` (or a dotted
module name, or a `:factory` suffix) into something the generator can build.

These use scenario modules written into `tmp_path` rather than the repo's own,
so they test the resolver rather than the scenarios — and stay runnable
without SimPy or the PyO3 extension.
"""

from __future__ import annotations

import pytest

from wayfinder_ml import scenarios

_SCENARIO = """\
DURATION_S = 12.5


class Sim:
    def __init__(self, seed):
        self.seed = seed


def build_simulation(seed: int = 0):
    return Sim(seed)


def other(seed: int = 0):
    return Sim(seed + 100)


def takes_no_seed():
    return Sim(-1)
"""


@pytest.fixture
def scenario_path(tmp_path):
    path = tmp_path / "demo_scenario.py"
    path.write_text(_SCENARIO)
    return path


def test_loads_a_scenario_from_a_file_path(scenario_path) -> None:
    scenario = scenarios.load(str(scenario_path))

    assert scenario.name == "demo_scenario"
    assert scenario.build(3).seed == 3


def test_loads_a_scenario_from_a_dotted_module_path(scenario_path, monkeypatch) -> None:
    """`sim/scenarios/drone_relay.py` is also reachable as `scenarios.
    drone_relay` wherever `sim/` is importable, and both spellings must
    resolve to the same thing."""
    monkeypatch.syspath_prepend(str(scenario_path.parent))

    scenario = scenarios.load("demo_scenario")

    assert scenario.name == "demo_scenario"
    assert scenario.build(3).seed == 3


def test_seed_reaches_the_factory_so_episodes_differ(scenario_path) -> None:
    scenario = scenarios.load(str(scenario_path))
    assert [scenario.build(s).seed for s in (0, 1, 2)] == [0, 1, 2]


def test_a_colon_selects_a_different_factory(scenario_path) -> None:
    """A module may build more than one topology; naming the factory is how a
    caller picks one without a wrapper module."""
    scenario = scenarios.load(f"{scenario_path}:other")

    assert scenario.build(1).seed == 101


def test_a_factory_that_takes_no_seed_is_called_bare(scenario_path) -> None:
    """Not every scenario is seeded. Passing `seed=` to one that never
    declared it would be a TypeError at generation time, well after the point
    the mistake could be reported."""
    scenario = scenarios.load(f"{scenario_path}:takes_no_seed")

    assert scenario.build(7).seed == -1


def test_duration_comes_from_the_module_when_it_declares_one(scenario_path) -> None:
    """A scenario knows its own natural length — one flight, one orbit — and
    that beats a generic default."""
    assert scenarios.load(str(scenario_path)).duration_s == 12.5


def test_duration_is_none_when_the_module_declares_none(tmp_path) -> None:
    path = tmp_path / "bare.py"
    path.write_text("def build_simulation(seed=0):\n    return seed\n")

    assert scenarios.load(str(path)).duration_s is None


def test_a_scenario_can_import_its_own_neighbors(tmp_path) -> None:
    """Loading a file mirrors `python path/to/scenario.py`: the scenario's own
    directory is importable from it, so a scenario can split itself across
    sibling modules. (The engine needs none of this — `wayfinder_sim` is an
    installed distribution.)"""
    (tmp_path / "sibling.py").write_text("VALUE = 5\n")
    path = tmp_path / "importer.py"
    path.write_text(
        "from sibling import VALUE\n\ndef build_simulation(seed=0):\n    return VALUE\n"
    )

    assert scenarios.load(str(path)).build(0) == 5


def test_a_missing_file_names_the_path(tmp_path) -> None:
    with pytest.raises(FileNotFoundError, match="nope.py"):
        scenarios.load(str(tmp_path / "nope.py"))


def test_a_missing_factory_names_the_module_and_the_attribute(scenario_path) -> None:
    """The likeliest mistake is a scenario whose builder is called something
    else, so the error has to say which name was looked for and where."""
    with pytest.raises(AttributeError) as excinfo:
        scenarios.load(f"{scenario_path}:no_such_builder")

    assert "no_such_builder" in str(excinfo.value)
    assert "demo_scenario" in str(excinfo.value)


def test_a_module_with_no_default_factory_is_rejected(tmp_path) -> None:
    path = tmp_path / "empty_scenario.py"
    path.write_text("X = 1\n")

    with pytest.raises(AttributeError, match=scenarios.DEFAULT_FACTORY):
        scenarios.load(str(path))
