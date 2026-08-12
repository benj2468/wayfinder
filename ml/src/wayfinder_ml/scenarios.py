"""Locating a scenario and building simulations from it.

A scenario under `sim/scenarios/` is a plain module that wires a topology and
returns a `Simulation` — `drone_relay.build_simulation(seed)` is the shape.
Generation needs one of those and nothing more, so this module resolves a
reference to it rather than inventing a scenario description format: the
scenarios are already Python, already runnable on their own, and a second
declarative layer over them could only drift.

A reference is either a filesystem path or a dotted module name, optionally
suffixed with `:factory` to pick a builder other than `build_simulation`::

    sim/scenarios/drone_relay.py
    sim/scenarios/satellite_relay.py:build_simulation
    scenarios.drone_relay

The path form is the one the README leads with: `sim/scenarios/*.py` are
scripts, not an installed package, so a path is what reaches them from any
working directory. The dotted form is for a scenario that *is* importable —
one of your own, on `PYTHONPATH` or installed.
"""

from __future__ import annotations

import dataclasses
import importlib
import importlib.util
import inspect
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

DEFAULT_FACTORY = "build_simulation"
"""The builder looked up when a reference names no `:factory`. Matches what
`sim/scenarios/*.py` already call theirs."""

DURATION_ATTR = "DURATION_S"
"""Optional module-level attribute: how long one episode of this scenario
should run, in seconds. A scenario knows its own natural length — one flight,
one orbit — far better than a CLI default does."""


@dataclasses.dataclass(frozen=True)
class Scenario:
    """A resolved scenario: what to call, what to call the shards, and how
    long one episode of it lasts."""

    name: str
    """The module's stem, used as the shard filename prefix so a dataset says
    which scenario produced it."""

    build: Callable[[int], Any]
    """Builds a fresh `Simulation` for the given seed. Always takes the seed,
    even when the underlying factory does not declare one — the caller should
    not have to know which."""

    duration_s: float | None
    """The scenario's declared episode length, or `None` if it declares none
    and the caller must supply one."""


def load(ref: str) -> Scenario:
    """Resolve `ref` — a path or dotted module name, optionally `:factory` —
    to a `Scenario`.

    Raises `FileNotFoundError` for a path that does not exist, `ImportError`
    for a module that will not import, and `AttributeError` naming both the
    module and the attribute when the factory is missing, since a builder
    called something else is the likeliest mistake here.
    """
    head, _, factory = ref.rpartition(":")
    if not head:
        head, factory = ref, DEFAULT_FACTORY
    factory = factory or DEFAULT_FACTORY

    module = _import(head)
    if not hasattr(module, factory):
        raise AttributeError(
            f"scenario {module.__name__!r} ({getattr(module, '__file__', '?')}) "
            f"has no {factory!r}; name the builder with "
            f"'{head}:<factory>' if it is called something else"
        )

    duration = getattr(module, DURATION_ATTR, None)
    return Scenario(
        name=module.__name__.rpartition(".")[2],
        build=_seeded(getattr(module, factory)),
        duration_s=None if duration is None else float(duration),
    )


def _seeded(factory: Callable[..., Any]) -> Callable[[int], Any]:
    """Adapt `factory` to a uniform `build(seed)`.

    Not every scenario is seeded, and passing `seed=` to one that never
    declared it would be a `TypeError` raised deep inside a sweep — long after
    the point where the mismatch could be reported usefully.
    """
    try:
        parameters = inspect.signature(factory).parameters
    except (TypeError, ValueError):  # pragma: no cover - builtins, C callables
        return lambda seed: factory(seed)

    takes_seed = "seed" in parameters or any(
        p.kind is inspect.Parameter.VAR_KEYWORD for p in parameters.values()
    )
    if not takes_seed:
        return lambda seed: factory()
    if (
        parameters.get("seed")
        and parameters["seed"].kind is inspect.Parameter.POSITIONAL_ONLY
    ):
        return lambda seed: factory(seed)
    return lambda seed: factory(seed=seed)


def _import(ref: str) -> ModuleType:
    """Import a scenario module by path or by dotted name."""
    if ref.endswith(".py") or "/" in ref or Path(ref).is_file():
        return _import_file(Path(ref))
    return importlib.import_module(ref)


def _import_file(path: Path) -> ModuleType:
    """Import the module at `path`, with `path`'s own directory importable
    from it — the same rule `python path/to/scenario.py` follows, so a scenario
    that imports a sibling module resolves it the way running the script would.

    The engine itself needs no such help: `wayfinder_sim` is an installed
    distribution this package depends on, so a scenario's `from wayfinder_sim
    import ...` resolves from the environment wherever the file happens to sit.
    """
    path = path.expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"no scenario file at {path}")

    directory = str(path.parent)
    if directory not in sys.path:
        sys.path.insert(0, directory)

    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:  # pragma: no cover - not a Python file
        raise ImportError(f"cannot import a scenario from {path}")
    module = importlib.util.module_from_spec(spec)
    # Registered before execution so the module can import itself (and so a
    # dataclass defined in it can resolve its own module), matching what a
    # normal import does.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module
