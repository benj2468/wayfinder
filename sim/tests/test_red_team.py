"""The red-team scenario, run as a test.

``sim/scenarios/red_team.py`` is a report generator rather than a test module:
its attacks print a verdict instead of asserting one, and pytest does not
collect it (it is a plain script under ``sim/scenarios/``, not a ``test_*.py``).
That leaves the script itself uncovered even though the guarantees it probes
are pinned elsewhere — it drives a wide slice of the simulator's API (forgery,
injection, wiretaps, revocation, flooding), so it is the first thing to break
when that API moves, and nothing would notice until someone ran it by hand.

What is asserted here is the *report*: that every attack still runs to a
verdict, and that each verdict matches the baseline recorded in
``docs/design/09-mesh-auth-gaps.md``. A newly-succeeding attack fails the
suite — and so does a fix, which is the point: closing a gap should flip the
verdict, the doc and this baseline in one change.

The individual guarantees behind the verdicts stay in ``test_security.py`` and
``test_adversary.py``; this file deliberately does not restate them.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCENARIO = Path(__file__).resolve().parents[1] / "scenarios" / "red_team.py"


def _load_scenario():
    """Import ``red_team.py`` by path.

    The scenarios are standalone scripts, not part of the ``wayfinder_sim``
    package, so there is no module path to import them by. The module goes into
    ``sys.modules`` before it is executed because ``@dataclasses.dataclass``
    resolves a class's annotations through its own module entry, which does not
    exist yet for a module loaded this way.
    """
    spec = importlib.util.spec_from_file_location("red_team_scenario", _SCENARIO)
    assert spec is not None and spec.loader is not None, _SCENARIO
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


red_team = _load_scenario()

BASELINE = {
    "attack_unauthenticated_joiner": red_team.HELD,
    "attack_foreign_mesh": red_team.HELD,
    "attack_forged_ogm": red_team.HELD,
    "attack_revocation": red_team.HELD,
    "attack_flood": red_team.HELD,
    "attack_passive_eavesdrop": red_team.BY_DESIGN,
    "attack_expired_credential": red_team.HELD,
    "attack_ogm_replay": red_team.HELD,
    "attack_ogm_replay_hijacks_local_traffic": red_team.HELD,
    "attack_forged_challenge_response_flood": red_team.HELD,
    "attack_challenge_response_replay": red_team.HELD,
    "attack_broadcast_addressed_challenge": red_team.HELD,
    "attack_unauthenticated_relay": red_team.HELD,
    "attack_ca_misissuance": red_team.GAP,
    "attack_proof_starvation_by_neighbour_count": red_team.HELD,
}
"""Expected verdict per attack — the table in ``docs/design/09-mesh-auth-gaps.md``.
Update both together."""


@pytest.mark.parametrize("attack", red_team.ATTACKS, ids=lambda a: a.__name__)
def test_each_attack_reaches_its_recorded_verdict(attack):
    finding = attack()
    assert finding.verdict == BASELINE[attack.__name__], finding.detail


def test_the_baseline_covers_every_attack():
    assert {attack.__name__ for attack in red_team.ATTACKS} == set(BASELINE)


def test_the_report_renders_every_finding(capsys):
    findings = [
        red_team.Finding("Held one", red_team.HELD, "held"),
        red_team.Finding("Gap one", red_team.GAP, "gap"),
        red_team.Finding("Design one", red_team.BY_DESIGN, "by design"),
    ]
    red_team.print_report(findings)

    out = capsys.readouterr().out
    for finding in findings:
        assert finding.name in out
        assert finding.detail in out
    assert "1 held, 1 by design, 1 gap(s)" in out
