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
    # --- 2026-08 sweep: certificate issuance / identity / enrollment ---
    "attack_reserved_address_originator": red_team.GAP,
    "attack_misissued_cert_overwrites_live_member": red_team.GAP,
    "attack_unbounded_validity_window": red_team.BY_DESIGN,
    "attack_degenerate_validity_window": red_team.HELD,
    "attack_fail_open_bridge_containment": red_team.HELD,
    # --- 2026-08 sweep: directed data plane / pairwise trailer ---
    "attack_multicast_addressed_directed_delivery": red_team.GAP,
    "attack_injected_directed_laundered_by_relay": red_team.GAP,
    "attack_directed_unicast_replay": red_team.HELD,
    "attack_cross_pair_tag_forgery": red_team.HELD,
    "attack_directed_frame_parsing_robustness": red_team.HELD,
    # --- 2026-08 sweep: next-hop proof protocol ---
    "attack_unicast_addressed_challenge_reflection": red_team.HELD,
    "attack_forged_response_reaches_proof_handler": red_team.HELD,
    "attack_challenge_nonce_is_unpredictable": red_team.HELD,
    "attack_captured_challenge_replayed": red_team.HELD,
    "attack_proof_survives_key_eviction_window": red_team.GAP,
    # --- 2026-08 sweep: revocation as a weapon ---
    "attack_forged_self_revocation_killswitch": red_team.HELD,
    "attack_self_revocation_replay_after_reenrollment": red_team.HELD,
    "attack_self_revocation_same_second_tie": red_team.BY_DESIGN,
    "attack_foreign_root_revokes_member": red_team.HELD,
    "attack_forged_revocation_flood_evicts_genuine": red_team.HELD,
    "attack_stale_revocation_denies_readmission": red_team.HELD,
    # --- 2026-08 sweep: OGM semantics / routing engine ---
    "attack_ogm_seqno_highwater_jam": red_team.GAP,
    "attack_broadcast_seqno_blackhole": red_team.HELD,
    "attack_broadcast_seqno_in_window_jump": red_team.HELD,
    "attack_broadcast_resync_hijack": red_team.HELD,
    "attack_broadcast_evict_then_reseed": red_team.HELD,
    "attack_broadcast_dedup_table_exhaustion": red_team.HELD,
    "attack_relayed_tq_inflation": red_team.HELD,
}
"""Expected verdict per attack — the baseline the ``09-mesh-auth-gaps.md`` design
doc records. A newly-succeeding attack (or a fix that closes a gap) must flip the
verdict here, in the report, and in the doc together."""


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


# --- the HTML report --------------------------------------------------------


def test_each_finding_carries_its_attacks_own_docstring():
    """The console line reports what was measured; the page also has to say
    what was attempted. That prose already exists — it is the attack's
    docstring — so the report reads it off the function rather than asking
    every attack to repeat itself into its `Finding`."""
    finding = red_team.described(
        red_team.Finding("Flood", red_team.HELD, "held"), red_team.attack_flood
    )
    assert "storm of garbage" in finding.description


def test_findings_render_into_the_report_rows_the_page_takes():
    findings = [
        red_team.Finding("Held one", red_team.HELD, "held", description="why"),
        red_team.Finding("Gap one", red_team.GAP, "gap"),
    ]
    rows = red_team.finding_reports(findings)

    assert [row.name for row in rows] == ["Held one", "Gap one"]
    assert [row.verdict for row in rows] == [red_team.HELD, red_team.GAP]
    assert rows[0].description == "why"


def test_write_report_writes_a_self_contained_page(tmp_path):
    out = tmp_path / "red_team_report.html"
    findings = [
        red_team.Finding("Held one", red_team.HELD, "the mesh refused it"),
        red_team.Finding("Gap one", red_team.GAP, "it got in"),
    ]
    written = red_team.write_report(findings, out)

    page = written.read_text(encoding="utf-8")
    assert page.lstrip().startswith("<!doctype html>")
    assert "the mesh refused it" in page
    assert "it got in" in page


def test_the_scenario_and_the_page_share_one_verdict_vocabulary():
    """Two copies of these strings is exactly the fragmentation the report is
    meant to remove: a verdict renamed in one place would silently render as
    an unclassified row in the other."""
    from wayfinder_sim import report

    assert (red_team.HELD, red_team.BY_DESIGN, red_team.GAP) == (
        report.HELD,
        report.BY_DESIGN,
        report.GAP,
    )


def test_the_page_says_plainly_when_nothing_got_through(tmp_path):
    """The state the repo is working towards, and the one the live battery
    never renders while a gap is still open."""
    out = red_team.write_report(
        [red_team.Finding("Held one", red_team.HELD, "refused")],
        tmp_path / "red_team_report.html",
    )
    assert "None of them got through" in out.read_text(encoding="utf-8")
