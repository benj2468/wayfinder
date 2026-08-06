import pytest

from wayfinder_sim.channel import PerfectWire
from wayfinder_sim.link import Link


def test_link_default_name_derived_from_endpoints():
    link = Link(("gcsa", "drone"), PerfectWire())
    assert link.name == "gcsa-drone"


def test_link_explicit_name_preserved():
    link = Link(("gcsa", "drone"), PerfectWire(), name="custom")
    assert link.name == "custom"


def test_link_shared_lan_name_joins_all_members():
    link = Link(("m1", "m2", "m3"), PerfectWire())
    assert link.name == "m1-m2-m3"


def test_link_rejects_single_endpoint():
    with pytest.raises(ValueError):
        Link(("gcsa",), PerfectWire())


def test_link_rejects_duplicate_endpoints():
    with pytest.raises(ValueError):
        Link(("gcsa", "gcsa"), PerfectWire())


def test_link_keepalive_override_defaults_to_unset():
    link = Link(("gcsa", "drone"), PerfectWire())
    assert link.tx_keepalive_interval_ms is None


def test_link_accepts_custom_keepalive_override():
    link = Link(("gcsa", "drone"), PerfectWire(), tx_keepalive_interval_ms=1000)
    assert link.tx_keepalive_interval_ms == 1000
