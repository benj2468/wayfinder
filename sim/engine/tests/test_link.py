import pytest

from engine.channel import PerfectWire
from engine.link import Link


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
