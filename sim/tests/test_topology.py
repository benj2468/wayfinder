from wayfinder_sim.channel import PerfectWire
from wayfinder_sim.topology import complete_graph, diamond, pair, path, shared_lan, star


def _members(links) -> set[frozenset[str]]:
    return {frozenset(link.endpoints) for link in links}


def test_pair_creates_a_single_point_to_point_link():
    link = pair("a", "b", PerfectWire())
    assert link.endpoints == ("a", "b")
    assert link.name == "a-b"


def test_pair_resolves_a_factory_with_both_endpoint_names():
    seen = []

    def factory(a: str, b: str):
        seen.append((a, b))
        return PerfectWire()

    pair("gcsa", "drone", factory)
    assert seen == [("gcsa", "drone")]


def test_pair_shares_one_channel_instance_when_given_directly():
    channel = PerfectWire()
    link = pair("a", "b", channel)
    assert link.channel is channel


def test_path_chains_adjacent_nodes():
    links = path(["a", "b", "c", "d"], PerfectWire())
    assert len(links) == 3
    assert _members(links) == {
        frozenset({"a", "b"}),
        frozenset({"b", "c"}),
        frozenset({"c", "d"}),
    }


def test_complete_graph_has_n_choose_2_edges():
    links = complete_graph(["m1", "m2", "m3", "m4", "m5"], PerfectWire())
    assert len(links) == 10  # 5*4/2
    assert _members(links) == {
        frozenset({a, b})
        for i, a in enumerate(["m1", "m2", "m3", "m4", "m5"])
        for b in ["m1", "m2", "m3", "m4", "m5"][i + 1 :]
    }


def test_shared_lan_is_one_link_with_every_member():
    links = shared_lan(["m1", "m2", "m3"], PerfectWire())
    assert len(links) == 1
    assert links[0].endpoints == ("m1", "m2", "m3")


def test_diamond_has_two_disjoint_two_hop_paths():
    links = diamond("a", "b", "c", "d", PerfectWire())
    assert _members(links) == {
        frozenset({"a", "b"}),
        frozenset({"a", "c"}),
        frozenset({"b", "d"}),
        frozenset({"c", "d"}),
    }


def test_star_joins_hub_to_every_spoke():
    links = star("hub", ["s1", "s2", "s3"], PerfectWire())
    assert _members(links) == {
        frozenset({"hub", "s1"}),
        frozenset({"hub", "s2"}),
        frozenset({"hub", "s3"}),
    }
