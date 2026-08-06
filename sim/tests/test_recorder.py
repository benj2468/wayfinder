from wayfinder_sim.recorder import Recorder


def test_append_and_column():
    rec = Recorder(interval_ms=50)
    rec.append(0.0, {"a": 1, "b": "x"})
    rec.append(0.05, {"a": 2, "b": "y"})
    assert rec.times_s == [0.0, 0.05]
    assert rec.column("a") == [1, 2]
    assert rec.column("b") == ["x", "y"]


def test_transitions_empty_column_is_empty():
    rec = Recorder(interval_ms=50)
    assert rec.transitions("a") == []


def test_transitions_skips_leading_and_interleaved_none():
    rec = Recorder(interval_ms=50)
    rec.append(0.0, {"route": None})
    rec.append(1.0, {"route": None})
    rec.append(2.0, {"route": "direct"})
    rec.append(3.0, {"route": None})
    rec.append(4.0, {"route": "direct"})
    assert rec.transitions("route") == [(2.0, "direct")]


def test_transitions_records_each_change_once():
    rec = Recorder(interval_ms=50)
    rec.append(0.0, {"route": "direct"})
    rec.append(1.0, {"route": "direct"})
    rec.append(2.0, {"route": "indirect"})
    rec.append(3.0, {"route": "indirect"})
    rec.append(4.0, {"route": "direct"})
    assert rec.transitions("route") == [
        (0.0, "direct"),
        (2.0, "indirect"),
        (4.0, "direct"),
    ]


def test_transitions_all_none_is_empty():
    rec = Recorder(interval_ms=50)
    rec.append(0.0, {"route": None})
    rec.append(1.0, {"route": None})
    assert rec.transitions("route") == []
