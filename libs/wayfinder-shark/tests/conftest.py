"""Fixtures for testing the Wayfinder Wireshark Lua dissector via tshark.

The reusable building blocks for any dissector test: locating the Lua plugin and
`tshark`, writing a single-frame pcap, and reading back the decoded fields. The
actual frame layouts and assertions live in the `test_*.py` modules alongside.
"""

import shutil
import struct
import subprocess
from pathlib import Path

import pytest

# This file is libs/wayfinder-shark/tests/conftest.py, so the plugin sits one
# directory up from the tests folder.
PLUGIN_DIR = Path(__file__).resolve().parents[1]
LUA_PLUGIN = PLUGIN_DIR / "wayfinder.lua"

# pcap link-layer type for raw Ethernet frames.
LINKTYPE_ETHERNET = 1


def write_pcap(path: Path, frame: bytes) -> None:
    """Write a minimal pcap holding the single Ethernet `frame`.

    Classic (microsecond) pcap format: a 24-byte global header followed by one
    16-byte record header and the frame bytes. Little-endian, snaplen 65535,
    LINKTYPE_ETHERNET so tshark hands the frame to its `eth` dissector.
    """
    with path.open("wb") as fh:
        # magic, version 2.4, thiszone, sigfigs, snaplen, network
        fh.write(
            struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)
        )
        # ts_sec, ts_usec, incl_len, orig_len
        fh.write(struct.pack("<IIII", 0, 0, len(frame), len(frame)))
        fh.write(frame)


@pytest.fixture(scope="session")
def tshark_bin() -> str:
    """Path to the `tshark` executable, or skip the test if it isn't installed."""
    exe = shutil.which("tshark")
    if exe is None:
        pytest.skip("tshark not found in PATH")
    return exe


@pytest.fixture(scope="session", autouse=True)
def _require_plugin() -> None:
    """Fail loudly if the dissector under test is missing — it's in-repo."""
    if not LUA_PLUGIN.is_file():
        pytest.fail(f"Lua dissector not found at {LUA_PLUGIN}")


@pytest.fixture
def dissect(tshark_bin, tmp_path):
    """Return ``dissect(frame, fields, extra_args=None) -> {field: value}``.

    Writes `frame` to a pcap, runs `tshark` with the Wayfinder Lua dissector
    loaded, and returns the requested ``-T fields`` values for the (single)
    decoded packet. `fields` are display-filter field names, e.g.
    ``"wayfinder.originator.seqno"`` or the pseudo-field ``"_ws.col.protocol"``.
    `extra_args` are appended verbatim, for tests that need to set a dissector
    preference (``-o wayfinder.carrier_ethertype:0x1234``).
    """

    def _dissect(
        frame: bytes, fields: list[str], extra_args: list[str] | None = None
    ) -> dict[str, str]:
        pcap = tmp_path / "frame.pcap"
        write_pcap(pcap, frame)

        cmd = [
            tshark_bin,
            "-r",
            str(pcap),
            "-X",
            f"lua_script:{LUA_PLUGIN}",
            "-T",
            "fields",
        ]
        cmd += extra_args or []
        for field in fields:
            cmd += ["-e", field]

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        # One packet -> one output line; tshark separates fields with tabs and
        # may drop trailing empty columns, so pad back out to len(fields).
        lines = result.stdout.splitlines()
        values = lines[0].split("\t") if lines else []
        values += [""] * (len(fields) - len(values))
        return dict(zip(fields, values))

    return _dissect
