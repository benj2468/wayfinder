"""Puts this directory on `sys.path` so the tests can `import fakesim`.

Lives here rather than in a `pythonpath` ini entry because only *one* ini file
is ever in effect: a `pytest` run from the repo root uses the root
`pyproject.toml` and never reads `ml/pyproject.toml`, so a `pythonpath` set
there would silently not apply. Conftests are loaded per-directory whatever the
rootdir is, so this works from both `ml/` and the repo root.
"""

from __future__ import annotations

import sys
from pathlib import Path

_TESTS_DIR = str(Path(__file__).parent)

if _TESTS_DIR not in sys.path:
    sys.path.insert(0, _TESTS_DIR)
