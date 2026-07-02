"""Repo-root pytest bootstrap.

Makes src/ importable so the suite runs against the working tree even
without `pip install -e .`. The kernel's verification path is deliberately
lightweight (blake3, pynacl, an ML-DSA-44 backend); there are no optional
heavyweight dependencies to stub. Tests that need an ML-DSA-44 backend
skip cleanly when none is installed (see tests/helpers.py).
"""
from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
