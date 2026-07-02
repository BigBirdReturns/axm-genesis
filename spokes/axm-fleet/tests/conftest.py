"""Spoke-local pytest bootstrap.

Makes the spoke's src/ and the in-repo kernel src/ importable so the suite
runs from a plain checkout without `pip install -e`. When the spoke is
lifted out into its own repository, the kernel fallback simply finds
nothing and the installed axm-genesis package is used instead.
"""
from __future__ import annotations

import sys
from pathlib import Path

_SPOKE_SRC = Path(__file__).resolve().parents[1] / "src"
_KERNEL_SRC = Path(__file__).resolve().parents[3] / "src"

for p in (_SPOKE_SRC, _KERNEL_SRC):
    if p.is_dir() and str(p) not in sys.path:
        sys.path.insert(0, str(p))
