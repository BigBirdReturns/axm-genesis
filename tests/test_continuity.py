"""The law-book guard (RFC_FAMILY_DOCTRINE, train PR 084).

Both game clients' CLAUDE.mds order every session to read
``docs/CONTINUITY.md`` before designing anything. Until train PR 082 that
file did not exist — a phantom pointer every session was aimed at. This
guard pins its existence and its load-bearing sections so the law book can
never silently go phantom (or hollow) again. It checks structure, not prose:
the owner remains free to amend any wording.
"""
from __future__ import annotations

from pathlib import Path

CONTINUITY = Path(__file__).resolve().parents[1] / "docs" / "CONTINUITY.md"

# The sections the family's docs rely on being present, by exact heading.
REQUIRED_HEADINGS = [
    "## The laws",
    "## Operating doctrine",
    "## The family",
    "## The record",
    "## Amendment",
]

# Load-bearing anchor phrases: the kernel invariant and the constitution's
# canonical citation. If either disappears, the file no longer consolidates
# the canon it exists to point at.
REQUIRED_ANCHORS = [
    "Genesis compiles and signs; everything else only reads.",
    "0002-platform-constitution.md",
]


def test_continuity_exists() -> None:
    assert CONTINUITY.is_file(), (
        "docs/CONTINUITY.md is missing — the file both game clients order "
        "every session to read (see RFC_FAMILY_DOCTRINE, train PR 082)."
    )


def test_continuity_carries_required_sections() -> None:
    text = CONTINUITY.read_text(encoding="utf-8")
    missing = [h for h in REQUIRED_HEADINGS if h not in text]
    assert not missing, f"CONTINUITY.md lost required section(s): {missing}"


def test_continuity_carries_load_bearing_anchors() -> None:
    # Whitespace-normalized: prose is free to re-wrap lines without breaking
    # the guard — only the words are load-bearing.
    text = " ".join(CONTINUITY.read_text(encoding="utf-8").split())
    missing = [a for a in REQUIRED_ANCHORS if a not in text]
    assert not missing, f"CONTINUITY.md lost load-bearing anchor(s): {missing}"
