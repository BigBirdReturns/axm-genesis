"""Shared utilities for the AXM build pipeline."""
from __future__ import annotations

import re
import unicodedata
from typing import List


def normalize_source_text(text: str) -> str:
    """Normalize source text for content/source.txt.

    - NFC unicode normalization
    - Strip trailing whitespace per line
    - Collapse runs of internal whitespace to single space
    - Ensure trailing newline
    """
    text = unicodedata.normalize("NFC", text)
    lines = text.splitlines()
    out: List[str] = []
    for line in lines:
        stripped = line.rstrip()
        stripped = re.sub(r"\s+", " ", stripped)
        out.append(stripped)
    result = "\n".join(out)
    if not result.endswith("\n"):
        result += "\n"
    return result
