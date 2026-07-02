from __future__ import annotations

from typing import Any, Dict

from .jsonl import canonical_json_bytes


def dumps_canonical_json(obj: Dict[str, Any]) -> bytes:
    """Canonical JSON encoding for normative artifacts (spec section 5).

    manifest.json is exactly these bytes — no trailing newline, no BOM.
    """
    return canonical_json_bytes(obj)
