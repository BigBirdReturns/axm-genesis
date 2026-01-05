from __future__ import annotations

import json
from typing import Any, Dict


def dumps_canonical_json(obj: Dict[str, Any]) -> bytes:
    """Canonical JSON encoding for normative artifacts.

    Must match: json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    and must be UTF-8 encoded.
    """

    s = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return s.encode("utf-8")

# Backwards-compat alias (older test suites expect this name)
def canonical_manifest_json(obj: dict) -> bytes:
    """Return canonical JSON bytes for a manifest dict."""
    return dumps_canonical_json(obj)

