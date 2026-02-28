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


# Backward-compatible alias
canonical_manifest_json = dumps_canonical_json
