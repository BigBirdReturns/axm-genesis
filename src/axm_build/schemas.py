"""Normative core-table schemas for AXM shards.

Re-exports from axm_verify.const so the reference implementation shares
one source of truth. Schemas are {field: "string" | "integer"} mappings
with exact key sets (spec section 11).
"""
from __future__ import annotations

from axm_verify.const import (
    CLAIMS_SCHEMA,
    ENTITIES_SCHEMA,
    PROVENANCE_SCHEMA,
    SPANS_SCHEMA,
    VALID_OBJECT_TYPES,
    VALID_TIERS,
)

__all__ = [
    "ENTITIES_SCHEMA",
    "CLAIMS_SCHEMA",
    "PROVENANCE_SCHEMA",
    "SPANS_SCHEMA",
    "VALID_OBJECT_TYPES",
    "VALID_TIERS",
]
