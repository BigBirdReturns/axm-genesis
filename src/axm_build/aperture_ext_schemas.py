"""Registered AXM Aperture package extensions (RFC 0009).

Aperture rows are ordinary canonical JSONL extension tables.  Genesis owns
byte custody, one-pass Merkle construction, signing, and verification.  The
Aperture and Core consumers own their domain validators; the frozen verifier
continues to treat extension contents as opaque Merkle-covered bytes.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict

from .ext_schemas import EXTENSION_REGISTRY

APERTURE_PACKAGE_REVISIONS_SCHEMA = {
    "package_id": "string",
    "revision": "string",
    "work_id": "string",
    "canonical_story_digest": "string",
    "canonical_edition_id": "string",
    "review_state": "string",
    "supersedes": "string",
    "edition_time_map_refs_json": "string",
}
APERTURE_PACKAGE_REVISIONS_SORT_KEY = ("package_id", "revision")

APERTURE_POSITIONS_SCHEMA = {
    "package_id": "string",
    "revision": "string",
    "position_id": "string",
    "canonical_start_us": "string",
    "canonical_end_us": "string",
    "kind": "string",
    "parent_id": "string",
    "label": "string",
}
APERTURE_POSITIONS_SORT_KEY = ("package_id", "revision", "position_id")

APERTURE_FACTS_SCHEMA = {
    "package_id": "string",
    "revision": "string",
    "fact_id": "string",
    "proposition": "string",
    "first_reveal_position_id": "string",
    "subject_ids_json": "string",
    "provenance_refs_json": "string",
}
APERTURE_FACTS_SORT_KEY = ("package_id", "revision", "fact_id")

APERTURE_CAUSAL_EDGES_SCHEMA = {
    "package_id": "string",
    "revision": "string",
    "edge_id": "string",
    "cause_fact_ids_json": "string",
    "effect_fact_id": "string",
    "strength": "string",
    "provenance_refs_json": "string",
}
APERTURE_CAUSAL_EDGES_SORT_KEY = ("package_id", "revision", "edge_id")

APERTURE_REVEALS_SCHEMA = {
    "package_id": "string",
    "revision": "string",
    "reveal_id": "string",
    "fact_id": "string",
    "position_id": "string",
    "mode": "string",
    "provenance_refs_json": "string",
}
APERTURE_REVEALS_SORT_KEY = ("package_id", "revision", "reveal_id")

APERTURE_EDITION_MAPS_SCHEMA = {
    "map_id": "string",
    "work_id": "string",
    "provider_edition_id": "string",
    "canonical_edition_id": "string",
    "segment_id": "string",
    "kind": "string",
    "provider_start_us": "string",
    "provider_end_us": "string",
    "canonical_start_us": "string",
    "canonical_end_us": "string",
    "rate_numerator": "string",
    "rate_denominator": "string",
    "evidence_refs_json": "string",
    "source_digests_json": "string",
    "confidence": "string",
    "review_state": "string",
}
APERTURE_EDITION_MAPS_SORT_KEY = ("map_id", "segment_id")

APERTURE_SOURCES_SCHEMA = {
    "package_id": "string",
    "revision": "string",
    "source_id": "string",
    "sha256": "string",
    "custody": "string",
    "contains_redistributable_text": "string",
}
APERTURE_SOURCES_SORT_KEY = ("package_id", "revision", "source_id")

APERTURE_EXTENSION_REGISTRY: Dict[str, Dict[str, Any]] = {
    "aperture-package-revisions@1": {
        "file": "aperture-package-revisions@1.jsonl",
        "schema": APERTURE_PACKAGE_REVISIONS_SCHEMA,
        "sort_key": APERTURE_PACKAGE_REVISIONS_SORT_KEY,
        "unique": True,
        "description": "Reviewed AXM Aperture story-package revisions",
    },
    "aperture-positions@1": {
        "file": "aperture-positions@1.jsonl",
        "schema": APERTURE_POSITIONS_SCHEMA,
        "sort_key": APERTURE_POSITIONS_SORT_KEY,
        "unique": True,
        "description": "Canonical timed narrative positions within a package revision",
    },
    "aperture-facts@1": {
        "file": "aperture-facts@1.jsonl",
        "schema": APERTURE_FACTS_SCHEMA,
        "sort_key": APERTURE_FACTS_SORT_KEY,
        "unique": True,
        "description": "Reviewed narrative facts bound to canonical positions",
    },
    "aperture-causal-edges@1": {
        "file": "aperture-causal-edges@1.jsonl",
        "schema": APERTURE_CAUSAL_EDGES_SCHEMA,
        "sort_key": APERTURE_CAUSAL_EDGES_SORT_KEY,
        "unique": True,
        "description": "Reviewed causal edges among Aperture package facts",
    },
    "aperture-reveals@1": {
        "file": "aperture-reveals@1.jsonl",
        "schema": APERTURE_REVEALS_SCHEMA,
        "sort_key": APERTURE_REVEALS_SORT_KEY,
        "unique": True,
        "description": "Fact acquisition modes at canonical story positions",
    },
    "aperture-edition-maps@1": {
        "file": "aperture-edition-maps@1.jsonl",
        "schema": APERTURE_EDITION_MAPS_SCHEMA,
        "sort_key": APERTURE_EDITION_MAPS_SORT_KEY,
        "unique": True,
        "description": "Piecewise provider-edition to canonical-edition TimeMaps",
    },
    "aperture-sources@1": {
        "file": "aperture-sources@1.jsonl",
        "schema": APERTURE_SOURCES_SCHEMA,
        "sort_key": APERTURE_SOURCES_SORT_KEY,
        "unique": True,
        "description": "Exact source identities and rights-safe custody declarations",
    },
}

APERTURE_EXTENSION_IDS = tuple(sorted(APERTURE_EXTENSION_REGISTRY))


def register_aperture_extensions() -> None:
    """Register RFC 0009 idempotently and refuse a conflicting definition."""
    for extension_id, registration in APERTURE_EXTENSION_REGISTRY.items():
        existing = EXTENSION_REGISTRY.get(extension_id)
        if existing is None:
            EXTENSION_REGISTRY[extension_id] = deepcopy(registration)
        elif existing != registration:
            raise RuntimeError(
                f"conflicting registered definition for {extension_id!r}; "
                "published extension versions are immutable"
            )
