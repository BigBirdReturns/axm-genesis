"""
AXM Extension Schemas

Normative Arrow schemas for ext/ parquet files.
Each extension has: schema, sort key, semantics, and validation rules.

INVARIANT: Extension schemas are versioned (name@version).
INVARIANT: Extensions use stable join keys that survive shard rebuilds.
INVARIANT: Old verifiers ignore extensions they don't understand.
"""
from __future__ import annotations

try:
    import pyarrow as pa
except ImportError:
    pa = None


# ---------------------------------------------------------------------------
# locators@1 — Structural position of evidence in source documents
# ---------------------------------------------------------------------------
# Join key: evidence_addr (deterministic hash of source_hash + byte range)
# Survives shard rebuilds because it depends only on content bytes, not internal IDs.
# Sort key: evidence_addr (deterministic)

if pa is not None:
    LOCATORS_SCHEMA = pa.schema([
        ("evidence_addr", pa.string()),       # Stable: hash(source_hash, byte_start, byte_end)
        ("span_id", pa.string()),             # Link to spans.parquet (present when available)
        ("source_hash", pa.string()),         # Content hash
        ("kind", pa.string()),                # pdf, docx, html, txt, pptx, xlsx
        ("page_index", pa.int16()),           # Nullable: page number (0-indexed)
        ("paragraph_index", pa.int32()),      # Nullable: paragraph index
        ("block_id", pa.string()),            # Nullable: section/div identifier
        ("file_path", pa.string()),           # Original filename
    ])
    LOCATORS_SORT_KEY = "evidence_addr"

    # ---------------------------------------------------------------------------
    # references@1 — Cross-shard claim references (composition)
    # ---------------------------------------------------------------------------
    # Enables: multi-shard queries, decision shards citing source shards,
    #          base+delta evaluation (SOCOM doctrine + FRAGO)
    # Integrity rule: if dst_shard_id is mounted, target must exist or ref is "broken"

    REFERENCES_SCHEMA = pa.schema([
        ("src_claim_id", pa.string()),        # Claim in THIS shard making the reference
        ("relation_type", pa.string()),       # supports, contradicts, derives_from, supersedes, cites
        ("dst_shard_id", pa.string()),        # Target shard ID
        ("dst_object_type", pa.string()),     # claim, entity, or shard
        ("dst_object_id", pa.string()),       # Target claim_id, entity_id, or shard_id
        ("confidence", pa.float32()),         # 0.0-1.0
        ("note", pa.string()),               # Optional human-readable annotation
    ])
    REFERENCES_SORT_KEY = "src_claim_id"

    # ---------------------------------------------------------------------------
    # lineage@1 — Shard versioning and supersession
    # ---------------------------------------------------------------------------
    # Enables: delta shards, incremental updates, version chains
    # Manifest also carries: "supersedes": [shard_id...] for cheap discovery

    LINEAGE_SCHEMA = pa.schema([
        ("shard_id", pa.string()),            # THIS shard
        ("supersedes_shard_id", pa.string()), # Shard being superseded
        ("action", pa.string()),              # supersede, amend, retract
        ("timestamp", pa.string()),           # ISO 8601
        ("note", pa.string()),               # Optional context
    ])
    LINEAGE_SORT_KEY = "shard_id"

    # ---------------------------------------------------------------------------
    # temporal@1 — Claim validity windows
    # ---------------------------------------------------------------------------
    # Enables: staleness detection, time-scoped queries

    TEMPORAL_SCHEMA = pa.schema([
        ("claim_id", pa.string()),
        ("valid_from", pa.string()),          # ISO 8601 or empty for "always"
        ("valid_until", pa.string()),         # ISO 8601 or empty for "until superseded"
        ("temporal_context", pa.string()),    # e.g. "valid until Army revision FM 21-11-1"
    ])
    TEMPORAL_SORT_KEY = "claim_id"

    # ---------------------------------------------------------------------------
    # coords@1 — Semantic coordinate space (from deprecated AXM-KG)
    # ---------------------------------------------------------------------------
    # Enables: geometric queries ("all quantities"), coordinate pathfinding
    # Maps to MM-TT-SS-XXXX 8-category coordinate system

    COORDS_SCHEMA = pa.schema([
        ("entity_id", pa.string()),
        ("major", pa.string()),               # Major category
        ("type", pa.string()),                # Type within major
        ("subtype", pa.string()),             # Subtype
        ("instance", pa.string()),            # Instance identifier
    ])
    COORDS_SORT_KEY = "entity_id"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

EXTENSION_REGISTRY = {
    "locators@1": {
        "file": "locators.parquet",
        "sort_key": "evidence_addr",
        "description": "Structural position of evidence in source documents",
        "stable_join": "evidence_addr = hash(source_hash + byte_start + byte_end)",
        "depends_on": [],
    },
    "references@1": {
        "file": "references.parquet",
        "sort_key": "src_claim_id",
        "description": "Cross-shard claim references for composition",
        "stable_join": "src_claim_id (from claims.parquet), dst_shard_id + dst_object_id",
        "depends_on": [],
        "integrity_rule": "If dst_shard_id is mounted, target must exist or ref is broken",
    },
    "lineage@1": {
        "file": "lineage.parquet",
        "sort_key": "shard_id",
        "description": "Shard versioning and supersession chains",
        "stable_join": "shard_id, supersedes_shard_id",
        "depends_on": [],
        "manifest_hint": "supersedes: [shard_id...] for cheap discovery",
    },
    "temporal@1": {
        "file": "temporal.parquet",
        "sort_key": "claim_id",
        "description": "Claim validity windows for staleness detection",
        "stable_join": "claim_id (from claims.parquet)",
        "depends_on": [],
    },
    "coords@1": {
        "file": "coords.parquet",
        "sort_key": "entity_id",
        "description": "Semantic coordinate space (MM-TT-SS-XXXX)",
        "stable_join": "entity_id (from entities.parquet)",
        "depends_on": [],
    },
}
