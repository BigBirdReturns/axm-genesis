from __future__ import annotations

from enum import Enum
try:
    import pyarrow as pa  # type: ignore
except Exception:
    pa = None  # type: ignore


class ErrorCode(str, Enum):
    # ── Layout ────────────────────────────────────────────────────────────
    E_LAYOUT_DIRTY   = "E_LAYOUT_DIRTY"    # unexpected file/dir at shard root or in required dir
    E_LAYOUT_MISSING = "E_LAYOUT_MISSING"  # required directory or file absent
    E_DOTFILE        = "E_DOTFILE"         # dotfile found anywhere in shard tree
    # ── Manifest ──────────────────────────────────────────────────────────
    E_MANIFEST_SYNTAX = "E_MANIFEST_SYNTAX"  # manifest.json is not valid JSON
    E_MANIFEST_SCHEMA = "E_MANIFEST_SCHEMA"  # manifest.json missing required field or wrong type
    # ── Signature ─────────────────────────────────────────────────────────
    E_SIG_MISSING = "E_SIG_MISSING"  # sig/manifest.sig or sig/publisher.pub not found
    E_SIG_INVALID = "E_SIG_INVALID"  # signature does not verify, key mismatch, or wrong size
    # ── Integrity ─────────────────────────────────────────────────────────
    E_MERKLE_MISMATCH = "E_MERKLE_MISMATCH"  # computed Merkle root != stored value
    # ── Schema ────────────────────────────────────────────────────────────
    E_SCHEMA_READ    = "E_SCHEMA_READ"    # parquet file unreadable or exceeds size limit
    E_SCHEMA_MISSING = "E_SCHEMA_MISSING" # required parquet file absent
    E_SCHEMA_TYPE    = "E_SCHEMA_TYPE"    # wrong column name, type, or count
    E_SCHEMA_NULL    = "E_SCHEMA_NULL"    # null in a required column
    E_SCHEMA_ENUM    = "E_SCHEMA_ENUM"    # invalid value for object_type or tier
    # ── Identity ──────────────────────────────────────────────────────────
    E_ID_ENTITY = "E_ID_ENTITY"  # entity_id does not match recomputed hash
    E_ID_CLAIM  = "E_ID_CLAIM"   # claim_id does not match recomputed hash
    # ── References ────────────────────────────────────────────────────────
    E_REF_ORPHAN = "E_REF_ORPHAN"  # claim subject/object not in entities
    E_REF_SOURCE = "E_REF_SOURCE"  # span/provenance source_hash not in content/, or byte range OOB
    E_REF_READ   = "E_REF_READ"    # content file unreadable during span verification
    # ── Stream continuity (REQ 5) ─────────────────────────────────────────
    E_BUFFER_DISCONTINUITY = "E_BUFFER_DISCONTINUITY"  # frame gap in cam_latents.bin

# Strict schemas (types must match exactly)
if pa is not None:
    ENTITIES_SCHEMA = pa.schema([
        ("entity_id", pa.string()),
        ("namespace", pa.string()),
        ("label", pa.string()),
        ("entity_type", pa.string()),
    ])

    CLAIMS_SCHEMA = pa.schema([
        ("claim_id", pa.string()),
        ("subject", pa.string()),
        ("predicate", pa.string()),
        ("object", pa.string()),
        ("object_type", pa.string()),
        ("tier", pa.int8()),
    ])

    PROVENANCE_SCHEMA = pa.schema([
        ("provenance_id", pa.string()),
        ("claim_id", pa.string()),
        ("source_hash", pa.string()),
        ("byte_start", pa.int64()),
        ("byte_end", pa.int64()),
    ])

    SPANS_SCHEMA = pa.schema([
        ("span_id", pa.string()),
        ("source_hash", pa.string()),
        ("byte_start", pa.int64()),
        ("byte_end", pa.int64()),
        ("text", pa.string()),
    ])
else:
    # Fallback schemas when pyarrow is unavailable. Types use DuckDB-style strings.
    ENTITIES_SCHEMA = [
        ("entity_id", "VARCHAR"),
        ("namespace", "VARCHAR"),
        ("label", "VARCHAR"),
        ("entity_type", "VARCHAR"),
    ]
    CLAIMS_SCHEMA = [
        ("claim_id", "VARCHAR"),
        ("subject", "VARCHAR"),
        ("predicate", "VARCHAR"),
        ("object", "VARCHAR"),
        ("object_type", "VARCHAR"),
        ("tier", "TINYINT"),
    ]
    PROVENANCE_SCHEMA = [
        ("provenance_id", "VARCHAR"),
        ("claim_id", "VARCHAR"),
        ("source_hash", "VARCHAR"),
        ("byte_start", "BIGINT"),
        ("byte_end", "BIGINT"),
    ]
    SPANS_SCHEMA = [
        ("span_id", "VARCHAR"),
        ("source_hash", "VARCHAR"),
        ("byte_start", "BIGINT"),
        ("byte_end", "BIGINT"),
        ("text", "VARCHAR"),
    ]


VALID_OBJECT_TYPES = {
    "entity",
    "literal:string",
    "literal:integer",
    "literal:decimal",
    "literal:boolean",
}

VALID_TIERS = {0, 1, 2, 3, 4}

REQUIRED_ROOT_ITEMS = {
    "manifest.json",
    "sig",
    "content",
    "graph",
    "evidence",
}

REQUIRED_SIG_FILES = {"manifest.sig", "publisher.pub"}
REQUIRED_GRAPH_FILES = {"entities.parquet", "claims.parquet", "provenance.parquet"}
REQUIRED_EVIDENCE_FILES = {"spans.parquet"}

KNOWN_SUITES = {"ed25519", "axm-blake3-mldsa44"}

SUITE_SIZES = {
    "ed25519": {"pk": 32, "sig": 64},
    "axm-blake3-mldsa44": {"pk": 1312, "sig": 2420},
}
