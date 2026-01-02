from __future__ import annotations

from enum import Enum
import pyarrow as pa

class ErrorCode(str, Enum):
    E_LAYOUT_DIRTY = "E_LAYOUT_DIRTY"
    E_LAYOUT_MISSING = "E_LAYOUT_MISSING"
    E_LAYOUT_TYPE = "E_LAYOUT_TYPE"
    E_DOTFILE = "E_DOTFILE"
    E_MANIFEST_SYNTAX = "E_MANIFEST_SYNTAX"
    E_MANIFEST_SCHEMA = "E_MANIFEST_SCHEMA"
    E_SIG_MISSING = "E_SIG_MISSING"
    E_SIG_INVALID = "E_SIG_INVALID"
    E_MERKLE_MISMATCH = "E_MERKLE_MISMATCH"
    E_SCHEMA_READ = "E_SCHEMA_READ"
    E_SCHEMA_MISSING = "E_SCHEMA_MISSING"
    E_SCHEMA_TYPE = "E_SCHEMA_TYPE"
    E_SCHEMA_NULL = "E_SCHEMA_NULL"
    E_SCHEMA_ENUM = "E_SCHEMA_ENUM"
    E_ID_ENTITY = "E_ID_ENTITY"
    E_ID_CLAIM = "E_ID_CLAIM"
    E_REF_ORPHAN = "E_REF_ORPHAN"
    E_REF_SOURCE = "E_REF_SOURCE"
    E_REF_READ = "E_REF_READ"

# Strict schemas (types must match exactly)
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

PUBKEY_LEN = 32
SIG_LEN = 64
