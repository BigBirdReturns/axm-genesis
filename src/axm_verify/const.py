"""AXM Genesis v1 — frozen kernel constants (spec/v1/SPECIFICATION.md)."""
from __future__ import annotations

import re
from enum import Enum


class ErrorCode(str, Enum):
    # ── Layout ────────────────────────────────────────────────────────────
    E_LAYOUT_DIRTY   = "E_LAYOUT_DIRTY"    # unexpected item, symlink, or resource-limit violation
    E_LAYOUT_MISSING = "E_LAYOUT_MISSING"  # required root item absent, or shard path missing
    E_DOTFILE        = "E_DOTFILE"         # dotfile found anywhere in shard tree
    # ── Manifest ──────────────────────────────────────────────────────────
    E_MANIFEST_SYNTAX = "E_MANIFEST_SYNTAX"  # manifest.json is not valid JSON
    E_MANIFEST_SCHEMA = "E_MANIFEST_SCHEMA"  # manifest violates spec section 6
    # ── Signature ─────────────────────────────────────────────────────────
    E_SIG_MISSING = "E_SIG_MISSING"  # sig/manifest.sig or sig/publisher.pub not found
    E_SIG_INVALID = "E_SIG_INVALID"  # wrong length, trusted-key mismatch, or a component fails
    # ── Integrity ─────────────────────────────────────────────────────────
    E_MERKLE_MISMATCH = "E_MERKLE_MISMATCH"  # computed Merkle root != stored value
    # ── Core tables ───────────────────────────────────────────────────────
    E_SCHEMA_READ    = "E_SCHEMA_READ"    # unreadable/malformed/non-canonical line, order, dup PK
    E_SCHEMA_MISSING = "E_SCHEMA_MISSING" # required core table file absent
    E_SCHEMA_TYPE    = "E_SCHEMA_TYPE"    # unexpected key or wrong JSON type
    E_SCHEMA_NULL    = "E_SCHEMA_NULL"    # required key missing from a record, or null
    E_SCHEMA_ENUM    = "E_SCHEMA_ENUM"    # invalid object_type or tier
    # ── Identity ──────────────────────────────────────────────────────────
    E_ID_ENTITY = "E_ID_ENTITY"  # entity_id does not match recomputed hash
    E_ID_CLAIM  = "E_ID_CLAIM"   # claim_id does not match recomputed hash
    # ── References ────────────────────────────────────────────────────────
    E_REF_ORPHAN = "E_REF_ORPHAN"  # claim subject/object not in entities; prov claim_id orphan
    E_REF_SOURCE = "E_REF_SOURCE"  # source_hash not in content/, byte range OOB, span mismatch
    E_REF_READ   = "E_REF_READ"    # content file unreadable during evidence checks
    # Profile error codes (e.g. E_BUFFER_DISCONTINUITY, embodied@1) are owned
    # by their profile modules under axm_verify/profiles/ — not by the kernel.


# ── Frozen protocol identifiers ──────────────────────────────────────────────

SPEC_VERSION = "1.0.0"
SUITE_HYBRID1 = "axm-hybrid1"

# Hybrid key/signature sizes (spec section 7.1)
ED25519_PK_LEN = 32
ED25519_SIG_LEN = 64
MLDSA44_PK_LEN = 1312
MLDSA44_SIG_LEN = 2420
HYBRID1_PK_LEN = ED25519_PK_LEN + MLDSA44_PK_LEN     # 1344
HYBRID1_SIG_LEN = ED25519_SIG_LEN + MLDSA44_SIG_LEN  # 2484

# Signature message domain prefix (spec section 7.2)
MANIFEST_SIG_DOMAIN = b"axm-genesis/v1/manifest\x00"

# ── Core table schemas (spec section 11) ─────────────────────────────────────
# field name -> JSON type ("string" | "integer"). Key sets are exact.

ENTITIES_SCHEMA = {
    "entity_id": "string",
    "namespace": "string",
    "label": "string",
    "entity_type": "string",
}
CLAIMS_SCHEMA = {
    "claim_id": "string",
    "subject": "string",
    "predicate": "string",
    "object": "string",
    "object_type": "string",
    "tier": "integer",
}
PROVENANCE_SCHEMA = {
    "provenance_id": "string",
    "claim_id": "string",
    "source_hash": "string",
    "byte_start": "integer",
    "byte_end": "integer",
}
SPANS_SCHEMA = {
    "span_id": "string",
    "source_hash": "string",
    "byte_start": "integer",
    "byte_end": "integer",
    "text": "string",
}

# (table file relpath, schema, primary key)
CORE_TABLES = (
    ("graph/entities.jsonl", ENTITIES_SCHEMA, "entity_id"),
    ("graph/claims.jsonl", CLAIMS_SCHEMA, "claim_id"),
    ("graph/provenance.jsonl", PROVENANCE_SCHEMA, "provenance_id"),
    ("evidence/spans.jsonl", SPANS_SCHEMA, "span_id"),
)

VALID_OBJECT_TYPES = {
    "entity",
    "literal:string",
    "literal:integer",
    "literal:decimal",
    "literal:boolean",
}

VALID_TIERS = {0, 1, 2, 3, 4}

# Largest integer permitted in kernel-defined documents (spec section 5).
MAX_JSON_INT = 2**63 - 1

# ── Layout (spec section 4) ──────────────────────────────────────────────────

REQUIRED_ROOT_ITEMS = {"manifest.json", "sig", "content", "graph", "evidence"}
OPTIONAL_ROOT_ITEMS = {"ext"}
REQUIRED_SIG_FILES = {"manifest.sig", "publisher.pub"}
REQUIRED_GRAPH_FILES = {"entities.jsonl", "claims.jsonl", "provenance.jsonl"}
REQUIRED_EVIDENCE_FILES = {"spans.jsonl"}

# ── Manifest (spec section 6) ────────────────────────────────────────────────

MANIFEST_TOP_KEYS = {
    "spec_version", "suite", "metadata", "publisher", "license",
    "sources", "integrity", "statistics", "profiles", "extensions",
    "supersedes",
}

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
PROFILE_ID_RE = re.compile(r"^[a-z][a-z0-9-]*@[1-9][0-9]*$")
EXTENSION_ID_RE = PROFILE_ID_RE
SHARD_ID_RE = re.compile(r"^sh1_[0-9a-f]{64}$")
# RFC 3339 date-time, UTC, Z designator only (numeric offsets rejected).
CREATED_AT_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?Z$")

# ── Identifiers (spec section 10) ────────────────────────────────────────────

ENTITY_ID_RE = re.compile(r"^e1_[a-z2-7]{52}$")
CLAIM_ID_RE = re.compile(r"^c1_[a-z2-7]{52}$")
PROVENANCE_ID_RE = re.compile(r"^p1_[a-z2-7]{52}$")
SPAN_ID_RE = re.compile(r"^s1_[a-z2-7]{52}$")

# ── CLI exit-code contract (spec section 13.4, frozen) ──────────────────────
# A verification failure where EVERY reported error code is in this set means
# the shard directory is structurally malformed → CLI exits 2. Otherwise 1.

MALFORMED_SHARD_CODES = frozenset({
    ErrorCode.E_LAYOUT_MISSING.value,
    ErrorCode.E_SCHEMA_MISSING.value,
    ErrorCode.E_SIG_MISSING.value,
})
