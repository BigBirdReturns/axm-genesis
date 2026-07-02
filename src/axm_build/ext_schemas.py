"""AXM extension table schemas (spec section 16).

AXM-defined extensions are canonical JSONL files under ext/, named
<name>@<version>.jsonl, with the same encoding discipline as the core
tables: canonical JSON lines, exact key sets, no nulls, no floats, rows
sorted bytewise ascending by the sort key.

ext/ is opaque to the kernel verifier; these schemas bind only the
reference compiler. Shard ids inside extension tables use the sh1_ form
and refer only to OTHER shards — never to the containing shard, whose id
is ambient (derived from its manifest).

INVARIANT: Extension schemas are versioned (name@version); a new version
is a new identifier.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# locators@1 — structural position of evidence in source documents
# ---------------------------------------------------------------------------
# Join key: evidence_addr (deterministic hash of source_hash + byte range);
# survives shard rebuilds because it depends only on content bytes.
# page_index / paragraph_index are decimal strings, "" when unknown
# (canonical JSONL forbids nulls, and negative sentinels are not encodable).

LOCATORS_SCHEMA = {
    "evidence_addr": "string",
    "span_id": "string",
    "source_hash": "string",
    "kind": "string",             # pdf, docx, html, txt, pptx, xlsx
    "page_index": "string",       # decimal or ""
    "paragraph_index": "string",  # decimal or ""
    "block_id": "string",
    "file_path": "string",
}
LOCATORS_SORT_KEY = "evidence_addr"

# ---------------------------------------------------------------------------
# references@1 — cross-shard claim references (composition)
# ---------------------------------------------------------------------------
# dst_shard_id is a predecessor/foreign shard id in sh1_ form.
# confidence is a decimal string in [0,1] (no floats in canonical JSONL).

REFERENCES_SCHEMA = {
    "src_claim_id": "string",     # claim in THIS shard making the reference
    "relation_type": "string",    # supports, contradicts, derives_from, supersedes, cites
    "dst_shard_id": "string",     # sh1_<64 hex> — target shard identity
    "dst_object_type": "string",  # claim, entity, or shard
    "dst_object_id": "string",
    "confidence": "string",       # decimal string, e.g. "1.0"
    "note": "string",
}
REFERENCES_SORT_KEY = "src_claim_id"

# ---------------------------------------------------------------------------
# lineage@1 — shard versioning and supersession
# ---------------------------------------------------------------------------
# One row per superseded shard. There is NO self-id column: a shard's own
# id is the hash of its manifest and cannot appear in its own files.

LINEAGE_SCHEMA = {
    "supersedes_shard_id": "string",  # sh1_<64 hex> — the predecessor
    "action": "string",               # supersede | amend | retract
    "timestamp": "string",            # RFC 3339
    "note": "string",
}
LINEAGE_SORT_KEY = "supersedes_shard_id"

# ---------------------------------------------------------------------------
# temporal@1 — claim validity windows
# ---------------------------------------------------------------------------

TEMPORAL_SCHEMA = {
    "claim_id": "string",
    "valid_from": "string",        # RFC 3339 or "" for "always"
    "valid_until": "string",       # RFC 3339 or "" for "until superseded"
    "temporal_context": "string",
}
TEMPORAL_SORT_KEY = "claim_id"

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

EXTENSION_REGISTRY = {
    "locators@1": {
        "file": "locators@1.jsonl",
        "schema": LOCATORS_SCHEMA,
        "sort_key": LOCATORS_SORT_KEY,
        "description": "Structural position of evidence in source documents",
    },
    "references@1": {
        "file": "references@1.jsonl",
        "schema": REFERENCES_SCHEMA,
        "sort_key": REFERENCES_SORT_KEY,
        "description": "Cross-shard claim references for composition",
    },
    "lineage@1": {
        "file": "lineage@1.jsonl",
        "schema": LINEAGE_SCHEMA,
        "sort_key": LINEAGE_SORT_KEY,
        "description": "Predecessor supersession rows (no self-id column)",
    },
    "temporal@1": {
        "file": "temporal@1.jsonl",
        "schema": TEMPORAL_SCHEMA,
        "sort_key": TEMPORAL_SORT_KEY,
        "description": "Claim validity windows for staleness detection",
    },
}
