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
# streams@1 — embodied binary stream evidence
# ---------------------------------------------------------------------------
# Defined by spec/profiles/embodied@1.md section 7 (informative there,
# binding here for the reference compiler). One row per stream record
# indexed by an embodied judge (StrictJudge or equivalent). Rows sort by
# the composite key (stream, frame_id, offset); integer components sort
# numerically.

STREAMS_SCHEMA = {
    "frame_id": "integer",        # frame index
    "stream": "string",           # "latents" or "residuals"
    "file": "string",             # "cam_latents.bin" or "cam_residuals.bin"
    "offset": "integer",          # byte offset of the record in the file
    "length": "integer",          # total record length (header + payload)
    "status": "string",           # "VERIFIED" or a failure reason
    "content_hash": "string",     # SHA-256 hex of the payload bytes
}
STREAMS_SORT_KEY = ("stream", "frame_id", "offset")

# ---------------------------------------------------------------------------
# attestations@1 — timestamp anchors over other shards (RFC 0005)
# ---------------------------------------------------------------------------
# One row per proof artifact carried in content/. target_shard_id names the
# ANCHORED shard (never the containing one). anchored_at is the
# authority-asserted time and is advisory — the raw proof at proof_path is
# authoritative.

ATTESTATIONS_SCHEMA = {
    "target_shard_id": "string",  # sh1_ id of the anchored shard
    "kind": "string",             # rfc3161 | opentimestamps
    "authority": "string",        # TSA URL / calendar identifier
    "digest_sha256": "string",    # SHA-256 hex of the target manifest bytes
    "anchored_at": "string",      # RFC 3339 UTC, authority-asserted (advisory)
    "proof_path": "string",       # e.g. "content/manifest.tsr"
}
ATTESTATIONS_SORT_KEY = ("target_shard_id", "kind", "proof_path")

# ---------------------------------------------------------------------------
# packets@1 — verbatim canonical packet bytes for a custody journal (RFC 0006)
# ---------------------------------------------------------------------------
# The archival rule (DURABILITY.md §5.3) is hash-over-STORED-bytes: the exact
# canonical bytes that were TPM-signed live in content/ as an ordinary Merkle
# leaf, and this table INDEXES them by (file, offset, length) so a future
# verifier recomputes packet_sha256 over stored bytes and never has to
# reproduce a canonicalization. No binary rides in the JSONL row.

PACKETS_SCHEMA = {
    "seq": "integer",             # packet sequence number (primary key)
    "file": "string",             # content path holding the bytes, e.g. "content/packets.bin"
    "offset": "integer",          # byte offset of the packet in that file
    "length": "integer",          # packet byte length
    "packet_sha256": "string",    # SHA-256 hex of the verbatim canonical packet bytes
}
PACKETS_SORT_KEY = "seq"

# ---------------------------------------------------------------------------
# tpm-attestation@1 — TPM hardware trust-chain evidence (RFC 0006)
# ---------------------------------------------------------------------------
# One row per stored evidence blob. Every binary blob (TPMT_SIGNATURE,
# TPM2B_ATTEST, quote nonce, TPM2B_PUBLIC key area, DER cert) lives in
# content/ and is indexed here by (file, offset, length) + its sha256 —
# never inlined. key/cert rows carry seq=0 (they are not sequence-bound);
# pcrs is a JSON array string on a quote's attest row, "" otherwise.
# (Registered under this name so it never collides with attestations@1,
# which is RFC 0005's unrelated proof-of-WHEN table.)

TPM_ATTESTATION_SCHEMA = {
    "kind": "string",             # packet_sig | quote | sign_pub | ak_pub | ek_cert
    "seq": "integer",             # sequence bound; 0 for non-sequence key/cert rows
    "field": "string",            # signature | attest | nonce | public | certificate
    "alg": "string",              # algorithm id, e.g. "tpm2:rsapss-2048-sha256:tpmt-signature"
    "key_fingerprint": "string",  # SHA-256 hex of the covering key's public-area bytes
    "file": "string",             # content path holding this blob
    "offset": "integer",          # byte offset of the blob in that file
    "length": "integer",          # blob byte length
    "sha256": "string",           # SHA-256 hex of the stored blob bytes
    "pcrs": "string",             # JSON array of quoted PCR indices; "" when absent
}
# (kind, seq, field, offset) is unique: distinct blobs never share a byte
# offset in the same file, so read-back stays strictly ordered.
TPM_ATTESTATION_SORT_KEY = ("kind", "seq", "field", "offset")

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
# "unique": True when the sort key is a primary key (a duplicate sort key
# is an error); False when it is merely an ordering key (rows tie-break on
# their full canonical encoding and only fully identical rows are
# rejected).

EXTENSION_REGISTRY = {
    "locators@1": {
        "file": "locators@1.jsonl",
        "schema": LOCATORS_SCHEMA,
        "sort_key": LOCATORS_SORT_KEY,
        "unique": False,
        "description": "Structural position of evidence in source documents",
    },
    "references@1": {
        "file": "references@1.jsonl",
        "schema": REFERENCES_SCHEMA,
        "sort_key": REFERENCES_SORT_KEY,
        "unique": False,
        "description": "Cross-shard claim references for composition",
    },
    "lineage@1": {
        "file": "lineage@1.jsonl",
        "schema": LINEAGE_SCHEMA,
        "sort_key": LINEAGE_SORT_KEY,
        "unique": True,
        "description": "Predecessor supersession rows (no self-id column)",
    },
    "temporal@1": {
        "file": "temporal@1.jsonl",
        "schema": TEMPORAL_SCHEMA,
        "sort_key": TEMPORAL_SORT_KEY,
        "unique": True,
        "description": "Claim validity windows for staleness detection",
    },
    "streams@1": {
        "file": "streams@1.jsonl",
        "schema": STREAMS_SCHEMA,
        "sort_key": STREAMS_SORT_KEY,
        "unique": True,
        "description": "Embodied binary stream evidence (profile embodied@1 §7)",
    },
    "attestations@1": {
        "file": "attestations@1.jsonl",
        "schema": ATTESTATIONS_SCHEMA,
        "sort_key": ATTESTATIONS_SORT_KEY,
        "unique": True,
        "description": "Timestamp anchors over other shards (RFC 0005)",
    },
    "packets@1": {
        "file": "packets@1.jsonl",
        "schema": PACKETS_SCHEMA,
        "sort_key": PACKETS_SORT_KEY,
        "unique": True,
        "description": "Verbatim canonical packet bytes for a custody journal (RFC 0006)",
    },
    "tpm-attestation@1": {
        "file": "tpm-attestation@1.jsonl",
        "schema": TPM_ATTESTATION_SCHEMA,
        "sort_key": TPM_ATTESTATION_SORT_KEY,
        "unique": True,
        "description": "TPM hardware trust-chain evidence, indexed into content/ (RFC 0006)",
    },
}
