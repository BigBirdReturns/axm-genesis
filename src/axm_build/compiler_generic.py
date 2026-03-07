from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

from axm_verify.identity import recompute_claim_id, recompute_entity_id
from axm_verify.logic import verify_shard

from .common import normalize_source_text, write_parquet_deterministic
from .manifest import dumps_canonical_json
from .merkle import compute_merkle_root
from .schemas import (
    CLAIMS_SCHEMA,
    ENTITIES_SCHEMA,
    PROVENANCE_SCHEMA,
    SPANS_SCHEMA,
    VALID_OBJECT_TYPES,
    VALID_TIERS,
)
from .sign import signing_key_from_private_key_bytes, mldsa44_keygen, MLDSAKeyPair, SUITE_MLDSA44, SUITE_ED25519


@dataclass(frozen=True)
class CompilerConfig:
    source_path: Path
    candidates_path: Path
    out_dir: Path
    private_key: bytes  # 32 bytes for ed25519, 2528 bytes for mldsa44 (or ignored if mldsa_keypair set)
    publisher_id: str
    publisher_name: str
    namespace: str
    created_at: str
    suite: str = "axm-blake3-mldsa44"  # "ed25519" for legacy, "axm-blake3-mldsa44" for post-quantum
    supersedes: tuple = ()   # shard IDs this shard supersedes — emits ext/lineage@1.parquet + manifest hint
    lineage_action: str = "supersede"   # supersede | amend | retract
    lineage_note: str = ""   # optional human-readable annotation
    domain_hints: str = ""   # domain-specific context injected into tier 2/3 LLM prompt


def _b32_id(prefix: str, data: str) -> str:
    digest = hashlib.sha256(data.encode("utf-8")).digest()
    return prefix + base64.b32encode(digest[:15]).decode("ascii").lower().rstrip("=")


def _find_span_strict(content_bytes: bytes, needle: str) -> Tuple[int, int]:
    try:
        needle_bytes = needle.encode("utf-8")
    except UnicodeEncodeError as e:
        raise ValueError(f"Evidence invalid UTF-8: {needle!r}") from e

    count = content_bytes.count(needle_bytes)
    if count == 0:
        raise ValueError(f"Evidence not found: {needle[:80]!r}")
    if count > 1:
        raise ValueError(f"Ambiguous evidence: found {count} matches for {needle[:40]!r}")

    idx = content_bytes.find(needle_bytes)
    return idx, idx + len(needle_bytes)


def compile_generic_shard(cfg: CompilerConfig) -> bool:
    """Compile a generic shard from canonical source.txt and candidates.jsonl.

    Invariants:
    - Evidence spans must match bytes in content/source.txt after normalization.
    - Ambiguous evidence fails the build.
    - Output Parquet files are written deterministically.
    - The compiled shard must pass axm-verify using the publisher key.
    - Locator data from candidates survives into ext/locators@1.parquet.
    """

    if not cfg.source_path.exists():
        raise FileNotFoundError(f"Source not found: {cfg.source_path}")
    if not cfg.candidates_path.exists():
        raise FileNotFoundError(f"Candidates not found: {cfg.candidates_path}")

    raw_text = cfg.source_path.read_text(encoding="utf-8", errors="strict")
    norm_text = normalize_source_text(raw_text)
    content_bytes = norm_text.encode("utf-8")
    source_hash = hashlib.sha256(content_bytes).hexdigest()

    # Fresh output
    if cfg.out_dir.exists():
        shutil.rmtree(cfg.out_dir)
    for d in ("content", "graph", "evidence", "sig", "ext"):
        (cfg.out_dir / d).mkdir(parents=True, exist_ok=True)

    (cfg.out_dir / "content" / "source.txt").write_bytes(content_bytes)

    # Load candidates
    candidates: List[Dict[str, Any]] = []
    with cfg.candidates_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            candidates.append(json.loads(line))

    if not candidates:
        return False

    # Pass 1: entities
    entities: Dict[str, str] = {}
    for c in candidates:
        subj = str(c.get("subject", "")).strip()
        if not subj:
            continue
        entities[subj] = recompute_entity_id(cfg.namespace, subj)

        obj_type = c.get("object_type", "entity")
        if obj_type == "entity":
            obj = str(c.get("object", "")).strip()
            if obj:
                entities[obj] = recompute_entity_id(cfg.namespace, obj)

    ent_rows: List[Dict[str, Any]] = []
    for label, eid in entities.items():
        ent_rows.append(
            {
                "entity_id": eid,
                "namespace": cfg.namespace,
                "label": label,
                "entity_type": "concept",
            }
        )

    # Pass 2: claims + evidence + locators + references
    claim_rows: List[Dict[str, Any]] = []
    prov_rows: List[Dict[str, Any]] = []
    span_rows: List[Dict[str, Any]] = []
    locator_rows: List[Dict[str, Any]] = []
    reference_rows: List[Dict[str, Any]] = []
    temporal_rows: List[Dict[str, Any]] = []

    for c in candidates:
        subj_label = str(c.get("subject", "")).strip()
        pred = str(c.get("predicate", "")).strip()
        obj_label_or_val = str(c.get("object", "")).strip()
        evidence = c.get("evidence") or c.get("evidence_quote")

        if not subj_label or not pred or not evidence:
            continue

        obj_type = c.get("object_type", "entity")
        if obj_type not in VALID_OBJECT_TYPES:
            continue

        try:
            tier = int(c.get("tier", 0))
        except Exception:
            tier = 0
        if tier not in VALID_TIERS:
            tier = 0

        subj_id = entities.get(subj_label) or recompute_entity_id(cfg.namespace, subj_label)

        if obj_type == "entity":
            obj_id = entities.get(obj_label_or_val) or recompute_entity_id(cfg.namespace, obj_label_or_val)
            obj_val = obj_id
        else:
            obj_val = obj_label_or_val

        # Evidence span
        try:
            byte_start, byte_end = _find_span_strict(content_bytes, str(evidence))
        except ValueError as e:
            msg = str(e)
            if msg.startswith("Evidence not found"):
                continue
            raise

        cid = recompute_claim_id(subj_id, pred, obj_val, obj_type)

        prov_id = _b32_id("p_", f"{source_hash}\x00{byte_start}\x00{byte_end}")
        span_id = _b32_id("s_", f"{source_hash}\x00{byte_start}\x00{byte_end}\x00{evidence}")

        # Stable evidence address: deterministic from source bytes, survives rebuilds.
        # This is the join key for ext/locators@1.parquet.
        evidence_addr = _b32_id("ea_", f"{source_hash}\x00{byte_start}\x00{byte_end}")

        claim_rows.append(
            {
                "claim_id": cid,
                "subject": subj_id,
                "predicate": pred,
                "object": obj_val,
                "object_type": obj_type,
                "tier": tier,
            }
        )
        prov_rows.append(
            {
                "provenance_id": prov_id,
                "claim_id": cid,
                "source_hash": source_hash,
                "byte_start": byte_start,
                "byte_end": byte_end,
            }
        )
        span_rows.append(
            {
                "span_id": span_id,
                "source_hash": source_hash,
                "byte_start": byte_start,
                "byte_end": byte_end,
                "text": str(evidence),
            }
        )

        # Locator: if the candidate carries structural position, preserve it.
        locator = c.get("locator")
        if locator and isinstance(locator, dict):
            loc_row = {
                "evidence_addr": evidence_addr,
                "span_id": span_id,
                "source_hash": source_hash,
                "kind": str(locator.get("kind", "")),
                "page_index": locator.get("page"),
                "paragraph_index": locator.get("paragraph_index"),
                "block_id": locator.get("block_id", ""),
                "file_path": locator.get("file_path", ""),
            }
            locator_rows.append(loc_row)

        # References: if the candidate links to claims in other shards, preserve it.
        refs = c.get("references")
        if refs and isinstance(refs, list):
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                reference_rows.append({
                    "src_claim_id": cid,
                    "relation_type": str(ref.get("relation_type", "cites")),
                    "dst_shard_id": str(ref.get("dst_shard_id", "")),
                    "dst_object_type": str(ref.get("dst_object_type", "shard")),
                    "dst_object_id": str(ref.get("dst_object_id", "")),
                    "confidence": float(ref.get("confidence", 1.0)),
                    "note": ref.get("note"),
                })

        # Temporal: if the candidate carries validity window, preserve it.
        valid_from = c.get("valid_from", "")
        valid_until = c.get("valid_until", "")
        temporal_context = c.get("temporal_context", "")
        if valid_from or valid_until or temporal_context:
            temporal_rows.append({
                "claim_id": cid,
                "valid_from": str(valid_from) if valid_from else "",
                "valid_until": str(valid_until) if valid_until else "",
                "temporal_context": str(temporal_context) if temporal_context else "",
            })

    if not claim_rows:
        return False

    # Write core tables deterministically (frozen Genesis schema)
    write_parquet_deterministic(cfg.out_dir / "graph" / "entities.parquet", ent_rows, ENTITIES_SCHEMA, "entity_id")
    write_parquet_deterministic(cfg.out_dir / "graph" / "claims.parquet", claim_rows, CLAIMS_SCHEMA, "claim_id")
    write_parquet_deterministic(cfg.out_dir / "graph" / "provenance.parquet", prov_rows, PROVENANCE_SCHEMA, "provenance_id")
    write_parquet_deterministic(cfg.out_dir / "evidence" / "spans.parquet", span_rows, SPANS_SCHEMA, "span_id")

    # Write ext/locators@1.parquet if locator data exists
    if locator_rows:
        _write_locators_extension(cfg.out_dir / "ext" / "locators.parquet", locator_rows)

    # Write ext/references@1.parquet if cross-shard references exist
    if reference_rows:
        _write_references_extension(cfg.out_dir / "ext" / "references.parquet", reference_rows)

    # Write ext/temporal@1.parquet if validity windows exist
    if temporal_rows:
        _write_temporal_extension(cfg.out_dir / "ext" / "temporal.parquet", temporal_rows)

    # Write ext/lineage@1.parquet if this shard supersedes/amends/retracts prior shards
    if cfg.supersedes:
        _write_lineage_extension(
            cfg.out_dir / "ext" / "lineage.parquet",
            supersedes=list(cfg.supersedes),
            action=cfg.lineage_action,
            created_at=cfg.created_at,
            note=cfg.lineage_note,
        )

    # Manifest + signatures — suite-aware
    # If lineage is present we need a two-pass Merkle:
    #   Pass 1: compute Merkle over __PENDING__ lineage → derive shard_id
    #   Backfill: rewrite lineage.parquet with real shard_id
    #   Pass 2: recompute Merkle over final bytes → this is the canonical root
    merkle_root = compute_merkle_root(cfg.out_dir, suite=cfg.suite)
    if cfg.supersedes:
        # Pass 1 root gives us the shard_id for backfill
        pending_shard_id = f"shard_blake3_{merkle_root}"
        backfill_lineage_shard_id(cfg.out_dir, pending_shard_id)
        # Pass 2: recompute over the now-correct lineage bytes
        merkle_root = compute_merkle_root(cfg.out_dir, suite=cfg.suite)

    # Detect active extensions (files in ext/)
    ext_dir = cfg.out_dir / "ext"
    active_extensions = []
    if ext_dir.exists():
        for f in sorted(ext_dir.iterdir()):
            if f.is_file() and not f.name.startswith("."):
                stem = f.stem
                active_extensions.append(f"{stem}@1")

    manifest = {
        "spec_version": "1.0.0",
        "suite": cfg.suite,
        "shard_id": f"shard_blake3_{merkle_root}",
        "created_at": cfg.created_at,
        "metadata": {"title": cfg.source_path.name, "namespace": cfg.namespace},
        "publisher": {"id": cfg.publisher_id, "name": cfg.publisher_name},
        "license": {"spdx": "UNLICENSED", "notes": "Generic build"},
        "sources": [{"path": "content/source.txt", "hash": source_hash}],
        "integrity": {"algorithm": "blake3", "merkle_root": merkle_root},
        "statistics": {"entities": len(ent_rows), "claims": len(claim_rows)},
    }
    if active_extensions:
        manifest["extensions"] = active_extensions
    if cfg.supersedes:
        manifest["supersedes"] = list(cfg.supersedes)

    manifest_bytes = dumps_canonical_json(manifest)
    (cfg.out_dir / "manifest.json").write_bytes(manifest_bytes)

    # Sign with the appropriate suite
    if cfg.suite == SUITE_MLDSA44:
        from .sign import mldsa44_keygen, mldsa44_sign
        # ML-DSA-44: pk is NOT derivable from sk (unlike Ed25519).
        # Convention: pass sk||pk (3840 bytes) or sk-only (2528, fresh keypair).
        if len(cfg.private_key) == 3840:
            # Full keypair blob: sk (2528) || pk (1312)
            sk_bytes = cfg.private_key[:2528]
            pk_bytes = cfg.private_key[2528:]
            sig = mldsa44_sign(sk_bytes, manifest_bytes)
            (cfg.out_dir / "sig" / "publisher.pub").write_bytes(pk_bytes)
            (cfg.out_dir / "sig" / "manifest.sig").write_bytes(sig)
        elif len(cfg.private_key) == 2528:
            # SK only — sign with it, but we need pk from somewhere.
            # Check if publisher.pub already exists (e.g. caller pre-placed it).
            pub_path = cfg.out_dir / "sig" / "publisher.pub"
            if pub_path.exists() and pub_path.stat().st_size == 1312:
                sig = mldsa44_sign(cfg.private_key, manifest_bytes)
                (cfg.out_dir / "sig" / "manifest.sig").write_bytes(sig)
            else:
                # No pk available — generate fresh keypair, discard caller's sk.
                kp = mldsa44_keygen()
                sig = kp.sign(manifest_bytes)
                (cfg.out_dir / "sig" / "publisher.pub").write_bytes(kp.public_key)
                (cfg.out_dir / "sig" / "manifest.sig").write_bytes(sig)
        else:
            # Unknown key size — generate fresh keypair.
            kp = mldsa44_keygen()
            sig = kp.sign(manifest_bytes)
            (cfg.out_dir / "sig" / "publisher.pub").write_bytes(kp.public_key)
            (cfg.out_dir / "sig" / "manifest.sig").write_bytes(sig)
    else:
        # Legacy Ed25519
        sk = signing_key_from_private_key_bytes(cfg.private_key)
        (cfg.out_dir / "sig" / "publisher.pub").write_bytes(bytes(sk.verify_key))
        (cfg.out_dir / "sig" / "manifest.sig").write_bytes(sk.sign(manifest_bytes).signature)

    # Self-verify using the publisher key as trusted anchor.
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write((cfg.out_dir / "sig" / "publisher.pub").read_bytes())
        trusted_path = Path(tf.name)

    try:
        res = verify_shard(cfg.out_dir, trusted_path)
    finally:
        if trusted_path.exists():
            os.unlink(trusted_path)

    return res.get("status") == "PASS"


def _write_locators_extension(path: Path, rows: List[Dict[str, Any]]) -> None:
    """Write ext/locators@1.parquet deterministically.

    Schema (locators@1):
        evidence_addr: string (stable join key = hash of source_hash + byte range)
        span_id: string (link to spans.parquet)
        source_hash: string
        kind: string (pdf, docx, html, txt, pptx, xlsx)
        page_index: int16 nullable
        paragraph_index: int32 nullable
        block_id: string
        file_path: string
    """
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq

        schema = pa.schema([
            ("evidence_addr", pa.string()),
            ("span_id", pa.string()),
            ("source_hash", pa.string()),
            ("kind", pa.string()),
            ("page_index", pa.int16()),
            ("paragraph_index", pa.int32()),
            ("block_id", pa.string()),
            ("file_path", pa.string()),
        ])

        # Sort deterministically by evidence_addr
        rows_sorted = sorted(rows, key=lambda r: r["evidence_addr"])

        arrays = {
            "evidence_addr": pa.array([r["evidence_addr"] for r in rows_sorted], type=pa.string()),
            "span_id": pa.array([r["span_id"] for r in rows_sorted], type=pa.string()),
            "source_hash": pa.array([r["source_hash"] for r in rows_sorted], type=pa.string()),
            "kind": pa.array([r["kind"] for r in rows_sorted], type=pa.string()),
            "page_index": pa.array([r.get("page_index") for r in rows_sorted], type=pa.int16()),
            "paragraph_index": pa.array([r.get("paragraph_index") for r in rows_sorted], type=pa.int32()),
            "block_id": pa.array([r.get("block_id", "") or "" for r in rows_sorted], type=pa.string()),
            "file_path": pa.array([r.get("file_path", "") or "" for r in rows_sorted], type=pa.string()),
        }

        table = pa.table(arrays, schema=schema)
        pq.write_table(table, str(path), compression="zstd")

    except ImportError:
        # Fallback: DuckDB
        import duckdb
        con = duckdb.connect(":memory:")
        rows_sorted = sorted(rows, key=lambda r: r["evidence_addr"])
        con.execute("CREATE TABLE locators (evidence_addr VARCHAR, span_id VARCHAR, source_hash VARCHAR, kind VARCHAR, page_index SMALLINT, paragraph_index INTEGER, block_id VARCHAR, file_path VARCHAR)")
        for r in rows_sorted:
            con.execute(
                "INSERT INTO locators VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [r["evidence_addr"], r["span_id"], r["source_hash"], r["kind"],
                 r.get("page_index"), r.get("paragraph_index"),
                 r.get("block_id", "") or "", r.get("file_path", "") or ""],
            )
        con.execute(f"COPY locators TO '{path}' (FORMAT PARQUET, COMPRESSION ZSTD)")
        con.close()


def _write_references_extension(path: Path, rows: List[Dict[str, Any]]) -> None:
    """Write ext/references@1.parquet deterministically.

    Schema (references@1):
        src_claim_id: string (claim in THIS shard making the reference)
        relation_type: string (supports, contradicts, derives_from, supersedes, cites)
        dst_shard_id: string (target shard ID)
        dst_object_type: string (claim, entity, or shard)
        dst_object_id: string (target claim_id, entity_id, or shard_id)
        confidence: float32 (0.0-1.0)
        note: string nullable
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    import pyarrow as pa
    import pyarrow.parquet as pq

    rows_sorted = sorted(rows, key=lambda r: r["src_claim_id"])

    schema = pa.schema([
        ("src_claim_id", pa.string()),
        ("relation_type", pa.string()),
        ("dst_shard_id", pa.string()),
        ("dst_object_type", pa.string()),
        ("dst_object_id", pa.string()),
        ("confidence", pa.float32()),
        ("note", pa.string()),
    ])

    table = pa.table({
        "src_claim_id": pa.array([r["src_claim_id"] for r in rows_sorted], type=pa.string()),
        "relation_type": pa.array([r["relation_type"] for r in rows_sorted], type=pa.string()),
        "dst_shard_id": pa.array([r["dst_shard_id"] for r in rows_sorted], type=pa.string()),
        "dst_object_type": pa.array([r["dst_object_type"] for r in rows_sorted], type=pa.string()),
        "dst_object_id": pa.array([r["dst_object_id"] for r in rows_sorted], type=pa.string()),
        "confidence": pa.array([r["confidence"] for r in rows_sorted], type=pa.float32()),
        "note": pa.array([r.get("note") for r in rows_sorted], type=pa.string()),
    }, schema=schema)

    pq.write_table(table, str(path), compression="zstd")


def _write_lineage_extension(
    path: Path,
    supersedes: List[str],
    action: str,
    created_at: str,
    note: str = "",
) -> None:
    """Write ext/lineage@1.parquet deterministically.

    One row per superseded shard. The shard_id field is filled in after
    the manifest is written — callers pass the superseded IDs, and the
    'THIS shard' ID is the content-addressed shard_id from the manifest.
    We leave shard_id as a placeholder sentinel here; the caller must
    call _backfill_lineage_shard_id() after the manifest is finalised.

    Schema (lineage@1):
        shard_id:            string — THIS shard (backfilled after manifest)
        supersedes_shard_id: string — the shard being superseded
        action:              string — supersede | amend | retract
        timestamp:           string — ISO 8601
        note:                string — optional context
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    valid_actions = {"supersede", "amend", "retract"}
    if action not in valid_actions:
        raise ValueError(f"lineage_action must be one of {valid_actions}, got {action!r}")

    rows = [
        {
            "shard_id": "__PENDING__",   # backfilled once shard_id is known
            "supersedes_shard_id": sid,
            "action": action,
            "timestamp": created_at,
            "note": note or "",
        }
        for sid in sorted(set(supersedes))   # deterministic, deduplicated
    ]

    import pyarrow as pa
    import pyarrow.parquet as pq

    schema = pa.schema([
        ("shard_id", pa.string()),
        ("supersedes_shard_id", pa.string()),
        ("action", pa.string()),
        ("timestamp", pa.string()),
        ("note", pa.string()),
    ])

    table = pa.table({
        "shard_id":            pa.array([r["shard_id"] for r in rows],            type=pa.string()),
        "supersedes_shard_id": pa.array([r["supersedes_shard_id"] for r in rows], type=pa.string()),
        "action":              pa.array([r["action"] for r in rows],              type=pa.string()),
        "timestamp":           pa.array([r["timestamp"] for r in rows],           type=pa.string()),
        "note":                pa.array([r["note"] for r in rows],                type=pa.string()),
    }, schema=schema)

    pq.write_table(table, str(path), compression="zstd")


def backfill_lineage_shard_id(shard_dir: Path, shard_id: str) -> None:
    """Rewrite ext/lineage@1.parquet with the now-known shard_id.

    Called by compile_generic_shard after the manifest (and therefore the
    content-addressed shard_id) has been finalised. Rewrites the file in
    place with the __PENDING__ sentinel replaced by the real shard_id.
    This preserves determinism: the lineage file changes content when the
    shard_id is known, but the Merkle tree is computed AFTER this call.
    """
    lineage_path = shard_dir / "ext" / "lineage.parquet"
    if not lineage_path.exists():
        return

    import pyarrow.parquet as pq
    import pyarrow as pa

    table = pq.read_table(str(lineage_path))
    df = table.to_pydict()

    df["shard_id"] = [shard_id] * len(df["shard_id"])

    schema = pa.schema([
        ("shard_id", pa.string()),
        ("supersedes_shard_id", pa.string()),
        ("action", pa.string()),
        ("timestamp", pa.string()),
        ("note", pa.string()),
    ])

    new_table = pa.table(df, schema=schema)
    pq.write_table(new_table, str(lineage_path), compression="zstd")


def _write_temporal_extension(path: Path, rows: List[Dict[str, Any]]) -> None:
    """Write ext/temporal@1.parquet deterministically.

    Schema (temporal@1):
        claim_id:         string — joins to claims.parquet
        valid_from:       string — ISO 8601 or empty for "always valid from"
        valid_until:      string — ISO 8601 or empty for "until superseded"
        temporal_context: string — human-readable note (e.g. "effective until FM 21-11 revision")

    Staleness filter in Spectra:
        WHERE (valid_until = '' OR valid_until > CURRENT_TIMESTAMP)
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    # Sort deterministically by claim_id
    rows_sorted = sorted(rows, key=lambda r: r["claim_id"])

    try:
        import pyarrow as pa
        import pyarrow.parquet as pq

        schema = pa.schema([
            ("claim_id",         pa.string()),
            ("valid_from",       pa.string()),
            ("valid_until",      pa.string()),
            ("temporal_context", pa.string()),
        ])

        table = pa.table({
            "claim_id":         pa.array([r["claim_id"]         for r in rows_sorted], type=pa.string()),
            "valid_from":       pa.array([r["valid_from"]       for r in rows_sorted], type=pa.string()),
            "valid_until":      pa.array([r["valid_until"]      for r in rows_sorted], type=pa.string()),
            "temporal_context": pa.array([r["temporal_context"] for r in rows_sorted], type=pa.string()),
        }, schema=schema)

        pq.write_table(table, str(path), compression="zstd")

    except ImportError:
        import duckdb
        con = duckdb.connect(":memory:")
        con.execute("""
            CREATE TABLE temporal (
                claim_id VARCHAR,
                valid_from VARCHAR,
                valid_until VARCHAR,
                temporal_context VARCHAR
            )
        """)
        for r in rows_sorted:
            con.execute(
                "INSERT INTO temporal VALUES (?, ?, ?, ?)",
                [r["claim_id"], r["valid_from"], r["valid_until"], r["temporal_context"]],
            )
        con.execute(f"COPY temporal TO '{path}' (FORMAT PARQUET, COMPRESSION ZSTD)")
        con.close()
