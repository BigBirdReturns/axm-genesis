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
from .sign import signing_key_from_private_key_bytes


@dataclass(frozen=True)
class CompilerConfig:
    source_path: Path
    candidates_path: Path
    out_dir: Path
    private_key: bytes
    publisher_id: str
    publisher_name: str
    namespace: str
    created_at: str


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
    for d in ("content", "graph", "evidence", "sig"):
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
    
    # Pass 2: claims + evidence
    claim_rows: List[Dict[str, Any]] = []
    prov_rows: List[Dict[str, Any]] = []
    span_rows: List[Dict[str, Any]] = []
    
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
    
    if not claim_rows:
        return False
    
    # Write tables deterministically
    write_parquet_deterministic(cfg.out_dir / "graph" / "entities.parquet", ent_rows, ENTITIES_SCHEMA, "entity_id")
    write_parquet_deterministic(cfg.out_dir / "graph" / "claims.parquet", claim_rows, CLAIMS_SCHEMA, "claim_id")
    write_parquet_deterministic(cfg.out_dir / "graph" / "provenance.parquet", prov_rows, PROVENANCE_SCHEMA, "provenance_id")
    write_parquet_deterministic(cfg.out_dir / "evidence" / "spans.parquet", span_rows, SPANS_SCHEMA, "span_id")
    
    # Manifest + signatures
    merkle_root = compute_merkle_root(cfg.out_dir)
    manifest = {
        "spec_version": "1.0.0",
        "shard_id": f"shard_blake3_{merkle_root}",
        "created_at": cfg.created_at,
        "metadata": {"title": cfg.source_path.name, "namespace": cfg.namespace},
        "publisher": {"id": cfg.publisher_id, "name": cfg.publisher_name},
        "license": {"spdx": "UNLICENSED", "notes": "Generic build"},
        "sources": [{"path": "content/source.txt", "hash": source_hash}],
        "integrity": {"algorithm": "blake3", "merkle_root": merkle_root},
        "statistics": {"entities": len(ent_rows), "claims": len(claim_rows)},
    }
    
    manifest_bytes = dumps_canonical_json(manifest)
    (cfg.out_dir / "manifest.json").write_bytes(manifest_bytes)
    
    sk = signing_key_from_private_key_bytes(cfg.private_key)
    (cfg.out_dir / "sig" / "publisher.pub").write_bytes(bytes(sk.verify_key))
    (cfg.out_dir / "sig" / "manifest.sig").write_bytes(sk.sign(manifest_bytes).signature)
    
    # Verify using the publisher key as trusted anchor for this build.
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(bytes(sk.verify_key))
        trusted_path = Path(tf.name)
    
    try:
        res = verify_shard(cfg.out_dir, trusted_path)
    finally:
        if trusted_path.exists():
            os.unlink(trusted_path)
    
    return res.get("status") == "PASS"
