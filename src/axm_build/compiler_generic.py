"""AXM Genesis v1 — generic shard compiler.

Compiles canonical source text + extracted candidates into a sealed,
signed v1 shard: canonical JSONL tables, single Merkle pass, hybrid
(axm-hybrid1) signature, derived shard identity (never stored).
"""
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

from axm_verify.const import CREATED_AT_RE, SHARD_ID_RE, SPEC_VERSION, SUITE_HYBRID1
from axm_verify.identity import (
    derive_provenance_id,
    derive_span_id,
    recompute_claim_id,
    recompute_entity_id,
)
from axm_verify.logic import verify_shard

from .common import normalize_source_text
from .ext_schemas import EXTENSION_REGISTRY
from .jsonl import canonical_json_bytes, write_table
from .merkle import compute_merkle_root
from .schemas import (
    CLAIMS_SCHEMA,
    ENTITIES_SCHEMA,
    PROVENANCE_SCHEMA,
    SPANS_SCHEMA,
    VALID_OBJECT_TYPES,
    VALID_TIERS,
)
from .sign import HYBRID1_SK_LEN, hybrid1_public_key, hybrid1_sign, manifest_signing_message


@dataclass(frozen=True)
class CompilerConfig:
    source_path: Path
    candidates_path: Path
    out_dir: Path
    private_key: bytes           # 3904-byte hybrid1 secret key blob (see sign.py)
    publisher_id: str
    publisher_name: str
    namespace: str
    created_at: str              # RFC 3339 UTC with Z suffix
    title: str = ""              # defaults to the source file name
    license_spdx: str = "UNLICENSED"
    profiles: Tuple[str, ...] = ()
    supersedes: Tuple[str, ...] = ()  # predecessor shard ids, sh1_ form
    lineage_action: str = "supersede"  # supersede | amend | retract
    lineage_note: str = ""


def _evidence_addr(source_hash: str, byte_start: int, byte_end: int) -> str:
    """Stable evidence address: deterministic from source bytes, survives rebuilds."""
    digest = hashlib.sha256(
        f"{source_hash}\x00{byte_start}\x00{byte_end}".encode("utf-8")
    ).digest()
    return "ea_" + base64.b32encode(digest).decode("ascii").lower().rstrip("=")


def _find_span_strict(content_bytes: bytes, needle: str) -> Tuple[int, int]:
    needle_bytes = needle.encode("utf-8")
    count = content_bytes.count(needle_bytes)
    if count == 0:
        raise ValueError(f"Evidence not found: {needle[:80]!r}")
    if count > 1:
        raise ValueError(f"Ambiguous evidence: found {count} matches for {needle[:40]!r}")
    idx = content_bytes.find(needle_bytes)
    return idx, idx + len(needle_bytes)


def _guard_out_dir_wipe(out_dir: Path) -> None:
    """Refuse to delete an out_dir that is not this compiler's own output.

    Deleting ``out_dir`` is permitted only when it is (a) empty, or (b) a
    single previously-compiled shard: a ``manifest.json`` at its root and no
    nested directory that itself contains a ``manifest.json``. Anything else
    (a shard-pool root, a directory of unrelated files) raises ``ValueError``
    before a single byte is deleted.
    """
    if not any(out_dir.iterdir()):
        return  # empty directory: nothing to lose

    if not (out_dir / "manifest.json").is_file():
        raise ValueError(
            f"Refusing to delete {out_dir}: it is non-empty and has no "
            f"manifest.json at its root, so it is not a previously compiled "
            f"shard. out_dir must be a fresh/empty directory or the single "
            f"shard being recompiled — never a directory containing other "
            f"shards or unrelated files."
        )

    nested = sorted(
        p.parent for p in out_dir.rglob("manifest.json") if p.parent != out_dir
    )
    if nested:
        listing = ", ".join(str(p) for p in nested)
        raise ValueError(
            f"Refusing to delete {out_dir}: it contains nested shard "
            f"manifests ({listing}), so it looks like a directory of shards "
            f"(e.g. a shard-pool root), not the single shard being "
            f"recompiled. out_dir must be a fresh/empty directory or the "
            f"shard being recompiled — never a directory containing other "
            f"shards."
        )


def _dedup_by_pk(rows: List[Dict[str, Any]], pk: str) -> List[Dict[str, Any]]:
    """Drop exact-duplicate rows; refuse two different rows with one PK."""
    seen: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        prev = seen.get(row[pk])
        if prev is None:
            seen[row[pk]] = row
        elif prev != row:
            raise ValueError(f"conflicting rows share primary key {row[pk]!r}")
    return list(seen.values())


def compile_generic_shard(cfg: CompilerConfig) -> bool:
    """Compile a v1 shard from canonical source.txt and candidates.jsonl.

    Invariants:
    - Evidence spans must match bytes in content/source.txt after normalization;
      ambiguous evidence fails the build.
    - All tables are canonical JSONL, reproducible by construction.
    - The manifest carries no shard_id (identity is derived); lineage rows
      name only PREDECESSOR shards, so a single Merkle pass suffices.
    - The compiled shard must pass axm-verify with the publisher key.
    """
    if not cfg.source_path.exists():
        raise FileNotFoundError(f"Source not found: {cfg.source_path}")
    if not cfg.candidates_path.exists():
        raise FileNotFoundError(f"Candidates not found: {cfg.candidates_path}")
    if len(cfg.private_key) != HYBRID1_SK_LEN:
        raise ValueError(
            f"private_key must be a {HYBRID1_SK_LEN}-byte hybrid1 secret key blob, "
            f"got {len(cfg.private_key)} bytes (generate one with `axm-build keygen`)"
        )
    if not CREATED_AT_RE.match(cfg.created_at):
        raise ValueError(
            f"created_at must be RFC 3339 UTC with Z suffix, got {cfg.created_at!r}"
        )
    for sid in cfg.supersedes:
        if not SHARD_ID_RE.match(sid):
            raise ValueError(f"supersedes id is not in sh1_ form: {sid!r}")
    if cfg.lineage_action not in {"supersede", "amend", "retract"}:
        raise ValueError(f"lineage_action must be supersede|amend|retract, got {cfg.lineage_action!r}")

    raw_text = cfg.source_path.read_text(encoding="utf-8", errors="strict")
    norm_text = normalize_source_text(raw_text)
    content_bytes = norm_text.encode("utf-8")
    source_hash = hashlib.sha256(content_bytes).hexdigest()

    # Fresh output directory. Guarded: wiping is legal only for an empty
    # directory or the single shard being recompiled — never a directory
    # holding other shards (e.g. a shard-pool root).
    if cfg.out_dir.exists():
        _guard_out_dir_wipe(cfg.out_dir)
        shutil.rmtree(cfg.out_dir)
    for d in ("content", "graph", "evidence", "sig"):
        (cfg.out_dir / d).mkdir(parents=True, exist_ok=True)
    (cfg.out_dir / "content" / "source.txt").write_bytes(content_bytes)

    # Load candidates
    candidates: List[Dict[str, Any]] = []
    with cfg.candidates_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
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
        if c.get("object_type", "entity") == "entity":
            obj = str(c.get("object", "")).strip()
            if obj:
                entities[obj] = recompute_entity_id(cfg.namespace, obj)

    ent_rows = [
        {"entity_id": eid, "namespace": cfg.namespace, "label": label, "entity_type": "concept"}
        for label, eid in entities.items()
    ]

    # Pass 2: claims + evidence + extensions
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
        except (TypeError, ValueError):
            tier = 0
        if tier not in VALID_TIERS:
            tier = 0

        subj_id = entities.get(subj_label) or recompute_entity_id(cfg.namespace, subj_label)
        if obj_type == "entity":
            obj_val = entities.get(obj_label_or_val) or recompute_entity_id(cfg.namespace, obj_label_or_val)
        else:
            obj_val = obj_label_or_val

        try:
            byte_start, byte_end = _find_span_strict(content_bytes, str(evidence))
        except ValueError as e:
            if str(e).startswith("Evidence not found"):
                continue
            raise

        cid = recompute_claim_id(subj_id, pred, obj_val, obj_type)
        prov_id = derive_provenance_id(cid, source_hash, byte_start, byte_end)
        span_id = derive_span_id(source_hash, byte_start, byte_end, str(evidence))
        evidence_addr = _evidence_addr(source_hash, byte_start, byte_end)

        claim_rows.append({
            "claim_id": cid,
            "subject": subj_id,
            "predicate": pred,
            "object": obj_val,
            "object_type": obj_type,
            "tier": tier,
        })
        prov_rows.append({
            "provenance_id": prov_id,
            "claim_id": cid,
            "source_hash": source_hash,
            "byte_start": byte_start,
            "byte_end": byte_end,
        })
        span_rows.append({
            "span_id": span_id,
            "source_hash": source_hash,
            "byte_start": byte_start,
            "byte_end": byte_end,
            "text": str(evidence),
        })

        locator = c.get("locator")
        if isinstance(locator, dict):
            locator_rows.append({
                "evidence_addr": evidence_addr,
                "span_id": span_id,
                "source_hash": source_hash,
                "kind": str(locator.get("kind", "")),
                "page_index": _opt_int_str(locator.get("page")),
                "paragraph_index": _opt_int_str(locator.get("paragraph_index")),
                "block_id": str(locator.get("block_id") or ""),
                "file_path": str(locator.get("file_path") or ""),
            })

        refs = c.get("references")
        if isinstance(refs, list):
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                dst = str(ref.get("dst_shard_id", ""))
                if not SHARD_ID_RE.match(dst):
                    raise ValueError(f"reference dst_shard_id is not in sh1_ form: {dst!r}")
                reference_rows.append({
                    "src_claim_id": cid,
                    "relation_type": str(ref.get("relation_type", "cites")),
                    "dst_shard_id": dst,
                    "dst_object_type": str(ref.get("dst_object_type", "shard")),
                    "dst_object_id": str(ref.get("dst_object_id", "")),
                    "confidence": str(ref.get("confidence", "1.0")),
                    "note": str(ref.get("note") or ""),
                })

        valid_from = c.get("valid_from", "")
        valid_until = c.get("valid_until", "")
        temporal_context = c.get("temporal_context", "")
        if valid_from or valid_until or temporal_context:
            temporal_rows.append({
                "claim_id": cid,
                "valid_from": str(valid_from or ""),
                "valid_until": str(valid_until or ""),
                "temporal_context": str(temporal_context or ""),
            })

    if not claim_rows:
        return False

    claim_rows = _dedup_by_pk(claim_rows, "claim_id")
    prov_rows = _dedup_by_pk(prov_rows, "provenance_id")
    span_rows = _dedup_by_pk(span_rows, "span_id")

    # Core tables — canonical JSONL, sorted, duplicate-free
    write_table(cfg.out_dir / "graph" / "entities.jsonl", ent_rows, ENTITIES_SCHEMA, "entity_id")
    write_table(cfg.out_dir / "graph" / "claims.jsonl", claim_rows, CLAIMS_SCHEMA, "claim_id")
    write_table(cfg.out_dir / "graph" / "provenance.jsonl", prov_rows, PROVENANCE_SCHEMA, "provenance_id")
    write_table(cfg.out_dir / "evidence" / "spans.jsonl", span_rows, SPANS_SCHEMA, "span_id")

    # Lineage: one row per PREDECESSOR (no self-id column — a shard's own id
    # is the hash of its manifest and cannot appear in its own files).
    lineage_rows = [
        {
            "supersedes_shard_id": sid,
            "action": cfg.lineage_action,
            "timestamp": cfg.created_at,
            "note": cfg.lineage_note,
        }
        for sid in sorted(set(cfg.supersedes))
    ]

    ext_tables = {
        "locators@1": _dedup_rows(locator_rows),
        "references@1": _dedup_rows(reference_rows),
        "temporal@1": _dedup_by_pk(temporal_rows, "claim_id"),
        "lineage@1": lineage_rows,
    }
    active_extensions: List[str] = []
    for ext_id, rows in ext_tables.items():
        if not rows:
            continue
        reg = EXTENSION_REGISTRY[ext_id]
        write_table(cfg.out_dir / "ext" / reg["file"], rows, reg["schema"],
                    reg["sort_key"], unique=ext_id in ("temporal@1", "lineage@1"))
        active_extensions.append(ext_id)

    # Single Merkle pass (lineage never needs backfill)
    merkle_root = compute_merkle_root(cfg.out_dir)

    manifest: Dict[str, Any] = {
        "spec_version": SPEC_VERSION,
        "suite": SUITE_HYBRID1,
        "metadata": {
            "title": cfg.title or cfg.source_path.name,
            "namespace": cfg.namespace,
            "created_at": cfg.created_at,
        },
        "publisher": {"id": cfg.publisher_id, "name": cfg.publisher_name},
        "license": {"spdx": cfg.license_spdx},
        "sources": [{"path": "content/source.txt", "hash": source_hash}],
        "integrity": {"algorithm": "blake3", "merkle_root": merkle_root},
        "statistics": {"entities": len(ent_rows), "claims": len(claim_rows)},
    }
    if active_extensions:
        manifest["extensions"] = sorted(active_extensions)
    if cfg.profiles:
        manifest["profiles"] = list(cfg.profiles)
    if cfg.supersedes:
        manifest["supersedes"] = sorted(set(cfg.supersedes))

    manifest_bytes = canonical_json_bytes(manifest)
    (cfg.out_dir / "manifest.json").write_bytes(manifest_bytes)

    # Hybrid signature over the domain-separated message
    public_key = hybrid1_public_key(cfg.private_key)
    signature = hybrid1_sign(cfg.private_key, manifest_signing_message(manifest_bytes))
    (cfg.out_dir / "sig" / "publisher.pub").write_bytes(public_key)
    (cfg.out_dir / "sig" / "manifest.sig").write_bytes(signature)

    # Self-verify using the publisher key as trusted anchor.
    fd, trusted_path = tempfile.mkstemp(suffix=".pub")
    try:
        with os.fdopen(fd, "wb") as tf:
            tf.write(public_key)
        res = verify_shard(cfg.out_dir, Path(trusted_path))
    finally:
        os.unlink(trusted_path)

    return res.get("status") == "PASS"


def _opt_int_str(v: Any) -> str:
    """Encode an optional integer as a decimal string, '' when unknown."""
    if v is None or v == "":
        return ""
    return str(int(v))


def _dedup_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop exact-duplicate rows, preserving first occurrence."""
    seen = set()
    out: List[Dict[str, Any]] = []
    for row in rows:
        key = canonical_json_bytes(row)
        if key not in seen:
            seen.add(key)
            out.append(row)
    return out
