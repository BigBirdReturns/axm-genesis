from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Set

import pyarrow as pa
import pyarrow.parquet as pq

from .const import (
    ErrorCode,
    ENTITIES_SCHEMA, CLAIMS_SCHEMA, PROVENANCE_SCHEMA, SPANS_SCHEMA,
    VALID_OBJECT_TYPES, VALID_TIERS,
    REQUIRED_ROOT_ITEMS, REQUIRED_SIG_FILES, REQUIRED_GRAPH_FILES, REQUIRED_EVIDENCE_FILES,
)
from .identity import recompute_entity_id, recompute_claim_id
from .crypto import compute_merkle_root, verify_manifest_signature

def _err(errors: List[Dict[str, str]], code: ErrorCode, message: str) -> None:
    errors.append({"code": code.value, "message": message})

def _is_hex_64(s: str) -> bool:
    if not isinstance(s, str) or len(s) != 64:
        return False
    try:
        int(s, 16)
        return True
    except Exception:
        return False

def _validate_root_layout(root: Path, errors: List[Dict[str, str]]) -> bool:
    if not root.exists() or not root.is_dir():
        _err(errors, ErrorCode.E_LAYOUT_MISSING, "Shard path does not exist or is not a directory")
        return False

    # Root must contain only manifest.json and the four dirs
    items = {p.name for p in root.iterdir()}
    missing = REQUIRED_ROOT_ITEMS - items
    extra = items - REQUIRED_ROOT_ITEMS
    if missing:
        _err(errors, ErrorCode.E_LAYOUT_MISSING, f"Missing required root items: {sorted(missing)}")
    if extra:
        _err(errors, ErrorCode.E_LAYOUT_DIRTY, f"Unexpected root items present: {sorted(extra)}")
    if missing or extra:
        return False

    # No dotfiles anywhere
    for p in root.rglob("*"):
        if p.name.startswith("."):
            _err(errors, ErrorCode.E_DOTFILE, f"Dotfile found: {p.relative_to(root).as_posix()}")
            return False

    # sig strict
    sig_dir = root / "sig"
    if not sig_dir.is_dir():
        _err(errors, ErrorCode.E_LAYOUT_MISSING, "Missing directory: sig/")
        return False
    sig_items = {p.name for p in sig_dir.iterdir() if p.is_file()}
    missing = REQUIRED_SIG_FILES - sig_items
    extra = sig_items - REQUIRED_SIG_FILES
    if missing:
        _err(errors, ErrorCode.E_LAYOUT_MISSING, f"Missing required sig/ files: {sorted(missing)}")
    if extra:
        _err(errors, ErrorCode.E_LAYOUT_DIRTY, f"Unexpected sig/ items present: {sorted(extra)}")
    if missing or extra:
        return False

    # graph strict
    graph_dir = root / "graph"
    if not graph_dir.is_dir():
        _err(errors, ErrorCode.E_LAYOUT_MISSING, "Missing directory: graph/")
        return False
    graph_items = {p.name for p in graph_dir.iterdir() if p.is_file()}
    missing = REQUIRED_GRAPH_FILES - graph_items
    extra = graph_items - REQUIRED_GRAPH_FILES
    if missing:
        _err(errors, ErrorCode.E_LAYOUT_MISSING, f"Missing required graph/ files: {sorted(missing)}")
    if extra:
        _err(errors, ErrorCode.E_LAYOUT_DIRTY, f"Unexpected graph/ items present: {sorted(extra)}")
    if missing or extra:
        return False

    # evidence strict
    ev_dir = root / "evidence"
    if not ev_dir.is_dir():
        _err(errors, ErrorCode.E_LAYOUT_MISSING, "Missing directory: evidence/")
        return False
    ev_items = {p.name for p in ev_dir.iterdir() if p.is_file()}
    missing = REQUIRED_EVIDENCE_FILES - ev_items
    extra = ev_items - REQUIRED_EVIDENCE_FILES
    if missing:
        _err(errors, ErrorCode.E_LAYOUT_MISSING, f"Missing required evidence/ files: {sorted(missing)}")
    if extra:
        _err(errors, ErrorCode.E_LAYOUT_DIRTY, f"Unexpected evidence/ items present: {sorted(extra)}")
    if missing or extra:
        return False

    # content exists
    content_dir = root / "content"
    if not content_dir.is_dir():
        _err(errors, ErrorCode.E_LAYOUT_MISSING, "Missing directory: content/")
        return False

    return True

def _read_manifest(root: Path, errors: List[Dict[str, str]]) -> Dict[str, Any]:
    mp = root / "manifest.json"
    try:
        data = json.loads(mp.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        _err(errors, ErrorCode.E_MANIFEST_SYNTAX, "Invalid JSON in manifest.json")
        return {}
    except Exception as e:
        _err(errors, ErrorCode.E_MANIFEST_SCHEMA, f"Cannot read manifest.json: {e}")
        return {}

    # Minimal required fields per prompt
    integ = data.get("integrity", {})
    if not isinstance(integ, dict):
        _err(errors, ErrorCode.E_MANIFEST_SCHEMA, "manifest.integrity must be an object")
        return {}
    merkle = integ.get("merkle_root")
    if not _is_hex_64(merkle):
        _err(errors, ErrorCode.E_MANIFEST_SCHEMA, "manifest.integrity.merkle_root must be 64 hex chars")
        return {}

    return data

def _validate_parquet_schema(path: Path, expected: pa.Schema, errors: List[Dict[str, str]]) -> pa.Table | None:
    if not path.exists():
        _err(errors, ErrorCode.E_SCHEMA_MISSING, f"Missing file: {path.name}")
        return None
    try:
        table = pq.read_table(path)
    except Exception as e:
        _err(errors, ErrorCode.E_SCHEMA_READ, f"Cannot read {path.name}: {e}")
        return None

    # Exact order, exact types
    if len(table.schema) != len(expected):
        _err(errors, ErrorCode.E_SCHEMA_TYPE, f"{path.name} column count mismatch")
        return None

    for i, field in enumerate(table.schema):
        exp = expected[i]
        if field.name != exp.name or field.type != exp.type:
            _err(errors, ErrorCode.E_SCHEMA_TYPE, f"{path.name} mismatch at col {i}: expected {exp.name}({exp.type}), got {field.name}({field.type})")
            return None

    # No nulls
    for name in table.column_names:
        if table[name].null_count > 0:
            _err(errors, ErrorCode.E_SCHEMA_NULL, f"{path.name} column {name} contains nulls")
            return None

    return table

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()

def verify_shard(shard_path: str | Path) -> Dict[str, Any]:
    root = Path(shard_path)
    errors: List[Dict[str, str]] = []

    # 1) Layout
    if not _validate_root_layout(root, errors):
        return {"shard": str(shard_path), "status": "FAIL", "error_count": len(errors), "errors": errors}

    # 2) Manifest
    manifest = _read_manifest(root, errors)
    if errors:
        return {"shard": str(shard_path), "status": "FAIL", "error_count": len(errors), "errors": errors}

    # 3) Crypto (signature + merkle)
    manifest_ok = verify_manifest_signature(root / "manifest.json", root / "sig/manifest.sig", root / "sig/publisher.pub")
    if not manifest_ok:
        _err(errors, ErrorCode.E_SIG_INVALID, "Signature verification failed")
        return {"shard": str(shard_path), "status": "FAIL", "error_count": len(errors), "errors": errors}

    computed = compute_merkle_root(root)
    stored = manifest["integrity"]["merkle_root"]
    if computed != stored:
        _err(errors, ErrorCode.E_MERKLE_MISMATCH, f"Merkle root mismatch: computed {computed}, stored {stored}")
        return {"shard": str(shard_path), "status": "FAIL", "error_count": len(errors), "errors": errors}

    # 4) Schema
    ent = _validate_parquet_schema(root / "graph/entities.parquet", ENTITIES_SCHEMA, errors)
    clm = _validate_parquet_schema(root / "graph/claims.parquet", CLAIMS_SCHEMA, errors)
    prv = _validate_parquet_schema(root / "graph/provenance.parquet", PROVENANCE_SCHEMA, errors)
    spn = _validate_parquet_schema(root / "evidence/spans.parquet", SPANS_SCHEMA, errors)
    if errors:
        return {"shard": str(shard_path), "status": "FAIL", "error_count": len(errors), "errors": errors}

    assert ent is not None and clm is not None and prv is not None and spn is not None

    entities = ent.to_pylist()
    claims = clm.to_pylist()
    prov = prv.to_pylist()
    spans = spn.to_pylist()

    # 5) Determinism and enums
    entity_ids: Set[str] = set()
    for row in entities:
        calc = recompute_entity_id(row["namespace"], row["label"])
        if calc != row["entity_id"]:
            _err(errors, ErrorCode.E_ID_ENTITY, f"Entity ID mismatch for label '{row['label']}'")
        entity_ids.add(row["entity_id"])

    claim_ids: Set[str] = set()
    for row in claims:
        if row["object_type"] not in VALID_OBJECT_TYPES:
            _err(errors, ErrorCode.E_SCHEMA_ENUM, f"Invalid object_type: {row['object_type']}")
        if int(row["tier"]) not in VALID_TIERS:
            _err(errors, ErrorCode.E_SCHEMA_ENUM, f"Invalid tier: {row['tier']}")

        calc = recompute_claim_id(row["subject"], row["predicate"], row["object"], row["object_type"])
        if calc != row["claim_id"]:
            _err(errors, ErrorCode.E_ID_CLAIM, f"Claim ID mismatch for claim_id '{row['claim_id']}'")
        claim_ids.add(row["claim_id"])

        # Claim references
        if row["subject"] not in entity_ids:
            _err(errors, ErrorCode.E_REF_ORPHAN, f"Claim subject '{row['subject']}' not found in entities")
        if row["object_type"] == "entity" and row["object"] not in entity_ids:
            _err(errors, ErrorCode.E_REF_ORPHAN, f"Claim object '{row['object']}' not found in entities")

    # 6) Content hashes (SHA-256) and referential integrity
    content_dir = root / "content"
    content_hashes: Set[str] = set()
    content_map: Dict[str, bytes] = {}
    try:
        for p in content_dir.rglob("*"):
            if p.is_file():
                h = _sha256_file(p)
                content_hashes.add(h)
                content_map[h] = p.read_bytes()
    except Exception as e:
        _err(errors, ErrorCode.E_REF_READ, f"Failed reading content files: {e}")

    for row in prov:
        if row["claim_id"] not in claim_ids:
            _err(errors, ErrorCode.E_REF_ORPHAN, f"Provenance claim_id '{row['claim_id']}' not found in claims")
        if row["source_hash"] not in content_hashes:
            _err(errors, ErrorCode.E_REF_SOURCE, f"Provenance source_hash '{row['source_hash']}' not found in content/ (SHA-256)")
            continue
        # Provenance byte range validity
        try:
            b = content_map[row["source_hash"]]
            bs = int(row["byte_start"])
            be = int(row["byte_end"])
            if bs < 0 or be < bs or be > len(b):
                _err(errors, ErrorCode.E_REF_SOURCE, f"Provenance byte range out of bounds for source_hash {row['source_hash']}: {bs}-{be}")
        except Exception as e:
            _err(errors, ErrorCode.E_REF_READ, f"Provenance integrity check failed: {e}")

    for row in spans:
        if row["source_hash"] not in content_hashes:
            _err(errors, ErrorCode.E_REF_SOURCE, f"Span source_hash '{row['source_hash']}' not found in content/ (SHA-256)")
            continue
        # Byte-span integrity check (UTF-8 byte offsets)
        try:
            b = content_map[row["source_hash"]]
            bs = int(row["byte_start"])
            be = int(row["byte_end"])
            if bs < 0 or be < bs or be > len(b):
                _err(errors, ErrorCode.E_REF_SOURCE, f"Span byte range out of bounds for source_hash {row['source_hash']}: {bs}-{be}")
            else:
                slice_bytes = b[bs:be]
                try:
                    slice_text = slice_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    _err(errors, ErrorCode.E_REF_SOURCE, f"Span bytes are not valid UTF-8 for source_hash {row['source_hash']}: {bs}-{be}")
                else:
                    if slice_text != row["text"]:
                        _err(errors, ErrorCode.E_REF_SOURCE, f"Span text mismatch at {bs}-{be} for source_hash {row['source_hash']}")
        except Exception as e:
            _err(errors, ErrorCode.E_REF_READ, f"Span integrity check failed: {e}")

    status = "FAIL" if errors else "PASS"
    return {"shard": str(shard_path), "status": status, "error_count": len(errors), "errors": errors}
