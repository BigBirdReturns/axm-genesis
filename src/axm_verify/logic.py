from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
from typing import Any, Dict, List, Set

import pyarrow as pa
import pyarrow.parquet as pq

from .const import (
    ErrorCode,
    ENTITIES_SCHEMA, CLAIMS_SCHEMA, PROVENANCE_SCHEMA, SPANS_SCHEMA,
    VALID_OBJECT_TYPES, VALID_TIERS,
    REQUIRED_ROOT_ITEMS,
)
from .identity import recompute_entity_id, recompute_claim_id
from .crypto import compute_merkle_root, verify_manifest_signature

# Limits (policy, not protocol)
MAX_MANIFEST_BYTES = 256 * 1024  # 256 KiB
MAX_FILE_BYTES = 512 * 1024 * 1024  # 512 MiB per file
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB total content scanned
MAX_CONTENT_FILES = 10000
MAX_PARQUET_ROWS = 1_000_000
HASH_CHUNK_SIZE = 64 * 1024


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


def _sha256_stream(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(HASH_CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _validate_root_layout(root: Path, errors: List[Dict[str, str]]) -> bool:
    if not root.exists() or not root.is_dir():
        _err(errors, ErrorCode.E_LAYOUT_MISSING, "Shard path does not exist or is not a directory")
        return False

    items = {p.name for p in root.iterdir()}
    missing = REQUIRED_ROOT_ITEMS - items
    extra = items - REQUIRED_ROOT_ITEMS
    if missing:
        _err(errors, ErrorCode.E_LAYOUT_MISSING, f"Missing required root items: {sorted(missing)}")
    if extra:
        _err(errors, ErrorCode.E_LAYOUT_DIRTY, f"Unexpected root items present: {sorted(extra)}")
    if missing or extra:
        return False

    # Dotfiles scan using os.walk (avoid symlink recursion)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dp = Path(dirpath)
        dirnames[:] = [d for d in dirnames if not (dp / d).is_symlink()]

        for name in filenames:
            p = dp / name
            if p.is_symlink():
                continue
            if p.name.startswith("."):
                _err(errors, ErrorCode.E_DOTFILE, f"Dotfile found: {p.relative_to(root).as_posix()}")
                return False

    return True


def _read_manifest(manifest_bytes: bytes, errors: List[Dict[str, str]]) -> Dict[str, Any]:
    try:
        data = json.loads(manifest_bytes)
    except json.JSONDecodeError:
        _err(errors, ErrorCode.E_MANIFEST_SYNTAX, "Invalid JSON in manifest.json")
        return {}
    except Exception as e:
        _err(errors, ErrorCode.E_MANIFEST_SCHEMA, f"Cannot parse manifest.json: {e}")
        return {}

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
        if path.stat().st_size > MAX_FILE_BYTES:
            _err(errors, ErrorCode.E_SCHEMA_READ, f"{path.name} exceeds file size limit ({MAX_FILE_BYTES} bytes)")
            return None

        pf = pq.ParquetFile(path)
        if pf.metadata is not None and pf.metadata.num_rows > MAX_PARQUET_ROWS:
            _err(errors, ErrorCode.E_SCHEMA_READ, f"{path.name} exceeds row limit ({MAX_PARQUET_ROWS})")
            return None

        table = pf.read()
    except Exception as e:
        _err(errors, ErrorCode.E_SCHEMA_READ, f"Cannot read {path.name}: {e}")
        return None

    if len(table.schema) != len(expected):
        _err(errors, ErrorCode.E_SCHEMA_TYPE, f"{path.name} column count mismatch")
        return None

    for i, field in enumerate(table.schema):
        exp = expected[i]
        if field.name != exp.name or field.type != exp.type:
            _err(
                errors,
                ErrorCode.E_SCHEMA_TYPE,
                f"{path.name} mismatch at col {i}: expected {exp.name}({exp.type}), got {field.name}({field.type})",
            )
            return None

    for name in table.column_names:
        if table[name].null_count > 0:
            _err(errors, ErrorCode.E_SCHEMA_NULL, f"{path.name} column {name} contains nulls")
            return None

    return table


def verify_shard(shard_path: str | Path, trusted_key_path: Path, mode: str = "strict") -> Dict[str, Any]:
    root = Path(shard_path)
    errors: List[Dict[str, str]] = []

    # 1) Layout
    if not _validate_root_layout(root, errors):
        return {"shard": str(shard_path), "status": "FAIL", "error_count": len(errors), "errors": errors}

    # 2) Manifest (bounded)
    try:
        manifest_path = root / "manifest.json"
        if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            _err(errors, ErrorCode.E_MANIFEST_SCHEMA, f"manifest.json exceeds size limit ({MAX_MANIFEST_BYTES} bytes)")
            return {"shard": str(shard_path), "status": "FAIL", "error_count": len(errors), "errors": errors}
        manifest_bytes = manifest_path.read_bytes()
    except Exception as e:
        _err(errors, ErrorCode.E_MANIFEST_SCHEMA, f"Cannot read manifest.json: {e}")
        return {"shard": str(shard_path), "status": "FAIL", "error_count": len(errors), "errors": errors}

    manifest = _read_manifest(manifest_bytes, errors)
    if errors:
        return {"shard": str(shard_path), "status": "FAIL", "error_count": len(errors), "errors": errors}

    # 3) Crypto (trusted anchor)
    try:
        trusted_pub = trusted_key_path.read_bytes()
    except Exception as e:
        _err(errors, ErrorCode.E_SIG_INVALID, f"Cannot read trusted key: {e}")
        return {"shard": str(shard_path), "status": "FAIL", "error_count": len(errors), "errors": errors}

    shard_pub_path = root / "sig/publisher.pub"
    try:
        shard_pub = shard_pub_path.read_bytes()
    except Exception as e:
        _err(errors, ErrorCode.E_SIG_INVALID, f"Cannot read shard publisher.pub: {e}")
        return {"shard": str(shard_path), "status": "FAIL", "error_count": len(errors), "errors": errors}

    if shard_pub != trusted_pub:
        _err(errors, ErrorCode.E_SIG_INVALID, "Shard publisher.pub does not match trusted key")
        return {"shard": str(shard_path), "status": "FAIL", "error_count": len(errors), "errors": errors}

    manifest_ok = verify_manifest_signature(manifest_bytes, root / "sig/manifest.sig", trusted_key_path)
    if not manifest_ok:
        _err(errors, ErrorCode.E_SIG_INVALID, "Signature verification failed (trusted key)")
        return {"shard": str(shard_path), "status": "FAIL", "error_count": len(errors), "errors": errors}

    try:
        computed = compute_merkle_root(root)
    except Exception as e:
        _err(errors, ErrorCode.E_LAYOUT_DIRTY, f"Cannot compute Merkle root: {e}")
        return {"shard": str(shard_path), "status": "FAIL", "error_count": len(errors), "errors": errors}
    stored = manifest["integrity"]["merkle_root"]
    if computed != stored:
        _err(errors, ErrorCode.E_MERKLE_MISMATCH, f"Merkle root mismatch: computed {computed}, stored {stored}")
        return {"shard": str(shard_path), "status": "FAIL", "error_count": len(errors), "errors": errors}

    # 4) Schema (bounded via metadata check)
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

    # 5) IDs and references
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

        if row["subject"] not in entity_ids:
            _err(errors, ErrorCode.E_REF_ORPHAN, f"Claim subject '{row['subject']}' not found in entities")
        if row["object_type"] == "entity" and row["object"] not in entity_ids:
            _err(errors, ErrorCode.E_REF_ORPHAN, f"Claim object '{row['object']}' not found in entities")

    # 6) Content hashes and span verification (streaming, bounded)
    content_dir = root / "content"
    content_hashes: Set[str] = set()
    content_map: Dict[str, Path] = {}

    total_bytes = 0
    file_count = 0

    try:
        for dirpath, dirnames, filenames in os.walk(content_dir, followlinks=False):
            dp = Path(dirpath)
            dirnames[:] = [d for d in dirnames if not (dp / d).is_symlink()]

            for name in filenames:
                p = dp / name
                if p.is_symlink():
                    _err(errors, ErrorCode.E_REF_READ, f"Symlink not allowed in content/: {p}")
                    continue
                if not p.is_file():
                    continue

                file_count += 1
                if file_count > MAX_CONTENT_FILES:
                    _err(errors, ErrorCode.E_REF_READ, f"Too many files in content/ (limit {MAX_CONTENT_FILES})")
                    raise RuntimeError("content file limit exceeded")

                st = p.stat()
                if st.st_size > MAX_FILE_BYTES:
                    _err(errors, ErrorCode.E_REF_READ, f"Content file too large: {p} ({st.st_size} bytes)")
                    continue

                total_bytes += st.st_size
                if total_bytes > MAX_TOTAL_BYTES:
                    _err(errors, ErrorCode.E_REF_READ, f"Total content bytes exceeded limit ({MAX_TOTAL_BYTES} bytes)")
                    raise RuntimeError("content byte limit exceeded")

                st = p.stat()
                if st.st_size > MAX_FILE_BYTES:
                    _err(errors, ErrorCode.E_REF_READ, f"Content file exceeds size limit: {p.relative_to(root).as_posix()} ({st.st_size} bytes)")
                    continue
                h = _sha256_stream(p)
                content_hashes.add(h)
                content_map[h] = p
    except Exception as e:
        _err(errors, ErrorCode.E_REF_READ, f"Failed reading content files: {e}")

    for row in prov:
        if row["claim_id"] not in claim_ids:
            _err(errors, ErrorCode.E_REF_ORPHAN, f"Provenance claim_id '{row['claim_id']}' not found in claims")

        if row["source_hash"] not in content_hashes:
            _err(errors, ErrorCode.E_REF_SOURCE, f"Provenance source_hash '{row['source_hash']}' not found in content/")
            continue

        try:
            p = content_map[row["source_hash"]]
            bs = int(row["byte_start"])
            be = int(row["byte_end"])

            fsize = p.stat().st_size
            if bs < 0 or be < bs or be > fsize:
                _err(errors, ErrorCode.E_REF_SOURCE, f"Provenance byte range out of bounds: {bs}-{be}")
        except Exception as e:
            _err(errors, ErrorCode.E_REF_READ, f"Provenance integrity check failed: {e}")

    for row in spans:
        if row["source_hash"] not in content_hashes:
            _err(errors, ErrorCode.E_REF_SOURCE, f"Span source_hash '{row['source_hash']}' not found in content/")
            continue

        try:
            p = content_map[row["source_hash"]]
            bs = int(row["byte_start"])
            be = int(row["byte_end"])

            fsize = p.stat().st_size
            if bs < 0 or be < bs or be > fsize:
                _err(errors, ErrorCode.E_REF_SOURCE, f"Span byte range out of bounds: {bs}-{be}")
                continue

            length = be - bs
            with p.open("rb") as f:
                f.seek(bs)
                slice_bytes = f.read(length)

            try:
                slice_text = slice_bytes.decode("utf-8")
            except UnicodeDecodeError:
                _err(errors, ErrorCode.E_REF_SOURCE, f"Span bytes invalid UTF-8 for {row['source_hash']}")
                continue

            if slice_text != row["text"]:
                _err(errors, ErrorCode.E_REF_SOURCE, f"Span text mismatch for {row['source_hash']}")

        except Exception as e:
            _err(errors, ErrorCode.E_REF_READ, f"Span integrity check failed: {e}")

    status = "FAIL" if errors else "PASS"
    return {"shard": str(shard_path), "status": status, "error_count": len(errors), "errors": errors}
