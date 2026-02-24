from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
from typing import Any, Dict, List, Set

try:
    import pyarrow as pa  # type: ignore
    import pyarrow.parquet as pq  # type: ignore
except Exception:
    pa = None  # type: ignore
    pq = None  # type: ignore

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
MAX_PARQUET_ROWS = 100_000
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



def _preflight_parquet_limits(path: Path, errors: List[Dict[str, str]]) -> None:
    """Bounded Parquet sanity check (no full reads).

    This runs *before* Merkle verification so a maliciously large Parquet cannot force
    expensive parsing or memory pressure even when the shard is already invalid.
    """
    try:
        st = path.lstat()
        if st.st_size > MAX_FILE_BYTES:
            _err(errors, ErrorCode.E_LAYOUT_DIRTY, f"Parquet file exceeds size limit: {path.name} ({st.st_size} bytes)")
            return
        pf = pq.ParquetFile(path)
        if pf.metadata is not None and pf.metadata.num_rows > MAX_PARQUET_ROWS:
            _err(errors, ErrorCode.E_LAYOUT_DIRTY, f"Parquet row limit exceeded: {path.name} has {pf.metadata.num_rows} rows (limit {MAX_PARQUET_ROWS})")
    except Exception as e:
        _err(errors, ErrorCode.E_SCHEMA_READ, f"Failed reading Parquet metadata for {path.name}: {e}")

def _validate_root_layout(root: Path, errors: List[Dict[str, str]]) -> bool:
    if not root.exists() or not root.is_dir():
        _err(errors, ErrorCode.E_LAYOUT_MISSING, "Shard path does not exist or is not a directory")
        return False

    for p in root.iterdir():
        if p.is_symlink():
            _err(errors, ErrorCode.E_LAYOUT_DIRTY, f"Symlink not allowed at shard root: {p.name}")
            return False

    items = {p.name for p in root.iterdir()}
    missing = REQUIRED_ROOT_ITEMS - items
    extra = (items - REQUIRED_ROOT_ITEMS) - {"ext"}
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
                _err(errors, ErrorCode.E_LAYOUT_DIRTY, f"Symlink not allowed: {p.relative_to(root).as_posix()}")
                return False
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


def _validate_parquet_schema(path: Path, expected: Any, errors: List[Dict[str, str]]) -> Any | None:
    if not path.exists():
        _err(errors, ErrorCode.E_SCHEMA_MISSING, f"Missing file: {path.name}")
        return None

    if path.stat().st_size > MAX_FILE_BYTES:
        _err(errors, ErrorCode.E_SCHEMA_READ, f"{path.name} exceeds file size limit ({MAX_FILE_BYTES} bytes)")
        return None

    if pa is not None and pq is not None:
        try:
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

    # DuckDB fallback (no pyarrow)
    try:
        import duckdb

        con = duckdb.connect(database=":memory:")
        desc = con.execute(f"DESCRIBE SELECT * FROM read_parquet('{str(path)}')").fetchall()
        # desc rows: (column_name, column_type, null, key, default, extra) in duckdb
        cols = [(r[0], r[1]) for r in desc]

        exp_cols = expected if isinstance(expected, list) else []
        if len(cols) != len(exp_cols):
            _err(errors, ErrorCode.E_SCHEMA_TYPE, f"{path.name} column count mismatch")
            return None

        for i, ((name, typ), (exp_name, exp_typ)) in enumerate(zip(cols, exp_cols)):
            if name != exp_name:
                _err(errors, ErrorCode.E_SCHEMA_TYPE, f"{path.name} mismatch at col {i}: expected {exp_name}, got {name}")
                return None
            # Type comparison is best-effort (DuckDB may use synonyms).
            if exp_typ.upper() not in typ.upper():
                _err(errors, ErrorCode.E_SCHEMA_TYPE, f"{path.name} mismatch at col {i}: expected {exp_typ}, got {typ}")
                return None

        # Null checks
        for name, _typ in cols:
            n_null = con.execute(
                f"SELECT COUNT(*) FROM read_parquet('{str(path)}') WHERE {duckdb.quote_identifier(name)} IS NULL"
            ).fetchone()[0]
            if n_null and n_null > 0:
                _err(errors, ErrorCode.E_SCHEMA_NULL, f"{path.name} column {name} contains nulls")
                return None

        return True
    except Exception as e:
        _err(errors, ErrorCode.E_SCHEMA_READ, f"Cannot read {path.name}: {e}")
        return None



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

    # Determine suite: if manifest has "suite" field, use it. Otherwise legacy ed25519.
    suite = manifest.get("suite", "ed25519")
    if suite not in ("ed25519", "axm-blake3-mldsa44"):
        _err(errors, ErrorCode.E_MANIFEST_SCHEMA, f"Unknown suite: {suite}")
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

    # Validate key size matches suite
    from .crypto import SUITE_SIZES
    expected_pk_size = SUITE_SIZES.get(suite, {}).get("pk")
    if expected_pk_size and len(shard_pub) != expected_pk_size:
        _err(errors, ErrorCode.E_SIG_INVALID,
             f"Publisher key size {len(shard_pub)} doesn't match suite {suite} (expected {expected_pk_size})")
        return {"shard": str(shard_path), "status": "FAIL", "error_count": len(errors), "errors": errors}

    manifest_ok = verify_manifest_signature(manifest_bytes, root / "sig/manifest.sig", trusted_key_path, suite=suite)
    if not manifest_ok:
        _err(errors, ErrorCode.E_SIG_INVALID, "Signature verification failed (trusted key)")
        return {"shard": str(shard_path), "status": "FAIL", "error_count": len(errors), "errors": errors}

    try:
        computed = compute_merkle_root(root, suite=suite)
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
                    _err(errors, ErrorCode.E_LAYOUT_DIRTY, f"Symlink not allowed in content/: {p}")
                    continue
                if not p.is_file():
                    continue

                file_count += 1
                if file_count > MAX_CONTENT_FILES:
                    _err(errors, ErrorCode.E_LAYOUT_DIRTY, f"Too many files in content/ (limit {MAX_CONTENT_FILES})")
                    raise RuntimeError("content file limit exceeded")

                st = p.stat()
                if st.st_size > MAX_FILE_BYTES:
                    _err(errors, ErrorCode.E_LAYOUT_DIRTY, f"Content file too large: {p} ({st.st_size} bytes)")
                    continue

                total_bytes += st.st_size
                if total_bytes > MAX_TOTAL_BYTES:
                    _err(errors, ErrorCode.E_LAYOUT_DIRTY, f"Total content bytes exceeded limit ({MAX_TOTAL_BYTES} bytes)")
                    raise RuntimeError("content byte limit exceeded")

                st = p.stat()
                if st.st_size > MAX_FILE_BYTES:
                    _err(errors, ErrorCode.E_LAYOUT_DIRTY, f"Content file exceeds size limit: {p.relative_to(root).as_posix()} ({st.st_size} bytes)")
                    continue
                h = _sha256_stream(p)
                content_hashes.add(h)
                content_map[h] = p
    except Exception as e:
        _err(errors, ErrorCode.E_LAYOUT_DIRTY, f"Failed reading content files: {e}")

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
