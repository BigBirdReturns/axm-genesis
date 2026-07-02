"""AXM Genesis v1 — reference kernel verifier (spec section 13).

Verification is deliberately stdlib-only on the parse path: UTF-8, json,
hashlib (SHA-256), plus blake3/pynacl/an ML-DSA-44 backend for the
cryptography. No Parquet, no Arrow, no DuckDB — a stranded implementer can
rebuild this from the spec alone.

The reference verifier performs the stages in spec order and stops at the
first failing stage (a single run reports the errors of one stage).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .const import (
    CLAIM_ID_RE,
    CORE_TABLES,
    CREATED_AT_RE,
    ENTITY_ID_RE,
    ErrorCode,
    EXTENSION_ID_RE,
    HEX64_RE,
    HYBRID1_PK_LEN,
    HYBRID1_SIG_LEN,
    MANIFEST_TOP_KEYS,
    MAX_JSON_INT,
    OPTIONAL_ROOT_ITEMS,
    PROFILE_ID_RE,
    PROVENANCE_ID_RE,
    REQUIRED_EVIDENCE_FILES,
    REQUIRED_GRAPH_FILES,
    REQUIRED_ROOT_ITEMS,
    REQUIRED_SIG_FILES,
    SHARD_ID_RE,
    SPAN_ID_RE,
    SPEC_VERSION,
    SUITE_HYBRID1,
    VALID_OBJECT_TYPES,
    VALID_TIERS,
)
from .crypto import compute_merkle_root, verify_manifest_signature
from .identity import recompute_claim_id, recompute_entity_id
from .profiles import IMPLEMENTED_PROFILES

# Limits (implementation policy, not protocol)
MAX_MANIFEST_BYTES = 256 * 1024  # 256 KiB
MAX_FILE_BYTES = 512 * 1024 * 1024  # 512 MiB per file
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB total content scanned
MAX_CONTENT_FILES = 10_000
MAX_TABLE_BYTES = 512 * 1024 * 1024  # 512 MiB per core table
HASH_CHUNK_SIZE = 64 * 1024

_ID_RES = {
    "entity_id": ENTITY_ID_RE,
    "claim_id": CLAIM_ID_RE,
    "provenance_id": PROVENANCE_ID_RE,
    "span_id": SPAN_ID_RE,
}


def _err(errors: List[Dict[str, str]], code: ErrorCode, message: str) -> None:
    errors.append({"code": code.value, "message": message})


def _canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _is_hex64(v: Any) -> bool:
    return isinstance(v, str) and bool(HEX64_RE.match(v))


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _sha256_stream(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(HASH_CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ── Stage 1: layout ──────────────────────────────────────────────────────────

def _validate_layout(root: Path, errors: List[Dict[str, str]]) -> None:
    items = {p.name: p for p in root.iterdir()}

    missing = REQUIRED_ROOT_ITEMS - set(items)
    if missing:
        _err(errors, ErrorCode.E_LAYOUT_MISSING, f"Missing required root items: {sorted(missing)}")
    extra = set(items) - REQUIRED_ROOT_ITEMS - OPTIONAL_ROOT_ITEMS
    for name in sorted(extra):
        if name.startswith("."):
            _err(errors, ErrorCode.E_DOTFILE, f"Dotfile found: {name}")
        else:
            _err(errors, ErrorCode.E_LAYOUT_DIRTY, f"Unexpected root item: {name}")

    # Whole-tree symlink and dotfile scan
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dp = Path(dirpath)
        for d in list(dirnames):
            p = dp / d
            if p.is_symlink():
                _err(errors, ErrorCode.E_LAYOUT_DIRTY,
                     f"Symlink not allowed: {p.relative_to(root).as_posix()}")
                dirnames.remove(d)
            elif d.startswith(".") and p != root:
                _err(errors, ErrorCode.E_DOTFILE,
                     f"Dotfile found: {p.relative_to(root).as_posix()}")
        for name in filenames:
            p = dp / name
            if p.is_symlink():
                _err(errors, ErrorCode.E_LAYOUT_DIRTY,
                     f"Symlink not allowed: {p.relative_to(root).as_posix()}")
            elif name.startswith("."):
                _err(errors, ErrorCode.E_DOTFILE,
                     f"Dotfile found: {p.relative_to(root).as_posix()}")

    if errors:
        return

    # sig/: exactly manifest.sig and publisher.pub
    sig_dir = root / "sig"
    if not sig_dir.is_dir():
        _err(errors, ErrorCode.E_LAYOUT_MISSING, "sig is not a directory")
    else:
        sig_items = {p.name for p in sig_dir.iterdir()}
        for name in sorted(REQUIRED_SIG_FILES - sig_items):
            _err(errors, ErrorCode.E_SIG_MISSING, f"Missing sig/{name}")
        for name in sorted(sig_items - REQUIRED_SIG_FILES):
            _err(errors, ErrorCode.E_LAYOUT_DIRTY, f"Unexpected item in sig/: {name}")

    # graph/ and evidence/: exactly the required table files
    for dirname, required in (("graph", REQUIRED_GRAPH_FILES), ("evidence", REQUIRED_EVIDENCE_FILES)):
        d = root / dirname
        if not d.is_dir():
            _err(errors, ErrorCode.E_LAYOUT_MISSING, f"{dirname} is not a directory")
            continue
        present = {p.name for p in d.iterdir()}
        for name in sorted(required - present):
            _err(errors, ErrorCode.E_SCHEMA_MISSING, f"Missing table file: {dirname}/{name}")
        for name in sorted(present - required):
            _err(errors, ErrorCode.E_LAYOUT_DIRTY, f"Unexpected item in {dirname}/: {name}")

    # content/: at least one regular file
    content_dir = root / "content"
    if not content_dir.is_dir():
        _err(errors, ErrorCode.E_LAYOUT_MISSING, "content is not a directory")
    elif not any(p.is_file() for p in content_dir.rglob("*")):
        _err(errors, ErrorCode.E_LAYOUT_MISSING, "content/ contains no regular files")

    if (root / "manifest.json").is_dir():
        _err(errors, ErrorCode.E_LAYOUT_MISSING, "manifest.json is not a regular file")


# ── Stage 2: manifest ────────────────────────────────────────────────────────

def _valid_source_path(path: str) -> bool:
    if not path.startswith("content/") or "\x00" in path or "\\" in path:
        return False
    segments = path.split("/")
    return all(seg not in ("", ".", "..") for seg in segments)


class _FloatForbidden(ValueError):
    """A float or NaN/Infinity literal appeared in a kernel-defined document."""


def _no_floats(_: str) -> Any:
    raise _FloatForbidden("floats are not permitted in kernel-defined documents")


def _loads_strict(raw: bytes | str) -> Any:
    """json.loads that rejects floats and NaN/Infinity (spec section 5)."""
    return json.loads(raw, parse_float=_no_floats, parse_constant=_no_floats)


def _validate_manifest(manifest_bytes: bytes, errors: List[Dict[str, str]],
                       ext_dir_nonempty: bool) -> Dict[str, Any]:
    try:
        data = _loads_strict(manifest_bytes)
    except _FloatForbidden:
        _err(errors, ErrorCode.E_MANIFEST_SCHEMA, "manifest.json contains a float literal")
        return {}
    except (json.JSONDecodeError, UnicodeDecodeError):
        _err(errors, ErrorCode.E_MANIFEST_SYNTAX, "manifest.json is not valid JSON")
        return {}

    if not isinstance(data, dict):
        _err(errors, ErrorCode.E_MANIFEST_SCHEMA, "manifest must be a JSON object")
        return {}

    # Canonical-encoding byte check: re-encode and compare (spec section 6)
    try:
        reencoded = _canonical_bytes(data)
    except (TypeError, ValueError):
        reencoded = None
    if reencoded != manifest_bytes:
        _err(errors, ErrorCode.E_MANIFEST_SCHEMA,
             "manifest.json is not in canonical JSON encoding")
        return {}

    def bad(field: str, why: str) -> None:
        _err(errors, ErrorCode.E_MANIFEST_SCHEMA, f"manifest.{field} {why}")

    # Closed top-level key set; shard_id explicitly forbidden
    if "shard_id" in data:
        bad("shard_id", "is forbidden: shard identity is derived from the manifest hash")
    for key in sorted(set(data) - MANIFEST_TOP_KEYS - {"shard_id"}):
        bad(key, "is not a recognized manifest key (the top-level key set is closed)")

    if data.get("spec_version") != SPEC_VERSION:
        bad("spec_version", f'must equal "{SPEC_VERSION}", got {data.get("spec_version")!r}')
    if data.get("suite") != SUITE_HYBRID1:
        bad("suite", f'must equal "{SUITE_HYBRID1}", got {data.get("suite")!r}')

    def nonempty_str(v: Any) -> bool:
        return isinstance(v, str) and len(v) > 0

    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        bad("metadata", "must be an object")
    else:
        for f in ("title", "namespace"):
            if not nonempty_str(metadata.get(f)):
                bad(f"metadata.{f}", "must be a non-empty string")
        created_at = metadata.get("created_at")
        if not isinstance(created_at, str) or not _valid_created_at(created_at):
            bad("metadata.created_at",
                "must be an RFC 3339 UTC date-time with the Z designator "
                f"(e.g. 2026-07-02T00:00:00Z), got {created_at!r}")

    publisher = data.get("publisher")
    if not isinstance(publisher, dict):
        bad("publisher", "must be an object")
    else:
        for f in ("id", "name"):
            if not nonempty_str(publisher.get(f)):
                bad(f"publisher.{f}", "must be a non-empty string")

    lic = data.get("license")
    if not isinstance(lic, dict) or not nonempty_str(lic.get("spdx")):
        bad("license.spdx", "must be a non-empty string (an SPDX license expression)")

    sources = data.get("sources")
    if not isinstance(sources, list) or not sources:
        bad("sources", "must be a non-empty array")
    else:
        seen_paths: Set[str] = set()
        for i, src in enumerate(sources):
            if not isinstance(src, dict) or set(src) != {"path", "hash"}:
                bad(f"sources[{i}]", 'must be an object with exactly the keys "path" and "hash"')
                continue
            path = src["path"]
            if not isinstance(path, str) or not _valid_source_path(path):
                bad(f"sources[{i}].path",
                    'must be a clean POSIX relative path beginning with "content/"')
            elif path in seen_paths:
                bad(f"sources[{i}].path", f"is listed twice: {path}")
            else:
                seen_paths.add(path)
            if not _is_hex64(src["hash"]):
                bad(f"sources[{i}].hash", "must be exactly 64 lowercase hex characters")

    integ = data.get("integrity")
    if not isinstance(integ, dict) or set(integ) != {"algorithm", "merkle_root"}:
        bad("integrity", 'must be an object with exactly the keys "algorithm" and "merkle_root"')
    else:
        if integ["algorithm"] != "blake3":
            bad("integrity.algorithm", 'must equal "blake3"')
        if not _is_hex64(integ["merkle_root"]):
            bad("integrity.merkle_root", "must be exactly 64 lowercase hex characters")

    stats = data.get("statistics")
    if not isinstance(stats, dict) or set(stats) != {"entities", "claims"}:
        bad("statistics", 'must be an object with exactly the keys "entities" and "claims"')
    else:
        for f in ("entities", "claims"):
            v = stats[f]
            if not _is_int(v) or v < 0 or v > MAX_JSON_INT:
                bad(f"statistics.{f}", "must be a non-negative integer")

    # Optional fields
    for field, regex in (("profiles", PROFILE_ID_RE), ("supersedes", SHARD_ID_RE)):
        if field in data:
            v = data[field]
            if not isinstance(v, list) or not v:
                bad(field, "must be a non-empty array when present")
            else:
                if len(set(map(str, v))) != len(v):
                    bad(field, "must not contain duplicates")
                for i, item in enumerate(v):
                    if not isinstance(item, str) or not regex.match(item):
                        bad(f"{field}[{i}]", f"does not match the required grammar: {item!r}")

    if "extensions" in data:
        v = data["extensions"]
        if not isinstance(v, list) or not v:
            bad("extensions", "must be a non-empty array when present")
        else:
            for i, item in enumerate(v):
                if not isinstance(item, str) or not EXTENSION_ID_RE.match(item):
                    bad(f"extensions[{i}]", f"does not match the required grammar: {item!r}")
        if not ext_dir_nonempty:
            bad("extensions", "must be absent when ext/ is empty or absent")
    elif ext_dir_nonempty:
        bad("extensions", "must be present and list the extension identifiers when ext/ is non-empty")

    return {} if errors else data


def _valid_created_at(v: str) -> bool:
    """RFC 3339 date-time, UTC, Z designator (numeric offsets rejected).

    RFC 3339 permits a leap second (:60); fractional seconds are allowed
    by the grammar but NOT RECOMMENDED.
    """
    m = CREATED_AT_RE.match(v)
    if not m:
        return False
    year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
    if not (1 <= year and 1 <= month <= 12 and hour <= 23 and minute <= 59 and second <= 60):
        return False
    import calendar
    return 1 <= day <= calendar.monthrange(year, month)[1]


# ── Stage 5: sources bijection ───────────────────────────────────────────────

def _walk_content_files(content_dir: Path, errors: List[Dict[str, str]]) -> Optional[Dict[str, Path]]:
    """Map POSIX relpath (from shard root, 'content/...') -> Path."""
    out: Dict[str, Path] = {}
    total_bytes = 0
    root = content_dir.parent
    for dirpath, dirnames, filenames in os.walk(content_dir, followlinks=False):
        dp = Path(dirpath)
        dirnames[:] = [d for d in dirnames if not (dp / d).is_symlink()]
        for name in filenames:
            p = dp / name
            if p.is_symlink() or not p.is_file():
                continue
            if len(out) + 1 > MAX_CONTENT_FILES:
                _err(errors, ErrorCode.E_LAYOUT_DIRTY,
                     f"Too many files in content/ (limit {MAX_CONTENT_FILES})")
                return None
            st = p.stat()
            if st.st_size > MAX_FILE_BYTES:
                _err(errors, ErrorCode.E_LAYOUT_DIRTY,
                     f"Content file too large: {p.name} ({st.st_size} bytes)")
                return None
            total_bytes += st.st_size
            if total_bytes > MAX_TOTAL_BYTES:
                _err(errors, ErrorCode.E_LAYOUT_DIRTY,
                     f"Total content bytes exceeded limit ({MAX_TOTAL_BYTES})")
                return None
            out[p.relative_to(root).as_posix()] = p
    return out


def _validate_sources_bijection(
    manifest: Dict[str, Any],
    content_files: Dict[str, Path],
    errors: List[Dict[str, str]],
) -> Dict[str, Path]:
    """Check sources <-> content/ bijection. Returns hash -> Path map."""
    hash_map: Dict[str, Path] = {}
    declared: Dict[str, str] = {s["path"]: s["hash"] for s in manifest["sources"]}

    for path, declared_hash in declared.items():
        p = content_files.get(path)
        if p is None:
            _err(errors, ErrorCode.E_MANIFEST_SCHEMA,
                 f"sources lists {path} but no such file exists in the shard")
            continue
        try:
            actual = _sha256_stream(p)
        except OSError as e:
            _err(errors, ErrorCode.E_REF_READ, f"Cannot hash {path}: {e}")
            continue
        if actual != declared_hash:
            _err(errors, ErrorCode.E_MANIFEST_SCHEMA,
                 f"sources hash mismatch for {path}: declared {declared_hash}, actual {actual}")
        else:
            hash_map[actual] = p

    for path in sorted(set(content_files) - set(declared)):
        _err(errors, ErrorCode.E_MANIFEST_SCHEMA,
             f"file {path} exists in the shard but is not listed in sources")

    return hash_map


# ── Stage 6: core tables ─────────────────────────────────────────────────────

def _validate_table(
    path: Path,
    relpath: str,
    schema: Dict[str, str],
    pk: str,
    errors: List[Dict[str, str]],
) -> Optional[List[Dict[str, Any]]]:
    """Parse and validate one canonical JSONL core table (spec section 11).

    Returns the rows, or None if the file could not be validated at all.
    Uses only stdlib json — independent of any producer library.
    """
    if path.stat().st_size > MAX_TABLE_BYTES:
        _err(errors, ErrorCode.E_SCHEMA_READ,
             f"{relpath} exceeds file size limit ({MAX_TABLE_BYTES} bytes)")
        return None
    try:
        raw = path.read_bytes()
    except OSError as e:
        _err(errors, ErrorCode.E_SCHEMA_READ, f"Cannot read {relpath}: {e}")
        return None

    if raw == b"":
        return []  # a table with zero rows is a zero-byte file

    if not raw.endswith(b"\n"):
        _err(errors, ErrorCode.E_SCHEMA_READ, f"{relpath} does not end with a newline")
        return None

    rows: List[Dict[str, Any]] = []
    prev_pk: Optional[bytes] = None
    key_set = set(schema)

    for lineno, line in enumerate(raw.split(b"\n")[:-1], start=1):
        where = f"{relpath}:{lineno}"
        try:
            record = _loads_strict(line)
        except _FloatForbidden:
            _err(errors, ErrorCode.E_SCHEMA_READ, f"{where}: line contains a float literal")
            return rows
        except (json.JSONDecodeError, UnicodeDecodeError):
            _err(errors, ErrorCode.E_SCHEMA_READ, f"{where}: line is not valid JSON")
            return rows
        if not isinstance(record, dict):
            _err(errors, ErrorCode.E_SCHEMA_READ, f"{where}: line is not a JSON object")
            return rows
        try:
            canonical = _canonical_bytes(record)
        except (TypeError, ValueError):
            canonical = None
        if canonical != line:
            _err(errors, ErrorCode.E_SCHEMA_READ, f"{where}: line is not in canonical encoding")
            return rows

        # Exact key set, no nulls, exact JSON types
        row_ok = True
        for key in sorted(set(record) - key_set):
            _err(errors, ErrorCode.E_SCHEMA_TYPE, f"{where}: unexpected key {key!r}")
            row_ok = False
        for key, typ in schema.items():
            if key not in record or record[key] is None:
                _err(errors, ErrorCode.E_SCHEMA_NULL, f"{where}: missing or null field {key!r}")
                row_ok = False
                continue
            v = record[key]
            if typ == "string":
                if not isinstance(v, str):
                    _err(errors, ErrorCode.E_SCHEMA_TYPE,
                         f"{where}: field {key!r} must be a JSON string")
                    row_ok = False
            else:  # integer
                if not _is_int(v) or v < 0 or v > MAX_JSON_INT:
                    _err(errors, ErrorCode.E_SCHEMA_TYPE,
                         f"{where}: field {key!r} must be a JSON integer in [0, 2^63-1]")
                    row_ok = False
        if not row_ok:
            return rows

        pk_val = record[pk]
        if not _ID_RES[pk].match(pk_val):
            _err(errors, ErrorCode.E_SCHEMA_TYPE,
                 f"{where}: {pk} does not match the identifier grammar: {pk_val!r}")
            return rows
        pk_bytes = pk_val.encode("utf-8")
        if prev_pk is not None:
            if pk_bytes == prev_pk:
                _err(errors, ErrorCode.E_SCHEMA_READ, f"{where}: duplicate primary key {pk_val}")
                return rows
            if pk_bytes < prev_pk:
                _err(errors, ErrorCode.E_SCHEMA_READ,
                     f"{where}: rows out of order ({pk_val} sorts before its predecessor)")
                return rows
        prev_pk = pk_bytes
        rows.append(record)

    return rows


# ── Stage 8: references and evidence ─────────────────────────────────────────

def _validate_references(
    entities: List[Dict[str, Any]],
    claims: List[Dict[str, Any]],
    prov: List[Dict[str, Any]],
    spans: List[Dict[str, Any]],
    hash_map: Dict[str, Path],
    errors: List[Dict[str, str]],
) -> None:
    entity_ids = {row["entity_id"] for row in entities}
    claim_ids = {row["claim_id"] for row in claims}

    for row in claims:
        if row["subject"] not in entity_ids:
            _err(errors, ErrorCode.E_REF_ORPHAN,
                 f"Claim subject '{row['subject']}' not found in entities")
        if row["object_type"] == "entity" and row["object"] not in entity_ids:
            _err(errors, ErrorCode.E_REF_ORPHAN,
                 f"Claim object '{row['object']}' not found in entities")

    for row in prov:
        if row["claim_id"] not in claim_ids:
            _err(errors, ErrorCode.E_REF_ORPHAN,
                 f"Provenance claim_id '{row['claim_id']}' not found in claims")
        _check_byte_range(row, hash_map, "Provenance", errors)

    for row in spans:
        p = _check_byte_range(row, hash_map, "Span", errors)
        if p is None:
            continue
        try:
            with p.open("rb") as f:
                f.seek(row["byte_start"])
                slice_bytes = f.read(row["byte_end"] - row["byte_start"])
        except OSError as e:
            _err(errors, ErrorCode.E_REF_READ, f"Span read failed: {e}")
            continue
        try:
            slice_text = slice_bytes.decode("utf-8")
        except UnicodeDecodeError:
            _err(errors, ErrorCode.E_REF_SOURCE,
                 f"Span bytes are not valid UTF-8 for {row['span_id']}")
            continue
        if slice_text != row["text"]:
            _err(errors, ErrorCode.E_REF_SOURCE, f"Span text mismatch for {row['span_id']}")


def _check_byte_range(
    row: Dict[str, Any],
    hash_map: Dict[str, Path],
    kind: str,
    errors: List[Dict[str, str]],
) -> Optional[Path]:
    src = row["source_hash"]
    p = hash_map.get(src)
    if p is None:
        _err(errors, ErrorCode.E_REF_SOURCE,
             f"{kind} source_hash '{src}' does not match any file under content/")
        return None
    try:
        fsize = p.stat().st_size
    except OSError as e:
        _err(errors, ErrorCode.E_REF_READ, f"{kind} content stat failed: {e}")
        return None
    bs, be = row["byte_start"], row["byte_end"]
    if not (0 <= bs <= be <= fsize):
        _err(errors, ErrorCode.E_REF_SOURCE, f"{kind} byte range out of bounds: {bs}-{be}")
        return None
    return p


# ── Entry point ──────────────────────────────────────────────────────────────

def verify_shard(shard_path: str | Path, trusted_key_path: Path, mode: str = "strict") -> Dict[str, Any]:
    """Verify a shard per spec/v1/SPECIFICATION.md section 13.

    Returns the result JSON object; the CLI maps it onto the frozen
    exit-code contract.
    """
    root = Path(shard_path)
    errors: List[Dict[str, str]] = []
    profiles_checked: List[str] = []
    profiles_unchecked: List[str] = []

    def result(status: Optional[str] = None) -> Dict[str, Any]:
        return {
            "shard": str(shard_path),
            "status": status or ("FAIL" if errors else "PASS"),
            "error_count": len(errors),
            "errors": errors,
            "profiles_checked": profiles_checked,
            "profiles_unchecked": profiles_unchecked,
        }

    # 1) Layout
    if not root.exists() or not root.is_dir():
        _err(errors, ErrorCode.E_LAYOUT_MISSING,
             "Shard path does not exist or is not a directory")
        return result()
    _validate_layout(root, errors)
    if errors:
        return result()

    # 2) Manifest
    manifest_path = root / "manifest.json"
    try:
        if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            _err(errors, ErrorCode.E_MANIFEST_SCHEMA,
                 f"manifest.json exceeds size limit ({MAX_MANIFEST_BYTES} bytes)")
            return result()
        manifest_bytes = manifest_path.read_bytes()
    except OSError as e:
        _err(errors, ErrorCode.E_MANIFEST_SCHEMA, f"Cannot read manifest.json: {e}")
        return result()

    ext_dir = root / "ext"
    ext_nonempty = ext_dir.is_dir() and any(p.is_file() for p in ext_dir.rglob("*"))
    manifest = _validate_manifest(manifest_bytes, errors, ext_dir_nonempty=ext_nonempty)
    if errors:
        return result()

    # 3) Signature (trusted anchor supplied out of band)
    try:
        trusted_pub = trusted_key_path.read_bytes()
    except OSError as e:
        _err(errors, ErrorCode.E_SIG_INVALID, f"Cannot read trusted key: {e}")
        return result()
    if len(trusted_pub) != HYBRID1_PK_LEN:
        _err(errors, ErrorCode.E_SIG_INVALID,
             f"Trusted key must be {HYBRID1_PK_LEN} bytes, got {len(trusted_pub)}")
        return result()

    shard_pub = (root / "sig" / "publisher.pub").read_bytes()
    shard_sig_path = root / "sig" / "manifest.sig"
    if len(shard_pub) != HYBRID1_PK_LEN:
        _err(errors, ErrorCode.E_SIG_INVALID,
             f"sig/publisher.pub must be {HYBRID1_PK_LEN} bytes, got {len(shard_pub)}")
        return result()
    if shard_sig_path.stat().st_size != HYBRID1_SIG_LEN:
        _err(errors, ErrorCode.E_SIG_INVALID,
             f"sig/manifest.sig must be {HYBRID1_SIG_LEN} bytes")
        return result()
    if shard_pub != trusted_pub:
        _err(errors, ErrorCode.E_SIG_INVALID, "Shard publisher.pub does not match trusted key")
        return result()
    if not verify_manifest_signature(manifest_bytes, shard_sig_path, trusted_key_path):
        _err(errors, ErrorCode.E_SIG_INVALID,
             "Hybrid signature verification failed (both components must verify)")
        return result()

    # 4) Merkle
    try:
        computed = compute_merkle_root(root)
    except ValueError as e:
        _err(errors, ErrorCode.E_LAYOUT_DIRTY, f"Cannot compute Merkle root: {e}")
        return result()
    stored = manifest["integrity"]["merkle_root"]
    if computed != stored:
        _err(errors, ErrorCode.E_MERKLE_MISMATCH,
             f"Merkle root mismatch: computed {computed}, stored {stored}")
        return result()

    # 5) Sources <-> content/ bijection
    content_files = _walk_content_files(root / "content", errors)
    if content_files is None:
        return result()
    hash_map = _validate_sources_bijection(manifest, content_files, errors)
    if errors:
        return result()

    # 6) Core tables (canonical JSONL, stdlib json only)
    tables: List[List[Dict[str, Any]]] = []
    for relpath, schema, pk in CORE_TABLES:
        rows = _validate_table(root / relpath, relpath, schema, pk, errors)
        tables.append(rows if rows is not None else [])
    if errors:
        return result()
    entities, claims, prov, spans = tables

    # 6b) Enums
    for row in claims:
        if row["object_type"] not in VALID_OBJECT_TYPES:
            _err(errors, ErrorCode.E_SCHEMA_ENUM, f"Invalid object_type: {row['object_type']!r}")
        if row["tier"] not in VALID_TIERS:
            _err(errors, ErrorCode.E_SCHEMA_ENUM, f"Invalid tier: {row['tier']!r}")
    if errors:
        return result()

    # 7) Identifier recomputation
    for row in entities:
        try:
            calc = recompute_entity_id(row["namespace"], row["label"])
        except ValueError:
            calc = None
        if calc != row["entity_id"]:
            _err(errors, ErrorCode.E_ID_ENTITY, f"Entity ID mismatch for label {row['label']!r}")
    for row in claims:
        try:
            calc = recompute_claim_id(row["subject"], row["predicate"],
                                      row["object"], row["object_type"])
        except ValueError:
            calc = None
        if calc != row["claim_id"]:
            _err(errors, ErrorCode.E_ID_CLAIM, f"Claim ID mismatch for {row['claim_id']}")
    if errors:
        return result()

    # 8) References and evidence invariants
    _validate_references(entities, claims, prov, spans, hash_map, errors)
    if errors:
        return result()

    # 9) Statistics == actual row counts
    stats = manifest["statistics"]
    if stats["entities"] != len(entities):
        _err(errors, ErrorCode.E_MANIFEST_SCHEMA,
             f"statistics.entities is {stats['entities']} but "
             f"graph/entities.jsonl has {len(entities)} rows")
    if stats["claims"] != len(claims):
        _err(errors, ErrorCode.E_MANIFEST_SCHEMA,
             f"statistics.claims is {stats['claims']} but "
             f"graph/claims.jsonl has {len(claims)} rows")
    if errors:
        return result()

    # 10) Profiles: run every listed profile we implement; unchecked != passed
    for profile_id in manifest.get("profiles", []):
        check = IMPLEMENTED_PROFILES.get(profile_id)
        if check is None:
            profiles_unchecked.append(profile_id)
        else:
            check(root, errors)
            profiles_checked.append(profile_id)

    return result()
