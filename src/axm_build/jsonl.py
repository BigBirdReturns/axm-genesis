"""AXM Genesis v1 — canonical JSONL encoding (spec sections 5 and 11).

One canonical byte encoding for every table line: the output of
json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
encoded as UTF-8, followed by exactly one newline. A file is the exact
concatenation of its lines — no BOM, no blank lines, no trailing blank
line. A table with zero rows is a zero-byte file.

Schemas are mappings {field_name: "string" | "integer"} with exact key
sets; see axm_verify.const for the frozen core-table schemas.

Sort keys are either a single field name (core tables) or a composite —
a sequence of field names (some extension tables, e.g. streams@1). String
components sort bytewise on their UTF-8 encoding; integer components sort
numerically (implemented as fixed-width decimal so the whole key remains
one bytewise comparison).
"""
from __future__ import annotations

import json
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Union

# The only numbers permitted in kernel-defined documents (spec section 5).
MAX_JSON_INT = 2**63 - 1

# A sort key: one field name, or a sequence of field names (composite).
SortKey = Union[str, Sequence[str]]


def canonical_json_bytes(obj: Any) -> bytes:
    """Canonical JSON encoding of one abstract value (no trailing newline)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _validate_row(row: Dict[str, Any], schema: Mapping[str, str], where: str) -> None:
    extra = set(row) - set(schema)
    if extra:
        raise ValueError(f"{where}: unexpected keys {sorted(extra)}")
    for key, typ in schema.items():
        if key not in row or row[key] is None:
            raise ValueError(f"{where}: missing or null field {key!r}")
        v = row[key]
        if typ == "string":
            if not isinstance(v, str):
                raise ValueError(f"{where}: field {key!r} must be a string, got {type(v).__name__}")
            if unicodedata.normalize("NFC", v) != v:
                raise ValueError(f"{where}: field {key!r} is not NFC-normalized")
        elif typ == "integer":
            if isinstance(v, bool) or not isinstance(v, int):
                raise ValueError(f"{where}: field {key!r} must be an integer, got {type(v).__name__}")
            if not (0 <= v <= MAX_JSON_INT):
                raise ValueError(f"{where}: field {key!r} out of range [0, 2^63-1]: {v}")
        else:
            raise ValueError(f"{where}: schema declares unknown type {typ!r} for {key!r}")


def _sort_key_fields(pk: SortKey) -> tuple[str, ...]:
    return (pk,) if isinstance(pk, str) else tuple(pk)


def _sort_key_bytes(row: Dict[str, Any], pk: SortKey, schema: Mapping[str, str]) -> bytes:
    """Encode a row's sort key as bytes whose bytewise order is the key order.

    Integer fields (already validated to [0, 2^63-1]) are rendered as
    20-digit zero-padded decimal, so bytewise comparison equals numeric
    comparison. Components join on 0x00, which sorts below any UTF-8 byte
    that can appear in a validated string field.
    """
    parts: List[bytes] = []
    for name in _sort_key_fields(pk):
        if schema.get(name) == "integer":
            parts.append(b"%020d" % row[name])
        else:
            parts.append(row[name].encode("utf-8"))
    return b"\x00".join(parts)


def encode_table(rows: List[Dict[str, Any]], schema: Mapping[str, str], pk: SortKey,
                 unique: bool = True) -> bytes:
    """Encode rows as a canonical JSONL table, sorted bytewise by sort key.

    Validates every row against the schema (exact key set, types). With
    unique=True (core tables) a duplicate primary key is an error; with
    unique=False (extension tables whose sort key is not a primary key)
    rows tie-break on their full canonical encoding and only fully
    identical rows are rejected. ``pk`` may be a single field name or a
    composite (sequence of field names).
    """
    for i, row in enumerate(rows):
        _validate_row(row, schema, f"row {i}")

    encoded = sorted(
        (_sort_key_bytes(row, pk, schema), canonical_json_bytes(row)) for row in rows
    )
    out = bytearray()
    prev: tuple[bytes, bytes] | None = None
    for pk_bytes, line in encoded:
        if prev is not None:
            if unique and pk_bytes == prev[0]:
                raise ValueError(f"duplicate primary key {pk_bytes!r} in table (pk={pk})")
            if (pk_bytes, line) == prev:
                raise ValueError(f"duplicate row in table: {line!r}")
        prev = (pk_bytes, line)
        out += line
        out += b"\n"
    return bytes(out)


def write_table(path: Path, rows: List[Dict[str, Any]], schema: Mapping[str, str], pk: SortKey,
                unique: bool = True) -> None:
    """Write a canonical JSONL table file (see encode_table)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encode_table(rows, schema, pk, unique=unique))


def read_table(path: Path, schema: Mapping[str, str], pk: SortKey) -> List[Dict[str, Any]]:
    """Read a canonical JSONL table, enforcing encoding, schema, and order.

    Builder-side reader; the verifier has its own independent parse path.
    """
    raw = path.read_bytes()
    if raw == b"":
        return []
    if not raw.endswith(b"\n"):
        raise ValueError(f"{path}: file does not end with a newline")

    rows: List[Dict[str, Any]] = []
    prev_pk: bytes | None = None
    for lineno, line in enumerate(raw.split(b"\n")[:-1], start=1):
        where = f"{path}:{lineno}"
        record = json.loads(line)
        if not isinstance(record, dict):
            raise ValueError(f"{where}: line is not a JSON object")
        if canonical_json_bytes(record) != line:
            raise ValueError(f"{where}: line is not in canonical encoding")
        _validate_row(record, schema, where)
        pk_bytes = _sort_key_bytes(record, pk, schema)
        if prev_pk is not None and pk_bytes <= prev_pk:
            raise ValueError(f"{where}: rows out of order or duplicate primary key")
        prev_pk = pk_bytes
        rows.append(record)
    return rows
