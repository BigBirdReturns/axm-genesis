"""Shared utilities for AXM build pipeline."""
from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Any, Dict, List

import pyarrow as pa
import pyarrow.parquet as pq


def normalize_source_text(text: str) -> str:
    """Normalize source text for content/source.txt.

    - NFC unicode normalization
    - Strip trailing whitespace per line
    - Collapse runs of internal whitespace to single space
    - Ensure trailing newline
    """
    text = unicodedata.normalize("NFC", text)
    lines = text.splitlines()
    out: List[str] = []
    for line in lines:
        stripped = line.rstrip()
        stripped = re.sub(r"\s+", " ", stripped)
        out.append(stripped)
    result = "\n".join(out)
    if not result.endswith("\n"):
        result += "\n"
    return result


def write_parquet_deterministic(
    path: Path,
    rows: List[Dict[str, Any]],
    schema: pa.Schema,
    sort_key: str,
) -> None:
    """Write a Parquet file deterministically.

    Rows are sorted by sort_key before writing. This ensures
    identical inputs always produce identical Parquet bytes.
    """
    if not rows:
        table = pa.table(
            {f.name: pa.array([], type=f.type) for f in schema},
            schema=schema,
        )
        pq.write_table(table, str(path), compression="zstd")
        return

    rows_sorted = sorted(rows, key=lambda r: str(r.get(sort_key, "")))

    arrays = {}
    for field in schema:
        values = [r[field.name] for r in rows_sorted]
        arrays[field.name] = pa.array(values, type=field.type)

    table = pa.table(arrays, schema=schema)
    pq.write_table(table, str(path), compression="zstd")
