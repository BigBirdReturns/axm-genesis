from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple

from axm_extract.chunking.docx_chunker import chunk_docx
from axm_extract.chunking.pdf_chunker import chunk_pdf
from axm_build.common import normalize_source_text


def extract_to_canonical_text(file_path: Path) -> Tuple[str, List[Dict[str, Any]]]:
    """Extract deterministic text + chunk metadata from PDF/DOCX.

    Returns:
        canonical_text: normalized UTF-8 text with LF newlines and trailing \n
        chunks: list of JSON-serializable chunk dicts (best-effort)
    """
    ext = file_path.suffix.lower()
    if ext == ".pdf":
        _, text, chunks = chunk_pdf(file_path)
    elif ext == ".docx":
        _, text, chunks = chunk_docx(file_path)
    else:
        raise ValueError(f"Unsupported file format: {ext}")

    canonical_text = normalize_source_text(text)

    chunks_out: List[Dict[str, Any]] = []
    for c in chunks:
        d = getattr(c, "__dict__", {}).copy()
        # flatten locator/text_span if present
        loc = getattr(c, "locator", None)
        if loc is not None and hasattr(loc, "__dict__"):
            d["locator"] = loc.__dict__.copy()
        ts = getattr(c, "text_span", None)
        if ts is not None and hasattr(ts, "__dict__"):
            d["text_span"] = ts.__dict__.copy()
        # flatten cell_spans for tables
        if isinstance(d.get("cell_spans"), dict):
            d["cell_spans"] = {k: (v.__dict__.copy() if hasattr(v, "__dict__") else v) for k, v in d["cell_spans"].items()}
        chunks_out.append(d)

    return canonical_text, chunks_out
