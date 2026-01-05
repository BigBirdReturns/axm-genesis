from __future__ import annotations

from pathlib import Path
from typing import List, Tuple, Optional, Dict

import hashlib
import pdfplumber

from axm_extract.models.types import Chunk, Locator, TableChunk, TextSpan
from axm_extract.chunking.util import make_content_anchored_chunk_id, norm_ws

def _doc_id_from_path(path: Path) -> str:
    data = path.read_bytes()
    return "sha256:" + hashlib.sha256(data).hexdigest()

def chunk_pdf(path: Path, max_pages: Optional[int] = None) -> Tuple[str, str, List[object]]:
    """Chunk a PDF into page-level prose chunks and best-effort table chunks.

    v1 philosophy: be deterministic, keep provenance into the extracted_text artifact,
    do not claim semantic table reconstruction accuracy beyond what pdfplumber can extract.

    - Prose chunks: one per page (if text exists)
    - Table chunks: per detected table on page (if any)
    - cell_spans: spans into the normalized extracted_text (not the original PDF bytes)
    """
    doc_id = _doc_id_from_path(path)

    extracted_parts: List[str] = []
    chunks: List[object] = []
    cursor = 0

    with pdfplumber.open(str(path)) as pdf:
        pages = pdf.pages
        if max_pages is not None:
            pages = pages[:max_pages]

        for page_idx, page in enumerate(pages, start=1):
            # 1) Prose text
            page_text = norm_ws(page.extract_text() or "")
            if page_text:
                start = cursor
                extracted_parts.append(page_text)
                cursor += len(page_text)
                end = cursor
                extracted_parts.append("\n\n")
                cursor += 2

                locator = Locator(kind="pdf", page=page_idx, block_id="page_text")
                locator_key = f"p:{page_idx}:text"
                chunk_id = make_content_anchored_chunk_id(doc_id, "prose", locator_key, page_text)
                chunks.append(
                    Chunk(
                        chunk_id=chunk_id,
                        chunk_type="prose",
                        locator=locator,
                        text_span=TextSpan(artifact="extracted_text", start=start, end=end),
                        text=page_text,
                    )
                )

            # 2) Best-effort tables
            try:
                tables = page.extract_tables() or []
            except Exception:
                tables = []

            for t_idx, tbl in enumerate(tables):
                # tbl is List[List[str|None]]
                raw = [[norm_ws(c or "") for c in row] for row in tbl if row]
                raw = [r for r in raw if any(x for x in r)]
                if not raw:
                    continue

                headers = raw[0]
                rows = raw[1:] if len(raw) > 1 else []

                table_lines: List[str] = []
                table_lines.append("\t".join(headers))
                for r in rows:
                    table_lines.append("\t".join(r))
                table_text = "\n".join(table_lines)
                if not table_text.strip():
                    continue

                start_table = cursor
                extracted_parts.append(table_text)
                cursor += len(table_text)
                end_table = cursor
                extracted_parts.append("\n\n")
                cursor += 2

                # Build cell spans into extracted_text (deterministic from serialization).
                cell_spans: Dict[str, TextSpan] = {}
                offset = 0

                def _row_spans(row_vals: List[str], row_idx: int):
                    nonlocal offset
                    for col_idx, val in enumerate(row_vals):
                        v = val or ""
                        cell_start = offset
                        cell_end = offset + len(v)
                        cell_spans[f"{row_idx}:{col_idx}"] = TextSpan(
                            artifact="extracted_text",
                            start=start_table + cell_start,
                            end=start_table + cell_end,
                        )
                        offset = cell_end
                        if col_idx < len(row_vals) - 1:
                            offset += 1  # tab
                    offset += 1  # newline

                _row_spans(headers, 0)
                for i, r in enumerate(rows, start=1):
                    _row_spans(r, i)

                locator = Locator(kind="pdf", page=page_idx, block_id=f"table:{t_idx}")
                locator_key = f"p:{page_idx}:table:{t_idx}"
                chunk_id = make_content_anchored_chunk_id(doc_id, "table", locator_key, table_text)

                chunks.append(
                    TableChunk(
                        chunk_id=chunk_id,
                        chunk_type="table",
                        locator=locator,
                        headers=headers,
                        rows=rows,
                        cell_spans=cell_spans,
                        text_span=TextSpan(artifact="extracted_text", start=start_table, end=end_table),
                        text=table_text,
                    )
                )

    extracted_text = "".join(extracted_parts)
    return doc_id, extracted_text, chunks
