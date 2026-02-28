from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Dict, List, Literal, Optional


@dataclass(frozen=True)
class Locator:
    """Structured locator for provenance.

    v3 keeps a single Locator with optional fields for pragmatic serialization.
    Each extractor fills only fields relevant to its format.
    """

    kind: Literal["docx", "pdf", "pptx", "xlsx", "html"]
    page: Optional[int] = None
    paragraph_index: Optional[int] = None
    run_index: Optional[int] = None
    block_id: Optional[str] = None
    table_id: Optional[str] = None
    cell_row: Optional[int] = None
    cell_col: Optional[int] = None
    sheet: Optional[str] = None
    cell: Optional[str] = None


@dataclass(frozen=True)
class TextSpan:
    """Character offsets into a chunk's normalized text."""

    artifact: str = "extracted_text"
    start: int = 0
    end: int = 0

    @property
    def start_char(self) -> int:  # backward-compatible alias
        return self.start

    @property
    def end_char(self) -> int:  # backward-compatible alias
        return self.end

    def to_json(self) -> Dict[str, object]:
        return {"artifact": self.artifact, "start": self.start, "end": self.end}


@dataclass(frozen=True)
class Chunk:
    chunk_id: str
    chunk_type: Literal["prose", "table", "list", "heading"]
    locator: Locator
    text_span: TextSpan
    text: str


@dataclass(frozen=True)
class TableChunk(Chunk):
    chunk_type: Literal["table"]
    headers: List[str]
    rows: List[List[str]]
    # "row:col" -> TextSpan into the chunk's flattened text
    cell_spans: Dict[str, TextSpan]


@dataclass(frozen=True)
class DocumentRef:
    doc_id: str
    relationship: Literal["amends", "supersedes", "incorporates", "exhibits", "none"]
    effective_date: Optional[date] = None
    target_doc_id: Optional[str] = None


@dataclass(frozen=True)
class DocumentDifficultyProfile:
    category: Literal[
        "standard",
        "ocr_heavy",
        "foreign_language",
        "redacted",
        "handwritten",
        "legacy_format",
    ]
    expected_coverage_floor: float
    critical_threshold_override: Optional[float] = None
    routing: Literal["standard", "specialist_review", "human_first"] = "standard"


@dataclass(frozen=True)
class TriageResult:
    file_path: str
    file_hash: str
    status: Literal[
        "ok",
        "unreadable",
        "no_text",
        "duplicate",
        "unsupported_format",
        "needs_ocr",
        "password_protected",
        "other",
    ]
    notes: Optional[str] = None
    duplicate_of: Optional[str] = None
    ocr_confidence: Optional[float] = None
    difficulty: Optional[DocumentDifficultyProfile] = None


@dataclass(frozen=True)
class SignalStats:
    """Lightweight corpus signals used for completeness gating."""

    currency_hits: int
    percent_hits: int
    large_number_hits: int
    table_chunks: int
    keyword_hits: int

    @property
    def richness(self) -> int:
        return self.currency_hits + self.percent_hits + self.large_number_hits + self.table_chunks + self.keyword_hits
