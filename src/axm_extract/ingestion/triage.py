from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from typing import Dict, Literal

from axm_extract.models.types import DocumentDifficultyProfile, TriageResult

# Policy limits (ingestion safety, not protocol)
MAX_INGEST_FILE_BYTES = 512 * 1024 * 1024  # 512 MiB

# Encrypted Office documents are often stored as an OLE Compound File container.
OLE_MAGIC_BYTES = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"

PdfCheck = Literal["ok", "password_protected", "corrupt"]
DocxCheck = Literal["ok", "password_protected", "corrupt"]


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _check_pdf_openable(path: Path) -> PdfCheck:
    """
    Definitive check aligned with extraction.

    - If pdfplumber (pdfminer.six) cannot open due to encryption, we classify as password_protected.
    - If parsing fails for structural reasons, we classify as corrupt.

    If pdfplumber is not installed, we return "ok" and let extraction fail later.
    """
    try:
        import pdfplumber  # type: ignore
        from pdfminer.pdfdocument import PDFPasswordIncorrect  # type: ignore
        from pdfminer.pdfparser import PDFSyntaxError  # type: ignore
    except Exception:
        return "ok"

    try:
        # password=None triggers the default behavior.
        # Accessing metadata or first page forces decryption for many encrypted files.
        with pdfplumber.open(path) as pdf:
            _ = pdf.metadata
            if pdf.pages:
                _ = pdf.pages[0].extract_text()
        return "ok"
    except PDFPasswordIncorrect:
        return "password_protected"
    except PDFSyntaxError:
        return "corrupt"
    except Exception:
        # If the extraction stack errors here, extraction will fail too.
        return "corrupt"


def _check_docx_openable(path: Path) -> DocxCheck:
    """
    Definitive check for DOCX:

    - Standard DOCX is a Zip container.
    - Many password-protected DOCX files become an OLE container (not Zip).
    """
    try:
        with path.open("rb") as f:
            head = f.read(len(OLE_MAGIC_BYTES))
            if head.startswith(OLE_MAGIC_BYTES):
                return "password_protected"
    except Exception:
        return "corrupt"

    try:
        if not zipfile.is_zipfile(path):
            return "corrupt"
        with zipfile.ZipFile(path) as zf:
            # Minimal sanity check. Some docx variants vary, but a Zip container implies openable.
            _ = zf.namelist()
        return "ok"
    except Exception:
        return "corrupt"


def _detect_password_protected(path: Path) -> bool:
    ext = path.suffix.lower()

    if ext == ".pdf":
        return _check_pdf_openable(path) == "password_protected"

    if ext == ".docx":
        return _check_docx_openable(path) == "password_protected"

    return False


def _detect_needs_ocr(path: Path) -> bool:
    """
    Current v1 heuristic: treat PDFs with no extractable text as needing OCR.
    """
    if path.suffix.lower() != ".pdf":
        return False

    try:
        import pdfplumber  # type: ignore
    except Exception:
        # If pdfplumber is not installed, we cannot determine OCR needs.
        return False

    try:
        with pdfplumber.open(path) as pdf:
            for page in pdf.pages[:5]:
                text = page.extract_text() or ""
                if text.strip():
                    return False
        return True
    except Exception:
        return False


def _assign_difficulty(needs_ocr: bool) -> DocumentDifficultyProfile:
    if needs_ocr:
        return DocumentDifficultyProfile(
            category="ocr_heavy",
            expected_coverage_floor=0.85,
            critical_threshold_override=0.95,
            routing="specialist_review",
        )
    return DocumentDifficultyProfile(
        category="standard",
        expected_coverage_floor=0.98,
        critical_threshold_override=1.0,
        routing="standard",
    )


def triage_file(path: Path, seen_hashes: Dict[str, str]) -> TriageResult:
    # 0. Basic file existence
    if not path.exists() or not path.is_file():
        return TriageResult(
            file_path=str(path),
            file_hash="none",
            status="unreadable",
            notes="not a file",
            difficulty=_assign_difficulty(False),
        )

    # 1. Format gate
    ext = path.suffix.lower()
    if ext not in {".pdf", ".docx"}:
        return TriageResult(
            file_path=str(path),
            file_hash="none",
            status="unsupported_format",
            notes=f"unsupported extension: {ext}",
            difficulty=_assign_difficulty(False),
        )

    # 2. Size guard (DoS prevention)
    try:
        size = path.stat().st_size
        if size > MAX_INGEST_FILE_BYTES:
            return TriageResult(
                file_path=str(path),
                file_hash="none",
                status="other",
                notes=f"file exceeds ingest limit: {size} > {MAX_INGEST_FILE_BYTES}",
                difficulty=_assign_difficulty(False),
            )
    except Exception as e:
        return TriageResult(
            file_path=str(path),
            file_hash="none",
            status="unreadable",
            notes=f"stat failed: {e}",
            difficulty=_assign_difficulty(False),
        )

    # 3. Password protection and basic structural validation (aligned with extraction)
    if ext == ".pdf":
        pdf_check = _check_pdf_openable(path)
        if pdf_check == "password_protected":
            return TriageResult(
                file_path=str(path),
                file_hash="none",
                status="password_protected",
                notes="detected pdf encryption (pdfplumber)",
                difficulty=_assign_difficulty(False),
            )
        if pdf_check == "corrupt":
            return TriageResult(
                file_path=str(path),
                file_hash="none",
                status="unreadable",
                notes="pdf structure invalid or unreadable (pdfplumber)",
                difficulty=_assign_difficulty(False),
            )

    if ext == ".docx":
        docx_check = _check_docx_openable(path)
        if docx_check == "password_protected":
            return TriageResult(
                file_path=str(path),
                file_hash="none",
                status="password_protected",
                notes="detected OLE encrypted container",
                difficulty=_assign_difficulty(False),
            )
        if docx_check == "corrupt":
            return TriageResult(
                file_path=str(path),
                file_hash="none",
                status="unreadable",
                notes="docx structure invalid or unreadable",
                difficulty=_assign_difficulty(False),
            )

    # 4. Hash and dedupe
    try:
        file_hash = _hash_file(path)
    except Exception as e:
        return TriageResult(
            file_path=str(path),
            file_hash="none",
            status="unreadable",
            notes=f"hash failed: {e}",
            difficulty=_assign_difficulty(False),
        )

    if file_hash in seen_hashes:
        return TriageResult(
            file_path=str(path),
            file_hash=file_hash,
            status="duplicate",
            duplicate_of=seen_hashes[file_hash],
            notes="content hash duplicate",
            difficulty=_assign_difficulty(False),
        )

    # 5. Difficulty routing
    needs_ocr = _detect_needs_ocr(path)

    # 6. Success
    return TriageResult(
        file_path=str(path),
        file_hash=file_hash,
        status="ok",
        notes=("needs ocr" if needs_ocr else ""),
        difficulty=_assign_difficulty(needs_ocr),
    )
