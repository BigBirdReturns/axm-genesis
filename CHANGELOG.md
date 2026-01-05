# Changelog

## [1.1.0] - 2026-01-04

### Added
- `axm-judge`: Pattern 2 Stream Judge that scans `cam_residuals.bin` (Disk is Truth) and verifies `cam_latents.bin` with strict offset math, producing `evidence/streams.parquet`.
- `axm-extract`: Pattern 4 Extraction CLI that produces deterministic `source.txt` and `chunks.json` from PDF/DOCX.
- `axm_build.compiler_generic`: Generic compiler path to mint verified shards from `source.txt` + `candidates.jsonl`.
- `STREAM_FORMAT.md`: Explicit on-disk stream contract for Pattern 2.

### Security
- Enforced `MAX_INGEST_FILE_BYTES` at the ingestion boundary to prevent DoS via oversized inputs.
- Hardened triage encryption detection:
  - PDFs: definitive open check via the same extraction stack.
  - DOCX: explicit OLE-encrypted detection plus zip sanity checks.

### Fixed
- Removed duplicate constant definition in `axm_verify.crypto`.

## [1.0.2] - 2026-01-02

### Security
- Hardened shard file walking: refuse symlinks and disable link traversal during Merkle computation.
- Streamed file hashing and content scanning to reduce memory exhaustion risk.
- Added policy limits for manifest size, per-file size, and total scanned bytes.

## [1.0.0] - 2026-01-01

- Initial frozen release of AXM Genesis:
  - `axm-build` (shard builder)
  - `axm-verify` (shard verifier)
