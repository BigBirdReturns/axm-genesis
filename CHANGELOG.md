# Changelog

## [1.1.0] - 2026-01-04

### Added
- `axm-build compile`: compile shards from `source.txt` and `candidates.jsonl`.
- `axm-extract`: extract canonical UTF-8 text and chunk metadata from PDF/DOCX.
- `axm_build.compiler_generic`: Generic compiler path to mint verified shards from `source.txt` + `candidates.jsonl`.

### Security
- Enforced `MAX_INGEST_FILE_BYTES` at the ingestion boundary to prevent DoS via oversized inputs.
- Hardened triage encryption detection:
  - PDFs: definitive open check via the same extraction stack.
  - DOCX: explicit OLE-encrypted detection plus zip sanity checks.
- Hardened shard file walking: refuse symlinks and disable link traversal during Merkle computation.
- Streamed file hashing and content scanning to reduce memory exhaustion risk.
- Added policy limits for manifest size, per-file size, and total scanned bytes.

### Fixed
- Removed duplicate constant definition in `axm_verify.crypto`.
- Builder no longer emits non-shard top-level folders (e.g., `governance/`) in shard outputs.
- Shard payloads and test vectors are protected from line-ending conversion via `.gitattributes`.

## [1.0.2] - 2026-01-02

### Security
- Hardened shard file walking: refuse symlinks and disable link traversal during Merkle computation.
- Streamed file hashing and content scanning to reduce memory exhaustion risk.
- Added policy limits for manifest size, per-file size, and total scanned bytes.

## [1.0.1] - 2026-01-02
### Security
- Critical: Require an external trusted key for signature verification via `axm-verify shard --trusted-key`.
- Security: Read `manifest.json` once and verify signature on the same bytes to prevent TOCTOU swaps.
- Security: Reject symlinks during Merkle root computation and content reads.
- Security: Reject null bytes in identity inputs.

## [1.0.0]
- Initial frozen release of AXM Genesis v1.0.0
- Reference verifier (axm-verify)
- Reference builder (axm-build)
- Gold shard: fm21-11-hemorrhage-v1
