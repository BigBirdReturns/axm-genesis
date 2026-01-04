# Changelog


## 1.0.1 - 2026-01-02

### Security
- Critical: Require an external trusted key for signature verification via `axm-verify shard --trusted-key`.
- Security: Read `manifest.json` once and verify signature on the same bytes to prevent TOCTOU swaps.
- Security: Reject symlinks during Merkle root computation and content reads.
- Security: Reject null bytes in identity inputs.

## 1.0.0

- Initial frozen release of AXM Genesis v1.0.0
- Reference verifier (axm-verify)
- Reference builder (axm-build)
- Gold shard: fm21-11-hemorrhage-v1

## [1.0.2] - 2026-01-02
### Security
- Hardened shard file walking: refuse symlinks and disable link traversal during Merkle computation.
- Streamed file hashing and content scanning to reduce memory exhaustion risk.
- Added policy limits for manifest size, per-file size, total scanned bytes, content file count, and Parquet row counts.
