# Changelog

## [1.1.0] - 2026-02-22
### Added
- **Post-quantum cryptographic suite**: `axm-blake3-mldsa44` using ML-DSA-44 (FIPS 204 / Dilithium2).
- Suite-aware compiler: `CompilerConfig.suite` selects signing algorithm. Defaults to `axm-blake3-mldsa44` for new shards.
- Suite-aware verifier: detects suite from manifest or public key size. Verifies both Ed25519 and ML-DSA-44.
- Specification Section 11: Cryptographic Suites addendum (backward-compatible extension).
- New tests: `test_pq_upgrade.py`, `test_sign.py`, `test_e2e.py`, `test_identity.py`, `test_merkle.py`.

### Changed
- `sign.py`: supports both `Ed25519` and `MLDSAKeyPair`. Accepts 2528-byte (sk-only, generates fresh pk) or 3840-byte (sk||pk) key blobs for ML-DSA-44.
- `compiler_generic.py`: suite-aware signing path. PQ shards include `"suite": "axm-blake3-mldsa44"` in manifest.
- `crypto.py`: suite-aware signature verification. Auto-detects from manifest `suite` field or key size.

### Backward Compatibility
- Ed25519 shards (no `suite` field) continue to verify unchanged.
- Gold shard (`fm21-11-hemorrhage-v1`) passes verification before and after this upgrade.

## [1.0.2] - 2026-01-03
### Security
- **Critical**: Hardened shard file walking: refuse symlinks and disable link traversal during Merkle computation.
- **Critical**: Streamed file hashing and content scanning to reduce memory exhaustion risk.
- **High**: Added policy limits for manifest size, per-file size, total scanned bytes, content file count, and Parquet row counts.

## [1.0.1] - 2026-01-02
### Security
- Critical: Require an external trusted key for signature verification via `axm-verify shard --trusted-key`.
- Security: Read `manifest.json` once and verify signature on the same bytes to prevent TOCTOU swaps.
- Security: Reject symlinks during Merkle root computation and content reads.
- Security: Reject null bytes in identity inputs.

## [1.0.0]
- Initial frozen release of AXM Genesis v1.0.0.
- Reference verifier (`axm-verify`).
- Reference builder (`axm-build`).
- Gold shard: `fm21-11-hemorrhage-v1`.
