# Changelog

## [Unreleased] - 2026-07-01
Durability remediation change set, addressing the headline findings of the
30-year durability assessment (`docs/DURABILITY.md`, which now carries a
"Remediation status" table mapping each finding to its outcome).

### Added
- `docs/ERRATA.md`: numbered errata register for non-editable artifacts.
  Erratum 1 corrects the paper's §6.3.3 Merkle description (normative
  definition: spec §4 + `src/axm_build/merkle.py`); Erratum 2 records that
  spec v1.0 does not pin a Unicode version for canonicalization and declares
  `tests/vectors/identity.json` the normative anchor (Unicode 14.0.0 at time
  of writing); Erratum 3 records the de-facto Parquet feature subset
  (format 2.6, flat columns, PLAIN encoding, UNCOMPRESSED/SNAPPY/ZSTD, no
  encryption).
- `rfcs/0003-spec-v1-1-pinning-clarifications.md`: proposes spec v1.1
  additions — pinned Unicode data version policy, pinned Parquet subset, and
  a formalized verifier exit-code contract (0/1/2).
- `papers/README.md`: Errata section pointing paper readers to
  `docs/ERRATA.md` Erratum 1.
- `tests/test_compatibility_contract.py`: mechanically checks the checkable
  claims in COMPATIBILITY.md (suite identifiers, frozen schema columns,
  verifier exit codes) so doc/code drift fails CI.
- CI workflows: conformance suite plus a dedicated gold-shard verification
  job.
- `keys/README.md`: documents the canonical test publisher key and its
  zero-authentication-value caveat.
- Test-pollution fix: autouse fixture in `tests/test_mldsa_backend_contract.py`
  restores the real ML-DSA backend and re-reloads `axm_build.sign` /
  `axm_verify.crypto` after each reload-based test, so `make test` passes in
  any collection order.

### Changed
- `COMPATIBILITY.md`: rewritten against the spec and code — correct Merkle
  constructions per suite, correct suite identifiers (`ed25519`,
  `axm-blake3-mldsa44`), the actual frozen `claims.parquet` schema, the real
  verifier invocation and exit-code contract, and accurate extension-schema
  locations.
- `src/axm_verify/logic.py`: enforces the spec §5.2 required manifest fields;
  `E_MANIFEST_SCHEMA` now names the offending field.
- `src/axm_verify/cli.py`: exit-code contract implemented — 0 valid, 1
  verification failure, 2 structurally malformed shard.
- `src/axm_build/cli.py`: removed the hardcoded `CANONICAL_TEST_PRIVATE_KEY`;
  signing now requires `--private-key` or `AXM_SIGNING_KEY_HEX`.
- `shards/gold/README.md`: gold shard documented as frozen bytes; the
  public-signing-key caveat (the gold shard's signature has no
  authentication value; its authenticity rests on repository integrity) is
  stated explicitly.

### Backward Compatibility
- Every byte under `shards/gold/**` and `tests/vectors/**` is unchanged; the
  gold shard and all existing vectors verify exactly as before. `spec/v1.0/`
  is unchanged (frozen). Verifier changes are enforcement-only additions;
  previously-valid shards remain valid.

### Still open (tracked in `docs/DURABILITY.md`)
- Key rotation / trust store, timestamping and PQ attestation of the gold
  shard, release engineering (tags/PyPI/SWH/Zenodo), and an independent
  second implementation.

---

## [1.2.0] - 2026-02-25
### Added
- **REQ 5 enforcement**: `E_BUFFER_DISCONTINUITY` added to `ErrorCode` enum in `const.py`.
- `_validate_hot_stream_continuity()` in `logic.py`: reads `content/cam_latents.bin` if present, skips 4-byte `AXLF` file header, verifies gap-free `AXLR` record sequence, emits `E_BUFFER_DISCONTINUITY` on any gap, truncation, or bad magic. Shards without `cam_latents.bin` pass silently — document shards and non-embodied spokes unaffected.
- `tests/test_conformance.py`: AXM Compatibility conformance suite covering REQ 1–5 plus determinism. REQ 5 tests write synthetic binary fixtures with correct `AXLF`/`AXLR` format.

### Changed
- `const.py`: removed unused `E_LAYOUT_TYPE` (never emitted), `PUBKEY_LEN`, `SIG_LEN` (superseded by `SUITE_SIZES`), `REQUIRED_GRAPH_FILES`, `REQUIRED_EVIDENCE_FILES`, `REQUIRED_SIG_FILES` (declared but never referenced — `logic.py` hardcodes paths directly). Added section comments to `ErrorCode` enum.
- `logic.py`: missing `sig/publisher.pub` now correctly emits `E_SIG_MISSING` instead of `E_SIG_INVALID`.
- `STREAM_FORMAT.md`: corrected magic bytes (`LATN`/`RSID` → `AXLF`/`AXLR`/`AXRR`), documented 4-byte file header skip, corrected evidence output path (`ext/streams@1.parquet`, not `evidence/streams.parquet`).

### Backward Compatibility
- Additive only. No existing error codes changed or removed. `E_LAYOUT_TYPE` removal is safe — it was never emitted, never tested, and never documented in user-facing output.
- All existing shards (including gold shard) continue to verify unchanged.

---

## [1.1.0] - 2026-02-22
### Added
- **Post-quantum cryptographic suite**: `axm-blake3-mldsa44` using ML-DSA-44 (FIPS 204 / Dilithium2).
- Suite-aware compiler: `CompilerConfig.suite` selects signing algorithm. Defaults to `axm-blake3-mldsa44` for new shards.
- Suite-aware verifier: detects suite from manifest or public key size. Verifies both Ed25519 and ML-DSA-44.
- Specification Section 11: Cryptographic Suites addendum (backward-compatible extension).
- New tests: `test_pq_upgrade.py`, `test_sign.py`, `test_e2e.py`, `test_identity.py`, `test_merkle.py`.

### Changed
- `sign.py`: supports both `Ed25519` and `MLDSAKeyPair`. Accepts 2528-byte (sk-only) or 3840-byte (sk||pk) key blobs for ML-DSA-44.
- `compiler_generic.py`: suite-aware signing path. PQ shards include `"suite": "axm-blake3-mldsa44"` in manifest.
- `crypto.py`: suite-aware signature verification. Auto-detects from manifest `suite` field or key size.

### Backward Compatibility
- Ed25519 shards (no `suite` field) continue to verify unchanged.
- Gold shard (`fm21-11-hemorrhage-v1`) passes verification before and after this upgrade.

---

## [1.0.2] - 2026-01-03
### Security
- **Critical**: Hardened shard file walking — refuse symlinks, disable link traversal during Merkle computation.
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
