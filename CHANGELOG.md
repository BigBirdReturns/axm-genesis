# Changelog

## [Unreleased]

### Added (docs/tools/tests only; nothing frozen changes) — family doctrine lane (train 081–090)
- `docs/CONTINUITY.md` — the law book both game clients' session docs point
  at, previously a phantom: the kernel invariant + platform constitution
  (cited, not legislated), the practiced operating doctrine (RFC-first lanes,
  driver-model orchestration, per-repo verification bars, the stop/ask box),
  the games/ops family posture, and the release-train record.
- `tests/test_continuity.py` — the law-book guard: existence, required
  sections, load-bearing anchors (whitespace-normalized).
- `tools/doc-truth-sweep.sh` — mechanical cross-repo doc-pointer verification
  (12 hard-listed load-bearing pointers + conservative extraction across
  genesis/arc/world); an unresolvable pointer is a finding, never a skip.
  First run found 2 phantoms (fixed in arc); now clean.
- `docs/RFC_FAMILY_DOCTRINE.md` — the lane's RFC, delegated rulings recorded
  for the owner's audit.

### Added (compiler-side only; nothing frozen changes)
- `CompilerConfig.extra_content` — additional content files (e.g. an
  embodied spoke's binary sensor streams) copied verbatim into
  `content/`, listed in the manifest `sources` bijection (already
  multi-file per spec §6.4), and sealed as ordinary Merkle leaves. Names
  are validated (safe POSIX relative paths; `source.txt` cannot be
  shadowed).
- `CompilerConfig.extra_ext` — spoke-supplied extension tables
  (`{ext_id: rows}`). Ids must be registered and must not collide with
  the tables the kernel compiler derives from candidates
  (`locators@1`/`references@1`/`temporal@1`/`lineage@1`).
- `streams@1` registered in `EXTENSION_REGISTRY` (schema and composite
  sort key `(stream, frame_id, offset)` exactly as recommended by
  `spec/profiles/embodied@1.md` §7).
- Canonical JSONL writer: composite sort keys — a sort key may be a
  sequence of field names; integer components sort numerically
  (fixed-width decimal encoding keeps the whole key one bytewise
  comparison). Extension registry entries now declare their own
  `unique` flag (same values as the previous hard-coded set).

With these, an embodied spoke compiles its full shard (binary streams,
`embodied@1` profile declaration, stream index) through
`compile_generic_shard` in a single pass — no post-compile injection or
resealing in spoke code.

- **RFC 0005 (PROPOSED): attestation shards** — portable proof-of-when.
  Defines the convention for anchoring a shard's manifest bytes in time
  (RFC 3161 / OpenTimestamps) and publishing the proof as an ordinary v1
  shard that cites its target via `references@1`; addresses
  DURABILITY.md §2.4 for arbitrary shards, generalizing the detached
  gold-shard anchors. Registers `attestations@1` in
  `EXTENSION_REGISTRY` (composite sort key
  `(target_shard_id, kind, proof_path)`). No kernel change; the verifier
  never parses proofs.

- **RFC 0006 (PROPOSED): custody evidence extensions** — registers
  `packets@1` (verbatim canonical packet bytes, indexed into `content/`)
  and `tpm-attestation@1` (TPM trust-chain evidence, one row per stored
  blob, indexed by `(file, offset, length, sha256)`) in
  `EXTENSION_REGISTRY`. Both are index-into-content canonical JSONL — no
  binary in the row — so the custody spoke (`axm-sfn`) seals its evidence
  through the one-pass `extra_content`/`extra_ext` compiler instead of a
  two-pass reseal. The TPM table is named `tpm-attestation@1` to avoid
  colliding with RFC 0005's unrelated `attestations@1`. No kernel change.

- **RFC 0007 (PROPOSED): chat extensions** — registers `episodes@1`
  (distilled conversational episode index) and `engineering@1` (gated
  engineering-lens rows, joined on `episode_id`) in `EXTENSION_REGISTRY`.
  Both are canonical JSONL: array-valued domain fields ride as JSON-array
  strings, `confidence` as a decimal string, absent optionals as `""`, and
  `shard_id` is a foreign `sh1_` source reference (never a self id). The
  conversation spoke (`axm-chat`) seals them through the one-pass `extra_ext`
  compiler instead of post-compile Parquet injection + reseal. No kernel
  change; the verifier stays opaque to the tables' semantics.

## [1.0.0rc1] - 2026-07-02 — The v1.0 reset (RFC 0002)

Everything shipped before this entry is reclassified as the **v0.x
prototype lineage** (the "1.0.0"–"1.2.0" entries below were never tagged
or published; their artifacts live on under `archive/v0/`). This change
set implements [RFC 0002](rfcs/0002-v1-reset.md) — accepted 2026-07-02 —
in full, minus the two steps only the maintainer can perform (offline key
ceremony and the v1.0.0 tag; runbook in `RELEASE.md`).

### Changed (breaking — the premise of the RFC; no external dependents exist)
- **One signature suite**: `axm-hybrid1` — `publisher.pub` =
  Ed25519 ‖ ML-DSA-44 public keys (1344 B), `manifest.sig` = both
  signatures (2484 B), verification succeeds iff **both** components
  verify. The manifest `suite` field is required; suite detection by key
  size is deleted, as are the legacy `ed25519` and `axm-blake3-mldsa44`
  suites.
- **One Merkle construction**: domain-separated BLAKE3 with RFC 6962
  odd-node promotion (empty root `BLAKE3(0x01)` =
  `48fc721f…88652b`). The legacy duplicate-odd-leaf construction is
  deleted.
- **Canonical JSONL core tables**: `graph/entities.jsonl`,
  `graph/claims.jsonl`, `graph/provenance.jsonl`, `evidence/spans.jsonl` —
  one canonical-JSON record per line, exact key sets, no nulls/floats,
  rows sorted bytewise by primary key, duplicate keys rejected. **Parquet
  is gone from the shard** and from the kernel dependencies (pyarrow
  dropped); it is demoted to a derived, local, rebuildable query cache
  outside the shard.
- **Derived shard identity**: `shard_id` removed from the manifest;
  identity is `"sh1_" + BLAKE3(canonical manifest bytes).hex()`. A
  manifest containing `shard_id` is rejected. Lineage/references use the
  `sh1_` form for predecessor ids only; the compiler's two-pass
  Merkle/backfill is deleted.
- **Full-length, Unicode-stable identifiers**: full 32-byte SHA-256
  digests, base32 lowercase (52 chars), versioned prefixes `e1_` `c1_`
  `p1_` `s1_`. `canonicalize()` = NFC → ASCII-only lowercasing (not
  `casefold()`) → strip `Cc` controls → collapse whitespace; behavior
  locked by adversarial identity vectors.
- **Full manifest enforcement + domain-separated signing**: every required
  field validated (`spec_version` = `"1.0.0"`, `suite`, `metadata.*` with
  RFC 3339 `Z`-suffix `created_at`, `publisher.*`, `license.spdx`,
  `sources` as a bijection with `content/`, `integrity.*`, `statistics.*`
  equal to actual row counts; closed top-level key set). Signature message
  is `b"axm-genesis/v1/manifest\x00" + manifest_bytes`.
- **REQ 5 became the `embodied@1` profile**: the kernel no longer knows
  about `cam_latents.bin`/`AXLF`/`AXLR`. Manifests declare profiles; the
  verifier result gains `profiles_checked` / `profiles_unchecked`
  (unchecked ≠ passed). `E_BUFFER_DISCONTINUITY` is a profile error code;
  STREAM_FORMAT.md became `spec/profiles/embodied@1.md`.
- **Spec rewritten as `spec/v1/`** (SPECIFICATION.md + CONFORMANCE.md,
  single coherent documents); `spec/v1.0/`, the v0.x gold shard, keys, and
  vectors moved to `archive/v0/`. COMPATIBILITY.md regenerated from the
  new spec.
- Version is 1.0.0rc1, single-sourced from `axm_verify.__version__`.

### Added
- Gold shard v2 (`shards/gold/fm21-11-hemorrhage-v2/`, `axm-hybrid1`,
  JSONL), minted from the same FM 21-11 source — **provisionally signed**
  pending the offline key ceremony (`keys/gold-v2-provisional.pub`;
  caveats in `shards/gold/README.md`).
- `axm-build keygen` (hybrid keypair generation); hybrid signing path.
- Regenerated conformance vectors: manifest-schema violations (one per
  field), sources-bijection, statistics, `shard_id`-present, unknown
  suite, per-component bad signatures, ordering/duplicate-key, adversarial
  Unicode identity cases, profile vectors, and `EXPECTED.md` machine
  ground truth.
- `RELEASE.md`: the maintainer runbook — key ceremony, ceremony re-mint,
  re-attestation (RFC 3161 / OTS / SWH), OTS upgrade, signed v1.0.0 tag,
  GitHub release, PyPI, Zenodo, rc→final version flip.

### Backward Compatibility
- None, by design — RFC 0002's premise is that no external dependents
  exist yet. v0.x artifacts do not verify under the v1 kernel; they are
  preserved (with their original checksums and timestamp attestations)
  under `archive/v0/`.

---

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
