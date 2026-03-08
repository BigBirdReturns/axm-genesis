# AXM Genesis — Compatibility Contract

This document defines what is frozen in `axm-genesis` and what may change.  It is the primary stability guarantee for the AXM ecosystem.

---

## What is frozen

The following are considered stable across all `axm-genesis >= 1.x` releases.  A spoke or downstream tool that depends only on these will continue to work without modification.

### 1. Shard directory layout

```
<shard_name>/
  manifest.json
  content/source.txt
  graph/claims.parquet
  graph/entities.parquet
  graph/provenance.parquet
  evidence/spans.parquet
  sig/manifest.sig
  sig/publisher.pub
  ext/                    (extension tables, named <name>@<version>.parquet)
```

Field names and types in `manifest.json` are frozen.  New optional fields may be added in minor versions; existing fields will not be removed or renamed.

### 2. Merkle construction algorithm

```
merkle_root = BLAKE3( sorted( BLAKE3(file_bytes) for each file in shard ) )
```

"Sorted" means lexicographic sort on the relative file path.  This algorithm is frozen.  A verifier built against `axm-genesis 1.0.0` can verify a shard compiled by `axm-genesis 1.9.0`.

### 3. Signature scheme identifiers

| Suite identifier | Algorithm | Status |
|---|---|---|
| `axm-blake3-ed25519` | BLAKE3 Merkle + Ed25519 | Stable |
| `axm-blake3-mldsa44` | BLAKE3 Merkle + ML-DSA-44 (FIPS 204) | Stable |

New suites may be added.  Existing suite identifiers will not be reused for different algorithms.  A verifier must reject a shard whose suite identifier it does not recognise.

### 4. Verifier behavior contract

- `axm-verify <shard_dir>` exits 0 if and only if the Merkle root and signature both check out.
- Exit 1 means verification failed; stderr contains a human-readable reason.
- Exit 2 means the shard directory is malformed (missing required files).
- These exit codes are frozen.

### 5. Claim schema (core fields)

The following fields in `claims.parquet` are frozen:

| Field | Type | Semantics |
|---|---|---|
| `claim_id` | string | Stable unique identifier within the shard |
| `subject` | string | The entity the claim is about |
| `predicate` | string | The relationship or verb |
| `object` | string | The value or target |
| `confidence` | float | 0.0–1.0 |
| `speaker` | string | `"user"` or `"assistant"` |
| `source_span_id` | string | FK into `evidence/spans.parquet` |

Additional fields may be added in minor versions.

### 6. Extension table naming

Extension tables follow the pattern `<name>@<version>.parquet`.  The `@<version>` suffix is part of the name.  `lineage@1.parquet`, `temporal@1.parquet`, and `references@1.parquet` are the first stable extensions.  Their schemas are defined in `spec/extensions/`.

---

## What is not frozen

The following may change in minor or patch versions:

- Internal implementation details of the compiler, signing code, or Merkle builder
- CLI output formatting (human-readable text, not machine-parseable output)
- Default values for optional fields
- Performance characteristics
- README and documentation wording
- Test vector filenames (not the vectors themselves — see below)

---

## Test vectors

The `tests/vectors/` directory contains canonical shards and their expected verification results.  These are frozen once added.  A new vector may be added in a minor version.  An existing vector will never be modified or removed.

Test vectors are the ground truth for verifier compatibility.  A verifier implementation that passes all vectors in `tests/vectors/` is considered conformant.

---

## Versioning policy

`axm-genesis` follows semantic versioning with the following interpretation:

| Change | Version bump |
|---|---|
| Frozen item above is modified in a breaking way | Major (1.x → 2.0) |
| New optional field, new extension spec, new suite identifier | Minor (1.2 → 1.3) |
| Bug fix, doc fix, internal refactor with no behavior change | Patch (1.2.0 → 1.2.1) |

A major version bump is a serious commitment — it means existing shards may not be verifiable by the new version without a migration step.  We intend to avoid this for as long as possible.

---

## What "frozen kernel" means in practice

`axm-genesis` is the only package with write access to the signed shard format.  `axm-core`, `axm-chat`, and all other spokes may read shards and add extension tables via the defined protocol, but they do not modify the Merkle root or re-sign the manifest.  The only exception is the `_reseal_shard()` operation in `distill.py`, which calls Genesis's own compilation path to produce a new shard (not modify an existing one).

This boundary — Genesis compiles and signs, everything else reads — is the invariant that makes long-term verification possible.
