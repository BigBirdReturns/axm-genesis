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

**File collection rule** (shared by both suites): every file in the shard is a leaf **except** `manifest.json` and everything under `sig/`.  Leaves are ordered by sorting the POSIX relative path of each file by its UTF-8 bytes.

There are two frozen constructions, selected by the manifest `suite` field (reference implementation: `src/axm_build/merkle.py`):

**`ed25519` (legacy, v1.0):**

```
Leaf  = BLAKE3( relpath_utf8 || 0x00 || file_bytes )
Node  = BLAKE3( left || right )
Odd   = last node at a level is duplicated (Bitcoin style)
Empty = BLAKE3( b"" )
```

**`axm-blake3-mldsa44` (post-quantum):**

```
Leaf  = BLAKE3( 0x00 || relpath_utf8 || 0x00 || file_bytes )   (domain-separated)
Node  = BLAKE3( 0x01 || left || right )                        (domain-separated)
Odd   = last node at a level is promoted unchanged (RFC 6962, no duplication)
Empty = frozen constant 48fc721fbbc172e0925fa27af1671de225ba927134802998b10a1568a188652b
        (= BLAKE3( 0x01 ))
```

The `merkle_root` is the lowercase hex encoding of the root digest.  Both algorithms are frozen.  A verifier built against `axm-genesis 1.0.0` can verify a shard compiled by `axm-genesis 1.9.0`.

### 3. Signature scheme identifiers

| Suite identifier | Algorithm | Status |
|---|---|---|
| `ed25519` | BLAKE3 Merkle (legacy construction) + Ed25519 | Stable (legacy) |
| `axm-blake3-mldsa44` | BLAKE3 Merkle (domain-separated) + ML-DSA-44 (FIPS 204) | Stable |

A manifest with no `suite` field means `ed25519` (legacy).  These identifiers are frozen in `axm_verify.const.KNOWN_SUITES`.  New suites may be added.  Existing suite identifiers will not be reused for different algorithms.  A verifier must reject a shard whose suite identifier it does not recognise.

### 4. Verifier behavior contract

The invocation form is:

```
axm-verify shard <shard_dir> --trusted-key <publisher_pubkey>
```

- stdout always carries a single-line machine-readable JSON result (`{"shard": ..., "status": "PASS"|"FAIL", "error_count": ..., "errors": [...]}`).
- Exit 0 if and only if the shard verifies completely (`status` is `PASS`).
- Exit 1 means verification failed for any non-structural reason (bad signature, Merkle mismatch, schema or manifest violation, orphan reference, ...); stderr carries one human-readable reason line per error (`<code>: <message>`).
- Exit 2 means the shard directory is malformed (missing required files).  Precisely: `<shard_dir>` does not exist or is not a directory, or every reported error code is in `{E_LAYOUT_MISSING, E_SCHEMA_MISSING, E_SIG_MISSING}`.  (Command-line usage errors also exit 2, consistent with this rule.)
- These exit codes are frozen.

### 5. Claim schema (core fields)

The following fields in `claims.parquet` are frozen:

| Field | Type | Semantics |
|---|---|---|
| `claim_id` | string | Stable content-addressed identifier (`c_...`) |
| `subject` | string | `entity_id` of the entity the claim is about |
| `predicate` | string | The relationship or verb |
| `object` | string | `entity_id` or literal value |
| `object_type` | string | Enum: `entity`, `literal:string`, `literal:integer`, `literal:decimal`, `literal:boolean` |
| `tier` | int8 | Evidence tier, 0–4 |

These are exactly the columns of `axm_verify.const.CLAIMS_SCHEMA`; the `object_type` and `tier` value sets are frozen in `VALID_OBJECT_TYPES` and `VALID_TIERS`.  Additional fields may be added in minor versions.

### 6. Extension table naming

Extension tables follow the pattern `<name>@<version>.parquet`.  The `@<version>` suffix is part of the name.  `lineage@1.parquet`, `temporal@1.parquet`, and `references@1.parquet` are the first stable extensions.  Their normative Arrow schemas are defined in `src/axm_build/ext_schemas.py`; the extension protocol rules (Merkle coverage, `manifest.extensions` listing, opaque handling by older verifiers) are in `spec/v1.0/SPECIFICATION.md` section 10.

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
