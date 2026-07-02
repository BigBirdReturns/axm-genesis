# AXM Genesis — Compatibility Contract

This document defines what is frozen in `axm-genesis` and what may change.
It is the primary stability guarantee for the AXM ecosystem, regenerated
from [`spec/v1/SPECIFICATION.md`](spec/v1/SPECIFICATION.md) after RFC 0002
(the v1.0 reset). Where this summary and the spec disagree, the spec and
the conformance vectors win.

Every machine-checkable claim in this document is asserted by
`tests/test_compatibility_contract.py`, so the document cannot silently
drift from the code: the suite identifiers in section 3, the exit-code
contract in section 4, and the claim schema in section 5 are parsed out of
this file and compared against `axm_verify.const` and the CLI's actual
behavior in CI.

---

## What is frozen

The following are stable across all `axm-genesis >= 1.x` releases. A spoke
or downstream tool that depends only on these will continue to work without
modification.

### 1. Shard directory layout

```
<shard>/
  manifest.json             canonical JSON (spec §5–§6)
  sig/manifest.sig          exactly 2484 bytes (hybrid signature)
  sig/publisher.pub         exactly 1344 bytes (hybrid public key)
  content/                  one or more source files, any format
  graph/entities.jsonl      canonical JSONL core table
  graph/claims.jsonl        canonical JSONL core table
  graph/provenance.jsonl    canonical JSONL core table
  evidence/spans.jsonl      canonical JSONL core table
  ext/                      optional extension tables, named <name>@<version>.<suffix>
```

The root item set is closed: exactly the items above, nothing else
(`E_LAYOUT_MISSING` / `E_LAYOUT_DIRTY`). Symlinks and dotfiles are
forbidden anywhere in the tree. Core tables are canonical JSONL — one
canonical-JSON record per line, bytewise-sorted by primary key, no
trailing blank line (spec §11). **Parquet is not part of the shard**; a
runtime may build a derived, local, rebuildable query cache in any format,
outside the shard directory, never Merkle-covered.

### 2. Merkle construction algorithm

There is exactly **one** frozen construction (spec §8; reference
implementation `src/axm_build/merkle.py`). The legacy duplicate-odd-leaf
construction of the v0.x prototype lineage is deleted and MUST NOT be
implemented.

**File collection rule**: every regular file in the shard is a leaf
**except** `manifest.json` and everything under `sig/`. Leaves are ordered
by sorting the POSIX relative path of each file by its UTF-8 bytes,
ascending.

**Construction** (domain-separated BLAKE3, RFC 6962 odd-node promotion):

```
Leaf  = BLAKE3( 0x00 || relpath_utf8 || 0x00 || file_bytes )
Node  = BLAKE3( 0x01 || left || right )
Odd   = last node at a level is promoted unchanged (RFC 6962, no duplication)
Empty = frozen constant 48fc721fbbc172e0925fa27af1671de225ba927134802998b10a1568a188652b
        (= BLAKE3( 0x01 ))
```

`integrity.merkle_root` is the lowercase hex encoding of the root digest.
A verifier built against `axm-genesis 1.0.0` can verify a shard compiled
by any later 1.x version.

### 3. Signature suite identifiers

There is exactly one suite. The manifest `suite` field is **required** and
must equal it; suite detection by key size does not exist and must not be
implemented.

| Suite identifier | Algorithm | Status |
|---|---|---|
| `axm-hybrid1` | BLAKE3 Merkle (section 2) + hybrid Ed25519 ‖ ML-DSA-44 (FIPS 204); verification succeeds iff **both** components verify | Stable |

Key and signature material (spec §7): `publisher.pub` =
`pk_ed25519 (32 B) ‖ pk_mldsa44 (1312 B)` = 1344 bytes; `manifest.sig` =
`sig_ed25519 (64 B) ‖ sig_mldsa44 (2420 B)` = 2484 bytes. Both components
sign the domain-separated message
`b"axm-genesis/v1/manifest\x00" + manifest_bytes`.

A verifier must reject a shard whose suite identifier it does not
recognise. New suites may be added in minor versions; an existing suite
identifier will never be reused for different algorithms.

### 4. Verifier behavior contract

The invocation form is:

```
axm-verify shard <shard_dir> --trusted-key <publisher_pubkey>
```

where the trusted key is the 1344-byte hybrid public key, supplied out of
band. The shard's embedded `sig/publisher.pub` must equal it
byte-for-byte.

- stdout always carries a single-line machine-readable JSON result:
  `{"shard": ..., "status": "PASS"|"FAIL", "error_count": ..., "errors": [...],
  "profiles_checked": [...], "profiles_unchecked": [...]}`.
- `profiles_checked` / `profiles_unchecked` report which manifest-declared
  profiles were run. **Unchecked is not passed** (spec §15.3).
- Exit 0 if and only if the shard verifies completely (`status` is `PASS`,
  including every profile that was run).
- Exit 1 means verification failed for any non-structural reason (bad
  signature, Merkle mismatch, manifest/schema violation, orphan reference,
  profile failure, ...); stderr carries one human-readable reason line per
  error (`<code>: <message>`).
- Exit 2 means the shard directory is structurally malformed. Precisely:
  `<shard_dir>` does not exist or is not a directory, or every reported
  error code is in `{E_LAYOUT_MISSING, E_SCHEMA_MISSING, E_SIG_MISSING}`.
  (Command-line usage errors also exit 2, consistent with this rule.)
- These exit codes are frozen (spec §13.4).

### 5. Claim record schema (core fields)

Each line of `graph/claims.jsonl` is a canonical-JSON record with
**exactly** this key set — no extra keys, no missing keys, no nulls:

| Field | JSON type | Semantics |
|---|---|---|
| `claim_id` | string | Content-addressed identifier, `c1_` + 52 base32 chars (full SHA-256) |
| `subject` | string | `entity_id` of the entity the claim is about |
| `predicate` | string | The relationship or verb |
| `object` | string | `entity_id` (when `object_type` is `entity`) or literal value |
| `object_type` | string | Enum: `entity`, `literal:string`, `literal:integer`, `literal:decimal`, `literal:boolean` |
| `tier` | integer | Evidence tier, 0–4 |

These are exactly the fields of `axm_verify.const.CLAIMS_SCHEMA`; the
`object_type` and `tier` value sets are frozen in `VALID_OBJECT_TYPES` and
`VALID_TIERS`. The other three core tables' key sets are frozen the same
way (spec §11; `ENTITIES_SCHEMA`, `PROVENANCE_SCHEMA`, `SPANS_SCHEMA`).
Adding a field to a core table is a breaking change and requires a new
major format.

### 6. Manifest schema

`manifest.json` is byte-exact canonical JSON with a **closed** top-level
key set (spec §6). Required: `spec_version` (= `"1.0.0"`), `suite`
(= `"axm-hybrid1"`), `metadata.title`, `metadata.namespace`,
`metadata.created_at` (RFC 3339 UTC, `Z` suffix, validated), `publisher.id`,
`publisher.name`, `license.spdx`, `sources` (non-empty; a **bijection**
with the files under `content/`, each with its SHA-256),
`integrity.algorithm` (= `"blake3"`), `integrity.merkle_root` (64 lowercase
hex), `statistics.entities` and `statistics.claims` (must equal actual row
counts). Optional: `profiles`, `extensions`, `supersedes`.

There is **no `shard_id` field** — its presence is `E_MANIFEST_SCHEMA`.
Shard identity is derived:
`shard_id = "sh1_" + hex(BLAKE3(canonical manifest bytes))` (spec §9).

### 7. Identifier derivations

All row identifiers use the **full 32-byte** SHA-256 digest, base32
lowercase, no padding — 52 characters after a versioned prefix: `e1_`
(entity), `c1_` (claim), `p1_` (provenance), `s1_` (span). Entity and
claim IDs are recomputed by the verifier (spec §10.3–§10.4); provenance
and span IDs are checked for syntax and uniqueness.

`canonicalize()` is frozen and Unicode-version-independent (spec §10.1):
NFC normalize → ASCII-only lowercasing (`A–Z` → `a–z`, **not**
`casefold()`) → strip category-`Cc` control characters → collapse
whitespace runs to a single ASCII space and trim.

### 8. Test vector policy

The `tests/vectors/` directory contains canonical inputs/outputs
(identity, Merkle) and complete shards with their expected verification
results. These are **frozen once added**. A new vector may be added in a
minor version. An existing vector will never be modified or removed.

Test vectors are the ground truth for verifier compatibility: a verifier
implementation that passes all vectors in `tests/vectors/` and honors the
behavioral contract of `spec/v1/CONFORMANCE.md` is conformant. If prose
and vectors are ever found to disagree, the vectors govern while the
discrepancy is resolved by RFC.

---

## What is not frozen

The following may change in minor or patch versions:

- Internal implementation details of the compiler, signing code, or Merkle
  builder
- CLI output formatting (human-readable text, not machine-parseable output)
- Default values for optional builder flags
- Performance characteristics and resource-limit policies (which must stay
  generous enough to accept the conformance vectors and the gold shard)
- README and documentation wording
- Test vector filenames (not the vectors themselves — see section 8)

---

## Versioning policy

`axm-genesis` follows semantic versioning with the following
interpretation:

| Change | Version bump |
|---|---|
| Frozen item above is modified in a breaking way | Major (1.x → 2.0) |
| New optional manifest field, new profile, new extension spec, new suite identifier | Minor (1.2 → 1.3) |
| Bug fix, doc fix, internal refactor with no behavior change | Patch (1.2.0 → 1.2.1) |

A major version bump is a serious commitment — it means existing shards
may not be verifiable by the new version without a migration step. The
whole point of the RFC 0002 reset was to make the freeze *before* external
adoption so this never has to happen.

---

## What "frozen kernel" means in practice

`axm-genesis` is the only package with write access to the signed shard
format. Spokes and runtimes may read shards, build local query caches, and
add extension tables via the defined protocol (spec §16), but they do not
modify the Merkle root or re-sign the manifest. Anything a domain needs
beyond the kernel goes into a **profile** (spec §15) or an **extension**,
both of which version independently of the kernel.

This boundary — Genesis compiles and signs, everything else reads — is the
invariant that makes long-term verification possible.
