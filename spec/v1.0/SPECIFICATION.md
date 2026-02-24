# AXM Genesis Specification v1.0.0 (Frozen)

Status: Normative and frozen. Section 11 is an addendum added in v1.1.0 that extends the specification without breaking backward compatibility.

This document defines the AXM Genesis shard format, identifiers, and verification rules.

## 1. Terminology

- Shard: a directory on disk containing immutable, verifiable files.
- Content: raw source files (UTF-8 text, PDFs, images, and so on). The reference release includes a UTF-8 text source.
- Graph: Parquet tables representing entities and claims.
- Evidence: Parquet tables linking claims to byte ranges in content.

## 2. Shard Layout

A shard is a directory with this required layout:

- `manifest.json`
- `sig/manifest.sig`
- `sig/publisher.pub`
- `content/` (one or more source files)
- `graph/entities.parquet`
- `graph/claims.parquet`
- `graph/provenance.parquet`
- `evidence/spans.parquet`

The verifier treats missing required paths as an error.

An optional `ext/` directory may contain extension parquet files. Extensions are Merkle-covered but not required. See Section 10.

## 3. Cryptographic Primitives

- Content hash: SHA-256 over the raw bytes of a content file. Hex lowercase.
- Merkle hash: Blake3.
- Signature: Ed25519 over the raw bytes of `manifest.json` (default suite). For alternative suites, see Section 11.

## 4. Merkle Root (Ed25519 legacy suite)

The Merkle root commits to all files in the shard except:

- `manifest.json`
- all files under `sig/`

This section defines the legacy Merkle construction used when the manifest `suite` field is absent or set to "ed25519". The post-quantum suite uses a different Merkle construction defined in Section 11.3.

Leaf hash for each included file:

`leaf = Blake3( relpath_utf8 + 0x00 + file_bytes )`

Where `relpath_utf8` is the POSIX relative path from the shard root, encoded as UTF-8.

Leaves are sorted by UTF-8 byte order of `relpath_utf8`.

Internal nodes:

- pair adjacent leaves left-to-right
- if the level has an odd count, duplicate the last leaf
- `parent = Blake3(left + right)`

The Merkle root is the final node as lowercase hex.

## 5. Manifest

`manifest.json` is a UTF-8 JSON object.

### 5.1 Canonical JSON for normative artifacts

For canonical artifacts (gold shard and test vectors), the canonical JSON encoding is:

`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`

### 5.2 Required fields

- `spec_version`: string, must equal `"1.0.0"`
- `shard_id`: string, recommended `shard_blake3_<merkle_root>`
- `metadata.title`: string
- `metadata.namespace`: string
- `metadata.created_at`: RFC 3339 timestamp string
- `publisher.id`: string
- `publisher.name`: string
- `license.spdx`: string
- `sources`: array of objects with:
  - `path`: relative POSIX path under `content/`
  - `hash`: SHA-256 hex of that file
- `integrity.algorithm`: must equal `"blake3"`
- `integrity.merkle_root`: lowercase hex Merkle root
- `statistics.entities`: integer
- `statistics.claims`: integer

### 5.3 Optional fields

- `suite`: string identifying the cryptographic suite (Section 11). Absent means Ed25519 legacy.
- `extensions`: array of extension identifiers. Present only when `ext/` is non-empty.

## 6. Identifiers

AXM defines stable, content-addressed identifiers for entities and claims.

### 6.1 Canonicalization

Canonicalization applies to namespace, labels, and predicates:

1. Unicode normalize to NFC
2. Case-fold
3. Remove ASCII control characters (code points < 0x20 and 0x7f)
4. Collapse all whitespace runs to a single ASCII space
5. Trim leading and trailing whitespace

The reference implementation is `axm_verify.identity.canonicalize`.

### 6.2 Entity IDs

`entity_id = "e_" + base32lower( sha256( canon(namespace) + 0x00 + canon(label) )[:15] )`

Where base32lower is RFC 4648 base32, lowercased, without `=` padding.

### 6.3 Claim IDs

Let:

- `subject`: the entity_id string for the subject
- `predicate`: canonicalized predicate
- `object_type`: `"entity"` or `"literal:string"`
- `object_value`:
  - if object_type is `"entity"`, the entity_id string for the object
  - otherwise, canonicalized literal value

`claim_id = "c_" + base32lower( sha256( subject + 0x00 + predicate + 0x00 + object_type + 0x00 + object_value )[:15] )`

## 7. Parquet Tables

All tables are Parquet files with explicit Arrow schemas.

### 7.1 entities.parquet

| Column | Type |
|--------|------|
| entity_id | string |
| namespace | string |
| label | string |
| entity_type | string |

### 7.2 claims.parquet

| Column | Type | Notes |
|--------|------|-------|
| claim_id | string | |
| subject | string | entity_id |
| predicate | string | |
| object | string | entity_id or literal value |
| object_type | string | `entity` or `literal:string` |
| tier | int8 | 0 to 2 |

### 7.3 provenance.parquet

| Column | Type | Notes |
|--------|------|-------|
| provenance_id | string | |
| claim_id | string | |
| source_hash | string | SHA-256 hex of a content file |
| byte_start | int64 | |
| byte_end | int64 | |

### 7.4 spans.parquet

| Column | Type | Notes |
|--------|------|-------|
| span_id | string | |
| source_hash | string | SHA-256 hex of a content file |
| byte_start | int64 | |
| byte_end | int64 | |
| text | string | |

## 8. Evidence Byte Offsets

Byte offsets refer to UTF-8 bytes of the referenced content file.

For every row in `spans.parquet`:

- `source_hash` must match a content file hash from `content/`
- `0 <= byte_start <= byte_end <= len(content_bytes)`
- `content_bytes[byte_start:byte_end].decode("utf-8")` must equal `text`

For every row in `provenance.parquet`:

- `source_hash` must match a content file hash from `content/`
- the byte range must be within bounds

## 9. Verification Rules

A verifier must:

1. Validate layout and required paths
2. Compute Merkle root and compare to `manifest.integrity.merkle_root`
3. Verify signature of `manifest.json` using `sig/publisher.pub` and the appropriate suite (Section 11)
4. Validate Parquet schemas for all required tables
5. Validate references:
   - claims.subject exists in entities
   - claims.object exists in entities when object_type is `entity`
   - provenance.claim_id exists in claims
   - provenance.source_hash exists in content hashes
   - spans.source_hash exists in content hashes
6. Validate evidence byte offset invariants (Section 8)

The reference verifier is `axm-verify` in this repository.

## 10. Extensions

The optional `ext/` directory at shard root holds extension parquet files.

Rules:

- `ext/` is covered by the Merkle tree (Section 4)
- Verifiers that do not understand extensions treat `ext/` as opaque files
- Extensions do not affect core verification (Sections 1-9)
- When `ext/` is non-empty, `manifest.extensions` lists the extension identifiers
- When `ext/` is empty or absent, `manifest.extensions` is omitted to preserve hash stability

Extension naming convention: `ext/<name>@<version>.parquet`

## 11. Cryptographic Suites

*Added in v1.1.0. This section extends the specification without breaking shards created under v1.0.0.*

### 11.1 Suite identification

The optional `suite` field in `manifest.json` identifies which cryptographic suite was used to sign the shard. If `suite` is absent, the shard uses the Ed25519 legacy suite.

### 11.2 Ed25519 (legacy, default)

- Suite identifier: absent (no `suite` field) or `"ed25519"`
- Signature algorithm: Ed25519
- Public key: 32 bytes
- Signature: 64 bytes
- Signature input: raw bytes of `manifest.json`
- Merkle construction: legacy (Section 4)

### 11.3 axm-blake3-mldsa44 (post-quantum)

- Suite identifier: `"axm-blake3-mldsa44"`
- Signature algorithm: ML-DSA-44 (FIPS 204, also known as Dilithium2)
- Public key: 1312 bytes
- Signature: 2420 bytes
- Signature input: raw bytes of `manifest.json`
- Merkle construction:
  - Leaf: `Blake3(0x00 + relpath_utf8 + 0x00 + file_bytes)`
  - Leaves sorted by UTF-8 byte order of `relpath_utf8`
  - Node: `Blake3(0x01 + left + right)`
  - Odd node rule: promote the final unpaired node unchanged (RFC 6962 style)

- Secret key: 2528 bytes; combined format `sk || pk` = 3840 bytes
- Signatures are deterministic: same key + same message = same signature

### 11.4 Suite detection

A verifier determines the suite from:

1. The `suite` field in `manifest.json` (if present), or
2. The size of `sig/publisher.pub` (32 bytes = Ed25519, 1312 bytes = ML-DSA-44)

A verifier that does not support a given suite must report an error rather than silently skip verification.

### 11.5 Backward compatibility

- Shards signed with Ed25519 remain valid indefinitely
- New shards may use `axm-blake3-mldsa44` for post-quantum signatures
- Merkle construction is suite-specific (Section 4 for legacy Ed25519; Section 11.3 for the post-quantum suite)
- Source file content hashes (`sources[].hash`) remain SHA-256 across suites
- Shard layout, required tables, and identifiers remain unchanged across suites
