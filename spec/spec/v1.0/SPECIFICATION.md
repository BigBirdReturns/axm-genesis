# AXM Genesis Specification v1.0.0 (Frozen)

Status: Normative and frozen.

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

## 3. Cryptographic Primitives

- Content hash: SHA-256 over the raw bytes of a content file. Hex lowercase.
- Merkle hash: Blake3.
- Signature: Ed25519 over the raw bytes of `manifest.json`.

## 4. Merkle Root

The Merkle root commits to all files in the shard except:

- `manifest.json`
- all files under `sig/`

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

## 6. Identifiers

AXM defines stable, content-independent identifiers for entities and claims.

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

Schema:

- entity_id: string
- namespace: string
- label: string
- entity_type: string

### 7.2 claims.parquet

Schema:

- claim_id: string
- subject: string (entity_id)
- predicate: string
- object: string (entity_id or literal)
- object_type: string, one of: `entity`, `literal:string`
- tier: int8, 0 to 2

### 7.3 provenance.parquet

Schema:

- provenance_id: string
- claim_id: string
- source_hash: string (SHA-256 hex of a content file)
- byte_start: int64
- byte_end: int64

### 7.4 spans.parquet

Schema:

- span_id: string
- source_hash: string (SHA-256 hex of a content file)
- byte_start: int64
- byte_end: int64
- text: string

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
3. Verify Ed25519 signature of `manifest.json` using `sig/publisher.pub`
4. Validate Parquet schemas for all required tables
5. Validate references:
   - claims.subject exists in entities
   - claims.object exists in entities when object_type is `entity`
   - provenance.claim_id exists in claims
   - provenance.source_hash exists in content hashes
   - spans.source_hash exists in content hashes
6. Validate evidence byte offset invariants in Section 8

The reference verifier is `axm-verify` in this repository.
