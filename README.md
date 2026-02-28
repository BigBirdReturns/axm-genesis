# AXM Genesis

**The cryptographic kernel. Compiled knowledge with post-quantum provenance.**

AXM Genesis is the specification and toolchain for creating signed, verifiable knowledge shards. It is the immutable foundation of the AXM ecosystem — every spoke, every hub, every runtime depends on it. Nothing changes here without a frozen-spec RFC.

## What's in a Shard

```
shard/
├── manifest.json          # Metadata, Merkle root, cryptographic suite
├── sig/
│   ├── manifest.sig       # ML-DSA-44 (post-quantum) or Ed25519 signature
│   └── publisher.pub
├── content/
│   ├── source.txt         # Primary document (byte-addressable)
│   └── [domain files]     # e.g. cam_latents.bin for embodied spokes
├── graph/
│   ├── entities.parquet
│   ├── claims.parquet
│   └── provenance.parquet
├── evidence/
│   └── spans.parquet
└── ext/                   # Domain extensions (streams, coords, locators, etc.)
```

Every claim traces to exact bytes in the source document. Tamper any byte → Merkle fails → signature fails → shard rejected.

## Quick Start

```bash
pip install -e .

# Verify the gold shard
axm-verify shard shards/gold/fm21-11-hemorrhage-v1/ \
  --trusted-key keys/canonical_test_publisher.pub

# Run all tests
python -m pytest tests/ -v

# Run the conformance suite only
python -m pytest tests/test_conformance.py -v
```

## Cryptographic Suites

| Suite | Algorithm | Key Size | Sig Size | Default |
|-------|-----------|----------|----------|---------|
| Ed25519 (legacy) | Ed25519 | 32 B | 64 B | Pre-v1.1.0 |
| `axm-blake3-mldsa44` | ML-DSA-44 (FIPS 204) | 1312 B | 2420 B | v1.1.0+ |

Both suites use Blake3 and SHA-256 content hashing. Merkle construction differs by suite (see Specification Sections 4.1 and 4.2). Ed25519 shards remain valid indefinitely.

## The Gold Shard

`shards/gold/fm21-11-hemorrhage-v1/` is the reference shard extracted from FM 21-11, the US Army first aid field manual. It defines correctness:

- Any verifier that **accepts** this shard and **rejects** the invalid test vectors in `tests/vectors/shards/invalid/` is conformant.
- The gold shard is frozen. It will never be recompiled.

## AXM Compatibility Requirements

Spokes that produce shards must satisfy all five requirements:

| Req | Description | Error Codes |
|-----|-------------|------------|
| REQ 1 | Manifest integrity | `E_SIG_INVALID`, `E_MERKLE_MISMATCH` |
| REQ 2 | Content identity | `E_MERKLE_MISMATCH`, `E_REF_SOURCE` |
| REQ 3 | Lineage events | `E_REF_ORPHAN`, `E_SCHEMA_NULL` |
| REQ 4 | Proof bundle | `E_SIG_INVALID`, `E_SIG_MISSING` |
| REQ 5 | Non-selective recording | `E_BUFFER_DISCONTINUITY` |

REQ 5 applies to spokes that maintain binary hot streams (e.g. embodied robotics). Shards without `content/cam_latents.bin` pass through the check silently.

## Conformance Suite

```bash
python -m pytest tests/test_conformance.py -v
```

Tests REQ 1–5 plus determinism. All 13 tests are active. REQ 5 tests write synthetic `cam_latents.bin` fixtures using the correct `AXLF`/`AXLR` binary format and verify gap detection end-to-end.

## Error Codes

All error codes are prefixed `E_` and defined in `axm_verify/const.py`. The full set with descriptions:

| Code | Meaning |
|------|---------|
| `E_LAYOUT_MISSING` | Required directory or file absent |
| `E_LAYOUT_DIRTY` | Unexpected file in a required directory |
| `E_DOTFILE` | Dotfile found anywhere in shard tree |
| `E_MANIFEST_SYNTAX` | `manifest.json` is not valid JSON |
| `E_MANIFEST_SCHEMA` | `manifest.json` missing required field or wrong type |
| `E_SIG_MISSING` | `sig/manifest.sig` or `sig/publisher.pub` not found |
| `E_SIG_INVALID` | Signature does not verify, key mismatch, or wrong size |
| `E_MERKLE_MISMATCH` | Computed Merkle root ≠ stored value |
| `E_SCHEMA_READ` | Parquet file unreadable or exceeds size limit |
| `E_SCHEMA_MISSING` | Required Parquet file absent |
| `E_SCHEMA_TYPE` | Wrong column name, type, or count |
| `E_SCHEMA_NULL` | Null value in a required column |
| `E_SCHEMA_ENUM` | Invalid `object_type` or `tier` value |
| `E_ID_ENTITY` | `entity_id` does not match recomputed hash |
| `E_ID_CLAIM` | `claim_id` does not match recomputed hash |
| `E_REF_ORPHAN` | Claim subject/object not in entities |
| `E_REF_SOURCE` | Span/provenance points to non-existent file or OOB byte range |
| `E_REF_READ` | Content file unreadable during span verification |
| `E_BUFFER_DISCONTINUITY` | Frame gap in `cam_latents.bin` |

## Documentation

- [Specification](spec/v1.0/SPECIFICATION.md) — frozen protocol
- [Conformance](spec/v1.0/CONFORMANCE.md) — minimum requirements for valid shards
- [Stream Format](STREAM_FORMAT.md) — binary hot stream format (`AXLF`/`AXLR`/`AXRR`)
- [Changelog](CHANGELOG.md) — release history
- [Contributing](CONTRIBUTING.md) — RFC process for spec changes

## Reimplementation

AXM Genesis can be reimplemented in any language using:

- Canonical UTF-8 (NFC normalization)
- Deterministic JSON (sorted keys, no whitespace)
- BLAKE3 for Merkle hashing, SHA-256 for content hashing
- Ed25519 or ML-DSA-44 for signatures
- Parquet with explicit schemas and deterministic row ordering

Correctness is defined by the gold shard.

## License

Apache-2.0
