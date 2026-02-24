# AXM Genesis

**Compiled knowledge with cryptographic provenance.**

AXM Genesis is a specification and toolchain for creating signed, verifiable knowledge shards that work offline, forever. It splits AI into two phases: expensive extraction (done once) and cheap retrieval (forever, without recomputation).

## What's in a Shard

A shard is a directory containing structured claims extracted from source documents, with byte-level provenance linking every claim to the exact text that supports it.

```
shard/
├── manifest.json          # Metadata, Merkle root, cryptographic suite
├── sig/
│   ├── manifest.sig       # Ed25519 or ML-DSA-44 signature
│   └── publisher.pub      # Public key
├── content/
│   └── source.txt         # Original document (byte-addressable)
├── graph/
│   ├── entities.parquet   # Things (procedures, conditions, statutes)
│   ├── claims.parquet     # Facts (tourniquet treats severe_bleeding)
│   └── provenance.parquet # Which claim came from which bytes
└── evidence/
    └── spans.parquet      # The actual source text for each claim
```

Every claim traces back to exact bytes in the source document.

## Quick Start

```bash
pip install -e .

# Verify the gold shard
axm-verify shard shards/gold/fm21-11-hemorrhage-v1/ \
  --trusted-key keys/canonical_test_publisher.pub

# Query it
python examples/query_shard.py shards/gold/fm21-11-hemorrhage-v1/
```

## Cryptographic Suites

Genesis v1.1.0 supports two signing suites:

| Suite | Algorithm | Key Size | Signature Size | Default |
|-------|-----------|----------|----------------|---------|
| Ed25519 (legacy) | Ed25519 | 32 B | 64 B | Pre-1.1.0 shards |
| `axm-blake3-mldsa44` | ML-DSA-44 (FIPS 204) | 1312 B | 2420 B | New shards |

Both suites use Blake3 Merkle trees and SHA-256 content hashing. The signature algorithm is the only difference. Ed25519 shards remain valid indefinitely.

## The Gold Shard

The repository includes a gold shard extracted from FM 21-11, the US Army field manual for first aid:

- 8 entities, 6 claims with byte-level provenance
- Signed with Ed25519 (canonical test key)
- Passes verification
- Defines correctness: any verifier that accepts this shard and rejects the invalid test vectors is conformant

## Documentation

- [Specification](spec/v1.0/SPECIFICATION.md) — The frozen protocol (Sections 1-10) plus the v1.1.0 cryptographic suites addendum (Section 11)
- [Conformance](spec/v1.0/CONFORMANCE.md) — Minimum requirements for valid shards and verifiers
- [Contributing](CONTRIBUTING.md) — RFC process for proposing specification changes
- [Changelog](CHANGELOG.md) — Release history including security patches

## Reimplementation

AXM Genesis can be reimplemented in any language using:

- Canonical UTF-8 text normalization (NFC, case-fold, collapse whitespace)
- Deterministic JSON serialization (sorted keys, no whitespace)
- BLAKE3 for Merkle hashing
- SHA-256 for content hashing
- Ed25519 or ML-DSA-44 for signatures
- Parquet with explicit schemas and deterministic row ordering

Correctness is defined by the ability to verify the gold shard and reject the invalid test vectors.

## License

Apache-2.0
