# AXM Genesis

**Knowledge you can own, verify, and keep.**

## The Problem

Right now, almost all "AI knowledge" has these properties:

- It only exists at inference time
- It is recomputed over and over
- You cannot inspect it
- You cannot move it
- You cannot verify where it came from
- You cannot keep it without paying rent

Even when the answer is correct, it evaporates.

## The Solution

AXM Genesis compiles documents into **signed, verifiable knowledge shards** that work offline, forever.

It splits AI into two phases:

**Phase 1: Expensive extraction (done once)**
- Large models read documents
- Extract entities and claims
- Bind every claim to byte-level source evidence
- Sign and Merkle-root the result
- Freeze it

**Phase 2: Cheap use (forever)**
- Small models, scripts, or humans query the frozen shard
- Offline, deterministically, without recomputation
- Without trusting the builder
- Without calling an API

Knowledge becomes **compiled**, not performed.

## What's in a Shard

A shard is a directory containing:

```
manifest.json          # Signed metadata + Merkle root
sig/                   # Ed25519 signature + public key
content/               # Source documents
graph/
  entities.parquet     # Things (procedures, conditions, tools)
  claims.parquet       # Facts (tourniquet treats severe_bleeding)
  provenance.parquet   # Which claim came from which bytes
evidence/
  spans.parquet        # The actual source text for each claim
```

Every claim traces back to exact bytes in the source document. No hallucination can survive verification.

## Quick Start

```bash
# Install
pip install -e .

# Verify the gold shard
axm-verify shard shards/gold/fm21-11-hemorrhage-v1/ --trusted-key keys/canonical_test_publisher.pub
# {"status": "PASS", "error_count": 0, "errors": []}

# Query it
python examples/query_shard.py shards/gold/fm21-11-hemorrhage-v1/
```

## The Gold Shard

The repository includes a gold shard extracted from FM 21-11, the US Army's field manual for first aid. It contains:

- 8 entities (procedures like "tourniquet", conditions like "severe bleeding")
- 6 claims with byte-level provenance
- Signed with a canonical test key
- Passes verification

This shard proves the system works in a domain where hallucination is unacceptable.

## Why This Matters

Cloud AI companies profit because:
- Every question triggers compute
- Every answer disappears
- You must ask again tomorrow

AXM Genesis inverts this:
- Pay once to compile knowledge
- Keep the output forever
- Copy it, verify it, run it offline
- Nobody can revoke it

This is the same shift Linux made: from time-sharing to personal computing, from vendor permission to user possession.

AXM does that for knowledge.

## Documentation

- [Specification](spec/v1.0/SPECIFICATION.md) - The frozen protocol definition
- [Conformance](spec/v1.0/CONFORMANCE.md) - Minimum requirements for valid shards
- [Contributing](CONTRIBUTING.md) - How to propose changes (RFC process)

## Project Status

This is a working protocol with:
- A reference verifier (`axm-verify`)
- A gold shard that passes verification
- Test vectors for reimplementation
- Governance documents for community development

It is ready for use and extension.

## License

Apache-2.0


## Reimplementation Notes

AXM Genesis can be reimplemented in any language using only the following primitives:

- Canonical UTF-8 text normalization (lowercase, trim, collapse whitespace)
- Deterministic JSON serialization (sorted keys, no whitespace)
- BLAKE3 for content and Merkle hashing
- Ed25519 for signatures
- Parquet files with explicit schemas and deterministic row ordering

Correctness is defined by the ability to verify the gold shard byte-for-byte.
Any verifier implementation that accepts the gold shard and rejects the invalid test vectors is conformant.

## New tooling (v1.1.0)

This release adds three production-grade components that sit **alongside** the shard protocol. They do **not** change the shard directory layout, manifest fields, hashing rules, or any existing “golden shard” fixtures.

### 1) `axm-extract` (Pattern 4: Miner)

Extract canonical, normalized UTF-8 text from PDF/DOCX.

```bash
axm-extract ./manual.pdf --out ./staging/manual/
# writes:
#   staging/manual/source.txt
#   staging/manual/chunks.json
```

### 2) `axm-build compile` (Pattern 3: Factory)

Compile a shard from canonical text plus a claims file.

```bash
axm-build compile ./staging/manual/source.txt \
  --candidates ./staging/manual/candidates.jsonl \
  --out ./shards/manual-v1 \
  --created-at 2026-01-04T00:00:00Z
```

### 3) `axm-judge` (Pattern 2: Disk is Truth)

Scan and adjudicate stream evidence:

- Discovers residual records by scanning `cam_residuals.bin` (no JSON pointers).
- Verifies latent offsets against strict math for drift detection.
- Writes an evidence index at `evidence/streams.parquet`.

```bash
axm-judge ./capsule_dir
```

See `STREAM_FORMAT.md` for the on-disk stream contract.

## Running without a local environment

You can run AXM Genesis in any hosted Python environment:

- **GitHub Codespaces**: open the repository in a codespace, then run `pip install -e .`.
- **GitHub Actions**: run the test suite on every push.
- **Google Colab**: clone the repo and run the CLIs in a notebook.

Minimal verification commands:

```bash
pip install -e .
pytest -q
axm-verify --help
axm-build --help
axm-extract --help
axm-judge --help
```

## End-to-end smoke test (no PDFs required)

```bash
mkdir -p smoke/staging
printf "The unit must maintain silence.\n" > smoke/staging/source.txt
printf '{"subject":"Unit","predicate":"must maintain","object":"silence","evidence":"maintain silence","tier":0}\n' > smoke/staging/candidates.jsonl

axm-build compile smoke/staging/source.txt \
  --candidates smoke/staging/candidates.jsonl \
  --out smoke/shard_v1 \
  --created-at 2026-01-04T00:00:00Z

axm-verify smoke/shard_v1 --trusted-key smoke/shard_v1/sig/publisher.pub
```
