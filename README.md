# AXM Genesis

**Verifiable knowledge shards that work offline, forever.**

## What Is This?

AXM Genesis compiles documents into **signed, cryptographically verifiable knowledge shards**.

A shard is a directory containing:
- **Source documents** (PDFs, text files)
- **Extracted claims** (entities, relationships, provenance)
- **Cryptographic proof** (Merkle root + Ed25519 signature)

Once built, a shard can be:
- Verified offline without trusting the builder
- Queried locally with stable, replayable results over the stored tables and provenance
- Copied, archived, and used forever

---

## Quick Start

### Install
```bash
pip install -e .
```

### Verify the Gold Shard
```bash
axm-verify shard shards/gold/fm21-11-hemorrhage-v1/ --trusted-key keys/canonical_test_publisher.pub
# {"status": "PASS", "error_count": 0, "errors": []}
```

**Windows note (Git Bash):** If the `axm-verify` wrapper fails with permission errors, use:
```bash
python -m axm_verify.cli shard shards/gold/fm21-11-hemorrhage-v1/ --trusted-key keys/canonical_test_publisher.pub
```

### Query the Gold Shard
```bash
python examples/query_shard.py shards/gold/fm21-11-hemorrhage-v1/
```

---

## Build Your Own Shard

AXM Genesis ships a reference toolchain:
- `axm-extract`: extract canonical text from PDF or DOCX
- `axm-build compile`: build a shard from canonical text plus a claims file
- `axm-verify`: verify a shard offline

**Windows note (Git Bash):** If wrapper scripts fail with permission errors, use the module form:
```bash
python -m axm_verify.cli --help
python -m axm_build.cli --help
python -m axm_extract.cli --help
```

### 1. Extract Text from a Document
```bash
axm-extract ./manual.pdf --out ./staging/manual/
# Writes:
#   staging/manual/source.txt
#   staging/manual/chunks.json
```

Or using the module form:
```bash
python -m axm_extract.cli ./manual.pdf --out ./staging/manual/
```

### 2. Create a Claims File
Create `staging/manual/candidates.jsonl` with one JSON object per line:
```jsonl
{"subject":"tourniquet","predicate":"treats","object":"severe bleeding","evidence":"tourniquet can be used to control bleeding","tier":0}
```

**Required fields:**
- `subject`: entity label (string)
- `predicate`: relationship (string)
- `object`: entity label or literal value (string)
- `evidence`: exact text from source.txt that supports this claim (string)
- `tier`: importance tier, 0-2 (integer)

**Optional fields:**
- `object_type`: "entity" (default) or "literal:string"

### 3. Compile the Shard
```bash
axm-build compile staging/manual/source.txt \
  --candidates staging/manual/candidates.jsonl \
  --out shards/manual-v1 \
  --created-at 2026-01-04T00:00:00Z
```

Or using the module form:
```bash
python -m axm_build.cli compile staging/manual/source.txt \
  --candidates staging/manual/candidates.jsonl \
  --out shards/manual-v1 \
  --created-at 2026-01-04T00:00:00Z
```

**Notes:**
- The compiler writes the shard layout: `content/`, `graph/`, `evidence/`, `sig/`, plus `manifest.json`.
- The compiler generates a signing keypair in `sig/` for new shards.
- Evidence text must match byte-for-byte in the normalized source.txt.

### 4. Verify Your Shard
```bash
axm-verify shard shards/manual-v1/ --trusted-key shards/manual-v1/sig/publisher.pub
```

Or using the module form:
```bash
python -m axm_verify.cli shard shards/manual-v1/ --trusted-key shards/manual-v1/sig/publisher.pub
```

---

## The Gold Shard

The repository includes a **gold shard** extracted from FM 21-11 (US Army field manual):
- 8 entities (procedures like "tourniquet", conditions like "severe bleeding")
- 6 claims with byte-level provenance
- Signed with a canonical test key
- **Passes verification**

This shard proves the system works in a domain where hallucination is unacceptable.

---

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

Every claim traces back to exact bytes in the source document, and the shard signature proves nothing was altered. Verification rejects any claim that lacks byte-level evidence or a valid signature chain.

---

## Documentation

- [Specification](spec/v1.0/SPECIFICATION.md) - The frozen protocol definition
- [Conformance](spec/v1.0/CONFORMANCE.md) - Requirements for valid shards
- [Contributing](CONTRIBUTING.md) - How to propose changes (RFC process)

---

## Project Status

This is a **working protocol** with:
- A reference builder (`axm-build`)
- A reference verifier (`axm-verify`)
- A gold shard that passes verification
- Test vectors for reimplementation

It is ready for use and extension.

---

## Reimplementation Notes

AXM Genesis can be reimplemented in any language using only the following primitives:

- Canonical UTF-8 text normalization (lowercase, trim, collapse whitespace)
- Deterministic JSON serialization (sorted keys, no whitespace)
- BLAKE3 for content and Merkle hashing
- Ed25519 for signatures
- Parquet files with explicit schemas and deterministic row ordering

Correctness is defined by the ability to verify the gold shard byte-for-byte.
Any verifier implementation that accepts the gold shard and rejects the invalid test vectors is conformant.

---

## Running Without a Local Environment

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
```

---

## End-to-End Smoke Test (No PDFs Required)
```bash
mkdir -p smoke/staging
printf "The unit must maintain silence.\n" > smoke/staging/source.txt
printf '{"subject":"Unit","predicate":"must maintain","object":"silence","evidence":"maintain silence","tier":0}\n' > smoke/staging/candidates.jsonl

axm-build compile smoke/staging/source.txt \
  --candidates smoke/staging/candidates.jsonl \
  --out smoke/shard_v1 \
  --created-at 2026-01-04T00:00:00Z

axm-verify shard smoke/shard_v1/ --trusted-key smoke/shard_v1/sig/publisher.pub
```

Or using module form:
```bash
python -m axm_build.cli compile smoke/staging/source.txt \
  --candidates smoke/staging/candidates.jsonl \
  --out smoke/shard_v1 \
  --created-at 2026-01-04T00:00:00Z

python -m axm_verify.cli shard smoke/shard_v1/ --trusted-key smoke/shard_v1/sig/publisher.pub
```

---

## License

Apache-2.0
