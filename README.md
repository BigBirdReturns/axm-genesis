# AXM Genesis

[![CI](https://github.com/BigBirdReturns/axm-genesis/actions/workflows/ci.yml/badge.svg)](https://github.com/BigBirdReturns/axm-genesis/actions/workflows/ci.yml)

**The cryptographic kernel. Compiled knowledge with post-quantum provenance.**

AXM Genesis is the specification and toolchain for creating signed, verifiable
knowledge shards. Every claim in a shard traces to exact bytes in a source
document; tamper any byte and the Merkle root fails, the signature fails, and
the shard is rejected. Nothing changes here without a frozen-spec RFC.

The project's discipline is simple: **every claim in these documents is
executable.** The compatibility contract is enforced by tests that parse the
document itself, CI pins the gold shard's bytes with checksums, and the
verifier's exit codes are frozen and exercised by the conformance suite.

## The AXM ecosystem

| Repository | Role | Explainer |
|---|---|---|
| [axm-genesis](https://github.com/BigBirdReturns/axm-genesis) | The frozen cryptographic kernel — compiles and verifies signed knowledge shards | [site](https://bigbirdreturns.github.io/axm-genesis/) |
| [axm-core](https://github.com/BigBirdReturns/axm-core) | The runtime — Spectra query engine, Forge extraction, spoke host | [site](https://bigbirdreturns.github.io/axm-core/) |
| [axm-chat](https://github.com/BigBirdReturns/axm-chat) | The first spoke — turns conversation exports into verified memory | [site](https://bigbirdreturns.github.io/axm-chat/) |

Genesis compiles and signs; everything else reads. That boundary is the
invariant that makes long-term verification possible.

## Quick start

```bash
make install        # pip install -e ".[dev]"
make test           # full suite — 90 passed, 3 skipped
make verify-gold    # verify the gold shard — exit 0, status PASS
make verify-frozen  # sha256 check that the gold shard bytes are untouched
```

The verifier's command form and exit codes are frozen
(see [COMPATIBILITY.md](COMPATIBILITY.md)):

```bash
axm-verify shard <shard_dir> --trusted-key <publisher_pubkey>
# exit 0: verified   exit 1: verification failed   exit 2: malformed shard
```

## What's in a shard

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
└── ext/                   # Domain extensions (streams, coords, locators, …)
```

## Cryptographic suites

| Suite | Algorithm | Key size | Sig size | Default |
|-------|-----------|----------|----------|---------|
| `ed25519` (legacy; absent `suite` field) | Ed25519 | 32 B | 64 B | pre-v1.1.0 |
| `axm-blake3-mldsa44` | ML-DSA-44 (FIPS 204) | 1312 B | 2420 B | v1.1.0+ |

Both suites use BLAKE3 Merkle trees and SHA-256 content hashing; the Merkle
construction differs by suite (COMPATIBILITY.md §2 states both exactly).

> **Roadmap.** [RFC 0002](rfcs/0002-v1-reset.md) — the v1.0 reset — was
> **accepted 2026-07-02**: one hybrid suite (`axm-hybrid1`, Ed25519 ‖
> ML-DSA-44), canonical JSONL core tables, Unicode-independent
> canonicalization, and a gold shard v2 under a real key ceremony.
> Implementation is in progress; the suites above remain the shipped
> surface until it lands.

ML-DSA-44 support is optional, with backend preference ordering:

```bash
pip install -e ".[pq]"         # liboqs-python (preferred C bindings)
pip install -e ".[pq-compat]"  # dilithium-py (pure-Python fallback)
```

For ML-DSA-44 compilation, `private_key` must be `sk||pk` (3840 bytes), or
`sk` alone (2528 bytes) with `sig/publisher.pub` pre-placed — the compiler
preserves a pre-placed key across its output-directory wipe.

## The gold shard

`shards/gold/fm21-11-hemorrhage-v1/` is the reference shard, extracted from
FM 21-11 (US Army first aid field manual). It defines correctness:

- A verifier that **accepts** this shard and **rejects** every invalid vector
  in `tests/vectors/shards/invalid/` is conformant.
- The gold shard is frozen — CI enforces this with byte-level checksums
  (`shards/gold/CHECKSUMS.sha256`).
- Its signature proves **integrity, not authenticity** — the signing key was
  historically published in this repository. The honest trust model is in
  [`shards/gold/README.md`](shards/gold/README.md); independent existence
  proofs (RFC 3161 timestamp, OpenTimestamps, Software Heritage archival)
  are committed under [`attestations/`](attestations/).

## Compatibility requirements

Spokes that produce shards must satisfy all five requirements:

| Req | Description | Error codes |
|-----|-------------|------------|
| REQ 1 | Manifest integrity | `E_SIG_INVALID`, `E_MERKLE_MISMATCH` |
| REQ 2 | Content identity | `E_MERKLE_MISMATCH`, `E_REF_SOURCE` |
| REQ 3 | Lineage events | `E_REF_ORPHAN`, `E_SCHEMA_NULL` |
| REQ 4 | Proof bundle | `E_SIG_INVALID`, `E_SIG_MISSING` |
| REQ 5 | Non-selective recording | `E_BUFFER_DISCONTINUITY` |

REQ 5 applies to spokes that maintain binary hot streams (e.g. embodied
robotics); shards without `content/cam_latents.bin` pass through silently.
The full error-code table lives in `src/axm_verify/const.py`, and every code
is documented in [COMPATIBILITY.md](COMPATIBILITY.md) and the spec.

## Documentation

| Document | What it is |
|---|---|
| [spec/v1.0/SPECIFICATION.md](spec/v1.0/SPECIFICATION.md) | The frozen protocol (normative) |
| [spec/v1.0/CONFORMANCE.md](spec/v1.0/CONFORMANCE.md) | Minimum requirements for a valid shard |
| [COMPATIBILITY.md](COMPATIBILITY.md) | What is frozen and what may change — machine-checked against the code by `tests/test_compatibility_contract.py` |
| [CONTRIBUTING.md](CONTRIBUTING.md) | RFC process; gold-shard policy; what CI enforces |
| [rfcs/](rfcs/README.md) | Design decisions with status — the project's durable decision log |
| [docs/DURABILITY.md](docs/DURABILITY.md) | The 30-year durability assessment and remediation status |
| [docs/ERRATA.md](docs/ERRATA.md) | Corrections to published artifacts that cannot be edited |
| [papers/](papers/README.md) | The design paper (explanatory, not normative) + errata pointer |
| [attestations/](attestations/README.md) | RFC 3161 / OpenTimestamps / Software Heritage existence proofs |
| [STREAM_FORMAT.md](STREAM_FORMAT.md) | Binary hot-stream format (`AXLF`/`AXLR`) |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [tests/vectors/](tests/vectors/) | Conformance ground truth — frozen once added |

## Reimplementation

AXM Genesis can be reimplemented in any language from the spec and vectors
alone, using: canonical UTF-8 (NFC), deterministic JSON (sorted keys, no
whitespace), BLAKE3 for Merkle hashing, SHA-256 for content hashing, Ed25519
or ML-DSA-44 for signatures, and Parquet with explicit schemas. Correctness
is defined by the gold shard and the test vectors — an implementation that
passes them is conformant, whatever language it's written in.

## License

Apache-2.0
