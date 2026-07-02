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

Building a new spoke? The adoption kit is [docs/ADOPTING.md](docs/ADOPTING.md)
plus the copy-and-rename starter at [templates/spoke-template/](templates/spoke-template/).

## Quick start

```bash
make install        # pip install -e ".[dev]"
make test           # full conformance suite
make verify-frozen  # sha256 check that the gold shard bytes are untouched

# Verify the gold shard (v2, axm-hybrid1) — exit 0, status PASS
axm-verify shard shards/gold/fm21-11-hemorrhage-v2 \
  --trusted-key keys/gold-v2-provisional.pub
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
├── manifest.json          # Canonical JSON: metadata, Merkle root, suite
├── sig/
│   ├── manifest.sig       # Hybrid signature: Ed25519 ‖ ML-DSA-44 (2484 B)
│   └── publisher.pub      # Hybrid public key (1344 B)
├── content/
│   └── source.txt         # Primary document(s), byte-addressable
├── graph/
│   ├── entities.jsonl     # Canonical JSONL core tables —
│   ├── claims.jsonl       #   one canonical-JSON record per line,
│   └── provenance.jsonl   #   sorted bytewise by primary key
├── evidence/
│   └── spans.jsonl
└── ext/                   # Optional extensions (opaque to the kernel)
```

There is no Parquet in the shard. A runtime may build a derived, local,
rebuildable query cache in any format it likes — outside the shard, never
Merkle-covered, never normative.

## Cryptographic suite

| Suite | Algorithm | Key size | Sig size | Status |
|-------|-----------|----------|----------|--------|
| `axm-hybrid1` | Ed25519 ‖ ML-DSA-44 (FIPS 204); **both** components must verify | 1344 B | 2484 B | The only suite; `suite` field required |

One suite, one Merkle construction (domain-separated BLAKE3, RFC 6962
odd-node promotion), one domain-separated signature message
(`b"axm-genesis/v1/manifest\x00" + manifest_bytes`). A future break of
either signature algorithm — quantum against Ed25519, cryptanalytic
against the lattice — leaves the other component holding.
COMPATIBILITY.md §2–§3 state the constructions exactly.

> **Roadmap.** [RFC 0002](rfcs/0002-v1-reset.md) — the v1.0 reset — is
> **implemented on this branch**: hybrid suite, canonical JSONL core
> tables, derived shard identity, full manifest enforcement,
> Unicode-independent canonicalization, profiles, gold shard v2.
> Pending before the freeze is declared: the offline key ceremony
> (re-mint of gold v2 under the canonical publisher key) and the v1.0.0
> tag — the maintainer runbook is [RELEASE.md](RELEASE.md).

ML-DSA-44 needs a backend, with this preference ordering:

```bash
pip install -e ".[mldsa]"         # liboqs-python (preferred C bindings)
pip install -e ".[mldsa-compat]"  # dilithium-py (pure-Python fallback)
```

Keys are generated with `axm-build keygen <outdir> --name <publisher>`:
a 3904-byte hybrid secret blob (keep it offline) and the 1344-byte public
key. The builder deliberately has no default signing key.

## The gold shard

`shards/gold/fm21-11-hemorrhage-v2/` is the reference shard, extracted from
FM 21-11 (US Army first aid field manual) and minted under `axm-hybrid1`.
It defines correctness:

- A verifier that **accepts** this shard and **rejects** every invalid vector
  in `tests/vectors/shards/invalid/` is conformant.
- The gold shard is frozen — CI enforces this with byte-level checksums
  (`shards/gold/CHECKSUMS.sha256`).
- Its current signature is **provisional**: the signing key was generated in
  a cloud session (private half destroyed after one use), pending the
  RFC 0002 offline key ceremony. The honest trust model is in
  [`shards/gold/README.md`](shards/gold/README.md); independent existence
  proofs (RFC 3161 timestamp, OpenTimestamps, Software Heritage archival)
  are committed under [`attestations/`](attestations/).
- The v0.x gold shard (`fm21-11-hemorrhage-v1`, Ed25519, Parquet) is
  archived history at [`archive/v0/`](archive/v0/README.md) — kept, not
  normative.

## Compatibility requirements

Spokes that produce shards must satisfy the four kernel requirements;
domain checks live in profiles:

| Req | Description | Error codes |
|-----|-------------|------------|
| REQ 1 | Manifest integrity | `E_MANIFEST_SCHEMA`, `E_SIG_INVALID` |
| REQ 2 | Content identity | `E_MERKLE_MISMATCH`, `E_REF_SOURCE` |
| REQ 3 | Traceable lineage | `E_REF_ORPHAN`, `E_ID_CLAIM`, `E_SCHEMA_*` |
| REQ 4 | Proof bundle | `E_SIG_INVALID`, `E_SIG_MISSING` |

The former REQ 5 (non-selective recording for embodied hot streams) is now
the [`embodied@1` profile](spec/profiles/embodied@1.md): shards declare
`"profiles": ["embodied@1"]` in the manifest, verifiers that implement a
listed profile must run it, and verifiers that don't must report it as
**unchecked** — silence never impersonates verification. Its error code
`E_BUFFER_DISCONTINUITY` is a profile code, not a kernel code. The kernel
error-code table lives in `src/axm_verify/const.py` and spec §14.

## Documentation

| Document | What it is |
|---|---|
| [spec/v1/SPECIFICATION.md](spec/v1/SPECIFICATION.md) | The frozen protocol (normative) |
| [spec/v1/CONFORMANCE.md](spec/v1/CONFORMANCE.md) | What a conforming shard and verifier must do |
| [spec/profiles/embodied@1.md](spec/profiles/embodied@1.md) | The `embodied@1` profile (hot-stream continuity; formerly STREAM_FORMAT.md + REQ 5) |
| [COMPATIBILITY.md](COMPATIBILITY.md) | What is frozen and what may change — machine-checked against the code by `tests/test_compatibility_contract.py` |
| [RELEASE.md](RELEASE.md) | Maintainer runbook: key ceremony, gold re-mint, attestations, tag, PyPI, Zenodo |
| [CONTRIBUTING.md](CONTRIBUTING.md) | RFC process; gold-shard policy; what CI enforces |
| [docs/ADOPTING.md](docs/ADOPTING.md) | How to build a spoke — the adoption kit (keys, compile→verify, conformance in CI, ext/, profiles, runtime registration) |
| [templates/spoke-template/](templates/spoke-template/) | Minimal working spoke package — copy, rename, replace the extractor; ships the tamper-roundtrip test |
| [rfcs/](rfcs/README.md) | Design decisions with status — the project's durable decision log |
| [docs/DURABILITY.md](docs/DURABILITY.md) | The 30-year durability assessment and remediation status |
| [docs/ERRATA.md](docs/ERRATA.md) | Corrections to published artifacts that cannot be edited |
| [papers/](papers/README.md) | The design paper (explanatory, not normative) + errata pointer |
| [attestations/](attestations/README.md) | RFC 3161 / OpenTimestamps / Software Heritage existence proofs |
| [archive/v0/](archive/v0/README.md) | The v0.x prototype lineage (old spec, gold shard, vectors) — historical, not normative |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [tests/vectors/](tests/vectors/) | Conformance ground truth — frozen once added |

## Reimplementation

AXM Genesis can be reimplemented in any language from the spec and vectors
alone, using primitives a stranded implementer can rebuild in 2056:
UTF-8 with NFC normalization, canonical JSON (sorted keys, no whitespace),
SHA-256 for content hashing and identifiers, BLAKE3 for the Merkle tree and
shard identity, and Ed25519 + ML-DSA-44 for the hybrid signature. That's
the whole list — the JSONL move took Parquet off the verification-critical
path, which was the point. Correctness is defined by the gold shard and the
test vectors — an implementation that passes them is conformant, whatever
language it's written in.

## License

Apache-2.0
