# archive/v0 — the v0.x prototype lineage

**Status: historical. Nothing in this directory is normative.**

RFC 0002 ("The v1.0 Reset — Freeze Once, Freeze Right", accepted
2026-07-02) reclassified everything the project shipped before the reset as
the **v0.x prototype lineage**. These artifacts are kept here as history:
they document what the prototype produced, they anchor the timestamp
attestations made over it, and they make the pre-reset behavior
reconstructible — but they are **no longer part of the specification, the
conformance suite, or the trust chain** of AXM Genesis v1.

## What is here

| Path | What it was |
|------|-------------|
| `spec/` | The v0.x specification and conformance documents (formerly `spec/v1.0/`). Superseded by `spec/v1/`. |
| `vectors/identity.json`, `vectors/merkle.json` | v0.x identity and Merkle test vectors (truncated 15-byte IDs, `e_`/`c_` prefixes, legacy duplicate-odd-leaf Merkle cases). Superseded by `tests/vectors/`. |
| `vectors-shards/` | v0.x shard vectors (Parquet tables, legacy Ed25519 suite; formerly `tests/vectors/shards/`). Superseded by `tests/vectors/shards/`. |
| `gold/fm21-11-hemorrhage-v1/` | The v0.x gold shard (Parquet tables, legacy Ed25519 suite, `shard_id` in the manifest). Superseded by `shards/gold/fm21-11-hemorrhage-v2/`. |
| `gold/CHECKSUMS.sha256` | SHA-256 byte pins over the v0.x gold shard. Paths were repointed to this archive location when the shard moved; the hashes themselves are unchanged and still check out (`sha256sum -c archive/v0/gold/CHECKSUMS.sha256` from the repo root). |
| `keys/canonical_test_publisher.pub` | The Ed25519 public key the v0.x gold shard was signed with. Its private half was historically published in this repository, so it pins integrity only — it never proved authenticity. |
| `STREAM_FORMAT.md` | The v0.x hot-stream (`cam_latents.bin` / `AXLF` / `AXLR`) format note. Its normative successor is `spec/profiles/embodied@1.md`; the continuity check left the kernel and became the `embodied@1` profile. |

## Verifying these artifacts

The v0.x gold shard and vectors **do not verify — and must not verify —
under the v1 kernel** (`axm-verify` on this branch and later): the reset
deleted the legacy Ed25519 suite, the duplicate-odd-leaf Merkle
construction, the Parquet table readers, and the `shard_id` manifest field.
To re-verify them, check out pre-reset code from git history (any commit at
or before the RFC 0002 acceptance, e.g. the tree that carried
`spec/v1.0/`) and run that era's verifier.

The byte-level pins remain checkable today: `gold/CHECKSUMS.sha256` above,
and the RFC 3161 and OpenTimestamps attestations under `attestations/` at
the repository root, which anchor the v0 gold shard manifest's existence in
time independently of any signing key.

## Why the reset

See `rfcs/0002-v1-reset.md`. In short: two signature suites, two Merkle
constructions, Parquet on the verification-critical path, truncated
identifiers, an under-enforced manifest, and a gold shard signed by a key
with a published private half — all fixable for free before any external
party depended on the format, and effectively unfixable after. v1
(`spec/v1/`) is the lineage that freezes.
