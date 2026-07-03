# RFC 0006: Custody Evidence Extensions — `packets@1` and `tpm-attestation@1`

> **Status: PROPOSED** — drafted 2026-07-03 (UTC). Registers the two
> extension tables the custody spoke (`axm-sfn`) needs so it can seal its
> TPM trust-chain evidence through the **one-pass** compiler
> (`extra_content` / `extra_ext`) instead of the hand-rolled two-pass
> reseal that [`docs/DURABILITY.md`](../docs/DURABILITY.md) §4 flagged as a
> "Phase 3 reseal primitive in embryo." Nothing frozen in `spec/v1`
> changes; the kernel verifier is untouched (it treats `ext/` as opaque).

## Summary

Register two AXM extensions:

- **`packets@1`** — an index over the verbatim canonical packet bytes of a
  custody journal. The bytes themselves live in `content/` as an ordinary
  Merkle leaf; the table names each packet by `(file, offset, length)` and
  its `packet_sha256`.
- **`tpm-attestation@1`** — the TPM hardware trust-chain evidence for a
  custody journal: one row per stored blob (packet signature, quote
  signature, quote attest blob, quote nonce, signing/AK public area, EK
  certificate). Every binary blob lives in `content/`; each row indexes it
  by `(file, offset, length)` + `sha256`.

Both are canonical-JSONL, index-into-content tables. Neither carries binary
in the row. With them registered, `axm-sfn` compiles its full custody shard
— `cam_latents.bin`, `streams@1`, `packets@1`, `tpm-attestation@1` — in a
single `compile_generic_shard` call and stops reimplementing Merkle
construction, manifest encoding, identity derivation, and signing.

## Motivation

The custody spoke seals what a machine's TPM attested it did. Historically
it did so with a **two-pass reseal**: call the kernel compiler once, then
write extra `content/` and `ext/` files into the sealed shard by hand and
recompute the Merkle root, re-encode the manifest, re-assign a stored
`shard_id`, and re-sign. That is exactly the anti-pattern the kernel
forbids — a spoke must never own signing, hashing, Merkle construction,
manifest encoding, or identity derivation — and it is brittle: a second
independent implementation of four frozen surfaces that must stay
bit-identical to the kernel forever.

The kernel already shipped the sanctioned replacement:
`CompilerConfig.extra_content` (additional content leaves) and
`CompilerConfig.extra_ext` (spoke-supplied registered extension tables),
which the embodied spoke uses for `cam_latents.bin` + `streams@1`. The only
thing stopping the custody spoke from using it is registration: `extra_ext`
rejects any extension id not in `EXTENSION_REGISTRY`, and the custody
spoke's two tables were never registered (and were Parquet, which canonical
JSONL forbids). This RFC registers them.

RFC 0004 (additive reseal layers for signature-suite migration) is a
*different* operation and is **not** a prerequisite: the custody spoke never
needed to migrate an existing shard's suite — it only needed to seal extra
evidence at compile time, which `extra_content`/`extra_ext` does today.

## Specification

All of the following is **registration plus a storage convention**. It
requires no kernel change: to the verifier, a custody shard is an ordinary
v1 shard and verifies under the existing rules.

### 1. Index-into-content (no binary in JSONL)

Canonical JSONL admits only `string` and `integer` fields — no binary, no
floats, no nulls (spec §5). Custody evidence is binary (TPM signatures,
attest blobs, DER certificates, verbatim packet bytes). Therefore the bytes
MUST be stored as content leaves and the tables MUST only **index** them:

- the verbatim/binary bytes are supplied via `extra_content` and become
  ordinary `content/` files, listed in the manifest `sources` bijection and
  sealed as Merkle leaves like any other content;
- each row names the bytes it describes by `file` (a `content/…` path),
  `offset`, `length`, and a `sha256` (hex) over the stored bytes.

This preserves the archival rule already stated for the custody spoke in
[`docs/DURABILITY.md`](../docs/DURABILITY.md) §5.3 — **hash-over-stored-bytes,
not hash-over-recomputable-canonicalization** — and it means a flipped
evidence byte fails as `E_MERKLE_MISMATCH` under the standard verifier, with
no domain logic required.

### 2. `packets@1`

| key | type | meaning |
|---|---|---|
| `seq` | integer | packet sequence number (primary key) |
| `file` | string | content path holding the bytes, e.g. `content/packets.bin` |
| `offset` | integer | byte offset of the packet in that file |
| `length` | integer | packet byte length |
| `packet_sha256` | string | SHA-256 hex of the verbatim canonical packet bytes |

Sort key: `seq`, unique. A verifier recomputes `packet_sha256` over the
stored slice and, for TPM-signed packets, checks it against the signature
carried in `tpm-attestation@1`.

### 3. `tpm-attestation@1`

One row per stored evidence blob (discriminated by `kind` and `field`):

| key | type | meaning |
|---|---|---|
| `kind` | string | `packet_sig` \| `quote` \| `sign_pub` \| `ak_pub` \| `ek_cert` |
| `seq` | integer | sequence bound; `0` for non-sequence key/cert rows |
| `field` | string | `signature` \| `attest` \| `nonce` \| `public` \| `certificate` |
| `alg` | string | algorithm id, e.g. `tpm2:rsapss-2048-sha256:tpmt-signature` |
| `key_fingerprint` | string | SHA-256 hex of the covering key's public-area bytes |
| `file` | string | content path holding this blob |
| `offset` | integer | byte offset of the blob in that file |
| `length` | integer | blob byte length |
| `sha256` | string | SHA-256 hex of the stored blob bytes |
| `pcrs` | string | JSON array of quoted PCR indices; `""` when absent |

Sort key: composite `(kind, seq, field, offset)`, unique — distinct blobs
never share a byte offset in one file, so the strict reader stays ordered.
`key_fingerprint` is the archival key id: SHA-256 over the exact stored
public-area/cert bytes — no TPM Name computation, recomputable from the
shard alone.

### 4. Naming — why `tpm-attestation@1`, not `attestation@1`

The custody spoke previously called this table `attestation@1` (singular).
RFC 0005 registered `attestations@1` (plural) for an unrelated purpose —
timestamp **proof-of-when** anchors over *other* shards. Two near-identical
ids for two different concepts is a footgun. This RFC registers the TPM
table under the unambiguous **`tpm-attestation@1`**; `attestations@1`
remains RFC 0005's proof-of-when table. The custody spoke renames on
adoption. (Fleet's aspirational "node TPM quote at record time" capsule
uses `tpm-attestation@1` as well — it is the same kind of evidence.)

### 5. Non-goals

- No kernel semantics: the verifier does not parse TPM structures; PCR /
  signature checking is domain logic in the spoke's own tooling.
- No `streams@1` change: the embodied stream index is already registered
  and already matches the custody spoke's stream schema; the custody spoke
  simply emits it as canonical JSONL rather than Parquet.
- Not a reseal: this is compile-time sealing, orthogonal to RFC 0004.

## Compatibility

Purely additive. Existing shards, vectors, and verifiers are unaffected; no
core table or manifest field changes. Published extension schemas are
frozen — a future revision is a new id (`packets@2`, …), never a mutation.

## Reference implementation

- `src/axm_build/ext_schemas.py` — `packets@1` and `tpm-attestation@1`
  registry entries (schemas, composite sort keys, `unique`).
- `tests/test_rfc0006_custody_extensions.py` — a shard carrying both tables
  compiled through `extra_content`/`extra_ext`, verified PASS, tables
  round-tripped through the strict reader, and an indexed-byte tamper caught
  as `E_MERKLE_MISMATCH`.
- `axm-sfn` (first consumer): its `compile.py` drops the two-pass reseal and
  passes packet/TPM bytes as `extra_content` and these rows as `extra_ext`.

## Decision points

| # | Question | Recommendation | Alternative | Resolution |
|---|----------|----------------|-------------|------------|
| D1 | How are binary custody blobs carried? | **Index-into-content**: bytes in `content/`, rows carry `(file, offset, length, sha256)`. Mirrors `streams@1`; keeps JSONL blob-free; a flipped byte fails `E_MERKLE_MISMATCH` with no domain logic; honors DURABILITY §5.3. | Inline base64 in the JSONL row — self-contained rows, but fat tables and a base64 decode step in the hash path. | **Resolved: index-into-content** (2026-07-03) |
| D2 | What id for the TPM table? | **`tpm-attestation@1`** — unambiguous against RFC 0005's `attestations@1`. | Keep the singular `attestation@1` and accept the near-collision. | **Resolved: `tpm-attestation@1`** (2026-07-03) |
| D3 | Does removing the custody spoke's reseal need RFC 0004? | **No** — `extra_content`/`extra_ext` already seal compile-time evidence in one pass; RFC 0004 is suite-migration, a different operation. | Block on RFC 0004 acceptance. | **Resolved: independent of 0004** (2026-07-03) |
