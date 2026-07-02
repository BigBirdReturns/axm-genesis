# RFC 0005: Attestation Shards — Portable Proof-of-When

> **Status: PROPOSED** — drafted 2026-07-02 (UTC). Addresses
> [`docs/DURABILITY.md`](../docs/DURABILITY.md) §2.4 ("signatures prove
> *who*, never *when*") for arbitrary shards, generalizing the detached
> gold-shard anchors in [`attestations/`](../attestations/README.md) into
> a self-describing, verifiable, citable artifact. Nothing frozen in
> `spec/v1` changes; the kernel verifier is untouched.

## Summary

Define the **attestation shard**: an ordinary v1 shard whose content is a
timestamp proof (RFC 3161 response, OpenTimestamps proof, or both) over
another shard's manifest bytes, whose claims state what was anchored,
where, and when, and whose `ext/references@1` row cites the target shard
by derived `sh1_` identity. Register one extension table,
`attestations@1`, so anchor metadata is machine-readable. The result: the
proof that a record existed at a point in time travels the same rails as
the record itself — content-addressed, signed, offline-verifiable.

## Motivation

A shard signature authenticates the publisher; it says nothing about
time, because `metadata.created_at` is self-asserted. Long-horizon
verification ("this incident record predates the key leak / the
algorithm break / the lawsuit") requires an out-of-band time anchor over
the shard bytes. The repository already does this for the gold shard with
detached files under `attestations/`, but detached files have no
identity, no signature, no citation mechanism, and no standard layout a
downstream verifier can discover.

Embodied spokes sharpen the need: a robot that seals an incident queues a
timestamp query at the moment of the event and anchors it when
connectivity returns. That anchor must be handed to insurers and courts
*with* the incident — as evidence, not as loose files.

## Specification

All of the following is a **convention plus one registered extension**.
It requires no kernel change: to the verifier, an attestation shard is an
ordinary v1 shard and verifies under the existing rules.

### 1. Anchoring target

The anchored digest MUST be computed over the target shard's canonical
`manifest.json` bytes. The manifest commits to the Merkle root, which
commits to every byte of the target shard, so timestamping the manifest
pins the entire record. The target's identity is
`sh1_ + BLAKE3(manifest bytes)` per spec §9.

### 2. Content layout

An attestation shard's `content/` MUST carry, listed in the `sources`
bijection like any content file:

- `source.txt` — the human-readable anchor record (evidence spans for the
  claims below);
- a byte-identical copy of the target's `manifest.json` (conventionally
  `target-manifest.json`);
- the raw proof artifact(s): the RFC 3161 query and response
  (conventionally `manifest.tsq`, `manifest.tsr`) and/or an
  OpenTimestamps proof (`manifest.json.ots`).

A verifier of the *proof* recomputes SHA-256 over the embedded manifest
copy, checks it equals the digest inside the proof artifact, checks the
copy's BLAKE3 equals the cited target id, and then verifies the proof
with standard tooling (`openssl ts -verify`, `ots verify`). All of this
is offline and independent of the kernel.

### 3. Claims

For each anchor, the shard SHOULD state (namespace at the publisher's
discretion; tier 1):

| predicate | object |
|---|---|
| `target_shard_id` | the `sh1_` id (literal:string) |
| `digest_sha256` | SHA-256 hex of the target manifest bytes |
| `anchor_kind` | `rfc3161` or `opentimestamps` |
| `anchor_authority` | TSA URL or calendar identifier |
| `anchored_at` | the authority-asserted time, RFC 3339 UTC |

`anchored_at` is extracted from the proof (the `genTime` of an RFC 3161
token; the Bitcoin block time of an upgraded OTS proof) and is advisory
convenience — **the proof artifact is authoritative**, exactly as stream
offsets in an embodied event log are advisory and the binary is truth.

### 4. Citation

The claim carrying `target_shard_id` MUST reference the target via
`ext/references@1` with `relation_type: "cites"`,
`dst_object_type: "shard"`. This is what makes the anchor discoverable
from graph tooling and keeps the constraint that shard ids in extension
tables refer only to *other* shards (the attestation shard never names
its own id).

### 5. Registered extension `attestations@1`

One row per proof artifact in the shard:

| key | type | meaning |
|---|---|---|
| `target_shard_id` | string | `sh1_` id of the anchored shard |
| `kind` | string | `rfc3161` or `opentimestamps` |
| `authority` | string | TSA URL / calendar identifier |
| `digest_sha256` | string | SHA-256 hex of the target manifest bytes |
| `anchored_at` | string | authority-asserted time, RFC 3339 UTC (advisory) |
| `proof_path` | string | content path of the raw proof, e.g. `content/manifest.tsr` |

Sort key: composite `(target_shard_id, kind, proof_path)`, unique. Like
all of `ext/`, the table is opaque to the kernel verifier; the schema
binds the reference compiler.

### 6. Non-goals

- No kernel semantics: the verifier does not parse timestamp proofs, and
  `profiles_checked` is unaffected. Proof verification is domain logic.
- No re-timestamping policy (RFC 4998-style renewal chains): a renewal
  is simply a *newer attestation shard* over the same target — the
  convention composes with itself; policy for when renewals are required
  is deferred.
- Not a substitute for RFC 0004 reseals: reseal migrates a shard's own
  signature suite; attestation pins bytes in time. They compose.

## Compatibility

Purely additive. Existing shards, vectors, and verifiers are unaffected.
The detached `attestations/` directory for the gold shard remains valid;
it MAY be republished as an attestation shard under this convention.

## Reference implementation

- `src/axm_build/ext_schemas.py` — `attestations@1` registry entry.
- `axm-embodied` (first consumer): queue at seal time, anchor on flush,
  `axm-runtime attest-publish` compiles the anchored entry into an
  attestation shard citing the incident.
