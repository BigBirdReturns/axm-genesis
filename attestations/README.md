# Attestations

Independent, third-party proofs that the artifacts in this repository
existed no later than the timestamps below. These bind the gold shard to a
point in time *while its cryptography still proves what it proves*: any
future forgery (e.g. after a quantum break of Ed25519) cannot back-date
itself past these anchors.

## What is attested

`gold-manifest.json` — a byte-identical copy of
`shards/gold/fm21-11-hemorrhage-v1/manifest.json` (SHA-256 matches the
committed shard bytes; see `shards/gold/CHECKSUMS.sha256`). The manifest
contains the Merkle root, which commits to every byte of the shard.

## Proofs

### RFC 3161 (freetsa.org) — anchored 2026-07-02 02:43:37 GMT

- `gold-manifest.tsq` — the timestamp query (SHA-256 of the manifest)
- `gold-manifest.tsr` — the signed timestamp response
- `freetsa-tsa.crt`, `freetsa-cacert.pem` — the TSA's certificate chain,
  vendored so verification works even if freetsa.org disappears

Verify:

```
openssl ts -verify \
  -queryfile attestations/gold-manifest.tsq \
  -in attestations/gold-manifest.tsr \
  -CAfile attestations/freetsa-cacert.pem \
  -untrusted attestations/freetsa-tsa.crt
```

### OpenTimestamps — anchored in Bitcoin

- `gold-manifest.json.ots` — **upgraded 2026-07-02 (UTC)**: the proof is
  now a self-contained Bitcoin attestation (block header attestations at
  heights 956302 and 956349). Verify against any Bitcoin node:

```
ots verify -f attestations/gold-manifest.json attestations/gold-manifest.json.ots
```

### Software Heritage — save requests accepted 2026-07-02

Archival of all three repositories was requested and accepted:

- https://archive.softwareheritage.org/browse/origin/https://github.com/BigBirdReturns/axm-genesis/
- https://archive.softwareheritage.org/browse/origin/https://github.com/BigBirdReturns/axm-core/
- https://archive.softwareheritage.org/browse/origin/https://github.com/BigBirdReturns/axm-chat/

SWH re-archives on request; re-trigger after significant merges
(`curl -X POST https://archive.softwareheritage.org/api/1/origin/save/git/url/<repo-url>/`).

## Gold shard v2 (provisional) — anchored 2026-07-02 (UTC)

`gold-v2-manifest.json` is a byte-identical copy of
`shards/gold/fm21-11-hemorrhage-v2/manifest.json` (the provisional,
pre-ceremony sealing). Anchoring it now means even the provisional
artifact has an independent existence date; the ceremony re-mint
(RELEASE.md steps 1–3) repeats this for the final manifest.

- `gold-v2-manifest.tsq` / `gold-v2-manifest.tsr` — RFC 3161 timestamp
  from freetsa.org, verified against the vendored chain:

```
openssl ts -verify \
  -queryfile attestations/gold-v2-manifest.tsq \
  -in attestations/gold-v2-manifest.tsr \
  -CAfile attestations/freetsa-cacert.pem \
  -untrusted attestations/freetsa-tsa.crt
```

- `gold-v2-manifest.json.ots` — OpenTimestamps proof, submitted to the
  public calendars (upgrade with `ots upgrade` once anchored).

Software Heritage archival was re-requested and accepted for all three
repositories after the v1 merge (2026-07-02 UTC).

## Still open (requires account credentials)

- **Zenodo deposit** (DOI + long-term storage): create a release first,
  then deposit via https://zenodo.org/ (GitHub integration automates this
  per-release). See RELEASE.md on the v1-reset branch.
- **Gold shard v2**: once RFC 0002's key ceremony produces the real
  canonical keypair, mint gold v2 and repeat both timestamp attestations
  over its manifest.
