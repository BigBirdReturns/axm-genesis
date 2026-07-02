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

### OpenTimestamps — submitted 2026-07-02, pending Bitcoin anchor

- `gold-manifest.json.ots` — proof submitted to three public calendars
  (b.pool.opentimestamps.org, a.pool.eternitywall.com,
  ots.btc.catallaxy.com)

The proof is *pending* until the calendars anchor into a Bitcoin block
(typically within hours). Upgrade it to a self-contained proof and commit
the result:

```
ots upgrade attestations/gold-manifest.json.ots
ots verify  attestations/gold-manifest.json.ots
```

### Software Heritage — save requests accepted 2026-07-02

Archival of all three repositories was requested and accepted:

- https://archive.softwareheritage.org/browse/origin/https://github.com/BigBirdReturns/axm-genesis/
- https://archive.softwareheritage.org/browse/origin/https://github.com/BigBirdReturns/axm-core/
- https://archive.softwareheritage.org/browse/origin/https://github.com/BigBirdReturns/axm-chat/

SWH re-archives on request; re-trigger after significant merges
(`curl -X POST https://archive.softwareheritage.org/api/1/origin/save/git/url/<repo-url>/`).

## Still open (requires account credentials)

- **Zenodo deposit** (DOI + long-term storage): create a release first,
  then deposit via https://zenodo.org/ (GitHub integration automates this
  per-release). See RELEASE.md on the v1-reset branch.
- **Gold shard v2**: once RFC 0002's key ceremony produces the real
  canonical keypair, mint gold v2 and repeat both timestamp attestations
  over its manifest.
