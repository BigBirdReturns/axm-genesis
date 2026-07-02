# axm-fleet

Fleet sustainment record spoke for AXM. Compiles a `node_record.json` into a
genesis-verifiable shard; an update is a **new** shard that supersedes the
old one through the kernel's lineage extension. Records are never mutated,
they are succeeded.

The control question this spoke answers, for any fleet of deployed assets:

> Can the system prove what is running, who built it, who signed it, what
> dependencies it contains, when it changed, and what key authorized the
> change — offline, with no vendor infrastructure in the loop?

A record shard is a self-contained, offline-verifiable answer. Trust is
anchored to a public key supplied out of band (e.g. escrowed), never to
anything inside the shard. Verification needs no transparency log, no
network, and no reference implementation — the independent Go verifier
(`verifiers/go`), built from the spec and vectors alone, accepts the same
shards.

## The four-beat demo

```bash
./demo.sh
```

1. **RECORD** — compile a node record; verify offline with the trusted key.
2. **PATCH** — compile a successor that `--supersedes` the first. The kernel
   emits `manifest.supersedes` and `ext/lineage@1.jsonl`; `axm-fleet history`
   walks the chain.
3. **TAMPER** — flip one sealed byte → `E_MERKLE_MISMATCH`. Wrong trusted
   key → `E_SIG_INVALID`.
4. **REMOVE THE VENDOR** — verify the same shard with the second,
   independently implemented verifier. The record layer passes its own
   substitution test.

## What a node record is

```
asset       -> what physical node this describes (id, platform, program,
               compute module — the substitutable surface)
image       -> the deployed image and its supply-chain digests
               (image, SBOM, SLSA provenance — by sha256 content address)
components  -> pinned models and firmware, each with version + digest
event       -> why this record exists: deploy | patch | rollback | recovery,
               when, and who authorized it
```

The record document itself becomes the sealed `content/source.txt`; every
claim cites a byte span of it. The record's digests bind the external
artifacts: the shard seals the record, the record's hashes pin the image,
SBOM, provenance statement, models, and firmware. `examples/` carries real
sample artifacts whose digests the example records actually match
(`tests/test_fleet_roundtrip.py::test_artifact_digests_bind`).

## Claim tiers

| Tier | Source | Claims |
|------|--------|--------|
| 0 | digests, key id | Integrity facts — content addresses of image/SBOM/provenance/components, signing key id. Facts, not choices. |
| 1 | configuration | Build id, versions, platform, compute module — the surface a rehost changes. |
| 2 | event | What happened, when, authorized by whom. |

## Usage

```bash
pip install -e '../..[mldsa-compat]'   # the kernel (from its repo root)
pip install -e .                        # this spoke

axm-build keygen /secure/axm-keys --name publisher   # once, offline

# Deploy: first record for an asset
axm-fleet record examples/node-0042.deploy.json pool/deploy \
    --key /secure/axm-keys/publisher.key
# -> prints the derived sh1_ identity (never stored in the shard)

# Patch: successor record, lineage sealed by the kernel
axm-fleet record examples/node-0042.patch.json pool/patch \
    --key /secure/axm-keys/publisher.key --supersedes sh1_<deploy-id>

# Audit: offline, out-of-band trust anchor
axm-verify shard pool/patch --trusted-key /secure/axm-keys/publisher.pub
axm-fleet history pool/
```

Reproducible builds: same record + same key + fixed `--created-at` →
byte-identical manifest, identical `sh1_` id.

## Conformance

The spoke does not check kernel requirements itself — the kernel verifier
runs against the spoke's own output in the test suite
(`pytest tests/ -v`, 9 tests): the tamper roundtrip, the wrong-trusted-key
case, the supersede/lineage chain, artifact-digest binding, reproducible
builds, and cross-verification by the independent Go verifier. Requirements
are defined in [`spec/v1/CONFORMANCE.md`](../../spec/v1/CONFORMANCE.md).

## Relation to the other spokes

`axm-show` seals a *mission authorization* (what may fly, under which
ceiling). `axm-fleet` seals the *fleet lifecycle* (what is running, and how
it got there). `axm-sfn` seals *hardware custody* (what the machine
attested it actually did, TPM-bound). Same kernel, three record types.

A natural next step is a hardware-attestation capsule on fleet records —
an `ext/attestation@1` table carrying the node's TPM quote at record time,
following the conventions axm-sfn established (self-fingerprinting key
rows, algorithm-tagged signature rows, everything recomputable from the
shard alone). The kernel seals it; the claim outlives the TPM's
cryptography.

## Where this lives

This spoke sits in the kernel repository (`spokes/axm-fleet`) as the worked
sustainment demo. It is deliberately self-contained: lift it out with
`cp -r spokes/axm-fleet ../axm-fleet` when it grows a life of its own —
only the tests' in-repo kernel fallback and the demo's Go-verifier path
notice the move, and both degrade gracefully.

## Version

axm-fleet v0.1.0 · depends on axm-genesis ≥1.0.0rc1,<2 (the frozen v1 kernel)
