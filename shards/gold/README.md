# Gold Shard

The gold shard (`fm21-11-hemorrhage-v1/`) is the definition of correctness.
It is **frozen bytes**: it is never regenerated, and every byte under
`shards/gold/fm21-11-hemorrhage-v1/` must remain exactly as committed.

It was originally built from the FM 21-11 markdown source with:

```bash
axm-build gold-fm21-11 path/to/fm21-11.md <some-other-outdir>/
```

That command remains available for reproduction experiments into a *different*
output directory — never run it against `shards/gold/`. It now requires an
explicit signing key (`--private-key` or `AXM_SIGNING_KEY_HEX`); see below for
why there is no default.

The gold shard uses Ed25519 (legacy suite, no `suite` field in manifest).
It must pass verification under both v1.0 and v1.1 verifiers:

```bash
make verify-gold
```

## What the signature proves — and what it does not

The shard's Ed25519 signature (`sig/manifest.sig`, verified against
`keys/canonical_test_publisher.pub`) was made with a key whose **private half
was historically published in this repository**. Anyone with that key can
produce signatures that validate against the same public key.

Consequently:

- The signature **demonstrates the verification pipeline** and **pins
  integrity**: any modification to the shard's bytes is detected by
  verification.
- The signature does **not** establish authenticity. Authenticity of the gold
  shard rests on the git history of this repository, not on that signature.

For the same reason, the builder CLI no longer ships a default signing key —
you must supply your own.

See `docs/DURABILITY.md` for the planned remediation: a detached attestation
and timestamping of the frozen gold-shard bytes.
