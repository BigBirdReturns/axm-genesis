# Gold Shard

The gold shard (`fm21-11-hemorrhage-v1/`) is the definition of correctness.
It must be built from the FM 21-11 markdown source:

```bash
axm-build gold-fm21-11 path/to/fm21-11.md shards/gold/fm21-11-hemorrhage-v1/
```

The gold shard uses Ed25519 (legacy suite, no `suite` field in manifest).
It must pass verification under both v1.0 and v1.1 verifiers.
