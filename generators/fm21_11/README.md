# FM 21-11 Generator

This directory contains a domain-specific extractor for the FM 21-11 First Aid manual.

It is not part of the core AXM specification.

## Build the gold shard

```bash
axm-build gold-fm21-11 path/to/fm21-11.md shards/gold/fm21-11-hemorrhage-v1/
```

The gold shard uses a fixed test key and a fixed timestamp. It exists to make independent reimplementation possible.
