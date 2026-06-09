# Extension: `lineage@1`

> **Status: protospec.** Defined but not compatibility-frozen until a tagged
> release explicitly declares it frozen (see COMPATIBILITY.md §6). Columns may
> still change in place until then.

## Summary
`lineage@1` records shard supersession: which prior shards a shard acts on, and
how. It is **predecessor-oriented** — rows describe relationships to *other*
shards. The owning shard is identified by `manifest.shard_id`; lineage rows do
not repeat it.

## Schema (`lineage@1`)

One row per superseded shard, in `ext/lineage@1.parquet`.

| column                | type   | description                              |
|-----------------------|--------|------------------------------------------|
| `supersedes_shard_id` | string | the shard being superseded               |
| `action`              | string | `supersede` \| `amend` \| `retract`      |
| `timestamp`           | string | RFC 3339                                 |
| `note`                | string | optional context (empty string if unset) |

- Sort key / stable join: `supersedes_shard_id`.
- Rows are sorted by `supersedes_shard_id` and deduplicated for determinism.
- The manifest also carries `supersedes: [shard_id, ...]` as a cheap discovery
  hint.

## On disk
- File: `ext/lineage@1.parquet` (spec §10 naming; the `@1` suffix is part of the
  name).
- Manifest: `extensions` lists `lineage@1` when the file is present.
- Single deterministic Merkle pass: no field depends on the owning shard's
  content-addressed id, so the bytes are final before hashing.

## Design note (RFC 0002)
An earlier protospec draft of this schema carried a `shard_id` column intended
to name *this* shard. Because the shard id is the content address computed over
the bytes that included the column, the value could never be consistent — it
required a `__PENDING__` sentinel and a two-pass Merkle backfill, and the
backfilled id still did not match the final manifest `shard_id`. The column was
removed in place while `lineage@1` was still protospec (no published schema, no
test vectors, no external dependents). See `rfcs/0002-lineage-self-reference.md`.

## Backward compatibility
Protospec: no compatibility guarantee until frozen by a tagged release. The
pre-correction shape (with `shard_id` / `__PENDING__` / two-pass build) was never
released, never vectored, and is not preserved.
