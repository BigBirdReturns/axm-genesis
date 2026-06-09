# RFC 0002: Lineage Self-Reference (`lineage@1.shard_id`)

**Status:** Accepted — corrected in place (protospec). See Decision below.
**Affects:** `lineage@1` extension schema (protospec — see COMPATIBILITY.md §6)

## Decision (spec owner, accepted)
The original draft of this RFC assumed `lineage@1` was frozen and therefore
recommended introducing a new `lineage@2`. That premise was false. Established
facts at decision time:

- No `lineage@1` schema doc was ever published (`spec/extensions/` did not
  exist). COMPATIBILITY.md's "stable extensions" sentence pointed at a document
  that was never written.
- No frozen test vector contains a lineage file; the guard test had to be
  written from scratch because no fixture exercised lineage.
- The gold shard carries no `ext/`. Nothing fixed, released, or externally
  depended-upon was built on `lineage@1`. **This is still protospec.**

Because `lineage@1` is editable protospec, not a compatibility commitment,
preserving the broken shape as `lineage@2` would be ceremony. **Decision: remove
the self-referential `shard_id` column from `lineage@1` in place, before
freezing it. No `lineage@2` is introduced now.** Option A's direction (drop the
self column) stands; only its versioning conclusion changed, because the facts
did. If a future *frozen* `lineage@1` ever needs to change again, that change
will use `lineage@2`.

The paper trail starts with the spec owner reading the document and accepting it
in their own words. The correction is also announced loudly in CHANGELOG (the
schema changed pre-freeze, the old shape, and why), since the repositories are
public and "no dependents" cannot be fully asserted for strangers — protospec
earns the right to change, not to change silently.

## Summary
The `lineage@1` extension has a `shard_id` column that tries to store the
content-addressed id of the shard the lineage file belongs to. That id is
computed over the bytes that include the column, so it can never be made
consistent. This RFC states the contradiction and proposes resolutions. It
does **not** change behavior yet; it exists so the column's semantics are
decided deliberately rather than left as a latent defect.

## Motivation
Compilation with `supersedes` set uses a two-pass Merkle build
(`compiler_generic.compile_generic_shard`):

1. **Pass 1** — write `ext/lineage@1.parquet` with `shard_id = "__PENDING__"`,
   compute the Merkle root, derive `shard_id = shard_blake3_<root>`.
2. **Backfill** — rewrite the lineage table, replacing `__PENDING__` with the
   pass-1 `shard_id`.
3. **Pass 2** — recompute the Merkle root over the now-changed lineage bytes.
   This pass-2 root is the canonical root and the manifest `shard_id`.

Because the backfill changes the lineage bytes, the pass-2 root necessarily
differs from the pass-1 root. So the `shard_id` embedded in `lineage@1` is the
**pass-1 (pre-image) id**, while the manifest's `shard_id` is the **pass-2 id**.
They cannot be equal. The file embeds an id that is not the id of the shard it
ships in — the record is self-referential and, as written, wrong.

A separate guard
(`tests/test_extensions.py::test_compiler_lineage_ships_without_pending_sentinel`)
ensures the `__PENDING__` sentinel never ships. That guard is necessary but
orthogonal: it proves the backfill ran, not that the embedded id is meaningful.
This RFC is about what the column should *mean*.

## Constraint: the schema is frozen
COMPATIBILITY.md freezes `lineage@1` as a stable extension. Removing or
re-typing the `shard_id` column is a breaking change to a frozen schema and
therefore requires a **new version** (`lineage@2`), not an in-place edit.
Verifiers built against `lineage@1` must continue to read existing shards.

## Options

### Option A — `lineage@2` drops the self column (recommended)
Lineage rows describe only the **predecessors** a shard acts on:
`supersedes_shard_id`, `action`, `timestamp`, `note`. The owning shard is
identified by the manifest (which already carries the `supersedes` hint and the
canonical `shard_id`). No row needs to name its own shard.

- Pro: eliminates the contradiction at the root; no self-reference exists.
- Pro: removes the two-pass backfill entirely — lineage bytes no longer depend
  on the final id, so a single Merkle pass suffices.
- Con: new extension version; writers/readers must learn `lineage@2`.

### Option B — keep the column, redefine it as a pre-image id
Document `lineage@1.shard_id` as the **pass-1 pre-image root**, explicitly *not*
equal to the manifest `shard_id`, retained only as a build artifact.

- Pro: no schema change.
- Con: preserves a confusing field whose value looks like — but is not — the
  shard id; invites exactly the misreading this RFC documents. Breaking on
  *meaning* even though not on shape.

### Option C — exclude lineage bytes from the Merkle
Let the backfill happen after hashing by keeping lineage outside the Merkle
tree, so the final `shard_id` can be written into it.

- **Rejected.** Spec §4/§10 make `ext/` Merkle-covered; excluding it would make
  lineage tamperable without detection, defeating the extension envelope's
  entire purpose.

## Recommendation
Option A. The self-reference is not a bug to patch but a modeling error: a
record should not need to name the container it lives in. `lineage@2` without
the column also deletes the two-pass build and its failure modes. This is a
frozen-schema version bump, so it is the spec owner's decision to make.

## Backward Compatibility
- Existing `lineage@1` shards remain valid — they are signed over their own
  bytes and the gold shard is never regenerated.
- New shards emit `lineage@2`; the manifest `extensions` entry becomes
  `lineage@2`. Verifiers accept both versions.
- No change to non-lineage shards.

## Open questions
- Should `action`/`note` semantics carry over to `lineage@2` unchanged?
- Do any downstream readers depend on `lineage@1.shard_id` today? If so, what is
  the migration window before `lineage@1` is deprecated?
