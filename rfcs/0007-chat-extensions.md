# RFC 0007: Chat Extensions — `episodes@1` and `engineering@1`

> **Status: PROPOSED** — drafted 2026-07-03 (UTC). Registers the two extension
> tables the conversation spoke (`axm-chat`) needs so it can seal its distilled
> episodic index and engineering-lens rows through the **one-pass** compiler
> (`extra_ext`) instead of the post-compile Parquet injection + reseal it does
> today. Nothing frozen in `spec/v1` changes; the kernel verifier is untouched
> and stays opaque to these tables' semantics.

## Summary

Register two AXM extensions, both canonical JSONL:

- **`episodes@1`** — one row per episode distilled from a source conversation
  shard: topic/people/tool tags, a question, a resolution state and tone, a
  summary, and lens hints.
- **`engineering@1`** — the gated engineering-lens rows over the episodes whose
  `lens_hints` include `engineering`: problem statement, technologies, failed
  attempts, the adopted solution, an architectural rule, and a confidence.

Both are fed to `compile_generic_shard` via `extra_ext` and sealed in the first
(only) compiler pass. `engineering@1` joins `episodes@1` on `episode_id`.

## Motivation

`axm-chat` distills a conversation shard into a **derived episodic shard**
carrying these two tables. Today it does so with the anti-pattern this kernel
exists to prevent: it compiles the shard, writes `ext/episodes@1.parquet` and
`ext/engineering@1.parquet` into the sealed tree by hand, recomputes the Merkle
root, and **re-signs** the manifest so the injected result looks canonical
(`src/axm_chat/distill.py`). The reseal and the Parquet tables are one linked
control violation: a spoke writing extra material after compile and re-signing
to launder it.

The kernel already ships the sanctioned replacement — `CompilerConfig.extra_ext`
computes and seals registered extension tables in the single compile pass, with
the kernel owning Merkle and signing. The only thing stopping `axm-chat` from
using it is registration: `extra_ext` rejects any id not in
`EXTENSION_REGISTRY`, and these two tables were never registered (and were
Parquet, which canonical JSONL forbids). This RFC registers them.

## Specification

Registration plus an encoding convention. No kernel change: to the verifier a
chat episodic shard is an ordinary v1 shard and verifies under existing rules.

### 1. Canonical JSONL, scalar-only — encoding the non-scalars

Canonical JSONL admits only `string` and `integer` fields (spec §5) — no arrays,
floats, or nulls. The chat tables carry all three shapes, encoded as follows;
the kernel stores them opaquely and `axm-chat` decodes them after verification.

- **Array fields** (`topic_tags`, `people`, `animals`, `tools_places_services`,
  `projects`, `lens_hints`, `core_technologies`, `failed_attempts`) are a compact
  canonical JSON array of strings carried **inside a string value** — e.g.
  `["home","plumbing"]`; an empty list is `[]`. Element order is
  domain-significant and preserved.
- **Decimals** (`confidence`) are a **decimal string** in `[0,1]` — e.g.
  `"0.82"` — never a float. This is the same rule as `references@1.confidence`.
- **Absent optionals** (`question_text`, `solution_adopted`,
  `architectural_rule`) are the empty string `""`, never null.

### 2. `episodes@1`

| key | type | meaning |
|---|---|---|
| `episode_id` | string | primary key, stable within the shard |
| `shard_id` | string | `sh1_` id of the **source** conversation shard (foreign) |
| `batch_index` | integer | distillation batch |
| `timestamp` | string | RFC 3339 |
| `topic_tags` / `people` / `animals` / `tools_places_services` / `projects` | string | JSON array of strings |
| `question_text` | string | the episode's question, `""` if none |
| `state` | string | `resolved` \| `unresolved` \| `abandoned` \| `ongoing` |
| `tone` | string | `positive` \| `neutral` \| `negative` \| `stressed` \| `relieved` \| `mixed` |
| `summary` | string | |
| `lens_hints` | string | JSON array of `engineering` \| `audit` \| `reflect` \| `general` |

Sort key: `episode_id`, unique.

### 3. `engineering@1`

| key | type | meaning |
|---|---|---|
| `episode_id` | string | primary key; **foreign key** to `episodes@1.episode_id` |
| `shard_id` | string | `sh1_` id of the source shard (foreign) |
| `problem_statement` | string | |
| `core_technologies` / `failed_attempts` | string | JSON array of strings |
| `solution_adopted` | string | `""` when unresolved |
| `architectural_rule` | string | `""` when none |
| `confidence` | string | decimal string in `[0,1]`, e.g. `"0.82"` |

Sort key: `episode_id`, unique (one lens row per episode).

### 4. Identity rule

`shard_id` names the **source** conversation shard (`sh1_` form) — a foreign
reference, exactly like `references@1.dst_shard_id`. A shard never records its
own id (the id is the BLAKE3 of its manifest, which hashes its files), so these
rows carry **no derived or self identity** and no binary.

### 5. One-pass sealing — no reseal, ever

The rows MUST be sealed through `extra_ext` in the first (only)
`compile_generic_shard` pass. The spoke MUST NOT write files into a sealed
shard, recompute the Merkle root, or re-sign — that reimplements frozen kernel
surfaces. `axm-chat` MAY query the sealed JSONL however it likes **after**
verification (DuckDB `read_json`, etc.); it MUST NOT reseal.

### 6. Non-goals

- No kernel semantics: the verifier does not parse tags, decode confidence, or
  enforce the `episodes@1`↔`engineering@1` foreign key; `profiles_checked` is
  unaffected. The join and the array/decimal decoding are domain logic.
- No list/float types added to canonical JSONL: the scalar-only core is
  preserved; the non-scalars live inside string values by convention.

## Compatibility

Purely additive. Existing shards, vectors, and verifiers are unaffected; no core
table or manifest field changes. Published extension schemas are frozen — a
future revision is a new id (`episodes@2`, …), never a mutation.

## Reference implementation

- `src/axm_build/ext_schemas.py` — `episodes@1` and `engineering@1` registry
  entries (schemas, `episode_id` sort keys, `unique`).
- `tests/test_rfc0007_chat_extensions.py` — a derived episodic shard compiled
  through `extra_ext`, verified PASS, with the array-string / decimal-string /
  `""`-for-absent encodings round-tripped through the strict reader, and an
  assertion that no `.parquet` file exists in the shard.
- `axm-chat` (the consumer): its `distill.py` drops the two-pass reseal and
  passes `episodes@1`/`engineering@1` rows via `extra_ext`; `engineering_lens.py`
  queries the sealed JSONL instead of `read_parquet`.

## Decision points

| # | Question | Recommendation | Alternative | Resolution |
|---|----------|----------------|-------------|------------|
| D1 | How are the array-valued fields carried? | **JSON-array strings** inside a `string` field (`[]` empty). Keeps canonical JSONL scalar-only; matches the `pcrs` precedent (RFC 0006); kernel stays opaque. | Add a list type to canonical JSONL, or normalise into child tables (`episode_tags@1`, …). | **Resolved: JSON-array strings** (2026-07-03) |
| D2 | How is `confidence` carried? | **Decimal string** in `[0,1]` — same rule as `references@1.confidence`; no floats in canonical JSONL. | A scaled integer (basis points). | **Resolved: decimal string** (2026-07-03) |
| D3 | May the spoke reseal to inject these? | **No** — `extra_ext`, one pass; the reseal path in `distill.py` is the violation this RFC retires. | Permit an authorised reseal (RFC 0004) for post-compile injection. | **Resolved: one-pass only** (2026-07-03) |
