# RFC 0009: AXM Aperture Package Extensions

> **Status: PROPOSED** — drafted 2026-08-05 (UTC). Registers the seven
> canonical JSONL extension tables required to seal a reviewed AXM Aperture
> story package and its exact-edition TimeMaps through the existing one-pass
> compiler. Nothing frozen in `spec/v1` changes. The kernel verifier remains
> opaque to narrative, edition, playback, exposure, and viewer semantics.

## Summary

Register seven additive extension tables:

- `aperture-package-revisions@1`
- `aperture-positions@1`
- `aperture-facts@1`
- `aperture-causal-edges@1`
- `aperture-reveals@1`
- `aperture-edition-maps@1`
- `aperture-sources@1`

Aperture supplies a complete reviewed bundle. The reference wrapper validates
its cross-table semantics and delegates all file writing, canonical JSONL,
Merkle construction, manifest construction, hybrid signing, and self-
verification to `compile_generic_shard` through `CompilerConfig.extra_ext`.
There is no extension injection after compile and no second sealing path.

## Authority boundary

Genesis proves which exact bytes were compiled, which publisher signed them,
and whether the shard is intact. It does not decide whether a story claim is
true, whether an edition match is correct, what provider is playing, what a
viewer has encountered, or whether a seek succeeded.

Arc remains narrative authority. Aperture remains edition-resolution and
viewer-state authority. Core may construct a disposable query cache after
Genesis verification. World may project reviewed records. None may replace
Genesis byte or signature authority.

## Encoding law

Every field in all seven tables is a JSON string. Canonical JSONL remains
scalar-only. Domain values are encoded as follows:

- nonnegative integers and positive integers use canonical decimal strings;
- rational rates use reduced `rate_numerator` and positive
  `rate_denominator` decimal strings;
- confidence uses a canonical decimal string in `[0,1]`;
- lists use compact JSON-array strings containing unique strings;
- optional identifiers or interval coordinates use the empty string;
- digests are lowercase SHA-256 strings;
- package and TimeMap identities use their content-addressed prefixes.

The reference wrapper normalizes list order, rational fractions, and decimal
confidence before the generic compiler writes the table. Published rows are
therefore byte-stable under semantically irrelevant input ordering.

## `aperture-package-revisions@1`

One row identifies one reviewed package revision and the exact Arc canonical
story digest and canonical edition it binds.

| key | meaning |
|---|---|
| `package_id`, `revision` | composite primary key |
| `work_id` | stable work identity |
| `canonical_story_digest` | SHA-256 of the exact Arc story object |
| `canonical_edition_id` | canonical edition used by narrative positions |
| `review_state` | candidate, reviewed, published, or superseded |
| `supersedes` | prior package id or empty |
| `edition_time_map_refs_json` | TimeMap ids required by this revision |

Sort key: `(package_id, revision)`, unique.

## `aperture-positions@1`

One row identifies a positive canonical microsecond interval in a package
revision. `parent_id` is empty or names another position in that revision.
`kind` is `sequence`, `scene`, `beat`, or `event`.

Sort key: `(package_id, revision, position_id)`, unique.

## `aperture-facts@1`

One row carries a reviewed proposition, its subject identities, exact source
references, and the canonical position where the viewer can first acquire it.

Sort key: `(package_id, revision, fact_id)`, unique.

## `aperture-causal-edges@1`

One row carries one or more cause facts, one effect fact, reviewed source
references, and `necessary`, `strong`, or `contextual` strength. Every endpoint
must be a fact in the same package revision. Self-causal edges are refused.

Sort key: `(package_id, revision, edge_id)`, unique.

## `aperture-reveals@1`

One row binds a fact to a canonical position and an acquisition mode:
`seen`, `heard`, `explained`, or `outcome-spoiled`. Each fact's declared first
reveal position must have a corresponding reveal row.

Sort key: `(package_id, revision, reveal_id)`, unique.

## `aperture-edition-maps@1`

One row is one piecewise TimeMap segment. All rows sharing `map_id` must retain
one work, provider edition, canonical edition, source-digest set, and review
state. Segment kinds are:

- `mapped`: provider and canonical intervals are present;
- `provider_only`: only the provider interval is present;
- `canonical_only`: only the canonical interval is present.

Provider intervals and canonical intervals are each positive and non-
overlapping within a map. The rate remains an explicit reduced nonnegative
rational. The table does not claim that duration equality proves edition
identity.

Sort key: `(map_id, segment_id)`, unique.

## `aperture-sources@1`

One row binds a package revision to an exact source SHA-256, custody class, and
a boolean string stating whether redistributable text is carried. Source
custody is `public`, `holder_controlled`, or `derived`. Every fact, edge, and
reveal provenance reference must resolve to one source row in the same package
revision.

Sort key: `(package_id, revision, source_id)`, unique.

## Whole-bundle invariants

`compile_aperture_shard` requires all seven tables and at least one row in each.
It refuses unknown tables, unknown or missing fields, non-string values,
duplicate keys, bad identities, bad decimal forms, invalid intervals, unknown
package revisions, broken position parents, missing first reveals, unknown
causal endpoints, unknown provenance sources, incompatible TimeMaps, changed
map identity between segments, and overlapping provider or canonical ranges.

The wrapper receives `extension_rows` separately and requires
`CompilerConfig.extra_ext` to be empty, preventing two competing sources for
one extension. After normalization it calls `compile_generic_shard` exactly
once. Extension files enter the ordinary Merkle tree before the manifest and
signature are produced.

## Verification and trust

The compiler's self-check remains the existing reference behavior. Operators
and consumers must verify with a publisher public key held outside the shard.
An embedded `sig/publisher.pub` is evidence about the signer identity but is
not, by itself, an out-of-band trust decision.

The frozen verifier does not parse these seven schemas. It verifies the exact
extension bytes through the ordinary manifest, Merkle, and signature rules.
Aperture and Core may perform additional semantic validation only after the
Genesis integrity gate passes.

## Compatibility

The change is additive. Existing shards, the gold shard, conformance vectors,
manifest rules, identity derivation, signature suite, and verifier error codes
are unchanged. Published extension versions are immutable. A future schema
change requires an `@2` identifier.

## Reference implementation

- `src/axm_build/aperture_ext_schemas.py` registers the seven closed schemas.
- `src/axm_build/aperture_rows.py` validates and normalizes individual rows.
- `src/axm_build/aperture_bundle.py` enforces whole-package references.
- `src/axm_build/compiler_aperture.py` delegates one-pass compilation.
- `tests/test_rfc0009_aperture_extensions.py` proves registration,
  normalization, refusal, one-pass compilation, canonical extension bytes,
  repeated-build identity, no Parquet, and out-of-band verification.

## Decision record

| # | Question | Resolution |
|---|---|---|
| D1 | Does Genesis interpret story meaning? | No. Genesis seals exact bytes; Arc and Aperture retain domain authority. |
| D2 | How are arrays and decimals represented? | Compact array strings and canonical decimal strings inside scalar JSONL fields. |
| D3 | May a spoke inject the tables after compile? | No. `extra_ext` in the one compiler pass only. |
| D4 | Are local query tables normative? | No. Core caches are disposable and rebuildable from a verified shard. |
| D5 | Does the embedded publisher key establish trust? | No. Operational verification uses an out-of-band trusted key. |
