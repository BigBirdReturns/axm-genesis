# RFC 0002: The v1.0 Reset — Freeze Once, Freeze Right

## Summary

Reclassify everything shipped to date as v0.x prototype, and cut the real,
frozen v1.0 before any external party depends on the format. The reset makes
seven changes while they are still free: collapse to a single hybrid
signature suite with one Merkle construction; move the normative tables from
Parquet to canonical JSONL; derive shard identity from the manifest hash;
lengthen and simplify identifiers; enforce the full manifest schema and
domain-separate the signature; move embodied stream continuity (REQ 5) out of
the kernel into a versioned profile; and mint a new gold shard under a real
key ceremony with timestamp attestations. After this RFC lands, the freeze is
real and permanent.

## Motivation

The repository has adopted the posture of a frozen standard — "nothing
changes here without a frozen-spec RFC", a gold shard that "will never be
recompiled" — before shipping a single release. There are no git tags, no
published packages, no second implementation, and no shards in the wild. Yet
the codebase already carries the costs of legacy compatibility:

- **Two Merkle constructions and two signature suites** (spec §4.1/§4.2,
  §11), where the legacy pair exists solely to keep verifying one shard.
- **A gold shard whose signing key is public** — the Ed25519 private key
  behind `keys/canonical_test_publisher.pub` is hardcoded in
  `src/axm_build/cli.py` (`CANONICAL_TEST_PRIVATE_KEY`). Its signature
  authenticates nothing; the "never recompile" pledge is spent protecting an
  artifact that cannot anchor trust.
- **A quantum-vulnerable suite declared "valid indefinitely"** (spec §11.5),
  written into a document that intends to outlive the algorithm.
- **Parquet on the verification-critical path**, contradicting the
  architecture's own thesis that only the query layer is an implementation
  choice.
- **Under-enforced spec**: the reference verifier validates one manifest
  field out of the eleven §5.2 requires.

Every one of these becomes effectively unfixable the moment a third party
compiles a shard or ships a verifier. None of them is fixable-by-addendum
without permanently complicating the spec. The window in which deletion is
cheaper than compatibility is open now and closes at first external adoption.

## Specification

The deltas below are written against `spec/v1.0/SPECIFICATION.md` as it
exists today. The output is a rewritten, single-document `spec/v1/`
(no addenda, no legacy sections), plus regenerated vectors and gold shard.

### D1. Single hybrid signature suite

Replace both existing suites with one:

- **Suite identifier**: `axm-hybrid1` (the `suite` field becomes **required**
  in the manifest; suite detection by key size is deleted).
- **Keys**: `publisher.pub` = `pk_ed25519 (32 B) ‖ pk_mldsa44 (1312 B)`
  = 1344 bytes.
- **Signature**: `manifest.sig` = `sig_ed25519 (64 B) ‖ sig_mldsa44 (2420 B)`
  = 2484 bytes. Both components sign the same message (D5). Verification
  succeeds iff **both** components verify. A break of either algorithm —
  quantum against Ed25519, cryptanalytic against the lattice — leaves the
  other holding.
- **Merkle construction**: exactly the current §4.2 (domain-separated BLAKE3,
  RFC 6962 odd-leaf promotion, empty root `BLAKE3(0x01)`). §4.1 (duplicate
  odd leaf, no domain separation) is deleted. One tree, forever.

Deleted with this change: spec §4.1, §11.2, §11.4, §11.5; the legacy
branches of `axm_build/merkle.py`, `axm_build/sign.py`,
`axm_verify/crypto.py`; suite-sniffing in `axm_verify/logic.py`.

### D2. Canonical JSONL normative tables

The four core tables move from Parquet to canonical JSONL:

```
graph/entities.jsonl
graph/claims.jsonl
graph/provenance.jsonl
evidence/spans.jsonl
```

- **Line encoding**: each record is canonical JSON — the existing manifest
  rule (`sort_keys=True`, separators `(",", ":")`, `ensure_ascii=False`,
  UTF-8, NFC) — followed by a single `\n`. The file is the exact
  concatenation of encoded records; no BOM, no trailing blank line.
- **Row order**: bytewise ascending by primary key (`entity_id`, `claim_id`,
  `provenance_id`, `span_id`). Duplicate primary keys are a verification
  error.
- **Types**: all fields required, no nulls. `byte_start`, `byte_end`, `tier`
  are JSON integers; everything else is a JSON string. No floats in core
  tables.
- **Schema checks**: exact key set per record; `E_SCHEMA_TYPE`,
  `E_SCHEMA_NULL` (now "missing/null field"), `E_SCHEMA_ENUM` keep their
  semantics. `E_SCHEMA_READ` covers malformed JSON lines.

**Parquet is demoted to a derived, local, rebuildable query cache.** It is
not part of the shard, not Merkle-covered, and never written inside the shard
directory; a runtime (e.g. Spectra) builds it at mount time from the JSONL.
`ext/` extensions may still choose any format, including Parquet — they are
opaque to the kernel.

Rationale: verification must survive 30 years on primitives a stranded
implementer can rebuild from the spec alone — UTF-8, JSON, SHA-256, BLAKE3,
Ed25519, ML-DSA. Deterministic Parquet emission is not reproducible across
library versions (encodings, metadata, compression drift), which silently
breaks the "same input → same shard" claim; canonical JSONL is reproducible
by construction. This applies the paper's own compile-time/query-time split
to the format itself.

### D3. Shard identity = manifest hash

- `shard_id` is **removed from the manifest** and becomes a derived value:

  `shard_id = "sh1_" + hex( BLAKE3( canonical manifest bytes ) )`

- Because the manifest contains `integrity.merkle_root`, the identity now
  commits to content **and** metadata **and** publisher **and** suite.
  Today `shard_id` equals the Merkle root, so two shards with identical
  content but different publishers or licenses share an identity — and
  `ext/references` cross-links cannot distinguish them. After D3, every
  cross-shard reference binds to the exact sealed artifact.
- `ext/lineage` and `ext/references` schemas use the derived `sh1_` form.
  The two-pass Merkle/backfill dance in `compiler_generic.py` is replaced by:
  write lineage with the *predecessor's* id (always known), no self-id in
  lineage rows (a shard's own id is ambient — it is the manifest hash).

### D4. Identifiers: full-length and Unicode-stable

- Entity/claim/provenance/span IDs use the **full 32-byte** SHA-256 digest
  (base32lower, no padding), not `digest[:15]`. Prefixes become versioned:
  `e1_`, `c1_`, `p1_`, `s1_`. This deletes the 120-bit birthday-bound caveat
  from the spec permanently.
- `canonicalize()` is simplified to be Unicode-version-independent:
  1. NFC normalize (Unicode version pinned normatively in the spec, with
     conformance vectors)
  2. **ASCII-only lowercasing** (`A–Z → a–z`; replaces `str.casefold()`,
     whose mappings drift across Unicode versions)
  3. Strip category-`Cc` control characters
  4. Collapse whitespace runs to a single ASCII space; trim
- `tests/vectors/identity.json` grows adversarial cases: combining
  characters, casefold-expansion characters (ß, ﬁ), Turkish dotless-i,
  Cyrillic confusables — locking the function's behavior in vectors rather
  than in a moving Unicode table.

Consequence: non-ASCII case variants become distinct entities. Case
normalization beyond ASCII is an extraction-pipeline concern (compile-time,
correctable), not an identity concern (frozen).

### D5. Full manifest enforcement and domain-separated signing

- The verifier MUST validate every §5.2 field: `spec_version` is a version
  it implements; `metadata.*`, `publisher.*`, `license.spdx` present with
  correct types; `created_at` is RFC 3339 UTC (`Z` suffix).
- `sources` must be a **bijection** with `content/`: every listed path
  exists with the declared SHA-256, and every file under `content/` is
  listed. (Today a content file absent from `sources` is invisible to
  manifest-level checks.)
- `statistics.entities` / `statistics.claims` must equal actual row counts.
- Each gap gets an invalid test vector, so a verifier that skips manifest
  validation cannot pass conformance — today it can.
- **Signature message is domain-separated**:

  `msg = "axm-genesis/v1/manifest" ‖ 0x00 ‖ manifest_bytes`

  preventing cross-protocol replay of manifest signatures. Both hybrid
  components sign `msg`.

### D6. REQ 5 becomes a profile

The kernel spec and verifier lose all knowledge of `cam_latents.bin`, `AXLF`,
`AXLR`, and latent dimensions. In their place, **profiles**:

- A profile is a named, versioned set of additional checks over `content/`
  and `ext/` (`spec/profiles/<name>@<version>.md`).
- The manifest gains an optional `profiles` array (e.g. `["embodied@1"]`).
  Profiles listed are covered by the signature, so a publisher's compliance
  claim is non-repudiable.
- A verifier that implements a listed profile MUST run it; a verifier that
  does not MUST report the profile as **unchecked** (distinct from PASS —
  silence must not impersonate verification).
- STREAM_FORMAT.md and the REQ 5 logic move to `spec/profiles/embodied@1.md`
  and a profile module; `E_BUFFER_DISCONTINUITY` becomes a profile error
  code. Frozen constants are restated normatively there — no references to
  external repositories.

Core conformance (REQ 1–4) is what the kernel freezes. Profiles version
independently and can be added for decades without touching the kernel.

### D7. Gold shard v2, key ceremony, timestamps

- Mint `shards/gold/fm21-11-hemorrhage-v2/` under `axm-hybrid1` from the
  same FM 21-11 source.
- **Key ceremony**: generate the canonical publisher keypair offline;
  document custody in `keys/README.md`; the private key never enters the
  repository. (A test keypair for CI lives under `tests/keys/` and is
  labeled as proving nothing.)
- **Attestations**: commit OpenTimestamps and/or RFC 3161 proofs over the
  gold manifest hash under `attestations/`, dated at sealing. Trigger
  Software Heritage archival; deposit the v1.0.0 release with Zenodo.
- The v0.x gold shard and vectors move to `archive/v0/` — kept as history,
  no longer normative. The "never recompiled" pledge attaches to v2 and is
  then credible: the signature proves authorship, the timestamp proves
  existence before any future forgery capability.

### D8. Repository and process reset

- `spec/v1/SPECIFICATION.md` + `CONFORMANCE.md` rewritten as single coherent
  documents incorporating D1–D6. `spec/v1.0/` moves to `archive/`.
- COMPATIBILITY.md regenerated from the new spec (its current content
  contradicts spec and code in five places: Merkle algorithm, suite
  identifier, claims schema, exit codes, `spec/extensions/`).
- CI (required before the freeze is declared): pytest on all supported
  Pythons and OSes; a dedicated gold-shard verification job; liboqs,
  dilithium-py, and no-backend matrix; ruff.
- Fix the test-pollution bug in `tests/test_mldsa_backend_contract.py`
  (module reload leaks a fake always-true backend into subsequent tests;
  `make test` currently fails 5/77 out of the box).
- Version single-sourced (`axm_verify.__version__` says 1.1.0; pyproject
  says 1.2.0). CLI exit codes specified and implemented (0 pass / 1 fail /
  2 malformed-layout).
- `index.html` moves out of the kernel repo (site branch or separate repo).
- v1.0.0 ships as: signed git tag, GitHub release with checksums, PyPI
  package, SWH + Zenodo deposits.

### Decision points requiring maintainer sign-off

| # | Decision | Recommendation | Alternative |
|---|----------|----------------|-------------|
| 1 | Suite: hybrid vs PQ-only | **Hybrid** (`axm-hybrid1`) — 64 extra sig bytes buys survival of either algorithm breaking | PQ-only `axm-blake3-mldsa44`; simpler, bets everything on lattices |
| 2 | Core tables: JSONL vs pinned Parquet | **Canonical JSONL** — reproducible bytes, stdlib-parseable in 2056 | Keep Parquet, pin format version/encodings/codec normatively; larger 30-year dependency |
| 3 | `canonicalize()`: ASCII-lower vs pinned casefold | **ASCII-only lowercasing** — Unicode-version-independent | Keep `casefold()`, pin Unicode 15.1 + vendor vectors; richer matching, heavier spec |
| 4 | Naming (`axm-hybrid1`, `sh1_`, `e1_`…) | As proposed | Bikeshed freely — cheap until D7, immutable after |

## Backwards Compatibility

**None required — that is the premise of this RFC.** There are no external
dependents: no releases, no published packages, no third-party shards or
verifiers. Internal artifacts (the v0.x gold shard, test vectors) migrate by
recompilation from source or retirement to `archive/v0/`; git history
preserves everything. This is the last moment at which a breaking change
costs nothing. After v1.0.0 is tagged, the CONTRIBUTING.md freeze rules apply
with full force, and the next breaking change costs a major version and a
migration path.

## Reference Implementation

Phased, on a working branch, landing as one reviewed unit:

1. **Decide** the four sign-off points above.
2. **Spec**: write `spec/v1/` incorporating D1–D6; regenerate
   COMPATIBILITY.md.
3. **Code**: delete legacy suite/Merkle paths; implement hybrid suite, JSONL
   read/write/verify, derived shard_id, full manifest enforcement,
   domain-separated signing, profile hooks; fix test pollution; single-source
   version. (Net code size goes down: D1 and D2 remove more than D5 and D6
   add.)
4. **Vectors**: regenerate valid/invalid vectors against the new spec; add
   manifest-schema, identity-Unicode, and profile vectors.
5. **CI** up and green.
6. **Ceremony**: keys, gold shard v2, attestations, archive v0.x.
7. **Ship**: tag v1.0.0, release, PyPI, SWH/Zenodo. Declare the freeze.
