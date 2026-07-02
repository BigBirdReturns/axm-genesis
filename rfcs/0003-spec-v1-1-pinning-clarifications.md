# RFC 0003: Spec v1.1 Pinning Clarifications

## Summary
Propose three additive clarifications for a future `spec/v1.1/`: (1) a pinned
Unicode data version policy for identifier canonicalization, (2) a pinned
Parquet feature subset for core tables, and (3) a formalized verifier
exit-code contract. All three close gaps recorded in
[`docs/ERRATA.md`](../docs/ERRATA.md) (Errata 2 and 3) and in the durability
assessment ([`docs/DURABILITY.md`](../docs/DURABILITY.md) §3.2–§3.3). No
existing shard or vector changes meaning; `spec/v1.0/` remains frozen and
untouched.

**Relationship to RFC 0002.** [RFC 0002 (the v1.0 reset)](0002-v1-reset.md)
resolves all three gaps more fundamentally — Unicode-independent
canonicalization (D4), JSONL core tables replacing Parquet (D2), and a
spec-level exit-code contract (D8). If RFC 0002 is accepted, this RFC is
superseded and should be closed without action; it is the additive fallback
path if the reset is rejected and `spec/v1.0/` remains the shipped surface.

## Motivation
Spec v1.0 delegates identifier canonicalization to host Unicode tables and
says only "Parquet with explicit schemas", and the verifier's exit codes live
in COMPATIBILITY.md and code rather than in the spec. Each of these is the
kind of unpinned dependency that breaks archival formats decades out: Unicode
casefold/NFC drift silently changes content-addressed IDs; Parquet feature
growth makes old shards unreadable without a full contemporary stack; an
unspecified CLI contract lets independent implementations diverge on the one
machine-readable signal scripts depend on. See Errata 2 and 3 for the full
statements of the gaps and their current de-facto answers.

## Specification
Exact additions proposed for `spec/v1.1/SPECIFICATION.md` (all additive):

1. **Unicode pinning (extends §6.1).** Add: "Canonicalization is defined
   against Unicode character database version 14.0.0. The committed identity
   vectors (`tests/vectors/identity.json`) are normative: an implementation
   conforms if and only if it reproduces them exactly, regardless of the
   Unicode version its host ships. A Unicode data upgrade that changes the
   output of canonicalization on any committed vector MUST be rejected by
   the implementation (pin or vendor the Unicode data instead)." Grow the
   vector corpus with adversarial cases (combining characters, casefold
   expansions such as ß→ss, Turkish dotless-i, Cyrillic confusables) in new
   vector files; existing vector files never change.

2. **Parquet subset pinning (extends §7).** Add: "Core tables use Parquet
   format version 2.6 with flat (non-nested) columns matching the schemas of
   §7 exactly; PLAIN data encoding (RLE for levels); compression codec
   UNCOMPRESSED, SNAPPY, or ZSTD; no modular encryption. Verifiers MUST
   accept these and MAY reject anything outside the subset. The gold shard
   and the committed shard vectors are the executable anchor." Also pin the
   `tier` column as signed 8-bit storage with valid values 0–4 (resolving the
   §7.2 "0 to 4" / `int8` ambiguity).

3. **Verifier exit-code contract (new subsection under §9, Verification
   Rules).** Add: "A conforming command-line verifier MUST exit 0 if and only
   if the shard verifies completely; 1 when verification fails for any
   non-structural reason (signature, Merkle, schema/manifest, orphan
   references); 2 when the shard directory is structurally malformed (the
   directory is missing/not a directory, or every reported error is a
   missing-required-file/dir error: `E_LAYOUT_MISSING`, `E_SCHEMA_MISSING`,
   `E_SIG_MISSING`). stdout carries a single-line machine-readable JSON
   result; stderr carries one human-readable reason line per error." This
   matches the reference CLI (`src/axm_verify/cli.py`) and COMPATIBILITY.md
   section 4 as of this RFC.

## Backwards Compatibility
No. Nothing here changes how any existing shard verifies: every committed
shard (including the gold shard) is already inside the proposed Parquet
subset, all committed identity vectors already reflect Unicode 14.0.0
semantics, and the exit-code contract codifies the reference verifier's
current behavior. `spec/v1.0/` is not modified; existing vectors are not
modified.

## Reference Implementation
Already in-tree: [`src/axm_verify/identity.py`](../src/axm_verify/identity.py)
(canonicalization), [`src/axm_build/common.py`](../src/axm_build/common.py)
(deterministic Parquet writing), [`src/axm_verify/cli.py`](../src/axm_verify/cli.py)
(exit codes), with anchors [`tests/vectors/identity.json`](../tests/vectors/identity.json)
and [`shards/gold/fm21-11-hemorrhage-v1/`](../shards/gold/fm21-11-hemorrhage-v1/).
The v1.1 spec text itself is the only new artifact this RFC requires.
