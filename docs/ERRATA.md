# AXM Genesis — Errata Register

**Status**: Normative corrections to non-editable artifacts
**Maintained in**: this file (append-only; entries are numbered and never renumbered)

Some AXM Genesis artifacts cannot be edited after publication: the design paper
is a distributed PDF, and everything under [`spec/v1.0/`](../spec/v1.0/) is
frozen per [CONTRIBUTING.md](../CONTRIBUTING.md). When an error or gap is found
in one of those artifacts, the correction is recorded here. Each entry states
(a) what is wrong and where, (b) the correct/normative statement, and (c) the
long-term fix path.

Where this register conflicts with the paper, this register wins. Where it
conflicts with `spec/v1.0/` or the committed test vectors, the spec and
vectors win — entries about the spec below record *gaps* (things the spec does
not say), not overrides of things it does say.

---

## Erratum 1 — Paper §6.3.3 misdescribes the Merkle construction

**Artifact**: [`papers/axm-genesis-frozen-cryptographic-kernel-v0.6.pdf`](../papers/axm-genesis-frozen-cryptographic-kernel-v0.6.pdf), section 6.3.3 (draft v0.6, June 2026).

**The error.** Section 6.3.3 describes the shard Merkle construction
incorrectly in three ways:

1. It says an odd node count is handled by pairing the last node "with
   itself". That is true only for the legacy `ed25519` suite; the
   `axm-blake3-mldsa44` suite *promotes* the odd node unchanged (RFC 6962
   style, the CVE-2012-2459-safe behavior) and never duplicates.
2. It says internal nodes set "the PARENT flag in the BLAKE3 context". No
   BLAKE3 tree-mode flags or contexts are used anywhere. Domain separation is
   done with plain byte prefixes (`0x00` for leaves, `0x01` for internal
   nodes) fed to ordinary BLAKE3, and only in the `axm-blake3-mldsa44` suite.
3. It says dotfiles are excluded from the covered file set. They are not
   excluded from the Merkle walk; a shard containing a dotfile is rejected
   earlier by layout validation (`E_DOTFILE`), so the question never reaches
   the Merkle computation.

**The normative statement.** The paper is explicitly non-normative. The
normative definition of the Merkle construction is
[`spec/v1.0/SPECIFICATION.md`](../spec/v1.0/SPECIFICATION.md) section 4
(§4.1 legacy, §4.2 post-quantum) together with the reference implementation
[`src/axm_build/merkle.py`](../src/axm_build/merkle.py). For the record, the
correct construction is:

*File collection (both suites)*: every regular file under the shard root is a
leaf **except** `manifest.json` and everything under `sig/`. Symlinks are
refused. Leaves are ordered by sorting each file's POSIX relative path by its
UTF-8 bytes.

*`ed25519` (legacy, v1.0 — `suite` field absent or `"ed25519"`)*:

```
Leaf  = BLAKE3( relpath_utf8 || 0x00 || file_bytes )
Node  = BLAKE3( left || right )
Odd   = last node at a level is duplicated (Bitcoin style)
Empty = BLAKE3( b"" )
```

*`axm-blake3-mldsa44` (post-quantum)*:

```
Leaf  = BLAKE3( 0x00 || relpath_utf8 || 0x00 || file_bytes )   (domain prefix)
Node  = BLAKE3( 0x01 || left || right )                        (domain prefix)
Odd   = last node at a level is promoted unchanged (RFC 6962, no duplication)
Empty = frozen constant
        48fc721fbbc172e0925fa27af1671de225ba927134802998b10a1568a188652b
        (= BLAKE3( 0x01 ))
```

The `merkle_root` recorded in the manifest is the lowercase hex encoding of
the root digest. The executable oracle is [`tests/vectors/merkle.json`](../tests/vectors/merkle.json)
plus the gold shard.

**Fix path.** A future paper revision (v0.7) should correct §6.3.3 or replace
it with an explicit deferral to spec §4. Until then, [`papers/README.md`](../papers/README.md)
points readers to this erratum. Nothing in `spec/v1.0/` changes.

---

## Erratum 2 — spec v1.0 does not pin a Unicode version for canonicalization

**Artifact**: [`spec/v1.0/SPECIFICATION.md`](../spec/v1.0/SPECIFICATION.md), section 6.1 (Canonicalization).

**The gap.** Section 6.1 defines canonicalization as NFC normalization,
case-folding, control-character removal, and whitespace collapsing, and
delegates to the reference implementation
[`src/axm_verify/identity.py`](../src/axm_verify/identity.py)
(`canonicalize`, which uses `unicodedata.normalize("NFC", ...)`,
`str.casefold()`, and category-`Cc` checks). It does **not** pin which
Unicode character database version those operations use. NFC composition,
casefold mappings, and character categories can all change between Unicode
versions, so the same (namespace, label) pair could in principle yield
different `entity_id`s / `claim_id`s on different Python builds decades
apart — silently breaking content-addressing, the property the whole format
depends on.

**The normative statement.** The committed vector file
[`tests/vectors/identity.json`](../tests/vectors/identity.json) is the
normative anchor for canonicalization and ID derivation. A conforming
implementation must reproduce those vectors byte-for-byte, whatever Unicode
tables its host environment ships. Consequently: **any Unicode data upgrade
that changes the output of `canonicalize` on the committed identity vectors
is a breaking change and must be rejected** (the implementation must pin or
vendor Unicode data rather than accept the drift). This is the same principle
as the gold-shard policy: the vectors are frozen bytes and define correctness.

For the record, the reference environment at the time of writing (2026-07-01)
is CPython 3.11.15 with Unicode character database version **14.0.0**
(`python3 -c "import unicodedata; print(unicodedata.unidata_version)"`).
All committed identity vectors were produced under Unicode 14.0.0 semantics.

**Fix path.** [RFC 0003](../rfcs/0003-spec-v1-1-pinning-clarifications.md)
proposes that spec v1.1 pin a Unicode data version policy explicitly and grow
`tests/vectors/identity.json`-style coverage with adversarial cases
(combining characters, casefold expansions such as ß→ss, Turkish dotless-i,
Cyrillic confusables) so drift is caught mechanically. New vector files may
be added; the existing vectors never change.

---

## Erratum 3 — spec v1.0 does not pin the Parquet feature subset

**Artifact**: [`spec/v1.0/SPECIFICATION.md`](../spec/v1.0/SPECIFICATION.md), section 7 (Parquet Tables).

**The gap.** Section 7 says the core tables are "Parquet files with explicit
Arrow schemas" but does not pin which subset of the (large, evolving) Parquet
format a conforming shard may use: format version, allowed encodings,
compression codecs, nested types, row-group expectations, or encryption.
Without a pinned subset, verifying a shard in 2056 requires a full
contemporary Parquet stack forever.

**The normative statement (de facto, recorded here as the compatibility
expectation).** A conforming shard uses the subset that the pyarrow version
pinned in [`pyproject.toml`](../pyproject.toml) (`pyarrow>=14.0.0`) writes by
default, and nothing more:

- Parquet format version 2.6, as written by `parquet-cpp-arrow` (the gold
  shard's files record `created_by: parquet-cpp-arrow version 14.0.2`).
- Flat (non-nested) columns only — exactly the frozen schemas of spec §7;
  no lists, maps, or structs in core tables.
- Plain data encoding (`PLAIN`, with `RLE` for definition levels), i.e.
  pyarrow's default encoding; no delta or byte-stream-split encodings.
- Compression: the gold shard's tables are `UNCOMPRESSED`; the current
  builder (`src/axm_build/common.py`, `write_parquet_deterministic`) writes
  `zstd`. Verifiers must accept at least `UNCOMPRESSED`, `SNAPPY`, and
  `ZSTD`; builders should emit no other codecs.
- No Parquet modular encryption, no bloom filters required for reading, a
  single row group per table at current shard sizes.

The executable anchors are the gold shard
([`shards/gold/fm21-11-hemorrhage-v1/`](../shards/gold/fm21-11-hemorrhage-v1/))
and the committed shard vectors under
[`tests/vectors/shards/`](../tests/vectors/shards/): a Parquet reader that can
read those files can read any conforming shard's core tables.

Related pinning gap, recorded with this erratum: the `tier` column is `int8`
in the reference Arrow schema while spec §7.2 says "0 to 4" without stating
signedness or storage width; the reference implementation
(`axm_verify.const.VALID_TIERS`) is authoritative (signed 8-bit storage,
values 0–4).

**Fix path.** [RFC 0003](../rfcs/0003-spec-v1-1-pinning-clarifications.md)
proposes that spec v1.1 state this Parquet subset normatively (additive —
every existing shard, including the gold shard, is already inside the
subset).
