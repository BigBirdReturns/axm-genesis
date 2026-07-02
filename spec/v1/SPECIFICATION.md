# AXM Genesis Specification v1.0.0

Status: **Normative. Frozen on release of v1.0.0.**

This document is the complete definition of the AXM Genesis shard format,
its identifiers, its cryptography, and its verification rules. It is
self-contained: an implementer with this document, the conformance vectors,
and libraries for JSON, UTF-8, SHA-256, BLAKE3, Ed25519, and ML-DSA-44 can
build an independent, interoperable verifier with no access to the reference
code.

Everything shipped before this document — including the documents formerly
under `spec/v1.0/` that carried `spec_version` values `"1.0.0"` and
`"1.1.0"` — is reclassified as the **v0.x prototype lineage**. It is
non-normative, archived, and not accepted by v1 verifiers. This document
supersedes it entirely; there are no addenda and no legacy sections.

## 1. The freeze

The following are frozen **forever**. Changing any of them requires a new
major format (a different `spec_version`, a different suite identifier, and
different identifier prefixes), never a mutation of this one:

- The shard layout (Section 4).
- The canonical JSON encoding (Section 5).
- The manifest schema (Section 6).
- The `axm-hybrid1` signature suite and the signature message construction
  (Section 7).
- The Merkle tree construction and its empty-root constant (Section 8).
- The shard identity derivation (Section 9).
- The `canonicalize()` function and the identifier derivations (Section 10).
- The core table schemas and their file encoding (Section 11).
- The evidence invariants (Section 12).
- The kernel verification procedure, error codes, and CLI exit-code
  contract (Sections 13–14).

Profiles (Section 15) version independently of the kernel and may be added
for decades without touching anything above. Extensions (Section 16) are
opaque to the kernel.

The conformance vectors (Section 17) are **normative ground truth**. If
prose in this document and a conformance vector are ever found to disagree,
the vectors govern conformance while the discrepancy is resolved by RFC.

## 2. Terminology and requirements language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD
NOT, RECOMMENDED, MAY, and OPTIONAL are to be interpreted as described in
RFC 2119 and RFC 8174.

- **Shard**: a directory on disk containing immutable, verifiable files.
- **Content**: raw source files under `content/` (UTF-8 text, PDFs, binary
  streams, and so on).
- **Core tables**: the four canonical JSONL tables under `graph/` and
  `evidence/` (Section 11).
- **Kernel**: the frozen format and checks defined by this document,
  exclusive of profiles and extensions.
- **Producer** (or compiler): software that emits a shard.
- **Verifier**: software that checks a shard against this specification.
- `a ‖ b` denotes byte-string concatenation. `0x00` and `0x01` denote
  single bytes. All paths are POSIX-style (`/` separator) relative paths
  from the shard root unless stated otherwise.

## 3. Cryptographic and encoding primitives

| Primitive | Definition | Used for |
|---|---|---|
| SHA-256 | FIPS 180-4 | Content file hashes; identifier digests |
| BLAKE3 | BLAKE3 v1, 256-bit (32-byte) default output | Merkle tree; shard identity |
| Ed25519 | RFC 8032 §5.1 (plain Ed25519, **not** Ed25519ph or Ed25519ctx) | First hybrid signature component |
| ML-DSA-44 | FIPS 204, pure ML-DSA (not HashML-DSA), **empty context string** (`ctx` = 0 bytes) | Second hybrid signature component |
| base32lower | RFC 4648 §6 base32, output lowercased, `=` padding removed | Identifier encoding |
| hex | Lowercase hexadecimal, two digits per byte | Hash encoding |
| NFC | Unicode Normalization Form C, pinned at Unicode 15.1.0 | `canonicalize()`; canonical JSON string content |

Notes:

- base32lower of a 32-byte digest is always exactly **52 characters** drawn
  from `abcdefghijklmnopqrstuvwxyz234567`.
- The Unicode pin: NFC is computed per Unicode 15.1.0. Under the Unicode
  Normalization Stability Policy, any later Unicode version produces
  identical NFC results for all code points assigned in 15.1.0, so any
  conforming Unicode library released after 15.1.0 is acceptable.
  Unassigned code points pass through NFC unchanged. The identity vectors
  (Section 17) pin the observable behavior.
- ML-DSA-44 sizes: public key 1312 bytes, signature 2420 bytes.
  Ed25519 sizes: public key 32 bytes, signature 64 bytes.
- ML-DSA-44 verification does not depend on whether the signer used the
  hedged or deterministic signing variant; verifiers MUST accept both.

## 4. Shard layout

A shard is a directory with exactly this structure:

```
manifest.json               required  (Section 6)
sig/manifest.sig            required  (Section 7; exactly 2484 bytes)
sig/publisher.pub           required  (Section 7; exactly 1344 bytes)
content/                    required  (one or more source files, any format)
graph/entities.jsonl        required  (Section 11)
graph/claims.jsonl          required  (Section 11)
graph/provenance.jsonl      required  (Section 11)
evidence/spans.jsonl        required  (Section 11)
ext/                        optional  (Section 16)
```

Layout rules:

- The shard root MUST contain exactly the items `manifest.json`, `sig`,
  `content`, `graph`, `evidence`, and optionally `ext` — nothing else.
  A missing required item is `E_LAYOUT_MISSING`; an unexpected item is
  `E_LAYOUT_DIRTY`.
- `sig/` MUST contain exactly `manifest.sig` and `publisher.pub`.
- `graph/` MUST contain exactly the three listed `.jsonl` files;
  `evidence/` MUST contain exactly `spans.jsonl`. A missing table file is
  `E_SCHEMA_MISSING`; an unexpected file in these directories is
  `E_LAYOUT_DIRTY`.
- `content/` MUST contain at least one regular file and MAY contain
  subdirectories.
- Symbolic links are forbidden anywhere in the shard (`E_LAYOUT_DIRTY`).
- Files or directories whose name begins with `.` (dotfiles) are forbidden
  anywhere in the shard (`E_DOTFILE`).
- Parquet files are **not** part of the shard. A runtime MAY build derived
  query caches (in Parquet or any other format) outside the shard
  directory; such caches are rebuildable, non-normative, and never
  Merkle-covered.

## 5. Canonical JSON encoding

One canonical byte encoding is used for `manifest.json`, for every line of
every core table, and for AXM-defined extension tables. It is defined so
that the same abstract value always yields the same bytes in any language.

An abstract JSON value is encoded as follows:

1. **Objects**: `{`, then members sorted by the Unicode code points of
   their key strings (ascending), each as `"key":value`, joined by `,`,
   then `}`. No whitespace anywhere. Duplicate keys MUST NOT occur.
   (All keys defined by this specification are ASCII, so code-point order
   equals ASCII byte order.)
2. **Arrays**: `[`, elements in order joined by `,`, then `]`. No
   whitespace.
3. **Strings**: `"` … `"` with exactly these escapes and no others:
   - `"` → `\"` and `\` → `\\`
   - U+0008 → `\b`, U+0009 → `\t`, U+000A → `\n`, U+000C → `\f`,
     U+000D → `\r`
   - every other code point below U+0020 → `\u00XX` with lowercase hex
     digits
   - every other character (including all non-ASCII characters) is emitted
     literally as UTF-8, never `\uXXXX`-escaped.
4. **Integers**: shortest decimal form — no leading zeros, no `+`, no
   fraction part, no exponent, and no `-0`. The only numbers permitted in
   kernel-defined documents are integers in `[0, 2^63 − 1]`. Floats and
   negative numbers MUST NOT appear.
5. **Literals**: `true`, `false`. `null` MUST NOT appear in kernel-defined
   documents.
6. The result is encoded as UTF-8 with **no byte order mark**.
7. All string values written by a producer MUST be in Unicode NFC.

This is exactly the output of Python's
`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`
for inputs obeying rules 4–7.

### 5.1 Worked example — one claim row

The abstract claim row (fields explained in Section 11.2, identifiers
derived in Section 10.5):

| field | value |
|---|---|
| claim_id | `c1_a6v74qtzhdchfmnjhd7coivtunpqa7kqra5k44ohifxwfgulalqq` |
| subject | `e1_k6igl4utryn6jl2th7bmpluql2dsiou52ufwcebn775u3mtxvkkq` |
| predicate | `treats` |
| object | `e1_7fr5ezvpq7k5ovatswocd7lypzooolbgebkwj4ibifdnmkftmeca` |
| object_type | `entity` |
| tier | 2 (integer) |

Its canonical encoding is the following single line (keys sorted:
`claim_id`, `object`, `object_type`, `predicate`, `subject`, `tier`):

```
{"claim_id":"c1_a6v74qtzhdchfmnjhd7coivtunpqa7kqra5k44ohifxwfgulalqq","object":"e1_7fr5ezvpq7k5ovatswocd7lypzooolbgebkwj4ibifdnmkftmeca","object_type":"entity","predicate":"treats","subject":"e1_k6igl4utryn6jl2th7bmpluql2dsiou52ufwcebn775u3mtxvkkq","tier":2}
```

That is 258 bytes of UTF-8; as a line in `graph/claims.jsonl` it is
followed by a single `\n` (0x0A), for 259 bytes total.

## 6. Manifest

`manifest.json` MUST be the canonical JSON encoding (Section 5) of a single
JSON object — no trailing newline, no BOM, byte-exact. A verifier MUST
check this by parsing the file and re-encoding canonically: if the
re-encoded bytes differ from the file bytes, the manifest is invalid
(`E_MANIFEST_SCHEMA`). A file that is not valid JSON at all is
`E_MANIFEST_SYNTAX`.

### 6.1 Required fields

| Field | Type | Constraint |
|---|---|---|
| `spec_version` | string | MUST equal `"1.0.0"` |
| `suite` | string | MUST equal `"axm-hybrid1"` |
| `metadata.title` | string | non-empty |
| `metadata.namespace` | string | non-empty; used in entity ID derivation (Section 10) |
| `metadata.created_at` | string | RFC 3339 `date-time` in UTC with the `Z` designator, e.g. `2026-07-02T00:00:00Z`. A numeric offset (`+00:00`) MUST be rejected. Fractional seconds are permitted but NOT RECOMMENDED. Verifiers MUST validate the format. |
| `publisher.id` | string | non-empty |
| `publisher.name` | string | non-empty |
| `license.spdx` | string | non-empty (an SPDX license expression) |
| `sources` | array | non-empty; see Section 6.3 |
| `integrity.algorithm` | string | MUST equal `"blake3"` |
| `integrity.merkle_root` | string | exactly 64 lowercase hex characters; MUST equal the computed Merkle root (Section 8) |
| `statistics.entities` | integer | MUST equal the exact number of rows in `graph/entities.jsonl` |
| `statistics.claims` | integer | MUST equal the exact number of rows in `graph/claims.jsonl` |

Violation of any constraint in this section is `E_MANIFEST_SCHEMA`, except
where another code is named explicitly. A `statistics` count that does not
match the actual row count is `E_MANIFEST_SCHEMA`.

### 6.2 Optional fields

| Field | Type | Constraint |
|---|---|---|
| `profiles` | array of strings | non-empty if present; each element MUST match `^[a-z][a-z0-9-]*@[1-9][0-9]*$` (e.g. `"embodied@1"`); no duplicates. See Section 15. |
| `extensions` | array of strings | non-empty if present; each element MUST match `^[a-z][a-z0-9-]*@[1-9][0-9]*$`. MUST be present and list the extension identifiers when `ext/` is non-empty; MUST be absent when `ext/` is empty or absent. See Section 16. |
| `supersedes` | array of strings | non-empty if present; each element MUST match `^sh1_[0-9a-f]{64}$` (a predecessor shard identity, Section 9); no duplicates. |

### 6.3 The forbidden `shard_id` field, and unknown fields

The manifest MUST NOT contain a `shard_id` field. Shard identity is
*derived* from the manifest (Section 9); storing it would be circular. The
presence of `shard_id` is `E_MANIFEST_SCHEMA`.

The set of top-level manifest keys is **closed**: any top-level key other
than `spec_version`, `suite`, `metadata`, `publisher`, `license`,
`sources`, `integrity`, `statistics`, `profiles`, `extensions`, and
`supersedes` is `E_MANIFEST_SCHEMA`. The sub-objects `metadata`,
`publisher`, and `license` MAY carry additional members (e.g.
`license.notes`); such members are covered by the signature and the shard
identity like everything else in the manifest.

### 6.4 `sources` — bijection with `content/`

Each element of `sources` is an object with exactly two keys:

- `path`: string — a POSIX relative path beginning with `content/`,
  containing no `.` or `..` segments, no backslashes, no leading `/`, and
  no NUL.
- `hash`: string — exactly 64 lowercase hex characters, the SHA-256 of that
  file's raw bytes.

`sources` MUST be a **bijection** with the regular files under `content/`:

1. Every listed `path` MUST exist in the shard and its SHA-256 MUST equal
   the declared `hash`.
2. Every regular file under `content/` (recursively) MUST appear exactly
   once in `sources`.
3. No `path` may be listed twice.

Any violation is `E_MANIFEST_SCHEMA`. (Tampering with a content file is
additionally caught by the Merkle check; the bijection rule exists so that
the *signed manifest* is a complete, accurate index of the content, and so
no file can ride inside `content/` invisibly to manifest-level review.)

### 6.5 Worked example manifest

This manifest is used by the worked examples in Sections 7.3 and 9.1. Its
shard contains a single content file `content/source.txt` with the 12
bytes `hello world\n` (SHA-256
`a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447`); the
`merkle_root` value is illustrative. Canonically encoded (one line,
506 bytes):

```
{"integrity":{"algorithm":"blake3","merkle_root":"7048fb2e31b2ef3f932ec77a2dccc3afd2381a780766287fc89b35981de41558"},"license":{"spdx":"CC0-1.0"},"metadata":{"created_at":"2026-07-02T00:00:00Z","namespace":"survival/medical","title":"Worked Example"},"publisher":{"id":"@axm_genesis","name":"AXM Genesis"},"sources":[{"hash":"a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447","path":"content/source.txt"}],"spec_version":"1.0.0","statistics":{"claims":1,"entities":2},"suite":"axm-hybrid1"}
```

## 7. Signature suite `axm-hybrid1`

There is exactly one suite. The manifest `suite` field is REQUIRED and MUST
equal `"axm-hybrid1"`. There is no suite negotiation and no detection by
key size; a verifier MUST NOT infer a suite from key material.

### 7.1 Key and signature material

- `sig/publisher.pub` = `pk_ed25519 (32 bytes) ‖ pk_mldsa44 (1312 bytes)`
  — exactly **1344 bytes**.
- `sig/manifest.sig` = `sig_ed25519 (64 bytes) ‖ sig_mldsa44 (2420 bytes)`
  — exactly **2484 bytes**.

A key or signature file of any other length is `E_SIG_INVALID`. A missing
key or signature file is `E_SIG_MISSING`.

### 7.2 Signature message (domain separation)

Both components sign the same message:

```
msg = b"axm-genesis/v1/manifest" ‖ 0x00 ‖ manifest_bytes
```

where `manifest_bytes` is the exact raw byte content of `manifest.json`
(which, per Section 6, is the canonical encoding). The domain prefix is 24
bytes: the 23 ASCII bytes of `axm-genesis/v1/manifest` followed by one NUL.
In hex:

```
61786d2d67656e657369732f76312f6d616e696665737400
```

The prefix prevents a manifest signature from being replayed as a signature
over any other AXM or non-AXM structure.

### 7.3 Worked example — message construction

For the 506-byte example manifest of Section 6.5, `msg` is
24 + 506 = 530 bytes. Its first 32 bytes are:

```
61786d2d67656e657369732f76312f6d616e6966657374007b22696e74656772
└──────────── 24-byte domain prefix ────────────┘└─ {"integr… ─┘
```

### 7.4 Verification

Given a trusted hybrid public key `T` (1344 bytes, supplied out of band —
see Section 13.1) and the shard files:

1. `sig/publisher.pub` MUST equal `T` byte-for-byte (`E_SIG_INVALID`
   otherwise).
2. Split `publisher.pub` into `pk_ed25519` = bytes 0–31 and `pk_mldsa44` =
   bytes 32–1343. Split `manifest.sig` into `sig_ed25519` = bytes 0–63 and
   `sig_mldsa44` = bytes 64–2483.
3. Verify `sig_ed25519` over `msg` with `pk_ed25519` (RFC 8032 Ed25519).
4. Verify `sig_mldsa44` over `msg` with `pk_mldsa44` (FIPS 204 ML-DSA-44,
   empty context).
5. The signature is valid **iff BOTH components verify**. If either fails,
   report `E_SIG_INVALID`.

Rationale (informative): a future break of either algorithm — quantum
against Ed25519, cryptanalytic against the lattice — leaves the other
component holding. The 2484-byte signature is the price of not betting the
archive on one assumption.

## 8. Merkle root

There is exactly one Merkle construction.

### 8.1 Covered files

The tree commits to every regular file under the shard root **except**
`manifest.json` and everything under `sig/`. This includes all of
`content/`, `graph/`, `evidence/`, and `ext/`, recursively. Directories
themselves are not hashed; empty directories are not representable.

Each covered file contributes its POSIX relative path from the shard root
(e.g. `graph/claims.jsonl`), encoded as UTF-8. The file list is sorted by
the **UTF-8 bytes** of these relative paths, ascending.

### 8.2 Construction

```
leaf  = BLAKE3( 0x00 ‖ relpath_utf8 ‖ 0x00 ‖ file_bytes )
node  = BLAKE3( 0x01 ‖ left ‖ right )
```

All hashes are 32-byte BLAKE3 digests. Build the tree bottom-up from the
sorted leaves:

- Pair adjacent nodes left to right: positions (0,1), (2,3), …
- If a level has an odd count, the last node is **promoted unchanged** to
  the next level (RFC 6962 style). It is never duplicated
  (CVE-2012-2459-safe).
- Repeat until one node remains; that node is the root.
- A tree with exactly one leaf has that leaf as its root.
- The empty tree (no covered files — impossible in a valid shard, defined
  for completeness) has the constant root
  `BLAKE3(0x01)` = `48fc721fbbc172e0925fa27af1671de225ba927134802998b10a1568a188652b`.

The `0x00`/`0x01` prefixes domain-separate leaves from interior nodes, so
crafted file content cannot be confused with an interior node.

`integrity.merkle_root` is the root as 64 lowercase hex characters. A
mismatch between the computed and stored root is `E_MERKLE_MISMATCH`.

### 8.3 Worked examples

Single file — `content/test.txt` containing the 12 bytes `hello world\n`:

```
leaf = BLAKE3(0x00 ‖ "content/test.txt" ‖ 0x00 ‖ "hello world\n")
     = 7048fb2e31b2ef3f932ec77a2dccc3afd2381a780766287fc89b35981de41558
root = leaf   (single-leaf tree)
```

Two files — `content/a.txt` = `aaa\n`, `content/b.txt` = `bbb\n`
(sorted order: `content/a.txt` < `content/b.txt`):

```
leaf_a = BLAKE3(0x00 ‖ "content/a.txt" ‖ 0x00 ‖ "aaa\n")
       = 422f59424a9909a500ce1b5aa17002cf6d52eef6f246a0e6edd80fdcb09aa081
leaf_b = BLAKE3(0x00 ‖ "content/b.txt" ‖ 0x00 ‖ "bbb\n")
       = 96fcc5df8709524e84e1844f4d5f618cc5c404a080e8e7c2a433acf9e172d209
root   = BLAKE3(0x01 ‖ leaf_a ‖ leaf_b)
       = 4e987438705f9aa7a927c933f18e32497689417f8d6fb6d4580d300f04e1d9db
```

## 9. Shard identity

A shard's identity is derived, never stored:

```
shard_id = "sh1_" + hex( BLAKE3( manifest_bytes ) )
```

where `manifest_bytes` is the exact byte content of `manifest.json`
(canonical per Section 6). The identifier is `sh1_` followed by 64
lowercase hex characters.

Because the manifest contains `integrity.merkle_root`, the identity commits
to the full content **and** the metadata **and** the publisher **and** the
suite. Two shards with identical content but different publishers or
licenses have different identities. Every cross-shard reference (e.g. in
`supersedes`, `ext/lineage@1`, `ext/references@1`) therefore binds to one
exact sealed artifact.

The `sh1_` form is used only for **predecessor / foreign** shard ids inside
a shard. A shard never records its own id anywhere in its own files — it
cannot, since the id is a hash of the manifest, and the manifest hashes the
files. A shard's own id is ambient: recompute it from `manifest.json`
whenever needed.

### 9.1 Worked example

For the 506-byte example manifest of Section 6.5:

```
shard_id = "sh1_" + hex(BLAKE3(manifest_bytes))
         = sh1_69490226770fe3aefe2ebaffb939a772b2f8ce39390acbefd79e0977dc0d6e73
```

## 10. Identifiers

### 10.1 `canonicalize()`

`canonicalize(text)` applies, **in this order**:

1. **NFC-normalize** (Unicode 15.1.0 pin; see Section 3).
2. **ASCII-only lowercasing**: map each of `A`–`Z` (U+0041–U+005A) to
   `a`–`z` (U+0061–U+007A). No other character is changed. This is
   deliberately *not* Unicode case folding: `str.casefold()` mappings drift
   across Unicode versions; this step never will.
3. **Strip control characters**: remove every character in Unicode general
   category `Cc` (U+0000–U+001F and U+007F–U+009F).
4. **Collapse whitespace**: replace every maximal run of one or more
   characters from the frozen whitespace set `WS` with a single ASCII space
   (U+0020), then remove leading and trailing spaces.

The frozen set `WS` is exactly these code points (the non-`Cc` Unicode
whitespace characters, enumerated here so the function is independent of
future Unicode changes):

```
U+0020  U+00A0  U+1680  U+2000–U+200A  U+2028  U+2029  U+202F  U+205F  U+3000
```

Note that tabs and newlines (U+0009, U+000A, U+000D, …) are category `Cc`
and are therefore *removed* in step 3, before whitespace collapsing — they
do not become spaces.

Producers MUST reject input containing U+0000 (NUL) rather than
canonicalizing it: NUL is the field separator inside identifier preimages,
and its appearance in raw input indicates corruption.

Illustrative behavior (the identity vectors are the normative set):

| input | output | why |
|---|---|---|
| `"  Tourniquet "` | `"tourniquet"` | ASCII lowering, trim |
| `"Severe   Bleeding"` | `"severe bleeding"` | whitespace collapse |
| `"STRASSE"` | `"strasse"` | ASCII lowering |
| `"Straße"` | `"straße"` | `ß` is untouched (no casefold expansion) |
| `"İstanbul"` | `"İstanbul"` | U+0130 is not ASCII; untouched |
| `"ﬁre"` | `"ﬁre"` | U+FB01 ligature survives NFC; untouched |

Consequence (informative): non-ASCII case variants are **distinct
entities**. Case normalization beyond ASCII is an extraction-pipeline
concern (compile-time, correctable); identity is frozen.

### 10.2 Common form

All four identifier kinds share one shape:

```
id = prefix + base32lower( SHA-256( preimage_utf8 ) )
```

The **full 32-byte** digest is encoded — never truncated — yielding exactly
52 base32 characters after the versioned prefix. The prefixes are:

| kind | prefix | regex |
|---|---|---|
| entity | `e1_` | `^e1_[a-z2-7]{52}$` |
| claim | `c1_` | `^c1_[a-z2-7]{52}$` |
| provenance | `p1_` | `^p1_[a-z2-7]{52}$` |
| span | `s1_` | `^s1_[a-z2-7]{52}$` |

### 10.3 Entity IDs

```
entity_id = "e1_" + base32lower( SHA-256(
    canonicalize(namespace) ‖ 0x00 ‖ canonicalize(label)
) )
```

`namespace` is the shard's `metadata.namespace`; `label` is the entity's
label. The preimage is the UTF-8 encoding of the canonicalized strings
joined by a single NUL byte.

### 10.4 Claim IDs

Let:

- `subject` — the subject's `entity_id` string, verbatim;
- `predicate_c` — `canonicalize(predicate)`;
- `object_type` — one of `entity`, `literal:string`, `literal:integer`,
  `literal:decimal`, `literal:boolean` (verbatim, not canonicalized);
- `object_value` — the object's `entity_id` string verbatim if
  `object_type` is `entity`, otherwise `canonicalize(object)`.

```
claim_id = "c1_" + base32lower( SHA-256(
    subject ‖ 0x00 ‖ predicate_c ‖ 0x00 ‖ object_type ‖ 0x00 ‖ object_value
) )
```

When recomputing IDs, a verifier canonicalizes the *stored* `predicate` and
literal `object` values; producers SHOULD store already-canonical forms.

### 10.5 Worked example — label to `c1_`

Entity 1: namespace `survival/medical`, label `  Tourniquet `.

```
canonicalize("survival/medical")            = "survival/medical"
canonicalize("  Tourniquet ")               = "tourniquet"
preimage  = "survival/medical" ‖ 0x00 ‖ "tourniquet"          (27 bytes UTF-8)
SHA-256   = 579065f2938e1be4af533fc2c7ae905e87243a9dd50b61102dfffb4db277aa95
entity_id = e1_k6igl4utryn6jl2th7bmpluql2dsiou52ufwcebn775u3mtxvkkq
```

Entity 2: same namespace, label `Severe   Bleeding` →
`canonicalize` = `severe bleeding` →
SHA-256 `f963d266af87d5d75413959c21fd787e5ce72c26205564f1014146d628b36104` →
`e1_7fr5ezvpq7k5ovatswocd7lypzooolbgebkwj4ibifdnmkftmeca`.

Claim: subject = entity 1, predicate `Treats` (canonicalizes to `treats`),
object = entity 2, object_type `entity`:

```
preimage = "e1_k6igl4utryn6jl2th7bmpluql2dsiou52ufwcebn775u3mtxvkkq" ‖ 0x00 ‖
           "treats" ‖ 0x00 ‖ "entity" ‖ 0x00 ‖
           "e1_7fr5ezvpq7k5ovatswocd7lypzooolbgebkwj4ibifdnmkftmeca"
SHA-256  = 07abfe427938c472b1a938fe2722b3a35f007d50883aae71c7416f629a8b02e1
claim_id = c1_a6v74qtzhdchfmnjhd7coivtunpqa7kqra5k44ohifxwfgulalqq
```

This is the claim encoded in the Section 5.1 example.

### 10.6 Provenance and span IDs

`provenance_id` and `span_id` are primary keys with the syntax of
Section 10.2 (`p1_` / `s1_` + 52 base32 chars). The kernel verifier checks
their **syntax and uniqueness** but does not recompute them; any stable,
unique derivation conforms. The RECOMMENDED derivation (used by the
reference compiler; decimal ASCII for integers, NUL separators) is:

```
provenance_id = "p1_" + base32lower( SHA-256(
    claim_id ‖ 0x00 ‖ source_hash ‖ 0x00 ‖ dec(byte_start) ‖ 0x00 ‖ dec(byte_end) ) )

span_id = "s1_" + base32lower( SHA-256(
    source_hash ‖ 0x00 ‖ dec(byte_start) ‖ 0x00 ‖ dec(byte_end) ‖ 0x00 ‖ text ) )
```

## 11. Core tables — canonical JSONL

The four core tables are canonical JSONL files:

```
graph/entities.jsonl      primary key: entity_id
graph/claims.jsonl        primary key: claim_id
graph/provenance.jsonl    primary key: provenance_id
evidence/spans.jsonl      primary key: span_id
```

File encoding rules — all MUST hold:

1. Each row is one record encoded as canonical JSON (Section 5), followed
   by exactly one `\n` (0x0A).
2. The file is the exact concatenation of these lines: no BOM, no blank
   lines, no trailing blank line, no other bytes. A table with zero rows is
   a zero-byte file.
3. Each record carries **exactly** the key set of its schema below — no
   extra keys, no missing keys, no `null` values.
4. `byte_start`, `byte_end`, and `tier` are JSON integers; every other
   field is a JSON string. No floats anywhere in core tables.
5. Rows are sorted by the **bytewise ascending** UTF-8 order of their
   primary-key value. A duplicate primary key is a verification error.

Error codes for table validation:

| Condition | Code |
|---|---|
| Required table file absent | `E_SCHEMA_MISSING` |
| File unreadable; a line is not valid JSON; a line is not in canonical encoding (re-encode-and-compare fails); rows out of order; duplicate primary key | `E_SCHEMA_READ` |
| Extra/unexpected key in a record, or a value of the wrong JSON type | `E_SCHEMA_TYPE` |
| Required key missing from a record, or value is `null` | `E_SCHEMA_NULL` |
| `object_type` not in the allowed set, or `tier` outside 0–4 | `E_SCHEMA_ENUM` |

A verifier MUST check canonical form per line by parsing the line and
re-encoding it canonically; a byte difference is `E_SCHEMA_READ`.

### 11.1 `graph/entities.jsonl`

| key | type | constraint |
|---|---|---|
| `entity_id` | string | `^e1_[a-z2-7]{52}$`; MUST equal the recomputation of Section 10.3 (`E_ID_ENTITY` on mismatch) |
| `namespace` | string | |
| `label` | string | |
| `entity_type` | string | |

### 11.2 `graph/claims.jsonl`

| key | type | constraint |
|---|---|---|
| `claim_id` | string | `^c1_[a-z2-7]{52}$`; MUST equal the recomputation of Section 10.4 (`E_ID_CLAIM` on mismatch) |
| `subject` | string | MUST be an `entity_id` present in `entities.jsonl` (`E_REF_ORPHAN`) |
| `predicate` | string | |
| `object` | string | when `object_type` = `entity`: MUST be an `entity_id` present in `entities.jsonl` (`E_REF_ORPHAN`); otherwise a literal value |
| `object_type` | string | one of `entity`, `literal:string`, `literal:integer`, `literal:decimal`, `literal:boolean` (`E_SCHEMA_ENUM`) |
| `tier` | integer | 0 ≤ tier ≤ 4 (`E_SCHEMA_ENUM`) |

### 11.3 `graph/provenance.jsonl`

| key | type | constraint |
|---|---|---|
| `provenance_id` | string | `^p1_[a-z2-7]{52}$` |
| `claim_id` | string | MUST be present in `claims.jsonl` (`E_REF_ORPHAN`) |
| `source_hash` | string | 64 lowercase hex; MUST equal the SHA-256 of some file under `content/` (`E_REF_SOURCE`) |
| `byte_start` | integer | see Section 12 |
| `byte_end` | integer | see Section 12 |

### 11.4 `evidence/spans.jsonl`

| key | type | constraint |
|---|---|---|
| `span_id` | string | `^s1_[a-z2-7]{52}$` |
| `source_hash` | string | 64 lowercase hex; MUST equal the SHA-256 of some file under `content/` (`E_REF_SOURCE`) |
| `byte_start` | integer | see Section 12 |
| `byte_end` | integer | see Section 12 |
| `text` | string | see Section 12 |

## 12. Evidence byte offsets

Byte offsets refer to the raw bytes of the referenced content file (the
file whose SHA-256 equals `source_hash`).

For every row of `provenance.jsonl` and `spans.jsonl`:

- `0 ≤ byte_start ≤ byte_end ≤ size_of(content file)` — out-of-bounds or
  inverted ranges are `E_REF_SOURCE`.

Additionally, for every row of `spans.jsonl`:

- `content_bytes[byte_start:byte_end]` MUST decode as UTF-8, and the
  decoded string MUST equal `text` exactly (`E_REF_SOURCE` on invalid UTF-8
  or mismatch).

An I/O failure while reading a content file during these checks is
`E_REF_READ`.

## 13. Verification procedure

### 13.1 Trust model and CLI

Trust is anchored in a publisher public key obtained **out of band** (not
from the shard). The reference CLI form is frozen:

```
axm-verify shard PATH --trusted-key KEY
```

where `KEY` is a file containing the trusted 1344-byte hybrid public key.
The shard's embedded `sig/publisher.pub` MUST equal the trusted key
byte-for-byte; the embedded copy is a convenience, never an authority.

### 13.2 Procedure

A verifier MUST perform all of the following checks. The reference verifier
performs them in this order and stops at the first failing stage (a single
run reports the errors of one stage); other orderings are conformant so
long as a nonconforming shard is always rejected with an appropriate code.

1. **Layout** (Section 4): required items present, no extras, no symlinks,
   no dotfiles.
2. **Manifest** (Section 6): parse; canonical-encoding byte check; full
   field validation including `spec_version`, `suite`, `created_at`
   format, closed key set, absence of `shard_id`.
3. **Signature** (Section 7): trusted-key equality; both hybrid components
   verify over the domain-separated message.
4. **Merkle** (Section 8): recompute the root over the covered files;
   compare to `integrity.merkle_root`.
5. **Sources bijection** (Section 6.4): hash every file under `content/`;
   check both directions.
6. **Core tables** (Section 11): canonical JSONL form, exact key sets,
   types, enums, row order, primary-key uniqueness.
7. **Identifiers** (Section 10): recompute every `entity_id` and
   `claim_id`.
8. **References** (Sections 11–12): subject/object/claim_id/source_hash
   resolution; byte-range and span-text invariants.
9. **Statistics** (Section 6.1): `statistics.entities` and
   `statistics.claims` equal actual row counts.
10. **Profiles** (Section 15): run every listed profile the verifier
    implements; record the rest as unchecked.

Implementations MAY enforce resource-limit policies (maximum file sizes,
file counts, row counts) to bound work on hostile inputs; such limits are
implementation policy, not protocol, and MUST be generous enough to accept
the conformance vectors and the gold shard.

### 13.3 Result JSON

A verifier MUST emit a machine-readable JSON result on stdout with at least
these members:

```json
{
  "shard": "<path as given>",
  "status": "PASS" | "FAIL",
  "error_count": <integer>,
  "errors": [ { "code": "<ERROR_CODE>", "message": "<free text>" }, ... ],
  "profiles_checked": [ "<name@N>", ... ],
  "profiles_unchecked": [ "<name@N>", ... ]
}
```

- `status` MUST be `PASS` only when zero errors were found by the kernel
  checks **and** by every profile that was run.
- `errors[].code` values are normative (Section 14); `message` text is
  free-form and non-normative.
- `profiles_checked` lists the manifest-declared profiles this verifier
  implemented and ran; `profiles_unchecked` lists the manifest-declared
  profiles it did not run. Both keys MUST always be present (empty arrays
  when the manifest declares no profiles). **Unchecked is not passed**
  (Section 15.3).

### 13.4 Exit codes (frozen contract)

| Exit | Meaning |
|---|---|
| 0 | `status` is `PASS` |
| 2 | Verification failed and **every** reported error code is in `{E_LAYOUT_MISSING, E_SCHEMA_MISSING, E_SIG_MISSING}` — the shard directory is structurally malformed. A `PATH` that does not exist or is not a directory also exits 2. |
| 1 | Any other failure (bad signature, Merkle mismatch, manifest/schema violations, reference errors, profile failures, …) |

On failure the verifier SHOULD additionally print one line per error to
stderr in the form `CODE: message`.

## 14. Error codes

| Code | Meaning |
|---|---|
| `E_LAYOUT_MISSING` | Required root item absent, or shard path missing/not a directory |
| `E_LAYOUT_DIRTY` | Unexpected file/dir; symlink anywhere; resource-limit violation |
| `E_DOTFILE` | Dotfile anywhere in the shard tree |
| `E_MANIFEST_SYNTAX` | `manifest.json` is not valid JSON |
| `E_MANIFEST_SCHEMA` | Manifest violates Section 6: missing/mistyped field, non-canonical encoding, unknown or forbidden key (incl. `shard_id`), bad `created_at`, sources-bijection failure, statistics mismatch, unknown `suite` or `spec_version` |
| `E_SIG_MISSING` | `sig/manifest.sig` or `sig/publisher.pub` absent |
| `E_SIG_INVALID` | Wrong key/signature length, trusted-key mismatch, or either hybrid component fails to verify |
| `E_MERKLE_MISMATCH` | Computed Merkle root ≠ `integrity.merkle_root` |
| `E_SCHEMA_MISSING` | Required core table file absent |
| `E_SCHEMA_READ` | Table unreadable, malformed JSON line, non-canonical line encoding, row-order violation, or duplicate primary key |
| `E_SCHEMA_TYPE` | Unexpected key in a record, or wrong JSON type |
| `E_SCHEMA_NULL` | Required field missing from a record, or `null` |
| `E_SCHEMA_ENUM` | Invalid `object_type` or `tier` |
| `E_ID_ENTITY` | Stored `entity_id` ≠ recomputed value |
| `E_ID_CLAIM` | Stored `claim_id` ≠ recomputed value |
| `E_REF_ORPHAN` | Claim subject/object not in entities; provenance `claim_id` not in claims |
| `E_REF_SOURCE` | `source_hash` not a content-file hash; byte range out of bounds; span text/UTF-8 mismatch |
| `E_REF_READ` | Content file unreadable during evidence checks |

Profiles define their own error codes in their own documents (e.g.
`E_BUFFER_DISCONTINUITY` belongs to the `embodied@1` profile,
`spec/profiles/embodied@1.md`). Profile error codes flow into the same
`errors` array and cause `status: FAIL` and exit code 1.

## 15. Profiles

The kernel knows nothing about any application domain. A **profile** is a
named, versioned set of additional checks over `content/` and `ext/`,
defined in its own normative document at `spec/profiles/<name>@<version>.md`.

### 15.1 Declaration

A publisher declares compliance by listing profile identifiers in the
manifest's optional `profiles` array, e.g. `"profiles":["embodied@1"]`.
Because the manifest is signed, the compliance claim is non-repudiable.
The identifier grammar is `<name>@<version>` with `name` matching
`[a-z][a-z0-9-]*` and `version` a positive decimal integer. A new version
of a profile is a new identifier; profile documents, once published, are
frozen like the kernel.

### 15.2 Verifier obligations

- A verifier that implements a listed profile MUST run it. Profile errors
  make the shard FAIL exactly like kernel errors.
- A verifier that does not implement a listed profile MUST NOT fail the
  shard for that reason and MUST NOT run partial checks; it MUST report the
  profile in `profiles_unchecked`.
- Profiles not listed in the manifest MUST NOT be run against the shard for
  conformance purposes.
- An unrecognized profile *name* is not an error; that is the mechanism's
  point — profiles can be minted for decades without touching the kernel or
  old verifiers.

### 15.3 The unchecked-reporting rule

**Unchecked is distinct from passed.** A `PASS` with a non-empty
`profiles_unchecked` array means only the kernel guarantees (and any
checked profiles) hold; silence about a profile MUST never impersonate
verification of it. Consumers that rely on a profile's guarantees MUST
confirm the profile appears in `profiles_checked`.

### 15.4 Defined profiles

| Profile | Document | Summary |
|---|---|---|
| `embodied@1` | `spec/profiles/embodied@1.md` | Hot-stream continuity for embodied recordings (`content/cam_latents.bin`); error code `E_BUFFER_DISCONTINUITY` |

## 16. Extensions (`ext/`)

The optional `ext/` directory holds extension tables. Rules:

- `ext/` is fully Merkle-covered (Section 8): extension bytes are sealed
  and signed like everything else.
- `ext/` is **opaque to the kernel verifier**: extension contents never
  affect kernel verification (a profile MAY define checks over `ext/`).
- When `ext/` is non-empty, `manifest.extensions` MUST list the extension
  identifiers; when empty or absent, the field MUST be omitted
  (Section 6.2).
- Naming convention: `ext/<name>@<version>.<format-suffix>`. Extensions MAY
  use any file format; AXM-defined extensions use canonical JSONL
  (Section 5) with the same encoding discipline as the core tables.
- Shard ids inside extension tables MUST use the `sh1_` form (Section 9)
  and MUST refer only to *other* shards — never to the containing shard,
  whose id is ambient.

AXM-defined extensions (informative for the kernel; each is normatively
specified where registered): `lineage@1` (predecessor lineage rows:
`supersedes_shard_id` in `sh1_` form, `action` ∈
`supersede`/`amend`/`retract`, `timestamp`, `note`; **no self-id column**),
`references@1` (cross-shard claim references with `dst_shard_id` in `sh1_`
form), `locators@1` (structural positions of evidence spans), `temporal@1`
(claim validity windows). All four are `.jsonl`.

## 17. Conformance vectors

The vector suite is **normative ground truth** for this specification:

- `tests/vectors/identity.json` — canonicalization and identifier
  derivations, including adversarial Unicode cases (combining characters,
  casefold-expansion characters such as `ß` and `ﬁ`, Turkish dotless-i,
  Cyrillic confusables).
- `tests/vectors/merkle.json` — Merkle roots for known file sets.
- `tests/vectors/shards/valid/` — complete shards that MUST verify PASS.
- `tests/vectors/shards/invalid/` — complete shards that MUST verify FAIL,
  each targeting a specific check (including one vector per manifest field
  of Section 6, so a verifier that skips manifest enforcement cannot pass).
- The gold shard (see `spec/v1/CONFORMANCE.md`).

A verifier is conformant only if it produces the expected outcome on every
vector. See `spec/v1/CONFORMANCE.md` for the precise definition.
