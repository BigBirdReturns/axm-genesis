# FINDINGS — building a v1 verifier from the spec and vectors alone

Every gap, ambiguity, or noteworthy confirmation encountered while
implementing `axm-verify-go` from `spec/v1/SPECIFICATION.md`,
`spec/v1/CONFORMANCE.md`, `spec/profiles/embodied@1.md`,
`COMPATIBILITY.md`, and `tests/vectors/**` — with zero access to the
reference implementation. Where the prose was ambiguous, the resolution
was chosen empirically against the vectors and is recorded here. This list
is the spec-improvement backlog.

## 1. CONFIRMED: the ML-DSA component really is FIPS 204 final ML-DSA-44

Checked empirically before anything else was built. The gold shard's and
the CI vectors' second signature half **verifies** with circl's
`sign/mldsa/mldsa44` (FIPS 204 final, pure ML-DSA, empty context) and
**does not verify** with circl's round-3 `sign/dilithium/mode2`. The spec's
claim (section 3: "FIPS 204, pure ML-DSA, empty context string") matches
the shipped artifacts exactly. No spec-vs-implementation divergence.
The public key parses as a valid 1312-byte ML-DSA-44 key; the signature is
2420 bytes; the Ed25519 half also verifies over the same domain-separated
message. Interop confirmed end to end.

## 2. Reproducing EXPECTED.md error codes requires replicating the staged stop

Spec 13.2 says the reference verifier "stops at the first failing stage (a
single run reports the errors of one stage); other orderings are
conformant". But several invalid vectors deliberately leave *later*-stage
defects in place (`merkle_mismatch` also has a stale `sources` hash;
`dup_primary_key` also has a stale `statistics.entities` — their READMEs
say so), and `EXPECTED.md` records only the single first-stage code. A
verifier that runs all stages and reports everything would emit extra
codes and fail a strict `error_codes` comparison against EXPECTED.md, even
though CONFORMANCE.md section 3 only binds the exit-code class and FAIL
status. **Resolution**: implemented the exact reference staging (layout →
manifest → signature → Merkle → bijection → tables → identifiers →
references → statistics → profiles), stopping at the first failing stage.
**Suggestion**: state explicitly whether the error-code *set* in
EXPECTED.md is binding, and if so, that the staged stop is effectively
part of the contract.

## 3. Entity-ID recomputation: which namespace?

Spec 10.3 derives `entity_id` from **`metadata.namespace`**, yet each
`entities.jsonl` row carries its own `namespace` field (spec 11.1 gives it
no constraint). Nothing says the verifier must check
`row.namespace == metadata.namespace`, and nothing says which of the two
feeds the recomputation. A row whose `namespace` differs from
`metadata.namespace` but whose id was derived from the row value would
pass one reading and fail the other. No vector covers this.
**Resolution**: recompute from `metadata.namespace` (the letter of 10.3);
the per-row field is effectively unvalidated redundancy.
**Suggestion**: either require row/manifest namespace equality or declare
the row field informative.

## 4. No error code for malformed `p1_`/`s1_` primary keys

Spec 10.6 says the kernel checks provenance/span id **syntax and
uniqueness**, and tables 11.3/11.4 give the regexes, but no error code is
named for a syntax violation (uniqueness falls out of the primary-key
rules as `E_SCHEMA_READ`). For `e1_`/`c1_` a syntax violation is subsumed
by the recompute-mismatch codes. No vector covers it. **Resolution**:
report `E_SCHEMA_TYPE` (reading a malformed id as "a value of the wrong
form"). **Suggestion**: name the code in section 11.

## 5. Are `integrity` and `statistics` closed objects?

Spec 6.3 explicitly permits extra members in `metadata`, `publisher`, and
`license` — and is silent about `integrity` and `statistics` (`sources`
elements are pinned to "exactly two keys"). The pointed enumeration
suggests the other two are closed, but it is never said. No vector covers
it. **Resolution**: treat `integrity` and `statistics` as closed
(`E_MANIFEST_SCHEMA` on extra keys). **Suggestion**: one sentence in 6.3.

## 6. Error class for numbers with no canonical encoding

A table line or manifest containing `1.5`, `-1`, `1e3`, or `01` parses as
JSON but has *no* canonical encoding (spec 5 rule 4 permits only integers
in [0, 2^63-1]). Two codes are defensible: `E_SCHEMA_TYPE` (wrong type) or
`E_SCHEMA_READ` (canonical re-encode-and-compare fails — it cannot even
produce bytes). No vector covers it. **Resolution**: the canonical-form
check fails first → `E_SCHEMA_READ` for table lines, `E_MANIFEST_SCHEMA`
for the manifest.

## 7. `null` is byte-canonical but forbidden — code precedence

`{"a":null}` is already in canonical byte form, yet spec 5 rule 5 forbids
`null` in kernel documents, and spec 11's table assigns null *values* to
`E_SCHEMA_NULL`. If the canonical-form check refused to re-encode `null`,
every null would surface as the less precise `E_SCHEMA_READ`.
**Resolution**: the canonical encoder passes `null` through, letting the
schema layer report `E_SCHEMA_NULL` (tables) / `E_MANIFEST_SCHEMA`
(manifest) — consistent with the `missing_field` vector's expectation of
`E_SCHEMA_NULL` for the sibling case of a *missing* key.

## 8. No error code for an empty `content/`

Spec 4: `content/` MUST contain at least one regular file — no code named.
**Resolution**: `E_LAYOUT_MISSING` (a required item is absent), which puts
the failure in the exit-2 structural class. Note the interplay: had the
layout stage not caught it, the non-empty-`sources` rule would catch it
later as `E_MANIFEST_SCHEMA` (exit 1). The choice of stage changes the
exit-code class. No vector covers it.

## 9. Missing `sig/` file: `E_SIG_MISSING` vs `E_LAYOUT_MISSING`

Spec 4 says a missing required root item is `E_LAYOUT_MISSING`; spec 7.1
says a missing key or signature *file* is `E_SIG_MISSING`. **Resolution**:
`sig/` directory itself absent → `E_LAYOUT_MISSING`; `sig/` present but a
file inside missing → `E_SIG_MISSING`. Both are in the structural exit-2
class, so the distinction is invisible to the CLI exit code, but the
`errors[].code` value differs. No vector covers the split.

## 10. `created_at`: leap seconds and lowercase designators

RFC 3339 permits `23:59:60Z` (leap second) and its ABNF is
case-insensitive (`t`/`z` are legal). Spec 6.1 says "RFC 3339 date-time in
UTC with the Z designator" and only explicitly rejects numeric offsets.
**Resolution**: require uppercase `T` and `Z` (reading "the `Z` designator"
literally) and reject second = 60 (Go's `time.Parse` does not accept leap
seconds). No vector covers either. **Suggestion**: pin both in 6.1.

## 11. `extensions` lacks the "no duplicates" clause

Spec 6.2 forbids duplicates in `profiles` and `supersedes` but not in
`extensions` — almost certainly an oversight. **Resolution**: followed the
letter; duplicate extension identifiers are not rejected.

## 12. `extensions` entries are not bound to `ext/` filenames

Spec 6.2 says `extensions` "MUST be present and list the extension
identifiers when `ext/` is non-empty", but `ext/<name>@<version>.<suffix>`
is only a *naming convention* (section 16) and extensions "MAY use any
file format", so there is no normative mapping from files to identifiers a
kernel verifier could enforce. **Resolution**: enforce only (a) the
presence/absence correlation between the field and a non-empty `ext/`, and
(b) the identifier grammar.

## 13. Profile reporting when the kernel fails before the profile stage

Spec 13.3/15 define `profiles_checked`/`profiles_unchecked`, but not what
they contain when verification stops before profiles run (e.g. a bad
signature on a shard declaring `embodied@1`). **Resolution**: profiles
that were declared but not run are reported in `profiles_unchecked`
(truthful: they were not checked); `profiles_checked` lists only profiles
actually executed. Both arrays are empty when the manifest itself is
unavailable or unparsable. No vector covers the early-stop case.

## 14. Non-regular files (FIFOs, sockets, device nodes)

Spec 4 forbids symlinks (`E_LAYOUT_DIRTY`) and speaks otherwise only of
regular files and directories. **Resolution**: any other file type
anywhere in the tree is `E_LAYOUT_DIRTY`.

## 15. Trusted-key input edge cases

The trusted key is out-of-band input, not shard material, so shard error
codes do not obviously apply to its defects. **Resolution**: an unreadable
key file is a command-line usage error (exit 2 per COMPATIBILITY section
4); a readable key of the wrong length simply fails the byte-for-byte
equality with the embedded `sig/publisher.pub` → `E_SIG_INVALID`.

## 16. I/O failure while hashing Merkle-covered files has no code

`E_REF_READ` is defined as "content file unreadable during evidence
checks"; no code covers an unreadable file during the *Merkle* pass (or
the sources-bijection hashing). **Resolution**: `E_REF_READ` for both.

## 17. The self-containment claim omits the Unicode/NFC dependency

Spec section 1 promises independence given "libraries for JSON, UTF-8,
SHA-256, BLAKE3, Ed25519, and ML-DSA-44" — but `canonicalize()` (section
10.1) also requires **Unicode NFC normalization** (pinned at 15.1.0),
which is a real library dependency in most languages (Go needs
`golang.org/x/text/unicode/norm`; the stdlib has none). Minor doc gap: add
"Unicode NFC" to the section-1 list.

## 18. Manifest that is valid JSON but not an object

Spec 6 distinguishes `E_MANIFEST_SYNTAX` (not valid JSON) from
`E_MANIFEST_SCHEMA` (everything else), but a top-level `[]` or `"x"` is
valid JSON and violates no *named* field constraint. **Resolution**:
`E_MANIFEST_SCHEMA`. Similarly, invalid UTF-8 inside manifest strings is
accepted by Go's JSON parser (replacement characters) and surfaces via the
byte-exact canonical comparison as `E_MANIFEST_SCHEMA`, not
`E_MANIFEST_SYNTAX` — the spec could classify encoding-level violations
explicitly.

## 19. Implementation trap: language-default JSON encoders do not match section 5

Recorded for future implementers (the spec's own Python one-liner hides
this): Go's `encoding/json` escapes `<`, `>`, `&` by default, emits
uppercase hex in `\uXXXX` escapes, and provides no way to get the exact
escape set of section 5 — a hand-written encoder (~60 lines) was required.
Likewise Go's parser silently keeps the *last* of duplicate keys; the
byte-exact re-encode comparison is what actually catches duplicate-key
documents. The spec's design (re-encode-and-compare) proved robust: every
such parser quirk is converted into a detectable byte difference.

## 20. EXPECTED.md profile columns assume the reference's profile set

The `valid/valid_embodied` row pins `profiles_checked = embodied@1`. The
preamble scopes the "only binding for verifiers implementing embodied@1"
caveat to `invalid/invalid_embodied_gap`, but a verifier *without*
`embodied@1` support also diverges on the valid row's `profiles_checked`
column (it would report `profiles_unchecked` and still PASS). Harmless
here — this verifier implements the profile — but the preamble sentence
should cover both rows.
