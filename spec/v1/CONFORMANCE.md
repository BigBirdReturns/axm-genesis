# AXM Genesis Conformance v1.0.0

Status: **Normative. Frozen on release of v1.0.0.**

This document defines what it means for a shard and for a verifier to
conform to `spec/v1/SPECIFICATION.md` (hereafter "the Specification"), and
fixes the requirement set (REQ 1–4) that the kernel freezes.

## 1. Requirements

The kernel freezes four requirements. The former REQ 5 is no longer part of
the kernel: it moved, unchanged in substance, to the `embodied@1` profile.

| Req | Name | What it guarantees | Enforced by | Principal error codes |
|-----|------|--------------------|-------------|----------------------|
| REQ 1 | Manifest integrity | The manifest is complete, canonically encoded, internally consistent, and signed by the trusted publisher under the `axm-hybrid1` hybrid suite with the domain-separated message | Spec §6, §7 | `E_MANIFEST_SYNTAX`, `E_MANIFEST_SCHEMA`, `E_SIG_INVALID` |
| REQ 2 | Content identity | Every byte outside `manifest.json` and `sig/` is committed by the Merkle root; `sources` is a bijection with `content/`; evidence spans resolve to the exact bytes they quote | Spec §6.4, §8, §12 | `E_MERKLE_MISMATCH`, `E_MANIFEST_SCHEMA`, `E_REF_SOURCE`, `E_REF_READ` |
| REQ 3 | Traceable lineage | Every claim is content-addressed, references resolve (subject/object → entities, provenance → claims, hashes → content), and the graph tables are canonical, typed, ordered, and duplicate-free | Spec §10, §11 | `E_ID_ENTITY`, `E_ID_CLAIM`, `E_REF_ORPHAN`, `E_SCHEMA_READ`, `E_SCHEMA_TYPE`, `E_SCHEMA_NULL`, `E_SCHEMA_ENUM` |
| REQ 4 | Proof bundle | The shard carries complete, well-formed proof material: layout intact, `sig/publisher.pub` (1344 B) and `sig/manifest.sig` (2484 B) present, both hybrid components verifying | Spec §4, §7 | `E_LAYOUT_MISSING`, `E_LAYOUT_DIRTY`, `E_DOTFILE`, `E_SIG_MISSING`, `E_SIG_INVALID` |
| ~~REQ 5~~ | Non-selective recording | **Moved to the `embodied@1` profile** (`spec/profiles/embodied@1.md`). Applies only to shards whose manifest lists `"embodied@1"` in `profiles`; its error code `E_BUFFER_DISCONTINUITY` is a profile code, not a kernel code | Profile doc | `E_BUFFER_DISCONTINUITY` |

## 2. Conforming shard

A shard conforms if and only if it satisfies every MUST in the
Specification, Sections 4 through 12 and Section 16, i.e.:

- the layout of §4, byte-exact canonical `manifest.json` per §5–§6, and the
  hybrid signature material of §7;
- a Merkle root per §8 matching `integrity.merkle_root`;
- core tables in canonical JSONL per §11 with recomputable `e1_`/`c1_`
  identifiers per §10 and evidence invariants per §12;
- and, for every profile listed in `manifest.profiles`, the requirements of
  that profile's document.

## 3. Conforming verifier

A verifier conforms if and only if all of the following hold.

**Behavioral contract:**

1. It emits the machine-readable JSON result of Spec §13.3, including the
   `profiles_checked` / `profiles_unchecked` arrays.
2. It reports `PASS` only for shards that conform (Section 2), evaluated
   against the kernel plus the profiles it implements.
3. It reports `FAIL` with at least one specification-defined error code for
   every nonconforming shard.
4. It verifies against a trusted key supplied out of band and rejects
   shards whose embedded `publisher.pub` differs from it (Spec §13.1).
5. It never treats an unimplemented listed profile as passed, and never
   fails a shard solely because it lists a profile the verifier does not
   implement (Spec §15).
6. If it is a command-line tool, it implements the frozen CLI form and
   exit-code contract of Spec §13.1 and §13.4:
   `axm-verify shard PATH --trusted-key KEY`; exit 0 = pass; exit 2 =
   failure where every reported error is in
   `{E_LAYOUT_MISSING, E_SCHEMA_MISSING, E_SIG_MISSING}` or `PATH` itself
   is missing; exit 1 = any other failure.

**What it MUST accept:**

- The gold shard (Section 5), verified with the canonical publisher key.
- Every shard under `tests/vectors/shards/valid/`, verified with its
  accompanying key.

**What it MUST reject:**

- Every shard under `tests/vectors/shards/invalid/`, each with `FAIL`
  status and the exit-code class the vector prescribes. The invalid set
  includes, at minimum, one vector per manifest requirement of Spec §6
  (missing/mistyped field, bad `created_at`, present `shard_id`, broken
  `sources` bijection, wrong `statistics`), plus signature, Merkle,
  canonical-form, identifier, ordering/duplicate-key, reference, and
  evidence-span violations — so a verifier that skips any enforcement
  class cannot pass conformance.

**Vector-derived checks it MUST reproduce:**

- Every case in `tests/vectors/identity.json` (canonicalization outputs,
  rejected inputs, and full `e1_`/`c1_` derivations).
- Every case in `tests/vectors/merkle.json` (roots over the retained
  construction only — the legacy duplicate-odd-leaf construction is
  deleted and MUST NOT be implemented).

## 4. Vectors are ground truth

The conformance vectors are **normative**. Conformance is defined
operationally: a verifier is conformant exactly when it produces the
expected outcome for every vector *and* honors the behavioral contract of
Section 3. If prose and vectors are found to disagree, the vectors govern
until the discrepancy is resolved by RFC; a resolution that changes any
vector requires a new major format, not a mutation of this one.

## 5. Gold shard

The reference artifact is:

```
shards/gold/fm21-11-hemorrhage-v2/
```

minted under `axm-hybrid1` with an offline key ceremony (custody documented
in `keys/README.md`) and timestamp attestations under `attestations/`. It
is frozen and will never be recompiled. A change to the implementation or
the vectors that causes the gold shard to fail verification is rejected
outright.

The v0.x gold shard (`fm21-11-hemorrhage-v1`) and v0.x vectors are archived
history under `archive/v0/`; they are not normative and MUST NOT verify
under a v1 verifier.
