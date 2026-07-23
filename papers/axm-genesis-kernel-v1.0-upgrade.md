# AXM Genesis kernel paper — v0.6 → v1.0 upgrade

**Status:** reviewable upgrade content for the design paper. Drop these into your
source and re-export to produce v1.0. Nothing here changes the normative kernel
(`spec/v1.0/`, the gold shard, the verifier); it strengthens the *paper*.

Why a version bump rather than another erratum: v0.6 has one open erratum (the
Merkle description) and one argument that can now be stated from measurement, not
just construction (the runtime-entropy theorem). Folding both in is a v1.0, and it
makes the central claim *obvious* instead of merely valid.

---

## Metadata changes

- Title line: `Draft v0.6, June 2026` → **`v1.0, July 2026`**.
- Artifact commit: refresh the `Commit:` line to the current
  `axm-genesis` HEAD at export time (v0.6 referenced `6fa74b6d`).
- Add to the artifact-availability note: *"This version incorporates Erratum 1
  (Merkle construction, §6.3.3) and adds an empirical entropy measurement (§5.4).
  A capability companion — cheap-model reconstruction economics under this kernel
  — is reported separately (see `BigBirdReturns/tier-bench`, `experiments/tier-uplift`)."*

## Change 1 — fold in Erratum 1 (§6.3.3 Merkle construction)

Replace the v0.6 §6.3.3 prose with the normative construction already recorded in
[`docs/ERRATA.md`](../docs/ERRATA.md) (Erratum 1) and implemented in
[`src/axm_build/merkle.py`](../src/axm_build/merkle.py). The v0.6 text misstates
odd-node handling, the BLAKE3 "PARENT flag" phrasing, and dotfile exclusion; the
erratum's construction is authoritative. Once the paper carries the correct text,
add one line to `docs/ERRATA.md` under Erratum 1: *"Resolved in paper v1.0."*

## Change 2 — the centerpiece: state Theorem 5.1 from measurement (new §5.4)

v0.6 proves the runtime-entropy bound by construction: *if* the runtime processor
has `H(D_x) > 0`, determinism is unreachable by better selection. A reader can
still ask whether real frontier processors actually have `H(D_x) > 0` on the
outputs that matter, or whether that entropy is a corner case. It is not a corner
case — it is measurable, and it is present in the single strongest processor
available. Add the following subsection after §5.3.

> ### 5.4 The processor disagrees with itself: an empirical lower bound
>
> Theorem 5.1 assumes a runtime processor with non-zero output entropy. That
> assumption is not hypothetical. It can be observed directly, and — critically —
> it holds *within a single fixed model*, not merely across providers, versions, or
> sampling seeds.
>
> In a controlled elicitation, one frontier model was asked to judge the same fixed
> set of twelve candidate outputs two ways: as a holistic ranking, and as the
> aggregate of all pairwise comparisons. For a deterministic processor these must
> agree. They did not: the two induced rankings correlated at only ρ ≈ 0.43, and on
> near-equivalent pairs the model's pairwise preferences were unstable across
> elicitation. The processor is internally non-deterministic on this class of
> output. This is a measured instance of `H(D_x) > 0` for a *fixed* `L_θ`, holding
> `q` and `C(q)` constant — exactly the premise of Theorem 5.1, observed rather than
> assumed.[^tb]
>
> Two consequences sharpen the paper's thesis:
>
> 1. **The entropy is not rescued by retrieval, or by choosing a better model.**
>    If the best available processor disagrees with itself under fixed input, no
>    improvement to `C(q)` and no change of `L_θ` yields a reproducible answer at
>    query time. Corollary 5.1 is therefore not a conservative recommendation; for
>    outputs in this class it is forced. Determinism must come from the runtime
>    procedure, i.e. from `Query(q, S_verified)`.
>
> 2. **The entropy is concentrated where there is nothing to reconstruct.** The
>    same measurement, split by whether a judgment carried operational content,
>    found that on *decisive* calls — a clearly-correct output versus a clearly-wrong
>    one — agreement was near-total, while essentially all of the disagreement fell
>    on operationally-equivalent near-ties. The runtime entropy that Theorem 5.1
>    bounds is real, but it lives in the region the sand analogy (§5.1) names: the
>    grain-level arrangement of outputs that are interchangeable for the task. A VRA
>    compiles the *operational* content — the part that is stable and reconstructible
>    — and the variance it declines to reproduce is variance that carried no
>    knowledge to begin with.
>
> The practical reading: high-assurance systems lose nothing of value by removing
> the stochastic processor from the query-time authority path. What they give up is
> sand.
>
> [^tb]: Measurement and analysis: `BigBirdReturns/tier-bench`,
> `experiments/tier-uplift/task07_taste/` (pairwise elicitation, `analyze_pairwise.py`
> and `operational_reanalysis.py`; deterministic from the committed votes).

## Change 3 — one sentence in §8.4 (Incentives)

v0.6 argues VRA shifts cost from per-query inference to one-time compilation. That
cost shift now has a measured magnitude worth citing. Append to §8.4:

> Where a query can be answered by deterministic reconstruction, the marginal cost
> difference is not marginal: independent measurement of cheap-model reconstruction
> under a compile-once/verify-many discipline found end-to-end costs several times
> below a single frontier query for the same verified result. Compilation is paid
> once; the query path is local.

(Keep this to one sentence — it is a pointer, not a benchmark; the paper's
evaluation remains proof-by-construction per §7.5.)

## What v1.0 deliberately does NOT do

Per §7.5, this paper does not make capability or quality claims, and v1.0 keeps
that discipline. The capability results (a cheap model plus a harness matching or
beating a frontier model on operational tasks, and the operational/​sand
distinction) are the subject of a **companion**, not a section here. v1.0 cites the
companion once; it does not import it. The kernel paper stays about determinism,
provenance, and integrity — which is what makes it strong.

---

### Reviewer checklist for cutting v1.0

- [ ] Metadata: version → 1.0, date → July 2026, `Commit:` refreshed.
- [ ] §6.3.3 replaced with the Erratum-1 construction; ERRATA marked resolved.
- [ ] §5.4 inserted after §5.3, footnote wired.
- [ ] §8.4 one-sentence cost pointer added.
- [ ] Abstract: consider adding one clause — *"…and we exhibit a measured instance
      of the runtime entropy the argument assumes."*
- [ ] Nothing normative changed; gold shard, verifier, and spec untouched.
