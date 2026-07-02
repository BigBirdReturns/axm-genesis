# RFCs — the decision log

Every change to frozen surfaces goes through an RFC (process in
[CONTRIBUTING.md](../CONTRIBUTING.md)). This index is the project's durable
decision record: what was proposed, what was decided, when, and by whom.
Accepted RFCs keep their resolved decision table inline, so the reasoning
that produced each freeze survives alongside the freeze itself.

| RFC | Title | Status | Decision |
|-----|-------|--------|----------|
| [0001](0001-post-quantum-suite.md) | Post-Quantum Cryptographic Suite | **IMPLEMENTED** | Added `axm-blake3-mldsa44` (ML-DSA-44, domain-separated Merkle, RFC 6962); legacy Ed25519 shards verify unchanged |
| [0002](0002-v1-reset.md) | The v1.0 Reset — Freeze Once, Freeze Right | **IMPLEMENTED** (accepted 2026-07-02 (UTC); pending ceremony + tag) | Hybrid suite `axm-hybrid1` (Ed25519 ‖ ML-DSA-44, both must verify); canonical JSONL core tables; ASCII-only lowercasing in `canonicalize()`; naming as proposed (`sh1_`, `e1_`, `c1_`, `p1_`, `s1_`). Spec/v1, kernel, vectors, provisional gold v2 landed; key ceremony and v1.0.0 tag remain (RELEASE.md) |
| [0003](0003-spec-v1-1-pinning-clarifications.md) | Spec v1.1 Pinning Clarifications | **SUPERSEDED** by 0002 | Fallback path not needed once the reset was accepted |
| [0004](0004-reseal-authorization.md) | Reseal Authorization Semantics | **PROPOSED** — specification text complete, ready for maintainer review | Additive reseal (`reseal/<n>/` layers, Merkle-covered, required `reseals` manifest field), provable key succession (`key-succession@1` statement shards; unvalidatable chain reports as re-publication), pre-anchored original root (≥1 RFC 3161 or upgraded OTS proof predating the reseal) — must be accepted before the first real reseal (DURABILITY §6.3). Vectors + reference implementation land with the implementing PR after acceptance |

## The template this sets

1. **Propose** — one file, `NNNN-short-title.md`, using the template in
   CONTRIBUTING.md: Summary, Motivation, Specification (exact deltas),
   Backwards Compatibility, Reference Implementation.
2. **Decide** — decision points go in a sign-off table with a
   recommendation and the honest alternative. The maintainer resolves them;
   the resolution is recorded inline with the date, and the original
   recommendation table is kept verbatim below it for the review history.
3. **Execute** — the RFC links its implementing branch/PR. Status moves
   PROPOSED → ACCEPTED → IMPLEMENTED (or REJECTED / SUPERSEDED, with a
   pointer to what replaced it).

All dates in this repository are UTC.

Nothing in `spec/` changes without a row in this table.
