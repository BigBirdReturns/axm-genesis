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
| [0005](0005-attestation-shards.md) | Attestation Shards — Portable Proof-of-When | **PROPOSED** — drafted 2026-07-02 | Convention + one extension: anchor a target shard's manifest bytes in time (RFC 3161 / OpenTimestamps), publish the proof as an ordinary v1 shard that cites its target via `references@1`, register `attestations@1` (composite sort key `(target_shard_id, kind, proof_path)`). Addresses DURABILITY §2.4 for arbitrary shards; no kernel change |
| [0006](0006-custody-evidence-extensions.md) | Custody Evidence Extensions — `packets@1` and `tpm-attestation@1` | **PROPOSED** — drafted 2026-07-03 | Register two index-into-content JSONL extensions so the custody spoke seals TPM trust-chain evidence through the one-pass compiler (`extra_content`/`extra_ext`) instead of a two-pass reseal. Binary blobs live in `content/`; rows index them by `(file, offset, length, sha256)`. TPM table named `tpm-attestation@1` to avoid colliding with RFC 0005's `attestations@1`. Independent of RFC 0004; no kernel change |
| [0007](0007-chat-extensions.md) | Chat Extensions — `episodes@1` and `engineering@1` | **PROPOSED** — drafted 2026-07-03 | Register two canonical-JSONL extensions so the conversation spoke seals its distilled episodic index + engineering-lens rows through the one-pass compiler (`extra_ext`) instead of post-compile Parquet injection + reseal. Array fields as JSON-array strings, `confidence` as a decimal string, `""` for absent, `shard_id` a foreign `sh1_` source reference; `engineering@1` joins `episodes@1` on `episode_id`. No kernel change; verifier stays opaque |
| [0008](0008-sealed-runs.md) | Sealed Runs — Deterministic Replay Across the Watershed | **PROPOSED** — drafted 2026-07-14, owner ratification required | Define an additive `replay-run@1` profile plus `replays@1` extension: games clients export a complete canonical replay package; Genesis seals it unchanged; a profile-aware independent verifier re-executes and byte-compares every checkpoint. Native unsigned runs still boot, the kernel stays frozen, and unchecked is never called replay-verified. |

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
