# RFC 0004: Reseal Authorization Semantics

> **Status: PROPOSED** — drafted 2026-07-02 (UTC) from the Phase 3
> semantics in `docs/DURABILITY.md` §6.3, which requires an accepted RFC
> before the first real reseal is performed. No reseal may occur under
> spec/v1 until this RFC is accepted.

## Summary

Define what distinguishes an *authorized reseal* — re-signing an existing
shard's content under a stronger signature suite as older algorithms
weaken — from an unauthorized re-publication. Three requirements: the
reseal is additive (original manifest, signature, and public key are
retained inside the resealed artifact), key succession is provable (the
resealing key traces to the original publisher through signed rotation
statements), and the original Merkle root is anchored (timestamp proofs
committed before the reseal demonstrate the original bytes predate it).

## Motivation

The 30-year durability plan (`docs/DURABILITY.md` §6.3) depends on
resealing as the migration path when a signature algorithm weakens. A
reseal without authorization semantics is indistinguishable from an
attacker re-signing tampered content with their own key. The semantics
must be frozen *before* the first reseal, because the first reseal sets
the precedent every verifier will encode.

## Specification

To be completed before acceptance. The normative content will define:

1. **Additive structure.** Where the original `manifest.json`,
   `sig/manifest.sig`, and `sig/publisher.pub` live inside the resealed
   shard (proposed: `reseal/<n>/…`, Merkle-covered), and how the resealed
   manifest references the original's derived `sh1_` identity.
2. **Key succession.** The rotation-statement format (itself a shard, per
   §6.3), the chain-validation rule, and the failure mode when the chain
   is broken (verifiers MUST report re-publication, not reseal).
3. **Anchoring precondition.** The minimum timestamp evidence
   (RFC 3161 and/or OpenTimestamps, per the §6.4 cadence) that must exist
   for the original root before a reseal of it is authorized.
4. **Verifier behavior.** How a spec/v1 verifier reports reseal layers:
   checked, unchecked, or invalid — following the profile reporting rule
   (unchecked never impersonates verification).

## Backwards Compatibility

Additive. Shards without reseal layers are unaffected. The first version
of this RFC intentionally freezes semantics before any reseal exists, so
there is no migration burden.

## Reference Implementation

None yet. Must land with conformance vectors (valid reseal, broken
succession chain, missing anchor) before acceptance, per the project's
vector-first discipline.
