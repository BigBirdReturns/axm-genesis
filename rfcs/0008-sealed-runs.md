# RFC 0008: Sealed Runs — Deterministic Replay Across the Watershed

> **Status: PROPOSED — owner ratification required.** Drafted 2026-07-14
> (UTC). This RFC authorizes one deliberately narrow join between the games
> and ops lines. It does not amend the Genesis v1 kernel, the games platform
> constitution, or either line's product mission.

## Summary

Define the **sealed run**: an ordinary AXM Genesis v1 shard containing one
complete, canonical replay package for an AXM cartridge run. The shard declares
the additive `replay-run@1` profile and carries one `replays@1` extension row.
The kernel continues to do exactly what it does now — compile, sign, and verify
the custody envelope. A profile-aware games-line verifier additionally checks
that the package contains the validated cartridge, founding state, every
state-changing input in order, the expected resolution outputs, and the final
state; re-executes the journal under the named engine contract; and byte-compares
every checkpoint.

The one rule is:

> A run may be called **replay-verified** only when its shard passes Genesis
> verification, `replay-run@1` appears in `profiles_checked`, and deterministic
> re-execution matches every recorded checkpoint. A signature alone never makes
> that claim.

This is the convergence artifact between the two existing AXM product lines:
the games line contributes executable authored law and deterministic replay;
the ops line contributes sealed, signed, offline-verifiable custody. Neither
line reimplements the other.

## Motivation

The family already contains both halves of a sovereign executable record, but
not their join:

- `axm-arc` and `axm-world` validate content-addressed cartridges and execute
  them deterministically. World exports `axm-cartridge-run/v2`, but that object
  currently contains a readable summary and ledger — not the serialized engine
  state or ordered inputs required to reproduce its outcomes.
- `axm-genesis` seals immutable records under `axm-hybrid1`, binds every byte
  through the Merkle root, and supports independent offline verification from a
  frozen specification and vectors. Its shards remember; they do not execute.

Today a recipient can inspect a run's reported outcome, or rerun a simulation
from a seed in controlled tooling, but cannot take one exported player run and
prove all of the following from the artifact alone:

1. which exact authored cartridge governed it;
2. which exact state it began from;
3. which choices and assignments were applied, in what order;
4. which outputs and state transitions the engine produced;
5. whether failure and partial outcomes were retained as faithfully as success;
6. whether an independent compatible interpreter reproduces those bytes; and
7. whether any byte changed after the publisher sealed the record.

Genesis already provides (7). The games line can provide (1)–(6), but only if
the run record carries its inputs instead of merely summarizing its results.
This RFC composes the two properties without changing the kernel.

## Specification

### 1. Boundary and division of labor

The family boundary remains unchanged:

> **Genesis compiles and signs; everything else only reads.**

The responsibilities are:

| Component | Responsibility |
|---|---|
| Games runtime (`axm-arc` / `axm-world`) | Produce a canonical, unsigned replay package and continue to import/resume the native holder-owned run without any Genesis dependency. |
| Sealing adapter | Pass the package, explicit publisher metadata, and an explicitly selected private key to the one-pass Genesis compiler. It never hashes, signs, or rewrites a compiled shard itself. |
| Genesis kernel verifier | Verify manifest, Merkle root, signature, identity, lineage, and proof bundle exactly as it does for every v1 shard. It remains opaque to replay semantics. |
| `replay-run@1` verifier | Verify package structure and continuity, then re-execute through a conforming games engine and compare the recorded outputs and state checkpoints. |
| Runtime UI | Render trust states honestly: portable, sealed, replay checked/unchecked/failed, and independently verified are distinct facts. |

The native run export is not replaced by a shard. A holder may always play,
save, export, import, fork, and resume without a key, account, server, Genesis
installation, or platform permission. Sealing is an additive custody operation.

### 2. Shard layout

A sealed run is an ordinary Genesis v1 shard. In addition to the required core
files, it MUST contain these Merkle-covered files:

```text
content/
  cartridge.arc.json       canonical validated Arc bytes
  founding.json            canonical bootstrap input, including resolved seed
  founding-state.json      canonical engine state produced by founding.json
  journal.jsonl            complete ordered input/output journal
  final-state.json         canonical engine state after the final frame
ext/
  replays@1.jsonl          one index row for this replay package
```

The manifest MUST declare:

```json
{
  "profiles": ["replay-run@1"],
  "extensions": ["replays@1"]
}
```

Other profiles and extensions MAY coexist. For example, a later attestation
shard may timestamp the sealed run under RFC 0005. Nothing in this RFC makes a
timestamp mandatory or treats a self-asserted `created_at` as proof of time.

All five content files MUST appear in the manifest `sources` bijection and the
Merkle tree. The shard is compiled once. No game client or adapter may add the
profile, extension, or replay files after Genesis has signed the manifest.

### 3. Canonical replay package

The games line MUST publish a versioned replay-package specification and
conformance corpus named `axm-engine@1` before an implementation may claim this
RFC is implemented. The corpus, not a repository commit hash, defines compatible
execution behavior.

For `replay-run@1`:

- `cartridge.arc.json` MUST be exactly `canonicalizeArc(validatedArc)` encoded
  as UTF-8 with no byte-order mark. Recomputing `cartridgeDigest` over these
  bytes MUST yield the `cart1_` value in `replays@1`.
- `founding.json` MUST contain every input required to construct the initial
  runnable state from the embedded Arc, including the resolved PRNG seed and all
  bootstrap options. It may not rely on a client default, ambient randomness,
  locale, wall clock, or UI state.
- `founding-state.json` and `final-state.json` MUST use the canonical
  **run-state** serialization defined by `axm-engine@1`. That state contains the
  exact serialized `Organization` plus the shared append-only structured run
  record from which client ledger surfaces derive. It excludes prose, layout,
  animation, translated labels, and other presentation state. A replay verifier
  MUST reject a package that contains only the current
  `axm-cartridge-run/v2.runState` summary.
- `journal.jsonl` MUST be canonical JSONL: one canonical JSON object per line,
  LF separators, no blank lines, no floats, and no `null` placeholders where an
  omitted field or empty string is defined.
- Every state-changing operation after the founding state MUST appear exactly
  once in the journal. Navigation, animation, view selection, and other
  presentation-only actions MUST NOT appear.

`axm-engine@1` MUST freeze numeric semantics and encoding. Engine arithmetic is
finite IEEE 754 binary64 in the exact operation order exercised by the
conformance vectors. Integers in the safe range remain JSON integers. Every
non-integral binary64 value is serialized as a tagged lowercase string
`f64:<16-hex-big-endian-bits>`; negative zero normalizes to positive zero; NaN
and infinities are invalid. A verifier decodes the tagged value before
execution and re-encodes it for comparison. This prevents language-specific
decimal formatting from masquerading as a replay difference while preserving
the exact value the producer used.

The native games client MAY wrap these bytes in a holder-friendly archive or
JSON envelope. The replay bytes named above are normative; wrapper filenames,
download UX, and MIME types are not.

### 4. Journal frame contract

Every journal frame MUST contain:

| Field | Type | Meaning |
|---|---|---|
| `seq` | integer | Zero-based contiguous frame sequence. |
| `kind` | string | Versioned action kind defined by `axm-engine@1`. |
| `input` | object | Complete engine input for this transition; no UI-derived defaults may be omitted. |
| `output` | object | Canonical engine output produced by the transition. |
| `before_state_sha256` | string | Lowercase SHA-256 hex of canonical state bytes before the transition. |
| `after_state_sha256` | string | Lowercase SHA-256 hex of canonical state bytes after the transition. |
| `previous_frame_sha256` | string | Sixty-four zeroes for frame 0; otherwise the prior frame hash. |
| `frame_sha256` | string | Lowercase SHA-256 hex of the domain-separated canonical frame bytes with this field omitted. |

The frame hash preimage is:

```text
UTF8("axm-replay-run/v1/frame") || 0x00 || canonical_frame_without_frame_sha256
```

Frame 0's `before_state_sha256` MUST equal the SHA-256 of
`founding-state.json`. Every later frame's `before_state_sha256` MUST equal the
previous frame's `after_state_sha256`. The last frame's
`after_state_sha256` MUST equal the SHA-256 of `final-state.json`. An empty
journal is valid only when founding and final state bytes are identical.

The profile verifier MUST execute `founding.json` against the embedded Arc and
byte-compare the result with `founding-state.json` before processing frame 0.
The `axm-engine@1` action vocabulary MUST then cover every current
state-changing path, including at minimum:

- authored opening and drama choices;
- challenge selection, party assignment, difficulty posture, and resource
  spend;
- challenge resolution and all deterministic random draws derived from the
  recorded state and inputs;
- reward and loot choices;
- downtime, recruitment, progression, and other between-resolution mutations;
- explicit run completion, abandonment, and failed/partial resolution paths.

If a client can change durable engine or ledger state through an action not in
the versioned vocabulary, it is not yet conformant and MUST NOT export a shard
claiming `replay-run@1`.

### 5. Non-selective recording

The profile's honesty property is **complete state-transition recording**:

- success, partial, failure, rejected actions that consume or change state, and
  recovery actions are recorded under the same rules;
- a runtime may not begin or end the journal around a desirable interval;
- `seq` is gap-free and no frame may be deleted, reordered, or duplicated;
- the final serialized engine state and ledger MUST be derivable by replaying
  the complete journal from the founding state;
- a resolved encounter in the ledger without its causative journal frame is a
  profile failure; a journalled resolution without the corresponding ledger
  consequence is also a profile failure.

This is the games-line counterpart of `embodied@1` non-selective recording. It
does not reuse that profile's binary format or error code.

### 6. Extension `replays@1`

Register one canonical-JSONL extension. Version 1 permits exactly one row per
sealed run shard:

| Field | Type | Meaning |
|---|---|---|
| `cartridge_digest` | string | `cart1_` plus 64 lowercase SHA-256 hex characters, recomputed from `content/cartridge.arc.json`. |
| `engine_contract` | string | Exactly `axm-engine@1`. |
| `founding_input_path` | string | Exactly `content/founding.json`. |
| `founding_input_sha256` | string | Lowercase SHA-256 hex of the founding-input bytes. |
| `founding_state_path` | string | Exactly `content/founding-state.json`. |
| `founding_state_sha256` | string | Lowercase SHA-256 hex of the founding-state bytes. |
| `journal_path` | string | Exactly `content/journal.jsonl`. |
| `journal_sha256` | string | Lowercase SHA-256 hex of the journal bytes. |
| `frame_count` | integer | Number of journal frames. |
| `final_state_path` | string | Exactly `content/final-state.json`. |
| `final_state_sha256` | string | Lowercase SHA-256 hex of the final-state bytes. |

Sort key: composite `(cartridge_digest, journal_sha256)`, unique. The profile
MUST recompute every hash and count; the extension is a queryable index, not an
authority.

A later sealed checkpoint for the same continuing native run MUST include the
complete journal from its founding state, not only a delta. It SHOULD identify
the immediately prior sealed checkpoint through `lineage@1` with action
`amend`. Earlier checkpoints remain independently verifiable historical
records; the later shard is the more complete checkpoint, not a mutation of the
earlier bytes.

### 7. Profile `replay-run@1`

The normative profile document will live at
`spec/profiles/replay-run@1.md`. A conforming implementation MUST perform these
checks in order:

1. Require the five replay content files and exactly one well-formed
   `replays@1` row.
2. Validate and canonicalize the embedded Arc; recompute the `cart1_` digest.
3. Validate `founding.json`, execute it against the embedded Arc, and
   byte-compare the canonical result with `founding-state.json`.
4. Recompute content hashes, frame count, sequence continuity, state continuity,
   and the frame hash chain.
5. Validate every `kind` and `input` against `axm-engine@1`.
6. Load the verified founding state under the named engine contract.
7. Apply every input without consulting wall-clock time, locale, network state,
   ambient randomness, or UI defaults.
8. Byte-compare each canonical output and after-state hash.
9. Byte-compare the resulting final state with `final-state.json`.
10. Cross-check journalled resolutions against the final ledger in both
   directions.

Profile failures use profile-owned error codes:

| Code | Meaning |
|---|---|
| `E_REPLAY_LAYOUT` | Required replay file or extension row missing/extra/malformed. |
| `E_REPLAY_CARTRIDGE` | Embedded Arc invalid, non-canonical, or digest mismatch. |
| `E_REPLAY_FOUNDING` | Founding input invalid or its executed state differs from `founding-state.json`. |
| `E_REPLAY_CONTINUITY` | Sequence, state, or frame-hash chain has a gap, reorder, duplicate, or mismatch. |
| `E_REPLAY_ACTION` | Action kind/input is unknown or invalid for `axm-engine@1`. |
| `E_REPLAY_OUTPUT` | Re-executed output differs from the recorded canonical output. |
| `E_REPLAY_STATE` | Re-executed state differs from a checkpoint or final-state bytes. |
| `E_REPLAY_LEDGER` | Resolution journal and final ledger disagree. |
| `E_REPLAY_ENGINE_UNAVAILABLE` | Verifier cannot execute the named engine contract; it MUST report the profile unchecked rather than silently pass it. |

As required by Genesis profile law, a kernel-only verifier that does not
implement `replay-run@1` reports it in `profiles_unchecked` and may still return
kernel PASS. Consumers relying on replay MUST require it in
`profiles_checked`.

### 8. Claims and trust vocabulary

These labels are intentionally non-interchangeable:

| Claim | Required evidence |
|---|---|
| **Portable run** | Native game-client import/export roundtrip succeeds. |
| **Sealed run** | Genesis kernel PASS under an out-of-band trusted publisher key. |
| **Self-replayed** | The producing implementation re-executes the package successfully. Useful as a build guard, not independent verification. |
| **Replay-verified** | Kernel PASS and `replay-run@1` present in `profiles_checked`. |
| **Independently replay-verified** | Replay-verified by a second implementation built from the engine contract and vectors without importing the producing engine. |
| **Time-attested** | A valid external timestamp proof or attestation shard covers the sealed run. |

None of these means empirically true, institutionally certified, fair, safe,
authorized, or correctly modeled. A publisher signature identifies the sealing
publisher under the supplied trust anchor; it does not prove that publisher was
the player, creator, owner, or witness unless separate evidence establishes that
role.

Game-facing UI MUST NOT show “verified replay” for a self-replay alone. Until a
second implementation exists, the honest label is “self-replayed.”

### 9. Signing and custody

The sealer MUST require an explicit `axm-hybrid1` private key. There is no
default key, generated fallback, platform key, or server-side signing service.
The private key never enters a cartridge or run package and never ships in a
repository.

Signing is optional for play and mandatory only for producing a **sealed** run.
An unsigned native run remains fully playable and exportable. A cartridge may
also remain unsigned and boot; the embedded canonical Arc is sufficient for
replay. If the cartridge has separately been published as a Genesis shard, the
sealed run MAY cite that foreign `sh1_` through `references@1`, but such a
reference is additive and never substitutes for embedding the exact Arc bytes.

### 10. Conformance and independent implementation

The implementation lane MUST ship, before any production “replay-verified”
claim:

1. one frozen valid sealed-run vector with at least one successful, one partial,
   and one failed resolution in its journal;
2. invalid vectors for each profile error code;
3. the tamper trio: changed cartridge byte, changed input frame, changed final
   state byte;
4. a truncation/gap vector proving non-selective recording;
5. a cross-client vector produced in one games client and replayed in the other;
6. a second verifier implemented from `axm-engine@1` plus vectors without
   importing the producing engine package;
7. a gold roundtrip: native export → Genesis one-pass seal → kernel verify →
   replay verify → import/resume from the native package with identical final
   state.

Compatibility is mechanical. A runtime may call itself `replay-run@1`
compatible only if it accepts every valid vector, rejects every invalid vector
with the expected code, and reproduces the gold run's canonical outputs and
state bytes.

### 11. Implementation sequence

Acceptance authorizes the lane, not a one-PR cross-repository rewrite. Work
lands in this order:

1. **Games contract, arc first.** Specify `axm-engine@1`, canonical state bytes,
   the shared structured run record, action vocabulary, journal writer, and
   vectors in `axm-arc`. Existing client ledgers become projections or lossless
   migrations of that one record; no parallel source of outcome truth is added.
   Any engine/save changes originate there.
2. **World sync and native custody.** Re-vendor the shared surface; upgrade the
   holder-owned export/import path so a run carries exact state and journal
   bytes while old `axm-cartridge-run/v2` artifacts still boot or degrade
   honestly.
3. **Genesis additive registration.** Add `replays@1`, the
   `replay-run@1` profile document/hook, vectors, and tests. No v1 kernel field or
   construction changes.
4. **One-pass sealing adapter.** Add a small adopter/spoke that accepts the
   native replay package plus explicit key and calls Genesis compilation once.
   Its repository placement is decided during implementation review; it may not
   smuggle Python/kernel dependencies into the browser runtime.
5. **Independent verifier.** Implement from the contract and vectors; do not
   import the TypeScript engine implementation.
6. **Blind-party drill.** Separate cartridge publisher, run operator, sealer,
   and verifier. The operator receives no signing key; the verifier receives the
   public trust anchor out of band; adjudication records checked and unchecked
   layers separately.
7. **Three-minute convergence receipt.** Operate one cartridge, export the
   native run, seal it, verify it offline, replay it in the other client, and
   recover the same final state and ledger without an account or network.

Every step retains the existing repo-specific gates and the arc-first → world
sync discipline.

### 12. Non-goals and walls

This RFC does **not**:

- change `spec/v1`, the Merkle construction, signature suite, shard identity,
  core tables, or Genesis exit codes;
- authorize a client to compile or sign shards independently of Genesis;
- require signing, Genesis, an account, or a network connection to play or
  retain a native run;
- make the ops line wear game UI or the games line wear ops product language;
- define Program of Record as a cartridge or authorize its port;
- claim empirical truth, certification, legal admissibility, player identity,
  fairness, or authorship from deterministic replay;
- use wall-clock timestamps as run order; journal order is `seq` plus the hash
  chain;
- permit selective recording, summary-only replay, unknown action kinds, or
  “verified” language when the profile is unchecked;
- redesign campaign balance, game presentation, Library, Workshop, or the
  cartridge format beyond what exact replay requires.

## Backwards Compatibility

Purely additive at the Genesis layer. Existing shards, profiles, extensions,
vectors, keys, and verifiers are unchanged. Kernel-only verifiers report
`replay-run@1` as unchecked, exactly as profile law requires.

The games implementation MUST preserve existing cartridges, saves, ledgers, and
native run exports. A legacy run that lacks a complete journal may be imported
and resumed under existing migration law, but it can never be upgraded by
fabrication into a replay-verified record. Its honest state is “legacy — replay
inputs unavailable.”

## Reference Implementation

No implementation exists at proposal time. The current evidence for the gap is:

- `axm-world/src/world/custody.ts` — `axm-cartridge-run/v2` summary export;
- `axm-world/src/world/save.ts` — restorable serialized engine state exists in
  the local save but is not carried by the custody export;
- `axm-world/src/world/ledger.ts` — append-only consequence memory exists but
  lacks the causative inputs required for replay;
- `axm-genesis/spec/v1/SPECIFICATION.md` §15 — additive profile mechanism;
- `axm-genesis/spec/profiles/embodied@1.md` — precedent for non-selective
  recording as a profile;
- `axm-genesis/src/axm_build/ext_schemas.py` — one-pass extension registry;
- `axm-genesis/verifiers/go/` — precedent for a second implementation built
  from specification and vectors.

Implementing PRs will be linked here after acceptance. Status remains
**PROPOSED** until the owner resolves the decision table below.

## Owner decision table

| Decision | Recommendation | Honest alternative | Resolution |
|---|---|---|---|
| D1 — May a run cross the games/ops watershed? | **Yes, through this one profiled shard boundary.** The native run remains a games artifact; sealing is an additive custody operation. | Keep the lines entirely separate; runs remain portable but not Genesis-sealed. | Pending owner |
| D2 — Kernel change? | **No.** `replay-run@1` + `replays@1`; kernel stays frozen and opaque. | New Genesis core record type, rejected because execution is domain law. | Pending owner |
| D3 — Is sealing required to play? | **Never.** Unsigned cartridges and native runs always boot; trust remains a layer, not a gate. | Require sealed artifacts, rejected as a platform-constitution violation. | Pending owner |
| D4 — What proves replay? | **Complete inputs + deterministic re-execution + byte comparison.** A summary or matching final outcome is insufficient. | Treat ledger/result hashes as replay evidence, rejected because causes are missing. | Pending owner |
| D5 — What may UI claim before an independent verifier exists? | **Self-replayed**, never replay-verified. | Allow the producer to verify itself, rejected as circular evidence. | Pending owner |
| D6 — How are later checkpoints represented? | **New immutable shard with complete journal, linked by `lineage@1` action `amend`.** | Mutable/appendable shard or delta-only checkpoint, rejected because it breaks independent recovery. | Pending owner |
| D7 — Who signs? | **An explicitly selected publisher key; role is not inferred.** | Platform/default key, rejected because it centralizes custody and confuses identity. | Pending owner |
| D8 — Does this authorize a PoR product lane? | **No.** It supplies the custody/replay substrate only; PoR remains a separate owner decision. | Bundle PoR into this RFC, rejected as an uncabined second product decision. | Pending owner |
