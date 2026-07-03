# AXM Perimeter Sweep — conformance against the genesis ground truth

**Date:** 2026-07-03
**Reference (ground truth):** `axm-genesis` `COMPATIBILITY.md` + `src/axm_verify/const.py` (RFC 0002 v1 kernel, tip `db89746`)
**Method:** read-only audit, one auditor per perimeter repo, run in parallel. No perimeter repo was modified. Headline findings re-confirmed firsthand against the cited `file:line`.
**Scope swept:** `axm-core`, `axm-chat`, `axm-embodied`, `axm-exposure`, `axm-wolf`, `axm-capability-claim-test`.

---

## TL;DR

**The load-bearing invariant holds across the entire perimeter.** *Genesis compiles and signs; everything else only reads.* No perimeter repo re-signs a manifest, mutates a Merkle root, adds a core-table field, emits/requires a `shard_id`, reimplements the Merkle construction, or writes Parquet inside a shard. Every sealing path delegates to the kernel's `compile_generic_shard`. Structurally, the seam that makes long-term verification possible is intact.

**The leaks are all at the edges** — verify-UI trust anchoring, "verified" badges, skill prose, and stale v0.x documentation — never in the crypto core. Nine findings, clustered into three themes:

| # | Repo | ID | Severity | One-line |
|---|------|----|----------|----------|
| 1 | axm-chat | F1 | **HIGH** | `verify` CLI + `/verify` anchor trust to the shard's *own* embedded `publisher.pub` → a re-signed tampered shard shows `PASS` |
| 2 | axm-core | F1 | MEDIUM | `IDENTITY.md` documents the deleted v0.x "first 15 bytes / `s_`/`p_`/`ea_`" id scheme, contradicting frozen §7 and core's own `INVARIANTS.md` |
| 3 | axm-core | F2 | MEDIUM | `axm list` prints "✓ verified" from the mere *existence* of `sig/manifest.sig` — verification is never run |
| 4 | axm-capability-claim-test | F1 | MEDIUM | `SKILL.md` + `claim.schema.json` state the gate as "not class `open`" (a blacklist that counts `judgment`), contradicting the enforced allowlist and the README |
| 5 | axm-core | F3 | LOW | Clarion retains guarded v0.x shims (`manifest.get("shard_id")` fallback, `claims.parquet` read fallback) |
| 6 | axm-embodied | F1 | LOW | Dead, unused local `span_id`/`prov_id` helpers mint 24-char `s_`/`p_` ids (never reach a shard) |
| 7 | axm-embodied | F2 | LOW | `docs/SPECIFICATION.md` carries legacy spoke-era table format (already annotated `drift-ok`) |
| 8 | axm-wolf | W7 | LOW | README/`PACK_AUTHORING.md` say pack-import UI is "not yet implemented" — it shipped |
| 9 | axm-wolf | W8 | LOW/INFO | Boundary lint blocklists bare `HP`/`EDS` case-sensitively — future false positives |

**Clean:** `axm-exposure` (honest independent Lean/PK-PD vertical), `axm-wolf` (all falsifiable claims true, provenance honestly disclaimed), `axm-embodied` (model citizen of the profile/extension mechanism).

---

## Ground truth — baseline confirmed

Before measuring the perimeter, the reference itself was spot-checked and holds:

- Gold shard `sig/manifest.sig` = **2484 bytes**, `sig/publisher.pub` = **1344 bytes** (exact frozen sizes).
- Gold manifest key set is closed and contains **no `shard_id`** (`{integrity, license, metadata, publisher, sources, spec_version, statistics, suite}`).
- `tests/test_compatibility_contract.py` enforces the exit-code contract end-to-end via subprocess and asserts `SUITE_HYBRID1 == "axm-hybrid1"`.

*(The BLAKE3 empty-tree constant could not be re-derived in the sandbox — `blake3` is not installed — an environment limit, not drift.)*

The rubric each auditor swept against is reproduced in the appendix.

---

## Theme A — Verification theater *(the one that matters)*

Two surfaces present a green "verified" signal that the genesis verifier would **not** grant. This is the only security-relevant class in the sweep.

### A1 · axm-chat F1 — `verify` anchors to the shard's own key **(HIGH)**

`src/axm_chat/cli.py:386` and `server/axm_server.py:812` both do:

```python
trusted_key = shard_path / "sig" / "publisher.pub"     # the shard's OWN embedded key
result = verify_shard(shard_path, trusted_key_path=trusted_key)
```

Passing the embedded key as the `--trusted-key` makes the trust anchor vacuous: the "does the embedded key equal the trusted key" check is satisfied by definition. An attacker who tampers with `content/`, recomputes the Merkle root, and re-signs the manifest under a **freshly minted** hybrid keypair (embedding their own `publisher.pub`) still gets `status: PASS`. The only thing that would catch this — comparing the embedded key to a known-good publisher key held **out of band** — is exactly what's bypassed.

This contradicts three things at once:
- **Genesis contract §4:** *"the trusted key … supplied out of band; the shard's embedded `sig/publisher.pub` must equal it byte-for-byte."*
- **axm-chat's own README (lines 62–66):** *"The trusted key is supplied out of band — from the sibling axm-genesis checkout, **never from inside the shard**."*
- **axm-chat's own `start.sh:169`,** which does it correctly: `axm-verify shard "$GOLD_DEST" --trusted-key "$GOLD_KEY"` where `GOLD_KEY` is the out-of-band `keys/gold-v2-provisional.pub`.

The genuine anchor is readily available (`~/.axm/keys/publisher.pub` for the user's own shards).

**Fix:** require an out-of-band `--trusted-key` (default `~/.axm/keys/publisher.pub`); refuse to fall back to `sig/publisher.pub`.

### A2 · axm-core F2 — `axm list` shows "verified" without verifying **(MEDIUM)**

`src/axm_core/cli.py:144`:

```python
sig_path = shard_dir / "sig" / "manifest.sig"
is_verified = sig_path.exists()          # existence, not verification
...
flag = "✓" if is_verified else "✗"
```

A shard with a present-but-invalid or tampered signature is listed as `✓`. A real `axm verify` exists and does the right thing; this is the *listing* over-claiming. (The same lines also read v0.x manifest keys `shard_type` and top-level `title`, which are not in the v1 closed key set — it degrades gracefully rather than crashing.)

**Fix:** compute the flag via the genesis verifier (as `cmd_verify` already does); drop the `shard_type` / top-level-`title` reads.

> **Pattern:** both A1 and A2 conflate "a signature file is present" (or "self-consistent") with "verified against a trusted publisher." A green check in AXM should mean the genesis verifier returned `PASS` against an out-of-band key — nothing less.

---

## Theme B — Stale v0.x lineage in docs & dead code

The code is conformant everywhere — identity is delegated to `axm_verify.identity`, and no v0.x id is ever *sealed*. The risk is purely that a human or extension author follows a stale document and mints non-conformant join keys.

- **axm-core F1 (MEDIUM):** `IDENTITY.md:38` — *"All `_b32_id` hashes: SHA-256 of UTF-8 input, **first 15 bytes**, base32 lowercase no padding, type prefix,"* with prefixes `ea_`/`s_`/`p_`. Frozen §7 requires the **full 32-byte** SHA-256 → 52 base32 chars with `e1_`/`c1_`/`p1_`/`s1_`. This also contradicts axm-core's *own* `INVARIANTS.md:61` (*"Full 32-byte SHA-256, base32lower, `e1_` prefix"*). No `_b32_id` function exists in the code — but an extension author trusting this doc would build wrong-length, wrong-prefix keys. **Fix:** rewrite the `IDENTITY.md` hash-function note and prefix table to match §7.
- **axm-embodied F1 (LOW):** `src/axm_embodied_core/ids.py` exports `span_id`/`prov_id` helpers that hash to 15 bytes → 24 chars with `s_`/`p_` prefixes. Never called in any shard-writing path (the kernel mints `s1_`/`p1_`); dead code. **Fix:** delete or align to `s1_`/`p1_` 52-char.
- **axm-embodied F2 (LOW):** `docs/SPECIFICATION.md:195-260` documents the legacy spoke-era table format (`e_/c_/s_/p_`, `.parquet`, extra provenance columns) — already annotated `<!-- drift-ok: historical spoke-era format … -->`. Non-binding; no core-table field is actually added. **Fix:** none strictly required.
- **axm-core F3 (LOW):** Clarion (`clarion/clarion/core.py:369`) keeps `manifest.get("shard_id", "unknown")` as a v0.x fallback on `blake3` import failure (unreachable — blake3 is a hard dep) and a `graph/claims.parquet` read fallback for old shards. Guarded, read-only, used only for AEAD AAD binding, never for identity/verification. **Fix (optional):** delete the dead v0.x branches now that v1 is pinned.

---

## Theme C — Rule semantics drift: prose/skill vs enforced code

### C1 · axm-capability-claim-test F1 — skill/schema loosen the sourcing gate **(MEDIUM)**

The enforced app uses an **allowlist** (`app/src/lib/runSourcingGate.ts:23`):

```ts
const SOURCING_CLASSES = new Set<EvidenceClass>(["confirmed", "reported", "derived"]);
```

with a comment explaining it deliberately rejects the "everything except open/judgment" blacklist so unknown/`judgment` classes fail closed. But two consumer-facing surfaces state the rule as a **blacklist**:

- `skill/capability-claim-test/SKILL.md:48` — *"A claim is **sourced** only if it cites a source and is **not class `open`**."*
- `schemas/claim.schema.json` (`sourceIds` description) — *"sourced iff it cites ≥1 source and is not class 'open'."*

"Not class `open`" counts `judgment` as sourced. The skill is billed as a zero-install, "no runtime" door, so a model following the prose (rather than calling the MCP tool, which shares the app's allowlist) could count a `judgment` field toward the three and unlock a verdict the page/MCP would refuse. That directly contradicts the README's own falsifiable claim: *"`judgment` [is] recorded but never enough to unlock a verdict."*

**Fix:** change both lines to the external-class allowlist wording — "class ∈ `confirmed` | `reported` | `derived`."

*(Everything else cct claims holds: gate = exactly 3, the four worked examples acquit/classify/refuse/route as advertised, object routing is structurally enforced, and the page is genuinely inert — no `fetch`/XHR/WebSocket, no API keys, no CDN/analytics, no storage, exports via in-browser Blob. No genesis over-claim.)*

---

## What's clean (positive confirmations)

- **The invariant, everywhere.** No re-signing, no `manifest.sig` writes, no `merkle_root` mutation, no Merkle reimplementation (no duplicate-odd-leaf, no sha256 tree, no rogue empty-constant), no `shard_id` field emitted, no suite-by-size detection, no second suite id. Sizes `2484/1344` appear only in imported constants, contract tests, and help text.
- **axm-embodied — CLEAN.** Binary sensor streams (`cam_latents.bin`, …) enter as `content/` files that the *kernel* Merkle-covers via `extra_content`; non-selectivity is the kernel-owned `embodied@1` **profile**, not new core-table fields; StrictJudge / citation / attestation data ride registered `streams@1` / `references@1` / `attestations@1` extensions. Verifies against an out-of-band governance key and requires `status == "PASS"`.
- **axm-exposure — CLEAN & honest.** Genuinely independent Lean/PK-PD vertical. Every executable README claim holds exactly (certify exit codes 0/0/0/2/3, byte-identical pre-rendered reports, a real "diff the demo bundle against the tree" CI check, proof hashes that match the kernel-checked `.lean` artifacts, 37 passing tests). Uses **none** of genesis's frozen crypto vocabulary; its own exit codes (0/2/3) legitimately differ and never collide because it never touches a shard.
- **axm-wolf — CLEAN & honest.** All falsifiable claims true: 7 sections / 58 prompts, runtime-derived with no hard-codes; the legacy "62 vs 58" reconciliation is fully consistent across `AUDIT.md`, the migration map, and the inventory; the engine boundary is real and lint-enforced; the engine stores testimony verbatim. `canonicalizePack`/`digestPack` is a deterministic, key-order-canonical SHA-256 — a separate local-provenance scheme that the docs go out of their way to disclaim (*"detects tampering, not authorship … not a genesis signature/Merkle/shard"*).
  - *One INFO nuance (W6):* Wolf's digest is JSON-structure-canonical but **not** Unicode-canonical (no NFC), unlike genesis's `canonicalize()` (NFC → ASCII-lowercase → strip-Cc → collapse-whitespace). Two Unicode-equivalent-but-differently-normalized packs digest differently. This is the single technical divergence from the genesis canonicalization discipline — correctly **not** represented as equivalence, so informational only.

---

## Recommended remediation order

1. **axm-chat F1 (HIGH)** — restore out-of-band trust anchoring in `verify` + `/verify`. This is the only finding with security weight; the fix is unambiguous and the repo already does it correctly in `start.sh`.
2. **axm-core F2 (MEDIUM)** — make `axm list`'s "✓" mean the verifier returned `PASS`, not "a file exists."
3. **axm-capability-claim-test F1 (MEDIUM)** — align `SKILL.md` + `claim.schema.json` to the enforced allowlist (two one-line edits).
4. **axm-core F1 (MEDIUM)** — rewrite `IDENTITY.md` to the frozen §7 id scheme; it contradicts the repo's own invariants doc.
5. **LOW/INFO cleanup** — delete dead v0.x id helpers/shims (embodied F1, core F3), refresh stale docs (embodied F2, wolf W7), harden the boundary lint (wolf W8).

None of these touch the kernel or the shard format. All are edits to perimeter docs / UI / skill surfaces.

---

## Appendix — the rubric (genesis frozen contract)

- **Sizes:** `manifest.sig` = 2484 B, `publisher.pub` = 1344 B (Ed25519 32/64, ML-DSA-44 1312/2420).
- **Suite:** exactly one, `axm-hybrid1` (Ed25519 ‖ ML-DSA-44); `suite` field required; no size-based detection.
- **Merkle:** BLAKE3 only. `Leaf = BLAKE3(0x00 ‖ relpath ‖ 0x00 ‖ bytes)`, `Node = BLAKE3(0x01 ‖ L ‖ R)`, RFC 6962 odd-promotion (no duplicate-odd-leaf), empty = `48fc721f…652b`. Hashed = every regular file except `manifest.json` and `sig/*`.
- **Sig message:** `b"axm-genesis/v1/manifest\x00" + manifest_bytes`.
- **Verifier:** `axm-verify shard <dir> --trusted-key <pub>`; exit 0 PASS / 1 fail / 2 malformed (2 only when every code ∈ `{E_LAYOUT_MISSING, E_SCHEMA_MISSING, E_SIG_MISSING}`); single-line JSON stdout; "unchecked profile ≠ passed."
- **Manifest:** closed key set; `spec_version="1.0.0"`, `integrity.algorithm="blake3"`, 64-hex `merkle_root`; **no `shard_id` field** (derived `sh1_"+hex(BLAKE3(canonical manifest))`).
- **Claim schema:** exact keys `{claim_id, subject, predicate, object, object_type, tier}`; `object_type ∈ {entity, literal:string, literal:integer, literal:decimal, literal:boolean}`; `tier ∈ 0..4`. All core-table key sets closed — adding a field is a breaking change (use a profile/extension instead).
- **IDs:** full 32-byte SHA-256, base32 lowercase, 52 chars, prefixes `e1_`/`c1_`/`p1_`/`s1_` (regex `[a-z2-7]{52}`).
- **canonicalize():** NFC → ASCII-only lowercase (not `casefold()`) → strip category-Cc → collapse whitespace.
- **Invariant:** Genesis compiles and signs; spokes/runtimes only read, build local caches *outside* the shard, and add data via profiles/extensions. No re-signing, no Merkle mutation, no symlinks/dotfiles.
