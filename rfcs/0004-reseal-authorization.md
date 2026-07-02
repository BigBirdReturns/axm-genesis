# RFC 0004: Reseal Authorization Semantics

> **Status: PROPOSED** — drafted 2026-07-02 (UTC) from the Phase 3
> semantics in [`docs/DURABILITY.md`](../docs/DURABILITY.md) §6.3, which
> requires an accepted RFC before the first real reseal is performed. No
> reseal may occur under spec/v1 until this RFC is accepted.
>
> Specification complete — ready for maintainer review; conformance
> vectors and the reference implementation land with the implementing PR
> after acceptance, per the project's decide-then-execute discipline.

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

The 30-year durability plan ([`docs/DURABILITY.md`](../docs/DURABILITY.md)
§6.3) depends on resealing as the migration path when a signature
algorithm weakens. A reseal without authorization semantics is
indistinguishable from an attacker re-signing tampered content with their
own key. The semantics must be frozen *before* the first reseal, because
the first reseal sets the precedent every verifier will encode.

## Specification

All section references of the form §N are to
[`spec/v1/SPECIFICATION.md`](../spec/v1/SPECIFICATION.md) unless another
document is named. Requirements language is per §2 (RFC 2119 / RFC 8174).
This RFC is written as an **additive delta** to spec/v1: it defines one
new optional root directory (`reseal/`), one new manifest field
(`reseals`), one new shard kind (the key-succession statement, an
ordinary v1 shard carrying a registered extension), one new member of the
verifier result JSON, and three new error codes. Nothing already frozen
changes meaning; a shard with no reseal layers is bit-for-bit and
semantics-for-semantics unaffected.

Terminology used throughout:

- **Layer** *k* (for *k* = 1 … *N*): the *k*-th seal in a shard's history.
  Layer 1 is the original seal. After *N* reseals the shard has *N*
  retired layers stored under `reseal/` and one **live seal** (the current
  `manifest.json` + `sig/`), which we index as layer *N* + 1.
- **Superseding seal of layer *k***: layer *k* + 1 — the seal created by
  the reseal that retired layer *k* (the live seal, when *k* = *N*).
- **Resealing key / resealing suite**: the public key and suite of the
  live seal.

### 1. Reseal layout — additive, never destructive

#### 1.1 The `reseal/` directory

A resealed shard adds exactly one item to the §4 root layout:

```
manifest.json               required  (the live seal; §6 plus §1.4 below)
sig/manifest.sig            required  (signature of the live seal, §7)
sig/publisher.pub           required  (key of the live seal, §7)
reseal/                     required in a resealed shard; forbidden otherwise
reseal/1/manifest.json      required  (byte-exact original manifest)
reseal/1/manifest.sig       required  (byte-exact original sig/manifest.sig)
reseal/1/publisher.pub      required  (byte-exact original sig/publisher.pub)
reseal/2/ …                 one directory per retired layer
content/  graph/  evidence/  ext/     exactly as in §4, byte-identical
                                      across every layer (§1.3)
```

Byte-level rules, in the style of §4:

- `reseal/` MUST contain exactly the directories `1`, `2`, …, `N` for
  some *N* ≥ 1 — decimal, no leading zeros, contiguous from 1, nothing
  else. `reseal/<k>/` MUST contain exactly the three files
  `manifest.json`, `manifest.sig`, `publisher.pub` — nothing else, no
  subdirectories.
- `reseal/<k>/manifest.json` MUST be the byte-exact `manifest.json` of
  layer *k* as it existed when layer *k* was live; likewise
  `reseal/<k>/manifest.sig` = that layer's `sig/manifest.sig` and
  `reseal/<k>/publisher.pub` = that layer's `sig/publisher.pub`. A reseal
  moves the retired seal's three files into `reseal/<N>/` verbatim; it
  MUST NOT re-encode, reformat, or otherwise touch them.
- `reseal/` MUST be present if and only if the live manifest carries the
  `reseals` field (§1.4), and *N* MUST equal the length of that array.
- The dotfile and symlink prohibitions of §4 apply under `reseal/`
  unchanged.

Violations of this subsection are `E_RESEAL_LAYER` (§4.3), except that a
verifier which does not implement this RFC reports the pre-existing §4
codes (`E_LAYOUT_DIRTY` for the unexpected `reseal/` root item) and fails
the shard — see Backwards Compatibility.

#### 1.2 Merkle coverage of reseal layers

Reseal layers ARE Merkle-covered by the new root. This follows from §8.1
as written — the tree commits to every regular file under the shard root
except `manifest.json` and everything under `sig/`; files under
`reseal/` are neither — and this RFC makes it explicit and normative:
the nine-or-more bytes-exact files under `reseal/` contribute leaves
(`0x00 ‖ relpath ‖ 0x00 ‖ bytes`, §8.2) to the live seal's
`integrity.merkle_root` exactly like core-table files. The live
signature therefore seals the *entire prior history*: retired manifests,
retired signatures, retired keys. Tampering with any retired layer
breaks the live Merkle root (`E_MERKLE_MISMATCH`) before reseal-specific
checks even run.

Each retired layer's own root is recomputable from the shard alone. For
layer *k*, define the **layer-k covered set**: every §8.1-covered file
whose path does not begin with `reseal/`, plus every file under
`reseal/<j>/` for *j* < *k*. (For layer 1 this is exactly `content/`,
`graph/`, `evidence/`, and `ext/` — the covered set at original sealing
time. For the live seal it is everything, per the previous paragraph.)
The §8 root computed over the layer-k covered set MUST equal the
`integrity.merkle_root` inside `reseal/<k>/manifest.json`; a mismatch is
`E_RESEAL_LAYER`. This check proves the sealed content bytes are exactly
the bytes every earlier seal committed to — the additive-never-destructive
requirement of DURABILITY §6.3 point 1, made mechanical.

#### 1.3 What a reseal may and may not change

`content/`, `graph/`, `evidence/`, and `ext/` MUST be byte-identical
across all layers; §1.2's per-layer Merkle rule enforces this. A reseal
re-signs; it never re-compiles. Consequently every derived identifier
(§10), every table row, and every evidence offset (§12) is unchanged by
construction.

The live manifest MUST differ from `reseal/<N>/manifest.json` (its
immediate predecessor) in **at most** these members, and MUST be
byte-identical in all others after canonical re-encoding (§5):

| member | rule |
|---|---|
| `suite` | MAY change to the resealing suite (a suite is only valid if defined by an accepted RFC; today only `axm-hybrid1` exists) |
| `integrity.merkle_root` | MUST be recomputed over the enlarged covered set (§1.2) |
| `reseals` | MUST be extended by exactly one element (§1.4) |

Everything else — `spec_version`, `metadata.*` (including `created_at`,
which remains the *original* creation time), `publisher.id`,
`publisher.name`, `license`, `sources`, `statistics`, `profiles`,
`extensions`, `supersedes` — is copied verbatim. A reseal that edits a
title, a license, or a publisher name is not a reseal; it is a new
publication and MUST be rejected (`E_RESEAL_LAYER`). Key succession is
key-level, not identity-level: the publisher persists, the key rotates.

The resealed manifest remains canonical JSON (§5, §6) and is signed per
§7 with the domain-separated message unchanged
(`axm-genesis/v1/manifest` ‖ `0x00` ‖ manifest bytes). No new signing
domain is introduced: what makes a reseal distinguishable from the
original is the `reseals` field *inside* the signed bytes, not the
message framing.

#### 1.4 The `reseals` manifest field

This RFC adds `reseals` to the closed top-level key set of §6.3. It is
REQUIRED in a resealed manifest and FORBIDDEN (as today) in a manifest
with no reseal layers.

`reseals` is a non-empty array of objects; element *k* (1-based)
describes retired layer *k* and MUST have exactly these keys:

| key | type | constraint |
|---|---|---|
| `layer` | integer | MUST equal *k*, the element's 1-based position; binds the element to `reseal/<k>/` |
| `shard_id` | string | MUST match `^sh1_[0-9a-f]{64}$` and MUST equal `"sh1_" + hex(BLAKE3(bytes of reseal/<k>/manifest.json))` — the §9 identity of the retired seal, recomputed from the stored bytes. Element 1 is therefore the shard's **original** identity, permanently and verifiably named inside every future seal. |
| `resealed_at` | string | RFC 3339 UTC date-time with the `Z` designator, same grammar and validation rule as `metadata.created_at` (§6.1): the time at which layer *k* was retired. Values MUST be strictly increasing in *k*, and `resealed_at` of element 1 MUST NOT precede `metadata.created_at`. |
| `succession` | array of strings | The succession-statement reference: the `sh1_` ids (§9) of the key-succession statement shards (§2) that authorize the superseding seal's key, ordered oldest-to-newest. REQUIRED and non-empty when the superseding seal's `publisher.pub` differs byte-wise from `reseal/<k>/publisher.pub`; MUST be absent when the key bytes are identical (a same-key reseal, e.g. refreshing the wrapper after adding anchor coverage). No duplicates; each element MUST match `^sh1_[0-9a-f]{64}$`. |

Rules:

- Field-shape violations (wrong keys, bad types, bad `sh1_` grammar, bad
  timestamp grammar, `layer` ≠ position, array length ≠ *N*) are
  `E_MANIFEST_SCHEMA`, consistent with §6's treatment of manifest shape.
- Cross-checks against the shard bytes (identity mismatch with
  `reseal/<k>/manifest.json`, `succession` presence inconsistent with the
  actual key bytes, non-increasing `resealed_at`) are `E_RESEAL_LAYER`.
- Because `shard_id` here names a *predecessor* seal — never the live
  manifest's own (uncomputable) identity — the §9 rule that a shard never
  records its own id is preserved. Note the retired manifests inside
  `reseal/` themselves carry no id either; identity is recomputed, never
  stored, at every layer.

#### 1.5 Per-layer signature retention and checking

The retired signature is *evidence*, retained forever (DURABILITY §6.3:
"destroying it during migration converts the shard from 'provably sealed
in 2026' to 'asserted to have been sealed in 2026'"). A verifier:

- MUST verify `reseal/<k>/manifest.sig` over the §7.2 message built from
  `reseal/<k>/manifest.json`, using `reseal/<k>/publisher.pub`, under the
  suite named *inside* that stored manifest — **when it implements that
  suite**. Failure is `E_RESEAL_LAYER` (a shard whose sealed history is
  internally inconsistent is corrupt or forged, not merely old).
- MUST NOT fail a layer solely because it does not implement the layer's
  (retired, possibly long-broken) suite: the authorization evidence for
  such layers is the succession chain plus the anchor (§2, §3) — that is
  the entire point of resealing. The uncheckable signature stays sealed
  under the live Merkle root as historical evidence.

### 2. Key succession statements

#### 2.1 Statements are shards

Per DURABILITY §6.3, a rotation statement is itself a shard: an ordinary
spec/v1 shard, sealed and signed **by the OLD key while it is still
trusted**, whose sole payload is the declaration of its successor key. It
therefore inherits, with zero new machinery: canonical encoding (§5),
the closed manifest schema (§6), hybrid signature (§7), Merkle sealing
(§8), derived `sh1_` identity (§9), and anchorability (§3). Nothing
about a succession statement is special to the kernel verifier; the
semantics live in a registered extension.

#### 2.2 Record schema — `ext/key-succession@1.jsonl`

A succession statement carries the extension identifier
`key-succession@1` (declared in `manifest.extensions`, §6.2/§16) and the
file `ext/key-succession@1.jsonl`: canonical JSONL with the same encoding
discipline as the core tables (§11 rules 1–5), containing **exactly one
row** with exactly these keys:

| key | type | constraint |
|---|---|---|
| `old_key_sha256` | string | 64 lowercase hex — SHA-256 over the complete public-key bytes of the key being retired. MUST equal SHA-256 of the statement shard's own `sig/publisher.pub`: the statement is *self-signed by the old key*, so the retiring key's authority over the declaration is checked, not asserted. |
| `old_suite` | string | the suite identifier of the old key (today: `"axm-hybrid1"`); MUST equal the statement manifest's `suite` |
| `new_public_key_hex` | string | lowercase hex of the complete new public-key bytes (2688 hex characters for a 1344-byte `axm-hybrid1` key; length per the new suite's key definition) |
| `new_key_sha256` | string | 64 lowercase hex — SHA-256 over the new public-key bytes; MUST equal the hash of `new_public_key_hex` decoded |
| `new_suite` | string | the suite identifier the new key belongs to; MUST name a suite defined by an accepted RFC |
| `effective_at` | string | RFC 3339 UTC with `Z`, as §6.1 `created_at`: when the new key assumes authority |
| `note` | string | free text (MAY be empty): human context for the rotation |

The statement's `content/` MUST contain a human-readable rendering of
the same declaration (the §4 rule that `content/` is non-empty holds; a
succession whose machine record and human record disagree fails no
kernel check, so the machine record in `ext/` is the normative one).

Succession statements SHOULD be anchored (§3) at sealing time: the
anchor is what makes "signed by the old key *while still trusted*"
provable later, rather than merely asserted — after the old suite
breaks, a forger can back-date a statement's `created_at` but cannot
back-date a timestamp proof.

#### 2.3 Chain-validation rule

Given a trusted original-publisher key `K₀` obtained out of band (§13.1
— the trust anchor for a resealed shard's *history* is the original key,
exactly as for an unresealed shard), and a `succession` array
`[S₁, …, Sₘ]` from a `reseals` element for layer *k*, the chain
validates iff **all** of the following hold:

1. **Start**: `K₀` for this chain is the key stored at
   `reseal/<k>/publisher.pub`. For *k* = 1 it MUST equal, byte-for-byte,
   the out-of-band trusted original key; for *k* > 1 trust in it is
   established transitively by the validated chains of layers 1 … *k*−1
   (whose termination rule, condition 5, ends at exactly this key).
2. **Resolution**: each `Sᵢ` resolves to a shard whose recomputed §9
   identity equals the listed `sh1_` id. Statement shards are supplied
   to the verifier out of band (a directory or lookup service); the id
   binds the bytes exactly, so *where* they come from carries no trust.
3. **Statement validity**: each `Sᵢ` verifies as a spec/v1 shard (§13.2,
   all kernel checks) using its own embedded `sig/publisher.pub` as the
   trusted key for this purpose, and declares `key-succession@1` with a
   well-formed single-row table (§2.2).
4. **Linkage**: for each *i*, `Sᵢ.old_key_sha256` =
   SHA-256(`Kᵢ₋₁`) — the statement is signed by the key it retires — and
   `Kᵢ` := the key bytes decoded from `Sᵢ.new_public_key_hex`.
5. **Termination**: `Kₘ` equals, byte-for-byte, the `publisher.pub` of
   the superseding seal of layer *k* (`reseal/<k+1>/publisher.pub`, or
   the live `sig/publisher.pub` when *k* = *N*), and `Sₘ.new_suite`
   equals that seal's manifest `suite`.
6. **Monotonicity**: the statements' `effective_at` values are strictly
   increasing, and `Sₘ.effective_at` does not postdate
   `reseals[k].resealed_at`.

#### 2.4 Failure mode — re-publication, never reseal

Two distinct failure modes, and the distinction is normative:

- **Unvalidatable** (evidence absent): one or more listed statement
  shards were not supplied to the verifier. The layer MUST be reported
  as **unchecked** (§4.2). An unvalidatable chain MUST be reported as
  **re-publication, never reseal**: tooling, result renderers, and
  downstream consumers MUST NOT describe the artifact as a verified
  reseal of the original `sh1_` identity; the strongest honest statement
  is "an artifact *claiming* succession from `sh1_…`, unverified." This
  mirrors §15.3 — silence about evidence never impersonates verification
  of it.
- **Invalid** (evidence present, checks fail): any of §2.3's conditions
  1–6 fails on supplied statements. This is a **hard failure**:
  `E_RESEAL_CHAIN`, `status: FAIL`, exit code 1. A reseal signed by a
  key that does not provably trace to the original publisher is exactly
  the attack this RFC exists to prevent, and MUST NOT be reported as
  merely "unchecked" — the shard affirmatively claims a succession that
  is demonstrably false.

### 3. Anchoring precondition

A reseal is only as good as the proof that the original bytes predate it
(DURABILITY §6.3 point 3): after the original suite breaks, the retired
signature no longer proves anything by itself, and `created_at` is
self-asserted. Timestamp evidence, committed while the original
cryptography still held, is what breaks the symmetry between the true
original and a back-dated forgery.

#### 3.1 Minimum evidence (producer-side MUST)

Before performing reseal *N* (retiring layer *N*), the resealer MUST
hold, for the layer-being-retired's manifest bytes (equivalently, for
its Merkle root, which those bytes contain — §9's commitment argument),
**at least one** of:

- an **RFC 3161 timestamp token** from a TSA, whose `messageImprint` is
  the SHA-256 of the exact bytes of what becomes
  `reseal/<N>/manifest.json`, with the TSA certificate chain retained
  alongside it (the vendoring pattern of
  [`attestations/README.md`](../attestations/README.md)); or
- an **OpenTimestamps proof upgraded to a Bitcoin attestation** (a
  *pending* calendar promise does not satisfy the precondition; run
  `ots upgrade` first) over the same digest.

Its attested time MUST be earlier than the reseal's `resealed_at`. Per
the DURABILITY §6.4 cadence, publishers SHOULD hold proofs from **two
independent venues** (one RFC 3161 TSA and OpenTimestamps) and SHOULD
have been anchoring on a fixed cadence since first publication — the
minimum above is the authorization floor, not the recommended practice,
because every unanchored year is irreversible (§6.4). For layer 1 this
evidence anchors the *original* root, which is the load-bearing case;
each subsequent reseal anchors its immediate predecessor the same way,
extending the chain of custody in time.

#### 3.2 Where proofs live

Anchor proofs are stored **outside the shard**, in the publisher's
attestation archive, following the existing
[`attestations/`](../attestations/README.md) pattern (query/response/
certificate files per digest for RFC 3161; `.ots` files for
OpenTimestamps). They cannot live inside the layer they attest (they
postdate its sealing), and this RFC deliberately does not seal them into
later layers either: proofs are renewed and upgraded over time
(RFC 4998 spirit, DURABILITY §2.4), so freezing one snapshot into the
Merkle tree would privilege a stale proof. Proofs are supplied to the
verifier out of band, like the trusted key (§13.1) and the succession
statements (§2.3): keyed by the digest they attest, so provenance of the
proof files themselves carries no trust — either the token verifies over
the recomputed digest or it does not.

#### 3.3 How a verifier checks the linkage

For each layer *k* with anchor evidence supplied, the verifier:

1. recomputes SHA-256 over the exact bytes of
   `reseal/<k>/manifest.json`;
2. checks the proof binds that digest — RFC 3161: the token's
   `messageImprint` octets equal it and the token verifies against the
   supplied TSA chain (e.g. `openssl ts -verify`); OpenTimestamps: the
   proof commits to it and terminates in a Bitcoin block attestation;
3. checks the attested time (RFC 3161 `genTime`; for OTS, the anchoring
   block's timestamp) is **earlier than** `reseals[k].resealed_at`;
4. on any mismatch, invalid token, unupgraded (calendar-only) OTS proof,
   or time ordering violation: `E_RESEAL_ANCHOR`, hard failure.

If no anchor evidence for layer *k* is supplied, the layer is at best
**unchecked** (§4.2) — never failed for absence, never reported
authorized without it.

### 4. Verifier behavior

#### 4.1 Procedure (delta to §13.2)

For a shard whose manifest carries `reseals`, a conforming verifier runs
the §13.2 procedure on the live seal exactly as today — with the
resealed layout of §1.1 accepted, the `reseals` field validated per
§1.4, `--trusted-key` naming the **resealing** key (the §13.1 byte-
equality rule binds `sig/publisher.pub` unchanged) — and then, per
retired layer *k* = 1 … *N*:

1. structural checks (§1.1) and manifest-copy discipline (§1.3);
2. identity recomputation (§1.4 `shard_id` rule);
3. per-layer Merkle recomputation (§1.2);
4. per-layer signature verification where the suite is implemented
   (§1.5);
5. succession-chain validation, if the key changed and statements are
   supplied (§2.3);
6. anchor validation, if proofs are supplied (§3.3).

A layer is **checked** when 1–4 pass and both 5 and 6 were run and
passed (a same-key layer with no `succession` field needs only 6).
A layer is **unchecked** when 1–4 pass but the out-of-band evidence for
5 and/or 6 was not supplied. Any failure in 1–6 on supplied material is
a hard error (codes below) and fails the shard.

#### 4.2 The `reseals` result field

The §13.3 result JSON gains one member, present if and only if the
manifest declares `reseals`, mirroring the profile checked/unchecked
reporting rule (§13.3, §15.3):

```json
"reseals": {
  "declared": <N>,
  "checked":   [ <layer indices validated end-to-end> ],
  "unchecked": [ <layer indices lacking succession and/or anchor evidence> ]
}
```

- Every layer 1 … *N* appears in exactly one of the two arrays when
  `status` is `PASS`.
- **Unchecked is not authorized.** A `PASS` with a non-empty
  `reseals.unchecked` array means only: the live seal verifies, the
  layer bytes are internally consistent and Merkle-sealed. It does NOT
  mean the reseal was authorized by the original publisher. Consumers
  that rely on succession from the original `sh1_` identity MUST confirm
  the relevant layer appears in `reseals.checked` — exactly as consumers
  of a profile's guarantees must find it in `profiles_checked` (§15.3).
  Renderers MUST describe unchecked layers as unverified re-publication
  claims (§2.4), never as reseals.
- Shards without reseal layers omit the member entirely; their result
  JSON is byte-compatible with today's.

#### 4.3 Error codes (additive)

Three codes join the §14 table; like profile codes, they flow into the
same `errors` array, force `status: FAIL`, and exit 1 (§13.4's frozen
contract is untouched — none of them is in the exit-2 malformed set,
because a reseal failure is a *verification* failure of an existing,
structurally complete shard, not a missing-shard condition):

| Code | Meaning | Why a distinct code is justified |
|---|---|---|
| `E_RESEAL_LAYER` | A retired layer's own invariants fail: `reseal/` layout violations (§1.1), manifest-copy discipline (§1.3), stored-identity mismatch (§1.4), per-layer Merkle mismatch (§1.2), or a retired signature that fails under its own stored key and implemented suite (§1.5) | This is tampering with *sealed history* — a different event, with a different response (treat the artifact as forged), than a bad live signature (`E_SIG_INVALID`) or a bad live tree (`E_MERKLE_MISMATCH`). Reusing kernel codes would make "the current seal is bad" and "someone rewrote the past" indistinguishable to tooling. |
| `E_RESEAL_CHAIN` | Supplied succession statements fail chain validation (§2.3 conditions 1–6): bad statement shard, key-hash linkage broken, terminal key ≠ resealing key, ordering violations | The unrelated-key reseal is the core attack of this RFC's threat model. It must be a *named, hard* failure so that no implementation can soft-pedal it into "unchecked" (§2.4), and so conformance vectors can pin the exact code. |
| `E_RESEAL_ANCHOR` | Supplied timestamp evidence fails (§3.3): digest mismatch, invalid or unupgraded proof, or attested time not earlier than `resealed_at` | Anchor failure defeats sealed-before-break, the property Phase 4 verification rests on (DURABILITY §6, §6.4). It is orthogonal to chain failure — a perfect succession chain with a forged anchor is still an unauthorized reseal — so conflating the two codes would erase exactly the diagnostic a 2045 verifier needs. |

Per §13.4, on failure each is additionally printed to stderr as
`CODE: message`.

### 5. Composition summary (informative)

Everything above reuses frozen machinery: canonical JSON (§5) encodes
the `reseals` field and the succession row; the §7 hybrid signature and
domain prefix are unchanged at every layer; the §8 Merkle construction
covers `reseal/` with no new rules; §9 identity names retired layers and
succession statements; §11's JSONL discipline governs
`ext/key-succession@1.jsonl`; §16 hosts the extension; the §15.3
unchecked-reporting philosophy governs the result field; and the
[`attestations/`](../attestations/README.md) pattern supplies the anchor
format. The only genuinely new surface is the authorization *rule* — the
three requirements of the Summary — which is precisely what DURABILITY
§6.3 said had to be decided by RFC before the first reseal.

## Decision points for the maintainer

Per the [`rfcs/README.md`](README.md) process, the open decisions, with
recommendations. Acceptance resolves them inline.

| # | Decision | Recommendation | Honest alternative |
|---|---|---|---|
| D1 | Anchor floor: one venue or two? | **MUST ≥ 1, SHOULD 2** (§3.1) — a floor of two makes the first reseal hostage to any one venue's availability | MUST 2, matching the §6.4 recommendation exactly; stronger, but brittle |
| D2 | Same-key reseals (no succession chain) permitted? | **Yes** (§1.4) — needed for wrapper-refresh reseals and suite migration under an unchanged publisher keypair is impossible anyway (new suite ⇒ new key format), so the allowance is narrow | Forbid; every reseal requires a rotation, simplifying the field to always-required |
| D3 | Reseal errors named codes vs reusing kernel codes | **Named codes** (§4.3) | Reuse `E_SIG_INVALID`/`E_MERKLE_MISMATCH`/`E_MANIFEST_SCHEMA`; fewer codes, lost diagnostics |

## Backwards Compatibility

Additive. Shards without reseal layers are unaffected: no layout change,
no manifest change, no result-JSON change, no new obligations. The first
version of this RFC intentionally freezes semantics before any reseal
exists, so there is no migration burden.

A **pre-0004 verifier** given a *resealed* shard fails closed: the
unexpected `reseal/` root item is `E_LAYOUT_DIRTY` and the unknown
`reseals` manifest key is `E_MANIFEST_SCHEMA` (§4, §6.3). It can never
silently mis-verify a resealed shard, and — consistent with §15.3's
philosophy — rejecting what it cannot understand is the correct behavior
for a verifier that predates these semantics. Conversely, deleting
`reseal/` and restoring `reseal/1/`'s three files to the root positions
reconstructs the original shard byte-for-byte, which verifies under
unmodified spec/v1 rules for as long as its suite stands.

## Reference Implementation

None yet — deliberately. Specification complete — ready for maintainer
review; conformance vectors and the reference implementation land with
the implementing PR after acceptance, per the project's
decide-then-execute discipline. The implementing PR MUST include, per
§17's vector-first rule, at minimum: a valid resealed shard (checked
end-to-end), a valid-but-unchecked reseal (evidence withheld), a broken
succession chain (`E_RESEAL_CHAIN`), a missing/invalid anchor
(`E_RESEAL_ANCHOR`), a tampered retired layer (`E_RESEAL_LAYER`), and a
valid `key-succession@1` statement shard — plus the negative vector for
each `reseals` field constraint of §1.4.
