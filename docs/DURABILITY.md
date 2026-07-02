# AXM Genesis — 30-Year Durability Assessment and Roadmap

**Status**: Advisory (non-normative)
**Date**: 2026-07-01
**Scope**: Full audit of the repository at the time of writing — the kernel paper
(`papers/axm-genesis-frozen-cryptographic-kernel-v0.6.pdf`), the specification
(`spec/v1.0/`), the reference implementation (`src/`), the conformance suite
(`tests/`), the gold shard, and the project's process documents.

The project's central promise is that a shard sealed today is verifiable
decades from now. This document lists everything that currently works against
that promise, ordered by urgency. Sections 1–2 are things that are broken or
contradictory *today*. Sections 3–5 are the structural work a 30-year horizon
actually requires.

---

## Remediation status (2026-07-01)

Status of the headline findings after the first remediation change set. The
report body below is unchanged and still describes the state *at audit time*;
this table is the only part that tracks fixes. Findings not listed here
remain open.

| Finding | Where | Status |
|---|---|---|
| Test pollution breaks `make test` (§1.1) | `tests/test_mldsa_backend_contract.py` | **Fixed** — autouse fixture restores the real backend and re-reloads `axm_build.sign` / `axm_verify.crypto` after every reload-based test |
| No CI (§1.2) | `.github/workflows/` | **Added** in this change set — conformance suite plus a dedicated gold-shard verification job |
| COMPATIBILITY.md contradicts spec and code (§1.3) | `COMPATIBILITY.md`, `tests/test_compatibility_contract.py` | **Corrected + drift-tested** — rewritten against the spec/code; a new test mechanically checks its checkable claims (suite identifiers, schema columns, exit codes) |
| Verifier under-enforces the manifest schema (§3.1) | `src/axm_verify/logic.py` | **Enforced** — spec §5.2 required fields now validated, `E_MANIFEST_SCHEMA` names the offending field |
| Hardcoded gold-shard signing key (§2.1) | `src/axm_build/cli.py`, `shards/gold/README.md`, `keys/README.md` | **Removed from the CLI** (signing now requires `--private-key` / `AXM_SIGNING_KEY_HEX`); the gold shard's zero-authentication-value caveat is documented where the key and shard live |
| Paper §6.3.3 Merkle description wrong (§1.5) | `docs/ERRATA.md` Erratum 1, `papers/README.md` | **Erratum published** — correct construction reproduced; paper README points readers to it. Paper v0.7 fix still pending |
| Unicode version unpinned (§3.3) | `docs/ERRATA.md` Erratum 2, `rfcs/0003-spec-v1-1-pinning-clarifications.md` | **Erratum + RFC 0003** — `tests/vectors/identity.json` declared the normative anchor; spec v1.1 pinning proposed. Spec text itself unchanged (frozen) |
| Parquet subset unpinned (§3.2) | `docs/ERRATA.md` Erratum 3, `rfcs/0003-spec-v1-1-pinning-clarifications.md` | **Erratum + RFC 0003** — de-facto subset recorded; spec v1.1 pinning proposed. Spec text itself unchanged (frozen) |
| Key rotation / trust store (§2.3) | — | **Open** |
| Timestamping / PQ attestation of the gold shard (§2.2, §2.4) | — | **Open** |
| Release engineering: tags, releases, PyPI, SWH/Zenodo (§4.1) | — | **Open** |
| Independent second implementation (§5) | — | **Open** |

---

## What already holds up well

Credit where due — the foundations are unusually good for a project this young:

- **Correctness is defined by artifacts, not prose.** The gold shard plus the
  invalid vectors form an executable oracle. This is the single most important
  durability property the project has, because it makes independent
  reimplementation testable.
- **Post-quantum signatures exist now** (ML-DSA-44 / FIPS 204), with
  domain-separated Merkle construction and RFC 6962 odd-leaf promotion
  (CVE-2012-2459 addressed), adopted through a written RFC.
- **Canonicalization is specified**: canonical JSON encoding, NFC
  normalization, deterministic Parquet row ordering, lexicographic Merkle leaf
  ordering.
- **The verifier is hardened**: symlink refusal, size/count limits, TOCTOU-safe
  manifest handling, streamed hashing, bounded Parquet preflight.
- **The paper anchors itself to a commit** (`6fa74b6d…`), which exists in
  history, and its stated gold-shard Merkle root matches the committed
  manifest.

The problems below are fixable, and most are cheap. But several of them are
exactly the kind of quiet rot that kills archival formats.

---

## 1. Broken today — fix before anything else

### 1.1 `make test` fails out of the box (test pollution)

A fresh `pip install -e ".[dev]" && make test` fails 5 of 77 tests
(`test_pq_upgrade.py`, `test_sign.py`). Root cause:
`tests/test_mldsa_backend_contract.py` injects a fake Dilithium backend whose
`verify` always returns `True`, then calls `importlib.reload(axm_build.sign)`.
`monkeypatch` restores `sys.modules` at teardown, but the **reloaded module
object retains the fake backend closures**, so every ML-DSA test that runs
after that file (alphabetical collection order) runs against crypto that
accepts everything. Confirmed order-dependent: each file passes in isolation.

This matters beyond hygiene: the project's stated contribution gate is
"ensure `make test` passes" (CONTRIBUTING.md), and that gate is currently
unsatisfiable. Fix: a fixture that re-reloads `axm_build.sign` (and
`axm_verify.crypto`) after each reload-based test, restoring the real backend.

### 1.2 There is no CI

CONTRIBUTING.md states "CI verifies the committed bytes pass verification" —
but no `.github/workflows/` exists. Nothing verifies the gold shard on push,
nothing runs the conformance suite, nothing catches 1.1. For a repository
whose whole identity is "the frozen definition of correctness," an unenforced
invariant is a decaying invariant. Minimum viable CI:

- `pytest tests/` on every supported Python (3.10–3.13+), on Linux/macOS/Windows
- `axm-verify shard shards/gold/… --trusted-key keys/…` as its own required job
- One job with `liboqs-python`, one with `dilithium-py`, one with **no** PQ
  backend (the RuntimeError path)
- `ruff check src/`

### 1.3 COMPATIBILITY.md contradicts the spec and the code

COMPATIBILITY.md presents itself as "the primary stability guarantee for the
AXM ecosystem," and nearly every technical claim in it is wrong:

| COMPATIBILITY.md says | Reality (spec + code) |
|---|---|
| Merkle: `BLAKE3(sorted(BLAKE3(file_bytes)))` | Leaves bind the relative path (`BLAKE3(relpath ‖ 0x00 ‖ bytes)`), and the PQ suite adds domain prefixes and RFC 6962 promotion (spec §4.1/§4.2) |
| Suite identifier `axm-blake3-ed25519` | Actual identifier is `"ed25519"` or an absent `suite` field (spec §11.2, `const.KNOWN_SUITES`) |
| claims.parquet has `confidence`, `speaker`, `source_span_id` (frozen) | Actual frozen schema: `claim_id, subject, predicate, object, object_type, tier` (spec §7.2) |
| Exit codes 0/1/2 are frozen (2 = malformed shard) | `axm_verify/cli.py` exits 0 or 1 only; a malformed-but-existing shard exits 1 |
| Extension schemas defined in `spec/extensions/` | Directory does not exist |
| References `distill.py` / `_reseal_shard()` | Not in this repository |

An engineer in 2040 doing a clean-room reimplementation from this document
would build a verifier that rejects every valid shard. Doc-vs-code divergence
is the number-one killer of archival formats. Fix: rewrite COMPATIBILITY.md
against the spec, and add a CI job that mechanically checks the claims that
can be checked (suite identifiers, schema column lists, exit codes).

### 1.4 Version and metadata drift

- `axm_verify/__init__.py` says `__version__ = "1.1.0"`; `pyproject.toml`
  says `1.2.0`. Single-source the version.
- `pyproject.toml` description ("Protocol for immutable, content-addressed
  knowledge graphs") differs from the repo's self-description; harmless but
  drift is drift.

### 1.5 The paper's Merkle description doesn't match the spec or code

Paper §6.3.3 describes leaf pairing where an odd count is "paired with itself"
and internal nodes that set "the PARENT flag in the BLAKE3 context," and says
dotfiles are excluded from the covered set. The implementation uses plain
BLAKE3 with `0x00`/`0x01` byte prefixes (not BLAKE3 tree-mode flags), the PQ
suite *promotes* odd leaves rather than duplicating them, and dotfiles are not
excluded from the Merkle walk — the shard is rejected earlier by layout
validation (`E_DOTFILE`). The paper is labeled non-normative, which saves it,
but a v0.7 should correct §6.3.3 or explicitly defer to spec §4. The paper's
conformance table (T1: "missing fields") also overstates what the verifier
checks — see 3.1.

---

## 2. Trust-anchor gaps — the 30-year critical path

### 2.1 The gold shard's signing key is public

`CANONICAL_TEST_PRIVATE_KEY` — the Ed25519 private key behind
`keys/canonical_test_publisher.pub`, i.e. the key that signed the gold shard —
is hardcoded in `src/axm_build/cli.py`. Deliberate for a test publisher, but
the consequence must be stated plainly: **the gold shard's signature has zero
authentication value.** Anyone can mint a different shard that verifies under
the canonical key. The gold shard's authenticity today rests entirely on this
git repository's integrity, which is a single GitHub account.

### 2.2 The gold shard is Ed25519-signed, frozen forever, and Ed25519 will fall

The correctness oracle for the entire ecosystem is signed with a
quantum-vulnerable algorithm (compounded by 2.1), is contractually never
recompiled, and spec §11.5 says Ed25519 shards "remain valid indefinitely."
On the day a cryptographically relevant quantum computer exists, every legacy
signature — including the oracle's — becomes forgeable, and "indefinitely
valid" becomes a liability written into the spec.

The fix does not require recompiling anything. What's needed is **out-of-band
anchoring of the exact bytes**, established while the current cryptography
still holds:

1. **Detached PQ attestation**: an ML-DSA-44 signature over the gold shard's
   Merkle root + manifest hash, published in the repo *outside* the shard
   directory (a `attestations/` dir), so the frozen bytes are untouched.
2. **Trusted timestamps**: RFC 3161 and/or OpenTimestamps proofs over the same
   digests, proving the artifacts existed before any future forgery capability.
3. **Independent replication**: trigger Software Heritage archival of the
   repository; deposit a release tarball with Zenodo (gets a DOI); optionally
   publish the gold shard's Merkle root somewhere out-of-band and
   human-durable (the paper itself partially serves this — Table 4 pins
   `e30deb23…dcee21`).
4. **A spec-level policy** (via RFC) for what "valid" means for legacy-suite
   shards after a stated sunset: e.g. "Ed25519 shards verify only in
   combination with a pre-sunset timestamp proof."

### 2.3 There is no key lifecycle at all

Verification is `shard_pub == trusted_pub` — raw byte equality against exactly
one key file. Over 30 years a publisher will rotate keys many times. Missing,
and needed as an RFC (all additive, none of it breaks the frozen spec):

- A trust-store format (multiple keys, validity windows, suite per key)
- A rotation mechanism: new key cross-signed by old key (a rotation statement
  is itself a natural fit for a signed shard)
- Revocation semantics — what does a verifier do with a shard signed by a
  since-revoked key? (Answer probably interacts with timestamps: valid if
  provably sealed before revocation.)
- Publisher identity ↔ key binding: `publisher.id` in the manifest is a free
  string with no defined relationship to the key that signs.

### 2.4 Signatures prove *who*, never *when*

Nothing in the format proves when a shard was sealed (`created_at` is a
self-asserted string). Long-term verification depends on "this existed before
algorithm X broke / before key Y leaked," which requires timestamping. Adopt a
re-timestamping policy in the spirit of RFC 4998 evidence records: an
extension table or detached artifact carrying periodic timestamp renewals over
the Merkle root. This is the standard answer in long-term digital preservation
and it composes cleanly with `ext/`.

---

## 3. Specification completeness — close the spec/verifier gap

### 3.1 The verifier does not enforce the manifest schema the spec requires

Spec §5.2 lists required manifest fields (`spec_version`, `metadata.*`,
`publisher.*`, `license.spdx`, `sources`, `statistics.*`). The reference
verifier (`logic.py::_read_manifest`) validates exactly one thing:
`integrity.merkle_root` is 64 hex chars. A manifest missing `spec_version` —
or `sources`, whose hashes anchor all span/provenance verification — passes.
Nothing checks that `sources[].hash` values correspond to actual content
files, that `statistics` match table row counts, or that `spec_version` is a
version the verifier understands. `E_MANIFEST_SCHEMA` exists but fires only
for the merkle_root shape.

Either enforce §5.2 in the verifier (and add invalid vectors for each missing
field — the conformance suite currently cannot distinguish a conforming
verifier from one that skips manifest validation entirely), or amend the spec
to mark those fields advisory. A frozen spec whose reference implementation
silently under-enforces it trains every downstream implementer to
under-enforce differently.

### 3.2 Pin the Parquet subset

The frozen format's core tables are Parquet — a large, evolving format. The
spec says "Parquet with explicit schemas" but does not pin: format version,
allowed encodings, compression codecs (the builder emits zstd; the gold shard
predates that), nested-type prohibition, single-vs-multi row-group
expectations. A 2056 reimplementer needs to know the *subset* of Parquet a
conforming shard may use, or verification of Section-8 invariants requires a
full Parquet stack forever. Write it down (RFC, additive). Same for a byte
range: `tier` is int8 in code, "0 to 4" in spec — pin signedness and range in
one place.

### 3.3 Pin Unicode behavior

`canonicalize()` = NFC + `str.casefold()` + category-`Cc` stripping, delegated
to whatever Unicode tables ship with the host Python. Unicode normalization
and casefold mappings change across Unicode versions; the same label could
yield different `entity_id`s decades apart, breaking content-addressing. Fix:
declare a Unicode version in the spec, and grow `tests/vectors/identity.json`
with adversarial cases (combining characters, casefold expansions like ß→ss,
Turkish dotless-i, Cyrillic confusables) so any drift is caught mechanically.

### 3.4 Document the ID-truncation tradeoff

Entity/claim/span IDs are SHA-256 truncated to 15 bytes = 120 bits (~2⁶⁰
birthday bound). Almost certainly fine, but for an archival format the
collision policy should be explicit in the spec: what a verifier does when two
distinct (namespace, label) pairs collide, and why 120 bits was chosen.

### 3.5 Specify verifier behavior for future suites

Spec §11.4 says a verifier "must report an error rather than silently skip"
for unknown suites — good. But `crypto.verify_manifest_signature` defaults
unknown suites to Ed25519 key-size checks when called directly. Tighten the
API so the spec rule is structurally impossible to bypass.

---

## 4. Process and ecosystem durability

### 4.1 Release engineering (currently: none)

There are **no git tags, no GitHub releases, no published packages**. The only
way to obtain axm-genesis is to clone one repository on one platform.
Needed:

- Signed, annotated git tags for every version in CHANGELOG.md going forward
- GitHub releases carrying: sdist/wheel, a checksum manifest, and the gold
  shard's digests restated
- PyPI publication (squats the name, adds a mirror, enables `pip install`)
- Software Heritage save + Zenodo DOI per release (see 2.2)

### 4.2 Bus factor is one

One maintainer, one GitHub account, one Proton address. For a 30-year project
this is the largest single risk, bigger than any cryptographic concern.
Mitigations, in increasing order of effort: a `SECURITY.md` with a disclosure
contact; a second maintainer with full access; moving the repo to a GitHub
organization; a short `GOVERNANCE.md` stating what happens to spec authority
if the maintainer disappears (e.g. "any verifier passing `tests/vectors/` is
conformant; the vectors are the authority" — which the project already
half-believes, so write it down).

### 4.3 Dependency strategy

- Requirements are lower-bounds only. Reproducing "the reference environment"
  in 10 years will be archaeology. Ship a lockfile (`constraints.txt` or
  `uv.lock`) and/or record a container digest per release, as a *record*, not
  a runtime constraint.
- `dilithium-py` (explicitly unaudited) is the only PQ backend in the `dev`
  extra, so the conformance suite's PQ results ride on unaudited crypto unless
  CI also exercises liboqs (see 1.2). The liboqs `SystemExit` incident in the
  git history shows backend API drift is already real.
- The DuckDB no-pyarrow fallback path in `logic.py` builds SQL by
  interpolating file paths and is far less tested than the pyarrow path; CI
  should run the suite once with pyarrow removed, or the fallback should be
  dropped and pyarrow made a hard requirement (simpler surface to keep alive).

### 4.4 Cross-repo references need pinning

STREAM_FORMAT.md derives constants from `axm_embodied_core/protocol.py`;
THREE_LAYERS.md and COMPATIBILITY.md reference Forge, Spectra, `distill.py` —
none of which live here, none pinned to a commit. The kernel repo should be
self-contained: either restate frozen constants normatively here (mostly done
for STREAM_FORMAT) with external references clearly non-normative, or pin
external repos by commit hash.

### 4.5 Repository hygiene

- `index.html` (a marketing/GitHub Pages page) lives at the root of the
  frozen-kernel repo. Move it to a `gh-pages` branch or separate site repo;
  the paper already declares website content non-normative.
- `docs/REQ5_implementation_notes.md` is a completed implementation work
  order; move under `rfcs/` or an `archive/` folder so `docs/` stays current.

---

## 5. The real 30-year test: independent reimplementation

Everything above serves one goal: that someone with no access to this codebase
— possibly no access to a working Python ecosystem — can rebuild a conforming
verifier from the spec and vectors. That is the durability test that matters.
Concrete program:

1. **Fund/write a second verifier in another language** (Rust or Go), in a
   separate repo, developed only from `spec/` + `tests/vectors/` + the gold
   shard. Every ambiguity it hits is a spec bug; file and fix each one. This
   will flush out sections 1.3, 3.1–3.3 faster than any review.
2. **Expand the vector corpus** as the conformance contract: add valid+invalid
   vectors for the ML-DSA suite (current committed vectors are Ed25519-era),
   manifest-schema violations (3.1), extension handling, Unicode identity
   edge cases (3.3), and an `ext/`-bearing shard. COMPATIBILITY.md's one true
   sentence — "test vectors are the ground truth" — should become the
   project's operating principle.
3. **Adopt a durability cadence**: an annual, dated review (this document is
   the template) that re-verifies the gold shard on current toolchains,
   renews timestamps (2.4), checks dependency health, and records results in
   the repo. Thirty years is not one decision; it is sixty of these reviews
   not being skipped.

---

## Priority summary

| Horizon | Actions |
|---|---|
| **This week** | Fix test pollution (1.1) · Add CI incl. gold-shard job (1.2) · Rewrite COMPATIBILITY.md (1.3) · Sync versions (1.4) |
| **This quarter** | Timestamp + PQ-attest the gold shard (2.1–2.2) · Tag/release/PyPI/SWH/Zenodo (4.1) · Close spec/verifier manifest gap + new vectors (3.1) · SECURITY.md + second maintainer (4.2) · Correct paper §6.3.3 in v0.7 (1.5) |
| **This year** | Key-rotation/trust-store RFC (2.3) · Re-timestamping policy RFC (2.4) · Pin Parquet subset + Unicode version (3.2–3.3) · Lockfile per release (4.3) · Repo hygiene (4.4–4.5) |
| **Ongoing** | Independent second verifier (5.1) · Vector corpus growth (5.2) · Annual durability review (5.3) |
