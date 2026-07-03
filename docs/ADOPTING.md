# Adopting AXM — building a spoke

This is the on-ramp for a new project that wants to produce AXM shards.
Every command in this document was executed against the current tree
(commit `9c0b749`, `axm-genesis 1.0.0rc1`) before it was written down;
outputs shown are real. A copy-out-and-rename starter package lives at
[`templates/spoke-template/`](../templates/spoke-template/).

## 1. What a spoke is

A **spoke** is a domain package (chat exports, sensor logs, CAD files,
weather reports, …) that turns its domain's input into claim candidates
and hands them to the axm-genesis kernel, which compiles them into a
sealed, signed, verifiable shard. Optionally, the spoke registers a CLI
with the [axm-core](https://github.com/BigBirdReturns/axm-core) runtime so
its commands appear under `axm <name>`.

The division of labor is the ecosystem's one invariant
([COMPATIBILITY.md](../COMPATIBILITY.md)):

> **Genesis compiles and signs; everything else reads.**

A spoke owns exactly three things: domain extraction, its CLI/UI, and its
dependency declarations. It never reimplements compilation, verification,
Merkle construction, identity derivation, or key handling — those are
kernel surfaces, and spoke-level copies of them silently break the
signature contract. The full do/don't table is in
[SPOKE_API.md](https://github.com/BigBirdReturns/axm-core/blob/main/SPOKE_API.md).

## 2. Depend on the kernel

Declare `axm-genesis` in your `pyproject.toml`. Signing needs an ML-DSA-44
backend, so include one of the extras: `[mldsa-compat]` (pure-Python
`dilithium-py`) or `[mldsa]` (`liboqs-python`, preferred where the C
library is available).

**Today (pre-v1.0.0):** the package is not yet on PyPI
([RELEASE.md](../RELEASE.md) step 7 publishes it). Pin the exact commit
you built against:

```toml
dependencies = [
  "axm-genesis[mldsa-compat] @ git+https://github.com/BigBirdReturns/axm-genesis@9c0b749c3843d3bd7b341117ce6971e0c6d30418",
]
```

**After the v1.0.0 tag:** switch to the semver range. The kernel is frozen
at 1.0.0 — [COMPATIBILITY.md](../COMPATIBILITY.md) guarantees that a shard
your spoke compiles under any 1.x verifies under every other 1.x, so a
range (not an exact pin) is correct:

```toml
dependencies = [
  "axm-genesis[mldsa-compat]>=1.0.0,<2",
]
```

Do not pin exact versions of `axm-genesis` or `axm-core` in a released
spoke; minimum-plus-major-cap is the convention (SPOKE_API.md
"Versioning").

## 3. Publisher identity — keys

One `axm-build keygen` run creates one **publisher identity**: a hybrid
axm-hybrid1 keypair (Ed25519 ‖ ML-DSA-44).

```console
$ axm-build keygen /secure/axm-keys --name publisher
Secret key (3904 bytes): /secure/axm-keys/publisher.key
Public key (1344 bytes): /secure/axm-keys/publisher.pub
```

The rules, learned the hard way by the first spoke (`axm-chat`):

- **The secret blob stays offline and out of the repository.** The
  3904-byte `.key` file is written `0o600` and is the only thing that can
  sign as you. Only the 1344-byte `.pub` file is ever committed,
  distributed, or handed to verifiers. The maintainer-grade ceremony for
  the canonical key is [RELEASE.md](../RELEASE.md) §1; the custody model
  is [`keys/README.md`](../keys/README.md).
- **One publisher identity per key pool, and pools are suite-aware.** A
  key directory holds keys for exactly one suite. If code finds key
  material of an unexpected size or suite in a pool, it must raise — never
  fall back to generating a fresh key or coercing the bytes. A silent
  fallback mints shards under an identity nobody controls or produces a
  confusing size error three layers down. (`keygen` itself refuses to
  overwrite existing files; keep your loaders equally strict.)
- **There is deliberately no default signing key** anywhere in the
  toolchain. A signature under a published key proves integrity, never
  authenticity. Tests generate throwaway keypairs per run (or use a
  committed test key that is *documented* as proving nothing — see
  [`tests/keys/README.md`](../tests/keys/README.md)); real keys never
  appear in CI.

## 4. The compile → verify roundtrip

This is the spoke's whole production path: candidates in, verified shard
out. Both forms below were run end-to-end; the programmatic form is what
[`templates/spoke-template/`](../templates/spoke-template/) wires up for
you.

### 4.1 CLI form

`axm-build compile` takes a candidates file, a content directory (copied
into the shard verbatim), and an output directory. Its candidates format
uses explicit byte offsets against your content files:

```
{"type":"entity", "namespace":"...", "label":"...", "entity_type":"..."}
{"type":"claim", "subject_label":"...", "predicate":"...", "object_label":"...",
 "object_type":"entity|literal:...", "tier":0-4,
 "evidence":{"source_file":"<name in content dir>", "byte_start":N, "byte_end":N, "text":"..."}}
```

Executed:

```console
$ printf 'Tourniquets stop severe bleeding.\nElevation supports hemorrhage control.\n' > content/notes.txt
$ cat > candidates.jsonl <<'EOF'
{"type":"entity","label":"tourniquet","entity_type":"concept"}
{"type":"entity","label":"severe bleeding","entity_type":"concept"}
{"type":"claim","subject_label":"tourniquet","predicate":"treats","object_label":"severe bleeding","object_type":"entity","tier":3,"evidence":{"source_file":"notes.txt","byte_start":0,"byte_end":33,"text":"Tourniquets stop severe bleeding."}}
{"type":"claim","subject_label":"elevation","predicate":"supports","object_label":"hemorrhage control","object_type":"entity","tier":2,"evidence":{"source_file":"notes.txt","byte_start":34,"byte_end":72,"text":"Elevation supports hemorrhage control."}}
EOF
$ axm-build compile candidates.jsonl content out-shard \
    --private-key keys/publisher.key \
    --namespace demo/notes --title "Demo Notes" \
    --created-at 2026-07-02T00:00:00Z --license-spdx CC0-1.0
{
  "spec_version": "1.0.0",
  "suite": "axm-hybrid1",
  ...
  "statistics": { "entities": 4, "claims": 2 }
}
Shard written to out-shard

$ axm-verify shard out-shard --trusted-key keys/publisher.pub
{"shard": "out-shard", "status": "PASS", "error_count": 0, "errors": [], "profiles_checked": [], "profiles_unchecked": []}
$ echo $?
0
```

Tamper one byte of sealed content and the verifier catches it:

```console
$ printf 'X' | dd of=out-shard/content/notes.txt bs=1 seek=0 count=1 conv=notrunc
$ axm-verify shard out-shard --trusted-key keys/publisher.pub
{"shard": "out-shard", "status": "FAIL", "error_count": 1, "errors": [{"code": "E_MERKLE_MISMATCH", ...}], ...}
$ echo $?
1
```

Note: the CLI `compile` command currently stamps a fixed
`publisher.id`/`publisher.name` (`@axm_builder`). A real spoke should use
the programmatic API below, which makes the publisher identity explicit.

### 4.2 Programmatic form — `CompilerConfig` / `compile_generic_shard`

The programmatic compiler is the surface spokes build on. Its candidates
format is quote-based: no byte offsets — each `evidence` string must occur
**exactly once** in the normalized source text (missing evidence drops the
candidate; ambiguous evidence fails the build). The source file is
normalized on the way in (NFC, per-line trailing-whitespace strip,
internal-whitespace collapse, trailing newline) and written to
`content/source.txt`.

```
{"subject":"<entity label>", "predicate":"<verb>", "object":"<label or literal>",
 "object_type":"entity|literal:string|literal:integer|literal:decimal|literal:boolean",
 "tier":0-4, "evidence":"<exact quote from the normalized source>"}
```

Optional per-candidate keys feed the extension tables (§6): `locator`
(dict → `ext/locators@1.jsonl`), `references` (list of
`{"dst_shard_id":"sh1_...", ...}` → `ext/references@1.jsonl`),
`valid_from`/`valid_until`/`temporal_context` (→ `ext/temporal@1.jsonl`).

Complete working example (executed as shown):

```python
from pathlib import Path
import blake3
from axm_build.compiler_generic import CompilerConfig, compile_generic_shard
from axm_verify.logic import verify_shard

base = Path("prog")
# prog/source.txt:
#   Tourniquets stop severe bleeding.\nElevation supports hemorrhage control.\n
# prog/candidates.jsonl (one JSON object per line):
#   {"subject":"tourniquet","predicate":"treats","object":"severe bleeding",
#    "object_type":"entity","tier":3,"evidence":"Tourniquets stop severe bleeding."}
#   {"subject":"elevation","predicate":"supports","object":"hemorrhage control",
#    "object_type":"entity","tier":2,"evidence":"Elevation supports hemorrhage control."}

cfg = CompilerConfig(
    source_path=base / "source.txt",
    candidates_path=base / "candidates.jsonl",
    out_dir=base / "shard",
    private_key=Path("keys/publisher.key").read_bytes(),  # 3904-byte hybrid1 blob
    publisher_id="@demo_spoke",
    publisher_name="Demo Spoke",
    namespace="demo/notes",
    created_at="2026-07-02T00:00:00Z",   # RFC 3339 UTC, Z suffix — enforced
    title="Demo Notes",
    license_spdx="CC0-1.0",
)
ok = compile_generic_shard(cfg)   # writes the shard AND self-verifies it
assert ok                          # False = the kernel rejected its own output

# Independent verification with the trusted key, supplied out of band:
result = verify_shard(base / "shard", Path("keys/publisher.pub"))
assert result["status"] == "PASS", result["errors"]

# Shard identity is DERIVED, never stored (spec §9):
shard_id = "sh1_" + blake3.blake3((base / "shard" / "manifest.json").read_bytes()).hexdigest()
```

Output of that exact script:

```
compile self-verify: True
verify: PASS []
shard_id: sh1_f4d4ff4fe5c5d6704c1fe87a7b66afb8887c2864378fc8230dc6d9a94babdfc7
```

`verify_shard(shard_path, trusted_key_path)` returns the frozen result
JSON (`status`, `error_count`, `errors[]`, `profiles_checked`,
`profiles_unchecked` — spec §13.3); the CLI maps it onto the exit-code
contract for you.

## 5. Conformance in CI

Your spoke conforms when the shards it emits satisfy the four kernel
requirements — REQ 1 manifest integrity, REQ 2 content identity, REQ 3
traceable lineage, REQ 4 proof bundle — defined in
[`spec/v1/CONFORMANCE.md`](../spec/v1/CONFORMANCE.md). You do not check
these yourself; you **run the kernel verifier against your own output in
CI** and fail the build on anything but PASS:

```bash
axm-verify shard "$SHARD" --trusted-key "$PUBKEY"
# exit 0  status PASS — ship it
# exit 2  structurally malformed (missing required files/dirs)
# exit 1  any other failure (signature, Merkle, schema, references, profiles)
```

The exit codes are frozen ([COMPATIBILITY.md](../COMPATIBILITY.md) §4), so
`axm-verify shard ... || exit 1` in a CI step is a stable contract, not a
convention. The minimum test every spoke ships is the tamper roundtrip —
build a shard with a throwaway key, verify PASS, flip one content byte,
assert FAIL with `E_MERKLE_MISMATCH` — exactly what
[`templates/spoke-template/tests/test_roundtrip.py`](../templates/spoke-template/tests/test_roundtrip.py)
does.

Ground truth is the vector suite, not prose: the shards under
[`tests/vectors/`](../tests/vectors/) and the gold shard define
correctness, and where prose and vectors disagree, the vectors govern.
Vectors are frozen once added, so behavior your CI observes against them
today holds for the life of the major version.

## 6. Extension tables — `ext/`

Anything your domain needs beyond the four core tables goes in `ext/`,
which is sealed and Merkle-covered like everything else but **opaque to
the kernel verifier** (spec §16). To add one:

1. **Name it `<name>@<version>`** (grammar `^[a-z][a-z0-9-]*@[1-9][0-9]*$`);
   the file is `ext/<name>@<version>.<suffix>`. A new version is a new
   identifier — published extension schemas are frozen.
2. **Use canonical JSONL** for AXM-defined extensions: same encoding
   discipline as the core tables — canonical JSON per line (sorted keys,
   no whitespace, no floats, no nulls), rows sorted bytewise by the sort
   key. See `src/axm_build/ext_schemas.py` for the registered schemas
   (`locators@1`, `references@1`, `temporal@1`, `lineage@1`).
3. **Declare it in the manifest**: when `ext/` is non-empty,
   `manifest.extensions` must list every extension identifier; when `ext/`
   is empty, the field must be absent. The reference compiler does this
   automatically for the registered extensions.
4. **Cross-shard ids use the `sh1_` form and name only *other* shards.** A
   shard never records its own id — it can't, since the id is the BLAKE3
   hash of the manifest, which hashes the files.

**Lineage / supersedes** is how a shard replaces a predecessor, and it
follows directly from rule 4: pass the predecessor's derived id(s) to the
compiler and it emits both the manifest `supersedes` array and an
`ext/lineage@1.jsonl` row per predecessor — with **no self-id column**, so
a single Merkle pass suffices. Executed:

```python
cfg = CompilerConfig(
    ...,                                # as in §4.2
    supersedes=("sh1_f4d4ff4fe5c5d6704c1fe87a7b66afb8887c2864378fc8230dc6d9a94babdfc7",),
    lineage_action="supersede",         # supersede | amend | retract
    lineage_note="corrected tiers",
)
```

producing (verified PASS):

```
manifest.extensions = ["lineage@1"]
manifest.supersedes = ["sh1_f4d4ff4f...babdfc7"]
ext/lineage@1.jsonl:
{"action":"supersede","note":"corrected tiers","supersedes_shard_id":"sh1_f4d4ff4f...babdfc7","timestamp":"2026-07-02T01:00:00Z"}
```

### Spoke-owned content and extension tables — one pass, never a reseal

Domains that seal more than text — binary sensor streams, packet journals,
hardware-attestation blobs — hand that evidence to the **same** compiler call,
never a post-compile edit. `CompilerConfig` takes:

- `extra_content` — additional `content/` files (e.g. `cam_latents.bin`,
  `packets.bin`), copied verbatim, listed in the `sources` bijection, and
  sealed as ordinary Merkle leaves;
- `extra_ext` — `{extension_id: rows}` for **registered** extensions the spoke
  computed itself (ids the kernel derives — `locators@1`/`references@1`/
  `temporal@1`/`lineage@1` — are refused, to avoid a two-writer race).

Binary never rides in a JSONL row. The convention (RFC 0006) is
**index-into-content**: put the bytes in `content/` via `extra_content` and let
the table reference them by `(file, offset, length)` + a `sha256` — exactly how
`streams@1` indexes `cam_latents.bin`. A flipped evidence byte then fails as
`E_MERKLE_MISMATCH` under the stock verifier, with no domain logic.

The registered non-core extensions today:

| id | purpose | RFC |
|---|---|---|
| `streams@1` | embodied binary stream index (`embodied@1` profile) | — |
| `attestations@1` | timestamp *proof-of-when* anchors over other shards | 0005 |
| `packets@1` | verbatim canonical packet bytes for a custody journal | 0006 |
| `tpm-attestation@1` | TPM hardware trust-chain evidence, indexed into content/ | 0006 |

Adding a new one is a one-line `EXTENSION_REGISTRY` entry behind an RFC
(`extra_ext` rejects unregistered ids). **Never** write files into a sealed
shard and re-hash/re-sign it yourself — that reimplements four frozen kernel
surfaces (the anti-pattern axm-sfn carried and RFC 0006 retires). If you must
migrate an *existing* shard's signature suite, that is RFC 0004 (additive
reseal layers) — a kernel operation, not a spoke's.

## 7. Profiles

A **profile** is a named, versioned set of *additional checks* over
`content/` and `ext/`, defined in its own frozen document under
`spec/profiles/` (e.g. [`embodied@1`](../spec/profiles/embodied@1.md)).
Declare one — `CompilerConfig(profiles=("embodied@1",))`, which becomes
`"profiles": ["embodied@1"]` in the signed manifest — when your domain
makes a guarantee the kernel cannot express and you want that compliance
claim to be non-repudiable. Adding a new profile is a spec PR
(minor version, no kernel change): see [CONTRIBUTING.md](../CONTRIBUTING.md).

The rule your consumers must understand: **unchecked is not passed**
(spec §15.3). A verifier that doesn't implement a listed profile reports
it in `profiles_unchecked` and must not fail the shard for it — so a PASS
with a non-empty `profiles_unchecked` covers only the kernel guarantees.
Anyone relying on your profile's guarantee must confirm it appears in
`profiles_checked`. If your spoke's checks are advisory rather than
verifiable-forever, keep them in your own test suite instead of minting a
profile.

## 8. Registering with the runtime

Producing shards requires only `axm-genesis`. To surface your spoke in the
`axm` CLI and query its shards with Spectra, register a `click.Group`
under the `axm.spokes` entry-point group:

```toml
[project.entry-points."axm.spokes"]
myspoke = "axm_myspoke.cli:myspoke_group"
```

axm-core discovers every installed spoke via
`importlib.metadata.entry_points(group="axm.spokes")` at startup — no core
code changes needed. The runtime contract — what a spoke may import
(Spectra engine, NL→SQL, Forge extractors/emission), what it must never
reimplement, and the `axm-<domain>`/`axm_<domain>` naming convention — is
[SPOKE_API.md](https://github.com/BigBirdReturns/axm-core/blob/main/SPOKE_API.md)
in the axm-core repository. Declare `axm-core` as a dependency only if you
use those runtime surfaces; import/distill that works with `axm-genesis`
alone is encouraged as a `minimal` extra.

## 9. The documentation contract

Genesis holds itself to one discipline and asks the same of every spoke:

> **Every claim in your README is a command someone can run or a test that
> runs in CI.**

Here, COMPATIBILITY.md is parsed and asserted by
`tests/test_compatibility_contract.py`, the gold shard's bytes are pinned
by checksums CI re-checks on every push, and this document's commands were
executed before being written. For a spoke that means: the install command
is run in CI, the build→verify roundtrip is a test, the tamper case is a
test, and any performance or capability claim links to the script that
demonstrates it. If a sentence in your README can't fail a build, either
make it executable or delete it.

## 10. Start here

```bash
cp -r templates/spoke-template ../axm-mydomain && cd ../axm-mydomain
# follow the renaming checklist in its README.md
python -m venv .venv && . .venv/bin/activate
pip install "axm-genesis[mldsa-compat] @ git+https://github.com/BigBirdReturns/axm-genesis@<commit>"
pip install -e ".[dev]"
pytest tests/ -v        # 2 passed — the roundtrip works before you write a line
```

The template ships `build_shard()` (source file → signed shard → derived
`sh1_` id), a click group with `build` and `verify` wired to the
`axm.spokes` entry point, and the tamper-roundtrip test. Replace its
`extract_candidates()` with your domain extraction; leave the kernel calls
alone.
