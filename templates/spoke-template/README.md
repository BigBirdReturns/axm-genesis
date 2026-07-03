# axm-spoke-template

A minimal, **working** AXM spoke. It reads a text file, extracts claim
candidates, hands them to the axm-genesis kernel (`CompilerConfig` +
`compile_generic_shard`), and returns the derived `sh1_` shard identity.
Its test suite is the conformance habit in miniature: build → verify PASS →
tamper one byte → verify FAIL.

Copy this directory out of `axm-genesis` to start a new spoke. The full
adoption guide is [`docs/ADOPTING.md`](../../docs/ADOPTING.md); the runtime
contract (entry points, what to import from Core, what never to
reimplement) is
[SPOKE_API.md](https://github.com/BigBirdReturns/axm-core/blob/main/SPOKE_API.md).

## Layout

```
pyproject.toml                       axm-genesis pin, axm.spokes entry point, dev extra
src/axm_spoke_template/spoke.py      build_shard() — the one function a spoke owns
src/axm_spoke_template/cli.py        click group: build + verify passthrough
tests/test_roundtrip.py              build → PASS → tamper → FAIL, throwaway keys in tmp
tests/fixtures/sample.txt            fixture source text
.github/workflows/ci.yml             self-verifying CI: tests + kernel-boundary drift check
.github/workflows/pages.yml          GitHub Actions Pages deploy (guarded: no-op until you add index.html)
```

## Run it

```bash
python -m venv .venv && . .venv/bin/activate
pip install /path/to/axm-genesis          # or the pinned commit/PyPI release
pip install -e ".[dev]"
pytest tests/ -v                          # 2 passed

# End to end, by hand:
axm-build keygen /secure/keys --name publisher       # secret key stays offline
axm-spoke-template build tests/fixtures/sample.txt /tmp/shard \
  --key /secure/keys/publisher.key --namespace template/demo
axm-spoke-template verify /tmp/shard --trusted-key /secure/keys/publisher.pub
```

`build` prints the derived shard id (`sh1_` + 64 hex chars — never stored
in the shard); `verify` is a passthrough to the kernel verifier and honors
the frozen exit-code contract (0 PASS, 2 malformed, 1 any other failure).

## Renaming checklist

Per the naming convention in SPOKE_API.md (`axm-<domain>` / `axm_<domain>`
/ entry key `<domain>`), for a domain called `weather`:

1. `pyproject.toml`: `name = "axm-weather"`, entry point
   `weather = "axm_weather.cli:weather_group"`, script `axm-weather`.
2. `mv src/axm_spoke_template src/axm_weather`; update the imports in
   `tests/test_roundtrip.py`.
3. `cli.py`: rename `spoke_template_group` → `weather_group` and the group
   name string to `"weather"`.
4. Replace `extract_candidates()` in `spoke.py` with your real extraction.
   Everything below it — `CompilerConfig`, `compile_generic_shard`, the
   derived id — stays exactly as is: compilation, signing, and verification
   belong to axm-genesis and are never reimplemented in a spoke.
5. Update the publisher defaults (`publisher_id`, `publisher_name`) and the
   axm-genesis pin comment to whatever you actually depend on.
6. Keep `tests/test_roundtrip.py` green. CI is already wired
   (`.github/workflows/ci.yml`) — just bump its `ref:` to the kernel commit
   you pin in `pyproject.toml`.

## Stay synced with the kernel (CI + drift check)

`.github/workflows/ci.yml` is the anti-drift habit: on every push it checks
your spoke out beside the pinned kernel, installs it, runs the roundtrip
tests, and runs `tools/drift-check.sh` **from genesis** against your tree.
Drift becomes a red build in this one repo — caught at push — instead of
silent rot you rediscover a year later. The lint fails the build if a spoke:

- hardcodes a signing key/seed (keys come from `axm-build keygen`);
- reimplements a frozen kernel surface (signing, Merkle, manifest encoding);
- stores a derived identity (`shard_blake3_…` / a stored `shard_id`); <!-- drift-ok: documenting the rule -->
- ships Parquet shard tables (v1 tables are canonical JSONL); or
- names a retired suite (`SUITE_MLDSA44` / `axm-blake3-mldsa44`). <!-- drift-ok: documenting the rule -->

Because the check lives in genesis, every spoke runs the *same* current rules
— the lint can't drift either. After the v1.0.0 PyPI release, drop the
genesis checkout and float on `axm-genesis[mldsa-compat]>=1.0.0,<2`: a 1.x
kernel bump can't break your shards (COMPATIBILITY.md), so you never sync
pins by hand. (The CI's `ref:` must point at a kernel commit that contains
`tools/drift-check.sh`; the pin shipped here already does.)

## Publishing a Pages site

`.github/workflows/pages.yml` deploys a GitHub Pages site via GitHub Actions
(set Settings → Pages → Source to "GitHub Actions"). It is **guarded**: with
no root `index.html` — the state of a fresh code-only spoke — the deploy is
skipped and the job stays green. Add an `index.html` (see the ecosystem house
style in `axm-genesis/index.html`) and it publishes on the next push to the
default branch. Nothing to wire up; it activates when a site exists.

## The rule this template exists to teach

**Every claim in your spoke's README must be a command someone can run or
a test that runs in CI.** This README says the tests pass and the CLI
builds a verifiable shard — both are checked by `pytest tests/` against
the kernel verifier, with fresh throwaway keys, on every run. Hold your
own README to the same standard.
