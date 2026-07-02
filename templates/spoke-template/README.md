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
6. Keep `tests/test_roundtrip.py` green and wire `pytest` into CI.

## The rule this template exists to teach

**Every claim in your spoke's README must be a command someone can run or
a test that runs in CI.** This README says the tests pass and the CLI
builds a verifiable shard — both are checked by `pytest tests/` against
the kernel verifier, with fresh throwaway keys, on every run. Hold your
own README to the same standard.
