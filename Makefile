.PHONY: install test test-reversed verify-gold verify-frozen verify-archive verify-expected lint clean

install:
	pip install -e ".[dev]"

test:
	python -m pytest tests/ -q

# Order-independence guard: the suite must also pass with the test files
# collected in reverse order (same invariant CI enforces).
test-reversed:
	python -m pytest -q -p no:cacheprovider $$(ls tests/test_*.py | sort -r)

# Gold shard v2 (axm-hybrid1), signed by the provisional gold key minted
# on 2026-07-02 (see keys/README.md). The v0.x gold shard lives in archive/.
verify-gold:
	axm-verify shard shards/gold/fm21-11-hemorrhage-v2 --trusted-key keys/gold-v2-provisional.pub

# Frozen-bytes guard: the gold shard is never regenerated. This checks the
# committed bytes against the pinned checksums (same command CI runs in the
# gold-shard job of .github/workflows/ci.yml). Run from the repo root.
verify-frozen:
	sha256sum -c shards/gold/CHECKSUMS.sha256

# Archived v0.x gold shard byte pins (historical, non-normative — see
# archive/v0/README.md). CI enforces these next to the frozen-bytes guard.
verify-archive:
	sha256sum -c archive/v0/gold/CHECKSUMS.sha256

# Drift gate for the shard-vector ground truth: EXPECTED.md must be
# byte-identical to what tools/regen_expected.py derives from the vectors.
verify-expected:
	python tools/regen_expected.py --check

lint:
	ruff check src/ tests/

clean:
	rm -rf build/ dist/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
