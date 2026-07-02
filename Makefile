.PHONY: install test verify-gold verify-frozen lint clean

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

verify-gold:
	axm-verify shard shards/gold/fm21-11-hemorrhage-v1/ --trusted-key keys/canonical_test_publisher.pub

# Frozen-bytes guard: the gold shard is never regenerated. This checks the
# committed bytes against the pinned checksums (same command CI runs in the
# gold-shard job of .github/workflows/ci.yml). Run from the repo root.
verify-frozen:
	sha256sum -c shards/gold/CHECKSUMS.sha256

lint:
	ruff check src/

clean:
	rm -rf build/ dist/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
