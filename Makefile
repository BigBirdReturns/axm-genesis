.PHONY: install test verify-gold lint clean

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

verify-gold:
	axm-verify shard shards/gold/fm21-11-hemorrhage-v1/ --trusted-key keys/canonical_test_publisher.pub

lint:
	ruff check src/

clean:
	rm -rf build/ dist/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
