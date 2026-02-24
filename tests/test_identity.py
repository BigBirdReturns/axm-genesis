"""Test identity computation against frozen test vectors."""
import json
import pytest
from pathlib import Path

from axm_verify.identity import canonicalize, recompute_entity_id, recompute_claim_id

VECTORS = Path(__file__).parent / "vectors" / "identity.json"


@pytest.fixture
def vectors():
    return json.loads(VECTORS.read_text())


def test_canonicalization(vectors):
    for case in vectors["canonicalization"]:
        if "expected_error" in case:
            with pytest.raises(ValueError):
                canonicalize(case["input"])
        else:
            assert canonicalize(case["input"]) == case["expected"], f"Failed on: {case['input']!r}"


def test_entity_ids(vectors):
    for case in vectors["entity_ids"]:
        result = recompute_entity_id(case["namespace"], case["label"])
        assert result == case["expected_id"], f"Failed on: {case['label']}"


def test_claim_ids(vectors):
    for case in vectors["claim_ids"]:
        result = recompute_claim_id(
            case["subject"], case["predicate"], case["object"], case["object_type"]
        )
        assert result == case["expected_id"]
